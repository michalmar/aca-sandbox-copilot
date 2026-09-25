"""Explicit subprocess-only P4 transport injection; never imported by production."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time


def append_record(path: str, record: dict) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, (json.dumps(record) + "\n").encode())
    finally:
        os.close(descriptor)


def install() -> None:
    if os.environ.get("HERMES_RUNTIME_IMAGE_TESTS") != "1":
        raise RuntimeError("offline fake provider requires the explicit image test opt-in")
    import azure.identity
    from azure.core.credentials import AccessToken, AccessTokenInfo
    import httpx
    import requests
    import aiohttp
    from urllib.parse import urlsplit

    def reject_external(url) -> None:
        host = urlsplit(str(url)).hostname
        if host not in {"127.0.0.1", "localhost", "::1"}:
            capture = os.environ.get("HERMES_RUNTIME_WIRE_CAPTURE")
            if capture:
                append_record(capture + ".network-attempts", {"host": host})
            raise AssertionError("unapproved network request in the offline test")

    requests_send = requests.Session.send
    aiohttp_request = aiohttp.ClientSession._request

    def guarded_requests_send(self, request, *args, **kwargs):
        reject_external(request.url)
        return requests_send(self, request, *args, **kwargs)

    async def guarded_aiohttp_request(self, method, url, *args, **kwargs):
        reject_external(url)
        return await aiohttp_request(self, method, url, *args, **kwargs)

    requests.Session.send = guarded_requests_send
    aiohttp.ClientSession._request = guarded_aiohttp_request

    def get_token(self, *scopes, **kwargs):
        if scopes != ("https://ai.azure.com/.default",):
            raise AssertionError("unexpected inference scope")
        return AccessToken("offline-test-only-token", int(time.time()) + 3600)

    def get_token_info(self, *scopes, **kwargs):
        token = get_token(self, *scopes, **kwargs)
        return AccessTokenInfo(token.token, token.expires_on)

    azure.identity.ManagedIdentityCredential.get_token = get_token
    azure.identity.ManagedIdentityCredential.get_token_info = get_token_info
    original_send = httpx.Client.send
    original_async_send = httpx.AsyncClient.send

    def response(request):
        if request.url.host != "example.services.ai.azure.com":
            reject_external(request.url)
            return None
        body = json.loads(request.content)
        tools = body.get("tools")
        tool_results = [str(message.get("content", "")) for message in body.get("messages", [])
                        if message.get("role") == "tool"]
        hidden_tool = os.environ.get("HERMES_RUNTIME_HIDDEN_TOOL_TEST") == "1" and bool(tools) and not tool_results
        scenario = os.environ.get("HERMES_RUNTIME_TUI_SCENARIO")
        clarify = scenario in {"clarify-single", "clarify-batch"} and bool(tools) and not tool_results
        last_user = next((item.get("content") for item in reversed(body.get("messages", []))
                          if item.get("role") == "user"), "")
        long_stream = scenario == "interrupt" and bool(tools) and last_user == "Offline long streaming prompt"
        message = {"role": "assistant", "content": "Offline P4 response"}
        finish_reason = "stop"
        if hidden_tool:
            message = {"role": "assistant", "content": None, "tool_calls": [{
                "id": "offline-hidden-call", "type": "function", "function": {
                    "name": "terminal",
                    "arguments": json.dumps({
                        "command": "printf forbidden > /mnt/data/forbidden-tool-executed",
                    }),
                },
            }]}
            finish_reason = "tool_calls"
        elif clarify:
            arguments = {"question": "Pick a color", "choices": ["Blue", "Red"]}
            if scenario == "clarify-batch":
                arguments = {"questions": [
                    arguments, {"question": "Pick a shape", "choices": ["Round", "Square"]},
                ]}
            message = {"role": "assistant", "content": None, "tool_calls": [{
                "id": "offline-clarify-call", "type": "function",
                "function": {"name": "clarify", "arguments": json.dumps(arguments)},
            }]}
            finish_reason = "tool_calls"
        capture = os.environ.get("HERMES_RUNTIME_WIRE_CAPTURE")
        if capture:
            append_record(capture, {
                "model": body.get("model"), "api_path": request.url.path,
                "surface": os.environ.get("HERMES_RUNTIME_TEST_SURFACE", "unknown"),
                "tools": None if tools is None else [tool.get("function", tool).get("name") for tool in tools],
                "hidden_tool_emitted": hidden_tool,
                "clarify_emitted": clarify, "user_prompt": last_user,
                "tool_results": tool_results,
                "test_bearer": request.headers.get("authorization") == "Bearer offline-test-only-token",
            })
        if body.get("stream"):
            if long_stream:
                class SlowStream(httpx.SyncByteStream):
                    closed = False

                    def __iter__(self):
                        for _ in range(2000):
                            if self.closed:
                                return
                            chunk = {
                                "id": "chatcmpl-offline", "object": "chat.completion.chunk", "created": 1,
                                "model": body["model"], "choices": [{"index": 0, "delta": {
                                    "role": "assistant", "content": "Offline stream running ",
                                }, "finish_reason": None}],
                            }
                            yield ("data: " + json.dumps(chunk) + "\n\n").encode()
                            time.sleep(0.05)

                    def close(self):
                        if not self.closed and capture:
                            append_record(capture + ".stream", {"event": "closed", "time": time.monotonic()})
                        self.closed = True

                return httpx.Response(200, request=request, stream=SlowStream(),
                                      headers={"content-type": "text/event-stream"})
            delta = dict(message)
            if hidden_tool or clarify:
                delta["tool_calls"] = [{"index": 0, **message["tool_calls"][0]}]
            records = [
                {"id": "chatcmpl-offline", "object": "chat.completion.chunk", "created": 1,
                 "model": body["model"], "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                {"id": "chatcmpl-offline", "object": "chat.completion.chunk", "created": 1,
                 "model": body["model"], "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
                 "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}},
            ]
            content = "".join("data: " + json.dumps(record) + "\n\n" for record in records) + "data: [DONE]\n\n"
            return httpx.Response(200, request=request, content=content,
                                  headers={"content-type": "text/event-stream"})
        return httpx.Response(200, request=request, json={
            "id": "chatcmpl-offline", "object": "chat.completion", "created": 1, "model": body["model"],
            "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
        })

    def send(self, request, *args, **kwargs):
        result = response(request)
        return original_send(self, request, *args, **kwargs) if result is None else result

    async def async_send(self, request, *args, **kwargs):
        result = response(request)
        return await original_async_send(self, request, *args, **kwargs) if result is None else result

    httpx.Client.send = send
    httpx.AsyncClient.send = async_send

    if os.environ.get("HERMES_RUNTIME_FAKE_BRIDGE") == "1":
        import subprocess
        original_popen = subprocess.Popen
        capture_bridge = os.environ["HERMES_RUNTIME_BRIDGE_CAPTURE"]

        class BridgeProcess(original_popen):
            def __init__(self, args, *positional, **kwargs):
                if list(args[:2]) == ["/usr/local/bin/node", "/opt/hermes/scripts/whatsapp-bridge/bridge.js"]:
                    if args[2:] != ["--port", "3000", "--session", "/mnt/data/hermes/platforms/whatsapp/session",
                                    "--mode", "self-chat"]:
                        raise AssertionError("unexpected native bridge invocation")
                    kwargs["env"] = {
                        **kwargs["env"], "HERMES_RUNTIME_IMAGE_TESTS": "1",
                        "HERMES_RUNTIME_BRIDGE_CAPTURE": capture_bridge,
                        "HERMES_RUNTIME_WHATSAPP_PROMPT": os.environ.get(
                            "HERMES_RUNTIME_WHATSAPP_PROMPT", "Offline actual WhatsApp adapter P4 prompt",
                        ),
                        "PYTHONPATH": "/runtime-tests",
                    }
                    args = [sys.executable, "/runtime-tests/test_hermes_runtime_whatsapp_bridge.py"]
                super().__init__(args, *positional, **kwargs)

        subprocess.Popen = BridgeProcess

    if os.environ.get("HERMES_RUNTIME_GOOGLE_FIXTURE") == "1":
        sys.path.insert(0, "/opt/hermes-sandbox/google")
        from test_hermes_google_core import FakeTransport
        import google_readonly
        from tools import mcp_tool_config, mcp_tool_discovery

        original_discover = mcp_tool_discovery.discover_mcp_tools
        def discover(*args, **kwargs):
            capture = os.environ.get("HERMES_RUNTIME_WIRE_CAPTURE")
            if capture:
                append_record(capture + ".discovery", {
                    "event": "discover", "configured": sorted(mcp_tool_config._load_mcp_config()),
                })
            try:
                result = original_discover(*args, **kwargs)
            except Exception as exc:
                if capture:
                    import traceback
                    append_record(capture + ".discovery", {
                        "event": "error", "type": type(exc).__name__,
                        "frames": [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                                   for frame in traceback.extract_tb(exc.__traceback__)],
                    })
                raise
            if capture:
                append_record(capture + ".discovery", {"event": "registered", "names": result})
            return result
        mcp_tool_discovery.discover_mcp_tools = discover

        class OfflineGoogleHTTP(FakeTransport):
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def request(self, operation, **kwargs):
                capture = os.environ.get("HERMES_RUNTIME_WIRE_CAPTURE")
                if capture:
                    append_record(capture + ".google-operations", {"operation": operation})
                return await super().request(operation, **kwargs)

        google_readonly.GoogleHTTP = OfflineGoogleHTTP
        original_safe_env = mcp_tool_config._build_safe_env

        def fixture_safe_env(user_env):
            environment = original_safe_env(user_env)
            for key in ("PYTHONPATH", "HERMES_RUNTIME_IMAGE_TESTS", "HERMES_RUNTIME_GOOGLE_FIXTURE",
                        "HERMES_RUNTIME_WIRE_CAPTURE"):
                if key in os.environ:
                    environment[key] = os.environ[key]
            return environment

        mcp_tool_config._build_safe_env = fixture_safe_env

    capture_rpc = os.environ.get("HERMES_RUNTIME_CAPTURE_RPC")
    # Importing the RPC server replaces stdout; a slash worker owns a different stdio protocol.
    if capture_rpc and "--session-key" not in sys.argv:
        import logging
        logging.basicConfig(filename=capture_rpc + ".errors", level=logging.WARNING, force=True)
        from tui_gateway import server
        from tui_gateway.ws import WSTransport
        original_dispatch = server.dispatch
        methods = {}
        def record_response(frame):
            method = methods.get(frame.get("id"))
            if ("error" in frame or frame.get("method") or method in {
                "session.create", "prompt.submit", "setup.status", "command.dispatch", "command.resolve", "slash.exec",
                "clarify.lock", "session.interrupt", "session.close",
                "complete.path", "complete.slash", "terminal.resize",
            }):
                append_record(capture_rpc + ".responses", {"request_method": method, **frame})

        def recorded_write(original_write):
            def write(self, frame):
                record_response(frame)
                return original_write(self, frame)
            return write

        for transport_type in (type(server._stdio_transport), WSTransport):
            transport_type.write = recorded_write(transport_type.write)
        original_write_async = WSTransport.write_async

        async def write_async(self, frame):
            record_response(frame)
            return await original_write_async(self, frame)

        WSTransport.write_async = write_async
        def dispatch(frame, *args, **kwargs):
            methods[frame.get("id")] = frame.get("method")
            append_record(capture_rpc, frame)
            return original_dispatch(frame, *args, **kwargs)
        server.dispatch = dispatch
