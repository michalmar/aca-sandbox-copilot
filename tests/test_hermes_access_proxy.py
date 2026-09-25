"""Real aiohttp hops with explicit test-only credential and transport injection."""

import asyncio
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import aiohttp
from aiohttp import WSMsgType, web
from aiohttp.test_utils import TestServer
from multidict import CIMultiDict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "hermes/image"))
sys.path.insert(0, str(ROOT / "scripts"))
import access_proxy as proxy

TARGET = "https://hermes-test--8080.swedencentral.adcproxy.io"
FAKE_BEARER = "explicit-test-only-azure-bearer"
FAKE_SESSION = "explicit-test-only-dashboard-session"


class MappedClient:
    """Only the test transport remaps a validated production URL to a fixture."""

    def __init__(self, client, source, destination):
        self.client, self.source, self.destination = client, source, destination

    def _url(self, value):
        if not value.startswith(self.source + "/"):
            raise AssertionError("Unexpected test upstream")
        return self.destination + value[len(self.source):]

    def request(self, method, url, **kwargs):
        return self.client.request(method, self._url(url), **kwargs)

    def ws_connect(self, url, **kwargs):
        return self.client.ws_connect(self._url(url), **kwargs)


class RoutePolicyTests(unittest.TestCase):
    def source_root(self):
        source = Path(os.environ.get("HERMES_UPSTREAM_SOURCE", "/opt/hermes"))
        if not source.is_dir():
            if "HERMES_UPSTREAM_SOURCE" in os.environ or any(
                os.environ.get(name) == "1" for name in (
                    "HERMES_RUNTIME_IMAGE_TESTS", "HERMES_ENTRYPOINT_IMAGE_TEST", "HERMES_UPLOAD_IMAGE_TEST",
                    "HERMES_BROWSER_IMAGE_TEST", "HERMES_BROWSER_REAL_IMAGE_TEST",
                    "HERMES_NATIVE_ACCESS_IMAGE_TEST",
                )
            ):
                self.fail("Explicit source/image verification requires the pinned Hermes checkout.")
            self.skipTest("Image/source tier requires the exact pinned Hermes checkout.")
        return source

    def test_pinned_source_has_exact_classified_inventory(self):
        source = self.source_root()
        proxy.validate_route_inventory(source)
        self.assertEqual(len(proxy.ROUTE_INVENTORY), 353)
        self.assertEqual(len(proxy.REGISTERED_ROUTE_INVENTORY), 300)
        self.assertIn(("GET", "/api/plugins/kanban/board"), proxy.ROUTE_INVENTORY)
        self.assertIn(("HEAD", "/openapi.json"), proxy.ROUTE_INVENTORY)
        self.assertIn(("MOUNT", "/assets"), proxy.ROUTE_INVENTORY)

    def test_any_new_get_or_rpc_route_needs_review(self):
        for route in (("GET", "/api/new-side-effect"), ("WEBSOCKET", "/api/hidden-admin")):
            with self.subTest(route=route), patch.object(
                proxy, "collect_route_inventory", return_value=proxy.ROUTE_INVENTORY | {route}
            ), self.assertRaises(RuntimeError):
                proxy.validate_route_inventory()

    def test_source_scanner_rejects_imperative_and_automatic_new_routes(self):
        source = self.source_root()
        original_read = Path.read_text
        additions = [
            'app.add_api_route("/api/unreviewed", lambda: None, methods=["GET"])\n',
            'app.router.add_route("/api/unreviewed", lambda: None, methods=["GET"])\n',
            'app.get("/api/unreviewed")(lambda: None)\n',
            'FastAPI(docs_url="/api/unreviewed-docs")\n',
        ]
        for addition in additions:
            def injected_read(path, *args, **kwargs):
                text = original_read(path, *args, **kwargs)
                return text + "\n" + addition if path == source / "hermes_cli/web_server.py" else text

            with self.subTest(addition=addition), patch.object(Path, "read_text", new=injected_read):
                with self.assertRaisesRegex(RuntimeError, "Unclassified"):
                    proxy.validate_route_inventory(source)

    def test_new_plugin_get_is_classified_even_though_plugins_are_disabled(self):
        source = self.source_root()
        original_read = Path.read_text

        def injected_read(path, *args, **kwargs):
            text = original_read(path, *args, **kwargs)
            if path == source / "plugins/kanban/dashboard/plugin_api.py":
                text += '\n@router.get("/unreviewed-get")\ndef unreviewed(): return None\n'
            return text

        with patch.object(Path, "read_text", new=injected_read), self.assertRaisesRegex(RuntimeError, "inventory changed"):
            proxy.validate_route_inventory(source)

    def test_registered_route_gate_rejects_new_routes_plugins_duplicates_and_mounts(self):
        routes = []
        for method, path in proxy.REGISTERED_ROUTE_INVENTORY:
            if method == "WEBSOCKET":
                route = type("APIWebSocketRoute", (), {})()
                route.path = path
            elif method == "MOUNT":
                route = type("Mount", (), {})()
                route.path = path
                route.app = type("_ImmutableAssetFiles", (), {})()
            else:
                route = SimpleNamespace(path=path, methods={method})
            routes.append(route)
        proxy.validate_registered_routes(SimpleNamespace(routes=routes))
        for added in (
            SimpleNamespace(path="/api/unreviewed-get", methods={"GET"}),
            SimpleNamespace(path="/api/plugins/kanban/board", methods={"GET"}),
            routes[0],
            SimpleNamespace(path="/unexpected-mount"),
        ):
            with self.subTest(added=type(added).__name__), self.assertRaises(RuntimeError):
                proxy.validate_registered_routes(SimpleNamespace(routes=[*routes, added]))

    def test_only_real_sidebar_rpc_shape_allowed(self):
        good = {"jsonrpc": "2.0", "id": 1, "method": "session.create",
                "params": {"close_on_disconnect": True, "source": "tool", "profile": "default"}}
        self.assertTrue(proxy.rpc_allowed(good))
        self.assertTrue(proxy.rpc_allowed({"jsonrpc": "2.0", "method": "gateway.ping"}))
        for name, value in (("model", "external"), ("tools", ["terminal"]), ("cwd", "/"), ("profile", "other")):
            changed = {**good, "params": {**good["params"], name: value}}
            with self.subTest(name=name):
                self.assertFalse(proxy.rpc_allowed(changed))
        for method in ("config.set", "file.read", "model.set", "tools.set", "gateway.start", "shell.exec", "prompt.submit"):
            with self.subTest(method=method):
                self.assertFalse(proxy.rpc_allowed({**good, "method": method}))

    def test_envelopes_batches_and_duplicate_fields_fail_closed(self):
        for frame in ([], None, {"jsonrpc": "1.0", "method": "gateway.ping"},
                      {"jsonrpc": "2.0", "method": ["gateway.ping"]},
                      {"jsonrpc": "2.0", "method": "gateway.ping", "params": []},
                      {"jsonrpc": "2.0", "method": "gateway.ping", "extra": True}):
            self.assertFalse(proxy.rpc_allowed(frame))
        with self.assertRaises(ValueError):
            proxy._safe_json('{"method":"gateway.ping","method":"config.set"}')

    def test_captured_native_tui_boot_frames_have_a_distinct_policy(self):
        frames = [
            ("pet.info.meta", {}), ("client.capabilities", {"server_requests": True}),
            ("config.get", {"key": "full"}), ("config.get", {"key": "mtime"}),
            ("commands.catalog", {}), ("setup.status", {}), ("session.create", {"cols": 120}),
            ("session.control.read", {"session_id": "d5a4f029"}),
            ("subagent.list", {"session_id": "d5a4f029"}),
            ("process.list", {"session_id": "d5a4f029"}),
            ("session.active_list", {"current_session_id": "d5a4f029"}),
            ("slash.exec", {"command": "context", "session_id": "501d9e85"}),
        ]
        for method, params in frames:
            frame = {"jsonrpc": "2.0", "id": "r1", "method": method, "params": params}
            with self.subTest(method=method, params=params):
                self.assertTrue(proxy.rpc_allowed(frame, surface="tui"))
                self.assertFalse(proxy.rpc_allowed(frame))
                self.assertFalse(proxy.rpc_allowed(frame, surface="unknown"))

    def test_native_tui_handshake_rejects_overrides_and_unknown_methods(self):
        denied = [
            ("wake.start", {"surface": "tui"}), ("config.set", {"key": "full"}),
            ("config.get", {"key": "env"}), ("config.get", {"key": ["full"]}),
            ("session.create", {"cols": 120, "model": "external"}),
            ("session.create", {"cols": 120, "profile": "other"}),
            ("session.create", {"cols": True}), ("session.create", {"cols": 0}),
            ("session.create", {"cols": 1001}), ("session.create", {}),
            ("session.control.read", {"session_id": "../../secret"}),
            ("process.list", {"session_id": "valid", "cwd": "/"}),
            ("client.capabilities", {"server_requests": True, "shell": True}),
            ("setup.status", {"force": True}), ("unknown.future.method", {}),
            ("slash.exec", {"command": "context"}),
            ("slash.exec", {"command": "context", "session_id": "../private"}),
            ("slash.exec", {"command": "context", "session_id": "501d9e85", "profile": "default"}),
            ("slash.exec", {"command": "context", "session_id": "501d9e85", "args": []}),
        ]
        denied.extend(
            ("slash.exec", {"command": command, "session_id": "501d9e85"})
            for command in ("context ", "/context", "context extra", "Context", "help", "model", "tools", "shell", "")
        )
        for method, params in denied:
            with self.subTest(method=method, params=params):
                self.assertFalse(proxy.rpc_allowed(
                    {"jsonrpc": "2.0", "id": "r1", "method": method, "params": params}, surface="tui",
                ))

    def test_native_prompt_is_bounded_text_without_attachment_or_model_overrides(self):
        frame = {
            "jsonrpc": "2.0", "id": "r20", "method": "prompt.submit",
            "params": {"session_id": "85ad509c", "text": "Offline native TUI P4 prompt"},
        }
        self.assertTrue(proxy.rpc_allowed(frame, surface="tui"))
        self.assertFalse(proxy.rpc_allowed(frame))
        for key, value in (
            ("attachments", ["/mnt/data/secrets/google/credentials.json"]),
            ("model", "external"), ("tools", ["terminal"]), ("cwd", "/"), ("profile", "other"),
        ):
            self.assertFalse(proxy.rpc_allowed(
                {**frame, "params": {**frame["params"], key: value}}, surface="tui",
            ))
        for text in ("", " ", "\x00", "\ud800", "x" * (proxy.MAX_FRAME + 1), "\u2603" * (proxy.MAX_FRAME // 3 + 1)):
            self.assertFalse(proxy.rpc_allowed(
                {**frame, "params": {**frame["params"], "text": text}}, surface="tui",
            ))
        self.assertTrue(proxy.rpc_allowed(
            {**frame, "params": {**frame["params"], "text": "x" * proxy.MAX_FRAME}}, surface="tui",
        ))
        self.assertFalse(proxy.rpc_allowed({**frame, "method": "input.detect_drop"}, surface="tui"))

    def test_native_clarify_lock_and_interrupt_have_exact_non_sidebar_shapes(self):
        lock = {
            "jsonrpc": "2.0", "id": "r42", "method": "clarify.lock",
            "params": {"request_id": "srq-012345abcdef", "question_id": "q1", "answer": ""},
        }
        interrupt = {
            "jsonrpc": "2.0", "id": "r43", "method": "session.interrupt", "params": {"session_id": "501d9e85"},
        }
        close = {**interrupt, "method": "session.close"}
        for frame in (lock, interrupt, close):
            self.assertTrue(proxy.rpc_allowed(frame, surface="tui"))
            self.assertFalse(proxy.rpc_allowed(frame))
        invalid_locks = [
            {key: value for key, value in lock["params"].items() if key != missing}
            for missing in lock["params"]
        ]
        invalid_locks.extend([
            {**lock["params"], "request_id": "srq-too-short"},
            {**lock["params"], "request_id": "srq-012345ABCDEF"},
            {**lock["params"], "question_id": "../foreign"},
            {**lock["params"], "answer": "\x00"},
            {**lock["params"], "answer": "\ud800"},
            {**lock["params"], "answer": "x" * (proxy.MAX_FRAME + 1)},
            {**lock["params"], "profile": "default"},
            {**lock["params"], "session_id": "foreign-session"},
        ])
        for params in invalid_locks:
            self.assertFalse(proxy.rpc_allowed({**lock, "params": params}, surface="tui"))
        for params in ({}, {"session_id": True}, {"session_id": "../foreign"},
                       {"session_id": "501d9e85", "expected_hosted_task_id": "other-task"}):
            for frame in (interrupt, close):
                self.assertFalse(proxy.rpc_allowed({**frame, "params": params}, surface="tui"))

    def test_explicit_missing_inventory_source_is_a_failure_not_a_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"HERMES_UPSTREAM_SOURCE": str(Path(directory) / "absent")}):
                with self.assertRaisesRegex(AssertionError, "requires the pinned"):
                    self.source_root()

    def test_native_empty_completions_and_owned_resize_have_exact_bounded_shapes(self):
        frames = [
            ("complete.slash", {"text": ""}),
            ("complete.slash", {"text": "/context", "session_id": "501d9e85"}),
            ("complete.slash", {"text": "x" * 257}),
            ("complete.path", {"word": "/mnt/data/secrets/google/credentials.json"}),
            ("complete.path", {"word": "é" * 129}),
        ]
        frames.extend(
            ("terminal.resize", {"session_id": "501d9e85", "cols": cols})
            for cols in (1, 19, 20, 500, 501, 1000)
        )
        for method, params in frames:
            frame = {"jsonrpc": "2.0", "id": "r44", "method": method, "params": params}
            self.assertTrue(proxy.rpc_allowed(frame, surface="tui"))
            self.assertFalse(proxy.rpc_allowed(frame))
        invalid = [
            ("complete.slash", {}),
            ("complete.slash", {"text": "/context", "session_id": "../foreign"}),
            ("complete.slash", {"text": "/context", "profile": "default"}),
            ("complete.slash", {"text": "x" * (proxy.MAX_FRAME + 1)}),
            ("complete.slash", {"text": "\x00"}),
            ("complete.slash", {"text": "\ud800"}),
            ("complete.path", {"word": "é" * (proxy.MAX_FRAME // 2 + 1)}),
            ("complete.path", {"word": "", "cwd": "/mnt/data"}),
            ("complete.path", {"word": "", "session_id": "501d9e85"}),
            ("complete.path", {"word": True}),
        ]
        invalid.extend(
            ("terminal.resize", {"session_id": "501d9e85", "cols": value})
            for value in (True, False, 0, 1001, 80.0, "80", None)
        )
        invalid.extend([
            ("terminal.resize", {"session_id": "../foreign", "cols": 80}),
            ("terminal.resize", {"session_id": "501d9e85", "cols": 80, "rows": 24}),
            ("terminal.resize", {"cols": 80}),
        ])
        for method, params in invalid:
            frame = {"jsonrpc": "2.0", "id": "r44", "method": method, "params": params}
            self.assertFalse(proxy.rpc_allowed(frame, surface="tui"))

    def test_native_completion_limit_counts_the_entire_escaped_request(self):
        def wire_size(value):
            return len(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii"))

        for method, key in (("complete.slash", "text"), ("complete.path", "word")):
            for identifier in ("r44", "x" * 128, "é" * 128):
                for character in ("x", '"', "\\", "\n", "\u2603", "\U0001f680"):
                    with self.subTest(method=method, identifier=identifier, character=character):
                        params = {key: ""}
                        if method == "complete.slash":
                            params["session_id"] = "501d9e85"
                        frame = {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params}
                        budget = proxy.MAX_FRAME - wire_size(frame)
                        char_size = wire_size(character) - 2
                        params[key] = character * (budget // char_size) + "x" * (budget % char_size)
                        self.assertEqual(wire_size(frame), proxy.MAX_FRAME)
                        self.assertTrue(proxy.rpc_allowed(frame, surface="tui"))
                        self.assertFalse(proxy.rpc_allowed(frame))
                        params[key] += "x"
                        self.assertLessEqual(len(params[key].encode("utf-8")), proxy.MAX_FRAME)
                        self.assertEqual(wire_size(frame), proxy.MAX_FRAME + 1)
                        self.assertFalse(proxy.rpc_allowed(frame, surface="tui"))

    def test_native_clarify_responses_use_a_separate_bounded_predicate(self):
        envelope = {"jsonrpc": "2.0", "id": "srq-012345abcdef"}
        frames = [
            {**envelope, "result": {"answer": ""}},
            {**envelope, "result": {"answer": "A multiline\nanswer"}},
            {**envelope, "result": {"answers": {"q1": "First", "q2": ""}}},
            {**envelope, "error": {"code": -32601, "message": "Cancelled"}},
        ]
        for frame in frames:
            self.assertTrue(proxy.rpc_response_allowed(frame, surface="tui"))
            self.assertFalse(proxy.rpc_response_allowed(frame))
            self.assertFalse(proxy.rpc_allowed(frame, surface="tui"))
        invalid = [
            {**envelope, "result": {}},
            {**envelope, "result": {"approved": True}},
            {**envelope, "result": {"answer": "yes", "approval": True}},
            {**envelope, "result": {"answers": {}}},
            {**envelope, "result": {"answers": {f"q{i}": "text" for i in range(6)}}},
            {**envelope, "result": {"answers": {"../foreign": "text"}}},
            {**envelope, "result": {"answer": "\x00"}},
            {**envelope, "result": {"answer": "\ud800"}},
            {**envelope, "result": {"answer": "x" * proxy.MAX_FRAME}},
            {**envelope, "result": {"answers": {f"q{i}": "x" * (proxy.MAX_FRAME // 3) for i in range(4)}}},
            {**envelope, "result": {"answer": "ok"}, "error": {"code": -1, "message": ""}},
            {**envelope, "result": {"answer": "ok"}, "method": "shell.exec"},
            {**envelope, "result": {"answer": "ok"}, "profile": "default"},
            {**envelope, "error": {"code": True, "message": "cancel"}},
            {**envelope, "error": {"code": -1, "message": "cancel", "data": {"approved": True}}},
            {**envelope, "id": "r1", "result": {"answer": "ok"}},
            {**envelope, "id": "srq-012345abcdef/foreign", "result": {"answer": "ok"}},
            {"id": "srq-012345abcdef", "result": {"answer": "ok"}},
            {**envelope, "jsonrpc": "1.0", "result": {"answer": "ok"}},
        ]
        for frame in invalid:
            self.assertFalse(proxy.rpc_response_allowed(frame, surface="tui"))
        self.assertFalse(proxy.rpc_response_allowed(frames, surface="tui"))

    def test_exact_origin_and_fixed_upstream_validation(self):
        self.assertTrue(proxy.valid_local_origin("http://127.0.0.1:8765"))
        for origin in ("http://localhost:8765", "http://127.0.0.1", "null", "http://127.0.0.1:8765/",
                       "http://127.0.0.1:0", "http://127.0.0.1:65536", "https://attacker.invalid"):
            self.assertFalse(proxy.valid_local_origin(origin))
        for target in (TARGET + "/", TARGET + "?token=x", TARGET.replace("https:", "http:"),
                       "https://user@hermes-test--8080.swedencentral.adcproxy.io",
                       TARGET.replace("8080", "8642"), "https://attacker.invalid"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                proxy.validate_target(target)

    def test_forwarded_and_hop_headers_never_reach_dashboard(self):
        headers = CIMultiDict({
            "Authorization": "secret", "X-Hermes-Access-Key": "key", "Forwarded": "evil",
            "X-Forwarded-Host": "evil", "X-Forwarded-Proto": "evil", "Connection": "x-remove",
            "X-Remove": "nominated", "Host": "evil", "Origin": "http://127.0.0.1:8765",
            "X-Hermes-Session-Token": FAKE_SESSION,
        })
        cleaned = proxy.clean_headers(headers)
        self.assertEqual(dict(cleaned), {"Origin": "http://127.0.0.1:8765", "X-Hermes-Session-Token": FAKE_SESSION})

    def test_no_tmpfs_has_no_persistent_fallback(self):
        with patch.object(Path, "read_text", return_value="1 2 0:1 / /dev/shm rw - ext4 /dev/disk rw\n"):
            with self.assertRaisesRegex(RuntimeError, "no disk fallback"):
                proxy.create_access_key()


class ProxyHopTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers = []
        self.clients = []
        self.observed = []
        self.rpc_observed = []
        self.ws_payload_sizes = []
        self.release_stream = asyncio.Event()
        self.current_key = "a" * 64
        self.bearer = FAKE_BEARER
        self.key_reads = 0
        self.ingress_requests = 0
        self.expired_forever = False
        self.redirect_ws = False
        self.redirect_hits = 0
        self.event_socket = None

        async def dashboard(request):
            self.observed.append((request.method, request.path, dict(request.headers)))
            if request.headers.get("Upgrade", "").lower() == "websocket":
                if self.redirect_ws:
                    return web.Response(status=302, headers={"Location": "/redirect-trap"})
                socket = web.WebSocketResponse(max_msg_size=proxy.MAX_FRAME + 1)
                await socket.prepare(request)
                if request.path == "/api/ws":
                    await socket.send_json({"jsonrpc": "2.0", "method": "gateway.ready", "params": {}})
                elif request.path == "/api/events":
                    self.event_socket = socket
                    await socket.send_json({"jsonrpc": "2.0", "method": "event", "params": {"type": "gateway.ready"}})
                async for message in socket:
                    if message.type == WSMsgType.TEXT:
                        self.ws_payload_sizes.append(len(message.data.encode()))
                        if request.path == "/api/ws":
                            self.rpc_observed.append(message.data)
                            request_frame = json.loads(message.data)
                            await socket.send_json({"jsonrpc": "2.0", "id": request_frame.get("id"), "result": {"ok": True}})
                        else:
                            await socket.send_str(message.data)
                    elif message.type == WSMsgType.BINARY:
                        self.ws_payload_sizes.append(len(message.data))
                        await socket.send_bytes(message.data)
                return socket
            if request.path == "/redirect-trap":
                self.redirect_hits += 1
                return web.Response(text="unexpected")
            if request.path == "/api/status" and request.query.get("q") == "stream":
                response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
                await response.prepare(request)
                await response.write(b"data: first\n\n")
                await self.release_stream.wait()
                await response.write(b"data: second\n\n")
                return response
            if request.path == "/api/status" and request.query.get("q") == "broken-stream":
                response = web.StreamResponse(headers={"Content-Length": "4096"})
                await response.prepare(request)
                await response.write(b"first chunk\n")
                await self.release_stream.wait()
                request.transport.abort()
                return response
            if request.path == "/api/status" and request.query.get("q") == "redirect":
                return web.Response(status=302, headers={"Location": "https://attacker.invalid/collect"})
            if request.method == "PATCH":
                return web.json_response({"updated": await request.json()})
            if request.path == "/":
                return web.Response(text=f'<html><script>window.__HERMES_SESSION_TOKEN__="{FAKE_SESSION}"</script></html>',
                                    content_type="text/html")
            return web.json_response({"ok": True})

        app = web.Application()
        app.router.add_route("*", "/{path:.*}", dashboard)
        dashboard_url = await self.server(app)
        inner_client = await self.client(auto_decompress=False, trace_configs=[proxy.no_redirect_trace()])
        self.inner = proxy.Proxy(
            access_key=self.current_key, client=MappedClient(inner_client, proxy.DASHBOARD_URL, dashboard_url),
        )
        inner_url = await self.server(self.inner.app)
        ingress_client = await self.client(auto_decompress=False, trace_configs=[proxy.no_redirect_trace()])

        def wire_headers(headers):
            return {name: value for name, value in headers.items()
                    if name.lower() not in {"connection", "upgrade", "transfer-encoding"}
                    and not name.lower().startswith("sec-websocket-")}

        async def ingress(request):
            self.ingress_requests += 1
            if request.headers.get("Authorization") != "Bearer " + FAKE_BEARER:
                return web.Response(status=401, text="fake Entra ingress rejected")
            if self.expired_forever:
                return web.Response(status=401, headers={proxy.EXPIRED_HEADER: "1"})
            headers = wire_headers(request.headers)
            if request.headers.get("Upgrade", "").lower() == "websocket":
                try:
                    upstream = await ingress_client.ws_connect(
                        inner_url + request.raw_path, headers=headers, max_msg_size=proxy.MAX_FRAME + 1,
                    )
                except aiohttp.WSServerHandshakeError as error:
                    return web.Response(status=error.status, headers=wire_headers(error.headers), body=b"")
                downstream = web.WebSocketResponse(max_msg_size=proxy.MAX_FRAME + 1)
                await downstream.prepare(request)

                async def pump(source, destination):
                    async for message in source:
                        if message.type == WSMsgType.TEXT:
                            await destination.send_str(message.data)
                        elif message.type == WSMsgType.BINARY:
                            await destination.send_bytes(message.data)
                    code = source.close_code or 1000
                    await destination.close(code=code if code not in {1005, 1006, 1015} else 1011)

                tasks = [asyncio.create_task(pump(downstream, upstream)), asyncio.create_task(pump(upstream, downstream))]
                try:
                    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    await upstream.close()
                    await downstream.close()
                return downstream
            async with ingress_client.request(
                request.method, inner_url + request.raw_path, headers=headers,
                data=request.content.iter_chunked(proxy.CHUNK) if request.can_read_body else None,
                allow_redirects=False,
            ) as upstream:
                response = web.StreamResponse(status=upstream.status, headers=wire_headers(upstream.headers))
                await response.prepare(request)
                try:
                    async for chunk in upstream.content.iter_chunked(proxy.CHUNK):
                        await response.write(chunk)
                except (aiohttp.ClientError, ConnectionError):
                    response.force_close()
                    if request.transport is not None:
                        request.transport.abort()
                return response

        app = web.Application()
        app.router.add_route("*", "/{path:.*}", ingress)
        ingress_url = await self.server(app)

        async def token_provider():
            return self.bearer

        async def key_provider():
            self.key_reads += 1
            return self.current_key

        local_client = await self.client(auto_decompress=False, trace_configs=[proxy.no_redirect_trace()])
        self.local = proxy.Proxy(
            local_origin="http://127.0.0.1:18765", target=TARGET,
            token_provider=token_provider, key_provider=key_provider,
            client=MappedClient(local_client, TARGET, ingress_url),
        )
        self.local_url = await self.server(self.local.app)
        self.local.local_origin = self.local_url
        self.browser = await self.client(cookie_jar=aiohttp.CookieJar(unsafe=True))
        self.headers = {"Origin": self.local_url, "X-Hermes-Session-Token": FAKE_SESSION}
        async with self.browser.get(self.local_url + "/") as response:
            self.assertEqual(response.status, 200)
            await response.read()

    async def server(self, app):
        server = TestServer(app, host="127.0.0.1")
        await server.start_server()
        self.servers.append(server)
        return str(server.make_url("")).rstrip("/")

    async def client(self, **kwargs):
        client = aiohttp.ClientSession(**kwargs)
        self.clients.append(client)
        return client

    async def asyncTearDown(self):
        self.release_stream.set()
        for client in reversed(self.clients):
            await client.close()
        for server in reversed(self.servers):
            await server.close()

    async def test_real_http_hops_preserve_dashboard_session_not_transport_secrets(self):
        async with self.browser.get(self.local_url + "/api/status", headers={
            **self.headers, "Forwarded": "evil", "X-Forwarded-Host": "evil",
        }) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(await response.json(), {"ok": True})
            self.assertNotIn(proxy.KEY_HEADER, response.headers)
            self.assertNotIn("Authorization", response.headers)
            self.assertIn("HttpOnly", response.headers["Set-Cookie"])
            self.assertIn("SameSite=Strict", response.headers["Set-Cookie"])
        headers = self.observed[-1][2]
        self.assertEqual(headers["Host"], "127.0.0.1:9119")
        self.assertEqual(headers["Origin"], self.local_url)
        self.assertEqual(headers["X-Hermes-Session-Token"], FAKE_SESSION)
        for name in ("Authorization", proxy.KEY_HEADER, proxy.RELAY_ORIGIN_HEADER, proxy.RELAY_AUTHORITY_HEADER,
                     "Forwarded", "X-Forwarded-Host", "Cookie"):
            self.assertNotIn(name, headers)

    async def test_host_origin_and_csrf_boundaries(self):
        for headers in ({"Host": "attacker.invalid"}, {"Origin": "null"},
                        {"Origin": "http://127.0.0.1:8766"}, {"Sec-Fetch-Site": "cross-site"}):
            with self.subTest(headers=headers):
                async with self.browser.get(self.local_url + "/api/status", headers=headers) as response:
                    self.assertEqual(response.status, 403)
        stranger = await self.client()
        async with stranger.get(self.local_url + "/api/status") as response:
            self.assertEqual(response.status, 403)
        async with self.browser.patch(self.local_url + "/api/sessions/session-1", json={"title": "Safe"}) as response:
            self.assertEqual(response.status, 403)

    async def test_inner_requires_key_and_exact_authenticated_authority_origin(self):
        inner_url = str(self.servers[1].make_url("")).rstrip("/")
        for headers, expected in (
            ({}, 401),
            ({proxy.KEY_HEADER: self.current_key}, 403),
            ({proxy.KEY_HEADER: self.current_key, proxy.RELAY_ORIGIN_HEADER: self.local_url,
              proxy.RELAY_AUTHORITY_HEADER: TARGET.removeprefix("https://"), "Host": "different.invalid"}, 403),
        ):
            async with self.browser.get(inner_url + "/api/status", headers=headers) as response:
                self.assertEqual(response.status, expected)
                if expected == 401:
                    self.assertEqual(response.headers[proxy.EXPIRED_HEADER], "1")

    async def test_exactly_one_key_refresh_before_forwarding_http_mutation(self):
        self.current_key = "b" * 64
        self.inner.key = self.current_key
        previous = len(self.observed)
        async with self.browser.patch(self.local_url + "/api/sessions/session-1", headers=self.headers,
                                      json={"title": "Safe title"}) as response:
            self.assertEqual(response.status, 200)
        self.assertEqual(self.key_reads, 2)
        self.assertEqual(len(self.observed), previous + 1)

    async def test_generic_ingress_401_never_refreshes_or_retries(self):
        self.bearer = "wrong-bearer"
        previous = self.ingress_requests
        async with self.browser.get(self.local_url + "/api/status", headers=self.headers) as response:
            self.assertEqual(response.status, 401)
        self.assertEqual(self.key_reads, 1)
        self.assertEqual(self.ingress_requests, previous + 1)

    async def test_expired_marker_allows_no_more_than_one_retry(self):
        self.expired_forever = True
        previous = self.ingress_requests
        async with self.browser.get(self.local_url + "/api/status", headers=self.headers) as response:
            self.assertEqual(response.status, 401)
            self.assertNotIn(proxy.EXPIRED_HEADER, response.headers)
        self.assertEqual(self.ingress_requests, previous + 2)
        self.assertEqual(self.key_reads, 2)

    async def test_management_mutations_and_side_effectful_gets_are_explicitly_denied(self):
        previous = len(self.observed)
        cases = (
            ("POST", "/api/gateway/start"), ("POST", "/api/messaging/whatsapp/onboarding/start"),
            ("GET", "/api/dashboard/plugins/rescan"), ("GET", "/api/mcp/oauth/callback/server"),
            ("GET", "/api/hermes/update/check"), ("PUT", "/api/config"), ("POST", "/api/cron/jobs"),
            ("GET", "/api/files/read?path=/mnt/data/secrets/google/credentials.json"),
            ("GET", "/api/env"), ("GET", "/api/unknown-get"),
        )
        for method, path in cases:
            with self.subTest(method=method, path=path):
                async with self.browser.request(method, self.local_url + path, headers=self.headers) as response:
                    self.assertEqual(response.status, 403)
                    self.assertIn("Managed mode", await response.text())
        self.assertEqual(len(self.observed), previous)

    async def test_duplicate_or_privileged_query_parameters_are_denied(self):
        for query in ("?profile=default&profile=evil", "?profile=evil", "?full=true", "?url=https://evil.invalid"):
            async with self.browser.get(self.local_url + "/api/sessions" + query, headers=self.headers) as response:
                self.assertEqual(response.status, 403)

    async def test_sse_streams_first_chunk_without_buffering(self):
        async with self.browser.get(self.local_url + "/api/status?q=stream", headers=self.headers) as response:
            self.assertEqual(await asyncio.wait_for(response.content.readexactly(13), timeout=2), b"data: first\n\n")
            self.release_stream.set()
            self.assertEqual(await response.read(), b"data: second\n\n")

    async def test_http_cross_origin_redirect_is_not_followed_or_exposed(self):
        async with self.browser.get(self.local_url + "/api/status?q=redirect", headers=self.headers) as response:
            self.assertEqual(response.status, 502)
            self.assertNotIn("Location", response.headers)

    async def test_body_limit_and_small_session_edit_schema(self):
        for payload, expected in (({"title": "x" * (16 * 1024)}, 413),
                                  ({"title": "safe", "model": "other"}, 403), ({"pinned": "true"}, 403)):
            async with self.browser.patch(
                self.local_url + "/api/sessions/session-1", headers=self.headers, json=payload,
            ) as response:
                self.assertEqual(response.status, expected)
        async with self.browser.patch(
            self.local_url + "/api/sessions/session-1", headers=self.headers,
            data=io.BytesIO(b"x" * (proxy.MAX_BODY + 1)),
        ) as response:
            self.assertEqual(response.status, 413)

    async def test_websocket_session_binary_text_ping_and_reconnect(self):
        for _ in range(2):
            async with self.browser.ws_connect(
                self.local_url + f"/api/pty?token={FAKE_SESSION}&channel=test-channel&attach=test-attach",
                headers=self.headers, heartbeat=30,
            ) as socket:
                await socket.send_str("chat text")
                self.assertEqual(await socket.receive_str(timeout=3), "chat text")
                await socket.send_bytes(b"\x1b[12;34R")
                self.assertEqual(await socket.receive_bytes(timeout=3), b"\x1b[12;34R")
                await socket.ping()
                await socket.send_str("after ping")
                self.assertEqual(await socket.receive_str(timeout=3), "after ping")

    async def test_websocket_key_rotation_retries_only_handshake(self):
        self.current_key = "c" * 64
        self.inner.key = self.current_key
        async with self.browser.ws_connect(self.local_url + "/api/pty?token=" + FAKE_SESSION, headers=self.headers) as socket:
            await socket.send_str("after rotation")
            self.assertEqual(await socket.receive_str(timeout=3), "after rotation")
        self.assertEqual(self.key_reads, 2)

    async def test_websocket_rpc_denials_preserve_request_ids_and_never_forward(self):
        async with self.browser.ws_connect(self.local_url + "/api/ws?token=" + FAKE_SESSION, headers=self.headers) as socket:
            self.assertEqual((await socket.receive_json())["method"], "gateway.ready")
            for method in ("config.set", "model.set", "file.read", "gateway.start"):
                await socket.send_json({"jsonrpc": "2.0", "id": method, "method": method, "params": {}})
                error = await socket.receive_json(timeout=3)
                self.assertEqual(error["id"], method)
                self.assertIn("Managed mode", error["error"]["message"])
            self.assertEqual(self.rpc_observed, [])
            await socket.send_json({"jsonrpc": "2.0", "id": 5, "method": "session.create",
                                    "params": {"close_on_disconnect": True, "source": "tool"}})
            self.assertEqual((await socket.receive_json(timeout=3))["result"], {"ok": True})
            self.assertEqual(len(self.rpc_observed), 1)

    async def test_events_are_read_only_and_console_is_not_exposed(self):
        with self.assertRaises(aiohttp.WSServerHandshakeError) as captured:
            await self.browser.ws_connect(self.local_url + "/api/console?token=" + FAKE_SESSION, headers=self.headers)
        self.assertEqual(captured.exception.status, 403)
        async with self.browser.ws_connect(
            self.local_url + "/api/events?token=" + FAKE_SESSION + "&channel=test-channel", headers=self.headers,
        ) as socket:
            self.assertEqual((await socket.receive_json(timeout=3))["params"]["type"], "gateway.ready")
            await socket.send_json({"jsonrpc": "2.0", "id": "e1", "method": "client.capabilities",
                                    "params": {"server_requests": True}})
            await socket.send_json({"jsonrpc": "2.0", "id": "e2", "method": "prompt.submit",
                                    "params": {"session_id": "test", "text": "forged"}})
            await socket.send_bytes(b"forged event")
            replies = [await socket.receive_json(timeout=3), await socket.receive_json(timeout=3)]
            self.assertEqual({reply["id"] for reply in replies}, {"e1", "e2"})
            self.assertTrue(all("Managed mode" in reply["error"]["message"] for reply in replies))
            await asyncio.sleep(0.55)
            self.assertFalse(socket.closed)
            self.assertEqual(self.ws_payload_sizes, [])
            later = {"jsonrpc": "2.0", "method": "event", "params": {"type": "session.info"}}
            await self.event_socket.send_json(later)
            self.assertEqual(await socket.receive_json(timeout=3), later)
            try:
                await socket.send_bytes(b"x" * (proxy.MAX_FRAME + 1))
            except ConnectionError:
                pass
            await socket.receive(timeout=3)
            self.assertIn(socket.close_code, {1006, 1009})
            self.assertEqual(self.ws_payload_sizes, [])

    async def test_rpc_is_one_json_object_and_client_responses_are_not_echoed(self):
        async with self.browser.ws_connect(self.local_url + "/api/ws?token=" + FAKE_SESSION, headers=self.headers) as socket:
            await socket.receive_json(timeout=3)
            identifier = "request\u2028identifier"
            await socket.send_str(json.dumps(
                {"jsonrpc": "2.0", "id": identifier, "method": "gateway.ping", "params": {}},
                ensure_ascii=False, indent=2,
            ))
            self.assertEqual((await socket.receive_json(timeout=3))["id"], identifier)
            await socket.send_json({"jsonrpc": "2.0", "id": "server-response", "result": {"ok": True}})
            await socket.send_json({"jsonrpc": "2.0", "id": "next", "method": "gateway.ping", "params": {}})
            self.assertEqual((await socket.receive_json(timeout=3))["id"], "next")
            self.assertEqual(len(self.rpc_observed), 2)
            await socket.send_str('{"jsonrpc":"2.0","method":"gateway.ping"}\n{"jsonrpc":"2.0","method":"gateway.ping"}')
            self.assertEqual((await socket.receive_json(timeout=3))["error"]["code"], -32601)
            self.assertEqual(len(self.rpc_observed), 2)

    async def test_actual_access_credentials_map_azure_errors_without_secrets_or_tracebacks(self):
        from azure.core.exceptions import ClientAuthenticationError, ServiceRequestError
        from access_hermes import AzureRelayCredentials

        for error in (ClientAuthenticationError("PRIVATE-AZURE-DETAIL"), ServiceRequestError("PRIVATE-AZURE-DETAIL")):
            clients = SimpleNamespace(credential=MagicMock())
            sandbox = MagicMock()
            clients.credential.get_token.return_value = SimpleNamespace(token=FAKE_BEARER, expires_on=10 ** 15)
            sandbox.read_file.return_value = self.current_key.encode()
            if isinstance(error, ClientAuthenticationError):
                clients.credential.get_token.side_effect = error
            else:
                sandbox.read_file.side_effect = error
            credentials = AzureRelayCredentials(clients, sandbox)
            self.local.token_provider = credentials.bearer
            self.local.key_provider = credentials.access_key
            self.local.key = None
            with self.subTest(error=type(error).__name__), self.assertLogs("hermes.access", level="INFO") as captured:
                async with self.browser.get(self.local_url + "/api/status", headers=self.headers) as response:
                    self.assertEqual(response.status, 502)
                    self.assertIn("owner login", (await response.json())["error"])
            output = "\n".join(captured.output)
            self.assertIn(type(error).__name__, output)
            self.assertNotIn("PRIVATE-AZURE-DETAIL", output)
            self.assertNotIn("Traceback", output)

    async def test_broken_stream_aborts_without_a_second_http_response(self):
        received = bytearray()
        with self.assertLogs("hermes.access", level="INFO") as captured:
            async with self.browser.get(self.local_url + "/api/status?q=broken-stream", headers=self.headers) as response:
                self.assertEqual(response.status, 200)
                received.extend(await response.content.readexactly(len(b"first chunk\n")))
                self.release_stream.set()
                with self.assertRaises(aiohttp.ClientError):
                    async for chunk in response.content.iter_chunked(32):
                        received.extend(chunk)
            await asyncio.sleep(0.02)
        self.assertEqual(received, b"first chunk\n")
        self.assertNotIn(b"HTTP/1.1", received)
        self.assertNotIn("GET /api/status 502", "\n".join(captured.output))
        self.assertNotIn("Traceback", "\n".join(captured.output))

    async def test_abrupt_websocket_disconnect_never_becomes_a_502(self):
        with self.assertLogs("hermes.access", level="INFO") as captured:
            socket = await self.browser.ws_connect(
                self.local_url + "/api/pty?token=" + FAKE_SESSION, headers=self.headers,
            )
            await socket.send_str("connected")
            self.assertEqual(await socket.receive_str(timeout=3), "connected")
            socket._response.connection.transport.abort()
            await socket.close()
            await asyncio.sleep(0.05)
        output = "\n".join(captured.output)
        self.assertNotIn("GET /api/pty 502", output)
        self.assertNotIn("Traceback", output)

    async def test_oversized_websocket_frame_rejected(self):
        async with self.browser.ws_connect(self.local_url + "/api/pty?token=" + FAKE_SESSION, headers=self.headers) as socket:
            try:
                await socket.send_bytes(b"x" * (proxy.MAX_FRAME + 1))
            except ConnectionError:
                # aiohttp can reject the declared frame length before the
                # sender finishes writing it, resetting the rejected stream.
                pass
            await socket.receive(timeout=3)
            self.assertIn(socket.close_code, {1006, 1009})
            self.assertEqual(self.ws_payload_sizes, [])

    async def test_exact_one_mib_and_frame_below_cap_stream_intact(self):
        async with self.browser.ws_connect(self.local_url + "/api/pty?token=" + FAKE_SESSION, headers=self.headers) as socket:
            for size in (proxy.MAX_FRAME - 1, proxy.MAX_FRAME):
                payload = b"x" * size
                await socket.send_bytes(payload)
                self.assertEqual(await socket.receive_bytes(timeout=3), payload)

    async def test_websocket_redirect_does_not_forward_bearer_or_follow(self):
        self.redirect_ws = True
        with self.assertRaises(aiohttp.WSServerHandshakeError):
            await self.browser.ws_connect(self.local_url + "/api/pty?token=" + FAKE_SESSION, headers=self.headers)
        self.assertEqual(self.redirect_hits, 0)

    async def test_no_query_or_credentials_in_proxy_logs(self):
        with self.assertLogs("hermes.access", level="INFO") as captured:
            async with self.browser.ws_connect(
                self.local_url + "/api/pty?token=" + FAKE_SESSION, headers=self.headers,
            ) as socket:
                await socket.send_str("message")
                await socket.receive_str(timeout=3)
            await asyncio.sleep(0.02)
        output = "\n".join(captured.output)
        for secret in (FAKE_BEARER, FAKE_SESSION, self.current_key, "token=", self.local.cookie):
            self.assertNotIn(secret, output)

    async def test_browser_resource_policy_survives_all_hops(self):
        async with self.browser.get(self.local_url + "/", headers=self.headers) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["Content-Security-Policy"], proxy.browser_policy(self.local_url))
            self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
            self.assertIn("window.__HERMES_SESSION_TOKEN__", await response.text())


if __name__ == "__main__":
    unittest.main()
