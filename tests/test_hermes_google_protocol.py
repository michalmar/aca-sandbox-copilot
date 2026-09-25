from __future__ import annotations

import asyncio
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from collections import deque
from unittest.mock import AsyncMock, patch

import jsonschema
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import MCPError

from test_hermes_google_core import (
    ACCESS_TOKEN, CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, ROOT,
    FakeTransport, PrivateFiles, google, runtime_document, text_part, token_document,
)

spec = importlib.util.spec_from_file_location("hermes_google_server", ROOT / "hermes" / "image" / "google" / "server.py")
server = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(server)


class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.policy = google.GooglePolicy.from_runtime(runtime_document())
        self.tools = {tool.name: tool for tool in server.tool_definitions(self.policy)}

    def test_exact_three_tools_and_strict_schemas(self):
        self.assertEqual(set(self.tools), {"gmail_search", "gmail_read", "calendar_events"})
        properties = {
            "gmail_search": {"query", "max_results", "page_token"},
            "gmail_read": {"message_id"},
            "calendar_events": {"calendar_id", "time_min", "time_max", "max_results"},
        }
        for name, tool in self.tools.items():
            schema = tool.input_schema
            jsonschema.Draft202012Validator.check_schema(schema)
            self.assertEqual(schema["type"], "object")
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(schema["properties"]), properties[name])
            self.assertTrue(tool.annotations.read_only_hint)
            self.assertFalse(tool.annotations.destructive_hint)
        self.assertEqual(self.tools["gmail_search"].input_schema["properties"]["max_results"]["maximum"], 20)
        self.assertEqual(self.tools["gmail_search"].input_schema["properties"]["query"]["maxLength"], 512)
        self.assertEqual(self.tools["calendar_events"].input_schema["properties"]["max_results"]["maximum"], 50)
        self.assertEqual(self.tools["calendar_events"].input_schema["properties"]["calendar_id"]["enum"], ["primary"])

    def test_schema_rejects_extra_bool_and_oversized_fields(self):
        for name, args in (
            ("gmail_search", {"query": "x", "max_results": True}),
            ("gmail_search", {"query": "x" * 513}),
            ("gmail_search", {"query": "x", "page_token": "x" * 1025}),
            ("gmail_search", {"query": "x", "page_token": None}),
            ("gmail_read", {"message_id": "abc", "format": "raw"}),
            ("gmail_read", {"message_id": "../other"}),
            ("calendar_events", {"time_min": "2026-09-24T00:00:00Z", "time_max": "2026-09-25T00:00:00Z", "calendar_id": "other"}),
            ("calendar_events", {"time_min": "2026-09-24T00:00:00.\u0661Z", "time_max": "2026-09-25T00:00:00Z"}),
            ("calendar_events", {"time_min": "2026-09-24T00:00:00.\uff11Z", "time_max": "2026-09-25T00:00:00Z"}),
        ):
            with self.subTest(name=name, args=args):
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.validate(args, self.tools[name].input_schema)

    def test_nonprimary_calendar_schema_requires_an_allowed_explicit_id(self):
        policy = google.GooglePolicy.from_runtime(runtime_document(calendar_ids=["team@group.calendar.google.com"]))
        schema = server.tool_definitions(policy)[2].input_schema
        self.assertNotIn("default", schema["properties"]["calendar_id"])
        self.assertIn("calendar_id", schema["required"])
        valid = {"calendar_id": "team@group.calendar.google.com", "time_min": "2026-09-24T00:00:00Z", "time_max": "2026-09-25T00:00:00Z"}
        jsonschema.validate(valid, schema)
        del valid["calendar_id"]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(valid, schema)

    def test_offline_cli_exit_semantics_do_not_claim_live_connection(self):
        for status, code in (("configured", 0), ("not-connected", 0), ("reconnect-required", 0), ("disabled", 0), ("failed", 1)):
            output = io.StringIO()
            diagnostic = {"status": status, "live_verified": False}
            with patch.object(server, "credential_status", return_value=diagnostic), contextlib.redirect_stdout(output):
                self.assertEqual(server.main(["--status", "--offline"]), code)
            self.assertEqual(json.loads(output.getvalue()), diagnostic)

    def test_discovery_budget_does_not_expand_the_existing_tool_read_deadline(self):
        self.assertEqual(server.DISCOVERY_TIMEOUT_SECONDS, 40)
        self.assertEqual(google.TOOL_TIMEOUT_SECONDS, 45)

    def test_live_cli_status_exit_codes_and_nonsecret_stdout(self):
        for status, expected in (("connected", 0), ("disabled", 0), ("not-connected", 1), ("reconnect-required", 1), ("failed", 1)):
            output = io.StringIO()
            diagnostic = {"status": status, "live_verified": status == "connected"}
            with patch.object(server, "live_status", AsyncMock(return_value=diagnostic)), contextlib.redirect_stdout(output):
                self.assertEqual(server.main(["--status"]), expected)
            self.assertEqual(json.loads(output.getvalue()), diagnostic)
            for secret in (ACCESS_TOKEN, CLIENT_SECRET, REFRESH_TOKEN):
                self.assertNotIn(secret, output.getvalue())

    def test_real_server_entrypoint_by_path_for_offline_status(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "hermes" / "image" / "google" / "server.py"), "--status", "--offline"],
            capture_output=True, text=True, timeout=10,
        )
        diagnostic = json.loads(result.stdout)
        if not google.RUNTIME_PATH.exists():
            self.assertEqual(result.returncode, 1)
            self.assertEqual(diagnostic["code"], "configuration_io")
        else:
            self.assertEqual(result.returncode, int(diagnostic["status"] == "failed"))
        self.assertFalse(diagnostic["live_verified"])
        self.assertEqual(result.stderr, "")


class LiveStatusTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.files = PrivateFiles()
        self.addCleanup(self.files.close)

    async def status(self, transport):
        with contextlib.redirect_stderr(io.StringIO()):
            return await server.live_status(runtime_path=self.files.runtime, credential_path=self.files.credential, transport=transport)

    async def test_live_status_proves_account_and_calendar_api_access(self):
        transport = FakeTransport()
        result = await self.status(transport)
        self.assertEqual(result["status"], "connected")
        self.assertTrue(result["live_verified"])
        self.assertEqual([op for op, _ in transport.calls], ["token", "tokeninfo", "profile", "events"])
        self.assertEqual(transport.calls[-1][1]["params"]["fields"], "nextPageToken")

    async def test_live_status_invalid_missing_disabled_and_unexpected_failures(self):
        for overrides, code in (
            ({"profile": google.HTTPResult(200, {"emailAddress": "wrong@example.test"})}, "wrong_account"),
            ({"token": google.HTTPResult(400, {"error": "invalid_grant"})}, "refresh_revoked"),
            ({"events": google.HTTPResult(403, {"error": "Calendar API disabled"})}, "api_denied"),
            ({"events": google.HTTPResult(404, {"error": {"code": 404}})}, "not_found"),
            ({"tokeninfo": RuntimeError(ACCESS_TOKEN + CLIENT_SECRET + REFRESH_TOKEN)}, "internal_error"),
        ):
            result = await self.status(FakeTransport(**overrides))
            self.assertEqual(result["code"], code)
            self.assertFalse(result["live_verified"])
            self.assertNotIn(ACCESS_TOKEN, json.dumps(result))
        self.files.credential.unlink()
        self.assertEqual((await self.status(FakeTransport()))["status"], "not-connected")
        self.files.runtime.write_text(json.dumps(runtime_document(enabled=False)), encoding="utf-8")
        self.assertEqual((await self.status(FakeTransport()))["status"], "disabled")

    async def test_busy_guard_is_explicit_and_does_not_start_a_second_read(self):
        policy = google.GooglePolicy.from_runtime(runtime_document())
        transport = FakeTransport()
        client = google.GoogleClient(policy, google.load_credential(policy, self.files.credential), transport)
        service = server.GoogleService(client)
        entered, finish = asyncio.Event(), asyncio.Event()

        async def blocked(*args):
            entered.set()
            await finish.wait()
            return {"untrusted": True}

        params = types.CallToolRequestParams(name="gmail_search", arguments={"query": "safe"})
        with patch.object(client, "call", side_effect=blocked) as call:
            pending = asyncio.create_task(service.call_tool(None, params))
            await entered.wait()
            result = await service.call_tool(None, params)
            self.assertTrue(result.is_error)
            self.assertEqual(json.loads(result.content[0].text)["code"], "busy")
            self.assertEqual(call.call_count, 1)
            finish.set()
            self.assertFalse((await pending).is_error)
        self.assertFalse(service.busy)

    async def test_discovery_deadline_includes_lock_wait_without_releasing_its_owner(self):
        transport = FakeTransport()
        service = server._service(self.files.runtime, self.files.credential, transport)
        client = service.client
        assert client is not None
        await client._refresh_lock.acquire()
        try:
            with patch.object(server, "DISCOVERY_TIMEOUT_SECONDS", 0.02), contextlib.redirect_stderr(io.StringIO()):
                listed = await service.list_tools(None, None)
            self.assertEqual(len(listed.tools), 3)
            self.assertEqual(service.error.code, "request_timeout")
            self.assertFalse(service.error.diagnostic()["live_verified"])
            self.assertTrue(client._refresh_lock.locked())
            self.assertIsNone(client._token)
            self.assertEqual(transport.calls, [])
        finally:
            client._refresh_lock.release()
        self.assertEqual(len((await service.list_tools(None, None)).tools), 3)
        self.assertIsNone(service.error)
        self.assertEqual([operation for operation, _ in transport.calls], ["token", "tokeninfo", "profile"])

    async def test_queued_discovery_timeout_cannot_mask_concurrent_proven_revocation(self):
        entered, finish = asyncio.Event(), asyncio.Event()

        class RevokedTransport(FakeTransport):
            reads = 0

            async def request(self, operation, **kwargs):
                if operation == "messages":
                    self.reads += 1
                    if self.reads == 2:
                        entered.set()
                        await finish.wait()
                return await super().request(operation, **kwargs)

        transport = RevokedTransport(messages=google.HTTPResult(401, {}))
        service = server._service(self.files.runtime, self.files.credential, transport)
        client = service.client
        assert client is not None
        params = types.CallToolRequestParams(name="gmail_search", arguments={"query": "safe"})
        with patch.object(server, "DISCOVERY_TIMEOUT_SECONDS", 0.05), contextlib.redirect_stderr(io.StringIO()):
            async with asyncio.TaskGroup() as tasks:
                reading = tasks.create_task(service.call_tool(None, params))
                await asyncio.wait_for(entered.wait(), 5)
                await client._refresh_lock.acquire()
                try:
                    listing = tasks.create_task(service.list_tools(None, None))
                    await asyncio.sleep(0)
                    finish.set()
                    result = await reading
                    self.assertEqual(json.loads(result.content[0].text)["code"], "access_revoked")
                    self.assertEqual((await listing).tools, [])
                    self.assertEqual(service.error.code, "access_revoked")
                    self.assertTrue(client._refresh_lock.locked())
                finally:
                    finish.set()
                    client._refresh_lock.release()

class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.files = PrivateFiles()
        self.addCleanup(self.files.close)

    @contextlib.asynccontextmanager
    async def session(self, *, mode="normal", read_timeout=10):
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(Path(__file__).resolve()), "--fixture-server", str(self.files.runtime), str(self.files.credential), mode],
            env={"PYTHONUNBUFFERED": "1"},
        )
        with tempfile.TemporaryFile(mode="a+", encoding="utf-8") as log:
            async with stdio_client(params, errlog=log) as (reader, writer):
                async with ClientSession(reader, writer, read_timeout_seconds=read_timeout) as session:
                    initialized = await session.initialize()
                    yield session, initialized, log
            output = self.log_output(log)
            for secret in (ACCESS_TOKEN, REFRESH_TOKEN, CLIENT_SECRET, "private query marker"):
                self.assertNotIn(secret, output)

    @staticmethod
    def log_output(log):
        log.flush()
        log.seek(0)
        return log.read()

    def requests(self, log):
        return [
            line.split("=", 1)[1] for line in self.log_output(log).splitlines()
            if line.startswith("fixture-request=")
        ]

    async def wait_for_log(self, log, marker):
        async with asyncio.timeout(5):
            while marker not in self.log_output(log):
                await asyncio.sleep(0.02)

    async def test_handshake_and_ping_precede_network_and_rediscovery_uses_cached_proof(self):
        async with self.session() as (session, _, log):
            self.assertEqual(self.requests(log), [])
            await session.send_ping()
            self.assertEqual(self.requests(log), [])
            self.assertEqual(len((await session.list_tools()).tools), 3)
            self.assertEqual(self.requests(log), ["token", "tokeninfo", "profile"])
            self.assertEqual(len((await session.list_tools()).tools), 3)
            self.assertEqual(self.requests(log), ["token", "tokeninfo", "profile"])

    async def test_call_before_discovery_still_proves_current_token_before_any_read(self):
        for mode, expected, code in (
            ("normal", ["token", "tokeninfo", "profile", "messages"], None),
            ("wrong-account", ["token", "tokeninfo", "profile"], "wrong_account"),
            ("broad-scope", ["token", "tokeninfo"], "scope_mismatch"),
            ("revoked", ["token"], "refresh_revoked"),
        ):
            async with self.session(mode=mode) as (session, _, log):
                self.assertEqual(self.requests(log), [])
                result = await session.send_request(
                    types.CallToolRequest(params=types.CallToolRequestParams(
                        name="gmail_search", arguments={"query": "safe"},
                    )),
                    types.CallToolResult,
                )
                self.assertEqual(result.is_error, code is not None)
                if code:
                    self.assertEqual(json.loads(result.content[0].text)["code"], code)
                self.assertEqual(self.requests(log), expected)

    async def test_client_cancellation_stops_proof_releases_lock_and_allows_retry(self):
        before = self.files.credential.read_bytes()
        async with self.session(mode="cancel-proof") as (session, _, log):
            self.assertEqual(self.requests(log), [])
            pending = asyncio.create_task(session.list_tools())
            try:
                await self.wait_for_log(log, "fixture-proof-waiting")
                pending.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await pending
            finally:
                pending.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await pending
            await self.wait_for_log(log, "fixture-proof-cancelled")
            self.assertNotIn("internal_error", self.log_output(log))
            self.assertNotIn("request_timeout", self.log_output(log))
            await session.send_ping()
            self.assertEqual(len((await session.list_tools()).tools), 3)
            self.assertEqual(self.requests(log), ["token", "tokeninfo", "profile", "token", "tokeninfo", "profile"])
            self.assertFalse((await session.call_tool("gmail_search", {"query": "safe"})).is_error)
        self.assertEqual(self.files.credential.read_bytes(), before)

    async def test_discovery_deadline_cancels_partial_proof_before_any_data_read(self):
        async with self.session(mode="proof-deadline") as (session, _, log):
            self.assertEqual(self.requests(log), [])
            started = time.monotonic()
            self.assertEqual(len((await session.list_tools()).tools), 3)
            self.assertLess(time.monotonic() - started, 3)
            output = self.log_output(log)
            self.assertIn("fixture-proof-cancelled", output)
            self.assertIn('"code": "request_timeout"', output)
            self.assertIn('"live_verified": false', output)
            self.assertEqual(self.requests(log), ["token", "tokeninfo", "profile"])
            self.assertFalse((await session.call_tool("gmail_search", {"query": "safe"})).is_error)
            self.assertEqual(self.requests(log), [
                "token", "tokeninfo", "profile", "token", "tokeninfo", "profile", "messages",
            ])

    async def test_real_40_second_discovery_budget_includes_locked_refresh(self):
        async with self.session(mode="locked-refresh", read_timeout=45) as (session, _, log):
            self.assertEqual(self.requests(log), [])
            started = time.monotonic()
            self.assertEqual(len((await session.list_tools()).tools), 3)
            elapsed = time.monotonic() - started
            self.assertGreaterEqual(elapsed, 39)
            self.assertLess(elapsed, 45)
            self.assertEqual(self.requests(log), [])
            output = self.log_output(log)
            self.assertIn('"code": "request_timeout"', output)
            self.assertIn('"live_verified": false', output)
            self.assertNotIn("fixture-lock-released", output)
            await session.send_ping()
            self.assertFalse((await session.call_tool("gmail_search", {"query": "safe"})).is_error)
            self.assertEqual(self.requests(log), ["token", "tokeninfo", "profile", "messages"])
            self.assertIn("fixture-lock-released", self.log_output(log))

    async def test_actual_mcp2_stdio_enumeration_capabilities_and_reads(self):
        async with self.session() as (session, initialized, _):
            self.assertEqual(initialized.server_info.name, "google_readonly")
            capabilities = initialized.capabilities
            self.assertIsNotNone(capabilities.tools)
            for name in ("resources", "prompts", "logging", "completions", "tasks", "extensions"):
                self.assertIsNone(getattr(capabilities, name))
            listed = await session.list_tools()
            self.assertEqual([tool.name for tool in listed.tools], ["gmail_search", "gmail_read", "calendar_events"])
            for tool in listed.tools:
                self.assertFalse(tool.input_schema["additionalProperties"])
            await session.send_ping()
            for name, arguments, key in (
                ("gmail_search", {"query": "safe"}, "messages"),
                ("gmail_read", {"message_id": "abc123"}, "text"),
                ("calendar_events", {"time_min": "2026-09-24T00:00:00Z", "time_max": "2026-09-25T00:00:00Z"}, "events"),
            ):
                result = await session.call_tool(name, arguments)
                self.assertFalse(result.is_error)
                data = json.loads(result.content[0].text)
                self.assertIn(key, data)
                self.assertTrue(data["untrusted"])
            for operation in (session.list_resources, session.list_prompts):
                with self.assertRaises(MCPError) as raised:
                    await operation()
                self.assertEqual(raised.exception.code, -32601)

    async def test_actual_protocol_validation_and_write_denial_are_sanitized(self):
        async with self.session() as (session, _, _):
            for name, arguments, code in (
                ("gmail_search", {"query": "private query marker", "max_results": True}, "invalid_max_results"),
                ("gmail_search", {"query": "private query marker", "page_token": "x" * 1025}, "invalid_page_token"),
                ("gmail_read", {"message_id": "../send"}, "invalid_message_id"),
                ("gmail_send", {"to": "not-sent@example.test"}, "unknown_tool"),
                ("status", {}, "unknown_tool"),
                ("gmail_search", {"query": "private query marker", "url": "http://127.0.0.1:9119"}, "invalid_arguments"),
            ):
                result = await session.call_tool(name, arguments)
                self.assertTrue(result.is_error)
                data = json.loads(result.content[0].text)
                self.assertEqual(data["code"], code)
                self.assertNotIn("private query marker", result.content[0].text)

    async def test_wire_text_preserves_readable_czech_and_emoji(self):
        async with self.session(mode="unicode") as (session, _, _):
            result = await session.call_tool("gmail_read", {"message_id": "abc123"})
            self.assertFalse(result.is_error)
            wire_text = result.content[0].text
            self.assertIn("Příliš", wire_text)
            self.assertIn("\U0001f469\u200d\U0001f4bb", wire_text)
            self.assertNotIn("\\u0159", wire_text)
            self.assertNotIn("\u202e", wire_text)
            self.assertEqual(json.loads(wire_text)["text"], "Příliš žluťoučký \U0001f469\u200d\U0001f4bb")

    async def test_missing_message_is_not_found_without_disabling_other_reads(self):
        async with self.session(mode="missing-message") as (session, _, _):
            missing = await session.call_tool("gmail_read", {"message_id": "abc123"})
            self.assertTrue(missing.is_error)
            self.assertEqual(json.loads(missing.content[0].text)["code"], "not_found")
            self.assertFalse((await session.call_tool("gmail_search", {"query": "safe"})).is_error)

    async def test_invalid_live_credentials_withhold_tools_without_killing_mcp(self):
        for mode, code in (("wrong-account", "wrong_account"), ("broad-scope", "scope_mismatch"), ("revoked", "refresh_revoked")):
            async with self.session(mode=mode) as (session, _, _):
                self.assertEqual((await session.list_tools()).tools, [])
                await session.send_ping()
                result = await session.call_tool("gmail_search", {"query": "safe"})
                self.assertTrue(result.is_error)
                self.assertEqual(json.loads(result.content[0].text)["code"], code)

    async def test_transient_startup_does_not_hide_tools_permanently(self):
        for mode, success in (("flaky-start", True), ("network-down", False), ("api-disabled", False)):
            async with self.session(mode=mode) as (session, _, _):
                self.assertEqual(len((await session.list_tools()).tools), 3)
                result = await session.call_tool("gmail_search", {"query": "safe"})
                self.assertEqual(result.is_error, not success)
                data = json.loads(result.content[0].text)
                if success:
                    self.assertIn("messages", data)
                else:
                    self.assertEqual(data["code"], "api_denied" if mode == "api-disabled" else "network_error")

    async def test_repeated_transient_failures_remain_unverified_until_a_later_read_proof(self):
        async with self.session(mode="flaky-twice") as (session, _, log):
            self.assertEqual(self.requests(log), [])
            self.assertEqual(len((await session.list_tools()).tools), 3)
            self.assertEqual(self.requests(log), ["token"])
            failed = await session.call_tool("gmail_search", {"query": "safe"})
            self.assertTrue(failed.is_error)
            self.assertFalse(json.loads(failed.content[0].text)["live_verified"])
            self.assertEqual(self.requests(log), ["token", "token"])
            self.assertFalse((await session.call_tool("gmail_search", {"query": "safe"})).is_error)
            self.assertEqual(self.requests(log), ["token", "token", "token", "tokeninfo", "profile", "messages"])

    async def test_startup_and_list_exceptions_do_not_crash_or_leak_secrets(self):
        async with self.session(mode="proof-exception") as (session, _, _):
            self.assertEqual((await session.list_tools()).tools, [])
            await session.send_ping()
            result = await session.call_tool("gmail_search", {"query": "safe"})
            self.assertTrue(result.is_error)
            self.assertEqual(json.loads(result.content[0].text)["code"], "internal_error")
            self.assertNotIn(ACCESS_TOKEN, result.content[0].text)

    async def test_missing_credential_is_visible_onboarding_not_an_empty_success(self):
        self.files.credential.unlink()
        async with self.session() as (session, _, log):
            self.assertIn('"status": "not-connected"', self.log_output(log))
            self.assertEqual(self.requests(log), [])
            self.assertEqual((await session.list_tools()).tools, [])
            result = await session.call_tool("gmail_search", {"query": "safe"})
            self.assertTrue(result.is_error)
            self.assertEqual(json.loads(result.content[0].text)["status"], "not-connected")

    async def test_invalid_local_config_is_diagnosed_before_discovery_without_network(self):
        document = runtime_document()
        document["google"]["token"] = ACCESS_TOKEN
        self.files.runtime.write_text(json.dumps(document), encoding="utf-8")
        async with self.session() as (session, _, log):
            self.assertIn('"code": "runtime_invalid"', self.log_output(log))
            self.assertEqual(self.requests(log), [])
            await session.send_ping()
            self.assertEqual((await session.list_tools()).tools, [])
            self.assertEqual(self.requests(log), [])

    async def test_two_real_mcp_processes_refresh_without_touching_persistent_file(self):
        before = self.files.credential.stat()
        digest = hashlib.sha256(self.files.credential.read_bytes()).hexdigest()
        pids = []

        async def exercise():
            async with self.session(mode="short-lived") as (session, _, log):
                self.assertEqual(len((await session.list_tools()).tools), 3)
                first = await session.call_tool("gmail_search", {"query": "safe"})
                self.assertFalse(first.is_error)
                await asyncio.sleep(1.2)
                second = await session.call_tool("gmail_search", {"query": "safe"})
                self.assertFalse(second.is_error)
                log.flush()
                log.seek(0)
                output = log.read()
                self.assertGreaterEqual(output.count("fixture-refresh"), 2)
                pids.append(next(line.split("=", 1)[1] for line in output.splitlines() if line.startswith("fixture-pid=")))

        await asyncio.gather(exercise(), exercise())
        self.assertEqual(len(set(pids)), 2)
        after = self.files.credential.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns, before.st_size), (after.st_ino, after.st_mtime_ns, after.st_size))
        self.assertEqual(hashlib.sha256(self.files.credential.read_bytes()).hexdigest(), digest)
        self.assertEqual(list(self.files.credential.parent.iterdir()), [self.files.credential])

    async def test_unexpected_dependency_exception_cannot_leak_through_mcp(self):
        async with self.session(mode="api-exception") as (session, _, _):
            result = await session.call_tool("gmail_search", {"query": "private query marker"})
            self.assertTrue(result.is_error)
            self.assertEqual(json.loads(result.content[0].text)["code"], "internal_error")
            self.assertNotIn(ACCESS_TOKEN, result.content[0].text)


def fixture_main(runtime: str, credential: str, mode: str) -> None:
    class FixtureTransport(FakeTransport):
        proof_blocked = False

        async def request(self, operation, **kwargs):
            print(f"fixture-request={operation}", file=sys.stderr)
            if operation == "token":
                print("fixture-refresh", file=sys.stderr)
            if operation == "profile" and mode in {"cancel-proof", "proof-deadline"} and not self.proof_blocked:
                self.proof_blocked = True
                print("fixture-proof-waiting", file=sys.stderr)
                try:
                    await asyncio.sleep(90)
                except asyncio.CancelledError:
                    print("fixture-proof-cancelled", file=sys.stderr)
                    raise
            return await super().request(operation, **kwargs)

    overrides = {}
    if mode == "wrong-account":
        overrides["profile"] = google.HTTPResult(200, {"emailAddress": "wrong@example.test"})
    elif mode == "broad-scope":
        overrides["tokeninfo"] = google.HTTPResult(200, {
            "scope": " ".join(google.SCOPES) + " openid", "aud": CLIENT_ID, "expires_in": 3600,
        })
    elif mode == "revoked":
        overrides["token"] = google.HTTPResult(400, {"error": "invalid_grant", "error_description": REFRESH_TOKEN})
    elif mode == "short-lived":
        overrides["token"] = google.HTTPResult(200, token_document(expires_in=61))
        overrides["tokeninfo"] = google.HTTPResult(200, {
            "scope": " ".join(google.SCOPES), "aud": CLIENT_ID, "expires_in": 61,
        })
    elif mode == "api-exception":
        overrides["messages"] = RuntimeError(ACCESS_TOKEN + CLIENT_SECRET + REFRESH_TOKEN)
    elif mode == "proof-exception":
        overrides["tokeninfo"] = RuntimeError(ACCESS_TOKEN + CLIENT_SECRET + REFRESH_TOKEN)
    elif mode == "network-down":
        overrides["token"] = google.GoogleError("network_error")
    elif mode == "api-disabled":
        overrides["profile"] = google.HTTPResult(403, {"error": "Gmail API disabled"})
    elif mode == "missing-message":
        overrides["message"] = google.HTTPResult(404, {"error": {"code": 404}})
    elif mode == "unicode":
        overrides["message"] = google.HTTPResult(200, {
            "id": "abc123", "payload": text_part("Příliš \u202ežluťoučký\u202c \U0001f469\u200d\U0001f4bb"),
        })
    elif mode in {"flaky-start", "flaky-twice"}:
        overrides["token"] = deque([
            *[google.GoogleError("network_error") for _ in range(1 if mode == "flaky-start" else 2)],
            google.HTTPResult(200, token_document()),
        ])
    elif mode not in {"normal", "cancel-proof", "proof-deadline", "locked-refresh"}:
        raise ValueError("Unknown fixture mode")
    server.configure_logging()
    print(f"fixture-pid={os.getpid()}", file=sys.stderr)

    async def run():
        runtime_path, credential_path = Path(runtime), Path(credential)
        transport = FixtureTransport(**overrides)
        if mode == "proof-deadline":
            server.DISCOVERY_TIMEOUT_SECONDS = 0.15
        if mode != "locked-refresh":
            await server.serve(runtime_path=runtime_path, credential_path=credential_path, transport=transport)
            return

        service = server._service(runtime_path, credential_path, transport)
        assert service.client is not None
        lock = service.client._refresh_lock
        await lock.acquire()

        async def release():
            try:
                await asyncio.sleep(server.DISCOVERY_TIMEOUT_SECONDS + 2)
            finally:
                lock.release()
                print("fixture-lock-released", file=sys.stderr)

        async with asyncio.TaskGroup() as tasks:
            releasing = tasks.create_task(release())
            try:
                with patch.object(server, "_service", return_value=service):
                    await server.serve(runtime_path=runtime_path, credential_path=credential_path, transport=transport)
            finally:
                releasing.cancel()

    asyncio.run(run())


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--fixture-server":
        fixture_main(*sys.argv[2:])
    else:
        unittest.main()
