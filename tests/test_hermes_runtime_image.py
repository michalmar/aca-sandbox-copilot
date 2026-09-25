"""Run explicitly in the pinned amd64 image; fakes are test-local, never production fallbacks."""

from __future__ import annotations

import json
import copy
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

IN_IMAGE = os.environ.get("HERMES_RUNTIME_IMAGE_TESTS") == "1"


def write_bootstrap(directory: str) -> None:
    Path(directory, "sitecustomize.py").write_text(
        "import os, traceback\n"
        "try:\n"
        "    from test_hermes_runtime_fake_provider import install\n"
        "    install()\n"
        "except BaseException:\n"
        "    traceback.print_exc()\n"
        "    os._exit(97)\n"
    )


@unittest.skipUnless(IN_IMAGE, "requires the true amd64 Hermes image and explicit offline test opt-in")
class RuntimeImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, "/opt/hermes-sandbox")
        sys.path.insert(0, "/opt/hermes")
        from test_hermes_runtime_profile import sample_runtime
        import runtime
        cls.runtime_module = runtime
        cls.runtime = sample_runtime()
        runtime.private_directory(runtime.HOME)
        runtime.atomic_json(runtime.RUNTIME, cls.runtime)
        runtime.apply_profile(cls.runtime, configured=False)
        environment = runtime.child_environment(cls.runtime)
        environment["HERMES_RUNTIME_IMAGE_TESTS"] = "1"
        os.environ.clear()
        os.environ.update(environment)

    def setUp(self):
        self.runtime_module.apply_profile(self.runtime, configured=False)

    @contextmanager
    def google_profile(self):
        from test_hermes_google_core import credential_document, EMAIL
        runtime = self.runtime_module
        previous = self.runtime
        self.runtime = copy.deepcopy(previous)
        self.runtime["google"].update(enabled=True, expected_email=EMAIL)
        for directory in (Path("/mnt/data/secrets"), Path("/mnt/data/secrets/google")):
            runtime.private_directory(directory)
        runtime.atomic_json(Path("/mnt/data/secrets/google/credentials.json"), credential_document())
        runtime.atomic_json(runtime.RUNTIME, self.runtime)
        runtime.apply_profile(self.runtime, configured=True)
        try:
            yield
        finally:
            self.runtime = previous
            runtime.atomic_json(runtime.RUNTIME, previous)
            runtime.apply_profile(previous, configured=False)

    def fixture_environment(self, bootstrap, capture, surface):
        return {
            **os.environ,
            "PYTHONPATH": f"{bootstrap}:/runtime-tests:/c-tests:/c-fixture/tests:/opt/hermes-sandbox:/opt/hermes",
            "HERMES_RUNTIME_WIRE_CAPTURE": str(capture), "HERMES_RUNTIME_TEST_SURFACE": surface,
            "HERMES_RUNTIME_GOOGLE_FIXTURE": "1" if self.runtime["google"]["enabled"] else "0",
        }

    def expected_tools(self):
        runtime = self.runtime_module
        return runtime.BASE_TOOLS | (runtime.MCP_TOOLS if self.runtime["google"]["enabled"] else frozenset())

    def assert_no_external_attempts(self, capture):
        attempts = Path(str(capture) + ".network-attempts")
        self.assertFalse(attempts.exists(), attempts.read_text() if attempts.exists() else "")

    @contextmanager
    def reference_canaries(self, *, whatsapp=True):
        import secrets
        runtime = self.runtime_module
        marker = "offline-reference-canary-" + secrets.token_hex(12)
        paths = [Path("/mnt/data/secrets/google/credentials.json")]
        if whatsapp:
            paths.append(runtime.SESSION / "creds.json")
        saved = []
        created = []
        try:
            for path in paths:
                destination = path.resolve()
                saved.append((destination, destination.read_bytes() if destination.exists() else None))
                if not destination.parent.exists():
                    created.append(destination.parent)
                runtime.private_directory(destination.parent)
                runtime.atomic_json(destination, {"test_only_canary": marker})
            yield marker
        finally:
            for destination, previous in reversed(saved):
                if previous is None:
                    destination.unlink(missing_ok=True)
                else:
                    runtime.atomic_write(destination, previous)
            for directory in reversed(created):
                directory.rmdir()

    def assert_canary_not_persisted(self, marker):
        home = self.runtime_module.HOME
        for path in (home / "state.db", home / "state.db-wal", *home.glob("sessions/**/*.jsonl")):
            if path.is_file():
                self.assertNotIn(marker.encode(), path.read_bytes(), str(path))

    def agent(self, platform="cli"):
        from run_agent import AIAgent
        return AIAgent(
            provider="azure-foundry", model=self.runtime["foundry"]["deployment"],
            base_url=self.runtime["foundry"]["endpoint"], api_mode="chat_completions",
            api_key=lambda: "offline-test-only-token", platform=platform,
            enabled_toolsets=["memory", "clarify"], quiet_mode=True,
        )

    def test_real_amd64_runtime_and_locked_dependencies(self):
        import importlib.metadata
        import platform
        self.assertEqual(platform.machine(), "x86_64")
        self.assertEqual(sys.version_info[:2], (3, 12))
        self.assertEqual(importlib.metadata.version("azure-identity"), "1.25.3")
        self.assertEqual(importlib.metadata.version("msal"), "1.37.0")
        self.assertEqual(importlib.metadata.version("cryptography"), "50.0.0")
        self.assertEqual(importlib.metadata.version("hermes-agent"), "0.21.5")

    def test_native_cli_tui_whatsapp_agents_have_exact_two_tools_when_google_disabled(self):
        for platform in ("cli", "tui", "whatsapp"):
            with self.subTest(platform=platform):
                agent = self.agent(platform)
                self.assertEqual({tool["function"]["name"] for tool in agent.tools}, {"memory", "clarify"})

    def test_actual_wire_kwargs_have_exact_tools_and_native_foundry_route(self):
        from agent.chat_completion_helpers import build_api_kwargs
        for platform in ("cli", "tui", "whatsapp"):
            with self.subTest(platform=platform):
                agent = self.agent(platform)
                kwargs = build_api_kwargs(agent, [{"role": "user", "content": "offline test"}])
                self.assertEqual(kwargs["model"], self.runtime["foundry"]["deployment"])
                self.assertEqual({tool["function"]["name"] for tool in kwargs["tools"]}, {"memory", "clarify"})
                self.assertEqual(agent.provider, "azure-foundry")

    def test_real_cli_command_dispatch_refuses_mutation_before_handler(self):
        from cli import HermesCLI
        shell = object.__new__(HermesCLI)
        shell._console_print = Mock()
        shell._slash_handler = Mock(side_effect=AssertionError("unsafe dispatcher reached"))
        for command in ("/model", "/models", "/tools", "/toolsets all", "/yolo", "/cron",
                        "/restart", "/whatsapp", "/memory edit", "/skills", "/provider"):
            self.assertTrue(shell.process_command(command))
        self.assertEqual(shell._console_print.call_count, 11)
        shell._slash_handler.assert_not_called()

    def test_real_bang_dispatch_cannot_execute(self):
        from hermes_cli.bang_shell import run_bang_command, bang_shell_enabled
        messages = []
        with patch("subprocess.Popen", side_effect=AssertionError("shell launched")):
            self.assertFalse(bang_shell_enabled())
            self.assertEqual(run_bang_command("echo forbidden", writer=messages.append), 126)
        self.assertTrue(messages)

    def test_real_tool_dispatch_and_registry_dispatch_deny_generic_http_shell_and_files(self):
        from model_tools import handle_function_call
        from tools.registry import registry
        from runtime import PolicyError
        for name in ("terminal", "execute_code", "read_file", "write_file", "web_fetch", "delegate_task",
                     "browser_navigate", "skill_view", "unknown_tool"):
            with self.subTest(tool=name):
                with self.assertRaises(PolicyError):
                    handle_function_call(name, {})
                with self.assertRaises(PolicyError):
                    registry.dispatch(name, {})

    def test_context_references_refuse_all_expansion_without_io(self):
        import asyncio
        from agent import context_references as refs
        prompts = [
            "@file:secrets/google/credentials.json",
            "@file:hermes/platforms/whatsapp/session/creds.json",
            '@file:"secrets/google/credentials.json":1-2',
            "@folder:secrets", "@diff", "@staged", "@git:1",
            "@url:https://example.com/page", "@url:http://127.0.0.1:9119/",
            "@offline:provider",
        ]
        with self.reference_canaries() as marker:
            with patch.dict(refs._context_reference_providers, {"offline": Mock()}), \
                    patch.object(refs, "_expand_reference", side_effect=AssertionError("reference expansion")) as expand, \
                    patch("pathlib.Path.open", side_effect=AssertionError("file read")) as read, \
                    patch("subprocess.Popen", side_effect=AssertionError("process launch")) as spawn, \
                    patch("socket.getaddrinfo", side_effect=AssertionError("DNS lookup")) as dns:
                for cwd in ("/mnt/data", "/root", "/opt/hermes"):
                    for message in prompts:
                        with self.subTest(cwd=cwd, prompt=message):
                            options = {"cwd": cwd, "allowed_root": cwd, "context_length": 128000}
                            for result in (
                                refs.preprocess_context_references(message, **options),
                                asyncio.run(refs.preprocess_context_references_async(message, **options)),
                            ):
                                self.assertTrue(result.blocked)
                                self.assertFalse(result.expanded)
                                self.assertEqual(result.injected_tokens, 0)
                                self.assertEqual(result.message, message)
                                self.assertNotIn(marker, result.message)
                                self.assertEqual(result.warnings, [
                                    "Context references are disabled in managed Sandbox mode.",
                                ])
                ordinary = "Read mail from bob@example.com and calendar events, without attachments."
                result = refs.preprocess_context_references(ordinary, cwd="/mnt/data", context_length=128000)
                self.assertEqual(result.message, ordinary)
                self.assertFalse(result.blocked)
                self.assertEqual(result.warnings, [])
                for operation in (expand, read, spawn, dns):
                    operation.assert_not_called()

    def test_context_reference_source_fingerprint_rejects_one_byte_drift(self):
        import patch_upstream
        name = "agent/context_references.py"
        original = subprocess.check_output(
            ["git", "show", "645da6561c724b7ca163d4af9c21de3a6397c9f2:" + name], cwd="/opt/hermes",
        )
        expected = patch_upstream.FINGERPRINTS[name]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / name
            path.parent.mkdir()
            path.write_bytes(original)
            with patch.dict(patch_upstream.FINGERPRINTS, {name: expected}, clear=True):
                patch_upstream.Patcher(root)
                path.write_bytes(original + b" ")
                with self.assertRaisesRegex(RuntimeError, "upstream source mismatch"):
                    patch_upstream.Patcher(root)

    def test_unknown_registry_name_and_toolset_fail_even_after_cache_fill(self):
        from model_tools import get_tool_definitions
        from tools.registry import registry
        from runtime import PolicyError
        get_tool_definitions(["memory", "clarify"], quiet_mode=True)
        original = registry.get_tool_to_toolset_map
        for extra in ({"rogue_in_known_set": "memory"}, {"rogue": "unclassified"}):
            with patch.object(registry, "get_tool_to_toolset_map", side_effect=lambda: {**original(), **extra}):
                with self.assertRaises(PolicyError):
                    get_tool_definitions(["memory", "clarify"], quiet_mode=True)

    def test_model_and_auxiliary_fallback_overrides_are_forbidden(self):
        from runtime import PolicyError
        from managed_policy import auxiliary_route
        from run_agent import AIAgent
        with self.assertRaises(PolicyError):
            AIAgent(provider="openrouter", api_key="forbidden", model="other")
        with self.assertRaises(PolicyError):
            auxiliary_route("anthropic", None, None, None, None)
        self.assertEqual(auxiliary_route("auto", None, None, None, None)[:2],
                         ("azure-foundry", self.runtime["foundry"]["deployment"]))

    def test_real_cached_agent_request_override_is_rejected(self):
        from agent.chat_completion_helpers import build_api_kwargs
        from runtime import PolicyError
        agent = self.agent("tui")
        agent.request_overrides = {"tools": [{"type": "function", "function": {"name": "terminal"}}]}
        with self.assertRaises(PolicyError):
            build_api_kwargs(agent, [{"role": "user", "content": "do not execute"}])

    def test_native_rpc_rejects_mutations_attachments_unknown_methods_and_drift(self):
        from tui_gateway import server
        unsafe = (
            ("config.set", {"key": "model.provider", "value": "other"}),
            ("input.detect_drop", {"session_id": "fixture", "text": "/mnt/data/hermes/.env"}),
            ("prompt.submit", {"session_id": "fixture", "text": "test", "attachments": ["/etc/passwd"]}),
            ("prompt.submit", {"session_id": "fixture", "text": "test", "model": "other"}),
            ("terminal.run", {"command": "echo forbidden"}),
            ("profile.activate", {"name": "foreign"}),
            ("future.unknown", {}),
        )
        for method, params in unsafe:
            with self.subTest(method=method, params=params):
                handler = Mock(side_effect=AssertionError("disallowed native RPC executed"))
                with patch.dict(server._methods, {method: handler}):
                    response = server.handle_request({
                        "jsonrpc": "2.0", "id": "fixture", "method": method, "params": params,
                    })
                self.assertEqual(response["error"]["code"], 4030)
                handler.assert_not_called()
        status_rpc = {"jsonrpc": "2.0", "id": "fixture", "method": "config.get", "params": {"key": "mtime"}}
        self.assertNotIn("error", server.handle_request(status_rpc))
        config = self.runtime_module.HOME / "config.yaml"
        altered = json.loads(config.read_text())
        altered["platform_toolsets"]["tui"].append("terminal")
        self.runtime_module.atomic_json(config, altered)
        try:
            response = server.handle_request(status_rpc)
            self.assertEqual(response["error"]["code"], 4030)
            self.assertIn("drift", response["error"]["message"])
        finally:
            self.runtime_module.apply_profile(self.runtime, configured=False)

    def test_native_config_full_uses_only_validated_nonsecret_managed_values(self):
        import managed_policy
        from tui_gateway import server
        with patch.object(managed_policy, "checked_runtime", wraps=managed_policy.checked_runtime) as validate:
            with patch.object(server, "_load_cfg", side_effect=AssertionError("unsafe effective config read")):
                response = server.handle_request({
                    "jsonrpc": "2.0", "id": "full-config", "method": "config.get", "params": {"key": "full"},
                })
        self.assertGreaterEqual(validate.call_count, 2)
        self.assertEqual(response["result"]["config"],
                         self.runtime_module.managed_config(self.runtime, google_configured=False))
        self.assertEqual(response["result"]["config"]["providers"], {})
        self.assertEqual(response["result"]["config"]["mcp_servers"], {})

    def test_native_executable_handlers_independently_deny_even_with_permissive_proxy(self):
        import access_proxy
        from tui_gateway import server
        sentinel = Path("/mnt/data/forbidden-native-shell")
        sentinel.unlink(missing_ok=True)
        with patch.object(access_proxy, "rpc_allowed", return_value=True):
            for method in ("shell.exec", "cli.exec"):
                response = server.handle_request({
                    "jsonrpc": "2.0", "id": method, "method": method,
                    "params": ({"command": "touch " + str(sentinel)} if method == "shell.exec"
                               else {"argv": ["doctor"]}),
                })
                self.assertEqual(response["error"]["code"], 4030, response)
        self.assertFalse(sentinel.exists())

    def test_native_completion_handlers_never_enumerate_files_skills_or_plugins(self):
        from tui_gateway import server
        with patch("os.listdir", side_effect=AssertionError("directory listing")) as listing, \
                patch("pathlib.Path.iterdir", side_effect=AssertionError("directory iteration")) as iteration, \
                patch("subprocess.Popen", side_effect=AssertionError("completion subprocess")) as process:
            for method, params in (
                ("complete.path", {"word": "@file:secrets/google/credentials.json"}),
                ("complete.path", {"word": "/mnt/data"}),
                ("complete.slash", {"text": "/skills"}),
                ("complete.slash", {"text": "/co"}),
            ):
                response = server._methods[method]("completion", params)
                self.assertEqual(response["result"], {"items": []})
            for operation in (listing, iteration, process):
                operation.assert_not_called()

    def test_native_completion_dispatch_enforces_the_whole_escaped_envelope(self):
        from queue import Queue
        import access_proxy
        from tui_gateway import server

        class Transport:
            def __init__(self):
                self.responses = Queue()

            def write(self, frame):
                self.responses.put(frame)
                return True

            def close(self):
                return None

        transport = Transport()

        def dispatch(frame):
            self.assertTrue(transport.responses.empty())
            response = server.dispatch(frame, transport)
            return transport.responses.get(timeout=5) if response is None else response

        def size(frame):
            return len(json.dumps(frame, ensure_ascii=True, separators=(",", ":")).encode("ascii"))

        self.assertEqual(access_proxy.MAX_FRAME, 1024 * 1024)
        for method, key, extra in (
            ("complete.path", "word", {}),
            ("complete.slash", "text", {}),
            ("complete.slash", "text", {"session_id": "completion-owned"}),
        ):
            for identifier, character in (
                ("i" * 128, "x"), ("\u00e9" * 128, '"'), ("id", "\\"),
                ("id", "\n"), ("id", "\u00e9"), ("\U0001f9ea" * 128, "\U0001f9ea"),
            ):
                with self.subTest(method=method, session=bool(extra), character=repr(character)):
                    frame = {"jsonrpc": "2.0", "id": identifier, "method": method,
                             "params": {key: "", **extra}}
                    budget = access_proxy.MAX_FRAME - size(frame)
                    repeats, padding = divmod(budget, len(json.dumps(character, ensure_ascii=True)) - 2)
                    frame["params"][key] = character * repeats + "x" * padding
                    self.assertEqual(size(frame), access_proxy.MAX_FRAME)
                    self.assertLessEqual(len(frame["params"][key].encode("utf-8")), access_proxy.MAX_FRAME)
                    self.assertFalse(access_proxy.rpc_allowed(frame, surface="sidebar"))
                    response = dispatch(frame)
                    self.assertEqual(response, {"jsonrpc": "2.0", "id": identifier, "result": {"items": []}})
                    frame["params"][key] += "x"
                    self.assertEqual(size(frame), access_proxy.MAX_FRAME + 1)
                    self.assertLessEqual(len(frame["params"][key].encode("utf-8")), access_proxy.MAX_FRAME)
                    handler = Mock(side_effect=AssertionError("oversized completion reached its handler"))
                    with patch.dict(server._methods, {method: handler}):
                        response = dispatch(frame)
                    self.assertEqual(response["error"]["code"], 4030)
                    handler.assert_not_called()

            for value in ("", "x" * 257):
                frame = {"jsonrpc": "2.0", "id": "short", "method": method, "params": {key: value, **extra}}
                self.assertEqual(dispatch(frame)["result"], {"items": []})
            invalid = [
                {key: value, **extra} for value in ("\x00", "\ud800", "x" * (access_proxy.MAX_FRAME + 1), None)
            ]
            invalid.extend({key: "", **extra, field: "default"} for field in ("profile", "cwd", "tool"))
            invalid.append({key: "", "session_id": "invalid/session"})
            if method == "complete.path":
                invalid.append({key: "", "session_id": "otherwise-valid"})
            for params in invalid:
                handler = Mock(side_effect=AssertionError("invalid completion reached its handler"))
                with patch.dict(server._methods, {method: handler}):
                    response = dispatch({"jsonrpc": "2.0", "id": "invalid", "method": method, "params": params})
                self.assertEqual(response["error"]["code"], 4030)
                handler.assert_not_called()

    def test_native_resize_extremes_require_valid_columns_and_own_live_transport(self):
        import access_proxy
        from tui_gateway import server

        class Transport:
            _closed = False

            def write(self, frame):
                return True

            def close(self):
                self._closed = True

        own, foreign = Transport(), Transport()
        sid = "resize-owned"
        session = {"transport": own, "cols": 80}

        def request(params):
            return {"jsonrpc": "2.0", "id": "resize", "method": "terminal.resize", "params": params}

        with patch.dict(server._sessions, {sid: session}):
            for cols in (1, 19, 20, 500, 501, 1000):
                with self.subTest(cols=cols):
                    frame = request({"session_id": sid, "cols": cols})
                    self.assertFalse(access_proxy.rpc_allowed(frame, surface="sidebar"))
                    self.assertEqual(server.dispatch(frame, own)["result"], {"cols": cols})
                    self.assertEqual(session["cols"], cols)
            invalid = [{"session_id": sid, "cols": cols} for cols in (-1, 0, 1001, True, False, 1.0, "100", None)]
            invalid.extend(({"cols": 100}, {"session_id": sid}, {"session_id": "missing", "cols": 100},
                            {"session_id": sid, "cols": 100, "profile": "default"}))
            for params in invalid:
                handler = Mock(side_effect=AssertionError("invalid resize reached its handler"))
                with patch.dict(server._methods, {"terminal.resize": handler}):
                    self.assertEqual(server.dispatch(request(params), own)["error"]["code"], 4030)
                handler.assert_not_called()
                self.assertEqual(session["cols"], 1000)
            for cols in (1, 1000):
                with patch.object(access_proxy, "rpc_allowed", return_value=True):
                    response = server.dispatch(request({"session_id": sid, "cols": cols}), foreign)
                self.assertEqual(response["error"]["code"], 4030)
                self.assertEqual(session["cols"], 1000)
            own.close()
            self.assertEqual(server.dispatch(request({"session_id": sid, "cols": 100}), own)["error"]["code"], 4030)
            self.assertEqual(session["cols"], 1000)

    def test_native_clarification_replies_and_locks_are_pending_transport_scoped(self):
        import access_proxy
        from tui_gateway import server, server_requests

        class Transport:
            def write(self, frame):
                return True

            def close(self):
                return None

        own, foreign = Transport(), Transport()
        sid = "clarify-owned"

        def pending(*, batch=False, method="clarify"):
            params = {"request_id": "approval-fixture"} if method == "approval" else {"question": "Pick a color"}
            if batch:
                params = {"questions": [
                    {"qid": "q0", "question": "Pick a color"}, {"qid": "q1", "question": "Pick a shape"},
                ]}
            request = server_requests.ServerRequest(sid, method, params, qids=["q0", "q1"] if batch else None)
            server_requests._register(request)
            return request

        def reply(request, result, transport=own):
            return server.dispatch({"jsonrpc": "2.0", "id": request.id, "result": result}, transport)

        def lock(request_id, question_id, transport=own):
            return server.dispatch({
                "jsonrpc": "2.0", "id": "lock-fixture", "method": "clarify.lock",
                "params": {"request_id": request_id, "question_id": question_id, "answer": "Blue"},
            }, transport)

        server_requests.reset_for_tests()
        try:
            with patch.dict(server._sessions, {sid: {"transport": own}}), \
                    patch.object(server_requests, "_write"), \
                    patch.object(server, "_relay_compute_host_response", side_effect=AssertionError("foreign relay")), \
                    patch.object(server, "_lock_compute_host_clarify", side_effect=AssertionError("foreign lock relay")):
                for method in ("session.close", "session.interrupt", "terminal.resize"):
                    with patch.object(access_proxy, "rpc_allowed", return_value=True), \
                            patch.dict(server._methods, {method: Mock(side_effect=AssertionError("foreign lifecycle"))}):
                        result = server.dispatch({
                            "jsonrpc": "2.0", "id": method, "method": method,
                            "params": {"session_id": sid, **({"cols": 100} if method == "terminal.resize" else {})},
                        }, foreign)
                    self.assertEqual(result["error"]["code"], 4030)
                single = pending()
                server.dispatch({"jsonrpc": "2.0", "id": "srq-000000000000", "result": {"answer": "forged"}}, own)
                reply(single, {"answer": "forged"}, foreign)
                reply(single, {"answers": {"q0": "wrong shape"}})
                reply(single, {"answer": "forged", "choice": "always"})
                self.assertFalse(single.event.is_set())
                self.assertEqual(len(server_requests.open_requests(sid)), 1)
                reply(single, {"answer": "Blue"})
                self.assertTrue(single.event.is_set())
                self.assertEqual(single.result, {"answer": "Blue"})
                reply(single, {"answer": "replayed"})
                self.assertEqual(single.result, {"answer": "Blue"})

                batch = pending(batch=True)
                self.assertEqual(lock("srq-000000000000", "q0")["result"]["status"], "expired")
                self.assertEqual(lock(batch.id, "q0", foreign)["result"]["status"], "expired")
                self.assertEqual(lock(batch.id, "unknown")["error"]["code"], 4002)
                reply(batch, {"answers": {"unknown": "forged"}})
                reply(batch, {"answer": "wrong shape"})
                self.assertEqual(batch.locked, {})
                self.assertFalse(batch.event.is_set())
                self.assertEqual(lock(batch.id, "q0")["result"]["remaining"], ["q1"])
                self.assertEqual(batch.locked, {"q0": "Blue"})
                self.assertFalse(batch.event.is_set())
                reply(batch, {"answers": {"q1": "Round"}})
                self.assertEqual(batch.result, {"answers": {"q0": "Blue", "q1": "Round"}})
                self.assertTrue(batch.event.is_set())

                approval = pending(method="approval")
                reply(approval, {"answer": "always"})
                self.assertFalse(approval.event.is_set())
                self.assertIsNone(approval.result)
                server_requests.cancel(sid)

                cancelled = pending()
                reply(cancelled, {"answer": ""})
                self.assertTrue(cancelled.event.is_set())
                self.assertEqual(cancelled.result, {"answer": ""})

                drifted = pending()
                config = self.runtime_module.HOME / "config.yaml"
                altered = json.loads(config.read_text())
                altered["platform_toolsets"]["tui"].append("terminal")
                self.runtime_module.atomic_json(config, altered)
                reply(drifted, {"answer": "must not settle"})
                self.assertFalse(drifted.event.is_set())
                self.runtime_module.apply_profile(self.runtime, configured=False)
                server.dispatch({"jsonrpc": "2.0", "id": drifted.id, "error": {"code": -1, "message": ""}}, own)
                self.assertTrue(drifted.event.is_set())
                self.assertIsNone(drifted.result)
        finally:
            server_requests.reset_for_tests()
            self.runtime_module.apply_profile(self.runtime, configured=False)

    def test_native_expired_clarification_race_never_delivers_a_late_answer(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        from tui_gateway import server, server_requests

        class Transport:
            def write(self, frame):
                return True

            def close(self):
                return None

        own, foreign = Transport(), Transport()
        sid = "clarify-expiry-race"
        registered, lock_entered = threading.Event(), threading.Event()
        expire, release_answer = threading.Event(), threading.Event()
        request_ids = []
        original_lock = server_requests.lock_answer

        def publish(frame):
            request_ids.append(frame["id"])
            registered.set()
            self.assertTrue(expire.wait(10), "timeout fixture was not released")

        def delayed_lock(*args):
            lock_entered.set()
            self.assertTrue(release_answer.wait(10), "late-answer fixture was not released")
            return original_lock(*args)

        def lock(request_id, question_id="q0", transport=own):
            return server.dispatch({
                "jsonrpc": "2.0", "id": "late-lock", "method": "clarify.lock",
                "params": {"request_id": request_id, "question_id": question_id, "answer": "late-secret-answer"},
            }, transport)

        server_requests.reset_for_tests()
        try:
            with patch.dict(server._sessions, {sid: {"transport": own}}), \
                    patch.object(server_requests, "_write", side_effect=publish), \
                    patch.object(server_requests, "_emit"), \
                    ThreadPoolExecutor(max_workers=2) as workers:
                server_requests.advertise(own, True)
                try:
                    with self.assertNoLogs(server_requests.logger, level="WARNING"):
                        model = workers.submit(
                            server_requests.send, "clarify", sid,
                            {"questions": [{"qid": "q0", "question": "Pick a color"}]},
                            timeout=0, qids=["q0"],
                        )
                        self.assertTrue(registered.wait(10))
                        request_id = request_ids[0]
                        native_request = server_requests._open[request_id]
                        with patch.object(server_requests, "lock_answer", side_effect=delayed_lock):
                            late_answer = workers.submit(lock, request_id)
                            self.assertTrue(lock_entered.wait(10))
                            self.assertEqual(len(server_requests.open_requests(sid)), 1)
                            expire.set()
                            self.assertEqual(model.result(timeout=10), {"answers": {}, "timed_out": True})
                            self.assertEqual(server_requests.open_requests(sid), [])
                            release_answer.set()
                            self.assertEqual(late_answer.result(timeout=10)["result"], {"status": "expired"})
                        server.dispatch({
                            "jsonrpc": "2.0", "id": request_id,
                            "result": {"answers": {"q0": "late-secret-answer"}},
                        }, own)
                        self.assertFalse(native_request.answered)
                        self.assertIsNone(native_request.result)
                        self.assertEqual(native_request.locked, {})
                    for identifier, question_id, transport in (
                        (request_id, "q0", foreign), (request_id, "wrong-question", own),
                        ("srq-000000000000", "q0", own),
                    ):
                        with self.subTest(identifier=identifier, question_id=question_id, transport=transport):
                            with self.assertLogs(server_requests.logger, level="WARNING") as logs:
                                self.assertEqual(lock(identifier, question_id, transport)["result"], {"status": "expired"})
                            self.assertIn("denied an unrelated clarification lock", logs.output[0])
                    approval = server_requests.ServerRequest(sid, "approval", {"request_id": "approval-fixture"})
                    with patch.object(server_requests, "_write"):
                        server_requests._register(approval)
                    with self.assertLogs(server_requests.logger, level="WARNING"):
                        self.assertEqual(lock(approval.id)["result"], {"status": "expired"})
                    self.assertFalse(approval.answered)
                    self.assertFalse(approval.event.is_set())
                    self.assertIsNone(approval.result)
                    self.assertIs(server_requests._open[approval.id], approval)
                finally:
                    expire.set()
                    release_answer.set()
        finally:
            server_requests.reset_for_tests()

    def test_native_retired_clarifications_are_metadata_only_bounded_and_reset(self):
        from tui_gateway import server, server_requests

        class Transport:
            def write(self, frame):
                return True

            def close(self):
                return None

        own = Transport()
        sid = "clarify-expiry-cap"
        requests = []
        server_requests.reset_for_tests()
        try:
            with patch.dict(server._sessions, {sid: {"transport": own}}), \
                    patch.object(server_requests, "_write"), patch.object(server_requests, "_emit"):
                for index in range(129):
                    request = server_requests.ServerRequest(
                        sid, "clarify", {"questions": [{"qid": "q0", "question": f"private-question-{index}"}]},
                        qids=["q0"],
                    )
                    request.locked["q0"] = "private-answer"
                    server_requests._register(request)
                    self.assertEqual(server_requests.cancel(sid, reason="timeout"), 1)
                    requests.append(request)
                retired = server_requests._managed_retired_clarifications
                self.assertEqual(len(retired), 128)
                self.assertNotIn(requests[0].id, retired)
                self.assertEqual(set(retired), {request.id for request in requests[1:]})
                self.assertTrue(all(value == (sid, ("q0",)) for value in retired.values()))
                self.assertNotIn("private-question", repr(retired))
                self.assertNotIn("private-answer", repr(retired))
                frame = {
                    "jsonrpc": "2.0", "id": "expired-cap", "method": "clarify.lock",
                    "params": {"request_id": requests[-1].id, "question_id": "q0", "answer": "too-late"},
                }
                with self.assertNoLogs(server_requests.logger, level="WARNING"):
                    self.assertEqual(server.dispatch(frame, own)["result"], {"status": "expired"})
                frame["params"]["request_id"] = requests[0].id
                with self.assertLogs(server_requests.logger, level="WARNING"):
                    self.assertEqual(server.dispatch(frame, own)["result"], {"status": "expired"})
                server_requests.reset_for_tests()
                self.assertEqual(retired, {})
                frame["params"]["request_id"] = requests[-1].id
                with self.assertLogs(server_requests.logger, level="WARNING"):
                    self.assertEqual(server.dispatch(frame, own)["result"], {"status": "expired"})
                self.assertTrue(all(not request.answered and request.result is None for request in requests))
        finally:
            server_requests.reset_for_tests()

    def test_native_slash_worker_preserves_only_the_fixed_managed_path(self):
        from tui_gateway import server
        environment = self.runtime_module.child_environment(self.runtime)
        result = server._prepend_tool_paths(environment)
        self.assertEqual(result["PATH"], environment["PATH"])
        self.assertNotIn("/mnt/data", result["PATH"])
        self.assertNotIn("/root/.local", result["PATH"])
        with patch.object(server, "_hermes_home", str(self.runtime_module.HOME)):
            worker = server._SlashWorker("p4-safe-worker", self.runtime["foundry"]["deployment"])
            try:
                response = worker.run("/context")
                self.assertTrue(response)
            finally:
                worker.close()

    def test_bridge_absence_probe_distinguishes_listener_from_time_wait(self):
        import socket
        from lifecycle import prove_bridge_absent
        from runtime import PolicyError
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            listener.listen(1)
            with socket.socket() as client:
                client.connect(("127.0.0.1", port))
                connection, _ = listener.accept()
                with self.assertRaises(PolicyError):
                    prove_bridge_absent(port)
                connection.close()
                client.recv(1)
        prove_bridge_absent(port)

    def test_reaped_parent_orphan_is_still_owned_by_exact_session_and_stopped(self):
        import time
        from lifecycle import Child, process_identity
        process = subprocess.Popen(
            [sys.executable, "-c", "import subprocess,sys; p=subprocess.Popen([sys.executable,'-c',"
             "'import time; time.sleep(60)']); print(p.pid,flush=True)"],
            stdout=subprocess.PIPE, text=True, start_new_session=True,
        )
        child = Child("orphan-fixture", process)
        descendant = int(process.stdout.readline().strip())
        process.wait(timeout=5)
        process.stdout.close()
        try:
            self.assertIsNotNone(process_identity(descendant))
            child.capture()
            self.assertIn(descendant, child.identities)
            child.stop(timeout=2)
            deadline = time.monotonic() + 2
            while process_identity(descendant) is not None and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertIsNone(process_identity(descendant))
        finally:
            child.stop(timeout=1)

    def test_native_replay_total_envelope_fits_and_reconnect_watermark_advances(self):
        from tui_gateway import event_replay, server
        event_replay.reset_replay_state()
        sid = "replay-p4"
        try:
            for index in range(48):
                event_replay._stamp_event({"method": "event", "params": {
                    "session_id": sid, "type": "tool.result", "text": ('"\U0001f4a1' * 15000), "index": index,
                }})
            def replay(last_seen):
                return server.handle_request({
                    "jsonrpc": "2.0", "id": "replay", "method": "session.events.since",
                    "params": {"session_id": sid, "last_seen": last_seen},
                })
            reply = replay(0)
            self.assertLessEqual(len(json.dumps(reply).encode()), 1024 * 1024)
            self.assertLessEqual(len(json.dumps(reply, ensure_ascii=False).encode()), 1024 * 1024)
            self.assertTrue(reply["result"]["truncated"])
            self.assertGreater(reply["result"]["count"], 0)
            self.assertEqual(reply["result"]["events"][-1]["seq"], 48)
            self.assertEqual(reply["result"]["latest_seq"], 48)
            followup = replay(reply["result"]["latest_seq"])
            self.assertEqual(followup["result"]["events"], [])
            self.assertFalse(followup["result"]["truncated"])
            with patch.object(server, "_open_requests", return_value=[{"question": "x" * (1024 * 1024)}]):
                too_large = replay(48)
            self.assertEqual(too_large["error"]["code"], 4130)
            self.assertLessEqual(len(json.dumps(too_large).encode()), 1024 * 1024)
        finally:
            event_replay.reset_replay_state()

    def test_models_catalog_is_offline_even_when_network_requested(self):
        from agent import models_dev
        from agent.model_metadata import fetch_endpoint_model_metadata, get_model_context_length
        with patch("socket.create_connection", side_effect=AssertionError("network bootstrap")):
            models_dev.fetch_models_dev(force_refresh=True, allow_network=True)
            models_dev._start_background_refresh_models_dev()
            self.assertEqual(fetch_endpoint_model_metadata(self.runtime["foundry"]["endpoint"]), {})
            self.assertEqual(get_model_context_length(
                self.runtime["foundry"]["deployment"], self.runtime["foundry"]["endpoint"],
                provider="azure-foundry",
            ), self.runtime["foundry"]["context_length"])

    def test_google_enabled_native_cli_emits_exact_five_tools(self):
        import copy
        from test_hermes_google_core import credential_document, EMAIL
        runtime = self.runtime_module
        configured = copy.deepcopy(self.runtime)
        configured["google"].update(enabled=True, expected_email=EMAIL)
        runtime.private_directory(Path("/mnt/data/secrets"))
        runtime.private_directory(Path("/mnt/data/secrets/google"))
        runtime.atomic_json(Path("/mnt/data/secrets/google/credentials.json"), credential_document())
        runtime.atomic_json(runtime.RUNTIME, configured)
        runtime.apply_profile(configured, configured=True)
        capture = Path("/mnt/data/google-cli-wire.jsonl")
        capture.unlink(missing_ok=True)
        try:
            with tempfile.TemporaryDirectory(prefix="hermes-google-bootstrap-") as bootstrap:
                write_bootstrap(bootstrap)
                environment = {
                    **os.environ,
                    "PYTHONPATH": f"{bootstrap}:/runtime-tests:/c-tests:/opt/hermes-sandbox:/opt/hermes",
                    "HERMES_RUNTIME_WIRE_CAPTURE": str(capture), "HERMES_RUNTIME_TEST_SURFACE": "cli-google",
                    "HERMES_RUNTIME_GOOGLE_FIXTURE": "1",
                }
                result = subprocess.run(
                    ["/opt/hermes/.venv/bin/hermes", "chat", "-q", "Offline Google descriptor P4 prompt",
                     "-Q", "--max-turns", "1"],
                    env=environment, capture_output=True, text=True, timeout=100, cwd="/mnt/data",
                )
                diagnostic = result.stdout + result.stderr
                stderr_log = Path("/mnt/data/hermes/logs/mcp-stderr.log")
                if stderr_log.exists():
                    diagnostic += stderr_log.read_text()[-4000:]
                self.assertEqual(result.returncode, 0, diagnostic)
                self.assertTrue(capture.exists(), result.stdout + result.stderr)
                records = [json.loads(line) for line in capture.read_text().splitlines()]
                main = [record for record in records if record["tools"] is not None]
                self.assertTrue(main, result.stdout + result.stderr)
                for record in main:
                    self.assertEqual(set(record["tools"]), runtime.BASE_TOOLS | runtime.MCP_TOOLS,
                                     result.stdout + result.stderr)
                    self.assertEqual(len(record["tools"]), 5)
                    self.assertTrue(record["test_bearer"])
                self.assert_no_external_attempts(capture)
                operations = Path(str(capture) + ".google-operations")
                self.assertTrue(operations.exists(), "Google fixture injection did not execute")
                observed = {json.loads(line)["operation"] for line in operations.read_text().splitlines()}
                self.assertTrue({"token", "tokeninfo", "profile"} <= observed, observed)
        finally:
            runtime.atomic_json(runtime.RUNTIME, self.runtime)
            runtime.apply_profile(self.runtime, configured=False)

    def test_real_native_mcp_deadline_handshake_cancellation_recovery_and_auth_withholding(self):
        import asyncio
        import hashlib
        import time
        from lifecycle import process_identity
        from tools import mcp_tool, mcp_tool_config, mcp_tool_discovery, mcp_tool_registration, mcp_tool_transport
        fixture_root = next(root for root in (Path("/c-fixture"), Path("/test-repo"))
                            if (root / "tests/test_hermes_google_protocol.py").is_file())

        for name in ("google_readonly.py", "server.py"):
            self.assertEqual(
                hashlib.sha256(Path(fixture_root, "hermes/image/google", name).read_bytes()).digest(),
                hashlib.sha256(Path("/opt/hermes-sandbox/google", name).read_bytes()).digest(),
                "native deadline fixture must use the exact integrated C version",
            )
        runtime = self.runtime_module
        log = runtime.HOME / "logs/mcp-stderr.log"
        original_negotiate = mcp_tool_transport.MCPServerTransportMixin._negotiate_session

        async def exercise(mode):
            handshake = []
            servers = []
            initial_log = log.stat().st_size if log.exists() else 0
            original_start = mcp_tool.MCPServerTask.start

            async def start(server, config):
                servers.append(server)
                return await original_start(server, config)

            async def negotiate(server, session, timeout):
                result = await original_negotiate(server, session, timeout)
                handshake.append(time.monotonic())
                return result

            config = runtime.managed_config(self.runtime, google_configured=True)["mcp_servers"]["google_readonly"]
            self.assertEqual((config["timeout"], config["connect_timeout"]), (45, 45))
            config = {**config, "command": sys.executable, "args": [
                str(fixture_root / "tests/test_hermes_google_protocol.py"), "--fixture-server", str(runtime.RUNTIME),
                "/mnt/data/secrets/google/credentials.json", mode,
            ]}
            began = time.monotonic()
            with patch.object(mcp_tool.MCPServerTask, "start", start), \
                    patch.object(mcp_tool_transport.MCPServerTransportMixin, "_negotiate_session", negotiate):
                task = asyncio.create_task(mcp_tool_discovery._discover_and_register_server("google_readonly", config))
                try:
                    if mode == "cancel-proof":
                        deadline = time.monotonic() + 12
                        while time.monotonic() < deadline:
                            text = log.read_text()[initial_log:] if log.exists() else ""
                            if "fixture-proof-waiting" in text:
                                break
                            await asyncio.sleep(0.05)
                        self.assertIn("fixture-proof-waiting", text)
                        self.assertTrue(handshake, "authorization proof blocked the handshake")
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                    else:
                        names = await asyncio.wait_for(task, 48)
                        elapsed = time.monotonic() - began
                        self.assertTrue(handshake)
                        self.assertLess(handshake[0] - began, 5)
                        self.assertLess(elapsed, 45, "native full discovery exceeded its unchanged deadline")
                        self.assertEqual(set(names), set() if mode == "revoked" else runtime.MCP_TOOLS)
                        print("P4_NATIVE_MCP_TIMING=" + json.dumps({
                            "mode": mode, "handshake_seconds": round(handshake[0] - began, 3),
                            "discovery_seconds": round(elapsed, 3), "remaining_seconds": round(45 - elapsed, 3),
                        }))
                        if mode == "locked-refresh":
                            self.assertGreaterEqual(elapsed, 40)
                            self.assertIn('"request_timeout"', log.read_text()[initial_log:])
                            result = await asyncio.wait_for(
                                servers[0].session.call_tool("gmail_search", {"query": "offline"}), 8,
                            )
                            self.assertFalse(result.is_error, result)
                            self.assertIn("fixture-request=profile", log.read_text()[initial_log:])
                            self.assertIn("fixture-request=messages", log.read_text()[initial_log:])
                finally:
                    if not task.done():
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                    for server in servers:
                        await server.shutdown()
                    for key, server in list(mcp_tool._servers.items()):
                        if server in servers:
                            for name in getattr(server, "_registered_tool_names", []):
                                mcp_tool_registration._deregister_mcp_tool_all_scopes(key, name)
                            del mcp_tool._servers[key]
                text = log.read_text()[initial_log:] if log.exists() else ""
                pids = [int(line.partition("=")[2]) for line in text.splitlines()
                        if line.startswith("fixture-pid=")]
                self.assertTrue(pids, "the real fixture subprocess did not start")
                self.assertTrue(all(process_identity(pid) is None for pid in pids), "native MCP child leaked")
                if mode == "cancel-proof":
                    self.assertIn("fixture-proof-cancelled", text)
                if mode == "revoked":
                    self.assertIn('"refresh_revoked"', text)

        async def all_modes():
            for mode in ("locked-refresh", "cancel-proof", "normal", "revoked"):
                await exercise(mode)

        with self.google_profile():
            try:
                asyncio.run(all_modes())
            finally:
                mcp_tool_config._close_mcp_stderr_logs()

    def test_real_cli_emits_exact_tools_to_test_native_foundry_transport(self):
        capture = Path("/mnt/data/cli-wire.jsonl")
        capture.unlink(missing_ok=True)
        env = {
            **os.environ, "PYTHONPATH": "/runtime-tests:/opt/hermes-sandbox:/opt/hermes",
            "HERMES_RUNTIME_WIRE_CAPTURE": str(capture), "HERMES_RUNTIME_TEST_SURFACE": "cli",
        }
        result = subprocess.run([
            sys.executable, "-c",
            "from test_hermes_runtime_fake_provider import install; install(); "
            "import sys; sys.argv=['hermes', 'chat', '-q', 'Offline P4 prompt', '-Q', '--max-turns', '1']; "
            "from hermes_cli.main import main; main()",
        ], env=env, capture_output=True, text=True, timeout=90, cwd="/mnt/data")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(capture.exists(), result.stdout + result.stderr)
        records = [json.loads(line) for line in capture.read_text().splitlines()]
        main = [record for record in records if record["tools"] is not None]
        self.assertTrue(main, records)
        for record in main:
            self.assertEqual(set(record["tools"]), {"memory", "clarify"})
            self.assertEqual(len(record["tools"]), 2)
            self.assertEqual(record["model"], self.runtime["foundry"]["deployment"])
            self.assertTrue(record["test_bearer"])
        self.assert_no_external_attempts(capture)

    def test_native_cli_context_reference_refuses_before_model(self):
        with self.reference_canaries(whatsapp=False) as marker, tempfile.TemporaryDirectory() as directory:
            capture = Path(directory, "wire.jsonl")
            environment = {
                **os.environ, "PYTHONPATH": "/runtime-tests:/opt/hermes-sandbox:/opt/hermes",
                "HERMES_RUNTIME_WIRE_CAPTURE": str(capture), "HERMES_RUNTIME_TEST_SURFACE": "cli",
            }
            for flags in ([], ["-Q"], ["--format", "stream-json"]):
                with self.subTest(flags=flags):
                    argv = ["hermes", "chat", "-q", "summarise @file:secrets/google/credentials.json",
                            "--max-turns", "1", *flags]
                    result = subprocess.run([
                        sys.executable, "-c",
                        "from test_hermes_runtime_fake_provider import install; install(); "
                        f"import sys; sys.argv={argv!r}; "
                        "from hermes_cli.main import main; main()",
                    ], env=environment, capture_output=True, text=True, timeout=60, cwd="/mnt/data")
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("Context references are disabled in managed Sandbox mode.", result.stdout + result.stderr)
                    self.assertNotIn(marker, result.stdout + result.stderr)
                    if "--format" in flags:
                        for line in result.stdout.splitlines():
                            try:
                                self.assertIsInstance(json.loads(line), dict)
                            except json.JSONDecodeError:
                                self.fail(f"Non-JSON stream output: {result.stdout!r}; stderr={result.stderr!r}")
                    self.assertFalse(capture.exists(), "reference refusal invoked a model")
                    self.assert_no_external_attempts(capture)
                    self.assert_canary_not_persisted(marker)

    def test_real_model_hidden_tool_call_is_rejected_without_execution(self):
        capture = Path("/mnt/data/hidden-tool-wire.jsonl")
        sentinel = Path("/mnt/data/forbidden-tool-executed")
        capture.unlink(missing_ok=True)
        sentinel.unlink(missing_ok=True)
        environment = {
            **os.environ, "PYTHONPATH": "/runtime-tests:/opt/hermes-sandbox:/opt/hermes",
            "HERMES_RUNTIME_WIRE_CAPTURE": str(capture), "HERMES_RUNTIME_TEST_SURFACE": "cli",
            "HERMES_RUNTIME_HIDDEN_TOOL_TEST": "1",
        }
        result = subprocess.run([
            sys.executable, "-c",
            "from test_hermes_runtime_fake_provider import install; install(); "
            "import sys; sys.argv=['hermes', 'chat', '-q', 'Offline hidden-tool P4 prompt', '-Q', '--max-turns', '3']; "
            "from hermes_cli.main import main; main()",
        ], env=environment, capture_output=True, text=True, timeout=90, cwd="/mnt/data")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(sentinel.exists(), "the unadvertised tool executed")
        records = [json.loads(line) for line in capture.read_text().splitlines()]
        self.assertTrue(any(record["hidden_tool_emitted"] for record in records), records)
        replies = [content.lower() for record in records for content in record["tool_results"]]
        self.assertTrue(any("denied" in reply or "not available" in reply or "not enabled" in reply
                            or "unknown tool" in reply or "tool 'terminal' does not exist" in reply
                            for reply in replies), replies)
        for record in records:
            if record["tools"] is not None:
                self.assertEqual(set(record["tools"]), {"memory", "clarify"})
                self.assertEqual(len(record["tools"]), 2)
        self.assert_no_external_attempts(capture)

    def test_real_dashboard_chat_pty_emits_exact_tools(self):
        self.dashboard_p4()

    def test_google_enabled_real_dashboard_chat_pty_emits_exact_five_tools(self):
        with self.google_profile():
            self.dashboard_p4()

    def test_native_dashboard_context_reference_refuses_without_secret_and_recovers(self):
        with self.reference_canaries(whatsapp=False) as marker:
            self.dashboard_p4(reference_sentinel=marker)
            self.assert_canary_not_persisted(marker)

    def dashboard_p4(self, reference_sentinel=""):
        import asyncio
        import re
        import time
        import aiohttp
        from lifecycle import Child

        capture = Path("/mnt/data/dashboard-wire.jsonl")
        rpc_capture = Path("/mnt/data/dashboard-rpc.jsonl")
        replies = Path(str(rpc_capture) + ".responses")
        for path in (capture, rpc_capture, replies):
            path.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix="hermes-dashboard-test-") as bootstrap:
            write_bootstrap(bootstrap)
            environment = {
                **self.fixture_environment(bootstrap, capture, "dashboard-pty"),
                "HERMES_RUNTIME_CAPTURE_RPC": str(rpc_capture), "TERM": "xterm-256color",
            }
            log_path = Path(bootstrap, "dashboard.log")
            with log_path.open("wb") as log:
                process = subprocess.Popen(
                    ["/opt/hermes/.venv/bin/hermes", "dashboard", "--host", "127.0.0.1", "--port", "9119",
                     "--no-open", "--skip-build"],
                    env=environment, cwd="/mnt/data", stdout=log, stderr=log, start_new_session=True,
                )
                child = Child("test-dashboard", process)
                output = bytearray()

                async def exercise():
                    base = "http://127.0.0.1:9119"
                    async with aiohttp.ClientSession() as session:
                        token = None
                        deadline = time.monotonic() + 40
                        while time.monotonic() < deadline and process.poll() is None:
                            child.capture()
                            try:
                                async with session.get(base + "/chat", timeout=aiohttp.ClientTimeout(total=2)) as response:
                                    if response.status == 200:
                                        html = await response.text()
                                        match = re.search(r'window\.__HERMES_SESSION_TOKEN__="([^"]+)"', html)
                                        if match:
                                            token = match[1]
                                            break
                            except (aiohttp.ClientConnectionError, asyncio.TimeoutError):
                                pass
                            await asyncio.sleep(0.2)
                        self.assertIsNotNone(token, "the real compiled dashboard never became ready")
                        async with session.ws_connect(
                            base + "/api/pty", params={"token": token}, headers={"Origin": base},
                        ) as ws:
                            ready_at = None
                            enter_at = None
                            pending_text = ""
                            pending_from = 0
                            submitted = False
                            refused = False
                            recovery_submitted = False
                            frames = []
                            responses = []
                            deadline = time.monotonic() + 55
                            while time.monotonic() < deadline and process.poll() is None and not ws.closed:
                                child.capture()
                                try:
                                    message = await ws.receive(timeout=0.1)
                                    if message.type == aiohttp.WSMsgType.BINARY:
                                        output.extend(message.data)
                                    elif message.type == aiohttp.WSMsgType.TEXT:
                                        output.extend(message.data.encode())
                                    elif message.type in {aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR}:
                                        break
                                except asyncio.TimeoutError:
                                    pass
                                rendered = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output.decode(errors="replace"))
                                if rpc_capture.exists():
                                    frames = [json.loads(line) for line in rpc_capture.read_text().rpartition("\n")[0].splitlines()]
                                    if ready_at is None and any(frame.get("method") == "session.create" for frame in frames):
                                        ready_at = time.monotonic() + 2
                                if replies.exists():
                                    responses = [json.loads(line) for line in replies.read_text().rpartition("\n")[0].splitlines()]
                                if not submitted and ready_at is not None and time.monotonic() >= ready_at:
                                    pending_text = ("summarise @file:secrets/google/credentials.json" if reference_sentinel
                                                    else "Offline real dashboard Chat P4 prompt")
                                    pending_from = len(output)
                                    await ws.send_str(pending_text)
                                    submitted = True
                                    enter_at = time.monotonic() + 0.6
                                if enter_at is not None and time.monotonic() >= enter_at:
                                    draft = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output[pending_from:].decode(errors="replace"))
                                    if re.sub(r"\s+", "", pending_text) in re.sub(r"\s+", "", draft):
                                        await ws.send_str("\r")
                                        enter_at = None
                                if reference_sentinel and not refused:
                                    if "ContextreferencesaredisabledinmanagedSandboxmode." in re.sub(r"\s+", "", rendered):
                                        self.assertFalse(capture.exists(), "dashboard refusal invoked a model")
                                        self.assertNotIn(reference_sentinel.encode(), output)
                                        self.assert_no_external_attempts(capture)
                                        refused = True
                                if refused and not recovery_submitted:
                                    refusal = next((index for index, frame in enumerate(responses)
                                                    if frame.get("method") == "event"
                                                    and frame["params"].get("type") == "error"
                                                    and frame["params"].get("payload", {}).get("message")
                                                    == "Context references are disabled in managed Sandbox mode."), None)
                                    settled = refusal is not None and any(
                                        frame.get("method") == "event" and frame["params"].get("type") == "session.info"
                                        and frame["params"].get("session_id")
                                        == responses[refusal]["params"]["session_id"]
                                        for frame in responses[refusal + 1:]
                                    )
                                    if settled:
                                        pending_text = "Offline real dashboard Chat P4 prompt"
                                        pending_from = len(output)
                                        await ws.send_str(pending_text)
                                        recovery_submitted = True
                                        enter_at = time.monotonic() + 0.6
                                if capture.exists():
                                    records = [json.loads(line) for line in capture.read_text().splitlines()]
                                    main = [record for record in records if record["tools"] is not None]
                                    if main:
                                        if reference_sentinel:
                                            self.assertTrue(refused, "dashboard reached model before rejecting the reference")
                                        return main
                            self.fail(json.dumps({
                                "submitted": submitted, "refused": refused,
                                "recovery_submitted": recovery_submitted, "enter_pending": enter_at is not None,
                                "rpc_methods": [frame.get("method") for frame in frames],
                                "recent_events": [frame.get("params", {}).get("type") for frame in responses[-8:]],
                            }) + output[-3000:].decode(errors="replace"))

                try:
                    records = asyncio.run(exercise())
                    self.assertTrue(records, output[-5000:].decode(errors="replace"))
                    for record in records:
                        self.assertEqual(record["surface"], "dashboard-pty")
                        self.assertEqual(set(record["tools"]), self.expected_tools())
                        self.assertEqual(len(record["tools"]), len(self.expected_tools()))
                        self.assertTrue(record["test_bearer"])
                    self.assert_no_external_attempts(capture)
                    if reference_sentinel:
                        self.assertNotIn(reference_sentinel.encode(), output)
                        self.assertNotIn(reference_sentinel, capture.read_text())
                except Exception:
                    print(re.sub(r'(?i)(token[=": ]+)[^\\s"<&]+', r"\1[redacted]", log_path.read_text())[-5000:])
                    raise
                finally:
                    child.stop(timeout=8)
                self.assert_no_external_attempts(capture)

    def test_real_identity_sdk_chain_is_only_managed_identity_and_refreshes(self):
        import azure.identity
        from azure.core.credentials import AccessTokenInfo
        from agent.azure_identity_adapter import build_token_provider, reset_credential_cache
        import time
        credential = azure.identity.DefaultAzureCredential()
        self.assertEqual([type(item).__name__ for item in credential.credentials], ["ManagedIdentityCredential"])
        reset_credential_cache()
        # Expiring SDK tokens force a callback refresh rather than a frozen string.
        sequence = iter([AccessTokenInfo("offline-one", int(time.time()) + 1),
                         AccessTokenInfo("offline-two", int(time.time()) + 3600)])
        with patch.object(azure.identity.DefaultAzureCredential, "get_token_info",
                          side_effect=lambda *a, **k: next(sequence)):
            provider = build_token_provider()
            self.assertEqual(provider(), "offline-one")
            self.assertEqual(provider(), "offline-two")
        reset_credential_cache()

    def test_real_whatsapp_adapter_fake_bridge_native_lock_and_sigusr1(self):
        self.whatsapp_p4()

    def test_google_enabled_real_whatsapp_adapter_emits_exact_five_tools(self):
        with self.google_profile():
            self.whatsapp_p4()

    def test_native_whatsapp_context_reference_refuses_before_model(self):
        self.whatsapp_p4(reference_prompt=True)

    def whatsapp_p4(self, reference_prompt=False):
        import signal
        import time
        import control
        from lifecycle import Child, native_gateway_identity, prove_gateway_absent
        from test_hermes_runtime_profile import fake_creds

        runtime = self.runtime_module
        for directory in (runtime.WHATSAPP, runtime.WHATSAPP / "sessions", runtime.WHATSAPP / "sessions/offline"):
            runtime.private_directory(directory)
        runtime.atomic_json(runtime.WHATSAPP / "sessions/offline/creds.json", fake_creds())
        control.activate(runtime.WHATSAPP / "sessions/offline", self.runtime["owner"]["whatsapp_phone"])
        runtime.write_state("running")
        capture = Path("/mnt/data/whatsapp-wire.jsonl")
        bridge_capture = Path("/mnt/data/whatsapp-bridge.jsonl")
        for path in (capture, bridge_capture):
            path.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix="hermes-whatsapp-test-") as bootstrap:
            write_bootstrap(bootstrap)
            environment = {
                **self.fixture_environment(bootstrap, capture, "whatsapp"),
                "HERMES_RUNTIME_FAKE_BRIDGE": "1", "HERMES_RUNTIME_BRIDGE_CAPTURE": str(bridge_capture),
                "HERMES_RUNTIME_WHATSAPP_PROMPT": (
                    "Read @url:https://example.com/page" if reference_prompt
                    else "Offline actual WhatsApp adapter P4 prompt"
                ),
            }
            command = ["/opt/hermes/.venv/bin/hermes", "gateway", "run", "--external-supervisor"]
            log_path = Path(bootstrap, "gateway.log")
            with log_path.open("wb") as log:
                process = subprocess.Popen(command, env=environment, cwd="/mnt/data", stdout=log,
                                           stderr=log, start_new_session=True)
                child = Child("test-gateway", process)
                try:
                    deadline = time.monotonic() + 75
                    sent = []
                    expected_reply = (
                        "Context references are disabled in managed Sandbox mode."
                        if reference_prompt else "Offline P4 response"
                    )
                    while process.poll() is None and time.monotonic() < deadline:
                        child.capture()
                        import yaml
                        config = yaml.safe_load((runtime.HOME / "config.yaml").read_text())
                        expected = runtime.managed_config(self.runtime, google_configured=self.runtime["google"]["enabled"])
                        self.assertEqual(runtime._changed_keys(config, expected), [],
                                         "native gateway rewrote keys; extra names=" + repr(sorted(set(config) - set(expected))))
                        if bridge_capture.exists():
                            sent = [json.loads(line) for line in bridge_capture.read_text().splitlines()]
                            if any(expected_reply in item.get("payload", {}).get("message", "") for item in sent):
                                break
                        time.sleep(0.1)
                    self.assertIsNone(process.poll(), log_path.read_text()[-7000:])
                    self.assertTrue(any(expected_reply in item.get("payload", {}).get("message", "")
                                        for item in sent), log_path.read_text()[-7000:])
                    self.assertIsNotNone(native_gateway_identity())
                    records = [json.loads(line) for line in capture.read_text().splitlines()] if capture.exists() else []
                    main = [record for record in records if record["tools"] is not None]
                    if reference_prompt:
                        self.assertEqual(records, [], "reference refusal invoked a model")
                    else:
                        self.assertTrue(main)
                    mcp_log = runtime.HOME / "logs/mcp-stderr.log"
                    discovery_log = Path(str(capture) + ".discovery")
                    for record in main:
                        self.assertEqual(set(record["tools"]), self.expected_tools(),
                                         log_path.read_text()[-4000:] + (mcp_log.read_text()[-4000:] if mcp_log.exists() else "")
                                         + (discovery_log.read_text() if discovery_log.exists() else "no discovery capture"))
                        self.assertEqual(len(record["tools"]), len(self.expected_tools()))
                        self.assertTrue(record["test_bearer"])
                    self.assertFalse(any(item["event"] in {"wrong-target", "unexpected-route"} for item in sent), sent)
                    contender = subprocess.run(command, env=environment, cwd="/mnt/data",
                                               capture_output=True, text=True, timeout=15)
                    self.assertIn("already", (contender.stdout + contender.stderr).lower())
                    starts = [json.loads(line) for line in bridge_capture.read_text().splitlines()
                              if json.loads(line)["event"] == "started"]
                    self.assertEqual(len(starts), 1, "a second gateway started another bridge")
                    child.capture()
                    process.send_signal(signal.SIGUSR1)
                    self.assertEqual(process.wait(timeout=40), 75, log_path.read_text()[-7000:])
                    child.stop(timeout=5)
                    prove_gateway_absent()
                    runtime.write_state("maintenance")
                    denied = subprocess.run(command, env=environment, cwd="/mnt/data",
                                            capture_output=True, text=True, timeout=15)
                    self.assertNotEqual(denied.returncode, 0)
                    self.assertIn("maintenance", (denied.stdout + denied.stderr).lower())
                    prove_gateway_absent()
                    self.assert_no_external_attempts(capture)
                finally:
                    child.stop(timeout=5)
                    runtime.write_state("maintenance")
                self.assert_no_external_attempts(capture)

    def test_native_tui_emits_tools_and_captures_actual_chat_rpc(self):
        self.tui_p4()

    def test_google_enabled_native_tui_emits_exact_five_tools(self):
        with self.google_profile():
            self.tui_p4()

    def test_native_tui_safe_context_uses_managed_rpc(self):
        self.tui_p4(context_command=True)

    def test_google_enabled_native_tui_context_reuses_live_session_without_workers(self):
        with self.google_profile():
            self.tui_p4(context_command=True)

    def test_native_tui_single_clarify_round_trip(self):
        self.tui_p4(interaction="clarify-single")

    def test_native_tui_batch_clarify_locks_then_completes(self):
        self.tui_p4(interaction="clarify-batch")

    def test_native_tui_interrupts_stream_and_accepts_next_prompt(self):
        self.tui_p4(interaction="interrupt")

    def test_native_tui_context_reference_refuses_without_secret_or_provider_and_recovers(self):
        with self.reference_canaries(whatsapp=False) as marker:
            self.tui_p4(interaction="context-reference", reference_sentinel=marker)
            self.assert_canary_not_persisted(marker)

    def test_native_tui_completions_and_resize_are_safe_and_do_not_show_denial_popups(self):
        self.tui_p4(interaction="completion-resize")

    def tui_p4(self, context_command=False, interaction="", reference_sentinel=""):
        import fcntl
        import pty
        import psutil
        import re
        import select
        import struct
        import termios
        import time
        from lifecycle import Child
        with tempfile.TemporaryDirectory(prefix="hermes-test-bootstrap-") as bootstrap:
            capture = Path(bootstrap, "wire.jsonl")
            rpc_capture = Path(bootstrap, "rpc.jsonl")
            replies = Path(str(rpc_capture) + ".responses")
            errors = Path(str(rpc_capture) + ".errors")
            write_bootstrap(bootstrap)
            environment = {
                **self.fixture_environment(bootstrap, capture, "tui"),
                "HERMES_RUNTIME_CAPTURE_RPC": str(rpc_capture), "TERM": "xterm-256color",
                "HERMES_RUNTIME_TUI_SCENARIO": interaction,
            }
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
            process = subprocess.Popen(
                ["/usr/local/bin/node", "/opt/hermes/ui-tui/dist/entry.js"],
                stdin=slave, stdout=slave, stderr=slave, env=environment, cwd="/mnt/data",
                start_new_session=True,
            )
            os.close(slave)
            child = Child("test-tui", process)
            output = bytearray()
            frames = []
            responses = []
            main = []

            def records(path):
                if not path.exists():
                    return []
                return [json.loads(line) for line in path.read_text().rsplit("\n", 1)[0].splitlines()]

            def pump_until(predicate, timeout=20):
                nonlocal frames, responses, main
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    child.capture()
                    if select.select([master], [], [], 0.05)[0]:
                        try:
                            output.extend(os.read(master, 65536))
                        except OSError:
                            self.assertIsNotNone(process.poll(), "PTY failed while native TUI was still live")
                    frames = records(rpc_capture)
                    responses = records(replies)
                    main = [record for record in records(capture) if record["tools"] is not None]
                    if predicate():
                        return
                    if process.poll() is not None:
                        break
                self.fail((errors.read_text()[-4000:] if errors.exists() else "")
                          + json.dumps(responses[-8:])[-7000:] + output[-5000:].decode(errors="replace"))

            def submit(text):
                os.write(master, text.encode())
                time.sleep(0.6)
                os.write(master, b"\r")

            def methods(method):
                return [frame for frame in frames if frame.get("method") == method]

            def results(method):
                return [frame for frame in responses if frame.get("request_method") == method and "result" in frame]

            def terminal_fragments(start=0):
                # Ink emits cursor moves in place of some spaces in a retained frame.
                text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output[start:].decode(errors="replace"))
                return re.sub(r"\s+", "", text)

            try:
                pump_until(lambda: bool(results("session.create")), timeout=45)
                time.sleep(0.3)
                if interaction == "completion-resize":
                    import signal
                    action_output_start = len(output)
                    for method, text in (
                        ("complete.slash", "/co"),
                        ("complete.slash", "/co " + "x" * 300),
                        ("complete.path", "see https://example.com/x and/or ./" + "x" * 300),
                    ):
                        previous = len(results(method))
                        os.write(master, text.encode())
                        pump_until(lambda: len(results(method)) > previous)
                        os.write(master, b"\t\x15")
                    for cols in (19, 501, 100):
                        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 40, cols, 0, 0))
                        process.send_signal(signal.SIGWINCH)
                        pump_until(lambda: any(frame["result"].get("cols") == cols
                                               for frame in results("terminal.resize")))
                    for method in ("complete.path", "complete.slash"):
                        self.assertTrue(all(frame["result"] == {"items": []} for frame in results(method)))
                    self.assertTrue(any(len(frame["params"]["text"]) > 256 for frame in methods("complete.slash")))
                    self.assertTrue(any(len(frame["params"]["word"]) > 256 for frame in methods("complete.path")))
                    self.assertEqual(records(capture), [], "completion or resize invoked a model")
                    self.assertFalse(any(
                        frame.get("request_method") in {"complete.path", "complete.slash", "terminal.resize"}
                        and "error" in frame for frame in responses
                    ))
                    self.assertNotIn("completionunavailable", terminal_fragments(action_output_start))
                    self.assertNotIn("error:Unsupported", terminal_fragments(action_output_start))
                if interaction == "context-reference":
                    submit("summarise @file:secrets/google/credentials.json")
                    pump_until(lambda: "ContextreferencesaredisabledinmanagedSandboxmode." in terminal_fragments())
                    self.assertEqual(records(capture), [], "reference refusal invoked a model")
                    self.assertNotIn(reference_sentinel.encode(), output)
                    self.assert_no_external_attempts(capture)
                submit("Offline long streaming prompt" if interaction == "interrupt" else "Offline native TUI P4 prompt")
                pump_until(lambda: bool(main))
                distinct = {json.dumps([frame.get("method"), frame.get("params")], sort_keys=True): frame for frame in frames}
                print("P4_TUI_RPC_FRAMES=" + json.dumps(list(distinct.values()), sort_keys=True))
                if interaction.startswith("clarify-"):
                    pump_until(lambda: any(frame.get("method") == "clarify" for frame in responses)
                               and b"Pick a color" in output)
                    question = next(frame for frame in responses if frame.get("method") == "clarify")
                    os.write(master, b"\r")
                    if interaction == "clarify-batch":
                        pump_until(lambda: any(frame["result"].get("remaining") == ["q1"]
                                               for frame in results("clarify.lock")))
                        self.assertFalse(any(record["tool_results"] for record in main), "batch settled before second answer")
                        time.sleep(0.3)
                        os.write(master, b"\r")
                        pump_until(lambda: any(frame["result"].get("remaining") == []
                                               for frame in results("clarify.lock")))
                        self.assertEqual([frame["params"]["question_id"] for frame in methods("clarify.lock")], ["q0", "q1"])
                    else:
                        pump_until(lambda: any(frame.get("id") == question["id"] and "result" in frame for frame in frames))
                    pump_until(lambda: any(record["tool_results"] for record in main))
                    tool_result = json.loads(next(record["tool_results"][-1] for record in main if record["tool_results"]))
                    if interaction == "clarify-batch":
                        self.assertEqual([item["user_response"] for item in tool_result["responses"]], ["Blue", "Round"])
                    else:
                        self.assertEqual(tool_result["user_response"], "Blue")
                    print("P4_TUI_CLARIFY=" + json.dumps({"scenario": interaction, "result": tool_result}))
                elif interaction == "interrupt":
                    pump_until(lambda: b"Offline stream running" in output)
                    interrupted_at = time.monotonic()
                    os.write(master, b"\x03")
                    pump_until(lambda: bool(results("session.interrupt")))
                    self.assertEqual(results("session.interrupt")[-1]["result"]["status"], "interrupted")
                    stream = Path(str(capture) + ".stream")
                    pump_until(lambda: any(record["event"] == "closed" for record in records(stream)), timeout=8)
                    elapsed = records(stream)[-1]["time"] - interrupted_at
                    self.assertLess(elapsed, 8)
                    submit("Offline after interrupt")
                    pump_until(lambda: any(record.get("user_prompt") == "Offline after interrupt" for record in main)
                               and b"Offline P4 response" in output)
                    self.assertIsNone(process.poll())
                    print("P4_TUI_INTERRUPT=" + json.dumps({"stream_closed_seconds": round(elapsed, 3), "next_prompt": True}))
                if context_command:
                    pump_until(lambda: b"Offline P4 response" in output)
                    before = {item.pid: item.create_time() for item in psutil.Process(process.pid).children(recursive=True)}
                    submit("/context")
                    pump_until(lambda: bool(results("slash.exec")))
                    context_output = results("slash.exec")[-1]["result"]["output"]
                    self.assertIn("Conversation: 2 messages", context_output)
                    self.assertIn("Provider: azure-foundry", context_output)
                    self.assertNotIn("No active agent", context_output)
                    pump_until(lambda: "Conversation:2messages" in terminal_fragments())
                    tree = [psutil.Process(process.pid), *psutil.Process(process.pid).children(recursive=True)]
                    owned = {item.pid: item.create_time() for item in tree}
                    self.assertEqual({pid: identity for pid, identity in owned.items() if pid != process.pid}, before)
                    self.assertFalse(any("tui_gateway.slash_worker" in item.cmdline() for item in tree))
                    self.assertEqual(len(main), 1, "read-only context triggered another provider request")
                    rss = sum(item.memory_info().rss for item in tree)
                    self.assertLess(rss, 4 * 1024 ** 3)
                    print("P4_TUI_CONTEXT_RESOURCES=" + json.dumps({
                        "google_enabled": self.runtime["google"]["enabled"], "extra_workers": 0,
                        "runtime_tree_processes": len(owned), "runtime_tree_rss_bytes": rss,
                        "context": context_output,
                    }))
                    self.assert_no_external_attempts(capture)
                    os.write(master, b"\x1b")
                    time.sleep(0.3)
                    previous_sid = results("session.create")[0]["result"]["session_id"]
                    submit("/new")
                    pump_until(lambda: "Startanewsession?" in terminal_fragments())
                    os.write(master, b"y")
                    pump_until(lambda: bool(results("session.close")) and len(results("session.create")) == 2, timeout=15)
                    self.assertTrue(results("session.close")[-1]["result"]["closed"])
                    self.assertNotEqual(results("session.create")[-1]["result"]["session_id"], previous_sid)
                    print("P4_TUI_CONTEXT_SESSION_TEARDOWN=passed")
                for record in main:
                    self.assertEqual(set(record["tools"]), self.expected_tools())
                    self.assertEqual(len(record["tools"]), len(self.expected_tools()))
                    self.assertTrue(record["test_bearer"])
                self.assertTrue(any(
                    response.get("request_method") == "input.detect_drop"
                    and response.get("error", {}).get("code") == 4030
                    for response in responses
                ), "native attachment discovery was not explicitly rejected")
                self.assert_no_external_attempts(capture)
                if reference_sentinel:
                    pump_until(lambda: b"Offline P4 response" in output)
                    self.assertNotIn(reference_sentinel.encode(), output)
                    self.assertNotIn(reference_sentinel, capture.read_text())
            finally:
                child.stop(timeout=5)
                os.close(master)
            self.assert_no_external_attempts(capture)


if __name__ == "__main__":
    unittest.main()
