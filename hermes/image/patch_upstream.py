"""Build-only, exact-source patches for the pinned managed Sandbox image."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import textwrap

FINGERPRINTS = {
    "model_tools.py": "5d5a947d84f31f1ba4ef5267e28154b819e8f957a0b378739696f1ac305e1509",
    "tools/registry.py": "1dd185b85dee4e578905273668369efc3abd8ce6d55abf8fa3d133393cb9dedc",
    "run_agent.py": "244da863d3c21591a3b5326dc14c2962d4e31131dda52df628502cd9fcbfea33",
    "agent/chat_completion_helpers.py": "72400c39a7999d617fed99329ec9ea1ed891dc46e5e3349079f1a026f29122a0",
    "agent/auxiliary_client.py": "e83807074f3577ac3980f43bfd578ffcc95efb591e38a9427d0e7d33ec7d8e4a",
    "agent/models_dev.py": "b59ee0eae86e08eb57260fba231959ad40de1fc9c71f72f4895216c113138062",
    "agent/model_metadata.py": "b93bcdb69c2c182178fcc82eb618df72fe40fce28a900e1e276760858d8c5643",
    "agent/context_references.py": "c905f30e6adbc47063b039af44c22b637cca76ed79b08c49a82a3bfecee6e413",
    "cli.py": "267c7566b53c079b9f9c69794231d4f8e5907939f6167a2f96e4cff671c18b25",
    "hermes_cli/bang_shell.py": "d1422f9694cbaef736842bbdbf236857821a1312b4dd8f8b6d95e668d687b741",
    "hermes_cli/gateway_multiplex_mode.py": "d61d2a27d92fa70a113f80ab248991f3ae363f66bcec940ea3f581305cd608de",
    "hermes_cli/web_server.py": "dd095ecfe0a8a1dcc9148c170e96efd8eb9a5ce9a3de68d905f0d61024b144a0",
    "hermes_cli/web_server_dashboard.py": "4265a820f10112b0779a97bbb722a43950c4be4ef080999d5d477579b652db98",
    "hermes_cli/main_platform_setup.py": "92a9d1dcbbd4ddd5c93b019118ade63d3aeb92e57ade7a38508c0d00fc4977d9",
    "hermes_cli/cli_modal_mixin.py": "4c065b5816bd1584a169c59877b97a3d24b2aa9eeefa959dc6f3a5ea7efabf17",
    "hermes_cli/cli_tui_mixin.py": "9cdbe471c0121ec08f76769108537f82d5a81094501ff4ba164302c7dff426a9",
    "hermes_cli/cli_single_query.py": "6baa1f802c4709f7cf66b5841dd9bd23a5be2407743730480830de7a3a26bd5c",
    "hermes_cli/web_routers/messaging.py": "e142bb155379791595e2c72d366211f93cf0d4cea97dd3801bc33bcdec3ee6f9",
    "tui_gateway/methods_tools.py": "53cb2d126a2d998e66603613964fa98bc9b8d835d41502a9eaf0e10e79a6fc96",
    "tui_gateway/methods_prompt.py": "c3b31b794542410fa39fd27b0433b5d9b7e1ca04a6c33fc2781378f87213b507",
    "tui_gateway/methods_slash.py": "489a955790e92b9f3b99379a621ec43b381b125cedebc2f91c4be0509617386a",
    "tui_gateway/methods_config.py": "8143eb959c6abdaba3743c89a196f6352ec83def5088a1ef02f49bb5532229fb",
    "tui_gateway/methods_complete.py": "cfc54f7dbe740041ad7ca454bfb031c2363d294845ed6aa68c669eaa0e750d3b",
    "tui_gateway/methods_session.py": "6510098165745c41f92a53cbe35ec7bbf8cbbf6623ffc535f46e960b5a320623",
    "tui_gateway/server.py": "164ad8a1b43671c2a47829502f9a40f4355fc8060f2f6c2506b8aec44f1c0a51",
    "tui_gateway/rpc_dispatch.py": "0a3119156f29273a98d6159468a5f7c18289b981d867692c7f5b61c92883c985",
    "tui_gateway/server_requests.py": "a3a58ed22cba8b9228d2b35eabb46e6bdc90b09630277ccc102cad9ad4c464fa",
    "gateway/run.py": "324f7095223816b865dd68a75dc83bfd1c3d101ac8c1c38dba69026dab2b6af1",
    "gateway/run_inbound.py": "6089acbd0302316a89a3b289e9f0f314f2736f9cdd580e2c2481ab12152239ef",
    "plugins/platforms/whatsapp/adapter.py": "e38142c524db1ac71bb91fc81051df8dc7a9eb61daf1e40541d9da95ebe5d9f0",
    "scripts/whatsapp-bridge/bridge.js": "ea12266d0900294e9ccb98b35cc4a7204e8dbb7e50d975268f39c13a9bbe47b7",
    "gateway/platforms/whatsapp_common.py": "3ad51b589a4355716cafa057a6f951b669ba2cc43134fd0204f36042327a19ac",
    "ui-tui/src/lib/editor.ts": "74e81b90b516a05034a4a2fbbb9f92a339b10de48892a587e377a89e32187368",
    "ui-tui/src/lib/externalCli.ts": "790c524f35fa65124a98deb6bea64865942f752766da86b37fcc5b49ab9e8dff",
    "ui-tui/src/app/useComposerState.ts": "af18af323150abe9666ec132314b9207b737c584b8024bb64cefafcb05690303",
}


class Patcher:
    def __init__(self, root: Path):
        self.root = root
        self.sources = {}
        for name, expected in FINGERPRINTS.items():
            content = (root / name).read_bytes()
            if hashlib.sha256(content).hexdigest() != expected:
                raise RuntimeError(f"upstream source mismatch: {name}; review the exact image pin")
            self.sources[name] = content.decode()

    def replace(self, name: str, old: str, new: str) -> None:
        source = self.sources[name]
        if source.count(old) != 1:
            raise RuntimeError(f"non-unique image patch anchor: {name}")
        self.sources[name] = source.replace(old, new, 1)

    def function(self, name: str, function: str, body: str, *, replace: bool = False,
                 decorator: str | None = None) -> None:
        source = self.sources[name]
        nodes = [node for node in ast.walk(ast.parse(source))
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function
                 and (decorator is None or any(decorator in ast.unparse(d) for d in node.decorator_list))]
        if len(nodes) != 1:
            raise RuntimeError(f"non-unique image function patch: {name}:{function}")
        node = nodes[0]
        first = node.body[0]
        docstring = isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str)
        start = first.end_lineno if docstring else first.lineno - 1
        end = node.end_lineno if replace else start
        lines = source.splitlines(keepends=True)
        lines[start:end] = [textwrap.indent(textwrap.dedent(body).strip() + "\n", " " * (node.col_offset + 4))]
        self.sources[name] = "".join(lines)

    def write(self) -> None:
        for name, source in self.sources.items():
            if name.endswith(".py"):
                compile(source, name, "exec")
        for name, source in self.sources.items():
            (self.root / name).write_text(source)
        for name in self.sources:
            if name.endswith((".js", ".mjs")):
                subprocess.run(["node", "--check", str(self.root / name)], check=True)


def patch(root: Path, support: Path) -> None:
    p = Patcher(root)
    p.function("model_tools.py", "get_tool_definitions", """
        from managed_policy import select_tools
        enabled_toolsets = select_tools(enabled_toolsets)
    """)
    p.function("model_tools.py", "handle_function_call", """
        from managed_policy import check_tool_name
        check_tool_name(function_name)
    """)
    p.function("tools/registry.py", "dispatch", """
        from managed_policy import check_tool_name
        check_tool_name(name)
    """)
    p.replace("run_agent.py",
              '        init_kwargs = {k: v for k, v in locals().items() if k not in ("self", "tool_delay")}',
              '        init_kwargs = {k: v for k, v in locals().items() if k not in ("self", "tool_delay")}\n'
              '        from managed_policy import agent_parameters\n        agent_parameters(init_kwargs)')
    p.replace("run_agent.py", "        init_agent(self, **init_kwargs)",
              "        init_agent(self, **init_kwargs)\n        from managed_policy import check_schemas\n"
              "        check_schemas(self.tools)")
    p.function("agent/chat_completion_helpers.py", "build_api_kwargs", """
        from managed_policy import before_request
        before_request(agent, tools_for_api)
    """)
    p.function("agent/auxiliary_client.py", "resolve_provider_client", """
        from managed_policy import auxiliary_route
        provider, model, explicit_base_url, api_mode = auxiliary_route(
            provider, model, explicit_base_url, explicit_api_key, api_mode)
    """)
    p.function("agent/models_dev.py", "fetch_models_dev", "allow_network = False")
    p.function("agent/models_dev.py", "_start_background_refresh_models_dev", "return", replace=True)
    p.function("agent/model_metadata.py", "fetch_endpoint_model_metadata", """
        logger.debug("Remote model catalogs are disabled in managed Sandbox mode")
        return {}
    """, replace=True)
    p.function("agent/model_metadata.py", "get_model_context_length", """
        from managed_policy import auxiliary_route, checked_runtime
        auxiliary_route(provider or None, model or None, base_url or None, None, None)
        return checked_runtime()["foundry"]["context_length"]
    """, replace=True)
    p.function("agent/context_references.py", "preprocess_context_references_async", """
        refs = parse_context_references(message)
        if not refs:
            return ContextReferenceResult(message=message, original_message=message)
        return ContextReferenceResult(
            message=message, original_message=message, references=refs, blocked=True,
            warnings=["Context references are disabled in managed Sandbox mode."],
        )
    """, replace=True)
    p.function("hermes_cli/gateway_multiplex_mode.py", "resolve_multiplex_mode", """
        from managed_policy import standalone
        return standalone(config)
    """, replace=True)
    p.function("cli.py", "process_command", """
        from managed_policy import COMMAND_DENIED, command_allowed
        if not command_allowed(command):
            self._console_print(COMMAND_DENIED)
            return True
    """)
    p.function("hermes_cli/bang_shell.py", "bang_shell_enabled", "return False", replace=True)
    p.function("hermes_cli/bang_shell.py", "run_bang_command", """
        (writer or print)("Shell execution is disabled in managed Sandbox mode.")
        return 126
    """, replace=True)
    p.function("hermes_cli/cli_modal_mixin.py", "_open_external_editor", """
        self._console_print("External editors are disabled in managed Sandbox mode.")
        return False
    """, replace=True)
    p.function("hermes_cli/cli_tui_mixin.py", "_tui_handle_ctrl_z", """
        self._console_print("Process suspension is disabled in managed Sandbox mode.")
    """, replace=True)
    p.replace("hermes_cli/cli_single_query.py", """            if cli._ensure_runtime_credentials():
                effective_query: Any = _route_single_query_images(""", """            from agent.context_references import preprocess_context_references
            context = preprocess_context_references(query or "", cwd=os.getcwd(), context_length=0)
            if context.blocked:
                message = "\\n".join(context.warnings)
                if emitter is not None:
                    emitter.emit_result({"failed": True, "error": message},
                                        session_id=cli.session_id or "", exit_code=2)
                else:
                    print("Error: " + message, file=sys.stderr)
                exit_single_query(2)
            if cli._ensure_runtime_credentials():
                effective_query: Any = _route_single_query_images(""")
    p.replace("ui-tui/src/lib/editor.ts",
              "export async function openInEditor(initial: string, suffix = '.txt'): Promise<null | string> {",
              "export async function openInEditor(initial: string, suffix = '.txt'): Promise<null | string> {\n"
              "  process.stderr.write('External editors are disabled in managed Sandbox mode.\\n'.replace('\\n', '\\r\\n'))\n"
              "  return null\n")
    p.replace("ui-tui/src/app/useComposerState.ts",
              "  const openEditor = useCallback(async () => {",
              "  const openEditor = useCallback(async () => {\n"
              "    sys('External editors are disabled in managed Sandbox mode.')\n    return\n")
    p.sources["ui-tui/src/lib/externalCli.ts"] = """export interface LaunchResult {
  code: null | number
  error?: string
}

export const launchHermesCommand = async (_args: string[]): Promise<LaunchResult> => ({
  code: 126,
  error: 'External commands are disabled in managed Sandbox mode; use control.py for maintenance.',
})
"""
    p.function("tui_gateway/methods_tools.py", "_", """
        from managed_policy import COMMAND_DENIED, command_allowed
        if not command_allowed(str(params.get("name", "")) + " " + str(params.get("arg", ""))):
            return _err(rid, 4030, COMMAND_DENIED)
    """, decorator="command.dispatch")
    p.function("tui_gateway/methods_tools.py", "_", """
        from managed_policy import COMMAND_DENIED, command_allowed
        if not command_allowed(params.get("command", "")):
            return _err(rid, 4030, COMMAND_DENIED)
    """, decorator="slash.exec")
    p.replace("tui_gateway/methods_slash.py",
              '_ISOLATED_SESSION_READ_COMMANDS = frozenset({"context", "tools", "help"})',
              '_ISOLATED_SESSION_READ_COMMANDS = frozenset({"tools", "help"})')
    p.replace("tui_gateway/methods_slash.py",
              'lines.append(f"Provider: {mirror.get(\'provider\') or \'auto\'}")',
              'lines.append(f"Provider: {mirror.get(\'provider\') or getattr(session.get(\'agent\'), \'provider\', \'\') or \'auto\'}")')
    for rpc in ("shell.exec", "cli.exec"):
        p.function("tui_gateway/methods_tools.py", "_", """
            from managed_policy import COMMAND_DENIED
            return _err(rid, 4030, COMMAND_DENIED)
        """, replace=True, decorator=rpc)
    for rpc in ("complete.path", "complete.slash"):
        p.function("tui_gateway/methods_complete.py", "_", """
            return _ok(rid, {"items": []})
        """, replace=True, decorator=rpc)
    p.function("tui_gateway/server.py", "_prepend_tool_paths", """
        from managed_policy import checked_runtime
        checked_runtime()
        return dict(env)
    """, replace=True)
    p.function("tui_gateway/server.py", "_load_enabled_toolsets", """
        from managed_policy import select_tools
        explicit = [item.strip() for item in os.environ.get("HERMES_TUI_TOOLSETS", "").split(",") if item.strip()]
        return select_tools(explicit or None)
    """, replace=True)
    p.function("tui_gateway/methods_config.py", "_", """
        if params.get("key") == "full":
            from managed_policy import ui_config
            return _ok(rid, {"config": ui_config()})
    """, decorator="config.get")
    p.replace("tui_gateway/methods_session.py", """    return _ok(rid, {"events": frames, "latest_seq": er.latest_seq(sid), "truncated": er.is_truncated(sid, last_seen),
                     "count": len(frames), "epoch": er.replay_epoch(), "open_requests": _open_requests(sid)})""",
              """    from managed_policy import replay_reply
    return replay_reply(rid, {"events": frames, "latest_seq": er.latest_seq(sid), "truncated": er.is_truncated(sid, last_seen),
                             "count": len(frames), "epoch": er.replay_epoch(), "open_requests": _open_requests(sid)})""")
    p.function("tui_gateway/rpc_dispatch.py", "_handle_admitted_request", """
        from managed_policy import check_rpc
        from runtime import PolicyError
        try:
            check_rpc(req)
        except PolicyError as exc:
            return _err(req.get("id"), 4030, str(exc))
    """)
    p.replace("tui_gateway/rpc_dispatch.py",
              "if not server_requests.resolve_response(req) and not _relay_compute_host_response(req):",
              "if not server_requests.resolve_response(req):")
    p.replace("tui_gateway/server_requests.py", "_open: dict[str, ServerRequest] = {}", """_open: dict[str, ServerRequest] = {}
_managed_retired_clarifications: dict[str, tuple[str, tuple[str, ...]]] = {}


def _managed_pop_request(request_id: str) -> ServerRequest | None:
    # Every caller holds the native pending-request lock; retirement is atomic with removal.
    req = _open.pop(request_id, None)
    if req is not None and req.method == "clarify" and req.qids is not None:
        _managed_retired_clarifications[request_id] = (req.sid, tuple(req.qids))
        if len(_managed_retired_clarifications) > 128:
            del _managed_retired_clarifications[next(iter(_managed_retired_clarifications))]
    return req""")
    for old, new in (
        ("still_open = _open.pop(req.id, None) is req", "still_open = _managed_pop_request(req.id) is req"),
        ("timed_out = _open.pop(req.id, None) is req", "timed_out = _managed_pop_request(req.id) is req"),
        ("still_open = _open.pop(req.id, None) is not None", "still_open = _managed_pop_request(req.id) is not None"),
        ("            _open.pop(request_id, None)", "            _managed_pop_request(request_id)"),
        ("            _open.pop(req.id, None)", "            _managed_pop_request(req.id)"),
        ("        _open.clear()", "        _open.clear()\n        _managed_retired_clarifications.clear()"),
    ):
        p.replace("tui_gateway/server_requests.py", old, new)
    p.function("tui_gateway/server_requests.py", "resolve_response", """
        from managed_policy import check_rpc_response, session_transport_matches
        from runtime import PolicyError
        try:
            check_rpc_response(frame)
        except PolicyError:
            logger.warning("Managed mode denied a server-request response")
            return False
    """)
    p.replace("tui_gateway/server_requests.py", "        _open.pop(rid, None)",
              """        result = frame.get("result", {})
        matching_shape = "error" in frame or (
            req.qids is None and set(result) == {"answer"}
            or req.qids is not None and (
                set(result) == {"answer"} and result["answer"] == ""
                or set(result) == {"answers"} and set(result["answers"]) <= set(req.qids)
            )
        )
        if req.method != "clarify" or not matching_shape or not session_transport_matches(req.sid):
            logger.warning("Managed mode denied an unrelated clarification response")
            return False
        _managed_pop_request(rid)""")
    p.function("tui_gateway/server_requests.py", "lock_answer", """
        from managed_policy import session_transport_matches
    """)
    p.replace("tui_gateway/server_requests.py",
              "        if req is None or req.qids is None:\n            return None",
              """        if req is None:
            retired = _managed_retired_clarifications.get(request_id)
            if retired is not None and question_id in retired[1] and session_transport_matches(retired[0]):
                logger.debug("Managed mode ignored a stale clarification lock")
            else:
                logger.warning("Managed mode denied an unrelated clarification lock")
            return None
        if (req.method != "clarify" or req.qids is None
                or not session_transport_matches(req.sid)):
            logger.warning("Managed mode denied an unrelated clarification lock")
            return None""")
    p.replace("tui_gateway/methods_prompt.py",
              """    if (proxied := _lock_compute_host_clarify(rid, request_id, question_id, answer)) is not None:
        return proxied
""", "")
    p.replace("gateway/run_inbound.py", "        event, source, is_internal = _admitted",
              "        event, source, is_internal = _admitted\n"
              "        from managed_policy import COMMAND_DENIED, command_allowed, checked_runtime\n"
              "        checked_runtime()\n"
              "        if event.is_command() and not command_allowed(event.text):\n"
              "            return COMMAND_DENIED")
    p.function("gateway/run.py", "start_gateway", """
        from managed_policy import gateway_start
        gateway_start(replace=replace, force=force)
    """)
    p.function("gateway/run.py", "_start_gateway_start_cron_and_housekeeping", """
        cron_stop = threading.Event()
        housekeeping_thread = threading.Thread(
            target=_start_gateway_housekeeping, args=(cron_stop,),
            kwargs={"adapters": runner.adapters, "loop": asyncio.get_running_loop(), "runner": runner},
            daemon=True, name="gateway-housekeeping")
        housekeeping_thread.start()
        return cron_stop, None, None, housekeeping_thread
    """, replace=True)
    p.function("gateway/run.py", "_stop_cron_provider", """
        if provider is None:
            return
    """)
    p.function("gateway/run.py", "_start_gateway_start_control_socket", """
        # The managed supervisor owns lifecycle; native mutation verbs are unavailable.
        return None
    """, replace=True)
    p.replace("hermes_cli/web_server.py", 'log_level="warning",', 'log_level="warning", access_log=False,')
    p.replace("hermes_cli/web_server.py", "mount_spa(app)",
              "mount_spa(app)\nfrom access_proxy import validate_registered_routes\nvalidate_registered_routes(app)")
    p.function("hermes_cli/web_server_dashboard.py", "_discover_dashboard_plugins", "return []", replace=True)
    p.function("hermes_cli/web_server_dashboard.py", "_mount_plugin_api_routes", "return", replace=True)
    for name, function in (
        ("hermes_cli/main_platform_setup.py", "cmd_whatsapp"),
        ("hermes_cli/main_platform_setup.py", "cmd_whatsapp_cloud"),
        ("hermes_cli/web_routers/messaging.py", "start_whatsapp_onboarding"),
        ("hermes_cli/web_routers/messaging.py", "apply_whatsapp_onboarding"),
        ("hermes_cli/web_routers/messaging.py", "cancel_whatsapp_onboarding"),
    ):
        p.function(name, function, """
            from runtime import PolicyError
            raise PolicyError("Use control.py pair in an approved interactive terminal; managed mode has no onboarding wizard")
        """, replace=True)
    p.function("gateway/platforms/whatsapp_common.py", "resolve_whatsapp_bridge_dir", """
        from adapter_policy import bridge_directory
        return bridge_directory()
    """, replace=True)
    adapter = "plugins/platforms/whatsapp/adapter.py"
    p.function(adapter, "_ensure_bridge_deps", """
        from adapter_policy import bridge_dependencies
        return bridge_dependencies(bridge_dir)
    """, replace=True)
    p.function(adapter, "_preflight", """
        from adapter_policy import preflight
        return preflight(self)
    """, replace=True)
    p.function(adapter, "connect", """
        from adapter_policy import connect
        return await connect(self, is_reconnect=is_reconnect)
    """, replace=True)
    p.function(adapter, "_terminate_bridge", """
        from adapter_policy import terminate
        terminate(self, force=force)
    """, replace=True)
    p.function(adapter, "_bridge_req", """
        from adapter_policy import bridge_headers
        kwargs["headers"] = {**kwargs.get("headers", {}), **bridge_headers(self)}
    """)
    p.replace(adapter, 'self._bridge_url("health"), timeout=aiohttp.ClientTimeout(total=2)',
              'self._bridge_url("health"), timeout=aiohttp.ClientTimeout(total=2), '
              'headers=__import__("adapter_policy").bridge_headers(self)')
    p.replace(adapter, 'self._set_fatal_error("whatsapp_bridge_exited", message, retryable=True)',
              'self._set_fatal_error("whatsapp_bridge_exited", message, retryable=False)')
    p.function(adapter, "send_clarify", """
        return await super().send_clarify(chat_id=chat_id, question=question, choices=choices,
                                         clarify_id=clarify_id, session_key=session_key, metadata=metadata)
    """, replace=True)
    for function in ("_send_media_to_bridge", "send_poll", "send_location", "send_image"):
        p.function(adapter, function, """
            return SendResult(success=False, error="Managed WhatsApp is text-only; media, polls and locations are disabled")
        """, replace=True)
    bridge = "scripts/whatsapp-bridge/bridge.js"
    p.replace(bridge, "#!/usr/bin/env node\n",
              "#!/usr/bin/env node\nimport { createPolicy, installSafeConsole } from './managed-policy.mjs';\n")
    p.replace(bridge, "const MAX_MESSAGE_LENGTH = parseInt(process.env.WHATSAPP_MAX_MESSAGE_LENGTH || '4096', 10);", """
const managed = createPolicy({
  ownerPhone: process.env.HERMES_SANDBOX_OWNER_PHONE,
  mode: WHATSAPP_MODE, replyPrefix: REPLY_PREFIX, sessionDir: SESSION_DIR,
  pairOnly: PAIR_ONLY, pairJson: PAIR_JSON,
  interactive: process.env.HERMES_SANDBOX_PAIR_APPROVED === '1'
    && process.stdin.isTTY === true && process.stdout.isTTY === true,
  bridgeKey: process.env.HERMES_SANDBOX_BRIDGE_KEY,
});
installSafeConsole(managed);
managed.status('starting');
const MAX_MESSAGE_LENGTH = 4096 - REPLY_PREFIX.length;
""".strip())
    p.replace(bridge, "const getWAVersion = createVersionResolver(fetchLatestBaileysVersion);",
              "const getWAVersion = async () => undefined; // Use the locked Baileys bundled protocol version.")
    p.replace(bridge, "  return REPLY_PREFIX ? `${REPLY_PREFIX}${message}` : message;",
              "  if (typeof message !== 'string') throw new Error('Only text messages are permitted');\n"
              "  // The managed socket prefixes each chunk, not the unchunked input.\n"
              "  const content = message.startsWith(REPLY_PREFIX) ? message.slice(REPLY_PREFIX.length) : message;\n"
              "  if (!content) throw new Error('Only nonempty text messages are permitted');\n"
              "  return content;")
    p.replace(bridge, "sock.ev.on('creds.update', () => { saveCreds(); lidToPhone = buildLidMap(); });",
              "managed.wrapSocket(sock);\n"
              "  sock.ev.on('creds.update', async () => { await saveCreds(); lidToPhone = {}; });")
    p.replace(bridge, "sock.ev.on('connection.update', (update) => {",
              "sock.ev.on('connection.update', async (update) => {")
    p.replace(bridge, """    if (qr) {
      if (PAIR_JSON) {
        emitPairEvent({ event: 'qr', qr });
      } else {
        console.log('\\n📱 Scan this QR code with WhatsApp on your phone:\\n');
        qrcode.generate(qr, { small: true });
        console.log('\\nWaiting for scan...\\n');
      }
    }""", """    if (qr) {
      try { managed.qr(qr, qrcode.generate.bind(qrcode)); }
      catch { process.exit(78); }
    }""")
    p.replace(bridge, "      if (reason === DisconnectReason.loggedOut) {",
              "      if (reason === DisconnectReason.loggedOut) {\n        managed.status('loggedOut');")
    p.replace(bridge, "      connectionState = 'connected';",
              "      try { await managed.connected(sock); await saveCreds(); }\n"
              "      catch { process.exit(78); return; }\n      connectionState = 'connected';")
    p.replace(bridge, "  sock.ev.on('messages.update', async (updates) => {",
              "  sock.ev.on('messages.update', async (updates) => {\n    return; // Poll/media updates are not a text message.")
    p.replace(bridge, "    for (const msg of messages) {",
              "    for (const msg of messages) {\n      if (!managed.acceptsInbound(msg)) continue;")
    p.replace(bridge, "const event = await extractBridgeEvent({\n        msg,",
              "const event = await extractBridgeEvent({\n        msg: managed.textMessage(msg),")
    p.replace(bridge, "      event.fromOwner = fromOwner;",
              "      event.fromOwner = fromOwner;\n      event.senderName = 'Owner';\n"
              "      event.chatName = 'Self';")
    p.replace(bridge, "app.use(express.json());",
              "app.use(express.json({ limit: '64kb' }));\napp.use(managed.middleware);")
    p.replace(bridge, "capabilities: { outboundMentions: true }", "capabilities: { outboundMentions: false }")
    # Pino's structured records can contain credential/contact objects.
    if p.sources[bridge].count("level: 'warn'") != 1:
        raise RuntimeError("non-unique Baileys logger anchor")
    p.replace(bridge, "level: 'warn'", "level: 'silent'")
    p.sources["scripts/whatsapp-bridge/managed-policy.mjs"] = (support / "bridge_policy.mjs").read_text()
    p.write()
    (support / "source-patch-manifest.json").write_text(json.dumps({
        "upstream": "645da6561c724b7ca163d4af9c21de3a6397c9f2",
        "files": {name: hashlib.sha256(content.encode()).hexdigest() for name, content in p.sources.items()},
    }, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    patch(Path(sys.argv[1]), Path(__file__).resolve().parent)
