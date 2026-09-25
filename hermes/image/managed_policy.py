"""Image-only guards, called at upstream selection, dispatch and model boundaries."""

from __future__ import annotations

import os
import json
from pathlib import Path

from runtime import (
    ALLOWED_TOOLSETS, BASE_TOOLS, BUNDLES, CONCRETE_TOOLSETS, HOME, MCP_TOOLS,
    PolicyError, REGISTRY_ONLY_TOOLSETS, SUPPORT, check_single_profile, managed_config, read_json,
    read_state, validate_profile,
)

COMMAND_DENIED = "Unsupported in managed Sandbox mode; use control.py for maintenance."
SAFE_COMMANDS = frozenset({
    "help", "clear", "new", "reset", "stop", "retry", "undo", "compress", "compact",
    "history", "sessions", "resume", "status", "context", "usage", "version", "quit", "exit",
})
MAX_RPC_BYTES = 1024 * 1024


def checked_runtime() -> dict:
    return validate_profile(environment=os.environ)


def check_rpc(frame: dict) -> None:
    from access_proxy import rpc_allowed
    checked_runtime()
    # The embedded backend serves native PTYs and the separately filtered Sidebar.
    if not (rpc_allowed(frame, surface="tui") or rpc_allowed(frame, surface="sidebar")):
        raise PolicyError(COMMAND_DENIED)
    if frame.get("method") in {"session.interrupt", "session.close", "terminal.resize"} and not session_transport_matches(
        frame["params"]["session_id"],
    ):
        raise PolicyError(COMMAND_DENIED)


def check_rpc_response(frame: dict) -> None:
    from access_proxy import rpc_response_allowed
    checked_runtime()
    if not rpc_response_allowed(frame, surface="tui"):
        raise PolicyError(COMMAND_DENIED)


def session_transport_matches(session_id: str) -> bool:
    from tui_gateway import server
    # Do not acquire the sessions lock while the native pending-request lock is held.
    return server._session_transport_contains(
        server._sessions.get(session_id), server.current_transport(),
    )


def ui_config() -> dict:
    runtime = checked_runtime()
    policy = read_json(HOME / "profile-policy.json")
    return managed_config(runtime, google_configured=policy["google_configured"])


def replay_reply(request_id, payload: dict) -> dict:
    """Retain the newest suffix and signal the native history-refetch path."""
    reply = {"jsonrpc": "2.0", "id": request_id, "result": dict(payload)}

    def fits() -> bool:
        # The proxy may re-encode with ASCII escapes; budget that larger envelope.
        return len(json.dumps(reply).encode("utf-8")) <= MAX_RPC_BYTES

    if fits():
        return reply
    events = payload["events"]
    result = reply["result"]
    result["truncated"] = True
    low, high = 0, len(events)
    while low < high:
        middle = (low + high) // 2
        result["events"] = events[middle:]
        result["count"] = len(events) - middle
        if fits():
            high = middle
        else:
            low = middle + 1
    result["events"] = events[low:]
    result["count"] = len(events) - low
    if fits():
        return reply
    # Never silently discard a pending clarification/approval to fit the frame.
    safe_id = request_id if isinstance(request_id, (int, str)) and len(str(request_id)) <= 128 else None
    return {"jsonrpc": "2.0", "id": safe_id, "error": {
        "code": 4130, "message": "Pending replay metadata exceeds the managed 1 MiB limit; stop the affected turn.",
    }}


def registry_contract() -> None:
    from toolsets import TOOLSETS
    from tools.registry import registry
    declared = set(TOOLSETS) - {"google_readonly", "mcp-google_readonly"}
    if declared != (CONCRETE_TOOLSETS - REGISTRY_ONLY_TOOLSETS) | BUNDLES:
        raise PolicyError("upstream toolset inventory changed; image review is required")
    actual = set(registry.get_tool_to_toolset_map().values())
    if actual - CONCRETE_TOOLSETS - BUNDLES - ALLOWED_TOOLSETS:
        raise PolicyError("unclassified toolset registered; image review is required")
    baseline = json.loads((SUPPORT / "tool-registry.json").read_text())
    for name, toolset in registry.get_tool_to_toolset_map().items():
        if name in MCP_TOOLS and toolset in {"google_readonly", "mcp-google_readonly"}:
            continue
        if baseline.get(name) != toolset:
            raise PolicyError("unclassified tool registered; image review is required")


def select_tools(enabled: list[str] | None) -> list[str]:
    checked_runtime()
    registry_contract()
    if enabled is not None and (not isinstance(enabled, (list, tuple))
                               or set(enabled) - ALLOWED_TOOLSETS - {"hermes-cli", "hermes-whatsapp"}):
        raise PolicyError("managed mode permits only memory, clarify and google_readonly toolsets")
    policy = read_json(HOME / "profile-policy.json")
    return ["memory", "clarify"] + (["mcp-google_readonly"] if policy["google_configured"] else [])


def allowed_names() -> frozenset[str]:
    from tools.registry import registry
    runtime = checked_runtime()
    registry_contract()
    available = set(registry.get_tool_to_toolset_map())
    configured = read_json(HOME / "profile-policy.json")["google_configured"]
    google = MCP_TOOLS & available if runtime["google"]["enabled"] and configured else frozenset()
    if google and google != MCP_TOOLS:
        raise PolicyError("Google registry must expose exactly the three approved tools")
    return BASE_TOOLS | google


def check_tool_name(name: str) -> None:
    if name not in allowed_names():
        raise PolicyError("tool execution denied by the image-managed capability policy")


def check_schemas(schemas: list | None, *, exact: bool = True) -> None:
    names = [schema.get("function", schema).get("name") for schema in (schemas or [])]
    expected = allowed_names()
    if len(names) != len(set(names)) or set(names) - expected or (exact and set(names) != expected):
        raise PolicyError("model-visible tools differ from the image-managed capability contract")


def agent_parameters(parameters: dict) -> None:
    runtime = checked_runtime()
    if parameters.get("platform") not in {None, "cli", "tui", "whatsapp"}:
        raise PolicyError("agent platform is disabled in this image")
    for key, expected in (
        ("provider", "azure-foundry"), ("requested_provider", "azure-foundry"),
        ("model", runtime["foundry"]["deployment"]), ("base_url", runtime["foundry"]["endpoint"]),
        ("api_mode", runtime["foundry"]["api_mode"]),
    ):
        supplied = parameters.get(key)
        if supplied and str(supplied).rstrip("/") != expected.rstrip("/"):
            raise PolicyError(f"managed model route override denied: {key}")
    if parameters.get("api_key") and not callable(parameters["api_key"]):
        raise PolicyError("static model credentials are forbidden; Managed Identity is required")
    if parameters.get("fallback_model") or parameters.get("credential_pool"):
        raise PolicyError("model fallback and credential pools are forbidden")
    if parameters.get("request_overrides") or parameters.get("acp_command") or parameters.get("command"):
        raise PolicyError("raw request overrides and external agent commands are forbidden")
    parameters["enabled_toolsets"] = select_tools(parameters.get("enabled_toolsets"))
    for key, value in (
        ("provider", "azure-foundry"), ("requested_provider", "azure-foundry"),
        ("model", runtime["foundry"]["deployment"]), ("base_url", runtime["foundry"]["endpoint"]),
        ("api_mode", runtime["foundry"]["api_mode"]),
        ("save_trajectories", False), ("verbose_logging", False),
        ("checkpoints_enabled", False), ("skip_background_review", True),
    ):
        parameters[key] = value


def before_request(agent, tools: list | None) -> None:
    agent_parameters({
        "platform": getattr(agent, "platform", None),
        "provider": getattr(agent, "provider", None),
        "model": getattr(agent, "model", None),
        "base_url": getattr(agent, "base_url", None),
        "api_mode": getattr(agent, "api_mode", None),
        "api_key": getattr(agent, "api_key", None),
        "request_overrides": getattr(agent, "request_overrides", None),
        "fallback_model": getattr(agent, "_fallback_chain", None),
        "credential_pool": getattr(agent, "_credential_pool", None),
        "enabled_toolsets": getattr(agent, "enabled_toolsets", None),
    })
    check_schemas(agent.tools if tools is None else tools)


def standalone(config):
    from hermes_cli.gateway_multiplex_mode import MultiplexDecision
    checked_runtime()
    check_single_profile(HOME)
    config.multiplex_profiles = False
    return MultiplexDecision(False, "guard", "image-managed single-profile sandbox")


def auxiliary_route(provider, model, base_url, api_key, api_mode):
    runtime = checked_runtime()
    expected = runtime["foundry"]
    if provider not in (None, "", "auto", "azure-foundry"):
        raise PolicyError("auxiliary fallback provider is forbidden")
    for actual, desired in ((model, expected["deployment"]), (base_url, expected["endpoint"]),
                            (api_mode, expected["api_mode"])):
        if actual and str(actual).rstrip("/") != desired.rstrip("/"):
            raise PolicyError("auxiliary model route override is forbidden")
    if api_key and not callable(api_key):
        raise PolicyError("static auxiliary credentials are forbidden")
    return "azure-foundry", expected["deployment"], expected["endpoint"], expected["api_mode"]


def command_allowed(command: str) -> bool:
    if not isinstance(command, str) or not command.strip():
        return False
    words = command.strip().split(None, 1)
    name = words[0].lstrip("/").lower()
    return name in SAFE_COMMANDS or (name == "memory" and len(words) == 1)


def gateway_start(*, replace: bool, force: bool) -> None:
    checked_runtime()
    if replace or force:
        raise PolicyError("gateway replacement/force is forbidden; use control.py")
    if read_state()["desired"] != "running":
        raise PolicyError("gateway is in persistent maintenance; use control.py start-gateway")
