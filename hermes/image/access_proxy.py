#!/usr/bin/env python3
"""Fixed-target, managed-mode HTTP/WebSocket transport for Hermes.

The local relay authenticates Azure outside the browser. The inner hop verifies
its rotating tmpfs key before sending anything to the loopback dashboard.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import hmac
import json
import logging
import os
import re
import secrets
import stat
from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp
from aiohttp import WSMsgType, web
from multidict import CIMultiDict

UPSTREAM_COMMIT = "645da6561c724b7ca163d4af9c21de3a6397c9f2"
KEY_PATH = Path("/dev/shm/hermes/access-key")
DASHBOARD_URL = "http://127.0.0.1:9119"
MAX_BODY = 10 * 1024 * 1024
MAX_FRAME = 1024 * 1024
# aiohttp 3.14.3 rejects declared payload sizes >= max_msg_size.
_READER_LIMIT = MAX_FRAME + 1
CHUNK = 64 * 1024
MAX_CONNECTIONS = 32
HEARTBEAT = 30
KEY_HEADER = "X-Hermes-Access-Key"
EXPIRED_HEADER = "X-Hermes-Access-Key-Expired"
RELAY_ORIGIN_HEADER = "X-Hermes-Relay-Origin"
RELAY_AUTHORITY_HEADER = "X-Hermes-Relay-Authority"
MANAGED_ERROR = "Managed mode: this operation is disabled. Use the owner CLI and control.py reconfigure."
LOG = logging.getLogger("hermes.access")
_STARTED_RESPONSE = web.RequestKey("hermes.response", web.StreamResponse)
_TARGET = re.compile(r"https://[a-z0-9][a-z0-9-]{1,127}--8080\.[a-z0-9]+\.adcproxy\.io\Z")
_LOCAL_ORIGIN = re.compile(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})\Z")
_SAFE_PATH = re.compile(r"/[A-Za-z0-9._/-]*\Z")
_ID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_SERVER_REQUEST_ID = re.compile(r"srq-[0-9a-f]{12}\Z")
_TUI_ID_PARAMS = {
    "session.control.read": "session_id", "subagent.list": "session_id",
    "process.list": "session_id", "session.active_list": "current_session_id",
    "session.interrupt": "session_id", "session.close": "session_id",
}
_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host",
}
_TRANSPORT_HEADERS = {
    "authorization", KEY_HEADER.lower(), EXPIRED_HEADER.lower(),
    RELAY_ORIGIN_HEADER.lower(), RELAY_AUTHORITY_HEADER.lower(),
}

# Every route is classified: these vetted reads plus the narrow session/WS
# policies below are allowed; all other pinned routes are explicitly managed.
READ_ROUTES = frozenset("""
/api/analytics/usage
/api/auth/me
/api/chat/workspaces
/api/dashboard/font
/api/dashboard/plugins
/api/dashboard/themes
/api/health
/api/memory
/api/model/info
/api/profiles
/api/profiles/active
/api/profiles/sessions
/api/profiles/sessions/sidebar
/api/sessions
/api/sessions/empty/count
/api/sessions/search
/api/sessions/stats
/api/sessions/{session_id}
/api/sessions/{session_id}/latest-descendant
/api/sessions/{session_id}/messages
/api/sessions/{session_id}/messages/around
/api/sessions/{session_id}/timeline
/api/status
/api/system/stats
""".split())

_PINNED_ROUTES = """
DELETE /api/credentials/pool/{provider}/{index}
DELETE /api/cron/jobs/{job_id}
DELETE /api/dashboard/agent-plugins/{name:path}
DELETE /api/env
DELETE /api/files
DELETE /api/learning/node
DELETE /api/local-models/models/{model_id}
DELETE /api/mcp/oauth/flows/{flow_id}
DELETE /api/mcp/servers/{name}
DELETE /api/messaging/telegram/onboarding/{pairing_id}
DELETE /api/messaging/whatsapp/onboarding/{pairing_id}
DELETE /api/ops/hooks
DELETE /api/profiles/{name}
DELETE /api/providers/custom-endpoints/{endpoint_id}
DELETE /api/providers/oauth/sessions/{session_id}
DELETE /api/providers/oauth/{provider_id}
DELETE /api/sessions/empty
DELETE /api/sessions/{session_id}
DELETE /api/webhooks/{name}
GET /api/actions/{name}/status
GET /api/analytics/models
GET /api/analytics/usage
GET /api/audio/elevenlabs/voices
GET /api/audio/voice-config
GET /api/audio/voice-live/status
GET /api/auth/me
GET /api/auth/providers
GET /api/chat/workspaces
GET /api/config
GET /api/config/defaults
GET /api/config/raw
GET /api/config/schema
GET /api/credentials/pool
GET /api/cron/blueprints
GET /api/cron/delivery-targets
GET /api/cron/jobs
GET /api/cron/jobs/{job_id}
GET /api/cron/jobs/{job_id}/runs
GET /api/curator
GET /api/dashboard/font
GET /api/dashboard/plugins
GET /api/dashboard/plugins/catalog
GET /api/dashboard/plugins/hub
GET /api/dashboard/plugins/rescan
GET /api/dashboard/themes
GET /api/egress/status
GET /api/env
GET /api/files
GET /api/files/download
GET /api/files/read
GET /api/files/stream
GET /api/fs/default-cwd
GET /api/fs/download
GET /api/fs/git-root
GET /api/fs/list
GET /api/fs/read-data-url
GET /api/fs/read-text
GET /api/gateway/migrate/plan
GET /api/git/base-branches
GET /api/git/branches
GET /api/git/file-diff
GET /api/git/gh-auth
GET /api/git/review/commit-context
GET /api/git/review/diff
GET /api/git/review/list
GET /api/git/review/rev-parse
GET /api/git/review/ship-info
GET /api/git/status
GET /api/git/worktrees
GET /api/health
GET /api/health/idle
GET /api/hermes/update/check
GET /api/hermes/update/receipt
GET /api/host/identity
GET /api/learning/graph
GET /api/learning/node
GET /api/local-models/catalog
GET /api/local-models/hardware
GET /api/local-models/jobs
GET /api/local-models/jobs/{job_id}
GET /api/local-models/search
GET /api/local-models/search/files
GET /api/local-models/status
GET /api/logs
GET /api/mcp/catalog
GET /api/mcp/oauth/callback/{server_name:path}
GET /api/mcp/oauth/flows/{flow_id}
GET /api/mcp/servers
GET /api/media
GET /api/memory
GET /api/memory/providers/{name}/config
GET /api/memory/providers/{provider}/oauth/status
GET /api/messaging/platforms
GET /api/messaging/telegram/onboarding/{pairing_id}
GET /api/messaging/whatsapp/onboarding/{pairing_id}
GET /api/model/auxiliary
GET /api/model/info
GET /api/model/moa
GET /api/model/options
GET /api/model/recommended-default
GET /api/ops/backup/download
GET /api/ops/checkpoints
GET /api/ops/hooks
GET /api/pairing
GET /api/portal
GET /api/profiles
GET /api/profiles/active
GET /api/profiles/projects/tree
GET /api/profiles/sessions
GET /api/profiles/sessions/sidebar
GET /api/profiles/{name}/desktop-overlay
GET /api/profiles/{name}/setup-command
GET /api/profiles/{name}/soul
GET /api/providers/custom-endpoints
GET /api/providers/oauth
GET /api/providers/oauth/{provider_id}/poll/{session_id}
GET /api/sessions
GET /api/sessions/empty/count
GET /api/sessions/search
GET /api/sessions/stats
GET /api/sessions/{session_id}
GET /api/sessions/{session_id}/export
GET /api/sessions/{session_id}/latest-descendant
GET /api/sessions/{session_id}/messages
GET /api/sessions/{session_id}/messages/around
GET /api/sessions/{session_id}/timeline
GET /api/skills
GET /api/skills/content
GET /api/skills/hub/official
GET /api/skills/hub/preview
GET /api/skills/hub/scan
GET /api/skills/hub/search
GET /api/skills/hub/sources
GET /api/ssh/ownership
GET /api/status
GET /api/system/stats
GET /api/tools/computer-use/status
GET /api/tools/terminal/backends
GET /api/tools/toolsets
GET /api/tools/toolsets/{name}/config
GET /api/tools/toolsets/{name}/models
GET /api/webhooks
GET /assets/{filename}.css
GET /auth/callback
GET /auth/login
GET /auth/native/authorize
GET /dashboard-plugins/{plugin_name}/{file_path:path}
GET /login
GET /{full_path:path}
HEAD /api/files/stream
PATCH /api/profiles/{name}
PATCH /api/sessions/{session_id}
POST /api/audio/speak
POST /api/audio/transcribe
POST /api/audio/tts-lease
POST /api/audio/voice-live/session
POST /api/auth/ws-ticket
POST /api/chat/image-upload
POST /api/credentials/pool
POST /api/cron/blueprints/instantiate
POST /api/cron/fire
POST /api/cron/jobs
POST /api/cron/jobs/{job_id}/pause
POST /api/cron/jobs/{job_id}/resume
POST /api/cron/jobs/{job_id}/trigger
POST /api/curator/run
POST /api/dashboard/agent-plugins/activate
POST /api/dashboard/agent-plugins/install
POST /api/dashboard/agent-plugins/{name:path}/disable
POST /api/dashboard/agent-plugins/{name:path}/enable
POST /api/dashboard/agent-plugins/{name:path}/update
POST /api/dashboard/plugins/{name:path}/visibility
POST /api/env/reveal
POST /api/files/mkdir
POST /api/files/upload
POST /api/files/upload-stream
POST /api/fs/write-text
POST /api/gateway/drain
POST /api/gateway/migrate
POST /api/gateway/restart
POST /api/gateway/start
POST /api/gateway/stop
POST /api/git/branch/switch
POST /api/git/review/commit
POST /api/git/review/create-pr
POST /api/git/review/pr-list
POST /api/git/review/push
POST /api/git/review/revert
POST /api/git/review/stage
POST /api/git/review/unstage
POST /api/git/worktree/add
POST /api/git/worktree/remove
POST /api/health/retirement
POST /api/hermes/update
POST /api/local-models/activate
POST /api/local-models/download
POST /api/local-models/download-browsed
POST /api/local-models/eject
POST /api/local-models/quickstart
POST /api/local-models/runtime/install
POST /api/local-models/server
POST /api/local-models/sideload
POST /api/mcp/catalog/install
POST /api/mcp/servers
POST /api/mcp/servers/{name}/auth
POST /api/mcp/servers/{name}/test
POST /api/memory/providers/{name}/setup
POST /api/memory/providers/{provider}/oauth/start
POST /api/memory/reset
POST /api/messaging/platforms/{platform_id}/test
POST /api/messaging/telegram/onboarding/start
POST /api/messaging/telegram/onboarding/{pairing_id}/apply
POST /api/messaging/whatsapp/onboarding/start
POST /api/messaging/whatsapp/onboarding/{pairing_id}/apply
POST /api/model/set
POST /api/ops/backup
POST /api/ops/checkpoints/prune
POST /api/ops/config-migrate
POST /api/ops/debug-share
POST /api/ops/doctor
POST /api/ops/dump
POST /api/ops/hooks
POST /api/ops/import
POST /api/ops/import-upload
POST /api/ops/prompt-size
POST /api/ops/security-audit
POST /api/pairing/approve
POST /api/pairing/clear-pending
POST /api/pairing/revoke
POST /api/profiles
POST /api/profiles/active
POST /api/profiles/import
POST /api/profiles/sessions/pull-requests
POST /api/profiles/{name}/describe-auto
POST /api/profiles/{name}/export
POST /api/profiles/{name}/open-terminal
POST /api/providers/custom-endpoints
POST /api/providers/custom-endpoints/validate
POST /api/providers/custom-endpoints/{endpoint_id}/activate
POST /api/providers/oauth/{provider_id}/start
POST /api/providers/oauth/{provider_id}/submit
POST /api/providers/validate
POST /api/sessions/bulk-delete
POST /api/sessions/import
POST /api/sessions/owner-backfill
POST /api/sessions/prune
POST /api/skills
POST /api/skills/hub/install
POST /api/skills/hub/uninstall
POST /api/skills/hub/update
POST /api/tools/computer-use/permissions/grant
POST /api/tools/toolsets/{name}/post-setup
POST /api/webhooks
POST /api/webhooks/enable
POST /auth/logout
POST /auth/native/refresh
POST /auth/native/token
POST /auth/password-login
PUT /api/config
PUT /api/config/raw
PUT /api/cron/jobs/{job_id}
PUT /api/curator/paused
PUT /api/dashboard/font
PUT /api/dashboard/plugin-providers
PUT /api/dashboard/theme
PUT /api/env
PUT /api/learning/node
PUT /api/mcp/servers
PUT /api/mcp/servers/{name}/enabled
PUT /api/memory/provider
PUT /api/memory/providers/{name}/config
PUT /api/messaging/platforms/{platform_id}
PUT /api/model/moa
PUT /api/profiles/{name}/description
PUT /api/profiles/{name}/model
PUT /api/profiles/{name}/soul
PUT /api/skills/content
PUT /api/skills/toggle
PUT /api/tools/terminal/backend
PUT /api/tools/toolsets/{name}
PUT /api/tools/toolsets/{name}/env
PUT /api/tools/toolsets/{name}/model
PUT /api/tools/toolsets/{name}/provider
PUT /api/webhooks/{name}/enabled
WEBSOCKET /api/audio/speak-stream
WEBSOCKET /api/console
WEBSOCKET /api/display/ws
WEBSOCKET /api/events
WEBSOCKET /api/pty
WEBSOCKET /api/pub
WEBSOCKET /api/ws
"""
_PINNED_ADDITIONAL_ROUTES = """
DELETE /api/plugins/kanban/attachments/{attachment_id}
DELETE /api/plugins/kanban/boards/{slug}
DELETE /api/plugins/kanban/links
DELETE /api/plugins/kanban/tasks/{task_id}
DELETE /api/plugins/kanban/tasks/{task_id}/home-subscribe/{platform}
GET /api/plugins/hermes-achievements/achievements
GET /api/plugins/hermes-achievements/recent-unlocks
GET /api/plugins/hermes-achievements/scan-status
GET /api/plugins/hermes-achievements/sessions/{session_id}/badges
GET /api/plugins/kanban/assignees
GET /api/plugins/kanban/attachments/{attachment_id}
GET /api/plugins/kanban/board
GET /api/plugins/kanban/boards
GET /api/plugins/kanban/config
GET /api/plugins/kanban/diagnostics
GET /api/plugins/kanban/home-channels
GET /api/plugins/kanban/model-options
GET /api/plugins/kanban/orchestration
GET /api/plugins/kanban/profiles
GET /api/plugins/kanban/projects
GET /api/plugins/kanban/runs/{run_id}
GET /api/plugins/kanban/runs/{run_id}/inspect
GET /api/plugins/kanban/stats
GET /api/plugins/kanban/tasks/{task_id}
GET /api/plugins/kanban/tasks/{task_id}/attachments
GET /api/plugins/kanban/tasks/{task_id}/log
GET /api/plugins/kanban/workers/active
GET /docs
GET /docs/oauth2-redirect
GET /openapi.json
GET /redoc
HEAD /docs
HEAD /docs/oauth2-redirect
HEAD /openapi.json
HEAD /redoc
MOUNT /assets
PATCH /api/plugins/kanban/boards/{slug}
PATCH /api/plugins/kanban/profiles/{profile_name}
PATCH /api/plugins/kanban/tasks/{task_id}
POST /api/plugins/hermes-achievements/rescan
POST /api/plugins/hermes-achievements/reset-state
POST /api/plugins/kanban/boards
POST /api/plugins/kanban/boards/import
POST /api/plugins/kanban/boards/{slug}/export
POST /api/plugins/kanban/boards/{slug}/switch
POST /api/plugins/kanban/dispatch
POST /api/plugins/kanban/estimate
POST /api/plugins/kanban/links
POST /api/plugins/kanban/profiles/{profile_name}/describe-auto
POST /api/plugins/kanban/runs/{run_id}/terminate
POST /api/plugins/kanban/tasks
POST /api/plugins/kanban/tasks/bulk
POST /api/plugins/kanban/tasks/{task_id}/attachments
POST /api/plugins/kanban/tasks/{task_id}/comments
POST /api/plugins/kanban/tasks/{task_id}/decompose
POST /api/plugins/kanban/tasks/{task_id}/estimate
POST /api/plugins/kanban/tasks/{task_id}/home-subscribe/{platform}
POST /api/plugins/kanban/tasks/{task_id}/reassign
POST /api/plugins/kanban/tasks/{task_id}/reclaim
POST /api/plugins/kanban/tasks/{task_id}/specify
PUT /api/plugins/kanban/orchestration
WEBSOCKET /api/plugins/kanban/events
"""
ROUTE_INVENTORY = frozenset(
    tuple(line.split(" ", 1))
    for line in (_PINNED_ROUTES + _PINNED_ADDITIONAL_ROUTES).strip().splitlines() if line
)
REGISTERED_ROUTE_INVENTORY = frozenset(
    route for route in ROUTE_INVENTORY if not route[1].startswith("/api/plugins/")
)
_FASTAPI_DOCUMENT_PATHS = {
    "openapi_url": "/openapi.json", "docs_url": "/docs",
    "redoc_url": "/redoc", "swagger_ui_oauth2_redirect_url": "/docs/oauth2-redirect",
}
_WS_ROUTES = {"/api/pty", "/api/ws", "/api/events"}
_SPA_ROUTES = {"/", "/chat", "/sessions", "/memory", "/settings", "/system"}
_READ_PATTERNS = tuple(
    re.compile(re.escape(path).replace(r"\{session_id\}", r"[A-Za-z0-9._-]{1,128}") + r"\Z")
    for path in READ_ROUTES
)
_QUERY_KEYS = {
    "profile", "limit", "offset", "q", "source", "sources", "exclude_sources", "archived",
    "order", "min_messages", "before", "after", "cursor", "around", "days", "hours",
    "before_id", "after_id", "message_id", "direction", "include_children",
}
_WS_QUERY_KEYS = {"token", "channel", "attach", "resume", "fresh", "profile", "cwd"}


def collect_route_inventory(root: Path) -> frozenset[tuple[str, str]]:
    cli = root / "hermes_cli"
    files = list((cli / "web_routers").glob("*.py")) + [
        cli / "web_server.py", cli / "web_server_dashboard.py",
        cli / "memory_oauth.py", cli / "dashboard_auth/routes.py",
    ] + list((root / "plugins").glob("*/dashboard/*.py"))
    if not files or not (cli / "web_routers/chat_ws.py").is_file():
        raise RuntimeError("Pinned dashboard sources are missing.")
    routes = set()
    methods = {"get", "head", "post", "put", "patch", "delete", "options", "websocket"}
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        plugin_prefix = (
            f"/api/plugins/{path.relative_to(root).parts[1]}"
            if path.is_relative_to(root / "plugins") else ""
        )
        prefixes: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if isinstance(node.value.func, ast.Name) and node.value.func.id == "APIRouter":
                    prefix = next((kw.value for kw in node.value.keywords if kw.arg == "prefix"), ast.Constant(""))
                    if not isinstance(prefix, ast.Constant) or not isinstance(prefix.value, str):
                        raise RuntimeError("Unclassified dynamic dashboard router prefix.")
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            prefixes[target.id] = prefix.value
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "FastAPI":
                for keyword in node.keywords:
                    if keyword.arg is None or (
                        keyword.arg in _FASTAPI_DOCUMENT_PATHS
                        and (
                            not isinstance(keyword.value, ast.Constant)
                            or keyword.value.value != _FASTAPI_DOCUMENT_PATHS[keyword.arg]
                        )
                    ):
                        raise RuntimeError("Unclassified automatic FastAPI routes.")
                routes.update(
                    (method, route)
                    for route in _FASTAPI_DOCUMENT_PATHS.values() for method in ("GET", "HEAD")
                )
        decorators = set()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                decorators.add(id(decorator))
                if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                    continue
                method = decorator.func.attr
                if method in {"api_route", "route", "websocket_route"}:
                    raise RuntimeError("Unclassified dashboard route registration.")
                if method not in methods:
                    continue
                if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
                    raise RuntimeError("Unclassified dynamic dashboard route.")
                route = decorator.args[0].value
                if not isinstance(route, str) or not route.startswith("/"):
                    raise RuntimeError("Invalid dashboard route.")
                owner = decorator.func.value
                prefix = prefixes.get(owner.id, "") if isinstance(owner, ast.Name) else ""
                routes.add((method.upper(), plugin_prefix + prefix + route))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            method, owner = node.func.attr, node.func.value
            if method in {"add_api_route", "add_route", "add_api_websocket_route", "add_websocket_route"}:
                raise RuntimeError("Unclassified imperative dashboard route registration.")
            if isinstance(owner, ast.Name) and owner.id in {"app", "application", "router", *prefixes}:
                if method in methods and id(node) not in decorators:
                    raise RuntimeError("Unclassified imperative dashboard route registration.")
                if method == "mount":
                    if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                        raise RuntimeError("Unclassified dynamic dashboard mount.")
                    routes.add(("MOUNT", plugin_prefix + node.args[0].value))
    return frozenset(routes)


def validate_route_inventory(root: Path = Path("/opt/hermes")) -> None:
    actual = collect_route_inventory(root)
    if actual != ROUTE_INVENTORY:
        added = sorted(actual - ROUTE_INVENTORY)
        removed = sorted(ROUTE_INVENTORY - actual)
        raise RuntimeError(
            f"Dashboard route inventory changed ({len(added)} new, {len(removed)} removed); managed policy review required."
        )


def collect_registered_route_inventory(application) -> frozenset[tuple[str, str]]:
    routes = []
    for route in application.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if not isinstance(path, str) or not path.startswith("/"):
            raise RuntimeError("Unclassified registered dashboard route.")
        if isinstance(methods, (set, frozenset, tuple, list)) and methods:
            if not all(isinstance(method, str) for method in methods):
                raise RuntimeError("Invalid registered dashboard methods.")
            routes.extend((method, path) for method in methods)
        elif type(route).__name__ in {"APIWebSocketRoute", "WebSocketRoute"}:
            routes.append(("WEBSOCKET", path))
        elif type(route).__name__ == "Mount" and type(route.app).__name__ == "_ImmutableAssetFiles":
            routes.append(("MOUNT", path))
        else:
            raise RuntimeError("Unclassified registered dashboard transport or mount.")
    if len(routes) != len(set(routes)):
        raise RuntimeError("Duplicate dashboard routes require managed policy review.")
    return frozenset(routes)


def validate_registered_routes(application) -> None:
    actual = collect_registered_route_inventory(application)
    if actual != REGISTERED_ROUTE_INVENTORY:
        raise RuntimeError(
            "Registered dashboard routes differ from managed mode; plugins must be disabled and new routes reviewed."
        )


def valid_local_origin(value: str) -> bool:
    match = _LOCAL_ORIGIN.fullmatch(value)
    return bool(match and 1024 <= int(match.group(1)) <= 65535)


def validate_target(value: str) -> str:
    if not _TARGET.fullmatch(value):
        raise ValueError("The relay target must be the fixed HTTPS Sandbox 8080 endpoint.")
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON fields.")
        result[key] = value
    return result


def _safe_json(value: str | bytes):
    try:
        return json.loads(value, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid JSON.") from None


def _bounded_rpc_text(value, *, allow_empty: bool = False, max_bytes: int = MAX_FRAME) -> bool:
    if not isinstance(value, str) or (not allow_empty and not value.strip()) or "\x00" in value:
        return False
    try:
        return len(value.encode("utf-8")) <= max_bytes
    except UnicodeError:
        return False


def rpc_response_allowed(frame: dict, *, surface: str = "sidebar") -> bool:
    """Shape only: A must also match an active clarify request and its transport."""
    if (
        surface != "tui" or not isinstance(frame, dict)
        or set(frame) not in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"})
        or frame.get("jsonrpc") != "2.0" or not isinstance(frame.get("id"), str)
        or not _SERVER_REQUEST_ID.fullmatch(frame["id"])
    ):
        return False
    if "result" in frame:
        result = frame["result"]
        if not isinstance(result, dict):
            return False
        if set(result) == {"answer"}:
            valid = _bounded_rpc_text(result["answer"], allow_empty=True)
        elif set(result) == {"answers"}:
            answers = result["answers"]
            valid = (
                isinstance(answers, dict) and 1 <= len(answers) <= 5
                and all(
                    isinstance(key, str) and _ID.fullmatch(key) and _bounded_rpc_text(value, allow_empty=True)
                    for key, value in answers.items()
                )
            )
        else:
            return False
    else:
        error = frame["error"]
        valid = (
            isinstance(error, dict) and set(error) == {"code", "message"}
            and type(error["code"]) is int and -(2 ** 31) <= error["code"] < 2 ** 31
            and _bounded_rpc_text(error["message"], allow_empty=True)
        )
    return bool(valid) and len(json.dumps(frame, separators=(",", ":")).encode("utf-8")) <= MAX_FRAME


def rpc_allowed(frame: dict, *, surface: str = "sidebar") -> bool:
    if (
        surface not in ("sidebar", "tui")
        or not isinstance(frame, dict) or not {"jsonrpc", "method"} <= frame.keys()
        or set(frame) - {"jsonrpc", "id", "method", "params"}
        or frame.get("jsonrpc") != "2.0"
        or not isinstance(frame.get("method"), str)
        or not isinstance(frame.get("params", {}), dict)
    ):
        return False
    identifier = frame.get("id")
    if identifier is not None and (
        type(identifier) not in (int, str)
        or isinstance(identifier, str) and len(identifier) > 128
        or isinstance(identifier, int) and not -(2 ** 53) < identifier < 2 ** 53
    ):
        return False
    method, params = frame["method"], frame.get("params", {})
    if params.get("profile") not in (None, "", "default", "current"):
        return False
    if method == "gateway.ping":
        return not params
    if surface == "tui":
        if method in {"pet.info.meta", "commands.catalog", "setup.status"}:
            return not params
        if method == "client.capabilities":
            return set(params) == {"server_requests"} and params["server_requests"] is True
        if method == "config.get":
            return set(params) == {"key"} and params["key"] in ("full", "mtime")
        if method == "session.create":
            return (
                not set(params) - {"cols", "profile"}
                and type(params.get("cols")) is int and 1 <= params["cols"] <= 1000
            )
        if method in _TUI_ID_PARAMS:
            key = _TUI_ID_PARAMS[method]
            return (
                set(params) == {key} and isinstance(params[key], str) and bool(_ID.fullmatch(params[key]))
            )
        if method == "terminal.resize":
            return (
                set(params) == {"session_id", "cols"}
                and isinstance(params["session_id"], str) and bool(_ID.fullmatch(params["session_id"]))
                and type(params["cols"]) is int and 1 <= params["cols"] <= 1000
            )
        if method in {"complete.slash", "complete.path"}:
            key = "text" if method == "complete.slash" else "word"
            expected = {key}
            if method == "complete.slash" and "session_id" in params:
                expected.add("session_id")
            return (
                set(params) == expected and _bounded_rpc_text(params[key], allow_empty=True)
                and ("session_id" not in params or (
                    isinstance(params["session_id"], str) and bool(_ID.fullmatch(params["session_id"]))
                ))
                and len(json.dumps(frame, ensure_ascii=True, separators=(",", ":")).encode("ascii")) <= MAX_FRAME
            )
        if method == "clarify.lock":
            return (
                set(params) == {"request_id", "question_id", "answer"}
                and isinstance(params["request_id"], str) and bool(_SERVER_REQUEST_ID.fullmatch(params["request_id"]))
                and isinstance(params["question_id"], str) and bool(_ID.fullmatch(params["question_id"]))
                and _bounded_rpc_text(params["answer"], allow_empty=True)
            )
        if method == "slash.exec":
            return (
                set(params) == {"command", "session_id"} and params["command"] == "context"
                and isinstance(params["session_id"], str) and bool(_ID.fullmatch(params["session_id"]))
            )
        if method == "prompt.submit":
            return (
                set(params) == {"session_id", "text"}
                and isinstance(params["session_id"], str) and bool(_ID.fullmatch(params["session_id"]))
                and _bounded_rpc_text(params["text"])
            )
        return False
    if method == "session.create":
        return (
            not set(params) - {"source", "close_on_disconnect", "profile"}
            and params.get("source") == "tool" and params.get("close_on_disconnect") is True
        )
    if method == "session.events.since":
        return (
            not set(params) - {"session_id", "last_seen", "profile"}
            and isinstance(params.get("session_id"), str) and bool(_ID.fullmatch(params["session_id"]))
            and type(params.get("last_seen", 0)) is int and 0 <= params.get("last_seen", 0) <= 2 ** 53
        )
    return False


def _check_query(request: web.Request, *, websocket: bool) -> None:
    query = request.rel_url.query
    if len(query) > 32 or any(len(query.getall(key)) != 1 for key in query):
        raise web.HTTPForbidden(text=MANAGED_ERROR)
    allowed = _WS_QUERY_KEYS if websocket else _QUERY_KEYS
    if request.path == "/api/files/read":
        allowed = {"path"}
        if query.get("path") not in {
            "/mnt/data/hermes/memories/MEMORY.md", "/mnt/data/hermes/memories/USER.md",
        }:
            raise web.HTTPForbidden(text=MANAGED_ERROR)
    if any(key not in allowed or len(value) > 512 or any(ord(char) < 32 for char in value) for key, value in query.items()):
        raise web.HTTPForbidden(text=MANAGED_ERROR)
    if query.get("profile") not in (None, "", "default", "current"):
        raise web.HTTPForbidden(text=MANAGED_ERROR)
    if websocket:
        if query.get("cwd") not in (None, "/mnt/data"):
            raise web.HTTPForbidden(text=MANAGED_ERROR)
        for key in ("channel", "attach", "resume"):
            if key in query and not _ID.fullmatch(query[key]):
                raise web.HTTPForbidden(text=MANAGED_ERROR)


def _check_route(request: web.Request) -> bool:
    target = request.raw_path.split("?", 1)[0]
    if (
        not _SAFE_PATH.fullmatch(target) or target.startswith("//") or "//" in target
        or any(part in {".", ".."} for part in target.split("/"))
        or request.method == "CONNECT"
    ):
        raise web.HTTPBadRequest(text="Invalid proxy target.")
    websocket = request.headers.get("Upgrade", "").lower() == "websocket"
    if websocket:
        allowed = request.method == "GET" and request.path in _WS_ROUTES
    elif request.method in {"GET", "HEAD"}:
        allowed = (
            request.path in _SPA_ROUTES
            or any(pattern.fullmatch(request.path) for pattern in _READ_PATTERNS)
            or request.path == "/api/files/read"
            or bool(re.fullmatch(
                r"/(?:assets|fonts|fonts-terminal|ds-assets)/[A-Za-z0-9._/-]+\.(?:js|css|svg|png|ico|woff2?|ttf|webp)",
                request.path,
            ))
            or request.path == "/favicon.ico"
        )
    else:
        allowed = request.method == "PATCH" and bool(re.fullmatch(r"/api/sessions/[A-Za-z0-9._-]{1,128}", request.path))
    if not allowed:
        raise web.HTTPForbidden(text=MANAGED_ERROR)
    _check_query(request, websocket=websocket)
    return websocket


def clean_headers(headers, *, response: bool = False) -> CIMultiDict[str]:
    nominated = {
        item.strip().lower()
        for line in headers.getall("Connection", [])
        for item in line.split(",")
    }
    output: CIMultiDict[str] = CIMultiDict()
    for name, value in headers.items():
        key = name.lower()
        if (
            key in _HOP_HEADERS or key in _TRANSPORT_HEADERS or key in nominated
            or key == "forwarded" or key.startswith("x-forwarded-")
            or key.startswith("sec-websocket-") or key.startswith("access-control-")
        ):
            continue
        output.add(name, value)
    if response:
        output["X-Content-Type-Options"] = "nosniff"
        output["Content-Security-Policy"] = browser_policy()
        output["Referrer-Policy"] = "no-referrer"
    return output


def browser_policy(local_origin: str | None = None) -> str:
    connections = "'self'"
    if local_origin is not None:
        if not valid_local_origin(local_origin):
            raise ValueError("Browser policy requires the exact owner relay origin.")
        connections += " ws://" + urlsplit(local_origin).netloc
    # The real SPA injects its session bootstrap and theme inline. User content
    # is rendered as text, not HTML; remote resources remain forbidden.
    return (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; font-src 'self' data:; media-src 'none'; object-src 'none'; "
        "frame-src 'none'; worker-src 'self' blob:; "
        f"connect-src {connections}; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )


def create_access_key() -> str:
    mounts = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    if not any(
        line.split(" - ", 1)[0].split()[4] == "/dev/shm"
        and line.split(" - ", 1)[1].split()[0] == "tmpfs"
        for line in mounts
    ):
        raise RuntimeError("The access key requires /dev/shm tmpfs; no disk fallback is permitted.")
    if KEY_PATH.parent.is_symlink():
        raise RuntimeError("Unsafe access-key directory.")
    KEY_PATH.parent.mkdir(mode=0o700, exist_ok=True)
    directory = os.open(KEY_PATH.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = f".access-key-{secrets.token_hex(16)}"
    try:
        os.fchmod(directory, 0o700)
        key = secrets.token_hex(32)
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            os.write(descriptor, key.encode("ascii"))
            os.fsync(descriptor)
            if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
                raise RuntimeError("Unsafe access-key file permissions.")
        finally:
            os.close(descriptor)
        os.replace(temporary, KEY_PATH.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        return key
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=directory)
        os.close(directory)


def no_redirect_trace() -> aiohttp.TraceConfig:
    trace = aiohttp.TraceConfig()

    async def reject_redirect(session, context, params) -> None:
        raise aiohttp.ClientConnectionError("Redirects are disabled for authenticated WebSockets.")

    trace.on_request_redirect.append(reject_redirect)
    return trace


class Proxy:
    def __init__(
        self, *, local_origin: str | None = None, target: str = DASHBOARD_URL,
        token_provider: Callable[[], Awaitable[str]] | None = None,
        key_provider: Callable[[], Awaitable[str]] | None = None,
        access_key: str | None = None,
        client: aiohttp.ClientSession | None = None,
    ):
        self.local_origin = local_origin
        self.local = local_origin is not None
        if self.local:
            if not valid_local_origin(local_origin) or token_provider is None or key_provider is None:
                raise ValueError("Local relay needs its exact loopback origin and Azure/key providers.")
            validate_target(target)
        elif target != DASHBOARD_URL or not access_key or not re.fullmatch(r"[a-f0-9]{64}", access_key):
            raise ValueError("Inner proxy needs its tmpfs key and fixed loopback dashboard.")
        self.target = target
        self.token_provider = token_provider
        self.key_provider = key_provider
        self.key = access_key
        self.key_lock = asyncio.Lock()
        self.cookie_name = "hermes-local-" + (urlsplit(local_origin).netloc.rsplit(":", 1)[1] if self.local else "inner")
        self.cookie = secrets.token_urlsafe(32)
        self.client = client
        self.owns_client = client is None
        self.active = 0
        self.app = web.Application(client_max_size=MAX_BODY, middlewares=[self.errors])
        self.app.router.add_route("*", "/{path:.*}", self.handle)
        self.app.on_startup.append(self.start)
        self.app.on_cleanup.append(self.close)

    async def start(self, app: web.Application) -> None:
        if self.client is None:
            self.client = aiohttp.ClientSession(
                auto_decompress=False, trust_env=False,
                timeout=aiohttp.ClientTimeout(total=None, sock_connect=30, sock_read=300),
                connector=aiohttp.TCPConnector(limit=MAX_CONNECTIONS, limit_per_host=MAX_CONNECTIONS),
                cookie_jar=aiohttp.DummyCookieJar(),
                trace_configs=[no_redirect_trace()],
            )

    async def close(self, app: web.Application) -> None:
        if self.client is not None and self.owns_client:
            await self.client.close()

    @web.middleware
    async def errors(self, request: web.Request, handler):
        request_id = secrets.token_hex(8)
        status = 500
        try:
            response = await handler(request)
            status = response.status
            return response
        except (web.HTTPException, aiohttp.ClientError, TimeoutError, ConnectionError, RuntimeError) as error:
            started = request.get(_STARTED_RESPONSE)
            if isinstance(error, web.HTTPException) and started is None:
                status = error.status
                raise
            LOG.error("transport failure type=%s request=%s", type(error).__name__, request_id)
            if started is not None:
                status = started.status
                started.force_close()
                if request.transport is not None:
                    request.transport.abort()
                # Keep the committed response object; a fresh 502 would become
                # bytes inside its body or the already-upgraded WebSocket.
                return started
            status = 502
            return web.json_response({"error": "Hermes transport unavailable; check owner login and runtime status."}, status=502)
        finally:
            path = request.path if _SAFE_PATH.fullmatch(request.path) else "/invalid"
            LOG.info("%s %s %s request=%s", request.method, path, status, request_id)

    def check_boundary(self, request: web.Request) -> None:
        if any(len(request.headers.getall(name, [])) > 1 for name in (
            "Host", "Origin", KEY_HEADER, RELAY_ORIGIN_HEADER, RELAY_AUTHORITY_HEADER, "X-Hermes-Session-Token",
        )):
            raise web.HTTPBadRequest(text="Ambiguous request headers.")
        origin = request.headers.get("Origin")
        unsafe = request.method not in {"GET", "HEAD"} or request.headers.get("Upgrade", "").lower() == "websocket"
        if self.local:
            if request.headers.get("Host") != urlsplit(self.local_origin).netloc:
                raise web.HTTPForbidden(text="Invalid local Host.")
            if origin is not None and origin != self.local_origin or unsafe and origin != self.local_origin:
                raise web.HTTPForbidden(text="Invalid local Origin.")
            if request.headers.get("Sec-Fetch-Site") == "cross-site":
                raise web.HTTPForbidden(text="Cross-site localhost requests are not permitted.")
            initial = request.method == "GET" and request.path in _SPA_ROUTES and not unsafe
            if not initial and not hmac.compare_digest(request.cookies.get(self.cookie_name, ""), self.cookie):
                raise web.HTTPForbidden(text="Open the local dashboard first to establish its private browser session.")
        else:
            presented = request.headers.get(KEY_HEADER, "")
            if not hmac.compare_digest(presented.encode(), self.key.encode()):
                raise web.HTTPUnauthorized(
                    text="Hermes transport key expired.", headers={EXPIRED_HEADER: "1"},
                )
            declared_origin = request.headers.get(RELAY_ORIGIN_HEADER, "")
            authority = request.headers.get(RELAY_AUTHORITY_HEADER, "")
            if not valid_local_origin(declared_origin) or not _TARGET.fullmatch("https://" + authority):
                raise web.HTTPForbidden(text="Missing or invalid authenticated relay boundary.")
            if request.headers.get("Host") != authority:
                raise web.HTTPForbidden(text="Invalid ingress Host.")
            if origin is not None and origin != declared_origin or unsafe and origin != declared_origin:
                raise web.HTTPForbidden(text="Invalid relay Origin.")

    async def headers(self, request: web.Request, *, refresh: bool = False) -> CIMultiDict[str]:
        headers = clean_headers(request.headers)
        headers["Host"] = urlsplit(self.target).netloc
        if self.local:
            # This declaration is covered by the private transport key; browser
            # supplied values were removed. No persistent endpoint sidecar is needed.
            headers[RELAY_ORIGIN_HEADER] = self.local_origin
            headers[RELAY_AUTHORITY_HEADER] = urlsplit(self.target).netloc
            async with self.key_lock:
                if self.key is None or refresh:
                    self.key = await self.key_provider()
                if not re.fullmatch(r"[a-f0-9]{64}", self.key):
                    raise RuntimeError("Invalid private transport key.")
            headers[KEY_HEADER] = self.key
            headers["Authorization"] = "Bearer " + await self.token_provider()
            cookies = [(name, value) for name, value in request.cookies.items() if name != self.cookie_name]
            headers.pop("Cookie", None)
            if cookies:
                headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies)
        return headers

    async def body(self, request: web.Request) -> bytes | None:
        if request.content_length is not None and request.content_length > MAX_BODY:
            raise web.HTTPRequestEntityTooLarge(max_size=MAX_BODY, actual_size=request.content_length)
        if request.method != "PATCH":
            if request.can_read_body:
                raise web.HTTPBadRequest(text="This managed read/WS route accepts no request body.")
            return None
        # The only HTTP mutation is a small validated session edit. Keeping this
        # bounded JSON permits exactly one pre-forward key-rotation retry.
        data = bytearray()
        async for chunk in request.content.iter_chunked(CHUNK):
            data.extend(chunk)
            if len(data) > 16 * 1024:
                raise web.HTTPRequestEntityTooLarge(max_size=16 * 1024, actual_size=len(data))
        if request.content_type != "application/json":
            raise web.HTTPUnsupportedMediaType(text="Session edits require JSON.")
        try:
            payload = _safe_json(bytes(data))
        except ValueError:
            raise web.HTTPBadRequest(text="Invalid session edit JSON.") from None
        if (
            not isinstance(payload, dict) or not payload
            or set(payload) - {"title", "archived", "pinned", "profile"}
            or payload.get("profile") not in (None, "", "default", "current")
            or "title" in payload and (not isinstance(payload["title"], str) or len(payload["title"]) > 256)
            or any(type(payload[key]) is not bool for key in ("archived", "pinned") if key in payload)
        ):
            raise web.HTTPForbidden(text=MANAGED_ERROR)
        return bytes(data)

    async def handle(self, request: web.Request) -> web.StreamResponse:
        self.check_boundary(request)
        websocket = _check_route(request)
        body = await self.body(request)
        if self.active >= MAX_CONNECTIONS:
            raise web.HTTPServiceUnavailable(text="Hermes connection limit reached.")
        self.active += 1
        try:
            if websocket:
                return await self.websocket(request)
            return await self.http(request, body)
        finally:
            self.active -= 1

    async def http(self, request: web.Request, body: bytes | None) -> web.StreamResponse:
        for attempt in range(2 if self.local else 1):
            headers = await self.headers(request, refresh=attempt == 1)
            async with self.client.request(
                request.method, self.target + request.raw_path, headers=headers, data=body,
                allow_redirects=False,
            ) as upstream:
                if self.local and attempt == 0 and upstream.status == 401 and upstream.headers.get(EXPIRED_HEADER) == "1":
                    upstream.close()
                    continue
                location = upstream.headers.get("Location", "")
                if 300 <= upstream.status < 400 and location:
                    parsed = urlsplit(location)
                    if parsed.scheme or parsed.netloc or location.startswith("//") or "\\" in location:
                        raise web.HTTPBadGateway(text="Cross-origin redirects are disabled.")
                response_headers = clean_headers(upstream.headers, response=True)
                response = web.StreamResponse(status=upstream.status, headers=response_headers)
                if self.local:
                    response.headers["Cache-Control"] = "no-store"
                    response.headers["Content-Security-Policy"] = browser_policy(self.local_origin)
                    response.set_cookie(
                        self.cookie_name, self.cookie, httponly=True, samesite="Strict", path="/",
                    )
                request[_STARTED_RESPONSE] = response
                await response.prepare(request)
                if request.method != "HEAD":
                    async for chunk in upstream.content.iter_chunked(CHUNK):
                        await response.write(chunk)
                await response.write_eof()
                return response
        raise web.HTTPBadGateway(text="Private transport key could not be refreshed.")

    async def websocket(self, request: web.Request) -> web.StreamResponse:
        upstream = None
        for attempt in range(2 if self.local else 1):
            headers = await self.headers(request, refresh=attempt == 1)
            try:
                upstream = await self.client.ws_connect(
                    self.target + request.raw_path, headers=headers, heartbeat=HEARTBEAT,
                    max_msg_size=_READER_LIMIT, compress=0, autoping=True,
                    timeout=aiohttp.ClientWSTimeout(ws_close=10),
                )
                break
            except aiohttp.WSServerHandshakeError as error:
                if self.local and attempt == 0 and error.status == 401 and error.headers.get(EXPIRED_HEADER) == "1":
                    continue
                response = web.Response(status=error.status, text="Hermes WebSocket authorization or handshake rejected.")
                return response
        if upstream is None:
            raise web.HTTPBadGateway(text="Private WebSocket transport key could not be refreshed.")
        downstream = web.WebSocketResponse(
            heartbeat=HEARTBEAT, max_msg_size=_READER_LIMIT, compress=False, writer_limit=CHUNK,
        )
        request[_STARTED_RESPONSE] = downstream
        await downstream.prepare(request)

        async def pump(source, destination, *, from_browser: bool) -> None:
            async for message in source:
                if message.type not in {WSMsgType.TEXT, WSMsgType.BINARY}:
                    if message.type == WSMsgType.ERROR:
                        LOG.warning("websocket peer failed type=%s", type(source.exception()).__name__)
                    break
                size = len(message.data.encode("utf-8")) if message.type == WSMsgType.TEXT else len(message.data)
                if size > MAX_FRAME:
                    await source.close(code=1009, message=b"Frame exceeds 1 MiB.")
                    return
                if from_browser and not self.local and request.path in {"/api/events", "/api/ws"}:
                    frame = None
                    try:
                        if message.type != WSMsgType.TEXT:
                            raise ValueError("RPC must be text.")
                        frame = _safe_json(message.data)
                    except ValueError:
                        pass
                    if (
                        isinstance(frame, dict) and frame.get("jsonrpc") == "2.0"
                        and "method" not in frame and "id" in frame
                        and bool("result" in frame) != bool("error" in frame)
                    ):
                        LOG.debug("Ignoring client RPC response on a request/subscriber channel.")
                        continue
                    if request.path == "/api/events" or not rpc_allowed(frame):
                        if request.path == "/api/events" and not isinstance(frame, dict):
                            LOG.debug("Ignoring non-RPC subscriber input.")
                            continue
                        identifier = frame.get("id") if isinstance(frame, dict) else None
                        if (
                            type(identifier) not in (str, int)
                            or isinstance(identifier, str) and len(identifier) > 128
                            or isinstance(identifier, int) and not -(2 ** 53) < identifier < 2 ** 53
                        ):
                            identifier = None
                        await source.send_json({
                            "jsonrpc": "2.0", "id": identifier,
                            "error": {"code": -32601, "message": MANAGED_ERROR},
                        })
                        continue
                if message.type == WSMsgType.TEXT:
                    await destination.send_str(message.data)
                else:
                    await destination.send_bytes(message.data)
            code = source.close_code or 1000
            await destination.close(code=code if code not in {1005, 1006, 1015} else 1011)

        tasks = [
            asyncio.create_task(pump(downstream, upstream, from_browser=True)),
            asyncio.create_task(pump(upstream, downstream, from_browser=False)),
        ]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done:
                await task
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await upstream.close()
            await downstream.close()
        return downstream


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
    validate_route_inventory()
    proxy = Proxy(access_key=create_access_key())
    web.run_app(proxy.app, host="0.0.0.0", port=8080, access_log=None, print=None)


if __name__ == "__main__":
    main()
