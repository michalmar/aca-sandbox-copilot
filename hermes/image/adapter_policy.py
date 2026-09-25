"""Managed Baileys lifecycle without runtime installs, process adoption or port killing."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import secrets
import subprocess

from lifecycle import prove_bridge_absent
from managed_policy import checked_runtime
from runtime import INSTALL, SESSION, PolicyError, child_environment, whatsapp_status


def bridge_dependencies(bridge: Path) -> bool:
    expected = hashlib.sha256((bridge / "package.json").read_bytes()).hexdigest()[:16]
    try:
        actual = (bridge / "node_modules/.hermes-pkg-hash").read_text().strip()
        version = json.loads((bridge / "node_modules/@whiskeysockets/baileys/package.json").read_text())["version"]
    except (OSError, ValueError, KeyError) as exc:
        raise PolicyError("image is missing locked Baileys dependencies; rebuild, do not install at runtime") from exc
    if actual != expected or version != "7.0.0-rc13":
        raise PolicyError("image Baileys package stamp/version mismatch; rebuild the image")
    return True


def bridge_directory() -> Path:
    bridge = INSTALL / "scripts/whatsapp-bridge"
    bridge_dependencies(bridge)
    probe = bridge / ".managed-write-test"
    try:
        probe.touch(exist_ok=False)
        probe.unlink()
    except OSError as exc:
        raise PolicyError("image install must be writable; copying node_modules to DataDisk is forbidden") from exc
    return bridge


def bridge_headers(adapter) -> dict[str, str]:
    key = getattr(adapter, "_managed_bridge_key", "")
    if len(key) != 64:
        raise PolicyError("managed bridge has no ephemeral authentication key")
    return {"X-Hermes-Bridge-Key": key}


def preflight(adapter) -> bool:
    runtime = checked_runtime()
    if (Path(adapter._bridge_script) != INSTALL / "scripts/whatsapp-bridge/bridge.js"
            or adapter._session_path != SESSION or adapter._bridge_port != 3000
            or adapter._send_read_receipts or adapter._dm_policy != "allowlist"
            or adapter._group_policy != "disabled"):
        raise PolicyError("WhatsApp adapter policy override denied")
    bridge_dependencies(Path(adapter._bridge_script).parent)
    status = whatsapp_status(runtime)
    if status != "paired":
        adapter._set_fatal_error(f"whatsapp_{status}", "WhatsApp requires control.py pair in an interactive terminal",
                                 retryable=False)
        return False
    return True


async def connect(adapter, *, is_reconnect: bool = False) -> bool:
    if not preflight(adapter):
        return False
    if not adapter._acquire_platform_lock("whatsapp-session", str(adapter._session_path), "WhatsApp session"):
        raise PolicyError("WhatsApp session is already owned by another process")
    process = None
    try:
        prove_bridge_absent(adapter._bridge_port)
        adapter._managed_bridge_key = secrets.token_hex(32)
        env = child_environment(checked_runtime())
        env["HERMES_SANDBOX_BRIDGE_KEY"] = adapter._managed_bridge_key
        process = subprocess.Popen(
            ["/usr/local/bin/node", adapter._bridge_script, "--port", str(adapter._bridge_port),
             "--session", str(adapter._session_path), "--mode", "self-chat"],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        adapter._bridge_process = process
        adapter._bridge_log = adapter._session_path.parent / "bridge.log"
        if not await adapter._wait_for_bridge():
            raise PolicyError("WhatsApp bridge startup failed; inspect sanitized connection-state.json")
        adapter._attach_to_bridge(process)
        adapter._mark_connected()
        adapter._wire_plugin_handlers(None)
        return True
    finally:
        if not adapter._running:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            adapter._release_platform_lock()


def terminate(adapter, *, force: bool) -> None:
    process = adapter._bridge_process
    if process is not None and process.poll() is None:
        if force:
            process.kill()
        else:
            process.terminate()
