#!/opt/hermes/.venv/bin/python
"""The only supported gateway control and terminal-only pairing entrypoint."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import sys
import uuid

from lifecycle import CONTROL_SOCKET, OPERATION_LOCK, PAIR_LOCK, Child, prove_gateway_absent
from runtime import (
    HOME, INSTALL, SESSION, WHATSAPP, PolicyError, atomic_json, check_data_disk,
    child_environment, exclusive_lock, load_runtime, private_directory, read_json,
    _unique_object, validate_profile, verified_identity,
)


def request(command: str) -> dict:
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(120)
            connection.connect(str(CONTROL_SOCKET))
            connection.sendall(json.dumps({"command": command}).encode() + b"\n")
            data = bytearray()
            while not data.endswith(b"\n"):
                chunk = connection.recv(4096)
                if not chunk or len(data) + len(chunk) > 64 * 1024:
                    raise PolicyError("invalid supervisor response")
                data.extend(chunk)
        response = json.loads(data, object_pairs_hook=_unique_object)
        if not isinstance(response, dict):
            raise PolicyError("invalid supervisor response")
        if response.get("ok") is not True:
            message = response.get("error")
            raise PolicyError(message if isinstance(message, str) else "control operation failed")
        status = response.get("status")
        if (not isinstance(status, dict) or set(status) != {
                "schema_version", "dashboard", "gateway", "whatsapp", "google", "disk_free_bytes",
            } or type(status["schema_version"]) is not int or status["schema_version"] != 1
                or type(status["disk_free_bytes"]) is not int or status["disk_free_bytes"] < -1
                or any(not isinstance(status[key], str) or len(status[key]) > 80
                       for key in ("dashboard", "gateway", "whatsapp", "google"))):
            raise PolicyError("invalid supervisor status")
        return status
    except (OSError, ValueError, KeyError, RecursionError) as exc:
        raise PolicyError("managed supervisor is unavailable; no standalone fallback was started") from exc


def activate(stage: Path, owner_phone: str, *, session: Path = SESSION) -> None:
    sessions = session.parent / "sessions"
    if stage.parent.resolve() != sessions.resolve() or stage.is_symlink() or not stage.is_dir():
        raise PolicyError("pairing staging directory is outside the managed session store")
    verified_identity(read_json(stage / "creds.json", limit=1024 * 1024), owner_phone)
    if session.exists() and not session.is_symlink():
        raise PolicyError("existing non-managed session directory must be migrated offline, never overwritten")
    if session.is_symlink() and session.resolve().parent != sessions.resolve():
        raise PolicyError("existing session pointer is outside the managed session store")
    temporary = session.parent / f".activate-{uuid.uuid4().hex}"
    try:
        temporary.symlink_to(Path("sessions") / stage.name)
        os.replace(temporary, session)
        fd = os.open(session.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)
    atomic_json(session.parent / "connection-state.json", {"state": "disconnected"})


def remove_pair_stage(stage: Path, *, session: Path = SESSION) -> None:
    sessions = session.parent / "sessions"
    if (stage.is_symlink() or not stage.is_dir() or stage.parent.resolve() != sessions.resolve()
            or not stage.name.startswith("pair-") or len(stage.name) != 37):
        raise PolicyError("refusing to clean an unrecognized pairing stage")
    if session.is_symlink() and session.resolve() == stage.resolve():
        raise PolicyError("refusing to clean active WhatsApp credentials")
    shutil.rmtree(stage)


def pair(*, reconnect: bool = False) -> dict:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise PolicyError("pairing QR may only be displayed in an approved interactive terminal")
    runtime = load_runtime()
    check_data_disk()
    if validate_profile() != runtime:
        raise PolicyError("runtime changed during pairing; credentials were not activated")
    if SESSION.exists() and not reconnect:
        raise PolicyError("existing credentials preserved; use pair --reconnect for an explicit new-device pairing")
    if SESSION.exists() and not SESSION.is_symlink():
        raise PolicyError("existing non-managed session directory requires offline migration, not destructive onboarding")
    initial_status = request("status")
    if initial_status.get("dashboard") == "failed" or initial_status.get("gateway") == "failed":
        raise PolicyError("managed runtime failed; use control.py reconfigure before pairing")
    previous = SESSION.resolve() if SESSION.is_symlink() else None
    with exclusive_lock(PAIR_LOCK):
        request("stop-gateway")
        prove_gateway_absent()
        private_directory(WHATSAPP)
        private_directory(WHATSAPP / "sessions")
        stage = WHATSAPP / "sessions" / f"pair-{uuid.uuid4().hex}"
        private_directory(stage)
        environment = child_environment(runtime)
        environment["HERMES_SANDBOX_PAIR_APPROVED"] = "1"
        child = None
        activated = False
        try:
            process = subprocess.Popen(
                ["/usr/local/bin/node", str(INSTALL / "scripts/whatsapp-bridge/bridge.js"),
                 "--pair-only", "--session", str(stage), "--mode", "self-chat"],
                env=environment, cwd="/mnt/data", start_new_session=True, umask=0o077,
            )
            child = Child("pair", process)
            child.capture()
            if process.wait(timeout=600) != 0:
                raise PolicyError("pairing failed; existing credentials preserved; remain in maintenance")
            check_data_disk()
            if validate_profile() != runtime:
                raise PolicyError("runtime changed during pairing; credentials were not activated")
            activate(stage, runtime["owner"]["whatsapp_phone"])
            activated = True
        finally:
            if child:
                child.stop()
            if not activated:
                remove_pair_stage(stage)
                print("Pairing did not activate. Local staging keys removed; unlink any newly linked "
                      "Hermes device in WhatsApp unless logout was explicitly confirmed.", file=sys.stderr)
        prove_gateway_absent()
        if previous is not None and previous != stage:
            remove_pair_stage(previous)
            print("Reconnect activated. Unlink the previous Hermes device in WhatsApp on your phone.", file=sys.stderr)
    try:
        return request("start-gateway")
    except PolicyError as exc:
        raise PolicyError("new owner credentials activated; gateway start failed; remain in maintenance") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    status = commands.add_parser("status")
    status.add_argument("--json", action="store_true")
    commands.add_parser("stop-gateway")
    commands.add_parser("start-gateway")
    commands.add_parser("reconfigure")
    pairing = commands.add_parser("pair")
    pairing.add_argument("--reconnect", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    try:
        if args.command == "status":
            result = request("status")
        else:
            with exclusive_lock(OPERATION_LOCK):
                result = pair(reconnect=args.reconnect) if args.command == "pair" else request(args.command)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (PolicyError, OSError, subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        message = str(exc) if isinstance(exc, PolicyError) else "managed operation interrupted or unavailable"
        print(json.dumps({"error": message}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
