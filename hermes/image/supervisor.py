#!/opt/hermes/.venv/bin/python
"""Small single-home supervisor: persistent intent, native locks, bounded retries."""

from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import signal
import socket
import sys
import time

from lifecycle import (
    CONTROL_SOCKET, PAIR_LOCK, RUNTIME_DIRECTORY, Child, prove_gateway_absent, spawn, verify_tmpfs,
)
from runtime import (
    HOME, INSTALL, MIN_FREE_BYTES, PYTHON, RUNTIME, SUPPORT, PolicyError, apply_profile, check_data_disk,
    child_environment, disk_free_bytes, exclusive_lock, google_status, load_runtime, private_directory,
    _unique_object, read_state, validate_profile, whatsapp_status, write_state,
)

COMMANDS = {
    "proxy": [str(PYTHON), str(SUPPORT / "access_proxy.py")],
    "dashboard": [str(INSTALL / ".venv/bin/hermes"), "dashboard", "--host", "127.0.0.1",
                  "--port", "9119", "--no-open", "--skip-build"],
    "gateway": [str(INSTALL / ".venv/bin/hermes"), "gateway", "run", "--external-supervisor"],
}
MAX_RESTARTS = 3
RESTART_WINDOW = 300
CONTROL_TIMEOUT = 3


def event(name: str, **fields) -> None:
    print(json.dumps({"event": name, **fields}, sort_keys=True), flush=True)


def error_message(error: Exception) -> str:
    return str(error) if isinstance(error, PolicyError) else "managed operating-system operation failed"


class Supervisor:
    def __init__(self):
        self.children: dict[str, Child] = {}
        self.failures = {name: deque() for name in COMMANDS}
        self.retry_at = {name: 0.0 for name in COMMANDS}
        self.shutting_down = False
        self.runtime: dict = {}
        self.failure = ""
        self.gateway_failure = ""
        self.diagnostics: dict[str, str] = {}

    def diagnose(self, component: str, message: str) -> None:
        if self.diagnostics.get(component) != message:
            self.diagnostics[component] = message
            event("component-diagnostic", component=component, diagnostic=message)

    def environment(self) -> dict[str, str]:
        return child_environment(self.runtime)

    def apply(self) -> None:
        if self.children:
            raise PolicyError("managed profile may only be applied with managed processes stopped")
        prove_gateway_absent()
        check_data_disk()
        self.runtime = load_runtime()
        changed = apply_profile(self.runtime)
        environment = self.environment()
        os.environ.clear()
        os.environ.update(environment)
        event("profile-applied", changed_keys=changed)

    def validate(self, *, dashboard: bool = False) -> None:
        check_data_disk()
        validate_profile(environment=os.environ)
        if dashboard:
            from access_proxy import validate_route_inventory
            try:
                validate_route_inventory(INSTALL)
            except RuntimeError as exc:
                raise PolicyError("dashboard route inventory drift; managed review required") from exc

    def start(self, name: str) -> None:
        if self.failure or (name == "gateway" and self.gateway_failure):
            return
        if name == "gateway":
            if read_state()["desired"] != "running" or whatsapp_status(self.runtime) != "paired":
                return
        self.validate(dashboard=name == "dashboard")
        if name in self.children:
            if self.children[name].process.poll() is None:
                return
            raise PolicyError(f"{name}: previous process must be reaped before restart")
        if name == "gateway":
            prove_gateway_absent()
        self.children[name] = spawn(name, COMMANDS[name], self.environment())
        event("process-started", component=name)

    def stop(self, name: str) -> None:
        child = self.children.get(name)
        if child:
            child.stop()
            del self.children[name]
            event("process-stopped", component=name)
        if name == "gateway":
            prove_gateway_absent()

    def stop_all(self) -> list[str]:
        # Stop the browser producer before its PTY/RPC children and the gateway.
        errors = []
        for name in ("proxy", "dashboard", "gateway"):
            try:
                self.stop(name)
            except (PolicyError, OSError) as exc:
                errors.append(name)
                self.diagnose(name, error_message(exc))
        return errors

    def status(self) -> dict:
        def process_state(name: str) -> str:
            child = self.children.get(name)
            return "running" if child and child.process.poll() is None else "stopped"
        try:
            desired = read_state()["desired"]
        except (PolicyError, OSError) as exc:
            desired = "failed"
            self.diagnose("state", error_message(exc))
        try:
            wa = whatsapp_status(self.runtime) if self.runtime else "unknown"
        except (PolicyError, OSError) as exc:
            wa = "re-pair-required"
            self.diagnose("whatsapp", error_message(exc))
        gateway = process_state("gateway")
        if gateway == "stopped":
            gateway = ("failed" if self.failure or self.gateway_failure or desired == "failed" else
                       "maintenance" if desired == "maintenance" else
                       wa if wa != "paired" else "stopped")
        google = "unknown"
        if self.runtime and not self.runtime["google"]["enabled"]:
            google = "disabled"
        elif self.runtime:
            try:
                google = google_status()["status"]
            except (PolicyError, OSError) as exc:
                self.diagnose("google", error_message(exc))
        try:
            free = disk_free_bytes()
            if free < MIN_FREE_BYTES:
                self.diagnose("disk", "DataDisk has less than 256 MiB free; mutations remain disabled")
        except (PolicyError, OSError) as exc:
            free = -1
            self.diagnose("disk", error_message(exc))
        return {
            "schema_version": 1,
            "dashboard": "failed" if self.failure else process_state("dashboard"),
            "gateway": gateway,
            "whatsapp": wa,
            "google": google,
            "disk_free_bytes": free,
        }

    def handle(self, command: str) -> dict:
        if command == "status":
            return self.status()
        if command == "stop-gateway":
            if not self.failure and not self.gateway_failure and read_state()["desired"] != "failed":
                write_state("maintenance")
            self.stop("gateway")
        elif command == "start-gateway":
            if self.failure or self.gateway_failure:
                raise PolicyError("managed runtime failed; use control.py reconfigure before starting")
            with exclusive_lock(PAIR_LOCK):
                self.validate()
                if whatsapp_status(self.runtime) != "paired":
                    raise PolicyError("WhatsApp is not paired to the configured owner; use control.py pair")
                write_state("running")
                self.failures["gateway"].clear()
                self.retry_at["gateway"] = 0
                try:
                    self.start("gateway")
                except (PolicyError, OSError):
                    write_state("maintenance", "gateway start failed")
                    raise
        elif command == "reconfigure":
            with exclusive_lock(PAIR_LOCK):
                previous = read_state()["desired"]
                write_state("maintenance")
                if self.stop_all():
                    raise PolicyError("cannot reconfigure until all managed processes have stopped")
                self.apply()
                self.failure = self.gateway_failure = ""
                for name in self.failures:
                    self.failures[name].clear()
                    self.retry_at[name] = 0
                write_state("maintenance" if previous == "maintenance" else "running")
                for name in COMMANDS:
                    self.start(name)
        else:
            raise PolicyError("unsupported control operation")
        return self.status()

    def tick(self) -> None:
        check_data_disk()
        # Capture descendants even when their parent exits before the next tick.
        for child in self.children.values():
            child.capture()
        for name, child in list(self.children.items()):
            returncode = child.process.poll()
            if returncode is None:
                continue
            child.stop()
            del self.children[name]
            event("process-exited", component=name, exit_code=returncode)
            if name == "gateway" and read_state()["desired"] != "running":
                continue
            if name == "gateway" and whatsapp_status(self.runtime) != "paired":
                write_state("maintenance", "WhatsApp requires pairing")
                continue
            now = time.monotonic()
            failures = self.failures[name]
            while failures and now - failures[0] > RESTART_WINDOW:
                failures.popleft()
            if returncode != 75 or now - child.started < 30:
                failures.append(now)
            if len(failures) > MAX_RESTARTS or returncode == 78:
                if name == "gateway":
                    self.gateway_failure = "gateway: restart budget exhausted or fatal error"
                    write_state("failed", self.gateway_failure)
                    self.diagnose("gateway", self.gateway_failure)
                    continue
                raise PolicyError(f"{name}: restart budget exhausted or fatal policy error")
            self.retry_at[name] = now + 2 ** max(0, len(failures) - 1)
        if self.failure:
            return
        desired = read_state()["desired"]
        if desired != "running":
            if "gateway" in self.children:
                self.stop("gateway")
        elif whatsapp_status(self.runtime) == "re-pair-required":
            write_state("maintenance", "WhatsApp requires pairing")
            self.stop("gateway")
        for name in COMMANDS:
            if name not in self.children and time.monotonic() >= self.retry_at[name]:
                self.start(name)

    def fail(self, error: Exception) -> None:
        self.failure = error_message(error)
        try:
            write_state("failed", self.failure[:256])
        except (PolicyError, OSError) as exc:
            self.diagnose("state", error_message(exc))
        event("managed-failure", diagnostic=self.failure)
        self.stop_all()

    def connection(self, connection: socket.socket, *, awaiting: bool = False) -> None:
        connection.settimeout(CONTROL_TIMEOUT)
        try:
            raw = bytearray()
            while b"\n" not in raw:
                chunk = connection.recv(4097 - len(raw))
                if not chunk or len(raw) + len(chunk) > 4096:
                    raise PolicyError("invalid bounded control request")
                raw.extend(chunk)
            if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
                raise PolicyError("invalid control framing")
            request = json.loads(raw, object_pairs_hook=_unique_object)
            if not isinstance(request, dict) or set(request) != {"command"} or not isinstance(request["command"], str):
                raise PolicyError("invalid control request fields")
            if awaiting:
                if request["command"] != "status":
                    raise PolicyError("awaiting first atomic runtime.json upload")
                status = self.status()
                status.update(dashboard="awaiting-runtime", gateway="maintenance", whatsapp="not-paired")
            else:
                status = self.handle(request["command"])
            response = {"ok": True, "status": status}
        except (PolicyError, ValueError, OSError, RecursionError) as exc:
            message = error_message(exc) if isinstance(exc, (PolicyError, OSError)) else "invalid control request"
            event("control-denied", diagnostic=message)
            if isinstance(exc, OSError) and not isinstance(exc, (ConnectionError, TimeoutError)):
                self.fail(exc)
            response = {"ok": False, "error": message}
        try:
            connection.sendall(json.dumps(response).encode() + b"\n")
        except OSError:
            event("control-client-gone")

    def await_runtime(self, listener: socket.socket, timeout: float = 180) -> None:
        if RUNTIME.exists():
            return
        event("awaiting-runtime", deadline_seconds=timeout)
        deadline = time.monotonic() + timeout
        while not RUNTIME.exists():
            if self.shutting_down or time.monotonic() >= deadline:
                raise PolicyError("initial runtime.json upload deadline expired; no service became ready")
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            with connection:
                self.connection(connection, awaiting=True)

    def serve(self) -> int:
        verify_tmpfs()
        private_directory(RUNTIME_DIRECTORY)
        if CONTROL_SOCKET.exists():
            if not CONTROL_SOCKET.is_socket():
                raise PolicyError("control socket path is not a socket")
            CONTROL_SOCKET.unlink()
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(CONTROL_SOCKET))
            os.chmod(CONTROL_SOCKET, 0o600)
            listener.listen(8)
            listener.settimeout(0.25)
            try:
                try:
                    self.await_runtime(listener)
                    self.apply()
                    for name in COMMANDS:
                        self.start(name)
                except (PolicyError, OSError) as exc:
                    self.fail(exc)
                while not self.shutting_down:
                    try:
                        if not self.failure:
                            self.tick()
                    except (PolicyError, OSError) as exc:
                        self.fail(exc)
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        self.connection(connection)
            finally:
                self.stop_all()
                CONTROL_SOCKET.unlink(missing_ok=True)
        return 0


def main() -> int:
    os.umask(0o077)
    try:
        disk_free_bytes()
        private_directory(HOME)
        with exclusive_lock(HOME / "supervisor.lock"):
            supervisor = Supervisor()
            def shutdown(_signal, _frame):
                supervisor.shutting_down = True
            signal.signal(signal.SIGTERM, shutdown)
            signal.signal(signal.SIGINT, shutdown)
            return supervisor.serve()
    except (PolicyError, OSError) as exc:
        message = str(exc) if isinstance(exc, PolicyError) else "managed supervisor operating-system failure"
        event("startup-failed", diagnostic=message)
        return 78


if __name__ == "__main__":
    sys.exit(main())
