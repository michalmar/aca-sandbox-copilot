"""Exact-process ownership and the native gateway absence proof."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

from runtime import HOME, PolicyError

PROCFS = Path("/proc")
RUNTIME_DIRECTORY = Path("/dev/shm/hermes")
CONTROL_SOCKET = RUNTIME_DIRECTORY / "control.sock"
OPERATION_LOCK = HOME / "control.lock"
PAIR_LOCK = HOME / "pair.lock"


def native_gateway_identity():
    from gateway.status import get_running_pid_identity_strict
    try:
        return get_running_pid_identity_strict(HOME / "gateway.pid")
    except (RuntimeError, OSError, ValueError) as exc:
        raise PolicyError("native gateway lock/PID identity cannot be proved") from exc


def prove_gateway_absent() -> None:
    if native_gateway_identity() is not None:
        raise PolicyError("a native gateway still owns this home; refusing concurrent operation")
    prove_bridge_absent()


def prove_bridge_absent(port: int = 3000) -> None:
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as exc:
            raise PolicyError("a WhatsApp bridge still owns port 3000; no process was adopted or killed") from exc


def verify_tmpfs(mountinfo: Path = Path("/proc/self/mountinfo")) -> None:
    try:
        valid = any(line.split()[4] == "/dev/shm" and line.partition(" - ")[2].split()[0] == "tmpfs"
                    for line in mountinfo.read_text().splitlines())
    except (OSError, IndexError) as exc:
        raise PolicyError("cannot verify runtime tmpfs") from exc
    if not valid:
        raise PolicyError("/dev/shm must be tmpfs; persistent control/key fallback is forbidden")


def process_identity(pid: int) -> int | None:
    # Kernel start time in clock ticks since boot. psutil's wall-clock create_time() re-adds the
    # current /proc/stat btime, so a guest clock adjustment would make every owned process unrecognized.
    try:
        stat = (PROCFS / str(pid) / "stat").read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError as exc:
        raise PolicyError("owned process identity cannot be read") from exc
    _, closing, tail = stat.rpartition(b")")
    fields = tail.split()
    if not closing or len(fields) < 20 or not fields[19].isdigit():
        raise PolicyError("owned process identity cannot be read")
    return None if fields[0] in (b"Z", b"X") else int(fields[19])


@dataclass
class Child:
    name: str
    process: subprocess.Popen
    started: float = field(default_factory=time.monotonic)
    identities: dict[int, int] = field(default_factory=dict)

    def capture(self) -> None:
        import psutil
        parent_running = self.process.poll() is None
        try:
            root = psutil.Process(self.process.pid)
            if not parent_running:
                return  # A reaped child's PID cannot legitimately name a current session leader.
            current = process_identity(self.process.pid)
            if self.process.pid in self.identities and current is not None and current != self.identities[self.process.pid]:
                return
            for process in [root, *root.children(recursive=True)]:
                identity = process_identity(process.pid)
                if identity is not None:
                    self.identities.setdefault(process.pid, identity)
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied as exc:
            raise PolicyError("owned process descendants cannot be read") from exc
        # A gateway's bridge keeps its SID after the leader dies, including before our first poll.
        for process in psutil.process_iter(["pid"]):
            try:
                if os.getsid(process.pid) == self.process.pid:
                    identity = process_identity(process.pid)
                    if identity is not None:
                        self.identities.setdefault(process.pid, identity)
            except (ProcessLookupError, PermissionError):
                continue

    def live(self) -> list[int]:
        return [pid for pid, identity in self.identities.items() if process_identity(pid) == identity]

    def signal(self, sig: int) -> None:
        self.capture()
        for pid in reversed(self.live()):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                continue

    def stop(self, timeout: float = 12) -> None:
        self.capture()
        if self.process.pid in self.live():
            try:
                os.kill(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        else:
            self.signal(signal.SIGTERM)
        deadline = time.monotonic() + timeout
        orphan_signalled = False
        while self.live() and time.monotonic() < deadline:
            self.capture()
            if self.process.poll() is not None and not orphan_signalled:
                self.signal(signal.SIGTERM)
                orphan_signalled = True
            time.sleep(0.05)
        if self.live():
            self.signal(signal.SIGKILL)
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise PolicyError(f"{self.name}: owned process did not exit") from exc
        deadline = time.monotonic() + 5
        while self.live() and time.monotonic() < deadline:
            time.sleep(0.05)
        if self.live():
            raise PolicyError(f"{self.name}: owned descendant did not exit")


def spawn(name: str, argv: list[str], env: dict[str, str]) -> Child:
    process = subprocess.Popen(
        argv, env=env, cwd="/mnt/data", start_new_session=True, umask=0o077,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    child = Child(name, process)
    child.capture()
    return child
