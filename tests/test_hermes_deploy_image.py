"""Real production-entrypoint smoke on a fresh, disposable offline data mount."""

from __future__ import annotations

import json
import importlib.util
import os
from pathlib import Path
import platform
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request


@unittest.skipUnless(
    os.environ.get("HERMES_ENTRYPOINT_IMAGE_TEST") == "1",
    "requires the directly built production image and a fresh offline data mount",
)
class ProductionEntrypointTests(unittest.TestCase):
    def test_fresh_boot_atomic_runtime_maintenance_reserve_and_shutdown(self):
        if (
            platform.system() != "Linux" or platform.machine() != "x86_64" or os.getuid() != 0
            or not Path("/.dockerenv").exists() or not os.path.ismount("/mnt/data")
            or {name for _, name in socket.if_nameindex()
                if int(Path("/sys/class/net", name, "flags").read_text(), 16) & 1} != {"lo"}
        ):
            raise RuntimeError("This smoke requires one root amd64 --network none Docker container.")
        self.assertEqual(list(Path("/mnt/data").iterdir()), [], "Refusing a nonempty data mount.")
        sys.path.insert(0, "/opt/hermes-sandbox")
        import runtime
        from lifecycle import CONTROL_SOCKET, Child
        from test_hermes_runtime_profile import sample_runtime

        with tempfile.TemporaryDirectory(prefix="hermes-entrypoint-smoke-") as directory:
            temporary = Path(directory)
            attempts = temporary / "package-manager-invoked"
            hook = temporary / "hermes_smoke_packages.py"
            hook.write_text(
                "import os, shlex, sys\n"
                "from pathlib import Path\n"
                f"marker = Path({str(attempts)!r})\n"
                "def audit(event, values):\n"
                "    if event != 'subprocess.Popen': return\n"
                "    argv = values[1]\n"
                "    if isinstance(argv, str): argv = shlex.split(argv)\n"
                "    names = {'npm', 'npx', 'pip', 'pip3', 'uv'}\n"
                "    direct = bool(argv) and os.path.basename(str(argv[0])) in names\n"
                "    module = any(str(arg) == '-m' and str(argv[index + 1]) in {'pip', 'uv'}\n"
                "                 for index, arg in enumerate(argv[:-1]))\n"
                "    npm_js = any(os.path.basename(str(arg)) in {'npm-cli.js', 'npx-cli.js'} for arg in argv)\n"
                "    if direct or module or npm_js:\n"
                "        marker.touch(mode=0o600)\n"
                "        raise RuntimeError('Runtime package-manager attempt blocked by the offline fixture')\n"
                "sys.addaudithook(audit)\n"
            )
            site_packages = Path(importlib.util.find_spec("aiohttp").origin).parent.parent
            hook_path = site_packages / "hermes_smoke_packages.pth"
            self.assertFalse(hook_path.exists())
            wrapper = (
                "#!/opt/hermes/.venv/bin/python\n"
                "from pathlib import Path\n"
                f"Path({str(attempts)!r}).touch(mode=0o600)\n"
                "raise SystemExit(97)\n"
            )
            managers = [
                Path("/usr/local/bin/npm"), Path("/usr/local/bin/npx"), Path("/usr/local/bin/uv"),
                Path("/opt/hermes/.venv/bin/pip"), Path("/opt/hermes/.venv/bin/pip3"),
            ]
            backups = []
            child = None
            reserve_probe = Path("/mnt/data/.hermes-smoke-headroom")
            try:
                hook_path.write_text(str(temporary) + "\nimport hermes_smoke_packages\n")
                for manager in managers:
                    backup = manager.with_name(".hermes-smoke-original-" + manager.name)
                    self.assertFalse(backup.exists() or backup.is_symlink())
                    existed = manager.exists() or manager.is_symlink()
                    if existed:
                        manager.rename(backup)
                    backups.append((manager, backup, existed))
                    manager.write_text(wrapper)
                    manager.chmod(0o755)
                    sentinel = subprocess.run([str(manager), "--version"], capture_output=True, timeout=10)
                    self.assertEqual(sentinel.returncode, 97)
                    self.assertTrue(attempts.exists())
                    attempts.unlink()
                module_probe = subprocess.run(
                    [str(runtime.PYTHON), "-c",
                     "import subprocess,sys; subprocess.run([sys.executable, '-m', 'pip', '--version'])"],
                    capture_output=True, timeout=10,
                )
                self.assertNotEqual(module_probe.returncode, 0)
                self.assertTrue(attempts.exists())
                attempts.unlink()
                log_path = temporary / "entrypoint.log"
                with log_path.open("wb") as log:
                    process = subprocess.Popen(
                        ["/usr/bin/tini", "-s", "--", "/usr/local/bin/container-entrypoint"],
                        cwd="/mnt/data", stdout=log, stderr=log, start_new_session=True,
                    )
                child = Child("production-entrypoint-smoke", process)

                def control(command="status", expected=0):
                    args = [str(runtime.PYTHON), "/opt/hermes-sandbox/control.py", command]
                    if command == "status":
                        args.append("--json")
                    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    return json.loads(result.stdout if expected == 0 else result.stderr)

                def wait_status(predicate, label, timeout=45):
                    deadline = time.monotonic() + timeout
                    while time.monotonic() < deadline and process.poll() is None:
                        child.capture()
                        if CONTROL_SOCKET.exists():
                            current = control()
                            if predicate(current):
                                return current
                        time.sleep(0.1)
                    self.fail(label + "; sanitized supervisor log: " + log_path.read_text()[-3000:])

                initial = wait_status(lambda value: value["dashboard"] == "awaiting-runtime", "Initial upload window")
                self.assertEqual(set(initial), {
                    "schema_version", "dashboard", "gateway", "whatsapp", "google", "disk_free_bytes",
                })
                self.assertEqual(initial["gateway"], "maintenance")
                self.assertEqual(initial["whatsapp"], "not-paired")
                self.assertGreaterEqual(initial["disk_free_bytes"], runtime.MIN_FREE_BYTES)
                self.assertFalse(Path("/dev/shm/hermes/access-key").exists())
                runtime.atomic_json(runtime.RUNTIME, sample_runtime())
                self.assertEqual(runtime.RUNTIME.stat().st_uid, 0)
                self.assertEqual(stat.S_IMODE(runtime.RUNTIME.stat().st_mode), 0o600)
                ready = wait_status(lambda value: value["dashboard"] == "running", "Native dashboard start")
                self.assertIn(ready["gateway"], {"not-paired", "maintenance"})
                self.assertEqual(ready["google"], "disabled")
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                deadline = time.monotonic() + 30
                while True:
                    try:
                        with opener.open("http://127.0.0.1:9119/chat", timeout=2) as response:
                            html = response.read(512 * 1024)
                            self.assertEqual(response.status, 200)
                            self.assertIn(b"__HERMES_SESSION_TOKEN__", html)
                            break
                    except urllib.error.URLError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
                with self.assertRaises(urllib.error.HTTPError) as unauthorized:
                    opener.open("http://127.0.0.1:8080/", timeout=3)
                self.assertEqual(unauthorized.exception.code, 401)
                self.assertEqual(unauthorized.exception.headers["X-Hermes-Access-Key-Expired"], "1")
                unauthorized.exception.close()
                stopped = control("stop-gateway")
                self.assertEqual(stopped["gateway"], "maintenance")
                configured = control("reconfigure")
                self.assertEqual(configured["gateway"], "maintenance")
                wait_status(lambda value: value["dashboard"] == "running", "Reconfigured dashboard")
                denied = control("start-gateway", expected=1)
                self.assertIn("not paired", denied["error"])
                self.assertEqual(control()["gateway"], "maintenance")
                free = runtime.disk_free_bytes()
                with reserve_probe.open("wb") as probe:
                    os.fchmod(probe.fileno(), 0o600)
                    os.posix_fallocate(probe.fileno(), 0, free - 255 * 1024 * 1024)
                    probe.flush()
                    os.fsync(probe.fileno())
                failed = wait_status(lambda value: value["dashboard"] == "failed", "Real disk-reserve boundary")
                self.assertLess(failed["disk_free_bytes"], runtime.MIN_FREE_BYTES)
                self.assertEqual(failed["gateway"], "failed")
                reserve_probe.unlink()
                recovered = control("reconfigure")
                self.assertIn(recovered["gateway"], {"not-paired", "maintenance"})
                wait_status(lambda value: value["dashboard"] == "running", "Explicit reserve recovery")
                self.assertFalse(attempts.exists(), "A runtime package manager was invoked.")
                process.send_signal(signal.SIGTERM)
                self.assertEqual(process.wait(timeout=30), 0)
                self.assertFalse(CONTROL_SOCKET.exists())
                self.assertTrue(runtime.RUNTIME.exists())
                self.assertFalse(attempts.exists(), "A runtime package manager was invoked during shutdown.")
            finally:
                reserve_probe.unlink(missing_ok=True)
                if child is not None:
                    child.stop(timeout=8)
                hook_path.unlink(missing_ok=True)
                for manager, backup, existed in reversed(backups):
                    manager.unlink(missing_ok=True)
                    if existed:
                        backup.rename(manager)


if __name__ == "__main__":
    unittest.main()
