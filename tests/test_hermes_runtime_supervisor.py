"""Host lifecycle state-machine tests without importing the Hermes package."""

from __future__ import annotations

from contextlib import ExitStack
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hermes/image"))
import runtime
import supervisor
import lifecycle


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.state = {"schema_version": 1, "desired": "running", "diagnostic": ""}
        self.s = supervisor.Supervisor()
        self.s.runtime = {"owner": {}, "google": {"enabled": False}}
        self.s.validate = Mock()
        self.stack.enter_context(patch.object(supervisor, "read_state", side_effect=lambda: dict(self.state)))
        self.stack.enter_context(patch.object(supervisor, "write_state", side_effect=self.write_state))
        self.absent = self.stack.enter_context(patch.object(supervisor, "prove_gateway_absent"))
        self.wa = self.stack.enter_context(patch.object(supervisor, "whatsapp_status", return_value="paired"))
        self.stack.enter_context(patch.object(supervisor, "google_status", return_value={"status": "disabled"}))
        self.stack.enter_context(patch.object(supervisor, "check_data_disk", return_value=512 * 1024 * 1024))
        self.stack.enter_context(patch.object(supervisor, "event"))
        self.clock = self.stack.enter_context(patch.object(supervisor.time, "monotonic", return_value=100))
        self.spawn = self.stack.enter_context(patch.object(supervisor, "spawn", side_effect=self.spawn_child))
        self.s.environment = Mock(return_value={})
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.stack.enter_context(patch.object(supervisor, "PAIR_LOCK", Path(directory) / "pair.lock"))
        self.stack.enter_context(patch.object(supervisor, "disk_free_bytes", return_value=512 * 1024 * 1024))
        self.stack.enter_context(patch.object(supervisor, "check_data_disk", return_value=512 * 1024 * 1024))

    def write_state(self, desired, diagnostic=""):
        self.state.update(desired=desired, diagnostic=diagnostic)

    def spawn_child(self, name, argv, env):
        return types.SimpleNamespace(name=name, process=Mock(poll=Mock(return_value=None)),
                                     capture=Mock(), stop=Mock(), started=100)

    def test_status_shape_has_no_process_metadata_or_secrets(self):
        self.s.start("dashboard")
        self.assertEqual(set(self.s.status()), {
            "schema_version", "dashboard", "gateway", "whatsapp", "google", "disk_free_bytes",
        })
        self.assertEqual(self.s.status()["dashboard"], "running")
        self.assertNotIn("owner", json.dumps(self.s.status()))

    def test_start_is_idempotent_and_rechecks_policy(self):
        self.s.start("gateway")
        self.s.start("gateway")
        self.assertEqual(self.spawn.call_count, 1)
        self.assertEqual(self.s.validate.call_count, 2)

    def test_missing_pair_is_a_diagnostic_not_a_crash_loop(self):
        self.wa.return_value = "not-paired"
        for _ in range(6):
            self.s.start("gateway")
        self.assertNotIn("gateway", self.s.children)
        self.assertEqual(self.s.status()["gateway"], "not-paired")
        self.assertFalse(self.s.failures["gateway"])

    def test_stop_persists_maintenance_before_signalling(self):
        self.s.start("gateway")
        child = self.s.children["gateway"]
        child.stop.side_effect = lambda: self.assertEqual(self.state["desired"], "maintenance")
        self.s.handle("stop-gateway")
        self.assertEqual(self.state["desired"], "maintenance")
        self.assertNotIn("gateway", self.s.children)
        self.absent.assert_called()

    def test_maintenance_survives_supervisor_recreation(self):
        self.write_state("maintenance")
        replacement = supervisor.Supervisor()
        replacement.runtime = self.s.runtime
        replacement.validate = Mock()
        replacement.start("gateway")
        self.assertNotIn("gateway", replacement.children)
        self.spawn.assert_not_called()

    def test_sigusr1_exit_during_maintenance_cannot_restart(self):
        self.s.start("gateway")
        self.s.children["gateway"].process.poll.return_value = 75
        self.write_state("maintenance")
        self.s.tick()
        self.clock.return_value = 200
        self.s.tick()
        self.assertNotIn("gateway", self.s.children)
        gateway_spawns = [call for call in self.spawn.call_args_list if call.args[0] == "gateway"]
        self.assertEqual(len(gateway_spawns), 1)

    def test_restart_backoff_validates_again_and_refuses_drift(self):
        self.s.start("gateway")
        self.s.start("dashboard")
        self.s.start("proxy")
        self.s.children["gateway"].process.poll.return_value = 75
        self.s.tick()
        self.assertNotIn("gateway", self.s.children)
        self.assertEqual(self.s.retry_at["gateway"], 101)
        self.s.validate.side_effect = runtime.PolicyError("managed profile drift")
        self.clock.return_value = 101
        with self.assertRaisesRegex(runtime.PolicyError, "drift"):
            self.s.tick()
        self.assertNotIn("gateway", self.s.children)

    def test_dashboard_respawn_also_validates_policy_and_inventory(self):
        self.s.start("dashboard")
        self.s.validate.assert_called_with(dashboard=True)
        self.s.children["dashboard"].process.poll.return_value = 1
        self.s.tick()
        self.clock.return_value = 102
        self.s.tick()
        self.s.validate.assert_any_call(dashboard=True)
        self.assertEqual(len([c for c in self.spawn.call_args_list if c.args[0] == "dashboard"]), 2)

    def test_restart_budget_is_finite(self):
        self.s.start("proxy")
        self.s.start("dashboard")
        for iteration in range(supervisor.MAX_RESTARTS):
            self.s.start("gateway")
            self.s.children["gateway"].process.poll.return_value = 1
            self.s.tick()
            self.clock.return_value += 10
        self.s.start("gateway")
        self.s.children["gateway"].process.poll.return_value = 1
        self.s.tick()
        self.assertNotIn("gateway", self.s.children)
        self.assertIn("dashboard", self.s.children)
        self.assertIn("proxy", self.s.children)
        self.assertEqual(self.s.status()["gateway"], "failed")
        self.assertEqual(self.s.status()["dashboard"], "running")

    def test_logged_out_stops_gateway_without_retry(self):
        self.s.start("gateway")
        self.wa.return_value = "re-pair-required"
        self.s.tick()
        self.assertEqual(self.state["desired"], "maintenance")
        self.assertNotIn("gateway", self.s.children)
        self.assertEqual(self.s.status()["whatsapp"], "re-pair-required")

    def test_reconfigure_applies_only_after_all_processes_stop(self):
        for name in supervisor.COMMANDS:
            self.s.start(name)
        old = list(self.s.children.values())
        self.s.apply = Mock(side_effect=lambda: self.assertFalse(self.s.children))
        self.s.handle("reconfigure")
        self.s.apply.assert_called_once()
        for child in old:
            child.stop.assert_called_once()
        self.assertEqual(self.state["desired"], "running")

    def test_reconfigure_keeps_deliberate_maintenance(self):
        self.write_state("maintenance")
        self.s.apply = Mock()
        self.s.handle("reconfigure")
        self.assertEqual(self.state["desired"], "maintenance")
        self.assertNotIn("gateway", self.s.children)
        self.assertIn("dashboard", self.s.children)

    def test_process_reuse_is_never_signalled(self):
        process = Mock(pid=100, poll=Mock(return_value=1))
        child = lifecycle.Child("test", process, identities={100: 10.0, 101: 11.0})
        child.capture = Mock()
        with patch.object(lifecycle, "process_identity", side_effect=lambda pid: 99.0 if pid == 100 else 11.0), \
                patch.object(lifecycle.os, "kill") as kill:
            child.signal(15)
        kill.assert_called_once_with(101, 15)

    def test_initial_upload_wait_is_explicit_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(supervisor, "RUNTIME", Path(directory) / "runtime.json"):
            listener = Mock()
            self.clock.return_value = 100
            with self.assertRaisesRegex(runtime.PolicyError, "deadline expired"):
                self.s.await_runtime(listener, timeout=0)
            self.spawn.assert_not_called()

    def test_status_remains_available_on_low_disk_and_google_failure(self):
        self.s.runtime["google"]["enabled"] = True
        with patch.object(supervisor, "disk_free_bytes", return_value=128), \
                patch.object(supervisor, "google_status", side_effect=runtime.PolicyError("unavailable")):
            status = self.s.status()
        self.assertEqual(status["disk_free_bytes"], 128)
        self.assertEqual(status["google"], "unknown")
        self.assertEqual(len(status), 6)

    def test_disabled_google_does_not_spawn_diagnostics(self):
        with patch.object(supervisor, "google_status", side_effect=AssertionError("Google diagnostic spawned")):
            self.assertEqual(self.s.status()["google"], "disabled")

    def test_running_children_are_stopped_when_reserved_headroom_is_crossed(self):
        for name in supervisor.COMMANDS:
            self.s.start(name)
        with patch.object(supervisor, "check_data_disk", side_effect=runtime.PolicyError("less than 256 MiB")):
            with self.assertRaises(runtime.PolicyError) as context:
                self.s.tick()
        self.s.fail(context.exception)
        self.assertFalse(self.s.children)
        self.assertEqual(self.s.status()["dashboard"], "failed")

    def test_failure_cleanup_attempts_every_child_and_remains_diagnostic(self):
        for name in supervisor.COMMANDS:
            self.s.start(name)
        children = dict(self.s.children)
        for child in children.values():
            child.stop.side_effect = OSError("fixture cleanup failure")
        with patch.object(supervisor, "write_state", side_effect=OSError(28, "No space left")):
            self.s.fail(OSError(28, "No space left"))
        for child in children.values():
            child.stop.assert_called_once()
        self.assertEqual(self.s.status()["dashboard"], "failed")

    def test_raw_start_and_reconfigure_refuse_active_pairing(self):
        with runtime.exclusive_lock(supervisor.PAIR_LOCK):
            for command in ("start-gateway", "reconfigure"):
                with self.assertRaisesRegex(runtime.PolicyError, "already owns"):
                    self.s.handle(command)
        self.spawn.assert_not_called()

    def test_planned_restart_after_stable_uptime_does_not_exhaust_crash_budget(self):
        for name in supervisor.COMMANDS:
            self.s.start(name)
        for _ in range(6):
            self.clock.return_value += 60
            self.s.children["gateway"].process.poll.return_value = 75
            self.s.tick()
            self.clock.return_value += 2
            self.s.tick()
        self.assertFalse(self.s.failures["gateway"])
        self.assertEqual(self.s.status()["gateway"], "running")


class ControlSocketTests(unittest.TestCase):
    def test_real_socket_loop_survives_partial_empty_closed_silent_and_malformed_clients(self):
        import socket
        import threading
        import time

        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            path = Path(directory) / "control.sock"
            s = supervisor.Supervisor()
            listening = threading.Event()
            s.await_runtime = Mock(side_effect=lambda _listener: listening.set())
            s.apply = Mock(side_effect=runtime.PolicyError("boot fixture failure"))
            s.stop_all = Mock(return_value=[])
            status = {"schema_version": 1, "dashboard": "failed", "gateway": "failed",
                      "whatsapp": "unknown", "google": "unknown", "disk_free_bytes": 128}
            s.status = Mock(return_value=status)
            stack.enter_context(patch.object(supervisor, "CONTROL_SOCKET", path))
            stack.enter_context(patch.object(supervisor, "RUNTIME_DIRECTORY", Path(directory)))
            stack.enter_context(patch.object(supervisor, "CONTROL_TIMEOUT", 0.08))
            stack.enter_context(patch.object(supervisor, "verify_tmpfs"))
            stack.enter_context(patch.object(supervisor, "write_state", side_effect=OSError(28, "disk full")))
            stack.enter_context(patch.object(supervisor, "event"))
            failure = []

            def serve():
                try:
                    s.serve()
                except Exception as exc:
                    failure.append(exc)

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                # await_runtime starts after listen(); socket-path existence proves only bind().
                self.assertTrue(listening.wait(timeout=3), f"control listener did not become ready: {failure}")
                for payload in (b"", b'{"command":"status"}\n', b"garbage\n", b'{"command":[]}\n',
                                b'{"command":"status","command":"stop-gateway"}\n',
                                b'[' * 1500 + b']' * 1500 + b'\n'):
                    with socket.socket(socket.AF_UNIX) as client:
                        client.connect(str(path))
                        if payload:
                            client.sendall(payload)
                with socket.socket(socket.AF_UNIX) as silent:
                    silent.connect(str(path))
                    time.sleep(0.15)
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(2)
                    client.connect(str(path))
                    client.sendall(b'{"command":')
                    time.sleep(0.02)
                    client.sendall(b'"status"}\n')
                    response = json.loads(client.recv(4096))
                    self.assertEqual(response, {"ok": True, "status": status})
                self.assertEqual(failure, [])
                self.assertTrue(thread.is_alive())
                self.assertTrue(s.failure)
            finally:
                s.shutting_down = True
                thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(failure, [])


if __name__ == "__main__":
    unittest.main()
