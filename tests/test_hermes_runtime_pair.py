"""Pair-control transaction tests; the Node/device boundary is explicitly fake."""

from contextlib import ExitStack
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_hermes_runtime_profile import control, fake_creds, runtime, sample_runtime


class PairTransactionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.home = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.whatsapp = self.home / "whatsapp"
        self.sessions = self.whatsapp / "sessions"
        self.sessions.mkdir(parents=True)
        self.previous = self.sessions / ("pair-" + "a" * 32)
        self.previous.mkdir()
        runtime.atomic_json(self.previous / "creds.json", fake_creds())
        self.session = self.whatsapp / "session"
        self.session.symlink_to(self.previous)
        self.value = sample_runtime()
        self.operations = []
        self.state = "running"
        self.fail_start = False
        self.child = Mock()
        self.process = Mock()
        self.process.wait.return_value = 0
        self.stderr = io.StringIO()
        real_activate, real_cleanup = control.activate, control.remove_pair_stage

        def request(command):
            self.operations.append(command)
            if command == "stop-gateway":
                self.state = "maintenance"
            elif command == "start-gateway":
                if self.fail_start:
                    raise runtime.PolicyError("fixture startup failure")
                self.state = "running"
            return {"gateway": self.state}

        def spawn(argv, **kwargs):
            self.stage = Path(argv[argv.index("--session") + 1])
            self.assertEqual(kwargs["env"]["HERMES_SANDBOX_PAIR_APPROVED"], "1")
            self.assertIn("--pair-only", argv)
            runtime.atomic_json(self.stage / "creds.json", fake_creds())
            return self.process

        for name, value in (
            ("SESSION", self.session), ("WHATSAPP", self.whatsapp), ("PAIR_LOCK", self.home / "pair.lock"),
            ("load_runtime", Mock(return_value=self.value)), ("validate_profile", Mock(return_value=self.value)),
            ("check_data_disk", Mock()), ("child_environment", Mock(return_value={})),
            ("prove_gateway_absent", Mock()), ("request", request), ("Child", Mock(return_value=self.child)),
            ("activate", lambda stage, owner: real_activate(stage, owner, session=self.session)),
            ("remove_pair_stage", lambda stage: real_cleanup(stage, session=self.session)),
        ):
            self.stack.enter_context(patch.object(control, name, value))
        self.stack.enter_context(patch.object(control.subprocess, "Popen", side_effect=spawn))
        self.stack.enter_context(patch.object(control.sys, "stdin", Mock(isatty=Mock(return_value=True))))
        self.stack.enter_context(patch.object(control.sys, "stdout", Mock(isatty=Mock(return_value=True))))
        self.stack.enter_context(patch.object(control.sys, "stderr", self.stderr))

    def test_success_preserves_new_credentials_removes_only_old_stage_and_requires_manual_unlink(self):
        self.assertEqual(control.pair(reconnect=True)["gateway"], "running")
        self.assertEqual(self.session.resolve(), self.stage)
        self.assertFalse(self.previous.exists())
        self.assertEqual(self.operations, ["status", "stop-gateway", "start-gateway"])
        self.assertIn("Unlink the previous", self.stderr.getvalue())
        self.child.stop.assert_called_once()
        with runtime.exclusive_lock(control.PAIR_LOCK):
            pass

    def test_new_activation_followed_by_start_failure_is_not_reported_as_old_credentials_preserved(self):
        self.fail_start = True
        with self.assertRaisesRegex(runtime.PolicyError, "new owner credentials activated"):
            control.pair(reconnect=True)
        self.assertEqual(self.session.resolve(), self.stage)
        self.assertTrue((self.stage / "creds.json").is_file())
        self.assertEqual(self.state, "maintenance")
        self.assertNotIn("existing credentials preserved", self.stderr.getvalue())

    def test_failed_device_pair_does_not_replace_old_credentials_or_claim_remote_revocation(self):
        self.process.wait.return_value = 1
        with self.assertRaisesRegex(runtime.PolicyError, "existing credentials preserved"):
            control.pair(reconnect=True)
        self.assertEqual(self.session.resolve(), self.previous)
        self.assertFalse(self.stage.exists())
        self.assertEqual(self.operations, ["status", "stop-gateway"])
        self.assertEqual(self.state, "maintenance")
        self.assertIn("unlink any newly linked", self.stderr.getvalue())
        self.assertIn("Local staging keys removed", self.stderr.getvalue())

    def test_timeout_stops_pair_process_cleans_its_exact_stage_and_releases_pair_lock(self):
        self.process.wait.side_effect = subprocess.TimeoutExpired("fixture-node", 600)
        with self.assertRaises(subprocess.TimeoutExpired):
            control.pair(reconnect=True)
        self.child.stop.assert_called_once()
        self.assertFalse(self.stage.exists())
        self.assertEqual(self.session.resolve(), self.previous)
        self.assertEqual(self.state, "maintenance")
        with runtime.exclusive_lock(control.PAIR_LOCK):
            pass

    def test_disk_failure_after_pairing_preserves_prior_credentials_and_cleans_staging(self):
        control.check_data_disk.side_effect = [None, OSError(28, "No space left")]
        with self.assertRaises(OSError):
            control.pair(reconnect=True)
        self.assertFalse(self.stage.exists())
        self.assertEqual(self.session.resolve(), self.previous)
        self.assertEqual(self.state, "maintenance")

    def test_failed_runtime_is_not_downgraded_to_maintenance_by_pairing(self):
        self.state = "failed"
        with self.assertRaisesRegex(runtime.PolicyError, "reconfigure before pairing"):
            control.pair(reconnect=True)
        self.assertEqual(self.operations, ["status"])
        self.assertEqual(self.state, "failed")
        self.assertEqual(self.session.resolve(), self.previous)


if __name__ == "__main__":
    unittest.main()
