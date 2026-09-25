"""Host contract tests: no Hermes imports, credentials, network or personal pairing."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, call, patch
import yaml

SUPPORT = Path(__file__).resolve().parents[1] / "hermes/image"
sys.path.insert(0, str(SUPPORT))
import runtime
import managed_policy
import lifecycle
import control
import supervisor


def sample_runtime():
    return {
        "schema_version": 1,
        "foundry": {
            "endpoint": "https://example.services.ai.azure.com/openai/v1",
            "deployment": "personal-assistant", "api_mode": "chat_completions",
            "context_length": 128000, "scope": "https://ai.azure.com/.default",
        },
        "owner": {
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "object_id": "00000000-0000-0000-0000-000000000002",
            "whatsapp_phone": "+420777123456",
        },
        "google": {"enabled": False, "expected_email": "", "calendar_ids": ["primary"]},
    }


def fake_creds(phone="+420777123456"):
    return {"registered": True, "me": {"id": phone[1:] + ":42@s.whatsapp.net", "lid": "987654321:7@lid"}}


class RuntimeContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        self.value = sample_runtime()

    def tearDown(self):
        self.temporary.cleanup()

    def test_manual_workflow_verifies_before_opt_in_immutable_digest_publication(self):
        workflow = next(root / ".github/workflows/hermes-image.yml"
                        for root in (Path(__file__).resolve().parents[1], Path("/test-repo"))
                        if (root / ".github/workflows/hermes-image.yml").is_file())
        text = workflow.read_text()
        document = yaml.safe_load(text)
        trigger = document.get("on", document.get(True))
        self.assertEqual(set(trigger), {"workflow_dispatch"})
        self.assertIs(trigger["workflow_dispatch"]["inputs"]["publish"]["default"], False)
        job = document["jobs"]["image"]
        steps = job["steps"]
        verification = next(index for index, step in enumerate(steps) if "--network none" in step.get("run", ""))
        smoke = next(index for index, step in enumerate(steps)
                     if "HERMES_ENTRYPOINT_IMAGE_TEST=1" in step.get("run", ""))
        sdk_builds = [(index, step) for index, step in enumerate(steps)
                      if step.get("uses", "").startswith("docker/build-push-action@")
                      and step.get("with", {}).get("target") == "verification"]
        self.assertEqual(len(sdk_builds), 1, "CI must build the real SDK verification target")
        sdk_index, sdk_build = sdk_builds[0]
        self.assertEqual(sdk_build["with"]["context"], "hermes/image")
        self.assertEqual(sdk_build["with"]["platforms"], "linux/amd64")
        self.assertIs(sdk_build["with"]["load"], True)
        self.assertIs(sdk_build["with"]["push"], False)
        self.assertNotEqual(sdk_build["with"]["tags"], "hermes-offline-verification:local")
        self.assertNotIn("if", sdk_build)
        self.assertNotIn("continue-on-error", sdk_build)
        login = next(index for index, step in enumerate(steps) if step.get("uses", "").startswith("docker/login-action@"))
        publish = next(index for index, step in enumerate(steps) if step.get("id") == "publish")
        self.assertLess(verification, smoke)
        command = steps[verification]["run"]
        self.assertIn("set -euo pipefail;", command)
        self.assertLess(command.index("uv --no-config pip check --python /opt/hermes/.venv/bin/python;"),
                        command.index("node --test"))
        self.assertNotIn("|| true", command)
        self.assertLess(smoke, login)
        self.assertLess(sdk_index, login)
        self.assertLess(sdk_index, publish)
        for index in (verification, smoke):
            self.assertIn("--network none", steps[index]["run"])
            self.assertIn("--tmpfs /mnt/data:rw,size=1073741824,mode=700", steps[index]["run"])
            self.assertIn("hermes-offline-verification:local", steps[index]["run"])
            self.assertNotIn("if", steps[index])
        self.assertIn("-m unittest test_hermes_deploy_image -v", steps[smoke]["run"])
        self.assertLess(login, publish)
        self.assertEqual(steps[login]["if"], "inputs.publish")
        self.assertEqual(steps[publish]["if"], "inputs.publish")
        self.assertNotIn(":latest", text)
        self.assertIn(".RepoDigests", steps[publish]["run"])
        self.assertIn("$GITHUB_STEP_SUMMARY", steps[publish]["run"])
        self.assertIn("steps.publish.outputs.image_digest", job["outputs"]["image_digest"])

    def test_patcher_syntax_checks_each_emitted_javascript_and_propagates_failure(self):
        import patch_upstream
        from subprocess import CalledProcessError
        sources = {"entry.js": "#!/usr/bin/env node\nexport const value = 1;\n",
                   "policy.mjs": "export const allowed = true;\n", "module.py": "VALUE = 1\n"}
        for name, source in sources.items():
            (self.home / name).write_text(source)
        fingerprints = {name: hashlib.sha256(source.encode()).hexdigest() for name, source in sources.items()}
        with patch.dict(patch_upstream.FINGERPRINTS, fingerprints, clear=True):
            patcher = patch_upstream.Patcher(self.home)
        with patch.object(patch_upstream.subprocess, "run") as run:
            patcher.write()
        self.assertEqual(run.call_args_list, [
            call(["node", "--check", str(self.home / "entry.js")], check=True),
            call(["node", "--check", str(self.home / "policy.mjs")], check=True),
        ])
        with patch.object(patch_upstream.subprocess, "run", side_effect=CalledProcessError(1, ["node"])):
            with self.assertRaises(CalledProcessError):
                patcher.write()

    def test_exact_schema_and_native_provider(self):
        self.assertEqual(runtime.validate_runtime(self.value), self.value)
        config = runtime.managed_config(self.value, google_configured=False)
        self.assertEqual(config["model"]["provider"], "azure-foundry")
        self.assertEqual(config["model"]["auth_mode"], "entra_id")
        self.assertEqual(config["fallback_providers"], [])
        self.assertFalse(config["gateway"]["multiplex_profiles"])
        self.assertEqual(config["approvals"]["mode"], "manual")
        self.assertFalse(config["security"]["allow_lazy_installs"])
        self.assertEqual(config["tools"]["tool_search"]["enabled"], "off")
        self.assertFalse(config["web"]["keyless_fallback"])
        for auxiliary in config["auxiliary"].values():
            self.assertEqual(auxiliary["provider"], "azure-foundry")
            self.assertEqual(auxiliary["model"], self.value["foundry"]["deployment"])
        for platform, toolsets in config["platform_toolsets"].items():
            self.assertEqual(toolsets, ["memory", "clarify"] if platform in {"cli", "tui", "whatsapp"} else [])
        self.assertNotIn("hermes-cli", config["agent"]["disabled_toolsets"])
        self.assertEqual(set(config["agent"]["disabled_toolsets"]), runtime.CONCRETE_TOOLSETS - runtime.BASE_TOOLS)

    def test_schema_rejects_unknown_secret_fields_and_wrong_types(self):
        mutations = [
            lambda v: v.update(token="secret"),
            lambda v: v.update(schema_version=True),
            lambda v: v["foundry"].update(api_key="secret"),
            lambda v: v["foundry"].update(context_length=True),
            lambda v: v["foundry"].update(api_mode="auto"),
            lambda v: v["owner"].update(whatsapp_phone="420777123456"),
            lambda v: v["google"].update(enabled="false"),
            lambda v: v["google"].update(calendar_ids=["primary", "primary"]),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value = copy.deepcopy(self.value)
                mutate(value)
                with self.assertRaises(runtime.PolicyError):
                    runtime.validate_runtime(value)

    def test_endpoint_is_inference_https_without_credentials_query_or_fragment(self):
        for endpoint in (
            "http://example.services.ai.azure.com", "https://localhost:8080",
            "https://example.services.ai.azure.com.attacker.invalid",
            "https://user:pass@example.services.ai.azure.com",
            "https://example.services.ai.azure.com?api-key=secret",
            "https://example.services.ai.azure.com/#fragment",
            "https://example.services.ai.azure.com/api/projects/test",
            "https://example.services.ai.azure.com/agents/test",
            "https://example.services.ai.azure.com/${IDENTITY_HEADER}",
        ):
            with self.subTest(endpoint=endpoint):
                value = copy.deepcopy(self.value)
                value["foundry"]["endpoint"] = endpoint
                with self.assertRaises(runtime.PolicyError):
                    runtime.validate_runtime(value)

    def test_google_aliases_and_exact_three_names(self):
        self.value["google"].update(enabled=True, expected_email="owner@example.com")
        config = runtime.managed_config(self.value, google_configured=True)
        self.assertEqual(set(config["mcp_servers"]), {"google_readonly"})
        server = config["mcp_servers"]["google_readonly"]
        self.assertEqual(server["command"], "/opt/hermes/.venv/bin/python")
        self.assertEqual(server["args"], ["/opt/hermes-sandbox/google/server.py"])
        self.assertEqual(server["tools"]["include"], ["gmail_search", "gmail_read", "calendar_events"])
        self.assertFalse(server["sampling"]["enabled"])
        self.assertFalse(server["elicitation"]["enabled"])
        for alias in ("google_readonly", "mcp-google_readonly"):
            self.assertIn(alias, runtime.ALLOWED_TOOLSETS)
            self.assertNotIn(alias, config["agent"]["disabled_toolsets"])

    def test_profile_is_exact_and_keeps_personal_memory_and_persona(self):
        (self.home / "SOUL.md").write_text("Personal identity remains")
        (self.home / "MEMORY.md").write_text("Private memory remains")
        changed = runtime.apply_profile(self.value, home=self.home, configured=False)
        self.assertTrue(changed)
        runtime.validate_profile(self.value, home=self.home, configured=False)
        self.assertEqual((self.home / "SOUL.md").read_text(), "Personal identity remains")
        self.assertEqual((self.home / "MEMORY.md").read_text(), "Private memory remains")
        self.assertEqual(runtime.apply_profile(self.value, home=self.home, configured=False), [])
        self.assertEqual((self.home / "config.yaml").stat().st_mode & 0o777, 0o600)

    def test_profile_drift_fails_without_repair(self):
        runtime.apply_profile(self.value, home=self.home, configured=False)
        config = json.loads((self.home / "config.yaml").read_text())
        config["platform_toolsets"]["cli"].append("terminal")
        runtime.atomic_json(self.home / "config.yaml", config)
        before = (self.home / "config.yaml").read_bytes()
        with self.assertRaisesRegex(runtime.PolicyError, "drift"):
            runtime.validate_profile(self.value, home=self.home, configured=False)
        self.assertEqual((self.home / "config.yaml").read_bytes(), before)
        changed = runtime.apply_profile(self.value, home=self.home, configured=False)
        self.assertEqual(changed, ["platform_toolsets.cli"])

    def test_runtime_change_requires_explicit_reconfigure(self):
        runtime.apply_profile(self.value, home=self.home, configured=False)
        changed = copy.deepcopy(self.value)
        changed["foundry"]["deployment"] = "different"
        with self.assertRaisesRegex(runtime.PolicyError, "runtime policy drift"):
            runtime.validate_profile(changed, home=self.home)

    def test_diagnostic_field_names_never_include_values(self):
        old = runtime.managed_config(self.value, google_configured=False)
        old["model"]["base_url"] = "sensitive-value"
        old["secret-key-value"] = "sensitive-value"
        runtime.atomic_json(self.home / "config.yaml", old)
        changed = runtime.apply_profile(self.value, home=self.home, configured=False)
        self.assertIn("model.base_url", changed)
        self.assertNotIn("sensitive-value", repr(changed))
        self.assertNotIn("secret-key-value", repr(changed))

    def test_environment_secrets_never_go_to_profile_or_runtime(self):
        with patch.dict(os.environ, {"IDENTITY_HEADER": "SECRET_MI_HEADER", "OPENAI_API_KEY": "SECRET_API_KEY"}):
            environment = runtime.child_environment(self.value)
            self.assertEqual(environment["IDENTITY_HEADER"], "SECRET_MI_HEADER")
            self.assertNotIn("OPENAI_API_KEY", environment)
            runtime.apply_profile(self.value, home=self.home, configured=False)
        content = (self.home / ".env").read_text() + (self.home / "config.yaml").read_text()
        self.assertNotIn("SECRET", content)
        self.assertEqual(environment["AZURE_TOKEN_CREDENTIALS"], "ManagedIdentityCredential")
        self.assertEqual(environment["HERMES_CWD"], "/mnt/data")
        with self.assertRaises(runtime.PolicyError):
            runtime.validate_profile(self.value, home=self.home, configured=False,
                                     environment={**environment, "AZURE_TOKEN_CREDENTIALS": "EnvironmentCredential"})

    def test_unmanaged_env_secrets_are_not_silently_erased(self):
        runtime.atomic_write(self.home / ".env", b"UNMANAGED_TOKEN=secret\n")
        with self.assertRaises(runtime.PolicyError):
            runtime.apply_profile(self.value, home=self.home, configured=False)
        self.assertEqual((self.home / ".env").read_text(), "UNMANAGED_TOKEN=secret\n")

    def test_duplicate_oversized_public_and_symlink_json_fail(self):
        destination = self.home / "runtime.json"
        runtime.atomic_write(destination, b'{"a":1,"a":2}')
        with self.assertRaises(runtime.PolicyError):
            runtime.read_json(destination)
        runtime.atomic_write(destination, b'"' + b"x" * 66000 + b'"')
        with self.assertRaises(runtime.PolicyError):
            runtime.read_json(destination)
        runtime.atomic_json(destination, {})
        os.chmod(destination, 0o644)
        with self.assertRaises(runtime.PolicyError):
            runtime.read_json(destination)
        os.chmod(destination, 0o600)
        link = self.home / "alias.json"
        link.symlink_to(destination)
        with self.assertRaises(runtime.PolicyError):
            runtime.read_json(link)
        hardlink = self.home / "hardlink.json"
        os.link(destination, hardlink)
        with self.assertRaises(runtime.PolicyError):
            runtime.read_json(destination)

    def test_disk_requires_mount_and_reserved_headroom(self):
        mountinfo = self.home / "mountinfo"
        mountinfo.write_text(f"11 1 0:30 / {self.home} rw - ext4 /dev/example rw\n")
        for free, expected in ((runtime.MIN_FREE_BYTES, True), (runtime.MIN_FREE_BYTES - 1, False)):
            usage = types.SimpleNamespace(f_bavail=free, f_frsize=1)
            with patch.object(runtime.os, "statvfs", return_value=usage):
                if expected:
                    self.assertEqual(runtime.check_data_disk(self.home, mountinfo), free)
                else:
                    with self.assertRaisesRegex(runtime.PolicyError, "256 MiB"):
                        runtime.check_data_disk(self.home, mountinfo)
        mountinfo.write_text("11 1 0:30 / / rw - ext4 /dev/example rw\n")
        with self.assertRaisesRegex(runtime.PolicyError, "root filesystem fallback"):
            runtime.check_data_disk(self.home, mountinfo)

    def test_tmpfs_has_no_disk_fallback(self):
        mountinfo = self.home / "mountinfo"
        mountinfo.write_text("11 1 0:30 / /dev/shm rw - ext4 /dev/example rw\n")
        with self.assertRaises(runtime.PolicyError):
            lifecycle.verify_tmpfs(mountinfo)
        mountinfo.write_text("11 1 0:30 / /dev/shm rw - tmpfs shm rw\n")
        lifecycle.verify_tmpfs(mountinfo)

    def test_profile_and_plugin_expansion_fails(self):
        for name in ("profiles", "plugins", "bin"):
            directory = self.home / name
            directory.mkdir()
            (directory / "foreign").write_text("not allowed")
            with self.assertRaises(runtime.PolicyError):
                runtime.check_single_profile(self.home)
            (directory / "foreign").unlink()

    def test_whatsapp_owner_jid_and_lid_are_exact(self):
        ids = runtime.verified_identity(fake_creds(), self.value["owner"]["whatsapp_phone"])
        self.assertEqual(ids, {"420777123456@s.whatsapp.net", "987654321@lid"})
        for creds in (
            fake_creds("+420777123457"), {"registered": False}, {"registered": True, "me": {}},
            {"registered": True, "me": {"id": "420777123456@g.us"}},
            {"registered": True, "me": {"id": "420777123456@s.whatsapp.net", "lid": "attacker@lid"}},
        ):
            with self.assertRaises(runtime.PolicyError):
                runtime.verified_identity(creds, self.value["owner"]["whatsapp_phone"])

    def test_logged_out_is_repair_required_not_missing_pairing(self):
        session = self.home / "session"
        self.assertEqual(runtime.whatsapp_status(self.value, session), "not-paired")
        session.mkdir()
        runtime.atomic_json(session / "creds.json", fake_creds())
        self.assertEqual(runtime.whatsapp_status(self.value, session), "paired")
        runtime.atomic_json(self.home / "connection-state.json", {"state": "loggedOut"})
        self.assertEqual(runtime.whatsapp_status(self.value, session), "re-pair-required")
        runtime.atomic_json(self.home / "connection-state.json", {"state": "pair-required"})
        self.assertEqual(runtime.whatsapp_status(self.value, session), "re-pair-required")
        runtime.atomic_json(self.home / "connection-state.json", [])
        with self.assertLogs("runtime", level="ERROR"):
            self.assertEqual(runtime.whatsapp_status(self.value, session), "re-pair-required")

    def test_disabled_google_profile_does_not_need_google_imports(self):
        with patch.object(runtime, "google_status", side_effect=AssertionError("Google diagnostic spawned")):
            self.assertEqual(runtime.expected_profile(self.value)["mcp_servers"], {})

    def test_pair_stage_cleanup_cannot_remove_active_or_unknown_path(self):
        sessions = self.home / "sessions"
        sessions.mkdir()
        stage = sessions / ("pair-" + "a" * 32)
        stage.mkdir()
        runtime.atomic_json(stage / "creds.json", fake_creds())
        session = self.home / "session"
        session.symlink_to(stage)
        with self.assertRaisesRegex(runtime.PolicyError, "active"):
            control.remove_pair_stage(stage, session=session)
        session.unlink()
        control.remove_pair_stage(stage, session=session)
        self.assertFalse(stage.exists())
        with self.assertRaises(runtime.PolicyError):
            control.remove_pair_stage(sessions, session=session)

    def test_accidental_pair_on_existing_credentials_does_not_stop_gateway(self):
        session = self.home / "session"
        session.mkdir()
        with patch.object(control.sys, "stdin", Mock(isatty=Mock(return_value=True))), \
                patch.object(control.sys, "stdout", Mock(isatty=Mock(return_value=True))), \
                patch.object(control, "load_runtime", return_value=self.value), \
                patch.object(control, "check_data_disk"), \
                patch.object(control, "validate_profile", return_value=self.value), \
                patch.object(control, "SESSION", session), \
                patch.object(control, "request") as request:
            with self.assertRaisesRegex(runtime.PolicyError, "reconnect"):
                control.pair()
        request.assert_not_called()

    def test_pair_activation_is_atomic_and_wrong_owner_preserves_previous(self):
        sessions = self.home / "sessions"
        sessions.mkdir()
        old = sessions / "old"
        old.mkdir()
        runtime.atomic_json(old / "creds.json", fake_creds())
        session = self.home / "session"
        session.symlink_to("sessions/old")
        stage = sessions / "new"
        stage.mkdir()
        runtime.atomic_json(stage / "creds.json", fake_creds("+420777123457"))
        with self.assertRaises(runtime.PolicyError):
            control.activate(stage, self.value["owner"]["whatsapp_phone"], session=session)
        self.assertEqual(session.resolve(), old.resolve())
        runtime.atomic_json(stage / "creds.json", fake_creds())
        control.activate(stage, self.value["owner"]["whatsapp_phone"], session=session)
        self.assertEqual(session.resolve(), stage.resolve())
        self.assertTrue((old / "creds.json").exists())

    def test_pair_without_interactive_terminal_is_rejected_before_any_actions(self):
        with patch.object(sys.stdin, "isatty", return_value=False), patch.object(control, "request") as call:
            with self.assertRaises(runtime.PolicyError):
                control.pair()
            call.assert_not_called()

    def test_pair_and_start_lock_is_exclusive(self):
        lock = self.home / "operation.lock"
        with runtime.exclusive_lock(lock):
            with self.assertRaises(runtime.PolicyError):
                with runtime.exclusive_lock(lock):
                    self.fail("second operation acquired the lock")
        with runtime.exclusive_lock(lock):
            pass

    def test_command_aliases_and_management_are_fail_closed(self):
        for command in ("/tools", "/toolsets all", "/model", "/provider x", "/profiles", "/restart",
                        "/whatsapp", "/skills", "/install", "/cron", "/yolo", "/memory edit",
                        "/m", "/login", "/quick-command", "!cat /mnt/data/secrets/google/credentials.json"):
            with self.subTest(command=command):
                self.assertFalse(managed_policy.command_allowed(command))
        for command in ("/help", "/status", "/stop", "/new", "/retry", "/memory", "/resume session-id"):
            self.assertTrue(managed_policy.command_allowed(command))


if __name__ == "__main__":
    unittest.main()
