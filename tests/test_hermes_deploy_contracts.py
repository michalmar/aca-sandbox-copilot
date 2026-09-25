"""Host-tier policy and lifecycle tests; no Azure credentials or cloud mutations."""

import copy
import io
import json
import os
import runpy
import shlex
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError, ServiceRequestError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import cleanup_hermes
import deploy_hermes
import hermes_common as common


def config(**changes):
    values = {
        "subscription_id": "11111111-1111-1111-1111-111111111111",
        "tenant_id": "22222222-2222-2222-2222-222222222222",
        "owner_object_id": "33333333-3333-3333-3333-333333333333",
        "image": "example.invalid/hermes@sha256:" + "a" * 64,
        "foundry_endpoint": "https://personal.services.ai.azure.com/models",
        "foundry_deployment": "existing-deployment",
        "foundry_context_length": 128000,
        "whatsapp_phone": "+420123456789",
        "identity_host": "identity.platform.invalid",
        "whatsapp_hosts": ("web.whatsapp.com",),
    }
    return common.Config(**(values | changes))


class ConfigurationTests(unittest.TestCase):
    def test_runtime_exact_schema_and_no_credentials(self):
        document = common.runtime_document(config())
        self.assertEqual(set(document), {"schema_version", "foundry", "owner", "google"})
        self.assertEqual(set(document["foundry"]), {"endpoint", "deployment", "api_mode", "context_length", "scope"})
        self.assertEqual(common.validate_runtime(document), document)
        self.assertNotIn("IDENTITY_HEADER", json.dumps(document))
        self.assertNotIn("api_key", json.dumps(document))

    def test_invalid_runtime_fields_fail_closed(self):
        changes = [
            ("schema_version", True), ("schema_version", 2), ("unexpected", "secret"),
            ("foundry", {"api_key": "never-allowed"}), ("owner", None), ("google", {"enabled": True}),
        ]
        for field, value in changes:
            with self.subTest(field=field, value=value):
                document = common.runtime_document(config())
                document[field] = value
                with self.assertRaises(ValueError):
                    common.validate_runtime(document)

    def test_runtime_endpoint_and_identity_validation(self):
        for endpoint in (
            "http://model.example.com", "https://user:secret@model.example.com",
            "https://model.example.com/?token=secret", "https://model.example.com:8443/",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                common.runtime_document(config(foundry_endpoint=endpoint))
        for change in (
            {"whatsapp_phone": "123"}, {"foundry_context_length": True}, {"foundry_scope": "wrong"},
            {"google_enabled": True}, {"google_calendar_ids": ("primary", "primary")},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                common.runtime_document(config(**change))

    def test_duplicate_json_and_oversized_json_rejected(self):
        with self.assertRaises(ValueError):
            common.parse_json(b'{"schema_version":1,"schema_version":1}')
        with self.assertRaises(ValueError):
            common.parse_json(b" " * (256 * 1024 + 1))

    def test_hermes_env_never_loads_copilot_env(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text("COPILOT_GITHUB_TOKEN=do-not-read\nAZURE_SUBSCRIPTION_ID=wrong\n")
            path = root / ".env.hermes"
            path.write_text(
                "HERMES_SUBSCRIPTION_ID=11111111-1111-1111-1111-111111111111\n"
                "HERMES_TENANT_ID=22222222-2222-2222-2222-222222222222\n"
                "HERMES_OWNER_OBJECT_ID=33333333-3333-3333-3333-333333333333\n"
            )
            with patch.dict(os.environ, {"AZURE_SUBSCRIPTION_ID": "ignored"}, clear=True):
                loaded = common.Config.from_env(path)
            self.assertEqual(loaded.subscription_id, config().subscription_id)
            self.assertEqual(loaded.location, "swedencentral")
            with self.assertRaises(ValueError):
                common.Config.from_env(root / ".env")
            path.write_text(path.read_text() + "COPILOT_GITHUB_TOKEN=forbidden\n")
            with self.assertRaises(ValueError):
                common.Config.from_env(path)

    def test_credential_is_tenant_pinned_and_clients_subscription_pinned(self):
        with (
            patch.object(common, "AzureCliCredential") as credential,
            patch.object(common, "ResourceManagementClient") as resources,
            patch.object(common, "SandboxGroupManagementClient") as management,
            patch.object(common, "SandboxGroupClient") as group,
        ):
            with common.AzureClients.create(config()):
                pass
        credential.assert_called_once_with(tenant_id=config().tenant_id, process_timeout=30)
        resources.assert_called_once_with(credential.return_value, config().subscription_id)
        self.assertEqual(management.call_args.kwargs["subscription_id"], config().subscription_id)
        self.assertEqual(group.call_args.kwargs["subscription_id"], config().subscription_id)

    def test_environment_overrides_are_reported_by_name_not_value(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env.hermes"
            path.write_text("HERMES_FOUNDRY_DEPLOYMENT=old\n")
            with patch.dict(os.environ, {"HERMES_FOUNDRY_DEPLOYMENT": "private-override"}, clear=True):
                with self.assertLogs("hermes.config", level="WARNING") as captured:
                    values = common._read_env(path)
        self.assertEqual(values["HERMES_FOUNDRY_DEPLOYMENT"], "private-override")
        self.assertIn("HERMES_FOUNDRY_DEPLOYMENT", "\n".join(captured.output))
        self.assertNotIn("private-override", "\n".join(captured.output))

    def test_resource_names_and_images_are_isolated_and_immutable(self):
        for changes in ({"resource_group": "rg-copilot"}, {"image": "registry/hermes:latest"}, {"tenant_id": "email@example.com"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                config(**changes)

    def test_same_names_cannot_adopt_another_owners_hermes_resources(self):
        own = config()
        other = config(owner_object_id="44444444-4444-4444-4444-444444444444")
        self.assertEqual(own.sandbox_name, other.sandbox_name)
        self.assertNotEqual(own.labels, other.labels)
        with self.assertRaisesRegex(RuntimeError, "unowned"):
            common.assert_labels(other.labels, own, "Sandbox Group")
        with self.assertRaisesRegex(RuntimeError, "unowned"):
            common.assert_labels({**common.LABELS, "hermes-deployment": own.sandbox_name}, own, "resource group")


class AzurePolicyTests(unittest.TestCase):
    def setUp(self):
        self.config = config()
        self.identifier = "hermes-sandbox-123"
        self.port = common.port_document(self.config, self.identifier)
        self.egress = common.deployment_egress(self.config)

    def test_raw_payload_exact_resources_suspend_and_one_writer(self):
        payload = common.sandbox_document(self.config, disk_id="image-id", egress=self.egress)
        self.assertEqual(payload["resources"], {"cpu": "2000m", "memory": "4096Mi", "disk": "20Gi"})
        self.assertEqual(payload["lifecycle"], {"autoSuspendPolicy": {"enabled": False}})
        self.assertEqual(payload["volumes"], [{"volumeName": "hermes-data", "mountpoint": "/mnt/data", "readOnly": False}])
        self.assertEqual(payload["environment"], {"AZURE_TOKEN_CREDENTIALS": "ManagedIdentityCredential"})
        self.assertEqual(payload["entrypoint"], ["/usr/bin/tini", "-s", "--", "/usr/local/bin/hermes-entrypoint"])
        self.assertNotIn("ports", payload)

    def test_raw_suspend_readback_required(self):
        for raw in ({}, {"lifecycle": {}}, {"lifecycle": {"autoSuspendPolicy": {"enabled": True}}}):
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                common.assert_no_suspend(raw)
        common.assert_no_suspend({"lifecycle": {"autoSuspendPolicy": {"enabled": False}}})

    def test_exact_object_id_acl_no_tenant_widening(self):
        self.assertEqual(self.port["auth"], {
            "anonymous": False, "entraId": {"enabled": True, "objectIds": [self.config.owner_object_id]},
        })
        common.validate_ports({"ports": [self.port]}, self.config, self.identifier)
        for alteration in (
            {"tenantIds": [self.config.tenant_id]}, {"emails": ["owner@example.com"]},
            {"objectIds": []}, {"enabled": False},
        ):
            mutated = copy.deepcopy(self.port)
            mutated["auth"]["entraId"].update(alteration)
            with self.subTest(alteration=alteration), self.assertRaises(RuntimeError):
                common.validate_ports({"ports": [mutated]}, self.config, self.identifier)

    def test_foreign_ports_are_not_silently_removed(self):
        sandbox = MagicMock()
        sandbox.sandbox_id = self.identifier
        sandbox._dp_get.return_value = {"id": self.identifier, "ports": [self.port, {"port": 3000}]}
        with self.assertRaises(RuntimeError):
            common.configure_port(sandbox, self.config)
        sandbox._dp_put.assert_not_called()

    def test_port_update_uses_raw_put_and_readback(self):
        sandbox = MagicMock()
        sandbox.sandbox_id = self.identifier
        sandbox._sbx_path = "/explicit/sandbox"
        sandbox._dp_get.side_effect = [
            {"id": self.identifier, "ports": []}, {"id": self.identifier, "ports": [self.port]},
        ]
        common.configure_port(sandbox, self.config)
        sandbox._dp_put.assert_called_once_with("/explicit/sandbox/ports", {"ports": [self.port]})
        sandbox.update_ports.assert_not_called()
        sandbox.add_port.assert_not_called()

    def test_port_drift_and_wrong_target_fail(self):
        for key, value in (("port", 8642), ("activationMode", "Manual"), ("protocol", "Tcp"),
                           ("url", "https://evil.invalid"), ("auth", {"anonymous": True})):
            port = copy.deepcopy(self.port)
            port[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                common.validate_ports({"ports": [port]}, self.config, self.identifier)

    def test_egress_deny_default_partial_and_exact_hosts(self):
        self.assertEqual(self.egress["defaultAction"], "Deny")
        self.assertEqual(self.egress["trafficInspection"], "Partial")
        self.assertNotIn("rules", self.egress)
        hosts = {row["pattern"] for row in self.egress["hostRules"]}
        self.assertTrue(set(common.GOOGLE_HOSTS) <= hosts)
        self.assertNotIn("accounts.google.com", hosts)
        for host in ("*.google.com", "https://google.com", "host:443", "bad..host", "HOST.com"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                common.egress_document([host])
        for inspection in ("Full", "None", "Legacy", None):
            changed = dict(self.egress, trafficInspection=inspection)
            with self.subTest(inspection=inspection), self.assertRaises(RuntimeError):
                common.validate_egress({"egressPolicy": changed}, self.egress)

    def test_missing_verified_egress_inputs_block_deployment(self):
        for changes in ({"identity_host": ""}, {"whatsapp_hosts": ()}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                common.deployment_egress(config(**changes))

    def test_dns_or_timeout_alone_is_not_network_deny_proof(self):
        sandbox = MagicMock()
        raw = {"egressPolicy": self.egress}
        allowed = {
            host: {"public_ca_tls": True, "http_status": 404}
            for host in ("personal.services.ai.azure.com", *common.GOOGLE_HOSTS, "web.whatsapp.com")
        }
        evidence = {**allowed, "example.com": {"network_error": "URLError"}}
        sandbox._dp_post.return_value = {"exitCode": 0, "stdout": json.dumps(evidence)}
        sandbox._dp_get.return_value = {"networkEgress": {"denied": []}}
        with patch.object(common, "raw_sandbox", return_value=raw), patch.object(common.time, "monotonic", side_effect=[0, 31]):
            with self.assertRaisesRegex(RuntimeError, "no platform deny"):
                common.verify_partial_network(sandbox, self.config)

    def test_verified_public_tls_and_platform_deny_are_required_together(self):
        sandbox = MagicMock()
        allowed = {
            host: {"public_ca_tls": True, "http_status": 404}
            for host in ("personal.services.ai.azure.com", *common.GOOGLE_HOSTS, "web.whatsapp.com")
        }
        sandbox._dp_post.return_value = {
            "exitCode": 0, "stdout": json.dumps({**allowed, "example.com": {"network_error": "URLError"}}),
        }
        sandbox._dp_get.return_value = {"networkEgress": {"denied": [{"host": "example.com"}]}}
        with patch.object(common, "raw_sandbox", return_value={"egressPolicy": self.egress}):
            result = common.verify_partial_network(sandbox, self.config)
        self.assertTrue(result["platform_deny_observed"])


class PrivateUploadTests(unittest.TestCase):
    def setUp(self):
        self.sandbox = MagicMock()
        self.sandbox._sbx_path = "/test/sandbox"
        self.sandbox._dp_post.return_value = {"exitCode": 0, "stdout": ""}
        self.secret = b'{"refresh_token":"PRIVATE-TEST-SECRET"}'
        self.sandbox.read_file.return_value = self.secret

    def test_fixed_destinations_only(self):
        for path in ("/tmp/token", "/mnt/data/.env", "/mnt/data/secrets/google/../token"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                common.upload_private_file(self.sandbox, destination=path, content=self.secret)
        self.sandbox._dp_post.assert_not_called()

    def test_private_sdk_bytes_then_atomic_rename_without_secret_args(self):
        common.upload_private_file(self.sandbox, destination=common.GOOGLE_CREDENTIAL_PATH, content=self.secret)
        args, kwargs = self.sandbox.write_file.call_args
        self.assertEqual(args[1], self.secret)
        self.assertEqual(kwargs, {"create_dirs": False, "mode": "0600"})
        self.assertRegex(args[0], r"/mnt/data/secrets/google/\.credentials\.json\.[a-f0-9]{32}\.tmp")
        commands = [call.args[1]["command"] for call in self.sandbox._dp_post.call_args_list]
        self.assertEqual(len(commands), 2)
        self.assertTrue(commands[0].endswith("prepare"))
        self.assertTrue(commands[1].endswith("commit"))
        self.assertTrue(all(shlex.split(command)[0] == common.PYTHON for command in commands))
        self.assertNotIn(self.secret.decode(), repr(self.sandbox._dp_post.call_args_list))
        self.assertIn("os.replace", shlex.split(commands[1])[2])
        self.sandbox.read_file.assert_called_once_with(args[0])
        self.sandbox.delete_file.assert_not_called()

    def test_failed_upload_removes_only_its_staging_file(self):
        self.sandbox.write_file.side_effect = HttpResponseError("PRIVATE-TEST-SECRET")
        with self.assertRaisesRegex(RuntimeError, "Private SDK upload failed") as captured:
            common.upload_private_file(self.sandbox, destination=common.GOOGLE_CREDENTIAL_PATH, content=self.secret)
        self.assertNotIn("PRIVATE-TEST-SECRET", str(captured.exception))
        staged = self.sandbox.write_file.call_args.args[0]
        self.sandbox.delete_file.assert_called_once_with(staged)
        self.assertEqual(len(self.sandbox._dp_post.call_args_list), 1)

    def test_failed_exec_never_echoes_secret_output(self):
        self.sandbox._dp_post.return_value = {"exitCode": 1, "stdout": "PRIVATE-TEST-SECRET", "stderr": "PRIVATE-TEST-SECRET"}
        with self.assertRaises(RuntimeError) as captured:
            common.upload_private_file(self.sandbox, destination=common.GOOGLE_CREDENTIAL_PATH, content=self.secret)
        self.assertNotIn("PRIVATE-TEST-SECRET", str(captured.exception))
        self.sandbox.write_file.assert_not_called()

    def test_missing_or_noninteger_exit_code_never_means_success(self):
        for response in ({}, {"stdout": ""}, {"exitCode": None}, {"exitCode": False}, {"exitCode": "0"}):
            with self.subTest(response=response), self.assertRaisesRegex(RuntimeError, "explicit integer exitCode"):
                self.sandbox._dp_post.return_value = response
                common.exec_checked(self.sandbox, [common.PYTHON, "-c", "pass"])
        self.sandbox.exec.assert_not_called()

    def test_incomplete_upload_readback_preserves_target_and_removes_staging(self):
        self.sandbox.read_file.return_value = b'{"partial":'
        with self.assertRaisesRegex(RuntimeError, "previous private file was preserved"):
            common.upload_private_file(self.sandbox, destination=common.GOOGLE_CREDENTIAL_PATH, content=self.secret)
        self.assertEqual(len(self.sandbox._dp_post.call_args_list), 1)
        self.sandbox.delete_file.assert_called_once_with(self.sandbox.write_file.call_args.args[0])

    def test_non_http_azure_failure_is_sanitized_and_cleans_staging(self):
        self.sandbox.write_file.side_effect = ServiceRequestError("PRIVATE-TEST-SECRET")
        with self.assertRaisesRegex(RuntimeError, "Private SDK upload failed") as captured:
            common.upload_private_file(self.sandbox, destination=common.GOOGLE_CREDENTIAL_PATH, content=self.secret)
        self.assertNotIn("PRIVATE-TEST-SECRET", str(captured.exception))
        self.sandbox.delete_file.assert_called_once()

    def test_runtime_secret_fields_are_rejected_before_upload(self):
        content = json.dumps(common.runtime_document(config()) | {"IDENTITY_HEADER": "secret"}).encode()
        with self.assertRaises(ValueError):
            common.upload_private_file(self.sandbox, destination=common.RUNTIME_PATH, content=content)
        self.sandbox.write_file.assert_not_called()

    def test_private_upload_limits_and_invalid_key(self):
        with self.assertRaises(ValueError):
            common.upload_private_file(self.sandbox, destination=common.GOOGLE_CREDENTIAL_PATH, content=b"x" * (256 * 1024 + 1))
        self.sandbox.read_file.return_value = b"a" * 64 + b"\n"
        with self.assertRaises(RuntimeError):
            common.read_access_key(self.sandbox)


class ControlStatusTests(unittest.TestCase):
    def setUp(self):
        self.sandbox = MagicMock()
        self.status = {
            "schema_version": 1, "dashboard": "running", "gateway": "running",
            "whatsapp": "paired", "google": "disabled", "disk_free_bytes": common.MIN_FREE_BYTES,
        }
        self.patcher = patch.object(common, "exec_checked", side_effect=lambda *args: json.dumps(self.status))
        self.execute = self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_schema_only_read_does_not_require_disk_headroom(self):
        for free in (-1, 0, common.MIN_FREE_BYTES - 1):
            with self.subTest(free=free):
                self.status["disk_free_bytes"] = free
                self.assertEqual(common.read_control_status(self.sandbox), self.status)
                with self.assertRaises(RuntimeError):
                    common.control_status(self.sandbox)
        self.execute.assert_called_with(self.sandbox, [*common.CONTROL, "status", "--json"])

    def test_readiness_still_requires_the_exact_reserve_boundary(self):
        self.assertEqual(common.control_status(self.sandbox), self.status)
        self.status["gateway"] = "maintenance"
        self.assertEqual(common.read_control_status(self.sandbox)["gateway"], "maintenance")

    def test_invalid_control_schema_never_provides_gateway_intent(self):
        invalid = [
            {**self.status, "schema_version": True},
            {**self.status, "schema_version": 2},
            {**self.status, "disk_free_bytes": True},
            {**self.status, "disk_free_bytes": -2},
            {**self.status, "disk_free_bytes": "unknown"},
            {**self.status, "gateway": {"state": "running"}},
            {**self.status, "gateway": "running\nPRIVATE-DETAIL"},
            {**self.status, "whatsapp": False},
            {**self.status, "google": []},
            {**self.status, "dashboard": "invented"},
            {**self.status, "extra": "secret"},
            {key: value for key, value in self.status.items() if key != "gateway"},
        ]
        for value in invalid:
            with self.subTest(value=value):
                self.status = value
                with self.assertRaises((ValueError, RuntimeError)) as raised:
                    common.read_control_status(self.sandbox)
                self.assertNotIn("PRIVATE-DETAIL", str(raised.exception))


class ImageImportTests(unittest.TestCase):
    def test_image_submission_requires_a_valid_identifier_before_polling(self):
        clients = MagicMock()
        clients.group._group_path = "/test/group"
        for response in ({}, {"id": ""}, {"id": True}, {"id": 12}, [], None):
            with self.subTest(response=response):
                clients.group._dp_put.return_value = response
                with self.assertRaisesRegex(RuntimeError, "no valid identifier"):
                    deploy_hermes.create_image(config(), clients)
        clients.group.get_disk_image.assert_not_called()
        clients.group._dp_put.return_value = {"id": "new-image"}
        self.assertEqual(deploy_hermes.create_image(config(), clients), "new-image")
        clients.group.get_disk_image.assert_not_called()


class DeploymentRollbackTests(unittest.TestCase):
    def setUp(self):
        self.config = config()
        self.clients = MagicMock()
        self.clients.group._group_path = "/test/group"
        self.clients.group.list_sandboxes.return_value = []
        self.clients.group._dp_put.return_value = {"id": "new-sandbox"}
        self.sandbox = self.clients.group.get_sandbox_client.return_value
        self.sandbox.sandbox_id = "new-sandbox"
        self.sandbox._dp_post.return_value = {"exitCode": 0, "stdout": json.dumps({
            "schema_version": 1, "dashboard": "running", "gateway": "not-paired",
            "whatsapp": "not-paired", "google": "disabled", "disk_free_bytes": common.MIN_FREE_BYTES,
        })}
        self.output = io.StringIO()
        output_context = redirect_stdout(self.output)
        output_context.__enter__()
        self.addCleanup(output_context.__exit__, None, None, None)
        self.raw = {
            "id": "new-sandbox",
            "labels": {**self.config.labels, "name": self.config.sandbox_name},
            "sourcesRef": {"diskImage": {"id": "new-image"}},
            "egressPolicy": common.deployment_egress(self.config),
            "state": "Running",
        }
        self.sandbox._dp_get.return_value = self.raw
        self.deleted = False
        self.image_deleted = False

        def read_sandbox(path):
            if self.deleted:
                raise ResourceNotFoundError("fixture sandbox absent")
            return self.sandbox._dp_get.return_value

        self.sandbox._dp_get.side_effect = read_sandbox
        deletion = self.sandbox.begin_delete.return_value
        deletion.result.side_effect = lambda **kwargs: setattr(self, "deleted", True)
        deletion.done.return_value = True
        image = SimpleNamespace(
            id="new-image", labels={**self.config.labels, "name": self.config.disk_name},
            image=SimpleNamespace(base=self.config.image),
        )

        def read_image(identifier):
            if self.image_deleted:
                raise ResourceNotFoundError("fixture image absent")
            return image

        self.clients.group.get_disk_image.side_effect = read_image
        deletion = self.clients.group.begin_delete_disk_image.return_value
        deletion.result.side_effect = lambda **kwargs: setattr(self, "image_deleted", True)
        deletion.done.return_value = True
        replacements = {
            # This unit fixture tests the otherwise-blocked transaction only;
            # there is deliberately no production flag that bypasses the gate.
            "assert_deployment_supported": None, "assert_owner": None, "provision_group": None,
            "owned_inventory": ([], [], []), "create_image": "new-image", "wait_image": None, "wait_running": self.raw,
            "upload_private_file": None, "read_runtime": common.runtime_document(self.config),
            "verify_partial_network": None, "control_status": {"dashboard": "running"},
            "configure_port": "https://new-sandbox--8080.swedencentral.adcproxy.io",
        }
        self.mocks = {}
        for name, value in replacements.items():
            patcher = patch.object(deploy_hermes, name, return_value=value)
            self.mocks[name] = patcher.start()
            self.addCleanup(patcher.stop)

    def assert_rolled_back_without_data_deletion(self):
        self.sandbox.begin_delete.assert_called_once()
        self.clients.group.begin_delete_volume.assert_not_called()
        self.clients.groups.begin_delete_group.assert_not_called()
        self.mocks["configure_port"].assert_not_called()

    def test_runtime_readback_mismatch_never_exposes_the_sandbox(self):
        self.mocks["read_runtime"].return_value = common.runtime_document(config(foundry_deployment="stale"))
        with self.assertRaisesRegex(RuntimeError, "runtime readback differs"):
            deploy_hermes.deploy(self.config, self.clients)
        self.assert_rolled_back_without_data_deletion()

    def test_transport_failure_rolls_back_and_preserves_original_error(self):
        error = ServiceRequestError("synthetic transport interruption")
        self.mocks["wait_running"].side_effect = error
        with self.assertRaises(ServiceRequestError) as captured:
            deploy_hermes.deploy(self.config, self.clients)
        self.assertIs(captured.exception, error)
        self.assert_rolled_back_without_data_deletion()

    def test_unexpected_status_shape_rolls_back(self):
        self.mocks["control_status"].return_value = {}
        with self.assertRaises(KeyError):
            deploy_hermes.deploy(self.config, self.clients)
        self.assert_rolled_back_without_data_deletion()

    def test_keyboard_interrupt_during_readiness_rolls_back(self):
        self.mocks["control_status"].return_value = {"dashboard": "starting"}
        with patch.object(deploy_hermes.time, "sleep", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            deploy_hermes.deploy(self.config, self.clients)
        self.assert_rolled_back_without_data_deletion()

    def test_missing_create_id_recovers_only_the_matching_new_image(self):
        self.clients.group._dp_put.return_value = {}
        self.clients.group.list_sandboxes.side_effect = [[], [SimpleNamespace(id="new-sandbox")], []]
        with self.assertRaisesRegex(RuntimeError, "no valid ID"):
            deploy_hermes.deploy(self.config, self.clients)
        self.assert_rolled_back_without_data_deletion()

    def test_ambiguous_create_failure_never_deletes_foreign_image(self):
        self.clients.group._dp_put.side_effect = ServiceRequestError("create result unavailable")
        self.clients.group.list_sandboxes.side_effect = [[], [SimpleNamespace(id="foreign")], []]
        self.sandbox._dp_get.return_value = {**self.raw, "sourcesRef": {"diskImage": {"id": "foreign-image"}}}
        with self.assertRaises(ServiceRequestError):
            deploy_hermes.deploy(self.config, self.clients)
        self.sandbox.begin_delete.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_rollback_failure_is_explicit_without_replacing_original_error(self):
        error = ServiceRequestError("synthetic startup interruption")
        self.mocks["wait_running"].side_effect = error
        self.sandbox.begin_delete.side_effect = ServiceRequestError("PRIVATE-DELETE-DETAIL")
        with self.assertLogs("hermes.deploy", level="ERROR") as captured:
            with self.assertRaises(ServiceRequestError) as failure:
                deploy_hermes.deploy(self.config, self.clients)
        self.assertIs(failure.exception, error)
        self.assertIn("residual owned resources may remain", "\n".join(captured.output))
        self.assertNotIn("PRIVATE-DELETE-DETAIL", "\n".join(captured.output))

    def test_validated_transaction_opens_port_and_keeps_the_new_sandbox(self):
        self.assertEqual(deploy_hermes.deploy(self.config, self.clients), "new-sandbox")
        self.mocks["read_runtime"].assert_called_once_with(self.sandbox)
        self.mocks["configure_port"].assert_called_once_with(self.sandbox, self.config)
        self.sandbox.begin_delete.assert_not_called()

    def test_unfinished_rollback_poller_warns_and_keeps_the_original_error_and_image(self):
        original = ServiceRequestError("PRIVATE-ORIGINAL-DETAIL")
        self.mocks["wait_running"].side_effect = original
        poller = self.sandbox.begin_delete.return_value
        poller.result.side_effect = None
        poller.done.return_value = False
        with self.assertLogs("hermes.deploy", level="ERROR") as logged:
            with self.assertRaises(ServiceRequestError) as raised:
                deploy_hermes.deploy(self.config, self.clients)
        self.assertIs(raised.exception, original)
        self.assertIn("residual owned resources may remain", "\n".join(logged.output))
        self.assertNotIn("PRIVATE-ORIGINAL-DETAIL", "\n".join(logged.output))
        self.clients.group.begin_delete_disk_image.assert_not_called()

    def test_rollback_requires_a_confirmed_not_found_after_completed_poller(self):
        original = ServiceRequestError("fixture startup failed")
        self.mocks["wait_running"].side_effect = original
        self.sandbox.begin_delete.return_value.result.side_effect = None
        with self.assertLogs("hermes.deploy", level="ERROR") as logged:
            with self.assertRaises(ServiceRequestError) as raised:
                deploy_hermes.deploy(self.config, self.clients)
        self.assertIs(raised.exception, original)
        self.assertIn("residual owned resources may remain", "\n".join(logged.output))
        self.clients.group.begin_delete_disk_image.assert_not_called()

    def test_already_absent_new_sandbox_allows_only_its_unused_image_cleanup(self):
        self.deleted = True
        self.mocks["wait_running"].side_effect = RuntimeError("fixture disappeared")
        with self.assertRaisesRegex(RuntimeError, "fixture disappeared"):
            deploy_hermes.deploy(self.config, self.clients)
        self.sandbox.begin_delete.assert_not_called()
        self.clients.group.begin_delete_disk_image.assert_called_once_with("new-image")
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_ambiguous_put_with_empty_list_preserves_image_and_warns(self):
        original = ServiceRequestError("PRIVATE-CREATE-DETAIL")
        self.clients.group._dp_put.side_effect = original
        with self.assertLogs("hermes.deploy", level="ERROR") as logged:
            with self.assertRaises(ServiceRequestError) as raised:
                deploy_hermes.deploy(self.config, self.clients)
        self.assertIs(raised.exception, original)
        self.assertIn("outcome is unknown", "\n".join(logged.output))
        self.assertIn("image preserved", "\n".join(logged.output))
        self.assertNotIn("PRIVATE-CREATE-DETAIL", "\n".join(logged.output))
        self.clients.group.begin_delete_disk_image.assert_not_called()
        self.sandbox.begin_delete.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_listed_but_confirmed_absent_sandbox_does_not_orphan_unused_image(self):
        self.deleted = True
        self.clients.group.list_sandboxes.return_value = [SimpleNamespace(id="new-sandbox")]
        deploy_hermes.delete_unreferenced_image(self.config, self.clients, "new-image", self.config.image)
        self.clients.group.begin_delete_disk_image.assert_called_once_with("new-image")
        self.assertTrue(self.image_deleted)


class OrderedDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.original_create_image = deploy_hermes.create_image
        self.config = config()
        self.events = []
        self.clients = MagicMock()
        self.clients.group._group_path = "/test/group"
        self.volumes = [SimpleNamespace(name=self.config.volume_name)]
        self.active = {"old-sandbox"}
        self.compute_state = {"old-sandbox": "Running", "new-sandbox": "Running"}
        self.dashboard_state = {"old-sandbox": "running", "new-sandbox": "running"}
        self.desired = "running"
        self.gateway_running = {"old-sandbox": True, "new-sandbox": False}
        self.paired = True
        self.persist_stop = True
        self.start_exit = 0
        self.start_live = True
        self.final_status_error = None
        self.disk_free = {"old-sandbox": common.MIN_FREE_BYTES, "new-sandbox": common.MIN_FREE_BYTES}
        self.lingering_old = False
        self.delete_done = True
        self.stop_exit = 0
        self.image_delete_error = None
        self.import_state = "Ready"
        self.old = self.sandbox("old-sandbox", "old-image")
        self.new = self.sandbox("new-sandbox", "new-image")
        self.images = {
            "old-image": SimpleNamespace(
                id="old-image", labels={**self.config.labels, "name": self.config.disk_name},
                image=SimpleNamespace(base="example.invalid/hermes@sha256:" + "b" * 64),
            ),
        }
        self.clients.group.get_sandbox_client.side_effect = lambda identifier: (
            self.old if identifier == "old-sandbox" else self.new
        )
        self.clients.group.list_sandboxes.side_effect = self.list_sandboxes
        self.clients.group.get_disk_image.side_effect = self.get_image
        self.clients.group.begin_delete_disk_image.side_effect = self.delete_image
        self.clients.group._dp_put.side_effect = self.create_sandbox
        self.output = io.StringIO()
        output_context = redirect_stdout(self.output)
        output_context.__enter__()
        self.addCleanup(output_context.__exit__, None, None, None)

        replacements = {
            "assert_deployment_supported": lambda: None,
            "assert_owner": lambda *args: None,
            "provision_group": lambda *args: None,
            "owned_inventory": lambda *args: (
                [SimpleNamespace(id=identifier) for identifier in self.active], list(self.images.values()), list(self.volumes),
            ),
            "create_image": self.create_image,
            "wait_running": lambda sandbox: sandbox._dp_get(sandbox._sbx_path),
            "upload_private_file": lambda *args, **kwargs: self.events.append("upload-runtime"),
            "read_runtime": lambda *args: common.runtime_document(self.config),
            "verify_partial_network": lambda *args: None,
            "configure_port": lambda *args: self.events.append("open-port"),
        }
        self.mocks = {}
        for name, callback in replacements.items():
            patcher = patch.object(deploy_hermes, name, side_effect=callback)
            self.mocks[name] = patcher.start()
            self.addCleanup(patcher.stop)

    def sandbox(self, identifier, image_id):
        sandbox = MagicMock()
        sandbox.sandbox_id = identifier
        sandbox._sbx_path = "/test/" + identifier

        def get(path):
            self.events.append("get:" + identifier)
            if identifier not in self.active:
                raise ResourceNotFoundError("fixture absent")
            return {
                "id": identifier, "state": self.compute_state[identifier],
                "labels": {**self.config.labels, "name": self.config.sandbox_name},
                "sourcesRef": {"diskImage": {"id": image_id}},
                "lifecycle": {"autoSuspendPolicy": {"enabled": False}},
                "egressPolicy": common.deployment_egress(self.config),
                "ports": [common.port_document(self.config, identifier)],
            }

        def execute(path, payload):
            command = shlex.split(payload["command"])
            self.assertEqual(command[:2], common.CONTROL)
            action = command[2]
            self.events.append(action + ":" + identifier)
            code = 0
            if action == "stop-gateway":
                code = self.stop_exit
                if code == 0:
                    self.gateway_running[identifier] = False
                    if self.persist_stop and self.desired != "failed":
                        self.desired = "maintenance"
            elif action == "reconfigure":
                self.desired = "maintenance" if self.desired == "maintenance" else "running"
                self.gateway_running[identifier] = self.desired == "running" and self.paired
            elif action == "start-gateway":
                code = self.start_exit
                if code == 0:
                    self.desired = "running"
                    self.gateway_running[identifier] = self.start_live
            elif action == "status" and self.final_status_error and "open-port" in self.events:
                raise self.final_status_error
            gateway = (
                "running" if self.gateway_running[identifier] else
                self.desired if self.desired in {"maintenance", "failed"} else
                "stopped" if self.paired else "not-paired"
            )
            return {"exitCode": code, "stdout": json.dumps({
                "schema_version": 1, "dashboard": self.dashboard_state[identifier], "gateway": gateway,
                "whatsapp": "paired" if self.paired else "not-paired",
                "google": "disabled", "disk_free_bytes": self.disk_free[identifier],
            })}

        def delete():
            self.events.append("delete:" + identifier)
            poller = MagicMock()
            poller.done.return_value = self.delete_done

            def finish(**kwargs):
                if identifier != "old-sandbox" or not self.lingering_old:
                    self.active.discard(identifier)

            poller.result.side_effect = finish
            return poller

        sandbox._dp_get.side_effect = get
        sandbox._dp_post.side_effect = execute
        sandbox.begin_delete.side_effect = delete
        return sandbox

    def list_sandboxes(self):
        self.events.append("list:" + ",".join(sorted(self.active)))
        return [SimpleNamespace(id=identifier) for identifier in self.active]

    def create_image(self, *args):
        self.events.append("create-image")
        self.images["new-image"] = SimpleNamespace(
            id="new-image", labels={**self.config.labels, "name": self.config.disk_name},
            image=SimpleNamespace(base=self.config.image),
            status=SimpleNamespace(state=self.import_state),
        )
        return "new-image"

    def get_image(self, identifier):
        if identifier not in self.images:
            raise ResourceNotFoundError("fixture image absent")
        return self.images[identifier]

    def delete_image(self, identifier):
        self.events.append("delete-image:" + identifier)
        if self.image_delete_error:
            raise self.image_delete_error
        poller = MagicMock()
        poller.result.side_effect = lambda **kwargs: self.images.pop(identifier)
        poller.done.return_value = True
        return poller

    def create_sandbox(self, path, payload):
        self.events.append("put-sandbox")
        self.assertEqual(self.active, set(), "A new writer was created before the previous one disappeared.")
        self.active.add("new-sandbox")
        self.gateway_running["new-sandbox"] = self.desired == "running" and self.paired
        if self.gateway_running["new-sandbox"]:
            self.events.append("boot-gateway:new-sandbox")
        return {"id": "new-sandbox"}

    def test_replace_orders_image_stop_delete_empty_check_create_reconfigure_and_port(self):
        self.assertEqual(deploy_hermes.deploy(self.config, self.clients, replace=True), "new-sandbox")
        order = [
            "create-image", "status:old-sandbox", "stop-gateway:old-sandbox", "delete:old-sandbox", "list:",
            "put-sandbox", "upload-runtime", "reconfigure:new-sandbox", "open-port",
            "start-gateway:new-sandbox", "delete-image:old-image",
        ]
        positions = [self.events.index(event) for event in order]
        self.assertEqual(positions, sorted(positions))
        self.clients.group.create_volume.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()
        self.assertEqual(self.desired, "running")
        self.assertTrue(self.gateway_running["new-sandbox"])
        self.assertNotIn("boot-gateway:new-sandbox", self.events)
        self.assertIn("Hermes gateway state: running", self.output.getvalue())

    def test_replace_preserves_deliberate_maintenance_and_reports_resume_command(self):
        self.desired = "maintenance"
        self.gateway_running["old-sandbox"] = False
        self.assertEqual(deploy_hermes.deploy(self.config, self.clients, replace=True), "new-sandbox")
        self.assertEqual(self.desired, "maintenance")
        self.assertNotIn("start-gateway:new-sandbox", self.events)
        self.assertFalse(self.gateway_running["new-sandbox"])
        self.assertIn("Hermes gateway state: maintenance", self.output.getvalue())
        self.assertIn(" ".join([*common.CONTROL, "start-gateway"]), self.output.getvalue())

    def test_failed_resume_reports_ready_id_without_rolling_back(self):
        previous_image = self.images["old-image"]
        for start_exit, start_live in ((7, True), (0, False)):
            with self.subTest(start_exit=start_exit, start_live=start_live):
                self.start_exit, self.start_live = start_exit, start_live
                self.active = {"old-sandbox"}
                self.images = {"old-image": previous_image}
                self.desired = "running"
                self.gateway_running["old-sandbox"] = True
                self.events.clear()
                with self.assertLogs("hermes.deploy", level="WARNING") as logged:
                    self.assertEqual(deploy_hermes.deploy(self.config, self.clients, replace=True), "new-sandbox")
                self.assertEqual(self.active, {"new-sandbox"})
                self.assertNotIn("delete:new-sandbox", self.events)
                self.assertIn("gateway resume not confirmed", "\n".join(logged.output))
                self.assertIn(" ".join([*common.CONTROL, "start-gateway"]), "\n".join(logged.output))
                self.clients.group.begin_delete_volume.assert_not_called()

    def test_unreadable_final_gateway_state_warns_without_secret_details_or_rollback(self):
        self.final_status_error = ServiceRequestError("PRIVATE-STATUS-DETAIL")
        with self.assertLogs("hermes.deploy", level="WARNING") as logged:
            self.assertEqual(deploy_hermes.deploy(self.config, self.clients, replace=True), "new-sandbox")
        self.assertIn("gateway resume not confirmed", "\n".join(logged.output))
        self.assertNotIn("PRIVATE-STATUS-DETAIL", "\n".join(logged.output))
        self.assertEqual(self.active, {"new-sandbox"})
        self.assertNotIn("delete:new-sandbox", self.events)

    def test_preserved_cleanup_then_redeploy_stays_in_maintenance_with_explicit_notice(self):
        self.clients.resources.resource_groups.check_existence.return_value = True
        with patch.object(cleanup_hermes, "assert_owner"), patch.object(
            cleanup_hermes, "owned_inventory", side_effect=self.mocks["owned_inventory"],
        ):
            cleanup_hermes.cleanup(self.config, self.clients)
        self.assertEqual(self.active, set())
        self.assertEqual(self.desired, "maintenance")
        self.events.clear()
        self.assertEqual(deploy_hermes.deploy(self.config, self.clients), "new-sandbox")
        self.assertEqual(self.desired, "maintenance")
        self.assertNotIn("start-gateway:new-sandbox", self.events)
        self.assertNotIn("boot-gateway:new-sandbox", self.events)
        self.assertIn("Hermes gateway state: maintenance", self.output.getvalue())
        self.assertIn(" ".join([*common.CONTROL, "start-gateway"]), self.output.getvalue())
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_nonrunning_old_compute_is_not_implicitly_started_or_deleted(self):
        self.compute_state["old-sandbox"] = "Stopped"
        with self.assertLogs("hermes.deploy", level="WARNING") as logged:
            with self.assertRaisesRegex(RuntimeError, "running sandbox"):
                deploy_hermes.deploy(self.config, self.clients, replace=True)
        warning = "\n".join(logged.output)
        self.assertIn("Gateway stop was not issued", warning)
        self.assertIn("--confirm-unquiesced-writer " + self.config.group_scope + "/sandboxes/old-sandbox", warning)
        self.assertNotIn("resume explicitly", warning)
        self.assertEqual(self.active, {"old-sandbox"})
        self.assertNotIn("stop-gateway:old-sandbox", self.events)
        self.assertNotIn("delete:old-sandbox", self.events)
        self.assertNotIn("put-sandbox", self.events)
        self.old.begin_resume.assert_not_called()
        self.assertNotIn("new-image", self.images)

    def test_unconfirmed_persistent_maintenance_blocks_writer_deletion(self):
        self.persist_stop = False
        with self.assertRaisesRegex(RuntimeError, "persistent maintenance"):
            deploy_hermes.deploy(self.config, self.clients, replace=True)
        self.assertEqual(self.active, {"old-sandbox"})
        self.assertNotIn("delete:old-sandbox", self.events)
        self.assertNotIn("put-sandbox", self.events)
        self.assertNotIn("new-image", self.images)

    def cleanup_preserving_disk(self, confirmation=None):
        self.clients.resources.resource_groups.check_existence.return_value = True
        with patch.object(cleanup_hermes, "assert_owner"), patch.object(
            cleanup_hermes, "owned_inventory", side_effect=self.mocks["owned_inventory"],
        ):
            cleanup_hermes.cleanup(
                self.config, self.clients, confirm_unquiesced_writer=confirmation,
            )

    def test_unreadable_initial_status_reports_recovery_without_claiming_a_stop(self):
        original = ServiceRequestError("PRIVATE-INITIAL-STATUS")
        self.old._dp_post.side_effect = original
        for logger, operation in (
            ("hermes.deploy", lambda: deploy_hermes.deploy(self.config, self.clients, replace=True)),
            ("hermes.cleanup", self.cleanup_preserving_disk),
        ):
            with self.subTest(logger=logger), self.assertLogs(logger, level="WARNING") as logged:
                with self.assertRaises(ServiceRequestError) as raised:
                    operation()
            self.assertIs(raised.exception, original)
            warning = "\n".join(logged.output)
            self.assertIn("Gateway stop was not issued", warning)
            self.assertIn("--confirm-unquiesced-writer " + self.config.group_scope + "/sandboxes/old-sandbox", warning)
            self.assertNotIn("resume explicitly", warning)
            self.assertNotIn("PRIVATE-INITIAL-STATUS", warning)
        self.old.begin_delete.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()
        actions = [shlex.split(call.args[1]["command"])[2] for call in self.old._dp_post.call_args_list]
        self.assertEqual(actions, ["status", "status"])

    def assert_cleanup_failure_preserves_warning_and_exception(self, exception_type):
        original_delete = cleanup_hermes.delete_sandbox_confirmed
        failures = []

        def observe_delete(sandbox):
            try:
                original_delete(sandbox)
            except BaseException as error:
                failures.append(error)
                raise

        with patch.object(cleanup_hermes, "delete_sandbox_confirmed", side_effect=observe_delete):
            with self.assertLogs("hermes.cleanup", level="WARNING") as logged:
                with self.assertRaises(exception_type) as raised:
                    self.cleanup_preserving_disk()
        self.assertEqual(len(failures), 1)
        self.assertIs(raised.exception, failures[0])
        warning = "\n".join(message for message in logged.output if "Cleanup did not finish" in message)
        self.assertIn("prior gateway=running", warning)
        self.assertIn(" ".join([*common.CONTROL, "start-gateway"]), warning)
        self.assertIn("--confirm-unquiesced-writer " + self.config.group_scope + "/sandboxes/old-sandbox", warning)
        self.assertNotIn("PRIVATE-DELETE-DETAIL", warning)
        self.assertEqual(self.desired, "maintenance")
        self.clients.group.begin_delete_disk_image.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()
        self.clients.groups.begin_delete_group.assert_not_called()

    def test_default_cleanup_unfinished_delete_reports_stopped_writer_and_preserves_error(self):
        self.delete_done = False
        self.assert_cleanup_failure_preserves_warning_and_exception(TimeoutError)

    def test_default_cleanup_lingering_writer_reports_stopped_writer_and_preserves_error(self):
        self.lingering_old = True
        self.assert_cleanup_failure_preserves_warning_and_exception(RuntimeError)

    def test_default_cleanup_delete_error_reports_stopped_writer_and_preserves_error(self):
        self.old.begin_delete.side_effect = ServiceRequestError("PRIVATE-DELETE-DETAIL")
        self.assert_cleanup_failure_preserves_warning_and_exception(ServiceRequestError)

    def test_default_cleanup_cancelled_delete_reports_stopped_writer_and_preserves_error(self):
        self.old.begin_delete.side_effect = KeyboardInterrupt()
        self.assert_cleanup_failure_preserves_warning_and_exception(KeyboardInterrupt)

    def test_failed_persistent_state_refuses_default_handoff_with_observed_state_and_recovery_target(self):
        self.desired = "failed"
        self.gateway_running["old-sandbox"] = False
        target = self.config.group_scope + "/sandboxes/old-sandbox"
        for operation in (
            lambda: deploy_hermes.deploy(self.config, self.clients, replace=True),
            lambda: self.cleanup_preserving_disk(),
        ):
            with self.assertRaisesRegex(RuntimeError, "gateway=failed") as raised:
                operation()
            self.assertIn("--confirm-unquiesced-writer", str(raised.exception))
            self.assertIn(target, str(raised.exception))
            self.assertEqual(self.active, {"old-sandbox"})
            self.assertNotIn("delete:old-sandbox", self.events)
            self.assertNotIn("put-sandbox", self.events)
            self.assertNotIn("new-image", self.images)
            self.assertIn("old-image", self.images)
            self.clients.group.begin_delete_volume.assert_not_called()

    def test_exact_recovery_confirmation_keeps_failed_disk_without_starting_gateway(self):
        self.desired = "failed"
        self.gateway_running["old-sandbox"] = False
        with self.assertLogs("hermes.cleanup", level="WARNING") as logged:
            self.cleanup_preserving_disk(self.config.group_scope + "/sandboxes/old-sandbox")
        self.assertEqual(self.active, set())
        self.assertEqual(self.desired, "failed")
        self.assertNotIn("start-gateway:old-sandbox", self.events)
        self.old.begin_resume.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()
        self.assertIn("compute=running", "\n".join(logged.output))
        self.assertIn("gateway=failed", "\n".join(logged.output))
        self.assertIn("persistent gateway intent not confirmed", "\n".join(logged.output))
        self.assertIn("next boot", "\n".join(logged.output))
        self.events.clear()
        self.assertEqual(deploy_hermes.deploy(self.config, self.clients), "new-sandbox")
        self.assertIn("upload-runtime", self.events)
        self.assertIn("reconfigure:new-sandbox", self.events)
        self.assertTrue(self.gateway_running["new-sandbox"])
        self.assertNotIn("start-gateway:new-sandbox", self.events)
        self.assertIn("Hermes gateway state: running", self.output.getvalue())

    def test_exact_recovery_of_nonrunning_compute_never_uses_a_control_command_or_resume(self):
        self.compute_state["old-sandbox"] = "Stopped"
        with self.assertLogs("hermes.cleanup", level="WARNING") as logged:
            self.cleanup_preserving_disk(self.config.group_scope + "/sandboxes/old-sandbox")
        self.assertEqual(self.active, set())
        self.old._dp_post.assert_not_called()
        self.old.begin_resume.assert_not_called()
        self.assertIn("compute=stopped", "\n".join(logged.output))
        self.assertIn("gateway=unknown", "\n".join(logged.output))
        self.clients.group.begin_delete_volume.assert_not_called()
        self.events.clear()
        self.assertEqual(deploy_hermes.deploy(self.config, self.clients), "new-sandbox")
        self.assertLess(self.events.index("boot-gateway:new-sandbox"), self.events.index("upload-runtime"))
        self.assertNotIn("start-gateway:new-sandbox", self.events)
        self.assertIn("Hermes gateway state: running", self.output.getvalue())

    def test_recovery_does_not_log_unknown_compute_metadata(self):
        self.compute_state["old-sandbox"] = "PRIVATE-COMPUTE-DETAIL"
        with self.assertLogs("hermes.cleanup", level="WARNING") as logged:
            self.cleanup_preserving_disk(self.config.group_scope + "/sandboxes/old-sandbox")
        self.assertIn("compute=unknown", "\n".join(logged.output))
        self.assertNotIn("PRIVATE-COMPUTE-DETAIL", "\n".join(logged.output))
        self.old._dp_post.assert_not_called()
        self.old.begin_resume.assert_not_called()

    def test_recovery_still_requires_confirmed_deletion_before_images_or_data(self):
        self.desired = "failed"
        self.gateway_running["old-sandbox"] = False
        self.delete_done = False
        with self.assertLogs("hermes.cleanup", level="WARNING"):
            with self.assertRaisesRegex(TimeoutError, "deletion"):
                self.cleanup_preserving_disk(self.config.group_scope + "/sandboxes/old-sandbox")
        self.assertIn("old-image", self.images)
        self.clients.group.begin_delete_disk_image.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_recovery_reports_before_and_after_state_and_keeps_actual_prior_on_delete_failure(self):
        self.delete_done = False
        with self.assertLogs("hermes.cleanup", level="WARNING") as logged:
            with self.assertRaises(TimeoutError):
                self.cleanup_preserving_disk(self.config.group_scope + "/sandboxes/old-sandbox")
        warning = "\n".join(logged.output)
        self.assertIn("before gateway=running", warning)
        self.assertIn("after gateway=maintenance", warning)
        self.assertIn("stop=completed", warning)
        self.assertIn("prior gateway=running", warning)
        self.assertNotIn("prior gateway=maintenance", warning)
        self.assertIn("writer may still exist", warning)
        self.assertNotIn("Gateway stop was not issued", warning)
        self.clients.group.begin_delete_disk_image.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_running_data_cleanup_failed_delete_reports_issued_stop_before_any_data_removal(self):
        self.delete_done = False
        self.clients.resources.resource_groups.check_existence.return_value = True
        with patch.object(cleanup_hermes, "assert_owner"), patch.object(
            cleanup_hermes, "owned_inventory", side_effect=self.mocks["owned_inventory"],
        ), self.assertLogs("hermes.cleanup", level="WARNING") as logged:
            with self.assertRaises(TimeoutError):
                cleanup_hermes.cleanup(
                    self.config, self.clients, delete_data=True,
                    confirm_volume=self.config.group_scope + "/volumes/" + self.config.volume_name,
                )
        warning = "\n".join(logged.output)
        self.assertIn("Cleanup did not finish", warning)
        self.assertIn("prior gateway=unknown", warning)
        self.assertIn("writer may still exist", warning)
        self.assertNotIn("Gateway stop was not issued", warning)
        self.assertIn(" ".join([*common.CONTROL, "start-gateway"]), warning)
        self.assertIn("--confirm-unquiesced-writer " + self.config.group_scope + "/sandboxes/old-sandbox", warning)
        actions = [shlex.split(call.args[1]["command"])[2] for call in self.old._dp_post.call_args_list]
        self.assertEqual(actions, ["stop-gateway"])
        self.assertEqual(self.desired, "maintenance")
        self.old.begin_resume.assert_not_called()
        self.clients.group.begin_delete_disk_image.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()
        self.clients.groups.begin_delete_group.assert_not_called()

    def assert_recovery_status_error_is_separate_from_completed_stop(self, failure_number):
        execute = self.old._dp_post.side_effect
        reads = 0

        def status_failure(path, payload):
            nonlocal reads
            if shlex.split(payload["command"])[2] == "status":
                reads += 1
                if reads == failure_number:
                    raise ServiceRequestError("PRIVATE-STATUS-READ")
            return execute(path, payload)

        self.old._dp_post.side_effect = status_failure
        with self.assertLogs("hermes.cleanup", level="WARNING") as logged:
            self.cleanup_preserving_disk(self.config.group_scope + "/sandboxes/old-sandbox")
        warning = "\n".join(logged.output)
        self.assertEqual(reads, 2)
        self.assertEqual(self.active, set())
        self.assertIn("stop=completed", warning)
        self.assertNotIn("stop=ServiceRequestError", warning)
        self.assertIn(
            f"status-{'before' if failure_number == 1 else 'after'}=ServiceRequestError", warning,
        )
        self.assertIn("before gateway=" + ("unknown" if failure_number == 1 else "running"), warning)
        self.assertIn("after gateway=" + ("unknown" if failure_number == 2 else "maintenance"), warning)
        self.assertNotIn("PRIVATE-STATUS-READ", warning)
        self.assertEqual(self.events.count("stop-gateway:old-sandbox"), 1)
        self.old.begin_resume.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_recovery_keeps_successful_stop_when_following_status_is_unreadable(self):
        self.assert_recovery_status_error_is_separate_from_completed_stop(2)

    def test_recovery_still_attempts_stop_when_initial_status_is_unreadable(self):
        self.assert_recovery_status_error_is_separate_from_completed_stop(1)

    def test_exact_recovery_with_unreachable_control_still_confirms_deletion_without_private_error(self):
        self.old._dp_post.side_effect = ServiceRequestError("PRIVATE-CONTROL-DETAIL")
        with self.assertLogs("hermes.cleanup", level="WARNING") as logged:
            self.cleanup_preserving_disk(self.config.group_scope + "/sandboxes/old-sandbox")
        self.assertEqual(self.active, set())
        self.assertNotIn("PRIVATE-CONTROL-DETAIL", "\n".join(logged.output) + self.output.getvalue())
        self.assertIn("ServiceRequestError", "\n".join(logged.output))
        self.assertIn("persistent gateway intent not confirmed", "\n".join(logged.output))
        actions = [shlex.split(call.args[1]["command"])[2] for call in self.old._dp_post.call_args_list]
        self.assertEqual(actions, ["status", "stop-gateway", "status"])
        self.old.begin_resume.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_recovery_confirmation_must_match_the_exact_single_owned_writer_before_any_command(self):
        for identifier in ("old", "different-sandbox"):
            with self.subTest(identifier=identifier), self.assertRaisesRegex(ValueError, "exact owned sandbox"):
                self.cleanup_preserving_disk(self.config.group_scope + "/sandboxes/" + identifier)
        self.old._dp_post.assert_not_called()
        self.old.begin_delete.assert_not_called()
        self.clients.group.begin_delete_disk_image.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_replacement_during_restart_backoff_preserves_running_intent(self):
        self.gateway_running["old-sandbox"] = False
        self.assertEqual(self.desired, "running")
        self.assertEqual(deploy_hermes.deploy(self.config, self.clients, replace=True), "new-sandbox")
        self.assertTrue(self.gateway_running["new-sandbox"])
        self.assertLess(self.events.index("open-port"), self.events.index("start-gateway:new-sandbox"))
        self.assertIn("Hermes gateway state: running", self.output.getvalue())

    def test_delete_error_after_stop_warns_without_hiding_original_exception(self):
        original = ServiceRequestError("PRIVATE-DELETE-DETAIL")
        self.old.begin_delete.side_effect = original
        with self.assertLogs("hermes.deploy", level="WARNING") as logged:
            with self.assertRaises(ServiceRequestError) as raised:
                deploy_hermes.deploy(self.config, self.clients, replace=True)
        self.assertIs(raised.exception, original)
        self.assertEqual(self.active, {"old-sandbox"})
        self.assertEqual(self.desired, "maintenance")
        self.assertIn("prior gateway=running", "\n".join(logged.output))
        self.assertIn("gateway stopped or in maintenance", "\n".join(logged.output))
        self.assertIn(" ".join([*common.CONTROL, "start-gateway"]), "\n".join(logged.output))
        self.assertNotIn("PRIVATE-DELETE-DETAIL", "\n".join(logged.output))

    def test_cancelled_delete_after_stop_also_warns_and_preserves_the_disk(self):
        self.old.begin_delete.side_effect = KeyboardInterrupt
        with self.assertLogs("hermes.deploy", level="WARNING") as logged:
            with self.assertRaises(KeyboardInterrupt):
                deploy_hermes.deploy(self.config, self.clients, replace=True)
        self.assertIn("prior gateway=running", "\n".join(logged.output))
        self.assertIn(" ".join([*common.CONTROL, "start-gateway"]), "\n".join(logged.output))
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_low_old_disk_does_not_prevent_schema_only_stop_confirmation(self):
        self.disk_free["old-sandbox"] = 0
        self.assertEqual(deploy_hermes.deploy(self.config, self.clients, replace=True), "new-sandbox")
        self.assertEqual(self.events.count("status:old-sandbox"), 2)
        self.assertLess(self.events.index("stop-gateway:old-sandbox"), self.events.index("delete:old-sandbox"))

    def test_old_deletion_requires_completed_poller_even_when_listing_is_empty(self):
        self.delete_done = False
        with self.assertLogs("hermes.deploy", level="WARNING") as logged:
            with self.assertRaisesRegex(TimeoutError, "deletion"):
                deploy_hermes.deploy(self.config, self.clients, replace=True)
        self.assertIn("prior gateway=running", "\n".join(logged.output))
        self.assertIn(" ".join([*common.CONTROL, "start-gateway"]), "\n".join(logged.output))
        self.assertNotIn("put-sandbox", self.events)
        self.assertNotIn("new-image", self.images)
        self.assertIn("old-image", self.images)

    def test_lingering_writer_blocks_put_and_preserves_old_image_and_volume(self):
        self.lingering_old = True
        with self.assertLogs("hermes.deploy", level="WARNING") as logged:
            with self.assertRaisesRegex(RuntimeError, "deletion is incomplete"):
                deploy_hermes.deploy(self.config, self.clients, replace=True)
        self.assertIn("prior gateway=running", "\n".join(logged.output))
        self.assertIn(" ".join([*common.CONTROL, "start-gateway"]), "\n".join(logged.output))
        self.assertNotIn("put-sandbox", self.events)
        self.assertEqual(self.active, {"old-sandbox"})
        self.assertIn("old-image", self.images)
        self.assertEqual(self.events.count("delete-image:new-image"), 1)
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_failed_stop_blocks_delete_and_put_but_removes_only_unused_new_image(self):
        self.stop_exit = 7
        execute = self.old._dp_post.side_effect

        def persisted_stop_failure(path, payload):
            result = execute(path, payload)
            if shlex.split(payload["command"])[2] == "stop-gateway":
                self.desired = "maintenance"
                self.gateway_running["old-sandbox"] = False
            return result

        self.old._dp_post.side_effect = persisted_stop_failure
        with self.assertLogs("hermes.deploy", level="WARNING") as logged:
            with self.assertRaisesRegex(RuntimeError, "exit code 7"):
                deploy_hermes.deploy(self.config, self.clients, replace=True)
        self.assertIn("prior gateway=running", "\n".join(logged.output))
        self.assertIn(" ".join([*common.CONTROL, "start-gateway"]), "\n".join(logged.output))
        self.assertEqual(self.desired, "maintenance")
        self.assertNotIn("delete:old-sandbox", self.events)
        self.assertNotIn("put-sandbox", self.events)
        self.assertEqual(self.events.count("delete-image:new-image"), 1)
        self.assertIn("old-image", self.images)
        self.stop_exit = 0
        self.events.clear()
        self.assertEqual(deploy_hermes.deploy(self.config, self.clients, replace=True), "new-sandbox")
        self.assertEqual(self.desired, "maintenance")
        self.assertNotIn("start-gateway:new-sandbox", self.events)
        self.assertIn("Hermes gateway state: maintenance", self.output.getvalue())

    def test_failed_new_readiness_reports_confirmed_old_deletion_and_manual_resume_after_retry(self):
        self.dashboard_state["new-sandbox"] = "failed"
        with self.assertLogs("hermes.deploy", level="WARNING") as logged:
            with self.assertRaisesRegex(RuntimeError, "did not reach readiness"):
                deploy_hermes.deploy(self.config, self.clients, replace=True)
        warning = "\n".join(logged.output)
        self.assertIn("Previous writer deletion was confirmed", warning)
        self.assertIn("prior gateway=running", warning)
        self.assertIn("after a successful retry", warning)
        self.assertIn(" ".join([*common.CONTROL, "start-gateway"]), warning)
        self.assertNotIn("--confirm-unquiesced-writer", warning)
        self.assertNotIn("writer may still exist", warning)
        self.assertEqual(self.active, set())
        self.assertEqual(self.desired, "maintenance")
        self.clients.group.begin_delete_volume.assert_not_called()
        self.dashboard_state["new-sandbox"] = "running"
        self.events.clear()
        self.assertEqual(deploy_hermes.deploy(self.config, self.clients), "new-sandbox")
        self.assertNotIn("start-gateway:new-sandbox", self.events)
        self.assertEqual(self.desired, "maintenance")

    def test_fresh_volume_uses_boot_wait_without_reconfigure(self):
        self.active.clear()
        self.images.clear()
        self.volumes.clear()
        self.paired = False
        self.assertEqual(deploy_hermes.deploy(self.config, self.clients), "new-sandbox")
        self.clients.group.create_volume.assert_called_once()
        self.assertNotIn("reconfigure:new-sandbox", self.events)
        self.assertLess(self.events.index("upload-runtime"), self.events.index("open-port"))

    def test_failed_replacement_preserves_previous_image_and_rolls_back_new_resources(self):
        self.mocks["verify_partial_network"].side_effect = RuntimeError("fixture egress mismatch")
        with self.assertRaisesRegex(RuntimeError, "fixture egress mismatch"):
            deploy_hermes.deploy(self.config, self.clients, replace=True)
        self.assertIn("old-image", self.images)
        self.assertNotIn("new-image", self.images)
        self.assertEqual(self.active, set())
        self.assertNotIn("open-port", self.events)
        self.assertLess(self.events.index("delete:new-sandbox"), self.events.index("delete-image:new-image"))

    def test_old_image_cleanup_failure_does_not_hide_ready_sandbox(self):
        self.image_delete_error = ServiceRequestError("PRIVATE-OLD-IMAGE-DETAIL")
        with self.assertLogs("hermes.deploy", level="WARNING") as logged:
            self.assertEqual(deploy_hermes.deploy(self.config, self.clients, replace=True), "new-sandbox")
        self.assertEqual(self.active, {"new-sandbox"})
        self.assertIn("new sandbox ready", "\n".join(logged.output))
        self.assertNotIn("PRIVATE-OLD-IMAGE-DETAIL", "\n".join(logged.output))
        self.assertNotIn("delete:new-sandbox", self.events)

    def test_existing_sandbox_runtime_and_image_mismatches_never_mutate(self):
        for mismatch in ("Runtime differs", "Image differs"):
            self.events.clear()
            if mismatch == "Runtime differs":
                self.mocks["read_runtime"].side_effect = lambda *args: common.runtime_document(config(foundry_deployment="other"))
            else:
                self.mocks["read_runtime"].side_effect = lambda *args: common.runtime_document(self.config)
            with self.subTest(mismatch=mismatch), self.assertRaisesRegex(RuntimeError, mismatch):
                deploy_hermes.deploy(self.config, self.clients)
            self.assertEqual(self.events, ["get:old-sandbox"])
            self.mocks["create_image"].assert_not_called()
            self.clients.group._dp_put.assert_not_called()
            self.clients.group.create_volume.assert_not_called()

    def test_unchanged_existing_sandbox_returns_its_id_without_mutation(self):
        self.images["old-image"].image.base = self.config.image
        self.assertEqual(deploy_hermes.deploy(self.config, self.clients), "old-sandbox")
        self.assertEqual(self.events, ["get:old-sandbox", "status:old-sandbox"])
        self.mocks["create_image"].assert_not_called()

    def test_unchanged_but_unready_dashboard_never_reports_ready(self):
        self.images["old-image"].image.base = self.config.image
        self.dashboard_state["old-sandbox"] = "stopped"
        with self.assertRaisesRegex(RuntimeError, "existing Hermes dashboard is not ready"):
            deploy_hermes.deploy(self.config, self.clients)
        self.assertEqual(self.events, ["get:old-sandbox", "status:old-sandbox"])
        self.mocks["create_image"].assert_not_called()
        self.old.begin_delete.assert_not_called()

    def test_image_cleanup_refuses_live_references_changed_owner_and_source(self):
        with self.assertRaisesRegex(RuntimeError, "still references"):
            deploy_hermes.delete_unreferenced_image(
                self.config, self.clients, "old-image", self.images["old-image"].image.base,
            )
        self.active.clear()
        with self.assertRaisesRegex(RuntimeError, "source changed"):
            deploy_hermes.delete_unreferenced_image(self.config, self.clients, "old-image", self.config.image)
        self.images["old-image"].labels = config(
            owner_object_id="44444444-4444-4444-4444-444444444444",
        ).labels
        with self.assertRaisesRegex(RuntimeError, "unowned"):
            deploy_hermes.delete_unreferenced_image(
                self.config, self.clients, "old-image", self.images["old-image"].image.base,
            )
        self.assertFalse(any(event.startswith("delete-image") for event in self.events))

    def prepare_real_import(self, state):
        self.import_state = state
        self.mocks["create_image"].side_effect = self.original_create_image

        def image_put(path, payload):
            self.assertTrue(path.endswith("/diskimages"), "A sandbox was created before its image was ready.")
            return {"id": self.create_image()}

        self.clients.group._dp_put.side_effect = image_put

    def assert_failed_import_is_cleaned_without_stopping_old_writer(self):
        self.assertEqual(self.active, {"old-sandbox"})
        self.assertNotIn("stop-gateway:old-sandbox", self.events)
        self.assertNotIn("delete:old-sandbox", self.events)
        self.assertEqual(self.events.count("delete-image:new-image"), 1)
        self.assertIn("old-image", self.images)
        self.assertNotIn("new-image", self.images)
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_failed_import_cleans_only_new_image_before_any_writer_is_stopped(self):
        self.prepare_real_import("Failed")
        with self.assertRaisesRegex(RuntimeError, "image import failed"):
            deploy_hermes.deploy(self.config, self.clients, replace=True)
        self.assert_failed_import_is_cleaned_without_stopping_old_writer()

    def test_timed_out_import_is_inside_the_cleanup_transaction(self):
        self.prepare_real_import("Importing")
        with patch.object(deploy_hermes.time, "monotonic", side_effect=[0, 601]), self.assertRaises(TimeoutError):
            deploy_hermes.deploy(self.config, self.clients, replace=True)
        self.assert_failed_import_is_cleaned_without_stopping_old_writer()

    def test_cancelled_import_is_inside_the_cleanup_transaction(self):
        self.prepare_real_import("Importing")
        with patch.object(deploy_hermes.time, "sleep", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            deploy_hermes.deploy(self.config, self.clients, replace=True)
        self.assert_failed_import_is_cleaned_without_stopping_old_writer()


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.config = config()
        self.clients = MagicMock()
        self.clients.resources.resource_groups.check_existence.return_value = True
        self.clients.group.list_sandboxes.return_value = []
        self.clients.group.list_volumes.return_value = []
        self.clients.group.list_secrets.return_value = []
        self.clients.group.get_sandbox_client.return_value.sandbox_id = "owned-sandbox"
        self.clients.group.get_sandbox_client.return_value.begin_delete.return_value.done.return_value = True
        self.volume = SimpleNamespace(name=self.config.volume_name)
        self.image = SimpleNamespace(id="owned-image")

    def test_default_cleanup_never_deletes_personal_disk_or_group(self):
        with patch.object(cleanup_hermes, "assert_owner"), patch.object(
            cleanup_hermes, "owned_inventory", return_value=([], [self.image], [self.volume])
        ):
            cleanup_hermes.cleanup(self.config, self.clients)
        self.clients.group.begin_delete_volume.assert_not_called()
        self.clients.groups.begin_delete_group.assert_not_called()
        self.clients.resources.resource_groups.begin_delete.assert_not_called()
        self.clients.group.begin_delete_disk_image.assert_called_once_with("owned-image")

    def test_data_deletion_requires_exact_full_volume_target_before_cloud(self):
        with self.assertRaises(ValueError):
            cleanup_hermes.cleanup(self.config, self.clients, delete_data=True, confirm_volume="hermes-data")
        self.clients.resources.resource_groups.check_existence.assert_not_called()

    def test_malformed_recovery_confirmation_is_rejected_before_any_azure_call(self):
        prefix = self.config.group_scope + "/sandboxes/"
        for value in ("", "old-sandbox", self.config.group_scope, prefix, prefix + "../old-sandbox",
                      prefix + "old-sandbox?secret=value", prefix + "old-sandbox/extra"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "full owned sandbox target"):
                cleanup_hermes.cleanup(self.config, self.clients, confirm_unquiesced_writer=value)
            self.assertEqual(self.clients.method_calls, [])

    def test_cli_rejects_malformed_recovery_before_client_creation(self):
        with patch("sys.argv", [
            "cleanup_hermes.py", "--confirm-target", self.config.group_scope,
            "--confirm-unquiesced-writer", "partial-target",
        ]), patch.object(common.Config, "from_env", return_value=self.config), patch.object(
            common.AzureClients, "create",
        ) as clients, self.assertRaisesRegex(ValueError, "full owned sandbox target"):
            cleanup_hermes.main()
        clients.assert_not_called()

    def test_cli_transport_errors_never_print_private_sdk_details(self):
        self.clients.resources.resource_groups.check_existence.side_effect = ServiceRequestError("PRIVATE-CLI-DETAIL")
        with patch("sys.argv", [
            "cleanup_hermes.py", "--confirm-target", self.config.group_scope,
        ]), patch.object(common.Config, "from_env", return_value=self.config), patch.object(
            common, "assert_owner",
        ), patch.object(common.AzureClients, "create") as create:
            create.return_value.__enter__.return_value = self.clients
            with self.assertRaises(SystemExit) as raised:
                runpy.run_path(str(ROOT / "scripts/cleanup_hermes.py"), run_name="__main__")
        self.assertIn("ServiceRequestError", str(raised.exception))
        self.assertNotIn("PRIVATE-CLI-DETAIL", str(raised.exception))

    def test_group_delete_cannot_implicitly_delete_data(self):
        with self.assertRaises(ValueError):
            cleanup_hermes.cleanup(self.config, self.clients, delete_group=True)

    def test_foreign_inventory_blocks_all_deletion(self):
        with patch.object(cleanup_hermes, "assert_owner"), patch.object(
            cleanup_hermes, "owned_inventory", side_effect=RuntimeError("Unowned object")
        ), self.assertRaises(RuntimeError):
            cleanup_hermes.cleanup(self.config, self.clients)
        self.clients.group.begin_delete_disk_image.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_explicit_data_delete_only_named_volume(self):
        with patch.object(cleanup_hermes, "assert_owner"), patch.object(
            cleanup_hermes, "owned_inventory", return_value=([], [], [self.volume])
        ):
            cleanup_hermes.cleanup(
                self.config, self.clients, delete_data=True,
                confirm_volume=f"{self.config.group_scope}/volumes/{self.config.volume_name}",
            )
        self.clients.group.begin_delete_volume.assert_called_once_with(self.config.volume_name)
        self.clients.groups.begin_delete_group.assert_not_called()

    def test_target_confirmation_is_exact(self):
        with self.assertRaises(ValueError):
            common.confirm_target(self.config, "hermes-sandbox-group")
        common.confirm_target(self.config, self.config.group_scope)

    def test_running_cleanup_stops_before_delete_and_checks_absence_before_images(self):
        events = []
        sandbox = self.clients.group.get_sandbox_client.return_value
        sandbox.sandbox_id = "owned-sandbox"
        state = {"gateway": "running", "deleted": False}

        def get(path):
            if state["deleted"]:
                events.append("confirm-404")
                raise ResourceNotFoundError("fixture absent")
            return {"id": "owned-sandbox", "state": "Running"}

        def execute(path, payload):
            action = shlex.split(payload["command"])[2]
            events.append(action)
            if action == "stop-gateway":
                state["gateway"] = "maintenance"
            return {"exitCode": 0, "stdout": json.dumps({
                "schema_version": 1, "dashboard": "running", "gateway": state["gateway"],
                "whatsapp": "paired", "google": "disabled", "disk_free_bytes": 0,
            })}

        def finish(**kwargs):
            events.append("delete")
            state["deleted"] = True

        sandbox._dp_get.side_effect = get
        sandbox._dp_post.side_effect = execute
        sandbox.begin_delete.return_value.result.side_effect = finish
        self.clients.group.list_sandboxes.side_effect = lambda: events.append("check-absent") or []
        self.clients.group.begin_delete_disk_image.side_effect = lambda *args: events.append("image") or MagicMock()
        with patch.object(cleanup_hermes, "assert_owner"), patch.object(
            cleanup_hermes, "owned_inventory",
            return_value=([SimpleNamespace(id="owned-sandbox")], [self.image], [self.volume]),
        ):
            cleanup_hermes.cleanup(self.config, self.clients)
        self.assertEqual(events, ["status", "stop-gateway", "status", "delete", "confirm-404", "check-absent", "image"])
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_preserving_cleanup_refuses_unknown_intent_on_nonrunning_compute(self):
        sandbox = self.clients.group.get_sandbox_client.return_value
        sandbox._dp_get.return_value = {"id": "owned-sandbox", "state": "Stopped"}
        with patch.object(cleanup_hermes, "assert_owner"), patch.object(
            cleanup_hermes, "owned_inventory",
            return_value=([SimpleNamespace(id="owned-sandbox")], [self.image], [self.volume]),
        ), self.assertRaisesRegex(RuntimeError, "running sandbox"):
            cleanup_hermes.cleanup(self.config, self.clients)
        sandbox._dp_post.assert_not_called()
        sandbox.begin_resume.assert_not_called()
        sandbox.begin_delete.assert_not_called()
        self.clients.group.begin_delete_disk_image.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()

    def test_explicit_data_deletion_can_remove_confirmed_stopped_compute(self):
        sandbox = self.clients.group.get_sandbox_client.return_value
        sandbox._dp_get.side_effect = [
            {"id": "owned-sandbox", "state": "Stopped"}, ResourceNotFoundError("fixture deleted"),
        ]
        with patch.object(cleanup_hermes, "assert_owner"), patch.object(
            cleanup_hermes, "owned_inventory",
            return_value=([SimpleNamespace(id="owned-sandbox")], [self.image], [self.volume]),
        ):
            cleanup_hermes.cleanup(
                self.config, self.clients, delete_data=True,
                confirm_volume=f"{self.config.group_scope}/volumes/{self.config.volume_name}",
            )
        sandbox.begin_delete.assert_called_once()
        sandbox._dp_post.assert_not_called()
        self.clients.group.begin_delete_volume.assert_called_once_with(self.config.volume_name)

    def test_incomplete_compute_deletion_preserves_all_images_and_data(self):
        sandbox = self.clients.group.get_sandbox_client.return_value
        sandbox.sandbox_id = "owned-sandbox"
        sandbox._dp_get.return_value = {"id": "owned-sandbox", "state": "Stopped"}
        self.clients.group.list_sandboxes.return_value = [SimpleNamespace(id="owned-sandbox")]
        with patch.object(cleanup_hermes, "assert_owner"), patch.object(
            cleanup_hermes, "owned_inventory",
            return_value=([SimpleNamespace(id="owned-sandbox")], [self.image], [self.volume]),
        ), self.assertRaisesRegex(RuntimeError, "Sandbox deletion is incomplete"):
            cleanup_hermes.cleanup(
                self.config, self.clients, delete_data=True,
                confirm_volume=f"{self.config.group_scope}/volumes/{self.config.volume_name}",
            )
        self.clients.group.begin_delete_disk_image.assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()
        self.clients.groups.begin_delete_group.assert_not_called()

    def test_known_unsupported_policy_stops_before_any_azure_operation(self):
        with patch.object(deploy_hermes, "provision_group") as provision, self.assertRaisesRegex(
            RuntimeError, "Partial .* defaultAction Deny",
        ):
            deploy_hermes.deploy(config(image=""), self.clients)
        provision.assert_not_called()
        self.assertEqual(self.clients.method_calls, [])

    def test_production_cli_blocks_before_configuration_and_azure_clients(self):
        with patch("sys.argv", ["deploy_hermes.py"]), patch.object(
            common.Config, "from_env",
        ) as read_configuration, patch.object(common.AzureClients, "create") as create_clients:
            with self.assertRaisesRegex(RuntimeError, "before Azure changes"):
                deploy_hermes.main()
        read_configuration.assert_not_called()
        create_clients.assert_not_called()


if __name__ == "__main__":
    unittest.main()
