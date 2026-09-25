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
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError, ServiceRequestError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import access_hermes
import cleanup_hermes
import deploy_hermes
import hermes_common as common
import test_hermes


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
        "egress_mode": "allow-all-mvp",
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


class ExplicitEgressModeTests(unittest.TestCase):
    def test_missing_unknown_and_unverified_modes_fail_before_config_or_azure(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            path = Path(directory) / ".env.hermes"
            for mode in (None, "", "allow-all", "Allow-all-mvp", "allow-all-mvp-secret-canary", "hardened-unverified"):
                path.write_text("" if mode is None else f"HERMES_EGRESS_MODE={mode}\n")
                for entrypoint in (deploy_hermes, test_hermes, access_hermes):
                    with (
                        self.subTest(mode=mode, entrypoint=entrypoint.__name__),
                        patch.object(common.Config, "from_values") as construct,
                        patch.object(common.AzureClients, "create") as azure,
                        patch.object(sys, "argv", ["script", "--env-file", str(path)]),
                        self.assertRaisesRegex(RuntimeError, "HERMES_EGRESS_MODE") as raised,
                    ):
                        entrypoint.main()
                    construct.assert_not_called()
                    azure.assert_not_called()
                    self.assertNotIn("secret-canary", str(raised.exception))

    def test_programmatic_deploy_and_check_require_opt_in_before_any_clients(self):
        for mode in ("", "unknown", "hardened-unverified"):
            for operation in (deploy_hermes.deploy, test_hermes.inspect_deployment):
                clients = MagicMock()
                with self.subTest(mode=mode, operation=operation.__name__), self.assertRaises(RuntimeError):
                    operation(config(egress_mode=mode), clients)
                self.assertEqual(clients.mock_calls, [])

    def test_valid_opt_in_is_read_once_before_config_construction(self):
        values = {
            "HERMES_SUBSCRIPTION_ID": config().subscription_id,
            "HERMES_TENANT_ID": config().tenant_id,
            "HERMES_OWNER_OBJECT_ID": config().owner_object_id,
            "HERMES_EGRESS_MODE": common.MVP_EGRESS_MODE,
        }
        with patch.object(common, "_read_env", return_value=values) as read:
            loaded = common.load_egress_config(Path("chosen.env.hermes"))
        read.assert_called_once_with(Path("chosen.env.hermes"))
        self.assertEqual(loaded.egress_mode, common.MVP_EGRESS_MODE)

    def test_environment_opt_in_is_deliberate_and_invalid_override_does_not_fall_back_to_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env.hermes"
            path.write_text(
                f"HERMES_SUBSCRIPTION_ID={config().subscription_id}\n"
                f"HERMES_TENANT_ID={config().tenant_id}\n"
                f"HERMES_OWNER_OBJECT_ID={config().owner_object_id}\n"
                "HERMES_EGRESS_MODE=\n"
            )
            with patch.dict(os.environ, {"HERMES_EGRESS_MODE": "allow-all-mvp"}, clear=True):
                with self.assertLogs("hermes.config", level="WARNING"):
                    loaded = common.load_egress_config(path)
            self.assertEqual(loaded.egress_mode, common.MVP_EGRESS_MODE)
            path.write_text(path.read_text().replace("HERMES_EGRESS_MODE=\n", "HERMES_EGRESS_MODE=allow-all-mvp\n"))
            with patch.dict(os.environ, {"HERMES_EGRESS_MODE": "private-invalid-mode"}, clear=True):
                with self.assertLogs("hermes.config", level="WARNING") as captured:
                    with self.assertRaisesRegex(RuntimeError, "explicitly set") as raised:
                        common.load_egress_config(path)
            self.assertIn("HERMES_EGRESS_MODE", "\n".join(captured.output))
            self.assertNotIn("private-invalid-mode", "\n".join(captured.output) + str(raised.exception))

    def test_future_hardened_contract_is_not_an_allow_or_inspection_fallback(self):
        with self.assertRaises(RuntimeError) as raised:
            common.require_egress_mode("hardened-unverified")
        self.assertIn("Partial + Deny was rejected", str(raised.exception))
        self.assertIn("Full + Deny remains unverified", str(raised.exception))
        self.assertIn("our diagnostics", str(raised.exception))
        self.assertIn("no automatic fallback", str(raised.exception))

    def test_cleanup_can_load_missing_or_unusable_mode_without_accepting_unrestricted_access(self):
        values = {
            "HERMES_SUBSCRIPTION_ID": config().subscription_id,
            "HERMES_TENANT_ID": config().tenant_id,
            "HERMES_OWNER_OBJECT_ID": config().owner_object_id,
        }
        for mode in ("", "hardened-unverified", "typo"):
            with self.subTest(mode=mode), patch.object(common, "_read_env", return_value={
                **values, "HERMES_EGRESS_MODE": mode,
            }):
                loaded = common.Config.from_env()
            self.assertEqual(loaded.egress_mode, mode)
            clients = MagicMock()
            clients.resources.resource_groups.check_existence.return_value = False
            with patch.object(cleanup_hermes, "assert_owner"), redirect_stdout(io.StringIO()):
                cleanup_hermes.cleanup(loaded, clients)
            clients.resources.resource_groups.check_existence.assert_called_once_with(loaded.resource_group)
            clients.group._dp_put.assert_not_called()
            clients.group._dp_post.assert_not_called()

    def test_warning_names_the_privacy_risk_and_does_not_claim_tool_controls_are_isolation(self):
        with self.assertLogs("hermes.egress", level="WARNING") as captured:
            common.warn_unrestricted_egress("allow-all-mvp")
        output = "\n".join(captured.output)
        for text in ("TEMPORARY", "NO outbound network isolation", "All internet destinations",
                     "no TLS inspection", "compromised prompt/model path", "exfiltrate personal data",
                     "not an egress boundary"):
            self.assertIn(text, output)


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
        self.assertEqual(payload["egressPolicy"], {"defaultAction": "Allow", "trafficInspection": "None"})
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

    def test_none_allow_is_exact_and_reserved_hosts_do_not_create_rules(self):
        self.assertEqual(self.egress, {"defaultAction": "Allow", "trafficInspection": "None"})
        self.assertEqual(common.deployment_egress(config(identity_host="", whatsapp_hosts=())), self.egress)
        self.assertEqual(common.deployment_egress(config(
            identity_host="different.invalid", whatsapp_hosts=("different.whatsapp.invalid",),
        )), self.egress)
        self.assertNotIn("egress_mode", common.runtime_document(self.config))
        for host in ("*.google.com", "https://google.com", "host:443", "bad..host", "HOST.com"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                common.exact_host(host)

    def test_readback_never_accepts_another_inspection_mode_default_or_active_rule(self):
        for inspection in ("Full", "Partial", "Legacy", None, False, ""):
            changed = dict(self.egress, trafficInspection=inspection)
            with self.subTest(inspection=inspection), self.assertRaises(RuntimeError):
                common.validate_egress({"egressPolicy": changed}, self.egress)
        for changed in (
            {}, None, [], {"defaultAction": "Allow"},
            dict(self.egress, defaultAction="Deny"), dict(self.egress, defaultAction=None),
            dict(self.egress, hostRules=[{"pattern": "example.com", "action": "Allow"}]),
            dict(self.egress, rules=[{"action": {"type": "Transform", "headers": [{"value": "CANARY"}]}}]),
        ):
            with self.subTest(changed=changed), self.assertRaises(RuntimeError) as raised:
                common.validate_egress({"egressPolicy": changed}, self.egress)
            self.assertNotIn("CANARY", str(raised.exception))

    def test_known_readback_enums_are_normalized_without_treating_null_as_none(self):
        class Inspection(str, Enum):
            NONE = "None"

        class Action(str, Enum):
            ALLOW = "Allow"

        for action, inspection in (("allow", "none"), ("ALLOW", "NONE"), (Action.ALLOW, Inspection.NONE)):
            with self.subTest(action=action, inspection=inspection):
                result = common.validate_egress({
                    "egressPolicy": {"defaultAction": action, "trafficInspection": inspection},
                }, self.egress)
                self.assertTrue(result["known_fields_match"])
        for value in (None, False, 0, "", "no-inspection", " None "):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                common.validate_egress({"egressPolicy": dict(self.egress, trafficInspection=value)}, self.egress)

    def test_only_known_empty_optional_rule_lists_can_be_normalized_on_readback(self):
        for value in (None, []):
            common.validate_egress({"egressPolicy": dict(self.egress, hostRules=value, rules=value)}, self.egress)
        common.validate_egress({"egressPolicy": self.egress}, self.egress)
        for name in ("hostRules", "rules"):
            for value in ("", {}, False, True, 0, "CANARY", None, []):
                if value is None or value == []:
                    continue
                with self.subTest(name=name, value=value), self.assertRaises(RuntimeError):
                    common.validate_egress({"egressPolicy": {**self.egress, name: value}}, self.egress)

    def test_benign_unknown_metadata_is_tolerated_but_names_and_no_assurance_are_reported(self):
        for value in (None, [], {}, False, 0, "VALUE_CANARY", {"nested": "VALUE_CANARY"}):
            policy = {**self.egress, "metadata": value, "reportedAt": value, "apiVersion": value}
            with self.subTest(value=value), self.assertLogs("hermes.egress", level="WARNING") as captured:
                result = common.validate_egress({"egressPolicy": policy}, self.egress)
            self.assertEqual(result["unknown_field_names"], ["apiVersion", "metadata", "reportedAt"])
            self.assertEqual(result["unknown_field_count"], 3)
            self.assertEqual(result["unknown_field_semantics"], "NOT RELIED ON")
            self.assertEqual(result["unrestricted_connectivity"], "NOT VERIFIED")
            output = "\n".join(captured.output)
            self.assertIn('["apiVersion", "metadata", "reportedAt"]', output)
            self.assertIn("count=3", output)
            self.assertIn("semantics are not relied on", output)
            self.assertIn("not proof of unrestricted connectivity", output)
            self.assertNotIn("VALUE_CANARY", output + json.dumps(result))
            self.assertNotIn("nested", output + json.dumps(result))

    def test_suspicious_policy_field_names_fail_even_if_empty_with_no_value_disclosure(self):
        names = (
            "futureRules", "hostMetadata", "actionOverride", "inspectionStatus", "denyAll", "allowedOrigins",
            "destinationSet", "endpointMap", "networkIsolation", "egressDisabled", "proxyUrl", "TLSSettings",
            "certificateBundle", "securityOptions", "trustStore", "policyVersion", "caBundle", "CASettings",
            "portOverrides", "staticIP", "accessControl", "secretRef", "managedIdentityToken", "headers",
            "managedIdentity", "transportConfig", "enforcementMode", "certBundle",
        )
        for name in names:
            for value in (None, [], "VALUE_CANARY", {"Authorization": "VALUE_CANARY"}):
                with self.subTest(name=name, value=value), self.assertRaisesRegex(
                    RuntimeError, "policy/security-bearing",
                ) as raised:
                    common.validate_egress({"egressPolicy": {**self.egress, name: value}}, self.egress)
                self.assertIn(name, str(raised.exception))
                self.assertIn("count=1", str(raised.exception))
                self.assertNotIn("VALUE_CANARY", str(raised.exception))
                self.assertNotIn("Authorization", str(raised.exception))

    def test_security_acronym_plurals_and_synonyms_fail_name_only_without_logging_values(self):
        names = (
            "rootCAs", "ACLs", "sourceIPs", "SNIs", "CERTs", "PORTs", "SSLs",
            "sourceIps", "blockedIps", "customCas", "customAcls", "customSnis",
            "routes", "decryption", "decryptionMode", "interception", "auth", "authMode", "oauth",
            "apiKey", "apiKeys", "password", "passwd", "sas", "URLs", "url",
            "bypass", "overrides", "exemptions", "exceptions", "exclusions", "excluded",
            "upstream", "gateway", "tunnel", "forwarding", "domain", "fqdn", "patterns", "api.example.net",
        )
        for name in names:
            for value in (None, {"Authorization": "VALUE_CANARY"}):
                with self.subTest(name=name, value=value):
                    with self.assertNoLogs("hermes.egress", level="WARNING"), self.assertRaisesRegex(
                        RuntimeError, "policy/security-bearing",
                    ) as raised:
                        common.validate_egress({"egressPolicy": {**self.egress, name: value}}, self.egress)
                    self.assertIn(name, str(raised.exception))
                    self.assertIn("count=1", str(raised.exception))
                    self.assertNotIn("VALUE_CANARY", str(raised.exception))
                    self.assertNotIn("Authorization", str(raised.exception))

    def test_acronym_plurals_do_not_lose_existing_short_word_boundaries(self):
        names = (
            "rootCAId", "ACLId", "sourceIPId", "CERTId", "CAId",
            "IPId", "SNIId", "PORTId", "SSLOn", "SSLIs",
        )
        for name in names:
            for value in (None, {"Authorization": "VALUE_CANARY"}):
                with self.subTest(name=name, value=value):
                    with self.assertNoLogs("hermes.egress", level="WARNING"), self.assertRaisesRegex(
                        RuntimeError, "policy/security-bearing",
                    ) as raised:
                        common.validate_egress({"egressPolicy": {**self.egress, name: value}}, self.egress)
                    self.assertIn(name, str(raised.exception))
                    self.assertIn("count=1", str(raised.exception))
                    self.assertNotIn("VALUE_CANARY", str(raised.exception))
                    self.assertNotIn("Authorization", str(raised.exception))

    def test_benign_metadata_and_substring_traps_are_not_security_fields(self):
        names = (
            "metadata", "apiVersion", "reportedAt", "provisioningState", "createdAt", "updatedAt",
            "etag", "@odata.etag", "@odata.type", "resourceId", "id", "IDs", "APIs", "name", "kind", "type",
            "status", "state", "region", "location", "description", "version", "generation",
            "annotations", "labels", "monkey", "monkeys", "author", "authors", "portal", "portable",
            "caching", "documentation", "opaqueId", "diagnostics", "revision", "hash",
        )
        policy = {**self.egress, **{name: {"nested": "VALUE_CANARY"} for name in names}}
        with self.assertLogs("hermes.egress", level="WARNING") as captured:
            result = common.validate_egress({"egressPolicy": policy}, self.egress)
        self.assertEqual(result["unknown_field_names"], sorted(names))
        self.assertEqual(result["unknown_field_count"], len(names))
        self.assertEqual(result["unknown_field_semantics"], "NOT RELIED ON")
        self.assertEqual(result["unrestricted_connectivity"], "NOT VERIFIED")
        self.assertNotIn("VALUE_CANARY", "\n".join(captured.output) + json.dumps(result))
        self.assertNotIn("nested", "\n".join(captured.output) + json.dumps(result))

    def test_unsafe_or_oversized_field_names_are_not_echoed(self):
        for name in ("https://VALUE_CANARY.invalid/?token=VALUE_CANARY", "VALUE_CANARY\n", "x" * 129, 1):
            with self.subTest(kind=type(name).__name__), self.assertRaisesRegex(
                RuntimeError, "safe name-only",
            ) as raised:
                common.validate_egress({"egressPolicy": {**self.egress, name: "VALUE_CANARY"}}, self.egress)
            self.assertNotIn("VALUE_CANARY", str(raised.exception))
        with self.assertRaisesRegex(RuntimeError, "safe name-only"):
            common.validate_egress({"egressPolicy": {
                **self.egress, **{f"metadata_{index}": None for index in range(65)},
            }}, self.egress)

    def test_request_shape_cannot_smuggle_rules_even_empty_or_bypass_opt_in(self):
        for policy in (
            dict(self.egress, hostRules=[]), dict(self.egress, rules=None),
            dict(self.egress, unknown=False), dict(self.egress, trafficInspection="Partial"),
        ):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                common.sandbox_document(self.config, disk_id="image-id", egress=policy)
            with self.assertRaises(RuntimeError):
                common.validate_egress({"egressPolicy": policy}, policy)
        with self.assertRaises(RuntimeError):
            common.sandbox_document(config(egress_mode=""), disk_id="image-id", egress=self.egress)

    def test_missing_mode_prevents_egress_mutation(self):
        for mode in ("", "hardened-unverified", "typo"):
            sandbox = MagicMock()
            with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                common.configure_egress(sandbox, config(egress_mode=mode))
            self.assertEqual(sandbox.mock_calls, [])

    def test_service_error_never_retries_a_policy_with_different_inspection(self):
        sandbox = MagicMock()
        sandbox._sbx_path = "/test/sandbox"
        error = HttpResponseError("PRIVATE-SERVICE-DETAIL")
        sandbox._dp_post.side_effect = error
        with self.assertLogs("hermes.egress", level="WARNING"), self.assertRaises(HttpResponseError) as raised:
            common.configure_egress(sandbox, self.config)
        self.assertIs(raised.exception, error)
        sandbox._dp_post.assert_called_once_with("/test/sandbox/egresspolicy", self.egress)
        sandbox._dp_get.assert_not_called()

    def test_configure_egress_rejects_unclassified_security_fields_without_retry(self):
        sandbox = MagicMock(sandbox_id="sandbox-id", _sbx_path="/test/sandbox")
        sandbox._dp_get.return_value = {"id": "sandbox-id", "egressPolicy": dict(self.egress, networkMetadata=None)}
        with self.assertLogs("hermes.egress", level="WARNING"), self.assertRaisesRegex(RuntimeError, "networkMetadata"):
            common.configure_egress(sandbox, self.config)
        sandbox._dp_post.assert_called_once_with("/test/sandbox/egresspolicy", self.egress)
        sandbox._dp_get.assert_called_once_with("/test/sandbox")

    def test_network_error_is_not_success_and_does_not_change_policy_or_trust(self):
        sandbox = MagicMock()
        raw = {"egressPolicy": self.egress}
        for evidence in (
            {"example.com": {"network_error": "URLError"}},
            {"example.com": {"public_ca_tls": False, "http_status": 200}},
            {"example.com": {"public_ca_tls": True, "http_status": True}},
            {"example.com": {"public_ca_tls": True, "http_status": 200, "secret": "CANARY"}},
            {},
        ):
            sandbox.reset_mock()
            sandbox._dp_post.return_value = {"exitCode": 0, "stdout": json.dumps(evidence)}
            with patch.object(common, "raw_sandbox", return_value=raw):
                with self.subTest(evidence=evidence), self.assertRaisesRegex(RuntimeError, "public-CA") as raised:
                    common.verify_mvp_network(sandbox, self.config)
            self.assertNotIn("CANARY", str(raised.exception))
            self.assertEqual(sandbox._dp_post.call_count, 1)
            self.assertTrue(sandbox._dp_post.call_args.args[0].endswith("/executeShellCommand"))
            sandbox._dp_put.assert_not_called()

    def test_mvp_network_checks_only_nonpersonal_https_without_a_deny_or_isolation_claim(self):
        sandbox = MagicMock()
        sandbox._sbx_path = "/test/sandbox"
        sandbox._dp_post.return_value = {
            "exitCode": 0, "stdout": json.dumps({"example.com": {"public_ca_tls": True, "http_status": 404}}),
        }
        with patch.object(common, "raw_sandbox", return_value={"egressPolicy": self.egress}):
            result = common.verify_mvp_network(sandbox, self.config)
        self.assertFalse(result["outbound_isolation"])
        self.assertFalse(result["all_destinations_tested"])
        self.assertEqual(result["traffic_inspection"], "None")
        self.assertEqual(result["public_ca_tls_hosts"], ["example.com"])
        self.assertNotIn("platform_deny_observed", result)
        sandbox._dp_get.assert_not_called()
        command = shlex.split(sandbox._dp_post.call_args.args[1]["command"])
        self.assertEqual(json.loads(command[-1]), ["example.com"])
        self.assertIn("ssl.create_default_context", command[-2])
        self.assertIn("ProxyHandler({})", command[-2])
        self.assertNotIn("_create_unverified_context", command[-2])

    def test_network_mode_or_raw_policy_failure_precedes_guest_execution(self):
        sandbox = MagicMock()
        with self.assertRaises(RuntimeError):
            common.verify_mvp_network(sandbox, config(egress_mode="hardened-unverified"))
        self.assertEqual(sandbox.mock_calls, [])
        with patch.object(common, "raw_sandbox", return_value={
            "egressPolicy": dict(self.egress, trafficInspection="Full"),
        }), self.assertRaises(RuntimeError):
            common.verify_mvp_network(sandbox, self.config)
        sandbox._dp_post.assert_not_called()


class EgressStatusAndAccessTests(unittest.TestCase):
    def setUp(self):
        self.config = config()
        self.clients = MagicMock()
        self.sandbox = MagicMock(sandbox_id="sandbox-id")
        self.raw = {
            "id": "sandbox-id", "state": "Running",
            "lifecycle": {"autoSuspendPolicy": {"enabled": False}},
            "ports": [common.port_document(self.config, "sandbox-id")],
            "egressPolicy": common.deployment_egress(self.config),
        }
        self.status = {
            "schema_version": 1, "dashboard": "running", "gateway": "not-paired",
            "whatsapp": "not-paired", "google": "disabled", "disk_free_bytes": common.MIN_FREE_BYTES,
        }

    def test_status_has_unrestricted_warning_and_no_false_hardened_or_live_success(self):
        self.raw["egressPolicy"].update({"metadata": {"private": "VALUE_CANARY"}, "provisioningState": "VALUE_CANARY"})
        with (
            patch.object(test_hermes, "assert_owner"),
            patch.object(test_hermes, "owned_inventory", return_value=([], [], [object()])),
            patch.object(test_hermes, "get_sandbox", return_value=self.sandbox),
            patch.object(test_hermes, "raw_sandbox", return_value=self.raw),
            patch.object(test_hermes, "read_runtime", return_value=common.runtime_document(self.config)),
            patch.object(test_hermes, "read_access_key"),
            patch.object(test_hermes, "control_status", return_value=self.status),
            patch.object(test_hermes, "verify_mvp_network") as network,
            self.assertLogs("hermes.egress", level="WARNING") as logged,
        ):
            result = test_hermes.inspect_deployment(self.config, self.clients)
            self.assertEqual(result["network"], "NOT VERIFIED")
            network.assert_not_called()
            network.return_value = {"outbound_isolation": False}
            checked = test_hermes.inspect_deployment(self.config, self.clients, network=True)
        network.assert_called_once_with(self.sandbox, self.config)
        self.assertEqual(checked["network"], {"outbound_isolation": False})
        self.assertEqual(result["egress"]["mode"], "allow-all-mvp")
        self.assertEqual(result["egress"]["trafficInspection"], "None")
        self.assertEqual(result["egress"]["defaultAction"], "Allow")
        self.assertFalse(result["egress"]["outbound_isolation"])
        self.assertEqual(result["raw_azure_policy"], "KNOWN MVP FIELDS MATCH")
        self.assertEqual(result["egress"]["readback"]["unknown_field_names"], ["metadata", "provisioningState"])
        self.assertEqual(result["egress"]["readback"]["unknown_field_count"], 2)
        self.assertEqual(result["egress"]["readback"]["unrestricted_connectivity"], "NOT VERIFIED")
        self.assertIn("exfiltrate personal data", result["egress"]["warning"])
        self.assertIn("NO outbound network isolation", "\n".join(logged.output))
        self.assertNotIn("VALUE_CANARY", json.dumps(result) + "\n".join(logged.output))
        for key in ("foundry_inference", "whatsapp_delivery", "google_live_read", "entra_non_owner_and_websocket"):
            self.assertEqual(result[key], "NOT VERIFIED")
        self.assertNotIn("egress", result["runtime"])
        self.assertNotIn("partial_network", result)

    def test_access_warns_and_checks_policy_before_starting_the_fixed_loopback_relay(self):
        self.raw["egressPolicy"]["metadata"] = {"private": "VALUE_CANARY"}
        for valid in (False, True):
            raw = self.raw if valid else {**self.raw, "egressPolicy": {
                "defaultAction": "Allow", "trafficInspection": "Full",
            }}
            with (
                self.subTest(valid=valid),
                patch.object(access_hermes, "load_egress_config", return_value=self.config),
                patch.object(common.AzureClients, "create") as azure,
                patch.object(access_hermes, "assert_owner"),
                patch.object(access_hermes, "get_sandbox", return_value=self.sandbox),
                patch.object(access_hermes, "raw_sandbox", return_value=raw),
                patch.object(access_hermes, "Proxy") as proxy,
                patch.object(access_hermes.web, "run_app") as run,
                patch.object(sys, "argv", ["script"]),
                self.assertLogs("hermes.egress", level="WARNING") as logged,
                redirect_stdout(io.StringIO()),
            ):
                if valid:
                    access_hermes.main()
                    self.assertEqual(proxy.call_args.kwargs["target"], common.ingress_url("sandbox-id", "swedencentral"))
                    self.assertEqual(proxy.call_args.kwargs["local_origin"], "http://127.0.0.1:8765")
                    run.assert_called_once_with(
                        proxy.return_value.app, host="127.0.0.1", port=8765, access_log=None, print=None,
                    )
                else:
                    with self.assertRaises(RuntimeError):
                        access_hermes.main()
                    proxy.assert_not_called()
                    run.assert_not_called()
                azure.assert_called_once_with(self.config)
                self.assertNotIn("VALUE_CANARY", "\n".join(logged.output))


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
            "assert_owner": None, "provision_group": None,
            "owned_inventory": ([], [], []), "create_image": "new-image", "wait_image": None, "wait_running": self.raw,
            "upload_private_file": None, "read_runtime": common.runtime_document(self.config),
            "verify_mvp_network": None, "control_status": {"dashboard": "running"},
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

    def test_create_service_error_never_retries_or_changes_none_allow_policy(self):
        error = HttpResponseError("PRIVATE-CREATE-DETAIL")
        self.clients.group._dp_put.side_effect = error
        with self.assertLogs("hermes.deploy", level="ERROR"), self.assertRaises(HttpResponseError) as raised:
            deploy_hermes.deploy(self.config, self.clients)
        self.assertIs(raised.exception, error)
        self.clients.group._dp_put.assert_called_once()
        self.assertEqual(
            self.clients.group._dp_put.call_args.args[1]["egressPolicy"],
            {"trafficInspection": "None", "defaultAction": "Allow"},
        )
        self.sandbox._dp_post.assert_not_called()
        self.mocks["configure_port"].assert_not_called()

    def test_policy_readback_mismatch_rolls_back_without_exposure_or_policy_retry(self):
        for policy in (
            dict(common.deployment_egress(self.config), trafficInspection="Partial"),
            dict(common.deployment_egress(self.config), trafficInspection="Full"),
            dict(common.deployment_egress(self.config), futureRules=None),
        ):
            with self.subTest(policy=policy):
                self.deleted = False
                self.image_deleted = False
                self.mocks["wait_running"].return_value = {**self.raw, "egressPolicy": policy}
                with self.assertRaisesRegex(RuntimeError, "raw egress policy|policy/security-bearing"):
                    deploy_hermes.deploy(self.config, self.clients)
        self.assertEqual(self.clients.group._dp_put.call_count, 3)
        self.sandbox._dp_post.assert_not_called()
        self.mocks["configure_port"].assert_not_called()
        self.mocks["upload_private_file"].assert_not_called()
        self.clients.group.begin_delete_volume.assert_not_called()

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
            "assert_owner": lambda *args: None,
            "provision_group": lambda *args: None,
            "owned_inventory": lambda *args: (
                [SimpleNamespace(id=identifier) for identifier in self.active], list(self.images.values()), list(self.volumes),
            ),
            "create_image": self.create_image,
            "wait_running": lambda sandbox: sandbox._dp_get(sandbox._sbx_path),
            "upload_private_file": lambda *args, **kwargs: self.events.append("upload-runtime"),
            "read_runtime": lambda *args: common.runtime_document(self.config),
            "verify_mvp_network": lambda *args: None,
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
        self.mocks["verify_mvp_network"].side_effect = RuntimeError("fixture egress mismatch")
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

    def test_existing_policy_mismatch_is_not_adopted_or_rewritten(self):
        self.images["old-image"].image.base = self.config.image
        original_get = self.old._dp_get.side_effect

        def mismatched(path):
            raw = original_get(path)
            raw["egressPolicy"] = {"trafficInspection": "Full", "defaultAction": "Deny"}
            return raw

        self.old._dp_get.side_effect = mismatched
        with self.assertRaisesRegex(RuntimeError, "raw egress policy"):
            deploy_hermes.deploy(self.config, self.clients)
        self.assertEqual(self.events, ["get:old-sandbox"])
        self.mocks["create_image"].assert_not_called()
        self.clients.group._dp_put.assert_not_called()
        self.old._dp_post.assert_not_called()
        self.old.begin_delete.assert_not_called()

    def test_existing_mvp_benign_metadata_does_not_trigger_replacement_or_policy_mutation(self):
        self.images["old-image"].image.base = self.config.image
        original_get = self.old._dp_get.side_effect

        def metadata(path):
            raw = original_get(path)
            raw["egressPolicy"]["metadata"] = {"private": "VALUE_CANARY"}
            return raw

        self.old._dp_get.side_effect = metadata
        with self.assertLogs("hermes.egress", level="WARNING") as captured:
            self.assertEqual(deploy_hermes.deploy(self.config, self.clients), "old-sandbox")
        self.assertIn('["metadata"]', "\n".join(captured.output))
        self.assertNotIn("VALUE_CANARY", "\n".join(captured.output) + self.output.getvalue())
        self.assertEqual(self.events, ["get:old-sandbox", "status:old-sandbox"])
        self.mocks["create_image"].assert_not_called()
        self.clients.group._dp_put.assert_not_called()
        self.old._dp_post.assert_called_once_with(
            "/test/old-sandbox/executeShellCommand", {"command": shlex.join([*common.CONTROL, "status", "--json"])},
        )
        self.old.begin_delete.assert_not_called()

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
            RuntimeError, "Partial \\+ Deny was rejected",
        ):
            deploy_hermes.deploy(config(image="", egress_mode="hardened-unverified"), self.clients)
        provision.assert_not_called()
        self.assertEqual(self.clients.method_calls, [])

    def test_production_cli_blocks_before_configuration_and_azure_clients(self):
        with patch("sys.argv", ["deploy_hermes.py"]), patch.object(
            common, "_read_env", return_value={"HERMES_EGRESS_MODE": "hardened-unverified"},
        ), patch.object(common.Config, "from_values") as read_configuration, patch.object(
            common.AzureClients, "create",
        ) as create_clients:
            with self.assertRaisesRegex(RuntimeError, "not deployable"):
                deploy_hermes.main()
        read_configuration.assert_not_called()
        create_clients.assert_not_called()


if __name__ == "__main__":
    unittest.main()
