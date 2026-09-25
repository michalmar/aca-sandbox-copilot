#!/usr/bin/env python3
"""Hermes-only configuration and pinned Azure Container Apps Sandbox helpers."""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import shlex
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import urlsplit

from azure.containerapps.sandbox import (
    SandboxClient,
    SandboxGroupClient,
    SandboxGroupManagementClient,
    endpoint_for_region,
)
from azure.core.exceptions import AzureError, HttpResponseError, ResourceNotFoundError
from azure.identity import AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient

ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env.hermes"
RUNTIME_PATH = "/mnt/data/hermes/runtime.json"
GOOGLE_CREDENTIAL_PATH = "/mnt/data/secrets/google/credentials.json"
ACCESS_KEY_PATH = "/dev/shm/hermes/access-key"
PYTHON = "/opt/hermes/.venv/bin/python"
CONTROL = [PYTHON, "/opt/hermes-sandbox/control.py"]
INGRESS_SCOPE = "https://auth.adcproxy.io/.default"
INGRESS_AUDIENCES = {"https://auth.adcproxy.io/", "9f34678b-7f96-4c6d-ac69-b06b1255b61e"}
LABELS = {"managed-by": "aca-sandbox-hermes"}
MIN_FREE_BYTES = 256 * 1024 * 1024
GOOGLE_HOSTS = ("oauth2.googleapis.com", "gmail.googleapis.com", "www.googleapis.com")
_NAME = re.compile(r"[a-z][a-z0-9-]{1,61}[a-z0-9]\Z")
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
_IMAGE = re.compile(r"[a-z0-9][a-z0-9./:_-]+@sha256:[a-f0-9]{64}\Z")
_PHONE = re.compile(r"\+[1-9][0-9]{6,14}\Z")
_EMAIL = re.compile(r"[^@\s\x00-\x1f]+@[^@\s\x00-\x1f]+\.[^@\s\x00-\x1f]+\Z")
_ENV_KEYS = {
    "HERMES_SUBSCRIPTION_ID", "HERMES_TENANT_ID", "HERMES_OWNER_OBJECT_ID",
    "HERMES_LOCATION", "HERMES_RESOURCE_GROUP", "HERMES_SANDBOX_GROUP",
    "HERMES_SANDBOX_NAME", "HERMES_DISK_NAME", "HERMES_VOLUME_NAME", "HERMES_IMAGE",
    "HERMES_FOUNDRY_ENDPOINT", "HERMES_FOUNDRY_DEPLOYMENT", "HERMES_FOUNDRY_API_MODE",
    "HERMES_FOUNDRY_CONTEXT_LENGTH", "HERMES_FOUNDRY_SCOPE", "HERMES_WHATSAPP_PHONE",
    "HERMES_GOOGLE_ENABLED", "HERMES_GOOGLE_EXPECTED_EMAIL", "HERMES_GOOGLE_CALENDAR_IDS",
    "HERMES_IDENTITY_HOST", "HERMES_WHATSAPP_HOSTS",
}


def _uuid(value: str, label: str) -> str:
    try:
        normalized = str(uuid.UUID(value))
    except (ValueError, AttributeError):
        raise ValueError(f"{label} must be a UUID.") from None
    if value != normalized:
        raise ValueError(f"{label} must be a canonical lowercase UUID.")
    return normalized


def exact_host(value: str) -> str:
    if (
        not _HOST.fullmatch(value)
        or value != value.lower()
        or ".." in value
        or any(not part or part.startswith("-") or part.endswith("-") for part in value.split("."))
    ):
        raise ValueError("An egress host must be an exact lowercase hostname, without a port or wildcard.")
    return value


def _object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} has missing or unrecognized fields.")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON contains duplicate fields.")
        result[key] = value
    return result


def parse_json(content: bytes) -> Any:
    if len(content) > 256 * 1024:
        raise ValueError("Configuration exceeds the 256 KiB limit.")
    try:
        return json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Configuration must be valid UTF-8 JSON.") from None


def validate_runtime(value: Any) -> dict[str, Any]:
    doc = _object(value, {"schema_version", "foundry", "owner", "google"}, "Runtime")
    if type(doc["schema_version"]) is not int or doc["schema_version"] != 1:
        raise ValueError("Only runtime schema_version 1 is supported.")
    foundry = _object(
        doc["foundry"], {"endpoint", "deployment", "api_mode", "context_length", "scope"}, "Foundry"
    )
    if not all(isinstance(foundry[key], str) for key in ("endpoint", "deployment", "api_mode", "scope")):
        raise ValueError("Foundry string fields have invalid types.")
    try:
        endpoint = urlsplit(foundry["endpoint"])
        valid_endpoint = (
            endpoint.scheme == "https"
            and endpoint.hostname is not None
            and endpoint.port in (None, 443)
            and not endpoint.username
            and not endpoint.password
            and not endpoint.query
            and not endpoint.fragment
            and not any(char.isspace() for char in foundry["endpoint"])
            and "\\" not in foundry["endpoint"]
        )
    except ValueError:
        valid_endpoint = False
    if not valid_endpoint:
        raise ValueError("Foundry endpoint must be a supplied HTTPS inference URL without credentials or query.")
    exact_host(endpoint.hostname)
    if not foundry["deployment"] or any(ord(char) < 32 for char in foundry["deployment"]):
        raise ValueError("An existing Foundry deployment is required.")
    if foundry["api_mode"] not in {"chat_completions", "codex_responses", "anthropic_messages"}:
        raise ValueError("Unsupported Foundry api_mode.")
    if type(foundry["context_length"]) is not int or foundry["context_length"] < 1:
        raise ValueError("Foundry context_length must be a verified positive integer.")
    if foundry["scope"] != "https://ai.azure.com/.default":
        raise ValueError("The managed profile requires the Foundry inference scope.")
    owner = _object(doc["owner"], {"tenant_id", "object_id", "whatsapp_phone"}, "Owner")
    _uuid(owner["tenant_id"], "Owner tenant_id")
    _uuid(owner["object_id"], "Owner object_id")
    if not isinstance(owner["whatsapp_phone"], str) or not _PHONE.fullmatch(owner["whatsapp_phone"]):
        raise ValueError("Owner whatsapp_phone must be an E.164 number.")
    google = _object(doc["google"], {"enabled", "expected_email", "calendar_ids"}, "Google")
    if type(google["enabled"]) is not bool or not isinstance(google["expected_email"], str):
        raise ValueError("Google enabled/expected_email types are invalid.")
    if (google["enabled"] or google["expected_email"]) and (
        not _EMAIL.fullmatch(google["expected_email"])
        or google["expected_email"] != google["expected_email"].casefold()
    ):
        raise ValueError("Google expected_email must be an exact lowercase email address.")
    calendars = google["calendar_ids"]
    if (
        not isinstance(calendars, list)
        or not 1 <= len(calendars) <= 20
        or not all(
            isinstance(item, str) and 1 <= len(item) <= 256
            and not any(ord(char) < 32 for char in item)
            for item in calendars
        )
        or len(set(calendars)) != len(calendars)
    ):
        raise ValueError("Google calendar_ids must be a bounded list of distinct exact identifiers.")
    return doc


def _read_env(path: Path) -> dict[str, str]:
    if path.name == ".env" or path.name == ".env.sample":
        raise ValueError("The Copilot environment file is never a Hermes configuration source.")
    if not path.is_file():
        raise ValueError("Missing Hermes configuration. Copy .env.hermes.sample to .env.hermes.")
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or key not in _ENV_KEYS or key in values:
            raise ValueError(f"Hermes configuration line {number} has an unknown or duplicate key.")
        if value[:1] in {"'", '"'}:
            if len(value) < 2 or value[-1] != value[0]:
                raise ValueError(f"Hermes configuration line {number} has an unmatched quote.")
            value = value[1:-1]
        if any(ord(char) < 32 for char in value):
            raise ValueError(f"Hermes configuration line {number} contains a control character.")
        values[key] = value
    overridden = sorted(key for key, value in values.items() if key in os.environ and os.environ[key] != value)
    if overridden:
        logging.getLogger("hermes.config").warning("Process environment overrides Hermes configuration keys: %s", ", ".join(overridden))
    return {key: os.environ.get(key, value) for key, value in values.items()} | {
        key: os.environ[key] for key in _ENV_KEYS - values.keys() if key in os.environ
    }


@dataclass(frozen=True)
class Config:
    subscription_id: str
    tenant_id: str
    owner_object_id: str
    location: str = "swedencentral"
    resource_group: str = "rg-hermes-sandbox"
    sandbox_group: str = "hermes-sandbox-group"
    sandbox_name: str = "hermes-personal"
    disk_name: str = "hermes-image"
    volume_name: str = "hermes-data"
    image: str = ""
    foundry_endpoint: str = ""
    foundry_deployment: str = ""
    foundry_api_mode: str = "chat_completions"
    foundry_context_length: int = 0
    foundry_scope: str = "https://ai.azure.com/.default"
    whatsapp_phone: str = ""
    google_enabled: bool = False
    google_expected_email: str = ""
    google_calendar_ids: tuple[str, ...] = ("primary",)
    identity_host: str = ""
    whatsapp_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _uuid(self.subscription_id, "HERMES_SUBSCRIPTION_ID")
        _uuid(self.tenant_id, "HERMES_TENANT_ID")
        _uuid(self.owner_object_id, "HERMES_OWNER_OBJECT_ID")
        if not re.fullmatch(r"[a-z][a-z0-9]{1,39}", self.location):
            raise ValueError("HERMES_LOCATION must be an explicit Azure region name.")
        for name in (self.resource_group, self.sandbox_group, self.sandbox_name, self.disk_name, self.volume_name):
            if not _NAME.fullmatch(name) or "hermes" not in name:
                raise ValueError("Resource names must be lowercase, Hermes-specific names.")
        if self.image and not _IMAGE.fullmatch(self.image):
            raise ValueError("HERMES_IMAGE must be a public container reference pinned with @sha256.")
        if self.identity_host:
            exact_host(self.identity_host)
        for host in self.whatsapp_hosts:
            exact_host(host)

    @classmethod
    def from_env(cls, env_path: Path | None = None) -> Config:
        values = _read_env(Path(env_path) if env_path is not None else ENV_PATH)
        fields = {
            "subscription_id": "SUBSCRIPTION_ID", "tenant_id": "TENANT_ID",
            "owner_object_id": "OWNER_OBJECT_ID", "location": "LOCATION",
            "resource_group": "RESOURCE_GROUP", "sandbox_group": "SANDBOX_GROUP",
            "sandbox_name": "SANDBOX_NAME", "disk_name": "DISK_NAME", "volume_name": "VOLUME_NAME",
            "image": "IMAGE", "foundry_endpoint": "FOUNDRY_ENDPOINT", "foundry_deployment": "FOUNDRY_DEPLOYMENT",
            "foundry_api_mode": "FOUNDRY_API_MODE", "foundry_scope": "FOUNDRY_SCOPE",
            "whatsapp_phone": "WHATSAPP_PHONE", "google_expected_email": "GOOGLE_EXPECTED_EMAIL",
            "identity_host": "IDENTITY_HOST",
        }
        kwargs: dict[str, Any] = {
            key: values[f"HERMES_{suffix}"]
            for key, suffix in fields.items() if f"HERMES_{suffix}" in values
        }
        for key in ("subscription_id", "tenant_id", "owner_object_id"):
            if not kwargs.get(key):
                raise ValueError(f"HERMES_{key.upper()} is required.")
        enabled = values.get("HERMES_GOOGLE_ENABLED", "false")
        if enabled not in {"true", "false"}:
            raise ValueError("HERMES_GOOGLE_ENABLED must be true or false.")
        kwargs["google_enabled"] = enabled == "true"
        try:
            kwargs["foundry_context_length"] = int(values.get("HERMES_FOUNDRY_CONTEXT_LENGTH", "") or "0")
        except ValueError:
            raise ValueError("HERMES_FOUNDRY_CONTEXT_LENGTH must be an integer.") from None
        kwargs["google_calendar_ids"] = tuple(
            item.strip() for item in values.get("HERMES_GOOGLE_CALENDAR_IDS", "primary").split(",") if item.strip()
        )
        kwargs["whatsapp_hosts"] = tuple(
            item.strip() for item in values.get("HERMES_WHATSAPP_HOSTS", "").split(",") if item.strip()
        )
        return cls(**kwargs)

    @property
    def labels(self) -> dict[str, str]:
        return {
            **LABELS, "hermes-deployment": self.sandbox_name,
            "hermes-owner-tenant-id": self.tenant_id, "hermes-owner-object-id": self.owner_object_id,
        }

    @property
    def group_scope(self) -> str:
        return (
            f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.App/sandboxGroups/{self.sandbox_group}"
        )


def runtime_document(config: Config) -> dict[str, Any]:
    return validate_runtime({
        "schema_version": 1,
        "foundry": {
            "endpoint": config.foundry_endpoint, "deployment": config.foundry_deployment,
            "api_mode": config.foundry_api_mode, "context_length": config.foundry_context_length,
            "scope": config.foundry_scope,
        },
        "owner": {
            "tenant_id": config.tenant_id, "object_id": config.owner_object_id,
            "whatsapp_phone": config.whatsapp_phone,
        },
        "google": {
            "enabled": config.google_enabled, "expected_email": config.google_expected_email,
            "calendar_ids": list(config.google_calendar_ids),
        },
    })


@dataclass
class AzureClients:
    credential: AzureCliCredential
    resources: ResourceManagementClient
    groups: SandboxGroupManagementClient
    group: SandboxGroupClient

    @classmethod
    def create(cls, config: Config) -> AzureClients:
        # az rejects --tenant and --subscription together on get-access-token.
        # The credential pins tenant; every ARM/SDK client pins subscription.
        credential = AzureCliCredential(tenant_id=config.tenant_id, process_timeout=30)
        return cls(
            credential=credential,
            resources=ResourceManagementClient(credential, config.subscription_id),
            groups=SandboxGroupManagementClient(
                credential, subscription_id=config.subscription_id, resource_group=config.resource_group,
            ),
            group=SandboxGroupClient(
                endpoint_for_region(config.location), credential,
                subscription_id=config.subscription_id, resource_group=config.resource_group,
                sandbox_group=config.sandbox_group,
            ),
        )

    def __enter__(self) -> AzureClients:
        return self

    def __exit__(self, *_: object) -> None:
        self.group.close()
        self.groups.close()
        self.resources.close()
        self.credential.close()


def assert_owner(credential: AzureCliCredential, config: Config) -> None:
    token = credential.get_token(INGRESS_SCOPE).token
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        valid = (
            claims.get("tid") == config.tenant_id and claims.get("oid") == config.owner_object_id
            and claims.get("idtyp") == "user" and claims.get("aud") in INGRESS_AUDIENCES
        )
    except (ValueError, IndexError, UnicodeDecodeError):
        valid = False
    if not valid:
        raise RuntimeError("Azure CLI must be signed in as the configured owner in the configured tenant.")


def assert_labels(labels: Any, config: Config, kind: str) -> None:
    if not isinstance(labels, dict) or any(labels.get(key) != value for key, value in config.labels.items()):
        raise RuntimeError(f"Refusing to adopt or change an unowned {kind}.")


def assert_group_owned(config: Config, clients: AzureClients) -> None:
    rg = clients.resources.resource_groups.get(config.resource_group)
    assert_labels(rg.tags, config, "resource group")
    if rg.location.replace(" ", "").lower() != config.location:
        raise RuntimeError("Resource group region differs from the configured region.")
    group = clients.groups.get_group(config.sandbox_group)
    assert_labels(group.tags, config, "Sandbox Group")
    if group.location.replace(" ", "").lower() != config.location:
        raise RuntimeError("Sandbox Group region differs from the configured region.")
    for resource in clients.resources.resources.list_by_resource_group(config.resource_group):
        if resource.id.lower() != config.group_scope.lower():
            raise RuntimeError("Resource group contains foreign resources; it is not a dedicated Hermes group.")


def owned_sandboxes(config: Config, clients: AzureClients) -> list[Any]:
    sandboxes = list(clients.group.list_sandboxes())
    for sandbox in sandboxes:
        assert_labels(sandbox.labels, config, "sandbox")
    return sandboxes


def get_sandbox(config: Config, clients: AzureClients) -> SandboxClient:
    assert_group_owned(config, clients)
    sandboxes = owned_sandboxes(config, clients)
    if len(sandboxes) != 1 or sandboxes[0].labels.get("name") != config.sandbox_name:
        raise RuntimeError("Expected exactly one owned Hermes sandbox. Run deploy_hermes.py explicitly.")
    return clients.group.get_sandbox_client(sandboxes[0].id)


def raw_sandbox(sandbox: SandboxClient) -> dict[str, Any]:
    raw = sandbox._dp_get(sandbox._sbx_path)
    if not isinstance(raw, dict) or raw.get("id") != sandbox.sandbox_id:
        raise RuntimeError("Sandbox API returned inconsistent metadata.")
    return raw


def compute_state(sandbox: SandboxClient) -> str:
    value = raw_sandbox(sandbox).get("state")
    known = {"running", "stopped", "failed", "creating", "starting", "stopping", "deleting", "suspended"}
    return value.lower() if isinstance(value, str) and value.lower() in known else "unknown"


def assert_no_suspend(raw: dict[str, Any]) -> None:
    if raw.get("lifecycle", {}).get("autoSuspendPolicy", {}).get("enabled") is not False:
        raise RuntimeError("BLOCKED: raw lifecycle readback did not disable automatic suspension.")


def ingress_url(sandbox_id: str, location: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,127}", sandbox_id) or not re.fullmatch(r"[a-z0-9]+", location):
        raise ValueError("Invalid sandbox endpoint identifiers.")
    return f"https://{sandbox_id}--8080.{location}.adcproxy.io"


def validate_ingress_url(value: str, *, sandbox_id: str, location: str) -> str:
    expected = ingress_url(sandbox_id, location)
    if value != expected:
        raise RuntimeError("Sandbox ingress metadata does not match the fixed HTTPS 8080 endpoint.")
    return expected


def port_document(config: Config, sandbox_id: str, *, object_ids: tuple[str, ...] | None = None) -> dict[str, Any]:
    owners = object_ids if object_ids is not None else (config.owner_object_id,)
    if not owners or len(set(owners)) != len(owners):
        raise ValueError("Port ACL must contain distinct explicit object IDs.")
    for owner in owners:
        _uuid(owner, "Port object ID")
    return {
        "port": 8080, "url": ingress_url(sandbox_id, config.location),
        "auth": {"anonymous": False, "entraId": {"enabled": True, "objectIds": list(owners)}},
        "activationMode": "OnDemand", "protocol": "Http",
    }


def validate_ports(raw: dict[str, Any], config: Config, sandbox_id: str, *, object_ids: tuple[str, ...] | None = None) -> str:
    ports = raw.get("ports")
    if not isinstance(ports, list) or len(ports) != 1 or not isinstance(ports[0], dict):
        raise RuntimeError("Expected exactly one Entra-only port.")
    port = ports[0]
    expected = port_document(config, sandbox_id, object_ids=object_ids)
    if any(port.get(key) != expected[key] for key in ("port", "activationMode", "protocol")):
        raise RuntimeError("Unexpected port, protocol or activation mode.")
    auth = port.get("auth", {})
    entra = auth.get("entraId", {})
    if (
        auth.get("anonymous") is not False or entra.get("enabled") is not True
        or sorted(entra.get("objectIds") or []) != sorted(expected["auth"]["entraId"]["objectIds"])
        or any(value for key, value in entra.items() if key not in {"enabled", "objectIds"})
        or any(value for key, value in auth.items() if key not in {"anonymous", "entraId"})
    ):
        raise RuntimeError("BLOCKED: raw ingress ACL is not the exact object-ID-only policy.")
    return validate_ingress_url(port.get("url", ""), sandbox_id=sandbox_id, location=config.location)


def configure_port(sandbox: SandboxClient, config: Config, *, object_ids: tuple[str, ...] | None = None) -> str:
    ports = raw_sandbox(sandbox).get("ports")
    if not isinstance(ports, list) or any(not isinstance(port, dict) or port.get("port") != 8080 for port in ports):
        raise RuntimeError("Refusing to replace unknown or foreign ports.")
    if len(ports) > 1:
        raise RuntimeError("Refusing ambiguous duplicate port mappings.")
    sandbox._dp_put(
        f"{sandbox._sbx_path}/ports", {"ports": [port_document(config, sandbox.sandbox_id, object_ids=object_ids)]}
    )
    return validate_ports(raw_sandbox(sandbox), config, sandbox.sandbox_id, object_ids=object_ids)


def egress_document(hosts: tuple[str, ...] | list[str]) -> dict[str, Any]:
    normalized = sorted({exact_host(host) for host in hosts})
    return {
        "defaultAction": "Deny", "trafficInspection": "Partial",
        "hostRules": [{"pattern": host, "action": "Allow"} for host in normalized],
    }


def deployment_egress(config: Config) -> dict[str, Any]:
    runtime_document(config)
    if not config.identity_host or not config.whatsapp_hosts:
        raise ValueError("Deployment is blocked until the MI path and minimal WhatsApp hosts are verified.")
    return egress_document([
        urlsplit(config.foundry_endpoint).hostname, config.identity_host,
        *GOOGLE_HOSTS, *config.whatsapp_hosts,
    ])


def validate_egress(raw: dict[str, Any], expected: dict[str, Any]) -> None:
    policy = raw.get("egressPolicy")
    if (
        not isinstance(policy, dict)
        or policy.get("defaultAction") != "Deny"
        or policy.get("trafficInspection") != "Partial"
        or policy.get("rules")
        or sorted(policy.get("hostRules") or [], key=lambda row: str(row)) !=
        sorted(expected["hostRules"], key=lambda row: str(row))
        or any(value for key, value in policy.items() if key not in {"defaultAction", "trafficInspection", "hostRules", "rules"})
    ):
        raise RuntimeError("BLOCKED: raw egress policy differs from the exact deny-default Partial policy.")


def configure_egress(sandbox: SandboxClient, policy: dict[str, Any]) -> None:
    validate_egress({"egressPolicy": policy}, policy)
    sandbox._dp_post(f"{sandbox._sbx_path}/egresspolicy", policy)
    validate_egress(raw_sandbox(sandbox), policy)


def sandbox_document(config: Config, *, disk_id: str, egress: dict[str, Any]) -> dict[str, Any]:
    validate_egress({"egressPolicy": egress}, egress)
    return {
        "sourcesRef": {"diskImage": {"id": disk_id}},
        "resources": {"cpu": "2000m", "memory": "4096Mi", "disk": "20Gi"},
        "lifecycle": {"autoSuspendPolicy": {"enabled": False}},
        "labels": {**config.labels, "name": config.sandbox_name},
        "environment": {"AZURE_TOKEN_CREDENTIALS": "ManagedIdentityCredential"},
        "egressPolicy": egress,
        "volumes": [{"volumeName": config.volume_name, "mountpoint": "/mnt/data", "readOnly": False}],
        "entrypoint": ["/usr/bin/tini", "-s", "--", "/usr/local/bin/hermes-entrypoint"],
    }


def wait_running(sandbox: SandboxClient, timeout: float = 300) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw = raw_sandbox(sandbox)
        state = str(raw.get("state", "")).lower()
        if state == "running":
            assert_no_suspend(raw)
            return raw
        if state in {"failed", "deleting"}:
            raise RuntimeError(f"Hermes sandbox entered state {state}.")
        time.sleep(3)
    raise TimeoutError("Hermes sandbox did not become running before the deadline.")


def exec_checked(sandbox: SandboxClient, command: list[str]) -> str:
    result = sandbox._dp_post(f"{sandbox._sbx_path}/executeShellCommand", {"command": shlex.join(command)})
    if not isinstance(result, dict) or type(result.get("exitCode")) is not int:
        raise RuntimeError("Sandbox command response lacks an explicit integer exitCode; success cannot be inferred.")
    if result["exitCode"] != 0:
        raise RuntimeError(f"Sandbox operation failed with exit code {result['exitCode']}; output suppressed for privacy.")
    output = result.get("stdout")
    if output is not None and not isinstance(output, str):
        raise RuntimeError("Sandbox command response has an invalid stdout field.")
    return output or ""


_PRIVATE_DIRECTORY_CODE = """
import os, stat, sys
from pathlib import PurePosixPath
destination, temporary, action = sys.argv[1:]
if os.geteuid() != 0:
    raise RuntimeError('Private uploads require the root sandbox runtime')
if not os.path.ismount('/mnt/data'):
    raise RuntimeError('DataDisk is not mounted')
parts = PurePosixPath(destination).parts
fd = os.open('/mnt/data', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    for part in parts[3:-1]:
        try:
            os.mkdir(part, 0o700, dir_fd=fd)
        except FileExistsError:
            pass
        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        os.close(fd)
        fd = child
        if os.fstat(fd).st_uid != os.geteuid():
            raise RuntimeError('Unsafe private directory owner')
        os.fchmod(fd, 0o700)
    target = parts[-1]
    try:
        info = os.stat(target, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        info = None
    if info is not None and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()):
        raise RuntimeError('Unsafe private destination')
    if action == 'prepare':
        staged = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        os.close(staged)
    elif action == 'commit':
        staged = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            info = os.fstat(staged)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1 or info.st_uid != os.geteuid()):
                raise RuntimeError('Unsafe staged private file')
            os.fsync(staged)
        finally:
            os.close(staged)
        os.replace(temporary, target, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    else:
        raise RuntimeError('Unknown private upload operation')
finally:
    os.close(fd)
"""


def upload_private_file(sandbox: SandboxClient, *, destination: str, content: bytes) -> None:
    if destination not in {RUNTIME_PATH, GOOGLE_CREDENTIAL_PATH}:
        raise ValueError("Private upload destination is not permitted.")
    if not isinstance(content, bytes) or not content or len(content) > 256 * 1024:
        raise ValueError("Private upload requires nonempty bytes, at most 256 KiB.")
    if destination == RUNTIME_PATH:
        validate_runtime(parse_json(content))
    path = PurePosixPath(destination)
    temporary = f".{path.name}.{uuid.uuid4().hex}.tmp"
    temporary_path = str(path.parent / temporary)
    prepared = False
    try:
        exec_checked(sandbox, [PYTHON, "-c", _PRIVATE_DIRECTORY_CODE, destination, temporary, "prepare"])
        prepared = True
        sandbox.write_file(temporary_path, content, create_dirs=False, mode="0600")
        if sandbox.read_file(temporary_path) != content:
            raise RuntimeError("Private SDK upload readback differs; the previous private file was preserved.")
        exec_checked(sandbox, [PYTHON, "-c", _PRIVATE_DIRECTORY_CODE, destination, temporary, "commit"])
        prepared = False
    except AzureError:
        raise RuntimeError("Private SDK upload failed; credential response suppressed.") from None
    finally:
        if prepared:
            try:
                sandbox.delete_file(temporary_path)
            except ResourceNotFoundError:
                pass
            except AzureError:
                raise RuntimeError("Private upload failed and its private staging file could not be removed.") from None


def read_runtime(sandbox: SandboxClient) -> dict[str, Any]:
    return validate_runtime(parse_json(sandbox.read_file(RUNTIME_PATH)))


def read_access_key(sandbox: SandboxClient) -> str:
    content = sandbox.read_file(ACCESS_KEY_PATH)
    try:
        key = content.decode("ascii")
    except UnicodeDecodeError:
        raise RuntimeError("Invalid in-memory transport key file.") from None
    if not re.fullmatch(r"[0-9a-f]{64}", key):
        raise RuntimeError("Invalid in-memory transport key file.")
    return key


def read_control_status(sandbox: SandboxClient) -> dict[str, Any]:
    value = parse_json(exec_checked(sandbox, [*CONTROL, "status", "--json"]).encode())
    status = _object(
        value, {"schema_version", "dashboard", "gateway", "whatsapp", "google", "disk_free_bytes"}, "Status"
    )
    if (
        type(status["schema_version"]) is not int or status["schema_version"] != 1
        or type(status["disk_free_bytes"]) is not int or status["disk_free_bytes"] < -1
    ):
        raise RuntimeError("Unexpected Hermes control status schema.")
    states = {
        "dashboard": {"awaiting-runtime", "running", "stopped", "failed"},
        "gateway": {"running", "stopped", "failed", "maintenance", "not-paired", "re-pair-required", "unknown"},
        "whatsapp": {"paired", "not-paired", "re-pair-required", "unknown"},
        "google": {"unknown", "disabled", "not-connected", "configured", "reconnect-required", "failed"},
    }
    if any(not isinstance(status[key], str) or status[key] not in allowed for key, allowed in states.items()):
        raise RuntimeError("Unexpected Hermes control component state.")
    return status


def control_status(sandbox: SandboxClient) -> dict[str, Any]:
    status = read_control_status(sandbox)
    if status["disk_free_bytes"] == -1:
        raise RuntimeError("Hermes disk free space is unavailable; readiness cannot be established.")
    if status["disk_free_bytes"] < MIN_FREE_BYTES:
        raise RuntimeError("Hermes DataDisk has less than 256 MiB headroom; no data was removed.")
    return status


@dataclass
class GatewayHandoff:
    target: str
    stage: Literal["inspecting", "stop-issued", "deleted"] = "inspecting"
    prior_gateway: str = "unknown"

    def warn_incomplete(self, logger: logging.Logger, operation: str) -> None:
        if self.stage == "deleted":
            logger.warning(
                "%s; prior gateway=%s. Previous writer deletion was confirmed, after confirming gateway maintenance. "
                "Inspect any rollback warnings; after a successful retry, resume explicitly: %s. "
                "A retry does not restore the prior running intent.",
                operation, self.prior_gateway, " ".join([*CONTROL, "start-gateway"]),
            )
        elif self.stage == "stop-issued":
            logger.warning(
                "%s; prior gateway=%s. The writer may still exist with its gateway stopped or in maintenance. "
                "Inspect compute first; if keeping it, resume explicitly: %s. Disk-preserving recovery requires "
                "--confirm-unquiesced-writer %s and the usual --confirm-target.",
                operation, self.prior_gateway, " ".join([*CONTROL, "start-gateway"]), self.target,
            )
        else:
            logger.warning(
                "%s; prior gateway=%s. Gateway stop was not issued. Inspect the current writer before retrying; "
                "disk-preserving recovery requires --confirm-unquiesced-writer %s and the usual --confirm-target.",
                operation, self.prior_gateway, self.target,
            )


def quiesce_gateway(sandbox: SandboxClient, config: Config, handoff: GatewayHandoff) -> None:
    """Confirm the preserved disk cannot restart its gateway during handoff."""
    state = compute_state(sandbox)
    recovery = (
        "Disk-preserving recovery requires explicit cleanup confirmation: "
        f"--confirm-unquiesced-writer {config.group_scope}/sandboxes/{sandbox.sandbox_id} "
        f"with --confirm-target {config.group_scope}. The next boot may use unconfirmed saved gateway intent."
    )
    if state != "running":
        raise RuntimeError(
            "A disk-preserving handoff requires a running sandbox with readable control state. "
            f"Observed compute={state}, gateway=unknown; nothing was started or deleted. {recovery}"
        )
    handoff.prior_gateway = read_control_status(sandbox)["gateway"]
    handoff.stage = "stop-issued"
    exec_checked(sandbox, [*CONTROL, "stop-gateway"])
    gateway = read_control_status(sandbox)["gateway"]
    if gateway != "maintenance":
        raise RuntimeError(
            "Gateway persistent maintenance could not be confirmed; the old writer was not deleted. "
            f"Observed compute={state}, gateway={gateway}. {recovery}"
        )


def delete_sandbox_confirmed(sandbox: SandboxClient) -> None:
    deletion = sandbox.begin_delete()
    deletion.result(timeout=300)
    if deletion.done() is not True:
        raise TimeoutError("Sandbox deletion has not completed; another writer must not be created.")
    try:
        raw_sandbox(sandbox)
    except ResourceNotFoundError:
        return
    raise RuntimeError("Sandbox deletion is incomplete; the writer may still exist.")


_NETWORK_PROBE = """
import json, ssl, sys, urllib.error, urllib.request
import certifi
hosts = json.loads(sys.argv[1])
context = ssl.create_default_context(cafile=certifi.where())
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())
results = {}
for host in hosts:
    try:
        with opener.open('https://' + host + '/.well-known/hermes-network-probe', timeout=15) as response:
            results[host] = {'public_ca_tls': True, 'http_status': response.status}
    except urllib.error.HTTPError as error:
        results[host] = {'public_ca_tls': True, 'http_status': error.code}
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        results[host] = {'network_error': type(error).__name__}
print(json.dumps(results))
"""


def verify_partial_network(sandbox: SandboxClient, config: Config) -> dict[str, Any]:
    policy = deployment_egress(config)
    validate_egress(raw_sandbox(sandbox), policy)
    allowed = sorted({urlsplit(config.foundry_endpoint).hostname, *GOOGLE_HOSTS, *config.whatsapp_hosts})
    denied_host = "example.com"
    if denied_host in {row["pattern"] for row in policy["hostRules"]}:
        raise RuntimeError("The negative network-probe host must not be allowed.")
    result = parse_json(exec_checked(
        sandbox, [PYTHON, "-c", _NETWORK_PROBE, json.dumps([*allowed, denied_host])]
    ).encode())
    if not isinstance(result, dict) or any(
        not isinstance(result.get(host), dict) or result[host].get("public_ca_tls") is not True for host in allowed
    ):
        raise RuntimeError("BLOCKED: at least one explicit host failed public-CA-only TLS in Partial mode.")
    if not isinstance(result.get(denied_host), dict) or "http_status" in result[denied_host]:
        raise RuntimeError("BLOCKED: a disallowed hostname reached an HTTP origin.")
    deadline = time.monotonic() + 30
    while True:
        audit = sandbox._dp_get(f"{sandbox._sbx_path}/egress-decisions")
        entries = audit.get("networkEgress", {}).get("denied", []) if isinstance(audit, dict) else []
        if any(isinstance(row, dict) and row.get("host") == denied_host for row in entries):
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("BLOCKED: no platform deny decision proves the negative hostname test.")
        time.sleep(2)
    return {"traffic_inspection": "Partial", "public_ca_tls_hosts": allowed, "denied_host": denied_host,
            "platform_deny_observed": True}


def confirm_target(config: Config, value: str | None) -> None:
    if value != config.group_scope:
        raise ValueError(f"Pass --confirm-target with the exact intended Sandbox Group resource ID: {config.group_scope}")


def owned_inventory(config: Config, clients: AzureClients) -> tuple[list[Any], list[Any], list[Any]]:
    assert_group_owned(config, clients)
    sandboxes = owned_sandboxes(config, clients)
    images = list(clients.group.list_disk_images())
    volumes = list(clients.group.list_volumes())
    if len(sandboxes) > 1:
        raise RuntimeError("More than one sandbox exists; refusing to risk multiple DataDisk writers.")
    for image in images:
        assert_labels(image.labels, config, "disk image")
        if image.labels.get("name") != config.disk_name:
            raise RuntimeError("Unrecognized Hermes disk image name.")
    for volume in volumes:
        assert_labels(volume.labels, config, "DataDisk")
        if volume.name != config.volume_name or volume.type != "DataDisk" or volume.size != "1Gi":
            raise RuntimeError("The managed pilot requires exactly its own 1 GiB DataDisk.")
    if len(volumes) > 1:
        raise RuntimeError("Unexpected additional volumes; no resource will be removed.")
    return sandboxes, images, volumes
