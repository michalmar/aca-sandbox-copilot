#!/usr/bin/env python3
"""Explicitly deploy or replace a separate, persistent personal Hermes Sandbox."""

from __future__ import annotations

import argparse
import json
import logging
import math
import time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from azure.core.exceptions import AzureError, ClientAuthenticationError, HttpResponseError, ResourceNotFoundError

from hermes_common import (
    AzureClients, Config, CONTROL, GatewayHandoff, RUNTIME_PATH, ReadinessTimeoutError, StatusRecorder, StatusSink,
    _egress_value_type, _status_error_category, _status_list, assert_group_owned, assert_labels,
    assert_no_suspend, assert_owner, configure_port, confirm_target, control_status,
    delete_sandbox_confirmed, deployment_egress, endpoint_for_region, exec_checked, load_egress_config, owned_inventory,
    quiesce_gateway, raw_sandbox, read_control_status, read_runtime,
    runtime_document, sandbox_document, upload_private_file, validate_egress,
    validate_ports, verify_mvp_network, wait_running, warn_unrestricted_egress,
)

LOG = logging.getLogger("hermes.deploy")
_READINESS_SECONDS = 900
_READINESS_SPACING = 10
_READINESS_READ_SECONDS = 10
_READINESS_ROUNDS = 3
_READINESS_READS = (
    ("volumes", "list_volumes", "/volumes", "value"),
    ("sandboxes", "list_sandboxes", "/sandboxes", "value"),
    ("images", "list_disk_images", "/diskimages", "value"),
    ("secrets", "list_secrets", "/secrets", "secrets"),
)


def _readiness_remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ReadinessTimeoutError()
    return remaining


@contextmanager
def _readiness_transport(config: Config, clients: AzureClients, suffix: str, items_key: str, deadline: float, step):
    group = clients.group
    expected_path = (
        f"/subscriptions/{config.subscription_id}/resourceGroups/{config.resource_group}"
        f"/sandboxGroups/{config.sandbox_group}{suffix}"
    )
    expected_endpoint = urlsplit(endpoint_for_region(config.location))
    if (
        group._credential is not clients.credential
        or group.subscription_id != config.subscription_id
        or group.resource_group != config.resource_group
        or group.sandbox_group != config.sandbox_group
    ):
        step.error_category = "resource_mismatch"
        raise RuntimeError("Fresh readiness requires the configured group's existing owner client.")
    transport = group._pipeline._transport
    original = transport.send
    had_override = "send" in vars(transport)
    previous = vars(transport).get("send")
    seen = set()

    def matches_read_url(value):
        try:
            target = urlsplit(value)
            return (
                target.scheme == expected_endpoint.scheme and target.netloc == expected_endpoint.netloc
                and target.path == expected_path
                and parse_qs(target.query).get("api-version") == ["2026-02-01-preview"]
                and not target.fragment
            )
        except (TypeError, ValueError):
            return False

    def send(request, **options):
        _readiness_remaining(deadline)
        for field in ("http_status", "response_type", "items_key_present", "items_type"):
            step.details.pop(field, None)
        step.details["request_matches"] = request.method == "GET" and matches_read_url(request.url)
        if not step.details["request_matches"]:
            step.error_category = "resource_mismatch"
            raise RuntimeError("Fresh readiness attempted a request outside its exact read boundary.")
        if request.url in seen:
            step.error_category = "malformed_type"
            raise RuntimeError("Fresh readiness returned cyclic pagination.")
        seen.add(request.url)
        started = time.monotonic()
        budget = min(_READINESS_READ_SECONDS, _readiness_remaining(deadline))
        limit = budget / 2
        connection = getattr(transport, "connection_config", None)
        for key, attribute in (("connection_timeout", "timeout"), ("read_timeout", "read_timeout")):
            configured = options.get(key, getattr(connection, attribute, _READINESS_READ_SECONDS))
            if type(configured) not in (int, float) or not math.isfinite(configured) or configured <= 0:
                step.error_category = "malformed_type"
                raise RuntimeError("Fresh readiness requires finite positive transport timeouts.")
            options[key] = min(configured, limit)
        try:
            response = original(request, **options)
        except (AzureError, OSError, ValueError, TypeError) as error:
            step.error_category = _status_error_category(error, "transport")
            raise RuntimeError("Fresh readiness transport failed; details suppressed.") from None
        _readiness_remaining(deadline)
        if time.monotonic() - started >= budget:
            raise ReadinessTimeoutError()
        code = response.status_code
        if type(code) is not int or not 100 <= code <= 599:
            step.error_category = "malformed_type"
            raise RuntimeError("Fresh readiness returned an invalid HTTP status.")
        step.details["http_status"] = code
        if code in (401, 403):
            # Surface denial before the SDK's existing retry/auth policies can hide it.
            denied = ClientAuthenticationError("Fresh readiness was denied.")
            denied.status_code = code
            raise denied
        if code != 200:
            step.error_category = "notfound" if code == 404 else "service_error"
            raise RuntimeError("Fresh readiness did not return HTTP 200.")
        try:
            raw = response.json()
        except (AzureError, ValueError, TypeError):
            step.error_category = "parser"
            raise RuntimeError("Fresh readiness returned invalid JSON; details suppressed.") from None
        present = isinstance(raw, dict) and items_key in raw
        step.details.update({
            "response_type": _egress_value_type(raw), "items_key_present": present,
            "items_type": _egress_value_type(raw[items_key]) if present else "absent",
        })
        if isinstance(raw, dict) and isinstance(raw.get(items_key), list):
            values = raw[items_key]
            if raw.get("nextLink") is not None and not isinstance(raw["nextLink"], str):
                step.error_category = "malformed_type"
                raise RuntimeError("Fresh readiness returned malformed pagination.")
            if raw.get("nextLink") and not matches_read_url(raw["nextLink"]):
                step.error_category = "resource_mismatch"
                raise RuntimeError("Fresh readiness pagination leaves its exact read boundary.")
            if raw.get("nextLink") in seen:
                step.error_category = "malformed_type"
                raise RuntimeError("Fresh readiness returned cyclic pagination.")
        elif items_key == "value" and isinstance(raw, list):
            values = raw
        else:
            step.error_category = "malformed_type"
            raise RuntimeError("Fresh readiness returned a malformed list envelope.")
        step.details["count"] += len(values)
        if values:
            step.error_category = "inventory_count"
            raise RuntimeError("Fresh deployment requires an empty owned group; existing data was not changed.")
        step.details["pages_completed"] += 1
        return response

    # SDK 0.1.0b4 list methods discard timeout kwargs. Scope the existing transport,
    # not a replacement client/session or changed SDK retry configuration.
    transport.send = send
    try:
        yield
    finally:
        if had_override:
            transport.send = previous
        else:
            del transport.send


def _readiness_list(
    config: Config, clients: AzureClients, trace: StatusRecorder, deadline: float,
    kind: str, method: str, suffix: str, items_key: str, round_index: int, *, operation: str | None = None,
) -> None:
    deadline = min(deadline, time.monotonic() + _READINESS_READ_SECONDS)
    with trace.step(operation or f"readiness.{kind}.list", details={
        "round_index": round_index, "count": 0, "pages_completed": 0, "complete": False,
    }) as step:
        _readiness_remaining(deadline)
        with _readiness_transport(config, clients, suffix, items_key, deadline, step):
            source = getattr(clients.group, method)()
            if source is None or isinstance(source, (str, bytes, dict)):
                step.error_category = "malformed_type"
                raise RuntimeError("Fresh readiness did not return an SDK list iterator.")
            for _ in source:
                step.error_category = "inventory_count"
                raise RuntimeError("Fresh readiness returned a nonempty SDK inventory.")
        _readiness_remaining(deadline)
        if not step.details["pages_completed"]:
            step.error_category = "malformed_type"
            raise RuntimeError("Fresh readiness completed without an observed SDK response.")
        step.details["complete"] = True


def _wait_fresh_group_ready(config: Config, clients: AzureClients, trace: StatusRecorder) -> float:
    started = time.monotonic()
    deadline = started + _READINESS_SECONDS
    consecutive = 0
    last_finished = None
    with trace.step("readiness.wait", details={
        "consecutive_rounds": 0, "elapsed_ms": 0, "authorization_guaranteed": False,
    }) as waiting:
        while consecutive < _READINESS_ROUNDS:
            if last_finished is not None:
                with trace.step("readiness.spacing", details={"spacing_met": False}) as spacing:
                    delay = max(0, last_finished + _READINESS_SPACING - time.monotonic())
                    if delay >= _readiness_remaining(deadline):
                        raise ReadinessTimeoutError()
                    if delay:
                        time.sleep(delay)
                    _readiness_remaining(deadline)
                    spacing.details["spacing_met"] = time.monotonic() - last_finished >= _READINESS_SPACING
                    if not spacing.details["spacing_met"]:
                        raise RuntimeError("Fresh readiness spacing was interrupted.")
            _readiness_remaining(deadline)
            round_index = consecutive + 1
            try:
                with trace.step("readiness.round", details={
                    "round_index": round_index, "reads_completed": 0, "complete": False,
                }) as round_step:
                    for kind, method, suffix, items_key in _READINESS_READS:
                        _readiness_list(config, clients, trace, deadline, kind, method, suffix, items_key, round_index)
                        round_step.details["reads_completed"] += 1
                    _readiness_remaining(deadline)
                    round_step.details["complete"] = True
            except HttpResponseError as error:
                if error.status_code not in (401, 403):
                    raise
                with trace.step("readiness.reset", details={
                    "round_index": round_index, "http_status": error.status_code,
                    "consecutive_rounds": 0, "authorization_guaranteed": False,
                }):
                    consecutive = 0
            else:
                consecutive += 1
            last_finished = time.monotonic()
            waiting.details.update({
                "consecutive_rounds": consecutive, "elapsed_ms": int((last_finished - started) * 1000),
            })
        _readiness_remaining(deadline)
    return deadline


def provision_group(
    config: Config, clients: AzureClients, *, fresh: bool = False, status_capture: StatusSink = None,
) -> None:
    trace = StatusRecorder.coerce(status_capture)
    if clients.resources.resource_groups.check_existence(config.resource_group):
        rg = clients.resources.resource_groups.get(config.resource_group)
        assert_labels(rg.tags, config, "resource group")
        if rg.location.replace(" ", "").lower() != config.location:
            raise RuntimeError("Refusing a resource group in a different region.")
        for resource in clients.resources.resources.list_by_resource_group(config.resource_group):
            if resource.id.lower() != config.group_scope.lower():
                raise RuntimeError("The resource group contains foreign resources.")
    else:
        clients.resources.resource_groups.create_or_update(
            config.resource_group,
            {"location": config.location, "tags": {**config.labels, "SecurityControl": "ignore"}},
        )
    try:
        group = clients.groups.get_group(config.sandbox_group)
    except ResourceNotFoundError:
        group = clients.groups.begin_create_group(
            config.sandbox_group, config.location, identity={"type": "SystemAssigned"}, tags=config.labels,
        ).result(timeout=300)
    assert_labels(group.tags, config, "Sandbox Group")
    identity = group.identity
    if not isinstance(identity, dict) or identity.get("type") != "SystemAssigned" or not identity.get("principalId"):
        raise RuntimeError("Hermes requires the new Sandbox Group's system-assigned managed identity.")
    assert_group_owned(config, clients)
    deadline = _wait_fresh_group_ready(config, clients, trace) if fresh else None
    try:
        if deadline is not None:
            _readiness_list(
                config, clients, trace, deadline, *_READINESS_READS[0], _READINESS_ROUNDS,
                operation="provision.volumes.list",
            )
        else:
            _status_list(trace, "provision.volumes.list", clients.group.list_volumes)
    except HttpResponseError as error:
        if error.status_code == 403:
            raise RuntimeError(
                "Sandbox data-plane access is blocked. Separately authorize Container Apps SandboxGroup Data Owner "
                "on the new group, then retry; a newly assigned role may need several minutes to propagate. "
                "No roles or Foundry resources were changed."
            ) from None
        raise


def create_image(config: Config, clients: AzureClients) -> str:
    created = clients.group._dp_put(f"{clients.group._group_path}/diskimages", {
        "image": {"base": config.image, "entrypoint": ["/usr/bin/tini", "-s", "--", "/usr/local/bin/hermes-entrypoint"]},
        "labels": {**config.labels, "name": config.disk_name},
    })
    identifier = created.get("id") if isinstance(created, dict) else None
    if not isinstance(identifier, str) or not identifier:
        raise RuntimeError("Disk image creation returned no valid identifier; inspect the configured group for an incomplete import.")
    return identifier


def wait_image(config: Config, clients: AzureClients, identifier: str) -> None:
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        image = clients.group.get_disk_image(identifier)
        assert_labels(image.labels, config, "disk image")
        if not image.image or image.image.base != config.image:
            raise RuntimeError("Disk image source digest differs from the requested public image.")
        state = image.status.state.lower() if image.status else ""
        if state == "ready":
            return
        if state in {"failed", "deleting"}:
            raise RuntimeError("Public immutable Hermes image import failed.")
        time.sleep(5)
    raise TimeoutError("Hermes disk image import did not finish within ten minutes.")


def rollback_new_sandbox(config: Config, clients: AzureClients, image_id: str, sandbox) -> bool:
    if sandbox is None:
        matches = []
        for entry in clients.group.list_sandboxes():
            candidate = clients.group.get_sandbox_client(entry.id)
            try:
                raw = raw_sandbox(candidate)
            except ResourceNotFoundError:
                continue
            labels = raw.get("labels") or {}
            source_id = raw.get("sourcesRef", {}).get("diskImage", {}).get("id")
            if (
                labels.get("name") == config.sandbox_name and source_id == image_id
                and all(labels.get(key) == value for key, value in config.labels.items())
            ):
                matches.append(candidate)
        if len(matches) > 1:
            raise RuntimeError("Ambiguous new sandbox ownership; refusing rollback deletion.")
        if not matches:
            return False
        sandbox = matches[0]
    try:
        raw = raw_sandbox(sandbox)
    except ResourceNotFoundError:
        return True
    assert_labels(raw.get("labels"), config, "new sandbox rollback")
    if (
        raw.get("labels", {}).get("name") != config.sandbox_name
        or raw.get("sourcesRef", {}).get("diskImage", {}).get("id") != image_id
    ):
        raise RuntimeError("New sandbox ownership changed; refusing rollback deletion.")
    delete_sandbox_confirmed(sandbox)
    return True


def delete_unreferenced_image(config: Config, clients: AzureClients, identifier: str, expected_base: str) -> None:
    try:
        image = clients.group.get_disk_image(identifier)
    except ResourceNotFoundError:
        return
    assert_labels(image.labels, config, "disk image cleanup")
    if (
        image.id != identifier or image.labels.get("name") != config.disk_name
        or not image.image or image.image.base != expected_base
    ):
        raise RuntimeError("Image ownership or source changed; refusing deletion.")
    for entry in clients.group.list_sandboxes():
        try:
            raw = raw_sandbox(clients.group.get_sandbox_client(entry.id))
        except ResourceNotFoundError:
            continue
        source = raw.get("sourcesRef")
        disk = source.get("diskImage") if isinstance(source, dict) else None
        if not isinstance(disk, dict) or not isinstance(disk.get("id"), str) or not disk["id"]:
            raise RuntimeError("Cannot establish image references; refusing deletion.")
        if disk["id"] == identifier:
            raise RuntimeError("A sandbox still references the image; refusing deletion.")
    deletion = clients.group.begin_delete_disk_image(identifier)
    deletion.result(timeout=300)
    if deletion.done() is not True:
        raise TimeoutError("Owned image deletion has not completed.")
    try:
        clients.group.get_disk_image(identifier)
    except ResourceNotFoundError:
        return
    raise RuntimeError("Owned image still exists after deletion.")


def report_gateway_state(status: dict) -> None:
    print(f"Hermes gateway state: {status['gateway']}.")
    if status["gateway"] != "running":
        print(
            "The gateway was not automatically started. After any required pairing or controlled reconfiguration, "
            f"resume explicitly in the owner shell: {' '.join([*CONTROL, 'start-gateway'])}"
        )


def deploy(
    config: Config, clients: AzureClients, *, replace: bool = False, fresh: bool = False,
    egress_capture: Callable[[dict[str, Any]], None] | None = None,
    status_capture: StatusSink = None,
) -> str:
    if fresh and replace:
        raise ValueError("Fresh empty-group readiness cannot be combined with replacement.")
    trace = StatusRecorder.coerce(status_capture)
    egress = deployment_egress(config)
    warn_unrestricted_egress(config.egress_mode)
    document = runtime_document(config)
    if not config.image:
        raise ValueError("Supply an existing public immutable HERMES_IMAGE before deployment.")
    assert_owner(clients.credential, config)
    provision_group(config, clients, fresh=fresh, **trace.options())
    sandboxes, images, volumes = owned_inventory(config, clients, **trace.options())
    if fresh:
        with trace.step("provision.fresh-inventory", error_category="inventory_count", details={
            "count": len(sandboxes) + len(images) + len(volumes),
        }):
            if sandboxes or images or volumes:
                raise RuntimeError("Fresh inventory changed after readiness; existing data was not adopted or changed.")
    if sandboxes and not replace:
        sandbox = clients.group.get_sandbox_client(sandboxes[0].id)
        raw = raw_sandbox(sandbox)
        assert_no_suspend(raw)
        validate_egress(raw, egress, capture=egress_capture)
        validate_ports(raw, config, sandbox.sandbox_id)
        if read_runtime(sandbox) != document:
            raise RuntimeError("Runtime differs. Use explicit --replace or controlled reconfigure; nothing was changed.")
        source_id = raw.get("sourcesRef", {}).get("diskImage", {}).get("id")
        source = next((image for image in images if image.id == source_id), None)
        if source is None or not source.image or source.image.base != config.image:
            raise RuntimeError("Image differs; use explicit --replace to preserve the DataDisk.")
        status = control_status(sandbox)
        if status["dashboard"] != "running":
            raise RuntimeError("The existing Hermes dashboard is not ready; no resources were changed.")
        report_gateway_state(status)
        return sandbox.sandbox_id
    if not volumes:
        clients.group.create_volume(config.volume_name, type="DataDisk", size="1Gi", labels=config.labels)
    image_id = create_image(config, clients)
    sandbox = None
    validated = False
    put_attempted = False
    handoff: GatewayHandoff | None = None
    try:
        wait_image(config, clients, image_id)
        for previous in sandboxes:
            previous_sandbox = clients.group.get_sandbox_client(previous.id)
            handoff = GatewayHandoff(f"{config.group_scope}/sandboxes/{previous.id}")
            quiesce_gateway(previous_sandbox, config, handoff)
            delete_sandbox_confirmed(previous_sandbox)
            handoff.stage = "deleted"
        if list(clients.group.list_sandboxes()):
            raise RuntimeError("Previous writer has not disappeared; replacement is blocked.")
        put_attempted = True
        created = clients.group._dp_put(
            f"{clients.group._group_path}/sandboxes", sandbox_document(config, disk_id=image_id, egress=egress)
        )
        identifier = created.get("id") if isinstance(created, dict) else None
        if isinstance(identifier, str) and identifier:
            sandbox = clients.group.get_sandbox_client(identifier)
        validate_egress(created, egress, operation="create", capture=egress_capture)
        if sandbox is None:
            raise RuntimeError("Sandbox creation returned no valid ID; checking exact new-image ownership for rollback.")
        raw = wait_running(sandbox)
        validate_egress(raw, egress, capture=egress_capture)
        upload_private_file(
            sandbox, destination=RUNTIME_PATH,
            content=(json.dumps(document, indent=2) + "\n").encode("utf-8"),
        )
        if read_runtime(sandbox) != document:
            raise RuntimeError("Uploaded runtime readback differs; the new sandbox will not be exposed.")
        # Existing disks may have booted before the updated runtime arrived.
        # Reconfigure is the explicit, serialized stop/apply/revalidate path.
        if volumes:
            exec_checked(sandbox, [*CONTROL, "reconfigure"])
        verify_mvp_network(sandbox, config, capture=egress_capture)
        deadline = time.monotonic() + 180
        while True:
            status = control_status(sandbox)
            state = status["dashboard"]
            if state == "running":
                break
            if state == "failed" or time.monotonic() >= deadline:
                raise RuntimeError("Hermes dashboard did not reach readiness; public port was not opened.")
            time.sleep(3)
        configure_port(sandbox, config)
        validated = True
    finally:
        if not validated:
            if handoff is not None:
                handoff.warn_incomplete(LOG, "Replacement failed during handoff")
            rollback_stage = "sandbox"
            try:
                confirmed = not put_attempted or rollback_new_sandbox(config, clients, image_id, sandbox)
                if not confirmed:
                    LOG.error(
                        "Sandbox creation outcome is unknown; new image preserved. "
                        "Inspect the configured Hermes group for residual owned resources."
                    )
                else:
                    rollback_stage = "image"
                    delete_unreferenced_image(config, clients, image_id, config.image)
            except Exception as error:
                # Preserve the original failure/cancellation, but never hide
                # a rollback failure or print secret-bearing SDK details.
                LOG.error(
                    "New %s rollback failed type=%s; residual owned resources may remain. Inspect the configured Hermes group.",
                    rollback_stage, type(error).__name__,
                )
    resume_gateway = handoff is not None and handoff.prior_gateway in {"running", "stopped"}
    try:
        if resume_gateway:
            exec_checked(sandbox, [*CONTROL, "start-gateway"])
        status = read_control_status(sandbox)
        if resume_gateway and status["gateway"] != "running":
            raise RuntimeError("Gateway did not report running after resume.")
        report_gateway_state(status)
    except (AzureError, ValueError, RuntimeError, TimeoutError) as error:
        LOG.warning(
            "Hermes new sandbox ready; gateway %s not confirmed type=%s. Compute and DataDisk were preserved. "
            "Check control.py status --json, then resume explicitly in the owner shell: %s",
            "resume" if resume_gateway else "status", type(error).__name__,
            " ".join([*CONTROL, "start-gateway"]),
        )
    for previous_image in images:
        try:
            if not previous_image.image or not previous_image.image.base:
                raise RuntimeError("Previous image source is unknown; preserving it.")
            delete_unreferenced_image(config, clients, previous_image.id, previous_image.image.base)
        except (AzureError, RuntimeError, TimeoutError) as error:
            LOG.warning(
                "Hermes new sandbox ready; previous image cleanup incomplete type=%s. Inspect the configured Hermes group.",
                type(error).__name__,
            )
    return sandbox.sandbox_id


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path)
    lifecycle = parser.add_mutually_exclusive_group()
    lifecycle.add_argument("--replace", action="store_true", help="Replace the owned sandbox, preserving its single-writer DataDisk.")
    lifecycle.add_argument("--fresh", action="store_true", help="Require sustained readiness of an owned empty group before first deployment.")
    parser.add_argument("--confirm-target", help="Exact full Sandbox Group resource ID authorizing this operation.")
    args = parser.parse_args()
    config = load_egress_config(args.env_file)
    confirm_target(config, args.confirm_target)
    with AzureClients.create(config) as clients:
        identifier = deploy(config, clients, replace=args.replace, fresh=args.fresh)
    print(f"Hermes sandbox ready: {identifier}")
    print("Use scripts/access_hermes.py. Personal pairing, Google consent and Foundry inference remain separate gates.")


if __name__ == "__main__":
    try:
        main()
    except HttpResponseError as error:
        raise SystemExit(f"Azure provisioning failed (HTTP {error.status_code}); inspect the owned group. DataDisk is preserved.") from None
    except AzureError as error:
        raise SystemExit(f"Azure provisioning failed (type={type(error).__name__}); inspect residual owned resources. DataDisk is preserved.") from None
    except (ValueError, RuntimeError, TimeoutError) as error:
        raise SystemExit(str(error)) from None
