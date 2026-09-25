#!/usr/bin/env python3
"""Explicitly deploy or replace a separate, persistent personal Hermes Sandbox."""

from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path

from azure.core.exceptions import AzureError, HttpResponseError, ResourceNotFoundError

from hermes_common import (
    AzureClients, Config, CONTROL, GatewayHandoff, RUNTIME_PATH, assert_group_owned, assert_labels,
    assert_no_suspend, assert_owner, configure_port, confirm_target, control_status,
    delete_sandbox_confirmed, deployment_egress, exec_checked, load_egress_config, owned_inventory,
    quiesce_gateway, raw_sandbox, read_control_status, read_runtime,
    runtime_document, sandbox_document, upload_private_file, validate_egress,
    validate_ports, verify_mvp_network, wait_running, warn_unrestricted_egress,
)

LOG = logging.getLogger("hermes.deploy")


def provision_group(config: Config, clients: AzureClients) -> None:
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
    try:
        list(clients.group.list_volumes())
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


def deploy(config: Config, clients: AzureClients, *, replace: bool = False) -> str:
    egress = deployment_egress(config)
    warn_unrestricted_egress(config.egress_mode)
    document = runtime_document(config)
    if not config.image:
        raise ValueError("Supply an existing public immutable HERMES_IMAGE before deployment.")
    assert_owner(clients.credential, config)
    provision_group(config, clients)
    sandboxes, images, volumes = owned_inventory(config, clients)
    if sandboxes and not replace:
        sandbox = clients.group.get_sandbox_client(sandboxes[0].id)
        raw = raw_sandbox(sandbox)
        assert_no_suspend(raw)
        validate_egress(raw, egress)
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
        if not isinstance(created, dict) or not isinstance(created.get("id"), str) or not created["id"]:
            raise RuntimeError("Sandbox creation returned no valid ID; checking exact new-image ownership for rollback.")
        sandbox = clients.group.get_sandbox_client(created["id"])
        raw = wait_running(sandbox)
        validate_egress(raw, egress)
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
        verify_mvp_network(sandbox, config)
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
    parser.add_argument("--replace", action="store_true", help="Replace the owned sandbox, preserving its single-writer DataDisk.")
    parser.add_argument("--confirm-target", help="Exact full Sandbox Group resource ID authorizing this operation.")
    args = parser.parse_args()
    config = load_egress_config(args.env_file)
    confirm_target(config, args.confirm_target)
    with AzureClients.create(config) as clients:
        identifier = deploy(config, clients, replace=args.replace)
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
