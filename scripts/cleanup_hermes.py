#!/usr/bin/env python3
"""Remove only owned Hermes compute; preserve personal DataDisk by default."""

from __future__ import annotations

import argparse
import logging
import re
from pathlib import Path

from azure.containerapps.sandbox import SandboxClient
from azure.core.exceptions import AzureError, HttpResponseError

from hermes_common import (
    AzureClients, Config, CONTROL, GatewayHandoff, assert_group_owned, assert_owner, confirm_target,
    compute_state, delete_sandbox_confirmed, exec_checked, owned_inventory, quiesce_gateway, read_control_status,
)

LOG = logging.getLogger("hermes.cleanup")


def recovery_confirmation(config: Config, value: str | None) -> str | None:
    if value is None:
        return None
    prefix = config.group_scope + "/sandboxes/"
    match = re.fullmatch(re.escape(prefix) + r"([a-z0-9][a-z0-9-]{1,127})", value) if isinstance(value, str) else None
    if not match:
        raise ValueError(
            "Unquiesced recovery requires the full owned sandbox target: "
            f"{prefix}<exact-sandbox-id>"
        )
    return match[1]


def stop_unquiesced_writer(sandbox: SandboxClient, handoff: GatewayHandoff) -> None:
    def observe_gateway() -> tuple[str, str]:
        try:
            return read_control_status(sandbox)["gateway"], "completed"
        except (AzureError, ValueError, RuntimeError, TimeoutError) as error:
            return "unknown", type(error).__name__

    state, compute_error = "unknown", "none"
    gateway, result = "unknown", "not-attempted"
    before_read, after_read = "not-attempted", "not-attempted"
    try:
        state = compute_state(sandbox)
    except (AzureError, ValueError, RuntimeError, TimeoutError) as error:
        compute_error = type(error).__name__
    if state == "running":
        handoff.prior_gateway, before_read = observe_gateway()
        handoff.stage = "stop-issued"
        try:
            exec_checked(sandbox, [*CONTROL, "stop-gateway"])
            result = "completed"
        except (AzureError, ValueError, RuntimeError, TimeoutError) as error:
            result = type(error).__name__
        gateway, after_read = observe_gateway()
    LOG.warning(
        "Explicit unquiesced recovery: compute=%s, compute-error=%s, before gateway=%s, after gateway=%s, "
        "stop=%s, status-before=%s, status-after=%s; persistent gateway intent not confirmed. "
        "Cleanup never starts or resumes compute or the gateway. The next boot may start the gateway with "
        "the old on-disk runtime; controlled reconfigure may start a previously failed paired gateway.",
        state, compute_error, handoff.prior_gateway, gateway, result, before_read, after_read,
    )


def cleanup(
    config: Config, clients: AzureClients, *,
    delete_data: bool = False, confirm_volume: str | None = None, delete_group: bool = False,
    confirm_unquiesced_writer: str | None = None,
) -> None:
    if delete_group and not delete_data:
        raise ValueError("--delete-group also requires explicit --delete-data and the exact --confirm-volume.")
    volume_target = f"{config.group_scope}/volumes/{config.volume_name}"
    if delete_data and confirm_volume != volume_target:
        raise ValueError(f"Personal data deletion requires --confirm-volume {volume_target}")
    confirmed_writer = recovery_confirmation(config, confirm_unquiesced_writer)
    assert_owner(clients.credential, config)
    if not clients.resources.resource_groups.check_existence(config.resource_group):
        print("The configured Hermes resource group is already absent.")
        return
    sandboxes, images, volumes = owned_inventory(config, clients)
    if confirmed_writer is not None and (len(sandboxes) != 1 or sandboxes[0].id != confirmed_writer):
        raise ValueError("Unquiesced recovery must name the exact owned sandbox from the current single-writer inventory.")
    if delete_group and list(clients.group.list_secrets()):
        raise RuntimeError("Sandbox Group contains unexpected secrets; refusing whole-group deletion.")
    for entry in sandboxes:
        sandbox = clients.group.get_sandbox_client(entry.id)
        handoff = GatewayHandoff(f"{config.group_scope}/sandboxes/{entry.id}")
        try:
            if confirmed_writer is not None:
                stop_unquiesced_writer(sandbox, handoff)
            elif not delete_data:
                quiesce_gateway(sandbox, config, handoff)
            elif compute_state(sandbox) == "running":
                handoff.stage = "stop-issued"
                exec_checked(sandbox, [*CONTROL, "stop-gateway"])
            delete_sandbox_confirmed(sandbox)
            handoff.stage = "deleted"
        finally:
            if handoff.stage != "deleted":
                handoff.warn_incomplete(LOG, "Cleanup did not finish")
    if list(clients.group.list_sandboxes()):
        raise RuntimeError("Sandbox deletion is incomplete; no volume or group was removed.")
    for image in images:
        clients.group.begin_delete_disk_image(image.id).result(timeout=300)
    if not delete_data:
        print("Owned Hermes compute removed. DataDisk, Google grant and WhatsApp device keys were preserved.")
        if confirmed_writer is not None:
            print("Personal data was preserved; persistent gateway intent is unconfirmed. Review the recovery warning before redeploying.")
        elif sandboxes:
            print("A later deploy keeps confirmed gateway maintenance; resume explicitly after deployment.")
        else:
            print("No gateway state was changed. A later deploy reports its state and any required manual resume.")
        return
    for volume in volumes:
        clients.group.begin_delete_volume(volume.name).result(timeout=300)
    if list(clients.group.list_volumes()):
        raise RuntimeError("Volume deletion is incomplete; group was preserved.")
    if delete_group:
        assert_group_owned(config, clients)
        clients.groups.begin_delete_group(config.sandbox_group).result(timeout=300)
        if list(clients.resources.resources.list_by_resource_group(config.resource_group)):
            raise RuntimeError("Resource group is not empty; it was preserved.")
        clients.resources.resource_groups.begin_delete(config.resource_group).result(timeout=600)
        if clients.resources.resource_groups.check_existence(config.resource_group):
            raise RuntimeError("Resource group deletion could not be verified.")
    print("The explicitly confirmed Hermes DataDisk was removed.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--confirm-target")
    parser.add_argument("--delete-data", action="store_true", help="Permanently delete personal history and credentials.")
    parser.add_argument("--confirm-volume", help="Exact full group resource ID followed by /volumes/<name>.")
    parser.add_argument("--delete-group", action="store_true", help="Also delete the dedicated, otherwise-empty group/RG.")
    parser.add_argument(
        "--confirm-unquiesced-writer",
        help="Exact full group ID followed by /sandboxes/<id>; authorize compute recovery without confirmed gateway maintenance. "
             "Preserves data unless separately confirmed. A later boot may start saved gateway intent.",
    )
    args = parser.parse_args()
    config = Config.from_env(args.env_file)
    confirm_target(config, args.confirm_target)
    recovery_confirmation(config, args.confirm_unquiesced_writer)
    with AzureClients.create(config) as clients:
        cleanup(
            config, clients, delete_data=args.delete_data, confirm_volume=args.confirm_volume, delete_group=args.delete_group,
            confirm_unquiesced_writer=args.confirm_unquiesced_writer,
        )


if __name__ == "__main__":
    try:
        main()
    except HttpResponseError as error:
        raise SystemExit(f"Hermes cleanup failed (HTTP {error.status_code}); inspect residual owned resources.") from None
    except AzureError as error:
        raise SystemExit(f"Hermes cleanup failed (type={type(error).__name__}); inspect residual owned resources.") from None
    except (ValueError, RuntimeError, TimeoutError) as error:
        raise SystemExit(str(error)) from None
