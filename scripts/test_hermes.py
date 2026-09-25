#!/usr/bin/env python3
"""Check actual Hermes Azure policy and runtime, without sending personal messages."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from azure.core.exceptions import HttpResponseError

from hermes_common import (
    AzureClients, Config, assert_no_suspend, assert_owner, control_status, deployment_egress,
    get_sandbox, owned_inventory, raw_sandbox, read_access_key, read_runtime, runtime_document,
    validate_egress, validate_ports, verify_partial_network,
)


def inspect_deployment(config: Config, clients: AzureClients, *, network: bool = False) -> dict:
    assert_owner(clients.credential, config)
    _, _, volumes = owned_inventory(config, clients)
    if len(volumes) != 1:
        raise RuntimeError("Exactly one owned 1 GiB DataDisk is required.")
    sandbox = get_sandbox(config, clients)
    raw = raw_sandbox(sandbox)
    assert_no_suspend(raw)
    validate_ports(raw, config, sandbox.sandbox_id)
    validate_egress(raw, deployment_egress(config))
    if read_runtime(sandbox) != runtime_document(config):
        raise RuntimeError("Actual runtime.json differs from the configured managed profile.")
    read_access_key(sandbox)
    status = control_status(sandbox)
    result = {
        "schema_version": 1, "raw_azure_policy": "PASS", "runtime": status,
        "foundry_inference": "NOT VERIFIED", "whatsapp_delivery": "NOT VERIFIED",
        "google_live_read": "NOT VERIFIED", "token_expiry_soak": "NOT VERIFIED",
        "entra_non_owner_and_websocket": "NOT VERIFIED",
    }
    result["partial_network"] = verify_partial_network(sandbox, config) if network else "NOT VERIFIED"
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--network", action="store_true", help="Probe exact hosts with public CA trust and check a platform deny.")
    args = parser.parse_args()
    config = Config.from_env(args.env_file)
    with AzureClients.create(config) as clients:
        result = inspect_deployment(config, clients, network=args.network)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except HttpResponseError as error:
        raise SystemExit(f"Hermes check failed (HTTP {error.status_code}); no credentials or personal data were exported.") from None
    except (ValueError, RuntimeError, TimeoutError) as error:
        raise SystemExit(str(error)) from None
