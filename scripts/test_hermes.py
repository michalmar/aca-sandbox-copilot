#!/usr/bin/env python3
"""Check actual Hermes Azure policy and runtime, without sending personal messages."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from azure.core.exceptions import HttpResponseError

from hermes_common import (
    AzureClients, Config, MVP_EGRESS_MODE, MVP_EGRESS_WARNING, StatusRecorder, StatusSink,
    assert_no_suspend, assert_owner, control_status, deployment_egress,
    get_sandbox, load_egress_config, owned_inventory, raw_sandbox, read_access_key, read_runtime, runtime_document,
    validate_egress, validate_ports, verify_mvp_network, warn_unrestricted_egress,
)


def inspect_deployment(
    config: Config, clients: AzureClients, *, network: bool = False, capture: StatusSink = None,
) -> dict:
    trace = StatusRecorder.coerce(capture)
    with trace.step("status.mode", error_category="mode_mismatch", details={
        "config_mode_matches": config.egress_mode == MVP_EGRESS_MODE,
    }):
        egress = deployment_egress(config)
        warn_unrestricted_egress(config.egress_mode)
    assert_owner(clients.credential, config, **trace.options())
    _, _, volumes = owned_inventory(config, clients, **trace.options())
    with trace.step("status.volume-count", error_category="inventory_count", details={"count": len(volumes)}):
        if len(volumes) != 1:
            raise RuntimeError("Exactly one owned 1 GiB DataDisk is required.")
    sandbox = get_sandbox(config, clients, **trace.options())
    raw = raw_sandbox(sandbox, **trace.options("status.raw"))
    with trace.step("status.lifecycle", error_category="lifecycle_mismatch"):
        assert_no_suspend(raw)
    with trace.step("status.ports", error_category="ingress_mismatch", details={
        "count": len(raw["ports"]) if isinstance(raw.get("ports"), list) else None,
    }):
        validate_ports(raw, config, sandbox.sandbox_id)
    readback = validate_egress(raw, egress, **trace.options("status.policy"))
    with trace.step("status.runtime", error_category="runtime_mismatch") as step:
        step.details["runtime_matches"] = read_runtime(sandbox) == runtime_document(config)
        if not step.details["runtime_matches"]:
            raise RuntimeError("Actual runtime.json differs from the configured managed profile.")
    with trace.step("status.access-key", error_category="private_key_shape") as step:
        read_access_key(sandbox)
        step.details["key_checked"] = True
    with trace.step("status.control", error_category="runtime_status") as step:
        status = control_status(sandbox)
        step.details["control_checked"] = True
    result = {
        "schema_version": 1, "raw_azure_policy": "KNOWN MVP FIELDS MATCH", "runtime": status,
        "egress": {
            "mode": config.egress_mode, **egress,
            "outbound_isolation": False, "warning": MVP_EGRESS_WARNING, "readback": readback,
        },
        "foundry_inference": "NOT VERIFIED", "whatsapp_delivery": "NOT VERIFIED",
        "google_live_read": "NOT VERIFIED", "token_expiry_soak": "NOT VERIFIED",
        "entra_non_owner_and_websocket": "NOT VERIFIED",
    }
    result["network"] = verify_mvp_network(sandbox, config, **trace.options()) if network else "NOT VERIFIED"
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument(
        "--network", action="store_true",
        help="Check harmless public-CA HTTPS reachability; MVP mode has no outbound isolation or deny proof.",
    )
    args = parser.parse_args()
    config = load_egress_config(args.env_file)
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
