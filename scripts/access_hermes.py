#!/usr/bin/env python3
"""Open an owner-only loopback browser relay after az login."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from pathlib import Path

from aiohttp import web
from azure.core.exceptions import AzureError

from hermes_common import (
    AzureClients, INGRESS_SCOPE, ROOT, assert_no_suspend, assert_owner,
    deployment_egress, get_sandbox, load_egress_config, raw_sandbox, read_access_key,
    validate_egress, validate_ports, warn_unrestricted_egress,
)

sys.path.insert(0, str(ROOT / "hermes/image"))
from access_proxy import Proxy


class AzureRelayCredentials:
    def __init__(self, clients: AzureClients, sandbox):
        self.clients = clients
        self.sandbox = sandbox
        self.token = None
        self.lock = asyncio.Lock()

    async def bearer(self) -> str:
        async with self.lock:
            try:
                if self.token is None or self.token.expires_on <= time.time() + 120:
                    self.token = await asyncio.to_thread(self.clients.credential.get_token, INGRESS_SCOPE)
            except AzureError as error:
                logging.getLogger("hermes.access").warning("Azure owner authentication failed type=%s", type(error).__name__)
                raise RuntimeError("Owner authentication failed; check the configured tenant and az login.") from None
            return self.token.token

    async def access_key(self) -> str:
        try:
            return await asyncio.to_thread(read_access_key, self.sandbox)
        except AzureError as error:
            logging.getLogger("hermes.access").warning("Azure transport-key read failed type=%s", type(error).__name__)
            raise RuntimeError("Private transport-key read failed; check the owned Sandbox and Azure permissions.") from None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535.")
    logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
    config = load_egress_config(args.env_file)
    warn_unrestricted_egress(config.egress_mode)
    with AzureClients.create(config) as clients:
        assert_owner(clients.credential, config)
        sandbox = get_sandbox(config, clients)
        raw = raw_sandbox(sandbox)
        assert_no_suspend(raw)
        validate_egress(raw, deployment_egress(config))
        if str(raw.get("state", "")).lower() != "running":
            raise RuntimeError("Hermes is not running; automatic disk-mode resume is not supported.")
        target = validate_ports(raw, config, sandbox.sandbox_id)
        credentials = AzureRelayCredentials(clients, sandbox)
        origin = f"http://127.0.0.1:{args.port}"
        proxy = Proxy(
            local_origin=origin, target=target,
            token_provider=credentials.bearer, key_provider=credentials.access_key,
        )
        print(f"Open {origin}/ in this computer's browser. Keep this owner relay running.")
        web.run_app(proxy.app, host="127.0.0.1", port=args.port, access_log=None, print=None)


if __name__ == "__main__":
    try:
        main()
    except AzureError as error:
        raise SystemExit(f"Azure access failed ({type(error).__name__}); check tenant login and Sandbox Group permissions.") from None
    except (ValueError, RuntimeError) as error:
        raise SystemExit(str(error)) from None
