#!/usr/bin/env python3
"""Explicit local Google Desktop consent and atomic Hermes credential upload."""

from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import logging
import sys
import webbrowser
from pathlib import Path
from typing import Any, Callable, Protocol

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "hermes" / "image" / "google"))

from google_readonly import (
    AUTH_URL,
    CREDENTIAL_PATH,
    MAX_DOCUMENT_BYTES,
    SCOPES,
    TOKEN_URL,
    GoogleError,
    GoogleHTTP,
    GooglePolicy,
    Transport,
    json_object,
    verified_oauth_credential,
)

CONSENT_TIMEOUT_SECONDS = 300
_DIAGNOSTICS = {
    "desktop_client_invalid": "Provide a valid local Google OAuth Desktop client JSON file, not a web client or existing token export.",
    "browser_unavailable": "Could not open the local browser. Configure a browser and run connect again.",
    "consent_timeout": "Timed out waiting for local Google consent. Run connect again.",
    "consent_cancelled": "Google consent was not completed. The sandbox credential was not changed.",
    "consent_failed": "Google Desktop authorization failed. No credential was uploaded.",
    "runtime_changed": "Local and deployed Google policies differ. Reconfigure the intended Hermes sandbox before reconnecting.",
    "upload_failed": "Google credential upload failed. Check the authenticated Hermes SDK connection; no local credential export was created.",
    "host_config_failed": "Could not load the Hermes-only configuration or SDK helpers. Install requirements-hermes.txt and configure .env.hermes.",
}


class OnboardingError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(_DIAGNOSTICS[code])
        self.code = code


class PrivateUploader(Protocol):
    def __call__(self, sandbox: Any, *, destination: str, content: bytes) -> None: ...


def desktop_client(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            content = stream.read(MAX_DOCUMENT_BYTES + 1)
        if len(content) > MAX_DOCUMENT_BYTES:
            raise OnboardingError("desktop_client_invalid")
        document = json_object(content, "credentials_invalid")
        if set(document) != {"installed"} or not isinstance(document["installed"], dict):
            raise OnboardingError("desktop_client_invalid")
        installed = document["installed"]
        if installed.get("auth_uri") not in {
            AUTH_URL, "https://accounts.google.com/o/oauth2/auth",
        } or installed.get("token_uri") != TOKEN_URL:
            raise OnboardingError("desktop_client_invalid")
        client_id, client_secret = installed.get("client_id"), installed.get("client_secret")
        if (
            not isinstance(client_id, str) or not client_id.endswith(".apps.googleusercontent.com")
            or not 1 <= len(client_id) <= 256
            or not isinstance(client_secret, str) or not 1 <= len(client_secret) <= 4096
            or any(c.isspace() or ord(c) < 32 for c in client_id + client_secret)
        ):
            raise OnboardingError("desktop_client_invalid")
    except (OSError, GoogleError):
        raise OnboardingError("desktop_client_invalid") from None
    return {"installed": {
        "client_id": client_id, "client_secret": client_secret,
        "auth_uri": AUTH_URL, "token_uri": TOKEN_URL,
        "redirect_uris": ["http://127.0.0.1"],
    }}


async def consent(
    client: dict[str, Any], policy: GooglePolicy, transport: Transport,
    *, open_browser: Callable[..., bool] = webbrowser.open,
) -> dict[str, Any]:
    """Loopback+PKCE, with bounded official token exchange and no URL logging."""
    try:
        from aiohttp import web
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:
        raise OnboardingError("host_config_failed") from None
    if not policy.enabled:
        raise GoogleError("disabled")
    flow = InstalledAppFlow.from_client_config(client, scopes=list(SCOPES), autogenerate_code_verifier=True)
    loop = asyncio.get_running_loop()
    received: asyncio.Future[str] = loop.create_future()
    expected_state = ""
    expected_host = ""

    async def callback(request: web.Request) -> web.Response:
        headers = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}
        state = request.query.get("state", "")
        if (
            request.host != expected_host or received.done()
            or len(request.query_string) > 16 * 1024
            or len(request.query.getall("state", [])) != 1
            or not state.isascii() or len(state) > 1024
            or not hmac.compare_digest(state, expected_state)
        ):
            return web.Response(status=400, text="Invalid OAuth callback.", headers=headers)
        if "error" in request.query:
            received.set_exception(OnboardingError("consent_cancelled"))
            return web.Response(status=400, text="Authorization was not completed.", headers=headers)
        codes = request.query.getall("code", [])
        if len(codes) != 1 or not 1 <= len(codes[0]) <= 8192:
            return web.Response(status=400, text="Invalid OAuth callback.", headers=headers)
        received.set_result(codes[0])
        return web.Response(
            text="Authorization received. Return to the terminal for account and scope verification.",
            headers=headers,
        )

    app = web.Application(client_max_size=16 * 1024)
    app.router.add_get("/", callback, allow_head=False)
    runner = web.AppRunner(app, access_log=None, shutdown_timeout=1)
    try:
        await runner.setup()
        site = web.TCPSite(runner, host="127.0.0.1", port=0)
        await site.start()
        port = runner.addresses[0][1]
        expected_host = f"127.0.0.1:{port}"
        flow.redirect_uri = f"http://{expected_host}/"
        auth_url, expected_state = flow.authorization_url(
            access_type="offline", include_granted_scopes="false", prompt="consent",
            login_hint=policy.expected_email,
        )
        if not await asyncio.to_thread(open_browser, auth_url, new=1, autoraise=True):
            raise OnboardingError("browser_unavailable")
        try:
            code = await asyncio.wait_for(received, timeout=CONSENT_TIMEOUT_SECONDS)
        except TimeoutError:
            raise OnboardingError("consent_timeout") from None
        response = await transport.request("token", form={
            "grant_type": "authorization_code", "code": code,
            "client_id": client["installed"]["client_id"],
            "client_secret": client["installed"]["client_secret"],
            "redirect_uri": flow.redirect_uri, "code_verifier": flow.code_verifier,
        })
        if response.status != 200 or "error" in response.data:
            raise OnboardingError("consent_failed")
        return response.data
    except (OSError, webbrowser.Error):
        raise OnboardingError("consent_failed") from None
    finally:
        if not received.done():
            received.cancel()
        elif not received.cancelled():
            received.exception()
        await runner.cleanup()


async def authorize(client_path: Path, policy: GooglePolicy) -> bytes:
    client = desktop_client(client_path)
    async with GoogleHTTP() as transport:
        token_response = await consent(client, policy, transport)
        return await verified_oauth_credential(
            policy, client_id=client["installed"]["client_id"],
            client_secret=client["installed"]["client_secret"],
            token_response=token_response, transport=transport,
        )


def upload_verified_credential(
    sandbox: Any, *, content: bytes, local_policy: GooglePolicy,
    deployed_runtime: dict[str, Any], uploader: PrivateUploader | None = None,
) -> None:
    if GooglePolicy.from_runtime(deployed_runtime) != local_policy:
        raise OnboardingError("runtime_changed")
    if uploader is None:
        from hermes_common import upload_private_file

        uploader = upload_private_file
    try:
        uploader(sandbox, destination=str(CREDENTIAL_PATH), content=content)
    except Exception:
        # SDK exceptions may include file request bodies; never echo them.
        raise OnboardingError("upload_failed") from None


def connect(client_path: Path, env_path: Path | None) -> None:
    try:
        from hermes_common import (
            AzureClients, Config, get_sandbox, read_runtime, runtime_document,
        )

        config = Config.from_env(env_path=env_path)
        policy = GooglePolicy.from_runtime(runtime_document(config))
    except GoogleError:
        raise
    except Exception:
        raise OnboardingError("host_config_failed") from None
    content = asyncio.run(authorize(client_path, policy))
    try:
        with AzureClients.create(config) as clients:
            sandbox = get_sandbox(config, clients)
            upload_verified_credential(
                sandbox, content=content, local_policy=policy,
                deployed_runtime=read_runtime(sandbox),
            )
    except (OnboardingError, GoogleError):
        raise
    except Exception:
        raise OnboardingError("upload_failed") from None
    print(
        "Google account and exact read-only scopes verified; credential uploaded. "
        "Run /opt/hermes-sandbox/control.py reconfigure explicitly to enable the managed MCP profile. "
        "External OAuth apps in Testing may require reconnect after seven days."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    connect_parser = subparsers.add_parser("connect", help="Explicitly consent or reconnect; replaces only the protected Google credential.")
    connect_parser.add_argument("--client-secrets", required=True, type=Path, help="Path to your local Google Desktop client JSON. Never pass secret values.")
    connect_parser.add_argument("--env-file", type=Path, help="Hermes-only env file; defaults to .env.hermes.")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    for name in ("aiohttp", "oauthlib", "requests_oauthlib", "google_auth_oauthlib"):
        logging.getLogger(name).setLevel(logging.CRITICAL + 1)
    try:
        connect(args.client_secrets, args.env_file)
        return 0
    except (OnboardingError, GoogleError) as error:
        print(json.dumps({"status": "failed", "code": error.code, "message": str(error)}), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Google onboarding cancelled. No local credential export was created.", file=sys.stderr)
        return 130
    except Exception:
        error = OnboardingError("consent_failed")
        print(json.dumps({"status": "failed", "code": error.code, "message": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
