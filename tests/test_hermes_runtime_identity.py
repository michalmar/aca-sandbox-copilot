"""Real MI/MSAL/OpenAI offline paths; not proof of live Azure access or graph consistency."""

from __future__ import annotations

import importlib.metadata
import io
import json
import logging
import os
from pathlib import Path
import platform
import signal
import socket
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit


def probe() -> dict:
    if (
        os.environ.get("HERMES_RUNTIME_IDENTITY_PROBE") != "1"
        or platform.system() != "Linux"
        or platform.machine() != "x86_64"
        or not Path("/.dockerenv").exists()
        or {name for _, name in socket.if_nameindex()
            if int(Path("/sys/class/net", name, "flags").read_text(), 16) & 1} != {"lo"}
    ):
        raise RuntimeError("Requires the amd64 image, explicit test opt-in and --network none")

    def deadline(_signal, _frame):
        raise TimeoutError("MI compatibility probe exceeded its 30-second bound")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(30)
    connections = []
    subprocesses = []

    def audit(event, arguments):
        if event == "subprocess.Popen":
            if tuple(arguments[1]) != ("uname", "-p"):
                raise RuntimeError("Only the standard library's exact uname probe is permitted")
            subprocesses.append("uname -p")
        if event == "socket.connect":
            address = arguments[1]
            if not isinstance(address, tuple) or address[0] != "127.0.0.1":
                raise RuntimeError("Only the in-container loopback fixture may be contacted")
            connections.append(address)

    sys.addaudithook(audit)
    versions = {name: importlib.metadata.version(name) for name in (
        "azure-identity", "azure-core", "msal", "msal-extensions", "cryptography", "PyJWT", "openai",
    )}
    built = json.loads(Path("/opt/hermes-sandbox/build-versions.json").read_text())
    for name in ("azure-identity", "msal", "cryptography", "openai"):
        assert versions[name] == built[name], f"{name} no longer matches verified build provenance"

    from agent.azure_identity_adapter import (
        EntraIdentityConfig, build_credential, build_token_provider, reset_credential_cache,
    )
    from openai import OpenAI

    results = []
    diagnostic = io.StringIO()
    handler = logging.StreamHandler(diagnostic)
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

    def run_identity_flow(mode):
        tokens = []
        inference_auth = []
        failures = []

        class Endpoint(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def respond(self, status, value):
                data = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                query = parse_qs(urlsplit(self.path).query)
                expected_header = (
                    self.headers.get("X-IDENTITY-HEADER") == "offline-endpoint-header"
                    if mode == "endpoint" else self.headers.get("Metadata") == "true"
                )
                if (
                    urlsplit(self.path).path != "/metadata/identity/oauth2/token"
                    or query.get("resource") != ["https://ai.azure.com"]
                    or not expected_header
                    or "client_id" in query
                ):
                    failures.append("Unexpected token request shape")
                    return self.respond(400, {"error": "invalid_request"})
                token = f"offline-{mode}-{len(tokens) + 1}"
                tokens.append(token)
                lifetime = 1 if len(tokens) == 1 else 3600
                self.respond(200, {"access_token": token, "expires_in": lifetime,
                                   "expires_on": str(int(time.time()) + lifetime),
                                   "resource": "https://ai.azure.com", "token_type": "Bearer"})

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                if urlsplit(self.path).path != "/v1/chat/completions" or payload.get("model") != "offline":
                    failures.append("Unexpected inference request shape")
                    return self.respond(400, {"error": "invalid_request"})
                inference_auth.append(self.headers.get("Authorization"))
                self.respond(200, {"id": "offline", "object": "chat.completion",
                                   "created": int(time.time()), "model": "offline",
                                   "choices": [{"index": 0,
                                                "message": {"role": "assistant", "content": "offline accepted"},
                                                "finish_reason": "stop"}]})

        server = ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        environment = {"AZURE_TOKEN_CREDENTIALS": "ManagedIdentityCredential", "NO_PROXY": "*",
                       "PATH": "/opt/hermes/.venv/bin:/usr/local/bin:/usr/bin:/bin"}
        if mode == "endpoint":
            environment.update(IDENTITY_ENDPOINT=base + "/metadata/identity/oauth2/token",
                               IDENTITY_HEADER="offline-endpoint-header")
        else:
            environment["AZURE_POD_IDENTITY_AUTHORITY_HOST"] = base
        credential = None
        try:
            with patch.dict(os.environ, environment, clear=True):
                reset_credential_cache()
                credential = build_credential(EntraIdentityConfig())
                assert [type(item).__name__ for item in credential.credentials] == ["ManagedIdentityCredential"]
                native = credential.credentials[0]._credential
                assert type(native._msal_client).__module__ == "msal.managed_identity"
                assert type(native).__name__ == ("AppServiceCredential" if mode == "endpoint" else "ImdsCredential")
                provider = build_token_provider()
                with OpenAI(api_key=provider, base_url=base + "/v1", max_retries=0, timeout=3) as client:
                    for _ in range(3):
                        response = client.chat.completions.create(
                            model="offline", messages=[{"role": "user", "content": "offline compatibility probe"}],
                        )
                        assert response.choices[0].message.content == "offline accepted"
                assert not failures, failures
                assert len(tokens) == 2, "MI refresh/cache did not produce exactly two token exchanges"
                assert inference_auth == ["Bearer " + tokens[0], "Bearer " + tokens[1], "Bearer " + tokens[1]]
                assert all(token not in diagnostic.getvalue() for token in tokens)
                results.append({"mode": mode, "credential": type(native).__name__,
                                "msal_client": type(native._msal_client).__name__,
                                "token_exchanges": len(tokens), "inference_requests": len(inference_auth),
                                "refresh_and_cache": "passed", "resource": "https://ai.azure.com"})
        finally:
            if credential is not None:
                credential.close()
            reset_credential_cache()
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            assert not thread.is_alive(), "Loopback fixture thread did not stop"

    for mode in ("endpoint", "imds"):
        run_identity_flow(mode)

    import jwt
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from msal.oauth2cli.assertion import JwtAssertionCreator

    signing = []
    for algorithm, key in (
        ("RS256", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        ("ES256", ec.generate_private_key(ec.SECP256R1())),
    ):
        creator = JwtAssertionCreator(key, algorithm)
        assertion = creator.create_normal_assertion(audience="https://offline.invalid/token", issuer="offline")
        claims = jwt.decode(assertion, key.public_key(), algorithms=[algorithm],
                            audience="https://offline.invalid/token", issuer="offline")
        assert claims["iss"] == claims["sub"] == "offline"
        assertion_text = assertion.decode() if isinstance(assertion, bytes) else assertion
        assert assertion_text not in diagnostic.getvalue()
        signing.append(algorithm)

    logging.getLogger().removeHandler(handler)
    signal.alarm(0)
    return {"versions": versions, "identity_flows": results, "msal_sign_verify": signing,
            "non_loopback_requests": 0, "loopback_connections": len(connections),
            "subprocesses": subprocesses, "token_method_monkeypatches": 0,
            "bounded_offline_paths_only": True, "result": "passed"}


@unittest.skipUnless(os.environ.get("HERMES_RUNTIME_IMAGE_TESTS") == "1",
                     "requires the true amd64 Hermes image and explicit offline test opt-in")
class RuntimeIdentityTests(unittest.TestCase):
    def test_real_mi_msal_token_refresh_cache_and_signing(self):
        result = subprocess.run(
            [sys.executable, "-I", str(Path(__file__).resolve()), "--probe"],
            env={**os.environ, "HERMES_RUNTIME_IDENTITY_PROBE": "1"},
            capture_output=True, text=True, timeout=45,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["result"], "passed")
        for name, version in (("msal", "1.37.0"), ("cryptography", "50.0.0"), ("azure-identity", "1.25.3")):
            self.assertEqual(report["versions"][name], version)
        self.assertEqual(report["non_loopback_requests"], 0)
        self.assertEqual(report["loopback_connections"], 10)
        self.assertEqual(report["token_method_monkeypatches"], 0)
        self.assertEqual(report["msal_sign_verify"], ["RS256", "ES256"])
        self.assertEqual([flow["mode"] for flow in report["identity_flows"]], ["endpoint", "imds"])
        for flow in report["identity_flows"]:
            self.assertEqual(flow["token_exchanges"], 2)
            self.assertEqual(flow["inference_requests"], 3)
        self.assertIn(report["subprocesses"], ([], ["uname -p"]))
        self.assertNotIn("offline-endpoint-header", result.stdout + result.stderr)
        self.assertNotIn("Bearer offline-", result.stdout + result.stderr)
        print("REAL_MI_CLIENT_PROBE=" + json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    if sys.argv[1:] == ["--probe"]:
        print(json.dumps(probe(), sort_keys=True))
    else:
        unittest.main()
