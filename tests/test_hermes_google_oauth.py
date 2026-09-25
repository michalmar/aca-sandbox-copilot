from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import types
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from test_hermes_google_core import (
    ACCESS_TOKEN, CLIENT_ID, CLIENT_SECRET, EMAIL, REFRESH_TOKEN, ROOT,
    FakeTransport, PrivateFiles, credential_document, google, runtime_document,
    token_document,
)

spec = importlib.util.spec_from_file_location("google_auth_hermes", ROOT / "scripts" / "google_auth_hermes.py")
onboarding = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(onboarding)


def desktop_document():
    return {"installed": {
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
        "auth_uri": google.AUTH_URL, "token_uri": google.TOKEN_URL,
        "redirect_uris": ["http://localhost"], "project_id": "test-only",
    }}


class DesktopClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hermes-desktop-test-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "desktop-client.json"

    def read(self, document):
        self.path.write_text(json.dumps(document), encoding="utf-8")
        return onboarding.desktop_client(self.path)

    def test_accepts_only_desktop_and_uses_fixed_official_endpoints(self):
        result = self.read(desktop_document())
        self.assertEqual(result["installed"]["auth_uri"], google.AUTH_URL)
        self.assertEqual(result["installed"]["token_uri"], google.TOKEN_URL)
        self.assertEqual(result["installed"]["redirect_uris"], ["http://127.0.0.1"])
        self.assertNotIn("project_id", result["installed"])

    def test_web_export_or_endpoint_substitution_is_rejected(self):
        bad = [
            {"web": desktop_document()["installed"]}, credential_document(),
            {"installed": {**desktop_document()["installed"], "auth_uri": "https://attacker.test/auth"}},
            {"installed": {**desktop_document()["installed"], "token_uri": "https://attacker.test/token"}},
            {"installed": {**desktop_document()["installed"], "client_secret": ""}},
            {"installed": {**desktop_document()["installed"], "client_id": "invalid"}},
        ]
        for document in bad:
            with self.assertRaises(onboarding.OnboardingError) as raised:
                self.read(document)
            self.assertEqual(raised.exception.code, "desktop_client_invalid")
            self.assertNotIn(CLIENT_SECRET, str(raised.exception))
        self.path.write_bytes(b"x" * (google.MAX_DOCUMENT_BYTES + 1))
        with self.assertRaises(onboarding.OnboardingError):
            onboarding.desktop_client(self.path)


class ConsentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.policy = google.GooglePolicy.from_runtime(runtime_document())
        self.urls = []

    def browser(self, *, error=None, invalid_first=False):
        def open_browser(url, **kwargs):
            self.urls.append(url)
            parsed = urllib.parse.urlsplit(url)
            self.assertEqual((parsed.scheme, parsed.netloc, parsed.path), ("https", "accounts.google.com", "/o/oauth2/v2/auth"))
            query = urllib.parse.parse_qs(parsed.query)
            self.assertEqual(query["include_granted_scopes"], ["false"])
            self.assertEqual(query["access_type"], ["offline"])
            self.assertEqual(query["prompt"], ["consent"])
            self.assertEqual(set(query["scope"][0].split()), set(google.SCOPES))
            self.assertEqual(query["code_challenge_method"], ["S256"])
            redirect = query["redirect_uri"][0]
            self.assertEqual(urllib.parse.urlsplit(redirect).hostname, "127.0.0.1")
            state = query["state"][0]

            def request(values, headers=None):
                request = urllib.request.Request(redirect + "?" + urllib.parse.urlencode(values, doseq=True), headers=headers or {})
                try:
                    with urllib.request.urlopen(request, timeout=3) as response:
                        return response.status, response.read().decode(), response.headers
                except urllib.error.HTTPError as raised:
                    return raised.code, raised.read().decode(), raised.headers

            if invalid_first:
                for values, headers in (
                    ({"state": "wrong", "code": "ignored"}, None),
                    ({"state": "\u2603", "code": "ignored"}, None),
                    ({"state": [state, state], "code": "ignored"}, None),
                    ({"state": state, "code": "ignored"}, {"Host": "attacker.test"}),
                    ({"state": state, "code": ["one", "two"]}, None),
                ):
                    status, body, _ = request(values, headers)
                    self.assertEqual(status, 400)
                    self.assertNotIn(state, body)
            values = {"state": state, "error": error} if error else {"state": state, "code": "test-authorization-code"}
            status, body, headers = request(values)
            self.assertEqual(status, 400 if error else 200)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertEqual(headers["Referrer-Policy"], "no-referrer")
            self.assertNotIn(state, body)
            return True
        return open_browser

    async def test_real_loopback_pkce_state_and_bounded_token_exchange(self):
        transport = FakeTransport(token=google.HTTPResult(200, token_document(refresh_token=REFRESH_TOKEN)))
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            response = await onboarding.consent(desktop_document(), self.policy, transport, open_browser=self.browser(invalid_first=True))
        self.assertEqual(response["refresh_token"], REFRESH_TOKEN)
        self.assertEqual([op for op, _ in transport.calls], ["token"])
        form = transport.calls[0][1]["form"]
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.urls[0]).query)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).decode().rstrip("=")
        self.assertEqual(query["code_challenge"], [challenge])
        self.assertEqual(form["grant_type"], "authorization_code")
        self.assertEqual(form["redirect_uri"], query["redirect_uri"][0])
        self.assertEqual(form["client_id"], CLIENT_ID)
        self.assertEqual(form["client_secret"], CLIENT_SECRET)
        self.assertNotIn("scope", form)
        self.assertNotIn(CLIENT_SECRET, self.urls[0])
        self.assertNotIn(REFRESH_TOKEN, self.urls[0])
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

    async def test_cancelled_consent_never_exchanges_a_token(self):
        transport = FakeTransport()
        with self.assertRaises(onboarding.OnboardingError) as raised:
            await onboarding.consent(desktop_document(), self.policy, transport, open_browser=self.browser(error="access_denied"))
        self.assertEqual(raised.exception.code, "consent_cancelled")
        self.assertEqual(transport.calls, [])

    async def test_missing_browser_and_timeout_are_explicit(self):
        with self.assertRaises(onboarding.OnboardingError) as raised:
            await onboarding.consent(desktop_document(), self.policy, FakeTransport(), open_browser=lambda *a, **k: False)
        self.assertEqual(raised.exception.code, "browser_unavailable")
        with patch.object(onboarding, "CONSENT_TIMEOUT_SECONDS", 0.02):
            with self.assertRaises(onboarding.OnboardingError) as raised:
                await onboarding.consent(desktop_document(), self.policy, FakeTransport(), open_browser=lambda *a, **k: True)
        self.assertEqual(raised.exception.code, "consent_timeout")

    async def test_missing_host_dependency_has_a_sanitized_install_diagnostic(self):
        with patch.dict(sys.modules, {"google_auth_oauthlib.flow": None}):
            with self.assertRaises(onboarding.OnboardingError) as raised:
                await onboarding.consent(desktop_document(), self.policy, FakeTransport(), open_browser=lambda *a, **k: False)
        self.assertEqual(raised.exception.code, "host_config_failed")
        with patch.dict(sys.modules, {"aiohttp": None}):
            with self.assertRaises(google.GoogleError) as raised:
                async with google.GoogleHTTP():
                    pass
        self.assertEqual(raised.exception.code, "dependency_missing")

    async def test_token_endpoint_error_is_sanitized(self):
        transport = FakeTransport(token=google.HTTPResult(400, {"error": CLIENT_SECRET, "error_description": ACCESS_TOKEN}))
        with self.assertRaises(onboarding.OnboardingError) as raised:
            await onboarding.consent(desktop_document(), self.policy, transport, open_browser=self.browser())
        self.assertEqual(raised.exception.code, "consent_failed")
        self.assertNotIn(CLIENT_SECRET, str(raised.exception))
        self.assertNotIn(ACCESS_TOKEN, str(raised.exception))

    async def test_consent_and_refresh_grant_must_both_be_verified_before_bytes_exist(self):
        for transport in (
            FakeTransport(profile=google.HTTPResult(200, {"emailAddress": "wrong@example.test"})),
            FakeTransport(tokeninfo=google.HTTPResult(200, {"scope": "openid", "aud": CLIENT_ID, "expires_in": 3600})),
            FakeTransport(token=google.HTTPResult(400, {"error": "invalid_grant"})),
            FakeTransport(token=google.HTTPResult(200, token_document(refresh_token="rotated"))),
        ):
            with self.assertRaises(google.GoogleError):
                await google.verified_oauth_credential(
                    self.policy, client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
                    token_response=token_document(refresh_token=REFRESH_TOKEN), transport=transport,
                )


class UploadDelegationTests(unittest.TestCase):
    def setUp(self):
        self.policy = google.GooglePolicy.from_runtime(runtime_document())
        self.content = json.dumps(credential_document()).encode()
        self.sandbox = object()

    def test_delegates_in_memory_bytes_exactly_once_to_b_helper(self):
        uploader = Mock()
        with patch("subprocess.run", side_effect=AssertionError("No shell credential args")), patch("pathlib.Path.write_bytes", side_effect=AssertionError("No host credential file")):
            onboarding.upload_verified_credential(
                self.sandbox, content=self.content, local_policy=self.policy,
                deployed_runtime=runtime_document(), uploader=uploader,
            )
        uploader.assert_called_once_with(
            self.sandbox, destination="/mnt/data/secrets/google/credentials.json", content=self.content,
        )

    def test_lazy_import_calls_only_the_shared_uploader(self):
        helper = types.ModuleType("hermes_common")
        helper.upload_private_file = Mock()
        with patch.dict(sys.modules, {"hermes_common": helper}):
            onboarding.upload_verified_credential(
                self.sandbox, content=self.content, local_policy=self.policy,
                deployed_runtime=runtime_document(),
            )
        helper.upload_private_file.assert_called_once()
        self.assertIs(helper.upload_private_file.call_args.kwargs["content"], self.content)

    def test_policy_change_blocks_upload(self):
        uploader = Mock()
        with self.assertRaises(onboarding.OnboardingError) as raised:
            onboarding.upload_verified_credential(
                self.sandbox, content=self.content, local_policy=self.policy,
                deployed_runtime=runtime_document(expected_email="changed@example.test"), uploader=uploader,
            )
        self.assertEqual(raised.exception.code, "runtime_changed")
        uploader.assert_not_called()

    def test_failed_injected_atomic_uploader_preserves_previous_file(self):
        files = PrivateFiles()
        self.addCleanup(files.close)
        old = files.credential.read_bytes()

        def failed_upload(sandbox, *, destination, content):
            self.assertEqual(destination, str(google.CREDENTIAL_PATH))
            staging = files.credential.with_name(".staging-test")
            try:
                descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                self.assertEqual(staging.stat().st_mode & 0o777, 0o600)
                raise OSError("injected failure containing " + REFRESH_TOKEN)
            finally:
                staging.unlink()

        with self.assertRaises(onboarding.OnboardingError) as raised:
            onboarding.upload_verified_credential(
                self.sandbox, content=self.content, local_policy=self.policy,
                deployed_runtime=runtime_document(), uploader=failed_upload,
            )
        self.assertEqual(raised.exception.code, "upload_failed")
        self.assertNotIn(REFRESH_TOKEN, str(raised.exception))
        self.assertEqual(files.credential.read_bytes(), old)
        self.assertEqual(list(files.credential.parent.iterdir()), [files.credential])

    def shared_helpers(self):
        helper = types.ModuleType("hermes_common")
        helper.Config = Mock()
        helper.AzureClients = Mock()
        helper.AzureClients.create.return_value = MagicMock()
        helper.get_sandbox = Mock(return_value=self.sandbox)
        helper.runtime_document = Mock(return_value=runtime_document())
        helper.read_runtime = Mock(return_value=runtime_document())
        helper.upload_private_file = Mock()
        return helper

    def test_cli_loads_only_hermes_config_and_reports_explicit_reconfigure(self):
        helper = self.shared_helpers()
        stdout, stderr = io.StringIO(), io.StringIO()
        client_path, env_path = Path("/local/desktop-client.json"), Path("/local/.env.hermes")
        with patch.dict(sys.modules, {"hermes_common": helper}), patch.object(onboarding, "authorize", AsyncMock(return_value=self.content)) as authorize, contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = onboarding.main(["connect", "--client-secrets", str(client_path), "--env-file", str(env_path)])
        self.assertEqual(result, 0)
        helper.Config.from_env.assert_called_once_with(env_path=env_path)
        authorize.assert_awaited_once_with(client_path, self.policy)
        helper.upload_private_file.assert_called_once()
        self.assertIn("reconfigure", stdout.getvalue())
        self.assertIn("seven days", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        for secret in (CLIENT_SECRET, REFRESH_TOKEN, ACCESS_TOKEN):
            self.assertNotIn(secret, stdout.getvalue())

    def test_cli_never_uploads_or_opens_azure_clients_after_bad_google_grant(self):
        helper = self.shared_helpers()
        with patch.dict(sys.modules, {"hermes_common": helper}), patch.object(onboarding, "authorize", AsyncMock(side_effect=google.GoogleError("scope_mismatch"))), contextlib.redirect_stderr(io.StringIO()):
            result = onboarding.main(["connect", "--client-secrets", "/local/desktop-client.json"])
        self.assertEqual(result, 1)
        helper.AzureClients.create.assert_not_called()
        helper.upload_private_file.assert_not_called()

    def test_onboarding_calendar_404_gives_config_remedy_and_never_uploads(self):
        helper = self.shared_helpers()
        http = MagicMock()
        http.__aenter__ = AsyncMock(return_value=FakeTransport(
            events=google.HTTPResult(404, {"error": {"code": 404}}),
        ))
        http.__aexit__ = AsyncMock(return_value=None)
        stderr = io.StringIO()
        with patch.dict(sys.modules, {"hermes_common": helper}), patch.object(onboarding, "desktop_client", return_value=desktop_document()), patch.object(onboarding, "GoogleHTTP", return_value=http), patch.object(onboarding, "consent", AsyncMock(return_value=token_document(refresh_token=REFRESH_TOKEN))), contextlib.redirect_stderr(stderr):
            result = onboarding.main(["connect", "--client-secrets", "/local/desktop-client.json"])
        self.assertEqual(result, 1)
        diagnostic = json.loads(stderr.getvalue())
        self.assertEqual(diagnostic["code"], "not_found")
        self.assertIn("calendar_ids", diagnostic["message"])
        helper.AzureClients.create.assert_not_called()
        helper.upload_private_file.assert_not_called()

    def test_sdk_and_unexpected_errors_never_echo_secret_payloads(self):
        for exception in (google.GoogleError("wrong_account"), RuntimeError(ACCESS_TOKEN + CLIENT_SECRET + REFRESH_TOKEN)):
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(onboarding, "connect", side_effect=exception), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = onboarding.main(["connect", "--client-secrets", "/local/desktop-client.json"])
            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue(), "")
            json.loads(stderr.getvalue())
            for secret in (ACCESS_TOKEN, CLIENT_SECRET, REFRESH_TOKEN):
                self.assertNotIn(secret, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
