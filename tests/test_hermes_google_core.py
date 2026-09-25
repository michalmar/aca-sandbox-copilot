from __future__ import annotations

import asyncio
import base64
import copy
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from collections import deque
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "hermes" / "image" / "google"))

import google_readonly as google

CLIENT_ID = "desktop-example.apps.googleusercontent.com"
CLIENT_SECRET = "test-client-secret-not-valid"
REFRESH_TOKEN = "test-refresh-not-a-real-token"
ACCESS_TOKEN = "test-access-not-a-real-token"
EMAIL = "owner@example.test"


def runtime_document(**google_values):
    return {
        "schema_version": 1,
        "foundry": {
            "endpoint": "https://model.example.test", "deployment": "test",
            "api_mode": "chat_completions", "context_length": 4096,
            "scope": "https://ai.azure.com/.default",
        },
        "owner": {
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "object_id": "00000000-0000-0000-0000-000000000002",
            "whatsapp_phone": "+420123456789",
        },
        "google": {
            "enabled": True, "expected_email": EMAIL, "calendar_ids": ["primary"],
            **google_values,
        },
    }


def credential_document(**values):
    return {
        "schema_version": 1, "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET, "refresh_token": REFRESH_TOKEN,
        "expected_email": EMAIL, "granted_scopes": list(google.SCOPES),
        "scope_verified_at": "2026-09-24T18:00:00Z", **values,
    }


def token_document(**values):
    return {
        "access_token": ACCESS_TOKEN, "token_type": "Bearer",
        "expires_in": 3600, **values,
    }


def text_part(text: str, *, mime: str = "text/plain", charset: str = "utf-8"):
    raw = text.encode(charset)
    return {
        "mimeType": mime, "filename": "",
        "headers": [{"name": "Content-Type", "value": f"{mime}; charset={charset}"}],
        "body": {"size": len(raw), "data": base64.urlsafe_b64encode(raw).decode().rstrip("=")},
    }


class FakeTransport:
    def __init__(self, **overrides):
        self.overrides = overrides
        self.calls = []

    async def request(self, operation, **kwargs):
        self.calls.append((operation, copy.deepcopy(kwargs)))
        if operation in self.overrides:
            value = self.overrides[operation]
            if isinstance(value, deque):
                value = value.popleft()
            if isinstance(value, Exception):
                raise value
            return copy.deepcopy(value)
        defaults = {
            "token": google.HTTPResult(200, token_document()),
            "tokeninfo": google.HTTPResult(200, {
                "scope": " ".join(google.SCOPES), "aud": CLIENT_ID, "azp": CLIENT_ID,
                "expires_in": "3600",
            }),
            "profile": google.HTTPResult(200, {"emailAddress": EMAIL}),
            "messages": google.HTTPResult(200, {
                "messages": [{"id": "abc123", "threadId": "def456"}], "resultSizeEstimate": 1,
            }),
            "message": google.HTTPResult(200, {"id": "abc123", "payload": text_part("A harmless test message.")}),
            "events": google.HTTPResult(200, {"items": [{
                "id": "event123", "summary": "Test event", "status": "confirmed",
                "start": {"dateTime": "2026-09-24T12:00:00+02:00"},
                "end": {"dateTime": "2026-09-24T13:00:00+02:00"},
            }]}),
        }
        if operation not in defaults:
            raise AssertionError("Unexpected Google operation")
        return copy.deepcopy(defaults[operation])


class PrivateFiles:
    def __init__(self, **google_values):
        self.temp = tempfile.TemporaryDirectory(prefix="hermes-google-test-")
        self.root = Path(self.temp.name)
        self.runtime = self.root / "hermes" / "runtime.json"
        self.credential = self.root / "secrets" / "google" / "credentials.json"
        self.runtime.parent.mkdir(mode=0o700)
        self.credential.parent.parent.mkdir(mode=0o700)
        self.credential.parent.mkdir(mode=0o700)
        self.runtime.write_text(json.dumps(runtime_document(**google_values)), encoding="utf-8")
        self.credential.write_text(json.dumps(credential_document()), encoding="utf-8")
        self.runtime.chmod(0o600)
        self.credential.chmod(0o600)

    def close(self):
        self.temp.cleanup()


class PolicyAndCredentialTests(unittest.TestCase):
    def setUp(self):
        self.files = PrivateFiles()
        self.addCleanup(self.files.close)
        self.policy = google.GooglePolicy.from_runtime(runtime_document())

    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(google.GoogleError) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)
        for secret in (CLIENT_SECRET, REFRESH_TOKEN, ACCESS_TOKEN):
            self.assertNotIn(secret, str(raised.exception))

    def test_canonical_policy_only(self):
        policy = google.load_policy(self.files.runtime)
        self.assertEqual(policy.expected_email, EMAIL)
        self.assertEqual(policy.calendar_ids, ("primary",))
        for change in (
            {"schema_version": True}, {"schema_version": 2}, {"token": "not-allowed"},
            {"foundry": []}, {"google": {"enabled": True}},
        ):
            with self.subTest(change=change):
                self.assert_code("runtime_invalid", google.GooglePolicy.from_runtime, {**runtime_document(), **change})

    def test_google_policy_rejects_invalid_and_duplicate_fields(self):
        changes = [
            {"enabled": 1}, {"expected_email": None}, {"expected_email": "bad"},
            {"expected_email": "owner@example.test "}, {"calendar_ids": []},
            {"calendar_ids": "primary"}, {"calendar_ids": ["primary", "primary"]},
            {"calendar_ids": ["../primary"]}, {"calendar_ids": ["x" * 257]},
            {"calendar_ids": ["calendar"] * 51}, {"access_token": "not-allowed"},
        ]
        for change in changes:
            with self.subTest(change=change):
                self.assert_code("runtime_invalid", google.GooglePolicy.from_runtime, runtime_document(**change))
        disabled = google.GooglePolicy.from_runtime(runtime_document(enabled=False, expected_email="", calendar_ids=[]))
        self.assertFalse(disabled.enabled)

    def test_duplicate_json_and_nonstandard_constants_are_rejected(self):
        self.assert_code("runtime_invalid", google.json_object, b'{"schema_version":1,"schema_version":1}', "runtime_invalid")
        self.assert_code("runtime_invalid", google.json_object, b'{"value":NaN}', "runtime_invalid")

    def test_credential_contains_refresh_only_and_is_redacted(self):
        credential = google.load_credential(self.policy, self.files.credential)
        self.assertEqual(json.loads(credential.to_bytes()), credential_document())
        self.assertNotIn(CLIENT_SECRET, repr(credential))
        self.assertNotIn(REFRESH_TOKEN, repr(credential))
        self.assertNotIn("access_token", json.loads(credential.to_bytes()))
        self.assertNotIn("token_uri", json.loads(credential.to_bytes()))

    def test_credential_schema_and_claims_are_strict(self):
        for change, code in [
            ({"schema_version": True}, "credentials_invalid"),
            ({"token_uri": "https://attacker.test"}, "credentials_invalid"),
            ({"access_token": ACCESS_TOKEN}, "credentials_invalid"),
            ({"client_id": "https://attacker.test"}, "credentials_invalid"),
            ({"client_secret": ""}, "credentials_invalid"),
            ({"refresh_token": ""}, "credentials_invalid"),
            ({"scope_verified_at": "yesterday"}, "credentials_invalid"),
            ({"scope_verified_at": "2026-09-24T18:00:00+00:00"}, "credentials_invalid"),
            ({"expected_email": "wrong@example.test"}, "wrong_account"),
            ({"granted_scopes": None}, "scope_unproven"),
            ({"granted_scopes": [google.SCOPES[0]]}, "scope_mismatch"),
            ({"granted_scopes": list(google.SCOPES) + ["openid"]}, "scope_mismatch"),
        ]:
            with self.subTest(change=change):
                self.assert_code(code, google.GoogleCredential.from_document, credential_document(**change), self.policy)

    def test_offline_status_never_claims_live_verification(self):
        self.assertEqual(google.credential_status(self.files.runtime, self.files.credential)["status"], "configured")
        self.assertFalse(google.credential_status(self.files.runtime, self.files.credential)["live_verified"])
        self.files.credential.unlink()
        self.assertEqual(google.credential_status(self.files.runtime, self.files.credential)["status"], "not-connected")
        self.files.runtime.write_text(json.dumps(runtime_document(enabled=False)), encoding="utf-8")
        self.assertEqual(google.credential_status(self.files.runtime, self.files.credential)["status"], "disabled")

    @unittest.skipUnless(os.name == "posix", "Sandbox credential permission checks are POSIX.")
    def test_private_modes_and_symlinks_fail_closed(self):
        for path in (self.files.credential.parent.parent, self.files.credential.parent, self.files.credential):
            with self.subTest(path=path.name):
                old_mode = path.stat().st_mode & 0o777
                path.chmod(0o755 if path.is_dir() else 0o644)
                self.assert_code("credentials_permissions", google.load_credential, self.policy, self.files.credential)
                path.chmod(old_mode)
        target = self.files.credential.with_name("saved.json")
        self.files.credential.rename(target)
        self.files.credential.symlink_to(target)
        self.assert_code("credentials_permissions", google.load_credential, self.policy, self.files.credential)

    @unittest.skipUnless(os.name == "posix", "Sandbox credential files are POSIX.")
    def test_hardlinks_and_fifos_are_rejected_without_blocking(self):
        linked = self.files.credential.with_name("linked.json")
        os.link(self.files.credential, linked)
        self.assert_code("credentials_permissions", google.load_credential, self.policy, self.files.credential)
        linked.unlink()
        self.files.credential.unlink()
        os.mkfifo(self.files.credential, mode=0o600)
        self.assert_code("credentials_io", google.load_credential, self.policy, self.files.credential)

    def test_offline_import_and_status_need_only_standard_library(self):
        script = (
            "import json,sys; from pathlib import Path; "
            "sys.path.insert(0,sys.argv[1]); import google_readonly; "
            "assert 'aiohttp' not in sys.modules; "
            "print(json.dumps(google_readonly.credential_status(Path(sys.argv[2]),Path(sys.argv[3]))))"
        )
        result = subprocess.run(
            [sys.executable, "-S", "-c", script, str(ROOT / "hermes" / "image" / "google"),
             str(self.files.runtime), str(self.files.credential)],
            check=True, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(json.loads(result.stdout)["status"], "configured")
        self.assertEqual(result.stderr, "")

    def test_bad_file_is_not_a_healthy_empty_configuration(self):
        self.files.credential.write_bytes(b"x" * (google.MAX_DOCUMENT_BYTES + 1))
        self.assertEqual(google.credential_status(self.files.runtime, self.files.credential)["status"], "reconnect-required")
        self.files.runtime.write_bytes(b"not json")
        self.assertEqual(google.credential_status(self.files.runtime, self.files.credential)["status"], "failed")


class ArgumentTests(unittest.TestCase):
    def setUp(self):
        self.policy = google.GooglePolicy.from_runtime(runtime_document())
        self.times = {"time_min": "2026-09-01T00:00:00Z", "time_max": "2026-10-02T00:00:00Z"}

    def reject(self, name, arguments):
        with self.assertRaises(google.GoogleError):
            google.validate_arguments(self.policy, name, arguments)

    def test_search_bounds_and_defaults(self):
        good = google.validate_arguments(self.policy, "gmail_search", {"query": "x" * 512})
        self.assertEqual(good["max_results"], 10)
        for query in ("", "   ", "x" * 513, None, True, "x\nsecret", "\ud800"):
            with self.subTest(query=repr(query)):
                self.reject("gmail_search", {"query": query})
        for maximum in (True, False, 0, 21, "10", 1.0, None):
            with self.subTest(maximum=maximum):
                self.reject("gmail_search", {"query": "x", "max_results": maximum})
        for maximum in (1, 20):
            self.assertEqual(google.validate_arguments(self.policy, "gmail_search", {"query": "x", "max_results": maximum})["max_results"], maximum)

    def test_page_token_is_bounded_opaque_data_not_a_url(self):
        for token in ("x" * 1024, "abc_-./+=~123"):
            self.assertEqual(google.validate_arguments(self.policy, "gmail_search", {"query": "x", "page_token": token})["page_token"], token)
        for token in ("x" * 1025, "", None, True, "x&access_token=secret", "https://attacker.test", "x\n"):
            with self.subTest(token=repr(token)):
                self.reject("gmail_search", {"query": "x", "page_token": token})

    def test_only_validated_message_ids(self):
        for identifier in ("a", "f" * 64, "ABC123"):
            google.validate_arguments(self.policy, "gmail_read", {"message_id": identifier})
        for identifier in ("", "g123", "f" * 65, "me/messages", "../123", "abc?format=raw", 123, True):
            with self.subTest(identifier=identifier):
                self.reject("gmail_read", {"message_id": identifier})

    def test_calendar_allowlist_not_widened_by_defaults(self):
        self.assertEqual(google.validate_arguments(self.policy, "calendar_events", self.times)["calendar_id"], "primary")
        self.assertEqual(google.validate_arguments(self.policy, "calendar_events", self.times)["max_results"], 50)
        for calendar in ("other@example.test", "PRIMARY", True, ["primary"]):
            self.reject("calendar_events", {**self.times, "calendar_id": calendar})
        for count in (0, 51, True, "10", 10.0):
            self.reject("calendar_events", {**self.times, "max_results": count})

    def test_nonprimary_policy_requires_an_explicit_calendar(self):
        self.policy = google.GooglePolicy.from_runtime(runtime_document(calendar_ids=["team@group.calendar.google.com"]))
        self.reject("calendar_events", self.times)
        result = google.validate_arguments(self.policy, "calendar_events", {
            **self.times, "calendar_id": "team@group.calendar.google.com",
        })
        self.assertEqual(result["calendar_id"], "team@group.calendar.google.com")

    def test_calendar_exact_elapsed_31_days_and_nanoseconds(self):
        google.validate_arguments(self.policy, "calendar_events", self.times)
        google.validate_arguments(self.policy, "calendar_events", {
            "time_min": "2026-09-01T02:00:00+02:00", "time_max": "2026-10-02T00:00:00Z",
        })
        self.reject("calendar_events", {**self.times, "time_max": "2026-10-02T00:00:00.000000001Z"})
        self.reject("calendar_events", {**self.times, "time_max": self.times["time_min"]})
        self.reject("calendar_events", {**self.times, "time_max": "2026-08-31T23:59:59Z"})

    def test_calendar_requires_explicit_valid_timezone(self):
        for value in (
            "2026-09-01", "2026-09-01T00:00:00", "2026-09-01 00:00:00Z",
            "2026-09-01T00:00:00-00:00", "2026-09-01T00:00:00+00:99",
            "2026-09-01T00:00:00+24:00", "2026-02-30T00:00:00Z",
            "2026-09-01T00:00:60Z", True, None,
        ):
            with self.subTest(value=value):
                self.reject("calendar_events", {**self.times, "time_min": value})

    def test_calendar_fractional_digits_must_be_ascii(self):
        for digit in ("\u0661", "\uff11"):
            with self.subTest(digit=digit):
                with self.assertRaises(google.GoogleError) as raised:
                    google.validate_arguments(self.policy, "calendar_events", {
                        **self.times, "time_min": f"2026-09-01T00:00:00.{digit}Z",
                    })
                self.assertEqual(raised.exception.code, "invalid_time_range")

    def test_extra_arguments_and_write_tools_are_not_executable(self):
        for name in ("gmail_send", "gmail_modify", "event_insert", "calendar_delete", "fetch", "shell", "status"):
            self.reject(name, {})
        for args in (None, [], {}, {"query": "x", "url": "https://attacker.test"}, {"query": "x", "method": "POST"}):
            self.reject("gmail_search", args)


class MimeTests(unittest.TestCase):
    def test_alternative_prefers_plain_and_does_not_fetch_attachments(self):
        payload = {"mimeType": "multipart/mixed", "parts": [
            {"mimeType": "multipart/alternative", "parts": [
                text_part("Plain message"), text_part("<p>Duplicate HTML</p>", mime="text/html"),
            ]},
            {"mimeType": "text/plain", "filename": "private.txt", "body": {"attachmentId": "DO-NOT-FETCH", "data": "!!!", "size": 2**40}},
            {"mimeType": "message/rfc822", "body": {}, "parts": [text_part("Attached email")]},
        ]}
        text, truncated, omitted = google.message_text(payload)
        self.assertEqual(text, "Plain message")
        self.assertFalse(truncated)
        self.assertTrue(omitted)

    def test_attachment_disposition_and_externalized_text_are_not_decoded(self):
        payload = text_part("Do not return")
        payload["headers"].append({"name": "Content-Disposition", "value": "attachment; filename=secret.txt"})
        self.assertEqual(google.message_text(payload), ("", False, True))
        payload = text_part("Do not return")
        payload["body"]["attachmentId"] = "not-fetched"
        self.assertEqual(google.message_text(payload), ("", False, True))

    def test_html_text_has_no_script_style_or_remote_fetch(self):
        html = '<head>hidden</head><p>Hello &amp; welcome</p><script>steal()</script><style>hidden</style><img src="https://attacker.test"><p>Visible</p>'
        text, truncated, omitted = google.message_text(text_part(html, mime="text/html"))
        self.assertIn("Hello & welcome", text)
        self.assertIn("Visible", text)
        for hidden in ("steal", "hidden", "attacker.test"):
            self.assertNotIn(hidden, text)
        self.assertFalse(truncated)
        self.assertFalse(omitted)

    def test_charset_and_maximum_text_characters(self):
        text, truncated, _ = google.message_text(text_part("Příliš žluťoučký", charset="iso-8859-2"))
        self.assertEqual(text, "Příliš žluťoučký")
        text, truncated, _ = google.message_text(text_part("x" * (google.MAX_TEXT_CHARS + 1)))
        self.assertEqual(len(text), 16_000)
        self.assertTrue(truncated)

    def test_text_keeps_czech_and_emoji_but_removes_invisible_controls(self):
        raw = "Příliš \u202ežluťoučký\u202c \U0001f469\u200d\U0001f4bb\U000e0061\x00\ntext"
        text, _, _ = google.message_text(text_part(raw))
        self.assertEqual(text, "Příliš žluťoučký \U0001f469\u200d\U0001f4bb\ntext")

    def test_decoded_size_is_actual_and_cumulative(self):
        for payload in (
            text_part("x" * (google.MAX_DECODED_BYTES + 1)),
            {"mimeType": "multipart/mixed", "parts": [text_part("x" * 150_000), text_part("y" * 150_000)]},
        ):
            with self.assertRaises(google.GoogleError) as raised:
                google.message_text(payload)
            self.assertEqual(raised.exception.code, "payload_limit")
        payload = text_part("x" * (google.MAX_DECODED_BYTES + 1))
        payload["body"]["size"] = 1
        with self.assertRaises(google.GoogleError):
            google.message_text(payload)

    def test_invalid_base64_charset_and_tree_are_explicit(self):
        malformed = text_part("test")
        malformed["body"]["data"] = "%%%"
        bad_charset = text_part("test")
        bad_charset["headers"][0]["value"] = "text/plain; charset=no-such-codec"
        deep = text_part("deep")
        for _ in range(14):
            deep = {"mimeType": "multipart/mixed", "parts": [deep]}
        for payload in (None, malformed, bad_charset, deep, {"parts": [text_part("x")] * 129}):
            with self.subTest(payload_type=type(payload).__name__):
                with self.assertRaises(google.GoogleError):
                    google.message_text(payload)


class GoogleClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.policy = google.GooglePolicy.from_runtime(runtime_document())
        self.credential = google.GoogleCredential.from_document(credential_document(), self.policy)

    def client(self, transport=None):
        return google.GoogleClient(self.policy, self.credential, transport or FakeTransport())

    async def assert_async_code(self, code, awaitable):
        with self.assertRaises(google.GoogleError) as raised:
            await awaitable
        self.assertEqual(raised.exception.code, code)
        for secret in (ACCESS_TOKEN, REFRESH_TOKEN, CLIENT_SECRET):
            self.assertNotIn(secret, str(raised.exception))

    async def test_startup_proves_live_scopes_client_and_profile(self):
        transport = FakeTransport()
        client = self.client(transport)
        await client.ensure_ready()
        self.assertEqual([operation for operation, _ in transport.calls], ["token", "tokeninfo", "profile"])
        self.assertEqual(transport.calls[0][1]["form"]["grant_type"], "refresh_token")
        self.assertNotIn("scope", transport.calls[0][1]["form"])
        self.assertEqual(transport.calls[1][1]["form"], {"access_token": ACCESS_TOKEN})
        self.assertNotIn("params", transport.calls[1][1])
        self.assertEqual(transport.calls[2][1]["token"], ACCESS_TOKEN)
        self.assertEqual(client._token, ACCESS_TOKEN)

    async def test_persisted_claims_cannot_authorize_broad_narrow_unknown_live_scopes(self):
        for scopes, code in (
            (None, "scope_unproven"), ("", "scope_unproven"), (True, "scope_unproven"),
            (google.SCOPES[0], "scope_mismatch"),
            (" ".join(google.SCOPES) + " openid", "scope_mismatch"),
            ("https://www.googleapis.com/auth/gmail.modify", "scope_mismatch"),
        ):
            transport = FakeTransport(tokeninfo=google.HTTPResult(200, {
                "scope": scopes, "aud": CLIENT_ID, "expires_in": "3600",
            }))
            client = self.client(transport)
            await self.assert_async_code(code, client.ensure_ready())
            self.assertIsNone(client._token)
            self.assertNotIn("profile", [operation for operation, _ in transport.calls])

    async def test_wrong_account_client_or_missing_evidence_rejected(self):
        cases = [
            ("wrong_account", {"profile": google.HTTPResult(200, {"emailAddress": "wrong@example.test"})}),
            ("wrong_account", {"profile": google.HTTPResult(200, {})}),
            ("wrong_client", {"tokeninfo": google.HTTPResult(200, {"scope": " ".join(google.SCOPES), "aud": "attacker", "expires_in": 3600})}),
            ("token_invalid", {"tokeninfo": google.HTTPResult(200, {"scope": " ".join(google.SCOPES), "aud": CLIENT_ID})}),
        ]
        for code, overrides in cases:
            await self.assert_async_code(code, self.client(FakeTransport(**overrides)).ensure_ready())
        await self.client(FakeTransport(profile=google.HTTPResult(200, {"emailAddress": EMAIL.upper()}))).ensure_ready()

    async def test_profile_api_denial_is_recoverable_not_invalid_credentials(self):
        for status in (400, 403):
            transport = FakeTransport(profile=google.HTTPResult(status, {"error": {"message": "API disabled"}}))
            client = self.client(transport)
            await self.assert_async_code("api_denied", client.ensure_ready())
            self.assertIsNone(client._terminal_error)
            self.assertIsNone(client._token)
            del transport.overrides["profile"]
            result = await client.call("gmail_search", {"query": "safe"})
            self.assertIn("messages", result)
        transport = FakeTransport(profile=google.HTTPResult(401, {"error": "invalid token"}))
        client = self.client(transport)
        await self.assert_async_code("access_revoked", client.ensure_ready())
        await self.assert_async_code("access_revoked", client.ensure_ready())
        self.assertEqual([op for op, _ in transport.calls].count("profile"), 1)

    async def test_onboarding_api_denial_has_the_correct_remedy_and_no_bytes(self):
        for operation in ("profile", "events"):
            transport = FakeTransport(**{operation: google.HTTPResult(403, {"error": {"message": "API disabled"}})})
            await self.assert_async_code("api_denied", google.verified_oauth_credential(
                self.policy, client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
                token_response=token_document(refresh_token=REFRESH_TOKEN), transport=transport,
            ))

    async def test_profile_403_quota_is_retryable_and_never_latched(self):
        transport = FakeTransport(profile=google.HTTPResult(403, {"error": {
            "errors": [{"reason": "userRateLimitExceeded", "message": ACCESS_TOKEN}],
        }}))
        client = self.client(transport)
        await self.assert_async_code("rate_limited", client.ensure_ready())
        self.assertIsNone(client._terminal_error)
        self.assertIsNone(client._token)
        del transport.overrides["profile"]
        await client.ensure_ready()
        self.assertEqual(client._token, ACCESS_TOKEN)

    async def test_refresh_expiration_is_memory_only_and_rechecks_scope_account(self):
        transport = FakeTransport()
        client = self.client(transport)
        await client.ensure_ready()
        original = self.credential.to_bytes()
        client._expires_at = time.monotonic() - 1
        with patch("pathlib.Path.write_bytes", side_effect=AssertionError("No file write")), patch("pathlib.Path.write_text", side_effect=AssertionError("No file write")):
            await client.call("gmail_search", {"query": "safe"})
        self.assertEqual([operation for operation, _ in transport.calls].count("tokeninfo"), 2)
        self.assertEqual([operation for operation, _ in transport.calls].count("profile"), 2)
        self.assertEqual(self.credential.to_bytes(), original)

    async def test_refresh_revocation_rotation_and_malformed_tokens_latch_reconnect(self):
        for response, code in (
            (google.HTTPResult(400, {"error": "invalid_grant", "error_description": REFRESH_TOKEN}), "refresh_revoked"),
            (google.HTTPResult(200, token_document(refresh_token="rotated-test-token")), "refresh_rotated"),
            (google.HTTPResult(200, token_document(token_type=None)), "token_invalid"),
            (google.HTTPResult(200, token_document(expires_in=True)), "token_invalid"),
            (google.HTTPResult(200, token_document(expires_in=60)), "token_invalid"),
            (google.HTTPResult(200, token_document(scope=google.SCOPES[0])), "scope_mismatch"),
        ):
            transport = FakeTransport(token=response)
            client = self.client(transport)
            await self.assert_async_code(code, client.ensure_ready())
            await self.assert_async_code(code, client.ensure_ready())
            self.assertEqual(len(transport.calls), 1)
        await self.client(FakeTransport(token=google.HTTPResult(200, token_document(refresh_token=REFRESH_TOKEN)))).ensure_ready()

    async def test_non_oauth_error_bodies_do_not_latch_credentials_invalid(self):
        good = {
            "token": google.HTTPResult(200, token_document()),
            "tokeninfo": google.HTTPResult(200, {
                "scope": " ".join(google.SCOPES), "aud": CLIENT_ID, "expires_in": "3600",
            }),
        }
        for operation in ("token", "tokeninfo"):
            for status in (400, 403, 404):
                with self.subTest(operation=operation, status=status):
                    transport = FakeTransport(**{operation: deque([google.HTTPResult(status, {}), good[operation]])})
                    client = self.client(transport)
                    await self.assert_async_code("response_invalid", client.ensure_ready())
                    self.assertIsNone(client._terminal_error)
                    self.assertIsNone(client._token)
                    await client.ensure_ready()
                    self.assertEqual(client._token, ACCESS_TOKEN)
        client = self.client(FakeTransport(token=google.HTTPResult(401, {"error": "invalid_client"})))
        await self.assert_async_code("token_invalid", client.ensure_ready())
        self.assertIsNotNone(client._terminal_error)

    async def test_concurrent_refreshes_in_one_process_are_serialized(self):
        transport = FakeTransport()
        client = self.client(transport)
        await asyncio.gather(*(client.ensure_ready() for _ in range(8)))
        self.assertEqual([operation for operation, _ in transport.calls].count("token"), 1)

    async def test_refresh_scope_change_never_reaches_the_mail_api(self):
        transport = FakeTransport()
        client = self.client(transport)
        await client.ensure_ready()
        client._expires_at = 0
        transport.overrides["tokeninfo"] = google.HTTPResult(200, {
            "scope": " ".join(google.SCOPES) + " openid", "aud": CLIENT_ID, "expires_in": 3600,
        })
        await self.assert_async_code("scope_mismatch", client.call("gmail_search", {"query": "private query"}))
        self.assertNotIn("messages", [operation for operation, _ in transport.calls])

    async def test_unauthorized_read_reverifies_once_then_fails_explicitly(self):
        transport = FakeTransport(messages=google.HTTPResult(401, {"error": {"message": ACCESS_TOKEN}}))
        await self.assert_async_code("access_revoked", self.client(transport).call("gmail_search", {"query": "private query"}))
        operations = [operation for operation, _ in transport.calls]
        self.assertEqual(operations.count("token"), 2)
        self.assertEqual(operations.count("messages"), 2)

    async def test_search_returns_only_ids_and_one_page(self):
        transport = FakeTransport(messages=google.HTTPResult(200, {
            "messages": [{"id": "abc123", "threadId": "def456", "snippet": "Do not return"}],
            "nextPageToken": "opaque_123", "resultSizeEstimate": 30,
        }))
        result = await self.client(transport).call("gmail_search", {"query": "safe", "max_results": 1})
        self.assertEqual(result["messages"], [{"id": "abc123", "threadId": "def456"}])
        self.assertEqual(result["next_page_token"], "opaque_123")
        self.assertTrue(result["untrusted"])
        self.assertEqual([op for op, _ in transport.calls].count("messages"), 1)
        self.assertNotIn("message", [op for op, _ in transport.calls])

    async def test_message_projection_no_attachment_path_and_header_caps(self):
        payload = text_part("safe")
        payload["headers"].extend([
            {"name": "Subject", "value": "x" * 1025}, {"name": "X-Private", "value": "Do not return"},
        ])
        transport = FakeTransport(message=google.HTTPResult(200, {"id": "abc123", "payload": payload}))
        result = await self.client(transport).call("gmail_read", {"message_id": "abc123"})
        self.assertEqual(len(result["headers"]["subject"]), 1024)
        self.assertTrue(result["headers_truncated"])
        self.assertNotIn("x-private", result["headers"])
        self.assertEqual(result["text"], "safe")
        self.assertEqual([op for op, _ in transport.calls], ["token", "tokeninfo", "profile", "message"])
        self.assertEqual(transport.calls[-1][1]["params"]["format"], "full")

    async def test_missing_message_and_calendar_have_actionable_nonlatched_errors(self):
        transport = FakeTransport(message=google.HTTPResult(404, {"error": {"code": 404}}))
        client = self.client(transport)
        await self.assert_async_code("not_found", client.call("gmail_read", {"message_id": "abc123"}))
        self.assertIsNone(client._terminal_error)
        del transport.overrides["message"]
        self.assertEqual((await client.call("gmail_read", {"message_id": "abc123"}))["id"], "abc123")
        await self.assert_async_code("not_found", self.client(FakeTransport(
            events=google.HTTPResult(404, {"error": {"code": 404}}),
        )).probe_calendar())

    async def test_calendar_minimized_bounded_results_and_all_day(self):
        item = {
            "id": "event123", "summary": "x" * 513, "description": "d" * 1025,
            "location": "l" * 257, "start": {"date": "2026-09-24"},
            "end": {"date": "2026-09-25"}, "attendees": [{"email": "private@example.test"}],
        }
        transport = FakeTransport(events=google.HTTPResult(200, {"items": [item], "nextPageToken": "more"}))
        result = await self.client(transport).call("calendar_events", {
            "time_min": "2026-09-24T00:00:00Z", "time_max": "2026-09-25T00:00:00Z",
        })
        event = result["events"][0]
        self.assertTrue(event["truncated"])
        self.assertEqual(len(event["summary"]), 512)
        self.assertEqual(len(event["description"]), 1024)
        self.assertEqual(len(event["location"]), 256)
        self.assertNotIn("attendees", event)
        self.assertTrue(result["has_more"])
        self.assertEqual(transport.calls[-1][1]["params"]["maxResults"], "50")
        self.assertEqual(transport.calls[-1][1]["params"]["singleEvents"], "true")

    async def test_bad_inputs_never_make_http_calls(self):
        transport = FakeTransport()
        await self.assert_async_code("invalid_max_results", self.client(transport).call("gmail_search", {"query": "x", "max_results": True}))
        self.assertEqual(transport.calls, [])

    async def test_api_errors_and_oversized_lists_are_not_empty_success(self):
        for response, code in (
            (google.HTTPResult(403, {"error": ACCESS_TOKEN}), "api_denied"),
            (google.HTTPResult(429, {"error": ACCESS_TOKEN}), "rate_limited"),
            (google.HTTPResult(500, {"error": ACCESS_TOKEN}), "api_unavailable"),
            (google.HTTPResult(200, {"messages": [{"id": "a", "threadId": "b"}] * 21}), "response_invalid"),
            (google.HTTPResult(200, {"messages": None}), "response_invalid"),
            (google.HTTPResult(200, {"nextPageToken": "x" * 1025}), "response_invalid"),
        ):
            await self.assert_async_code(code, self.client(FakeTransport(messages=response)).call("gmail_search", {"query": "x"}))
        result = await self.client(FakeTransport(messages=google.HTTPResult(200, {"resultSizeEstimate": 0}))).call("gmail_search", {"query": "x"})
        self.assertEqual(result["messages"], [])

    async def test_total_tool_deadline_is_enforced_for_injected_transports_too(self):
        class SlowTransport(FakeTransport):
            async def request(self, operation, **kwargs):
                await asyncio.sleep(1)
                return await super().request(operation, **kwargs)

        with patch.object(google, "TOOL_TIMEOUT_SECONDS", 0.02):
            await self.assert_async_code("request_timeout", self.client(SlowTransport()).call("gmail_search", {"query": "x"}))

    async def test_result_cap_measures_utf8_not_ascii_escapes(self):
        transport = FakeTransport(message=google.HTTPResult(200, {"id": "abc123", "payload": text_part("Příliš \U0001f4bb")}))
        client = self.client(transport)
        result = await client.call("gmail_read", {"message_id": "abc123"})
        size = len(json.dumps(result, ensure_ascii=False).encode("utf-8"))
        with patch.object(google, "MAX_RESULT_BYTES", size):
            await client.call("gmail_read", {"message_id": "abc123"})
        with patch.object(google, "MAX_RESULT_BYTES", size - 1):
            await self.assert_async_code("result_limit", client.call("gmail_read", {"message_id": "abc123"}))

    async def test_calendar_status_probe_also_has_a_total_deadline(self):
        class SlowCalendar(FakeTransport):
            async def request(self, operation, **kwargs):
                if operation == "events":
                    await asyncio.sleep(1)
                return await super().request(operation, **kwargs)

        with patch.object(google, "TOOL_TIMEOUT_SECONDS", 0.02):
            await self.assert_async_code("request_timeout", self.client(SlowCalendar()).probe_calendar())

    async def test_onboarding_checks_consent_token_and_actual_refresh(self):
        transport = FakeTransport()
        content = await google.verified_oauth_credential(
            self.policy, client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
            token_response=token_document(refresh_token=REFRESH_TOKEN), transport=transport,
        )
        result = json.loads(content)
        self.assertEqual(result["granted_scopes"], list(google.SCOPES))
        self.assertEqual(result["refresh_token"], REFRESH_TOKEN)
        self.assertNotIn("access_token", result)
        self.assertEqual([op for op, _ in transport.calls], ["tokeninfo", "profile", "token", "tokeninfo", "profile", "events"])
        params = transport.calls[-1][1]["params"]
        self.assertEqual(params["fields"], "nextPageToken")
        self.assertEqual(params["maxResults"], "1")
        self.assertNotIn("items", params["fields"])


if __name__ == "__main__":
    unittest.main()
