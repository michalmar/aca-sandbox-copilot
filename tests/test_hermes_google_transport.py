from __future__ import annotations

import asyncio
import json
import traceback
import unittest
from collections import deque
from unittest.mock import Mock, patch

import aiohttp

from test_hermes_google_core import (
    ACCESS_TOKEN, CLIENT_ID, CLIENT_SECRET, EMAIL, credential_document,
    google, runtime_document, token_document,
)


class Response:
    def __init__(self, chunks, *, status=200, headers=None, content_length=None, delay=0):
        self.chunks = chunks
        self.status = status
        self.headers = headers or {}
        self.content_length = content_length
        self.delay = delay
        self.content = self

    async def __aenter__(self):
        await asyncio.sleep(self.delay)
        return self

    async def __aexit__(self, *_):
        return None

    async def iter_chunked(self, size):
        for chunk in self.chunks:
            await asyncio.sleep(self.delay)
            yield chunk


class Session:
    def __init__(self, response):
        self.response = response
        self.calls = []
        self.closed = False

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        response = self.response.popleft() if isinstance(self.response, deque) else self.response
        if isinstance(response, Exception):
            raise response
        return response

    async def close(self):
        self.closed = True


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def perform(self, response, *, operation="profile", **kwargs):
        session = Session(response)
        factory = Mock(return_value=session)
        with patch("aiohttp.ClientSession", factory):
            async with google.GoogleHTTP() as http:
                result = await http.request(operation, **kwargs)
        self.assertTrue(session.closed)
        return result, session, factory.call_args.kwargs

    async def reject(self, code, response):
        with self.assertRaises(google.GoogleError) as raised:
            await self.perform(response)
        self.assertEqual(raised.exception.code, code)
        formatted = "".join(traceback.format_exception(raised.exception))
        self.assertNotIn(ACCESS_TOKEN, formatted)
        self.assertNotIn(CLIENT_SECRET, formatted)

    async def test_fixed_url_tls_no_redirect_proxy_or_decompression(self):
        result, session, options = await self.perform(Response([b'{"emailAddress":"owner@example.test"}']), token=ACCESS_TOKEN)
        self.assertEqual(result.status, 200)
        method, url, arguments = session.calls[0]
        self.assertEqual((method, url), ("GET", google.GMAIL_URL + "/profile"))
        self.assertFalse(arguments["allow_redirects"])
        self.assertTrue(arguments["ssl"])
        self.assertEqual(arguments["headers"]["Authorization"], f"Bearer {ACCESS_TOKEN}")
        self.assertFalse(options["trust_env"])
        self.assertFalse(options["auto_decompress"])
        self.assertEqual(options["headers"]["Accept-Encoding"], "identity")
        self.assertEqual(options["timeout"].total, google.HTTP_TIMEOUT_SECONDS)

    async def test_declared_and_streaming_payload_limits(self):
        await self.reject("payload_limit", Response([], content_length=8 * 1024 + 1))
        await self.reject("payload_limit", Response([b"x" * 4096, b"x" * 4096, b"x"]))
        valid = b'{"data":"' + b"x" * (8192 - 11) + b'"}'
        self.assertEqual(len(valid), 8192)
        result, _, _ = await self.perform(Response([valid], content_length=8192))
        self.assertEqual(len(result.data["data"]), 8192 - 11)

    async def test_redirects_and_compression_are_explicit_errors(self):
        await self.reject("response_invalid", Response([], status=302, headers={"Location": "https://attacker.test/" + ACCESS_TOKEN}))
        await self.reject("response_invalid", Response([b"{}"], headers={"Content-Encoding": "gzip"}))

    async def test_bad_json_and_in_band_google_errors_are_not_logged(self):
        for data in (b"[]", b'{"error":NaN}', b'{"x":1,"x":2}', b"not json"):
            await self.reject("response_invalid", Response([data]))
        result, _, _ = await self.perform(Response([json.dumps({"error": ACCESS_TOKEN}).encode()], status=401))
        self.assertEqual(result.status, 401)
        self.assertNotIn(ACCESS_TOKEN, repr(result))

    async def test_non_json_error_bodies_preserve_failure_status_without_payload(self):
        for status in (403, 429, 500):
            result, _, _ = await self.perform(Response([f"<html>{ACCESS_TOKEN}</html>".encode()], status=status))
            self.assertEqual(result, google.HTTPResult(status, {}))
        await self.reject("response_invalid", Response([b"<html>not an API response</html>"]))

    async def test_tokeninfo_post_body_never_puts_access_token_in_url(self):
        _, session, _ = await self.perform(Response([b"{}"]), operation="tokeninfo", form={"access_token": ACCESS_TOKEN})
        method, url, arguments = session.calls[0]
        self.assertEqual((method, url), ("POST", google.TOKENINFO_URL))
        self.assertIsNone(arguments["params"])
        self.assertEqual(arguments["data"], {"access_token": ACCESS_TOKEN})
        self.assertNotIn(ACCESS_TOKEN, url)

    async def test_html_oauth_errors_recover_end_to_end_without_reconnect(self):
        def response(data):
            return Response([json.dumps(data).encode()])

        def successful_proof():
            return [
                response(token_document()),
                response({"scope": " ".join(google.SCOPES), "aud": CLIENT_ID, "expires_in": 3600}),
                response({"emailAddress": EMAIL}),
            ]

        policy = google.GooglePolicy.from_runtime(runtime_document())
        credential = google.GoogleCredential.from_document(credential_document(), policy)
        for operation in ("token", "tokeninfo"):
            responses = []
            if operation == "tokeninfo":
                responses.append(response(token_document()))
            responses.append(Response([b"<html>Non-OAuth frontend error</html>"], status=403))
            session = Session(deque(responses + successful_proof()))
            with patch("aiohttp.ClientSession", return_value=session):
                async with google.GoogleHTTP() as http:
                    client = google.GoogleClient(policy, credential, http)
                    with self.assertRaises(google.GoogleError) as raised:
                        await client.ensure_ready()
                    self.assertEqual(raised.exception.code, "response_invalid")
                    self.assertIsNone(client._terminal_error)
                    await client.ensure_ready()
                    self.assertEqual(client._token, ACCESS_TOKEN)
            self.assertTrue(session.closed)

    async def test_network_errors_drop_original_urls_and_tokens(self):
        await self.reject("network_error", aiohttp.ClientConnectionError(f"GET {google.TOKENINFO_URL}?access_token={ACCESS_TOKEN} {CLIENT_SECRET}"))

    async def test_total_deadline_includes_response_and_stream_time(self):
        with patch.object(google, "HTTP_TIMEOUT_SECONDS", 0.02):
            await self.reject("request_timeout", Response([b"{}"], delay=0.04))
            await self.reject("request_timeout", Response([b"{", b"}"], delay=0.012))

    def test_no_google_write_or_generic_http_endpoint(self):
        expected = {
            "token": "POST", "tokeninfo": "POST", "profile": "GET", "messages": "GET",
        }
        for operation, method in expected.items():
            self.assertEqual(google.GoogleHTTP.endpoint(operation)[0], method)
        self.assertEqual(google.GoogleHTTP.endpoint("message", "abc123")[0], "GET")
        self.assertEqual(google.GoogleHTTP.endpoint("events", "primary")[0], "GET")
        self.assertIn("%23", google.GoogleHTTP.endpoint("events", "cs.czech#holiday@group.v.calendar.google.com")[1])
        for operation in ("gmail_send", "modify", "delete", "draft", "event_insert", "attachment", "https://attacker.test"):
            with self.assertRaises(google.GoogleError):
                google.GoogleHTTP.endpoint(operation)
        with self.assertRaises(google.GoogleError):
            google.GoogleHTTP.endpoint("message", "../send")

    async def test_no_post_body_to_any_data_endpoint(self):
        with self.assertRaises(google.GoogleError):
            await self.perform(Response([b"{}"]), form={"write": "attempt"})


if __name__ == "__main__":
    unittest.main()
