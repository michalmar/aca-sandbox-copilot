"""Sustained readiness with actual SDK list methods and an offline clock/transport."""

import base64
from collections import deque
import copy
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

from azure.containerapps.sandbox import SandboxGroupClient, endpoint_for_region
from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ServiceRequestError
from azure.core.pipeline.transport import HttpResponse, HttpTransport

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import deploy_hermes as deploy
import hermes_common as common
from test_hermes_deploy_contracts import config

CANARY = "READINESS_PRIVATE_CANARY"
PREFIX = "hermes.status.v1."
READS = ["/volumes", "/sandboxes", "/diskimages", "/secrets"]
_AUTO_BODY = object()


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class Credential:
    def __init__(self, settings):
        self.config = settings
        self.scopes = []

    def get_token(self, scope, **_):
        self.scopes.append(scope)
        claims = {
            "tid": self.config.tenant_id, "oid": self.config.owner_object_id,
            "idtyp": "user", "aud": next(iter(common.INGRESS_AUDIENCES)),
        }
        body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        return AccessToken("e30." + body + "." + CANARY, 2**40)


def reply(status=200, body=_AUTO_BODY, duration=0):
    return SimpleNamespace(status=status, body=body, duration=duration)


class Response(HttpResponse):
    def __init__(self, request, data):
        super().__init__(request, None)
        self.status_code = data.status
        self.headers = {"content-type": "application/json"}
        self.content_type = "application/json"
        self.reason = "fixture"
        self.data = data.body

    def body(self):
        return json.dumps(self.data if not isinstance(self.data, Exception) else {}).encode()

    def json(self):
        if isinstance(self.data, Exception):
            raise self.data
        return copy.deepcopy(self.data)


class Transport(HttpTransport):
    def __init__(self, clock):
        self.clock = clock
        self.connection_config = SimpleNamespace(timeout=90, read_timeout=90)
        self.queue = deque()
        self.calls = []
        self.on_send = None
        self.default = reply()

    def open(self):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def sleep(self, seconds):
        self.clock.sleep(seconds)

    def send(self, request, **kwargs):
        if request.method != "GET":
            raise AssertionError("Readiness may not send a mutation.")
        self.calls.append((request.method, urlsplit(request.url).path, self.clock.now, dict(kwargs)))
        if self.on_send:
            self.on_send(request, kwargs)
        data = self.queue.popleft() if self.queue else self.default
        if isinstance(data, Exception):
            raise data
        self.clock.now += data.duration
        if data.body is _AUTO_BODY:
            key = "secrets" if urlsplit(request.url).path.endswith("/secrets") else "value"
            data = reply(data.status, {key: []}, data.duration)
        return Response(request, data)


class FreshReadinessTests(unittest.TestCase):
    def setUp(self, *, retry_total=2):
        self.config = config()
        self.clock = Clock()
        self.credential = Credential(self.config)
        self.transport = Transport(self.clock)
        self.group = SandboxGroupClient(
            endpoint_for_region(self.config.location), self.credential,
            subscription_id=self.config.subscription_id, resource_group=self.config.resource_group,
            sandbox_group=self.config.sandbox_group, transport=self.transport, retry_total=retry_total, redirect_max=0,
        )
        self.addCleanup(self.group.close)
        self.resources = MagicMock()
        self.management = MagicMock()
        self.resources.resource_groups.check_existence.return_value = True
        self.resources.resource_groups.get.return_value = SimpleNamespace(
            id=self.config.group_scope, tags=dict(self.config.labels), location=self.config.location,
        )
        self.resources.resources.list_by_resource_group.return_value = [SimpleNamespace(id=self.config.group_scope)]
        self.management.get_group.return_value = SimpleNamespace(
            id=self.config.group_scope, tags=dict(self.config.labels), location=self.config.location,
            identity={"type": "SystemAssigned", "principalId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
        )
        self.clients = common.AzureClients(self.credential, self.resources, self.management, self.group)
        self.events = []
        self.recorder = common.StatusRecorder(self.events.append)
        self.time_patch = patch.object(deploy, "time", self.clock)
        self.time_patch.start()
        self.addCleanup(self.time_patch.stop)

    def provision(self, *, fresh=True, recorder=None):
        return deploy.provision_group(
            self.config, self.clients, fresh=fresh, status_capture=recorder or self.recorder,
        )

    def completed(self, operation):
        return [event for event in self.events if event["operation"] == PREFIX + operation and event["event"] == "pass"]

    def assert_no_mutations(self):
        self.assertTrue(all(call[0] == "GET" for call in self.transport.calls))
        self.assertEqual({call[0] for call in self.resources.mock_calls} - {
            "resource_groups.check_existence", "resource_groups.get", "resources.list_by_resource_group",
        }, set())
        self.assertEqual({call[0] for call in self.management.mock_calls} - {"get_group"}, set())
        self.assertNotIn("send", vars(self.transport))

    def test_three_complete_rounds_same_client_and_immediate_original_boundary(self):
        pipeline = self.group._pipeline
        policies = tuple(pipeline._impl_policies)
        scopes = self.group._scope
        objects = (self.config, self.clients, self.credential, self.group, pipeline, self.transport)
        self.provision()
        self.assertEqual([Path(call[1]).name for call in self.transport.calls],
                         [item.lstrip("/") for item in READS] * 3 + ["volumes"])
        self.assertEqual([call[2] for call in self.transport.calls], [0] * 4 + [10] * 4 + [20] * 5)
        self.assertEqual(self.clock.sleeps, [10, 10])
        self.assertEqual([event["details"]["round_index"] for event in self.completed("readiness.round")], [1, 2, 3])
        self.assertTrue(all(event["details"]["reads_completed"] == 4 for event in self.completed("readiness.round")))
        self.assertEqual(self.completed("readiness.wait")[0]["details"]["consecutive_rounds"], 3)
        self.assertFalse(self.completed("readiness.wait")[0]["details"]["authorization_guaranteed"])
        self.assertEqual(len(self.completed("provision.volumes.list")), 1)
        for current, expected in zip(
            (self.config, self.clients, self.credential, self.group, self.group._pipeline, self.group._pipeline._transport),
            objects,
        ):
            self.assertIs(current, expected)
        self.assertEqual(tuple(pipeline._impl_policies), policies)
        self.assertEqual(self.group._scope, scopes)
        self.assertEqual(self.credential.scopes, ["https://dynamicsessions.io/.default"])
        self.assertTrue(all(0 < call[3]["read_timeout"] <= 5 for call in self.transport.calls))
        self.assertTrue(all(0 < call[3]["connection_timeout"] <= 5 for call in self.transport.calls))
        self.assertEqual((self.transport.connection_config.timeout, self.transport.connection_config.read_timeout), (90, 90))
        self.assert_no_mutations()

    def test_one_or_two_passes_never_declare_ready(self):
        def inspect_before_send(_request, _kwargs):
            if len(self.transport.calls) in (5, 9):
                self.assertEqual(self.completed("readiness.wait"), [])
                self.assertEqual(self.completed("provision.volumes.list"), [])
        self.transport.on_send = inspect_before_send
        self.provision()
        self.assertEqual(len(self.completed("readiness.wait")), 1)

    def test_pass_pass_permission_resets_then_requires_three_new_passes(self):
        for code in (401, 403):
            with self.subTest(code=code):
                self.setUp()
                self.transport.queue.extend([reply()] * 8 + [reply(code, {"error": CANARY})])
                self.provision()
                self.assertEqual([e["details"]["round_index"] for e in self.completed("readiness.round")], [1, 2, 1, 2, 3])
                reset = self.completed("readiness.reset")
                self.assertEqual(len(reset), 1)
                self.assertEqual(reset[0]["details"]["consecutive_rounds"], 0)
                self.assertEqual(reset[0]["details"]["http_status"], code)
                self.assertFalse(reset[0]["details"]["authorization_guaranteed"])
                self.assertEqual(self.clock.now, 50)
                self.assertEqual(len(self.transport.calls), 22)
                self.assertEqual(len(self.credential.scopes), 1)
                self.assertTrue(any(e.get("error_category") == "permission" for e in self.events))
                self.assertNotIn(CANARY, json.dumps(self.events))
                self.assert_no_mutations()

    def test_denial_at_each_read_never_counts_a_partial_round(self):
        for position in range(4):
            with self.subTest(position=position):
                self.setUp()
                self.transport.queue.extend([reply()] * position + [reply(403, {"error": CANARY})])
                self.provision()
                failed = [e for e in self.events if e["operation"] == PREFIX + "readiness.round" and e["event"] == "fail"]
                self.assertEqual(failed[0]["details"]["reads_completed"], position)
                self.assertFalse(failed[0]["details"]["complete"])
                self.assertEqual([e["details"]["round_index"] for e in self.completed("readiness.round")], [1, 2, 3])
                self.assertEqual(self.clock.now, 30)
                self.assert_no_mutations()

    def test_sdk_retries_do_not_hide_denial_or_change_the_configured_policy(self):
        retry = next(policy for policy in self.group._pipeline._impl_policies if hasattr(policy, "total_retries"))
        before = (retry.total_retries, retry.status_retries, retry.connect_retries, retry.read_retries)
        self.transport.queue.append(reply(403, {"error": CANARY}))
        self.provision()
        self.assertEqual(self.transport.calls[0][2], 0)
        self.assertEqual(self.transport.calls[1][2], 10)
        self.assertEqual(before, (retry.total_retries, retry.status_retries, retry.connect_retries, retry.read_retries))
        self.assertEqual(len(self.completed("readiness.reset")), 1)
        self.assertEqual(len(self.transport.calls), 14)

    def test_spacing_is_from_complete_round_and_no_delay_after_third(self):
        self.transport.default = reply(duration=1)
        self.provision()
        self.assertEqual([self.transport.calls[index][2] for index in (0, 4, 8, 12)], [0, 14, 28, 32])
        self.assertEqual(self.clock.sleeps, [10, 10])
        self.assertEqual(self.clock.now, 33)

    def test_interrupted_spacing_does_not_start_an_early_round(self):
        with patch.object(self.clock, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "spacing"):
                self.provision()
        self.assertEqual(len(self.transport.calls), 4)
        self.assertEqual(self.completed("readiness.wait"), [])
        self.assert_no_mutations()

    def test_repeated_denial_expires_without_creation_or_success(self):
        self.transport.default = reply(403, {"error": CANARY})
        with self.assertRaises(common.ReadinessTimeoutError) as raised:
            self.provision()
        self.assertLessEqual(self.clock.now, 900)
        self.assertEqual(len(self.transport.calls), 90)
        self.assertEqual(self.completed("readiness.round"), [])
        self.assertEqual(self.completed("readiness.wait"), [])
        self.assertEqual(self.completed("provision.volumes.list"), [])
        self.assertEqual(self.events[-1]["error_category"], "readiness_timeout")
        self.assertNotIn(CANARY, str(raised.exception))
        self.assert_no_mutations()

    def test_no_late_success_and_per_request_budget_is_enforced(self):
        self.transport.queue.append(reply(duration=10))
        with self.assertRaises(common.ReadinessTimeoutError):
            self.provision()
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(self.completed("readiness.round"), [])
        self.assertEqual(self.events[-1]["error_category"], "readiness_timeout")
        self.assert_no_mutations()

    def test_remaining_deadline_and_smaller_existing_timeouts_are_preserved(self):
        self.transport.connection_config.timeout = 1
        self.transport.connection_config.read_timeout = 2
        deploy._readiness_list(
            self.config, self.clients, self.recorder, 0.8, "volumes", "list_volumes", "/volumes", "value", 1,
        )
        options = self.transport.calls[0][3]
        self.assertLessEqual(options["connection_timeout"] + options["read_timeout"], 0.8)
        self.assertEqual((self.transport.connection_config.timeout, self.transport.connection_config.read_timeout), (1, 2))
        self.assert_no_mutations()

    def test_preexpired_deadline_never_sends_a_read(self):
        with self.assertRaises(common.ReadinessTimeoutError):
            deploy._readiness_list(
                self.config, self.clients, self.recorder, 0, "volumes", "list_volumes", "/volumes", "value", 1,
            )
        self.assertEqual(self.transport.calls, [])
        self.assert_no_mutations()

    def test_nonpermission_http_statuses_stop_without_sdk_or_outer_retries(self):
        for status in (204, 302, 404, 429, 500, 503):
            with self.subTest(status=status):
                self.setUp()
                self.transport.queue.append(reply(status, {"error": CANARY}))
                with self.assertRaises(RuntimeError) as raised:
                    self.provision()
                self.assertEqual(len(self.transport.calls), 1)
                self.assertEqual(self.completed("readiness.reset"), [])
                self.assertNotIn(CANARY, str(raised.exception))
                self.assertNotIn(CANARY, json.dumps(self.events))
                self.assert_no_mutations()

    def test_transport_parser_and_malformed_fail_immediately_without_leaking(self):
        cases = (
            ServiceRequestError(CANARY), reply(body=ValueError(CANARY)),
            reply(body=CANARY), reply(body={}), reply(body={"value": None}),
            reply(body={"value": CANARY}), reply(body={"value": [], "nextLink": 42}),
        )
        for response in cases:
            with self.subTest(response_type=type(response).__name__):
                self.setUp()
                self.transport.queue.append(response)
                with self.assertRaises(RuntimeError) as raised:
                    self.provision()
                self.assertEqual(len(self.transport.calls), 1)
                self.assertEqual(self.clock.sleeps, [])
                self.assertNotIn(CANARY, str(raised.exception))
                self.assertNotIn(CANARY, json.dumps(self.events))
                self.assert_no_mutations()

    def test_each_nonempty_inventory_stops_at_first_response(self):
        for index in range(4):
            with self.subTest(index=index):
                self.setUp()
                key = "secrets" if index == 3 else "value"
                self.transport.queue.extend([reply()] * index + [reply(body={key: [{"secret": CANARY}]})])
                with self.assertRaisesRegex(RuntimeError, "empty owned group") as raised:
                    self.provision()
                self.assertEqual(len(self.transport.calls), index + 1)
                self.assertTrue(any(event.get("error_category") == "inventory_count" for event in self.events))
                self.assertNotIn(CANARY, str(raised.exception))
                self.assertNotIn(CANARY, json.dumps(self.events))
                self.assert_no_mutations()

    def test_secrets_schema_matches_sdk_and_structural_details_are_durable(self):
        self.provision()
        pages = self.completed("readiness.secrets.list")
        self.assertEqual(len(pages), 3)
        for event in pages:
            self.assertEqual(event["details"]["response_type"], "object")
            self.assertIs(event["details"]["items_key_present"], True)
            self.assertEqual(event["details"]["items_type"], "array")
            self.assertEqual(event["details"]["count"], 0)
            self.assertEqual(event["details"]["pages_completed"], 1)
            self.assertTrue(event["details"]["complete"])
        self.assert_no_mutations()

    def test_secrets_wrong_missing_and_null_envelopes_are_malformed_without_sdk_crash(self):
        for body in ([], {"value": []}, {}, {"secrets": None}, {"secrets": CANARY}, None):
            with self.subTest(body_type=type(body).__name__):
                self.setUp()
                self.transport.queue.extend([reply()] * 3 + [reply(body=body)])
                with self.assertRaisesRegex(RuntimeError, "malformed list envelope") as raised:
                    self.provision()
                self.assertEqual(len(self.transport.calls), 4)
                failure = next(event for event in self.events
                               if event["operation"] == PREFIX + "readiness.secrets.list" and event["event"] == "fail")
                self.assertEqual(failure["error_category"], "malformed_type")
                self.assertEqual(failure["details"]["response_type"], common._egress_value_type(body))
                self.assertEqual(failure["details"]["items_key_present"], isinstance(body, dict) and "secrets" in body)
                self.assertFalse(failure["details"]["complete"])
                self.assertNotIn(CANARY, str(raised.exception))
                self.assertNotIn(CANARY, json.dumps(self.events))
                self.assert_no_mutations()

    def test_secrets_empty_and_nonempty_pages_follow_the_sdk_secrets_key(self):
        next_link = self.group._endpoint + self.group._group_path + "/secrets?api-version=2026-02-01-preview&cursor=synthetic"
        self.transport.queue.extend([reply()] * 3 + [
            reply(body={"secrets": [], "nextLink": next_link}), reply(body={"secrets": []}),
        ])
        self.provision()
        first = self.completed("readiness.secrets.list")[0]["details"]
        self.assertEqual(first["pages_completed"], 2)
        self.assertEqual(first["count"], 0)
        self.assertTrue(first["complete"])
        self.assertEqual(len(self.transport.calls), 14)
        self.assertNotIn(next_link, json.dumps(self.events))
        self.assert_no_mutations()
        self.setUp()
        self.transport.queue.extend([reply()] * 3 + [
            reply(body={"secrets": [], "nextLink": next_link}), reply(body={"secrets": [{"secret": CANARY}]}),
        ])
        with self.assertRaisesRegex(RuntimeError, "empty owned group"):
            self.provision()
        failure = next(event for event in self.events
                       if event["operation"] == PREFIX + "readiness.secrets.list" and event["event"] == "fail")
        self.assertEqual(failure["error_category"], "inventory_count")
        self.assertEqual(failure["details"]["pages_completed"], 1)
        self.assertEqual(failure["details"]["count"], 1)
        self.assertNotIn(CANARY, json.dumps(self.events))
        self.assert_no_mutations()

    def test_secrets_foreign_and_cyclic_pagination_never_send_followup(self):
        for link in (
            "https://foreign.invalid/" + CANARY,
            self.group._endpoint + self.group._group_path + "/volumes?api-version=2026-02-01-preview",
            self.group._endpoint + self.group._group_path + "/secrets?api-version=2026-02-01-preview",
        ):
            with self.subTest(link_type="synthetic"):
                self.setUp()
                self.transport.queue.extend([reply()] * 3 + [reply(body={"secrets": [], "nextLink": link})])
                with self.assertRaisesRegex(RuntimeError, "pagination") as raised:
                    self.provision()
                self.assertEqual(len(self.transport.calls), 4)
                self.assertNotIn(CANARY, str(raised.exception))
                self.assertNotIn(CANARY, json.dumps(self.events))
                self.assert_no_mutations()

    def test_secrets_later_page_denial_never_reuses_previous_page_shape(self):
        link = self.group._endpoint + self.group._group_path + "/secrets?api-version=2026-02-01-preview&cursor=next"
        self.transport.queue.extend([reply()] * 3 + [
            reply(body={"secrets": [], "nextLink": link}), reply(403, {"error": CANARY}),
        ])
        self.provision()
        failure = next(event for event in self.events
                       if event["operation"] == PREFIX + "readiness.secrets.list" and event["event"] == "fail")
        self.assertEqual(failure["error_category"], "permission")
        self.assertEqual(failure["details"]["http_status"], 403)
        self.assertEqual(failure["details"]["pages_completed"], 1)
        self.assertFalse(failure["details"]["complete"])
        for key in ("response_type", "items_key_present", "items_type"):
            self.assertNotIn(key, failure["details"])
        self.assertNotIn(CANARY, json.dumps(self.events))
        self.assertEqual([event["details"]["round_index"] for event in self.completed("readiness.round")], [1, 2, 3])
        self.assert_no_mutations()

    def test_empty_array_envelopes_and_complete_empty_pagination(self):
        next_link = self.group._endpoint + self.group._group_path + "/volumes?api-version=2026-02-01-preview&cursor=synthetic"
        self.transport.queue.extend([reply(body={"value": [], "nextLink": next_link}), reply(body=[])])
        self.provision()
        first = self.completed("readiness.volumes.list")[0]["details"]
        self.assertTrue(first["complete"])
        self.assertEqual(first["pages_completed"], 2)
        self.assertEqual(first["count"], 0)
        self.assertEqual(len(self.transport.calls), 14)
        self.assertNotIn(next_link, json.dumps(self.events))
        self.assert_no_mutations()

    def test_foreign_or_malformed_pagination_never_sends_followup(self):
        for link in (
            "https://foreign.invalid/" + CANARY,
            self.group._endpoint + "/foreign?api-version=2026-02-01-preview",
            self.group._endpoint + self.group._group_path + "/secrets?api-version=2026-02-01-preview",
            "https://[" + CANARY,
        ):
            with self.subTest(link_type="synthetic"):
                self.setUp()
                self.transport.queue.append(reply(body={"value": [], "nextLink": link}))
                with self.assertRaisesRegex(RuntimeError, "pagination") as raised:
                    self.provision()
                self.assertEqual(len(self.transport.calls), 1)
                self.assertNotIn(CANARY, str(raised.exception))
                self.assertNotIn(CANARY, json.dumps(self.events))
                self.assert_no_mutations()

    def test_cyclic_empty_pagination_fails_immediately(self):
        link = self.group._endpoint + self.group._group_path + "/volumes?api-version=2026-02-01-preview"
        self.transport.default = reply(body={"value": [], "nextLink": link}, duration=1)
        with self.assertRaisesRegex(RuntimeError, "cyclic pagination"):
            self.provision()
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(self.completed("readiness.round"), [])
        self.assert_no_mutations()

    def test_unique_unfinished_pages_share_one_ten_second_read_budget(self):
        def page(_request, _kwargs):
            link = (
                self.group._endpoint + self.group._group_path + "/volumes?api-version=2026-02-01-preview"
                + "&cursor=" + str(len(self.transport.calls))
            )
            self.transport.queue.append(reply(body={"value": [], "nextLink": link}, duration=1))
        self.transport.on_send = page
        with self.assertRaises(common.ReadinessTimeoutError):
            self.provision()
        self.assertLessEqual(self.clock.now, 10)
        self.assertEqual(len(self.transport.calls), 10)
        self.assertEqual(self.completed("readiness.round"), [])
        self.assert_no_mutations()

    def test_malformed_status_and_timeouts_fail_without_value_emission(self):
        for status in (True, 700, CANARY):
            with self.subTest(status_type=type(status).__name__):
                self.setUp()
                self.transport.queue.append(reply(status, {"error": CANARY}))
                with self.assertRaisesRegex(RuntimeError, "invalid HTTP status") as raised:
                    self.provision()
                self.assertNotIn(CANARY, str(raised.exception))
                self.assertNotIn(CANARY, json.dumps(self.events))
                self.assert_no_mutations()
        for timeout in (0, -1, True, float("inf"), float("nan"), CANARY):
            with self.subTest(timeout_type=type(timeout).__name__):
                self.setUp()
                self.transport.connection_config.read_timeout = timeout
                with self.assertRaisesRegex(RuntimeError, "positive transport timeouts") as raised:
                    self.provision()
                self.assertEqual(self.transport.calls, [])
                self.assertNotIn(CANARY, str(raised.exception))
                self.assert_no_mutations()

    def test_existing_resources_and_wrong_client_refuse_without_data_reads(self):
        self.management.get_group.return_value.tags = {}
        with self.assertRaisesRegex(RuntimeError, "unowned"):
            self.provision()
        self.assertEqual(self.transport.calls, [])
        self.management.get_group.return_value.tags = dict(self.config.labels)
        self.group._credential = Credential(self.config)
        with self.assertRaisesRegex(RuntimeError, "existing owner client"):
            self.provision()
        self.assertEqual(self.transport.calls, [])
        self.assert_no_mutations()

    def test_one_sdk_iterator_without_an_observed_response_is_not_proof(self):
        for source in ([], None, {}, CANARY):
            with self.subTest(source_type=type(source).__name__), patch.object(self.group, "list_volumes", return_value=source):
                with self.assertRaises(RuntimeError):
                    self.provision()
                self.assertEqual(self.transport.calls, [])
        self.assert_no_mutations()

    def test_first_post_ready_403_is_recorded_before_runtimeerror_and_not_retried(self):
        self.transport.queue.extend([reply()] * 12 + [reply(403, {"error": CANARY})])
        with self.assertRaisesRegex(RuntimeError, "data-plane access is blocked") as raised:
            self.provision()
        self.assertEqual(len(self.transport.calls), 13)
        self.assertEqual(self.clock.sleeps, [10, 10])
        self.assertEqual(len(self.completed("readiness.wait")), 1)
        self.assertEqual(self.completed("provision.volumes.list"), [])
        self.assertEqual(self.events[-1]["operation"], PREFIX + "provision.volumes.list")
        self.assertEqual(self.events[-1]["event"], "fail")
        self.assertEqual(self.events[-1]["error_category"], "permission")
        self.assertEqual(self.events[-1]["details"]["http_status"], 403)
        self.assertNotIn(CANARY, str(raised.exception))
        self.assert_no_mutations()

    def test_post_ready_401_keeps_only_its_safe_status_not_the_response_body(self):
        self.transport.queue.extend([reply()] * 12 + [reply(401, {"error": {"code": CANARY, "message": CANARY}})])
        with self.assertRaises(ClientAuthenticationError) as raised:
            self.provision()
        self.assertEqual(raised.exception.status_code, 401)
        self.assertIsNone(raised.exception.response)
        self.assertNotIn(CANARY, str(raised.exception))
        self.assertNotIn(CANARY, json.dumps(self.events))
        self.assertEqual(len(self.transport.calls), 13)
        self.assertEqual(self.events[-1]["error_category"], "permission")
        self.assert_no_mutations()

    def test_driver_calls_production_gate_and_failure_never_reaches_any_creation(self):
        self.transport.queue.extend([reply()] * 12 + [reply(403, {"error": CANARY})])
        with (
            patch.object(common.AzureClients, "create") as create_clients,
            patch.object(deploy, "create_image") as image,
            patch.object(deploy, "upload_private_file") as upload,
            patch.object(deploy, "configure_port") as port,
            patch.object(deploy, "exec_checked") as guest,
            self.assertRaises(RuntimeError),
        ):
            deploy.deploy(self.config, self.clients, fresh=True, status_capture=self.recorder)
        for mocked in (create_clients, image, upload, port, guest):
            mocked.assert_not_called()
        self.assertEqual(len(self.transport.calls), 13)
        self.assert_no_mutations()

    def test_shared_recorder_is_forwarded_to_the_exact_production_boundary(self):
        marker = RuntimeError("Synthetic boundary stop.")
        with (
            patch.object(deploy, "provision_group", side_effect=marker) as boundary,
            self.assertRaises(RuntimeError) as raised,
        ):
            deploy.deploy(self.config, self.clients, fresh=True, status_capture=self.recorder)
        self.assertIs(raised.exception, marker)
        boundary.assert_called_once_with(self.config, self.clients, fresh=True, status_capture=self.recorder)
        self.assertEqual(self.transport.calls, [])

    def test_post_ready_inventory_permission_is_linked_to_the_shared_recorder(self):
        self.setUp(retry_total=0)
        self.transport.queue.extend([reply()] * 13 + [reply(403, {"error": {"message": CANARY}})])
        with (
            patch.object(deploy, "create_image") as image, self.assertRaises(HttpResponseError) as raised,
        ):
            deploy.deploy(self.config, self.clients, fresh=True, status_capture=self.recorder)
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(len(self.completed("provision.volumes.list")), 1)
        self.assertEqual(self.events[-1]["operation"], PREFIX + "inventory.sandboxes.list")
        self.assertEqual(self.events[-1]["event"], "fail")
        self.assertEqual(self.events[-1]["error_category"], "permission")
        self.assertFalse(self.events[-1]["details"]["complete"])
        self.assertNotIn(CANARY, json.dumps(self.events))
        image.assert_not_called()
        self.assertEqual(len(self.transport.calls), 14)
        self.assertEqual(self.clock.sleeps, [10, 10])
        self.assert_no_mutations()

    def test_late_owned_inventory_is_rechecked_before_any_fresh_adoption_or_creation(self):
        entries = (
            {"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "labels": {**self.config.labels, "name": self.config.sandbox_name}},
            {"id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "labels": {**self.config.labels, "name": self.config.disk_name},
             "image": {"base": self.config.image}},
            {"volumeName": self.config.volume_name, "type": "DataDisk", "size": "1Gi", "labels": self.config.labels},
        )
        for position, entry in enumerate(entries):
            with self.subTest(position=position):
                self.setUp()
                lists = [reply(), reply(), reply()]
                lists[position] = reply(body={"value": [entry]})
                self.transport.queue.extend([reply()] * 13 + lists)
                with (
                    patch.object(self.group, "create_volume", side_effect=AssertionError("Unexpected creation.")) as volume,
                    patch.object(self.group, "get_sandbox_client", side_effect=AssertionError("Unexpected adoption.")) as sandbox,
                    patch.object(deploy, "create_image", side_effect=AssertionError("Unexpected creation.")) as image,
                    self.assertRaisesRegex(RuntimeError, "inventory changed"),
                ):
                    deploy.deploy(self.config, self.clients, fresh=True, status_capture=self.recorder)
                for operation in (volume, sandbox, image):
                    operation.assert_not_called()
                self.assertEqual(len(self.transport.calls), 16)
                self.assertEqual(self.events[-1]["operation"], PREFIX + "provision.fresh-inventory")
                self.assertEqual(self.events[-1]["details"]["count"], 1)
                self.assertEqual(self.events[-1]["error_category"], "inventory_count")
                self.assert_no_mutations()

    def test_nonfresh_existing_volume_has_no_wait_or_fresh_empty_gate(self):
        self.transport.queue.append(reply(body={"value": [{
            "volumeName": self.config.volume_name, "type": "DataDisk", "size": "1Gi", "labels": self.config.labels,
        }]}))
        self.provision(fresh=False)
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(self.clock.sleeps, [])
        self.assertFalse(any(event["operation"].startswith(PREFIX + "readiness.") for event in self.events))
        self.assertEqual(self.completed("provision.volumes.list")[0]["details"]["count"], 1)
        self.assert_no_mutations()

    def test_fresh_replacement_combination_rejected_before_any_clients(self):
        clients = MagicMock()
        with self.assertRaisesRegex(ValueError, "cannot be combined"):
            deploy.deploy(self.config, clients, fresh=True, replace=True)
        self.assertEqual(clients.mock_calls, [])

    def test_cli_modes_are_explicit_and_exclusive(self):
        with (
            patch.object(sys, "argv", ["deploy", "--fresh", "--replace"]),
            patch.object(common.AzureClients, "create") as azure,
            patch.object(sys, "stderr", io.StringIO()), self.assertRaises(SystemExit),
        ):
            deploy.main()
        azure.assert_not_called()
        with (
            patch.object(sys, "argv", ["deploy", "--fresh", "--confirm-target", self.config.group_scope]),
            patch.object(deploy, "load_egress_config", return_value=self.config),
            patch.object(common.AzureClients, "create") as azure,
            patch.object(deploy, "deploy", return_value="synthetic") as operation,
            patch.object(sys, "stdout", io.StringIO()),
        ):
            deploy.main()
        operation.assert_called_once_with(
            self.config, azure.return_value.__enter__.return_value, replace=False, fresh=True,
        )

    def test_persistence_failure_at_boundaries_stops_and_restores_transport(self):
        for operation, phase in (
            ("readiness.wait", "begin"), ("readiness.volumes.list", "pass"),
            ("readiness.round", "pass"), ("readiness.spacing", "begin"),
            ("provision.volumes.list", "begin"), ("provision.volumes.list", "pass"),
        ):
            with self.subTest(operation=operation, phase=phase):
                self.setUp()
                before_failure = []
                def persist(event):
                    if event["operation"] == PREFIX + operation and event["event"] == phase:
                        before_failure.append(len(self.transport.calls))
                        raise OSError(CANARY)
                    self.events.append(copy.deepcopy(event))
                recorder = common.StatusRecorder(persist)
                with self.assertRaises(common.StatusCaptureError) as raised:
                    self.provision(recorder=recorder)
                self.assertEqual(before_failure, [len(self.transport.calls)])
                self.assertEqual(raised.exception.error_category, "capture_persistence")
                self.assertNotIn(CANARY, str(raised.exception))
                self.assert_no_mutations()

    def test_transport_existing_override_is_restored_even_on_failure(self):
        original = self.transport.send
        def override(request, **kwargs):
            return original(request, **kwargs)
        self.transport.send = override
        self.transport.queue.append(reply(body=CANARY))
        with self.assertRaises(RuntimeError):
            self.provision()
        self.assertIs(self.transport.send, override)

    def test_all_new_operations_and_safe_schema_are_exercised(self):
        self.transport.queue.append(reply(403, {"error": CANARY}))
        self.provision()
        expected = {operation for operation in common.STATUS_OPERATION_IDS
                    if operation.startswith(PREFIX + "readiness.") or operation == PREFIX + "provision.volumes.list"}
        self.assertEqual({event["operation"] for event in self.events}, expected)
        self.assertEqual([event["sequence"] for event in self.events], list(range(1, len(self.events) + 1)))
        self.assertTrue(all(common._safe_status_value(event["details"]) for event in self.events))
        indexes = [event["details"]["round_index"] for event in self.events if "round_index" in event["details"]]
        self.assertTrue(all(1 <= value <= 3 for value in indexes))
        output = json.dumps(self.events)
        for private in (CANARY, self.config.subscription_id, self.config.group_scope, self.group._endpoint,
                        self.config.whatsapp_phone, "Authorization", "nextLink", "cache"):
            self.assertNotIn(private, output)
        self.assert_no_mutations()


if __name__ == "__main__":
    unittest.main()
