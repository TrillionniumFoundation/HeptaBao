"""Bounded fixture contracts only; these tests do not qualify a native binary."""
from __future__ import annotations

from email.message import Message
import json
import os
from pathlib import Path
import tempfile
import unittest

import native_v6_authbus_refresh_live as live


class MemoryBackend:
    """Explicit unit double. Actual live evidence requires the owned binary."""
    def __init__(self, document=None):
        self.document = document
        self.version = 2
        self.token = "synthetic-private-observer"
        self.calls = []
        self.cas_status = 200
        self.readback_change = False

    def wire(self, method, route, raw=None, *, token=""):
        self.calls.append((method, route))
        if method == "POST":
            value = live.checked_json(raw)
            if self.cas_status != 200:
                return live.WireReply(self.cas_status, b'{}', "Mon, 19 Oct 2026 01:00:00 GMT", "application/json")
            self.document = value["data"]
            self.version = value["options"]["cas"] + 1
            return live.WireReply(200, live.canonical({"data": {"version": self.version}}), "Mon, 19 Oct 2026 01:00:00 GMT", "application/json")
        document = dict(self.document or {})
        if self.readback_change:
            document["changed"] = True
        return live.WireReply(200, live.canonical({"data": {"data": document, "metadata": {"version": self.version}}}),
                              "Mon, 19 Oct 2026 01:00:00 GMT", "application/json")


class NativeRefreshFixtureContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="authbus-native-unit-")
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.cases = live.make_cases("unit-only")
        self.backend = MemoryBackend()
        self.gateway = live.FixtureGateway(self.backend, self.root, self.cases, lambda: 30)
        self.gateway.phase = "warm"

    def tearDown(self):
        self.temp.cleanup()

    def headers(self, *pairs):
        result = Message()
        for key, value in pairs:
            result[key] = value
        return result

    def unknown(self, scenario):
        original = next(item for item in self.cases if item["scenario"] == scenario)
        return {"protocol": live.PROTOCOL, "assignments": [{"status": "REFRESH_PENDING", "scopeDigest": "scope-unit",
                 "bootId": "boot-unit", "epoch": 2}], "refreshAttempts": [{"status": "UNKNOWN", "scopeDigest": "scope-unit",
                 "bootId": "boot-unit", "fenceEpoch": 2, "credentialDigest": original["originalDigest"]}]}

    def provider_body(self, scenario):
        original = next(item for item in self.cases if item["scenario"] == scenario)
        return live.canonical({"grant_type": "refresh_token", "client_id": "unit-only", "refresh_token": original["original"]["refresh"]})

    def test_exact_configured_routes(self):
        self.assertTrue(live.admitted_route("POST", "/v1/auth/approle/login"))
        for name in live.CASES:
            self.assertTrue(live.admitted_route("GET", "/v1/authbus/data/" + name))
            self.assertTrue(live.admitted_route("POST", "/v1/authbus/data/" + name))

    def test_route_aliases_and_unconfigured_authorities_rejected(self):
        for target in ("/v1/sys/mounts", "/v1/authbus/data/manager-success?namespace=x", "/v1/authbus/data/manager%2dsuccess",
                       "/v1/authbus/data/../manager-success", "/v1/auth/token/create", "https://foreign.example/v1/auth/approle/login"):
            self.assertFalse(live.admitted_route("POST", target))
        self.assertFalse(live.admitted_route("DELETE", "/v1/authbus/data/manager-success"))

    def test_content_length_exact_limit(self):
        self.assertEqual(live.request_length(self.headers(("Content-Length", str(live.MAX_CONTROL_BYTES))), live.MAX_CONTROL_BYTES), live.MAX_CONTROL_BYTES)
        self.assertEqual(live.request_length(self.headers(), live.MAX_CONTROL_BYTES), 0)

    def test_duplicate_or_transfer_framing_rejected(self):
        for headers in (self.headers(("Content-Length", "2"), ("Content-Length", "2")),
                        self.headers(("Content-Length", "2"), ("Transfer-Encoding", "chunked"))):
            with self.assertRaises(live.CanaryFailure):
                live.request_length(headers, live.MAX_CONTROL_BYTES)

    def test_noncanonical_or_excessive_body_rejected(self):
        for size in (str(live.MAX_CONTROL_BYTES + 1), "-1", "+2", "02", "2,2", "", "999999999999999999999"):
            with self.assertRaises(live.CanaryFailure):
                live.request_length(self.headers(("Content-Length", size)), live.MAX_CONTROL_BYTES)

    def test_original_deadline_only_shortens(self):
        start = 1_000_000_000
        self.assertEqual(live.bounded_deadline(start), start + 180_000_000_000)
        self.assertEqual(live.bounded_deadline(start, start + 9_000_000_000), start + 9_000_000_000)
        self.assertEqual(live.bounded_deadline(start, start + 999_000_000_000), start + 180_000_000_000)

    def test_expired_original_deadline_rejected(self):
        for deadline in (1_000_000_000, 999_999_999, True):
            with self.assertRaises(live.CanaryFailure):
                live.bounded_deadline(1_000_000_000, deadline)

    def test_duplicate_and_nonfinite_json_rejected(self):
        for raw in (b'{"options":{"cas":0,"cas":1}}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.assertRaises(live.CanaryFailure):
                live.checked_json(raw)

    def test_unknown_ack_drop_requires_commit_then_exact_readback(self):
        document = self.unknown("intent-ack-lost")
        result = self.gateway.forward("POST", "/v1/authbus/data/intent-ack-lost", live.canonical({"options": {"cas": 2}, "data": document}), "synthetic-issuer")
        self.assertIsNone(result)
        self.assertEqual(self.backend.calls, [("POST", "authbus/data/intent-ack-lost"), ("GET", "authbus/data/intent-ack-lost")])
        self.assertEqual(self.backend.document, document)
        self.assertEqual(self.gateway.counts["intent-ack-lost"]["unknownAckDrops"], 1)
        self.assertEqual(self.gateway.events[0]["nativeVersion"], 3)
        self.assertEqual(self.gateway.events[0]["documentSha256"], live.value_sha(document))

    def test_unknown_rejected_native_cas_is_never_counted_as_lost_ack(self):
        self.backend.cas_status = 400
        with self.assertRaisesRegex(live.CanaryFailure, "requires_actual_cas_ack"):
            self.gateway.forward("POST", "/v1/authbus/data/intent-ack-lost", live.canonical({"options": {"cas": 2}, "data": self.unknown("intent-ack-lost")}), "synthetic-issuer")
        self.assertEqual(self.gateway.counts["intent-ack-lost"]["unknownAckDrops"], 0)
        self.assertEqual(self.backend.calls, [("POST", "authbus/data/intent-ack-lost")])

    def test_unknown_changed_readback_never_counts_as_committed_fault(self):
        self.backend.readback_change = True
        with self.assertRaisesRegex(live.CanaryFailure, "readback_mismatch"):
            self.gateway.forward("POST", "/v1/authbus/data/intent-ack-lost", live.canonical({"options": {"cas": 2}, "data": self.unknown("intent-ack-lost")}), "synthetic-issuer")
        self.assertEqual(self.gateway.counts["intent-ack-lost"]["unknownAckDrops"], 0)

    def test_nonfault_response_preserves_native_bytes_and_date(self):
        self.backend.document = {"observed": "native-unit-byte-value"}
        reply = self.gateway.forward("GET", "/v1/authbus/data/manager-success", b"", "synthetic-reader")
        self.assertEqual(reply.date, "Mon, 19 Oct 2026 01:00:00 GMT")
        self.assertEqual(reply.raw, live.canonical({"data": {"data": self.backend.document, "metadata": {"version": 2}}}))
        self.assertEqual(self.gateway.events, [])

    def test_provider_sends_only_after_bound_unknown(self):
        self.backend.document = self.unknown("manager-success")
        reply = self.gateway.provider("POST", "/v1/oauth/token", "application/json", self.provider_body("manager-success"))
        self.assertEqual(reply.status, 200)
        self.assertEqual(self.gateway.counts["manager-success"]["providerRequests"], 1)
        self.assertEqual(self.gateway.events[0]["event"], "actual_sdk_https_after_native_unknown")

    def test_provider_rejects_published_or_unbound_native_state(self):
        for mutate in (lambda doc: doc["refreshAttempts"][0].update(status="PUBLISHED"),
                       lambda doc: doc["refreshAttempts"][0].update(credentialDigest="wrong"),
                       lambda doc: doc["assignments"][0].update(bootId="wrong"),
                       lambda doc: doc["assignments"][0].update(epoch=3)):
            self.backend.document = self.unknown("manager-success")
            mutate(self.backend.document)
            with self.assertRaisesRegex(live.CanaryFailure, "requires_native_unknown"):
                self.gateway.provider("POST", "/v1/oauth/token", "application/json", self.provider_body("manager-success"))
        self.assertEqual(self.gateway.counts["manager-success"]["providerRequests"], 0)

    def test_provider_ack_loss_is_after_one_native_observation(self):
        self.backend.document = self.unknown("provider-ack-lost")
        reply = self.gateway.provider("POST", "/v1/oauth/token", "application/json", self.provider_body("provider-ack-lost"))
        self.assertIsNone(reply)
        self.assertEqual(self.backend.calls, [("GET", "authbus/data/provider-ack-lost")])
        self.assertEqual(self.gateway.counts["provider-ack-lost"]["providerRequests"], 1)

    def test_duplicate_provider_request_is_refused_before_native_read(self):
        self.backend.document = self.unknown("manager-success")
        self.gateway.provider("POST", "/v1/oauth/token", "application/json", self.provider_body("manager-success"))
        self.backend.calls.clear()
        with self.assertRaisesRegex(live.CanaryFailure, "duplicate_or_cold"):
            self.gateway.provider("POST", "/v1/oauth/token", "application/json", self.provider_body("manager-success"))
        self.assertEqual(self.backend.calls, [])

    def test_cold_provider_request_is_refused_before_native_read(self):
        self.gateway.phase = "cold-after-server"
        with self.assertRaisesRegex(live.CanaryFailure, "duplicate_or_cold"):
            self.gateway.provider("POST", "/v1/oauth/token", "application/json", self.provider_body("manager-success"))
        self.assertEqual(self.backend.calls, [])

    def test_unconfigured_request_never_reaches_backend(self):
        with self.assertRaisesRegex(live.CanaryFailure, "unconfigured_proxy_route"):
            self.gateway.forward("POST", "/v1/auth/token/create", b"{}", "synthetic-reader")
        self.assertEqual(self.backend.calls, [])

    def test_expired_original_budget_never_sends_backend_or_provider(self):
        def expired():
            raise live.CanaryFailure("unit-original-deadline")
        self.gateway.remaining = expired
        with self.assertRaisesRegex(live.CanaryFailure, "original-deadline"):
            self.gateway.forward("GET", "/v1/authbus/data/manager-success", b"", "synthetic-reader")
        with self.assertRaisesRegex(live.CanaryFailure, "original-deadline"):
            self.gateway.provider("POST", "/v1/oauth/token", "application/json", self.provider_body("manager-success"))
        self.assertEqual(self.backend.calls, [])

    def test_private_read_rejects_symlink_and_size(self):
        target = self.root / "owned"
        target.write_bytes(b"unit-owned-private")
        target.chmod(0o600)
        self.assertEqual(live.owned_read(target, 64), b"unit-owned-private")
        with self.assertRaises(live.CanaryFailure):
            live.owned_read(target, 2)
        link = self.root / "symlink"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            live.owned_read(link, 64)

    def test_date_must_be_timezone_qualified(self):
        self.assertEqual(live.WireReply(200, b"{}", "Mon, 19 Oct 2026 01:00:00 GMT", "application/json").server_ms(), 1792371600000)
        with self.assertRaises(live.CanaryFailure):
            live.WireReply(200, b"{}", "invalid", "application/json").server_ms()


if __name__ == "__main__":
    unittest.main()
