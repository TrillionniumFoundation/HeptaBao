"""RADIUS renewal harness keeps protocol checks strict and receipts secret-free."""
import hashlib
import hmac
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure, successful_comparison
from radius_renewal_live import (ADAPTATION, PASSWORD, SECRET, USERNAME,
    md5, message_authenticator, pap_packet_response, renewal_token_shape, wrapped_renewal_shape, run_scenarios)


def request_packet(*, with_ma=True, bad_ma=False, password=PASSWORD):
    authenticator = bytes(range(16))
    padded = password + b"\0" * (-len(password) % 16)
    encrypted = bytearray()
    previous = authenticator
    for start in range(0, len(padded), 16):
        chunk = bytes(a ^ b for a, b in zip(padded[start:start + 16], md5(SECRET, previous)))
        encrypted.extend(chunk)
        previous = chunk
    attributes = bytes([1, 2 + len(USERNAME)]) + USERNAME
    attributes += bytes([2, 2 + len(encrypted)]) + encrypted
    ma_offset = 20 + len(attributes) + 2
    if with_ma:
        attributes += bytes([80, 18]) + b"\0" * 16
    # MA intentionally is not the final attribute.
    attributes += bytes([5, 6]) + struct.pack("!I", 10)
    packet = bytearray(bytes([1, 17]) + struct.pack("!H", 20 + len(attributes)) + authenticator + attributes)
    if with_ma:
        packet[ma_offset:ma_offset + 16] = message_authenticator(packet)
        if bad_ma:
            packet[ma_offset] ^= 1
    return bytes(packet)


class EmptyResponder:
    def count(self):
        return 0

    def observed(self, start, *, accepted):
        return False


class FailedClient:
    def request(self, *args, **kwargs):
        return Response(503, {"errors": ["private-error"], "auth": {"client_token": "private-token"}})


class LocalOnlyClient:
    def request(self, method, path, payload=None, **kwargs):
        if path.endswith("/login"):
            return Response(200, {"auth": {"client_token": "private-token", "accessor": "private-accessor"}})
        return Response(204, {})


class ObservedResponder(EmptyResponder):
    allow = True

    def observed(self, start, *, accepted):
        return True


class WrongRenewalEchoClient:
    def __init__(self, responder, *, leak_accessor=False):
        self.responder = responder
        self.leak_accessor = leak_accessor

    def request(self, method, path, payload=None, **kwargs):
        if path.endswith("/login"):
            return Response(200, {"auth": {"client_token": "private-target", "accessor": "private-accessor"}})
        if path.endswith("/lookup-self"):
            return Response(200, {"data": {"ttl": 120}})
        if "/renew" in path:
            if not self.responder.allow:
                return Response(400, {"errors": ["private-provider-error"]})
            value = "private-target" if self.leak_accessor else "private-wrong-token"
            if path.endswith("renew-accessor"):
                value = "private-leaked-bearer"
            return Response(200, {"auth": {"client_token": value, "renewable": True, "lease_duration": 120}})
        return Response(204, {})


class RadiusRenewalTests(unittest.TestCase):
    def test_both_request_profiles_get_fully_authenticated_responses(self):
        for with_ma in (False, True):
            request = request_packet(with_ma=with_ma)
            for allow in (False, True):
                reply, observation = pap_packet_response(request, require_ma=with_ma, allow=allow)
                self.assertEqual(reply[0], 2 if allow else 3)
                self.assertEqual(reply[1], request[1])
                self.assertEqual(reply[4:20], md5(reply[:4], request[4:20], reply[20:], SECRET))
                signed = bytearray(reply)
                signed[4:20] = request[4:20]
                signed[22:] = b"\0" * 16
                self.assertEqual(reply[22:], hmac.new(SECRET, signed, hashlib.md5).digest())
                self.assertEqual(observation, {"credentials_valid": True, "message_authenticator_present": with_ma, "accepted": allow})

    def test_candidate_requires_ma_and_oracle_adapter_rejects_invalid_present_ma(self):
        with self.assertRaises(ValueError):
            pap_packet_response(request_packet(with_ma=False), require_ma=True, allow=True)
        for require_ma in (False, True):
            with self.assertRaises(ValueError):
                pap_packet_response(request_packet(bad_ma=True), require_ma=require_ma, allow=True)

    def test_valid_authenticator_cannot_hide_incorrect_pap_credentials(self):
        reply, observation = pap_packet_response(request_packet(password=b"wrong-synthetic-password"), require_ma=True, allow=True)
        self.assertEqual(reply[0], 3)
        self.assertIs(observation["credentials_valid"], False)
        self.assertIs(observation["accepted"], False)

    def test_malformed_requests_fail_without_reflecting_payload(self):
        for packet in (b"private", request_packet()[:-1], bytes([2]) + request_packet()[1:]):
            with self.assertRaises(ValueError) as raised:
                pap_packet_response(packet, require_ma=False, allow=True)
            self.assertNotIn("private", str(raised.exception))

    def test_failed_prefix_does_not_qualify_or_leak(self):
        observations = []
        with self.assertRaisesRegex(ScenarioFailure, "^radius_renewal.mount$"):
            run_scenarios(FailedClient(), EmptyResponder(), lambda _: {}, lambda: None, observations)
        self.assertFalse(observations[-1]["passed"])
        self.assertNotIn("private", json.dumps(observations))
        self.assertFalse(successful_comparison({"candidate": observations, "oracle": observations}, {}))

    def test_a_local_success_without_real_pap_cannot_qualify(self):
        observations = []
        with self.assertRaisesRegex(ScenarioFailure, "^radius_renewal.login$"):
            run_scenarios(LocalOnlyClient(), EmptyResponder(), lambda _: {}, lambda: None, observations)
        self.assertFalse(observations[-1]["provider_checked"])
        self.assertFalse(observations[-1]["passed"])
        self.assertNotIn("private", json.dumps(observations))
        self.assertFalse(successful_comparison({"candidate": observations, "oracle": observations}, {}))

    def test_renewal_response_identity_rejects_wrong_echo_and_accessor_bearer(self):
        for leak_accessor, failed_case in [(False, "self"), (True, "accessor")]:
            observations = []
            responder = ObservedResponder()
            with self.assertRaisesRegex(ScenarioFailure, "^radius_renewal." + failed_case + ".token_response_shape$"):
                run_scenarios(WrongRenewalEchoClient(responder, leak_accessor=leak_accessor), responder, lambda _: {}, lambda: None, observations)
            self.assertFalse(observations[-1]["passed"])
            self.assertNotIn("private", json.dumps(observations))
            self.assertFalse(successful_comparison({"candidate": observations, "oracle": observations}, {}))

    def test_accessor_echo_allows_only_missing_or_empty_token(self):
        for value in (None, ""):
            self.assertTrue(renewal_token_shape({"client_token": value}, "private-target", via_accessor=True))
        for value in ("private-target", "private-other-token", False, 0, []):
            self.assertFalse(renewal_token_shape({"client_token": value}, "private-target", via_accessor=True))

    def test_wrapping_never_accepts_exposed_or_reused_target_bearer(self):
        valid = {"wrap_info": {"token": "private-wrapper"}}
        self.assertTrue(wrapped_renewal_shape(valid, "private-target"))
        for body in [dict(valid, auth={"client_token": "private-target"}),
                     dict(valid, client_token="private-target"),
                     dict(valid, data={"private": "data"}),
                     {"wrap_info": {"token": "private-target"}}, {}]:
            self.assertFalse(wrapped_renewal_shape(body, "private-target"))

    def test_configuration_adaptation_is_explicit(self):
        self.assertIs(ADAPTATION["configuration_api_parity"], False)
        self.assertIn("enrolled", ADAPTATION["candidate"])
        self.assertIn("host, port", ADAPTATION["oracle"])


if __name__ == "__main__":
    unittest.main()
