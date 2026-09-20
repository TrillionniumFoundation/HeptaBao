"""Prevent provider failures or lost HTTP replies from masquerading as HA fencing."""
from pathlib import Path
import sys
import unittest
import struct
import hmac
import hashlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from radius_renewal_ha import authority_denied, profile_configuration, native_nas_valid
from radius_renewal_live import SECRET, USERNAME, PASSWORD, md5, pap_packet_response


class RenewalFaultClassification(unittest.TestCase):
    def test_native_profile_uses_api_secret_and_only_fixed_process_address(self):
        endpoint, config = profile_configuration(18120, native=True)
        self.assertEqual(endpoint, {"origin":"radius://127.0.0.1:18120", "address":"127.0.0.1:18120",
                                  "server_name":"127.0.0.1", "ca_pem":"", "path_prefix":"/"})
        self.assertNotIn("shared_secret", endpoint)
        self.assertNotIn("url", config)
        self.assertEqual((config["host"],config["port"],config["secret"]), ("127.0.0.1",18120,SECRET.decode()))
        self.assertEqual((config["read_timeout"],config["dial_timeout"]),(3,3))
        legacy_endpoint, legacy_config = profile_configuration(18120)
        self.assertEqual(legacy_endpoint["shared_secret"],SECRET.decode())
        self.assertEqual(legacy_config,{"url":legacy_endpoint["origin"],"token_policies":["default"],
                                       "token_ttl":120,"token_max_ttl":600})

    def test_native_nas_additions_remain_covered_by_strict_packet_authentication(self):
        authenticator=bytes(range(16));padded=PASSWORD+b"\0"*((-len(PASSWORD))%16)
        encrypted=bytearray();previous=authenticator
        for offset in range(0,len(padded),16):
            block=bytes(a^b for a,b in zip(padded[offset:offset+16],md5(SECRET,previous)))
            encrypted.extend(block);previous=block
        attrs=bytes([1,len(USERNAME)+2])+USERNAME+bytes([2,len(encrypted)+2])+encrypted
        attrs+=bytes([5,6])+struct.pack("!I",10)+bytes([80,18])+b"\0"*16
        packet=bytearray([1,7])+struct.pack("!H",20+len(attrs))+authenticator+attrs
        packet[-16:]=hmac.new(SECRET,packet,hashlib.md5).digest()
        reply, observation=pap_packet_response(packet,require_ma=True,allow=True)
        self.assertEqual(observation,{"credentials_valid":True,"message_authenticator_present":True,"accepted":True})
        self.assertEqual(reply[0],2);self.assertTrue(native_nas_valid(packet))
        damaged=bytearray(packet);damaged[-19]^=1
        with self.assertRaises(ValueError):pap_packet_response(damaged,require_ma=True,allow=True)
        self.assertFalse(native_nas_valid(damaged))
        missing=bytearray(packet[:-18]);missing[2:4]=struct.pack("!H",len(missing))
        with self.assertRaises(ValueError):pap_packet_response(missing,require_ma=True,allow=True)

    def test_provider_failure_is_not_a_ha_pass_even_if_leader_died(self):
        for phase in ("leader_killed", "quorum_lost", "sealed"):
            for body in ({"errors": ["RADIUS provider unavailable or response unauthenticated"]},
                         {"errors": []}, {}, {"errors": "HA unavailable"}):
                self.assertFalse(authority_denied(503, body, phase))

    def test_transport_loss_only_qualifies_the_process_kill(self):
        self.assertTrue(authority_denied(None, {}, "leader_killed"))
        self.assertFalse(authority_denied(None, {}, "quorum_lost"))
        self.assertFalse(authority_denied(None, {}, "sealed"))

    def test_sealed_rejection_is_not_quorum_evidence(self):
        body = {"errors": ["online authentication authority changed"]}
        self.assertTrue(authority_denied(503, body, "sealed"))
        self.assertFalse(authority_denied(503, body, "quorum_lost"))
        self.assertTrue(authority_denied(503, {"errors": ["HA linearizable state is unavailable"]}, "quorum_lost"))


if __name__ == "__main__":
    unittest.main()
