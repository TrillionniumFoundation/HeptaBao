"""Controller regressions only: no server, physical-host or replacement claim."""
import base64
import copy
from email.message import Message
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import native_v6_ha_official_history_live as profile
import native_v6_ha_official_history_wire as wire

exact = profile.exact


def make_source(root):
    """Synthetic controller inputs, not a receipt from an actual official binary."""
    (root / "source-api-oracle").mkdir(mode=0o700)
    entry = {"created_time": "2026-10-29T00:00:01.000000001Z",
        "updated_time": "2026-10-29T00:00:19.000000001Z", "current_version": 19,
        "oldest_version": 0, "current_metadata_version": 2, "max_versions": 25,
        "cas_required": True, "metadata_cas_required": True, "delete_version_after": "0s",
        "custom_metadata": {"purpose": "synthetic-native-migration", "revision": "second"},
        "versions": {}}
    config = {key: entry[key] for key in ("max_versions", "cas_required", "metadata_cas_required", "delete_version_after")}
    metadata, observations, rows = copy.deepcopy(entry), {}, []
    for version in range(1, 20):
        key = str(version)
        vm = {"created_time": f"2026-10-29T00:00:{version:02}.000000001Z",
              "deletion_time": "2026-10-29T00:01:00.000000001Z" if version == 1 else "",
              "destroyed": version == 2}
        payload = exact.payload(version, 17, 2 * exact.MIB)
        entry["versions"][key] = {**vm, "source_deletion_time": "", "data": None if version == 2 else payload}
        metadata["versions"][key] = vm
        actual = {**payload, "wide_integer": 9007199254740992,
                  "exact_decimal": exact.Decimal("0.12345678901234568")}
        original_meta = {**vm, "version": version, "custom_metadata": entry["custom_metadata"]}
        observations[key] = {"status": 404 if version < 3 else 200,
            "data": {"data": None if version < 3 else actual, "metadata": original_meta}}
        source = {"data": {"data": actual, "metadata": {**original_meta,
                  "deletion_time": "", "destroyed": False, "custom_metadata": {"revision": "first"}}}}
        raw = exact.canonical(source)
        exact.private_write(root / "source-api-oracle" / f"version-{version:04}.json", raw)
        rows.append({"endpoint": "source", "method": "GET", "path": "secret/data/history?version=" + key,
                     "status": 200, "same_response_decoded": True, "body_bytes": len(raw),
                     "body_sha256": profile.digest(raw)})
    bundle = {"schema": "openbao270-kv2-lossless-v1", "config": config, "entries": {"history": entry}}
    raw = exact.canonical(bundle)
    exact.private_write(root / "source-bundle.json", raw)
    identity = {"product": "OpenBao", "version": "2.7.1", "storage": "pebbledb",
        "cluster_id": "unit-controller-synthetic-not-an-official-run", "tls_verified": True,
        "synthetic_only": True, "server_mode": "server_not_dev", "archive_member_matches_executable": True,
        "provenance_url": "https://github.com/openbao/openbao/releases/tag/v2.7.1",
        **profile.official.PINNED_RELEASES["2.7.1"][("linux", "amd64")]}
    receipt = {"schema": "heptabao.openbao271-kv2-lossless-native-live.v1", "status": "passed",
        "profile": "full34", "official_version": "2.7.1", "migration_lane": "native-large",
        "full34_qualified": True, "synthetic_only": True, "source_unchanged_at_cleanup": True,
        "checks": [{"case": case, "passed": True} for case in exact.CHECKS],
        "official_identity": identity, "migration_invocations": [{"operation": "export", "status": "completed",
            "retried": False, "receipt": {"lane": "native-large", "bytes": len(raw), "sha256": profile.digest(raw)}}],
        "source_api_wire_observations": rows,
        "source_history_sha256": profile.digest(exact.canonical({"config": config, "metadata": metadata,
                                                                "versions": observations}))}
    raw_receipt = exact.canonical(receipt)
    exact.private_write(root / "summary.json", raw_receipt)
    return profile.digest(raw_receipt), receipt


class EvidenceAdmission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.pin, cls.receipt = make_source(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_full_19_history_and_raw_precision_are_distinct_from_api_projection(self):
        raw, original, api, _, _ = profile.admit_source(self.root, self.pin)
        retained = exact.decode(raw)["entries"]["history"]["versions"]
        self.assertEqual(set(retained), {str(v) for v in range(1, 20)})
        self.assertEqual(sum(len(retained[str(v)]["data"]["payload"]) for v in range(3, 20)), 34 * exact.MIB)
        self.assertEqual(retained["3"]["data"]["wide_integer"], 9007199254740993)
        self.assertEqual(api["3"]["wide_integer"], 9007199254740992)
        self.assertEqual(original["versions"]["1"]["status"], 404)
        self.assertIsNone(retained["2"]["data"])

    def test_tampered_actual_api_response_rejected_even_when_pass_flags_remain(self):
        path = self.root / "source-api-oracle/version-0003.json"
        original = path.read_bytes()
        try:
            exact.private_write(path, original.replace(b"9007199254740992", b"9007199254740991"), replace=True)
            with self.assertRaisesRegex(profile.base.FixtureError, "source_api_response_binding"):
                profile.admit_source(self.root, self.pin)
        finally:
            exact.private_write(path, original, replace=True)

    def test_receipt_pin_and_release_identity_are_not_pass_flag_substitutes(self):
        with self.assertRaisesRegex(profile.base.FixtureError, "source_receipt_pin"):
            profile.admit_source(self.root, "0" * 64)
        path = self.root / "summary.json"
        original = path.read_bytes()
        try:
            changed = copy.deepcopy(self.receipt)
            changed["official_identity"]["binary_sha256"] = "0" * 64
            raw = exact.canonical(changed)
            exact.private_write(path, raw, replace=True)
            with self.assertRaisesRegex(profile.base.FixtureError, "source_official_identity"):
                profile.admit_source(self.root, profile.digest(raw))
        finally:
            exact.private_write(path, original, replace=True)

    def test_complete_31_evidence_required_and_original_98_denominator_preserved(self):
        self.assertEqual(len(profile.direct.DIRECT_CHECKS), 98)
        self.assertEqual(len(profile.EXTRA_CHECKS), 30)
        self.assertFalse(profile.direct.DIRECT_CHECKS & profile.EXTRA_CHECKS)
        path = self.root / "summary.json"
        original = path.read_bytes()
        try:
            changed = copy.deepcopy(self.receipt)
            changed["checks"].pop()
            raw = exact.canonical(changed)
            exact.private_write(path, raw, replace=True)
            with self.assertRaisesRegex(profile.base.FixtureError, "source_cohort"):
                profile.admit_source(self.root, profile.digest(raw))
        finally:
            exact.private_write(path, original, replace=True)


class MutationAndTlsCustody(unittest.TestCase):
    def test_history_observation_survives_actual_base_history_dictionary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = profile.base.Node(1, "unit-owned", "192.168.0.10", "/unit-owned", 18200, 18201)
            args = SimpleNamespace(work_root=root, source_commit="a" * 40, source_tree="b" * 40)
            run = object.__new__(profile.OfficialHistoryRun)
            # Use the real inherited constructor that owns the core CAS ledger.
            profile.native.NativeRun.__init__(run, args, [node], None, {}, {}, {"1": "c" * 64})
            core_history = run.history
            core_history["acknowledged-core-history"] = {"version": 1}
            run.report["official_history_observations"] = []
            observed = {"versions": {"1": {"status": 200, "data": {"fixture": True}}}}
            with patch.object(profile.exact, "observations", return_value=observed) as observe:
                run.verify_history([node], observed)
            self.assertEqual(observe.call_count, 1)
            self.assertIs(run.history, core_history)
            self.assertEqual(run.history, {"acknowledged-core-history": {"version": 1}})
            self.assertEqual(len(run.report["official_history_observations"]), 1)
            self.assertEqual(run.report["official_history_observations"][0]["node"], 1)

    def test_binary_download_requires_unambiguous_complete_length(self):
        headers = Message()
        response = SimpleNamespace(headers=headers, status=200)
        with self.assertRaises(ValueError):
            wire.response_length(response, 131 * exact.MIB, binary=True)
        headers["Content-Length"] = "123"
        self.assertEqual(wire.response_length(response, 131 * exact.MIB, binary=True), 123)
        headers["Transfer-Encoding"] = "chunked"
        with self.assertRaises(ValueError):
            wire.response_length(response, 131 * exact.MIB, binary=True)
        del headers["Transfer-Encoding"]
        headers["Content-Length"] = "123"
        with self.assertRaises(ValueError):
            wire.response_length(response, 131 * exact.MIB, binary=True)

    def test_timeout_records_one_exact_body_intent_unknown_effect_and_reaps_original_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = profile.base.Node(1, "unit-owned", "192.168.0.10", "/unit-owned", 18200, 18201)
            ledger = profile.native.recovery.FixtureRecoveryLedger(root, "unit-run", "a" * 40, "b" * 40,
                       [node], {"1": "c" * 64}, error_type=profile.base.FixtureError)
            ledger.preserve_initialization(node, {"root_token": "unit-root", "keys_base64": ["unit-key"]})
            run = object.__new__(profile.OfficialHistoryRun)
            run.nodes, run.work, run.stage, run.recovery = [node], root, "unit-timeout", ledger
            run.ca_sha256, run.root_token = "d" * 64, "unit-root"
            run.peers = {"1": {"certificate_sha256": "e" * 64}}
            run.report = {"official_chain_mutations": [], "official_history_chain_qualified": False}
            run.checkpoint = lambda: None
            child = Mock()
            child.communicate.side_effect = [subprocess.TimeoutExpired("owned-leaf", 15), (b"", b"")]
            child.poll.side_effect = [None, 0]
            with patch.object(profile.subprocess, "Popen", return_value=child) as spawn:
                with self.assertRaises(subprocess.TimeoutExpired):
                    run.wire(node, "POST", "oracle271/undelete/history", {"versions": [1]})
            self.assertEqual(spawn.call_count, 1)
            child.kill.assert_called_once()
            self.assertEqual(child.communicate.call_count, 2)
            intent = json.loads((ledger.root / "mutation-00001.intent.json").read_text())
            self.assertEqual(intent["request_body_sha256"], profile.digest(exact.canonical({"versions": [1]})))
            outcome = json.loads((ledger.root / "mutation-00001.outcome.json").read_text())
            self.assertEqual(outcome["dispatch_outcome"], "unknown")
            self.assertEqual(ledger.public_receipt["mutation_intents"], 1)
            self.assertEqual(ledger.public_receipt["unknown_transport_outcomes"], 1)
            self.assertFalse(run.report["official_history_chain_qualified"])
            self.assertNotIn("effect_observation", run.report["official_chain_mutations"][0])
            self.assertTrue(run.report["official_chain_mutations"][0]["owned_leaf_wait_completed"])

    def test_same_connection_wrong_leaf_rejects_before_http_credentials_or_body(self):
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca.crt"
            exact.private_write(ca, b"unit-pem-context-is-mocked")
            packet = {"ip": "192.168.0.10", "port": 18200, "ca_file": str(ca),
                "ca_sha256": profile.digest(ca.read_bytes()), "leaf_sha256": profile.digest(b"enrolled-leaf"),
                "token": "unit-root", "method": "POST", "path": "oracle271/undelete/history",
                "body": base64.b64encode(b'{"versions":[1]}').decode(), "archive_in": None,
                "archive_sha256": None, "archive_out": None}
            context, connection, tcp = Mock(), Mock(), Mock()
            context.wrap_socket.return_value.getpeercert.return_value = b"wrong-leaf"
            with patch.object(wire.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(packet).encode()))), \
                 patch.object(wire.ssl, "create_default_context", return_value=context), \
                 patch.object(wire.socket, "create_connection", return_value=tcp), \
                 patch.object(wire.http.client, "HTTPConnection", return_value=connection):
                with self.assertRaises(ValueError):
                    wire.main()
            context.wrap_socket.assert_called_once_with(tcp, server_hostname="192.168.0.10")
            connection.request.assert_not_called()
            connection.close.assert_called_once()
            tcp.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
