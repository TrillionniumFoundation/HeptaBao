"""Native large CLI admission boundaries; synthetic input, no HTTP calls."""
import importlib.util
import json
from pathlib import Path
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "native_large_capacity_subject",
    ROOT / "tools/migration/openbao271_kv2_native_large_migrate.py")
subject = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = subject
SPEC.loader.exec_module(subject)


class ObservedClient:
    def __init__(self):
        self.namespace = ""
        self.limits = subject.LIMITS
        self.end = time.monotonic() + 360
        self.calls = []

    def request(self, method, route, body=None, **options):
        self.calls.append((method, route, body, options))
        return None


def bundle(paths, live=True, extra_version=False):
    at = "1970-01-01T00:01:30.000000113Z"
    entries = {}
    for index in range(paths):
        versions = {"1": {"created_time": at, "deletion_time": "", "destroyed": False,
                          "source_deletion_time": "", "data": {"index": index}}} if live else {}
        current = 1 if live else 0
        if extra_version and index == 0:
            versions["2"] = {**versions["1"], "data": {"index": index, "second": True}}
            current = 2
        entries["credential/%05d" % index] = {
            "created_time": at, "updated_time": at, "current_version": current,
            "current_metadata_version": 0, "oldest_version": 0, "max_versions": 0,
            "cas_required": False, "metadata_cas_required": False,
            "delete_version_after": "0s", "custom_metadata": None, "versions": versions}
    value = {"schema": "openbao270-kv2-lossless-v1", "entries": entries,
             "config": {"max_versions": 0, "cas_required": False,
                        "metadata_cas_required": False, "delete_version_after": "0s"}}
    return json.dumps(value, separators=(",", ":")).encode()


class NativeLargeCapacityTests(unittest.TestCase):
    def assert_forwarded_once_without_reencoding(self, raw):
        client = ObservedClient()
        subject.import_bundle(client, "secret", raw)
        self.assertEqual(len(client.calls), 1)
        method, route, forwarded, options = client.calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(route, "sys/migration/openbao/kv2/native-large?mount=secret")
        self.assertIs(forwarded, raw)
        self.assertEqual(options, {"native_import": True})

    def assert_rejected_before_request(self, raw):
        client = ObservedClient()
        with self.assertRaises(subject.DecodeError):
            subject.import_bundle(client, "secret", raw)
        self.assertEqual(client.calls, [])

    def test_actual_source_path_count_has_one_original_import(self):
        self.assert_forwarded_once_without_reencoding(bundle(40_486))

    def test_exact_joint_record_boundary(self):
        # 1 config + 49,999 metadata + 50,000 versions = 100,000 records.
        self.assert_forwarded_once_without_reencoding(bundle(49_999, extra_version=True))

    def test_one_record_over_joint_bound_never_dispatches(self):
        self.assert_rejected_before_request(bundle(50_000))

    def test_exact_path_boundary_with_metadata_only(self):
        self.assert_forwarded_once_without_reencoding(bundle(50_000, live=False))

    def test_one_path_over_bound_never_dispatches(self):
        self.assert_rejected_before_request(bundle(50_001, live=False))

    def test_duplicate_keys_never_dispatch(self):
        raw = bundle(1).replace(b'"schema":', b'"schema":"duplicate","schema":', 1)
        self.assert_rejected_before_request(raw)

    def test_only_explicit_large_profile_accepts_more_than_legacy_nodes(self):
        raw = b'[' + b'null,' * 1_000_000 + b'null]'
        with self.assertRaises(subject.DecodeError):
            subject.legacy.parse_json(raw, subject.LIMITS.bundle_bytes)
        value = subject.legacy.parse_json(raw, subject.LIMITS.bundle_bytes,
                                         maximum_nodes=subject.MAX_BUNDLE_JSON_NODES)
        self.assertEqual(len(value), 1_000_001)

    def test_large_profile_node_bound_is_not_user_selectable(self):
        for count in [True, 0, 2, 4_194_305, 10**40]:
            with self.assertRaises(subject.DecodeError):
                subject.legacy.parse_json(b"null", 4, maximum_nodes=count)
        raw = b'[' + b'null,' * (subject.MAX_BUNDLE_JSON_NODES - 1) + b'null]'
        with self.assertRaises(subject.DecodeError):
            subject.legacy.parse_json(raw, subject.LIMITS.bundle_bytes,
                                      maximum_nodes=subject.MAX_BUNDLE_JSON_NODES)


if __name__ == "__main__":
    unittest.main()
