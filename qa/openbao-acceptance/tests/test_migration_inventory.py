"""Selected-inventory consistency tests; these are not OpenBao compatibility evidence."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import BaoError, Response, digest
from migrate_kv2 import checkpoint_binding, selected_inventory_digest, snapshot_inventory


def metadata(version=1):
    return {"current_version": version,
            "versions": {str(i): {"destroyed": False, "deletion_time": ""}
                         for i in range(1, version + 1)},
            "cas_required": True, "custom_metadata": {"scope": "synthetic"},
            "max_versions": 5, "delete_version_after": "0s"}


class Source:
    def __init__(self, mutate_after=False):
        self.meta = {"one": metadata(), "two": metadata()}
        self.values = {"one": {1: {"value": "one"}}, "two": {1: {"value": "two"}}}
        self.mutate_after = mutate_after
        self.metadata_reads = 0

    def request(self, method, path, payload=None):
        if path == "/v1/sys/mounts":
            return Response(200, {"data": {"secret/": {"type": "kv-v2"}}})
        if "/metadata/" in path:
            key = path.rsplit("/", 1)[1]
            self.metadata_reads += 1
            if self.mutate_after and self.metadata_reads == 7:
                self.meta[key]["custom_metadata"]["scope"] = "changed"
            return Response(200, {"data": copy.deepcopy(self.meta[key])})
        key = path.split("/v1/secret/data/", 1)[1].split("?", 1)[0]
        version = int(path.split("?version=", 1)[1])
        return Response(200, {"data": {"data": copy.deepcopy(self.values[key][version]),
                                        "metadata": {"version": version}}})


class InventoryTests(unittest.TestCase):
    def test_selected_inventory_is_deterministic_and_digest_bound(self):
        source = Source()
        records, inventory_digest = snapshot_inventory(source, "secret", ["one", "two"])
        self.assertEqual(["one", "two"], [record["key"] for record in records])
        self.assertEqual(64, len(inventory_digest))
        manifest = {"mount": "secret", "objects": [
            {"key": record["key"], "source_digest": digest(record["source_metadata"]),
             "record_digest": digest(record)} for record in records]}
        self.assertEqual(inventory_digest, digest(manifest))

    def test_checkpoint_binding_reuses_the_exact_inventory_digest(self):
        source = Source()
        records, inventory_digest = snapshot_inventory(source, "secret", ["one", "two"])
        self.assertEqual(inventory_digest, selected_inventory_digest("secret", records))
        source_identity = {
            "endpoint": "https://source.example",
            "namespace": "",
            "mount": "secret",
            "cluster_id": "source-cluster",
            "version": "2.6.2",
        }
        target_identity = {
            "endpoint": "https://target.example",
            "namespace": "",
            "mount": "secret",
            "cluster_id": "target-cluster",
        }
        self.assertEqual(
            checkpoint_binding(
                source_identity,
                ["one", "two"],
                inventory_digest,
                target_identity,
            ),
            {
                "source_identity": source_identity,
                "keys_digest": digest(["one", "two"]),
                "inventory_digest": inventory_digest,
                "profile": "heptabao.kv2-migration.v1",
                "target_identity": target_identity,
            },
        )

    def test_inventory_rejects_source_change_during_read(self):
        with self.assertRaisesRegex(BaoError, "source_inventory_changed_during_snapshot"):
            snapshot_inventory(Source(mutate_after=True), "secret", ["one", "two"])

    def test_inventory_requires_unique_bounded_allowlist(self):
        with self.assertRaisesRegex(BaoError, "bounded_unique_key_allowlist_required"):
            snapshot_inventory(Source(), "secret", ["one", "one"])


if __name__ == "__main__":
    unittest.main()
