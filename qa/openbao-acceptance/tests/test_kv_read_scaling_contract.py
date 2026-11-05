"""The immutable-read profile must retain its full logical scale and record owner."""
from pathlib import Path
import unittest
import kv_read_scaling_live as fixture


class KvReadScalingContractTests(unittest.TestCase):
    def test_declared_workload_is_not_reduced_to_make_ci_green(self):
        self.assertEqual(fixture.PAYLOAD_BYTES, 224 * 1024)
        self.assertEqual(fixture.GROWTH_COUNTS, (8, 32, 64))
        self.assertEqual(fixture.READS_PER_POINT, 24)
        self.assertGreaterEqual(fixture.GROWTH_COUNTS[-1] * fixture.PAYLOAD_BYTES,
                                14 * 1024 * 1024)

    def test_setup_uses_current_record_owner_not_legacy_opaque_kv2(self):
        source = Path(fixture.__file__).read_text()
        self.assertIn("'record_oriented_writes': True", source)
        self.assertIn("'sys/mounts/read-scale'", source)
        self.assertIn("'options':{'version':'1'}", source)
        self.assertIn("before.get('state_storage_format') == 'heptabao-state-records-v5'", source)
        self.assertNotIn("secret/data/growth", source)
        self.assertNotIn("secret/metadata", source)

    def test_read_semantics_and_durable_nonmutation_remain_mandatory(self):
        source = Path(fixture.__file__).read_text()
        for marker in ("read_exact", "shallow_list", "scan_ignores_pagination",
                       "no_read_state_or_replay_mutation", "every_read_audited",
                       "actual_immutable_dispatch", "reopened_read_exact",
                       "all_declared_growth_points", "unchanged_logical_payload_scale"):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)


if __name__ == '__main__':
    unittest.main()
