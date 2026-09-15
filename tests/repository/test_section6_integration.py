from pathlib import Path
import unittest
import yaml
ROOT = Path(__file__).resolve().parents[2]


class SectionSixIntegrationTests(unittest.TestCase):
    def test_current_guides_do_not_deny_remote_keys_or_real_postgres(self):
        text = (ROOT/'docs/auth/HEPTABAO_SINGLE_NODE_AUTH.md').read_text()
        self.assertNotIn('It still does not fetch a `jwks_url`', text)
        self.assertIn('HEPTABAO_REMOTE_JWT_KEYS.md', text)
        self.assertNotIn('Actual PostgreSQL server/SQL acceptance has not been executed', (ROOT/'README.md').read_text())

    def test_blocker_corpus_count_is_not_a_duplicated_stale_constant(self):
        blockers = (ROOT/'planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml').read_text()
        self.assertNotIn('remaining 47 surfaces', blockers)
        self.assertNotIn('47 surface fixtures', blockers)
        self.assertIn('derived from the fixed corpus', blockers)

    def test_current_readonly_ci_requires_both_real_profiles(self):
        workflow = (ROOT/'.github/workflows/codex-openbao-replacement-ci.yml').read_text()
        for required in ['scripts/surface_work.py', 'capacity_live.py', 'transit_migration_live.py',
                         'postgres_live.py', 'run_official_comparison.py', 'ha_network_partition.py']:
            self.assertIn(required, workflow)
        config = yaml.safe_load(workflow)
        self.assertEqual(config['permissions'], {'contents': 'read'})
        self.assertIn('prospective-merge', workflow)
        self.assertNotIn('continue-on-error: true', workflow)

    def test_capacity_extension_does_not_silently_raise_source_limits(self):
        source = (ROOT/'crates/heptabao-server/src/service.rs').read_text()
        self.assertIn('MAX_STATE_BYTES: usize = 768 * 1024', source)
        self.assertIn('.put_with_compaction(request)', source)
        alias = (ROOT/'crates/heptabao-durable-service/src/capacity.rs').read_text()
        self.assertIn('pub fn put_with_maintenance(', alias)
        self.assertIn('self.put_with_compaction(request)', alias)
        contract = (ROOT/'docs/storage/HEPTABAO_CAPACITY_AND_GROWTH.md').read_text()
        self.assertIn('32,000', contract)
        self.assertIn('whole state', contract)

    def test_all_current_portals_link_the_increment_without_a_second_master(self):
        for name in ['README.md', 'docs/CURRENT_DOCUMENTATION.md']:
            text = (ROOT/name).read_text()
            self.assertIn('HEPTABAO_SECTION6_EXECUTION.md', text)
            self.assertIn('HEPTABAO_SURFACE_WORK_V1.json', text)
        for name in ['docs/storage/HEPTABAO_CAPACITY_AND_GROWTH.md',
                     'docs/migration/HEPTABAO_TRANSIT_REENCRYPTION.md']:
            self.assertTrue((ROOT/name).is_file())


if __name__ == '__main__':
    unittest.main()
