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

    def test_capacity_extension_is_explicit_bounded_and_atomically_published(self):
        service = (ROOT/'crates/heptabao-server/src/service.rs').read_text()
        lib = (ROOT/'crates/heptabao-server/src/lib.rs').read_text()
        owner_store = (ROOT/'crates/heptabao-server/src/service_owner_store.rs').read_text()
        legacy_state_store = (ROOT/'crates/heptabao-server/src/service_state_store.rs').read_text()
        ha_state = (ROOT/'crates/heptabao-server/src/ha_state.rs').read_text()
        durable = (ROOT/'crates/heptabao-durable-service/src/capacity.rs').read_text()

        self.assertIn(
            'MAX_STATE_BYTES: usize = state_store::MAX_SERIALIZED_STATE_BYTES',
            service,
        )
        self.assertIn('MAX_APPLICATION_STATE_BYTES: usize = 16 * 1024 * 1024', lib)
        self.assertIn(
            'MAX_SERIALIZED_STATE_BYTES: usize = crate::MAX_APPLICATION_STATE_BYTES',
            owner_store,
        )
        self.assertIn('MAX_STATE_BYTES: usize = crate::MAX_APPLICATION_STATE_BYTES', ha_state)
        self.assertIn('STATE_CHUNK_BYTES: usize = 512 * 1024', owner_store)
        self.assertIn('heptabao-state-owners-v4', owner_store)
        for owner in ['namespaces', 'auth', 'engines', 'database', 'raft_admin']:
            self.assertIn(f'"{owner}"', owner_store)
        # V1-V3 is retained strictly as a migration reader, not the current writer.
        self.assertIn('heptabao-state-chunks-v1', legacy_state_store)
        self.assertIn('Self::persist_owner_state_batch(', service)
        # The owner write plan is deliberately isolated in its storage module;
        # keep this check anchored to the module that owns the implementation
        # instead of requiring a stale call-site in service.rs.
        self.assertIn('OwnerWritePlan::new(', owner_store)
        self.assertIn('let replay_epoch = durable.replay_epoch();', service)
        self.assertIn('durable.apply_batch_in_replay_epoch(', service)
        self.assertIn('durable.apply_batch_with_compaction_in_replay_epoch(', service)
        self.assertIn('pub fn apply_batch_in_replay_epoch(', durable)
        self.assertIn('pub fn apply_batch_with_compaction_in_replay_epoch(', durable)

        navigation = (ROOT/'docs/storage/HEPTABAO_CAPACITY_AND_GROWTH.md').read_text()
        self.assertIn('docs/operations/HEPTABAO_CAPACITY_AND_GROWTH.md', navigation)
        self.assertIn('16 MiB', navigation)
        self.assertIn('content-defined', navigation)
        self.assertIn('replay', navigation.lower())
        contract = (ROOT/'docs/operations/HEPTABAO_CAPACITY_AND_GROWTH.md').read_text()
        self.assertIn('16 MiB', contract)
        self.assertIn('content-defined', contract)
        self.assertIn('capacity_live.py', contract)
        self.assertIn('write-amplification curves', contract.lower())
        self.assertIn('recovery', contract.lower())

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
