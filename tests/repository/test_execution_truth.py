"""Current text must not contradict the source or re-use stale fixture counts."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('execution_truth',ROOT/'scripts/validate_execution_truth.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class ExecutionTruthTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        for name in module.FILES:
            dest=self.root/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,dest)

    def test_current_truth(self): self.assertEqual(module.validate(self.root),[])

    def test_stale_jwks_denial_rejected(self):
        p=self.root/'docs/auth/HEPTABAO_SINGLE_NODE_AUTH.md'
        p.write_text(p.read_text()+'\nIt still does not fetch a `jwks_url`\n')
        self.assertTrue(module.validate(self.root))

    def test_stale_postgres_execution_denial_rejected(self):
        p=self.root/'README.md'
        p.write_text(p.read_text()+'\nActual PostgreSQL server/SQL acceptance has not been executed in this delivery\n')
        self.assertTrue(module.validate(self.root))

    def test_old_fixed_count_rejected(self):
        p=self.root/'planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml'
        p.write_text(p.read_text().replace('exact compatibility denominator is enforced but remaining surface fixtures are incomplete',
                                         'exact compatibility denominator is enforced but 47 surface fixtures remain incomplete'))
        self.assertTrue(module.validate(self.root))

    def test_source_binding_cannot_be_removed(self):
        p=self.root/'docs/plan/HEPTABAO_SINGLE_NODE_EXECUTION_STATUS.md'
        p.write_text(p.read_text().replace('34924284502','old-run'))
        self.assertTrue(module.validate(self.root))

    def test_removed_native_api_rejected(self):
        p=self.root/'crates/heptabao-durable-service/src/lib.rs'
        p.write_text(p.read_text().replace('pub fn put_with_compaction(', 'pub fn removed('))
        self.assertTrue(module.validate(self.root))

    def test_service_writer_requires_epoch_aware_compaction(self):
        p=self.root/'crates/heptabao-server/src/service.rs'
        p.write_text(p.read_text().replace(
            'apply_batch_with_compaction_in_replay_epoch(',
            'apply_batch_with_compaction(',
            1,
        ))
        self.assertIn(
            'atomic batch compaction is not bound to the current replay epoch in the real Service writer',
            module.validate(self.root),
        )

    def test_service_writer_cannot_hardcode_retired_epoch(self):
        p=self.root/'crates/heptabao-server/src/service.rs'
        p.write_text(p.read_text().replace(
            'let replay_epoch = durable.replay_epoch();',
            'let replay_epoch = 0;',
            1,
        ))
        self.assertIn(
            'atomic batch compaction is not bound to the current replay epoch in the real Service writer',
            module.validate(self.root),
        )

    def test_missing_document_rejected(self):
        (self.root/'README.md').unlink()
        self.assertTrue(module.validate(self.root))

    def test_additional_epoch_validation_is_not_a_source_shape_failure(self):
        p = self.root/'crates/heptabao-server/src/service.rs'
        guard = """
        // A safety check must not make the compaction drift guard fail.
        if replay_epoch != target_replay_epoch {
            return Err(ServiceError::ReplayEpochMismatch);
        }
"""
        p.write_text(p.read_text().replace(
            'let replay_epoch = durable.replay_epoch();',
            'let replay_epoch = durable.replay_epoch();' + guard,
            1,
        ))
        self.assertEqual(module.validate(self.root), [])

    def test_epoch_binding_tolerates_rustfmt_line_breaks(self):
        p = self.root/'crates/heptabao-server/src/service.rs'
        p.write_text(p.read_text().replace(
            'durable.apply_batch_with_compaction_in_replay_epoch(',
            'durable\n            .apply_batch_with_compaction_in_replay_epoch(',
            1,
        ))
        self.assertEqual(module.validate(self.root), [])

    def test_unrelated_helper_cannot_supply_missing_writer_binding(self):
        p = self.root/'crates/heptabao-server/src/service.rs'
        source = p.read_text().replace(
            'apply_batch_with_compaction_in_replay_epoch(',
            'apply_batch_with_compaction(', 1,
        )
        source += """
    fn unrelated_helper() {
        let replay_epoch = durable.replay_epoch();
        durable.apply_batch_with_compaction_in_replay_epoch(replay_epoch,);
    }
"""
        p.write_text(source)
        self.assertIn(
            'atomic batch compaction is not bound to the current replay epoch in the real Service writer',
            module.validate(self.root),
        )
