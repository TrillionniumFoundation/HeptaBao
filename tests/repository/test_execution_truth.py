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
        p.write_text(p.read_text().replace(
            'exact compatibility denominator and all inventoried scoped fixtures are implemented; independent exact-head differential admission is pending',
            'exact compatibility denominator and 47 surface fixtures are implemented; independent exact-head differential admission is pending',
        ))
        self.assertTrue(module.validate(self.root))

    def test_source_binding_cannot_be_removed(self):
        p=self.root/'docs/plan/HEPTABAO_SINGLE_NODE_EXECUTION_STATUS.md'
        p.write_text(p.read_text().replace('34924284502','old-run'))
        self.assertTrue(module.validate(self.root))

    def test_removed_native_api_rejected(self):
        p=self.root/'crates/heptabao-durable-service/src/lib.rs'
        p.write_text(p.read_text().replace('pub fn put_with_compaction(', 'pub fn removed('))
        self.assertTrue(module.validate(self.root))

    def test_replay_epoch_source_layout_is_not_a_document_truth_gate(self):
        p=self.root/'crates/heptabao-server/src/service.rs'
        source=p.read_text()
        # Harmless formatting/helper extraction must not turn documentation
        # validation into a Rust parser. Compiled Service/HA profiles own this
        # behavioral invariant.
        source=source.replace(
            'let replay_epoch = durable.replay_epoch();',
            'let replay_epoch = durable\n            .replay_epoch();',
            1,
        )
        p.write_text(source)
        self.assertEqual(module.validate(self.root),[])

    def test_missing_document_rejected(self):
        (self.root/'README.md').unlink()
        self.assertTrue(module.validate(self.root))


