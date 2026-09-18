"""Mutation tests for the current-schema/backend documentation boundary."""
import importlib.util
import re
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('runtime_doc_truth', ROOT / 'scripts/validate_runtime_doc_truth.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RuntimeDocumentationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        paths = [
            module.FORMAT,
            module.ENGINE,
            module.SERVER,
            module.ARCH,
            module.CAPACITY,
            module.REPLAY,
            module.REPLAY_HA,
            module.ACCEPTANCE,
            module.CORPUS,
            module.SERVER_LIB,
            module.STATE_STORE,
            'README.md',
            'docs/CURRENT_DOCUMENTATION.md',
            'crates/heptabao-server/src/service.rs',
            'crates/heptabao-server/src/engines.rs',
        ]
        for path in paths:
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)

    def change(self, path, before, after):
        target = self.root / path
        text = target.read_text()
        self.assertIn(before, text)
        target.write_text(text.replace(before, after))

    def test_current_documents_match_source(self):
        self.assertEqual(module.validate(self.root), [])

    def test_schema_change_requires_current_contract_update(self):
        source=(self.root/'crates/heptabao-server/src/service.rs').read_text()
        current=int(re.search(r'CURRENT_STATE_SCHEMA: u32 = (\d+)',source).group(1))
        self.change('crates/heptabao-server/src/service.rs', f'CURRENT_STATE_SCHEMA: u32 = {current}', f'CURRENT_STATE_SCHEMA: u32 = {current+1}')
        self.assertIn('current format contract differs from the source schema', module.validate(self.root))

    def test_backend_addition_requires_state_diagram_update(self):
        self.change('crates/heptabao-server/src/engines.rs', 'enum Backend {', 'enum Backend {\n    NewBackend,')
        self.assertIn('engine state diagram differs from current Backend variants', module.validate(self.root))

    def test_old_current_tense_schema_is_rejected(self):
        with (self.root / module.ARCH).open('a') as stream:
            stream.write('\nService schema remains 3.\n')
        self.assertTrue(any('obsolete current-tense' in p for p in module.validate(self.root)))

    def test_false_unsupported_mount_claim_is_rejected(self):
        with (self.root / module.ENGINE).open('a') as stream:
            stream.write('\nPKI, SSH, database, LDAP,\nKubernetes and other engine types return HTTP 501\n')
        self.assertIn('engine guide still denies currently implemented backends', module.validate(self.root))

    def test_missing_contract_fails_closed(self):
        (self.root / module.FORMAT).unlink()
        self.assertTrue(module.validate(self.root))

    def test_commented_replay_epoch_field_cannot_fake_runtime_anchor(self):
        path = self.root / 'crates/heptabao-server/src/service.rs'
        source = path.read_text()
        match = re.search(r'(?m)^(\s*)replay_epoch\s*:\s*u64\s*,', source)
        self.assertIsNotNone(match)
        source = (
            source[:match.start()]
            + match.group(1)
            + '// replay_epoch: u64, stale documentation example only\n'
            + match.group(1)
            + 'replay_generation: u64,'
            + source[match.end():]
        )
        path.write_text(source)
        self.assertIn(
            'current replay source missing semantic anchor: cluster replay_epoch field',
            module.validate(self.root),
        )

    def test_commented_replay_retirement_call_cannot_fake_runtime_anchor(self):
        path = self.root / 'crates/heptabao-server/src/service.rs'
        source = path.read_text()
        source = source.replace('retire_replay_epoch(', 'retire_replay_generation(', 1)
        source += '\n// retire_replay_epoch(fake);\n'
        path.write_text(source)
        self.assertIn(
            'current replay source missing semantic anchor: durable replay retirement call',
            module.validate(self.root),
        )

    def test_missing_navigation_is_rejected(self):
        self.change('docs/CURRENT_DOCUMENTATION.md', 'HEPTABAO_CURRENT_STATE_FORMAT.md', 'unrelated.md')
        self.assertTrue(any('missing current state-format navigation' in p for p in module.validate(self.root)))

    def test_historical_increment_is_not_claimed_current(self):
        with (self.root / module.ARCH).open('a') as stream:
            stream.write('\nThe wrapping increment originally introduced schema 3.\n')
        self.assertEqual(module.validate(self.root), [])

    def test_replacement_map_cannot_drop_a_surface(self):
        path=self.root/module.ACCEPTANCE
        lines=path.read_text().splitlines()
        lines=[line for line in lines if not line.startswith('| `HB-SURFACE-IDENTITY`')]
        path.write_text('\n'.join(lines)+'\n')
        self.assertIn('replacement execution map differs from fixed corpus rows', module.validate(self.root))

    def test_replacement_map_cannot_promote_fixture_state(self):
        self.change(module.ACCEPTANCE, '`DEFINED_NOT_IMPLEMENTED` | None', '`IMPLEMENTED_SCOPED` | None')
        self.assertIn('replacement execution map differs from fixed corpus rows', module.validate(self.root))

    def test_replacement_map_cannot_duplicate_its_denominator(self):
        path=self.root/module.ACCEPTANCE
        path.write_text(path.read_text()+path.read_text())
        self.assertIn('missing or ambiguous replacement surface projection', module.validate(self.root))
