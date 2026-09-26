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
            module.RECORD_ROOT,
            module.RECORD_CORE,
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

    def test_legacy_chunk_and_shared_owner_bounds_remain_checked(self):
        for path, before, after, expected in (
            (module.STATE_STORE, 'STATE_CHUNK_BYTES: usize = 512', 'STATE_CHUNK_BYTES: usize = 513', 'service_owner_store::STATE_CHUNK_BYTES'),
            (module.STATE_STORE, 'STATE_CHUNK_MIN_BYTES: usize = 384', 'STATE_CHUNK_MIN_BYTES: usize = 385', 'service_owner_store::STATE_CHUNK_MIN_BYTES'),
            (module.STATE_STORE, 'STATE_CHUNK_MAX_BYTES: usize = 768', 'STATE_CHUNK_MAX_BYTES: usize = 769', 'service_owner_store::STATE_CHUNK_MAX_BYTES'),
            (module.SERVER_LIB, 'MAX_APPLICATION_STATE_BYTES: usize = 16', 'MAX_APPLICATION_STATE_BYTES: usize = 17', 'server::MAX_APPLICATION_STATE_BYTES'),
        ):
            with self.subTest(constant=expected):
                original = (self.root / path).read_text()
                self.change(path, before, after)
                self.assertTrue(any(expected in error for error in module.validate(self.root)))
                (self.root / path).write_text(original)

    def test_record_bounds_are_independently_checked(self):
        for path, constant, old in (
            (module.RECORD_ROOT, 'MAX_ROOT_BYTES', 64),
            (module.RECORD_ROOT, 'OWNER_CHUNK_BYTES', 256),
            (module.RECORD_CORE, 'BLOCK_BYTES', 256),
            (module.RECORD_CORE, 'PAGE_BYTES', 32),
            (module.RECORD_CORE, 'MAX_VALUE_BYTES', 16),
            (module.RECORD_CORE, 'MAX_GRAPH_BYTES', 64),
        ):
            with self.subTest(constant=constant):
                original = (self.root / path).read_text()
                self.change(path, f'{constant}: usize = {old}', f'{constant}: usize = {old+1}')
                self.assertTrue(any(constant in error for error in module.validate(self.root)))
                (self.root / path).write_text(original)

    def test_capacity_rows_cannot_disappear_duplicate_or_swap_layout(self):
        path = self.root / module.CAPACITY
        original = path.read_text()
        row = next(line for line in original.splitlines() if '| `state_records::BLOCK_BYTES` |' in line)
        for changed in (original.replace(row, ''), original + '\n' + row,
                        original.replace(row, row.replace('V5 records', 'V4 legacy'))):
            path.write_text(changed)
            self.assertTrue(any('state_records::BLOCK_BYTES' in error for error in module.validate(self.root)))
        path.write_text(original)

    def test_formats_keep_distinct_current_and_legacy_anchors(self):
        for path, before in ((module.RECORD_ROOT, 'heptabao-state-records-v5'),
                             (module.STATE_STORE, 'heptabao-state-owners-v4')):
            original = (self.root / path).read_text()
            self.change(path, before, before + '-changed')
            self.assertTrue(any('storage format' in error for error in module.validate(self.root)))
            (self.root / path).write_text(original)

    def test_source_comment_cannot_supply_a_missing_record_constant(self):
        self.change(module.RECORD_CORE, 'pub(crate) const PAGE_BYTES:', '// pub(crate) const PAGE_BYTES:')
        self.assertTrue(any('PAGE_BYTES missing or ambiguous' in error for error in module.validate(self.root)))

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

    def test_common_current_tense_phrasings_cannot_hide_stale_schema(self):
        original = (self.root / module.ARCH).read_text()
        for phrase in ('Service schema is 4.', 'Service state is now schema 4.',
                       'Current application writes use schema 4.', 'current writes use schema 4.'):
            with self.subTest(phrase=phrase):
                (self.root / module.ARCH).write_text(original + '\n' + phrase + '\n')
                self.assertTrue(any('obsolete current-tense' in p for p in module.validate(self.root)))

    def test_false_unsupported_mount_claim_is_rejected(self):
        with (self.root / module.ENGINE).open('a') as stream:
            stream.write('\nPKI, SSH, database, LDAP,\nKubernetes and other engine types return HTTP 501\n')
        self.assertIn('engine guide still denies currently implemented backends', module.validate(self.root))

    def test_missing_contract_fails_closed(self):
        (self.root / module.FORMAT).unlink()
        self.assertTrue(module.validate(self.root))

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

    def test_replacement_map_cannot_drift_fixture_state(self):
        self.change(
            module.ACCEPTANCE,
            '| `HB-SURFACE-AUTH-KERBEROS` | `auth_methods` | `IMPLEMENTED_SCOPED` |',
            '| `HB-SURFACE-AUTH-KERBEROS` | `auth_methods` | `DEFINED_NOT_IMPLEMENTED` |',
        )
        self.assertIn('replacement execution map differs from fixed corpus rows', module.validate(self.root))

    def test_replacement_map_cannot_duplicate_its_denominator(self):
        path=self.root/module.ACCEPTANCE
        path.write_text(path.read_text()+path.read_text())
        self.assertIn('missing or ambiguous replacement surface projection', module.validate(self.root))
