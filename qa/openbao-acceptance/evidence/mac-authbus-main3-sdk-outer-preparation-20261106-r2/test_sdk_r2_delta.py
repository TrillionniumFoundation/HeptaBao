"""Check the actual-qualified sandbox change and new attempt bindings only."""
import ast
import json
from pathlib import Path
import unittest
from unittest.mock import patch

WORK=Path(__file__).resolve().parent
OLD=WORK.parent/'main3-sdk-outer-work'
NODE=WORK.parent/'main3-sdk-root-work'
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r2')
OLD_ROOT=str(ROOT).replace('20261106-r2','20261106-r1')
LIVE=Path('/Users/qianqi/.openclaw')

def need(value,code):
    if not value:raise RuntimeError(code)

def load_profile(path):
    tree=ast.parse(path.read_bytes())
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='sandbox_profile']
    assert len(nodes)==1
    scope={'ROOT':ROOT,'STATE':ROOT/'state','LIVE':LIVE,'Path':Path,'json':json,'need':need}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),scope)
    return scope['sandbox_profile']

class Delta(unittest.TestCase):
    def assert_profile(self,seed):
        before=load_profile(OLD/'main3_sdk_phase.py')
        after=load_profile(WORK/'main3_sdk_phase.py')
        with patch.object(Path,'cwd',return_value=LIVE.parent):
            original=before(None if seed else 46267,seed=seed).decode().splitlines()
            revised=after(None if seed else 46267,seed=seed).decode().splitlines()
        # Exactly the directory set used by the successful Mac factor probe,
        # after substituting the new fixture root. Directories are literals.
        probe_entry=ROOT/'qa/probe.mjs'
        directories={LIVE.parent,*LIVE.parent.parents,*probe_entry.parents,
                     *(ROOT/'input/plan.synthetic.json').parents}
        expected=['(allow file-read* (literal '+json.dumps(str(p))+'))'
                  for p in sorted(directories,key=str)]
        added=[line for line in revised if line not in original]
        self.assertEqual(added,expected)
        self.assertEqual([line for line in revised if line not in expected],original)
        self.assertNotIn(OLD_ROOT,'\n'.join(revised))
        self.assertFalse(any('file-write' in line or 'network-' in line or 'subpath' in line for line in added))

    def test_seed_has_only_actual_qualified_directory_literals(self):
        self.assert_profile(True)

    def test_worker_retains_all_original_write_and_network_boundaries(self):
        self.assert_profile(False)

    def test_unobserved_controller_cwd_refuses_before_profile(self):
        after=load_profile(WORK/'main3_sdk_phase.py')
        with patch.object(Path,'cwd',return_value=ROOT/'qa'):
            with self.assertRaisesRegex(RuntimeError,'sdk_original_account_home_cwd'):
                after(seed=True)

    def test_three_worker_scope_rebindings_preserve_every_other_byte(self):
        for name in ('main3_sdk_cycle_r2.mjs','main3_auth_rows_cas_r1.mjs','main3_authbus_cache_cas_r1.mjs'):
            original=(NODE/name).read_bytes()
            revised=(WORK/'assets/qa'/name).read_bytes()
            self.assertGreater(original.count(OLD_ROOT.encode()),0)
            self.assertEqual(revised,original.replace(OLD_ROOT.encode(),str(ROOT).encode()))
            self.assertNotIn(OLD_ROOT.encode(),revised)
        self.assertEqual((WORK/'assets/qa/main3_sdk_wire_r2.mjs').read_bytes(),
                         (NODE/'main3_sdk_wire_r2.mjs').read_bytes())

    def test_inline_operation_label_is_explicitly_bound_to_new_attempt(self):
        tree=ast.parse((WORK/'source-sdk-r2/main3_inline_capture.py').read_bytes())
        values=[ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign)
                and any(isinstance(t,ast.Name) and t.id=='OPERATION_KEY' for t in n.targets)]
        expected='heptabao-mac-authbus-main3-sdk-inline-capture-20261106-r2'
        self.assertEqual(values,[expected])
        manifest=json.loads((WORK/'manifest-sdk-r2.public.json').read_bytes())
        self.assertEqual(manifest['inlineCaptureOperationKey'],expected)
        self.assertEqual(len(manifest['nodeWorkerRootOnlyChanges']),3)
        self.assertFalse(manifest['nodeWorkerSourcesUnchanged'])

if __name__=='__main__':unittest.main(verbosity=2)
