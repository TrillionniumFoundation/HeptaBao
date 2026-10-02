"""Standard-library-only guards: no server, crypto runtime or VM required."""
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

import approle_secret_cidrs_upgrade_contract as f


class SecretSourceUpgradeGuards(unittest.TestCase):
    def test_receipt_admission_is_cli_pinned_clean_and_requires_both_complete_lanes(self):
        source, binary, digest = '1'*40, '2'*64, '3'*64
        identity = {'source_commit': '4'*40, 'binary_sha256': binary, 'source_dirty': False}
        expected = [{'case': 'actual-lane', 'status': 200}]
        receipt = {'schema': 'heptabao.jwt-batch-comparison.v1', 'status': 'passed',
            'build_source_commit': source, 'candidate_source': identity, 'candidate_source_after': identity,
            'oracle_only': False, 'target_version': '2.6.2', 'failures': {},
            'cases': {'candidate': expected, 'oracle': expected},
            'completed_scenarios': {'candidate': ['complete'], 'oracle': ['complete']},
            'calibrated_cases_match': {'candidate': True, 'oracle': True},
            'secrets_absent': {'candidate': True, 'oracle': True},
            'processes_stopped': {'candidate': True, 'oracle': True},
            'source_and_binary_unchanged': True, 'cases_match': True,
            'inputs_unchanged': True, 'oracle_binary_unchanged': True}
        observed = []
        def lane(rows, phases, target):
            observed.append(rows)
            return rows == target and phases == ['complete']
        def admit(value, actual=digest): f.admit_legacy(value, actual, digest, source, binary, expected, lane)
        admit(receipt); self.assertEqual(len(observed), 2)
        for key, value in [('status','failed'), ('oracle_only',True), ('build_source_commit','0'*40),
                           ('inputs_unchanged',False), ('secrets_absent',{'candidate':True}),
                           ('processes_stopped',{'oracle':True}), ('source_and_binary_unchanged',1)]:
            bad=copy.deepcopy(receipt);bad[key]=value
            with self.assertRaises(ValueError,msg=key):admit(bad)
        for change in ('binary','dirty','rows','after'):
            bad=copy.deepcopy(receipt)
            if change=='binary':bad['candidate_source']['binary_sha256']='0'*64
            if change=='dirty':bad['candidate_source']['source_dirty']=True
            if change=='rows':bad['cases']['candidate']=[]
            if change=='after':bad['candidate_source_after']={}
            with self.assertRaises(ValueError,msg=change):admit(bad)
        with self.assertRaises(ValueError):admit(receipt,'0'*64)

    def test_only_new_null_readback_is_allowed_while_old_state_is_not_reconstructed(self):
        old={'token_ttl':900,'token_bound_cidrs':[],'bind_secret_id':True}
        self.assertTrue(f.retained_role({**old,f.FIELD:None},old))
        for current in [old,{**old,f.FIELD:[]},{**old,f.FIELD:['127.0.0.1/32']},
                        {**old,f.FIELD:None,'token_ttl':901}]:
            self.assertFalse(f.retained_role(current,old))
        self.assertFalse(f.retained_role({**old,f.FIELD:None},{**old,f.FIELD:None}))

    def test_secret_readback_only_normalizes_present_null_cidrs_without_mutating_inputs(self):
        old = {'secret_id_accessor': 'synthetic', 'secret_id_num_uses': 2,
               'cidr_list': None, 'token_bound_cidrs': [], 'secret_id_ttl': 1800,
               'creation_time': '2026-01-01T00:00:00Z', 'expiration_time_unix': 1800}
        original = copy.deepcopy(old)
        current = {**old, 'cidr_list': []}
        self.assertTrue(f.retained_secret(current, old))
        self.assertTrue(f.retained_secret(current, current))
        self.assertEqual(old, original)
        self.assertEqual(current, {**original, 'cidr_list': []})
        self.assertFalse(f.retained_secret(old, old))
        for field, value in [('cidr_list', ['127.0.0.1/32']), ('secret_id_num_uses', 1),
                             ('secret_id_accessor', 'different'), ('secret_id_ttl', 1799),
                             ('token_bound_cidrs', ['127.0.0.1']), ('expiration_time_unix', 1799),
                             ('creation_time', None), ('invented', True)]:
            self.assertFalse(f.retained_secret({**current, field: value}, old), field)
        for field in current:
            self.assertFalse(f.retained_secret({k:v for k,v in current.items() if k != field}, old), field)
        missing = {k:v for k,v in old.items() if k != 'cidr_list'}
        self.assertTrue(f.retained_secret(missing, missing))
        self.assertFalse(f.retained_secret({**missing, 'cidr_list': []}, missing))
        self.assertFalse(f.retained_secret(current, None))

    def test_completion_requires_real_milestones_not_count_and_allows_additional_success(self):
        rows=[{'case':name,'passed':True} for name in sorted(f.REQUIRED-{'complete'})]
        rows.append({'case':'complete','passed':True})
        self.assertTrue(f.complete(rows))
        for name in f.REQUIRED:
            self.assertFalse(f.complete([r for r in rows if r['case']!=name]),name)
        self.assertTrue(f.complete(rows[:-1]+[{'case':'additional_meaningful_check','passed':True}]+rows[-1:]))
        for bad in [rows+rows[-1:],rows[:-1],rows[:-1]+[{'case':'complete','passed':1}],
                    rows[:-1]+[{'case':'complete','passed':True,'secret':'private'}]]:
            self.assertFalse(f.complete(bad))
        self.assertFalse(f.old_reader_observed(rows))
        self.assertTrue(f.old_reader_observed([{'case':'empty_downgrade_unseal_status','passed':False,'status':200}]))

    @unittest.skipIf(os.geteuid()==0,'nonroot permission fixture')
    def test_storage_fault_is_effective_and_restores_exact_file_after_exception(self):
        # The caller sets TMPDIR to its private SSD test directory.
        with tempfile.TemporaryDirectory() as temporary:
            store=Path(temporary);path=store/'journal.hbj';original=b'synthetic encrypted fixture bytes'
            path.write_bytes(original);path.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError,'synthetic interruption'):
                with f.denied_journal_append(store):
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o400)
                    with self.assertRaises(PermissionError):os.open(path,os.O_WRONLY|os.O_APPEND)
                    raise RuntimeError('synthetic interruption')
            self.assertEqual(path.read_bytes(),original)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)

    @unittest.skipIf(os.geteuid()==0,'nonroot permission fixture')
    def test_storage_fault_rejects_symlink_or_nonprivate_file_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);store=root/'store';store.mkdir();target=root/'target'
            target.write_bytes(b'synthetic');target.chmod(0o600);path=store/'journal.hbj';path.symlink_to(target)
            with self.assertRaises(ValueError):
                with f.denied_journal_append(store):pass
            self.assertEqual(target.read_bytes(),b'synthetic')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o600)
            path.unlink();path.write_bytes(b'synthetic');path.chmod(0o644)
            with self.assertRaises(ValueError):
                with f.denied_journal_append(store):pass
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o644)


if __name__=='__main__':unittest.main()
