import copy
from contextlib import ExitStack
from types import SimpleNamespace
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import approle_secretid_metadata_upgrade as f


class MetadataUpgradeGuards(unittest.TestCase):
    def test_cli_legacy_admission_requires_exact_binary_receipt_and_complete_calibrated_lanes(self):
        receipt = f.ROOT/'qa/openbao-acceptance/evidence/approle-secretid-overrides-live-fe49395.json'
        source = 'fe493955a30e372cabf0d0a9f6704b815f81f40d'
        binary = 'd243fef5c7a0066ef227a40a725fd93b2f298a94149f41247fa6ac3e28fc2608'
        digest = 'd797ab70d8f9cbcd280bc90fe329e38e216998fc3fcd49a212b85a91faa0a790'
        self.assertEqual(f.file_hash(receipt), digest)
        value = f.json.loads(receipt.read_text())
        def admit(body, actual=digest, src=source, sha=binary):
            f.admit_legacy(body, actual, digest, src, sha)
        admit(value)
        for field, bad in [('schema','wrong'), ('status','failed'), ('build_source_commit','0'*40),
            ('oracle_only', True), ('cases_match',False), ('source_and_binary_unchanged',False),
            ('inputs_unchanged', False), ('oracle_binary_unchanged',False), ('processes_stopped', False)]:
            wrong = copy.deepcopy(value); wrong[field] = bad
            with self.assertRaises(ValueError, msg=field): admit(wrong)
        for field in ('candidate_source', 'candidate_source_after'):
            wrong = copy.deepcopy(value); wrong[field]['source_dirty'] = True
            with self.assertRaises(ValueError, msg=field): admit(wrong)
        wrong = copy.deepcopy(value); wrong['cases']['candidate'].pop()
        with self.assertRaises(ValueError): admit(wrong)
        for kwargs in ({'actual':'0'*64}, {'src':'0'*40}, {'sha':'0'*64}):
            with self.assertRaises(ValueError): admit(value, **kwargs)

    def test_actual_run_order_first_candidate_write_is_immediately_followed_by_old_reader(self):
        for profile in f.PROFILES:
            events = []
            saved = {'role': {'bind_secret_id':True}, 'sid': {'metadata':{}, 'secret_id_num_uses':0},
                'creds': {'secret_id':'synthetic-sid', 'role_id':'synthetic-rid'},
                'auth': {'client_token':'synthetic-old-token'}, 'rid':'synthetic-rid',
                'entity':'synthetic-entity', 'alias': {'metadata':{}, 'custom_metadata':f.CUSTOM}}
            class ReachedOldReader(Exception): pass
            class T:
                sensitive = []
                def check(self, name, ok, **kwargs):
                    if not ok: raise AssertionError(name)
                def issued(self, name, body, kind): return body['auth']
                def call(self, name, method, route, body=None, **kwargs):
                    events.append(('request', method, route, copy.deepcopy(body)))
                    if route == f.ROLE: return {'data': saved['role']}
                    if route.endswith('/secret-id/lookup'): return {'data': saved['sid']}
                    if route.endswith('/secret-id'): return {'data': {'secret_id':'synthetic-first'}}
                    if route == 'auth/approle/login': return {'auth': {'metadata':f.HISTORICAL}}
                    raise AssertionError('unexpected request')
            class Instance:
                root = Path('/synthetic-unused')
                def stop(self): pass
            def downgrade(*args): events.append(('old-reader',)); raise ReachedOldReader
            with patch.object(f, 'seed', return_value=(T(),'key',saved)), \
                 patch.object(f, 'restart', side_effect=lambda *a: events.append(('reopen',))), \
                 patch.object(f, 'durable_manifest', return_value='same'), \
                 patch.object(f, 'inspect_token'), patch.object(f, 'read_alias', return_value=saved['alias']), \
                 patch.object(f.previous, 'downgrade', side_effect=downgrade):
                with self.assertRaises(ReachedOldReader):
                    f.run_store(Instance(), Path('candidate'), Path('legacy'), [], profile, [])
            writes = [e for e in events if e[0]=='request' and e[1]!='GET' and not e[2].endswith('/lookup')]
            if profile == 'legacy_login':
                expected = ('request','POST','auth/approle/login',saved['creds'])
            else:
                expected = ('request','POST',f.ROLE+'/secret-id',{'metadata': f.json.dumps({} if profile=='metadata_empty' else f.RAW)})
            self.assertEqual(writes, [expected])
            self.assertEqual(events[-2:], [expected, ('old-reader',)])

    def test_pure_read_rejects_added_removed_or_changed_legacy_sid_fields(self):
        saved = {'metadata':{}, 'secret_id_num_uses':0, 'last_updated_time':'fixed', 'cidr_list':[], 'token_bound_cidrs':[]}
        class T:
            sensitive=[]
            def check(self, name, ok, **kwargs):
                if not ok: raise f.ScenarioFailure(name)
            def call(self, *args, **kwargs): return {'data': {'name':'preserved'}}
        class Instance:
            root=Path('/synthetic-unused')
            def stop(self): pass
        state={'sid':saved,'role':{'name':'preserved'},'creds':{},'auth':{},'entity':'e','rid':'r','alias':{}}
        for bad in ({**saved,'metadata':{'role_name':'invented'}}, {**saved,'extra':True},
                    {k:v for k,v in saved.items() if k!='metadata'}, {**saved,'secret_id_num_uses':1}):
            with patch.object(f,'seed',return_value=(T(),'key',state)), patch.object(f,'restart'), \
                 patch.object(f,'durable_manifest',return_value='same'), patch.object(f,'sid',return_value=bad), \
                 self.assertRaises(f.ScenarioFailure):
                f.run_store(Instance(),Path('new'),Path('old'),[],'metadata_empty',[])

    def test_three_renewals_use_original_snapshot_and_never_reconstruct_accessor_bearer(self):
        auth={'client_token':'synthetic-private-token','accessor':'synthetic-private-accessor'}
        def execute(bad=None):
            calls=[]
            class T:
                def check(self, name, ok, **kwargs):
                    if not ok: raise f.ScenarioFailure(name)
                def call(self,name,method,path,body,**kwargs):
                    calls.append((method,path,body,kwargs))
                    accessor=path.endswith('renew-accessor')
                    response={'metadata':dict(f.EFFECTIVE),'lease_duration':100}
                    if not accessor: response['client_token']=auth['client_token']
                    if bad=='alias_backfill': response['metadata']=f.SECOND
                    if bad=='accessor_leak' and accessor: response['client_token']=auth['client_token']
                    return {'auth':response}
            f.renew(T(),'original',auth,f.EFFECTIVE);return calls
        calls=execute()
        self.assertEqual([c[1] for c in calls],['auth/token/renew-self','auth/token/renew','auth/token/renew-accessor'])
        self.assertEqual(calls[0][3]['token'],auth['client_token'])
        self.assertIsNone(calls[1][3]['token']);self.assertIsNone(calls[2][3]['token'])
        for bad in ('alias_backfill','accessor_leak'):
            with self.assertRaises(f.ScenarioFailure): execute(bad)

    def test_emitted_receipt_does_not_attribute_composite_login_to_an_independent_auth_gate(self):
        # Exercise main's actual output construction on both successful and failed
        # scheduling; no provider/binary is started and no durable state fabricated.
        for failed in (False, True):
            with tempfile.TemporaryDirectory() as directory, ExitStack() as mocks:
                base = Path(directory)
                candidate, legacy, receipt = (base/name for name in ('candidate','legacy','receipt'))
                for path in (candidate, legacy): path.write_bytes(b'synthetic-unused')
                receipt.write_text('{}')
                args = SimpleNamespace(binary=candidate, legacy_binary=legacy, legacy_receipt=receipt,
                    output=base/'report.json', work_parent=base, build_source_commit='1'*40,
                    expected_binary_sha256='2'*64, legacy_binary_sha256='3'*64,
                    legacy_build_source_commit='4'*40, legacy_receipt_sha256='5'*64)
                captured=[]
                instance=SimpleNamespace(process=None, stop=lambda:None)
                def capture(path, value, **kwargs): captured.append(f.json.loads(f.json.dumps(value)))
                bindings = {
                    'validate_binary_pins': {'return_value':('2'*64,'3'*64)},
                    'admit_legacy': {}, 'admit_output': {'return_value':'stable'},
                    'source_identity': {'return_value':{'source_dirty':False}},
                    'file_hash': {'return_value':'3'*64}, 'helpers': {'return_value':{}},
                    'private_parent': {'side_effect':lambda p:p},
                    'make_instance': {'return_value':instance},
                    'run_store': {'side_effect':f.ScenarioFailure('synthetic_failure') if failed else None},
                    'Trace': {}, 'complete': {'return_value':not failed},
                    'private_write': {'side_effect':capture},
                }
                for name, options in bindings.items(): mocks.enter_context(patch.object(f,name,**options))
                mocks.enter_context(patch.object(f.SafeArgumentParser,'parse_args',return_value=args))
                mocks.enter_context(patch('builtins.print'))
                self.assertEqual(f.main(), int(failed))
                self.assertEqual(len(captured),1)
                report=captured[0]
                self.assertIs(report['independent_issued_metadata_gate_covered'],False)
                self.assertIs(report['legacy_login_first_write_is_composite'],True)
                self.assertIs(report['alias_only_gate_covered'],False)
                self.assertIs(report['extended_alias_only_gate_covered'],False)
                self.assertEqual(report['first_write_profile']['legacy_login'],
                    'old None SID service login writes both issued_metadata and alias backend role_name')

    def test_required_phases_and_safe_rows_do_not_reduce_to_total_count(self):
        rows=[{'case':case,'passed':True} for case in sorted(f.REQUIRED-{'complete'})]+[{'case':'complete','passed':True}]
        self.assertTrue(f.complete(rows))
        for name in f.REQUIRED:
            self.assertFalse(f.complete([r for r in rows if r['case']!=name]),name)
        for bad in (rows+rows[:1],rows[:-1]+[{'case':'complete','passed':1}],
                    rows[:-1]+[{'case':'complete','passed':True,'raw':'private'}],
                    rows[:-1]+[{'case':'exception','passed':False}]+rows[-1:]): self.assertFalse(f.complete(bad))
        self.assertTrue(f.complete(rows[:-1]+[{'case':'additional','passed':True}]+rows[-1:]))


if __name__=='__main__':unittest.main()
