import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from pathlib import Path

import native_snapshot_ha_restore_live as f


class HaRestoreGuards(unittest.TestCase):
    def test_provider_request_is_real_json_and_retains_synthetic_credentials(self):
        import json
        value=f.radius_credentials()
        self.assertEqual(json.loads(json.dumps(value)),value)
        self.assertEqual(value['password'].encode(),f.PASSWORD)
        self.assertEqual(value['username'].encode(),f.USERNAME)

    def test_named_phases_cannot_be_skipped_duplicated_or_forged(self):
        rows = [{'case': k, 'passed': True} for k in sorted(f.REQUIRED-{'complete'})]
        rows.append({'case': 'complete', 'passed': True})
        self.assertTrue(f.complete(rows))
        for key in f.REQUIRED:
            self.assertFalse(f.complete([r for r in rows if r['case'] != key]),key)
        for bad in (rows+[rows[-1]],rows[:-1],rows[:-1]+[{'case':'complete','passed':1}],
                    rows[:-1]+[{'case':'complete','passed':False}],[]):
            self.assertFalse(f.complete(bad))
        self.assertTrue(f.complete(rows[:-1]+[{'case':'additional_real_observation','passed':True}]+rows[-1:]))

    def test_publication_requires_new_generation_exact_epoch_and_import_identity(self):
        value = {'data':{'cluster_coordinated':True,'imported_generation':5,
                        'previous_local_generation':20,'published_local_generation':22,'replay_epoch':9}}
        self.assertEqual(f.publication((200,value),20,5,previous_epoch=8)['replay_epoch'],9)
        for key,replacement in [('cluster_coordinated',1),('imported_generation',6),
                ('previous_local_generation',19),('published_local_generation',20),('replay_epoch',8),
                ('replay_epoch',10),('replay_epoch',True)]:
            changed=copy.deepcopy(value);changed['data'][key]=replacement
            self.assertIsNone(f.publication((200,changed),20,5,previous_epoch=8),key)
        for status in (409,500,503): self.assertIsNone(f.publication((status,value),20,5))
        secret=copy.deepcopy(value);secret['auth']={'client_token':'sensitive-sentinel'}
        self.assertIsNone(f.publication((200,secret),20,5))

    def test_provider_timeout_or_wrapper_cannot_count_as_epoch_fence(self):
        good=(503,{'errors':['online authentication authority changed']})
        self.assertTrue(f.late_denied(good))
        for bad in ((503,{'errors':['RADIUS provider timed out']}),(None,{}),
                    (200,{}),(409,good[1]),(503,{'errors':good[1]['errors'],'auth':{'client_token':'sentinel'}}),
                    (503,{'errors':good[1]['errors'],'wrap_info':{'token':'sentinel'}})):
            self.assertFalse(f.late_denied(bad))

    def test_expired_upload_never_accepts_ack_or_authenticated_body(self):
        self.assertTrue(f.expired_denied((None,{})))
        self.assertTrue(f.expired_denied((503,{'errors':['deadline']})))
        for bad in ((200,{}),(200,{'data':{}}),(503,{}),(None,{'errors':['unexpected']}),
                    (503,{'errors':['deadline'],'data':{'cluster_coordinated':True}})):
            self.assertFalse(f.expired_denied(bad))

    def test_legacy_pin_requires_actual_clean_qualified_build_and_unchanged_receipt(self):
        source={'source_commit':f.LEGACY_HARNESS,'source_dirty':False,'binary_sha256':f.LEGACY_SHA}
        receipt={'status':'passed','schema':'heptabao.native-snapshot-cli.v1',
                 'build_source_commit':f.LEGACY_BUILD,'source_identity':source,'source_identity_after':dict(source),
                 'source_and_binary_unchanged':True,'runner_unchanged':True,'postgres_restore_profile_covered':True}
        f.admit_legacy(receipt,f.LEGACY_RECEIPT_SHA)
        for key,value in [('status','failed'),('build_source_commit','0'*40),('runner_unchanged',1),
                          ('source_and_binary_unchanged',False),('postgres_restore_profile_covered',False)]:
            changed=copy.deepcopy(receipt);changed[key]=value
            with self.assertRaises(ValueError):f.admit_legacy(changed,f.LEGACY_RECEIPT_SHA)
        with self.assertRaises(ValueError):f.admit_legacy(receipt,'a'*64)
        changed=copy.deepcopy(receipt);changed['source_identity_after']['source_dirty']=True
        with self.assertRaises(ValueError):f.admit_legacy(changed,f.LEGACY_RECEIPT_SHA)

    def test_downgrade_stops_whole_cluster_never_starts_old_ha_and_checks_both_stores(self):
        events=[];nodes=[]
        class Node:
            def __init__(self,i):
                self.root=Path('/private')/str(i);self.data_dir=self.root/'data';self.process=object();self.binary='candidate'
            def stop(self):events.append(('stop',self));self.process=None
            def start(self,**kwargs):
                events.append(('start',self.binary,kwargs,all(n.process is None for n in nodes)))
                self.process=object()
            def call(self,method,path,body=None):
                return (503,{'errors':['unsupported schema']}) if method=='POST' else (503,{'sealed':True})
        nodes[:]=[Node(i) for i in range(3)]
        cluster=SimpleNamespace(nodes=nodes,unseal_key='secret-not-published')
        rows=[];manifest_calls=[]
        def manifest(path,**kw):manifest_calls.append((path,kw));return 'digest'
        with patch.object(f,'durable_manifest',manifest),patch.object(f,'restart',lambda _:events.append(('restart',))):
            f.downgrade(cluster,'legacy','candidate',lambda case,passed:rows.append((case,passed)),target=nodes[0])
        self.assertTrue(all(passed for _,passed in rows))
        self.assertEqual(events[3],('start','legacy',{'ha':False},True))
        self.assertEqual(nodes[0].binary,'candidate')
        self.assertEqual(len(manifest_calls),4)
        self.assertEqual(manifest_calls[0],manifest_calls[2]);self.assertEqual(manifest_calls[1],manifest_calls[3])
        self.assertEqual(manifest_calls[0][1],{'application_only':True})
        self.assertEqual(manifest_calls[1][1],{})

    def test_legacy_start_exception_restores_binary_and_never_claims_recovery(self):
        node=SimpleNamespace(root=Path('/private'),data_dir=Path('/private/data'),binary='candidate',process=None)
        node.stop=lambda:None
        def fail(**kwargs):raise OSError('sensitive-error-not-output')
        node.start=fail
        with patch.object(f,'durable_manifest',return_value='digest'),patch.object(f,'restart') as restart:
            with self.assertRaises(OSError):f.downgrade(SimpleNamespace(nodes=[node],unseal_key='secret'),
                                                     'legacy','candidate',lambda *_:None,target=node)
            self.assertEqual(node.binary,'candidate');restart.assert_not_called()


if __name__ == '__main__':unittest.main()
