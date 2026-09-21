import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import zlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import kv1_records_ha_upgrade as fixture


def b64(value):return base64.b64encode(value).decode().rstrip('=')
def encoded(value):return json.dumps(value,separators=(',',':')).encode()

def state_fixture():
    key=b'K'*32; cluster='synthetic-cluster'; data=b'synthetic-private-value-that-must-not-leave-the-observer'
    digest=hashlib.sha256(data).digest(); op=b'chunk'; rootop=b'manifest'; aes=AESGCM(key)
    def prefix(magic,operation):return magic+len(cluster).to_bytes(2,'big')+cluster.encode()+len(operation).to_bytes(2,'big')+operation
    def status(operation,digest,sealed):return f'hbr3:{len(operation)}:{operation.decode()}:{digest.hex()}:{b64(sealed)}'
    chunk=b'HBSC2'+b'1'*12+aes.encrypt(b'1'*12,data,prefix(b'HBSC2',op)+bytes(2)+bytes(1)+len(data).to_bytes(4,'big')+digest)
    body=len(data).to_bytes(8,'big')+bytes([0,1])+bytes([31])+b'M'*32+bytes(3)+len(data).to_bytes(4,'big')+digest
    sealed=b'HBSM4'+b'B'*32+b'2'*12+aes.encrypt(b'2'*12,body,prefix(b'HBSM4',rootop)+b'B'*32+digest)
    state={'last_applied_log':{'leader_id':{'term':1,'node_id':1},'index':3},
           'last_membership':{'log_id':None,'membership':{'configs':[[1,2,3]],'nodes':{'1':None,'2':None,'3':None}}},
           'client_status':{'heptabao-production-ha':status(rootop,digest,sealed),
             'heptabao-production-ha-chunk:000:0':status(op,digest,chunk),
             'heptabao-production-ha-chunk:000:1':status(op,digest,chunk),
             'unrelated-client':'not-a-production-chunk'}}
    return state,cluster,key,data


class NearLimitUpgradeGuards(unittest.TestCase):
    def test_authenticated_manifest_active_slots_and_safe_exact_accounting(self):
        state,cluster,key,secret=state_fixture()
        before=deepcopy(state); report=fixture.inspect_legacy_state(state,cluster,key)
        self.assertEqual(state,before)
        self.assertEqual(report['logical_state_bytes'],len(secret))
        self.assertEqual(report['active_chunk_count'],1)
        self.assertEqual(report['inactive_chunk_count'],1)
        self.assertEqual(report['logical_state_sha256'],hashlib.sha256(secret).hexdigest())
        self.assertEqual(report['legacy_charged_bytes'],2+sum(len(encoded(k))+len(encoded(v))+2 for k,v in state['client_status'].items()))
        safe=json.dumps(report)
        for value in [secret.decode(),cluster,'hbr3:','not-a-production-chunk',b64(key)]:self.assertNotIn(value,safe)

    def test_wrong_key_cluster_missing_active_or_corrupt_ciphertext_is_not_an_observation(self):
        state,cluster,key,_=state_fixture()
        for changed_cluster,changed_key in [(cluster+'x',key),(cluster,b'L'*32)]:
            with self.assertRaises(fixture.FixtureError):fixture.inspect_legacy_state(state,changed_cluster,changed_key)
        for variant in ('missing','corrupt','typed'):
            broken=deepcopy(state)
            if variant=='missing':del broken['client_status']['heptabao-production-ha-chunk:000:0']
            elif variant=='corrupt':
                original=broken['client_status']['heptabao-production-ha-chunk:000:0']
                broken['client_status']['heptabao-production-ha-chunk:000:0']=original[:-4]+('AAAA' if original[-4:]!='AAAA' else 'BBBB')
            else:broken['records_v5']={'objects':{},'published':None}
            with self.assertRaises(fixture.FixtureError):fixture.inspect_legacy_state(broken,cluster,key)

    def test_real_framed_bundle_must_contain_same_authenticated_snapshot_authority(self):
        state,cluster,key,_=state_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); folder=root/'raft'/'state-machine';folder.mkdir(parents=True)
            path=folder/'state-bundle.bin'
            bundle={'format_version':2,'journal_format':1,'generation':5,'state':state,
                'current_snapshot':{'meta':{'last_log_id':state['last_applied_log'],'last_membership':state['last_membership']},'data':b64(encoded(state))}}
            def write(value):
                payload=encoded(value);path.write_bytes(fixture.MAGIC+len(payload).to_bytes(8,'little')+payload+zlib.crc32(payload).to_bytes(4,'little'))
            write(bundle)
            report=fixture.inspect_legacy_bundle(SimpleNamespace(root=root),SimpleNamespace(cluster_id=cluster,replication_key=key))
            self.assertEqual(report['snapshot_index'],3)
            broken=deepcopy(bundle);broken['current_snapshot']['meta']['last_log_id']['index']=4;write(broken)
            with self.assertRaises(fixture.FixtureError):fixture.inspect_legacy_bundle(SimpleNamespace(root=root),SimpleNamespace(cluster_id=cluster,replication_key=key))

    def test_write_failure_is_not_retried_or_remembered(self):
        calls=[]; dataset=fixture.Dataset()
        def request(*args,**kwargs):calls.append((args,kwargs));return 503,{}
        def check(label,condition):fixture.require(condition,label)
        with self.assertRaises(fixture.FixtureError):
            fixture.put_once(SimpleNamespace(root_token='synthetic'),SimpleNamespace(call=request),dataset,'bulk/0000',{'value':'synthetic'},check,'write')
        self.assertEqual(len(calls),1);self.assertEqual(dataset.hashes,{})

    def test_workload_must_reach_real_old_limit_and_old_plus_new_budget_failure(self):
        self.assertTrue(fixture.migration_staging_would_exceed_unchanged_budget({'legacy_charged_bytes':42*fixture.MIB},16*fixture.MIB-8192))
        for observation,logical in [({},16*fixture.MIB),({'legacy_charged_bytes':2*fixture.MIB},16*fixture.MIB),
                                    ({'legacy_charged_bytes':47*fixture.MIB},fixture.MIB),({'legacy_charged_bytes':True},16*fixture.MIB)]:
            self.assertFalse(fixture.migration_staging_would_exceed_unchanged_budget(observation,logical))

    def test_milestones_are_required_without_a_fixed_total_and_failure_is_preserved(self):
        rows=[{'case':case,'passed':True} for case in sorted(fixture.required_cases()-{'complete'})]+[{'case':'complete','passed':True}]
        self.assertTrue(fixture.complete(rows));self.assertTrue(fixture.complete(rows[:-1]+[{'case':'additional','passed':True}]+rows[-1:]))
        for index in range(len(rows)):self.assertFalse(fixture.complete(rows[:index]+rows[index+1:]))
        for broken in ([],rows+[rows[0]],rows[:-1]+[{'case':'complete','passed':False}],
                       rows[:-1]+[{'case':'complete','passed':1}],rows[:-1]+[{'case':'complete','passed':True,'secret':'sensitive'}]):
            self.assertFalse(fixture.complete(broken))

    def test_old_launch_does_not_introduce_new_ha_config_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'server.json').write_text('{"timeout_seconds":5}');(root/'server.json').chmod(0o600)
            fake=object.__new__(fixture.UpgradeCluster);fake.nodes=[SimpleNamespace(root=root)]
            with patch.object(fixture.PartitionCluster,'configure',return_value=None):fixture.UpgradeCluster.configure(fake)
            saved=json.loads((root/'server.json').read_text())
            self.assertEqual(saved['timeout_seconds'],60);self.assertEqual(saved['lifecycle_interval_seconds'],0)
            self.assertNotIn('forward_timeout_ms',saved);self.assertFalse((root/'ha.json').exists())


if __name__=='__main__':unittest.main()
