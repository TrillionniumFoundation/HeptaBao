#!/usr/bin/env python3
"""Exercise the native JSON/base64 backup profile on real local record storage.

This does not claim OpenBao snapshot format/force semantics, HA restore, the
20MiB transfer boundary, or interruption of the physical restore transaction.
"""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from kv1_record_scale_live import Dataset, MOUNT
from online_evidence import admit_output, source_identity
from remote_jwks_live import Instance

REQUIRED = frozenset({'record_format', 'export_authenticated', 'changed_state',
    'rollback_rejected', 'rollback_preserves_generation', 'corruption_rejected',
    'corruption_preserves_generation', 'changed_data_retained', 'restore_committed',
    'restored_all_values', 'restored_other_owner', 'later_key_absent', 'restart_unsealed',
    'reopened_all_values', 'reopened_other_owner', 'reopened_later_key_absent',
    'plaintext_absent', 'complete'})


def complete(checks):
    if not isinstance(checks, list) or not checks:
        return False
    if any(not isinstance(row, dict) or set(row) != {'case', 'passed'}
           or row['passed'] is not True or not isinstance(row['case'], str)
           or re.fullmatch(r'[a-z0-9_]{1,100}', row['case']) is None for row in checks):
        return False
    names = [row['case'] for row in checks]
    return len(names) == len(set(names)) and names[-1] == 'complete' and REQUIRED.issubset(names)


def run(binary, work, checks, observations):
    instance = None
    def check(name, condition):
        checks.append({'case': name, 'passed': condition is True})
        if condition is not True:
            raise ScenarioFailure(name)
    try:
        instance = Instance(binary, work / 'instance')
        config_path = instance.root / 'server.json'
        config = json.loads(config_path.read_text()); config['lifecycle_interval_seconds'] = 0
        private_write(config_path, config, replace=True)
        instance.start()
        status, initialized = instance.call('POST', 'sys/init', {'secret_shares':1,'secret_threshold':1})
        check('initialized', status == 200)
        instance.token, unseal = initialized['root_token'], initialized['keys_base64'][0]
        check('unsealed', instance.call('POST', 'sys/unseal', {'key':unseal})[0] == 200)
        client = Client(instance.address, str(instance.root/'ca.crt'), instance.token, timeout=30)
        def call(method, path, body=None):
            result = client.request(method, '/v1/'+path, body)
            return result.status, result.body
        def capacity():
            status, body = call('GET','sys/internal/capacity')
            if status != 200: raise ScenarioFailure('capacity_unavailable')
            return body['data']
        check('mounted', call('POST','sys/mounts/'+MOUNT,{'type':'kv','options':{'version':'1'}})[0] == 204)
        original, changed = Dataset(), Dataset()
        for ordinal in range(8):
            key=f'bulk/{ordinal:04d}'; value=original.make_value(ordinal)
            check(f'write_{ordinal}', call('PUT',MOUNT+'/'+key,value)[0] == 204)
            original.remember(key,value); changed.remember(key,value)
        check('other_owner_written',call('PUT','secret/data/backup-control',{'data':{'value':'before'}})[0] == 200)
        check('record_format',capacity().get('state_storage_format') == 'heptabao-state-records-v5')
        status, body = call('GET','sys/storage/raft/snapshot'); data=body.get('data',{})
        encoded=data.get('snapshot'); archive=base64.b64decode(encoded,validate=True)
        check('export_authenticated',status == 200 and data.get('format') == 'heptabao-encrypted-backup-v1'
              and data.get('sha256') == hashlib.sha256(archive).hexdigest())
        observations.update(backup_bytes=len(archive),backup_sha256=hashlib.sha256(archive).hexdigest(),
                            logical_value_bytes=original.logical_bytes,record_count=len(original.hashes))
        value=changed.make_value(100)
        check('replace_after_backup',call('PUT',MOUNT+'/bulk/0000',value)[0] == 204)
        changed.remember('bulk/0000',value)
        check('delete_after_backup',call('DELETE',MOUNT+'/bulk/0001')[0] == 204)
        changed.forget('bulk/0001')
        check('write_later_key',call('PUT',MOUNT+'/later',{'value':'later'})[0] == 204)
        check('change_other_owner',call('PUT','secret/data/backup-control',{'data':{'value':'after'}})[0] == 200)
        generation=capacity()['generation']; check('changed_state',generation > data['generation'])
        check('rollback_rejected',call('POST','sys/storage/raft/snapshot',{'snapshot':encoded})[0] == 400)
        check('rollback_preserves_generation',capacity()['generation'] == generation)
        corrupt=bytearray(archive); corrupt[len(corrupt)//2] ^= 1
        check('corruption_rejected',call('POST','sys/storage/raft/snapshot-force',
                                       {'snapshot':base64.b64encode(corrupt).decode()})[0] == 400)
        check('corruption_preserves_generation',capacity()['generation'] == generation)
        def verify(dataset, phase):
            for index,key in enumerate(sorted(dataset.hashes)):
                status,body=call('GET',MOUNT+'/'+key)
                check(f'{phase}_{index}',dataset.matches(key,status,body))
        verify(changed,'changed');check('changed_data_retained',True)
        check('restore_committed',call('POST','sys/storage/raft/snapshot-force',{'snapshot':encoded})[0] == 200)
        verify(original,'restored');check('restored_all_values',True)
        check('restored_other_owner',call('GET','secret/data/backup-control')[1].get('data',{}).get('data') == {'value':'before'})
        check('later_key_absent',call('GET',MOUNT+'/later')[0] == 404)
        instance.stop(); instance.start()
        check('restart_unsealed',instance.call('POST','sys/unseal',{'key':unseal})[0] == 200)
        verify(original,'reopened');check('reopened_all_values',True)
        check('reopened_other_owner',call('GET','secret/data/backup-control')[1].get('data',{}).get('data') == {'value':'before'})
        check('reopened_later_key_absent',call('GET',MOUNT+'/later')[0] == 404)
        instance.stop()
        samples=[instance.token.encode(),unseal.encode(),*[s.encode() for s in original.sample_prefixes+changed.sample_prefixes]]
        files=[p for p in (instance.root/'data').rglob('*') if p.is_file()]
        files += [instance.root/'audit.jsonl',instance.root/'server.log']
        check('plaintext_absent',all(not any(sample in p.read_bytes() for sample in samples) for p in files if p.exists()))
        check('complete',True)
    finally:
        if instance is not None: instance.stop()


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--build-source-commit',required=True)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit) is None: parser.error('full source commit required')
    binary,output=args.binary.resolve(strict=True),args.output.absolute()
    admitted=admit_output(output);before=source_identity(ROOT,binary);runner_hash=file_hash(Path(__file__))
    work=Path(tempfile.mkdtemp(prefix='heptabao-record-backup-'));work.chmod(0o700)
    checks,observations,failure=[],{},None
    try: run(binary,work,checks,observations)
    except Exception as error:
        failure=next((r['case'] for r in reversed(checks) if r['passed'] is not True),'fixture_'+type(error).__name__)
    after=source_identity(ROOT,binary);runner_unchanged=runner_hash==file_hash(Path(__file__))
    if before!=after or not runner_unchanged:failure='source_binary_or_runner_changed'
    if not complete(checks):failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.kv1-record-backup.v1','status':'passed' if failure is None else 'failed',
        'failure':failure,'checks':checks,'observations':observations,'source_identity':before,'source_identity_after':after,
        'source_and_binary_unchanged':before==after,'build_source_commit':args.build_source_commit,
        'runner_sha256':runner_hash,'runner_unchanged':runner_unchanged,
        'retained_failure_work_dir':str(work) if failure else None,'native_backup_profile_only':True,
        'ha_restore_covered':False,'physical_restore_interruption_covered':False,'transfer_boundary_covered':False,
        'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False,'synthetic_only':True}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if failure is None:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'checks':len(checks),'failure':failure}))
    return int(failure is not None)


if __name__=='__main__':raise SystemExit(main())
