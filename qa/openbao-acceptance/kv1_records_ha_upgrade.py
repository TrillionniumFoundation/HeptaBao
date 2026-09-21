#!/usr/bin/env python3
"""Real schema-35 HA data near 16 MiB migrates without deleting old authority.

The pinned old process creates and twice overwrites 70 distinct 224 KiB values.
No on-disk application state is fabricated. The private work directory remains
available after either result; ambiguous writes are never retried. This covers
large values, not every possible dense small-record migration shape.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import stat
import time
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from ha_destructive import FixtureError
from ha_network_partition import PartitionCluster
from identity_upgrade import validate_binary_pins
from kv1_record_ha_live import compact_for_snapshot, read_exact, wait_record_snapshot
from kv1_record_scale_live import Dataset, MIB, MOUNT, process_observation
from kv1_records_upgrade import (LEGACY_SOURCE, LEGACY_SHA256, LEGACY_RECEIPT,
    LEGACY_FORMAT, CURRENT_FORMAT, admit_legacy_receipt)
from online_evidence import admit_output, source_identity
from raft_record_snapshot_observation import compact_bytes, encoded_size, strict_json
from raft_snapshot_observation import MAGIC, MAX_ARTIFACT_BYTES

COUNT = 70
REQUIRED = frozenset({'legacy_pin_admitted', 'old_mount', 'old_rounds_complete',
    'old_near_limit', 'old_full_read', 'old_authenticated_slots', 'old_peak_exceeds_unfixed_budget',
    'old_reopen_complete', 'old_reopen_full_read', 'old_reopen_same_authority',
    'candidate_read_only_v4', 'candidate_full_read_before_write', 'candidate_same_old_authority',
    'first_write', 'published_v5', 'migration_full_read', 'typed_snapshot',
    'candidate_reopen', 'candidate_reopen_full_read', 'new_leader_after_crash',
    'failover_full_read', 'secrets_absent', 'complete'})


def require(condition, label):
    if not condition:
        raise FixtureError(label)


def status_envelope(status):
    require(isinstance(status, str) and status.isascii() and status.startswith('hbr3:'), 'old_envelope_encoding')
    length, sep, rest = status[5:].partition(':')
    require(bool(sep) and re.fullmatch(r'[0-9]{1,3}', length) is not None and 1 <= int(length) <= 128,
            'old_envelope_operation_length')
    size = int(length); operation, rest = rest[:size], rest[size:]
    require(re.fullmatch(r'[a-zA-Z0-9_.:\-]{1,128}', operation) is not None and rest.startswith(':'),
            'old_envelope_operation')
    digest, sep, encoded = rest[1:].partition(':')
    require(bool(sep) and re.fullmatch(r'[0-9a-f]{64}', digest) is not None and digest != '0'*64,
            'old_envelope_digest')
    return operation.encode(), bytes.fromhex(digest), compact_bytes(encoded, MIB)


def inspect_legacy_state(state, cluster_id, replication_key):
    """Authenticate synthetic HBSM4 and every active HBSC2; return counts/hashes only."""
    require(isinstance(state, dict) and 'records_v5' not in state, 'old_state_already_typed')
    statuses = state.get('client_status')
    require(isinstance(statuses, dict) and all(isinstance(k,str) and isinstance(v,str) for k,v in statuses.items()),
            'old_status_map')
    production = statuses.get('heptabao-production-ha')
    operation, digest, sealed = status_envelope(production)
    require(sealed[:5] == b'HBSM4' and len(sealed) >= 65, 'old_manifest_not_hbsm4')
    cluster = cluster_id.encode(); aes = AESGCM(replication_key)
    def prefix(magic, op):
        return magic + len(cluster).to_bytes(2,'big') + cluster + len(op).to_bytes(2,'big') + op
    try:
        body = aes.decrypt(sealed[37:49], sealed[49:], prefix(b'HBSM4',operation)+sealed[5:37]+digest)
    except Exception:
        raise FixtureError('old_manifest_authentication') from None
    require(len(body) >= 43, 'old_manifest_body')
    logical = int.from_bytes(body[:8],'big'); count = int.from_bytes(body[8:10],'big')
    require(0 < logical <= 16*MIB and 0 < count <= 128 and len(body) == 43+39*count
            and body[10] & ~31 == 0 and body[11:43] != bytes(32), 'old_manifest_bounds')
    active = set(); total = 0; hasher = hashlib.sha256()
    for offset in range(43,len(body),39):
        index = int.from_bytes(body[offset:offset+2],'big'); slot = body[offset+2]
        size = int.from_bytes(body[offset+3:offset+7],'big'); expected = body[offset+7:offset+39]
        require(index <= 127 and slot <= 1 and 0 < size <= 384*1024 and index not in {x[0] for x in active},
                'old_manifest_reference')
        active.add((index,slot))
        name = f'heptabao-production-ha-chunk:{index:03d}:{slot}'
        op, observed, encrypted = status_envelope(statuses.get(name))
        require(observed == expected and encrypted[:5] == b'HBSC2' and len(encrypted) == size+33,
                'old_active_chunk_identity')
        aad = prefix(b'HBSC2',op)+index.to_bytes(2,'big')+bytes([slot])+size.to_bytes(4,'big')+expected
        try:
            plaintext = aes.decrypt(encrypted[5:17],encrypted[17:],aad)
        except Exception:
            raise FixtureError('old_chunk_authentication') from None
        require(len(plaintext) == size and hashlib.sha256(plaintext).digest() == expected, 'old_chunk_digest')
        total += size; hasher.update(plaintext)
        del plaintext
    require(total == logical and hasher.digest() == digest, 'old_whole_state_digest')
    def charged(name, value): return encoded_size(name)+encoded_size(value)+2
    legacy_bytes = 2+sum(charged(k,v) for k,v in statuses.items())
    chunks = {k:v for k,v in statuses.items() if re.fullmatch(r'heptabao-production-ha-chunk:[0-9]{3}:[01]',k)
              and int(k.rsplit(':',2)[1]) <= 127}
    active_names = {f'heptabao-production-ha-chunk:{i:03d}:{s}' for i,s in active}
    active_bytes = sum(charged(k,chunks[k]) for k in active_names)
    inactive_bytes = sum(charged(k,v) for k,v in chunks.items() if k not in active_names)
    return {'logical_state_bytes':logical, 'legacy_charged_bytes':legacy_bytes,
        'active_chunk_count':len(active), 'inactive_chunk_count':len(chunks)-len(active),
        'active_chunk_charged_bytes':active_bytes, 'inactive_chunk_charged_bytes':inactive_bytes,
        'manifest_status_sha256':hashlib.sha256(production.encode()).hexdigest(),
        'logical_state_sha256':digest.hex(), 'authenticated_active_closure':True}


def inspect_legacy_bundle(node, cluster):
    path = node.root/'raft'/'state-machine'/'state-bundle.bin'; metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and 20 <= metadata.st_size <= MAX_ARTIFACT_BYTES,'old_bundle_bound')
    with path.open('rb') as stream: data = stream.read(MAX_ARTIFACT_BYTES+1)
    require(data[:8] == MAGIC and len(data) <= MAX_ARTIFACT_BYTES
            and int.from_bytes(data[8:16],'little') == len(data)-20
            and int.from_bytes(data[-4:],'little') == zlib.crc32(data[16:-4]), 'old_bundle_frame')
    bundle = strict_json(data[16:-4])
    require(bundle.get('format_version') == 2 and isinstance(bundle.get('current_snapshot'),dict),'old_bundle_format')
    snapshot = bundle['current_snapshot']; decoded = compact_bytes(snapshot.get('data'),MAX_ARTIFACT_BYTES)
    snapstate = strict_json(decoded)
    require(snapstate.get('last_applied_log') == snapshot.get('meta',{}).get('last_log_id')
            and snapstate.get('last_membership') == snapshot.get('meta',{}).get('last_membership'), 'old_snapshot_metadata')
    current = inspect_legacy_state(bundle['state'],cluster.cluster_id,cluster.replication_key)
    snap = inspect_legacy_state(snapstate,cluster.cluster_id,cluster.replication_key)
    require(current['manifest_status_sha256'] == snap['manifest_status_sha256'],'old_snapshot_not_current_authority')
    current.update(artifact_bytes=len(data),artifact_sha256=hashlib.sha256(data).hexdigest(),
                   snapshot_bytes=len(decoded),snapshot_index=snapshot['meta']['last_log_id']['index'])
    return current


def migration_staging_would_exceed_unchanged_budget(observation, logical_value_bytes):
    # A lower bound: unique value bytes alone base64-expand by 4/3, before
    # descriptors, page metadata, auth owners or root. Do not infer a speedup.
    return (type(logical_value_bytes) is int and logical_value_bytes > 15*MIB
            and type(observation.get('legacy_charged_bytes')) is int
            and observation['legacy_charged_bytes']+132+(logical_value_bytes*4+2)//3 > 47*MIB)


class UpgradeCluster(PartitionCluster):
    def configure(self):
        super().configure()
        for node in self.nodes:
            path=node.root/'server.json'; config=json.loads(path.read_text())
            config.update(timeout_seconds=60,lifecycle_interval_seconds=0)
            private_write(path,config,replace=True)
    # Deliberately inherit ha.json with no new forward_timeout_ms field: old35
    # must construct and reopen its own data before new36 gets any authority.


def start_all(cluster,binary,check,phase):
    for node in cluster.nodes: node.stop(); node.binary=binary
    for node in cluster.nodes: node.start(wait=False)
    for node in cluster.nodes: node.wait_ready()
    cluster.wait_quorum()
    for node in cluster.nodes:
        check(f'{phase}_unseal_{node.node_id}',node.call('POST','sys/unseal',{'key':cluster.unseal_key},timeout=60)[0]==200)
    return cluster.leader()


def compact(cluster,node,check,phase):
    check(phase+'_compact',compact_for_snapshot(node,cluster.root_token)[0]==200)


def capacity(cluster,node,expected,check,phase):
    status,body=node.call('GET','sys/internal/capacity',token=cluster.root_token,timeout=60)
    data=body.get('data',{})
    check(phase,status==200 and data.get('state_storage_format')==expected)
    return data


def put_once(cluster,node,dataset,key,value,check,label):
    status,_=node.call('PUT',MOUNT+'/'+key,value,token=cluster.root_token,timeout=65)
    check(label,status==204)
    dataset.remember(key,value)


def scan(cluster,dataset):
    samples=[cluster.root_token.encode(),cluster.unseal_key.encode(),cluster.replication_key,
             *[p.encode() for p in dataset.sample_prefixes]]
    for node in cluster.nodes:
        paths=[p for folder in (node.data_dir,node.root/'raft') for p in folder.rglob('*') if p.is_file()]
        paths += [node.root/'process.log',node.root/'audit.jsonl']
        for path in paths:
            if path.exists():
                content=path.read_bytes()
                if any(sample in content for sample in samples):return False
    return True


def run(candidate,legacy,work,checks,observations):
    cluster=None; dataset=Dataset()
    def check(label,condition):
        checks.append({'case':label,'passed':condition is True})
        require(condition is True,label)
    try:
        check('legacy_pin_admitted',file_hash(legacy)==LEGACY_SHA256)
        cluster=UpgradeCluster(legacy,work/'cluster');cluster.bootstrap()
        observations['bootstrap_scenarios']=cluster.scenarios.copy()
        leader=cluster.leader()
        check('old_mount',leader.call('POST','sys/mounts/'+MOUNT,{'type':'kv','options':{'version':'1'}},
                                    token=cluster.root_token,timeout=65)[0]==204)
        for generation in range(3):
            for ordinal in range(COUNT):
                put_once(cluster,leader,dataset,f'bulk/{ordinal:04d}',dataset.make_value(generation*COUNT+ordinal),
                         check,f'old_write_{generation}_{ordinal}')
        check('old_rounds_complete',len(dataset.hashes)==COUNT)
        cap=capacity(cluster,leader,LEGACY_FORMAT,check,'old_format_v4')
        check('old_near_limit',15*MIB < cap.get('state_bytes',0) < 16*MIB and dataset.logical_bytes > 15*MIB)
        observations['old_logical_state_bytes']=cap['state_bytes'];observations['logical_value_bytes']=dataset.logical_bytes
        def all_values(node,phase,recover=False):
            for key in sorted(dataset.hashes):
                read_exact(node,cluster.root_token,dataset,key,recover=recover)
                check(phase+'_'+key.rsplit('/',1)[-1],True)
        all_values(leader,'old_read');check('old_full_read',True)
        compact(cluster,leader,check,'old')
        old=inspect_legacy_bundle(leader,cluster);observations['old']=old
        check('old_authenticated_slots',old['authenticated_active_closure'] is True and old['inactive_chunk_count']>0)
        check('old_peak_exceeds_unfixed_budget',migration_staging_would_exceed_unchanged_budget(old,dataset.logical_bytes))
        leader=start_all(cluster,legacy,check,'old_reopen');check('old_reopen_complete',True)
        all_values(leader,'old_reopen_read',True);check('old_reopen_full_read',True)
        compact(cluster,leader,check,'old_reopen')
        reopened=inspect_legacy_bundle(leader,cluster);observations['old_reopened']=reopened
        check('old_reopen_same_authority',reopened['manifest_status_sha256']==old['manifest_status_sha256'])
        leader=start_all(cluster,candidate,check,'candidate')
        capacity(cluster,leader,LEGACY_FORMAT,check,'candidate_read_only_v4')
        all_values(leader,'candidate_before_read',True);check('candidate_full_read_before_write',True)
        compact(cluster,leader,check,'candidate_before')
        observed=inspect_legacy_bundle(leader,cluster);observations['candidate_before']=observed
        check('candidate_same_old_authority',observed['manifest_status_sha256']==old['manifest_status_sha256'])
        before=process_observation(leader.process.pid);started=time.monotonic()
        put_once(cluster,leader,dataset,'bulk/0000',dataset.make_value(1_000_000),check,'first_write')
        observations['first_write_milliseconds']=round((time.monotonic()-started)*1000,3)
        observations['process_before_first_write']=before
        observations['process_after_first_write']=process_observation(leader.process.pid)
        capacity(cluster,leader,CURRENT_FORMAT,check,'published_v5')
        all_values(leader,'migration_read');check('migration_full_read',True)
        compact(cluster,leader,check,'typed')
        status,body=leader.call('GET','sys/storage/raft/snapshot-status',token=cluster.root_token,timeout=60)
        frontier=body.get('data',{}).get('snapshot_index')
        check('typed_snapshot_frontier',status==200 and type(frontier) is int and frontier>old['snapshot_index'])
        observations['typed']=wait_record_snapshot(leader,frontier);check('typed_snapshot',True)
        leader=start_all(cluster,candidate,check,'candidate_reopen');check('candidate_reopen',True)
        all_values(leader,'candidate_reopen_read',True);check('candidate_reopen_full_read',True)
        failed=leader;failed.stop();leader=cluster.leader()
        check('new_leader_after_crash',leader is not failed)
        all_values(leader,'failover_read',True);check('failover_full_read',True)
        observations['record_count']=len(dataset.hashes)
        observations['value_hashes_sha256']=hashlib.sha256(json.dumps(dataset.hashes,sort_keys=True).encode()).hexdigest()
        for node in cluster.nodes:node.stop()
        check('secrets_absent',scan(cluster,dataset));check('complete',True)
    finally:
        if cluster is not None:cluster.close()


def required_cases():
    writes = {f'old_write_{generation}_{ordinal}' for generation in range(3) for ordinal in range(COUNT)}
    reads = {f'{phase}_{ordinal:04d}' for phase in ('old_read','old_reopen_read','candidate_before_read',
        'migration_read','candidate_reopen_read','failover_read') for ordinal in range(COUNT)}
    return REQUIRED | writes | reads


def complete(rows):
    if not isinstance(rows,list) or not rows:return False
    if any(not isinstance(row,dict) or set(row)!={'case','passed'} or row['passed'] is not True
           or not isinstance(row['case'],str) or re.fullmatch(r'[a-z0-9_]{1,120}',row['case']) is None for row in rows):return False
    names=[row['case'] for row in rows]
    return len(names)==len(set(names)) and names[-1]=='complete' and required_cases().issubset(names)


def main():
    parser=SafeArgumentParser(description=__doc__)
    for name in ('binary','legacy-binary','output','work-dir'):parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--expected-legacy-sha256',required=True)
    parser.add_argument('--build-source-commit',required=True)
    args=parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit) is None:parser.error('full build commit required')
    candidate=args.binary.resolve(strict=True);legacy=args.legacy_binary.resolve(strict=True)
    admit_legacy_receipt(args.expected_legacy_sha256,json.loads(LEGACY_RECEIPT.read_text()))
    candidate_hash,legacy_hash=validate_binary_pins(candidate,legacy,args.expected_legacy_sha256)
    output=args.output.absolute();admitted=admit_output(output);work=args.work_dir.absolute()
    if work.exists() or work.resolve()!=work or not work.parent.is_dir():parser.error('new absolute private work directory required')
    work.mkdir(mode=0o700)
    before=source_identity(ROOT,candidate);runner_hash=file_hash(Path(__file__))
    checks,observations,failure=[],{},None
    try:run(candidate,legacy,work,checks,observations)
    except Exception as error:
        failure=next((r['case'] for r in reversed(checks) if r['passed'] is not True),
                     str(error) if isinstance(error,FixtureError) else 'fixture_'+type(error).__name__)
    unchanged=before==source_identity(ROOT,candidate)
    binaries_unchanged=file_hash(candidate)==candidate_hash and file_hash(legacy)==legacy_hash
    runner_unchanged=file_hash(Path(__file__))==runner_hash
    if not unchanged or not binaries_unchanged or not runner_unchanged:failure='source_binary_or_runner_changed'
    if not complete(checks):failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.kv1-records-ha-upgrade.v1','status':'passed' if failure is None else 'failed','failure':failure,
        'from_schema':35,'minimum_to_schema':36,'legacy_source_commit':LEGACY_SOURCE,'legacy_binary_sha256':legacy_hash,
        'legacy_receipt_sha256':file_hash(LEGACY_RECEIPT),'build_source_commit':args.build_source_commit,
        'candidate_binary_sha256':candidate_hash,'source_identity':before,'source_and_binary_unchanged':unchanged,
        'binaries_unchanged':binaries_unchanged,'runner_sha256':runner_hash,'runner_unchanged':runner_unchanged,
        'checks':checks,'observations':observations,'work_directory_retained':True,'work_directory':str(work),
        'legacy_state_created_by_real_binary':any(r['case']=='old_rounds_complete' and r['passed'] is True for r in checks),
        'legacy_manifest_and_active_chunks_aead_verified':any(r['case']=='old_authenticated_slots' and r['passed'] is True for r in checks),
        'typed_snapshot_observer_verifies_crypto':False,'dense_small_record_migration_covered':False,
        'rolling_mixed_version_covered':False,'exact_migration_crash_point_injected':False,
        'synthetic_only':True,'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    print(json.dumps({'status':report['status'],'checks':len(checks),'failure':failure}))
    return 0 if failure is None else 1


if __name__=='__main__':raise SystemExit(main())
