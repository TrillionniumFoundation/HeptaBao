#!/usr/bin/env python3
"""Three-process KV1 record data survives snapshot catch-up and authority loss.

The lagging voter is stopped before growth, resumes after the leader actually
purges its old log, and must become the serving leader before data is accepted
as recovered. Writes are never retried after an ambiguous result.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import tempfile
import time

from bao_http import SafeArgumentParser, private_write
from capacity_live import tree_bytes
from core_isolation import ROOT, file_hash
from ha_destructive import FixtureError
from ha_network_partition import PartitionCluster
from kv1_record_scale_live import Dataset, MIB, MOUNT, process_observation
from online_evidence import admit_output, source_identity

REQUIRED = frozenset({'mount_created', 'lagger_stopped_before_growth', 'growth_above_old_limit',
    'leader_all_records', 'snapshot_acknowledged', 'logs_purged_past_lagger', 'leader_snapshot_graph',
    'lagger_restarted', 'lagger_snapshot_graph', 'lagger_unsealed', 'lagger_became_leader', 'lagger_all_records',
    'post_snapshot_edit', 'post_snapshot_delete', 'new_leader_after_crash',
    'failover_all_records', 'all_processes_reopened', 'reopened_snapshot_graph', 'reopened_all_records',
    'quorum_loss_refuses_reads', 'quorum_restored', 'restored_all_records', 'secrets_absent', 'complete'})


def snapshot_frontier(data):
    return (isinstance(data, dict) and type(data.get('applied_index')) is int
            and type(data.get('snapshot_index')) is int and type(data.get('purged_index')) is int
            and 0 <= data['purged_index'] <= data['snapshot_index'] <= data['applied_index'])


def complete(checks):
    if not isinstance(checks, list) or not checks:
        return False
    if any(not isinstance(row, dict) or set(row) != {'case','passed'} or row['passed'] is not True
           or not isinstance(row['case'],str) or re.fullmatch(r'[a-z0-9_]{1,120}', row['case']) is None for row in checks):
        return False
    names = [row['case'] for row in checks]
    return len(names) == len(set(names)) and names[-1] == 'complete' and REQUIRED.issubset(names)


def read_exact(node, root_token, dataset, key, *, recover=False):
    deadline = time.monotonic() + 30
    while True:
        status, body = node.call('GET', MOUNT + '/' + key, token=root_token, timeout=15)
        if dataset.matches(key, status, body):
            return
        # A successful stale or corrupt value is never hidden by polling.
        if status == 200 or status not in (429,503) or not recover or time.monotonic() >= deadline:
            raise FixtureError('acknowledged_kv1_record_not_exact')
        time.sleep(.1)


def compact_for_snapshot(node, root_token):
    # This existing maintenance route triggers the real Raft snapshot but does
    # not export the application backup through its separate 20 MiB API bound.
    return node.call('POST', 'sys/storage/raft/compact', {}, token=root_token, timeout=60)


def wait_record_snapshot(node, minimum_index):
    # An older valid snapshot can still be installing. Structural corruption
    # is never converted into a polling delay or successful catch-up.
    from raft_record_snapshot_observation import SnapshotPending, inspect_record_bundle
    deadline=time.monotonic()+60
    while True:
        try:
            return inspect_record_bundle(node.root/'raft'/'state-machine'/'state-bundle.bin',
                                         minimum_index=minimum_index)
        except (FileNotFoundError, SnapshotPending):
            if time.monotonic()>=deadline:
                raise FixtureError('record_snapshot_install_not_observed') from None
            time.sleep(.25)



def transition_leader(cluster, observations, phase):
    try:
        return cluster.leader()
    except FixtureError:
        # Preserve safe health/authority facts from the actual failure. These
        # diagnostic reads do not retry or repair an ambiguous write.
        rows=[]
        for node in cluster.running():
            row={'node':node.node_id}
            for label,path,token in [('health','sys/health',''),('leader','sys/leader',cluster.root_token),
                                     ('health_after','sys/health','')]:
                try:
                    status,body=node.call('GET',path,token=token,timeout=15)
                    row[label]={'status':status,**{k:v for k,v in body.items()
                        if k in {'initialized','sealed','standby','ha_enabled','ha_active',
                                 'ha_application_ready','recovery_required','is_self','leader_id','local_id'}
                        and type(v) in (bool,int)}}
                except Exception as error:
                    row[label]={'exception_type':type(error).__name__}
            rows.append(row)
        observations[phase+'_failed_leader_observation']=rows
        raise

def run(binary, root, target_mib, checks, observations, inherited):
    cluster = None
    def check(name, condition):
        checks.append({'case':name, 'passed':condition is True})
        if condition is not True:
            raise FixtureError(name)
    try:
        cluster = PartitionCluster(binary, root / 'cluster')
        cluster.bootstrap(); inherited.extend(cluster.scenarios)
        leader = cluster.leader()
        check('mount_created', leader.call('POST','sys/mounts/'+MOUNT,
            {'type':'kv','options':{'version':'1'}},token=cluster.root_token)[0] == 204)
        status, body = leader.call('GET','sys/storage/raft/snapshot-status',token=cluster.root_token)
        old_index = body.get('data',{}).get('applied_index')
        check('old_frontier_observed', status == 200 and type(old_index) is int and old_index >= 0)
        lagger = min((node for node in cluster.nodes if node is not leader),key=lambda node:node.node_id)
        lagger.stop()
        check('lagger_stopped_before_growth', lagger.process is None)
        dataset, ordinal = Dataset(), 0
        while dataset.logical_bytes < target_mib * MIB:
            key, value = f'bulk/{ordinal:04d}', dataset.make_value(ordinal)
            observations['pending_growth_ordinal'] = ordinal
            started = time.monotonic()
            try:
                status,_ = leader.call('PUT',MOUNT+'/'+key,value,token=cluster.root_token,timeout=30)
            finally:
                observations.setdefault('growth_latency_ms', []).append(round((time.monotonic()-started)*1000, 3))
            observations['last_growth_status'] = status
            check(f'growth_{ordinal}',status == 204)
            dataset.remember(key,value); ordinal += 1
        check('growth_above_old_limit',dataset.logical_bytes > 16*MIB and dataset.logical_bytes >= target_mib*MIB)
        def all_records(node,phase,recover=False):
            for key in sorted(dataset.hashes):
                read_exact(node,cluster.root_token,dataset,key,recover=recover)
                check(phase+'_'+key.rsplit('/',1)[-1],True)
        all_records(leader,'leader_read')
        check('leader_all_records',True)
        status,_ = compact_for_snapshot(leader,cluster.root_token)
        check('snapshot_acknowledged',status == 200)
        deadline = time.monotonic()+15
        frontier = {}
        while time.monotonic()<deadline:
            status,body = leader.call('GET','sys/storage/raft/snapshot-status',token=cluster.root_token)
            frontier=body.get('data',{})
            if status==200 and snapshot_frontier(frontier) and frontier['purged_index']>old_index:
                break
            time.sleep(.2)
        check('logs_purged_past_lagger',snapshot_frontier(frontier) and frontier['purged_index']>old_index)
        observations['snapshot_frontier']={key:frontier[key] for key in ('applied_index','snapshot_index','purged_index')}
        observations['leader_snapshot']=wait_record_snapshot(leader,frontier['snapshot_index'])
        check('leader_snapshot_graph',True)
        observations['lagger_previous_upper_bound']=old_index
        observations['logical_payload_bytes_before_edits']=dataset.logical_bytes
        observations['large_record_count']=len(dataset.hashes)
        lagger.start()
        check('lagger_restarted',lagger.process is not None)
        # Runtime snapshot transport runs while the service is sealed. Observe
        # the actual installed format-3 graph before sending unseal once.
        observations['lagger_snapshot']=wait_record_snapshot(lagger,frontier['snapshot_index'])
        check('lagger_snapshot_graph',True)
        check('lagger_unsealed',lagger.call('POST','sys/unseal',{'key':cluster.unseal_key},timeout=60)[0]==200)
        check('same_leader_for_snapshot_catchup',cluster.leader() is leader)
        check('step_down_acknowledged',leader.call('POST','sys/step-down',{},token=cluster.root_token,timeout=15)[0]==204)
        recovered_leader=transition_leader(cluster,observations,'after_step_down')
        check('lagger_became_leader',recovered_leader is lagger)
        all_records(lagger,'lagger_leader_read')
        check('lagger_all_records',True)
        replacement=dataset.make_value(1_000_000)
        check('post_snapshot_edit',lagger.call('PUT',MOUNT+'/bulk/0000',replacement,token=cluster.root_token,timeout=30)[0]==204)
        dataset.remember('bulk/0000',replacement)
        check('post_snapshot_delete',lagger.call('DELETE',MOUNT+'/bulk/0001',token=cluster.root_token,timeout=30)[0]==204)
        dataset.forget('bulk/0001')
        lagger.stop()
        leader=transition_leader(cluster,observations,'after_crash')
        check('new_leader_after_crash',leader is not lagger)
        all_records(leader,'failover_read',recover=True)
        check('failover_all_records',True)
        status,body=leader.call('GET',MOUNT+'/bulk/0001',token=cluster.root_token)
        check('failover_deleted_absent',status==404 and not body.get('data'))
        observations['before_full_restart']=[{'node':node.node_id,'data_bytes':tree_bytes(node.data_dir),
            'raft_bytes':tree_bytes(node.root/'raft'),
            **({'process':process_observation(node.process.pid)} if node.process is not None else {})} for node in cluster.nodes]
        for node in cluster.nodes:node.stop()
        for node in cluster.nodes:node.start(wait=False)
        for node in cluster.nodes:node.wait_ready()
        cluster.wait_quorum()
        for node in cluster.nodes:
            check(f'reopen_unseal_{node.node_id}',node.call('POST','sys/unseal',{'key':cluster.unseal_key},timeout=60)[0]==200)
        leader=cluster.leader()
        check('all_processes_reopened',True)
        observations['reopened_snapshot']=wait_record_snapshot(lagger,frontier['snapshot_index'])
        check('reopened_snapshot_graph',True)
        all_records(leader,'reopen_read',recover=True)
        check('reopened_all_records',True)
        for node in cluster.nodes:
            read_exact(node,cluster.root_token,dataset,'bulk/0000',recover=True)
        for link in cluster.links.values():link.set_blocked(True)
        time.sleep(3)
        for node in cluster.nodes:
            status,body=node.call('GET',MOUNT+'/bulk/0000',token=cluster.root_token,timeout=15)
            check(f'partition_denied_{node.node_id}',status==503 and not any(body.get(key) for key in ('data','auth','wrap_info')))
        check('quorum_loss_refuses_reads',True)
        cluster._heal();leader=cluster.leader()
        check('quorum_restored',True)
        all_records(leader,'restored_read',recover=True)
        check('restored_all_records',True)
        observations['final_nodes']=[{'node':node.node_id,'data_bytes':tree_bytes(node.data_dir),
            'raft_bytes':tree_bytes(node.root/'raft'),'process':process_observation(node.process.pid)} for node in cluster.nodes]
        samples=[cluster.root_token.encode(),cluster.unseal_key.encode(),cluster.replication_key,
                 *[prefix.encode() for prefix in dataset.sample_prefixes]]
        for node in cluster.nodes:node.stop()
        safe=True
        for node in cluster.nodes:
            files=[path for folder in (node.data_dir,node.root/'raft') for path in folder.rglob('*') if path.is_file()]
            files += [node.root/'process.log',node.root/'audit.jsonl']
            for path in files:
                if path.exists():
                    data=path.read_bytes();safe &= not any(sample in data for sample in samples)
        check('secrets_absent',safe)
        check('complete',True)
    finally:
        if cluster is not None:
            observations['process_exit_codes_before_cleanup'] = {str(node.node_id):
                node.process.poll() if node.process is not None else 'stopped' for node in cluster.nodes}
            cluster.close()


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--build-source-commit',required=True)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--target-mib',type=int,choices=(24,32),default=32)
    args=parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit) is None:parser.error('full build source commit required')
    binary,output=args.binary.resolve(strict=True),args.output.absolute()
    admitted=admit_output(output);before=source_identity(ROOT,binary);runner_hash=file_hash(Path(__file__))
    root=Path(tempfile.mkdtemp(prefix='heptabao-kv1-record-ha-'));root.chmod(0o700)
    checks,observations,inherited,failure=[],{},[],None
    try:run(binary,root,args.target_mib,checks,observations,inherited)
    except Exception as error:
        failure=next((row['case'] for row in reversed(checks) if row['passed'] is not True),'fixture_'+type(error).__name__)
    after=source_identity(ROOT,binary)
    unchanged=before==after;runner_unchanged=runner_hash==file_hash(Path(__file__))
    if not unchanged or not runner_unchanged:failure='source_binary_or_runner_changed'
    if not complete(checks):failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.kv1-record-ha.v1','status':'passed' if failure is None else 'failed','failure':failure,
        'source_identity':before,'source_identity_after':after,
        'source_changed_fields':sorted(key for key in before.keys() | after.keys() if before.get(key)!=after.get(key)),
        'source_and_binary_unchanged':unchanged,'build_source_commit':args.build_source_commit,
        'retained_failure_work_dir':str(root) if failure is not None else None,
        'runner_sha256':runner_hash,'runner_unchanged':runner_unchanged,'target_payload_mib':args.target_mib,
        'checks':checks,'observations':observations,'inherited_bootstrap_scenarios':inherited,
        'snapshot_catchup_proof':'log purge beyond offline frontier followed by recovered voter serving all data as leader',
        'typed_snapshot_graph_inspected':all(name in {row['case'] for row in checks if row['passed'] is True}
            for name in ('leader_snapshot_graph','lagger_snapshot_graph','reopened_snapshot_graph')),
        'snapshot_observer_verifies_cryptographic_authenticity':False,
        'recovered_data_validation':'serving-leader HTTPS reads compared to every pre-fault canonical value hash',
        'exact_staging_crash_point_injected':False,'postgresql_covered':False,
        'synthetic_only':True,'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if failure is None:shutil.rmtree(root)
    print(json.dumps({'status':report['status'],'checks':len(checks),'failure':failure}))
    return 0 if failure is None else 1


if __name__=='__main__':raise SystemExit(main())
