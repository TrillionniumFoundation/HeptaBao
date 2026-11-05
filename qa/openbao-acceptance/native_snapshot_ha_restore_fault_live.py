#!/usr/bin/env python3
"""Release-binary incomplete-body death and deliberately unobserved HA restore.

Three local TLS voters, five-second listeners. These are not exact post-Stage or
commit-before-local-persist kill points. Read-only observation may repeat;
mutations and restore uploads never do. No server response is read by the fault
transport, and transport success is never evidence of publication.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import signal
import tempfile
import time
import urllib.error

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from ha_destructive import FixtureError
from native_restore_fault_transport import begin_unobserved_restore
from native_snapshot_cli_live import cli, contains_any, private_parent
from native_snapshot_ha_live import SaveCluster, client_view, strict_archive
from native_snapshot_ha_restore_live import canonical, restart
from official_openbao_launcher import pinned_artifact, verify_inputs
from online_evidence import admit_output, complete_checks, source_identity

MOUNT='native-fault'
POLICY='native-fault-owner'
OBSERVATION_SECONDS=30
REQUIRED=frozenset({'three_processes','listener_deadlines','archive_saved','archive_complete',
    'live_all_nodes','incomplete_body_withheld','incomplete_owned_kill','incomplete_survivor_live',
    'incomplete_all_nodes_live','incomplete_restart_live','incomplete_write','incomplete_save',
    'complete_body_sent','survivor_observed_restored','unobserved_owned_kill',
    'unobserved_survivor_restored','unobserved_all_nodes_restored','unobserved_restart_restored',
    'unobserved_write','unobserved_save','processes_stopped','plaintext_absent','complete'})


def complete(rows):
    return complete_checks(rows,required_cases=REQUIRED) and rows[-1]['case']=='complete'


def digest(value):return hashlib.sha256(canonical(value)).hexdigest()


def owned_kill(cluster,node):
    if node not in cluster.nodes or node.process is None or node.process.poll() is not None:
        raise FixtureError('kill_target_not_owned_live_node')
    process=node.process
    node.stop()
    return node.process is None and process.returncode == -signal.SIGKILL


def observe(node, token, hashes, policy_hash, *, later_present, deadline=None):
    def call(path):
        timeout=5 if deadline is None else min(2,deadline-time.monotonic())
        if timeout<=0:raise TimeoutError('observation_budget')
        return node.call('GET',path,token=token,timeout=timeout)
    for key,expected in hashes.items():
        status,body=call(MOUNT+'/'+key)
        if status!=200 or digest(body.get('data'))!=expected:return False
    status,body=call(MOUNT+'/later')
    if later_present:
        if status!=200 or digest(body.get('data'))!=digest({'value':'live-later'}):return False
    elif status!=404:return False
    status,body=call('sys/policies/acl/'+POLICY)
    return status==200 and digest(body.get('data'))==policy_hash


def wait_survivor_observation(nodes,token,hashes,policy_hash,*,later_present):
    deadline=time.monotonic()+OBSERVATION_SECONDS
    while time.monotonic()<deadline:
        for node in nodes:
            if time.monotonic()>=deadline:break
            try:
                if observe(node,token,hashes,policy_hash,later_present=later_present,deadline=deadline):
                    return node.node_id
            except (OSError,urllib.error.URLError,TimeoutError):pass
        remaining=deadline-time.monotonic()
        if remaining>0:time.sleep(min(0.1,remaining))
    raise FixtureError('restored_publication_not_observed')


def reopen_one(cluster,node):
    node.start()
    if node.call('POST','sys/unseal',{'key':cluster.unseal_key})[0]!=200:
        raise FixtureError('killed_node_unseal_failed')
    cluster.wait_quorum()


def run(binary,bao,work,checks,observations):
    cluster=None;upload=None;samples=[]
    def check(case,passed):
        if type(passed) is not bool:raise FixtureError('nonboolean_observation')
        checks.append({'case':case,'passed':passed})
        if not passed:raise FixtureError(case)
    try:
        cluster=SaveCluster(binary,work/'cluster');cluster.bootstrap()
        check('three_processes',len({n.process.pid for n in cluster.nodes})==3)
        check('listener_deadlines',all(json.loads((n.root/'server.json').read_text())['timeout_seconds']==5 for n in cluster.nodes))
        leader=cluster.leader();token=cluster.root_token
        def call(method,path,body=None):return leader.call(method,path,body,token=token,timeout=5)
        def verify(phase,hashes,policy_hash,*,later_present,nodes=None):
            for node in cluster.nodes if nodes is None else nodes:
                check(phase+'_node_'+str(node.node_id),observe(node,token,hashes,policy_hash,later_present=later_present))
            check(phase,True)
        check('mounted',call('POST','sys/mounts/'+MOUNT,{'type':'kv','options':{'version':'1'}})[0]==204)
        archived={f'k{n:02}':{'value':secrets.token_hex(2048),'ordinal':n} for n in range(8)}
        live={key:{'value':secrets.token_hex(2048),'ordinal':value['ordinal']} for key,value in archived.items()}
        samples.extend(value['value'][:80].encode() for values in (archived,live) for value in values.values())
        archived_hashes={key:digest(value) for key,value in archived.items()}
        live_hashes={key:digest(value) for key,value in live.items()}
        for key,value in archived.items():check('seed_'+key,call('PUT',MOUNT+'/'+key,value)[0]==204)
        check('archived_owner_written',call('PUT','sys/policies/acl/'+POLICY,{'policy':'path "secret/*" { capabilities = ["read"] }'})[0]==204)
        status,body=call('GET','sys/policies/acl/'+POLICY);check('archived_owner_read',status==200);archived_owner=digest(body['data'])
        archive=work/'archived.snap'
        check('archive_saved',cli(bao,client_view(cluster,leader),work,'save',archive)==0)
        observations['archive']=strict_archive(archive);check('archive_complete',True)
        for key,value in live.items():check('live_write_'+key,call('PUT',MOUNT+'/'+key,value)[0]==204)
        check('later_written',call('PUT',MOUNT+'/later',{'value':'live-later'})[0]==204)
        check('live_owner_written',call('PUT','sys/policies/acl/'+POLICY,{'policy':'path "secret/*" { capabilities = ["list"] }'})[0]==204)
        status,body=call('GET','sys/policies/acl/'+POLICY);check('live_owner_read',status==200);live_owner=digest(body['data'])
        check('owner_states_distinct',archived_owner!=live_owner)
        verify('live_all_nodes',live_hashes,live_owner,later_present=True)

        killed=leader
        observations['restore_upload_attempts']=1
        upload=begin_unobserved_restore(killed,token,archive,omit_final_byte=True)
        observations['incomplete_transport']=upload.safe_observation()
        # No polling/sleep between returning from sendall(length-1) and owned death.
        killed_ok=owned_kill(cluster,killed);upload.close();upload=None
        check('incomplete_owned_kill',killed_ok)
        check('incomplete_body_withheld',observations['incomplete_transport']['request_body_complete'] is False
              and observations['incomplete_transport']['request_body_bytes_sent']==archive.stat().st_size-1)
        leader=cluster.leader();check('incomplete_successor_changed',leader is not killed)
        verify('incomplete_survivor_live',live_hashes,live_owner,later_present=True,nodes=cluster.running())
        reopen_one(cluster,killed);leader=cluster.leader()
        verify('incomplete_all_nodes_live',live_hashes,live_owner,later_present=True)
        leader=restart(cluster);verify('incomplete_restart_live',live_hashes,live_owner,later_present=True)
        check('incomplete_write',call('PUT',MOUNT+'/probe-before',{'value':'after-incomplete'})[0]==204)
        saved=work/'after-incomplete.snap';check('incomplete_save',cli(bao,client_view(cluster,leader),work,'save',saved)==0)
        observations['incomplete_post_restart_archive']=strict_archive(saved)

        killed=leader;survivors=[n for n in cluster.nodes if n is not killed]
        observations['restore_upload_attempts']=2
        upload=begin_unobserved_restore(killed,token,archive)
        observations['unobserved_transport']=upload.safe_observation()
        check('complete_body_sent',observations['unobserved_transport']['request_body_complete'] is True)
        witness=wait_survivor_observation(survivors,token,archived_hashes,archived_owner,later_present=False)
        observations['restored_witness_node']=witness
        check('survivor_observed_restored',witness in [n.node_id for n in survivors])
        # Observation proves application publication, not a particular local-persist gap.
        check('unobserved_owned_kill',owned_kill(cluster,killed));upload.close();upload=None
        leader=cluster.leader();check('unobserved_successor_changed',leader is not killed)
        verify('unobserved_survivor_restored',archived_hashes,archived_owner,later_present=False,nodes=cluster.running())
        reopen_one(cluster,killed);leader=cluster.leader()
        verify('unobserved_all_nodes_restored',archived_hashes,archived_owner,later_present=False)
        leader=restart(cluster);verify('unobserved_restart_restored',archived_hashes,archived_owner,later_present=False)
        check('pre_restore_probe_absent',call('GET',MOUNT+'/probe-before')[0]==404)
        check('unobserved_write',call('PUT',MOUNT+'/probe-after',{'value':'after-unobserved'})[0]==204)
        saved=work/'after-unobserved.snap';check('unobserved_save',cli(bao,client_view(cluster,leader),work,'save',saved)==0)
        observations['unobserved_post_restart_archive']=strict_archive(saved)
        samples += [token.encode(),cluster.unseal_key.encode()]
        cluster.close();check('processes_stopped',all(n.process is None for n in cluster.nodes))
        files=[p for n in cluster.nodes for base in (n.data_dir,n.root/'raft') for p in base.rglob('*') if p.is_file()]
        files += [p for n in cluster.nodes for p in (n.root/'audit.jsonl',n.root/'process.log') if p.exists()]
        files += list(work.glob('*.snap'))
        check('plaintext_absent',bool(files) and all(not contains_any(p,samples) for p in files))
        check('complete',True)
    finally:
        if upload is not None:upload.close()
        if cluster is not None:cluster.close()


def main():
    parser=SafeArgumentParser(description=__doc__)
    for name in ('binary','work-parent','output'):parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--build-source-commit',required=True)
    args=parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit) is None:parser.error('full_build_commit_required')
    binary=args.binary.resolve(strict=True);parent=private_parent(args.work_parent);output=args.output.absolute();admitted=admit_output(output)
    bao=verify_inputs();cli_hash=file_hash(bao);before=source_identity(ROOT,binary);runner_hash=file_hash(Path(__file__))
    work=Path(tempfile.mkdtemp(prefix='native-ha-fault-',dir=parent));checks,observations,failure=[],{},None
    def interrupted(*_):raise FixtureError('fixture_interrupted')
    handlers={kind:signal.signal(kind,interrupted) for kind in (signal.SIGTERM,signal.SIGINT)}
    try:run(binary,bao,work,checks,observations)
    except Exception as error:
        failure=next((r['case'] for r in reversed(checks) if r['passed'] is not True),'fixture_'+type(error).__name__)
    finally:
        for kind,handler in handlers.items():signal.signal(kind,handler)
    after=source_identity(ROOT,binary);runner_ok=runner_hash==file_hash(Path(__file__));cli_ok=cli_hash==file_hash(bao)
    if before!=after or not runner_ok or not cli_ok:failure='source_binary_or_fixture_changed'
    if before['source_dirty'] or after['source_dirty']:failure='source_dirty'
    if not complete(checks):failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.native-snapshot-ha-restore-fault.v1','status':'failed' if failure else 'passed',
      'failure':failure,'checks':checks,'observations':observations,'source_identity':before,'source_identity_after':after,
      'source_and_binary_unchanged':before==after,'build_source_commit':args.build_source_commit,
      'runner_sha256':runner_hash,'runner_unchanged':runner_ok,'official_cli_sha256':cli_hash,'official_cli_unchanged':cli_ok,
      'official_cli_artifact_sha256':pinned_artifact()['artifact_sha256'],'official_cli_version':'2.6.2',
      'retained_failure_work_dir':str(work) if failure else None,'node_count':3,'listener_timeout_seconds':5,
      'observation_budget_seconds':OBSERVATION_SECONDS,'restore_uploads':observations.get('restore_upload_attempts',0),'mutation_retry':False,
      'incomplete_body_death_covered':failure is None,'unobserved_response_reconciliation_covered':failure is None,
      'post_stage_kill_covered':False,'commit_before_local_persist_kill_covered':False,
      'raw_epoch_value_observed':False,'multi_host_covered':False,'physical_power_loss_covered':False,
      'cross_seal_force':False,'external_provider_rollback':False,'openbao_state_interoperability':False,
      'full_openbao_compatibility':False,'production_authority':False,'independent_qualification':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if not failure:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'checks':len(checks),'failure':failure}))
    return int(failure is not None)


if __name__=='__main__':raise SystemExit(main())
