#!/usr/bin/env python3
"""P/Q native restore crash gates using a separately identified opt-in binary.

This is feature instrumentation, never a claim about an uninstrumented release.
Each phase uses a fresh three-voter TLS group and its original 5-second listener.
No log interpretation, ciphertext editing, release command or mutation retry.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
from types import MethodType

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from ha_destructive import FixtureError, checked_binary
from native_restore_gate_controller import FEATURE, PHASES, GateController
from native_restore_fault_transport import begin_unobserved_restore
from native_snapshot_cli_live import cli, contains_any, private_parent
from native_snapshot_ha_live import SaveCluster, client_view, strict_archive
from native_snapshot_ha_restore_live import restart
from native_snapshot_ha_restore_fault_live import MOUNT, POLICY, digest, observe, owned_kill, reopen_one
from official_openbao_launcher import pinned_artifact, verify_inputs
from online_evidence import admit_output, complete_checks, source_identity
from provider_renewal_upgrade import durable_manifest

PHASE_REQUIRED=frozenset({'three_processes','listener_deadlines','archive_saved','archive_complete',
    'live_changed','pre_gate_restarted','pre_gate_values','ready_validated','owned_kill',
    'local_durable_artifacts_unchanged','successor_changed','survivors_correct',
    'killed_node_recovered','recovery_binary_used','all_nodes_correct','whole_restart_correct','all_recovery_binaries_used','new_write','new_save',
    'processes_stopped','plaintext_absent','complete'})
REQUIRED=frozenset({prefix+'_'+name for prefix in ('p','q') for name in PHASE_REQUIRED} | {'complete'})


def complete(rows):return complete_checks(rows,required_cases=REQUIRED) and rows[-1]['case']=='complete'


class GatedCluster(SaveCluster):
    def __init__(self,binary,root,phase):
        self.phase=phase;self.allow_gates=True;super().__init__(binary,root)

    def configure(self):
        super().configure()
        for node in self.nodes:
            node.ordinary_start=node.start;node.gate=None
            node.start=MethodType(self._start,node)

    def _start(self,node,ha=True,*,wait=True):
        if node.gate is not None:node.gate.close();node.gate=None
        if not ha or not self.allow_gates:return node.ordinary_start(ha=ha,wait=wait)
        if node.process is not None:raise FixtureError('gated_node_already_running')
        gate=GateController(self.phase,secrets.token_hex(32));node.gate=gate
        fd=os.open(node.root/'process.log',os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
        node.log=os.fdopen(fd,'ab')
        command=[str(node.binary),'--config',str(node.root/'server.json'),'--ha-config',str(node.ha_config),*gate.arguments()]
        try:
            # Direct child, not a shell: Linux socketpair peer PID is this controller.
            node.process=subprocess.Popen(command,stdin=gate.child,stdout=node.log,stderr=node.log,
                                          close_fds=True,start_new_session=True)
            node.started_pids.append(node.process.pid);gate.child_started()
            if wait:node.wait_ready()
        except BaseException:
            gate.close()
            if node.process is None:node.log.close();node.log=None
            raise

    def close(self):
        try:super().close()
        finally:
            for node in self.nodes:
                if node.gate is not None:node.gate.close();node.gate=None


def generation(node,token):
    status,body=node.call('GET','sys/internal/capacity',token=token,timeout=5)
    value=body.get('data',{}).get('generation')
    if status!=200 or type(value) is not int or value<0:raise FixtureError('local_generation_unavailable')
    return value


def run_phase(binary,recovery_binary,bao,work,phase,check,observations):
    cluster=None;upload=None;samples=[]
    try:
        cluster=GatedCluster(binary,work/'cluster',phase);cluster.bootstrap()
        check('three_processes',len({n.process.pid for n in cluster.nodes})==3)
        check('listener_deadlines',all(json.loads((n.root/'server.json').read_text())['timeout_seconds']==5 for n in cluster.nodes))
        leader=cluster.leader();token=cluster.root_token
        def call(method,path,body=None):return leader.call(method,path,body,token=token,timeout=5)
        def verify(case,hashes,owner,later,nodes=None):
            for node in cluster.nodes if nodes is None else nodes:
                check(case+'_node_'+str(node.node_id),observe(node,token,hashes,owner,later_present=later))
            check(case,True)
        check('mounted',call('POST','sys/mounts/'+MOUNT,{'type':'kv','options':{'version':'1'}})[0]==204)
        archived={f'k{n:02}':{'value':secrets.token_hex(2048),'ordinal':n} for n in range(8)}
        live={key:{'value':secrets.token_hex(2048),'ordinal':value['ordinal']} for key,value in archived.items()}
        samples.extend(v['value'][:80].encode() for values in (archived,live) for v in values.values())
        archived_hashes={key:digest(value) for key,value in archived.items()};live_hashes={key:digest(value) for key,value in live.items()}
        for key,value in archived.items():check('seed_'+key,call('PUT',MOUNT+'/'+key,value)[0]==204)
        check('archived_owner_write',call('PUT','sys/policies/acl/'+POLICY,{'policy':'path "secret/*" { capabilities = ["read"] }'})[0]==204)
        status,body=call('GET','sys/policies/acl/'+POLICY);check('archived_owner_read',status==200);archived_owner=digest(body['data'])
        archive=work/'archived.snap';check('archive_saved',cli(bao,client_view(cluster,leader),work,'save',archive)==0)
        observations['archive']=strict_archive(archive);check('archive_complete',True)
        for key,value in live.items():check('live_'+key,call('PUT',MOUNT+'/'+key,value)[0]==204)
        check('later_written',call('PUT',MOUNT+'/later',{'value':'live-later'})[0]==204)
        check('live_owner_write',call('PUT','sys/policies/acl/'+POLICY,{'policy':'path "secret/*" { capabilities = ["list"] }'})[0]==204)
        status,body=call('GET','sys/policies/acl/'+POLICY);check('live_owner_read',status==200);live_owner=digest(body['data'])
        check('live_changed',archived_owner!=live_owner)
        # Reopening resets the existing HA GC cadence. The upcoming ordinary
        # commit GC may retire the old archive graph, requiring genuine Stage.
        # The ready record must still prove actual receipts; no count is assumed.
        leader=restart(cluster);check('pre_gate_restarted',True)
        verify('pre_gate_values',live_hashes,live_owner,True)
        before_generation=generation(leader,token)
        before_artifacts=durable_manifest(leader.data_dir)
        observations['before_local_generation']=before_generation
        observations['before_local_artifacts_sha256']=before_artifacts
        killed=leader;gate=leader.gate
        if gate is None:raise FixtureError('leader_gate_not_armed')
        # One absolute controller budget starts before transmission. The child
        # independently enforces its original accepted-request deadline.
        deadline=time.monotonic()+5
        observations['restore_upload_attempts']=1
        upload=begin_unobserved_restore(leader,token,archive)
        observations['transport']=upload.safe_observation()
        ready=gate.ready(pid=leader.process.pid,node_id=leader.node_id,generation=before_generation,deadline=deadline)
        # No HTTP read, generation query, sleep or filesystem walk between ready
        # and SIGKILL. The application writer is deliberately held by the gate.
        killed_ok=owned_kill(cluster,killed)
        observations['ready']=ready
        check('ready_validated',True);check('owned_kill',killed_ok)
        upload.close();upload=None
        cluster.allow_gates=False
        after_artifacts=durable_manifest(killed.data_dir)
        observations['after_kill_local_artifacts_sha256']=after_artifacts
        check('local_durable_artifacts_unchanged',after_artifacts==before_artifacts)
        expected_hashes,expected_owner,later=(live_hashes,live_owner,True) if phase==PHASES[0] else (archived_hashes,archived_owner,False)
        leader=cluster.leader();check('successor_changed',leader is not killed)
        verify('survivors_correct',expected_hashes,expected_owner,later,cluster.running())
        killed.binary=recovery_binary
        reopen_one(cluster,killed);leader=cluster.leader();check('killed_node_recovered',True)
        check('recovery_binary_used',killed.binary==recovery_binary and killed.gate is None)
        verify('all_nodes_correct',expected_hashes,expected_owner,later)
        for node in cluster.nodes:node.binary=recovery_binary
        leader=restart(cluster);verify('whole_restart_correct',expected_hashes,expected_owner,later)
        check('all_recovery_binaries_used',all(n.binary==recovery_binary and n.gate is None for n in cluster.nodes))
        check('new_write',call('PUT',MOUNT+'/post-gate',{'value':'after-recovery'})[0]==204)
        after=work/'after-recovery.snap';check('new_save',cli(bao,client_view(cluster,leader),work,'save',after)==0)
        observations['recovered_archive']=strict_archive(after)
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
    for name in ('binary','recovery-binary','work-parent','output'):parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--build-source-commit',required=True)
    parser.add_argument('--expected-binary-sha256',required=True)
    parser.add_argument('--expected-recovery-binary-sha256',required=True)
    parser.add_argument('--recovery-build-source-commit',required=True)
    args=parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}',args.build_source_commit):parser.error('full_build_commit_required')
    if not re.fullmatch('[0-9a-f]{64}',args.expected_binary_sha256):parser.error('feature_binary_sha256_required')
    if not re.fullmatch('[0-9a-f]{64}',args.expected_recovery_binary_sha256):parser.error('recovery_binary_sha256_required')
    if args.recovery_build_source_commit!=args.build_source_commit:parser.error('same_source_recovery_build_required')
    if args.expected_recovery_binary_sha256==args.expected_binary_sha256:parser.error('separate_default_off_artifact_required')
    binary=args.binary.resolve(strict=True);checked_binary(binary,args.expected_binary_sha256)
    recovery_binary=args.recovery_binary.resolve(strict=True);checked_binary(recovery_binary,args.expected_recovery_binary_sha256)
    parent=private_parent(args.work_parent);output=args.output.absolute();admitted=admit_output(output)
    bao=verify_inputs();cli_hash=file_hash(bao);before=source_identity(ROOT,binary);runner_hash=file_hash(Path(__file__))
    work=Path(tempfile.mkdtemp(prefix='native-ha-gated-',dir=parent));checks,observations,failure=[],{},None
    def check(name,passed):
        if type(passed) is not bool:raise FixtureError('nonboolean_observation')
        checks.append({'case':name,'passed':passed})
        if not passed:raise FixtureError(name)
    def interrupted(*_):raise FixtureError('fixture_interrupted')
    handlers={kind:signal.signal(kind,interrupted) for kind in (signal.SIGTERM,signal.SIGINT)}
    try:
        for prefix,phase in zip(('p','q'),PHASES):
            directory=work/prefix;directory.mkdir(mode=0o700);observations[prefix]={}
            run_phase(binary,recovery_binary,bao,directory,phase,lambda name,passed:check(prefix+'_'+name,passed),observations[prefix])
        check('complete',True)
    except Exception as error:
        failure=next((r['case'] for r in reversed(checks) if r['passed'] is not True),'fixture_'+type(error).__name__)
    finally:
        for kind,handler in handlers.items():signal.signal(kind,handler)
    after=source_identity(ROOT,binary);runner_ok=runner_hash==file_hash(Path(__file__));cli_ok=cli_hash==file_hash(bao)
    recovery_ok=file_hash(recovery_binary)==args.expected_recovery_binary_sha256
    if before!=after or not runner_ok or not cli_ok or not recovery_ok:failure='source_binary_or_fixture_changed'
    if before['source_dirty'] or after['source_dirty']:failure='source_dirty'
    if not complete(checks):failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.native-snapshot-ha-restore-gated.v1','status':'failed' if failure else 'passed',
      'failure':failure,'checks':checks,'observations':observations,'source_identity':before,'source_identity_after':after,
      'source_and_binary_unchanged':before==after,'build_source_commit':args.build_source_commit,
      'feature_binary_sha256':args.expected_binary_sha256,'enabled_feature':FEATURE,'instrumented_binary':True,
      'uninstrumented_release_recovery_tested':failure is None,'ready_evidence_source':'feature_instrumentation',
      'recovery_binary_sha256':args.expected_recovery_binary_sha256,'recovery_binary_unchanged':recovery_ok,
      'recovery_build_source_commit':args.recovery_build_source_commit,'recovery_build_profile':'caller_supplied_default_off',
      'same_source_build_identity_supplied':True,
      'runner_sha256':runner_hash,'runner_unchanged':runner_ok,'official_cli_sha256':cli_hash,'official_cli_unchanged':cli_ok,
      'official_cli_artifact_sha256':pinned_artifact()['artifact_sha256'],'official_cli_version':'2.6.2',
      'retained_failure_work_dir':str(work) if failure else None,'node_count_per_phase':3,'listener_timeout_seconds':5,
      'mutation_retry':False,'post_stage_pre_publish_kill_covered':failure is None,
      'commit_before_local_persist_kill_covered':failure is None,'raw_epoch_value_observed':False,
      'multi_host_covered':False,'physical_power_loss_covered':False,'cross_seal_force':False,
      'external_provider_rollback':False,'openbao_state_interoperability':False,
      'full_openbao_compatibility':False,'production_authority':False,'independent_qualification':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if not failure:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'checks':len(checks),'failure':failure}))
    return int(failure is not None)


if __name__=='__main__':raise SystemExit(main())
