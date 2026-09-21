#!/usr/bin/env python3
"""Small same-cluster/seal HA native-v2 restore with the pinned OpenBao CLI.

Three local TLS voters, unchanged five-second listeners, one attempt per mutation.
A quiescent real schema38 downgrade is tested before subsequent HA fault phases;
this is not a mixed-version rolling upgrade or OpenBao state.bin interoperability.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import tempfile
import time

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from ha_destructive import FixtureError, checked_binary
from native_snapshot_cli_live import cli, contains_any, private_parent
from native_snapshot_ha_live import SaveCluster, client_view, strict_archive, capacity_data
from official_openbao_launcher import pinned_artifact, verify_inputs
from online_evidence import admit_output, complete_checks, source_identity
from provider_renewal_upgrade import durable_manifest
from radius_renewal_ha import GatedRadius, profile_configuration
from radius_renewal_live import SECRET, USERNAME, PASSWORD

LEGACY_BUILD = 'fa61fa7eadd2c76a8fbcca7e9356ec678004c0aa'
LEGACY_HARNESS = '33593f6404b8755496d2cacb64322da3658aa8d6'
LEGACY_SHA = 'b289dd0b88652e174c8ea917b6d23605e7f770b43dfca93e8e708ef706bb14ef'
LEGACY_RECEIPT_SHA = '066363171a270dded80381a31212157b260bbd8deaff0c9e55cf21ab2b6599f9'
MOUNT = 'native-ha-restore'
REQUIRED = frozenset({'three_processes', 'listener_deadlines', 'payload_ready', 'archive_saved',
    'archive_complete', 'changed', 'initial_restore', 'new_publication', 'raft_frontier_advanced', 'all_restored',
    'legacy_all_nodes_stopped', 'legacy_unseal_refused', 'legacy_sealed',
    'legacy_application_unchanged', 'legacy_raft_unchanged', 'candidate_recovered',
    'cli_restore', 'cli_new_generation', 'all_cli_restored', 'expired_actor_denied',
    'expired_actor_unchanged', 'expired_upload_denied', 'expired_upload_unchanged',
    'provider_inflight', 'restore_while_provider_pending', 'epoch_advanced',
    'provider_valid_reply_before_timeout', 'late_auth_denied', 'late_auth_no_publication',
    'fresh_auth_succeeds', 'all_epoch_restored', 'restart_all_hashes', 'step_down',
    'successor_changed', 'successor_all_hashes', 'successor_save', 'successor_archive_complete',
    'admin_policy_changed', 'admin_restore_denied', 'admin_rejection_unchanged',
    'external_mount', 'external_restore_denied', 'external_rejection_unchanged',
    'final_all_hashes', 'processes_stopped', 'plaintext_absent', 'complete'})


def complete(rows):
    return complete_checks(rows, required_cases=REQUIRED) and rows[-1]['case'] == 'complete'


def admit_legacy(receipt, digest):
    source = receipt.get('source_identity', {})
    if (digest != LEGACY_RECEIPT_SHA or receipt.get('status') != 'passed'
            or receipt.get('schema') != 'heptabao.native-snapshot-cli.v1'
            or receipt.get('build_source_commit') != LEGACY_BUILD
            or receipt.get('source_and_binary_unchanged') is not True
            or receipt.get('runner_unchanged') is not True
            or receipt.get('postgres_restore_profile_covered') is not True
            or source.get('source_commit') != LEGACY_HARNESS
            or source.get('binary_sha256') != LEGACY_SHA or source.get('source_dirty') is not False
            or receipt.get('source_identity_after') != source):
        raise ValueError('legacy38_qualified_receipt_mismatch')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def publication(response, previous, imported, *, previous_epoch=None):
    status, body = response
    data = body.get('data', {})
    if status != 200 or body.get('auth') or body.get('wrap_info') or not isinstance(data, dict):
        return None
    fields = ('imported_generation', 'previous_local_generation', 'published_local_generation', 'replay_epoch')
    if (any(type(data.get(k)) is not int or data[k] < 0 for k in fields)
            or data.get('cluster_coordinated') is not True
            or data['imported_generation'] != imported or data['previous_local_generation'] != previous
            or data['published_local_generation'] <= previous or data['replay_epoch'] < 1
            or (previous_epoch is not None and data['replay_epoch'] != previous_epoch + 1)):
        return None
    return {k: data[k] for k in fields}


def radius_credentials():
    return {'username':USERNAME.decode('ascii'),'password':PASSWORD.decode('ascii')}


def late_denied(response):
    status, body = response
    return (status == 503 and body.get('errors') == ['online authentication authority changed']
            and not any(body.get(k) for k in ('auth', 'wrap_info', 'data')))


def restore_http(node, token, archive, *, expire=False):
    """Real binary upload; no redirect/retry. Delay only the expired-body case."""
    size = archive.stat().st_size
    if not 0 < size <= 2 * 1024 * 1024:
        raise FixtureError('small_archive_budget_exceeded')
    fields = (f'POST /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: localhost\r\n'
              f'X-Vault-Token: {token}\r\nContent-Type: application/gzip\r\n'
              f'Content-Length: {size}\r\nConnection: close\r\n\r\n').encode()
    try:
        with socket.create_connection(('127.0.0.1', node.http_port), timeout=7) as raw:
            with node.context.wrap_socket(raw, server_hostname='localhost') as tls:
                tls.sendall(fields)
                if expire:
                    # Exceed the unchanged listener budget, not a new per-body budget.
                    with archive.open('rb') as stream:
                        tls.sendall(stream.read(1)); time.sleep(5.25)
                        tls.sendall(stream.read())
                else:
                    with archive.open('rb') as stream: tls.sendall(stream.read())
                response = http.client.HTTPResponse(tls); response.begin()
                payload = response.read(65537)
                if len(payload) > 65536: raise FixtureError('restore_response_unbounded')
                return response.status, json.loads(payload)
    except (OSError, http.client.HTTPException):
        if expire: return None, {}
        raise


def expired_denied(response):
    status, body = response
    return ((status is None and body == {}) or
            (status in (400, 408, 503) and isinstance(body.get('errors'), list) and bool(body['errors'])
             and not any(body.get(k) for k in ('auth', 'data', 'wrap_info'))))


def downgrade(cluster, legacy, candidate, check, *, target):
    # No old reader ever joins the new Raft group. Stop *all* nodes first.
    for node in cluster.nodes: node.stop()
    check('legacy_all_nodes_stopped', all(node.process is None for node in cluster.nodes))
    node = target
    if node not in cluster.nodes: raise FixtureError('downgrade_target_outside_cluster')
    application = durable_manifest(node.data_dir, application_only=True)
    raft = durable_manifest(node.root / 'raft')
    node.binary = legacy
    try:
        node.start(ha=False)
        status, body = node.call('POST', 'sys/unseal', {'key': cluster.unseal_key})
        check('legacy_unseal_refused', status == 503 and bool(body.get('errors')))
        status, body = node.call('GET', 'sys/health')
        check('legacy_sealed', status == 503 and body.get('sealed') is True)
    finally:
        node.stop(); node.binary = candidate
    # ledger.hbl can be re-sealed by old durable reopen before application schema validation.
    check('legacy_application_unchanged', durable_manifest(node.data_dir, application_only=True) == application)
    check('legacy_raft_unchanged', durable_manifest(node.root / 'raft') == raft)
    restart(cluster)
    check('candidate_recovered', True)


def applied_index(node, token):
    status, body = node.call('GET','sys/storage/raft/snapshot-status',token=token)
    index = body.get('data',{}).get('applied_index')
    if status != 200 or type(index) is not int or index < 0:
        raise FixtureError('raft_applied_frontier_unavailable')
    return index


def restart(cluster):
    for node in cluster.nodes: node.stop()
    for node in cluster.nodes: node.start(wait=False)
    for node in cluster.nodes: node.wait_ready()
    cluster.wait_quorum()
    for node in cluster.nodes:
        if node.call('POST', 'sys/unseal', {'key': cluster.unseal_key})[0] != 200:
            raise FixtureError('candidate_restart_unseal_failed')
    return cluster.leader()


def run(binary, legacy, bao, work, checks, observations):
    def check(case, passed):
        if type(passed) is not bool: raise FixtureError('nonboolean_observation')
        checks.append({'case': case, 'passed': passed})
        if not passed: raise FixtureError(case)
    cluster = None; provider = GatedRadius(native=True); samples = []
    try:
        cluster = SaveCluster(binary, work / 'cluster'); cluster.bootstrap()
        check('three_processes', len({node.process.pid for node in cluster.nodes}) == 3)
        check('listener_deadlines', all(json.loads((n.root/'server.json').read_text())['timeout_seconds'] == 5
                                       for n in cluster.nodes))
        leader = cluster.leader(); token = cluster.root_token
        def call(method, route, payload=None): return leader.call(method, route, payload, token=token)
        check('mounted', call('POST', 'sys/mounts/'+MOUNT, {'type':'kv','options':{'version':'1'}})[0] == 204)
        check('radius_mounted', call('POST','sys/auth/restore-radius',{'type':'radius'})[0] == 204)
        _, config = profile_configuration(provider.port, native=True)
        config['unregistered_user_policies'] = 'default'
        check('radius_configured', call('POST','auth/restore-radius/config',config)[0] == 204)
        original = {f'k{number:02}': {'value': secrets.token_hex(2048), 'ordinal': number} for number in range(8)}
        hashes = {key: hashlib.sha256(canonical(value)).hexdigest() for key,value in original.items()}
        samples += [v['value'][:80].encode() for v in original.values()]
        for key,value in original.items(): check('seed_'+key, call('PUT', MOUNT+'/'+key,value)[0] == 204)
        check('payload_ready', True)
        def verify(phase, *, absent=True):
            for node in cluster.nodes:
                for key,digest in hashes.items():
                    status, body = node.call('GET', MOUNT+'/'+key, token=token)
                    check(phase+'_node_'+str(node.node_id)+'_'+key,
                          status == 200 and hashlib.sha256(canonical(body.get('data'))).hexdigest() == digest)
                if absent: check(phase+'_later_absent_'+str(node.node_id), node.call('GET',MOUNT+'/later',token=token)[0] == 404)
            check(phase, True)
        archive = work/'initial.snap'
        check('archive_saved', cli(bao,client_view(cluster,leader),work,'save',archive) == 0)
        meta = strict_archive(archive); observations['archive'] = meta; check('archive_complete',True)
        imported = meta['generation']
        check('changed',call('PUT',MOUNT+'/k00',{'value':'changed'})[0] == 204)
        check('later_written',call('PUT',MOUNT+'/later',{'value':'must-disappear'})[0] == 204)
        before = capacity_data(leader,token)['generation']
        raft_before = applied_index(leader,token)
        first = publication(restore_http(leader,token,archive),before,imported)
        check('initial_restore', first is not None); observations['initial_publication'] = first
        check('new_publication',capacity_data(leader,token)['generation'] == first['published_local_generation'])
        raft_after = applied_index(leader,token)
        check('raft_frontier_advanced',raft_after > raft_before)
        observations['raft_applied_before_after'] = [raft_before,raft_after]
        verify('all_restored')
        # Actual reader fencing is a prerequisite to the subsequent extended HA scenarios.
        downgrade(cluster,legacy,binary,check,target=leader); leader = cluster.leader()
        check('cli_changed',call('PUT',MOUNT+'/k00',{'value':'changed-again'})[0] == 204)
        before = capacity_data(leader,token)['generation']
        check('cli_restore',cli(bao,client_view(cluster,leader),work,'restore',archive) == 0)
        check('cli_new_generation',capacity_data(leader,token)['generation'] > before)
        verify('all_cli_restored')
        # Another observed restore establishes the exact current epoch after CLI publication.
        before = capacity_data(leader,token)['generation']
        observed = publication(restore_http(leader,token,archive),before,imported,previous_epoch=first['replay_epoch']+1)
        check('cli_epoch_advanced',observed is not None); observations['after_cli_publication'] = observed
        status, body = call('POST','auth/token/create',{'policies':['root'],'ttl':'1s'})
        check('expiring_actor_created',status == 200 and bool(body.get('auth',{}).get('client_token')))
        expiring = body['auth']['client_token']; samples.append(expiring.encode()); time.sleep(2.1)
        before = capacity_data(leader,token)['generation']
        check('expired_actor_denied',cli(bao,client_view(cluster,leader,expiring),work,'restore',archive,expected_error=403))
        check('expired_actor_unchanged',capacity_data(leader,token)['generation'] == before)
        check('expired_upload_denied',expired_denied(restore_http(leader,token,archive,expire=True)))
        check('expired_upload_unchanged',capacity_data(leader,token)['generation'] == before)
        # Genuine signed Accept held under the existing 2.7s/3s provider budgets.
        provider.arm(); count = provider.count()
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(leader.call,'POST','auth/restore-radius/login',
                radius_credentials(),wrap_ttl='60s',timeout=7)
            try:
                check('provider_inflight',provider.received.wait(1) and not provider.failed)
                before = capacity_data(leader,token)['generation']
                latest = publication(restore_http(leader,token,archive),before,imported,previous_epoch=observed['replay_epoch'])
                check('restore_while_provider_pending',latest is not None)
                check('epoch_advanced',latest['replay_epoch'] == observed['replay_epoch']+1)
            finally:
                provider.release.set()
            check('provider_valid_reply_before_timeout',provider.replied.wait(.5) and not provider.failed
                  and provider.gate_elapsed is not None and provider.gate_elapsed < 2.7 and provider.count() == count+1)
            response = pending.result(timeout=7)
        check('late_auth_denied',late_denied(response))
        check('late_auth_no_publication',capacity_data(leader,token)['generation'] == latest['published_local_generation'])
        status, body = leader.call('POST','auth/restore-radius/login',radius_credentials())
        check('fresh_auth_succeeds',status == 200 and bool(body.get('auth',{}).get('client_token')) and provider.count() == count+2)
        samples.append(body['auth']['client_token'].encode()); observations['last_publication'] = latest
        verify('all_epoch_restored')
        leader = restart(cluster); verify('restart_all_hashes')
        former = leader.node_id; check('step_down',call('POST','sys/step-down',{})[0] == 204)
        leader = cluster.leader(); check('successor_changed',leader.node_id != former)
        verify('successor_all_hashes')
        successor = work/'successor.snap'; before = capacity_data(leader,token)['generation']
        check('successor_save',cli(bao,client_view(cluster,leader),work,'save',successor) == 0)
        observations['successor_archive'] = strict_archive(successor)
        check('successor_archive_complete',capacity_data(leader,token)['generation'] == before)
        check('admin_policy_changed',call('POST','sys/storage/raft/autopilot/configuration',{'server_stabilization_time':'3s'})[0] == 204)
        before = capacity_data(leader,token)['generation']
        check('admin_restore_denied',cli(bao,client_view(cluster,leader),work,'restore',successor,expected_error=409,
              expected_message=b'native HA restore cannot change autopilot or promotion state'))
        check('admin_rejection_unchanged',capacity_data(leader,token)['generation'] == before)
        check('external_mount',call('POST','sys/mounts/external-db',{'type':'database'})[0] == 204)
        before = capacity_data(leader,token)['generation']
        check('external_restore_denied',cli(bao,client_view(cluster,leader),work,'restore',successor,expected_error=409,
              expected_message=b'external provider state'))
        check('external_rejection_unchanged',capacity_data(leader,token)['generation'] == before)
        verify('final_all_hashes')
        samples += [token.encode(),cluster.unseal_key.encode(),SECRET,PASSWORD]
        cluster.close(); provider.close()
        check('processes_stopped',all(n.process is None for n in cluster.nodes))
        files = [p for n in cluster.nodes for base in (n.data_dir,n.root/'raft') for p in base.rglob('*') if p.is_file()]
        files += [p for n in cluster.nodes for p in (n.root/'audit.jsonl',n.root/'process.log') if p.exists()]
        files += list(work.glob('*.snap'))
        check('plaintext_absent',bool(files) and all(not contains_any(p,samples) for p in files))
        check('complete',True)
    finally:
        provider.close()
        if cluster is not None: cluster.close()


def main():
    parser = SafeArgumentParser(description=__doc__)
    for name in ('binary','legacy-binary','legacy-receipt','work-parent','output'):
        parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--build-source-commit',required=True)
    args = parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit) is None: parser.error('full_build_commit_required')
    binary, legacy = args.binary.resolve(strict=True), args.legacy_binary.resolve(strict=True)
    checked_binary(legacy,LEGACY_SHA); receipt_hash = file_hash(args.legacy_receipt)
    admit_legacy(json.loads(args.legacy_receipt.read_text()),receipt_hash)
    parent, output = private_parent(args.work_parent), args.output.absolute(); admitted = admit_output(output)
    bao = verify_inputs(); cli_hash = file_hash(bao); before = source_identity(ROOT,binary); runner_hash = file_hash(Path(__file__))
    work = Path(tempfile.mkdtemp(prefix='native-ha-restore-',dir=parent))
    checks, observations, failure = [], {}, None
    def interrupted(signum,frame): raise FixtureError('fixture_interrupted')
    handlers = {kind:signal.signal(kind,interrupted) for kind in (signal.SIGTERM,signal.SIGINT)}
    try: run(binary,legacy,bao,work,checks,observations)
    except Exception as error:
        failure = next((r['case'] for r in reversed(checks) if r['passed'] is not True),'fixture_'+type(error).__name__)
    finally:
        for kind,handler in handlers.items(): signal.signal(kind,handler)
    after = source_identity(ROOT,binary)
    runner_ok = runner_hash == file_hash(Path(__file__)); cli_ok = cli_hash == file_hash(bao)
    legacy_ok = file_hash(legacy) == LEGACY_SHA and file_hash(args.legacy_receipt) == receipt_hash
    if before != after or not (runner_ok and cli_ok and legacy_ok): failure = 'source_binary_or_fixture_changed'
    if before['source_dirty'] or after['source_dirty']: failure = 'source_dirty'
    if not complete(checks): failure = failure or 'incomplete_observations'
    report = {'schema':'heptabao.native-snapshot-ha-restore.v1','status':'failed' if failure else 'passed',
        'failure':failure,'checks':checks,'observations':observations,'source_identity':before,'source_identity_after':after,
        'source_and_binary_unchanged':before==after,'build_source_commit':args.build_source_commit,
        'runner_sha256':runner_hash,'runner_unchanged':runner_ok,'official_cli_sha256':cli_hash,'official_cli_unchanged':cli_ok,
        'official_cli_version':'2.6.2','official_cli_artifact_sha256':pinned_artifact()['artifact_sha256'],
        'legacy_build_source':LEGACY_BUILD,'legacy_harness_source':LEGACY_HARNESS,'legacy_sha256':LEGACY_SHA,
        'legacy_receipt_sha256':receipt_hash,'legacy_unchanged':legacy_ok,'node_count':3,'listener_timeout_seconds':5,
        'retained_failure_work_dir':str(work) if failure else None,'mutation_retry':False,
        'same_cluster_same_seal_restore':failure is None,'real_schema38_refusal':failure is None,
        'late_provider_accept_fenced':failure is None,'mixed_version_ha':False,'physical_hosts':False,
        'external_provider_rollback':False,'cross_seal_force':False,'openbao_state_interoperability':False,
        'independent_qualification':False,'production_authority':False,'full_openbao_compatibility':False}
    if admit_output(output) != admitted: raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if not failure: shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'checks':len(checks),'failure':failure}))
    return int(failure is not None)


if __name__ == '__main__': raise SystemExit(main())
