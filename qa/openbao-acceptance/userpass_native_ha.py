#!/usr/bin/env python3
"""Userpass issuing-account provenance across real three-node HA transitions.

This exercises local user renewal, follower forwarding, leader replacement and
quorum loss. There is no external authentication provider and no timing-based
claim about a particular internal commit point.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import time

from bao_http import Response, SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from ha_destructive import FixtureError
from ha_network_partition import PartitionCluster
from online_evidence import admit_output, source_identity
from userpass_native_live import Trace, ROUTES, no_extension

MOUNT = 'ha-userpass'
REQUIRED = frozenset({'follower_login', 'follower_account_update', 'all_renew_routes',
    'all_voter_expiry_after_update', 'new_leader_after_kill', 'renew_after_failover',
    'all_voters_rejoined', 'changed_policy_rejects_all', 'changed_policy_no_extension',
    'deleted_user_route_statuses', 'deleted_user_no_extension', 'recreated_user_renews',
    'full_restart', 'renew_after_full_restart', 'all_voter_expiry_after_restart',
    'quorum_loss_rejects_all', 'quorum_recovery_no_extension', 'renew_after_quorum_recovery',
    'secrets_absent', 'complete'})

REQUIRED_API = frozenset({'userpass_native.ha.login.credentials', 'userpass_native.ha.login.metadata',
    'userpass_native.ha.update.status'}) | frozenset(
    'userpass_native.ha.' + phase + '.' + via + suffix
    for phase in ('updated', 'failover', 'recreated', 'restarted', 'quorum_restored')
    for via in ROUTES for suffix in ('.status', '.lease', '.shape')) | frozenset(
    'userpass_native.ha.' + phase + '.' + via + suffix
    for phase in ('policy_rejected', 'deleted', 'no_quorum')
    for via in ROUTES for suffix in ('.status', '.no_credentials'))


class NodeClient:
    def __init__(self,node,root_token):
        self.node,self.root_token=node,root_token
    def request(self,method,path,body=None,*,token=None,wrap_ttl=None):
        if not path.startswith('/v1/'):
            raise FixtureError('invalid_userpass_fixture_path')
        status,response=self.node.call(method,path[4:],body,
            token=self.root_token if token is None else token,wrap_ttl=wrap_ttl,timeout=15)
        return Response(status,response)


def expiry_projection(data):
    """TTL counts down; the absolute expiry and immutable token facts must agree."""
    fields=('creation_time','expire_time','explicit_max_ttl','period','meta','policies')
    if (not isinstance(data,dict) or not isinstance(data.get('expire_time'),str) or not data['expire_time']
        or type(data.get('ttl')) is not int or data['ttl']<=0 or data.get('meta')!={'username':'alice'}):
        return None
    return {key:data.get(key) for key in fields}


def complete(checks,api_checks):
    if not isinstance(checks,list) or not checks or not isinstance(api_checks,list) or not api_checks:
        return False
    names=[]
    for row in checks:
        if (not isinstance(row,dict) or set(row)!={'case','passed'} or row['passed'] is not True
            or not isinstance(row['case'],str) or re.fullmatch(r'[a-z0-9_]{1,120}',row['case']) is None):return False
        names.append(row['case'])
    api_names=[]
    for row in api_checks:
        if (not isinstance(row,dict) or row.get('passed') is not True or not isinstance(row.get('case'),str)
            or re.fullmatch(r'userpass_native\.[a-z0-9_.]{1,140}',row['case']) is None
            or any(type(value) not in (int,bool) for key,value in row.items() if key not in ('case','passed'))):return False
        api_names.append(row['case'])
    return (len(names)==len(set(names)) and names[-1]=='complete' and REQUIRED.issubset(names)
            and len(api_names)==len(set(api_names)) and REQUIRED_API.issubset(api_names))


def run(binary,root,checks,api_checks,diagnostics,inherited):
    cluster=None
    def check(name,condition):
        checks.append({'case':name,'passed':condition is True})
        if condition is not True:raise FixtureError(name)
    try:
        cluster=PartitionCluster(binary,root/'cluster')
        cluster.bootstrap();inherited.extend(cluster.scenarios)
        leader=cluster.leader();follower=next(node for node in cluster.nodes if node is not leader)
        client=NodeClient(follower,cluster.root_token)
        trace=Trace(client,api_checks,diagnostics)
        password,changed=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
        trace.sensitive.extend([password,changed])
        trace.call('ha.mount','sys/auth/'+MOUNT,{'type':'userpass'},status=204)
        trace.call('ha.user','auth/'+MOUNT+'/users/alice',
            {'password':password,'token_ttl':300,'token_max_ttl':1800,'token_policies':['ha-userpass-old']},status=204)
        auth=trace.auth('ha.login',trace.call('ha.login','auth/'+MOUNT+'/login/alice',{'password':password}),
                        exact=300,username='alice',policies=['default','ha-userpass-old'])
        check('follower_login',client.node is not leader)
        trace.call('ha.update','auth/'+MOUNT+'/users/alice',{'password':changed,'token_ttl':600},status=204)
        check('follower_account_update',True)
        def renew(label,statuses=None):
            for via in ROUTES:
                trace.renew('ha.'+label,auth,via=via,increment=1200 if statuses else None,
                            exact=None if statuses else 600,status=200 if statuses is None else statuses[via])
        def lookup(node):
            status,body=node.call('POST','auth/token/lookup',{'token':auth['client_token']},token=cluster.root_token,timeout=15)
            data=body.get('data') or {}
            if status!=200 or expiry_projection(data) is None:
                raise FixtureError('userpass_ha_lookup_unavailable')
            return data
        def voters_agree():
            projections=[expiry_projection(lookup(node)) for node in cluster.running()]
            return bool(projections) and all(value==projections[0] for value in projections)
        renew('updated');check('all_renew_routes',True)
        check('all_voter_expiry_after_update',voters_agree())
        old_leader=leader;old_leader.stop();leader=cluster.leader()
        check('new_leader_after_kill',leader is not old_leader)
        client.node=next(node for node in cluster.running() if node is not leader)
        renew('failover');check('renew_after_failover',voters_agree())
        cluster.restart(old_leader);leader=cluster.leader()
        check('all_voters_rejoined',len(cluster.running())==3 and voters_agree())
        client.node=next(node for node in cluster.running() if node is not leader)
        trace.call('ha.changed_policy','auth/'+MOUNT+'/users/alice',{'token_policies':['ha-userpass-new']},status=204)
        before=lookup(leader);renew('policy_rejected',dict.fromkeys(ROUTES,500))
        check('changed_policy_rejects_all',True)
        after=lookup(leader)
        check('changed_policy_no_extension',no_extension(before,after) and voters_agree())
        trace.call('ha.delete','auth/'+MOUNT+'/users/alice',method='DELETE',status=204)
        before=lookup(leader);renew('deleted',{'self':204,'token':204,'accessor':500})
        check('deleted_user_route_statuses',True)
        check('deleted_user_no_extension',no_extension(before,lookup(leader)) and voters_agree())
        trace.call('ha.recreate','auth/'+MOUNT+'/users/alice',
            {'password':changed,'token_ttl':600,'token_max_ttl':1800,'token_policies':['ha-userpass-old']},status=204)
        renew('recreated');check('recreated_user_renews',voters_agree())
        for node in cluster.nodes:node.stop()
        for node in cluster.nodes:node.start(wait=False)
        for node in cluster.nodes:node.wait_ready()
        cluster.wait_quorum()
        for node in cluster.nodes:
            if node.call('POST','sys/unseal',{'key':cluster.unseal_key})[0]!=200:
                raise FixtureError('userpass_ha_restart_unseal_failed')
        leader=cluster.leader();client.node=next(node for node in cluster.nodes if node is not leader)
        check('full_restart',True)
        renew('restarted');check('renew_after_full_restart',True)
        check('all_voter_expiry_after_restart',voters_agree())
        before=lookup(leader)
        client.node=leader
        for link in cluster.links.values():link.set_blocked(True)
        time.sleep(3)
        renew('no_quorum',dict.fromkeys(ROUTES,503))
        check('quorum_loss_rejects_all',True)
        cluster._heal();leader=cluster.leader();client.node=leader
        check('quorum_recovery_no_extension',no_extension(before,lookup(leader)) and voters_agree())
        renew('quorum_restored');check('renew_after_quorum_recovery',voters_agree())
        samples=[cluster.root_token.encode(),cluster.unseal_key.encode(),cluster.replication_key,
                 *[secret.encode() for secret in trace.sensitive]]
        for node in cluster.nodes:node.stop()
        safe=True
        for node in cluster.nodes:
            files=[path for folder in (node.data_dir,node.root/'raft') for path in folder.rglob('*') if path.is_file()]
            files += [node.root/'process.log',node.root/'audit.jsonl']
            for path in files:
                if path.exists():
                    content=path.read_bytes();safe &= not any(sample in content for sample in samples)
        encoded=json.dumps({'checks':checks,'api_checks':api_checks,'lease_diagnostics':diagnostics}).encode()
        check('secrets_absent',safe and not any(sample in encoded for sample in samples))
        check('complete',True)
    finally:
        if cluster is not None:cluster.close()


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--build-source-commit',required=True)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit) is None:parser.error('full build source commit required')
    binary,output=args.binary.resolve(strict=True),args.output.absolute()
    admitted=admit_output(output);before=source_identity(ROOT,binary);runner_hash=file_hash(Path(__file__))
    root=Path(tempfile.mkdtemp(prefix='heptabao-userpass-native-ha-'));root.chmod(0o700)
    checks,api_checks,diagnostics,inherited,failure=[],[],[],[],None
    try:run(binary,root,checks,api_checks,diagnostics,inherited)
    except Exception as error:
        failure=next((row['case'] for row in reversed(checks+api_checks) if row['passed'] is not True),'fixture_'+type(error).__name__)
    finally:shutil.rmtree(root)
    unchanged=before==source_identity(ROOT,binary);runner_unchanged=runner_hash==file_hash(Path(__file__))
    if not unchanged or not runner_unchanged:failure='source_binary_or_runner_changed'
    if not complete(checks,api_checks):failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.userpass-native-ha.v1','status':'passed' if failure is None else 'failed','failure':failure,
        'source_identity':before,'source_and_binary_unchanged':unchanged,'build_source_commit':args.build_source_commit,
        'runner_sha256':runner_hash,'runner_unchanged':runner_unchanged,'checks':checks,'api_checks':api_checks,
        'lease_diagnostics':diagnostics,'inherited_bootstrap_scenarios':inherited,
        'all_voter_expiry_basis':'HTTPS lookup through each voter plus leader transitions; not a raw local-state dump',
        'provider_io_covered':False,'exact_mid_commit_fault_injected':False,
        'synthetic_only':True,'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    print(json.dumps({'status':report['status'],'checks':len(checks),'api_checks':len(api_checks),'failure':failure}))
    return 0 if failure is None else 1


if __name__=='__main__':raise SystemExit(main())
