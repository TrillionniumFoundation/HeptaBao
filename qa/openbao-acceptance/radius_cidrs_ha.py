#!/usr/bin/env python3
"""Trusted socket-origin CIDRs through three-process mTLS HA forwarding."""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import tempfile
from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from online_evidence import admit_output, source_identity
from ha_destructive import Cluster
from radius_cidrs_live import SourceClient, Trace
from radius_native_live import NativeRadius, SECRET, PASSWORD


def run(binary,root,rows,inherited):
    cluster=None;provider=NativeRadius(require_ma=True)
    try:
        cluster=Cluster(binary,root/'cluster')
        for node in cluster.nodes:
            path=node.root/'server.json';settings=json.loads(path.read_text());settings['outbound_endpoints']=[];settings['lifecycle_interval_seconds']=0
            private_write(path,settings,replace=True)
        cluster.bootstrap();inherited.extend(cluster.scenarios)
        leader=cluster.leader();follower=next(node for node in cluster.nodes if node is not leader)
        def trace(node):return Trace(SourceClient(f'https://127.0.0.1:{node.http_port}',cluster.root/'ca.crt',cluster.root_token),provider,rows)
        primary=trace(leader);forward=trace(follower)
        primary.call('ha.mount','POST','sys/auth/radius',{'type':'radius'},status=204)
        primary.call('ha.kv_mount','POST','sys/mounts/cidr-kv',{'type':'kv','options':{'version':'1'}},status=204)
        primary.call('ha.policy','PUT','sys/policies/acl/cidr-user',{'policy':'path "cidr-kv/*" { capabilities = ["read", "update"] }'},status=204)
        primary.call('ha.seed','POST','cidr-kv/item',{'value':'synthetic'},status=204)
        primary.config('ha.config',{'host':'127.0.0.1','port':provider.port,'secret':SECRET.decode(),'token_ttl':120,'token_max_ttl':600,'token_policies':['cidr-user'],'token_bound_cidrs':['127.0.0.2']})
        # Every HA node connects from 127.0.0.1; successful source .2 proves the
        # authenticated frame preserves the listener socket origin.
        token=forward.login('ha.forwarded_login',source='127.0.0.2')
        forward.login('ha.forwarded_wrong_login',status=403,pap=0)
        for phase,t in [('leader',primary),('follower',forward)]:
            t.call('ha.'+phase+'.allowed_read','GET','cidr-kv/item',token=token['client_token'],source='127.0.0.2')
            t.call('ha.'+phase+'.wrong_read','GET','cidr-kv/item',token=token['client_token'],status=403,spoof=True)
            t.call('ha.'+phase+'.wrong_write','POST','cidr-kv/item',{'value':'denied'},token=token['client_token'],status=403)
            t.call('ha.'+phase+'.wrong_renew','POST','auth/token/renew-self',{'increment':300},token=token['client_token'],status=403)
        forward.renew_all('ha.forwarded_renew',token,self_source='127.0.0.2',admin_source='127.0.0.1')
        primary.config('ha.finite_config',{'token_num_uses':2})
        finite=forward.login('ha.finite_login',source='127.0.0.2')
        forward.call('ha.finite_denied','GET','cidr-kv/item',token=finite['client_token'],status=403)
        forward.call('ha.finite_first','GET','cidr-kv/item',token=finite['client_token'],source='127.0.0.2')
        forward.call('ha.finite_second','GET','cidr-kv/item',token=finite['client_token'],source='127.0.0.2')
        forward.call('ha.finite_exhausted','GET','cidr-kv/item',token=finite['client_token'],source='127.0.0.2',status=403)
        primary.config('ha.clear_config',{'token_bound_cidrs':[],'token_num_uses':0})
        leader.stop();replacement=cluster.leader();after=trace(replacement)
        after.check('ha.new_leader',replacement is not leader)
        after.bounds('ha.new_leader_snapshot',token,['127.0.0.2'])
        remaining=next(node for node in cluster.running() if node is not replacement);after_forward=trace(remaining)
        after_forward.call('ha.after_election_denied','GET','cidr-kv/item',token=token['client_token'],status=403)
        after_forward.renew_all('ha.after_election_renew',token,self_source='127.0.0.2',admin_source='127.0.0.1')
        after.check('ha.receipt_no_secrets',not any(value in json.dumps(rows) for value in [SECRET.decode(),PASSWORD.decode(),token['client_token'],finite['client_token']]))
        after.check('ha.complete',True)
    finally:
        if cluster is not None:cluster.close()
        provider.close()

MILESTONES={'ha.forwarded_login','ha.forwarded_wrong_login','ha.follower.wrong_read','ha.forwarded_renew.accessor.shape','ha.finite_second','ha.finite_exhausted','ha.new_leader','ha.after_election_denied','ha.after_election_renew.self.shape','ha.receipt_no_secrets','ha.complete'}
def complete(rows):
    names=[r.get('case') for r in rows]
    return bool(rows) and all(r.get('passed') is True for r in rows) and len(names)==len(set(names)) and {'radius_cidrs.'+n for n in MILESTONES}.issubset(names) and names[-1]=='radius_cidrs.ha.complete'

def main():
    parser=SafeArgumentParser(description=__doc__)
    for name in ('binary','build-source-commit','output'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit):parser.error('full build source commit required')
    binary=Path(args.binary).resolve(strict=True);output=Path(args.output).absolute();parent=admit_output(output)
    before=source_identity(ROOT,binary);runner=file_hash(Path(__file__));root=Path(tempfile.mkdtemp(prefix='heptabao-cidrs-ha-'));root.chmod(0o700)
    report={'schema':'heptabao.radius-cidrs-ha.v1','checks':[],'bootstrap_checks':[],'same_host':True,'synthetic_only':True,'physical_fault_qualification':False,'full_openbao_compatibility':False,'source_identity':before,'build_source_commit':args.build_source_commit,'build_source_binding_basis':'caller-supplied commit and observed binary hash; not independent attestation','runner_sha256':runner}
    try:
        run(binary,root,report['checks'],report['bootstrap_checks'])
        report['status']='passed' if complete(report['checks']) and bool(report['bootstrap_checks']) else 'failed'
    except Exception as error:
        report['status']='failed';report['safe_failure_code']=next((r['case'] for r in reversed(report['checks']) if not r['passed']),'fixture_'+type(error).__name__)
    finally:
        shutil.rmtree(root);report['source_and_binary_unchanged']=before==source_identity(ROOT,binary);report['runner_unchanged']=runner==file_hash(Path(__file__))
        if not report['source_and_binary_unchanged'] or not report['runner_unchanged']:report['status']='failed';report['safe_failure_code']='source_changed'
        if parent!=admit_output(output):raise ValueError('report_parent_changed')
        private_write(output,report)
    print(json.dumps({'status':report['status'],'checks':len(report['checks']),'safe_failure_code':report.get('safe_failure_code')}))
    return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
