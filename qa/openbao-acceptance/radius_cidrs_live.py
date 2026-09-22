#!/usr/bin/env python3
"""Actual socket-origin CIDR checks with HTTPS, signed RADIUS PAP, and restart.

IPv4 source addresses and IPv6 loopback are real sockets; no proxy headers set
origin authority. This selected profile does not claim all SockAddr API parity.
"""
from __future__ import annotations
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import tempfile
import time
from urllib.parse import urlsplit
from bao_http import Client, Response, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import start_oracle, stop_oracle, restart_oracle, BINARY_SHA256
from online_evidence import admit_output, source_identity
from radius_native_live import NativeRadius, SECRET, PASSWORD
from radius_renewal_live import renewal_token_shape, wrapped_renewal_shape
from remote_jwks_live import Instance


class SourceClient:
    """Verified TLS with a chosen real local IP, never an asserted HTTP origin."""
    def __init__(self,address,ca,root_token,*,spoof_source='127.0.0.1'):
        self.spoof_source=str(ipaddress.ip_address(spoof_source))
        self.port=urlsplit(address).port;self.context=ssl.create_default_context(cafile=str(ca));self.root_token=root_token
        self.context.minimum_version=ssl.TLSVersion.TLSv1_2
        self.last_family=None
    def request(self,method,path,body=None,*,token=None,source='127.0.0.1',wrap_ttl=None,spoof=False):
        family=ipaddress.ip_address(source).version;destination='::1' if family==6 else '127.0.0.1'
        connection=http.client.HTTPSConnection('localhost',self.port,context=self.context,timeout=5)
        try:
            raw=socket.create_connection((destination,self.port),timeout=5,source_address=(source,0))
            try:connection.sock=self.context.wrap_socket(raw,server_hostname='localhost')
            except BaseException:raw.close();raise
            actual=ipaddress.ip_address(connection.sock.getsockname()[0]);self.last_family=actual.version
            if actual!=ipaddress.ip_address(source):raise ScenarioFailure('radius_cidrs.socket_origin')
            headers={'X-Vault-Token':self.root_token if token is None else token,'Content-Type':'application/json'}
            if wrap_ttl:headers['X-Vault-Wrap-TTL']=wrap_ttl
            if spoof:headers.update({'X-Forwarded-For':self.spoof_source,'X-Real-IP':self.spoof_source,'Forwarded':'for='+self.spoof_source})
            connection.request(method,'/v1/'+path,body=None if body is None else json.dumps(body).encode(),headers=headers)
            response=connection.getresponse();raw=response.read(1024*1024+1)
            if len(raw)>1024*1024:raise ScenarioFailure('radius_cidrs.response_bound')
            return Response(response.status,json.loads(raw) if raw else {})
        finally:connection.close()


class Trace:
    def __init__(self,client,provider,rows):self.client,self.provider,self.rows=client,provider,rows;self.tokens=[]
    def check(self,name,passed,**safe):
        if not re.fullmatch(r'[a-z0-9_.]{1,140}',name) or any(type(v) not in (bool,int) for v in safe.values()):raise ValueError('unsafe_trace')
        self.rows.append({'case':'radius_cidrs.'+name,**safe,'passed':bool(passed)})
        if not passed:raise ScenarioFailure('radius_cidrs.'+name)
    def call(self,name,method,path,body=None,*,status=200,pap=0,token=None,source='127.0.0.1',wrap_ttl=None,spoof=False):
        before=self.provider.count();response=self.client.request(method,path,body,token=token,source=source,wrap_ttl=wrap_ttl,spoof=spoof)
        count=self.provider.count()-before
        self.check(name,response.status==status and count==pap and (pap==0 or self.provider.observed(before,accepted=True)),status=response.status,pap_count=count,source_family=self.client.last_family)
        return response.body
    def config(self,name,body):return self.call(name,'POST','auth/radius/config',body,status=204)
    def login(self,name,*,source='127.0.0.1',status=200,pap=1):
        body=self.call(name,'POST','auth/radius/login',{'username':'alice','password':PASSWORD.decode()},token='',source=source,status=status,pap=pap)
        auth=body.get('auth',{})
        if status==200:
            self.check(name+'.issued',bool(auth.get('client_token')) and bool(auth.get('accessor')) and auth.get('renewable') is True)
            self.tokens.append(auth['client_token'])
        else:self.check(name+'.no_auth',not auth and not body.get('wrap_info'))
        return auth
    def bounds(self,name,auth,expected,*,source='127.0.0.1'):
        data=self.call(name,'POST','auth/token/lookup',{'token':auth['client_token']},source=source).get('data',{})
        self.check(name+'.snapshot',data.get('bound_cidrs',[])==expected)
    def renew_all(self,name,auth,*,self_source='127.0.0.1',admin_source='127.0.0.2'):
        for via,path,body,actor,source in [('self','renew-self',{},auth['client_token'],self_source),('token','renew',{'token':auth['client_token']},None,admin_source),('accessor','renew-accessor',{'accessor':auth['accessor']},None,admin_source)]:
            result=self.call(name+'.'+via,'POST','auth/token/'+path,dict(body,increment=120),token=actor,source=source,pap=1)
            self.check(name+'.'+via+'.shape',renewal_token_shape(result.get('auth'),auth['client_token'],via_accessor=via=='accessor'))


def run_scenarios(trace,restart):
    t=trace;c=t.call
    c('mount','POST','sys/auth/radius',{'type':'radius'},status=204)
    c('kv_mount','POST','sys/mounts/cidr-kv',{'type':'kv','options':{'version':'1'}},status=204)
    rules='path "cidr-kv/*" { capabilities = ["create", "read", "update"] } path "auth/token/create" { capabilities = ["update", "sudo"] } path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }'
    c('policy','PUT','sys/policies/acl/cidr-user',{'policy':rules},status=204)
    c('seed','POST','cidr-kv/item',{'value':'synthetic'},status=204)
    t.config('config',{'host':'127.0.0.1','port':t.provider.port,'secret':SECRET.decode(),'token_ttl':120,'token_max_ttl':600,'token_policies':['cidr-user'],'token_bound_cidrs':['127.0.0.1/32']})
    original=t.login('allowed.login');t.bounds('allowed.lookup',original,['127.0.0.1'],source='127.0.0.2')
    t.login('denied.login',source='127.0.0.2',status=403,pap=0)
    for name,method,path,body in [('lookup','GET','auth/token/lookup-self',None),('read','GET','cidr-kv/item',None),('write','POST','cidr-kv/item',{'value':'denied'}),('renew','POST','auth/token/renew-self',{'increment':300})]:
        result=c('denied.'+name,method,path,body,token=original['client_token'],source='127.0.0.2',status=403,spoof=True)
        t.check('denied.'+name+'.no_auth',not result.get('auth') and not result.get('wrap_info'))
    c('allowed.read','GET','cidr-kv/item',token=original['client_token'])
    c('allowed.write','POST','cidr-kv/item',{'value':'allowed'},token=original['client_token'],status=204)
    t.renew_all('actor_scope',original)
    for name,path,inherits in [('child','create',True),('orphan','create-orphan',False)]:
        auth=c(name+'.create','POST','auth/token/'+path,{'policies':['default'],'ttl':120},token=original['client_token']).get('auth',{});t.tokens.append(auth['client_token'])
        t.bounds(name+'.lookup',auth,['127.0.0.1'] if inherits else [])
        c(name+'.other_source','GET','auth/token/lookup-self',token=auth['client_token'],source='127.0.0.2',status=403 if inherits else 200)
        c(name+'.own_source','GET','auth/token/lookup-self',token=auth['client_token'])
    t.config('changed.config',{'token_bound_cidrs':['192.0.2.0/24']})
    t.login('changed.new_login',status=403,pap=0)
    t.renew_all('changed.old_renew',original);t.bounds('changed.old_lookup',original,['127.0.0.1'])
    wrapped=c('wrapped.accepted','POST','auth/token/renew-self',{'increment':120},token=original['client_token'],pap=1,wrap_ttl='60s')
    t.check('wrapped.outer',wrapped_renewal_shape(wrapped,original['client_token']));wrapper=wrapped['wrap_info']['token'];t.tokens.append(wrapper)
    inner=c('wrapped.unwrap','POST','sys/wrapping/unwrap',token=wrapper)
    t.check('wrapped.inner',renewal_token_shape(inner.get('auth'),original['client_token'],via_accessor=False))
    denied=c('wrapped.denied','POST','auth/token/renew-self',{'increment':300},token=original['client_token'],source='127.0.0.2',status=403,wrap_ttl='60s')
    t.check('wrapped.no_publication',not denied.get('auth') and not denied.get('wrap_info'))
    t.config('finite.config',{'token_bound_cidrs':['127.0.0.1'],'token_num_uses':2})
    finite=t.login('finite.login')
    c('finite.denied_no_use','GET','cidr-kv/item',token=finite['client_token'],source='127.0.0.2',status=403)
    c('finite.first','GET','cidr-kv/item',token=finite['client_token'])
    c('finite.second','GET','cidr-kv/item',token=finite['client_token'])
    c('finite.exhausted','GET','cidr-kv/item',token=finite['client_token'],status=403)
    t.config('finite.restore',{'token_num_uses':0})
    for name,value,normalized,status in [('host_bits','127.0.0.2/24','127.0.0.2/24',200),('mapped','::ffff:127.0.0.1/128','127.0.0.1',200),('mapped_prefix','::ffff:127.0.0.2/120','127.0.0.2/24',200),('port','127.0.0.1:999','127.0.0.1:999',200),('v6_excludes_v4','::/0','::/0',403)]:
        t.config('parse.'+name,{'token_bound_cidrs':[value]})
        data=c('parse.'+name+'.read','GET','auth/radius/config').get('data',{})
        t.check('parse.'+name+'.canonical',data.get('token_bound_cidrs')==[normalized])
        t.login('parse.'+name+'.login',status=status,pap=int(status==200))
    t.config('v6.config',{'token_bound_cidrs':['::1/128']})
    v6=t.login('v6.login',source='::1');t.bounds('v6.lookup',v6,['::1'])
    c('v6.reject_v4','GET','auth/token/lookup-self',token=v6['client_token'],status=403)
    t.renew_all('v6.renew',v6,self_source='::1')
    t.config('clear.null',{'token_bound_cidrs':None})
    unbound=t.login('clear.login',source='127.0.0.2');t.bounds('clear.lookup',unbound,[])
    c('clear.cross_family','GET','auth/token/lookup-self',token=unbound['client_token'],source='::1')
    t.bounds('clear.old_snapshot',original,['127.0.0.1'])
    restart();t.check('restart.same_store',True)
    t.bounds('restart.old_snapshot',original,['127.0.0.1']);t.bounds('restart.v6_snapshot',v6,['::1'])
    c('restart.reject','GET','auth/token/lookup-self',token=original['client_token'],source='127.0.0.2',status=403)
    t.renew_all('restart.old_renew',original);t.renew_all('restart.v6_renew',v6,self_source='::1')
    t.check('receipt.no_sensitive_values',not any(secret in json.dumps(t.rows) for secret in [SECRET.decode(),PASSWORD.decode(),*t.tokens]))
    t.check('complete',True)

MILESTONES={'denied.login','denied.read','denied.write','denied.renew','actor_scope.accessor.shape','child.other_source','orphan.other_source','changed.old_renew.self.shape','wrapped.no_publication','finite.second','finite.exhausted','parse.mapped_prefix.canonical','v6.renew.self.shape','clear.cross_family','restart.old_renew.self.shape','restart.v6_renew.self.shape','receipt.no_sensitive_values','complete'}
def complete_scenarios(rows):
    if not rows or any(row.get('passed') is not True for row in rows):return False
    names=[row.get('case') for row in rows]
    return all(isinstance(n,str) for n in names) and len(names)==len(set(names)) and {'radius_cidrs.'+n for n in MILESTONES}.issubset(names) and names[-1]=='radius_cidrs.complete'


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary');parser.add_argument('--build-source-commit');parser.add_argument('--oracle-only',action='store_true');parser.add_argument('--output',required=True)
    args=parser.parse_args()
    if not args.oracle_only and (not args.binary or not args.build_source_commit or re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit) is None):parser.error('candidate binary and full build source commit required')
    binary=Path(args.binary or os.environ['HB_ORACLE_BINARY']).resolve(strict=True)
    output=Path(args.output).absolute();admitted=admit_output(output);before=source_identity(ROOT,binary)
    runner=Path(__file__);runner_hash=file_hash(runner)
    root=Path(tempfile.mkdtemp(prefix='heptabao-radius-cidrs-'));root.chmod(0o700)
    oracle=instance=None;providers=[]
    report={'schema':'heptabao.radius-cidrs-comparison.v1','target_version':'2.6.2','synthetic_only':True,'actual_https_udp':True,
            'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False,
            'scope': 'numeric CIDRs, real dual-stack socket peers, service tokens; excludes Unix/DNS SockAddr, strictly_bind_ip and batch','oracle_binary_sha256':BINARY_SHA256,'candidate_binary_sha256':None if args.oracle_only else file_hash(binary),
            'build_source_commit':None if args.oracle_only else args.build_source_commit,
            'build_source_binding_basis':'caller-supplied commit and observed binary hash; not independent attestation',
            'harness_source_commit':before['source_commit'],'harness_source_dirty':before['source_dirty'],
            'source_identity':before,'runner_sha256':runner_hash,'started_at_unix':time.time(),'cases':{},'side_failures':{},'transport_observations':{}}
    try:
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        oracle=start_oracle(port)
        oracle['process'].kill();oracle['process'].wait(timeout=5);stop_oracle(oracle)
        oracle_config=Path(oracle['root'])/'server.json';cfg=json.loads(oracle_config.read_text())
        cfg['listener'][0]['tcp']['address']=f'[::]:{port}'
        private_write(oracle_config,cfg,replace=True);restart_oracle(oracle)
        reference=SourceClient(oracle['address'],oracle['ca_file'],private_read(oracle['token_file']).decode().strip())
        def restart_reference():
            oracle['process'].kill();oracle['process'].wait(timeout=5);stop_oracle(oracle);restart_oracle(oracle)
        sides=[]
        if not args.oracle_only:
            instance=Instance(binary,root/'candidate');provider=NativeRadius(require_ma=True);providers.append(provider)
            cfg=json.loads((instance.root/'server.json').read_text());cfg['lifecycle_interval_seconds']=0
            cfg['outbound_endpoints']=[];cfg['listen']=f'[::]:{instance.port}'
            private_write(instance.root/'server.json',cfg,replace=True)
            instance.start();status,initialized=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
            if status!=200:raise ScenarioFailure('radius_cidrs.candidate_init')
            instance.token,key=initialized['root_token'],initialized['keys_base64'][0]
            if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ScenarioFailure('radius_cidrs.candidate_unseal')
            candidate=SourceClient(instance.address,str(instance.root/'ca.crt'),instance.token)
            def restart_candidate():
                instance.stop();instance.start()
                if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ScenarioFailure('radius_cidrs.candidate_reopen')
            sides.append(('candidate',candidate,provider,restart_candidate))
        provider=NativeRadius(require_ma=False);providers.append(provider);sides.append(('oracle',reference,provider,restart_reference))
        for side,client,provider,restart in sides:
            rows=report['cases'][side]=[]
            trace=Trace(client,provider,rows)
            try:run_scenarios(trace,restart)
            except ScenarioFailure as e:report['side_failures'][side]=str(e)
            except Exception as e:report['side_failures'][side]='unexpected_'+type(e).__name__
        expected_sides={'oracle'} if args.oracle_only else {'candidate','oracle'}
        complete=set(report['cases'])==expected_sides and all(complete_scenarios(rows) for rows in report['cases'].values())
        report['cases_match']=args.oracle_only or report['cases'].get('candidate')==report['cases'].get('oracle')
        report['status']=('oracle_passed' if args.oracle_only else 'passed') if complete and report['cases_match'] and not report['side_failures'] else 'failed'
    except Exception as e:report['status']='failed';report['safe_failure_code']=type(e).__name__
    finally:
        if instance is not None:instance.stop()
        for provider in providers:provider.close()
        if oracle is not None:stop_oracle(oracle);shutil.rmtree(oracle['root'])
        shutil.rmtree(root)
        report['source_and_binary_unchanged']=before==source_identity(ROOT,binary)
        report['runner_unchanged']=file_hash(runner)==runner_hash
        if not report['source_and_binary_unchanged'] or not report['runner_unchanged']:report['status']='failed';report['safe_failure_code']='source_or_binary_changed'
        report['finished_at_unix']=time.time()
        if admit_output(output)!=admitted:raise ValueError('report_directory_changed')
        private_write(output,report)
    print(json.dumps({'status':report['status'],'counts':{k:len(v) for k,v in report['cases'].items()},'side_failures':report['side_failures'],'safe_failure_code':report.get('safe_failure_code')}))
    return 0 if report['status'] in ('passed','oracle_passed') else 1

if __name__=='__main__':raise SystemExit(main())
