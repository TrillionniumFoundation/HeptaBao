#!/usr/bin/env python3
"""Native LDAP CIDRs: actual TLS socket sources, OpenLDAP Bind/Search and restart.

Uses shared numeric CIDR expectations; does not claim Unix/DNS SockAddr,
strict-IP or batch-token support. Credentials never enter the receipt.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import shutil
import socket
import tempfile
import time
from bao_http import SafeArgumentParser,private_read,private_write
from core_isolation import ROOT,ScenarioFailure,file_hash
from online_evidence import admit_output,source_identity
from official_openbao_launcher import start_oracle,stop_oracle,restart_oracle,BINARY_SHA256
from radius_cidrs_live import SourceClient
from radius_renewal_live import renewal_token_shape,wrapped_renewal_shape
from ldap_native_live import NativeDirectory,configuration
from ldap_native_upgrade import provider_idle as no_directory_requests
from remote_jwks_live import Instance

class Trace:
    def __init__(self,client,directory,configuration,rows):self.client,self.directory,self.configuration,self.rows=client,directory,configuration,rows;self.tokens=[]
    def check(self,name,passed,**safe):
        if not re.fullmatch(r'[a-z0-9_.]{1,140}',name) or any(type(v) not in (bool,int) for v in safe.values()):raise ValueError('unsafe_trace')
        self.rows.append({'case':'ldap_cidrs.'+name,**safe,'passed':bool(passed)})
        if not passed:raise ScenarioFailure('ldap_cidrs.'+name)
    def call(self,name,method,path,body=None,*,status=200,provider=False,token=None,source='127.0.0.1',wrap_ttl=None,spoof=False):
        cursor=self.directory.cursor();response=self.client.request(method,path,body,token=token,source=source,wrap_ttl=wrap_ttl,spoof=spoof)
        contacted=self.directory.observed(cursor,search=True) if provider else not no_directory_requests(self.directory,cursor)
        self.check(name,response.status==status and contacted==bool(provider),status=response.status,provider_contacted=contacted,source_family=self.client.last_family)
        return response.body
    def config(self,name,body):return self.call(name,'POST','auth/ldap/config',body,status=204)
    def login(self,name,*,source='127.0.0.1',status=200,provider=True):
        body=self.call(name,'POST','auth/ldap/login/alice',{'password':self.directory.user_password},token='',source=source,status=status,provider=provider)
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
            result=self.call(name+'.'+via,'POST','auth/token/'+path,dict(body,increment=120),token=actor,source=source,provider=True)
            self.check(name+'.'+via+'.shape',renewal_token_shape(result.get('auth'),auth['client_token'],via_accessor=via=='accessor'))


def run_scenarios(trace,restart):
    t=trace;c=t.call
    c('mount','POST','sys/auth/ldap',{'type':'ldap'},status=204)
    c('kv_mount','POST','sys/mounts/cidr-kv',{'type':'kv','options':{'version':'1'}},status=204)
    rules='path "cidr-kv/*" { capabilities = ["create", "read", "update"] } path "auth/token/create" { capabilities = ["update", "sudo"] } path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }'
    c('policy','PUT','sys/policies/acl/cidr-user',{'policy':rules},status=204)
    c('seed','POST','cidr-kv/item',{'value':'synthetic'},status=204)
    t.config('config',dict(t.configuration,token_ttl=120,token_max_ttl=600,token_policies=['cidr-user'],token_bound_cidrs=['127.0.0.1/32']))
    original=t.login('allowed.login');t.bounds('allowed.lookup',original,['127.0.0.1'],source='127.0.0.2')
    t.login('denied.login',source='127.0.0.2',status=403,provider=False)
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
    wrapped_login=c('wrapped_login.accepted','POST','auth/ldap/login/alice',{'password':t.directory.user_password},token='',provider=True,wrap_ttl='60s')
    t.check('wrapped_login.outer',not wrapped_login.get('auth') and bool(wrapped_login.get('wrap_info',{}).get('token')))
    login_wrapper=wrapped_login['wrap_info']['token'];t.tokens.append(login_wrapper)
    login_inner=c('wrapped_login.unwrap_other_source','POST','sys/wrapping/unwrap',{},token=login_wrapper,source='127.0.0.2').get('auth',{})
    t.check('wrapped_login.inner',bool(login_inner.get('client_token')) and login_inner.get('accessor')==wrapped_login['wrap_info'].get('wrapped_accessor'))
    t.tokens.append(login_inner['client_token'])
    c('wrapped_login.token_denied_other_source','GET','auth/token/lookup-self',token=login_inner['client_token'],source='127.0.0.2',status=403)
    c('wrapped_login.token_allowed','GET','auth/token/lookup-self',token=login_inner['client_token'])
    c('wrapped_login.single_use','POST','sys/wrapping/unwrap',{},token=login_wrapper,source='127.0.0.2',status=400)
    t.config('changed.config',{'token_bound_cidrs':['192.0.2.0/24']})
    t.login('changed.new_login',status=403,provider=False)
    t.renew_all('changed.old_renew',original);t.bounds('changed.old_lookup',original,['127.0.0.1'])
    wrapped=c('wrapped.accepted','POST','auth/token/renew-self',{'increment':120},token=original['client_token'],provider=True,wrap_ttl='60s')
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
        data=c('parse.'+name+'.read','GET','auth/ldap/config').get('data',{})
        t.check('parse.'+name+'.canonical',data.get('token_bound_cidrs')==[normalized])
        t.login('parse.'+name+'.login',status=status,provider=status==200)
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
    t.check('receipt.no_sensitive_values',not any(secret in json.dumps(t.rows) for secret in [t.directory.admin_password,t.directory.user_password,*t.tokens]))
    t.check('complete',True)

MILESTONES={'wrapped_login.token_denied_other_source','wrapped_login.single_use','denied.login','denied.read','denied.write','denied.renew','actor_scope.accessor.shape','child.other_source','orphan.other_source','changed.old_renew.self.shape','wrapped.no_publication','finite.second','finite.exhausted','parse.mapped_prefix.canonical','v6.renew.self.shape','clear.cross_family','restart.old_renew.self.shape','restart.v6_renew.self.shape','receipt.no_sensitive_values','complete'}
def complete_scenarios(rows):
    if not rows or any(row.get('passed') is not True for row in rows):return False
    names=[row.get('case') for row in rows]
    return all(isinstance(n,str) for n in names) and len(names)==len(set(names)) and {'ldap_cidrs.'+n for n in MILESTONES}.issubset(names) and names[-1]=='ldap_cidrs.complete'


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary');parser.add_argument('--build-source-commit');parser.add_argument('--oracle-only',action='store_true');parser.add_argument('--output',required=True)
    args=parser.parse_args()
    if not args.oracle_only and (not args.binary or not re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit or '')):parser.error('candidate binary and full build source commit required')
    binary=Path(args.binary or os.environ['HB_ORACLE_BINARY']).resolve(strict=True)
    output=Path(args.output).absolute();admitted=admit_output(output);before=source_identity(ROOT,binary);runner=Path(__file__);runner_hash=file_hash(runner)
    root=Path(tempfile.mkdtemp(prefix='heptabao-ldap-cidrs-'));root.chmod(0o700)
    oracle=instance=None;directories=[]
    report={'schema':'heptabao.ldap-cidrs-comparison.v1','target_version':'2.6.2','synthetic_only':True,'actual_https_openldap':True,'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False,'scope':'numeric CIDRs, real dual-stack socket peers, native LDAP service tokens; excludes Unix/DNS SockAddr, strictly_bind_ip and batch','oracle_binary_sha256':BINARY_SHA256,'candidate_binary_sha256':None if args.oracle_only else file_hash(binary),'build_source_commit':None if args.oracle_only else args.build_source_commit,'build_source_binding_basis':'caller-supplied commit and observed binary hash; not independent attestation','source_identity':before,'runner_sha256':runner_hash,'started_at_unix':time.time(),'cases':{},'side_failures':{}}
    try:
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        oracle=start_oracle(port);o=Path(oracle['root']);ca=Path(oracle['ca_file']).read_text()
        oracle['process'].kill();oracle['process'].wait(timeout=5);stop_oracle(oracle)
        config_file=o/'server.json';settings=json.loads(config_file.read_text());settings['listener'][0]['tcp']['address']=f'[::]:{port}'
        private_write(config_file,settings,replace=True);restart_oracle(oracle)
        for side in (['oracle'] if args.oracle_only else ['candidate','oracle']):
            directory=NativeDirectory(root/(side+'-ldap'),o/'tls.crt',o/'tls.key',o/'ca.crt');directories.append(directory)
            if side=='candidate':
                instance=Instance(binary,root/'candidate');settings=json.loads((instance.root/'server.json').read_text());settings.update(outbound_endpoints=[],lifecycle_interval_seconds=0,listen=f'[::]:{instance.port}')
                private_write(instance.root/'server.json',settings,replace=True);instance.start();status,initialized=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
                if status!=200:raise ScenarioFailure('ldap_cidrs.candidate_init')
                instance.token,key=initialized['root_token'],initialized['keys_base64'][0]
                if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ScenarioFailure('ldap_cidrs.candidate_unseal')
                client=SourceClient(instance.address,instance.root/'ca.crt',instance.token)
                def restart():
                    instance.stop();instance.start()
                    if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ScenarioFailure('ldap_cidrs.candidate_reopen')
            else:
                client=SourceClient(oracle['address'],oracle['ca_file'],private_read(oracle['token_file']).decode().strip())
                def restart():
                    oracle['process'].kill();oracle['process'].wait(timeout=5);stop_oracle(oracle);restart_oracle(oracle)
            rows=report['cases'][side]=[]
            try:run_scenarios(Trace(client,directory,configuration(side,directory,ca),rows),restart)
            except ScenarioFailure as error:report['side_failures'][side]=str(error)
            except Exception as error:report['side_failures'][side]='unexpected_'+type(error).__name__
        expected={'oracle'} if args.oracle_only else {'candidate','oracle'}
        report['cases_match']=args.oracle_only or report['cases'].get('candidate')==report['cases'].get('oracle')
        report['status']=('oracle_passed' if args.oracle_only else 'passed') if set(report['cases'])==expected and all(complete_scenarios(rows) for rows in report['cases'].values()) and report['cases_match'] and not report['side_failures'] else 'failed'
    except Exception as error:report['status']='failed';report['safe_failure_code']=type(error).__name__
    finally:
        if instance:instance.stop()
        for directory in directories:directory.stop()
        if oracle:stop_oracle(oracle);shutil.rmtree(oracle['root'])
        shutil.rmtree(root)
        report['source_and_binary_unchanged']=before==source_identity(ROOT,binary);report['runner_unchanged']=file_hash(runner)==runner_hash
        if not report['source_and_binary_unchanged'] or not report['runner_unchanged']:report['status']='failed';report['safe_failure_code']='source_or_binary_changed'
        report['finished_at_unix']=time.time()
        if admit_output(output)!=admitted:raise ValueError('report_directory_changed')
        private_write(output,report)
    print(json.dumps({'status':report['status'],'counts':{k:len(v) for k,v in report['cases'].items()},'side_failures':report['side_failures'],'safe_failure_code':report.get('safe_failure_code')}))
    return 0 if report['status'] in ('passed','oracle_passed') else 1
if __name__=='__main__':raise SystemExit(main())
