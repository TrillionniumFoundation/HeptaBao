#!/usr/bin/env python3
"""RADIUS, native LDAP and Kubernetes login wrapping over actual TLS providers.

A synthetic signed PAP responder, real OpenLDAP and synthetic TokenReview server
exercise selected paths. This does not qualify a real Kubernetes API server.
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
from bao_http import SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from online_evidence import admit_output, source_identity
from official_openbao_launcher import start_oracle,stop_oracle,restart_oracle,BINARY_SHA256
from radius_cidrs_live import SourceClient
from radius_native_live import NativeRadius,SECRET,PASSWORD
from ldap_native_live import NativeDirectory,configuration as ldap_config
from kubernetes_renewal_live import Reviewer,configuration as kube_config,role,assertion
from remote_jwks_live import Instance,signing_key

class Trace:
    def __init__(self,client,rows):self.client,self.rows=client,rows;self.sensitive=[]
    def check(self,name,condition,**safe):
        if not re.fullmatch(r'[a-z0-9_.]{1,140}',name) or any(type(v) not in (bool,int) for v in safe.values()):raise ValueError('unsafe_trace')
        self.rows.append({'case':'provider_login_wrapping.'+name,**safe,'passed':bool(condition)})
        if not condition:raise ScenarioFailure('provider_login_wrapping.'+name)
    def call(self,name,method,path,body=None,*,expected=200,token=None,source='127.0.0.1',wrap=None):
        r=self.client.request(method,path,body,token=token,source=source,wrap_ttl=wrap)
        self.check(name,r.status==expected,status=r.status);return r.body


def run_scenarios(t,side,radius,directory,reviewer,ca,restart):
    private,jwk=signing_key('ES256','wrap-kube');reviewer.presented=assertion(private,jwk)
    configs={'radius':{'host':'127.0.0.1','port':radius.port,'secret':SECRET.decode(),'token_ttl':120,'token_bound_cidrs':['127.0.0.1']},'ldap':ldap_config(side,directory,ca,token_ttl=120),'kubernetes':kube_config(side,reviewer,private,ca)}
    t.sensitive.extend([SECRET.decode(),PASSWORD.decode(),directory.user_password,directory.admin_password,reviewer.reviewer,reviewer.presented])
    for kind,config in configs.items():
        t.call(kind+'.mount','POST','sys/auth/'+kind,{'type':kind},expected=204)
        t.call(kind+'.config','POST','auth/'+kind+'/config',config,expected=204)
        if kind=='kubernetes':t.call(kind+'.role','POST','auth/kubernetes/role/app',role(token_policies=['default'],token_ttl=120,token_max_ttl=600),expected=204)
        path='auth/'+kind+'/login'+('/alice' if kind=='ldap' else '')
        body={'username':'alice','password':PASSWORD.decode()} if kind=='radius' else {'password':directory.user_password} if kind=='ldap' else {'role':'app','jwt':reviewer.presented}
        before=radius.count() if kind=='radius' else directory.cursor() if kind=='ldap' else len(reviewer.calls)
        result=t.call(kind+'.wrapped','POST',path,body,token='',wrap='60s');wrap=result.get('wrap_info',{});wrapper=wrap.get('token')
        observed=radius.count()==before+1 and radius.observed(before,accepted=True) if kind=='radius' else directory.observed(before,search=True) if kind=='ldap' else len(reviewer.calls)==before+1 and reviewer.request_valid
        t.check(kind+'.outer',not result.get('auth') and isinstance(wrapper,str) and bool(wrapper) and wrap.get('ttl')==60 and wrap.get('creation_path')==path and bool(wrap.get('wrapped_accessor')) and observed,provider_observed=observed)
        t.sensitive.append(wrapper)
        data=t.call(kind+'.wrapper_lookup','POST','auth/token/lookup',{'token':wrapper},source='127.0.0.2').get('data',{})
        t.check(kind+'.wrapper_unbound',not data.get('bound_cidrs') and data.get('num_uses')==1)
        # Keep one committed wrapped login across a real restart before unwrap.
        if kind=='ldap':restart();t.check(kind+'.wrapped_survives_restart',True)
        unwrapped=t.call(kind+'.unwrap_other_source','POST','sys/wrapping/unwrap',{},token=wrapper,source='127.0.0.2');auth=unwrapped.get('auth',{});bearer=auth.get('client_token')
        t.check(kind+'.inner',isinstance(bearer,str) and bool(bearer) and auth.get('accessor')==wrap.get('wrapped_accessor') and bool(auth.get('entity_id')))
        t.sensitive.append(bearer)
        t.call(kind+'.second_unwrap','POST','sys/wrapping/unwrap',{},token=wrapper,source='127.0.0.2',expected=400)
        t.call(kind+'.issued_allowed','GET','auth/token/lookup-self',token=bearer)
        t.call(kind+'.issued_other_source','GET','auth/token/lookup-self',token=bearer,source='127.0.0.2',expected=403 if kind=='radius' else 200)
        if kind=='radius':
            before=radius.count();denied=t.call(kind+'.denied_source_wrapped_login','POST',path,body,token='',source='127.0.0.2',wrap='60s',expected=403)
            t.check(kind+'.denied_source_no_provider_or_publication',radius.count()==before and not denied.get('auth') and not denied.get('wrap_info'))
        t.check(kind+'.complete',True)
    t.check('receipt_no_secrets',not any(value in json.dumps(t.rows) for value in t.sensitive))
    t.check('complete',True)

MILESTONES={'radius.outer','radius.wrapper_unbound','radius.issued_other_source','radius.denied_source_no_provider_or_publication','radius.complete','ldap.inner','ldap.wrapped_survives_restart','ldap.second_unwrap','ldap.complete','kubernetes.inner','kubernetes.second_unwrap','kubernetes.complete','receipt_no_secrets','complete'}
def complete(rows):
    names=[r.get('case') for r in rows]
    return bool(rows) and all(r.get('passed') is True for r in rows) and all(isinstance(n,str) for n in names) and len(names)==len(set(names)) and {'provider_login_wrapping.'+n for n in MILESTONES}.issubset(names) and names[-1]=='provider_login_wrapping.complete'


def main():
    p=SafeArgumentParser(description=__doc__);p.add_argument('--binary');p.add_argument('--build-source-commit');p.add_argument('--oracle-only',action='store_true');p.add_argument('--output',required=True);args=p.parse_args()
    if not args.oracle_only and (not args.binary or not re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit or '')):p.error('candidate binary and full source commit required')
    binary=Path(args.binary or os.environ['HB_ORACLE_BINARY']).resolve(strict=True);output=Path(args.output).absolute();parent=admit_output(output)
    before=source_identity(ROOT,binary);runner=file_hash(Path(__file__));root=Path(tempfile.mkdtemp(prefix='provider-login-wrapping-'));root.chmod(0o700)
    report={'schema':'heptabao.provider-login-wrapping-comparison.v1','target_version':'2.6.2','oracle_binary_sha256':BINARY_SHA256,'candidate_binary_sha256':None if args.oracle_only else file_hash(binary),'build_source_commit':args.build_source_commit,'build_source_binding_basis':'caller-supplied commit and observed binary hash; not independent attestation','source_identity':before,'runner_sha256':runner,'synthetic_only':True,'actual_openldap':True,'actual_kube_apiserver':False,'full_openbao_compatibility':False,'production_authority':False,'configuration_adaptation':'RADIUS/LDAP/Kubernetes auth use API-authorized egress; Kubernetes retains explicit candidate/oracle JWT-claim validation adaptation','cases':{},'side_failures':{},'started_at_unix':time.time()}
    oracle=instance=None;providers=[]
    try:
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        oracle=start_oracle(port);o=Path(oracle['root']);ca=Path(oracle['ca_file']).read_text()
        for side in (['oracle'] if args.oracle_only else ['candidate','oracle']):
            radius=NativeRadius(require_ma=side=='candidate');directory=NativeDirectory(root/(side+'-ldap'),o/'tls.crt',o/'tls.key',o/'ca.crt');reviewer=Reviewer(o/'tls.crt',o/'tls.key',side);providers.append((radius,directory,reviewer))
            if side=='candidate':
                instance=Instance(binary,root/'candidate');cfg=json.loads((instance.root/'server.json').read_text());cfg['lifecycle_interval_seconds']=0
                cfg['outbound_endpoints']=[]
                private_write(instance.root/'server.json',cfg,replace=True);instance.start();status,init=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
                if status!=200:raise ScenarioFailure('candidate_init')
                instance.token,key=init['root_token'],init['keys_base64'][0]
                if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ScenarioFailure('candidate_unseal')
                client=SourceClient(instance.address,instance.root/'ca.crt',instance.token)
                def restart():
                    instance.stop();instance.start()
                    if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ScenarioFailure('candidate_reopen')
            else:
                client=SourceClient(oracle['address'],oracle['ca_file'],private_read(oracle['token_file']).decode().strip())
                def restart():
                    oracle['process'].kill();oracle['process'].wait(timeout=5);stop_oracle(oracle);restart_oracle(oracle)
            rows=report['cases'][side]=[]
            try:run_scenarios(Trace(client,rows),side,radius,directory,reviewer,ca,restart)
            except Exception as error:report['side_failures'][side]=str(error) if isinstance(error,ScenarioFailure) else 'unexpected_'+type(error).__name__
        expected={'oracle'} if args.oracle_only else {'candidate','oracle'}
        report['cases_match']=args.oracle_only or report['cases'].get('candidate')==report['cases'].get('oracle')
        report['status']=('oracle_passed' if args.oracle_only else 'passed') if set(report['cases'])==expected and all(complete(rows) for rows in report['cases'].values()) and report['cases_match'] and not report['side_failures'] else 'failed'
    except Exception as error:report['status']='failed';report['safe_failure_code']=type(error).__name__
    finally:
        if instance:instance.stop()
        for radius,directory,reviewer in providers:radius.close();directory.stop();reviewer.close()
        if oracle:stop_oracle(oracle);shutil.rmtree(oracle['root'])
        shutil.rmtree(root);report['source_and_binary_unchanged']=before==source_identity(ROOT,binary);report['runner_unchanged']=runner==file_hash(Path(__file__))
        if not report['source_and_binary_unchanged'] or not report['runner_unchanged']:report['status']='failed';report['safe_failure_code']='source_changed'
        if admit_output(output)!=parent:raise ValueError('report_directory_changed')
        report['finished_at_unix']=time.time();private_write(output,report)
    print(json.dumps({'status':report['status'],'checks':{k:len(v) for k,v in report['cases'].items()},'failures':report['side_failures'],'safe_failure_code':report.get('safe_failure_code')}))
    return 0 if report['status'] in ('passed','oracle_passed') else 1
if __name__=='__main__':raise SystemExit(main())
