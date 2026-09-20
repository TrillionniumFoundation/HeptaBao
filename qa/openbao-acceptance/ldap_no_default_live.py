#!/usr/bin/env python3
"""Native LDAP no-default policy comparison with real TLS Bind/Search and restart."""
import json
import os
from pathlib import Path
import re
import shutil
import socket
import tempfile
from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, file_hash
from ldap_native_live import NativeDirectory, configuration
from ldap_native_upgrade import provider_idle
from official_openbao_launcher import start_oracle, stop_oracle, restart_oracle, BINARY_SHA256
from remote_jwks_live import Instance
from online_evidence import source_identity, admit_output

POLICIES={'default','ldap-renewer'}
def safe_policy_set(value):
    if value is None:return None
    if not isinstance(value,list) or any(type(x) is not str or x not in POLICIES for x in value):
        raise ValueError('unexpected_policy_shape')
    return sorted(value)

class Probe:
    def __init__(self,client,directory,config,rows):
        self.client,self.directory,self.config,self.rows=client,directory,config,rows
    def call(self,name,path,body=None,*,method='POST',token=None,wrap_ttl=None):
        if not re.fullmatch('[a-z0-9_.]+',name):raise ValueError('invalid_case')
        cursor=self.directory.cursor()
        r=self.client.request(method,'/v1/'+path,body,token=token,wrap_ttl=wrap_ttl)
        row={'case':name,'status':r.status,'directory_io':not provider_idle(self.directory,cursor),
             'bind_and_search':self.directory.observed(cursor,search=True)}
        auth=r.body.get('auth')
        if isinstance(auth,dict):
            row['policies']=safe_policy_set(auth.get('token_policies',auth.get('policies')))
            row['has_token_policies']='token_policies' in auth
        data=r.body.get('data')
        if isinstance(data,dict):
            if 'token_no_default_policy' in data:
                if type(data['token_no_default_policy']) is not bool:raise ValueError('unexpected_boolean')
                row['token_no_default_policy']=data['token_no_default_policy']
            for field in ('policies','token_policies'):
                if field in data:row[field]=safe_policy_set(data[field])
        self.rows.append(row)
        return r
    def mount(self,name,**options):
        mount='nd-'+name
        if self.call(name+'.mount','sys/auth/'+mount,{'type':'ldap'}).status!=204:raise ValueError('mount_failed')
        cfg=dict(self.config,token_no_default_policy=True,**options)
        if self.call(name+'.config','auth/'+mount+'/config',cfg).status!=204:raise ValueError('config_failed')
        return mount
    def login(self,name,mount):
        r=self.call(name,'auth/'+mount+'/login/alice',{'password':self.directory.user_password},token='')
        if r.status!=200 or not isinstance(r.body.get('auth'),dict):raise ValueError('login_failed')
        return r.body['auth']
    def renew(self,name,auth):
        for via,path,body,actor in [('self','renew-self',{},auth['client_token']),('token','renew',{'token':auth['client_token']},None),('accessor','renew-accessor',{'accessor':auth['accessor']},None)]:
            self.call(name+'.'+via,'auth/token/'+path,dict(body,increment=60),token=actor)
        self.call(name+'.lookup','auth/token/lookup',{'token':auth['client_token']})
    def update(self,name,mount,body):
        if self.call(name,'auth/'+mount+'/config',body).status!=204:raise ValueError('config_update_failed')
        self.call(name+'.read','auth/'+mount+'/config',method='GET')

def scenarios(p,restart):
    samples={}
    policy='path "auth/token/renew-self" { capabilities = ["update"] } path "auth/token/lookup-self" { capabilities = ["read"] }'
    if p.call('policy','sys/policies/acl/ldap-renewer',{'policy':policy},method='PUT').status!=204:raise ValueError('policy_failed')
    for name,extra,mapping in [('nil',{},None),('empty',{'token_policies':[]},None),('null',{'token_policies':None},None),('user_empty',{},('users/alice',{})),('group_empty',{},('groups/engineering',{'policies':[]})),('user_default',{},('users/alice',{'policies':['default']})),('group_default',{},('groups/engineering',{'policies':['default']})),('user_named',{},('users/alice',{'policies':['ldap-renewer']})),('group_named',{},('groups/engineering',{'policies':['ldap-renewer']}))]:
        mount=p.mount(name,**extra)
        if mapping and p.call(name+'.mapping','auth/'+mount+'/'+mapping[0],mapping[1]).status!=204:raise ValueError('mapping_failed')
        p.call(name+'.read','auth/'+mount+'/config',method='GET')
        auth=p.login(name+'.login',mount);p.renew(name+'.renew',auth);samples[name]=auth
        if name=='nil':
            p.update('nil.to_empty',mount,{'token_policies':[]});p.renew('nil.old_after_empty',auth)
    mount=p.mount('toggle',token_policies=['ldap-renewer'])
    absent=p.login('toggle.true_login',mount);p.renew('toggle.true_renew',absent)
    p.update('toggle.partial',mount,{'token_ttl':120});p.renew('toggle.old_after_partial',absent)
    p.update('toggle.false',mount,{'token_no_default_policy':False});p.renew('toggle.old_after_false',absent)
    default=p.login('toggle.false_login',mount)
    p.update('toggle.true',mount,{'token_no_default_policy':True});p.renew('toggle.old_default_after_true',default)
    p.update('toggle.null',mount,{'token_no_default_policy':None});p.login('toggle.null_login',mount)
    p.update('toggle.explicit_default',mount,{'token_no_default_policy':True,'token_policies':['default','ldap-renewer']})
    explicit=p.login('toggle.explicit_login',mount);p.renew('toggle.explicit_renew',explicit)
    p.update('toggle.policy_change',mount,{'token_policies':['default']});p.renew('toggle.changed_renew',explicit)
    p.update('wrap.config',mount,{'token_no_default_policy':True,'token_policies':['ldap-renewer']})
    wrapped=p.call('wrap.login','auth/'+mount+'/login/alice',{'password':p.directory.user_password},token='',wrap_ttl='60s')
    if wrapped.status!=200 or wrapped.body.get('auth') or not wrapped.body.get('wrap_info',{}).get('token'):raise ValueError('wrapped_login_failed')
    wrapper=wrapped.body['wrap_info']['token']
    inner=p.call('wrap.unwrap','sys/wrapping/unwrap',{},token=wrapper)
    if inner.status!=200 or inner.body.get('auth',{}).get('accessor')!=wrapped.body['wrap_info'].get('wrapped_accessor'):raise ValueError('wrapped_accessor_mismatch')
    p.call('wrap.single_use','sys/wrapping/unwrap',{},token=wrapper)
    restart()
    p.rows.append({'case':'restart.same_store','completed':True})
    p.renew('restart.old_no_default',absent)
    p.renew('restart.old_default',default)
    p.renew('restart.old_zero_explicit',samples['nil'])
    p.renew('restart.old_zero_nil',samples['user_empty'])
    p.call('restart.config','auth/'+mount+'/config',method='GET')
    p.rows.append({'case':'complete','completed':True})


MILESTONES={'nil.renew.token','nil.old_after_empty.token','null.renew.accessor','group_empty.renew.token','user_default.renew.self','group_named.renew.self','toggle.old_after_false.self','toggle.old_default_after_true.self','toggle.null.read','toggle.changed_renew.accessor','wrap.unwrap','wrap.single_use','restart.old_zero_nil.token','restart.old_zero_explicit.token','restart.config','complete'}
def complete(rows):
    names=[r.get('case') for r in rows]
    if not rows or len(set(names))!=len(names) or not MILESTONES.issubset(names) or names[-1]!='complete':return False
    by_name={r['case']:r for r in rows}
    expectations={'nil.renew.token':500,'nil.old_after_empty.token':200,'null.renew.accessor':200,'group_empty.renew.token':500,'toggle.changed_renew.accessor':500,'wrap.unwrap':200,'wrap.single_use':400,'restart.old_zero_nil.token':500,'restart.old_zero_explicit.token':200}
    return all(by_name[n].get('status')==status for n,status in expectations.items()) and by_name['complete'].get('completed') is True

def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary');parser.add_argument('--build-source-commit');parser.add_argument('--oracle-only',action='store_true');parser.add_argument('--output',required=True)
    args=parser.parse_args()
    if not args.oracle_only and (not args.binary or not re.fullmatch('[0-9a-f]{40}',args.build_source_commit or '')):parser.error('candidate binary and full build source commit required')
    binary=Path(args.binary or os.environ['HB_ORACLE_BINARY']).resolve(strict=True)
    output=Path(args.output).absolute();parent=admit_output(output);before=source_identity(ROOT,binary)
    runner=file_hash(Path(__file__))
    root=Path(tempfile.mkdtemp(prefix='ldap-no-default-live-'));root.chmod(0o700)
    oracle=instance=None;directories=[]
    report={'schema':'heptabao.ldap-no-default-comparison.v1','synthetic_only':True,'actual_https_openldap':True,'candidate_observed':not args.oracle_only,'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False,'oracle_binary_sha256':BINARY_SHA256,'candidate_binary_sha256':None if args.oracle_only else file_hash(binary),'build_source_commit':None if args.oracle_only else args.build_source_commit,'source_identity':before,'runner_sha256':runner,'cases':{},'side_failures':{}}
    try:
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        oracle=start_oracle(port);o=Path(oracle['root'])
        for side in (['oracle'] if args.oracle_only else ['candidate','oracle']):
            directory=NativeDirectory(root/(side+'-ldap'),o/'tls.crt',o/'tls.key',o/'ca.crt');directories.append(directory)
            if side=='candidate':
                instance=Instance(binary,root/'candidate')
                settings=json.loads((instance.root/'server.json').read_text());settings.update(outbound_endpoints=[],lifecycle_interval_seconds=0)
                private_write(instance.root/'server.json',settings,replace=True);instance.start()
                status,initialized=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
                if status!=200:raise ValueError('candidate_init_failed')
                instance.token,key=initialized['root_token'],initialized['keys_base64'][0]
                if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ValueError('candidate_unseal_failed')
                client=Client(instance.address,str(instance.root/'ca.crt'),instance.token)
                def restart():
                    instance.stop();instance.start()
                    if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ValueError('candidate_reopen_failed')
            else:
                client=Client(oracle['address'],oracle['ca_file'],private_read(oracle['token_file']).decode().strip())
                def restart():
                    oracle['process'].kill();oracle['process'].wait(timeout=5);stop_oracle(oracle);restart_oracle(oracle)
            cfg=configuration(side,directory,(o/'ca.crt').read_text(),token_ttl=120);del cfg['token_policies']
            rows=report['cases'][side]=[]
            try:scenarios(Probe(client,directory,cfg,rows),restart)
            except Exception as error:report['side_failures'][side]='unexpected_'+type(error).__name__
        expected={'oracle'} if args.oracle_only else {'candidate','oracle'}
        report['cases_match']=args.oracle_only or report['cases'].get('candidate')==report['cases'].get('oracle')
        report['status']=('oracle_passed' if args.oracle_only else 'passed') if set(report['cases'])==expected and not report['side_failures'] and report['cases_match'] and all(complete(rows) for rows in report['cases'].values()) else 'failed'
    except Exception as error:report['status']='failed';report['safe_failure_code']=type(error).__name__
    finally:
        if instance:instance.stop()
        for directory in directories:directory.stop()
        if oracle:stop_oracle(oracle);shutil.rmtree(oracle['root'])
        shutil.rmtree(root)
        report['source_and_binary_unchanged']=before==source_identity(ROOT,binary);report['runner_unchanged']=runner==file_hash(Path(__file__))
        if not report['source_and_binary_unchanged'] or not report['runner_unchanged']:report['status']='failed';report['safe_failure_code']='source_or_runner_changed'
        if admit_output(output)!=parent:raise ValueError('report_parent_changed')
        private_write(output,report)
    print(json.dumps({'status':report['status'],'counts':{k:len(v) for k,v in report['cases'].items()},'side_failures':report['side_failures'],'safe_failure_code':report.get('safe_failure_code')}))
    return 0 if report['status'] in ('passed','oracle_passed') else 1
if __name__=='__main__':raise SystemExit(main())
