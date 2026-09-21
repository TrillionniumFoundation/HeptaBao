#!/usr/bin/env python3
"""Official-only cert lifetime observations over real TLS; no candidate parity claim."""
from __future__ import annotations
import json
import os
from pathlib import Path
import signal
import tempfile
import time

import cert_batch_probe as base
from bao_http import SafeArgumentParser, private_read, private_write
from cert_auth_live import Fixture
from cert_renewal_live import tls_client
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity
from userpass_password_live import free_port, private_parent, safe_files

MOUNT, POLICY, KV = base.MOUNT, base.POLICY, base.KV
FIELDS=('token_ttl','token_max_ttl','token_period','token_explicit_max_ttl')
ALIASES=('ttl','max_ttl','period')
SCENARIOS=frozenset(('fresh.omitted','fresh.zero','partial.null','partial.zero','explicit.snapshot',
    'ordinary.currentmax','period.current','period.transition','aliases.old','aliases.precedence',
    'aliases.validation_order','lease.type','children','restart'))


class Trace(base.Trace):
    def finish(self, case):
        if case not in SCENARIOS or case in self.finished: raise ValueError('invalid_scenario')
        self.finished.append(case)
    def read(self, case, name):
        status, body=self.call(case,'GET',base.role_path(name))
        data=body.get('data') or {}
        safe={'status':status}
        for field in (*FIELDS,*ALIASES,'token_num_uses'):
            safe[field+'_present']=field in data
            if type(data.get(field)) is int: safe[field]=data[field]
        self.observe(case+'.duration_projection',**safe)
        return status,data
    def lookup(self, case, auth):
        status,body=self.call(case,'POST','auth/token/lookup',{'token':auth['client_token']})
        data=body.get('data') or {}
        self.observe(case+'.lease',status=status,live=status==200,
            **{k:data[k] for k in ('ttl','creation_time','creation_ttl','period','explicit_max_ttl')
               if type(data.get(k)) is int})
        return status,data


def tune(t,case,default=75,maximum=600):
    t.require(case,'POST','sys/auth/'+MOUNT+'/tune',
        {'token_type':'default-service','default_lease_ttl':default,'max_lease_ttl':maximum},status=204)


def create(t,case,certificate,**fields):
    name=case.replace('.','-')
    t.require(case+'.create','POST',base.role_path(name),
        {'certificate':certificate,'token_policies':[POLICY],**fields},status=204)
    return name


def issue(t,case,name):
    body=t.require(case,'POST','auth/'+MOUNT+'/login',{'name':name},token='',role=name)
    base.credential(body)
    auth=body.get('auth') or {}
    if not isinstance(auth.get('accessor'),str) or not auth['accessor']:
        raise ScenarioFailure('service_accessor_missing')
    return auth


def renew_three(t,case,auth,increment=None):
    for suffix in ('renew-self','renew','renew-accessor'):
        body={} if increment is None else {'increment':increment}
        if suffix=='renew':body['token']=auth['client_token']
        elif suffix=='renew-accessor':body['accessor']=auth['accessor']
        status,result=t.call(case+'.'+suffix.replace('-','_'),'POST','auth/token/'+suffix,body,
            token=auth['client_token'] if suffix=='renew-self' else None)
        received=result.get('auth') or {}
        t.observe(case+'.'+suffix.replace('-','_')+'.binding',status=status,
            echo_target=received.get('client_token')==auth['client_token'] if suffix!='renew-accessor' else False,
            accessor_no_bearer=not received.get('client_token') if suffix=='renew-accessor' else False)


def known_age(t,case,auth,*,wall=time.time,mono=time.monotonic,pause=time.sleep):
    # A public creation_time C is integer seconds. now >= C+2 proves at least
    # one whole second after even the latest fractional issue in that second.
    deadline=mono()+4
    count=0
    while True:
        count+=1
        status,data=t.lookup(case+'.poll'+str(count),auth)
        creation=data.get('creation_time')
        if status!=200 or type(creation) is not int:raise ScenarioFailure('age_lookup_unavailable')
        if wall()>=creation+2:
            t.observe(case+'.ready',known_issue_age_at_least_one_second=True,read_only_polls=count)
            return
        if mono()>=deadline:raise ScenarioFailure('known_issue_age_not_observed')
        pause(.05)


def mutate_observe(t,case,name,fields):
    _,before=t.read(case+'.before',name)
    status,_=t.call(case+'.write','POST',base.role_path(name),fields)
    _,after=t.read(case+'.after',name)
    t.observe(case+'.effect',status=status,role_exactly_unchanged=before==after)
    return status


def run(t,certificate,restart,plain):
    t.require('setup.mount','POST','sys/auth/'+MOUNT,{'type':'cert'},status=204)
    t.require('setup.kv','POST','sys/mounts/cert-batch-kv',{'type':'kv','options':{'version':'1'}},status=204)
    t.require('setup.value','POST',KV,{'value':'synthetic'},status=204)
    t.require('setup.policy','PUT','sys/policies/acl/'+POLICY,{'policy':
        'path "cert-batch-kv/*" { capabilities=["read"] } '
        'path "auth/token/create" { capabilities=["update","sudo"] } '
        'path "auth/token/create-orphan" { capabilities=["update","sudo"] }'},status=204)
    saved={}
    tune(t,'fresh.omitted.tune')
    name=create(t,'fresh.omitted',certificate);t.read('fresh.omitted.read',name)
    auth=issue(t,'fresh.omitted.login',name);saved['zero']=(name,auth)
    t.finish('fresh.omitted')

    name=create(t,'fresh.zero',certificate,token_ttl=0,token_max_ttl=0)
    t.read('fresh.zero.read',name);issue(t,'fresh.zero.login',name)
    t.require('fresh.zero.max','POST',base.role_path(name),{'token_max_ttl':60},status=204)
    t.read('fresh.zero.maxread',name);issue(t,'fresh.zero.clipped_login',name);t.finish('fresh.zero')

    name=create(t,'partial.null',certificate,token_ttl=40,token_max_ttl=300,token_period=20,token_explicit_max_ttl=180,
        allowed_common_names=['client.example.test'])
    mutate_observe(t,'partial.null.fields',name,dict.fromkeys(FIELDS))
    t.require('partial.null.selector','POST',base.role_path(name),{'allowed_dns_sans':['client.example.test']},status=204)
    t.read('partial.null.selector_read',name);issue(t,'partial.null.login',name);t.finish('partial.null')
    t.require('partial.zero.clear','POST',base.role_path(name),dict.fromkeys(FIELDS,0),status=204)
    tune(t,'partial.zero.tune',95)
    t.read('partial.zero.read',name);auth=issue(t,'partial.zero.login',name)
    renew_three(t,'partial.zero.omitted',auth);renew_three(t,'partial.zero.zero',auth,0)
    t.finish('partial.zero')

    tune(t,'explicit.snapshot.tune')
    name=create(t,'explicit.snapshot',certificate,token_ttl=60,token_max_ttl=600,token_explicit_max_ttl=120)
    auth=issue(t,'explicit.snapshot.login',name);known_age(t,'explicit.snapshot.age',auth)
    for cap in (1,600):
        t.require(f'explicit.snapshot.cap{cap}','POST',base.role_path(name),{'token_explicit_max_ttl':cap},status=204)
        renew_three(t,f'explicit.snapshot.old{cap}',auth,300)
        t.lookup(f'explicit.snapshot.old{cap}.lookup',auth)
        new=issue(t,f'explicit.snapshot.new{cap}.login',name)
        t.lookup(f'explicit.snapshot.new{cap}.lookup',new)
    saved['cap']=(name,auth);t.finish('explicit.snapshot')

    name=create(t,'ordinary.currentmax',certificate,token_ttl=60,token_max_ttl=90)
    auth=issue(t,'ordinary.currentmax.login',name)
    t.require('ordinary.currentmax.raise','POST',base.role_path(name),{'token_max_ttl':600},status=204)
    renew_three(t,'ordinary.currentmax.raised',auth,300);known_age(t,'ordinary.currentmax.age',auth)
    t.lookup('ordinary.currentmax.before',auth)
    t.require('ordinary.currentmax.shrink','POST',base.role_path(name),{'token_ttl':1,'token_max_ttl':1},status=204)
    renew_three(t,'ordinary.currentmax.past',auth,300);t.lookup('ordinary.currentmax.after',auth)
    t.finish('ordinary.currentmax')

    name=create(t,'period.current',certificate,token_ttl=60,token_max_ttl=600,token_period=20)
    auth=issue(t,'period.current.login',name)
    t.require('period.current.change','POST',base.role_path(name),{'token_period':10},status=204)
    renew_three(t,'period.current.ten',auth,300);t.lookup('period.current.snapshot',auth)
    tune(t,'period.current.clip',3,3)
    # Keep the clipped-three-second lease work adjacent; restore mount budget
    # before any unrelated request. No retry if this short lease expires.
    t.call('period.current.clipped','POST','auth/token/renew-self',{'increment':300},token=auth['client_token'])
    tune(t,'period.current.restore')
    renew_three(t,'period.current.restored',auth,300);saved['period']=(name,auth);t.finish('period.current')

    for cap in (0,120):
        prefix=f'period.transition.cap{cap}'
        name=create(t,prefix,certificate,token_ttl=60,token_max_ttl=600,token_explicit_max_ttl=cap)
        auth=issue(t,prefix+'.login',name);known_age(t,prefix+'.age',auth)
        t.require(prefix+'.period','POST',base.role_path(name),{'token_period':10},status=204)
        renew_three(t,prefix+'.periodic',auth,300);t.lookup(prefix+'.issued_snapshot',auth)
        t.require(prefix+'.finite','POST',base.role_path(name),{'token_period':0,'token_ttl':1,'token_max_ttl':1},status=204)
        renew_three(t,prefix+'.past_age',auth,300);t.lookup(prefix+'.still_live',auth)
    t.finish('period.transition')

    name=create(t,'aliases.old',certificate,ttl=40,max_ttl=300,period=20)
    t.read('aliases.old.read',name);saved['aliases']=(name,issue(t,'aliases.old.login',name))
    for label,fields in [('lease',{'lease':45}),('ignored',{'lease':55,'ttl':35}),('nullhigher',{'token_ttl':None,'ttl':None,'lease':50})]:
        other=create(t,'aliases.old.'+label,certificate,**fields);t.read('aliases.old.'+label+'.read',other)
    t.finish('aliases.old')

    name=create(t,'aliases.precedence',certificate,ttl=40,max_ttl=300,period=20)
    for label,fields in [('both',{'ttl':50,'token_ttl':60}),('newnull',{'ttl':45,'token_ttl':None}),
        ('oldnull',{'ttl':None,'token_ttl':65}),('zero',{'token_ttl':0}),('null',dict.fromkeys((*FIELDS,*ALIASES)))]:
        mutate_observe(t,'aliases.precedence.'+label,name,fields)
    saved['precedence']=(name,issue(t,'aliases.precedence.login',name));t.finish('aliases.precedence')

    name=create(t,'aliases.validation_order',certificate,token_ttl=300,token_max_ttl=600)
    mutate_observe(t,'aliases.validation_order.mixed',name,{'ttl':30,'token_max_ttl':60})
    other='aliases-batch-order'
    t.call('aliases.validation_order.batch_write','POST',base.role_path(other),
        {'certificate':certificate,'token_type':'batch','period':30})
    status,_=t.read('aliases.validation_order.batch_read',other)
    if status==200:t.call('aliases.validation_order.batch_login','POST','auth/'+MOUNT+'/login',{'name':other},token='',role=other)
    other=create(t,'aliases.validation_order.service',certificate,token_type='service')
    mutate_observe(t,'aliases.validation_order.service_to_batch',other,{'token_type':'batch','period':30})
    t.call('aliases.validation_order.changed_login','POST','auth/'+MOUNT+'/login',{'name':other},token='',role=other)
    t.finish('aliases.validation_order')

    for label,value in [('integer',45),('null',None),('numeric_string','45'),('duration_string','45s')]:
        name='lease-'+label.replace('_','-')
        status,_=t.call('lease.type.'+label+'.write','POST',base.role_path(name),{'certificate':certificate,'lease':value})
        t.read('lease.type.'+label+'.read',name)
        if status<300:issue(t,'lease.type.'+label+'.login',name)
    t.finish('lease.type')

    name=create(t,'children',certificate,token_ttl=120,token_max_ttl=600,token_period=60,token_explicit_max_ttl=180)
    parent=issue(t,'children.parent',name);children={}
    for label,path in [('child','auth/token/create'),('orphan','auth/token/create-orphan')]:
        value=t.require('children.'+label+'.create','POST',path,
            {'policies':[POLICY],'ttl':90,'explicit_max_ttl':40},token=parent['client_token'])
        children[label]=value['auth'];base.credential(value)
    t.require('children.delete_role','DELETE',base.role_path(name),status=204)
    for label,child in children.items():
        renew_three(t,'children.'+label+'.renew',child,120);t.lookup('children.'+label+'.lookup',child)
        old=t.client;t.client=plain
        try:t.call('children.'+label+'.no_leaf','POST','auth/token/renew-self',{},token=child['client_token'])
        finally:t.client=old
    t.finish('children')

    positive=create(t,'restart.positive',certificate,token_ttl=40,token_max_ttl=300)
    saved['positive']=(positive,issue(t,'restart.positive.login',positive))
    # Restart has its own deliberately fresh issuance. Earlier short-period
    # observations must not expire while unrelated cases run. This does not
    # pretend these new tokens retain an earlier token's issue-time snapshot.
    historical_cap=saved['cap'][1]
    for key,(name,_) in list(saved.items()):
        saved[key]=(name,issue(t,'restart.fresh.'+key,name))
    states={key:t.read('restart.before.'+key,name)[1] for key,(name,_) in saved.items()}
    restart()
    for key,(name,auth) in saved.items():
        _,after=t.read('restart.after.'+key,name)
        t.observe('restart.'+key+'.role_equal',exact_role_readback_preserved=states[key]==after)
        status,_=t.lookup('restart.'+key+'.lookup',auth)
        if status!=200:raise ScenarioFailure('restart_fresh_token_unavailable')
        t.require('restart.'+key+'.bearer','GET',KV,token=auth['client_token'])
    t.lookup('restart.original_cap.lookup',historical_cap)
    t.call('restart.original_cap.bearer','GET',KV,token=historical_cap['client_token'])
    t.finish('restart')


def complete(t):
    return bool(t and t.rows and set(t.finished)==SCENARIOS and len(t.finished)==len(SCENARIOS)
        and len({r['case'] for r in t.rows})==len(t.rows))


def helpers():
    return {**base.helper_hashes(),'cert_batch_probe':file_hash(Path(base.__file__))}


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--oracle-only',action='store_true',required=True)
    parser.add_argument('--work-parent',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();official=verify_inputs()
    output=args.output.absolute();admitted=admit_output(output)
    runner=file_hash(Path(__file__));inputs=helpers();archive=Path(os.environ['HB_ORACLE_ARCHIVE'])
    binary_hash,archive_hash=file_hash(official),file_hash(archive)
    work=Path(tempfile.mkdtemp(prefix='cert-native-ttl-',dir=private_parent(args.work_parent)))
    prior=os.environ.get('HB_ORACLE_WORK_ROOT');os.environ['HB_ORACLE_WORK_ROOT']=str(work)
    fixture=oracle=trace=None;processes=[];failure=None;roots=[];scans=False
    def interrupted(signum,frame):raise ScenarioFailure('interrupted')
    handlers={sig:signal.signal(sig,interrupted) for sig in (signal.SIGTERM,signal.SIGINT)}
    before=source_identity(ROOT,official)
    try:
        fixture=Fixture(official,work/'tls-material')
        oracle=start_oracle(free_port());processes.append(oracle['process'])
        data=Path(oracle['root']);token=private_read(oracle['token_file']).decode().strip()
        key=private_read(data/'unseal.key').decode().strip()
        client=tls_client(oracle['address'],oracle['ca_file'],token,
            (fixture.root/'client-chain.pem',fixture.root/'client.key'))
        plain=tls_client(oracle['address'],oracle['ca_file'],token)
        trace=Trace(client);trace.sensitive.extend((token,key))
        trace.sensitive.extend(private_read(p).decode() for p in fixture.root.glob('*.key'))
        roots=[data,fixture.root]
        def restart():
            stop_oracle(oracle);restart_oracle(oracle);processes.append(oracle['process'])
        run(trace,(fixture.root/'client.crt').read_text(),restart,plain)
    except Exception as error:
        failure=str(error) if isinstance(error,ScenarioFailure) else 'fixture_'+type(error).__name__
    finally:
        try:
            if oracle:stop_oracle(oracle)
        except Exception:failure=failure or 'oracle_cleanup_failed'
        if prior is None:os.environ.pop('HB_ORACLE_WORK_ROOT',None)
        else:os.environ['HB_ORACLE_WORK_ROOT']=prior
        for sig,handler in handlers.items():signal.signal(sig,handler)
    if trace and roots:scans=all(safe_files(root,trace.sensitive) for root in roots)
    after=source_identity(ROOT,official)
    unchanged=(runner==file_hash(Path(__file__)) and inputs==helpers()
        and binary_hash==file_hash(official) and archive_hash==file_hash(archive))
    stopped=all(p.poll() is not None for p in processes)
    observed=not failure and complete(trace) and scans and unchanged and stopped
    report={'schema':'heptabao.cert-native-ttl-probe.v1','status':'observed' if observed else 'failed',
        'target_version':'2.6.2','oracle_only':True,'candidate_executed':False,
        'cases':trace.rows if trace else [],'completed_scenarios':trace.finished if trace else [],
        'failure':failure,'secrets_absent':scans,'processes_stopped':stopped,'inputs_unchanged':unchanged,
        'runner_sha256':runner,'helper_sha256':inputs,'oracle_binary_sha256':binary_hash,'oracle_archive_sha256':archive_hash,
        'harness_source_before':before,'harness_source_after':after,'harness_source_unchanged':before==after,
        'candidate_source_binding_claimed':False,'mutating_requests_retried':False,'retained_work_dir':str(work),
        'positive_role_origin':'created by this exact official executable; not historical-version state',
        'renewal_tls':'same real leaf on all three direct renewal routes; child/orphan additionally tested without leaf',
        'age_observation':'public creation_time and same-host clock prove at least 1s age; max4s read-only polling',
        'restart_token_scope':'fresh pre-restart tokens plus separately identified original explicit-cap token',
        'parity_qualified':False,'full_cert_compatibility':False}
    if trace and any(secret in json.dumps(report) for secret in trace.sensitive):raise ValueError('sensitive_report')
    if admit_output(output)!=admitted:raise ValueError('output_parent_changed')
    private_write(output,report,replace=False)
    print(json.dumps({'status':report['status'],'checks':len(report['cases']),'failure':failure}))
    return int(not observed)


if __name__=='__main__':raise SystemExit(main())
