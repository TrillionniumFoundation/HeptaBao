#!/usr/bin/env python3
"""Official-only AppRole batch observations. Completion is not a parity claim."""
from __future__ import annotations
import json,os,re,shutil,sys,tempfile
from pathlib import Path
from bao_http import BaoError,Client,SafeArgumentParser,private_read,private_write
from core_isolation import file_hash
from official_openbao_launcher import verify_inputs,start_oracle,stop_oracle,restart_oracle
from online_evidence import admit_output
from userpass_password_live import free_port,private_parent,safe_files

MOUNT='approle-batch-probe';POLICY='approle-batch-probe'
MODES=('default-service','default-batch','service','batch')
ROLE_TYPES=('default','service','batch')
SCENARIOS=tuple('matrix.'+m.replace('-','_')+'.'+r for m in MODES for r in ROLE_TYPES)+(
 'alias.default_service','alias.default_batch','type.omitted','type.empty','type.null','type.invalid',
 'explicit.period','explicit.uses','explicit.cap','forced.period','forced.uses','forced.cap',
 'secret.two_uses','secret.unlimited','identity.alias','identity.disabled_secret_use',
 'batch.renew','batch.create','batch.create_orphan','batch.role_deleted','batch.restart')
TYPES={'default','service','batch','default-service','default-batch','none','other'}

def helpers():
 return {name:file_hash(Path(sys.modules[name].__file__)) for name in ('bao_http','core_isolation','official_openbao_launcher','online_evidence','userpass_password_live','heptabao.transport')}

class Trace:
 def __init__(self,client):self.client=client;self.rows=[];self.sensitive=[];self.finished=[]
 def call(self,case,step,method,path,body=None,*,token=None,role=None):
  response=self.client.request(method,'/v1/'+path,body,token=token)
  data=response.body.get('data') or {};auth=response.body.get('auth') or {}
  for value in (auth.get('client_token'),auth.get('accessor'),data.get('secret_id'),data.get('secret_id_accessor'),data.get('role_id')):
   if isinstance(value,str) and value:self.sensitive.append(value)
  name=case+'.'+step
  if any(row['case']==name for row in self.rows):raise ValueError('duplicate_case')
  row={'case':name,'status':response.status,'auth':bool(auth),'errors':bool(response.body.get('errors')),'warnings':bool(response.body.get('warnings'))}
  for key,source in [('configured_type',data.get('token_type')),('auth_type',auth.get('token_type')),('lookup_type',data.get('type'))]:
   row[key]=source if source in TYPES else 'none' if source is None else 'other'
  if auth:
   row.update(accessor=bool(auth.get('accessor')),renewable=auth.get('renewable') is True,orphan=auth.get('orphan') is True,entity=bool(auth.get('entity_id')),role_metadata=(auth.get('metadata') or {}).get('role_name')==role)
  for key in ('token_period','token_num_uses','token_explicit_max_ttl','secret_id_num_uses','num_uses','period','explicit_max_ttl'):
   if type(data.get(key)) is int:row[key]=data[key]
  for label,value in [('lease',auth.get('lease_duration')),('ttl',data.get('ttl'))]:
   if type(value) is int:
    row[label+'_positive']=value>0
    for cap in (20,30,60,120):row[label+'_le_'+str(cap)]=value<=cap
  self.rows.append(row)
  return response.status,response.body
 def finish(self,case):
  if case not in SCENARIOS or case in self.finished:raise ValueError('invalid_scenario')
  self.finished.append(case)
 def setup(self,case,role,fields,mode='default-service'):
  self.call(case,'tune','POST','sys/auth/'+MOUNT+'/tune',{'token_type':mode,'default_lease_ttl':60,'max_lease_ttl':300})
  status,_=self.call(case,'write','POST','auth/'+MOUNT+'/role/'+role,dict(token_ttl=60,token_max_ttl=300,token_policies=[POLICY],**fields))
  self.call(case,'read','GET','auth/'+MOUNT+'/role/'+role)
  return status
 def credentials(self,case,role):
  _,body=self.call(case,'role_id','GET','auth/'+MOUNT+'/role/'+role+'/role-id');rid=body['data']['role_id']
  _,body=self.call(case,'secret_id','POST','auth/'+MOUNT+'/role/'+role+'/secret-id',{});sid=body['data']['secret_id']
  return {'role_id':rid,'secret_id':sid}
 def login(self,case,step,role,creds):
  return self.call(case,step,'POST','auth/'+MOUNT+'/login',creds,token='',role=role)
 def lookup(self,case,step,raw):return self.call(case,step,'POST','auth/token/lookup',{'token':raw})

def run(t,restart):
 t.call('setup','mount','POST','sys/auth/'+MOUNT,{'type':'approle'})
 t.call('setup','policy','PUT','sys/policies/acl/'+POLICY,{'policy':'path "auth/token/*" { capabilities=["read","update","sudo"] }'})
 saved=None
 for mode in MODES:
  for kind in ROLE_TYPES:
   case='matrix.'+mode.replace('-','_')+'.'+kind;role=case.replace('.','-')
   t.setup(case,role,{'token_type':kind},mode)
   creds=t.credentials(case,role);_,body=t.login(case,'login',role,creds);auth=body.get('auth') or {}
   if auth.get('client_token'):t.lookup(case,'lookup',auth['client_token'])
   if mode=='default-service' and kind=='batch':saved=(role,creds,auth)
   t.finish(case)
 t.setup('type.omitted','type-omitted',{});omitted=t.credentials('type.omitted','type-omitted');t.login('type.omitted','login','type-omitted',omitted);t.finish('type.omitted')
 for case,value in [('alias.default_service','default-service'),('alias.default_batch','default-batch'),('type.empty',''),('type.null',None),('type.invalid','invalid')]:
  role=case.replace('.','-')
  try:status=t.setup(case,role,{'token_type':value})
  except BaoError as error:
   if case!='type.null' or error.code!='transport_outcome_unknown':raise
   t.rows.append({'case':'type.null.write','response_absent':True,'mutation_outcome_unknown':True})
   t.call(case,'after_disconnect_read','GET','auth/'+MOUNT+'/role/'+role)
   t.finish(case);continue
  if status<300:
   creds=t.credentials(case,role);t.login(case,'login',role,creds)
  t.finish(case)
 for case,fields,mode in [
  ('explicit.period',{'token_type':'batch','token_period':30},'default-service'),
  ('explicit.uses',{'token_type':'batch','token_num_uses':2},'default-service'),
  ('explicit.cap',{'token_type':'batch','token_explicit_max_ttl':20},'default-service'),
  ('forced.period',{'token_type':'service','token_period':30},'batch'),
  ('forced.uses',{'token_type':'service','token_num_uses':2},'batch'),
  ('forced.cap',{'token_type':'service','token_explicit_max_ttl':20},'batch')]:
  role=case.replace('.','-');status=t.setup(case,role,fields,mode)
  if status<300:
   creds=t.credentials(case,role);_,body=t.login(case,'login',role,creds)
   if (body.get('auth') or {}).get('client_token'):t.lookup(case,'lookup',body['auth']['client_token'])
  t.finish(case)
 for case,uses in [('secret.two_uses',2),('secret.unlimited',0)]:
  role=case.replace('.','-');t.setup(case,role,{'token_type':'batch','secret_id_num_uses':uses});creds=t.credentials(case,role)
  for n in range(3):t.login(case,'login_'+str(n+1),role,creds)
  t.call(case,'secret_lookup','POST','auth/'+MOUNT+'/role/'+role+'/secret-id/lookup',{'secret_id':creds['secret_id']});t.finish(case)
 if saved is None or not saved[2].get('client_token'):raise ValueError('batch_anchor_missing')
 role,creds,auth=saved;raw=auth['client_token'];entity=auth.get('entity_id')
 _,body=t.call('identity.alias','entity_read','GET','identity/entity/id/'+entity)
 aliases=(body.get('data') or {}).get('aliases') or []
 t.rows.append({'case':'identity.alias.role_id_binding','alias_matches_role_id':any(a.get('name')==creds['role_id'] for a in aliases),'role_metadata':auth.get('metadata')=={'role_name':role}});t.finish('identity.alias')
 case='identity.disabled_secret_use';disabled_role='disabled-use'
 t.setup(case,disabled_role,{'token_type':'batch','secret_id_num_uses':2});dc=t.credentials(case,disabled_role)
 _,body=t.login(case,'first_login',disabled_role,dc);de=body['auth']['entity_id']
 t.call(case,'disable','POST','identity/entity/id/'+de,{'disabled':True})
 t.login(case,'disabled_login',disabled_role,dc)
 t.call(case,'secret_lookup','POST','auth/'+MOUNT+'/role/'+disabled_role+'/secret-id/lookup',{'secret_id':dc['secret_id']})
 t.call(case,'enable','POST','identity/entity/id/'+de,{'disabled':False});t.login(case,'after_enable',disabled_role,dc);t.finish(case)
 for case,path,body in [('batch.renew','renew-self',{}),('batch.create','create',{'policies':['default']}),('batch.create_orphan','create-orphan',{'policies':['default']})]:
  t.call(case,'request','POST','auth/token/'+path,body,token=raw);t.finish(case)
 t.call('batch.role_deleted','delete','DELETE','auth/'+MOUNT+'/role/'+role);t.lookup('batch.role_deleted','lookup',raw);t.finish('batch.role_deleted')
 restart();t.lookup('batch.restart','lookup',raw);t.finish('batch.restart')

def main():
 parser=SafeArgumentParser(description=__doc__);parser.add_argument('--work-parent',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
 parent=private_parent(args.work_parent);output=args.output.absolute();admitted=admit_output(output)
 bao=verify_inputs();bh=file_hash(bao);rh=file_hash(Path(__file__));hh=helpers()
 work=Path(tempfile.mkdtemp(prefix='approle-batch-',dir=parent));prior=os.environ.get('HB_ORACLE_WORK_ROOT');os.environ['HB_ORACLE_WORK_ROOT']=str(work)
 oracle=None;trace=None;failure=None;scan=False
 try:
  oracle=start_oracle(free_port());token=private_read(oracle['token_file']).decode().strip();key=private_read(Path(oracle['root'])/'unseal.key').decode().strip()
  trace=Trace(Client(oracle['address'],oracle['ca_file'],token,timeout=5));trace.sensitive.extend([token,key])
  def restart():stop_oracle(oracle);restart_oracle(oracle)
  run(trace,restart);scan=safe_files(Path(oracle['root']),trace.sensitive)
 except Exception as e:failure='fixture_'+type(e).__name__
 finally:
  if oracle is not None:stop_oracle(oracle)
  if prior is None:os.environ.pop('HB_ORACLE_WORK_ROOT',None)
  else:os.environ['HB_ORACLE_WORK_ROOT']=prior
 unchanged=bh==file_hash(bao) and rh==file_hash(Path(__file__)) and hh==helpers()
 finished=trace.finished if trace else [];rows=trace.rows if trace else []
 panic_markers={'nil_string_panic':False,'approle_role_callback':False}
 for log in work.rglob('*.log'):
  contents=log.read_bytes();panic_markers['nil_string_panic']|=b'interface conversion: interface {} is nil, not string' in contents;panic_markers['approle_role_callback']|=b'pathRoleCreateUpdate' in contents
 complete=not failure and set(finished)==set(SCENARIOS) and len(finished)==len(SCENARIOS) and scan and unchanged
 report={'schema':'heptabao.approle-batch-observations.v1','status':'observed' if complete else 'incomplete','compatibility_passed':False,'oracle_only':True,'target_version':'2.6.2','cases':rows,'completed_scenarios':finished,'pending_scenarios':sorted(set(SCENARIOS)-set(finished)),'failure':failure,'secrets_absent':scan,'inputs_unchanged':unchanged,'runner_sha256':rh,'helper_sha256':hh,'oracle_binary_sha256':bh,'retained_failure_work_dir':None if complete else str(work),'unrun_features':['MFA_enforcement','HA','historical_upgrade','snapshot_key_history','role_CIDR','SecretID_CIDR','renewable_dynamic_provider'],'candidate_run':False,'upstream_panic_markers':panic_markers}
 if trace and any(secret in json.dumps(report) for secret in trace.sensitive):raise ValueError('sensitive_report_rejected')
 if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
 private_write(output,report,replace=False)
 if complete:shutil.rmtree(work)
 print(json.dumps({'status':report['status'],'completed_scenarios':len(finished),'observations':len(rows),'failure':failure}));return int(not complete)
if __name__=='__main__':raise SystemExit(main())
