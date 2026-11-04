#!/usr/bin/env python3
"""Fresh isolated normal-server lookup probe; no old fixture is restarted."""
from pathlib import Path
import hashlib, importlib.util, json, os, sys

CONTROL = Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-coordinator-manager-sdk-61ff8bef-control-r4')
ROOT = CONTROL.parent / 'authbus-token-metadata-61ff8bef-diagnostic-r2'
WRITER = 'authbus-central-writer'
os.umask(0o077)
def need(ok, name):
    if not ok: raise RuntimeError(name)
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
need(sha(CONTROL/'controller.py') == '041e2b8b1de966a6602d04073e53535859bd794cbac0596fe92e1c2a05a1e29a', 'controller_pin')
stage = json.loads((CONTROL/'stage.public.json').read_bytes())
for name,pin in {**stage['inputs'], **stage['helpers']}.items():
    need(sha(CONTROL/name) == pin, 'exact_frozen_source')
spec=importlib.util.spec_from_file_location('frozen_controller', CONTROL/'controller.py')
ctl=importlib.util.module_from_spec(spec);spec.loader.exec_module(ctl)
before=ctl.boundary(); protected_before=ctl.protected()
need(not ROOT.exists() and not ROOT.is_symlink(), 'fresh_root')
ROOT.mkdir(mode=0o700)
sys.path.insert(0,str(CONTROL/'qa/openbao-acceptance'))
import native_v6_authbus_coordinator_live as fixture
instance=None
secrets=[]
report={'schema':'heptabao.authbus-token-metadata-diagnostic.v1', 'ok':False,
        'production_changed':False,'old_fixture_restarted':False,'provider_called':False,
        'system_unit_used':False,'statuses':[],'boundary_before':before}
def call(label, method, route, body=None, expected=200, token=None):
    status,value=instance.call(method,route,body,token=token)
    report['statuses'].append({'case':label,'status':status,'expected':expected})
    need(status==expected,label)
    return value
try:
    instance=fixture.NormalInstance(ctl.BINARY,ROOT/'server');instance.start()
    init=call('init','POST','sys/init',{'secret_shares':1,'secret_threshold':1},token='')
    instance.token=init['root_token'];unseal=init['keys_base64'][0]
    secrets.extend((instance.token,unseal))
    call('unseal','POST','sys/unseal',{'key':unseal},token='')
    call('kv_mount','POST','sys/mounts/openclaw-auth',{'type':'kv','options':{'version':'2'}},expected=204)
    call('activate_native','POST','sys/storage/native-v6/activate',{},expected=204)
    call('approle_mount','POST','sys/auth/approle',{'type':'approle'},expected=204)
    call('writer_policy','PUT','sys/policies/acl/'+WRITER,{'policy':'path "openclaw-auth/data/manifest" { capabilities=["read"] }'},expected=204)
    route='auth/approle/role/'+WRITER
    call('writer_role','POST',route,{'token_policies':[WRITER],'token_ttl':'1200s','token_max_ttl':'1800s',
         'secret_id_num_uses':0,'secret_id_ttl':'3600s'},expected=204)
    role_id=call('role_id','GET',route+'/role-id')['data']['role_id']
    sid=call('secret_id','POST',route+'/secret-id',{})['data']
    secrets.extend((role_id,sid['secret_id'],sid['secret_id_accessor']))
    auth=call('exact_approle_login','POST','auth/approle/login',{'role_id':role_id,'secret_id':sid['secret_id']},token='')['auth']
    secrets.extend((auth['client_token'],auth['accessor']))
    info=call('writer_accessor_lookup','POST','auth/token/lookup-accessor',{'accessor':auth['accessor']})['data']
    need(info.get('accessor')==auth['accessor'] and info.get('id') in (None,''),'accessor_without_bearer')
    namespace=info.get('namespace');meta=info.get('meta');role=meta.get('role_name') if isinstance(meta,dict) else None;policies=info.get('policies')
    predicates={
       'policies_list':isinstance(policies,list),
       'writer_policy':isinstance(policies,list) and WRITER in policies,
       'no_other_policy':isinstance(policies,list) and set(policies)<={WRITER,'default'},
       'policies_unique':isinstance(policies,list) and len(policies)==len(set(policies)),
       'role_name_exact':role==WRITER,'service_type':info.get('type')=='service',
       'renewable_true':info.get('renewable') is True,
       'ttl_integer':isinstance(info.get('ttl'),int),'ttl_over_30':isinstance(info.get('ttl'),int) and info['ttl']>30,
       'original_namespace_predicate':namespace in ('','root')}
    report['predicates']=predicates
    report['lookup_metadata']={k:info.get(k) for k in ('policies','type','renewable','ttl','namespace')}
    report['lookup_metadata'].update(role_name=role,meta_keys=sorted(meta) if isinstance(meta,dict) else None,
                                     namespace_present='namespace' in info,data_keys=sorted(info))
    report['login_metadata']={k:auth.get(k) for k in ('policies','token_type','renewable','lease_duration','metadata')}
    report['strict_writer_guard_would_pass']=all(predicates.values())
    report['ok']=True
except Exception as exc:
    report['error_type']=type(exc).__name__
finally:
    if instance is not None:
        original_process=instance.process
        instance.stop()
        report['server_exit_code']=None if original_process is None else original_process.returncode
        report['server_stopped']=original_process is None or original_process.poll() is not None
        need(not any(s.encode() in (ROOT/'server/server.log').read_bytes() for s in secrets),'server_log_no_credentials')
    report['boundary_after']=ctl.boundary()
    report['protected_unchanged']=ctl.protected()==protected_before
    need(report['boundary_after']==before and report['protected_unchanged'],'production_boundary')
    encoded=json.dumps(report,sort_keys=True)
    need(not any(s in encoded for s in secrets),'public_no_credentials')
    ctl.write(ROOT/'metadata.public.json',(encoded+'\n').encode())
    print(encoded)
raise SystemExit(0 if report['ok'] else 1)
