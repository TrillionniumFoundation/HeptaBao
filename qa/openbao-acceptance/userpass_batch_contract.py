"""Shared scoped batch contract, calibrated against pinned OpenBao2.6.2.

Observation projection excludes credentials; the dual runner compares the full
safe trace and separately requires every named scenario to complete.
"""
from __future__ import annotations
import re,secrets,sys
from pathlib import Path
from core_isolation import file_hash

MOUNT='batch-probe'
TYPES={'default','service','batch','default-service','default-batch'}
ERRORS={'batch tokens cannot be renewed':'batch_not_renewable',
 'batch tokens cannot be revoked':'batch_not_revocable','batch tokens cannot create more tokens':'batch_cannot_create',
 'cubbyhole operations are only supported':'batch_no_cubbyhole','permission denied':'permission_denied',
 'missing accessor':'missing_accessor','invalid accessor':'invalid_accessor','invalid token':'invalid_token',
 'cannot be':'configuration_conflict','invalid':'invalid_request'}
REQUIRED={'type.omitted.read','type.null.read','type.empty.read','type.invalid_default_service.write',
 'override.batch.service.login','override.default_batch.service.login','override.default_service.batch.login',
 'conflict.batch_period.write','conflict.batch_uses.write','explicit.lookup','lifecycle.renew_self',
 'lifecycle.revoke_self','lifecycle.create_child','lifecycle.cubby_write','parent.revoke','parent.child_after',
 'parent.orphan_after','wrap.unwrap','restart.lookup','deleted_user.lookup','disabled_mount.lookup','complete'}

def helpers():
    names=('bao_http','core_isolation','official_openbao_launcher','online_evidence','userpass_password_live','heptabao','heptabao.transport')
    return {name:file_hash(Path(sys.modules[name].__file__)) for name in names}

class Trace:
    def __init__(self,client):self.client=client;self.rows=[];self.sensitive=[]
    def note(self,name,**facts):
        if not re.fullmatch('[a-z0-9_.]{1,140}',name) or any(r['case']==name for r in self.rows):raise ValueError('unsafe_or_duplicate_case')
        allowed_strings=TYPES|set(ERRORS.values())|{'other','none'}
        if any(type(v) not in (bool,int,str) or isinstance(v,str) and v not in allowed_strings for v in facts.values()):raise ValueError('unsafe_observation')
        self.rows.append({'case':name,**facts})
    def call(self,name,method,path,body=None,*,token=None,wrap=None):
        r=self.client.request(method,'/v1/'+path,body,token=token,wrap_ttl=wrap)
        a=r.body.get('auth') or {};d=r.body.get('data') or {};w=r.body.get('wrap_info') or {}
        facts={'status':r.status,'auth_present':bool(a),'wrapper_present':bool(w)}
        for label,obj,field in [('auth_type',a,'token_type'),('lookup_type',d,'type'),('configured_type',d,'token_type')]:
            if field in obj:facts[label]=obj[field] if obj[field] in TYPES else 'other'
        if a:
            facts.update(accessor_present=bool(a.get('accessor')),bearer_present=bool(a.get('client_token')),
                renewable=a.get('renewable') is True,orphan=a.get('orphan') is True,
                canonical_metadata=a.get('metadata')=={'username':'matrix'},entity_present=bool(a.get('entity_id')))
            for field in ['client_token','accessor']:
                if isinstance(a.get(field),str) and a[field]:self.sensitive.append(a[field])
        if w.get('token'):self.sensitive.append(w['token'])
        for field in ['renewable','orphan']:
            if field in d:facts['lookup_'+field]=d[field] is True
        if 'accessor' in d:facts['lookup_accessor_present']=bool(d['accessor'])
        if 'meta' in d:facts['lookup_canonical_metadata']=d['meta']=={'username':'matrix'}
        for label,value in [('lease',a.get('lease_duration')),('ttl',d.get('ttl'))]:
            if type(value) is int:
                facts[label+'_positive']=value>0
                for bound in [20,30,75,120,300,600]:facts[label+'_le_'+str(bound)]=value<=bound
        for field in ['token_ttl','token_max_ttl','token_period','token_num_uses','token_explicit_max_ttl','num_uses','explicit_max_ttl','period']:
            if type(d.get(field)) is int:facts[field]=d[field]
        errors=r.body.get('errors') or [];facts['errors_present']=bool(errors)
        if errors:
            facts['error_kind']=next((tag for needle,tag in ERRORS.items() if any(isinstance(e,str) and needle in e.lower() for e in errors)),'other')
        self.note(name,**facts);return r.status,r.body
    def write(self,name,fields):return self.call(name,'POST',f'auth/{MOUNT}/users/matrix',fields)
    def read(self,name):return self.call(name,'GET',f'auth/{MOUNT}/users/matrix')
    def login(self,name):
        _,body=self.call(name,'POST',f'auth/{MOUNT}/login/matrix',{'password':self.password},token='')
        return body.get('auth') or {}
    def lookup(self,name,auth):return self.call(name,'POST','auth/token/lookup',{'token':auth['client_token']})

def run(t,restart):
    t.password=secrets.token_urlsafe(28);t.sensitive.append(t.password)
    status,_=t.call('setup.mount','POST','sys/auth/'+MOUNT,{'type':'userpass'})
    if status!=204:raise ValueError('setup_mount_failed')
    t.call('setup.tune','POST','sys/auth/'+MOUNT+'/tune',{'default_lease_ttl':75,'max_lease_ttl':600})
    t.call('setup.policy','PUT','sys/policies/acl/batch-probe',{'policy':'path "auth/token/*" { capabilities=["read","list","create","update","delete","sudo"] } path "cubbyhole/*" {capabilities=["read","list","create","update","delete"]}'})
    t.write('type.omitted.write',{'password':t.password,'token_policies':['batch-probe']});t.read('type.omitted.read')
    for name,value in [('service','service'),('batch','batch'),('null',None),('empty',''),('default','default'),('invalid_default_service','default-service'),('invalid_default_batch','default-batch'),('invalid_unknown','unknown')]:
        t.write('type.'+name+'.write',{'token_type':value});t.read('type.'+name+'.read')
    t.write('type.batch_again.write',{'token_type':'batch'});t.write('type.partial.write',{'token_ttl':120});t.read('type.partial.read')
    for mount_type in ['default-service','default-batch','service','batch']:
        m=mount_type.replace('-','_');t.call('override.'+m+'.tune','POST','sys/auth/'+MOUNT+'/tune',{'token_type':mount_type})
        for user_type in ['default','service','batch']:
            p='override.'+m+'.'+user_type
            t.write(p+'.write',{'token_type':user_type,'token_ttl':0,'token_period':0,'token_num_uses':0,'token_explicit_max_ttl':0})
            t.login(p+'.login')
    t.call('conflict.restore_mount','POST','sys/auth/'+MOUNT+'/tune',{'token_type':'default-service'})
    t.write('conflict.base',{'token_type':'service','token_period':0,'token_num_uses':0})
    for tag,field in [('period','token_period'),('uses','token_num_uses')]:
        t.write('conflict.batch_'+tag+'.write',{'token_type':'batch',field:2});t.read('conflict.batch_'+tag+'.read')
    for usertype in ['default','service']:
        for tag,field in [('period','token_period'),('uses','token_num_uses')]:
            p='forced.'+usertype+'.'+tag
            t.write(p+'.write',{'token_type':usertype,'token_period':0,'token_num_uses':0,field:2})
            t.call(p+'.mount','POST','sys/auth/'+MOUNT+'/tune',{'token_type':'batch'})
            auth=t.login(p+'.login')
            if auth.get('client_token'):t.lookup(p+'.lookup',auth)
    t.call('explicit.mount','POST','sys/auth/'+MOUNT+'/tune',{'token_type':'default-service'})
    t.write('explicit.write',{'token_type':'batch','token_ttl':120,'token_period':0,'token_num_uses':0,'token_explicit_max_ttl':20})
    explicit=t.login('explicit.login');t.lookup('explicit.lookup',explicit)
    t.write('lifecycle.write',{'token_type':'batch','token_ttl':300,'token_explicit_max_ttl':0})
    auth=t.login('lifecycle.login');bearer=auth['client_token']
    t.lookup('lifecycle.lookup',auth)
    t.call('lifecycle.lookup_self','GET','auth/token/lookup-self',token=bearer)
    for tag,route,body,actor in [('renew_self','renew-self',{},bearer),('renew','renew',{'token':bearer},None),('renew_accessor','renew-accessor',{'accessor':''},None),('revoke_self','revoke-self',{},bearer),('revoke','revoke',{'token':bearer},None),('revoke_orphan','revoke-orphan',{'token':bearer},None),('lookup_accessor','lookup-accessor',{'accessor':''},None),('revoke_accessor','revoke-accessor',{'accessor':''},None),('create_child','create',{'policies':['batch-probe'],'ttl':120},bearer),('create_orphan','create-orphan',{'policies':['batch-probe'],'ttl':120},bearer)]:
        t.call('lifecycle.'+tag,'POST','auth/token/'+route,body,token=actor)
    t.call('lifecycle.cubby_write','POST','cubbyhole/item',{'value':'synthetic'},token=bearer)
    t.call('lifecycle.cubby_read','GET','cubbyhole/item',token=bearer)
    t.lookup('lifecycle.still_valid',auth)
    # Separate ACL denial from token-kind validation priority.
    t.write('priority.no_policy',{'token_no_default_policy':True,'token_policies':[]})
    none=t.login('priority.login');t.call('priority.renew_self','POST','auth/token/renew-self',{},token=none['client_token'])
    t.call('priority.cubby','GET','cubbyhole/item',token=none['client_token'])
    t.call('priority.create','POST','auth/token/create',{'ttl':120},token=none['client_token'])
    t.write('priority.restore_policy',{'token_no_default_policy':False,'token_policies':['batch-probe']})
    # A batch child is possible only when a service actor creates it.
    _,body=t.call('parent.create','POST','auth/token/create',{'policies':['batch-probe'],'ttl':300})
    parent=body['auth'];t.sensitive.append(parent['client_token'])
    children={}
    for tag,route in [('child','create'),('orphan','create-orphan')]:
        _,body=t.call('parent.'+tag+'.create','POST','auth/token/'+route,{'policies':['batch-probe'],'ttl':120,'type':'batch'},token=parent['client_token'])
        children[tag]=body['auth'];t.lookup('parent.'+tag+'.lookup',children[tag])
    t.call('parent.revoke','POST','auth/token/revoke',{'token':parent['client_token']})
    for tag,child in children.items():t.lookup('parent.'+tag+'_after',child)
    _,body=t.call('wrap.login','POST',f'auth/{MOUNT}/login/matrix',{'password':t.password},token='',wrap='60s')
    wrapper=body['wrap_info']['token'];t.sensitive.append(wrapper)
    t.call('wrap.unwrap','POST','sys/wrapping/unwrap',{},token=wrapper)
    t.call('wrap.second','POST','sys/wrapping/unwrap',{},token=wrapper)
    restart();t.lookup('restart.lookup',auth)
    t.call('deleted_user.delete','DELETE',f'auth/{MOUNT}/users/matrix');t.lookup('deleted_user.lookup',auth)
    t.call('disabled_mount.disable','DELETE','sys/auth/'+MOUNT);t.lookup('disabled_mount.lookup',auth)
    cubbyhole_priority(t)
    t.note('complete',observed=True)

def cubbyhole_priority(t):
    if t.call('cubby_priority.mount','POST','sys/auth/'+MOUNT,{'type':'userpass'})[0]!=204:
        raise ValueError('priority_mount_failed')
    for name,policy in [
        ('create','path "cubbyhole/*" { capabilities=["create"] }'),
        ('update','path "cubbyhole/*" { capabilities=["update"] }'),
        ('read','path "cubbyhole/*" { capabilities=["read"] }'),
        ('unrelated','path "secret/probe" { capabilities=["read"] }'),
        ('empty',None),
    ]:
        prefix='cubby_priority.'+name
        if policy is not None:
            if t.call(prefix+'.policy','PUT','sys/policies/acl/batch-priority-'+name,{'policy':policy})[0]!=204:
                raise ValueError('priority_policy_failed')
        if t.write(prefix+'.user',{'password':t.password,'token_type':'batch','token_ttl':120,
                'token_no_default_policy':True,'token_policies':[] if policy is None else ['batch-priority-'+name]})[0]!=204:
            raise ValueError('priority_user_failed')
        auth=t.login(prefix+'.login')
        for method in ('POST','PUT','GET','LIST','DELETE'):
            t.call(prefix+'.'+method.lower(),method,'cubbyhole/item',
                {'value':'synthetic'} if method in ('POST','PUT') else None,token=auth['client_token'])

# Require named business observations, not a fixed row count. New cases may be added.
REQUIRED_CASES=frozenset({
    'complete',
    'conflict.base',
    'conflict.batch_period.read',
    'conflict.batch_period.write',
    'conflict.batch_uses.read',
    'conflict.batch_uses.write',
    'conflict.restore_mount',
    'cubby_priority.create.delete',
    'cubby_priority.create.get',
    'cubby_priority.create.list',
    'cubby_priority.create.login',
    'cubby_priority.create.policy',
    'cubby_priority.create.post',
    'cubby_priority.create.put',
    'cubby_priority.create.user',
    'cubby_priority.empty.delete',
    'cubby_priority.empty.get',
    'cubby_priority.empty.list',
    'cubby_priority.empty.login',
    'cubby_priority.empty.post',
    'cubby_priority.empty.put',
    'cubby_priority.empty.user',
    'cubby_priority.mount',
    'cubby_priority.read.delete',
    'cubby_priority.read.get',
    'cubby_priority.read.list',
    'cubby_priority.read.login',
    'cubby_priority.read.policy',
    'cubby_priority.read.post',
    'cubby_priority.read.put',
    'cubby_priority.read.user',
    'cubby_priority.unrelated.delete',
    'cubby_priority.unrelated.get',
    'cubby_priority.unrelated.list',
    'cubby_priority.unrelated.login',
    'cubby_priority.unrelated.policy',
    'cubby_priority.unrelated.post',
    'cubby_priority.unrelated.put',
    'cubby_priority.unrelated.user',
    'cubby_priority.update.delete',
    'cubby_priority.update.get',
    'cubby_priority.update.list',
    'cubby_priority.update.login',
    'cubby_priority.update.policy',
    'cubby_priority.update.post',
    'cubby_priority.update.put',
    'cubby_priority.update.user',
    'deleted_user.delete',
    'deleted_user.lookup',
    'disabled_mount.disable',
    'disabled_mount.lookup',
    'explicit.login',
    'explicit.lookup',
    'explicit.mount',
    'explicit.write',
    'forced.default.period.login',
    'forced.default.period.lookup',
    'forced.default.period.mount',
    'forced.default.period.write',
    'forced.default.uses.login',
    'forced.default.uses.lookup',
    'forced.default.uses.mount',
    'forced.default.uses.write',
    'forced.service.period.login',
    'forced.service.period.lookup',
    'forced.service.period.mount',
    'forced.service.period.write',
    'forced.service.uses.login',
    'forced.service.uses.lookup',
    'forced.service.uses.mount',
    'forced.service.uses.write',
    'lifecycle.create_child',
    'lifecycle.create_orphan',
    'lifecycle.cubby_read',
    'lifecycle.cubby_write',
    'lifecycle.login',
    'lifecycle.lookup',
    'lifecycle.lookup_accessor',
    'lifecycle.lookup_self',
    'lifecycle.renew',
    'lifecycle.renew_accessor',
    'lifecycle.renew_self',
    'lifecycle.revoke',
    'lifecycle.revoke_accessor',
    'lifecycle.revoke_orphan',
    'lifecycle.revoke_self',
    'lifecycle.still_valid',
    'lifecycle.write',
    'override.batch.batch.login',
    'override.batch.batch.write',
    'override.batch.default.login',
    'override.batch.default.write',
    'override.batch.service.login',
    'override.batch.service.write',
    'override.batch.tune',
    'override.default_batch.batch.login',
    'override.default_batch.batch.write',
    'override.default_batch.default.login',
    'override.default_batch.default.write',
    'override.default_batch.service.login',
    'override.default_batch.service.write',
    'override.default_batch.tune',
    'override.default_service.batch.login',
    'override.default_service.batch.write',
    'override.default_service.default.login',
    'override.default_service.default.write',
    'override.default_service.service.login',
    'override.default_service.service.write',
    'override.default_service.tune',
    'override.service.batch.login',
    'override.service.batch.write',
    'override.service.default.login',
    'override.service.default.write',
    'override.service.service.login',
    'override.service.service.write',
    'override.service.tune',
    'parent.child.create',
    'parent.child.lookup',
    'parent.child_after',
    'parent.create',
    'parent.orphan.create',
    'parent.orphan.lookup',
    'parent.orphan_after',
    'parent.revoke',
    'priority.create',
    'priority.cubby',
    'priority.login',
    'priority.no_policy',
    'priority.renew_self',
    'priority.restore_policy',
    'restart.lookup',
    'setup.mount',
    'setup.policy',
    'setup.tune',
    'type.batch.read',
    'type.batch.write',
    'type.batch_again.write',
    'type.default.read',
    'type.default.write',
    'type.empty.read',
    'type.empty.write',
    'type.invalid_default_batch.read',
    'type.invalid_default_batch.write',
    'type.invalid_default_service.read',
    'type.invalid_default_service.write',
    'type.invalid_unknown.read',
    'type.invalid_unknown.write',
    'type.null.read',
    'type.null.write',
    'type.omitted.read',
    'type.omitted.write',
    'type.partial.read',
    'type.partial.write',
    'type.service.read',
    'type.service.write',
    'wrap.login',
    'wrap.second',
    'wrap.unwrap',
})
