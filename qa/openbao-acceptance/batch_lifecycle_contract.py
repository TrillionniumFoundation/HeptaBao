"""Batch bearer and real SSH OTP lifecycle, with distinct calibrated/extension lanes.

Issuer deletion and the three OTP phases reuse the actual OpenBao2.6.2 138-row
corpus. Identity and real socket CIDR cases are explicitly scoped extensions;
they only become compatibility evidence when both real implementations pass.
"""
from __future__ import annotations
import datetime as dt
import json,re,secrets,time
from core_isolation import ScenarioFailure

AUTH='batch-life';KV='batch-life-kv';SSH='batch-life-ssh';POLICY='batch-life-policy'
CALIBRATED_RECEIPT_SHA256='146d3a578fc7128845cd3988951f82849d2d4b6b0d8e9398ba469c3464c0cbac'
REQUIRED={'bearer.after_disabled_restart.value','identity.restored.value','identity.policy_restored.value',
 'cidr.denied_origin','cidr.cleared_old_snapshot','cidr.restart_denied','receipt.no_secrets','complete'}
for phase in ('revoke','parent_expiry','batch_expiry'):
    for kind in ('child','orphan'):
        REQUIRED.update({f'{phase}.{kind}.held.cap',f'{phase}.{kind}.renew_preserved',
                         f'{phase}.{kind}.after.bearer',f'{phase}.{kind}.after.verify'})

def lane(name):return 'scoped_extension' if name.startswith(('identity.','cidr.')) else 'same'

def timestamp(value):
    if not isinstance(value,str):return None
    try:
        parsed=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
        return parsed.timestamp() if parsed.tzinfo else None
    except (ValueError,OverflowError):return None

class Trace:
    def __init__(self,client):self.client=client;self.rows=[];self.sensitive=[]
    def note(self,name,passed,**facts):
        if not re.fullmatch('[a-z0-9_.]{1,140}',name) or any(r['case']==name for r in self.rows):raise ValueError('unsafe_or_duplicate_case')
        if any(type(v) not in (bool,int) for v in facts.values()):raise ValueError('unsafe_observation')
        self.rows.append({'case':name,'scope':lane(name),'passed':passed is True,**facts})
        if passed is not True:raise ScenarioFailure(name)
    def call(self,name,method,path,body=None,*,status=200,token=None,source='127.0.0.1',spoof=False):
        result=self.client.request(method,path,body,token=token,source=source,spoof=spoof)
        data=result.body.get('data') or {};auth=result.body.get('auth') or {};wrap=result.body.get('wrap_info') or {}
        for value in (auth.get('client_token'),auth.get('accessor'),data.get('key'),wrap.get('token')):
            if isinstance(value,str) and value:self.sensitive.append(value)
        self.note(name,result.status==status,status=result.status,source_family=self.client.last_family)
        if status>=400:self.note(name+'.no_credentials',not auth and not wrap)
        return result.body
    def bearer(self,name,token,*,status=200,source='127.0.0.1',spoof=False):
        result=self.call(name,'GET',KV+'/item',token=token,status=status,source=source,spoof=spoof)
        if status==200:self.note(name+'.value',result.get('data')=={'value':self.value})
    def login(self,name,*,mount=AUTH,source='127.0.0.1',status=200):
        result=self.call(name,'POST',f'auth/{mount}/login/matrix',{'password':self.password},token='',source=source,status=status)
        if status!=200:return None
        auth=result.get('auth') or {};raw=auth.get('client_token')
        self.note(name+'.batch',bool(raw) and auth.get('token_type')=='batch' and not auth.get('accessor') and auth.get('renewable') is False)
        return auth
    def otp(self,name,raw,ttl):
        result=self.call(name,'POST',SSH+'/creds/probe',{'ip':'127.0.0.1','username':'synthetic'},token=raw)
        lease=result.get('lease_id');otp=(result.get('data') or {}).get('key');duration=result.get('lease_duration')
        self.note(name+'.cap',bool(lease) and bool(otp) and result.get('renewable') is False
            and type(duration) is int and max(1,ttl-2)<=duration<=ttl,
            nonrenewable=result.get('renewable') is False,ttl_matches_batch_window=type(duration) is int and max(1,ttl-2)<=duration<=ttl)
        return lease,otp
    def lease(self,name,lease):return self.call(name,'PUT','sys/leases/lookup',{'lease_id':lease})
    def wait_absent(self,name,path,body):
        if path not in ('auth/token/lookup','sys/leases/lookup'):raise ValueError('poll_must_be_lookup')
        expected=403 if path.startswith('auth/') else 400
        deadline=time.monotonic()+10
        while True:
            response=self.client.request('POST' if path.startswith('auth/') else 'PUT',path,body)
            if response.status==expected:
                self.note(name,True,status=response.status,absence_observed=True);return
            if response.status!=200 or time.monotonic()>=deadline:
                self.note(name,False,status=response.status,absence_observed=False)
            time.sleep(.15)

def lease_phase(t,phase):
    parent_ttl=6 if phase=='parent_expiry' else 120;batch_ttl=6 if phase=='batch_expiry' else 60
    parent=t.call(phase+'.parent','POST','auth/token/create',{'policies':[POLICY],'ttl':parent_ttl})['auth']['client_token']
    holders={}
    for kind in ('child','orphan'):
        p=phase+'.'+kind
        result=t.call(p+'.issue','POST','auth/token/'+('create-orphan' if kind=='orphan' else 'create'),
            {'type':'batch','policies':[POLICY],'ttl':batch_ttl},token=parent)
        auth=result.get('auth') or {};raw=auth.get('client_token')
        t.note(p+'.batch',bool(raw) and auth.get('token_type')=='batch' and bool(auth.get('orphan'))==(kind=='orphan'))
        t.bearer(p+'.before',raw)
        token_lookup=t.call(p+'.token_lookup','POST','auth/token/lookup',{'token':raw})
        _,control=t.otp(p+'.control',raw,batch_ttl)
        t.call(p+'.control.verify','POST',SSH+'/verify',{'otp':control},token='')
        lease,otp=t.otp(p+'.held',raw,batch_ttl)
        before=t.lease(p+'.lease_lookup',lease);te=timestamp(token_lookup['data'].get('expire_time'));le=timestamp(before['data'].get('expire_time'))
        t.note(p+'.lease_times',te is not None and le is not None and le<=te+.001,lease_not_after_batch=te is not None and le is not None and le<=te+.001)
        # SSH OTP is nonrenewable. This negative test is not evidence of a
        # successful renewable backend's ceiling calculation.
        t.call(p+'.renew','PUT','sys/leases/renew',{'lease_id':lease,'increment':600},status=400)
        after=t.lease(p+'.renew_lookup',lease)
        t.note(p+'.renew_preserved',before['data'].get('expire_time')==after['data'].get('expire_time'))
        holders[kind]=(raw,lease,otp)
    if phase=='revoke':t.call(phase+'.event','POST','auth/token/revoke',{'token':parent},status=204)
    elif phase=='parent_expiry':t.wait_absent(phase+'.event','auth/token/lookup',{'token':parent})
    else:
        for kind,(raw,_,_) in holders.items():t.wait_absent(phase+'.'+kind+'.event','auth/token/lookup',{'token':raw})
    for kind,(raw,lease,otp) in holders.items():
        p=phase+'.'+kind+'.after';dead=kind=='child' or phase=='batch_expiry'
        if dead:t.wait_absent(p+'.lease_settled','sys/leases/lookup',{'lease_id':lease})
        else:t.lease(p+'.lease_lookup',lease)
        t.bearer(p+'.bearer',raw,status=403 if dead else 200)
        t.call(p+'.verify','POST',SSH+'/verify',{'otp':otp},status=400 if dead else 200,token='')

def extensions(t,restart):
    # Actual identity policies are live, while signed token policies/CIDRs are snapshots.
    t.call('identity.mount','POST','sys/auth/batch-id',{'type':'userpass'},status=204)
    t.call('identity.user','POST','auth/batch-id/users/matrix',{'password':t.password,'token_type':'batch','token_ttl':300},status=204)
    auth=t.login('identity.login',mount='batch-id');raw=auth['client_token'];entity=auth.get('entity_id')
    t.note('identity.entity',isinstance(entity,str) and bool(entity))
    t.bearer('identity.initial_no_policy',raw,status=403)
    t.call('identity.grant','POST','identity/entity/id/'+entity,{'policies':[POLICY]},status=204)
    t.bearer('identity.live_grant',raw)
    t.call('identity.disable','POST','identity/entity/id/'+entity,{'disabled':True},status=204)
    t.bearer('identity.disabled',raw,status=403)
    t.call('identity.enable','POST','identity/entity/id/'+entity,{'disabled':False},status=204)
    t.bearer('identity.restored',raw)
    t.call('identity.policy_remove','POST','identity/entity/id/'+entity,{'policies':[]},status=204)
    t.bearer('identity.policy_denied',raw,status=403)
    t.call('identity.policy_restore','POST','identity/entity/id/'+entity,{'policies':[POLICY]},status=204)
    t.bearer('identity.policy_restored',raw)
    t.call('cidr.user','POST','auth/batch-id/users/matrix',{'token_policies':[POLICY],'token_bound_cidrs':['127.0.0.1/32']},status=204)
    bound=t.login('cidr.login',mount='batch-id')['client_token']
    t.bearer('cidr.allowed',bound)
    t.bearer('cidr.denied_origin',bound,status=403,source='127.0.0.2',spoof=True)
    t.login('cidr.denied_login',mount='batch-id',source='127.0.0.2',status=403)
    t.call('cidr.root_target_lookup','POST','auth/token/lookup',{'token':bound},source='127.0.0.2')
    t.call('cidr.clear_user','POST','auth/batch-id/users/matrix',{'token_bound_cidrs':[]},status=204)
    t.bearer('cidr.cleared_old_snapshot',bound,status=403,source='127.0.0.2',spoof=True)
    unbound=t.login('cidr.new_unbound',mount='batch-id',source='127.0.0.2')['client_token']
    t.bearer('cidr.new_unbound_access',unbound,source='127.0.0.2')
    restart();t.note('cidr.restart',True)
    t.bearer('cidr.restart_denied',bound,status=403,source='127.0.0.2',spoof=True)
    t.bearer('identity.restart_access',raw)

def run(t,restart):
    t.password=secrets.token_urlsafe(28);t.value=secrets.token_urlsafe(32);t.sensitive.extend([t.password,t.value])
    t.call('setup.kv','POST','sys/mounts/'+KV,{'type':'kv','options':{'version':'1'}},status=204)
    t.call('setup.value','POST',KV+'/item',{'value':t.value},status=204)
    t.call('setup.ssh','POST','sys/mounts/'+SSH,{'type':'ssh'},status=204)
    t.call('setup.ssh_tune','POST','sys/mounts/'+SSH+'/tune',{'default_lease_ttl':120,'max_lease_ttl':600},status=204)
    t.call('setup.ssh_role','POST',SSH+'/roles/probe',{'key_type':'otp','default_user':'synthetic','cidr_list':'127.0.0.0/8'},status=204)
    policy=f'path "{KV}/*" {{ capabilities=["read"] }} path "{SSH}/creds/probe" {{ capabilities=["update"] }} path "auth/token/*" {{ capabilities=["read","update","sudo"] }}'
    t.call('setup.policy','PUT','sys/policies/acl/'+POLICY,{'policy':policy},status=204)
    t.call('setup.userpass','POST','sys/auth/'+AUTH,{'type':'userpass'},status=204)
    t.call('setup.user','POST','auth/'+AUTH+'/users/matrix',{'password':t.password,'token_policies':[POLICY],'token_type':'batch','token_ttl':300},status=204)
    raw=t.login('bearer.login')['client_token'];t.bearer('bearer.initial',raw)
    restart();t.note('bearer.restart',True);t.bearer('bearer.after_restart',raw)
    t.call('bearer.delete_user','DELETE','auth/'+AUTH+'/users/matrix',status=204);t.bearer('bearer.after_user_delete',raw)
    t.call('bearer.disable_mount','DELETE','sys/auth/'+AUTH,status=204);t.bearer('bearer.after_disable',raw)
    restart();t.note('bearer.disabled_restart',True);t.bearer('bearer.after_disabled_restart',raw)
    for phase in ('revoke','parent_expiry','batch_expiry'):lease_phase(t,phase)
    extensions(t,restart)
    t.note('receipt.no_secrets',not any(secret in json.dumps(t.rows) for secret in t.sensitive))
    t.note('complete',True)

def complete(rows):
    if not isinstance(rows,list) or not rows:return False
    names=[]
    allowed={'case','scope','passed','status','source_family','absence_observed','lease_not_after_batch','nonrenewable','ttl_matches_batch_window'}
    for row in rows:
        if not isinstance(row,dict) or set(row)-allowed or row.get('passed') is not True:return False
        name=row.get('case')
        if not isinstance(name,str) or not re.fullmatch('[a-z0-9_.]{1,140}',name) or row.get('scope')!=lane(name):return False
        names.append(name)
        if 'status' in row and (type(row['status']) is not int or not 100<=row['status']<=599):return False
        if 'source_family' in row and row['source_family'] not in (4,6):return False
        if any(type(v) is not bool for k,v in row.items() if k not in {'case','scope','status','source_family'}):return False
    return len(names)==len(set(names)) and REQUIRED<=set(names) and names[-1]=='complete'
