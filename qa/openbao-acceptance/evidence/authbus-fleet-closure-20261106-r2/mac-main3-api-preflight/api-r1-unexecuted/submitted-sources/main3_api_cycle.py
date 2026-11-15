#!/usr/bin/env python3
"""Actual three-owner OAuth bytes through isolated canonical HeptaBao APIs.

No provider request or refresh. Credentials and protocol tokens stay in memory
or create-only private recovery state. Public events contain fixed case labels,
route categories, ordinals and status/predicate evidence, never response bodies.
"""
from __future__ import annotations
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import time
from main3_source_fence import CapsuleFence,Refused,need,ident

ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-api-20261106-r1')
MOUNT='openclaw-auth'
MAX_HTTP=192
MAX_BODY=1048576

def private_new(path,value,guard,remaining):
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    need(len(raw)<=MAX_BODY and Path(path).parent==ROOT/'server/private','fixed_private_recovery_output')
    guard.check();remaining(1)
    with guard.parent(path) as (parent,name):
        p=os.fstat(parent);need(stat.S_ISDIR(p.st_mode) and p.st_uid==501 and stat.S_IMODE(p.st_mode)==0o700,'private_recovery_directory')
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        try:
            before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600,'private_recovery_file')
            offset=0
            while offset<len(raw):
                remaining(1)
                count=os.write(fd,raw[offset:]);need(count>0,'private_recovery_write_progress');offset+=count
            os.fsync(fd);os.fsync(parent);after=os.fstat(fd)
            need(ident(before)[:6]==ident(after)[:6] and after.st_size==len(raw)
                 and ident(after)==ident(os.stat(Path(path).name,dir_fd=parent,follow_symlinks=False)),'private_recovery_durable_same_file')
        finally:os.close(fd)
    guard.check();remaining(1)

class Api:
    def __init__(self,plan,phase,phase_until,journal,guard):
        need(phase in ('initial','cold-new-process'),'fixed_api_phase')
        need(type(plan['port']) is int and 1024<=plan['port']<=65535
             and re.fullmatch(r'[0-9a-f]{64}',plan['certificateLeafSha256']),'fixed_owned_tls_endpoint')
        self.plan=plan;self.phase=phase;self.until=phase_until;self.journal=journal;self.guard=guard
        self.context=ssl.create_default_context(cafile=str(ROOT/'server/tls/server.crt'))
        self.rows=[];self.checks=[];self.unknown=False;self.root_token=None;self.sensitive=[]
    def remaining(self,cap):
        left=self.until-time.monotonic();need(left>0,'original_api_phase_120_seconds');return min(left,cap)
    def check(self,case,value):
        need(re.fullmatch(r'[a-z0-9._-]{1,100}',case),'fixed_public_api_case')
        self.checks.append({'case':case,'passed':value is True});need(value is True,case)
    def call(self,case,method,route,body=None,*,expected=200,token=None,category,slot=0,readiness=False):
        self.remaining(1)
        self.guard.check()
        need(not self.unknown and len(self.rows)<MAX_HTTP,'no_http_after_unknown_and_finite_requests')
        need(re.fullmatch(r'[a-z0-9._-]{1,100}',case) and category in ('health','init','unseal','mount','activate','capacity','policy','role','role-id','secret-id','login','kv-read','kv-write','lookup','renew','revoke','secret-destroy','admin-denied'),
             'fixed_public_route_category')
        need(method in ('GET','POST','PUT') and isinstance(route,str) and route.startswith('/v1/')
             and re.fullmatch(r'/[A-Za-z0-9/._-]+',route) and 0<=slot<=3,'fixed_owned_api_route')
        need(not readiness or (method=='GET' and route=='/v1/sys/health' and body is None and token==''),'health_only_tcp_refusal_wait')
        bearer=self.root_token if token is None else token
        need(bearer is None or isinstance(bearer,str) and len(bearer)<=16384 and '\r' not in bearer and '\n' not in bearer,'private_single_line_bearer')
        payload=b'' if body is None else json.dumps(body,separators=(',',':'),ensure_ascii=False).encode()
        need(len(payload)<=MAX_BODY,'bounded_private_request_body')
        row={'phase':self.phase,'ordinal':len(self.rows)+1,'case':case,'routeCategory':category,'slotOrdinal':slot,
             'method':method,'dispatched':False,'responseComplete':False,'outcomeUnknown':False,
             'httpRequestCount':0,'connectionAttempts':0,'connectionRefusals':0,'tlsVerified':False,'socketsClosed':False}
        self.rows.append(row)
        self.journal.append('api-request-intent',dict(row))
        deadline=time.monotonic()+self.remaining(15 if readiness else 10)
        raw=tls=response=None
        def left():
            remaining=min(self.until,deadline)-time.monotonic();need(remaining>0,'one_http_original_absolute_deadline');return remaining
        try:
            for _ in range(256 if readiness else 1):
                row['connectionAttempts']+=1
                try:raw=socket.create_connection(('127.0.0.1',self.plan['port']),timeout=min(5,left()));break
                except ConnectionRefusedError as error:
                    if not readiness or error.errno!=errno.ECONNREFUSED:raise
                    row['connectionRefusals']+=1;time.sleep(min(0.1,left()))
            need(raw is not None,'bounded_health_connection_attempts')
            raw.settimeout(left());tls=self.context.wrap_socket(raw,server_hostname='localhost')
            need(hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()==self.plan['certificateLeafSha256'],'actual_tls_leaf_pin')
            row.update(tlsVerified=True,tlsVersion=tls.version())
            headers=[method+' '+route+' HTTP/1.1','Host: localhost:'+str(self.plan['port']),'Accept: application/json','Connection: close']
            if bearer:headers.append('X-Vault-Token: '+bearer)
            if body is not None:headers+=['Content-Type: application/json','Content-Length: '+str(len(payload))]
            request=('\r\n'.join(headers)+'\r\n\r\n').encode('ascii')+payload
            tls.settimeout(left());row['dispatched']=True;row['httpRequestCount']=1
            tls.sendall(request)
            tls.settimeout(left());response=http.client.HTTPResponse(tls);response.begin()
            row['status']=response.status
            length=response.getheader('Content-Length')
            need(not response.getheader('Transfer-Encoding') and (length is None or re.fullmatch(r'[0-9]{1,9}',length)),
                 'complete_fixed_http_response_framing')
            if response.status==204:
                need(length in (None,'0'),'empty_204_response_frame');amount=0
            else:
                need(length is not None and int(length)<=MAX_BODY,'bounded_content_length_required');amount=int(length)
            tls.settimeout(left());data=response.read(amount+1)
            need(len(data)==amount and response.isclosed(),'complete_http_body_before_acceptance')
            left();row.update(responseComplete=True,responseBytes=len(data))
            value=json.loads(data) if data else {}
        except BaseException as error:
            row['outcomeUnknown']=bool(row['dispatched'] and not row['responseComplete'])
            self.unknown=True;row['errorType']=type(error).__name__
            # Exception messages, response bodies and their hashes stay private.
            raise Refused('api_transport_or_complete_response_failed') from None
        finally:
            if response is not None:response.close()
            if tls is not None:tls.close()
            elif raw is not None:raw.close()
            row['socketsClosed']=True
            self.journal.append('api-request-result',dict(row))
        self.guard.check();self.remaining(1)
        self.check(case,row['status']==expected)
        return value
    def public(self):
        return {'phase':self.phase,'checks':self.checks,'requests':self.rows,'requestCount':len(self.rows),
                'unknownHttpOutcomeCount':sum(r['outcomeUnknown'] for r in self.rows),
                'allDispatchedResponsesComplete':all(not r['dispatched'] or r['responseComplete'] for r in self.rows),
                'allReturnedSocketsClosed':all(r['socketsClosed'] for r in self.rows),
                'credentialValuesOrDigestsPublished':False,'providerValid':False,'providerCalled':False,
                'providerRefreshAttempted':False,'productionCutover':False}

def slot_path(index):return '/v1/'+MOUNT+'/data/selected/main/slot-'+str(index)
def body_for(entry,version):
    return {'ownerAgent':'main','profileId':entry['profileId'],'actualProvider':'openai',
            'credential':entry['credential'],'canaryGeneration':version}
def initial(api,fence):
    fence.observe('before-phase')
    entries=fence.doc['ownerEntries']
    api.check('source.three_expired_real_oauth',sum(e['credential']['expires']<time.time()*1000 for e in entries)==3)
    health=api.call('initial.uninitialized_tls_health','GET','/v1/sys/health',token='',expected=501,category='health',readiness=True)
    api.check('initial.uninitialized_sealed',health.get('initialized') is False and health.get('sealed') is True)
    value=api.call('initial.initialize_once','POST','/v1/sys/init',{'secret_shares':1,'secret_threshold':1},token='',category='init')
    key=value.get('keys_base64',[None])[0];api.root_token=value.get('root_token')
    api.check('initial.private_recovery_material_received',isinstance(key,str) and bool(key) and isinstance(api.root_token,str) and bool(api.root_token))
    state={'rootToken':api.root_token,'unsealKey':key,'roles':[]}
    private_new(ROOT/'server/private/initial-recovery.private.json',state,api.guard,api.remaining)
    unsealed=api.call('initial.unseal','POST','/v1/sys/unseal',{'key':key},token='',category='unseal')
    api.check('initial.actually_unsealed',unsealed.get('sealed') is False)
    api.call('initial.kv2_mount','POST','/v1/sys/mounts/'+MOUNT,{'type':'kv','options':{'version':'2'}},expected=204,category='mount')
    api.call('initial.native_activate_once','POST','/v1/sys/internal/native-v6/activate',{},expected=204,category='activate')
    capacity=api.call('initial.native_capacity','GET','/v1/sys/internal/capacity',category='capacity')
    api.check('initial.native_format_two',capacity.get('data',{}).get('native_kv2_reader_format')==2)
    api.call('initial.approle_mount','POST','/v1/sys/auth/approle',{'type':'approle'},expected=204,category='mount')
    for i,entry in enumerate(entries,1):
        case='slot'+str(i);name='main3-current-slot-'+str(i);base='/v1/auth/approle/role/'+name
        fence.observe('before-canonical-write')
        result=api.call(case+'.root_cas_zero','POST',slot_path(i),{'data':body_for(entry,1),'options':{'cas':0}},category='kv-write',slot=i)
        api.check(case+'.created_version_one',result.get('data',{}).get('version')==1)
        policy='path "'+MOUNT+'/data/selected/main/slot-'+str(i)+'" { capabilities = ["create", "read", "update"] }\n'
        policy+='path "auth/token/lookup-self" { capabilities = ["read"] }\npath "auth/token/renew-self" { capabilities = ["update"] }\npath "auth/token/revoke-self" { capabilities = ["update"] }\n'
        api.call(case+'.scoped_policy','PUT','/v1/sys/policies/acl/'+name,{'policy':policy},expected=204,category='policy',slot=i)
        api.call(case+'.approle_create','POST',base,{'token_policies':[name],'token_ttl':'1200s','token_max_ttl':'1800s','secret_id_num_uses':0,'secret_id_ttl':'3600s'},expected=204,category='role',slot=i)
        role_id=api.call(case+'.role_id','GET',base+'/role-id',category='role-id',slot=i)['data']['role_id']
        secret=api.call(case+'.secret_id','POST',base+'/secret-id',{},category='secret-id',slot=i)['data']['secret_id']
        auth=api.call(case+'.approle_login','POST','/v1/auth/approle/login',{'role_id':role_id,'secret_id':secret},token='',category='login',slot=i)['auth']
        token=auth['client_token']
        api.check(case+'.renewable_service_lease',auth.get('renewable') is True and 0<auth.get('lease_duration',0)<=1800 and name in auth.get('policies',[]))
        state['roles'].append({'name':name,'roleId':role_id,'secretId':secret,'token':token})
        read=api.call(case+'.read_real_credential','GET',slot_path(i),token=token,category='kv-read',slot=i)
        api.check(case+'.private_deep_compare_v1',read.get('data',{}).get('data')==body_for(entry,1))
        other=i%3+1
        api.call(case+'.cross_slot_read_denied','GET',slot_path(other),token=token,expected=403,category='kv-read',slot=i)
        # Denied writes carry only a fixed synthetic marker, never another credential.
        api.call(case+'.cross_slot_write_denied','POST',slot_path(other),{'data':{'deniedProbe':True}},token=token,expected=403,category='kv-write',slot=i)
        api.call(case+'.admin_read_denied','GET','/v1/sys/mounts',token=token,expected=403,category='admin-denied',slot=i)
        lookup=api.call(case+'.lookup_self','GET','/v1/auth/token/lookup-self',token=token,category='lookup',slot=i)
        api.check(case+'.lookup_own_policy',name in lookup.get('data',{}).get('policies',[]) and lookup['data'].get('renewable') is True)
        renewed=api.call(case+'.renew_self','POST','/v1/auth/token/renew-self',{'increment':'1200s'},token=token,category='renew',slot=i)
        api.check(case+'.renewal_preserves_token_and_positive_lease',renewed.get('auth',{}).get('client_token')==token and renewed['auth'].get('renewable') is True and 0<renewed['auth'].get('lease_duration',0)<=1800)
        fence.observe('before-canonical-write')
        changed=api.call(case+'.scoped_cas_one','POST',slot_path(i),{'data':body_for(entry,2),'options':{'cas':1}},token=token,category='kv-write',slot=i)
        api.check(case+'.created_version_two',changed.get('data',{}).get('version')==2)
        api.call(case+'.stale_cas_denied','POST',slot_path(i),{'data':{'staleProbe':True},'options':{'cas':1}},token=token,expected=400,category='kv-write',slot=i)
        read=api.call(case+'.read_after_stale_cas','GET',slot_path(i),token=token,category='kv-read',slot=i)
        api.check(case+'.private_deep_compare_v2',read.get('data',{}).get('data')==body_for(entry,2) and read['data'].get('metadata',{}).get('version')==2)
    private_new(ROOT/'server/private/initial-roles.private.json',state,api.guard,api.remaining)
    fence.observe('after-phase');return state

def cold(api,fence,state):
    fence.observe('before-phase');api.root_token=state['rootToken']
    health=api.call('cold.sealed_tls_health','GET','/v1/sys/health',token='',expected=503,category='health',readiness=True)
    api.check('cold.initialized_sealed_after_restart',health.get('initialized') is True and health.get('sealed') is True)
    unsealed=api.call('cold.unseal_existing_store','POST','/v1/sys/unseal',{'key':state['unsealKey']},token='',category='unseal')
    api.check('cold.actually_unsealed',unsealed.get('sealed') is False)
    capacity=api.call('cold.native_capacity','GET','/v1/sys/internal/capacity',category='capacity')
    api.check('cold.native_format_two_preserved',capacity.get('data',{}).get('native_kv2_reader_format')==2)
    for i,(entry,role) in enumerate(zip(fence.doc['ownerEntries'],state['roles'],strict=True),1):
        case='cold.slot'+str(i);old=role['token'];login={'role_id':role['roleId'],'secret_id':role['secretId']}
        lookup=api.call(case+'.old_lease_lookup','GET','/v1/auth/token/lookup-self',token=old,category='lookup',slot=i)
        api.check(case+'.old_lease_policy_persisted',role['name'] in lookup.get('data',{}).get('policies',[]))
        value=api.call(case+'.old_lease_reads_persisted','GET',slot_path(i),token=old,category='kv-read',slot=i)
        api.check(case+'.old_private_deep_compare_persisted_v2',value.get('data',{}).get('data')==body_for(entry,2) and value['data'].get('metadata',{}).get('version')==2)
        auth=api.call(case+'.fresh_login_after_restart','POST','/v1/auth/approle/login',login,token='',category='login',slot=i)['auth'];new=auth['client_token']
        api.check(case+'.fresh_token_distinct',new!=old and auth.get('renewable') is True)
        value=api.call(case+'.fresh_lease_reads_persisted','GET',slot_path(i),token=new,category='kv-read',slot=i)
        api.check(case+'.fresh_private_deep_compare_persisted_v2',value.get('data',{}).get('data')==body_for(entry,2))
        api.call(case+'.self_revoke_once','POST','/v1/auth/token/revoke-self',{},token=old,expected=204,category='revoke',slot=i)
        api.call(case+'.self_revoked_lookup_denied','GET','/v1/auth/token/lookup-self',token=old,expected=403,category='lookup',slot=i)
        api.call(case+'.self_revoked_kv_denied','GET',slot_path(i),token=old,expected=403,category='kv-read',slot=i)
        api.call(case+'.admin_revoke_new_once','POST','/v1/auth/token/revoke',{'token':new},expected=204,category='revoke',slot=i)
        api.call(case+'.admin_revoked_lookup_denied','GET','/v1/auth/token/lookup-self',token=new,expected=403,category='lookup',slot=i)
        api.call(case+'.admin_revoked_kv_denied','GET',slot_path(i),token=new,expected=403,category='kv-read',slot=i)
        api.call(case+'.destroy_secret_id_once','POST','/v1/auth/approle/role/'+role['name']+'/secret-id/destroy',{'secret_id':role['secretId']},expected=204,category='secret-destroy',slot=i)
        api.call(case+'.destroyed_secret_login_denied','POST','/v1/auth/approle/login',login,token='',expected=400,category='login',slot=i)
    fence.observe('after-phase')
