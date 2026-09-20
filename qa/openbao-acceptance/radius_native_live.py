#!/usr/bin/env python3
"""Selected native RADIUS configuration/users behavior over real HTTPS and UDP.

Compares a candidate with pinned OpenBao 2.6.2 using synthetic PAP accounts.
The candidate still requires a process-enrolled address and strict response MA.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import tempfile
import threading
import time

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import start_oracle, stop_oracle, restart_oracle, BINARY_SHA256
from online_evidence import admit_output, source_identity
from radius_renewal_live import SECRET, PASSWORD, md5, renewal_token_shape, wrapped_renewal_shape
from remote_jwks_live import Instance

ADAPTATION = {
    'candidate': 'same native host/port/secret API; UDP address must be process-enrolled, with no process secret or ambient DNS',
    'oracle': 'native API host/port/secret without process address enrollment',
    'request_message_authenticator': 'candidate mandatory; official 2.6.2 PAP omits it',
    'response': 'both receive signed Response-Authenticator and Message-Authenticator',
    'bounds': 'candidate timeouts 0..60 seconds, secret 1..256 bytes, PAP username 1..253 and password 1..128 bytes, NAS-Identifier <=253 bytes',
    'numeric': 'common stored i64 NAS-Port behavior tested; invalid port transport failures and numeric overflow are not full API parity claims',
    'excluded': 'arbitrary DNS/destinations, CIDR/strict-IP/batch token parameters, non-PAP authentication, independent production RADIUS server qualification',
    'configuration_api_parity': False,
}


def pap_response(packet, *, require_ma, secret, username, password, allow, nas_port, nas_identifier):
    if len(packet)<20 or len(packet)>4096 or packet[0]!=1 or struct.unpack('!H',packet[2:4])[0]!=len(packet):
        raise ValueError('invalid_radius_request')
    values={};signed=bytearray(packet);offset=20
    while offset<len(packet):
        if len(packet)-offset<2:raise ValueError('invalid_radius_attribute')
        kind,length=packet[offset:offset+2]
        if length<2 or length>len(packet)-offset:raise ValueError('invalid_radius_attribute')
        if kind in values:raise ValueError('duplicate_radius_attribute')
        values[kind]=packet[offset+2:offset+length]
        if kind==80:
            if length!=18:raise ValueError('invalid_radius_authenticator')
            signed[offset+2:offset+length]=b'\0'*16
        offset+=length
    ma=80 in values
    if (require_ma and not ma) or (ma and not hmac.compare_digest(values[80],hmac.new(secret,signed,hashlib.md5).digest())):
        raise ValueError('invalid_radius_authenticator')
    encrypted=values.get(2,b'')
    if not encrypted or len(encrypted)>128 or len(encrypted)%16:raise ValueError('invalid_pap_shape')
    clear=bytearray();previous=packet[4:20]
    for offset in range(0,len(encrypted),16):
        block=encrypted[offset:offset+16];clear.extend(a^b for a,b in zip(block,md5(secret,previous)));previous=block
    valid=values.get(1)==username and hmac.compare_digest(bytes(clear).rstrip(b'\0'),password)
    clear[:]=b'\0'*len(clear)
    accepted=valid and allow
    nas_ok=(values.get(5)==struct.pack('!I',nas_port & 0xffffffff) and values.get(32)==nas_identifier)
    response=bytearray([2 if accepted else 3,packet[1],0,38]);response.extend(packet[4:20]);response.extend([80,18]);response.extend(b'\0'*16)
    response[22:]=hmac.new(secret,response,hashlib.md5).digest()
    response[4:20]=md5(response[:4],packet[4:20],response[20:],secret)
    return bytes(response),{'credentials_valid':valid,'message_authenticator_present':ma,'accepted':accepted,'nas_valid':nas_ok}


class NativeRadius:
    def __init__(self, *, require_ma):
        self.require_ma=require_ma;self.secret=SECRET;self.username=b'alice';self.nas_port=10;self.nas_identifier=None;self.allow=True
        self.requests=[];self.lock=threading.Lock();self.stopped=threading.Event()
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.socket.bind(('127.0.0.1',0));self.socket.settimeout(.2)
        self.port=self.socket.getsockname()[1];self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        while not self.stopped.is_set():
            try:
                packet,source=self.socket.recvfrom(4097)
                response,observed=pap_response(packet,require_ma=self.require_ma,secret=self.secret,username=self.username,password=PASSWORD,allow=self.allow,nas_port=self.nas_port,nas_identifier=self.nas_identifier)
                with self.lock:self.requests.append(observed)
                self.socket.sendto(response,source)
            except TimeoutError:continue
            except ValueError:continue
            except OSError:break
    def count(self):
        with self.lock:return len(self.requests)
    def observed(self,start,*,accepted):
        with self.lock:
            rows=self.requests[start:]
            return bool(rows) and all(row=={'credentials_valid':True,'message_authenticator_present':self.require_ma,'accepted':accepted,'nas_valid':True} for row in rows)
    def close(self):
        self.stopped.set();self.socket.close();self.thread.join(timeout=5)
        if self.thread.is_alive():raise ScenarioFailure('radius_native.provider_shutdown')


def config_matches(data, **fields):
    return 'secret' not in data and all(type(data.get(k)) is type(v) and data[k]==v for k,v in fields.items())


class Trace:
    def __init__(self,client,provider,rows):self.client,self.provider,self.rows=client,provider,rows;self.tokens=[]
    def check(self,name,passed,**safe):
        if not re.fullmatch(r'[a-z0-9_.]{1,140}',name) or any(type(v) not in (bool,int) for v in safe.values()):
            raise ValueError('unsafe_trace_field')
        case='radius_native.'+name;self.rows.append({'case':case,**safe,'passed':bool(passed)})
        if not passed:raise ScenarioFailure(case)
    def call(self,name,method,path,body=None,token=None,expected=200,contact=None,wrap_ttl=None):
        before=self.provider.count();r=self.client.request(method,'/v1/'+path,body,token=token,wrap_ttl=wrap_ttl)
        safe={'status':r.status};passed=r.status==expected
        if contact is not None:safe['provider_checked']=self.provider.observed(before,accepted=contact);passed &= safe['provider_checked']
        self.check(name,passed,**safe);return r.body
    def config(self,name,body,expected=204):return self.call(name,'POST','auth/radius/config',body,expected=expected)
    def read(self,name):return self.call(name,'GET','auth/radius/config').get('data',{})
    def login(self,name,path='auth/radius/login',body=None,policies=None,expected=200,username='alice'):
        body={'username':username,'password':PASSWORD.decode()} if body is None else body
        auth=self.call(name,'POST',path,body,token='',expected=expected,contact=expected==200).get('auth',{})
        if expected==200:
            token=auth.get('client_token');self.check(name+'.token',isinstance(token,str) and bool(token) and isinstance(auth.get('entity_id'),str) and bool(auth['entity_id']))
            self.tokens.append(token)
            if policies is not None:self.check(name+'.policies',set(auth.get('token_policies',[]))==set(policies))
            self.check(name+'.metadata_username',auth.get('metadata',{}).get('username')==username)
        return auth

    def lookup_metadata(self,name,auth):
        for via,method,path,body,token in [
            ('self','GET','auth/token/lookup-self',None,auth['client_token']),
            ('token','POST','auth/token/lookup',{'token':auth['client_token']},None),
            ('accessor','POST','auth/token/lookup-accessor',{'accessor':auth['accessor']},None),
        ]:
            data=self.call(name+'.'+via,method,path,body,token=token).get('data',{})
            self.check(name+'.'+via+'.meta',isinstance(auth.get('metadata'),dict)
                       and data.get('meta')==auth['metadata'])


def token_policy_shape(auth, expected):
    return isinstance(auth,dict) and auth.get('policies')==expected and (
        auth.get('token_policies')==expected if expected else 'token_policies' not in auth)


def run_no_default_scenarios(trace,restart):
    call,check=trace.call,trace.check
    mount='radius-nodefault';provider=trace.provider
    call('nodefault.mount','POST','sys/auth/'+mount,{'type':'radius'},expected=204)
    def config(label,**fields):
        call('nodefault.'+label,'POST','auth/'+mount+'/config',fields,expected=204)
    def flag(label,expected):
        data=call('nodefault.'+label,'GET','auth/'+mount+'/config').get('data',{})
        check('nodefault.'+label+'.flag',config_matches(data,token_no_default_policy=expected))
    def login(label,policies):
        auth=trace.login('nodefault.'+label,path='auth/'+mount+'/login',policies=policies)
        check('nodefault.'+label+'.policy_shape',token_policy_shape(auth,policies))
        return auth
    def renew(label,auth,policies,via):
        route,body,actor={
            'self':('renew-self',{},auth['client_token']),
            'token':('renew',{'token':auth['client_token']},None),
            'accessor':('renew-accessor',{'accessor':auth['accessor']},None),
        }[via]
        result=call('nodefault.'+label+'.renew_'+via,'POST','auth/token/'+route,dict(body,increment=240),token=actor,contact=True)
        renewed=result.get('auth',{})
        check('nodefault.'+label+'.renew_'+via+'.snapshot',token_policy_shape(renewed,policies)
              and renewal_token_shape(renewed,auth['client_token'],via_accessor=via=='accessor'))
    config('initial',host='127.0.0.1',port=provider.port,secret=provider.secret.decode(),
           token_ttl=120,token_max_ttl=600,nas_port=provider.nas_port,token_policies=[])
    flag('initial_read',False)
    default=login('default',['default'])
    config('true',token_no_default_policy=True)
    bare=login('bare',[])
    before=provider.count()
    call('nodefault.bare.self_lookup_denied','GET','auth/token/lookup-self',token=bare['client_token'],expected=403)
    call('nodefault.bare.self_renew_denied','POST','auth/token/renew-self',{},token=bare['client_token'],expected=403)
    check('nodefault.bare.no_default_authority',provider.count()==before)
    data=call('nodefault.bare.lookup','POST','auth/token/lookup',{'token':bare['client_token']}).get('data',{})
    check('nodefault.bare.lookup_policies',data.get('policies')==[])
    for via in ('token','accessor'):renew('bare',bare,[],via)
    renew('old_default',default,['default'],'self')
    config('explicit_config',token_policies=['default']);login('explicit',['default'])
    config('fallback_config',token_policies=[],unregistered_user_policies='default');login('fallback',['default'])
    config('empty_fallback',unregistered_user_policies='')
    config('false',token_no_default_policy=False);flag('false_read',False)
    login('after_false',['default']);renew('bare_after_false',bare,[],'token')
    call('nodefault.policy','PUT','sys/policies/acl/nodefault-renew',{'policy':
         'path "auth/token/renew-self" { capabilities = ["update"] } path "auth/token/lookup-self" { capabilities = ["read"] }'},expected=204)
    config('mapped',token_policies=['nodefault-renew'])
    original=login('original',['default','nodefault-renew'])
    config('mapped_true',token_no_default_policy=True)
    issued=login('issued',['nodefault-renew'])
    config('partial',token_ttl=121);flag('partial_read',True)
    config('null',token_no_default_policy=None);flag('null_read',False)
    login('after_null',['default','nodefault-renew'])
    config('before_restart',token_no_default_policy=True)
    restart();check('nodefault.restart',True);flag('restart_read',True)
    trace.lookup_metadata('nodefault.reopened_lookup',issued)
    login('reopened_login',['nodefault-renew'])
    for label,fields in [('toggle_false',{'token_no_default_policy':False}),
                         ('add_default',{'token_no_default_policy':True,'token_policies':['default','nodefault-renew']}),
                         ('remove_default',{'token_policies':['nodefault-renew']})]:
        config(label,**fields)
        for name,auth,policies in [('old',original,['default','nodefault-renew']),('new',issued,['nodefault-renew'])]:
            for via in ('self','token','accessor'):renew(label+'.'+name,auth,policies,via)
    config('real_policy_change',token_policies=['different'])
    before=call('nodefault.changed.before','GET','auth/token/lookup-self',token=issued['client_token'])['data']['ttl']
    call('nodefault.changed.rejected','POST','auth/token/renew',{'token':issued['client_token'],'increment':300},expected=500,contact=True)
    after=call('nodefault.changed.after','GET','auth/token/lookup-self',token=issued['client_token'])['data']['ttl']
    check('nodefault.changed.no_extension',type(before) is int and type(after) is int and 0<after<=before)
    # A fresh omitted token_policies slice is nil upstream; an explicit [] or
    # null materializes an empty slice. EquivalentPolicies treats them differently.
    for label,value in [('empty',[]),('null',None)]:
        m='radius-nodefault-nil-'+label
        call('nodefault.nil_'+label+'.mount','POST','sys/auth/'+m,{'type':'radius'},expected=204)
        call('nodefault.nil_'+label+'.config','POST','auth/'+m+'/config',{
            'host':'127.0.0.1','port':provider.port,'secret':provider.secret.decode(),
            'token_no_default_policy':True,'token_ttl':120,'token_max_ttl':600,'nas_port':provider.nas_port},expected=204)
        auth=trace.login('nodefault.nil_'+label+'.login',path='auth/'+m+'/login',policies=[])
        call('nodefault.nil_'+label+'.rejected','POST','auth/token/renew',
             {'token':auth['client_token'],'increment':240},expected=500,contact=True)
        call('nodefault.nil_'+label+'.materialize','POST','auth/'+m+'/config',{'token_policies':value},expected=204)
        body=call('nodefault.nil_'+label+'.accepted','POST','auth/token/renew',
             {'token':auth['client_token'],'increment':240},contact=True)
        check('nodefault.nil_'+label+'.empty_snapshot',token_policy_shape(body.get('auth'),[]))
    check('nodefault.complete',True)


def run_scenarios(trace,restart):
    call,check,config,read,login=trace.call,trace.check,trace.config,trace.read,trace.login
    provider=trace.provider
    call('preconfig.mount','POST','sys/auth/radius-preconfig',{'type':'radius'},expected=204)
    call('preconfig.user_write','POST','auth/radius-preconfig/users/alice',{'policies':['preconfig']},expected=204)
    data=call('preconfig.user_read','GET','auth/radius-preconfig/users/alice').get('data',{})
    check('preconfig.user_fields',data.get('policies')==['preconfig'])
    check('preconfig.list_fields',call('preconfig.list','LIST','auth/radius-preconfig/users').get('data',{}).get('keys')==['alice'])
    call('preconfig.delete_last','DELETE','auth/radius-preconfig/users/alice',expected=204)
    call('preconfig.deleted_read','GET','auth/radius-preconfig/users/alice',expected=404)
    call('preconfig.config','POST','auth/radius-preconfig/config',{'host':'127.0.0.1','port':provider.port,'secret':provider.secret.decode()},expected=204)
    login('preconfig.login',path='auth/radius-preconfig/login',policies=['default'])
    check('preconfig.complete',True)
    call('mount','POST','sys/auth/radius',{'type':'radius'},expected=204)
    call('defaults_mount','POST','sys/auth/radius-defaults',{'type':'radius'},expected=204)
    call('defaults_only_required','POST','auth/radius-defaults/config',{'host':'LOCALHOST','secret':provider.secret.decode()},expected=204)
    default=call('defaults_only_required_read','GET','auth/radius-defaults/config').get('data',{})
    check('defaults_host_lower_port1812',default.get('host')=='localhost' and default.get('port')==1812)
    config('initial',{'host':'127.0.0.1','port':provider.port,'secret':provider.secret.decode()})
    data=read('defaults')
    check('default_values',all(data.get(k)==v for k,v in {'port':provider.port,'dial_timeout':10,'read_timeout':10,'nas_port':10,'nas_identifier':'','unregistered_user_policies':[],'token_policies':[]}.items()))
    check('secret_omitted','secret' not in data and provider.secret.decode() not in json.dumps(data))
    a=login('absent_empty_fallback',policies=['default']);check('absent_metadata_policies_empty',a.get('metadata',{}).get('policies')=='')
    config('partial',{'token_policies':['base'],'unregistered_user_policies':'fallback','token_ttl':60,'token_max_ttl':600})
    data=read('partial_read');check('partial_host_secret_preserved',data.get('host')=='127.0.0.1' and data.get('port')==provider.port)
    a=login('fallback',policies=['base','default','fallback']);check('fallback_metadata',a.get('metadata',{}).get('policies')=='fallback')
    for field in ['host','secret']:
        for value,label in [(None,'null'),('','empty')]:config(field+'.'+label,{field:value},expected=400)
    config('null_port',{'port':None});check('null_port_zero',read('null_port_read').get('port')==0)
    config('restore_port',{'port':provider.port})
    config('timeouts_set',{'dial_timeout':3,'read_timeout':3})
    config('timeouts_null',{'dial_timeout':None,'read_timeout':None})
    data=read('timeouts_null_read');check('timeouts_null_preserve',data.get('dial_timeout')==3 and data.get('read_timeout')==3)
    config('nas_set',{'nas_port':12345,'nas_identifier':'synthetic-nas'})
    provider.nas_port=12345;provider.nas_identifier=b'synthetic-nas';login('nas_attributes',policies=['base','default','fallback'])
    config('nas_null',{'nas_port':None,'nas_identifier':None})
    provider.nas_port=0;provider.nas_identifier=None
    data=read('nas_null_read');check('nas_null_zero_empty',data.get('nas_port')==0 and data.get('nas_identifier')=='');login('nas_null_packet',policies=['base','default','fallback'])
    for value,label in [('', 'empty'),(None,'null')]:
        config('fallback_'+label,{'unregistered_user_policies':value});check('fallback_'+label+'_read',read('fallback_'+label+'_get').get('unregistered_user_policies')==[])
    config('fallback_csv',{'unregistered_user_policies':' Fallback ,fallback,other '})
    data=read('fallback_csv_get');check('fallback_csv_raw_preserved',data.get('unregistered_user_policies')==[' Fallback ','fallback','other '])
    raw_fallback=login('fallback_raw_login',policies=['base','default','fallback','other'])
    check('fallback_raw_metadata',raw_fallback.get('metadata',{}).get('policies')==' Fallback ,fallback,other ')
    call('fallback_raw_renew','POST','auth/token/renew-self',{'increment':120},token=raw_fallback['client_token'],expected=500,contact=True)
    config('fallback_restore',{'unregistered_user_policies':'fallback'})
    call('map_alice','POST','auth/radius/users/alice',{'policies':' MAPPED, mapped '},expected=204)
    data=call('map_case_read','GET','auth/radius/users/ALICE').get('data',{});check('map_policy_normalized',data.get('policies')==['mapped'])
    a=login('mapped',policies=['base','default','mapped']); target=a['client_token'];check('mapped_metadata',a.get('metadata',{}).get('policies')=='mapped')
    call('map_upper_literal','POST','auth/radius/users/ALICE',{'policies':['upper']},expected=204)
    data=call('map_upper_read','GET','auth/radius/users/ALICE').get('data',{});check('upper_write_not_lower_read',data.get('policies')==['mapped'])
    data=call('map_list','LIST','auth/radius/users').get('data',{});check('list_preserves_two_keys',data.get('keys')==['ALICE','alice'])
    data=call('map_list_page','LIST','auth/radius/users',{'after':'ALICE','limit':1}).get('data',{});check('list_body_parameters_ignored',data.get('keys')==['ALICE','alice'])
    data=call('map_list_query_page','LIST','auth/radius/users?after=ALICE&limit=1').get('data',{});check('list_query_after_limit',data.get('keys')==['alice'])
    call('map_upper_delete','DELETE','auth/radius/users/ALICE',expected=204)
    check('upper_delete_keeps_lower',call('map_after_upper_delete','GET','auth/radius/users/alice').get('data',{}).get('policies')==['mapped'])
    call('map_lower_delete','DELETE','auth/radius/users/alice',expected=204)
    call('map_deleted_read','GET','auth/radius/users/alice',expected=404)
    call('deleted_map_renew','POST','auth/token/renew-self',{'increment':120},token=target,expected=500,contact=True)
    login('deleted_map_new_login',policies=['base','default','fallback'])
    config('fallback_matches_old',{'unregistered_user_policies':'mapped'})
    call('deleted_map_same_policy_renew','POST','auth/token/renew-self',{'increment':120},token=target,contact=True)
    provider.allow=False
    call('provider_reject_renew','POST','auth/token/renew-self',{'increment':120},token=target,expected=400,contact=False)
    provider.allow=True
    for payload,label in [({},'omitted'),({'policies':None},'null'),({'policies':[]},'empty')]:
        call('map_reset_'+label,'POST','auth/radius/users/alice',payload,expected=204)
        check('map_reset_'+label+'_empty',call('map_reset_'+label+'_read','GET','auth/radius/users/alice').get('data',{}).get('policies')==[])
        login('empty_map_'+label,policies=['base','default'])
    call('map_root_denied','POST','auth/radius/users/alice',{'policies':['root']},expected=400)
    # Framework TypeString keeps the path value for null/empty body fields,
    # converts integer 123 to '123' and false to '0'; observed on official 2.6.2.
    for label,path,extra,username in [
        ('url_username','alice',{},'alice'),
        ('username_null','alice',{'username':None},'alice'),
        ('username_empty','alice',{'username':''},'alice'),
        ('username_integer','alice',{'username':123},'123'),
        ('username_false','alice',{'username':False},'0'),
        ('body_precedence','ignored',{'username':'alice'},'alice'),
    ]:
        provider.username=username.encode();cursor=provider.count()
        auth=login(label,path='auth/radius/login/'+path,body=dict(extra,password=PASSWORD.decode()),
                   username=username,policies=['base','default'] if username=='alice' else ['base','default','mapped'])
        check(label+'.pap_once',provider.count()==cursor+1)
        check(label+'.metadata_policy',auth.get('metadata',{}).get('policies')==('' if username=='alice' else 'mapped'))
        trace.lookup_metadata(label+'.lookup',auth)
    provider.username=b'alice'
    provider.username=b'ALICE';login('case_preserved_to_provider',username='ALICE',policies=['base','default'])
    provider.username=b'alice'
    new_secret=b'synthetic-radius-rotated-secret'
    config('secret_rotate',{'secret':new_secret.decode()});provider.secret=new_secret
    rotated=login('secret_rotated_packet',policies=['base','default'])
    call('secret_rotated_renew','POST','auth/token/renew-self',{'increment':120},token=rotated['client_token'],contact=True)
    check('secret_rotation_read_redacted','secret' not in read('secret_rotation_read'))
    call('config_delete','DELETE','auth/radius/config',expected=405)
    check('configuration_users.complete',True)
    for via,path,body,caller in [('self','auth/token/renew-self',{},rotated['client_token']),('token','auth/token/renew',{'token':rotated['client_token']},None),('accessor','auth/token/renew-accessor',{'accessor':rotated['accessor']},None)]:
        response=call('renew.'+via,'POST',path,dict(body,increment=120),token=caller,contact=True)
        check('renew.'+via+'.shape',response.get('auth',{}).get('lease_duration')==120 and renewal_token_shape(response.get('auth'),rotated['client_token'],via_accessor=via=='accessor'))
    wrapped=call('wrap.accepted','POST','auth/token/renew-self',{'increment':120},token=rotated['client_token'],contact=True,wrap_ttl='60s')
    check('wrap.outer',wrapped_renewal_shape(wrapped,rotated['client_token']))
    wrapper=wrapped['wrap_info']['token'];trace.tokens.append(wrapper)
    unwrapped=call('wrap.unwrap','POST','sys/wrapping/unwrap',token=wrapper)
    check('wrap.inner',renewal_token_shape(unwrapped.get('auth'),rotated['client_token'],via_accessor=False))
    call('wrap.single_use','POST','sys/wrapping/unwrap',token=wrapper,expected=400)
    before=call('denied.before','GET','auth/token/lookup-self',token=rotated['client_token']).get('data',{}).get('ttl')
    provider.allow=False
    rejected=call('denied.wrapped','POST','auth/token/renew-self',{'increment':300},token=rotated['client_token'],contact=False,expected=400,wrap_ttl='60s')
    after=call('denied.after','GET','auth/token/lookup-self',token=rotated['client_token']).get('data',{}).get('ttl')
    check('denied.no_wrapper_or_extension',not rejected.get('auth') and not rejected.get('wrap_info') and type(before) is int and type(after) is int and 0<after<=before)
    provider.allow=True
    config('timeout.zero',{'read_timeout':0});cursor=provider.count()
    call('timeout.zero_denied','POST','auth/radius/login',{'username':'alice','password':PASSWORD.decode()},token='',expected=400)
    check('timeout.zero_no_packet',provider.count()==cursor)
    config('timeout.restore',{'read_timeout':3})
    restart();check('restart.same_store',True)
    trace.lookup_metadata('restart.lookup',rotated)
    check('restart.secret_redacted',config_matches(read('restart.config'),host='127.0.0.1',port=provider.port,nas_port=0,nas_identifier=''))
    login('restart.login',policies=['base','default'])
    response=call('restart.renew','POST','auth/token/renew-self',{'increment':120},token=rotated['client_token'],contact=True)
    check('restart.renew_shape',response.get('auth',{}).get('lease_duration')==120 and renewal_token_shape(response.get('auth'),rotated['client_token'],via_accessor=False))
    entity=call('identity.read','GET','identity/entity/id/'+rotated['entity_id']).get('data',{})
    check('identity.alias',any(alias.get('name')=='alice' for alias in entity.get('aliases',[])))
    run_no_default_scenarios(trace,restart)
    check('receipt.no_sensitive_values',not any(secret in json.dumps(trace.rows) for secret in [SECRET.decode(),PASSWORD.decode(),provider.secret.decode(),*trace.tokens]))
    check('complete',True)


MILESTONES={
    'preconfig.complete','preconfig.login.token','configuration_users.complete','defaults_host_lower_port1812',
    'fallback_raw_renew','map_reset_omitted_empty','upper_delete_keeps_lower','list_query_after_limit',
    'deleted_map_renew','deleted_map_same_policy_renew','nas_attributes','nas_null_packet',
    'body_precedence.token','case_preserved_to_provider.token','secret_rotated_renew',
    'username_null.pap_once','username_empty.pap_once','username_integer.pap_once','username_false.pap_once',
    'url_username.lookup.self.meta','body_precedence.lookup.token.meta','username_false.lookup.accessor.meta',
    'restart.lookup.self.meta','restart.lookup.token.meta','restart.lookup.accessor.meta',
    'renew.accessor.shape','wrap.inner','wrap.single_use','denied.no_wrapper_or_extension',
    'nodefault.bare.policy_shape','nodefault.bare.no_default_authority','nodefault.partial_read.flag',
    'nodefault.null_read.flag','nodefault.restart_read.flag','nodefault.reopened_login.policy_shape',
    'nodefault.add_default.new.renew_accessor.snapshot','nodefault.remove_default.old.renew_self.snapshot',
    'nodefault.changed.no_extension','nodefault.nil_empty.rejected','nodefault.nil_empty.empty_snapshot',
    'nodefault.nil_null.rejected','nodefault.nil_null.empty_snapshot','nodefault.complete',
    'timeout.zero_no_packet','restart.renew_shape','identity.alias','receipt.no_sensitive_values','complete',
}

def complete_scenarios(rows):
    if not rows or any(row.get('passed') is not True for row in rows):return False
    names=[row.get('case') for row in rows]
    if any(not isinstance(name,str) for name in names) or len(names)!=len(set(names)):return False
    return {'radius_native.'+name for name in MILESTONES}.issubset(names) and names[-1]=='radius_native.complete'


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary');parser.add_argument('--build-source-commit');parser.add_argument('--oracle-only',action='store_true');parser.add_argument('--output',required=True)
    args=parser.parse_args()
    if not args.oracle_only and (not args.binary or not args.build_source_commit or re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit) is None):parser.error('candidate binary and full build source commit required')
    binary=Path(args.binary or os.environ['HB_ORACLE_BINARY']).resolve(strict=True)
    output=Path(args.output).absolute();admitted=admit_output(output);before=source_identity(ROOT,binary)
    runner=Path(__file__);runner_hash=file_hash(runner)
    root=Path(tempfile.mkdtemp(prefix='heptabao-radius-native-'));root.chmod(0o700)
    oracle=instance=None;providers=[]
    report={'schema':'heptabao.radius-native-comparison.v1','target_version':'2.6.2','synthetic_only':True,'actual_https_udp':True,
            'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False,
            'configuration_adaptation':ADAPTATION,'oracle_binary_sha256':BINARY_SHA256,'candidate_binary_sha256':None if args.oracle_only else file_hash(binary),
            'build_source_commit':None if args.oracle_only else args.build_source_commit,
            'build_source_binding_basis':'caller-supplied commit and observed binary hash; not independent attestation',
            'harness_source_commit':before['source_commit'],'harness_source_dirty':before['source_dirty'],
            'source_identity':before,'runner_sha256':runner_hash,'started_at_unix':time.time(),'cases':{},'side_failures':{}}
    try:
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        oracle=start_oracle(port);reference=Client(oracle['address'],oracle['ca_file'],private_read(oracle['token_file']).decode().strip())
        def restart_reference():
            oracle['process'].kill();oracle['process'].wait(timeout=5);stop_oracle(oracle);restart_oracle(oracle)
        sides=[]
        if not args.oracle_only:
            instance=Instance(binary,root/'candidate');provider=NativeRadius(require_ma=True);providers.append(provider)
            cfg=json.loads((instance.root/'server.json').read_text());cfg['lifecycle_interval_seconds']=0
            cfg['outbound_endpoints']=[{'origin':f'radius://127.0.0.1:{provider.port}','address':f'127.0.0.1:{provider.port}','server_name':'127.0.0.1','ca_pem':'','path_prefix':'/'}]
            private_write(instance.root/'server.json',cfg,replace=True)
            instance.start();status,initialized=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
            if status!=200:raise ScenarioFailure('radius_native.candidate_init')
            instance.token,key=initialized['root_token'],initialized['keys_base64'][0]
            if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ScenarioFailure('radius_native.candidate_unseal')
            candidate=Client(instance.address,str(instance.root/'ca.crt'),instance.token)
            def restart_candidate():
                instance.stop();instance.start()
                if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ScenarioFailure('radius_native.candidate_reopen')
            sides.append(('candidate',candidate,provider,restart_candidate))
        provider=NativeRadius(require_ma=False);providers.append(provider);sides.append(('oracle',reference,provider,restart_reference))
        for side,client,provider,restart in sides:
            rows=report['cases'][side]=[]
            try:run_scenarios(Trace(client,provider,rows),restart)
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
