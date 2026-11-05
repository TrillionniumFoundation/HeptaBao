#!/usr/bin/env python3
"""Actual owned Agent/Proxy processes: 2.7.1 header/quit and real PG lease cache.

No production configuration, provider OAuth refresh or existing database is used.
The bounded online lease cache is not full OpenBao cache renewal/watch parity.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'clients/python'))
sys.path.insert(0,str(ROOT/'qa/openbao-acceptance'))
from heptabao.transport import BaoError, Client, private_write
from official_openbao_launcher import start_oracle, stop_oracle
from postgres_live import Postgres, Instance, free_loopback_port


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class SlowTLSRelay:
    """Owned relay of the real backend response, trickling only the KV read."""
    def __init__(self,address,ca,tls_root):
        self.upstream=urlsplit(address);self.port=free_loopback_port()
        self.stop_event=threading.Event();self.dripping=threading.Event()
        self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(tls_root/'tls.crt'),str(tls_root/'tls.key'))
        self.upstream_context=ssl.create_default_context(cafile=ca)
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',self.port))
        self.listener.listen(8);self.listener.settimeout(.2)
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()

    def run(self):
        while not self.stop_event.is_set():
            try:raw,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:break
            with raw:
                try:
                    raw.settimeout(3)
                    with self.context.wrap_socket(raw,server_side=True) as local:
                        request=b''
                        while b'\r\n\r\n' not in request:
                            part=local.recv(4096)
                            if not part:raise OSError('relay peer closed')
                            request+=part
                            if len(request)>32768:raise ValueError('bounded_relay')
                        head,body=request.split(b'\r\n\r\n',1)
                        lengths=[int(line.split(b':',1)[1].strip()) for line in head.split(b'\r\n')[1:] if line.lower().startswith(b'content-length:')]
                        length=lengths[0] if lengths else 0
                        if length>262144:raise ValueError('bounded_relay')
                        while len(body)<length:
                            part=local.recv(length-len(body))
                            if not part:raise OSError('relay peer closed')
                            body+=part
                        with socket.create_connection((self.upstream.hostname,self.upstream.port),timeout=3) as upstream_raw:
                            with self.upstream_context.wrap_socket(upstream_raw,server_hostname=self.upstream.hostname) as upstream:
                                upstream.settimeout(3);upstream.sendall(head+b'\r\n\r\n'+body)
                                response=b''
                                while True:
                                    part=upstream.recv(65536)
                                    if not part:break
                                    response+=part
                                    if len(response)>1048576:raise ValueError('bounded_relay')
                        if head.startswith(b'GET /v1/apps/data/item '):
                            response_head,response_body=response.split(b'\r\n\r\n',1)
                            local.sendall(response_head+b'\r\n\r\n');self.dripping.set()
                            for byte in response_body:
                                if self.stop_event.wait(.08):break
                                local.sendall(bytes([byte]))
                        else:local.sendall(response)
                except (OSError,ValueError):pass

    def close(self):
        self.stop_event.set();self.listener.close();self.thread.join(4)
        if self.thread.is_alive():raise RuntimeError('owned_relay_failed_to_join')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend',choices=['oracle','candidate'],required=True)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--postgres-bin',type=Path,default=Path('/usr/lib/postgresql/17/bin'))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--skip-postgres',action='store_true',help='Only actual owner/header/quit scope; no PG/cache qualification')
    args=parser.parse_args()
    if args.output.exists() or not args.output.is_absolute() or args.output.parent.stat().st_mode&0o077:
        parser.error('new output in owned private directory required')
    root=Path(tempfile.mkdtemp(prefix='heptabao-owned-local-api-'));root.chmod(0o700)
    cases=[];processes=[];logs=[];oracle=None;instance=None;pg=None;relay=None
    report={'schema':'heptabao.agent-proxy-actual-runtime.v1','status':'failed','cases':cases,
            'backend':args.backend,'production_authority':False,'provider_oauth_refresh':False,
            'real_process_owner':True,'real_postgresql':False,'postgres_explicitly_skipped':args.skip_postgres,'full_agent_feature_parity':False,
            'full_managed_lease_cache_parity':False,'python_version':platform.python_version(),
            'platform':platform.platform(),'owner_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
            'owner_tree':subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True).strip(),
            'owner_dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),
            'owner_source_sha256':{n:digest(ROOT/'clients/python/heptabao'/n) for n in ('agent.py','proxy.py','local_api.py','deadline_transport.py')},
            'runner_sha256':digest(__file__),'upstream_binary_sha256':digest(args.binary)}
    def check(name,value):
        cases.append({'case':name,'passed':value is True})
        if value is not True:raise RuntimeError(name)
    def wait(predicate,timeout=8):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            try:
                if predicate():return True
            except (OSError,ValueError,KeyError):pass
            time.sleep(.05)
        return False
    def spawn(kind,config):
        log=(root/(kind+'-'+str(len(processes))+'.log')).open('wb');logs.append(log)
        env={**os.environ,'PYTHONPATH':str(ROOT/'clients/python')}
        p=subprocess.Popen([sys.executable,'-m','heptabao.'+kind,'--config',str(config)],
            cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        processes.append(p);return p
    def request(port,method,path,payload=None,headers=(('X-Vault-Request','true'),),raw_body=None,context=None):
        body=json.dumps(payload).encode() if payload is not None else b''
        if raw_body is not None:body=raw_body
        head=(method+' '+path+' HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body))+'\r\n')
        head+=''.join(name+': '+value+'\r\n' for name,value in headers)
        with socket.create_connection(('127.0.0.1',port),timeout=3) as raw:
            with (context or client_context).wrap_socket(raw,server_hostname='localhost') as tls:
                tls.settimeout(5);tls.sendall(head.encode()+b'\r\n'+body);response=b''
                while True:
                    part=tls.recv(65536)
                    if not part:break
                    response+=part
                    if len(response)>16777216:raise RuntimeError('unbounded_local_response')
        header,data=response.split(b'\r\n\r\n',1)
        return int(header.split(b' ')[1]),json.loads(data) if data else {}
    def unix_request(method,path,payload=None,headers=(('X-Vault-Request','true'),)):
        body=json.dumps(payload).encode() if payload is not None else b''
        head=(method+' '+path+' HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body))+'\r\n')
        head+=''.join(name+': '+value+'\r\n' for name,value in headers)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:
            stream.settimeout(5);stream.connect(str(proxy_state/'api.sock'))
            stream.sendall(head.encode()+b'\r\n'+body);response=b''
            while True:
                part=stream.recv(65536)
                if not part:break
                response+=part
                if len(response)>16777216:raise RuntimeError('unbounded_unix_response')
        header,data=response.split(b'\r\n\r\n',1)
        return int(header.split(b' ')[1]),json.loads(data) if data else {}
    try:
        if args.backend=='oracle':
            oracle=start_oracle(free_loopback_port(),version='2.7.1')
            tls_root=Path(oracle['root']);address=oracle['address'];ca=oracle['ca_file']
            root_token=Path(oracle['token_file']).read_text().strip()
            report['oracle_identity']=json.loads(Path(oracle['identity_file']).read_text())
        else:
            instance=Instance(args.binary,root/'upstream')
            tls_root=instance.root;address=instance.address;ca=str(tls_root/'ca.crt')
        if not args.skip_postgres:
            pg=Postgres(args.postgres_bin,root/'postgres',tls_root/'tls.crt',tls_root/'tls.key',Path(ca))
            pg.start();pg.install()
            report['real_postgresql']=True
            report['postgresql_version']=subprocess.check_output([str(args.postgres_bin/'postgres'),'--version'],text=True).strip()
        if instance is not None:
            cfg=json.loads((tls_root/'server.json').read_text())
            cfg['lifecycle_interval_seconds']=1
            if pg is not None:
                cfg['outbound_endpoints']=[{'origin':pg.origin,'address':'127.0.0.1:'+str(pg.port),
                    'server_name':'localhost','ca_pem':Path(ca).read_text()}]
            (tls_root/'server.json').write_text(json.dumps(cfg));(tls_root/'server.json').chmod(0o600)
            instance.start();status,value=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
            check('upstream.initialized',status==200)
            root_token=value['root_token']
            check('upstream.unsealed',instance.call('POST','sys/unseal',{'key':value['keys_base64'][0]})[0]==200)
        client=Client(address,ca,root_token,timeout=5)
        def call(method,path,payload=None):return client.request(method,'/v1/'+path,payload)
        if pg is not None:check('setup.real_pg_tls_scram',pg.sql('SELECT 1',database='app').returncode==0)
        check('setup.kv_mount',call('POST','sys/mounts/apps',{'type':'kv','options':{'version':'2'}}).status==204)
        marker='owned-local-api-read-positive'
        check('setup.kv_write',call('POST','apps/data/item',{'data':{'value':marker}}).status==200)
        if pg is not None:
            check('setup.database_mount',call('POST','sys/mounts/database',{'type':'database'}).status==204)
            if args.backend=='oracle':
                db_config={'plugin_name':'postgresql-database-plugin','allowed_roles':['reader','short'],
                    'connection_url':pg.origin+'/app?sslmode=verify-full&sslrootcert='+ca,
                    'username':'hb_bootstrap','password':pg.password}
                # Official database plugin substitutes the configured username/password
                # in the URL. They stay in private request memory, never argv/receipts.
                db_config['connection_url']='postgresql://{{username}}:{{password}}@localhost:'+str(pg.port)+'/app?sslmode=verify-full&sslrootcert='+ca
                role_base={'db_name':'local','creation_statements':['CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'{{password}}\' VALID UNTIL \'{{expiration}}\'; GRANT app_reader TO "{{name}}";'],
                    'revocation_statements':['REVOKE app_reader FROM "{{name}}"; DROP ROLE IF EXISTS "{{name}}";']}
            else:
                db_config={'plugin_name':'postgresql-database-plugin','connection_url':pg.origin+'/app',
                    'username':'hb_manager','password':pg.manager_password,'allowed_roles':['reader','short']}
                role_base={'db_name':'local','provider_role':'app_reader'}
            check('setup.database_real_provider',call('POST','database/config/local',db_config).status==204)
            for name,ttl in [('reader',30),('short',2)]:
                check('setup.database_role_'+name,call('POST','database/roles/'+name,{**role_base,'default_ttl':ttl,'max_ttl':60}).status==204)
        policy='path "apps/data/item" { capabilities = ["read"] } path "database/creds/*" { capabilities = ["read"] }'
        check('setup.policy',call('POST','sys/policies/acl/local-reader',{'policy':policy}).status==204)
        check('setup.approle',call('POST','sys/auth/local-approle',{'type':'approle'}).status==204)
        role='auth/local-approle/role/reader'
        check('setup.role',call('POST',role,{'token_policies':['default','local-reader'],
            'token_ttl':'120s','token_max_ttl':'180s','secret_id_num_uses':0}).status==204)
        for name,value in [('role',call('GET',role+'/role-id').data()['role_id']),
                           ('secret',call('POST',role+'/secret-id',{}).data()['secret_id'])]:
            path=root/name;path.write_text(value);path.chmod(0o600)
        client_key=root/'client.key';client_cert=root/'client.crt'
        commands=[['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(client_key),
            '-out',str(root/'client.csr'),'-subj','/CN=Owned Same UID Local API Client'],
            ['openssl','x509','-req','-in',str(root/'client.csr'),'-CA',ca,'-CAkey',str(tls_root/'ca.key'),
            '-CAcreateserial','-out',str(client_cert),'-days','2','-sha256','-extfile',str(root/'client.ext')]]
        (root/'client.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
        for command in commands:subprocess.run(command,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        client_key.chmod(0o600)
        client_context=ssl.create_default_context(cafile=ca);client_context.load_cert_chain(str(client_cert),str(client_key))
        routes=[{'method':'GET','path':path,'effectful':path.startswith('database/')} for path in
                (('apps/data/item','database/creds/reader','database/creds/short') if pg is not None else ('apps/data/item',))]
        agent_port=free_loopback_port();proxy_port=free_loopback_port()
        base_listener={'address':'https://127.0.0.1:'+str(agent_port),
            'tls_cert_file':str(tls_root/'tls.crt'),'tls_key_file':str(tls_root/'tls.key'),
            'tls_client_ca_file':ca,'routes':routes,'require_request_header':True,
            'allow_effects':True,'timeout':3,'max_runtime_seconds':90}
        state=root/'agent';state.mkdir(mode=0o700)
        proxy_state=root/'proxy';proxy_state.mkdir(mode=0o700)
        config={'address':address,'ca_file':ca,'auth_mount':'auth/local-approle',
            'role_id_file':str(root/'role'),'secret_id_file':str(root/'secret'),
            'state_dir':str(state),'interval_seconds':.2,'renew_increment_seconds':60,
            'max_token_ttl_seconds':180,'max_runtime_seconds':90,'listener':base_listener}
        agent_config=root/'agent.json';private_write(agent_config,config)
        agent=spawn('agent',agent_config)
        check('agent.actual_login_and_listener_ready',wait(lambda:request(agent_port,'GET','/v1/apps/data/item')[0]==200))
        check('agent.real_positive_forward',request(agent_port,'GET','/v1/apps/data/item')[1].get('data',{}).get('data')=={'value':marker})
        for path in ('/v1/apps/data/item','/agent/v1/quit','/agent/v1/cache-clear','/v1/unknown'):
            for name,headers in [('missing',()),('wrong',(('X-Vault-Request','false'),)),
                    ('case_value',(('X-Vault-Request','True'),)),
                    ('duplicate',(('X-Vault-Request','true'),('x-vault-request','true')))]:
                check('agent.header_'+name+'_'+path.replace('/','_'),request(agent_port,'POST' if '/agent/' in path else 'GET',path,headers=headers)[0]==412)
        check('agent.header_name_case_insensitive',request(agent_port,'GET','/v1/apps/data/item',headers=(('x-vAuLt-rEqUeSt','true'),))[0]==200)
        check('agent.quit_disabled_post',request(agent_port,'POST','/agent/v1/quit')[0]==404 and agent.poll() is None)
        check('agent.quit_disabled_get',request(agent_port,'GET','/agent/v1/quit')[0]==404 and agent.poll() is None)
        for method in ('GET','POST','PUT'):
            check('agent.no_cache_clear_'+method,request(agent_port,method,'/agent/v1/cache-clear',raw_body=b'not json')[0]==200)
        proxy_config=root/'proxy.json'
        private_write(proxy_config,{'agent_config':str(agent_config),'socket_dir':str(proxy_state),
            'routes':routes,'allow_effects':True,'timeout':3,'max_runtime_seconds':90,
            'listener':{**base_listener,'address':'https://127.0.0.1:'+str(proxy_port)}})
        proxy=spawn('proxy',proxy_config)
        check('proxy.no_cache_owner_real_positive',wait(lambda:request(proxy_port,'GET','/v1/apps/data/item')[0]==200))
        check('proxy.default_quit_disabled_post',request(proxy_port,'POST','/proxy/v1/quit')[0]==404 and proxy.poll() is None)
        check('proxy.default_quit_disabled_get',request(proxy_port,'GET','/proxy/v1/quit')[0]==404 and proxy.poll() is None)
        check('proxy.no_cache_clear_malformed_noop',request(proxy_port,'POST','/proxy/v1/cache-clear',raw_body=b'not json')[0]==200)
        # Termination during an incomplete TLS/HTTP request must still join the
        # listener and invalidate the actual Agent sink within the fixed budget.
        for kind,port,process in [('proxy',proxy_port,proxy),('agent',agent_port,agent)]:
            raw=socket.create_connection(('127.0.0.1',port),timeout=3)
            idle=client_context.wrap_socket(raw,server_hostname='localhost')
            idle.sendall(b'GET /v1/apps/data/item HTTP/1.1\r\nHost: localhost\r\n')
            time.sleep(.1);start=time.monotonic();process.terminate()
            check(kind+'.termination_during_incomplete_request_zero',process.wait(timeout=6)==0)
            check(kind+'.termination_request_budget_bounded',time.monotonic()-start<5)
            idle.close()
        check('agent.termination_invalidates_sink',not (state/'token').exists())
        config['listener']={**base_listener,'enable_quit':True,'cache_enabled':pg is not None}
        private_write(agent_config,config)
        agent=spawn('agent',agent_config)
        check('agent.cached_owner_reauthenticates',wait(lambda:request(agent_port,'GET','/v1/apps/data/item')[0]==200))
        private_write(proxy_config,{'agent_config':str(agent_config),'socket_dir':str(proxy_state),
            'routes':routes,'allow_effects':True,'cache_enabled':pg is not None,'timeout':3,'max_runtime_seconds':90,
            'listener':{**base_listener,'address':'https://127.0.0.1:'+str(proxy_port),'enable_quit':True}})
        proxy=spawn('proxy',proxy_config)
        check('proxy.actual_listener_ready',wait(lambda:request(proxy_port,'GET','/v1/apps/data/item')[0]==200))
        def role_count():return int(pg.sql('SELECT count(*) FROM pg_roles WHERE rolcanlogin',database='app').stdout.strip())
        def read_lease(port,path='reader'):
            status,body=request(port,'GET','/v1/database/creds/'+path)
            check('lease.real_response_'+str(len(cases)),status==200 and body.get('renewable') is True and bool(body.get('lease_id')))
            return body
        for kind,port,owner in [('agent',agent_port,agent),('proxy',proxy_port,proxy)]:
            control='/'+kind+'/v1/'
            if pg is not None:
                first=read_lease(port);before=role_count();second=read_lease(port)
                def same_lease(left,right):return left['lease_id']==right['lease_id'] and left['data']==right['data']
                check(kind+'.lease_cache_actual_hit',same_lease(first,second) and role_count()==before)
                check(kind+'.cached_lease_ttl_does_not_increase',second['lease_duration']<=first['lease_duration'])
                check(kind+'.real_pg_credential_login',pg.login(first['data']['username'],first['data']['password']))
                check(kind+'.header_blocks_cache_clear',request(port,'POST',control+'cache-clear',{'type':'all'},headers=())[0]==412)
                check(kind+'.blocked_clear_preserves_cached_lease',same_lease(read_lease(port),first) and role_count()==before)
                check(kind+'.wrong_namespace_clear_no_effect',request(port,'POST',control+'cache-clear',{'type':'request_path','value':'/v1/database/creds','namespace':'other/'} )[0]==200 and same_lease(read_lease(port),first))
                check(kind+'.actual_cache_clear',request(port,'POST',control+'cache-clear',{'type':'all'})[0]==200)
                third=read_lease(port)
                check(kind+'.clear_causes_real_new_pg_identity',third['lease_id']!=first['lease_id'] and third['data']['username']!=first['data']['username'] and role_count()==before+1)
                check(kind+'.new_credential_logs_in',pg.login(third['data']['username'],third['data']['password']))
                for selector in ('request_path','lease','token','token_accessor'):
                    token=(state/'token').read_text().strip()
                    value={'request_path':'/v1/database/creds','lease':third['lease_id'],'token':token,
                        'token_accessor':client.request('GET','/v1/auth/token/lookup-self',token=token).data()['accessor']}[selector]
                    check(kind+'.clear_selector_'+selector,request(port,'POST',control+'cache-clear',{'type':selector,'value':value})[0]==200)
                    fourth=read_lease(port)
                    check(kind+'.selector_forces_new_lease_'+selector,fourth['lease_id']!=third['lease_id'])
                    third=fourth
                short=read_lease(port,'short');time.sleep(2.3);short_after=read_lease(port,'short')
                check(kind+'.cache_lease_expiry_forces_new_identity',short['lease_id']!=short_after['lease_id'])
                check(kind+'.malformed_cache_clear',request(port,'POST',control+'cache-clear',raw_body=b'not json')[0]==400)
                check(kind+'.cache_clear_missing_type',request(port,'POST',control+'cache-clear',{})[0]==400)
                check(kind+'.cache_clear_missing_value',request(port,'POST',control+'cache-clear',{'type':'lease'})[0]==500)
                check(kind+'.cache_clear_wrong_value_type',request(port,'POST',control+'cache-clear',{'type':'all','value':{}})[0]==400)
                check(kind+'.cache_clear_other_method_noop',request(port,'GET',control+'cache-clear',raw_body=b'not json')[0]==200)
            for path in ('/v1/apps/data/item',control+'cache-clear',control+'quit','/v1/unknown'):
                for name,headers in [('missing',()),('wrong',(('X-Vault-Request','false'),)),
                        ('value_case',(('X-Vault-Request','True'),)),
                        ('duplicate',(('X-Vault-Request','true'),('x-vault-request','true'))),
                        ('other_header',(('Authorization','untrusted'),))]:
                    check(kind+'.header_precedes_dispatch_'+name+'_'+path.replace('/','_'),request(port,'POST' if '/'+kind+'/' in path else 'GET',path,headers=headers)[0]==412)
            check(kind+'.header_ows_exact_true',request(port,'GET','/v1/apps/data/item',headers=(('x-vault-request','\ttrue\t'),))[0]==200)
            check(kind+'.quit_wrong_method',request(port,'GET',control+'quit')[0]==405 and owner.poll() is None)
            check(kind+'.quit_header_denied_owner_alive',request(port,'POST',control+'quit',headers=())[0]==412 and owner.poll() is None)
            check(kind+'.incoming_token_cannot_override',request(port,'GET','/v1/apps/data/item',headers=(('X-Vault-Request','true'),('X-Vault-Token','untrusted')))[0]==503)
        no_client=ssl.create_default_context(cafile=ca)
        denied=False
        try:request(proxy_port,'GET','/v1/apps/data/item',context=no_client)
        except (OSError,ValueError):denied=True
        check('proxy.mtls_rejects_unadmitted_caller',denied)
        unix_config=root/'unix-proxy.json'
        private_write(unix_config,{'agent_config':str(agent_config),'socket_dir':str(proxy_state),
            'routes':routes,'allow_effects':True,'cache_enabled':pg is not None,'require_request_header':True,
            'enable_quit':True,'timeout':3,'max_runtime_seconds':90})
        unix_proxy=spawn('proxy',unix_config)
        check('unix.actual_listener_ready',wait(lambda:unix_request('GET','/v1/apps/data/item')[0]==200))
        check('unix.same_uid_actual_forward',unix_request('GET','/v1/apps/data/item')[1].get('data',{}).get('data')=={'value':marker})
        for name,headers in [('missing',()),('value_case',(('X-Vault-Request','True'),)),
                ('duplicate',(('X-Vault-Request','true'),('x-vault-request','true')))]:
            check('unix.header_'+name,unix_request('POST','/proxy/v1/cache-clear',{'type':'all'},headers=headers)[0]==412)
        if pg is not None:
            first=unix_request('GET','/v1/database/creds/reader')[1];before=role_count()
            second=unix_request('GET','/v1/database/creds/reader')[1]
            check('unix.actual_pg_lease_cache_hit',first['lease_id']==second['lease_id'] and role_count()==before)
            check('unix.actual_cache_clear',unix_request('POST','/proxy/v1/cache-clear',{'type':'all'})[0]==200)
            third=unix_request('GET','/v1/database/creds/reader')[1]
            check('unix.clear_causes_new_pg_identity',third['lease_id']!=first['lease_id'] and role_count()==before+1)
        check('unix.quit_positive_response',unix_request('POST','/proxy/v1/quit')[0]==200)
        check('unix.actual_process_exit_and_owned_inode_removed',unix_proxy.wait(timeout=6)==0 and not (proxy_state/'api.sock').exists())
        check('unix.quit_leaves_agent_running',agent.poll() is None)
        if args.backend=='oracle':
            # Execute the pinned official owners as an independent status/life
            # oracle. No cache stanza: the cache-clear handler must be a no-op.
            for kind in ('agent','proxy'):
                for enabled in (False,True):
                    port=free_loopback_port();path=root/('official-'+kind+'-'+str(enabled)+'.hcl')
                    q=json.dumps
                    lines=['vault {',' address = '+q(address),' ca_cert = '+q(ca),
                        ' retry {','  num_retries = -1',' }','}',
                        'auto_auth {',' method "approle" {','  mount_path = "auth/local-approle"',
                        '  config = {','   role_id_file_path = '+q(str(root/'role')),
                        '   secret_id_file_path = '+q(str(root/'secret')),
                        '   remove_secret_id_file_after_reading = false','  }',' }','}',
                        'api_proxy {',' use_auto_auth_token = "force"','}',
                        'listener "tcp" {',' address = '+q('127.0.0.1:'+str(port)),
                        ' tls_cert_file = '+q(str(tls_root/'tls.crt')),
                        ' tls_key_file = '+q(str(tls_root/'tls.key')),
                        ' tls_client_ca_file = '+q(ca),' tls_require_and_verify_client_cert = true',
                        ' require_request_header = true']
                    if enabled:lines += [' '+kind+'_api {','  enable_quit = true',' }']
                    lines += ['}']
                    path.write_text('\n'.join(lines)+'\n');path.chmod(0o600)
                    log=(root/('official-'+kind+'-'+str(enabled)+'.log')).open('wb');logs.append(log)
                    env={key:value for key,value in os.environ.items() if key.upper() not in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','VAULT_TOKEN','BAO_TOKEN')}
                    owner=subprocess.Popen([str(args.binary),kind,'-config='+str(path)],cwd=root,env=env,
                        stdin=subprocess.DEVNULL,stdout=log,stderr=log);processes.append(owner)
                    prefix='official.'+kind+'.'+('enabled' if enabled else 'disabled')
                    check(prefix+'.actual_autoauth_forward',wait(lambda:request(port,'GET','/v1/apps/data/item')[0]==200,timeout=12))
                    for name,headers in [('missing',()),('value_case',(('X-Vault-Request','True'),)),
                            ('duplicate',(('X-Vault-Request','true'),('x-vault-request','true'))),
                            ('other_header',(('Authorization','untrusted'),))]:
                        for endpoint in ('/v1/apps/data/item','/'+kind+'/v1/quit','/'+kind+'/v1/cache-clear'):
                            check(prefix+'.header_'+name+'_'+endpoint.replace('/','_'),request(port,'POST' if '/'+kind+'/' in endpoint else 'GET',endpoint,headers=headers)[0]==412)
                    check(prefix+'.no_cache_clear_malformed',request(port,'POST','/'+kind+'/v1/cache-clear',raw_body=b'not json')[0]==200)
                    if enabled:
                        check(prefix+'.quit_get_405',request(port,'GET','/'+kind+'/v1/quit')[0]==405 and owner.poll() is None)
                        check(prefix+'.quit_post_200',request(port,'POST','/'+kind+'/v1/quit')[0]==200)
                    else:
                        check(prefix+'.quit_disabled_404',request(port,'POST','/'+kind+'/v1/quit')[0]==404 and owner.poll() is None)
                        owner.terminate()
                    check(prefix+'.actual_process_exit_zero',owner.wait(timeout=6)==0)
            report['official_owner_controls_executed']=True
        relay=SlowTLSRelay(address,ca,tls_root)
        slow_state=root/'slow-agent';slow_state.mkdir(mode=0o700)
        slow_proxy_state=root/'slow-proxy';slow_proxy_state.mkdir(mode=0o700)
        slow_agent_port=free_loopback_port();slow_proxy_port=free_loopback_port()
        slow_agent_config=root/'slow-agent.json'
        private_write(slow_agent_config,{**config,'address':'https://127.0.0.1:'+str(relay.port),
            'state_dir':str(slow_state),'listener':{**base_listener,'enable_quit':True,
            'address':'https://127.0.0.1:'+str(slow_agent_port)}})
        slow_agent=spawn('agent',slow_agent_config)
        check('slow_upstream.agent_actual_autoauth_ready',wait(lambda:(slow_state/'state.json').exists() and json.loads((slow_state/'state.json').read_text()).get('phase')=='ready'))
        slow_proxy_config=root/'slow-proxy.json'
        private_write(slow_proxy_config,{'agent_config':str(slow_agent_config),'socket_dir':str(slow_proxy_state),
            'routes':routes,'allow_effects':True,'timeout':3,'max_runtime_seconds':90,
            'listener':{**base_listener,'address':'https://127.0.0.1:'+str(slow_proxy_port),'enable_quit':True}})
        slow_proxy=spawn('proxy',slow_proxy_config)
        check('slow_upstream.proxy_actual_listener_ready',wait(lambda:request(slow_proxy_port,'POST','/proxy/v1/cache-clear',raw_body=b'not json')[0]==200))
        for kind,port,owner in [('proxy',slow_proxy_port,slow_proxy),('agent',slow_agent_port,slow_agent)]:
            relay.dripping.clear();result=[]
            def slow_request():
                try:result.append(request(port,'GET','/v1/apps/data/item')[0])
                except (OSError,ValueError):result.append('closed')
            pending=threading.Thread(target=slow_request);pending.start()
            check(kind+'.real_upstream_response_trickling',relay.dripping.wait(4))
            start=time.monotonic()
            check(kind+'.quit_during_slow_upstream_response',request(port,'POST','/'+kind+'/v1/quit')[0]==200)
            check(kind+'.slow_upstream_owner_exits_zero',owner.wait(timeout=4)==0)
            check(kind+'.slow_upstream_shutdown_absolute_budget',time.monotonic()-start<5)
            pending.join(5)
            check(kind+'.slow_upstream_read_cancelled',not pending.is_alive() and result==[503])
        check('agent.slow_upstream_quit_invalidates_sink',not (slow_state/'token').exists())
        relay.close();relay=None
        token=(state/'token').read_text().strip()
        check('cache.revoke_managed_token',call('POST','auth/token/revoke',{'token':token}).status==204)
        check('proxy.secret_denied_after_token_revocation',request(proxy_port,'GET','/v1/database/creds/reader' if pg is not None else '/v1/apps/data/item')[0]==403)
        check('proxy.quit_positive_response',request(proxy_port,'POST','/proxy/v1/quit')[0]==200)
        check('proxy.actual_process_exited_zero',proxy.wait(timeout=6)==0)
        check('proxy.quit_does_not_stop_agent',agent.poll() is None)
        check('agent.quit_positive_response',request(agent_port,'POST','/agent/v1/quit')[0]==200)
        check('agent.actual_process_exited_zero',agent.wait(timeout=6)==0)
        check('agent.quit_invalidates_sink',not (state/'token').exists() and json.loads((state/'state.json').read_text()).get('phase')=='stopped')
        for kind,port in [('agent',agent_port),('proxy',proxy_port)]:
            closed=False
            try:socket.create_connection(('127.0.0.1',port),timeout=.2).close()
            except OSError:closed=True
            check(kind+'.listener_socket_closed',closed)
        report['status']='passed'
    except (BaoError,OSError,ValueError,RuntimeError,subprocess.SubprocessError,KeyError,TypeError):
        report['failure']='owned_runtime_check_failed'
    finally:
        for process in processes:
            if process.poll() is None:process.terminate()
            try:process.wait(timeout=6)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=6)
        for log in logs:log.close()
        if relay is not None:relay.close()
        if instance is not None:instance.stop()
        if oracle is not None:stop_oracle(oracle)
        if pg is not None:pg.stop()
        shutil.rmtree(root)
        report['private_fixture_removed']=not root.exists()
        report['denominator']=len(cases)
        report['passed']=sum(row['passed'] for row in cases)
        private_write(args.output,report,replace=False)
    print(json.dumps({'status':report['status'],'passed':report['passed'],'denominator':report['denominator'],
        'output':str(args.output),'private_fixture_removed':report['private_fixture_removed']}))
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
