#!/usr/bin/env python3
"""Exercise real Agent, Unix proxy and SSH helper subprocesses against pinned
OpenBao or the actual candidate TLS server. Synthetic data only; not PAM login,
independent acceptance or full CLI/Agent/Proxy parity. Every fixture is removed.
"""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from official_openbao_launcher import start_oracle, stop_oracle


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--oracle',action='store_true')
    parser.add_argument('--client-python')
    args=parser.parse_args()
    root=Path(tempfile.mkdtemp(prefix='bao-operational-'));root.chmod(0o700)
    output=Path(args.output).resolve()
    if output.exists() or output.parent.stat().st_mode&0o077:parser.error('new output in private directory required')
    cases=[];processes=[];logs=[];instance=oracle=None;secret_values=[]
    client_python=args.client_python or sys.executable
    env=os.environ.copy()
    if args.client_python:env.pop('PYTHONPATH',None)
    else:env['PYTHONPATH']=str(ROOT/'clients/python')
    report={'schema':'heptabao.operational-process-evidence.v1','cases':cases,'status':'failed',
            'synthetic_only':True,'independent_qualification':False,'production_authority':False,
            'actual_pam_or_sshd_login':False,'full_agent_proxy_compatibility':False,
            'target':'official-openbao-2.6.2' if args.oracle else 'heptabao-candidate',
            'client_distribution':'installed-wheel' if args.client_python else 'source',
            'candidate_binary_sha256':file_hash(Path(args.binary)),
            'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
            'source_tree':subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True).strip(),
            'source_dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),
            'runner_sha256':file_hash(Path(__file__))}
    def check(name,condition):
        if type(condition) is not bool:raise ValueError('non_boolean_case')
        cases.append({'case':name,'passed':condition})
        if not condition:raise AssertionError(name)
    def secret_file(name,value):
        p=root/name
        fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:f.write(value)
        secret_values.append(value)
        return str(p)
    def spawn(name,module,arguments):
        log=open(root/(name+'.log'),'wb');logs.append(log)
        p=subprocess.Popen([client_python,'-m',module]+arguments,cwd=root,env=env,stdin=subprocess.DEVNULL,
                           stdout=log,stderr=log);processes.append(p);return p
    def wait_for(predicate,timeout=12):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            try:
                if predicate():return True
            except (OSError,KeyError,ValueError):pass
            time.sleep(0.05)
        return False
    def state():return json.loads((root/'agent'/'state.json').read_text())
    def proxy_request(path='apps/data/item',extra=b''):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(6);sock.connect(str(root/'proxy'/'api.sock'))
            sock.sendall(b'GET /v1/'+path.encode()+b' HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n'+extra+b'\r\n')
            data=b''
            while True:
                part=sock.recv(65536)
                if not part:break
                data+=part
                if len(data)>1024*1024:raise ValueError('proxy_unbounded')
            head,body=data.split(b'\r\n\r\n',1)
            return int(head.split(b' ')[1]),json.loads(body) if body else {}
    helper_sequence = 0
    def helper(otp,username='deploy',config='helper.json'):
        nonlocal helper_sequence
        helper_sequence += 1
        result=subprocess.run([client_python,'-m','heptabao.ssh_helper','--config',str(root/config),
                               '--username',username],input=(otp+'\n').encode(),env=env,cwd=root,
                              capture_output=True,timeout=8,check=False)
        check('helper.diagnostics_'+str(helper_sequence),not result.stdout and all(v.encode() not in result.stderr for v in secret_values))
        return result.returncode
    try:
        if args.oracle:
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            oracle=start_oracle(port)
            address,ca=oracle['address'],oracle['ca_file']
            token=Path(oracle['token_file']).read_text().strip()
            report['oracle_identity']=json.loads(Path(oracle['identity_file']).read_text())
        else:
            spec=importlib.util.spec_from_file_location('operational_smoke',ROOT/'qa/single-node/smoke.py')
            smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
            instance=smoke.Instance(Path(args.binary).resolve(),root/'server')
            cfg=json.loads((instance.root/'server.json').read_text());cfg['lifecycle_interval_seconds']=1
            (instance.root/'server.json').write_text(json.dumps(cfg));instance.start()
            status,init=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
            check('server.init',status==200);token=init['root_token'];key=init['keys_base64'][0]
            check('server.unseal',instance.call('POST','sys/unseal',{'key':key})[0]==200)
            address,ca=instance.address,str(instance.root/'ca.crt')
        secret_values.append(token)
        rootclient=Client(address,ca,token,timeout=5)
        def call(method,path,payload=None):return rootclient.request(method,'/v1/'+path,payload)
        check('setup.kv_mount',call('POST','sys/mounts/apps',{'type':'kv','options':{'version':'2'}}).status==204)
        marker='synthetic-operational-secret';secret_values.append(marker)
        check('setup.kv_write',call('POST','apps/data/item',{'data':{'value':marker}}).status==200)
        policy='path "apps/data/item" { capabilities = ["read"] }'
        check('setup.policy',call('POST','sys/policies/acl/agent-reader',{'policy':policy}).status==204)
        check('setup.auth_mount',call('POST','sys/auth/agent-approle',{'type':'approle'}).status==204)
        role='auth/agent-approle/role/worker'
        check('setup.role',call('POST',role,{'token_policies':['default','agent-reader'],'token_ttl':'8s',
                                          'token_max_ttl':'120s','secret_id_num_uses':0}).status==204)
        role_id=call('GET',role+'/role-id').data()['role_id']
        secret_id=call('POST',role+'/secret-id',{}).data()['secret_id']
        (root/'agent').mkdir(mode=0o700);(root/'proxy').mkdir(mode=0o700)
        cfg={'address':address,'ca_file':ca,'auth_mount':'auth/agent-approle','role_id_file':secret_file('role',role_id),
             'secret_id_file':secret_file('secret',secret_id),'state_dir':str(root/'agent'),
             'renew_increment_seconds':8,'max_token_ttl_seconds':120,'interval_seconds':0.25,'timeout':2,'max_runtime_seconds':60}
        private_write(root/'agent.json',cfg,replace=False)
        agent=spawn('agent','heptabao.agent',['--config',str(root/'agent.json')])
        check('agent.real_login_ready',wait_for(lambda:state().get('phase')=='ready'))
        initial=state();agent_token=(root/'agent'/'token').read_text().strip();secret_values.append(agent_token)
        check('agent.private_sink',(root/'agent'/'token').stat().st_mode&0o777==0o600)
        check('agent.checkpoint_contains_no_secrets',all(v not in (root/'agent'/'state.json').read_text() for v in secret_values))
        private_write(root/'proxy.json',{'agent_config':str(root/'agent.json'),'socket_dir':str(root/'proxy'),
                    'routes':[{'method':'GET','path':'apps/data/item','effectful':False}],
                    'timeout':3,'max_runtime_seconds':60},replace=False)
        proxy=spawn('proxy','heptabao.proxy',['--config',str(root/'proxy.json')])
        check('proxy.listener_ready',wait_for(lambda:(root/'proxy'/'api.sock').exists()))
        status,body=proxy_request()
        check('proxy.real_secret_read',status==200 and body.get('data',{}).get('data')=={'value':marker})
        check('proxy.rejects_non_allowlisted_route',proxy_request('apps/data/other')[0]==503)
        check('proxy.rejects_supplied_root_token',proxy_request(extra=b'X-Vault-Token: '+token.encode()+b'\r\n')[0]==503)
        check('proxy.rejects_namespace_override',proxy_request(extra=b'X-Vault-Namespace: other\r\n')[0]==503)
        check('proxy.rejects_wrapping_injection',proxy_request(extra=b'X-Vault-Wrap-TTL: 60s\r\n')[0]==503)
        check('policy.revoke',call('POST','sys/policies/acl/agent-reader',{'policy':'path "apps/data/item" { capabilities = ["deny"] }'}).status==204)
        check('proxy.uses_live_server_authorization',proxy_request()[0]==403)
        check('policy.restore',call('POST','sys/policies/acl/agent-reader',{'policy':policy}).status==204)
        second=subprocess.run([client_python,'-m','heptabao.agent','--config',str(root/'agent.json'),'--once'],
                              env=env,cwd=root,capture_output=True,timeout=6,check=False)
        check('agent.second_writer_rejected',second.returncode==2)
        check('agent.second_writer_no_secret_output',all(v.encode() not in second.stdout+second.stderr for v in secret_values))
        check('agent.real_renewal',wait_for(lambda:state().get('phase')=='ready' and state().get('expires_at',0)>initial['expires_at']))
        check('agent.renewal_keeps_same_token',(root/'agent'/'token').read_text().strip()==agent_token)
        agent.terminate();agent.wait(timeout=6)
        check('agent.graceful_stop_invalidates_sink',state().get('phase')=='stopped' and not (root/'agent'/'token').exists())
        check('proxy.denies_stopped_agent',proxy_request()[0]==503)
        # An actual login response is received and then the client process dies,
        # before the response can be published. The normal executable must not
        # silently adopt or repeat the pending authentication on restart.
        (root/'crash-agent').mkdir(mode=0o700);crashcfg={**cfg,'state_dir':str(root/'crash-agent')}
        private_write(root/'crash-agent.json',crashcfg,replace=False)
        crashcode='import os,sys; from heptabao.agent import Agent,main; Agent._admit_token=lambda *args:os._exit(73); sys.exit(main(sys.argv[1:]))'
        killed=subprocess.run([client_python,'-c',crashcode,'--config',str(root/'crash-agent.json'),'--once'],
                              env=env,cwd=root,capture_output=True,timeout=8,check=False)
        check('agent.real_post_login_crash',killed.returncode==73)
        check('agent.crash_preserves_pending',json.loads((root/'crash-agent'/'state.json').read_text())['phase']=='auth_pending')
        resumed=subprocess.run([client_python,'-m','heptabao.agent','--config',str(root/'crash-agent.json'),'--once'],
                               env=env,cwd=root,capture_output=True,timeout=8,check=False)
        check('agent.pending_restart_blocked',resumed.returncode==2)
        check('agent.crash_has_no_published_token',not (root/'crash-agent'/'token').exists())
        check('agent.crash_diagnostics_redacted',all(v.encode() not in killed.stdout+killed.stderr+resumed.stdout+resumed.stderr for v in secret_values))
        check('ssh.mount',call('POST','sys/mounts/ssh-op',{'type':'ssh'}).status==204)
        check('ssh.role',call('POST','ssh-op/roles/local',{'key_type':'otp','default_user':'deploy',
                                                       'allowed_users':'deploy','cidr_list':'127.0.0.0/8'}).status==204)
        helpercfg={'address':address,'ca_file':ca,'mount':'ssh-op','host_ips':['127.0.0.1'],
                   'allowed_roles':['local'],'allowed_users':['deploy'],'timeout':3}
        private_write(root/'helper.json',helpercfg,replace=False)
        def issue():
            response=call('POST','ssh-op/creds/local',{'ip':'127.0.0.1'})
            if response.status!=200:raise AssertionError('ssh.issue')
            otp=response.data()['key'];secret_values.append(otp);return otp
        otp=issue();check('helper.real_valid_binding',helper(otp)==0)
        check('helper.replay_denied',helper(otp)==1)
        otp=issue();check('helper.wrong_login_user_denied',helper(otp,'root')==1)
        check('helper.denial_before_consumption',helper(otp)==0)
        private_write(root/'wrong-host.json',{**helpercfg,'host_ips':['127.0.0.2']},replace=False)
        otp=issue();check('helper.wrong_host_denied',helper(otp,config='wrong-host.json')==1)
        check('helper.wrong_host_no_blind_retry',helper(otp)==1)
        private_write(root/'wrong-role.json',{**helpercfg,'allowed_roles':['other']},replace=False)
        otp=issue();check('helper.wrong_role_denied',helper(otp,config='wrong-role.json')==1)
        # Deliberately wrong CA bytes; no network mutation should be accepted.
        private_write(root/'wrong-ca.json',{**helpercfg,'ca_file':str(root/'role')},replace=False)
        otp=issue();check('helper.invalid_trust_denied',helper(otp,config='wrong-ca.json')==1)
        check('helper.invalid_trust_did_not_consume',helper(otp)==0)
        if not args.oracle:
            check('idle.tune',call('POST','sys/mounts/ssh-op/tune',{'default_lease_ttl':'2s','max_lease_ttl':'2s'}).status==204)
            lease=call('POST','ssh-op/creds/local',{'ip':'127.0.0.1'})
            check('idle.issue',lease.status==200)
            wrapped=rootclient.request('POST','/v1/sys/wrapping/wrap',{'value':'synthetic-idle-value'},wrap_ttl='2s')
            check('idle.wrap',wrapped.status==200)
            before=len((instance.root/'audit.jsonl').read_text().splitlines())
            # No API traffic is sent while waiting for the autonomous worker.
            def idle_committed():
                lines=(instance.root/'audit.jsonl').read_text().splitlines()[before:]
                return sum(json.loads(row)['event']['kind']=='lifecycle-response' for row in lines)>=3
            check('idle.no_request_commits_observed',wait_for(idle_committed,6))
            check('idle.expired_lease_missing',call('POST','sys/leases/lookup',{'lease_id':lease.body['lease_id']}).status==400)
            denied=rootclient.request('POST','/v1/sys/wrapping/unwrap',{},token=wrapped.body['wrap_info']['token'])
            check('idle.expired_wrapping_denied',denied.status==400)
        proxy.terminate();proxy.wait(timeout=6)
        check('proxy.clean_shutdown_removes_only_owned_socket',not (root/'proxy'/'api.sock').exists())
        for log in logs:log.flush()
        all_logs=b''.join(p.read_bytes() for p in root.glob('*.log'))
        check('processes.no_secret_logs',all(v.encode() not in all_logs for v in secret_values))
        report['status']='passed'
    except Exception as error:
        report['failure']=str(error) if isinstance(error,AssertionError) else type(error).__name__
        try:report['agent_phase_on_failure']=state().get('phase')
        except (OSError,ValueError):pass
    finally:
        for p in processes:
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=6)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
        for f in logs:f.close()
        if instance is not None:instance.stop()
        if oracle is not None:stop_oracle(oracle);shutil.rmtree(oracle['root'])
        shutil.rmtree(root)
        private_write(output,report,replace=False)
    print(json.dumps({'status':report['status'],'cases':len(cases),'failure':report.get('failure')}))
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
