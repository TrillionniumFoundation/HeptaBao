#!/usr/bin/env python3
"""Prepare a private Shamir seed and verify every two-share cold recovery.

This creates only one fresh, owned loopback seed and three recovery copies. It
does not populate the prepared production node directory, register a service,
activate V6, distribute shares or change a client. A seed with an uncertain
initialization outcome is retained for reconciliation and is never retried.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import itertools
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import threading
import time
import uuid

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1')
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python')
PYTHON_SHA = '7ecc1ecbf9daa9303c4bf502ff62ffdd9010ed5c08729d470ae9380c10ce1211'
STAGE_SHA = '3c76be847908ecc9e96263822a5ae2852c0b674216c17bbdeb5d5d1d37fca2fc'
GUARD_SHA = 'ea5cb1367a82dea7c7caa97598573fd92f4afac6ea4c728b65b6e228523a84f0'
SOURCE = '33cafa4c6e29f0bde1553e041550d21b4c725d9c'
TREE = 'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
BINARY_SHA = 'd8a9e827a8c0dc0403df24783ea15849bbad88ca88c52985d1cdca0e4d75bd20'
LEAF_SHA = 'f1b41dc0bf36148b7693a1d0f9ecb77b29e546449cc8c89f6e6edc2b5d2447d2'
SERVER_CONFIG_SHA = '27653557ff3a91213dc65efad35fe1c0a26c28fd4670cd0235ff746cf34173cf'
HA_CONFIG_SHA = 'ce9a375a4b1584055df0fab868a974dd6511ab2a250db545c1737464e2578a49'
HTTP_SECONDS = 12
READINESS_SECONDS = 12
SHARES = 3
THRESHOLD = 2
MAX_RESPONSE = 256 * 1024
MAX_RESPONSE_HEADERS = 16 * 1024
MAX_COLD_BYTES = 256 * 1024 * 1024


class Refused(Exception):
    pass


def need(condition, code):
    if not condition:
        raise Refused(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def put(path, raw, mode=0o600):
    if not isinstance(raw, bytes):
        raw = encoded(raw)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fsync_dir(path.parent)
    return sha(raw)


def private_read(path, mode=0o600, maximum=MAX_COLD_BYTES):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode
             and before.st_size <= maximum, 'private_file_custody')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(fields(before) == fields(after) and len(raw) == before.st_size, 'private_file_changed')
        return raw
    finally:
        os.close(fd)


def mkdir(path):
    path.mkdir(mode=0o700)
    fsync_dir(path.parent)


class CompleteHeaderReader:
    """Reject EOF/bare-LF headers before HTTPResponse can accept them."""
    def __init__(self, stream):
        self.stream=stream
        self.header=bytearray()
        self.complete=False

    def readline(self, limit=-1):
        raw=self.stream.readline(limit)
        if not self.complete:
            need(bool(raw) and raw.endswith(b'\r\n'), 'http_response_header_incomplete')
            need(len(self.header)+len(raw)<=MAX_RESPONSE_HEADERS, 'http_response_header_bound')
            self.header.extend(raw)
            if raw==b'\r\n':
                self.complete=True
        return raw

    def __getattr__(self, name):
        return getattr(self.stream,name)


class CompleteHeaderResponse(http.client.HTTPResponse):
    def __init__(self, *args, **kwargs):
        super().__init__(*args,**kwargs)
        self.captured_header=CompleteHeaderReader(self.fp)
        self.fp=self.captured_header

    def begin(self):
        super().begin()
        captured=self.captured_header
        need(captured.complete and bytes(captured.header).endswith(b'\r\n\r\n'),
             'http_response_header_incomplete')
        # These fixed initialization/seal routes send no Expect request and
        # accept one final response. Do not silently lose interim framing.
        parts=bytes(captured.header).split(b'\r\n',1)[0].split(b' ',2)
        need(len(parts)>=2 and parts[1]==str(self.status).encode() and self.status>=200,
             'http_response_status_framing')


def inventory(path):
    files, total = {}, 0
    for item in sorted(path.rglob('*')):
        st = item.lstat()
        need(not item.is_symlink() and st.st_uid == os.getuid()
             and st.st_dev == path.stat().st_dev, 'cold_tree_custody')
        if item.is_dir():
            need(stat.S_IMODE(st.st_mode) == 0o700, 'cold_directory_mode')
            continue
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
             and not stat.S_IMODE(st.st_mode) & 0o077, 'cold_regular_private_file')
        total += st.st_size
        need(total <= MAX_COLD_BYTES and len(files) < 4096, 'cold_tree_bound')
        raw = private_read(item, stat.S_IMODE(st.st_mode))
        files[str(item.relative_to(path))] = {'bytes': len(raw), 'sha256': sha(raw)}
    need(bool(files), 'cold_tree_empty')
    return files


def boundary():
    need(sys.platform == 'darwin' and os.getuid() == 501
         and socket.gethostname() == 'MacBook-Pro.local', 'exact_mac_actor')
    need(Path(sys.executable).resolve() == PYTHON
         and sha(private_read(PYTHON, 0o755)) == PYTHON_SHA, 'exact_python_runtime')
    stage_raw = private_read(ROOT/'control/stage.private.json')
    need(sha(stage_raw) == STAGE_SHA, 'stage_pin')
    stage = json.loads(stage_raw)
    need(stage['source_commit'] == SOURCE and stage['source_tree'] == TREE
         and stage['files']['release/heptabao-server']['sha256'] == BINARY_SHA,
         'normal_source_and_binary_binding')
    guard = ROOT/'release/heptabao_mac_node_start.py'
    need(sha(private_read(guard, 0o500)) == GUARD_SHA, 'node_guard_pin')
    checked = subprocess.run([str(PYTHON), '-I', '-S', '-B', str(guard), 'check-stage',
        '--stage', str(ROOT/'control/stage.private.json'), '--stage-sha256', STAGE_SHA],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    need(checked.returncode == 0 and not checked.stderr, 'actual_stage_check')
    checked_value = json.loads(checked.stdout)
    need(checked_value['stage_verified'] is True and checked_value['service_started'] is False
         and checked_value['activation_present'] is False, 'stage_remains_unactivated')
    for path, pin in [(ROOT/'config/server.json', SERVER_CONFIG_SHA),
                      (ROOT/'config/ha.json', HA_CONFIG_SHA)]:
        need(sha(private_read(path)) == pin, 'production_config_pin')
    for relative in ('node/state', 'node/raft'):
        path = ROOT/relative
        st = path.lstat()
        need(stat.S_ISDIR(st.st_mode) and not path.is_symlink() and st.st_uid == os.getuid()
             and stat.S_IMODE(st.st_mode) == 0o700 and not list(path.iterdir()),
             'prepared_production_state_must_stay_empty')
    device = ROOT.stat().st_dev
    for relative in ('authority', 'authority/seed-custody'):
        path = ROOT/relative
        st = path.lstat()
        need(stat.S_ISDIR(st.st_mode) and not path.is_symlink() and st.st_uid == os.getuid()
             and stat.S_IMODE(st.st_mode) == 0o700 and st.st_dev == device,
             'seed_authority_directory_custody')
    need(not (ROOT/'control/activation.sha256').exists()
         and not (ROOT/'control/activation.private.json').exists(), 'no_production_activation')
    return {'stage_sha256':STAGE_SHA, 'source':SOURCE, 'tree':TREE, 'binary_sha256':BINARY_SHA,
            'server_config_sha256':SERVER_CONFIG_SHA, 'ha_config_sha256':HA_CONFIG_SHA}


class SeedRun:
    def __init__(self, work):
        self.work, self.child, self.phase, self.secret_values = work, None, 0, []
        self.root_token, self.shares, self.cluster_id = None, [], None
        self.creating_child, self.pending_signal = False, None
        self.context = ssl.create_default_context(cafile=str(ROOT/'tls/ca.crt'))
        self.report = {'schema':'heptabao.private-recoverable-seed-preparation.v1','ok':False,
            'source':SOURCE,'tree':TREE,'binary_sha256':BINARY_SHA,'secret_shares':SHARES,
            'secret_threshold':THRESHOLD,'checks':[], 'requests':[], 'processes':[],
            'production_node_state_populated':False,'production_service_started':False,
            'native_v6_activated':False,'client_changed':False,'credential_source_changed':False,
            'j3160_contacted':False,'shares_distributed':False,
            'transitional_complete_init_response_retained_privately':True,
            'split_custody_qualified':False,'production_start_qualified':False,
            'no_unknown_mutation_replayed':True}

    def check(self, case, condition, **data):
        self.report['checks'].append({'case':case,'passed':condition is True,**data})
        need(condition is True, case)

    def handle_signal(self, signum):
        if self.creating_child:
            self.pending_signal=signum
            return
        raise Refused('owned_seed_controller_interrupted')

    def request(self, label, method, path, body=None, *, auth=False, persist_init=False):
        self.phase += 1
        nonce = uuid.uuid4().hex
        prefix = f'{self.phase:03d}-{label}'
        payload = None if body is None else json.dumps(body,separators=(',',':')).encode()
        intent = {'label':label,'method':method,'path':path,'nonce':nonce,
                  'request_body_sha256':None if payload is None else sha(payload),
                  'http_seconds':HTTP_SECONDS,'replayed':False}
        put(self.work/'journal'/(prefix+'-intent.public.json'),intent)
        end = time.monotonic() + HTTP_SECONDS
        conn = http.client.HTTPSConnection('127.0.0.1',self.port,context=self.context,timeout=HTTP_SECONDS)
        conn.response_class=CompleteHeaderResponse
        wire_socket = []
        expired = threading.Event()
        def expire_socket():
            expired.set()
            if wire_socket:
                try:
                    wire_socket[0].shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        timer = threading.Timer(max(.001,end-time.monotonic()),expire_socket)
        timer.daemon = True
        headers = {'Connection':'close','Content-Type':'application/json'}
        if auth:
            need(bool(self.root_token),'root_not_available')
            headers['X-Vault-Token'] = self.root_token
        response_received = False
        timer.start()
        try:
            conn.connect()
            wire_socket.append(conn.sock)
            need(sha(conn.sock.getpeercert(binary_form=True)) == LEAF_SHA, 'exact_seed_tls_leaf')
            need(not expired.is_set() and time.monotonic() < end, 'original_http_deadline')
            conn.sock.settimeout(max(.001,end-time.monotonic()))
            conn.request(method,'/v1/'+path,body=payload,headers=headers)
            response = conn.getresponse()
            lengths=[value.strip() for name,value in response.getheaders() if name.lower()=='content-length']
            self_delimited=(len(lengths)==1 and lengths[0].isascii() and lengths[0].isdigit()
                            and len(lengths[0])<=10 and int(lengths[0])<=MAX_RESPONSE
                            and not any(name.lower()=='transfer-encoding' for name,_ in response.getheaders()))
            need(self_delimited,'fixed_seed_api_response_framing')
            conn.sock.settimeout(max(.001,end-time.monotonic())) if conn.sock is not None else None
            raw = response.read(MAX_RESPONSE+1)
            need(len(raw)==int(lengths[0]) and not expired.is_set() and time.monotonic()<end,
                 'original_http_deadline_or_size')
            # The exact secret-bearing response is made durable before parsing.
            if persist_init:
                put(self.work/'initialization-response.private.json',raw)
            outcome = {**intent,'status':response.status,'response_bytes':len(raw),
                       'response_sha256':sha(raw),'outcome':'response_received'}
            put(self.work/'journal'/(prefix+'-outcome.public.json'),outcome)
            self.report['requests'].append(outcome)
            response_received = True
            return response.status, json.loads(raw) if raw else None
        finally:
            timer.cancel()
            conn.close()
            if not response_received:
                outcome = {**intent,'outcome':'unknown' if method not in ('GET','HEAD','LIST') else 'read_failed'}
                put(self.work/'journal'/(prefix+'-unresolved.public.json'),outcome)
                self.report['requests'].append(outcome)

    def start(self, name):
        need(self.child is None,'previous_owned_child_not_reaped')
        node = self.work/name
        if not node.exists():
            mkdir(node)
        state = node/'state'
        if not state.exists():
            mkdir(state)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0))
            self.port = probe.getsockname()[1]
        config = {'listen':f'127.0.0.1:{self.port}','data_dir':str(state),
                  'audit_file':str(node/'audit.jsonl'),'tls_cert_file':str(ROOT/'tls/tls.crt'),
                  'tls_key_file':str(ROOT/'tls/tls.key'),'max_connections':8,
                  'timeout_seconds':HTTP_SECONDS,'rate_limit_per_second':100,
                  'rate_limit_burst':200,'rate_limit_entries':64,'lifecycle_interval_seconds':1}
        put(node/'server.private.json',config)
        out = (node/'server.stdout.private.log').open('xb')
        err = (node/'server.stderr.private.log').open('xb')
        process_record={'name':name,'pid':None,'owned_popen':False,
                        'port':self.port,'returncode':None,'stopped':True}
        self.report['processes'].append(process_record)
        self.creating_child=True
        try:
            self.child = subprocess.Popen([str(ROOT/'release/heptabao-server'),'--config',str(node/'server.private.json')],
                stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=False,
                env={'PATH':'/usr/bin:/bin','HOME':str(Path.home()),'LC_ALL':'C'})
            process_record.update(pid=self.child.pid,owned_popen=True,stopped=False)
        finally:
            self.creating_child=False
            out.close();err.close()
        if self.pending_signal is not None:
            self.pending_signal=None
            raise Refused('owned_seed_controller_interrupted')
        deadline = time.monotonic()+READINESS_SECONDS
        while time.monotonic()<deadline:
            need(self.child.poll() is None,'owned_seed_exited_before_ready')
            try:
                with socket.create_connection(('127.0.0.1',self.port),timeout=min(1,max(.001,deadline-time.monotonic()))):
                    return
            except OSError:
                time.sleep(min(.1,max(0,deadline-time.monotonic())))
        raise Refused('owned_seed_original_readiness_deadline')

    def stop(self):
        if self.child is None:
            return
        child = self.child
        forced = False
        if child.poll() is None:
            child.send_signal(signal.SIGTERM)
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                forced = True
                child.kill();child.wait(timeout=5)
        self.report['processes'][-1].update(returncode=child.returncode,stopped=True,forced_kill=forced)
        self.child = None
        need(not forced,'owned_seed_graceful_stop_failed')

    def unseal_pair(self, pair, label):
        for ordinal,index in enumerate(pair):
            code,body = self.request(label+f'-share-{index+1}','POST','sys/unseal',{'key':self.shares[index]})
            self.check(label+f'.share_{ordinal+1}',code==200 and isinstance(body,dict)
                and body.get('sealed') is (ordinal==0)
                and body.get('progress') == (1 if ordinal==0 else 0))
        code,health = self.request(label+'-health','GET','sys/health')
        self.check(label+'.same_initialized_cluster',code==200 and isinstance(health,dict)
                   and health.get('initialized') is True and health.get('sealed') is False
                   and isinstance(health.get('cluster_id'),str) and bool(health['cluster_id'])
                   and (self.cluster_id is None or health['cluster_id']==self.cluster_id))
        if self.cluster_id is None:
            self.cluster_id=health['cluster_id']
        code,lookup = self.request(label+'-root-lookup','GET','auth/token/lookup-self',auth=True)
        self.check(label+'.root_credential_survives',code==200 and lookup.get('data',{}).get('policies')==['root'])
        code,capacity = self.request(label+'-capacity','GET','sys/internal/capacity',auth=True)
        self.check(label+'.expected_seed_storage_format',code==200
                   and capacity.get('data',{}).get('state_storage_format')=='heptabao-state-records-v5')

    def seal(self,label):
        code,body = self.request(label+'-seal','POST','sys/seal',auth=True)
        self.check(label+'.seal_acknowledged',code==204 and body in (None,{}))

    def cold_archive(self):
        need(self.child is None,'archive_requires_stopped_seed')
        seed=self.work/'seed/state';before=inventory(seed)
        for relative in before:
            path=seed/relative
            raw=private_read(path,stat.S_IMODE(path.stat().st_mode))
            self.check('cold_cipher_no_cleartext_'+sha(relative.encode())[:12],
                       all(secret.encode() not in raw for secret in self.secret_values))
        archive=self.work/'seed-state.tgz'
        with archive.open('xb') as output:
            with tarfile.open(fileobj=output,mode='w:gz') as package:
                package.add(seed,arcname='state',recursive=True)
            output.flush();os.fsync(output.fileno())
        fsync_dir(self.work)
        self.check('stopped_seed_unchanged_during_archive',inventory(seed)==before)
        self.archive,self.seed_inventory=archive,before
        self.report['seed_archive']={'path':str(archive),'sha256':sha(private_read(archive)),
                                    'bytes':archive.stat().st_size,'files':before}

    def restore(self,label):
        node=self.work/label;mkdir(node)
        with tarfile.open(self.archive,'r:gz') as package:
            members=package.getmembers()
            need(0<len(members)<8192,'seed_archive_count')
            for member in members:
                relative=Path(member.name)
                need(not relative.is_absolute() and '..' not in relative.parts
                     and relative.parts[0]=='state' and (member.isdir() or member.isfile()),'seed_archive_shape')
                target=node/relative
                if member.isdir():
                    mkdir(target)
                else:
                    need(member.size<=MAX_COLD_BYTES,'seed_archive_member_bound')
                    source=package.extractfile(member)
                    need(source is not None,'seed_archive_member_missing')
                    raw=source.read(member.size+1)
                    need(len(raw)==member.size,'seed_archive_truncated')
                    put(target,raw)
        self.check(label+'.cipher_clone_exact',inventory(node/'state')==self.seed_inventory)

    def execute(self):
        self.report['boundary_before']=boundary()
        self.start('seed')
        code,health=self.request('fresh-uninitialized','GET','sys/health')
        self.check('fresh_uninitialized',code==501 and health.get('initialized') is False)
        code,body=self.request('initialize-once','POST','sys/init',
                              {'secret_shares':SHARES,'secret_threshold':THRESHOLD},persist_init=True)
        self.check('initialization_response_recorded',code==200 and isinstance(body,dict))
        self.root_token=body.get('root_token');self.shares=body.get('keys_base64',[])
        self.check('exact_recovery_material_shape',isinstance(self.root_token,str) and bool(self.root_token)
            and isinstance(self.shares,list) and len(self.shares)==SHARES and len(set(self.shares))==SHARES
            and all(isinstance(x,str) and 16<=len(x)<=1024 for x in self.shares))
        for share in self.shares:
            need(len(base64.b64decode(share,validate=True))>=16,'shamir_share_encoding')
        self.secret_values=[self.root_token,*self.shares,*body.get('keys',[])]
        self.unseal_pair((0,1),'seed-initial')
        self.seal('seed-initial')
        self.stop();self.cold_archive()
        for pair in itertools.combinations(range(SHARES),THRESHOLD):
            name='cold-recovery-'+''.join(str(i+1) for i in pair)
            self.restore(name);self.start(name)
            code,status=self.request(name+'-initial-status','GET','sys/seal-status')
            self.check(name+'.cold_sealed_threshold',code==200 and status.get('sealed') is True
                       and status.get('n')==SHARES and status.get('t')==THRESHOLD and status.get('progress')==0)
            self.unseal_pair(pair,name);self.seal(name);self.stop()
        self.check('original_cold_seed_still_exact',inventory(self.work/'seed/state')==self.seed_inventory)
        self.report['boundary_after']=boundary()
        self.check('prepared_production_boundary_unchanged',self.report['boundary_before']==self.report['boundary_after'])
        self.report['cluster_id']=self.cluster_id
        self.report['cold_recovery_pairs_verified']=[[a+1,b+1] for a,b in itertools.combinations(range(SHARES),THRESHOLD)]
        self.report['initialization_response_sha256']=sha(private_read(self.work/'initialization-response.private.json'))
        self.report['recovery_share_sha256']=[sha(s.encode()) for s in self.shares]
        for path in sorted(self.work.rglob('server.*.private.log')):
            raw=private_read(path)
            self.check('server_log_no_credential_'+sha(str(path.relative_to(self.work)).encode())[:12],
                       all(secret.encode() not in raw for secret in self.secret_values))
        self.check('public_receipt_contains_no_credential',all(value.encode() not in encoded(self.report) for value in self.secret_values))
        self.report['ok']=True


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-name',choices=['bootstrap-61ff8bef-r1'],required=True)
    args=parser.parse_args()
    boundary()
    work=ROOT/'authority/seed-custody'/args.work_name
    need(not work.exists() and not work.is_symlink(),'fresh_owned_work_required')
    mkdir(work);mkdir(work/'journal')
    put(work/'intent.public.json',{'schema':'heptabao.recoverable-seed-intent.v1','source':SOURCE,'tree':TREE,
        'binary_sha256':BINARY_SHA,'shares':SHARES,'threshold':THRESHOLD,
        'private_response_before_parse':True,'original_http_seconds':HTTP_SECONDS,
        'no_client_cutover':True,'production_state_population':False,'unknown_replay':False,
        'share_custody_scope':'Transitional private response on Mac only; split custody is a later separately verified gate.'})
    run=SeedRun(work)
    def interrupted(signum, frame):
        run.handle_signal(signum)
    previous_handlers = {sig:signal.signal(sig,interrupted) for sig in (signal.SIGINT,signal.SIGTERM)}
    try:
        run.execute()
    except BaseException as exc:
        run.report['ok']=False
        run.report['failure']=str(exc) if isinstance(exc,Refused) else type(exc).__name__
    finally:
        try:
            run.stop()
        except BaseException as exc:
            run.report['ok']=False
            run.report['cleanup_failure']=str(exc) if isinstance(exc,Refused) else type(exc).__name__
        run.report['all_owned_children_stopped']=all(x['stopped'] for x in run.report['processes'])
        need(all(s.encode() not in encoded(run.report) for s in run.secret_values),'public_secret_scan')
        digest=put(work/'result.public.json',run.report)
        run.root_token=None;run.shares=[];run.secret_values=[]
        for sig,handler in previous_handlers.items():
            signal.signal(sig,handler)
    print(json.dumps({'ok':run.report['ok'],'result':str(work/'result.public.json'),
                      'sha256':digest,'production_service_started':False,'shares_distributed':False,
                      'all_owned_children_stopped':run.report['all_owned_children_stopped']}))
    return 0 if run.report['ok'] else 1


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'ok':False,'error':str(exc) if isinstance(exc,Refused) else type(exc).__name__,
                          'automatic_retry':False,'production_service_started':False}))
        raise SystemExit(2)
