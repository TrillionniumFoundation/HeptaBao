#!/usr/bin/env python3
"""Exact finite SDK Storage invalidation over three owned physical LAN nodes."""
from pathlib import Path
import argparse, concurrent.futures, hashlib, json, os, secrets, shlex, ssl, subprocess, sys, time, traceback
import ha_multihost_live as ha

REQUIRED = frozenset({
    'source_frozen', 'native_build_bound', 'server_binary', 'companion_binary', 'fixture_binary',
    'seed_fresh', 'seed_init', 'seed_unseal', 'three_physical_hosts', 'all_unsealed',
    'sdk_catalog', 'sdk_mount', 'initial_write', 'initial_cache', 'warm_process_owned',
    'other_leader', 'remote_update', 'remote_hook_storage_attempt_written', 'old_node_caught_up', 'original_leader_reselected',
    'real_hook_new_value', 'same_plugin_process_after_hook', 'hook_has_no_storage_mutation',
    'busy_request_entered', 'busy_owner_stepdown', 'busy_original_staged_write_absent',
    'busy_remote_update', 'busy_original_call_fenced', 'busy_original_process_gone',
    'busy_owner_reselected', 'fresh_owner_reads_current', 'blocked_hook_other_leader',
    'blocked_hook_real_key_committed', 'blocked_hook_state_caught_up', 'blocked_hook_owned_process_gone',
    'blocked_hook_discard_observed', 'blocked_hook_fresh_owner_reads_current', 'seal', 'sealed_read_denied',
    'unseal', 'unseal_new_owner_reads_current', 'encrypted_restart', 'restart_reads_current',
    'source_unchanged', 'runner_unchanged', 'owned_servers_stopped', 'owned_plugins_absent', 'complete',
} | {f'node_{i}_{case}' for i in (1, 2, 3) for case in
     ('private_root_ports', 'binary_digest', 'sdk_binary_digests', 'ha_config', 'binary_unchanged')}
  | {'node_2_cold_clone', 'node_3_cold_clone'})

def frozen(path, commit, tree):
    def git(*args): return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()
    return git('rev-parse', 'HEAD') == commit and git('rev-parse', 'HEAD^{tree}') == tree and not git('status', '--porcelain')

def plugin_identity(node):
    # The fixture executable and ancestor chain must reach this exact owned
    # server PID/start identity. No argv, environment or credential is returned.
    script = '''import json,os,hashlib
from pathlib import Path
root=Path(ROOT)
server=json.loads((root/'process.identity.json').read_text())
expected_sha=hashlib.sha256((root/'sdk-plugins'/'sdk-fixture').read_bytes()).hexdigest()
def proc(pid):
 p=Path('/proc')/str(pid)
 text=(p/'stat').read_text();tail=text[text.rfind(')')+2:].split()
 return {'pid':pid,'ppid':int(tail[1]),'start_ticks':tail[19],'exe':os.readlink(p/'exe')}
owned=[]
for p in Path('/proc').iterdir():
 if not p.name.isdecimal():continue
 try:
  actual=proc(int(p.name))
  chain=[];parent=actual
  for _ in range(8):
   chain.append(parent)
   if parent['pid']==server['pid']:
    if parent['start_ticks']!=str(server['start']) or parent['exe']!=server['executable']:raise RuntimeError('server identity changed')
    # Linux SDK processes execute immutable sealed memfd images. Bind the
    # running /proc image itself, rather than its original source pathname.
    image=Path('/proc')/str(actual['pid'])/'exe'
    digest=hashlib.sha256(image.read_bytes()).hexdigest()
    if digest!=expected_sha:break
    meta=image.stat()
    after=proc(actual['pid'])
    if after!=actual:raise RuntimeError('plugin identity changed during image observation')
    actual.update(executable_sha256=digest,device=meta.st_dev,inode=meta.st_ino,exe_size=meta.st_size)
    owned.append(actual);break
   if parent['ppid']<=1:break
   parent=proc(parent['ppid'])
 except (FileNotFoundError,ProcessLookupError,PermissionError):pass
print(json.dumps(owned,sort_keys=True))
'''.replace('ROOT', repr(node.root))
    return json.loads(ha.ssh(node, 'python3 - <<\'PY\'\n' + script + '\nPY'))

def exact_pid_absent(node, identity):
    script = '''import json
from pathlib import Path
expected=EXPECTED
p=Path('/proc')/str(expected['pid'])
try:
 s=(p/'stat').read_text();tail=s[s.rfind(')')+2:].split()
 absent=tail[19]!=expected['start_ticks']
except FileNotFoundError:absent=True
print(json.dumps(absent))
'''.replace('EXPECTED', repr(identity))
    return json.loads(ha.ssh(node, 'python3 - <<\'PY\'\n' + script + '\nPY')) is True

def invalidation_trace(node):
    script = '''import json
from pathlib import Path
lines=[]
for line in (Path(ROOT)/'process.log').open():
 if line.startswith('HBSDK-INVALIDATION '):
  if len(line)>2048:raise RuntimeError('notification trace oversized')
  lines.append(line.rstrip())
  if len(lines)>256:raise RuntimeError('notification trace bound')
print(json.dumps(lines))
'''.replace('ROOT', repr(node.root))
    return json.loads(ha.ssh(node, 'python3 - <<\'PY\'\n' + script + '\nPY'))

def fixture_event(node, identity, event):
    script = '''import json,os,stat
from pathlib import Path
root=Path(ROOT)/'sdk-runtime'
seen=False
for path in root.glob('*/sdk-fixture-events.jsonl'):
 meta=path.lstat()
 if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&0o077 or meta.st_size>65536:raise RuntimeError('fixture journal custody')
 for line in path.read_text().splitlines():
  row=json.loads(line)
  if set(row)!={'event','pid'}:raise RuntimeError('fixture journal schema')
  if row['pid']==PID and row['event']==EVENT:seen=True
print(json.dumps(seen))
'''.replace('ROOT',repr(node.root)).replace('PID',str(identity['pid'])).replace('EVENT',repr(event))
    return json.loads(ha.ssh(node,'python3 - <<\'PY\'\n'+script+'\nPY')) is True

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'source-root', 'build-receipt', 'companion', 'fixture', 'work-root'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('source-commit', 'source-tree', 'expected-binary-sha256', 'expected-build-receipt-sha256',
                 'expected-companion-sha256', 'expected-fixture-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--node', required=True, action='append')
    parser.add_argument('--allow-private-lan', action='store_true')
    args = parser.parse_args()
    if len(args.node) != 3 or not args.allow_private_lan: parser.error('three explicit owned LAN fixtures required')
    root = args.work_root
    if (not root.is_absolute() or root.exists() or root.parent.resolve(strict=True) != root.parent
            or root.parent.stat().st_uid != os.getuid() or root.parent.stat().st_mode & 0o022):
        parser.error('fresh canonical owner-controlled evidence root required')
    os.umask(0o077); root.mkdir(mode=0o700); (root/'phases').mkdir(mode=0o700)
    nodes = [ha.parse_node(value, i + 1, 31092, 31093, allow_private_lan=True) for i, value in enumerate(args.node)]
    if len({node.ip for node in nodes}) != 3 or len({node.root for node in nodes}) != 3: parser.error('distinct physical roots required')
    started = set(); sensitive = []; root_token = ''; unseal = ''; plugin_owners = []
    runner_sha = ha.sha256_file(Path(__file__)); shared_sha = ha.sha256_file(Path(ha.__file__))
    report = dict(schema='heptabao.sdk-storage-invalidation-physical-lan.v1', status='failed',
        scope='genuine SDK secret cache invalidation under exact received committed record owner',
        source_commit=args.source_commit, source_tree=args.source_tree,
        binary_sha256=args.expected_binary_sha256, companion_sha256=args.expected_companion_sha256,
        fixture_sha256=args.expected_fixture_sha256, runner_sha256=runner_sha, shared_runner_sha256=shared_sha,
        required_check_count=len(REQUIRED), checks=[], events=[], transport='direct-private-lan-mtls',
        sdk_auth_invalidation=False, global_plugin_manager=False, full_openbao_replacement=False,
        production_authority=False, v6_writer_authority=False)
    phase = 0
    def save():
        nonlocal phase
        encoded = json.dumps(report, indent=2, sort_keys=True) + '\n'
        if any(value and value in encoded for value in sensitive): raise ha.FixtureError('report_runtime_secret')
        (root/'progress.json').write_text(encoded); phase += 1
        with (root/'phases'/f'{phase:05d}.json').open('x') as stream:
            stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
    def check(case, passed, **metadata):
        report['checks'].append(dict(case=case, passed=passed is True, **metadata)); save()
        if passed is not True: raise ha.FixtureError(case)
    def event(case, **metadata): report['events'].append(dict(event=case, **metadata)); save()
    def api(node, method, path, body=None, token=None, timeout=15):
        return ha.api(context, node, method, path, body, root_token if token is None else token, timeout)
    def elect(target=None, previous=None):
        current = ha.wait_leader(context, nodes, root_token, previous=previous, seconds=60)
        if target is None: return current
        for hop in range(8):
            if current == target: return current
            code, _ = api(current, 'POST', 'sys/step-down', {})
            if code != 204: raise ha.FixtureError('leadership_transfer_failed')
            event('leadership_transfer', from_node=current.node_id, hop=hop)
            current = ha.wait_leader(context, nodes, root_token, previous=current, seconds=60)
        raise ha.FixtureError('target_leader_not_elected')
    def remember(node):
        owned = plugin_identity(node)
        if len(owned) != 1: raise ha.FixtureError('exact_plugin_owner_missing')
        plugin_owners.append((node, owned[0])); return owned[0]
    handlers = ha.install_signal_handlers()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        check('source_frozen', frozen(args.source_root, args.source_commit, args.source_tree))
        check('native_build_bound', ha.sha256_file(args.build_receipt) == args.expected_build_receipt_sha256
              and bool(ha.validate_build_receipt(json.loads(args.build_receipt.read_text()), args.source_commit, args.source_tree, args.expected_binary_sha256)))
        for name, path, digest in [('server_binary', args.binary, args.expected_binary_sha256),
                                  ('companion_binary', args.companion, args.expected_companion_sha256),
                                  ('fixture_binary', args.fixture, args.expected_fixture_sha256)]:
            check(name, ha.sha256_file(path) == digest)
        payload = root/'server.gz'; ha.compress_candidate(args.binary, payload)
        ca_key, ca_cert = root/'ca.key', root/'ca.crt'; ha.create_fixture_ca(ca_key, ca_cert)
        context = ssl.create_default_context(cafile=str(ca_cert)); peers = {}; files = {}; hosts = {}
        for node in nodes:
            hosts[node.node_id] = ha.ssh(node, f'''set -eu
umask 077
test ! -e {shlex.quote(node.root)}
python3 - <<'PY'
import socket
for port in ({node.api_port},{node.raft_port}):
 s=socket.socket();s.bind(({node.ip!r},port));s.close()
PY
mkdir -m 700 {shlex.quote(node.root)}
mkdir -m 700 {shlex.quote(node.root+'/sdk-plugins')} {shlex.quote(node.root+'/sdk-runtime')}
hostname
''').strip()
            check(f'node_{node.node_id}_private_root_ports', bool(hosts[node.node_id]))
            directory = root/node.name; directory.mkdir(mode=0o700); files[node] = directory
            key, cert = ha.create_fixture_node_certificate(node, directory, ca_key, ca_cert)
            peers[str(node.node_id)] = dict(node_name=node.name, address=f'{node.ip}:{node.raft_port}', api_address=node.api_origin,
                server_name=node.server_name, certificate_sha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest())
            config = dict(listen=f'{node.ip}:{node.api_port}', data_dir=node.root+'/data', audit_file=node.root+'/audit.jsonl',
                tls_cert_file=node.root+'/tls.crt', tls_key_file=node.root+'/tls.key', max_connections=64,
                timeout_seconds=12, rate_limit_per_second=2000, rate_limit_burst=4000, rate_limit_entries=512,
                lifecycle_interval_seconds=1, openbao_sdk=dict(plugin_directory=node.root+'/sdk-plugins',
                companion=node.root+'/sdk-companion', companion_sha256=args.expected_companion_sha256,
                runtime_directory=node.root+'/sdk-runtime', timeout_ms=5000))
            cfg=directory/'server.json'; cfg.write_text(json.dumps(config)); cfg.chmod(0o600)
            ha.install_candidate(node, payload, args.expected_binary_sha256)
            for source, name, mode in [(ca_cert,'ca.crt',0o600),(cert,'tls.crt',0o600),(key,'tls.key',0o600),
                    (cfg,'server.json',0o600),(args.companion,'sdk-companion',0o500),(args.fixture,'sdk-plugins/sdk-fixture',0o500)]:
                ha.upload(node, source, node.root+'/'+name, mode)
            check(f'node_{node.node_id}_binary_digest', ha.remote_binary_digest(node) == args.expected_binary_sha256)
            actual = ha.ssh(node, f"sha256sum {shlex.quote(node.root+'/sdk-companion')} {shlex.quote(node.root+'/sdk-plugins/sdk-fixture')}").splitlines()
            check(f'node_{node.node_id}_sdk_binary_digests', [line.split()[0] for line in actual] == [args.expected_companion_sha256,args.expected_fixture_sha256])
        seed=nodes[0]; ha.remote_start(seed,ha=False); started.add(seed)
        check('seed_fresh', ha.wait_listener(context,seed)[0] == 501)
        code, body=api(seed,'POST','sys/init',dict(secret_shares=1,secret_threshold=1),token='')
        root_token=body.get('root_token',''); keys=body.get('keys_base64',[])
        check('seed_init',code==200 and bool(root_token) and len(keys)==1)
        unseal=keys[0]; sensitive.extend([root_token,unseal])
        check('seed_unseal',api(seed,'POST','sys/unseal',dict(key=unseal),token='')[0]==200)
        cluster=api(seed,'GET','sys/health',token='')[1]['cluster_id']; ha.remote_stop(seed); started.discard(seed)
        archive=root/'encrypted-seed.tgz'
        with archive.open('wb') as stream:ha.checked_run(['ssh',seed.alias,'tar','-C',seed.root,'-czf','-','data'],stdout=stream,timeout=180)
        for node in nodes[1:]:
            ha.upload(node,archive,node.root+'/encrypted-seed.tgz',0o600)
            ha.ssh(node,f'''set -eu
root={shlex.quote(node.root)}
test ! -e "$root/data"
tar -xzf "$root/encrypted-seed.tgz" -C "$root"
rm "$root/encrypted-seed.tgz"
test -d "$root/data"
'''); check(f'node_{node.node_id}_cold_clone',True)
        replication=root/'replication.key';replication.write_bytes(secrets.token_bytes(32));replication.chmod(0o600)
        for node in nodes:
            config=dict(node_id=node.node_id,cluster_id=cluster,raft_dir=node.root+'/raft',listen=f'{node.ip}:{node.raft_port}',
                ca_file=node.root+'/ca.crt',cert_file=node.root+'/tls.crt',key_file=node.root+'/tls.key',replication_key_file=node.root+'/replication.key',
                peers=peers,bootstrap=node.node_id==1,peer_timeout_ms=1500,forward_timeout_ms=8000,max_inflight=32)
            cfg=files[node]/'ha.json';cfg.write_text(json.dumps(config));cfg.chmod(0o600)
            ha.upload(node,replication,node.root+'/replication.key',0o600);ha.upload(node,cfg,node.root+'/ha.json',0o600)
            check(f'node_{node.node_id}_ha_config',True)
        ha.remote_start(seed,ha=True);started.add(seed);time.sleep(5)
        for node in nodes[1:]:ha.remote_start(node,ha=True);started.add(node)
        for node in nodes:ha.wait_listener(context,node)
        check('three_physical_hosts',len(set(hosts.values()))==3,hostnames=hosts)
        check('all_unsealed',[api(node,'POST','sys/unseal',dict(key=unseal),token='')[0] for node in nodes]==[200]*3)
        original=elect();mount='sdk-cache/'
        check('sdk_catalog',api(original,'POST','sys/plugins/catalog/secret/sdk-cache',dict(command='sdk-fixture',sha256=args.expected_fixture_sha256,version='v0.0.1',args=['--serve']))[0]==204)
        check('sdk_mount',api(original,'POST','sys/mounts/sdk-cache',dict(type='sdk-cache',config=dict(plugin_version='v0.0.1')))[0]==204)
        check('initial_write',api(original,'POST',mount+'item',dict(value='old-value'))[0]==204)
        code, body=api(original,'GET',mount+'cached-item')
        check('initial_cache',code==200 and body.get('data',{}).get('value')=='old-value',invalidations=body.get('data',{}).get('invalidations'))
        warm=remember(original);check('warm_process_owned',True,identity=warm,node=original.node_id)
        check('other_leader',api(original,'POST','sys/step-down',{})[0]==204)
        other=elect(previous=original)
        check('remote_update',api(other,'POST',mount+'item',dict(value='new-value'))[0]==204)
        check('remote_hook_storage_attempt_written',api(other,'POST',mount+'invalidation-control/storage-attempt',dict(value='trigger-genuine-hook'))[0]==204)
        frontier=ha.capture_committed_frontier(context,other)
        local=ha.wait_local_frontier(context,original,frontier,seconds=90)
        check('old_node_caught_up',True,required_index=frontier,local_committed_index=local[0],local_applied_index=local[1])
        check('original_leader_reselected',elect(target=original)==original)
        code,body=api(original,'GET',mount+'cached-item');data=body.get('data',{})
        check('real_hook_new_value',code==200 and data.get('value')=='new-value' and isinstance(data.get('invalidations'),int) and data['invalidations']>=1,invalidations=data.get('invalidations'))
        now=remember(original);check('same_plugin_process_after_hook',now==warm)
        check('hook_has_no_storage_mutation',data.get('storage_mutation_denied') is True and api(original,'GET',mount+'invalidation-control/invalidation-mutation')[0]==404,
              trace=invalidation_trace(original))
        # Actual backend blocks after its original StoragePut acknowledgement.
        busy_identity=remember(original)
        blocked=pool.submit(api,original,'POST',mount+'blocked',{})
        until=time.monotonic()+3;busy=False;ack_seen=False
        while time.monotonic()<until and not blocked.done():
            if api(original,'GET',mount+'cached-item')[0]==503:busy=True
            ack_seen=fixture_event(original,busy_identity,'blocked_storage_ack')
            if busy and ack_seen:break
            time.sleep(.05)
        check('busy_request_entered',busy and ack_seen and not blocked.done(),actual_original_storage_ack=ack_seen)
        check('busy_owner_stepdown',api(original,'POST','sys/step-down',{})[0]==204)
        other=elect(previous=original)
        code,body=api(other,'GET',mount+'invalidation-control/owner-death')
        # Admitted ordinary SDK StoragePut is staged until terminal publication.
        # The actual callback ACK above must not publish a blocked old Plan.
        check('busy_original_staged_write_absent',code==404 and not body.get('auth') and not body.get('wrap_info'),http_status=code)
        check('busy_remote_update',api(other,'POST',mount+'item',dict(value='after-busy'))[0]==204)
        code,body=blocked.result(timeout=20)
        check('busy_original_call_fenced',code==503 and not body.get('auth') and not body.get('wrap_info'),http_status=code)
        until=time.monotonic()+15
        while not exact_pid_absent(original,busy_identity) and time.monotonic()<until:time.sleep(.1)
        check('busy_original_process_gone',exact_pid_absent(original,busy_identity),identity=busy_identity)
        check('busy_owner_reselected',elect(target=original)==original)
        code,body=api(original,'GET',mount+'cached-item')
        fresh=remember(original)
        check('fresh_owner_reads_current',code==200 and body.get('data',{}).get('value')=='after-busy' and fresh!=busy_identity,identity=fresh)
        trace_before = invalidation_trace(original)
        check('blocked_hook_other_leader',api(original,'POST','sys/step-down',{})[0]==204)
        other=elect(previous=original)
        check('blocked_hook_real_key_committed',api(other,'POST',mount+'invalidation-control/deadline-blocked',dict(value='original-monotonic-hook'))[0]==204)
        frontier=ha.capture_committed_frontier(context,other)
        local=ha.wait_local_frontier(context,original,frontier,seconds=90)
        # ReadIndex installation owns the hook; ordinary standby forwarding is
        # only the normal request used to observe that exact received state.
        api(original,'GET',mount+'item',timeout=20)
        check('blocked_hook_state_caught_up',True,required_index=frontier,local_applied_index=local[1])
        until=time.monotonic()+20
        while not exact_pid_absent(original,fresh) and time.monotonic()<until:time.sleep(.1)
        check('blocked_hook_owned_process_gone',exact_pid_absent(original,fresh),identity=fresh)
        trace_after=invalidation_trace(original)
        new_trace=trace_after[len(trace_before):]
        check('blocked_hook_discard_observed',any('disposition=discarded ' in line for line in new_trace),trace=new_trace)
        active=elect(target=original);code,body=api(active,'GET',mount+'cached-item')
        after_hook=remember(active)
        check('blocked_hook_fresh_owner_reads_current',code==200 and body.get('data',{}).get('value')=='after-busy' and after_hook!=fresh,identity=after_hook)
        check('seal',api(original,'PUT','sys/seal',{})[0]==204)
        code,body=api(original,'GET',mount+'cached-item')
        check('sealed_read_denied',code>=400 and not body.get('auth') and not body.get('wrap_info'),http_status=code)
        check('unseal',api(original,'POST','sys/unseal',dict(key=unseal),token='')[0]==200)
        active=elect(target=original);code,body=api(active,'GET',mount+'cached-item')
        check('unseal_new_owner_reads_current',code==200 and body.get('data',{}).get('value')=='after-busy' and remember(active)!=after_hook)
        ha.remote_stop(original);started.discard(original)
        ha.remote_start(original,ha=True);started.add(original);ha.wait_listener(context,original)
        check('encrypted_restart',api(original,'POST','sys/unseal',dict(key=unseal),token='')[0]==200)
        active=elect(target=original);code,body=api(active,'GET',mount+'cached-item')
        check('restart_reads_current',code==200 and body.get('data',{}).get('value')=='after-busy')
        remember(active)
        check('source_unchanged',frozen(args.source_root,args.source_commit,args.source_tree))
        check('runner_unchanged',ha.sha256_file(Path(__file__))==runner_sha and ha.sha256_file(Path(ha.__file__))==shared_sha)
        for node in nodes:
            sdk=ha.ssh(node,f"sha256sum {shlex.quote(node.root+'/sdk-companion')} {shlex.quote(node.root+'/sdk-plugins/sdk-fixture')}").splitlines()
            check(f'node_{node.node_id}_binary_unchanged',ha.remote_binary_digest(node)==args.expected_binary_sha256
                  and [line.split()[0] for line in sdk]==[args.expected_companion_sha256,args.expected_fixture_sha256])
    except Exception as error:
        report['failure_code']=str(error) if isinstance(error,ha.FixtureError) else type(error).__name__
        report['failure_stack']=[dict(file=Path(frame.filename).name,line=frame.lineno,function=frame.name) for frame in traceback.extract_tb(error.__traceback__)]
    finally:
        pool.shutdown(wait=True,cancel_futures=True)
        clean=True
        for node in sorted(started,key=lambda n:n.node_id,reverse=True):
            try:ha.remote_stop(node)
            except Exception as error:clean=False;report.setdefault('cleanup_failures',[]).append(dict(node=node.node_id,type=type(error).__name__))
        try:check('owned_servers_stopped',clean)
        except ha.FixtureError:pass
        absent=True
        for node, identity in plugin_owners:
            try:absent=exact_pid_absent(node,identity) and absent
            except Exception:absent=False
        try:check('owned_plugins_absent',absent)
        except ha.FixtureError:pass
        try:check('complete',{row['case'] for row in report['checks']}==REQUIRED-{'complete'} and len(report['checks'])==len(REQUIRED)-1 and all(row['passed'] for row in report['checks']))
        except ha.FixtureError:pass
        if len(report['checks'])==len(REQUIRED) and {row['case'] for row in report['checks']}==REQUIRED and all(row['passed'] for row in report['checks']):report['status']='passed'
        (root/'summary.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        print(json.dumps(dict(status=report['status'],checks=len(report['checks']),required=len(REQUIRED),failure_code=report.get('failure_code'))))
        ha.restore_signal_handlers(handlers)
    return 0 if report['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
