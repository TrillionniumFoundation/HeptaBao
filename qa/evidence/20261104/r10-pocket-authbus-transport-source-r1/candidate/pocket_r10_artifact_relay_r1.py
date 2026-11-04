#!/usr/bin/env python3
"""One fixed public R10 artifact relay; never starts HeptaBao or a consumer."""
from pathlib import Path
import argparse, hashlib, json, os, re, shlex, signal, stat, subprocess, time

BASE = Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
CONTROL = BASE / 'pocket-r10-artifact-relay-control-r1'
ROOT = BASE / 'pocket-r10-artifact-relay-r1'
SOURCE = BASE / 'normal-r10-validation-source-r1'
UPSTREAM = BASE / 'normal-r10-shared-artifacts-r1'
HEAD = '49503322c7f446e5eb41e7744f1fdbd7f1192ecc'
TREE = '1d4211f91e1b34a2ed087a3bbef2e2884bac88e9'
DESKTOP_MACHINE = 'd90fa41f7e59edf2f2a732ea082cac83085a2a3695a503cd82b6b4eef9cab9f3'
UPSTREAM_RECEIPT_SHA = 'f8fd7d32498cb8d291407f5cc352f79584c57e55d48f028f26048097bb0bd7bf'
FILES = [
    ('heptabao-server', 'heptabao-server', 109091112,
     '67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113', 0o500),
    ('native-build.public.json', 'native-build.public.json', 801,
     '0e3d1ae800820d33f0d5369968cbccbab8fa62b077b142f87c9f52b31cd09c77', 0o600),
    ('normal-release-result.public.json', 'normal-build.result.public.json', 3227,
     '75f858b280249dcc981eee3e4340982a58027e8ca40217244ae029bb8e9011ee', 0o600),
]

SOURCE_MODES = {'heptabao-server': 0o500, 'native-build.public.json': 0o400,
                'normal-release-result.public.json': 0o400}
SOURCE_VERSIONS = {
 'heptabao-server': '2050:58120239:109091112:1793819286714153802:1793819286714153802',
 'native-build.public.json': '2050:58120241:801:1793819287399134926:1793819287399134926',
 'normal-release-result.public.json': '2050:58120242:3227:1793819287404134788:1793819287404134788'}
TRUST_FILES = [
 ('/home/qian-qi/.ssh/config', 1455, 'e7b887aad30f6642876c09744c317387b143e4a4b21ddc4879df2b558379ccf4'),
 ('/home/qian-qi/.ssh/hepta-transport/known_hosts', 5391, '1463442349bbb6b56e9ffbb66acce3c4abcceefe1c141c7b7f1ea9bb0dedf034')]
# This is the actual prior read-only probe, using this relay's unchanged ssh
# prefix. Runtime trust bytes are rechecked; no claim is made of a second
# effective-config observation inside this transfer.
ROUTE_WITNESS = {'job': '1a1a8313db3-fc05-2df6', 'receiptSha256': 'a2fca034263c1dc97e516e078572eff78e0af2f60bea22ce1948d3a1232a4fb2',
 'alias': 'pocket4-ts', 'hostname': '192.168.0.9', 'user': 'alex', 'port': '22',
 'hostKeyAlias': 'hepta-node-pocket4',
 'effectiveConfigSha256': '957b627df60bc0a47a7312c1ff13c773966e3050212dcd7f495cd47607a2ee39',
 'proxyCommandSha256': 'd13580ec3a9719e7b54969df0524f254e1d8040db86b0914b4085d6803847d85'}

RECEIVER = r'''
from pathlib import Path
import hashlib,json,os,signal,stat,sys,time
P=Path('/home/alex/heptabao-installed-authbus-consumer-36076-20261104-r1')
ROOT=P/'shared-first-cycle-r10-artifacts-r1'
MACHINE='83cf23c61610cc1595d7323f6ae2f1af29b364a4676cbee1385ba6d478ad853c'
HEAD='49503322c7f446e5eb41e7744f1fdbd7f1192ecc'
TREE='1d4211f91e1b34a2ed087a3bbef2e2884bac88e9'
EXPECTED=[('heptabao-server',109091112,'67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113',0o500),
 ('native-build.public.json',801,'0e3d1ae800820d33f0d5369968cbccbab8fa62b077b142f87c9f52b31cd09c77',0o600),
 ('normal-build.result.public.json',3227,'75f858b280249dcc981eee3e4340982a58027e8ca40217244ae029bb8e9011ee',0o600)]
def ident(s):return [str(getattr(s,k))for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def sync_dir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def put(p,v):
 raw=(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 sync_dir(p.parent)
 return {'path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def expired(*_):raise TimeoutError('fixed_artifact_receiver_deadline')
os.umask(0o077);created=False;rows=[];failure=None;started=time.time_ns()
signal.signal(signal.SIGALRM,expired);signal.alarm(180)
try:
 s=P.lstat();assert os.getuid()==1000 and P.resolve(strict=True)==P and stat.S_ISDIR(s.st_mode)and s.st_uid==1000 and stat.S_IMODE(s.st_mode)==0o700
 assert hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest()==MACHINE
 ROOT.mkdir(mode=0o700);created=True;sync_dir(P)
 line=sys.stdin.buffer.readline(16385);assert len(line)<=16384 and line.endswith(b'\n')
 manifest=json.loads(line)
 assert manifest['schema']=='heptabao.pocket-r10-public-artifact-transfer.v1'
 assert manifest['sourceCommit']==HEAD and manifest['sourceTree']==TREE and manifest['nativeBuildHost']=='rog'
 assert [(x['name'],x['bytes'],x['sha256'],x['mode'])for x in manifest['files']]==EXPECTED
 put(ROOT/'receive-intent.public.json',manifest)
 for name,size,expected,mode in EXPECTED:
  p=ROOT/name;fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
  h=hashlib.sha256();left=size
  with os.fdopen(fd,'wb')as f:
   while left:
    chunk=sys.stdin.buffer.read(min(left,1048576))
    if not chunk:raise EOFError('artifact_body_truncated')
    f.write(chunk);h.update(chunk);left-=len(chunk)
   f.flush();os.fsync(f.fileno());written=os.fstat(f.fileno())
  assert h.hexdigest()==expected and stat.S_ISREG(written.st_mode)and written.st_uid==1000 and written.st_nlink==1 and written.st_size==size and stat.S_IMODE(written.st_mode)==mode
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
  with os.fdopen(fd,'rb')as f:
   first=os.fstat(f.fileno());assert ident(first)==ident(written)==ident(p.lstat())
   readback=hashlib.file_digest(f,'sha256').hexdigest()
   assert ident(first)==ident(os.fstat(f.fileno()))==ident(p.lstat())
  assert readback==expected;sync_dir(ROOT)
  rows.append({'name':name,'path':str(p),'bytes':size,'mode':mode,'sha256':readback,'identity':ident(written),'createOnly':True})
 assert sys.stdin.buffer.read(1)==b''
except BaseException as e:failure=type(e).__name__
finally:
 signal.alarm(0)
 if created:
  result={'schema':'heptabao.pocket-r10-public-artifact-receive-result.v1','ok':failure is None and len(rows)==3,'errorClass':failure,'files':rows,'sourceCommit':HEAD,'sourceTree':TREE,'nativeBuildHost':'rog','machineIdSha256':MACHINE,'createdRoot':str(ROOT),'createOnly':True,'partialRootPreservedOnFailure':failure is not None,'serverOrConsumerStarted':False,'privateInputsTransferred':False,'productionChanged':False,'startedUnixNs':started,'finishedUnixNs':time.time_ns()}
  record=put(ROOT/'receive-result.public.json',result);sync_dir(P)
  print(json.dumps({'ok':result['ok'],'receipt':record,'filesReceived':len(rows),'errorClass':failure},sort_keys=True))
 else:print(json.dumps({'ok':False,'createdRoot':False,'errorClass':failure},sort_keys=True))
sys.exit(0 if failure is None and len(rows)==3 else 1)
'''


def identity(s):
    return [str(getattr(s, k)) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid',
        'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def put(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    sync_dir(path.parent)
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def read_file(path, size, expected, mode):
    assert path.resolve(strict=True) == path
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
        assert before.st_size == size and stat.S_IMODE(before.st_mode) == mode
        raw = f.read(size + 1)
        assert identity(before) == identity(os.fstat(f.fileno())) == identity(path.lstat())
    assert len(raw) == size and hashlib.sha256(raw).hexdigest() == expected
    return raw, identity(before)


def source():
    def git(*args):
        return subprocess.check_output(['/usr/bin/git', '--no-optional-locks', '-c', 'core.hooksPath=/dev/null',
            '-C', str(SOURCE), *args], timeout=15, text=True).strip()
    value = {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
             'status': git('status', '--porcelain')}
    assert value == {'commit': HEAD, 'tree': TREE, 'status': ''}
    return value


def validate_receiver_response(value):
    expected_path = '/home/alex/heptabao-installed-authbus-consumer-36076-20261104-r1/shared-first-cycle-r10-artifacts-r1/receive-result.public.json'
    if not isinstance(value, dict) or set(value) != {'ok', 'receipt', 'filesReceived', 'errorClass'}:
        raise ValueError('receiver_response_shape')
    receipt = value['receipt']
    if (value['ok'] is not True or type(value['filesReceived']) is not int
            or value['filesReceived'] != 3 or value['errorClass'] is not None
            or not isinstance(receipt, dict) or set(receipt) != {'path', 'bytes', 'sha256'}
            or receipt['path'] != expected_path or type(receipt['bytes']) is not int
            or not 0 < receipt['bytes'] <= 65536 or not isinstance(receipt['sha256'], str)
            or re.fullmatch('[a-f0-9]{64}', receipt['sha256']) is None):
        raise ValueError('receiver_result_not_verified')
    return True


def observed_group_members(pgid, until):
    remaining = until - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('artifact_cleanup_deadline')
    result = subprocess.run(['/usr/bin/ps', '-eo', 'pid=,pgid='], capture_output=True,
        text=True, timeout=min(2, remaining))
    if result.returncode != 0 or not result.stdout.strip() or len(result.stdout.encode()) > 1048576:
        raise RuntimeError('owned_group_observation_failed')
    members = []
    for line in result.stdout.splitlines():
        columns = line.split()
        if len(columns) != 2 or not all(c.isdecimal() for c in columns):
            raise RuntimeError('owned_group_observation_shape')
        pid, group = map(int, columns)
        if group == pgid:
            members.append(pid)
    return sorted(members)


def cleanup_ssh(child, started):
    until = time.monotonic() + 10
    error = None; members = None; group_empty = child is None
    if child is not None and child.poll() is None:
        try:
            # A still unreaped direct Popen child owns this PID; no PID reuse
            # is possible here. Never signal a group after that child is reaped.
            if os.getpgid(child.pid) != child.pid:
                raise RuntimeError('owned_ssh_process_group_mismatch')
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=min(5, max(0, until - time.monotonic())))
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=max(0, until - time.monotonic()))
        except BaseException as exc:
            error = type(exc).__name__
    if child is not None:
        try:
            while True:
                members = observed_group_members(child.pid, until)
                if not members:
                    group_empty = True
                    break
                remaining = until - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('artifact_cleanup_deadline')
                time.sleep(min(0.05, remaining))
            # In particular, a completed ssh cannot hide a remaining proxy
            # helper. This read-only check never signals a potentially reused
            # PGID after the direct child has already been reaped.
        except BaseException as exc:
            error = type(exc).__name__
    return {'sshStarted': started, 'pid': child.pid if child is not None else None,
        'returncode': child.returncode if child is not None else None,
        'directChildReaped': child is None or child.returncode is not None,
        'ownedProcessGroupObservedEmpty': group_empty, 'observedRemainingPids': members,
        'errorClass': error}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-controller-sha256', required=True)
    args = parser.parse_args(); os.umask(0o077)
    script = Path(__file__)
    assert script.resolve(strict=True) == CONTROL / 'pocket_r10_artifact_relay_r1.py'
    raw, _ = read_file(script, script.lstat().st_size, args.expected_controller_sha256, 0o600)
    assert hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest() == DESKTOP_MACHINE
    assert os.getuid() == 1000 and BASE.resolve(strict=True) == BASE
    ROOT.mkdir(mode=0o700); sync_dir(BASE)
    started = time.time_ns(); child = None; created = False; pending = None
    error = None; remote = None; response_valid = False
    before = None; after = None; records = []; out = b''; err = b''
    trust_before = None; trust_after = None
    creating_child = False
    def interrupted(signum, _frame):
        nonlocal pending
        if creating_child:
            pending = signum
            return
        raise RuntimeError('artifact_relay_interrupted')
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    try:
        trust_before = {path: read_file(Path(path), size, expected, 0o600)[1]
                        for path, size, expected in TRUST_FILES}
        before = source()
        receipt = UPSTREAM / 'control/result.public.json'
        receipt_raw, receipt_identity = read_file(receipt, 14209, UPSTREAM_RECEIPT_SHA, 0o600)
        upstream = json.loads(receipt_raw)
        assert (upstream['schema'] == 'heptabao.r10.shared-public-artifacts-relay.v1'
            and upstream['status'] == 'transferred' and upstream['source_commit'] == HEAD
            and upstream['source_tree'] == TREE and upstream['all_owned_stopped'] is True
            and upstream['remote_endpoint_completion_verified'] is True
            and upstream['remote_cleanup_unknown'] is False)
        parts = []
        for origin, name, size, expected, mode in FILES:
            path = UPSTREAM / 'incoming' / origin
            data, ident = read_file(path, size, expected, SOURCE_MODES[origin])
            assert ':'.join(ident[index] for index in (0, 1, 6, 7, 8)) == SOURCE_VERSIONS[origin]
            parts.append(data)
            records.append({'name': name, 'source': str(path), 'bytes': size,
                'sha256': expected, 'mode': mode, 'sourceMode': SOURCE_MODES[origin],
                'sourceVersion': SOURCE_VERSIONS[origin], 'sourceIdentityBefore': ident})
        manifest = {'schema': 'heptabao.pocket-r10-public-artifact-transfer.v1',
            'sourceCommit': HEAD, 'sourceTree': TREE, 'nativeBuildHost': 'rog',
            'upstreamReceiptSha256': UPSTREAM_RECEIPT_SHA,
            'files': [{k: r[k] for k in ('name', 'bytes', 'sha256', 'mode')} for r in records]}
        put(ROOT / 'intent.public.json', {'manifest': manifest, 'controllerSha256': args.expected_controller_sha256,
            'receiverSha256': hashlib.sha256(RECEIVER.encode()).hexdigest(), 'sourceBefore': before,
            'priorReadonlyRouteWitness': ROUTE_WITNESS, 'trustBefore': trust_before,
            'sshAlias': 'pocket4-ts', 'strictHostKeyChecking': True, 'updateHostKeys': False,
            'transferSeconds': 180, 'destination': '/home/alex/heptabao-installed-authbus-consumer-36076-20261104-r1/shared-first-cycle-r10-artifacts-r1',
            'productionChanged': False, 'privateInputsTransferred': False})
        payload = (json.dumps(manifest, sort_keys=True) + '\n').encode() + b''.join(parts)
        command = '/usr/bin/python3 -I -S -B -c ' + shlex.quote(RECEIVER)
        argv = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=8', '-o', 'ConnectionAttempts=1', 'pocket4-ts', command]
        until = time.monotonic() + 180
        try:
            creating_child = True
            child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True)
            created = True
        finally:
            creating_child = False
        if pending is not None:
            raise RuntimeError('artifact_relay_interrupted_during_spawn')
        remaining = until - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('artifact_relay_deadline_exceeded')
        out, err = child.communicate(payload, timeout=remaining)
        assert child.returncode == 0 and len(out) <= 16384 and len(err) <= 16384
        remote = json.loads(out)
        response_valid = validate_receiver_response(remote)
        for record, (origin, _, size, expected, mode) in zip(records, FILES):
            _, ident = read_file(UPSTREAM / 'incoming' / origin, size, expected, SOURCE_MODES[origin])
            assert ident == record['sourceIdentityBefore']
            record['sourceIdentityAfter'] = ident; record['sourceUnchanged'] = True
        _, ident = read_file(receipt, 14209, UPSTREAM_RECEIPT_SHA, 0o600)
        assert ident == receipt_identity
        after = source()
        trust_after = {path: read_file(Path(path), size, expected, 0o600)[1]
                       for path, size, expected in TRUST_FILES}
        assert trust_after == trust_before
    except BaseException as exc:
        error = type(exc).__name__
    finally:
        cleanup = cleanup_ssh(child, created)
        cleanup_qualified = (cleanup['errorClass'] is None and cleanup['directChildReaped']
            and cleanup['ownedProcessGroupObservedEmpty'])
        ok = error is None and response_valid and cleanup_qualified
        public_receiver = remote if response_valid else None
        result = {'schema': 'heptabao.pocket-r10-artifact-relay-result.v1', 'ok': ok,
            'errorClass': error, 'sourceBefore': before, 'sourceAfter': after, 'files': records,
            'priorReadonlyRouteWitness': ROUTE_WITNESS, 'trustBefore': trust_before, 'trustAfter': trust_after,
            'receiver': public_receiver, 'receiverResponseParsed': remote is not None,
            'receiverResponseValidated': response_valid,
            'remoteOutcomeUnknown': child is not None and not response_valid,
            'ownedProcessOutcomeUnknown': not cleanup_qualified,
            'outcomeUnknown': (child is not None and not response_valid) or not cleanup_qualified,
            'stdoutBytes': len(out), 'stdoutSha256': hashlib.sha256(out).hexdigest(),
            'stderrBytes': len(err), 'stderrSha256': hashlib.sha256(err).hexdigest(),
            'cleanup': cleanup, 'controllerSha256': args.expected_controller_sha256,
            'startedUnixNs': started, 'finishedUnixNs': time.time_ns(), 'automaticRetry': False,
            'productionChanged': False, 'serverOrConsumerStarted': False, 'privateInputsTransferred': False}
        record = put(ROOT / 'result.public.json', result)
        print(json.dumps({'ok': ok, 'receipt': record, 'receiver': public_receiver, 'cleanup': cleanup}, sort_keys=True))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
