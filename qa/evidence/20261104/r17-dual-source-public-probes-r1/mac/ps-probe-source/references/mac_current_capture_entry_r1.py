#!/usr/bin/env python3
"""Guarded current-Mac capture entry, after successful owned synthetic admission.

Source-only. The outer owner must execute this exact entry under its generated
sandbox profile. The entry itself verifies that exact profile and demonstrates
owned-file/sidecar write and loopback-connect refusal before any current input
is opened. Immutable observations are not database or cross-agent snapshots.
"""
from __future__ import annotations
import argparse, base64, errno, hashlib, json, math, os, signal, socket, stat, sys, time
from contextlib import contextmanager
from pathlib import Path

ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1')
QA=ROOT/'qa'
LIVE=Path('/Users/qianqi/.openclaw')
AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')
CACHE_NAMES=('applied-profiles.json','publish-baseline.json','bad-refresh-quarantine.json',
             'refresh-backoff.json','lease-epochs.json','status.json')
NAMES=('mac_current_capture_entry_r1.py','mac_guarded_current_capture_r3.py',
       'mac_t5_volume_guard_r1.py','mac_owned_commands_r1.py','mac_owned_unreaped_r1.py')
SYNTHETIC_SOURCE_SHA='f3c6bb336814411aa4a24490f0904cdbd0fac2bb89dbcc36d6151ada13a51ba2'
CAPTURE_SOURCE_SHA='606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693'
PROBE_CONTENT=b'owned capture kernel-write fence r1\n'
START=time.monotonic()
until=None
protected=0
pending=None
fds=[]
sockets=[]

class Refused(RuntimeError):pass
def need(value,code):
    if not value:raise Refused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def ident(s):
    return tuple(str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,
        s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))
@contextmanager
def critical():
    global protected
    protected+=1
    try:yield
    finally:protected-=1
def interrupted(signum,_frame):
    global pending
    pending=signum
    if not protected:raise KeyboardInterrupt()
def remaining():
    need(pending is None,'capture_entry_cancelled')
    need(until is not None,'capture_entry_deadline_not_bound')
    left=until-time.monotonic();need(left>0,'original_capture_entry_deadline');return left

def close_fd(row):
    if row['closeAttempted']:return row['closed']
    with critical():
        row['closeAttempted']=True
        try:os.close(row['fd']);row['closed']=True
        except BaseException as error:row['closeErrorType']=type(error).__name__
    return row['closed']

def source_bytes(path):
    remaining();row=None
    try:
        with critical():
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            row={'fd':fd,'closeAttempted':False,'closed':False};fds.append(row)
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
             and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=1024*1024,
             'fixed_public_source_custody')
        chunks=[];count=0
        while True:
            remaining();chunk=os.read(fd,min(65536,1024*1024+1-count))
            if not chunk:break
            count+=len(chunk);need(count<=1024*1024,'source_bound');chunks.append(chunk)
        need(count==before.st_size and ident(before)==ident(os.fstat(fd))==ident(path.lstat()),
             'source_fd_name_stable')
        return b''.join(chunks),ident(before)
    finally:
        if row is not None:need(close_fd(row),'public_source_fd_close_failed')

def capture_profile(stage):
    need(stage in ('before','after'),'fixed_capture_stage')
    read_paths={Path('/'),Path('/Volumes'),Path('/Volumes/T5'),ROOT,QA,ROOT/'proofs',
                ROOT/'captures',ROOT/'captures'/stage}
    files={LIVE/'openclaw.json'}
    for database in [LIVE/'state/openclaw.sqlite',*[
        LIVE/'agents'/agent/'agent/openclaw-agent.sqlite' for agent in AGENTS]]:
        for suffix in ('','-wal','-shm','-journal'):files.add(Path(str(database)+suffix))
    files.add(LIVE/'authbus')
    files.update(LIVE/'authbus'/name for name in CACHE_NAMES)
    for agent in AGENTS:
        native=LIVE/'agents'/agent/'agent/codex-home';files.add(native)
        files.update(native/name for name in ('config.toml','requirements.toml','auth.json'))
    for path in files:
        read_paths.add(path);read_paths.update(path.parents)
    q=lambda value:json.dumps(str(value))
    lines=['(version 1)','(deny default)','(allow process*)',
        '(allow signal (target children))','(allow sysctl-read)','(allow mach-lookup)',
        '(allow file-read-metadata)']
    for path in ('/System','/usr','/bin','/sbin','/Library','/private/etc','/opt/homebrew','/dev/fd'):
        lines.append('(allow file-read* (subpath '+q(path)+'))')
    for path in (QA,ROOT/'proofs',ROOT/'captures'/stage):
        lines.append('(allow file-read* (subpath '+q(path)+'))')
    for path in sorted(read_paths,key=str):
        lines.append('(allow file-read* (literal '+q(path)+'))')
    lines.extend(['(allow file-read* (literal "/dev/urandom"))',
        '(allow file-read* (literal "/dev/random"))',
        '(allow file-write* (subpath '+q(ROOT/'captures'/stage/'output')+'))',
        '(allow file-write* (literal "/dev/null"))'])
    # No network rule. The only write exception is the new capture output root.
    return ('\n'.join(lines)+'\n').encode()

def admitted_synthetic(guard,binding):
    expected={'schema','jobId','stdoutSha256','stdoutBytes','authoritySha256',
              'authorityBytes','controllerSha256'}
    need(isinstance(binding,dict) and set(binding)==expected
         and binding['schema']=='heptabao.mac-capture-synthetic-input-binding.r1'
         and isinstance(binding['jobId'],str) and 1<=len(binding['jobId'])<=128
         and binding['controllerSha256']==SYNTHETIC_SOURCE_SHA,
         'fixed_actual_synthetic_binding')
    for key in ('stdoutSha256','authoritySha256'):
        need(isinstance(binding[key],str) and len(binding[key])==64
             and all(c in '0123456789abcdef' for c in binding[key]),'synthetic_binding_sha')
    for key in ('stdoutBytes','authorityBytes'):
        need(type(binding[key]) is int and 0<binding[key]<=65536,'synthetic_binding_size')
    raw=guard.read(ROOT/'proofs/synthetic-r2.stdout.public.json',65536)
    authority_raw=guard.read(ROOT/'proofs/synthetic-r2.authority.public.json',65536)
    need(len(raw)==binding['stdoutBytes'] and sha(raw)==binding['stdoutSha256']
         and len(authority_raw)==binding['authorityBytes']
         and sha(authority_raw)==binding['authoritySha256'],'actual_original_synthetic_bytes')
    authority=json.loads(authority_raw);proof=json.loads(raw)
    need(isinstance(authority,dict) and authority.get('job_id')==binding['jobId']
         and type(authority.get('exit_code')) is int and authority['exit_code']==0
         and authority.get('state')=='succeeded'
         and all(authority.get(k) is True for k in
             ('output_complete','output_durable','terminal_publication_confirmed'))
         and all(authority.get(k) is False for k in ('timed_out','cancelled','automatic_retry')),
         'successful_authoritative_synthetic_terminal')
    for stream,size in (('stdout',len(raw)),('stderr',0)):
        need(authority.get('log_bytes',{}).get(stream)=={'seen':size,'stored':size}
             and authority.get('log_errors',{}).get(stream) is None
             and authority.get('log_synced',{}).get(stream) is True
             and authority.get('log_truncated',{}).get(stream) is False,
             'complete_original_synthetic_log_'+stream)
    need(isinstance(proof,dict) and proof.get('ok') is True
         and proof.get('outcomeUnknown') is False and proof.get('controllerGeneration')=='r2'
         and proof.get('productionOpened') is False
         and proof.get('originalDeadlineMetAfterClosure') is True
         and proof.get('sameRuntimeBeforeAfter') is True
         and type(proof.get('elapsedSeconds')) in (int,float)
         and 0<=proof['elapsedSeconds']<45
         and proof.get('sourcePins',{}).get('mac_capture_sqlite_synthetic_r2.py')==SYNTHETIC_SOURCE_SHA
         and proof.get('captureSourceSha256')==CAPTURE_SOURCE_SHA,
         'successful_complete_r2_synthetic_report')
    cases=proof.get('cases')
    need(isinstance(cases,list) and len(cases)==7
         and all(isinstance(row,dict) and row.get('passed') is True for row in cases),
         'all_seven_original_synthetic_cases')
    held=proof.get('heldT5Final',{});owned=proof.get('ownedCommands',{})
    need(proof.get('allOwnedDescriptorsClosed') is True
         and held.get('allDescriptorsClosed') is True and held.get('lastAnchorCheckPassed') is True
         and held.get('closeErrors')==[] and owned.get('allOwnedCommandsStopped') is True
         and owned.get('unknownCommandCount')==0,'synthetic_complete_owned_closure')
    return raw,proof

def kernel_refusals(guard,stage):
    directory=ROOT/'captures'/stage/'probe';main=directory/'writable-owned-main'
    need(guard.read(main,4096)==PROBE_CONTENT,'owned_probe_exact_initial_bytes')
    original=ident(main.lstat());rows=[]
    for path,create in ((main,False),(Path(str(main)+'-wal'),True),(Path(str(main)+'-shm'),True)):
        remaining();refusal=None;opened=None
        with guard.parent(path) as (parent,name):
            if create:
                try:os.stat(name,dir_fd=parent,follow_symlinks=False)
                except FileNotFoundError:pass
                else:raise Refused('owned_probe_sidecar_preexisting')
            try:
                with critical():
                    flags=os.O_WRONLY|os.O_NOFOLLOW|(os.O_CREAT|os.O_EXCL if create else os.O_APPEND)
                    fd=os.open(name,flags,0o600,dir_fd=parent)
                    opened={'fd':fd,'closeAttempted':False,'closed':False};fds.append(opened)
            except OSError as error:refusal=error.errno
            finally:
                if opened is not None:need(close_fd(opened),'owned_probe_fd_close')
            need(opened is None and refusal in (errno.EACCES,errno.EPERM),'kernel_owned_write_not_refused')
            if create:
                try:os.stat(name,dir_fd=parent,follow_symlinks=False)
                except FileNotFoundError:pass
                else:raise Refused('owned_probe_sidecar_created')
        rows.append({'case':'sidecar_create' if create else 'main_write_open',
                     'name':path.name,'denied':True,'errno':refusal})
    need(ident(main.lstat())==original and guard.read(main,4096)==PROBE_CONTENT,
         'owned_probe_no_file_change')
    endpoint=('127.0.0.1',9);sock=None;refusal=None;socket_row=None
    try:
        with critical():
            sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            socket_row={'socket':sock,'closeAttempted':False,'closed':False};sockets.append(socket_row)
        sock.settimeout(min(3.0,remaining()))
        sock.connect(endpoint)
    except OSError as error:refusal=error.errno
    finally:
        if socket_row is not None:
            with critical():
                socket_row['closeAttempted']=True
                try:sock.close();socket_row['closed']=True
                except BaseException as error:socket_row['closeErrorType']=type(error).__name__
    need(refusal in (errno.EACCES,errno.EPERM),'kernel_loopback_connect_not_refused')
    need(socket_row is None or socket_row['closed'],'owned_probe_socket_close')
    rows.append({'case':'loopback_connect','endpoint':'127.0.0.1:9','denied':True,'errno':refusal})
    remaining()
    return {'allFourDenied':True,'onlyOwnedWriteProbes':True,'externalAddressAttempted':False,
            'profileWriteScope':'fresh_capture_output_only','checks':rows}

def main():
    global until
    parser=argparse.ArgumentParser()
    parser.add_argument('--stage',choices=('before','after'),required=True)
    parser.add_argument('--absolute-until',type=float,required=True)
    parser.add_argument('--public-volume-anchor-base64',required=True)
    parser.add_argument('--public-volume-anchor-sha256',required=True)
    parser.add_argument('--source-pins-base64',required=True)
    parser.add_argument('--source-pins-sha256',required=True)
    parser.add_argument('--synthetic-binding-base64',required=True)
    parser.add_argument('--synthetic-binding-sha256',required=True)
    parser.add_argument('--sandbox-profile-sha256',required=True)
    args=parser.parse_args();os.umask(0o077)
    need(math.isfinite(args.absolute_until) and START<args.absolute_until<=START+45,
         'one_original_capture_deadline')
    until=args.absolute_until
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,interrupted)
    report={'schema':'heptabao.mac-guarded-current-capture-entry.r1','stage':args.stage,
        'ok':False,'outcomeUnknown':False,'productionReadAttempted':False,
        'productionWriteAttempted':False,'captureLibraryReturned':False,
        'providerRequestSent':False,'j3160Contacted':False,
        'wholeDatabaseBackupQualified':False,'crossAgentAtomicSnapshotClaimed':False,
        'originalCaptureSeconds':45}
    guard=None;commands=None;cap=None;complete=False;capsule=None
    try:
        need(sys.platform=='darwin' and os.getuid()==501,'actual_mac_capture_owner')
        pins_raw=base64.b64decode(args.source_pins_base64,validate=True)
        need(len(pins_raw)<=8192 and sha(pins_raw)==args.source_pins_sha256,'exact_entry_source_pins')
        pins=json.loads(pins_raw)
        need(isinstance(pins,dict) and set(pins)==set(NAMES)
             and all(isinstance(v,str) and len(v)==64 and all(c in '0123456789abcdef' for c in v)
                     for v in pins.values()) and pins['mac_guarded_current_capture_r3.py']==CAPTURE_SOURCE_SHA,
             'fixed_public_capture_modules')
        source_ids={}
        for name,pin in pins.items():
            raw,source_ids[name]=source_bytes(QA/name);need(sha(raw)==pin,'capture_public_source_pin')
        sys.path.insert(0,str(QA))
        from mac_t5_volume_guard_r1 import HeldT5
        from mac_owned_commands_r1 import Commands
        import mac_guarded_current_capture_r3 as capture
        cap=capture
        class SignalState:
            @property
            def pending(self):return pending
            def critical(self):return critical()
        commands=Commands(SignalState())
        anchor=base64.b64decode(args.public_volume_anchor_base64,validate=True)
        guard=HeldT5(anchor,args.public_volume_anchor_sha256,remaining,critical)
        row,out,_=commands.run('capture-t5-volume',
            ['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
            until=min(until,time.monotonic()+30),maximum=262144)
        need(row['exitCode']==0 and not row['outcomeUnknown'] and row['completeBeforeDeadline'],
             'capture_volume_probe_complete')
        guard.accept_diskutil(out)
        binding_raw=base64.b64decode(args.synthetic_binding_base64,validate=True)
        need(len(binding_raw)<=8192 and sha(binding_raw)==args.synthetic_binding_sha256,
             'actual_synthetic_public_binding')
        proof,proof_value=admitted_synthetic(guard,json.loads(binding_raw))
        capture.validate_synthetic_proof(proof,sha(proof),remaining=remaining,critical=critical)
        profile=guard.read(ROOT/'captures'/args.stage/'capture.sb',65536)
        need(profile==capture_profile(args.stage) and sha(profile)==args.sandbox_profile_sha256,
             'exact_reviewed_capture_sandbox')
        report['kernelSandboxProof']=kernel_refusals(guard,args.stage)
        remaining();guard.check()
        report['productionReadAttempted']=True
        document,observation=capture.capture_current(critical=critical,cancelled=lambda:pending is not None,
            synthetic_proof=proof,synthetic_proof_sha=sha(proof),until=until)
        report['captureLibraryReturned']=True
        report['observation']=observation;report['runtime']=document['runtime']
        report['syntheticProofSha256']=sha(proof)
        need(document['runtime']==proof_value['runtime'],'same_actual_capture_runtime')
        remaining()
        capsule_raw=capture.encoded(document)
        need(len(capsule_raw)<=4*1024*1024,'private_capsule_bound')
        output=ROOT/'captures'/args.stage/'output/capsule.private.json'
        capsule=guard.write_new(output,capsule_raw)
        report['capsule']={'path':str(output),**capsule}
        for name,pin in pins.items():
            raw,observed=source_bytes(QA/name)
            need(sha(raw)==pin and observed==source_ids[name],'capture_sources_after')
        guard.check();remaining();complete=True
    except BaseException as error:
        report['errorType']=type(error).__name__
        report['errorCode']=str(error) if isinstance(error,Refused) or (
            cap is not None and isinstance(error,cap.CaptureRefused)) else None
        report['outcomeUnknown']=bool(report['productionReadAttempted']
            and not report['captureLibraryReturned']) or isinstance(error,KeyboardInterrupt)
    finally:
        for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,signal.SIG_IGN)
        for row in reversed(fds):close_fd(row)
        for row in reversed(sockets):
            if not row['closeAttempted']:
                with critical():
                    row['closeAttempted']=True
                    try:row['socket'].close();row['closed']=True
                    except BaseException as error:row['closeErrorType']=type(error).__name__
        if commands is not None:report['ownedCommands']=commands.public()
        if guard is not None:
            guard.close();report['heldT5Final']=guard.public_state()
        closed=(all(row['closed'] for row in fds) and all(row['closed'] for row in sockets)
            and guard is not None and report['heldT5Final']['allDescriptorsClosed']
            and report['heldT5Final']['lastAnchorCheckPassed']
            and report['heldT5Final']['closeErrors']==[])
        stopped=(commands is not None and report['ownedCommands']['allOwnedCommandsStopped']
                 and report['ownedCommands']['unknownCommandCount']==0)
        report['allOwnedDescriptorsClosed']=closed
        report['outcomeUnknown']=bool(report['outcomeUnknown'] or not closed or not stopped or pending is not None)
        done=time.monotonic()
        report['elapsedSeconds']=done-START
        report['originalAbsoluteDeadlineMonotonic']=until
        report['originalDeadlineMetAfterPrivatePublicationAndClosure']=done<until
        report['ok']=bool(complete and capsule is not None and closed and stopped
                          and not report['outcomeUnknown'] and done<until)
        report['authoritativeExitZeroAndOriginalDeadlineRequired']=True
        raw=encoded(report);need(len(raw)<=262144,'public_capture_report_bound')
        sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
    return 0 if report['ok'] and time.monotonic()<until else 1

if __name__=='__main__':sys.exit(main())
