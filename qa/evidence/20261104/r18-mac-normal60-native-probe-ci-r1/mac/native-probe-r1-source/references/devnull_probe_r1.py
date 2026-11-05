#!/usr/bin/env python3
"""One fresh owned sandbox plumbing probe; no current DB or credential inputs.

The parent is admitted through the frozen stdin source loader. It creates only
ROOT below the existing owned fixture root, then runs two exact sandbox cases.
The child modes never import SQLite, the capture library, SDK, or a consumer.
Original profile generation is an exact source copy. The four kernel checks
only rebind their owned probe-directory expression. The generated profile
relocates three captures/before references to a new owned sibling of captures;
no existing captures path is opened by this probe.
"""
from __future__ import annotations
import argparse, base64, errno, hashlib, json, math, os, signal, socket, stat, sys, time
from contextlib import contextmanager
from pathlib import Path

SOURCE_ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1')
ROOT=SOURCE_ROOT
PROBE_STAGE='before'
PROBE_ROOT=ROOT/'devnull-sandbox-probe-r1'
QA=SOURCE_ROOT/'qa'
BASE=PROBE_ROOT
WORKER=BASE/'probe.py'
LIVE=Path('/Users/qianqi/.openclaw')
AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')
CACHE_NAMES=('applied-profiles.json','publish-baseline.json','bad-refresh-quarantine.json',
             'refresh-backoff.json','lease-epochs.json','status.json')
PROBE_CONTENT=b'owned capture kernel-write fence r1\n'
READ_NULL_RULE=b'(allow file-read* (literal "/dev/null"))\n'
ORIGINAL_CAPTURE_SECONDS=45
PUBLIC_HASH_BOUND=8*1024*1024
START=time.monotonic()
until=START+ORIGINAL_CAPTURE_SECONDS
protected=0
pending=None
fds=[]
sockets=[]
hashed_bytes=0

ANCHOR_RAW=base64.b64decode("ewogICJzY2hlbWEiOiAiaGVwdGFiYW8ubWFjLWN1cnJlbnQtdDUtcHVibGljLWFuY2hvci5yMSIsCiAgInNvdXJjZV9pbnZlbnRvcnlfc2hhMjU2IjogIjAwMWQ5ZDMzODRmMWI4YzAwZmEzY2JhOGFmN2YzMDIwYmVkYzU0ZjI2Njc4NjExYWIzY2QzYTUyNGNlMjM5MDIiLAogICJ2b2x1bWVVVUlEIjogIkZCODA0RDFCLTI0Q0ItNEQ2RS1BRUE3LUE5RTE4MDgwNzc1OCIsCiAgImV4cGVjdGVkVm9sdW1lRGV2aWNlIjogIjE2Nzc3MjQ0IiwKICAiYW5jaG9ycyI6IFsKICAgIHsKICAgICAgInBhdGgiOiAiLyIsCiAgICAgICJpZGVudGl0eSI6IFsKICAgICAgICAiMTY3NzcyMzMiLAogICAgICAgICIyIiwKICAgICAgICAiMCIsCiAgICAgICAgIjAiLAogICAgICAgICIxNjg3NyIsCiAgICAgICAgIjIyIiwKICAgICAgICAiNzA0IiwKICAgICAgICAiMTc4NjU4OTUxNTAwMDAwMDAwMCIsCiAgICAgICAgIjE3ODY1ODk1MTUwMDAwMDAwMDAiCiAgICAgIF0KICAgIH0sCiAgICB7CiAgICAgICJwYXRoIjogIi9Wb2x1bWVzIiwKICAgICAgImlkZW50aXR5IjogWwogICAgICAgICIxNjc3NzIzMyIsCiAgICAgICAgIjE4MzM2IiwKICAgICAgICAiMCIsCiAgICAgICAgIjAiLAogICAgICAgICIxNjg3NyIsCiAgICAgICAgIjUiLAogICAgICAgICIxNjAiLAogICAgICAgICIxNzkzMTAwNTk3NzU2NTE1NTkxIiwKICAgICAgICAiMTc5MzEwMDU5Nzc1NjUxNTU5MSIKICAgICAgXQogICAgfSwKICAgIHsKICAgICAgInBhdGgiOiAiL1ZvbHVtZXMvVDUiLAogICAgICAiaWRlbnRpdHkiOiBbCiAgICAgICAgIjE2Nzc3MjQ0IiwKICAgICAgICAiMiIsCiAgICAgICAgIjAiLAogICAgICAgICIwIiwKICAgICAgICAiMTY4OTMiLAogICAgICAgICIxMiIsCiAgICAgICAgIjM4NCIsCiAgICAgICAgIjE3OTMxNTI5NzMxNDQyNjA0OTUiLAogICAgICAgICIxNzkzMTUyOTczMTQ0MjYwNDk1IgogICAgICBdCiAgICB9CiAgXQp9Cg==",validate=True)
ANCHOR_SHA='dd6dce82fb0276d7c0fd181152aef07bb2857e47506311f70ae67cce41b1eab8'
PUBLIC_SOURCES=json.loads("{\"mac_current_capture_entry_r1.py\":{\"bytes\":19011,\"sha256\":\"fe56d9676aacf5cf4feb373130be93c4a17fab2589a1439da4ebe96a4cad4024\",\"git_blob\":\"d972159225b1d7478746c9296eb9bb69eb99844c\"},\"mac_t5_volume_guard_r1.py\":{\"bytes\":13387,\"sha256\":\"10e140b37a17b5f7fd5cc569b1632da99b61fd544ec732a8806ff402d4ee0d99\",\"git_blob\":\"938fd5e5663e004f9f6553548537ab3a931c50d0\"},\"mac_owned_commands_r1.py\":{\"bytes\":5965,\"sha256\":\"eb676e6dedb6d594d944e921738cf9b384f2a98a37ee2bd1fa5433b848a36867\",\"git_blob\":\"c102dfdc565484421bf7dbbb04b7c8b9e4cd5511\"},\"mac_owned_unreaped_r1.py\":{\"bytes\":10990,\"sha256\":\"a143ba334159931d530b49a55c24471f56fa1b62f1e1012e12c75e21f3c22b1d\",\"git_blob\":\"53cddd9243f9f890d9a1b9975b435280ff58ab77\"}}")
UTILITY_PINS=json.loads("[{\"identity\":[\"16777233\",\"1152921500312572700\",\"0\",\"0\",\"33261\",\"1\",\"102368\",\"1786589515000000000\",\"1786589515000000000\"],\"path\":\"/usr/bin/sandbox-exec\",\"resolved\":\"/usr/bin/sandbox-exec\",\"sha256\":\"abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a\"},{\"identity\":[\"16777233\",\"1152921500312575979\",\"0\",\"0\",\"33261\",\"1\",\"1937776\",\"1786589515000000000\",\"1786589515000000000\"],\"path\":\"/usr/sbin/diskutil\",\"resolved\":\"/usr/sbin/diskutil\",\"sha256\":\"624a8601b97ddfaa4b18dd2854c299e084cd45eb18fc152011c97615c3b9da1f\"},{\"identity\":[\"16777233\",\"1152921500312571399\",\"0\",\"0\",\"35309\",\"1\",\"170432\",\"1786589515000000000\",\"1786589515000000000\"],\"path\":\"/bin/ps\",\"resolved\":\"/bin/ps\",\"sha256\":\"3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c\"}]")

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
    need(pending is None,'probe_cancelled')
    left=until-time.monotonic()
    need(left>0,'original_shared_45_second_deadline')
    return left
def close_fd(row):
    if row['closeAttempted']:return row['closed']
    with critical():
        row['closeAttempted']=True
        try:os.close(row['fd']);row['closed']=True
        except BaseException as error:row['closeErrorType']=type(error).__name__
    return row['closed']
def public_read(path,expected_sha,expected_bytes=None,expected_identity=None):
    global hashed_bytes
    path=Path(path)
    allowed={QA/name for name in PUBLIC_SOURCES}|{Path(x['path']) for x in UTILITY_PINS}
    allowed|={WORKER,BASE/'original.sb',BASE/'patched.sb'}
    need(path in allowed,'closed_public_read_set')
    remaining();row=None
    try:
        need(path.resolve(strict=True)==path,'public_fixed_named_path')
        with critical():
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            row={'fd':fd,'closeAttempted':False,'closed':False};fds.append(row)
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1
             and 0<before.st_size<=4*1024*1024,'bounded_regular_public_file')
        if expected_identity is None:
            need(before.st_uid==501 and stat.S_IMODE(before.st_mode)==0o600,
                 'owned_public_source_mode_owner')
        else:
            need(ident(before)==tuple(expected_identity),'frozen_public_tool_identity')
        if expected_bytes is not None:need(before.st_size==expected_bytes,'fixed_public_size')
        raw=bytearray()
        while True:
            remaining()
            block=os.read(fd,min(65536,4*1024*1024+1-len(raw)))
            if not block:break
            raw.extend(block);hashed_bytes+=len(block)
            need(len(raw)<=4*1024*1024 and hashed_bytes<=PUBLIC_HASH_BOUND,
                 'public_hash_read_bounds')
        need(len(raw)==before.st_size and ident(before)==ident(os.fstat(fd))==ident(path.lstat()),
             'public_fd_named_whole_identity')
        need(sha(raw)==expected_sha,'public_whole_sha')
        return bytes(raw),{'bytes':len(raw),'sha256':sha(raw),'identity':list(ident(before))}
    finally:
        if row is not None:need(close_fd(row),'public_descriptor_close')
def source_snapshot():
    result={}
    for name,pin in PUBLIC_SOURCES.items():
        _,result[name]=public_read(QA/name,pin['sha256'],pin['bytes'])
    return result
def utility_snapshot():
    result={}
    for pin in UTILITY_PINS:
        _,result[pin['path']]=public_read(pin['path'],pin['sha256'],
            int(pin['identity'][6]),pin['identity'])
    return result
def safe_error(report,error,step):
    report['errorStage']=step
    report['errorType']=type(error).__name__
    report['errorCode']=str(error) if isinstance(error,Refused) else None
    value=getattr(error,'errno',None) if isinstance(error,OSError) else None
    report['errorErrno']=value if type(value) is int and 0<value<=4095 else None
    # No exception message, filename, private content, or child stderr is copied.
def absence_twice(guard,path):
    observations=[]
    with guard.parent(path) as (parent,name):
        for _ in range(2):
            remaining()
            try:os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:observations.append(True)
            else:raise Refused('fresh_probe_path_must_be_absent')
    need(observations==[True,True],'double_named_absence')
    return observations

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

def profiles():
    original=capture_profile('before')
    need(sha(original)=='de74f118ead7f9769dd12e692b116fc80aaaa5953d559c8f63b0f8c3125cf387',
         'exact_actual_failed_capture_profile')
    original_prefix=str(ROOT/'captures/before').encode()
    need(original.count(original_prefix)==3,'three_fixed_capture_path_bindings')
    original=original.replace(original_prefix,str(PROBE_ROOT).encode())
    need(READ_NULL_RULE not in original,'original_missing_exact_devnull_read_rule')
    marker=b'(allow file-read* (literal "/dev/urandom"))\n'
    need(original.count(marker)==1,'unique_original_profile_marker')
    patched=original.replace(marker,READ_NULL_RULE+marker,1)
    need(patched.replace(READ_NULL_RULE,b'',1)==original,'only_devnull_read_rule_added')
    return {'original':original,'patched':patched}

def kernel_refusals(guard,stage):
    directory=BASE/'probe';main=directory/'writable-owned-main'
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

def null_read_case(variant):
    row=None;error=None;kind=None;read_eof=None
    try:
        remaining()
        try:
            with critical():
                fd=os.open('/dev/null',os.O_RDONLY)
                row={'fd':fd,'closeAttempted':False,'closed':False};fds.append(row)
            kind=stat.S_ISCHR(os.fstat(fd).st_mode)
            read_eof=os.read(fd,1)==b''
        except OSError as caught:error=caught.errno
    finally:
        if row is not None:need(close_fd(row),'devnull_read_descriptor_close')
    observed={'opened':row is not None,'errno':error,'characterDevice':kind,
              'readReturnedEof':read_eof,
              'descriptorClosed':row is None or row['closed']}
    if variant=='original':
        need(row is None and error in (errno.EACCES,errno.EPERM),
             'original_profile_must_deny_new_devnull_read')
        observed['expectedReadRefused']=True
    else:
        need(row is not None and error is None and kind and read_eof and row['closed'],
             'patched_literal_must_allow_exact_devnull_read')
        observed['expectedReadRefused']=False
    remaining()
    return observed

def typed_child(raw,variant,source_sha):
    try:value=json.loads(raw)
    except (ValueError,UnicodeError) as error:raise Refused('child_json_unavailable') from error
    need(isinstance(value,dict) and value.get('schema')=='heptabao.mac-capture-devnull-sandbox-child.r1'
         and value.get('variant')==variant and value.get('sourceSha256')==source_sha
         and type(value.get('ok')) is bool and type(value.get('outcomeUnknown')) is bool,
         'child_report_protocol_unavailable')
    for key in ('productionReadAttempted','productionWriteAttempted','sqliteImported',
                'consumerStarted','providerRequested','j3160Contacted'):
        need(value.get(key) is False,'child_scope_field')
    count=value.get('boundedPublicPinReadBytesThisProcess')
    need(type(count) is int and 0<=count<=PUBLIC_HASH_BOUND
         and type(value.get('allOwnedDescriptorsClosed')) is bool
         and type(value.get('originalDeadlineMetAfterClosure')) is bool
         and value.get('originalAbsoluteDeadlineMonotonic')==until,
         'child_report_closure_and_accounting_protocol')
    if value['ok']:
        need(not value['outcomeUnknown'] and value['allOwnedDescriptorsClosed']
             and value['originalDeadlineMetAfterClosure']
             and value.get('ownedCommands',{}).get('allOwnedCommandsStopped') is True
             and value.get('ownedCommands',{}).get('unknownCommandCount')==0,
             'child_success_closure_consistency')
        null=value.get('devNullRead')
        need(isinstance(null,dict) and type(null.get('opened')) is bool
             and null.get('descriptorClosed') is True
             and null.get('expectedReadRefused') is (variant=='original'),
             'child_success_devnull_protocol')
    return value

def main():
    global until
    parser=argparse.ArgumentParser()
    parser.add_argument('--child',choices=('original','patched'))
    parser.add_argument('--absolute-until',type=float)
    parser.add_argument('--source-sha256')
    args=parser.parse_args()
    os.umask(0o077)
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,interrupted)
    is_child=args.child is not None
    report={'schema':'heptabao.mac-capture-devnull-sandbox-child.r1' if is_child else
            'heptabao.mac-capture-devnull-sandbox-probe.r1',
        'variant':args.child,'ok':False,'outcomeUnknown':False,
        'productionReadAttempted':False,'productionWriteAttempted':False,
        'sqliteImported':False,'consumerStarted':False,'providerRequested':False,
        'j3160Contacted':False,'failedCaptureBeforePathUsed':False,'freshOwnedProbeOnly':True,'businessReplay':False,
        'newOwnedRoot':str(PROBE_ROOT),'originalCaptureSeconds':45,
        'cases':[],'newFiles':[],'newDirectories':[],
        'publicDiagnosticsContainExceptionMessage':False,
        'publicDiagnosticsContainFilename':False,'childStderrPublished':False}
    guard=None;commands=None;complete=False
    step='argument_admission'
    try:
        need(sys.platform=='darwin' and os.getuid()==501,'actual_mac_probe_owner')
        if is_child:
            need(args.absolute_until is not None and math.isfinite(args.absolute_until)
                 and START<args.absolute_until<=START+45,'same_original_parent_deadline')
            until=args.absolute_until
            need(isinstance(args.source_sha256,str) and len(args.source_sha256)==64
                 and all(c in '0123456789abcdef' for c in args.source_sha256),'child_source_hash_shape')
            self_raw,self_pin=public_read(WORKER,args.source_sha256)
            report['sourceSha256']=args.source_sha256
        else:
            need(args.absolute_until is None and args.source_sha256 is None,'fixed_parent_no_input_overrides')
            self_raw=globals().get('_ROOT_AUTHORED_SOURCE')
            need(isinstance(self_raw,bytes) and 0<len(self_raw)<=131072,'exact_frozen_stdin_source')
            report['sourceSha256']=sha(self_raw)
        step='public_source_before'
        before_sources=source_snapshot()
        report['sourceBefore']=before_sources
        if not is_child:
            step='public_tools_before';report['utilityBefore']=utility_snapshot()
        sys.path.insert(0,str(QA))
        from mac_t5_volume_guard_r1 import HeldT5
        from mac_owned_commands_r1 import Commands
        class SignalState:
            @property
            def pending(self):return pending
            def critical(self):return critical()
        commands=Commands(SignalState())
        step='held_t5_anchor'
        guard=HeldT5(ANCHOR_RAW,ANCHOR_SHA,remaining,critical)
        policy=profiles()
        report['profileSha256']={name:sha(raw) for name,raw in policy.items()}
        if is_child:
            step='public_profile_before'
            _,profile_before=public_read(BASE/(args.child+'.sb'),sha(policy[args.child]),len(policy[args.child]))
            step='devnull_read_open'
            report['devNullRead']=null_read_case(args.child)
            if args.child=='patched':
                step='child_diskutil_command'
                row,out,err=commands.run('patched-sandbox-t5-volume',
                    ['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
                    until=min(until,time.monotonic()+30),maximum=262144)
                need(row['exitCode']==0 and row['completeBeforeDeadline']
                     and not row['outcomeUnknown'] and not err,'patched_diskutil_known_complete')
                step='child_diskutil_identity';guard.accept_diskutil(out)
                step='owned_write_sidecar_loopback_refusals'
                report['kernelSandboxProof']=kernel_refusals(guard,PROBE_STAGE)
            step='public_profile_after'
            _,profile_after=public_read(BASE/(args.child+'.sb'),sha(policy[args.child]),len(policy[args.child]))
            need(profile_after==profile_before,'public_profile_unchanged')
            _,self_after=public_read(WORKER,args.source_sha256)
            need(self_after==self_pin,'child_source_unchanged')
        else:
            step='parent_diskutil_command'
            row,out,err=commands.run('probe-parent-t5-volume',
                ['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
                until=min(until,time.monotonic()+30),maximum=262144)
            need(row['exitCode']==0 and row['completeBeforeDeadline']
                 and not row['outcomeUnknown'] and not err,'parent_diskutil_known_complete')
            guard.accept_diskutil(out)
            step='fresh_owned_root_absence'
            report['rootAbsenceBefore']=absence_twice(guard,PROBE_ROOT)
            step='fresh_owned_creation'
            for path in (PROBE_ROOT,BASE/'probe',BASE/'output'):
                record=guard.mkdir_new(path)
                report['newDirectories'].append({'path':str(path),'identity':record})
            for path,raw in ((WORKER,self_raw),(BASE/'original.sb',policy['original']),
                    (BASE/'patched.sb',policy['patched']),
                    (BASE/'probe/writable-owned-main',PROBE_CONTENT)):
                pin=guard.write_new(path,raw)
                need(guard.read(path,max(4096,len(raw)))==raw,'created_owned_whole_readback')
                report['newFiles'].append({'path':str(path),**pin})
            for variant in ('original','patched'):
                step='launch_'+variant+'_sandbox_child'
                argv=['/usr/bin/sandbox-exec','-f',str(BASE/(variant+'.sb')),
                    '/opt/homebrew/bin/python3','-I','-S','-B',str(WORKER),
                    '--child',variant,'--absolute-until',repr(until),
                    '--source-sha256',sha(self_raw)]
                row,out,err=commands.run('sandbox-'+variant,argv,until=until,maximum=262144)
                step='read_'+variant+'_public_report'
                try:value=typed_child(out,variant,sha(self_raw))
                except BaseException:
                    report['outcomeUnknown']=True
                    raise
                report['cases'].append({'variant':variant,'exitCode':row['exitCode'],
                    'stdoutBytes':len(out),'stdoutSha256':sha(out),
                    'stderrBytes':len(err),'stderrSha256':sha(err),'report':value})
                report['outcomeUnknown']=bool(report['outcomeUnknown'] or row['outcomeUnknown']
                                             or value['outcomeUnknown'])
                need(row['exitCode']==0 and row['completeBeforeDeadline']
                     and not row['outcomeUnknown'] and not err and value['ok']
                     and not value['outcomeUnknown'] and value.get('originalDeadlineMetAfterClosure') is True
                     and value.get('allOwnedDescriptorsClosed') is True,'child_known_expected_terminal')
                need(value['devNullRead']['expectedReadRefused']==(variant=='original')
                     and value['devNullRead']['descriptorClosed'],'actual_devnull_variant_result')
                if variant=='patched':
                    need(value.get('kernelSandboxProof',{}).get('allFourDenied') is True
                         and value.get('heldT5Final',{}).get('volumeUUIDVerified') is True,
                         'patched_other_kernel_fences_and_volume')
            step='owned_after_fences'
            need(guard.read(BASE/'probe/writable-owned-main',4096)==PROBE_CONTENT,
                 'owned_main_after_whole_bytes')
            for suffix in ('-wal','-shm'):
                absence_twice(guard,BASE/'probe'/('writable-owned-main'+suffix))
            for record in report['newFiles']:
                raw=guard.read(Path(record['path']),max(4096,record['bytes']))
                need(len(raw)==record['bytes'] and sha(raw)==record['sha256']
                     and list(ident(Path(record['path']).lstat()))==record['identity'],
                     'owned_new_file_full_identity_after')
            step='public_tools_after';report['utilityAfter']=utility_snapshot()
            need(report['utilityAfter']==report['utilityBefore'],'fixed_public_tools_before_after')
        step='public_source_after';report['sourceAfter']=source_snapshot()
        need(report['sourceAfter']==before_sources,'original_public_sources_before_after')
        step='final_anchor';guard.check();remaining();complete=True
    except BaseException as error:
        safe_error(report,error,step)
        report['outcomeUnknown']=bool(report['outcomeUnknown'] or isinstance(error,KeyboardInterrupt))
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
        report['outcomeUnknown']=bool(report['outcomeUnknown'] or pending is not None or not closed or not stopped)
        report['allOwnedDescriptorsClosed']=closed
        report['boundedPublicPinReadBytesThisProcess']=hashed_bytes
        report['totalBoundedPublicPinReadBytes']=hashed_bytes+sum(
            case['report'].get('boundedPublicPinReadBytesThisProcess',0) for case in report['cases'])
        report['aggregatePublicPinReadBound']=PUBLIC_HASH_BOUND
        done=time.monotonic()
        report['elapsedSeconds']=done-START
        report['originalAbsoluteDeadlineMonotonic']=until
        report['originalDeadlineMetAfterClosure']=done<until
        report['ok']=bool(complete and closed and stopped and not report['outcomeUnknown']
                         and done<until and report['totalBoundedPublicPinReadBytes']<=PUBLIC_HASH_BOUND)
        report['authoritativeExitZeroAndExactOriginalStdoutRequired']=True
        output=encoded(report);need(len(output)<=262144,'bounded_public_probe_result')
        sys.stdout.buffer.write(output);sys.stdout.buffer.flush()
    return 0 if report['ok'] and time.monotonic()<until else 1

if __name__=='__main__':sys.exit(main())
