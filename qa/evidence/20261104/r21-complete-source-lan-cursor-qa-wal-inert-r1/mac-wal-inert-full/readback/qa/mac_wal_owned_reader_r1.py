#!/usr/bin/env python3
"""One fresh public-only sandbox reader. No production namespace is read."""
from __future__ import annotations
import argparse, errno, hashlib, json, os, re, select, signal, socket, sqlite3, stat, sys, time
from pathlib import Path

TOP=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-current-registry-readonly-wal-synthetic-r1')
QA=TOP/'qa'
NAMES=('mac_guarded_current_capture_r3.py','mac_registry_readonly_wal_r1.py',
 'mac_wal_owned_reader_r1.py','mac_wal_owned_synthetic_r1.py',
 'mac_t5_volume_guard_r1.py','mac_darwin_owned_projection_r1.py',
 'mac_native_owned_unreaped_r1.py','mac_native_owned_commands_r1.py',
 'mac_owned_unreaped_r1.py','mac_owned_commands_r1.py')
ROOT=None;LIVE=None;AGENTS=None;CACHE_NAMES=None;signals=None;UNTIL=None
fds=[];sockets=[]
PROBE_CONTENT=b'owned-readonly-wal-kernel-probe-r1\n'

class Refused(RuntimeError):pass
def need(value,code):
    if not value:raise Refused(code)
def ident(s):
    return tuple(str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))
def digest(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def remaining(until=None):
    need(signals is None or signals.pending is None,'reader_cancelled')
    n=min(UNTIL,until if until is not None else UNTIL)-time.monotonic()
    need(n>0,'original_reader_deadline_exhausted');return n
def critical():return signals.critical()
def close_fd(row):
    if row['closeAttempted']:return row['closed']
    with critical():
        row['closeAttempted']=True
        try:os.close(row['fd']);row['closed']=True
        except BaseException as error:row['closeErrorType']=type(error).__name__
    return row['closed']
def read_public(path,maximum,expected=None):
    need(path.resolve(strict=True)==path,'public_path_has_no_alias')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_gid==20
             and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and 0<=before.st_size<=maximum,
             'public_file_custody')
        raw=b''
        while len(raw)<=maximum:
            block=os.read(fd,min(65536,maximum+1-len(raw)))
            if not block:break
            raw+=block
        need(len(raw)==before.st_size and ident(before)==ident(os.fstat(fd))==ident(path.lstat()),'public_file_changed')
        if expected is not None:need(digest(raw)==expected,'public_file_whole_pin')
        result=(raw,ident(before))
    finally:os.close(fd)
    return result

def existing_sidecar_write_refusals(guard):
    rows=[]
    for suffix in ('-wal','-shm'):
        path=LIVE/'state'/('openclaw.sqlite'+suffix);before=ident(path.lstat());opened=None;code=None
        with guard.parent(path) as (parent,name):
            try:
                with critical():
                    fd=os.open(name,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW,dir_fd=parent)
                    opened={'fd':fd,'closeAttempted':False,'closed':False};fds.append(opened)
            except OSError as error:code=error.errno
            finally:
                if opened is not None:close_fd(opened)
        need(opened is None and code in (errno.EACCES,errno.EPERM),'existing_sidecar_write_not_denied')
        need(ident(path.lstat())==before,'existing_sidecar_probe_changed_file')
        rows.append({'suffix':suffix,'errno':code,'denied':True})
    return rows

def barrier(case,event_fd,control_fd,until):
    message=encoded({'event':'after_fixed_read','case':case,'queryUntil':until})
    need(len(message)<=256,'barrier_message_bound')
    sent=0
    while sent<len(message):
        _,ready,_=select.select([],[event_fd],[],remaining(until));need(ready,'barrier_write_timeout')
        sent+=os.write(event_fd,message[sent:])
    response=b''
    while b'\n' not in response:
        ready,_,_=select.select([control_fd],[],[],remaining(until));need(ready,'barrier_read_timeout')
        block=os.read(control_fd,64)
        need(block,'barrier_eof');response+=block;need(len(response)<=64,'barrier_response_bound')
    need(response==('continue:'+case+'\n').encode(),'exact_barrier_response')
    remaining(until)

def shm_denied_engine_control(wal,inputs):
    connection=None;error=None;row_produced=False;readonly_denial=None;test_fd=None
    runtime=None;started=time.monotonic();until=min(UNTIL,started+3.0)
    path=LIVE/'state/openclaw.sqlite'
    try:
        runtime=wal.observed_runtime(inputs)
        main=inputs.hold(path)
        inputs.hold(Path(str(path)+'-wal'),maximum=wal.WAL_MAXIMUM)
        parent=inputs.parent(Path(str(path)+'-shm'))
        try:
            with critical():
                fd=os.open(path.name+'-shm',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent['fd'])
                test_fd={'fd':fd,'closeAttempted':False,'closed':False};fds.append(test_fd)
        except OSError as caught:readonly_denial=caught.errno
        finally:
            if test_fd is not None:close_fd(test_fd)
        need(test_fd is None and readonly_denial in (errno.EACCES,errno.EPERM),'actual_shm_read_denial_required')
        connection=inputs.connect(wal.uri_for({'main':main}),until=until,label='public-shm-engine-control')
        wal.configure_connection(inputs,connection,until=until)
        rows=inputs.execute(connection,'SELECT index_key,'+','.join('c_'+letter for letter in 'abcdefghijkl')+
            ' FROM installed_plugin_index WHERE index_key=? LIMIT 2',('installed-plugin-index',),
            until=until,limit=2,label='direct-shm-dependency-select')
        row_produced=bool(rows)
    except BaseException as caught:error=caught
    finally:
        if connection is not None:inputs.close_connection_once(connection)
        inputs.close()
    public=inputs.public();completed=time.monotonic()
    error_public=wal.failure_record(error) if error is not None else None
    expected=(isinstance(error,sqlite3.Error) and type(getattr(error,'sqlite_errorcode',None)) is int
              and error.sqlite_errorcode&255==sqlite3.SQLITE_CANTOPEN)
    public.update(runtime=runtime,error=error_public,readOnlyShmOpenDenied=readonly_denial,
        rowProduced=row_produced,expectedCantopen=expected,completedMonotonic=completed,
        originalDeadlineMetAfterClosure=completed<until,publicEngineControlOnly=True,
        parameterRecognitionProvedByThisCaseAlone=False)
    return expected and not row_produced and public['allOwnedDescriptorsClosed'] and completed<until,public

def main():
    global ROOT,LIVE,AGENTS,CACHE_NAMES,signals,UNTIL
    parser=argparse.ArgumentParser()
    parser.add_argument('--case',choices=tuple('W%02d'%x for x in range(1,11)),required=True)
    parser.add_argument('--candidate-sha256',required=True)
    parser.add_argument('--volume-sha256',required=True)
    parser.add_argument('--until',type=float,required=True)
    parser.add_argument('--event-fd',type=int,required=True)
    parser.add_argument('--control-fd',type=int,required=True)
    args=parser.parse_args();UNTIL=args.until
    need(sys.platform=='darwin' and os.getuid()==501,'exact_mac_reader')
    need(time.monotonic()<UNTIL<=time.monotonic()+45.0,'original_parent_deadline_not_reset')
    need(all(re.fullmatch('[0-9a-f]{64}',x) for x in (args.candidate_sha256,args.volume_sha256)),'public_sha_shape')
    candidate_raw,_=read_public(TOP/'candidate.public.json',65536,args.candidate_sha256)
    candidate=json.loads(candidate_raw)
    need(candidate['schema']=='heptabao.mac-owned-registry-wal-candidate.r1'
         and candidate['sourceOrder']==list(NAMES) and set(candidate['sourcePins'])==set(NAMES),'candidate_exact_source_set')
    before={}
    for name in NAMES:
        _,before[name]=read_public(QA/name,128*1024,candidate['sourcePins'][name])
    sys.path.insert(0,str(QA))
    from mac_native_owned_commands_r1 import Signals
    from mac_t5_volume_guard_r1 import HeldT5
    import mac_registry_readonly_wal_r1 as wal
    signals=Signals();signals.install();ROOT=TOP/'cases'/args.case;LIVE=ROOT/'live'
    AGENTS=wal.base.AGENTS;CACHE_NAMES=wal.base.CACHE_NAMES
    guard=None;report={'schema':'heptabao.mac-owned-registry-wal-reader.r1','case':args.case,
        'ok':False,'outcomeUnknown':True,'productionInputsRead':False,'privateCaptureAuthorized':False}
    try:
        need(args.event_fd!=args.control_fd and min(args.event_fd,args.control_fd)>=3,'two_distinct_inherited_pipes')
        for fd in (args.event_fd,args.control_fd):
            need(stat.S_ISFIFO(os.fstat(fd).st_mode),'inherited_pipe_type')
            fds.append({'fd':fd,'closeAttempted':False,'closed':False})
        anchor,_=read_public(TOP/'anchor.public.json',8192,candidate['documentPins']['anchor.public.json'])
        guard=HeldT5(anchor,candidate['documentPins']['anchor.public.json'],remaining,critical)
        volume,_=read_public(TOP/'volume.public.plist',65536,args.volume_sha256)
        guard.accept_diskutil(volume);guard.check()
        inputs=wal.WalInputs(until=UNTIL,critical=critical,cancelled=lambda:signals.pending is not None,
                             live=LIVE,synthetic=True)
        if args.case=='W01':
            report['originalFourKernelRefusals']=kernel_refusals(guard,'before')
            report['existingSidecarWriteRefusals']=existing_sidecar_write_refusals(guard)
        if args.case=='W03':
            matched,attempt=shm_denied_engine_control(wal,inputs)
            value=None
        else:
            hook=(lambda until:barrier(args.case,args.event_fd,args.control_fd,until)) if args.case in ('W05','W06','W07','W08') else None
            value,attempt=wal.attempt_registry(inputs,after_read=hook)
            code=(attempt.get('error') or {}).get('code')
            expected={'W02':'registry_wal_required_shm','W04':'registry_wal_journal_refused',
                'W05':'registry_wal_full_leaf_changed','W06':'registry_wal_full_leaf_changed',
                'W07':'registry_wal_full_leaf_changed','W08':'registry_wal_full_parent_changed',
                'W09':'fixed_key_search_required_no_data_scan','W10':'registry_returned_byte_cap'}
            matched=(attempt['ok'] is True and value is not None) if args.case=='W01' else (
                attempt['ok'] is False and value is None and code==expected[args.case]
                and attempt['allOwnedDescriptorsClosed'] and attempt['originalDeadlineMetAfterClosure'])
            if args.case in ('W02','W04'):
                matched=matched and not any(x['label']=='registry-wal' for x in attempt['connectAttempts'])
            if args.case=='W09':
                matched=matched and not any(x['label']=='registry-fixed-row' for x in attempt['cursors'])
        report.update(attempt=attempt,expectedResultMatched=matched,
            resultSha256=None if value is None else digest(wal.encoded(value)),
            resultBytes=0 if value is None else len(wal.encoded(value)))
        need(matched,'fixed_case_expectation_not_met')
        for name in NAMES:
            _,after=read_public(QA/name,128*1024,candidate['sourcePins'][name])
            need(after==before[name],'source_identity_changed')
        guard.check();report['sourcePinsUnchanged']=True;report['ok']=True
    except BaseException as error:
        report['ok']=False;report['error']=wal.failure_record(error)
    finally:
        signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
        for row in reversed(fds):close_fd(row)
        if guard is not None:
            try:guard.close()
            except BaseException as error:report['guardCloseErrorType']=type(error).__name__
            report['heldT5']=guard.public_state()
        report['ownedPipesAndProbeFds']=[{k:v for k,v in r.items()} for r in fds]
        report['ownedSockets']=[{k:v for k,v in r.items() if k!='socket'} for r in sockets]
        all_closed=(guard is not None and report.get('heldT5',{}).get('allDescriptorsClosed') is True
                    and report['heldT5'].get('lastAnchorCheckPassed') is True and report['heldT5'].get('closeErrors')==[]
                    and report.get('sourcePinsUnchanged') is True
                    and report.get('attempt',{}).get('allOwnedDescriptorsClosed') is True
                    and all(r['closed'] for r in fds) and all(r['closed'] for r in sockets))
        completed=time.monotonic()
        report['allOwnedClosed']=all_closed
        report['originalDeadlineAfterClosure']=completed<UNTIL
        report['outcomeUnknown']=not(all_closed and completed<UNTIL and signals.pending is None)
        report['ok']=report['ok'] and not report['outcomeUnknown']
        raw=encoded(report);need(len(raw)<=128*1024,'public_reader_report_bound')
        print(raw.decode().rstrip('\n'),flush=True)
    return 0 if report['ok'] and time.monotonic()<UNTIL else 1

# The original capture_profile() and kernel_refusals() bodies are appended
# byte-exactly from the reviewed capture entry before the final main guard.

def capture_profile(stage):
    need(stage in ('before','after'),'fixed_capture_stage')
    read_paths={Path('/'),Path('/Volumes'),Path('/Volumes/T5'),ROOT.parent,ROOT,QA,ROOT/'proofs',
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
    lines.extend(['(allow file-read* (literal "/dev/null"))',
        '(allow file-read* (literal "/dev/urandom"))',
        '(allow file-read* (literal "/dev/random"))',
        '(allow file-write* (subpath '+q(ROOT/'captures'/stage/'output')+'))',
        '(allow file-write* (literal "/dev/null"))'])
    # No network rule. The only write exception is the new capture output root.
    return ('\n'.join(lines)+'\n').encode()

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

if __name__=='__main__':sys.exit(main())
