#!/usr/bin/env python3
"""Owned-only Mac SQLite prerequisite for guarded current capture.

This is a separate one-shot component, not production credential capture.
Its actual final stdout plus authoritative exit zero is the proof input.
No fixture result authorizes a later production run by itself.
"""
from __future__ import annotations
import argparse, base64, hashlib, json, os, signal, sqlite3, stat, sys, time
from contextlib import contextmanager
from pathlib import Path

START=time.monotonic();UNTIL=START+45.0
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1')
QA=ROOT/'qa';OWNED=ROOT/'capture-sqlite-synthetic-r1'
NAMES=('mac_capture_sqlite_synthetic_r1.py','mac_guarded_current_capture_r3.py',
       'mac_t5_volume_guard_r1.py','mac_owned_unreaped_r1.py','mac_owned_commands_r1.py')
protected=0;pending=None
class Refused(RuntimeError):pass
def need(value,code):
    if not value:raise Refused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def remaining():
    need(pending is None,'synthetic_cancelled')
    left=UNTIL-time.monotonic();need(left>0,'original_synthetic_45s_exhausted');return left
def on_signal(signum,_frame):
    global pending
    pending=signum
    if not protected:raise KeyboardInterrupt()
@contextmanager
def critical():
    global protected
    protected+=1
    try:yield
    finally:protected-=1
def identity(s):
    return tuple(str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,
                                 s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))
def code_bytes(path,expected):
    # Only fixed public source files are read before the held volume guard.
    remaining();need(path.parent==QA and path.name in NAMES,'fixed_public_source_scope')
    with critical():fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
             and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=1048576,
             'public_source_custody')
        parts=[];count=0
        while count<=1048576:
            remaining();raw=os.read(fd,min(65536,1048577-count))
            if not raw:break
            count+=len(raw);parts.append(raw)
        raw=b''.join(parts)
        need(count==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat())
             and sha(raw)==expected,'fixed_whole_source_pin')
    finally:
        with critical():os.close(fd)
    remaining();return raw

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--public-volume-anchor-base64',required=True)
    parser.add_argument('--public-volume-anchor-sha256',required=True)
    parser.add_argument('--source-pins-base64',required=True)
    parser.add_argument('--source-pins-sha256',required=True)
    args=parser.parse_args()
    os.umask(0o077)
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,on_signal)
    report={'schema':'heptabao.mac-immutable-capture-synthetic.r1','ok':False,
        'ownedDatabaseOnly':True,'productionOpened':False,
        'wholeDatabaseBackupQualified':False,'crossAgentAtomicSnapshotClaimed':False,
        'newOriginalSyntheticSeconds':45,'cases':[],'outcomeUnknown':False}
    guard=None;commands=None;setup_connections=[];input_sets=[];extra_fds=[]
    cap=None;pins=None;complete=False
    try:
        need(sys.platform=='darwin' and os.getuid()==501,'actual_mac_component_owner')
        source_raw=base64.b64decode(args.source_pins_base64,validate=True)
        need(len(source_raw)<=16384 and sha(source_raw)==args.source_pins_sha256,'source_pin_input')
        pins=json.loads(source_raw)
        need(isinstance(pins,dict) and set(pins)==set(NAMES)
             and all(isinstance(v,str) and len(v)==64 and all(c in '0123456789abcdef' for c in v)
                     for v in pins.values()),'exact_five_public_sources')
        for name,pin in pins.items():code_bytes(QA/name,pin)
        sys.path.insert(0,str(QA))
        from mac_t5_volume_guard_r1 import HeldT5
        from mac_owned_commands_r1 import Commands
        import mac_guarded_current_capture_r3 as capture
        cap=capture
        # Commands uses this same pending signal state and critical section.
        class SignalState:
            @property
            def pending(self):return pending
            def critical(self):return critical()
        commands=Commands(SignalState())
        anchor=base64.b64decode(args.public_volume_anchor_base64,validate=True)
        guard=HeldT5(anchor,args.public_volume_anchor_sha256,remaining,critical)
        row,out,_=commands.run('synthetic-t5-volume',
            ['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
            until=min(UNTIL,time.monotonic()+30),maximum=262144)
        need(row['exitCode']==0 and not row['outcomeUnknown'],'actual_volume_query_complete')
        guard.accept_diskutil(out)
        report['volumeProbe']=row
        need(hasattr(sqlite3.Connection,'setlimit') and hasattr(sqlite3,'SQLITE_LIMIT_LENGTH'),
             'actual_runtime_setlimit_required_no_fallback')
        need(sqlite3.sqlite_version_info>=(3,22,0),'actual_sqlite_readonly_wal_version')
        report['runtime']=capture.runtime_identity(remaining=remaining,critical=critical)
        report['captureSourceSha256']=pins['mac_guarded_current_capture_r3.py']
        report['sourcePinsSha256']=args.source_pins_sha256
        report['sourcePins']=pins
        report['fixedOwnedRoot']=str(OWNED)
        guard.mkdir_new(OWNED)
        expected_store={'profiles':{'owned-fixture':{'provider':'synthetic','type':'api_key','key':'synthetic-only'}}}
        expected_state={'usageStats':{},'order':{}}

        def close_setup(item):
            if item['closeAttempted']:return
            with critical():
                item['closeAttempted']=True
                try:item['db'].close();item['closed']=True
                except BaseException as error:item['closeError']=type(error).__name__;raise
        def make_database(label,*,large=False):
            remaining()
            live=OWNED/label
            for path in (live,live/'agents',live/'agents/main',live/'agents/main/agent'):
                guard.mkdir_new(path)
            path=live/'agents/main/agent/openclaw-agent.sqlite'
            guard.write_new(path,b'')
            with guard.parent(path):
                with critical():
                    db=sqlite3.connect('file:'+str(path)+'?mode=rw',uri=True,timeout=0.0,isolation_level=None)
                    item={'db':db,'closeAttempted':False,'closed':False,'label':label}
                    setup_connections.append(item)
                try:
                    db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,2*1048576)
                    db.execute('PRAGMA journal_mode=WAL')
                    db.execute('PRAGMA synchronous=FULL')
                    db.execute('CREATE TABLE auth_profile_store (store_key TEXT PRIMARY KEY, store_json TEXT NOT NULL, updated_at INTEGER NOT NULL)')
                    db.execute('CREATE TABLE auth_profile_state (state_key TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at INTEGER NOT NULL)')
                    value={'profiles':{'owned-fixture':{'value':'x'*(1048576+128)}}} if large else expected_store
                    db.execute('INSERT INTO auth_profile_store VALUES (?,?,?)',
                               ('primary',json.dumps(value,separators=(',',':')),1))
                    db.execute('INSERT INTO auth_profile_state VALUES (?,?,?)',
                               ('primary',json.dumps(expected_state,separators=(',',':')),2))
                    db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                finally:close_setup(item)
            guard.check()
            # No production or arbitrary file is opened. SQLite owns and closes
            # its setup sidecars; the immutable reader must not recreate any.
            for suffix in ('-wal','-shm','-journal'):
                with guard.parent(Path(str(path)+suffix)) as (parent,name):
                    try:os.stat(name,dir_fd=parent,follow_symlinks=False)
                    except FileNotFoundError:pass
                    else:raise Refused('closed_owned_setup_sidecar_expected_absent')
            remaining()
            return live,path

        def input_set(live):
            obj=capture.FixedInputs(until=UNTIL,critical=critical,cancelled=lambda:pending is not None,
                                    live=live,synthetic=True)
            input_sets.append(obj);return obj
        def record(label,obj,passed,**details):
            obj.close()
            info=obj.public()
            need(info['allOwnedDescriptorsClosed'] and not info['closeErrors'],'component_descriptors_closed')
            remaining()
            report['cases'].append({'case':label,'passed':passed,**details,'inputClosure':info})
            need(passed,'component_case_failed.'+label)
        def exact_rows(value):
            return (value['rows']['store']==[['primary',json.dumps(expected_store,separators=(',',':')),1]]
                 and value['rows']['state']==[['primary',json.dumps(expected_state,separators=(',',':')),2]])

        live,path=make_database('absent-sidecars')
        inputs=input_set(live)
        value=capture.auth_rows(inputs,'main');inputs.verify()
        record('absent_sidecars_stay_absent',inputs,exact_rows(value)
            and all(str(path)+suffix in inputs.absent for suffix in ('-wal','-shm','-journal')))
        report['absentSidecarsStayedAbsent']=True;report['sameHeldFdUriCode']=True

        live,path=make_database('zero-wal')
        guard.write_new(Path(str(path)+'-wal'),b'')
        guard.write_new(Path(str(path)+'-shm'),bytes(32768))
        inputs=input_set(live)
        value=capture.auth_rows(inputs,'main');inputs.verify()
        record('empty_wal_and_shm_unchanged',inputs,exact_rows(value)
            and int(inputs.files[str(path)+'-wal']['expected'][6])==0
            and int(inputs.files[str(path)+'-shm']['expected'][6])==32768)
        report['emptyWalStayedEmpty']=True

        live,path=make_database('nonempty-wal')
        guard.write_new(Path(str(path)+'-wal'),b'owned-nonempty-wal')
        inputs=input_set(live);refusal=None
        try:capture.auth_rows(inputs,'main')
        except capture.CaptureRefused as error:refusal=str(error)
        record('nonempty_wal_refused_before_connection',inputs,
            refusal in ('current_input_size_bound','nonempty_wal_refused_before_sqlite')
            and not inputs.connections,refusalCode=refusal)
        report['nonemptyWalRefusedBeforeConnect']=True

        live,path=make_database('journal-present')
        guard.write_new(Path(str(path)+'-journal'),b'')
        inputs=input_set(live);refusal=None
        try:capture.auth_rows(inputs,'main')
        except capture.CaptureRefused as error:refusal=str(error)
        record('journal_refused_before_connection',inputs,
            refusal=='rollback_journal_refused_before_immutable' and not inputs.connections,refusalCode=refusal)
        report['journalRefusedBeforeConnect']=True

        live,path=make_database('oversize-row',large=True)
        inputs=input_set(live);refusal=None
        try:capture.auth_rows(inputs,'main')
        except capture.CaptureRefused as error:refusal=str(error)
        except sqlite3.DataError:refusal='sqlite_length_limit'
        record('oversize_fixed_primary_row_refused',inputs,
            refusal in ('auth_primary_payload_cap','sqlite_length_limit'),refusalCode=refusal)
        report['oversizeRowRefused']=True

        live,path=make_database('drift-before-query')
        inputs=input_set(live);inputs.database(path)
        with guard.parent(path) as (parent,name):
            with critical():
                fd=os.open(name,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW,dir_fd=parent)
                opened={'fd':fd,'closeAttempted':False,'closed':False};extra_fds.append(opened)
            try:
                need(identity(os.fstat(fd))==inputs.files[str(path)]['expected'],'owned_drift_exact_inode')
                need(os.write(fd,b'D')==1,'owned_drift_write_once');os.fsync(fd)
            finally:
                with critical():
                    opened['closeAttempted']=True;os.close(fd);opened['closed']=True
        refusal=None
        try:capture.auth_rows(inputs,'main')
        except capture.CaptureRefused as error:refusal=str(error)
        record('held_inode_drift_refused_before_connection',inputs,
            refusal=='current_input_fd_name_or_metadata_changed' and not inputs.connections,refusalCode=refusal)
        report['driftRefused']=True

        live,path=make_database('readonly-uri')
        inputs=input_set(live);main=inputs.database(path)
        def readonly_attempt(db,until):
            try:db.execute('CREATE TABLE should_not_exist (value TEXT)')
            except sqlite3.Error as error:
                return getattr(error,'sqlite_errorcode',-1)&255==sqlite3.SQLITE_READONLY
            return False
        readonly=capture.immutable_query(inputs,main,readonly_attempt)
        inputs.verify()
        record('actual_immutable_connection_rejects_write',inputs,readonly is True)
        report['readonlyImmutableConnection']=True
        report['sameRuntimeBeforeAfter']=capture.runtime_identity(remaining=remaining,critical=critical)==report['runtime']
        need(report['sameRuntimeBeforeAfter'],'runtime_code_unchanged')
        for name,pin in pins.items():code_bytes(QA/name,pin)
        guard.check();remaining();complete=True
    except BaseException as error:
        report['errorType']=type(error).__name__
        report['errorCode']=str(error) if isinstance(error,Refused) or (cap is not None
            and isinstance(error,cap.CaptureRefused)) else None
        if isinstance(error,(KeyboardInterrupt,SystemExit)):report['outcomeUnknown']=True
    finally:
        signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
        for obj in reversed(input_sets):obj.close()
        for item in reversed(setup_connections):
            if item['closeAttempted']:continue
            with critical():
                item['closeAttempted']=True
                try:item['db'].close();item['closed']=True
                except BaseException as error:item['closeError']=type(error).__name__
        for item in reversed(extra_fds):
            if item['closeAttempted']:continue
            with critical():
                item['closeAttempted']=True
                try:os.close(item['fd']);item['closed']=True
                except BaseException as error:item['closeError']=type(error).__name__
        if commands is not None:report['ownedCommands']=commands.public()
        report['allOwnedDescriptorsClosed']=(
            all(obj.public()['allOwnedDescriptorsClosed'] for obj in input_sets)
            and all(x['closed'] for x in setup_connections) and all(x['closed'] for x in extra_fds))
        if guard is not None:
            guard.close();report['heldT5Final']=guard.public_state()
            report['allOwnedDescriptorsClosed']=(report['allOwnedDescriptorsClosed']
                and report['heldT5Final']['allDescriptorsClosed'])
        commands_stopped=commands is not None and commands.public()['allOwnedCommandsStopped']
        command_unknown=commands is not None and commands.public()['unknownCommandCount']!=0
        report['outcomeUnknown']=bool(report['outcomeUnknown'] or command_unknown
            or not commands_stopped or not report['allOwnedDescriptorsClosed'] or pending is not None)
        completed=time.monotonic()
        report['elapsedSeconds']=completed-START
        report['originalDeadlineMetAfterClosure']=completed<UNTIL
        report['ok']=bool(complete and not report['outcomeUnknown'] and completed<UNTIL
            and guard is not None and report['heldT5Final']['lastAnchorCheckPassed']
            and len(report['cases'])==7 and all(x['passed'] for x in report['cases']))
        report['authoritativeExitZeroAndOriginalDeadlineRequired']=True
        raw=encoded(report);need(len(raw)<=65536,'bounded_synthetic_public_stdout')
        sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
    return 0 if report['ok'] and time.monotonic()<UNTIL else 1

if __name__=='__main__':sys.exit(main())
