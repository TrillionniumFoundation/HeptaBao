#!/usr/bin/env python3
"""Owned launchd server wrapper; validates custody, then execs the exact R10 binary.

This is a source-only candidate. It does not own launchd registration. The
manager must observe the same PID and birth become the pinned server executable;
an exec-ready file or stdout record alone is never evidence of server startup.
"""
from __future__ import annotations
import os
os.write(2,b'{"schema":"heptabao.mac-wrapper-fixed-stage.r1","stage":"python-entry"}\n')
import argparse, base64, hashlib, json, os, signal, stat, sys, time
from contextlib import contextmanager
from pathlib import Path

PYTHON_LAUNCHER = "/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
PYTHON_KERNEL_IMAGE = "/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python"
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r1')
QA=ROOT/'qa'
BINDING_READY=True  # Startup custody scope only; actual main3 capsule admission is independently fenced.
BINARY=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r1/bin/heptabao-server')
BINARY_SHA='5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
BINARY_BYTES=92359328
GENERATIONS=('server-initial','server-cold-new-process')
PUBLIC_MODULES=('mac_owned_unreaped_r1.py','mac_owned_commands_r1.py',
                'mac_t5_volume_guard_r1.py','mac_native_process_observer_r1.py')
START=time.monotonic()
UNTIL=START+30.0
protected=0
pending=None
stage_count=0
def stage(name):
    global stage_count
    allowed={'before-public-imports','after-public-imports','before-t5-anchors','after-t5-anchors',
        'before-diskutil','after-diskutil','before-workdir','after-workdir','before-plan','after-plan',
        'before-config','after-config','before-binary','after-binary','identity-observed',
        'ready-published','admission-observed','candidate-published','before-guard-close',
        'after-guard-close','terminal-record-written','before-exec'}
    allowed.update(op+':'+module for op in ('before-public-open','after-public-open',
        'after-public-read','before-public-close','after-public-close') for module in PUBLIC_MODULES)
    if name not in allowed or stage_count>=64:raise RuntimeError('fixed_stage_bound')
    stage_count+=1
    raw=(json.dumps({'schema':'heptabao.mac-wrapper-fixed-stage.r1',
         'stage':name,'elapsedSeconds':time.monotonic()-START},sort_keys=True)+'\n').encode()
    if len(raw)>512 or os.write(2,raw)!=len(raw):raise RuntimeError('fixed_stage_write')

class Refused(RuntimeError):pass
def need(value,code):
    if not value:raise Refused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def identity(s):
    return tuple(str(x) for x in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,
        s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))
def remaining():
    need(pending is None,'server_wrapper_cancelled')
    left=UNTIL-time.monotonic();need(left>0,'original_server_wrapper_deadline');return left
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

def stable_public(path,maximum):
    remaining();path=Path(path)
    need(path.is_absolute() and path==Path(os.path.normpath(str(path))),'public_path')
    fd=None
    try:
        stage('before-public-open:'+path.name)
        with critical():fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        stage('after-public-open:'+path.name)
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
             and not stat.S_IMODE(before.st_mode)&0o022 and 0<=before.st_size<=maximum,
             'public_source_custody')
        raw=bytearray()
        while True:
            remaining();block=os.read(fd,min(65536,maximum+1-len(raw)))
            if not block:break
            raw.extend(block);need(len(raw)<=maximum,'public_source_bound')
        need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))
             ==identity(path.lstat()),'public_source_stable')
        stage('after-public-read:'+path.name)
        return bytes(raw),identity(before)
    finally:
        if fd is not None:
            stage('before-public-close:'+path.name)
            with critical():os.close(fd)
            stage('after-public-close:'+path.name)

def binary_pin():
    remaining()
    fd=None
    try:
        with critical():fd=os.open(BINARY,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
             and stat.S_IMODE(before.st_mode)==0o500 and before.st_size==BINARY_BYTES,
             'exact_retained_normal_binary')
        digest=hashlib.sha256();size=0
        while True:
            remaining();chunk=os.read(fd,1024*1024)
            if not chunk:break
            size+=len(chunk);digest.update(chunk)
        need(size==BINARY_BYTES and digest.hexdigest()==BINARY_SHA
             and identity(before)==identity(os.fstat(fd))==identity(BINARY.lstat()),
             'retained_normal_binary_whole_pin')
        return identity(before)
    finally:
        if fd is not None:
            with critical():os.close(fd)

def main():
    need(BINDING_READY is True,'mac_normal61_binding_not_admitted')
    parser=argparse.ArgumentParser()
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--public-volume-anchor-base64',required=True)
    parser.add_argument('--public-volume-anchor-sha256',required=True)
    parser.add_argument('--public-source-pins-base64',required=True)
    parser.add_argument('--public-source-pins-sha256',required=True)
    args=parser.parse_args()
    os.umask(0o077)
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,interrupted)
    guard=None;commands=None;generation=None;plan=None;candidate=None
    report={'schema':'heptabao.mac-owned-launchd-server-wrapper.r1','ok':False,
        'execObservedByWrapper':False,'managerMustObserveSamePidBirthAndServerExecutable':True,
        'newWrapperSeconds':30,'outcomeUnknown':False,'productionCurrentPrivateInputsOpened':False,
        'ownedPrivateInputReadAttempted':False,'ownedPrivateInputReadCompleted':False,
        'productionChanged':False,'providerRequestSent':False,'j3160Contacted':False}
    try:
        need(sys.platform=='darwin' and os.getuid()==501,'exact_mac_owner')
        raw_pins=base64.b64decode(args.public_source_pins_base64,validate=True)
        need(len(raw_pins)<=8192 and sha(raw_pins)==args.public_source_pins_sha256,
             'exact_public_source_pins')
        pins=json.loads(raw_pins)
        need(isinstance(pins,dict) and set(pins)==set(PUBLIC_MODULES)
             and all(isinstance(v,str) and len(v)==64
                     and all(c in '0123456789abcdef' for c in v) for v in pins.values()),
             'fixed_public_source_set')
        source_identities={}
        for name in PUBLIC_MODULES:
            raw,source_identities[name]=stable_public(QA/name,1024*1024)
            need(sha(raw)==pins[name],'reviewed_public_source')
        stage('before-public-imports')
        sys.path.insert(0,str(QA))
        from mac_t5_volume_guard_r1 import HeldT5
        from mac_owned_commands_r1 import Signals,Commands
        from mac_native_process_observer_r1 import ProcessReader
        stage('after-public-imports')
        # Commands uses this wrapper's critical section and cancellation state.
        class CommandSignals:
            @property
            def pending(self):return pending
            def critical(self):return critical()
        commands=Commands(CommandSignals())
        anchor=base64.b64decode(args.public_volume_anchor_base64,validate=True)
        stage('before-t5-anchors')
        guard=HeldT5(anchor,args.public_volume_anchor_sha256,remaining,critical)
        stage('after-t5-anchors')
        stage('before-diskutil')
        row,out,err=commands.run('server-wrapper-t5-volume',
            ['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
            until=min(UNTIL,time.monotonic()+30),maximum=262144)
        need(row['exitCode']==0 and row['completeBeforeDeadline']
             and not row['outcomeUnknown'],'actual_volume_probe_complete')
        stage('after-diskutil')
        guard.accept_diskutil(out)
        stage('before-workdir')
        with guard.parent(ROOT/'launchd') as (work_fd,_name):
            with critical():os.fchdir(work_fd)
            need(identity(os.stat('.'))==identity(os.fstat(work_fd))
                 and os.getcwd()==str(ROOT),'held_t5_business_working_directory')
        stage('after-workdir')
        guard.check();report['ownedBusinessWorkingDirectoryHeldT5']=True
        stage('before-plan')
        report['ownedPrivateInputReadAttempted']=True
        raw=guard.read(args.plan)
        report['ownedPrivateInputReadCompleted']=True
        stage('after-plan')
        need(sha(raw)==args.plan_sha256,'exact_private_server_plan')
        plan=json.loads(raw);need(isinstance(plan,dict),'server_plan_object');generation=plan.get('generation')
        need(isinstance(plan,dict) and set(plan)=={'schema','generation','binaryPath',
            'binarySha256','binaryBytes','configPath','configSha256','port','workRoot'}
            and plan['schema']=='heptabao.mac-owned-launchd-server-plan.private.r1'
            and generation in GENERATIONS and args.plan==ROOT/'launchd'/(generation+'.private.json')
            and plan['binaryPath']==str(BINARY) and plan['binarySha256']==BINARY_SHA
            and plan['binaryBytes']==BINARY_BYTES and plan['configPath']==str(ROOT/'server/server.json')
            and plan['workRoot']==str(ROOT) and type(plan['port']) is int
            and 1024<=plan['port']<=65535,'fixed_owned_server_plan')
        stage('before-config')
        config_raw=guard.read(Path(plan['configPath']))
        stage('after-config')
        need(sha(config_raw)==plan['configSha256'],'exact_server_config')
        config=json.loads(config_raw)
        need(isinstance(config,dict) and set(config)=={'listen','data_dir','audit_file',
             'tls_cert_file','tls_key_file','storage'}
             and config['listen']=='127.0.0.1:'+str(plan['port'])
             and config['data_dir']==str(ROOT/'server/data')
             and config['audit_file']==str(ROOT/'server/audit.jsonl'),
             'actual_normal_flat_loopback_config')
        need(config['storage']=={'native_v6_file':{'path':str(ROOT/'server/data')}},
             'formal_owned_native_v6_file')
        need(config['tls_cert_file']==str(ROOT/'server/tls/server.crt')
             and config['tls_key_file']==str(ROOT/'server/tls/server.key'),
             'owned_tls_configuration')
        stage('before-binary')
        before_binary=binary_pin()
        stage('after-binary')
        reader=ProcessReader();self_identity=reader.read(os.getpid())
        need(self_identity['uid']==501 and self_identity['pid']==self_identity['pgid']
             and self_identity['executable']==PYTHON_KERNEL_IMAGE
             and str(Path(sys.executable).resolve())==PYTHON_LAUNCHER,
             'actual_launchd_wrapper_identity')
        stage('identity-observed')
        ready={'schema':'heptabao.mac-server-wrapper-ready.r1','generation':generation,
            'planSha256':args.plan_sha256,'wrapperIdentity':self_identity,
            'wrapperStartMonotonic':START,'originalWrapperDeadlineMonotonic':UNTIL}
        guard.write_new(ROOT/'launchd'/(generation+'.ready.public.json'),encoded(ready))
        stage('ready-published')
        admitted=ROOT/'launchd'/(generation+'.admitted.private.json')
        while True:
            remaining()
            try:admission=json.loads(guard.read(admitted));break
            except FileNotFoundError:time.sleep(min(0.025,remaining()))
        need(admission=={'schema':'heptabao.mac-owned-manager-admission.r1',
            'generation':generation,'planSha256':args.plan_sha256,'wrapperIdentity':self_identity},
            'one_exact_actual_manager_admission')
        stage('admission-observed')
        need(reader.read(os.getpid())==self_identity,'wrapper_birth_before_exec')
        need(binary_pin()==before_binary,'binary_name_identity_before_exec')
        need(sha(guard.read(Path(plan['configPath'])))==plan['configSha256'],
             'config_after_manager_admission')
        for name in PUBLIC_MODULES:
            raw,observed=stable_public(QA/name,1024*1024)
            need(observed==source_identities[name] and sha(raw)==pins[name],
                 'public_sources_before_exec')
        report.update(generation=generation,wrapperIdentity=self_identity,
            binaryPath=str(BINARY),binarySha256=BINARY_SHA,binaryBytes=BINARY_BYTES,
            binaryIdentity=before_binary,configSha256=plan['configSha256'],
            sourcePins=pins,commands=commands.public())
        need(report['commands']['allOwnedCommandsStopped']
             and report['commands']['unknownCommandCount']==0,'helpers_closed_before_exec')
        remaining();guard.check()
        report['preparedExecCandidate']=True
        candidate=guard.write_new(ROOT/'launchd'/(generation+'.exec-ready.public.json'),
                                 encoded(report))
        stage('candidate-published')
    except BaseException as error:
        report['errorType']=type(error).__name__
        report['errorCode']=str(error) if isinstance(error,Refused) else None
        report['outcomeUnknown']=isinstance(error,KeyboardInterrupt)
    finally:
        for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,signal.SIG_IGN)
        if commands is not None:report['commands']=commands.public()
        if guard is not None:
            stage('before-guard-close')
            guard.close();report['volumeGuardClosed']=guard.public_state()
            stage('after-guard-close')
        closed=(guard is not None and report['volumeGuardClosed']['allDescriptorsClosed']
            and report['volumeGuardClosed']['lastAnchorCheckPassed']
            and not report['volumeGuardClosed']['closeErrors'])
        owned=(commands is not None and report['commands']['allOwnedCommandsStopped']
               and report['commands']['unknownCommandCount']==0)
        ready=bool(candidate is not None and closed and owned and pending is None
                   and time.monotonic()<UNTIL and 'errorType' not in report)
        report['ok']=ready;report['readyToExec']=ready
        report['outcomeUnknown']=bool(report['outcomeUnknown'] or not closed or not owned)
        report['candidateReceiptSha256']=None if candidate is None else candidate['sha256']
        report['elapsedSeconds']=time.monotonic()-START
        print(json.dumps(report,sort_keys=True),flush=True)
        stage('terminal-record-written')
    if not ready or time.monotonic()>=UNTIL:return 1
    # A successful exec retains PID/birth and consumes this wrapper. The
    # independent manager must actually observe that transition and pinned file.
    try:
        for name in ('SIGTERM','SIGINT','SIGPIPE','SIGXFZ','SIGXFSZ'):
            sig=getattr(signal,name,None)
            if sig is not None:signal.signal(sig,signal.SIG_DFL)
        stage('before-exec')
        os.execve(str(BINARY),[str(BINARY),'--config',str(ROOT/'server/server.json')],
            {'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C',
             'HOME':str(ROOT/'server/home'),'TMPDIR':str(ROOT/'server/tmp')})
    except BaseException as error:
        print(json.dumps({'schema':'heptabao.mac-owned-server-exec-failure.r1',
            'generation':generation,'ok':False,'execFailureType':type(error).__name__,
            'outcomeUnknown':False},sort_keys=True),flush=True)
        return 1

if __name__=='__main__':sys.exit(main())
