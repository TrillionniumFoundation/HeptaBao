#!/usr/bin/env python3
"""Create only a fresh owned WAL synthetic ROOT, ten sources and two public documents.

No current credentials, production SQLite, consumer, manager or server is read
or executed. Three pinned import-safe custody libraries are loaded from the
already verified stdin bytes to guard diskutil and descriptor-relative writes.
"""
from __future__ import annotations
import ast, base64, hashlib, json, os, select, signal, sys, time, types
from contextlib import contextmanager
from pathlib import Path
START=time.monotonic();UNTIL=START+45.0
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-current-registry-readonly-wal-synthetic-r1')
QA=ROOT/'qa'
PINS={
    "mac_guarded_current_capture_r3.py": [
        23578,
        "606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693"
    ],
    "mac_registry_readonly_wal_r1.py": [
        31776,
        "60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed"
    ],
    "mac_wal_owned_reader_r1.py": [
        17861,
        "6bc5939de4b2b64ea771b2003efb20e9bbf5f2c56be49a1b0c227919c8f39833"
    ],
    "mac_wal_owned_synthetic_r1.py": [
        28281,
        "88a6abdc02c71b0cb25f6b85a4494f0b44a30c2f8a4936bb511948f258737cdc"
    ],
    "mac_t5_volume_guard_r1.py": [
        13398,
        "6cd665616c79a6d4e519e7ef0f9dda92e929f1e70479b2d65cc1f0520bb244ff"
    ],
    "mac_darwin_owned_projection_r1.py": [
        12858,
        "77b63286d79827671009d56d238494c472f37e3674bf903ab2da092b42733740"
    ],
    "mac_native_owned_unreaped_r1.py": [
        10761,
        "880794d5e0f01f45e9c559688b2ebd33c2c96399124ea3ecb9e58720a2424d0c"
    ],
    "mac_native_owned_commands_r1.py": [
        5972,
        "717feff0a8719a6c208b14aa1598cefd59881fffa09d19c781a89689b025b9cd"
    ],
    "mac_owned_unreaped_r1.py": [
        10990,
        "a143ba334159931d530b49a55c24471f56fa1b62f1e1012e12c75e21f3c22b1d"
    ],
    "mac_owned_commands_r1.py": [
        5965,
        "eb676e6dedb6d594d944e921738cf9b384f2a98a37ee2bd1fa5433b848a36867"
    ]
}
DOCUMENT_PINS={
    "anchor.public.json": [
        967,
        "dd6dce82fb0276d7c0fd181152aef07bb2857e47506311f70ae67cce41b1eab8"
    ],
    "candidate.public.json": [
        7506,
        "4db3624e3c6ca6ffeaefcfa03ae15e6aecb6f7cb7287b3ed34ce3bd110f2c33c"
    ]
}
PAYLOAD_BYTES=228368
PAYLOAD_SHA='5795faed4f6e3b80093b5affa5795f8fdbcd4a72da413ffc4ef0116b576d4e75'
ANCHOR_SHA='dd6dce82fb0276d7c0fd181152aef07bb2857e47506311f70ae67cce41b1eab8'
protected=0;pending=None
class Refused(RuntimeError):pass
def need(value,code):
    if not value:raise Refused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def remaining():
    need(pending is None,'inert_cancelled')
    left=UNTIL-time.monotonic();need(left>0,'original_inert45_exhausted');return left
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
def stdin_once():
    need(sys.stdin.fileno()==0,'fixed_stdin')
    os.set_blocking(0,False);parts=[];size=0
    while True:
        readable,_,_=select.select([0],[],[],min(remaining(),0.1))
        if not readable:continue
        raw=os.read(0,min(65536,PAYLOAD_BYTES+1-size))
        if not raw:break
        size+=len(raw);need(size<=PAYLOAD_BYTES,'public_payload_bound');parts.append(raw)
    remaining();return b''.join(parts)
def load_definition_module(name,raw):
    need(name in ('mac_t5_volume_guard_r1.py','mac_owned_unreaped_r1.py','mac_owned_commands_r1.py'),
         'only_reviewed_library_definitions')
    key=name[:-3];need(key not in sys.modules,'fresh_library_namespace')
    module=types.ModuleType(key);module.__file__='<reviewed-stdin:'+name+'>'
    sys.modules[key]=module
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module

def fresh_root_absent(guard):
    with guard.parent(ROOT) as (parent,name):
        info=os.fstat(parent)
        before=tuple(str(x) for x in (
            info.st_dev,info.st_ino,info.st_uid,info.st_gid,
            info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns))
        observations=[]
        for _ in range(2):
            remaining();guard.check()
            try:os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:observations.append(True)
            else:raise Refused('fresh_root_already_exists')
        info=os.fstat(parent)
        after=tuple(str(x) for x in (
            info.st_dev,info.st_ino,info.st_uid,info.st_gid,
            info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns))
        need(before==after,'fresh_root_parent_stable')
        guard.check();remaining()
        return {'path':str(ROOT),'twoEnoentObservations':observations,
                'heldParentIdentity':list(before)}

def publish_public(guard,path,content,expected,kind):
    remaining()
    written=guard.write_new(path,content)
    # write_new closes its write descriptor. This is a separate held read FD.
    readback=guard.read(path,1048576,private=False)
    need(readback==content and written['sha256']==expected[1]
        and written['bytes']==expected[0],'held_whole_public_readback')
    with guard.parent(path) as (parent,name):
        info=os.stat(name,dir_fd=parent,follow_symlinks=False)
        current=[str(x) for x in (info.st_dev,info.st_ino,info.st_uid,info.st_gid,
            info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)]
        need(current==written['identity'] and info.st_uid==501 and info.st_nlink==1
            and info.st_mode&0o7777==0o600,'published_full_identity')
    guard.check();remaining()
    return {'name':str(path.relative_to(ROOT)),'kind':kind,**written,
            'wholeReadbackVerified':True,'readbackUsesSeparateHeldFd':True}

def main():
    os.umask(0o077)
    for signum in (signal.SIGTERM,signal.SIGINT):signal.signal(signum,on_signal)
    report={'schema':'heptabao.mac-registry-wal-public-synthetic-inert.r1','ok':False,'files':[],
        'currentPrivateInputsOpened':False,'productionSqliteOpened':False,'sqliteExecuted':False,
        'consumerExecuted':False,'serviceStarted':False,'gitStarted':False,'cargoStarted':False,
        'fixedLibraryDefinitionsLoadedOnly':True,'newOriginalInertSeconds':45,
        'sourceCount':10,'publicDocumentCount':2,'compiledPythonCountExpected':10,
        'candidateFileAloneIsNotQualification':True}
    guard=None;commands=None;candidate=None;prepared=False
    try:
        need(sys.platform=='darwin' and os.getuid()==501,'exact_mac_inert_owner')
        raw=stdin_once()
        need(len(raw)==PAYLOAD_BYTES and sha(raw)==PAYLOAD_SHA,'entire_fixed_public_payload')
        payload=json.loads(raw)
        need(set(payload)=={'schema','files','documents','anchorBase64'}
            and payload['schema']=='heptabao.mac-registry-wal-public-synthetic-inert-inputs.r1',
            'exact_public_payload_schema')
        need(isinstance(payload['files'],dict) and set(payload['files'])==set(PINS),'exact_ten_sources')
        need(isinstance(payload['documents'],dict) and set(payload['documents'])==set(DOCUMENT_PINS),
             'exact_two_public_documents')
        decoded={};compiled=[]
        for name,(size,pin) in PINS.items():
            remaining()
            content=base64.b64decode(payload['files'][name],validate=True)
            need(len(content)==size and sha(content)==pin,'whole_source_pin.'+name)
            if name.endswith('.py'):
                compile(ast.parse(content,filename=name),name,'exec');compiled.append(name)
            else:need(name.endswith('.mjs'),'fixed_source_extension')
            decoded[name]=content
        need(len(compiled)==10,'exact_python_compile_count')
        decoded_documents={}
        for name,(size,pin) in DOCUMENT_PINS.items():
            remaining()
            content=base64.b64decode(payload['documents'][name],validate=True)
            need(len(content)==size and sha(content)==pin,'whole_public_document_pin.'+name)
            decoded_documents[name]=content
        contract=json.loads(decoded_documents['candidate.public.json'])
        need(contract['sourcePins']=={name:pair[1] for name,pair in PINS.items()}
            and contract['publicVolumeAnchorSha256']==ANCHOR_SHA,'fixed_candidate_source_anchor')
        anchor=base64.b64decode(payload['anchorBase64'],validate=True)
        need(len(anchor)==967 and sha(anchor)==ANCHOR_SHA,'actual_public_t5_anchor')
        report['inputSha256']=sha(raw);report['inputBytes']=len(raw)
        report['compiledSources']=compiled
        report['byteVerifiedJavascriptSources']=[name for name in PINS if name.endswith('.mjs')]
        report['inputEntrypointsExecuted']=False
        custody=load_definition_module('mac_owned_unreaped_r1.py',decoded['mac_owned_unreaped_r1.py'])
        runner=load_definition_module('mac_owned_commands_r1.py',decoded['mac_owned_commands_r1.py'])
        volume=load_definition_module('mac_t5_volume_guard_r1.py',decoded['mac_t5_volume_guard_r1.py'])
        report['loadedLibraryDefinitions']=['mac_owned_unreaped_r1.py','mac_owned_commands_r1.py',
                                             'mac_t5_volume_guard_r1.py']
        # The above import-safe libraries contain no import-time process/file
        # action. Only the following fixed, reviewed guard is now called.
        class SignalState:
            @property
            def pending(self):return pending
            def critical(self):return critical()
        commands=runner.Commands(SignalState())
        guard=volume.HeldT5(anchor,ANCHOR_SHA,remaining,critical)
        query,out,_=commands.run('inert-t5-volume',
              ['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
              until=min(UNTIL,time.monotonic()+30),maximum=262144)
        need(query['exitCode']==0 and not query['outcomeUnknown'],'actual_prewrite_t5_complete')
        guard.accept_diskutil(out);report['volumeProbe']=query
        report['freshRootAbsence']=fresh_root_absent(guard)
        guard.mkdir_new(ROOT);report['createdRoot']=str(ROOT)
        guard.mkdir_new(QA);report['createdQa']=str(QA)
        for name,content in decoded.items():
            report['files'].append(publish_public(guard,QA/name,content,PINS[name],'source'))
        for name,content in decoded_documents.items():
            report['files'].append(publish_public(
                guard,ROOT/name,content,DOCUMENT_PINS[name],'public_document'))
        guard.check();remaining()
        prepared=True
        report['preparedCandidate']=True
        receipt=encode(report)
        candidate=publish_public(guard,ROOT/'inert-owned-registry-wal-result.public.json',
                                 receipt,(len(receipt),sha(receipt)),'inert_candidate_receipt')
    except BaseException as error:
        report['errorType']=type(error).__name__
        report['errorCode']=str(error) if isinstance(error,Refused) else None
    finally:
        signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
        if guard is not None:
            guard.close();report['heldT5Final']=guard.public_state()
        report['commands']=None if commands is None else commands.public()
        stopped=commands is not None and report['commands']['allOwnedCommandsStopped']
        closed=guard is not None and report['heldT5Final']['allDescriptorsClosed']
        final_anchor=guard is not None and report['heldT5Final']['lastAnchorCheckPassed']
        report['allOwnedCommandsStopped']=stopped
        report['allOwnedDescriptorsClosed']=closed
        report['outcomeUnknown']=bool(pending is not None or (commands is not None
            and report['commands']['unknownCommandCount']) or not stopped or not closed)
        completed=time.monotonic();report['elapsedSeconds']=completed-START
        report['candidateReceiptSha256']=None if candidate is None else candidate['sha256']
        report['candidateReceipt']=candidate
        report['originalDeadlineMetAfterClosure']=completed<UNTIL
        report['authoritativeExitZeroRequired']=True
        report['ok']=bool(prepared and candidate is not None and len(report['files'])==12
            and sum(x['kind']=='source' for x in report['files'])==10
            and sum(x['kind']=='public_document' for x in report['files'])==2
            and stopped and closed and final_anchor and not report['outcomeUnknown'] and completed<UNTIL)
        out=encode(report);need(len(out)<=65536,'public_result_bound')
        sys.stdout.buffer.write(out);sys.stdout.buffer.flush()
    return 0 if report['ok'] and time.monotonic()<UNTIL else 1

if __name__=='__main__':sys.exit(main())
