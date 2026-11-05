#!/usr/bin/env python3
"""Create only a fresh Mac native-current ROOT, 21 sources and six public documents.

No current credentials, production SQLite, consumer, manager or server is read
or executed. Three pinned import-safe custody libraries are loaded from the
already verified stdin bytes to guard diskutil and descriptor-relative writes.
"""
from __future__ import annotations
import ast, base64, hashlib, json, os, select, signal, sys, time, types
from contextlib import contextmanager
from pathlib import Path
START=time.monotonic();UNTIL=START+45.0
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-native-custody-r1')
QA=ROOT/'qa'
PROOFS=ROOT/'proofs'
PINS={
    "mac_current_fixture_materializer_r1.py": [
        23649,
        "9a5a4a5ca7954cf3a46327126ccfd8ea07d1ebcfbb3919723913d3e88b0d49b1"
    ],
    "mac_current_capture_entry_native_r1.py": [
        29748,
        "bd2dba90647769e8fb6302b76a70631ec2a9a272da42e653007344a27528daac"
    ],
    "mac_owned_launchd_r3.py": [
        35554,
        "4144c7046b666de7f739255527411ea808de26262b91c988ccaa877058dc59fd"
    ],
    "mac_current_server_owner_r1.py": [
        13218,
        "0cd83910200ecc212e94ca8213ebef0f89e7d9ea5c12d5e283626595bb9b23d4"
    ],
    "mac_current_phase_owner_r2.py": [
        24977,
        "8cee6359b6a8d49409f300fb1c32a8b59e953c9c6c53150c4cf423d6625cf53a"
    ],
    "mac_native_process_observer_r1.py": [
        13423,
        "cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b"
    ],
    "mac_guarded_current_capture_r3.py": [
        23578,
        "606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693"
    ],
    "mac_owned_commands_r1.py": [
        5965,
        "eb676e6dedb6d594d944e921738cf9b384f2a98a37ee2bd1fa5433b848a36867"
    ],
    "mac_t5_volume_guard_r1.py": [
        13393,
        "08365bb592d5691e49a20fa655a2bfa1a55eb1df03f833d5f24098f8b84b4927"
    ],
    "mac_owned_unreaped_r1.py": [
        10990,
        "a143ba334159931d530b49a55c24471f56fa1b62f1e1012e12c75e21f3c22b1d"
    ],
    "mac_capture_sqlite_synthetic_r1.py": [
        16476,
        "108f956eb3779fce31e01d630547344e22362839041afecb3821bf8053ff392c"
    ],
    "mac_capture_sqlite_synthetic_r2.py": [
        16915,
        "f3c6bb336814411aa4a24490f0904cdbd0fac2bb89dbcc36d6151ada13a51ba2"
    ],
    "mac_current_cycle_r2.mjs": [
        24013,
        "90d291d8f7bfb2f485f69dada794165d8dd74fda895a7ed8bd49f8f03155e055"
    ],
    "mac_single_native_r2.mjs": [
        28533,
        "12aa3d4d56b1ad1208a8ae030758f9c5883860a22f50c4fd83b7ee099a06fbca"
    ],
    "mac_auth_rows_cas_r1.mjs": [
        3109,
        "58a9431768e895a0e024819474bc9d10394cc44125532026d7efdcb742e5bc51"
    ],
    "mac_authbus_cache_cas_r1.mjs": [
        6846,
        "91644b97ae7deb4ede468832d3f91646bb00cd919149a510bfffe38d23544af8"
    ],
    "mac_current_outer_inputs_r2.py": [
        27067,
        "3bc95dacdf551522fec32a60f635236ff8bd1867e1c440642d03e2a0654cac85"
    ],
    "mac_current_outer_native_r1.py": [
        62213,
        "64d7a772f5b273d33d66a49c7c175310a0953953290351ea14ec61919265f883"
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
    ]
}
DOCUMENT_PINS={
    "proofs/synthetic-r2.stdout.public.json": [
        16228,
        "6c14a7f95e4f059090da2e88a3fff80eac79c1d83ef58a29df3cc67a610cd8f5"
    ],
    "proofs/synthetic-r2.authority.public.json": [
        733,
        "1b33a9144712ac2bc3d16d87bb2a9ea1c2e4c0be236dfd08d8b599f7518942dd"
    ],
    "proofs/native-proc-r2.stdout.public.json": [
        24032,
        "7a1b715e595a2badf18e4f01506cca2ee7c4c0a760c5ef3c86708a435ace9c4f"
    ],
    "proofs/native-proc-r2.authority.public.json": [
        733,
        "411ea26371219c49547abc014464585551ba4a69b70bb906b92561a8d5bddf23"
    ],
    "proofs/native-proc-r2.child-stdout.public.json": [
        11066,
        "bb5717753866c0d7e647e4fd5c18a3342db0f530016cc7d92cb508c955ff8644"
    ],
    "candidate-current-manager-native-r1.public.json": [
        5103,
        "be996a13e1bad8980c2c86ddf36e7bc08a49db0ea0676d1fa4ecbf953635b581"
    ]
}
PAYLOAD_BYTES=625538
PAYLOAD_SHA='738df828f078fffb9610c6b98d6ba9a709446642a5a7ed3a43e62d19f2d9c800'
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
        before=tuple(str(x) for x in (
            (info:=os.fstat(parent)).st_dev,info.st_ino,info.st_uid,info.st_gid,
            info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns))
        observations=[]
        for _ in range(2):
            remaining();guard.check()
            try:os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:observations.append(True)
            else:raise Refused('fresh_root_already_exists')
        after=tuple(str(x) for x in (
            (info:=os.fstat(parent)).st_dev,info.st_ino,info.st_uid,info.st_gid,
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
    report={'schema':'heptabao.mac-current-native-df026-inert.r1','ok':False,'files':[],
        'currentPrivateInputsOpened':False,'productionSqliteOpened':False,'sqliteExecuted':False,
        'consumerExecuted':False,'serviceStarted':False,'gitStarted':False,'cargoStarted':False,
        'fixedLibraryDefinitionsLoadedOnly':True,'newOriginalInertSeconds':45,
        'sourceCount':21,'publicDocumentCount':6,'compiledPythonCountExpected':17,
        'candidateFileAloneIsNotQualification':True}
    guard=None;commands=None;candidate=None;prepared=False
    try:
        need(sys.platform=='darwin' and os.getuid()==501,'exact_mac_inert_owner')
        raw=stdin_once()
        need(len(raw)==PAYLOAD_BYTES and sha(raw)==PAYLOAD_SHA,'entire_fixed_public_payload')
        payload=json.loads(raw)
        need(set(payload)=={'schema','files','documents','anchorBase64'}
            and payload['schema']=='heptabao.mac-current-native-df026-inert-public-inputs.r1',
            'exact_public_payload_schema')
        need(isinstance(payload['files'],dict) and set(payload['files'])==set(PINS),'exact_21_sources')
        need(isinstance(payload['documents'],dict) and set(payload['documents'])==set(DOCUMENT_PINS),
             'exact_six_public_documents')
        decoded={};compiled=[]
        for name,(size,pin) in PINS.items():
            remaining()
            content=base64.b64decode(payload['files'][name],validate=True)
            need(len(content)==size and sha(content)==pin,'whole_source_pin.'+name)
            if name.endswith('.py'):
                compile(ast.parse(content,filename=name),name,'exec');compiled.append(name)
            else:need(name.endswith('.mjs'),'fixed_source_extension')
            decoded[name]=content
        need(len(compiled)==17,'exact_python_compile_count')
        decoded_documents={}
        for name,(size,pin) in DOCUMENT_PINS.items():
            remaining()
            content=base64.b64decode(payload['documents'][name],validate=True)
            need(len(content)==size and sha(content)==pin,'whole_public_document_pin.'+name)
            decoded_documents[name]=content
        contract=json.loads(decoded_documents['candidate-current-manager-native-r1.public.json'])
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
        guard.mkdir_new(PROOFS);report['createdProofs']=str(PROOFS)
        for name,content in decoded.items():
            report['files'].append(publish_public(guard,QA/name,content,PINS[name],'source'))
        for name,content in decoded_documents.items():
            report['files'].append(publish_public(
                guard,ROOT/name,content,DOCUMENT_PINS[name],'public_document'))
        guard.check();remaining()
        prepared=True
        report['preparedCandidate']=True
        receipt=encode(report)
        candidate=publish_public(guard,ROOT/'inert-native-df026-result.public.json',
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
        report['ok']=bool(prepared and candidate is not None and len(report['files'])==27
            and sum(x['kind']=='source' for x in report['files'])==21
            and sum(x['kind']=='public_document' for x in report['files'])==6
            and stopped and closed and final_anchor and not report['outcomeUnknown'] and completed<UNTIL)
        out=encode(report);need(len(out)<=65536,'public_result_bound')
        sys.stdout.buffer.write(out);sys.stdout.buffer.flush()
    return 0 if report['ok'] and time.monotonic()<UNTIL else 1

if __name__=='__main__':sys.exit(main())
