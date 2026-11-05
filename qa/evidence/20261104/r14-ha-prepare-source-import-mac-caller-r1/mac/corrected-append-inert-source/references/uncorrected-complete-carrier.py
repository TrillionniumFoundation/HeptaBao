#!/usr/bin/env python3
"""Append the complete reviewed Mac caller under the verified ROOT/qa.

No current credentials, production SQLite, consumer, manager or server is read
or executed. Three pinned import-safe custody libraries are loaded from the
already verified stdin bytes to guard diskutil and descriptor-relative writes.
"""
from __future__ import annotations
import ast, base64, hashlib, json, os, select, signal, sys, time, types
from contextlib import contextmanager
from pathlib import Path
START=time.monotonic();UNTIL=START+45.0
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1')
QA=ROOT/'qa'
NEW_NAMES=[
    "mac_current_outer_r3.py",
    "mac_current_outer_inputs_r1.py",
    "mac_current_fixture_materializer_r1.py",
    "mac_current_capture_entry_r1.py",
    "mac_owned_launchd_r3.py",
    "mac_current_server_owner_r1.py",
    "mac_current_phase_owner_r2.py",
    "mac_native_process_observer_r1.py",
    "mac_current_cycle_r2.mjs",
    "mac_single_native_r2.mjs",
    "mac_auth_rows_cas_r1.mjs",
    "mac_authbus_cache_cas_r1.mjs"
]
PINS={
    "mac_current_outer_r3.py": [
        58586,
        "986194f0da2d278986589d5ec757fb50a040182db6f610addba9469ee97e1be5"
    ],
    "mac_current_outer_inputs_r1.py": [
        24973,
        "be5da65ce3bd98586d36b11edba6a4619600b74fbabb93050a3325e89e9ed254"
    ],
    "mac_current_fixture_materializer_r1.py": [
        23631,
        "9ae14eccdec7742c31df92fede042acac68514b3713ef8cb751cb8f456fb1526"
    ],
    "mac_current_capture_entry_r1.py": [
        19011,
        "fe56d9676aacf5cf4feb373130be93c4a17fab2589a1439da4ebe96a4cad4024"
    ],
    "mac_owned_launchd_r3.py": [
        35532,
        "1c18be9069b4f7219a793c88e08a648841bcab992b8947a9064d55712539c09c"
    ],
    "mac_current_server_owner_r1.py": [
        13210,
        "3932ddada69310b700b7b6aafd325202c1deda84c2f12d711e27d022111bdfb6"
    ],
    "mac_current_phase_owner_r2.py": [
        25005,
        "42520fe933e2c0106e6983a282421759b260a2bf48a08f86d0f404caa3f2eb86"
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
        13387,
        "10e140b37a17b5f7fd5cc569b1632da99b61fd544ec732a8806ff402d4ee0d99"
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
        24007,
        "2b982383ce66028159ae84845bf5a0d3515e0308bab6916944bd7195bb948177"
    ],
    "mac_single_native_r2.mjs": [
        28527,
        "f90bbb2e9a1fa679d04fbef4328f3a1b9fc512d2b809dacd7eafce67f9cfd93c"
    ],
    "mac_auth_rows_cas_r1.mjs": [
        3103,
        "0021fa7539f4fb36e2ac907315da1c9d9e407c9ccac606d1908e0b7a3f7042dd"
    ],
    "mac_authbus_cache_cas_r1.mjs": [
        6846,
        "91644b97ae7deb4ede468832d3f91646bb00cd919149a510bfffe38d23544af8"
    ]
}
PRESERVED={
    "mac_guarded_current_capture_r3.py": [
        "16777244",
        "72546528",
        "501",
        "20",
        "33152",
        "1",
        "23578",
        "1793835363123696870",
        "1793835363123706328"
    ],
    "mac_capture_sqlite_synthetic_r1.py": [
        "16777244",
        "72546529",
        "501",
        "20",
        "33152",
        "1",
        "16476",
        "1793835363125849429",
        "1793835363125857554"
    ],
    "mac_owned_commands_r1.py": [
        "16777244",
        "72546530",
        "501",
        "20",
        "33152",
        "1",
        "5965",
        "1793835363126339808",
        "1793835363126345391"
    ],
    "mac_t5_volume_guard_r1.py": [
        "16777244",
        "72546531",
        "501",
        "20",
        "33152",
        "1",
        "13387",
        "1793835363126785478",
        "1793835363126791353"
    ],
    "mac_owned_unreaped_r1.py": [
        "16777244",
        "72546532",
        "501",
        "20",
        "33152",
        "1",
        "10990",
        "1793835363127259607",
        "1793835363127265315"
    ],
    "mac_capture_sqlite_synthetic_r2.py": [
        "16777244",
        "72548952",
        "501",
        "20",
        "33152",
        "1",
        "16915",
        "1793838192075174831",
        "1793838192075185998"
    ]
}
DOCUMENTS={
    "proofs/synthetic-r2.stdout.public.json": [
        16228,
        "6c14a7f95e4f059090da2e88a3fff80eac79c1d83ef58a29df3cc67a610cd8f5"
    ],
    "proofs/synthetic-r2.authority.public.json": [
        733,
        "1b33a9144712ac2bc3d16d87bb2a9ea1c2e4c0be236dfd08d8b599f7518942dd"
    ],
    "candidate-current-manager-r3.public.json": [
        3442,
        "2a5da6b02650c2ecf2134f68de90c4698a48757988f3b021e6015e74cc6bff03"
    ]
}
PAYLOAD_BYTES=513624
PAYLOAD_SHA='f819276fa24fc5f4d7136ccb7f382db3897bea82aea6ee25172d5edce0f7163a'
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
    remaining();raw=b''.join(parts)
    need(len(raw)==PAYLOAD_BYTES and sha(raw)==PAYLOAD_SHA,'exact_frozen_public_payload')
    return raw
def load_definition_module(name,raw):
    need(name in ('mac_t5_volume_guard_r1.py','mac_owned_unreaped_r1.py','mac_owned_commands_r1.py'),
         'only_reviewed_library_definitions')
    key=name[:-3];need(key not in sys.modules,'fresh_library_namespace')
    module=types.ModuleType(key);module.__file__='<reviewed-stdin:'+name+'>'
    sys.modules[key]=module
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module

def main():
    os.umask(0o077)
    for signum in (signal.SIGTERM,signal.SIGINT):signal.signal(signum,on_signal)
    report={'schema':'heptabao.mac-current-complete-source-append-inert.r3','ok':False,'files':[],
        'currentPrivateInputsOpened':False,'productionSqliteOpened':False,'sqliteExecuted':False,
        'consumerExecuted':False,'serviceStarted':False,'gitStarted':False,'cargoStarted':False,
        'fixedLibraryDefinitionsLoadedOnly':True,'newOriginalInertSeconds':45}
    guard=None;commands=None;candidate=None;prepared=False
    try:
        need(sys.platform=='darwin' and os.getuid()==501,'exact_mac_inert_owner')
        raw=stdin_once();payload=json.loads(raw)
        need(set(payload)=={'schema','files','documents','anchorBase64'}
            and payload['schema']=='heptabao.mac-current-complete-source-append-public-inputs.r3',
            'exact_public_payload_schema')
        need(isinstance(payload['files'],dict) and set(payload['files'])==set(PINS),'exact_eighteen_reviewed_sources')
        decoded={}
        for name,(size,pin) in PINS.items():
            content=base64.b64decode(payload['files'][name],validate=True)
            need(len(content)==size and sha(content)==pin,'whole_source_pin.'+name)
            if name.endswith('.py'):compile(ast.parse(content,filename=name),name,'exec')
            decoded[name]=content
        need(isinstance(payload['documents'],dict) and set(payload['documents'])==set(DOCUMENTS),
             'exact_three_public_documents')
        document_bytes={}
        for name,(size,pin) in DOCUMENTS.items():
            content=base64.b64decode(payload['documents'][name],validate=True)
            need(len(content)==size and sha(content)==pin,'whole_public_document_pin.'+name)
            document_bytes[name]=content
        anchor=base64.b64decode(payload['anchorBase64'],validate=True)
        need(len(anchor)==967 and sha(anchor)==ANCHOR_SHA,'actual_public_t5_anchor')
        report['inputSha256']=sha(raw);report['inputBytes']=len(raw)
        report['compiledSources']=[name for name in PINS if name.endswith('.py')]
        report['hashOnlyJavascriptSources']=[name for name in PINS if name.endswith('.mjs')]
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
        need(len(NEW_NAMES)==12 and len(set(NEW_NAMES))==12
             and set(PRESERVED)==set(PINS)-set(NEW_NAMES) and len(PRESERVED)==6,
             'preserved_six_and_new_twelve_contract')
        def preserve_sources():
            values=[]
            for name,expected in PRESERVED.items():
                with guard.parent(QA/name) as (parent,leaf):
                    initial=volume.identity(os.stat(leaf,dir_fd=parent,follow_symlinks=False))
                    need(initial==tuple(expected),'original_inert_source_named_identity')
                    observed=guard.read(QA/name,1048576)
                    final=volume.identity(os.stat(leaf,dir_fd=parent,follow_symlinks=False))
                    need(initial==final and observed==decoded[name],'original_inert_source_unchanged')
                    values.append({'name':name,'bytes':len(observed),'sha256':sha(observed),
                                   'identity':list(final)})
            return values
        report['preservedSourcesBefore']=preserve_sources()
        for name in NEW_NAMES:
            written=guard.write_new(QA/name,decoded[name])
            readback=guard.read(QA/name,1048576)
            need(readback==decoded[name] and written['sha256']==PINS[name][1]
                 and written['bytes']==PINS[name][0],'held_readback_exact_new_source')
            report['files'].append({'path':'qa/'+name,**written,'wholeReadbackVerified':True})
        report['proofDirectoryIdentity']=guard.mkdir_new(ROOT/'proofs')
        report['createdProofDirectory']=True
        for name,content in document_bytes.items():
            written=guard.write_new(ROOT/name,content)
            readback=guard.read(ROOT/name,1048576)
            need(readback==content and written['sha256']==DOCUMENTS[name][1]
                 and written['bytes']==DOCUMENTS[name][0],'held_readback_exact_public_document')
            report['files'].append({'path':name,**written,'wholeReadbackVerified':True})
            if name=='candidate-current-manager-r3.public.json':candidate=written
        report['preservedSourcesAfter']=preserve_sources()
        need(report['preservedSourcesBefore']==report['preservedSourcesAfter'],
             'all_original_six_source_identities_unchanged')
        report['createdRoot']=False;report['createdQa']=False
        guard.check();remaining()
        prepared=True
        report['preparedCandidate']=True
        need(candidate is not None and len(report['files'])==15,'all_append_members_complete')
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
        report['publishedCandidateSha256']=None if candidate is None else candidate['sha256']
        report['originalDeadlineMetAfterClosure']=completed<UNTIL
        report['authoritativeExitZeroRequired']=True
        report['ok']=bool(prepared and candidate is not None and len(report['files'])==15
            and len(report.get('preservedSourcesAfter',[]))==6
            and stopped and closed and final_anchor and not report['outcomeUnknown'] and completed<UNTIL)
        out=encode(report);need(len(out)<=65536,'public_result_bound')
        sys.stdout.buffer.write(out);sys.stdout.buffer.flush()
    return 0 if report['ok'] and time.monotonic()<UNTIL else 1

if __name__=='__main__':sys.exit(main())
