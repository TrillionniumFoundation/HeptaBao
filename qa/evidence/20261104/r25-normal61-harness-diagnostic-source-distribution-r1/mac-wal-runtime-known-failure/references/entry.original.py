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

ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-registry-wal-r1')
QA=ROOT/'qa'
LIVE=Path('/Users/qianqi/.openclaw')
AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')
CACHE_NAMES=('applied-profiles.json','publish-baseline.json','bad-refresh-quarantine.json',
             'refresh-backoff.json','lease-epochs.json','status.json')
NAMES=('mac_current_capture_entry_wal_r1.py','mac_guarded_current_capture_r3.py',
       'mac_t5_volume_guard_r1.py','mac_darwin_owned_projection_r1.py',
       'mac_native_owned_commands_r1.py','mac_native_owned_unreaped_r1.py',
       'mac_registry_readonly_wal_r1.py')
SYNTHETIC_SOURCE_SHA='f3c6bb336814411aa4a24490f0904cdbd0fac2bb89dbcc36d6151ada13a51ba2'
CAPTURE_SOURCE_SHA='606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693'
NATIVE_BINDING={
  "schema": "heptabao.mac-native-proc-input-binding.r1",
  "jobId": "1a1aa0eabee-fc05-3c36",
  "stdoutBytes": 24032,
  "stdoutSha256": "7a1b715e595a2badf18e4f01506cca2ee7c4c0a760c5ef3c86708a435ace9c4f",
  "authorityBytes": 733,
  "authoritySha256": "411ea26371219c49547abc014464585551ba4a69b70bb906b92561a8d5bddf23",
  "childStdoutBytes": 11066,
  "childStdoutSha256": "bb5717753866c0d7e647e4fd5c18a3342db0f530016cc7d92cb508c955ff8644",
  "controllerSha256": "4dc7cc28869ff4cd78bd4d442619e79a44d82b0ae46c5040dcd9b59e0e17921d",
  "modulePins": {
    "mac_darwin_owned_projection_r1.py": "77b63286d79827671009d56d238494c472f37e3674bf903ab2da092b42733740",
    "mac_native_owned_unreaped_r1.py": "880794d5e0f01f45e9c559688b2ebd33c2c96399124ea3ecb9e58720a2424d0c",
    "mac_native_owned_commands_r1.py": "717feff0a8719a6c208b14aa1598cefd59881fffa09d19c781a89689b025b9cd"
  },
  "probeProfileSha256": {
    "original": "d31751dc8da537121b3f1ccce832a666cc6499bdef4d956ab3208dec86daf35e",
    "patched": "58a8f52a66b0e6136b786857cb72e3f775837907bf382850320673342750c6bd"
  },
  "additionalReadOnlyDirectoryLiteral": "/Volumes/T5/hepta-vnext-recovery-20261013",
  "additionalReadRuleSha256": "f591502879fc5b1f579d5d8ced77ce375b37269725c5dd3531f650e4c46676ef"
}
WAL_BINDING={
  "schema": "heptabao.mac-registry-readonly-wal-input-binding.r1",
  "jobId": "1a1aaaaa6cd-fc05-45dd",
  "stdoutBytes": 62662,
  "stdoutSha256": "7d08a18c21a5d754ea9fbe7711e6315daf8fbd80c7b5a6937756fea7ba4d1c82",
  "authorityBytes": 733,
  "authoritySha256": "b564093e2300cdc44b2ae4724e869d5b24bfe3d94d269f8ebfa977e08b07505f",
  "controllerSha256": "88a6abdc02c71b0cb25f6b85a4494f0b44a30c2f8a4936bb511948f258737cdc",
  "librarySha256": "60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed",
  "cases": {
    "W01": {
      "stdoutBytes": 11923,
      "stdoutSha256": "65c7881d113e1922f47d514eeb2260d3fd5c29c26fb67f654219ff5d373a1961"
    },
    "W02": {
      "stdoutBytes": 7222,
      "stdoutSha256": "15e3a834a5b283f5d1bf229e9c927cbc93b9b75ce0cad5d7a1a9964a1fde69f6"
    },
    "W03": {
      "stdoutBytes": 8025,
      "stdoutSha256": "ec2ced80293abcb4e5bd6d28fa6155076565cd5fb8e3dddfb5425695e4689293"
    },
    "W04": {
      "stdoutBytes": 8078,
      "stdoutSha256": "0fe9136fa7e654e841b63fd377b17abe11fafef7bbb1b9ae24af4d31701be4fa"
    },
    "W05": {
      "stdoutBytes": 11300,
      "stdoutSha256": "39476829ff2ec1610894721f3f29bed8801e49833df1e0988e1e112a82111fb7"
    },
    "W06": {
      "stdoutBytes": 11300,
      "stdoutSha256": "f7c5e84d6fe464b285bec0a5418e757aa87c2d3755f6af0ef6411b53acf026bc"
    },
    "W07": {
      "stdoutBytes": 11296,
      "stdoutSha256": "aeca9311147e86b45ff3f70ff5227b1318b12aefa464fb78fa6734a41e4da62f"
    },
    "W08": {
      "stdoutBytes": 11298,
      "stdoutSha256": "d24ae166653df4c8ad209a3998afb6924d9287877321fc2046e4f125c6a36cb6"
    },
    "W09": {
      "stdoutBytes": 11049,
      "stdoutSha256": "a47c06c90261e1d8a2e1d7d1075a06ab33b577f27056ef66c28e3815c97ae9c0"
    },
    "W10": {
      "stdoutBytes": 11302,
      "stdoutSha256": "dad92e8055161be45c826bc1178a0b545250493e8d436edfe84753fa33d07a88"
    }
  }
}
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

def admitted_native(guard,binding):
    """Admit three exact original public records; never accept a template."""
    need(type(binding) is dict and binding==NATIVE_BINDING,'exact_actual_native_binding')
    originals={}
    for role,name,size_key,sha_key in (
        ('stdout','native-proc-r2.stdout.public.json','stdoutBytes','stdoutSha256'),
        ('authority','native-proc-r2.authority.public.json','authorityBytes','authoritySha256'),
        ('child','native-proc-r2.child-stdout.public.json','childStdoutBytes','childStdoutSha256')):
        raw=guard.read(ROOT/'proofs'/name,65536)
        need(len(raw)==binding[size_key] and sha(raw)==binding[sha_key],
             'whole_original_native_'+role)
        originals[role]=raw
    authority=json.loads(originals['authority'])
    proof=json.loads(originals['stdout']);child=json.loads(originals['child'])
    need(type(authority) is dict and authority.get('job_id')==binding['jobId']
         and type(authority.get('exit_code')) is int and authority['exit_code']==0
         and authority.get('state')=='succeeded'
         and all(authority.get(k) is True for k in
             ('output_complete','output_durable','terminal_publication_confirmed'))
         and all(authority.get(k) is False for k in ('timed_out','cancelled','automatic_retry')),
         'successful_authoritative_native_terminal')
    for stream,size in (('stdout',binding['stdoutBytes']),('stderr',0)):
        need(authority.get('log_bytes',{}).get(stream)=={'seen':size,'stored':size}
             and authority.get('log_errors',{}).get(stream) is None
             and authority.get('log_synced',{}).get(stream) is True
             and authority.get('log_truncated',{}).get(stream) is False,
             'complete_original_native_log_'+stream)
    need(type(proof) is dict and proof.get('schema')=='heptabao.mac-native-proc-sandbox-probe.r2'
         and type(child) is dict and child.get('schema')=='heptabao.mac-native-proc-sandbox-child.r2',
         'exact_public_native_report_schemas')
    cases=proof.get('cases')
    need(type(cases) is list and len(cases)==1 and type(cases[0]) is dict
         and cases[0].get('variant')=='native' and type(cases[0].get('exitCode')) is int
         and cases[0]['exitCode']==0 and cases[0].get('report')==child
         and cases[0].get('stdoutBytes')==binding['childStdoutBytes']
         and cases[0].get('stdoutSha256')==binding['childStdoutSha256']
         and cases[0].get('stderrBytes')==0
         and cases[0].get('stderrSha256')==sha(b''),'exact_original_native_child_terminal')
    for value,count in ((proof,2),(child,1)):
        need(value.get('ok') is True and value.get('outcomeUnknown') is False
             and value.get('sourceSha256')==binding['controllerSha256']
             and value.get('originalCaptureSeconds')==45
             and value.get('originalDeadlineMetAfterClosure') is True
             and type(value.get('elapsedSeconds')) in (int,float)
             and math.isfinite(value['elapsedSeconds']) and 0<=value['elapsedSeconds']<45,
             'successful_original_native_report')
        need(all(value.get(k) is False for k in (
            'productionReadAttempted','productionWriteAttempted','sqliteImported',
            'consumerStarted','providerRequested','j3160Contacted','businessReplay',
            'failedCaptureBeforePathUsed','systemUtilitiesCopiedOrChanged')),
             'public_native_probe_scope_only')
        held=value.get('heldT5Final',{});owned=value.get('ownedCommands',{})
        need(value.get('allOwnedDescriptorsClosed') is True
             and held.get('allDescriptorsClosed') is True
             and held.get('lastAnchorCheckPassed') is True
             and held.get('volumeUUIDVerified') is True and held.get('closeErrors')==[]
             and owned.get('allOwnedCommandsStopped') is True and owned.get('unknownCommandCount')==0
             and type(owned.get('commands')) is list and len(owned['commands'])==count,
             'complete_public_native_fd_and_owned_closure')
        for row in owned['commands']:
            need(type(row) is dict and type(row.get('exitCode')) is int and row['exitCode']==0
                 and row.get('completeBeforeDeadline') is True and row.get('outcomeUnknown') is False
                 and row.get('streamsClosed') is True,'public_native_command_known_complete')
            closed=row.get('cleanup',{})
            need(closed.get('ok') is True and closed.get('outcomeUnknown') is False
                 and closed.get('directChildReaped') is True
                 and closed.get('ownedLiveGroupEmptyBeforeReap') is True
                 and closed.get('allGroupRowsEmptyAfterReap') is True
                 and closed.get('remainingGroupRows')==[] and closed.get('signals')==[]
                 and closed.get('postReapSignalSent') is False,
                 'public_native_retained_custody_terminal')
        modules=value.get('nativeModulesBefore')
        need(type(modules) is dict and set(modules)==set(binding['modulePins'])
             and modules==value.get('nativeModulesAfter')
             and all(type(modules[name]) is dict and modules[name].get('sha256')==pin
                     for name,pin in binding['modulePins'].items()),
             'public_native_three_module_whole_pins')
        need(type(value.get('sourceBefore')) is dict and len(value['sourceBefore'])==4
             and value['sourceBefore']==value.get('sourceAfter'),
             'public_native_old_sources_unchanged')
        need(value.get('profileSha256')==binding['probeProfileSha256']
             and value.get('policyPermissionsAddedBeyondDevnull') is True
             and value.get('additionalReadOnlyDirectoryLiteral')==binding['additionalReadOnlyDirectoryLiteral']
             and value.get('additionalReadRuleSha256')==binding['additionalReadRuleSha256'],
             'explicit_public_native_policy_delta')
    need(type(proof.get('utilityBefore')) is dict and len(proof['utilityBefore'])==3
         and proof['utilityBefore']==proof.get('utilityAfter'),'public_native_utilities_unchanged')
    kernel=child.get('kernelSandboxProof',{});checks=kernel.get('checks')
    need(kernel.get('allFourDenied') is True and type(checks) is list and len(checks)==4
         and [row.get('case') for row in checks]==[
             'main_write_open','sidecar_create','sidecar_create','loopback_connect']
         and all(row.get('denied') is True and row.get('errno') in (errno.EACCES,errno.EPERM)
                 for row in checks),'all_four_original_native_kernel_refusals')
    projection=child.get('nativeProjection',{})
    need(projection.get('selfQualified') is True and type(projection.get('identity')) is dict
         and projection.get('allHostEnumerationUsed') is False
         and projection.get('commandNamesOrPathsProjected') is False
         and projection.get('pidListNullBufferUsed') is False
         and projection.get('maxGroupMembers')==64 and projection.get('querySeconds')==4,
         'public_native_bounded_projection_qualified')
    need(child.get('nativeSelfBefore')==child.get('nativeSelfAfter')
         and type(child.get('nativeSelfBefore')) is dict
         and child['nativeSelfBefore'].get('pidUidPpidPgidMatchedIndependentOsApis') is True,
         'public_native_same_self_birth_qualified')
    guard.check()
    return originals['stdout'],child

def admitted_wal(guard,binding):
    """Pin the actual public ten-case stdout and its authoritative terminal."""
    need(type(binding) is dict and binding==WAL_BINDING,'exact_actual_registry_wal_binding')
    raw=guard.read(ROOT/'proofs/registry-wal-r1.stdout.public.json',262144)
    authority_raw=guard.read(ROOT/'proofs/registry-wal-r1.authority.public.json',65536)
    need(len(raw)==binding['stdoutBytes'] and sha(raw)==binding['stdoutSha256']
         and len(authority_raw)==binding['authorityBytes']
         and sha(authority_raw)==binding['authoritySha256'],'actual_original_registry_wal_bytes')
    authority=json.loads(authority_raw);proof=json.loads(raw)
    need(type(authority) is dict and authority.get('job_id')==binding['jobId']
         and type(authority.get('exit_code')) is int and authority['exit_code']==0
         and authority.get('state')=='succeeded'
         and all(authority.get(k) is True for k in
             ('output_complete','output_durable','terminal_publication_confirmed'))
         and all(authority.get(k) is False for k in ('timed_out','cancelled','automatic_retry')),
         'successful_authoritative_registry_wal_terminal')
    for stream,size in (('stdout',len(raw)),('stderr',0)):
        need(authority.get('log_bytes',{}).get(stream)=={'seen':size,'stored':size}
             and authority.get('log_errors',{}).get(stream) is None
             and authority.get('log_synced',{}).get(stream) is True
             and authority.get('log_truncated',{}).get(stream) is False,
             'complete_original_registry_wal_log_'+stream)
    need(type(proof) is dict and proof.get('schema')=='heptabao.mac-owned-registry-wal-synthetic.r1'
         and proof.get('ok') is True and proof.get('outcomeUnknown') is False
         and proof.get('allCasesMatched') is True and proof.get('allOwnedClosed') is True
         and proof.get('originalDeadlineAfterClosure') is True
         and proof.get('sourceAndRuntimeAfterVerified') is True
         and proof.get('sharedSeconds')==45 and proof.get('querySeconds')==3
         and proof.get('supervisorSeconds')==60 and proof.get('applicationRetries')==0
         and type(proof.get('elapsedSeconds')) in (int,float)
         and math.isfinite(proof['elapsedSeconds']) and 0<=proof['elapsedSeconds']<45
         and all(proof.get(k) is False for k in
             ('productionInputsRead','privateCaptureAuthorized','wholeDatabaseBackupQualified')),
         'successful_complete_public_registry_wal_report')
    wanted=list(binding['cases'])
    need(proof.get('caseIds')==wanted and type(proof.get('cases')) is list
         and [x.get('case') for x in proof['cases']]==wanted,
         'all_ten_exact_registry_wal_cases')
    for row in proof['cases']:
        item=binding['cases'][row['case']];command=row.get('command',{})
        need(row.get('matched') is True and row.get('mainUnchangedAcrossWalCommit') is True
             and row.get('writerClosedBeforeHeldFdClose') is True
             and row.get('readerStdoutBytes')==item['stdoutBytes']
             and row.get('readerStdoutSha256')==item['stdoutSha256']
             and command.get('stdoutBytes')==item['stdoutBytes']
             and command.get('stdoutSha256')==item['stdoutSha256']
             and command.get('controlPipesClosed') is True,'exact_public_registry_wal_case')
    owned=proof.get('ownedCommands',{});volume=owned.get('commands');readers=proof.get('ownedReaders')
    need(owned.get('allOwnedCommandsStopped') is True and owned.get('unknownCommandCount')==0
         and type(volume) is list and len(volume)==1
         and volume[0].get('label')=='owned-wal-volume'
         and volume[0].get('argv')==['/usr/sbin/diskutil','info','-plist','/Volumes/T5']
         and type(readers) is list and len(readers)==10
         and [row.get('case') for row in readers]==wanted
         and all(row['command']==reader for row,reader in zip(proof['cases'],readers)),
         'public_registry_wal_one_volume_and_ten_reader_set')
    for row in [*volume,*readers]:
        closed=row.get('cleanup',{})
        need(type(row.get('exitCode')) is int and row['exitCode']==0
             and row.get('completeBeforeDeadline') is True and row.get('outcomeUnknown') is False
             and row.get('streamsClosed') is True and closed.get('ok') is True
             and closed.get('outcomeUnknown') is False and closed.get('directChildReaped') is True
             and closed.get('ownedLiveGroupEmptyBeforeReap') is True
             and closed.get('allGroupRowsEmptyAfterReap') is True
             and closed.get('remainingGroupRows')==[] and closed.get('postReapSignalSent') is False,
             'public_registry_wal_retained_child_closure')
    writers=proof.get('writerConnections');fds=proof.get('ownedFdLedger');held=proof.get('heldT5Final',{})
    need(type(writers) is list and len(writers)==10
         and all(x.get('closeAttempted') is True and x.get('closed') is True
             and x.get('closeErrorType') is None and x.get('cursorsClosed') is True
             and x.get('heldDescriptorsClosed') is True for x in writers)
         and type(fds) is list and fds and all(x.get('closeAttempted') is True
             and x.get('closed') is True for x in fds)
         and held.get('allDescriptorsClosed') is True and held.get('lastAnchorCheckPassed') is True
         and held.get('volumeUUIDVerified') is True and held.get('closeErrors')==[],
         'public_registry_wal_writer_fd_volume_closure')
    pins=proof.get('sourcePins',{})
    need(pins.get('mac_wal_owned_synthetic_r1.py')==binding['controllerSha256']
         and pins.get('mac_registry_readonly_wal_r1.py')==binding['librarySha256']
         and pins.get('mac_guarded_current_capture_r3.py')==CAPTURE_SOURCE_SHA
         and all(pins.get(name)==pin for name,pin in NATIVE_BINDING['modulePins'].items()),
         'actual_registry_wal_source_and_native_pins')
    guard.check()
    return raw,proof

def library_resources_closed(value):
    """Returned-handle/registered-FD evidence, never SQLite internal-FD inference."""
    if type(value) is not dict or value.get('schema')!='heptabao.mac-registry-readonly-wal-attempt.r1':
        return False
    if not all(value.get(key) is True for key in (
        'allOwnedDescriptorsClosed','allHeldDescriptorsClosed','allReturnedConnectionsClosed',
        'allExplicitCursorsClosed','allPublicCodeDescriptorsClosed',
        'publicCodeHashDescriptorsIndividuallyEnumerated')) or value.get('closeErrors')!=[]:
        return False
    for key in ('descriptors','connections','cursors','publicCodeDescriptors'):
        rows=value.get(key)
        if type(rows) is not list or not all(type(row) is dict
            and row.get('closeAttempted') is True and row.get('closed') is True
            and row.get('closeError') is None for row in rows):
            return False
    return True

def capture_envelope(value):
    need(type(value) is dict and value.get('schema')=='heptabao.mac-registry-readonly-wal-attempt.r1'
         and value.get('libraryFailureLedgerAvailable') is True
         and value.get('originalFiveAgentRouteUnchanged') is True
         and value.get('privateResultPublished') is False
         and all(type(value.get(key)) is bool for key in
             ('ok','observationComplete','observationUnknown','originalDeadlineMetAfterClosure')),
         'typed_current_capture_library_envelope')
    need(len(encoded(value))<=196608,'bounded_current_capture_library_envelope')
    if value['ok']:
        need(value['observationComplete'] and not value['observationUnknown']
             and value['originalDeadlineMetAfterClosure'] and value.get('error') is None
             and library_resources_closed(value),'successful_current_capture_library_envelope')
    return value

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
    parser.add_argument('--native-binding-base64',required=True)
    parser.add_argument('--native-binding-sha256',required=True)
    parser.add_argument('--wal-binding-base64',required=True)
    parser.add_argument('--wal-binding-sha256',required=True)
    parser.add_argument('--sandbox-profile-sha256',required=True)
    args=parser.parse_args();os.umask(0o077)
    need(math.isfinite(args.absolute_until) and START<args.absolute_until<=START+45,
         'one_original_capture_deadline')
    until=args.absolute_until
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,interrupted)
    report={'schema':'heptabao.mac-guarded-current-capture-entry.wal-r1','stage':args.stage,
        'ok':False,'outcomeUnknown':False,'productionReadAttempted':False,
        'productionWriteAttempted':False,'captureLibraryReturned':False,
        'providerRequestSent':False,'j3160Contacted':False,
        'wholeDatabaseBackupQualified':False,'crossAgentAtomicSnapshotClaimed':False,
        'originalCaptureSeconds':45,'captureLibraryAttempted':False,
        'captureLibraryLedgerAvailable':False,'captureLibraryFailureLedgerAvailable':False}
    guard=None;commands=None;cap=None;wal=None;complete=False;capsule=None;native_api=None
    try:
        need(sys.platform=='darwin' and os.getuid()==501,'actual_mac_capture_owner')
        pins_raw=base64.b64decode(args.source_pins_base64,validate=True)
        need(len(pins_raw)<=8192 and sha(pins_raw)==args.source_pins_sha256,'exact_entry_source_pins')
        pins=json.loads(pins_raw)
        need(isinstance(pins,dict) and set(pins)==set(NAMES)
             and all(isinstance(v,str) and len(v)==64 and all(c in '0123456789abcdef' for c in v)
                     for v in pins.values()) and pins['mac_guarded_current_capture_r3.py']==CAPTURE_SOURCE_SHA,
             'fixed_public_capture_modules')
        need(pins.get('mac_registry_readonly_wal_r1.py')==WAL_BINDING['librarySha256'],
             'exact_qualified_registry_wal_library')
        need(all(pins.get(name)==pin for name,pin in NATIVE_BINDING['modulePins'].items()),
             'exact_qualified_native_capture_modules')
        source_ids={}
        for name,pin in pins.items():
            raw,source_ids[name]=source_bytes(QA/name);need(sha(raw)==pin,'capture_public_source_pin')
        sys.path.insert(0,str(QA))
        from mac_t5_volume_guard_r1 import HeldT5
        need(all(name[:-3] not in sys.modules for name in NATIVE_BINDING['modulePins']),
             'new_native_capture_modules_not_preloaded')
        from mac_darwin_owned_projection_r1 import NativeProjection
        from mac_native_owned_unreaped_r1 import bind_projection
        from mac_native_owned_commands_r1 import Commands
        import mac_guarded_current_capture_r3 as capture
        import mac_registry_readonly_wal_r1 as wal_capture
        cap=capture;wal=wal_capture
        class SignalState:
            @property
            def pending(self):return pending
            def critical(self):return critical()
        remaining()
        native_api=NativeProjection(until=until)
        report['nativeSelfBefore']=native_api.qualify_self(until=until)
        bind_projection(native_api)
        commands=Commands(SignalState())
        anchor=base64.b64decode(args.public_volume_anchor_base64,validate=True)
        guard=HeldT5(anchor,args.public_volume_anchor_sha256,remaining,critical)
        row,out,_=commands.run('capture-t5-volume',
            ['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
            until=min(until,time.monotonic()+30),maximum=262144)
        need(row['exitCode']==0 and not row['outcomeUnknown'] and row['completeBeforeDeadline'],
             'capture_volume_probe_complete')
        guard.accept_diskutil(out)
        native_raw=base64.b64decode(args.native_binding_base64,validate=True)
        need(len(native_raw)<=8192 and sha(native_raw)==args.native_binding_sha256,
             'actual_native_public_binding')
        _,native_proof=admitted_native(guard,json.loads(native_raw))
        need(native_api.public()['identity']==native_proof['nativeProjection']['identity'],
             'same_actual_native_abi_os_and_loaded_image_observations')
        report['nativePublicProofSha256']=NATIVE_BINDING['stdoutSha256']
        report['nativePublicAuthoritySha256']=NATIVE_BINDING['authoritySha256']
        report['nativePublicChildSha256']=NATIVE_BINDING['childStdoutSha256']
        report['actualNativeRuntimeCompatible']=True
        remaining()
        binding_raw=base64.b64decode(args.synthetic_binding_base64,validate=True)
        need(len(binding_raw)<=8192 and sha(binding_raw)==args.synthetic_binding_sha256,
             'actual_synthetic_public_binding')
        proof,proof_value=admitted_synthetic(guard,json.loads(binding_raw))
        wal_binding_raw=base64.b64decode(args.wal_binding_base64,validate=True)
        need(len(wal_binding_raw)<=8192 and sha(wal_binding_raw)==args.wal_binding_sha256,
             'actual_registry_wal_public_binding')
        wal_proof,wal_proof_value=admitted_wal(guard,json.loads(wal_binding_raw))
        need(wal_proof_value.get('runtime',{}).get('runtime')==proof_value['runtime'],
             'same_original_immutable_and_registry_wal_runtime')
        report['walSyntheticProofSha256']=WAL_BINDING['stdoutSha256']
        report['walSyntheticAuthoritySha256']=WAL_BINDING['authoritySha256']
        # Both original immutable predicates and the WAL runtime/source gate
        # execute with tracked public-code descriptors inside the one library
        # attempt, before it opens any current config or database.
        profile=guard.read(ROOT/'captures'/args.stage/'capture.sb',65536)
        need(profile==capture_profile(args.stage) and sha(profile)==args.sandbox_profile_sha256,
             'exact_reviewed_capture_sandbox')
        report['kernelSandboxProof']=kernel_refusals(guard,args.stage)
        remaining();guard.check()
        report['productionReadAttempted']=True
        report['captureLibraryAttempted']=True
        document,observation=wal.capture_current_with_wal(
            critical=critical,cancelled=lambda:pending is not None,
            synthetic_proof=proof,synthetic_proof_sha=sha(proof),
            wal_proof=wal_proof,wal_proof_sha=sha(wal_proof),until=until)
        report['captureLibraryReturned']=True
        report['observation']=capture_envelope(observation)
        report['captureLibraryLedgerAvailable']=True
        report['runtime']=document['runtime']
        need(document.get('walSyntheticProofSha256')==WAL_BINDING['stdoutSha256'],
             'private_capsule_actual_wal_proof_binding')
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
        report['nativeSelfAfter']=native_api.qualify_self(until=until)
        before_self=report['nativeSelfBefore']['first'];after_self=report['nativeSelfAfter']['last']
        need(all(before_self[key]==after_self[key] for key in
             ('pid','ppid','pgid','uid','birthSeconds','birthMicroseconds')),
             'same_current_capture_native_self_birth')
        guard.check();remaining();complete=True
    except BaseException as error:
        if wal is not None and isinstance(error,wal.CaptureAttemptFailure):
            try:
                report['observation']=capture_envelope(error.public)
                report['captureLibraryLedgerAvailable']=True
                report['captureLibraryFailureLedgerAvailable']=True
            except BaseException:
                report['captureLibraryLedgerAvailable']=False
                report['captureLibraryFailureLedgerAvailable']=False
        report['errorType']=type(error).__name__
        report['errorCode']=str(error) if isinstance(error,Refused) or (
            cap is not None and isinstance(error,cap.CaptureRefused)) else None
        observation=report.get('observation',{})
        report['outcomeUnknown']=bool(
            (report['captureLibraryAttempted'] and
             (not report['captureLibraryLedgerAvailable']
              or observation.get('observationUnknown') is not False
              or not library_resources_closed(observation)))
            or isinstance(error,KeyboardInterrupt))
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
        if native_api is not None:report['nativeProjection']=native_api.public()
        if guard is not None:
            guard.close();report['heldT5Final']=guard.public_state()
        closed=(all(row['closed'] for row in fds) and all(row['closed'] for row in sockets)
            and guard is not None and report['heldT5Final']['allDescriptorsClosed']
            and report['heldT5Final']['lastAnchorCheckPassed']
            and report['heldT5Final']['closeErrors']==[])
        stopped=(commands is not None and report['ownedCommands']['allOwnedCommandsStopped']
                 and report['ownedCommands']['unknownCommandCount']==0)
        library_closed=(not report['captureLibraryAttempted'] or
            (report['captureLibraryLedgerAvailable'] and library_resources_closed(report.get('observation'))))
        report['entryOwnedDescriptorsClosed']=closed
        report['allCaptureLibraryResourcesClosed']=library_closed
        report['allOwnedDescriptorsClosed']=bool(closed and library_closed)
        report['outcomeUnknown']=bool(report['outcomeUnknown'] or not closed or not library_closed
                                     or not stopped or pending is not None)
        done=time.monotonic()
        report['elapsedSeconds']=done-START
        report['originalAbsoluteDeadlineMonotonic']=until
        report['originalDeadlineMetAfterPrivatePublicationAndClosure']=done<until
        report['ok']=bool(complete and capsule is not None and closed and library_closed and stopped
                          and not report['outcomeUnknown'] and done<until)
        report['authoritativeExitZeroAndOriginalDeadlineRequired']=True
        raw=encoded(report);need(len(raw)<=262144,'public_capture_report_bound')
        sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
    return 0 if report['ok'] and time.monotonic()<until else 1

if __name__=='__main__':sys.exit(main())
