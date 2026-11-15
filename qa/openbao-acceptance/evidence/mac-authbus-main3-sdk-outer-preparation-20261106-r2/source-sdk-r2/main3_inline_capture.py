#!/usr/bin/env python3
"""One source-bound selected-owner capture child inside the API parent's budget.

The original child's retained wait and all of its owned children must be known
and closed before the resulting capsule can admit any service effect. A running
runtime job is never treated as a completed source capture.
"""
from __future__ import annotations
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time
from main3_source_authority import SDK_SOURCE_PINS

ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r2')
QA=ROOT/'qa'
PREP=Path('/Users/qianqi/heptabao-mac-authbus-main3-sdk-preparation-20261106-r2')
CAPSULE_ROOT=Path('/Users/qianqi/heptabao-authbus-main3-sdk-inline-capsule-20261106-r2')
CAPSULE=CAPSULE_ROOT/'output/selected-owner-credentials.private.json'
AUTHORITY=PREP/'inline-capture-authority.public.json'
RESULT=PREP/'inline-capture-result.public.json'
OPERATION_KEY='heptabao-mac-authbus-main3-sdk-inline-capture-20261106-r2'
PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
CAPTURE_WORKER_SHA='62ef0de48e311976ae78abf124a45792de01f784509a36a8f9c1fc686a9de2f2'
CAPTURE_LAUNCHER_SHA='6a456279bb01774d7f9b61ef4a6f04953bbfd9be6b374d0f715905e7d044ef5d'
CAPTURE_GUARD_SHA='f5fb13e04b394320a44b6687b474f06c0bb49b2ef1e194b956f528e454453d1f'
CAPTURE_REGISTRY_SHA='b26b8a99d01d5a51caa5a209594257fde2a8f2aa7a121fb23557802c6b086afc'
CAPTURE_PAYLOAD_SHA='effbfa4219f8a4582056cd1a02065c71121c20360a0010deda9f299d04b0eada'
CAPTURE_PRIOR_LAUNCHER_SHA='06bef1e6d68c2f9aa401639396c055f6c4d9694a2a14498193a5cad5e6b6cb88'
AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')

class CaptureRefused(RuntimeError):pass
def need(value,code):
    if not value:raise CaptureRefused(code)
def ident(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def sha(raw):return hashlib.sha256(raw).hexdigest()

def validate_command(row,parent_pid):
    need(isinstance(row,dict) and row.get('label')=='current-main3-inline-capture'
         and type(row.get('exitCode')) is int and row.get('exitCode')==0 and row.get('completeBeforeDeadline') is True
         and row.get('outcomeUnknown') is False and row.get('streamsClosed') is True
         and row.get('errorType') is None and row.get('errorCode') is None
         and row.get('stderrBytes')==0 and type(row.get('stdoutBytes')) is int
         and 0<row['stdoutBytes']<=65536,'capture_original_command_known_zero')
    argv=row.get('argv')
    need(isinstance(argv,list) and len(argv)==6
         and argv[:5]==[PYTHON,'-I','-S','-B',str(QA/'main3_capture_launcher.py')]
         and isinstance(argv[5],str),'capture_exact_child_argv')
    try:deadline=float(argv[5])
    except (TypeError,ValueError):raise CaptureRefused('capture_finite_child_deadline')
    need(math.isfinite(deadline) and deadline>0 and deadline==row.get('commandDeadlineMonotonic'),
         'capture_finite_child_deadline')
    pid=row.get('pid');cleanup=row.get('cleanup',{});custody=cleanup.get('custody',{});ps=custody.get('ps',{})
    need(type(pid) is int and pid>1 and type(parent_pid) is int and parent_pid>1
         and cleanup.get('ok') is True and cleanup.get('outcomeUnknown') is False
         and cleanup.get('directChildReaped') is True and cleanup.get('allGroupRowsEmptyAfterReap') is True
         and cleanup.get('ownedLiveGroupEmptyBeforeReap') is True
         and cleanup.get('remainingGroupRows')==[] and cleanup.get('signals')==[]
         and cleanup.get('postReapSignalSent') is False
         and cleanup.get('pid')==pid and cleanup.get('pgid')==pid
         and ps.get('pid')==pid and ps.get('ppid')==parent_pid and ps.get('pgid')==pid
         and ps.get('uid')==501 and custody.get('sid_observed_while_live')==pid,
         'capture_original_parent_unreaped_custody_closed')
    event=cleanup.get('retainedExit',{})
    need(event.get('pid')==pid and event.get('code')==1 and event.get('status')==0,
         'capture_original_retained_wait_zero')
    return pid

def validate_report(value,capture_pid):
    need(isinstance(value,dict) and value.get('schema')=='heptabao.current-sdk-selected-capsule-inline-owned-observation.sdk-r2'
         and value.get('ok') is True and value.get('childExitCode')==0 and value.get('stderrBytes')==0
         and value.get('sharedSeconds')==45 and value.get('parentCommandSeconds')==45
         and value.get('applicationRetries')==0 and value.get('serviceActions')==0,
         'capture_complete_source_report')
    for name in ('credentialValuesOrDigestsIncluded','rawClientConfigHashIncluded','profileIdsPublished',
                 'providerCalled','refreshDispatched','j3160Contacted','productionConfigurationChanged',
                 'productionDatabaseChanged','credentialExportedOffHost','productBinaryExecuted',
                 'providerValidityQualified','full9GenerationComparisonWeakened'):
        need(value.get(name) is False,'capture_no_provider_or_production_effect')
    for name in ('originalDeadlineAfterClosure','freshSourceGenerationCapture',
                 'currentConfigAndAllFiveSourceGenerationsStillExact','actualRegistryGenerationStillExact',
                 'closedSourceNamesAndAbsencesReverified','privateSelectedCredentialCapsuleQualified'):
        need(value.get(name) is True,'capture_original_generation_and_after_close_gate')
    need(value.get('workerSourceSha256')==CAPTURE_WORKER_SHA
         and value.get('guardSourceSha256')==CAPTURE_GUARD_SHA
         and value.get('registryReaderSourceSha256')==CAPTURE_REGISTRY_SHA
         and value.get('sdkPins')==SDK_SOURCE_PINS
         and value.get('privateSelectedCredentialCapsule')==str(CAPSULE)
         and value.get('registeredMetadataFilesVerified')==145,
         'capture_source_bound_worker_and_current_sdk')
    for name in ('sourceGuardClosure','registryGuardClosure'):
        closure=value.get(name,{})
        need(closure.get('closeErrors')==[] and all(closure.get(k) is True for k in
             ('allOwnedDescriptorsClosed','allHeldDescriptorsClosed','allReturnedConnectionsClosed',
              'allExplicitCursorsClosed','allPublicCodeDescriptorsClosed')),'capture_all_source_handles_closed')
    custody=value.get('custody',{})
    need(custody.get('passed_process_custody') is True and custody.get('finished') is True
         and custody.get('failed') is False and custody.get('interrupted') is False
         and custody.get('original_count')==3 and custody.get('controls')==[]
         and custody.get('platform')=='darwin' and custody.get('unreaped_original_is_signal_anchor') is True,
         'capture_all_three_inner_originals_known')
    children=custody.get('children')
    need(isinstance(children,list) and len(children)==3
         and len({c.get('pid') for c in children})==3,'capture_three_unique_originals')
    for child in children:
        pid=child.get('pid');birth=child.get('birth',{})
        need(type(pid) is int and pid>1 and child.get('exec_admitted') is True
             and child.get('original_wait_completed') is True and child.get('original_wait_count')==1
             and child.get('returncode')==0 and child.get('no_live_members_before_reap') is True
             and child.get('gaps')==[] and child.get('signals')==[]
             and birth.get('pid')==pid and birth.get('ppid')==capture_pid
             and birth.get('pgid')==pid and birth.get('sid')==pid and birth.get('uid')==501,
             'capture_each_original_child_wait_and_birth_closed')
    observed=value.get('observation',{})
    need(observed.get('ok') is True and observed.get('actualSdkOwnershipFunctionsExecuted') is True
         and observed.get('selectionOrderExecuted') is True and observed.get('actualSdkSelectedOwnerCount')==3
         and observed.get('effectiveProfileReferenceCount')==15 and observed.get('allSelectedOwnersAreMain') is True
         and observed.get('allEffectiveOwnersMatch') is True
         and observed.get('currentGenerationRecapturedAndSdkSelectionRevalidated') is True
         and observed.get('exactPreviousSdkSelectedAllowlistRetained') is True
         and observed.get('privateSelectedOwnerCredentialCount')==3
         and observed.get('privateSelectedCredentialCapsulePublished') is True
         and observed.get('sdkSourcePins')==SDK_SOURCE_PINS
         and observed.get('unexpectedJsMutationNetworkChildAttempts')==0
         and observed.get('unexpectedSqliteOpenAttempts')==0
         and observed.get('selectedOwnerAllowlistSyntheticCasesPassed')==12,
         'capture_actual_sdk_three_selected_current_owners')
    sql=observed.get('sqliteReadScope',{})
    need(sql.get('allReturnedHandlesClosedOnce') is True and type(sql.get('returnedHandleCount')) is int
         and sql['returnedHandleCount']>0 and sql.get('memoryOpenCount')==1
         and type(sql.get('readOnlyFileOpenCount')) is int
         and sql['returnedHandleCount']==sql['readOnlyFileOpenCount']+1,'capture_all_sqlite_handles_closed')
    agents=observed.get('agents')
    need(isinstance(agents,list) and tuple(x.get('agent') for x in agents)==AGENTS
         and all(x.get('allEffectiveOwnersMatch') is True and x.get('effectiveProfileCount')==3
                 and x.get('persistedOwnerMatchesEffectiveCount')==3
                 and x.get('selection',{}).get('actualSdkFunctionExecuted') is True
                 and x['selection'].get('sourceStoreObjectUnchanged') is True for x in agents),
         'capture_current_five_scope_owner_selection')

def validate_authority(value,*,parent_pid):
    need(isinstance(value,dict) and value.get('schema')=='heptabao.main3-inline-capture-authority.public.r5'
         and value.get('operationKey')==OPERATION_KEY and value.get('parentPid')==parent_pid
         and value.get('authorityKind')=='original_direct_child_wait_and_closed_owned_inner_children'
         and value.get('runtimeJobTerminalAssumed') is False and value.get('ok') is True
         and value.get('captureLauncherSourceSha256')==CAPTURE_LAUNCHER_SHA
         and value.get('capturePayloadSha256')==CAPTURE_PAYLOAD_SHA,
         'capture_exact_inline_authority_scope')
    pid=validate_command(value.get('command'),parent_pid)
    validate_report(value.get('result'),pid)
    return value

def new_public(path,raw,remaining):
    need(path in (AUTHORITY,RESULT) and isinstance(raw,bytes) and len(raw)<=131072,'capture_fixed_public_leaf')
    remaining();parent=os.open(PREP,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        p=os.fstat(parent)
        need(stat.S_ISDIR(p.st_mode) and p.st_uid==501 and stat.S_IMODE(p.st_mode)==0o700
             and ident(p)[:5]==ident(PREP.lstat())[:5],'capture_owned_public_parent')
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        try:
            before=os.fstat(fd);offset=0
            need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
                 and stat.S_IMODE(before.st_mode)==0o600,'capture_new_public_file_custody')
            while offset<len(raw):
                remaining();count=os.write(fd,raw[offset:]);need(count>0,'capture_public_write_progress');offset+=count
            os.fsync(fd);os.fsync(parent);after=os.fstat(fd)
            need(ident(before)[:6]==ident(after)[:6] and after.st_size==len(raw)
                 and ident(after)==ident(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),
                 'capture_public_file_durable_identity')
        finally:os.close(fd)
    finally:os.close(parent)
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}

def preflight_inputs(plan,read):
    need(plan['pythonRuntime']['path']==PYTHON,'capture_exact_python_runtime')
    raw=read(QA/'main3_capture_launcher.py')
    need(sha(raw)==CAPTURE_LAUNCHER_SHA,'capture_pinned_launcher_source')
    for path in (CAPSULE_ROOT,AUTHORITY,RESULT):
        try:path.lstat()
        except FileNotFoundError:continue
        raise CaptureRefused('capture_new_operation_paths_must_be_absent')
    return {'inlineCaptureRequiredBeforeAnyService':True,'captureMaximumSeconds':45,
            'sameParentOuterMaximumSeconds':600,'sourceGenerationAdmitted':False}

def run_capture(commands,plan,journal,until,remaining,read):
    preflight_inputs(plan,read);remaining();capture_until=min(until,time.monotonic()+45.0)
    argv=[PYTHON,'-I','-S','-B',str(QA/'main3_capture_launcher.py'),repr(capture_until)]
    journal.append('inline-capture-intent',{'operationKey':OPERATION_KEY,'argv':argv,
        'captureLauncherSourceSha256':CAPTURE_LAUNCHER_SHA,'captureWorkerSourceSha256':CAPTURE_WORKER_SHA,
        'captureMaximumSeconds':45,'sameParentOuterMaximumSeconds':600,'serviceEffectsPermitted':False})
    row,out,err=commands.run('current-main3-inline-capture',argv,until=capture_until,maximum=65536)
    # A malformed child output is not a public diagnostic or credential digest.
    # Commands returns this same public object in its ledger; remove both
    # diagnostic hashes before any journal/final public projection can see it.
    row.pop('stdoutSha256',None);row.pop('stderrSha256',None)
    journal.append('inline-capture-child-terminal',{'operationKey':OPERATION_KEY,'command':row,
        'rawDiagnosticsOrDigestsPublished':False})
    pid=validate_command(row,os.getpid())
    # Revalidate every public capture source after the original child has
    # retired, before its report can authorize the capsule. The caller's plan
    # already binds the same inventory before dispatch.
    capture_names=[name for name in plan['sourcePins'] if name.startswith('main3_capture_')]
    need(len(capture_names)==5,'capture_exact_launcher_and_four_payload_parts')
    for name in capture_names:
        remaining();source=read(QA/name)
        need(len(source)==plan['sourcePins'][name]['bytes']
             and sha(source)==plan['sourcePins'][name]['sha256'],'capture_public_sources_still_exact_after_original_wait')
    need(not err,'capture_no_stderr');value=json.loads(out);validate_report(value,pid)
    need(read(CAPSULE_ROOT/'result.public.json',65536)==out,'capture_original_result_exact_readback')
    authority={'schema':'heptabao.main3-inline-capture-authority.public.r5','ok':True,
        'operationKey':OPERATION_KEY,'parentPid':os.getpid(),
        'authorityKind':'original_direct_child_wait_and_closed_owned_inner_children',
        'runtimeJobTerminalAssumed':False,'captureLauncherSourceSha256':CAPTURE_LAUNCHER_SHA,
        'capturePayloadSha256':CAPTURE_PAYLOAD_SHA,'capturePriorLauncherSourceSha256':CAPTURE_PRIOR_LAUNCHER_SHA,
        'command':row,'result':value}
    validate_authority(authority,parent_pid=os.getpid());remaining()
    result_pin=new_public(RESULT,out,remaining)
    raw=(json.dumps(authority,sort_keys=True,separators=(',',':'))+'\n').encode()
    authority_pin=new_public(AUTHORITY,raw,remaining)
    need(read(RESULT,65536)==out and read(AUTHORITY,131072)==raw,'capture_public_authority_exact_readback')
    journal.append('inline-capture-admitted',{'operationKey':OPERATION_KEY,'capturePid':pid,
        'originalChildKnownZero':True,'ownedInnerChildrenClosed':3,
        'publicResult':result_pin,'publicAuthority':authority_pin,'serviceEffectsPermitted':False})
    return {'ok':True,'operationKey':OPERATION_KEY,'capturePid':pid,'publicResult':result_pin,
        'publicAuthority':authority_pin,'captureMaximumSeconds':45,'sameParentOuterMaximumSeconds':600,
        'originalChildKnownZero':True,'ownedInnerChildrenClosed':3,'providerValid':False,
        'sourceGenerationRequiresImmediateFull9Admission':True}
