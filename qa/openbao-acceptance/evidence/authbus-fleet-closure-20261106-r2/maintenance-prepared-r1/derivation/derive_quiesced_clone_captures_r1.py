#!/usr/bin/env python3
"""Derive three fixed fresh-clone capture children from the qualified SDK r4.

Local code generation only. This never reads a production configuration or DB,
starts a child, changes a ref, or dispatches provider/service operations.
"""
import ast
import base64
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'main3-sdk-outer-r4-work/source-sdk-r4'
DEST = HERE / 'clone-capture-prepared-r1'
MAINT = '/Users/qianqi/heptabao-authbus-writer-maintenance-20261106-r1'
OLD_ROOT = '/Users/qianqi/heptabao-authbus-main3-sdk-inline-capsule-20261106-r4'
LAUNCHER_SHA = '6fe72ce9fe547d1d1f2167a2231752959529358ed11bd3f81369527a489214ea'
WORKER_SHA = '130de20e8d76f68889ecd28925809b96667c5b7756cc34b1b23f934f4dc6b030'
WHOLE_SHA = '6a6a6630204687c56e12bc0e616e062b4e574c0665bb177d938409e739b30f4a'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def once(text, old, new):
    assert text.count(old) == 1, old[:100]
    return text.replace(old, new, 1)


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


launcher = (BASE / 'main3_capture_launcher.py').read_bytes()
assert sha(launcher) == LAUNCHER_SHA
inline_original = (BASE / 'main3_inline_capture.py').read_text()
source_fence_original = (BASE / 'main3_source_fence.py').read_text()
parts = []
for i in range(4):
    tree = ast.parse((BASE / ('main3_capture_payload_%d.py' % i)).read_bytes())
    parts.append(ast.literal_eval(tree.body[0].value))
original_payload_bytes = base64.b64decode(''.join(parts), validate=True)
assert sha(original_payload_bytes) == '39d3b111e31a96f6c8bede7940cb853c55c93732e778605bdabb59a059cdf6d4'
payload = json.loads(original_payload_bytes)
assert sha(payload['worker'].encode()) == WORKER_SHA
whole = (HERE.parent / 'mac-whole-sqlite-streaming-r1-work/whole_sqlite_streaming_r1.py').read_bytes()
assert sha(whole) == WHOLE_SHA
clone_reader = (HERE / 'mac_sdk_private_clone_reader_r1.mjs').read_text()
registry_bridge = (HERE / 'mac_poststop_registry_read_r1.py').read_text()
old_worker = payload['worker']
worker = once(old_worker,
    'import {protectReadPhase} from "./authbus_sdk_read_guard.mjs";',
    'import {protectReadPhase} from "./authbus_sdk_read_guard.mjs";\n'
    'import {bindFreshCloneReader} from "./mac_sdk_private_clone_reader_r1.mjs";')
worker = once(worker, 'const db=Reflect.construct(target,args,target),record=',
    'const physicalArgs=memory?args:[cloneReader.route(filename,options),options];\n'
    '    const db=Reflect.construct(target,physicalArgs,target),record=')
worker = once(worker, 'let restore=null,sqlGuard=null,privateMapping=null,privateCapsule=null,input=null;',
    'let restore=null,sqlGuard=null,cloneReader=null,privateMapping=null,privateCapsule=null,input=null;\n'
    'report.actualSdkLogicalPathsReadThroughFreshPrivateClone=false;\n'
    'report.productionGatewayConsumptionQualified=false;')
worker = once(worker,
    '  sqlGuard=installSqliteGuard(new Set(input.agents.map(x=>path.join(x.agentDir,"openclaw-agent.sqlite"))));',
    '  report.privateCloneReader={};\n'
    '  cloneReader=bindFreshCloneReader({root:ROOT,binding:input.cloneReadBinding,until},report.privateCloneReader);\n'
    '  for(const item of input.agents){\n'
    '    let denied=false;\n'
    '    try{const fd=fs.openSync(path.join(item.agentDir,"openclaw-agent.sqlite"),fs.constants.O_RDONLY);fs.closeSync(fd);}\n'
    '    catch(error){denied=["EPERM","EACCES"].includes(error.code);}\n'
    '    need(denied,"kernel_original_database_read_denied_for_clone_sdk");\n'
    '  }\n'
    '  report.originalFiveDatabaseKernelReadRefusalsObserved=true;\n'
    '  sqlGuard=installSqliteGuard(new Set(input.agents.map(x=>path.join(x.agentDir,"openclaw-agent.sqlite"))));')
worker = once(worker, '    sdkSourcePins:sourcePins,sourceSelectionAuthority:input.sourceSelectionAuthority,',
    '    sdkSourcePins:sourcePins,sourceSelectionAuthority:input.sourceSelectionAuthority,\n'
    '    sdkPhysicalReadProvenance:{schema:"heptabao.actual-sdk-fresh-clone-provenance.private.r1",\n'
    '      logicalAgentPathsUnchanged:true,directProductionDatabaseRead:false,\n'
    '      physicalSource:"fresh_double_sqlite_backup",binding:input.cloneReadBinding},')
worker = once(worker, '  report.previousFrozenGenerationPromotedToLatest=false;\n  sdk.t();\n',
    '  report.previousFrozenGenerationPromotedToLatest=false;\n  sdk.t();\n'
    '  cloneReader.verify();\n'
    '  need(report.privateCloneReader.cloneDatabaseConstructorsRouted>0\n'
    '    &&report.agents.length===5,"actual_five_sdk_scope_reads_used_fresh_clones");\n'
    '  report.actualSdkLogicalPathsReadThroughFreshPrivateClone=true;\n'
    '  cloneReader.close();\n')
worker = once(worker, '  report.jsGuardBlockedAttemptCount=diagnostics.blockedAttempts;',
    '  if(cloneReader){try{cloneReader.close();}catch{report.ok=false;report.cloneReaderCloseUnknown=true;}}\n'
    '  if(report.privateCloneReader?.allOriginalDescriptorsClosedOnce!==true)report.ok=false;\n'
    '  report.jsGuardBlockedAttemptCount=diagnostics.blockedAttempts;')
worker = once(worker,
    '  report.registryMetadata={mode:"actual_sdk_provided_index_from_current_readonly_wal",',
    '  report.registryMetadata={mode:"actual_sdk_provided_index_from_current_source_transaction",\n'
    '    sourceRoute:input.registryRoute,')

registry_child = payload['registryChild']
registry_child = once(registry_child, 'import authbus_current_auth_wal as auth\n',
    'import authbus_current_auth_wal as auth\n'
    'sys.path.insert(0,str(ROOT/"code"))\n'
    'import mac_poststop_registry_read_r1 as poststop_registry\n')
registry_child = once(registry_child,
    '    bundle=wal.registry_wal_database(inputs)\n    registry=wal.readonly_wal_query(inputs,bundle)',
    '    bundle=poststop_registry.registry_database(auth,inputs)\n'
    '    registry,registry_route=poststop_registry.read_registry(auth,inputs,bundle)')
registry_child = registry_child.replace('wal.verify_bundle(inputs,bundle,until=until)',
    'poststop_registry.verify(auth,inputs,bundle,until=until)')
registry_child = once(registry_child,
    '        registryTransactionCount=1,registryDataRowCount=1,registryWalWasNonempty=True,\n'
    '        registryRoute="qualified_named_readonly_wal_transaction",',
    '        registryTransactionCount=1,registryDataRowCount=1,registryWalWasNonempty=bundle["nonemptyWal"],\n'
    '        registryRoute=registry_route,originalRegistrySidecarsCreated=False,\n'
    '        registryBridgeSourceSha256='+repr(sha(registry_bridge.encode()))+',')

backup_block = '''        # Independent fresh source transaction for each registered agent DB.
        # This is source cloning, never a post-refresh production rollback.
        import types
        whole_module=types.ModuleType("main3_whole_clone_store")
        whole_module.__file__=str(ROOT/"code/whole_sqlite_streaming_r1.py")
        whole_raw=public_read(ROOT/"code/whole_sqlite_streaming_r1.py",65536)
        need(sha(whole_raw)=="WHOLE_PIN","same_qualified_whole_backup_source")
        exec(compile(whole_raw,whole_module.__file__,"exec"),whole_module.__dict__)
        clone_root=ROOT/"output/source-clones"
        clone_root.mkdir(mode=0o700,exist_ok=False)
        clone_parent_rows=[]
        def clone_identity(value):
            return tuple(str(getattr(value,key)) for key in
                ("st_dev","st_ino","st_uid","st_gid","st_mode","st_nlink","st_size","st_mtime_ns","st_ctime_ns"))
        def verify_clone_parents():
            for position,row in enumerate(clone_parent_rows):
                remaining()
                held=os.fstat(row["fd"])
                named=os.lstat("/") if position==0 else os.stat(row["path"].name,
                    dir_fd=clone_parent_rows[position-1]["fd"],follow_symlinks=False)
                width=5 if row["path"]==clone_root else 9
                need(clone_identity(held)[:width]==row["identity"][:width]
                     ==clone_identity(named)[:width],"fresh_clone_original_parent_held_and_named")
        def close_clone_parents():
            for row in reversed(clone_parent_rows):
                if row["closeAttempts"]:continue
                row["closeAttempts"]=1
                try:os.close(row["fd"]);row["closed"]=True
                except BaseException:row["closeError"]=True
            report["wholeCloneParentDescriptors"]={"opened":len(clone_parent_rows),
                "allOriginalClosedOnce":all(row["closed"] and row["closeAttempts"]==1 for row in clone_parent_rows),
                "mutableDirectoryCount":1,"mutableScope":"only_this_new_source_clones_directory"}
        whole_store=None
        clone_entries=[]
        try:
            for current in [*reversed(clone_root.parents),clone_root]:
                remaining()
                parent_fd=clone_parent_rows[-1]["fd"] if clone_parent_rows else None
                fd=os.open("/" if parent_fd is None else current.name,
                    os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                    **({} if parent_fd is None else {"dir_fd":parent_fd}))
                row={"path":current,"fd":fd,"closeAttempts":0,"closed":False}
                clone_parent_rows.append(row)
                info=os.fstat(fd);row["identity"]=clone_identity(info)
                need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0,501)
                     and not stat.S_IMODE(info.st_mode)&0o022,"fresh_clone_parent_custody")
                if current==ROOT or current.is_relative_to(ROOT):
                    need(info.st_uid==501 and stat.S_IMODE(info.st_mode)==0o700,
                         "fresh_clone_owned_directory_custody")
                verify_clone_parents()
            whole_store=whole_module.WholeStore(root=clone_root,source_root=LIVE,until=UNTIL,
                                              maximum=4294967296,source_vfs="unix-posix")
            expected_namespaces=[]
            total_maximum=0
            for agent in AGENTS:
                database=LIVE/"agents"/agent/"agent/openclaw-agent.sqlite"
                expected=whole_store.namespace(database)
                expected_namespaces.append(expected)
                total_maximum+=int(expected[""][6])+(0 if expected["-wal"] is None else int(expected["-wal"][6]))
            available=os.statvfs(clone_root)
            need(available.f_bavail*available.f_frsize>=2*total_maximum+256*1048576,
                 "fresh_five_double_clone_capacity_before_copy")
            for ordinal,agent in enumerate(AGENTS):
                remaining();source_fence();verify_clone_parents()
                database=LIVE/"agents"/agent/"agent/openclaw-agent.sqlite"
                snapshot=whole_store.capture(database,expected_namespaces[ordinal],slot=ordinal,phase="candidate")
                source_fence();verify_clone_parents()
                clone_entries.append({"ordinal":ordinal,"logicalPath":str(database),
                    "physicalPath":snapshot["archivePath"],"physicalFull9":snapshot["archiveFull9"],
                    "twoCompleteBackupOutputsEqual":snapshot["twoCompleteBackupOutputsEqual"],
                    "freshIndependentTransaction":snapshot["freshIndependentTransaction"],
                    "keeperUsedAsLatestSource":snapshot["keeperUsedAsLatestSource"],
                    "sourceContentCopyAuthority":snapshot["sourceContentCopyAuthority"]})
            for ordinal,agent in enumerate(AGENTS):
                need(whole_store.namespace(LIVE/"agents"/agent/"agent/openclaw-agent.sqlite")
                     ==expected_namespaces[ordinal],"all_five_sources_exact_after_double_clone")
        finally:
            try:
                if whole_store is not None:
                    whole_store.close()
                    report["wholeCloneResources"]=whole_store.public()
                verify_clone_parents()
            finally:close_clone_parents()
        need(report["wholeCloneParentDescriptors"]["allOriginalClosedOnce"],
             "fresh_clone_original_parent_descriptors_closed")
        clone_resources=report["wholeCloneResources"]
        need(all(clone_resources[name] for name in ("allFileDescriptorsClosedOnce","allSqliteHandlesClosedOnce",
                 "allExplicitCursorsClosed","allOriginalBackupsCompleted","allStreamOperationsCompleteAndClosed"))
             and clone_resources["backupCalls"]==10 and not clone_resources["restoreStarted"],
             "all_five_fresh_double_backup_original_handles_closed")
        private_input["cloneReadBinding"]={"schema":"heptabao.fresh-whole-clone-read.private.r1",
            "backupSourceSha256":"WHOLE_PIN","sourcePhase":"after_writer_quiescence","entries":clone_entries}
        report["freshDoubleWholeCloneSourceCount"]=5
        report["allFiveAgentDatabasePagesCopiedPrivatelyOnHost"]=True
        report["privateWholeClonesMayContainUnselectedApplicationData"]=True
        report["sourceGuardClosureProjectionScope"]="descriptor_closure_only"
        report["wholeCloneBackupSourceSha256"]="WHOLE_PIN"
        report["cloneReaderSourceSha256"]=sha(PAYLOAD["cloneReader"].encode())
        report["preRefreshCloneClaimedAsRollback"]=False
'''.replace('WHOLE_PIN', WHOLE_SHA)

modified_launcher = launcher.decode()
modified_launcher = once(modified_launcher, 'registry_guard=None;registry_bundle=None;metadata_files=[]',
    'registry_guard=None;registry_bundle=None;metadata_files=[];whole_store=None;registry_bridge=None')
modified_launcher = once(modified_launcher,
    '    private(ROOT/"code/registry_read.py",PAYLOAD["registryChild"])',
    '    private(ROOT/"code/registry_read.py",PAYLOAD["registryChild"])\n'
    '    private(ROOT/"code/mac_sdk_private_clone_reader_r1.mjs",PAYLOAD["cloneReader"])\n'
    '    private(ROOT/"code/whole_sqlite_streaming_r1.py",PAYLOAD["wholeStore"])\n'
    '    private(ROOT/"code/mac_poststop_registry_read_r1.py",PAYLOAD["registryBridge"])\n'
    '    import types\n'
    '    registry_bridge=types.ModuleType("main3_poststop_registry")\n'
    '    registry_bridge.__file__=str(ROOT/"code/mac_poststop_registry_read_r1.py")\n'
    '    bridge_raw=public_read(Path(registry_bridge.__file__),16384)\n'
    '    need(sha(bridge_raw)=='+repr(sha(registry_bridge.encode()))+',"same_poststop_registry_bridge")\n'
    '    exec(compile(bridge_raw,registry_bridge.__file__,"exec"),registry_bridge.__dict__)')
modified_launcher = once(modified_launcher,
    'registry_guard.verify();auth.wal.verify_bundle(registry_guard,registry_bundle,until=UNTIL)',
    'registry_guard.verify();registry_bridge.verify(auth,registry_guard,registry_bundle,until=UNTIL)')
modified_launcher = once(modified_launcher,
    '        registry_bundle=auth.wal.registry_wal_database(registry_guard)',
    '        registry_bundle=registry_bridge.registry_database(auth,registry_guard)')
modified_launcher = once(modified_launcher,
    '        private_input.update(registry=registry_packet["registry"],registryPluginCount=len(plugins),',
    '        private_input.update(registry=registry_packet["registry"],registryPluginCount=len(plugins),\n'
    '            registryRoute=registry_observation["registryRoute"],')
modified_launcher = once(modified_launcher,
    '            for agent in AGENTS:\n'
    '                database=LIVE/"agents"/agent/"agent/openclaw-agent.sqlite"\n'
    '                for suffix in ("","-wal","-shm","-journal"):\n'
    '                    candidate=Path(str(database)+suffix);paths.add(candidate);paths.update(candidate.parents)\n',
    '            # Actual SDK SQLite reads are redirected only to private whole clones.\n'
    '            # No file-read-data grant covers an original agent database.\n')
modified_launcher = once(modified_launcher,
    '        private(ROOT/"input.private.json",json.dumps(private_input,sort_keys=True).encode()+b"\\n")',
    backup_block+'        private(ROOT/"input.private.json",json.dumps(private_input,sort_keys=True).encode()+b"\\n")')
modified_launcher = once(modified_launcher,
    '    if source is not None:\n',
    '    if whole_store is not None:\n'
    '        try:whole_store.close()\n'
    '        except BaseException:report["ok"]=False;report["wholeCloneCloseUnknown"]=True\n'
    '        report["wholeCloneResources"]=whole_store.public()\n'
    '    if source is not None:\n')
modified_launcher = once(modified_launcher,
    '         and public_read(ROOT/"code/authbus_sdk_read_guard.mjs")==PAYLOAD["guard"].encode(),"same_sdk_read_guard_sources_after")',
    '         and public_read(ROOT/"code/authbus_sdk_read_guard.mjs")==PAYLOAD["guard"].encode()\n'
    '         and public_read(ROOT/"code/mac_sdk_private_clone_reader_r1.mjs")==PAYLOAD["cloneReader"].encode()\n'
    '         and public_read(ROOT/"code/mac_poststop_registry_read_r1.py")==PAYLOAD["registryBridge"].encode()\n'
    '         and sha(public_read(ROOT/"code/whole_sqlite_streaming_r1.py",65536))=="'+WHOLE_SHA+'",\n'
    '         "same_sdk_read_guard_sources_after")')
modified_launcher = once(modified_launcher,
    'sourceCaptureReason="prior_capsule_registry_full9_changed"',
    'sourceCaptureReason="fresh_registered_owner_source_after_actual_writer_quiescence"')
modified_launcher = once(modified_launcher,
    '        source.close();report["sourceGuardClosure"]=source.public()',
    '        source.close()\n'
    '        sp=source.public()\n'
    '        report["sourceGuardClosure"]={key:sp[key] for key in\n'
    '            ("allOwnedDescriptorsClosed","allHeldDescriptorsClosed","allReturnedConnectionsClosed",\n'
    '             "allExplicitCursorsClosed","allPublicCodeDescriptorsClosed","closeErrors")}')

clone_report_gate = '''    need(value.get('freshDoubleWholeCloneSourceCount')==5
         and value.get('allFiveAgentDatabasePagesCopiedPrivatelyOnHost') is True
         and value.get('privateWholeClonesMayContainUnselectedApplicationData') is True
         and value.get('sourceGuardClosureProjectionScope')=='descriptor_closure_only'
         and value.get('wholeCloneBackupSourceSha256')==WHOLE_BACKUP_SHA
         and value.get('cloneReaderSourceSha256')==CLONE_READER_SHA
         and value.get('preRefreshCloneClaimedAsRollback') is False,
         'capture_five_fresh_whole_clones_not_rollback')
    backup=value.get('wholeCloneResources',{})
    need(backup.get('backupCalls')==10 and backup.get('restoreStarted') is False
         and backup.get('databaseSerializeCalls')==0 and backup.get('closeErrors')==[]
         and all(backup.get(name) is True for name in
             ('allFileDescriptorsClosedOnce','allSqliteHandlesClosedOnce','allExplicitCursorsClosed',
              'allOriginalBackupsCompleted','allStreamOperationsCompleteAndClosed')),
         'capture_all_ten_original_backup_calls_known_and_closed')
    clone_parents=value.get('wholeCloneParentDescriptors',{})
    need(type(clone_parents.get('opened')) is int and clone_parents['opened']>=8
         and clone_parents.get('allOriginalClosedOnce') is True
         and clone_parents.get('mutableDirectoryCount')==1
         and clone_parents.get('mutableScope')=='only_this_new_source_clones_directory',
         'capture_original_clone_output_parent_custody_closed')
    clone=observed.get('privateCloneReader',{})
    need(observed.get('originalFiveDatabaseKernelReadRefusalsObserved') is True
         and observed.get('actualSdkLogicalPathsReadThroughFreshPrivateClone') is True
         and observed.get('productionGatewayConsumptionQualified') is False
         and clone.get('schema')=='heptabao.actual-sdk-private-clone-reader.public.r1'
         and clone.get('fixedLogicalSourceCount')==clone.get('physicalWholeCloneCount')==5
         and clone.get('originalSdkLogicalPathsPreserved') is True
         and clone.get('originalSdkReadonlyOptionPreserved') is True
         and clone.get('sourceDatabaseConstructorsDispatched')==0
         and clone.get('cloneDatabaseConstructorsRouted')==sql['readOnlyFileOpenCount']
         and clone.get('physicalReadBoundByOriginalFull9') is True
         and clone.get('productionGatewayConsumptionProven') is False
         and clone.get('credentialOrPrivateConfigurationDigestsPublished') is False
         and type(clone.get('descriptorsOpened')) is int and clone['descriptorsOpened']>5
         and clone.get('closeAttempts')==clone.get('descriptorsClosed')==clone['descriptorsOpened']
         and clone.get('allOriginalDescriptorsClosedOnce') is True,
         'capture_actual_sdk_only_exact_five_physical_clones_all_descriptors_closed')
    registry=value.get('registryObservation',{})
    need(registry.get('ok') is True and registry.get('registryTransactionCount')==1
         and registry.get('registryDataRowCount')==1 and registry.get('queryBudgetSeconds')==3
         and type(registry.get('registryWalWasNonempty')) is bool
         and registry.get('registryRoute')==('qualified_named_readonly_wal_transaction'
             if registry['registryWalWasNonempty'] else 'tracked_held_fd_immutable_registry_transaction')
         and registry.get('originalRegistrySidecarsCreated') is False
         and registry.get('registryBridgeSourceSha256')==REGISTRY_BRIDGE_SHA
         and observed.get('registryMetadata',{}).get('sourceRoute')==registry['registryRoute'],
         'capture_exact_poststop_registry_route_fixed_one_row')
'''

manifest = {'schema': 'heptabao.quiesced-clone-capture-derivation.public.r1', 'preparedOnly': True,
    'originalLauncher': pin(launcher), 'originalPayload': pin(original_payload_bytes),
    'originalWorker': pin(old_worker.encode()), 'wholeBackupSource': pin(whole),
    'cloneAdapterSource': pin(clone_reader.encode()), 'registryBridgeSource':pin(registry_bridge.encode()),
    'owners': [],
    'actualMacQualified': False, 'providerRequests': 0, 'serviceActions': 0}
DEST.mkdir(exist_ok=True)
(DEST / 'worker-original-reference.mjs').write_text(old_worker)
for ordinal in range(1, 4):
    capture_root = MAINT + '/captures/owner-0%d' % ordinal
    stage_root = MAINT + '/code/owner-0%d' % ordinal
    directory = DEST / ('owner-0%d' % ordinal)
    directory.mkdir(exist_ok=True)
    derived_payload = dict(payload)
    derived_payload.update(worker=worker.replace(OLD_ROOT, capture_root),
        registryChild=registry_child.replace(OLD_ROOT, capture_root),
        wholeStore=whole.decode(), cloneReader=clone_reader,registryBridge=registry_bridge)
    raw_payload = json.dumps(derived_payload, ensure_ascii=False, separators=(',', ':')).encode()
    assert len(raw_payload) <= 262144
    text = base64.b64encode(raw_payload).decode()
    derived_parts = {}
    for i, begin in enumerate(range(0, len(text), 60000)):
        name = 'main3_capture_payload_%d.py' % i
        raw = ('DATA=' + repr(text[begin:begin+60000]) + '\n').encode()
        (directory / name).write_bytes(raw)
        derived_parts[name] = pin(raw)
    source = modified_launcher.replace(OLD_ROOT, capture_root)
    source = once(source, "CAPTURE_QA=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r4/qa')",
                  'CAPTURE_QA=Path('+repr(stage_root)+')')
    old_parts_line = next(line for line in source.splitlines() if line.startswith('PAYLOAD_PART_PINS='))
    source = once(source, old_parts_line, 'PAYLOAD_PART_PINS='+repr(derived_parts))
    source = once(source, '39d3b111e31a96f6c8bede7940cb853c55c93732e778605bdabb59a059cdf6d4', sha(raw_payload))
    source = source.replace('heptabao.current-sdk-selected-capsule-inline-owned-observation.sdk-r4',
                            'heptabao.current-sdk-selected-capsule-inline-owned-observation.clone-r1')
    compile(source, str(directory / 'main3_capture_launcher.py'), 'exec')
    (directory / 'main3_capture_launcher.py').write_text(source)
    (directory / 'owner_read.mjs').write_text(derived_payload['worker'])
    (directory / 'registry_read.py').write_text(derived_payload['registryChild'])
    sources = {**derived_parts, 'main3_capture_launcher.py': pin(source.encode())}
    inline = inline_original
    inline = once(inline,
        "ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r4')\nQA=ROOT/'qa'\nPREP=Path('/Users/qianqi/heptabao-mac-authbus-main3-sdk-preparation-20261106-r4')",
        'ROOT=Path('+repr(MAINT)+')\nQA=Path('+repr(stage_root)+")\nPREP=ROOT/'output'")
    inline = inline.replace(OLD_ROOT,capture_root)
    inline = once(inline,"AUTHORITY=PREP/'inline-capture-authority.public.json'",
        "AUTHORITY=PREP/'owner-0%d.inline-capture-authority.public.json'"%ordinal)
    inline = once(inline,"RESULT=PREP/'inline-capture-result.public.json'",
        "RESULT=PREP/'owner-0%d.inline-capture-result.public.json'"%ordinal)
    inline = once(inline,"OPERATION_KEY='heptabao-mac-authbus-main3-sdk-inline-capture-20261106-r4'",
        "OPERATION_KEY='heptabao-mac-authbus-writer-maintenance-owner-0%d-capture-20261106-r1'"%ordinal)
    for old,new in ((WORKER_SHA,sha(derived_payload['worker'].encode())),
        (LAUNCHER_SHA,sha(source.encode())),
        ('bbf04b5a60edd4e4213d9df60aee3cf6338683f553b534cdea449da350b95c3b',sha(derived_payload['registryChild'].encode())),
        ('39d3b111e31a96f6c8bede7940cb853c55c93732e778605bdabb59a059cdf6d4',sha(raw_payload))):
        inline=once(inline,old,new)
    inline = once(inline,"AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')",
        "AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')\n"
        +"WHOLE_BACKUP_SHA="+repr(WHOLE_SHA)+"\nCLONE_READER_SHA="+repr(sha(clone_reader.encode()))
        +"\nREGISTRY_BRIDGE_SHA="+repr(sha(registry_bridge.encode()))
        +"\nCAPTURE_SOURCE_PINS="+repr(sources))
    inline=once(inline,'06bef1e6d68c2f9aa401639396c055f6c4d9694a2a14498193a5cad5e6b6cb88',LAUNCHER_SHA)
    inline=inline.replace('heptabao.current-sdk-selected-capsule-inline-owned-observation.sdk-r4',
        'heptabao.current-sdk-selected-capsule-inline-owned-observation.clone-r1')
    inline=once(inline,"    agents=observed.get('agents')\n",clone_report_gate+"    agents=observed.get('agents')\n")
    inline=once(inline,"    return {'inlineCaptureRequiredBeforeAnyService':True,'captureMaximumSeconds':45,",
        "    return {'freshCaptureRequiredAfterWriterQuiescence':True,'captureMaximumSeconds':45,")
    inline=once(inline,'def run_capture(commands,plan,journal,until,remaining,read):\n',
        'def run_capture(commands,plan,journal,until,remaining,read,quiescence_fence):\n'
        "    need(callable(quiescence_fence) and quiescence_fence('before-fresh-owner-capture') is True,\n"
        "         'capture_parent_actual_writer_quiescence_before')\n")
    inline=once(inline,"    need(len(capture_names)==5,'capture_exact_launcher_and_four_payload_parts')",
        "    need({name:plan['sourcePins'][name] for name in capture_names}==CAPTURE_SOURCE_PINS,\n"
        "         'capture_exact_launcher_and_all_derived_payload_parts')")
    inline=once(inline,"    need(not err,'capture_no_stderr');value=json.loads(out);validate_report(value,pid)",
        "    need(quiescence_fence('after-fresh-owner-capture') is True,\n"
        "         'capture_parent_actual_writer_quiescence_after')\n"
        "    need(not err,'capture_no_stderr');value=json.loads(out);validate_report(value,pid)")
    inline=once(inline,"        'runtimeJobTerminalAssumed':False,'captureLauncherSourceSha256':CAPTURE_LAUNCHER_SHA,",
        "        'runtimeJobTerminalAssumed':False,'parentObservedWriterQuiescenceBeforeAndAfterCapture':True,\n"
        "        'captureLauncherSourceSha256':CAPTURE_LAUNCHER_SHA,")
    compile(inline,str(directory/'main3_inline_capture.py'),'exec')
    (directory/'main3_inline_capture.py').write_text(inline)
    fence=source_fence_original.replace(OLD_ROOT,capture_root)
    fence=once(fence,
        'from main3_inline_capture import AUTHORITY,OPERATION_KEY,CAPTURE_WORKER_SHA,validate_authority as validate_inline_authority',
        'from mac_maintenance_capture_owner_0%d_inline import AUTHORITY,OPERATION_KEY,CAPTURE_WORKER_SHA,validate_authority as validate_inline_authority'%ordinal)
    fence=once(fence,"PREP=Path('/Users/qianqi/heptabao-mac-authbus-main3-sdk-preparation-20261106-r4')",
        'PREP=Path('+repr(MAINT+'/output')+')')
    fence=once(fence,"BINDING=PREP/'capsule-admission-binding.private.json'",
        "BINDING=PREP/'owner-0%d.capsule-admission-binding.private.json'"%ordinal)
    fence=once(fence,"        metadata=doc.get('registeredMetadataFileBindings')\n",
        "        clone=doc.get('sdkPhysicalReadProvenance',{})\n"
        "        need(clone.get('schema')=='heptabao.actual-sdk-fresh-clone-provenance.private.r1'\n"
        "             and clone.get('logicalAgentPathsUnchanged') is True\n"
        "             and clone.get('directProductionDatabaseRead') is False\n"
        "             and clone.get('physicalSource')=='fresh_double_sqlite_backup',\n"
        "             'source_fence_actual_sdk_physical_clone_provenance')\n"
        "        mapping=clone.get('binding',{})\n"
        "        need(mapping.get('schema')=='heptabao.fresh-whole-clone-read.private.r1'\n"
        "             and mapping.get('backupSourceSha256')=="+repr(WHOLE_SHA)+"\n"
        "             and mapping.get('sourcePhase')=='after_writer_quiescence'\n"
        "             and isinstance(mapping.get('entries'),list) and len(mapping['entries'])==5,\n"
        "             'source_fence_same_original_double_backup_mapping')\n"
        "        for ordinal,entry in enumerate(mapping['entries']):\n"
        "            need(type(entry.get('ordinal')) is int and entry['ordinal']==ordinal\n"
        "                 and entry.get('logicalPath')==str(LIVE/'agents'/AGENTS[ordinal]/'agent/openclaw-agent.sqlite')\n"
        "                 and entry.get('physicalPath')==str(CAPSULE_ROOT/'output/source-clones'/('candidate-%d.sqlite'%ordinal))\n"
        "                 and entry.get('twoCompleteBackupOutputsEqual') is True\n"
        "                 and entry.get('freshIndependentTransaction') is True\n"
        "                 and entry.get('keeperUsedAsLatestSource') is False\n"
        "                 and entry.get('sourceContentCopyAuthority')=='sqlite_online_backup_api',\n"
        "                 'source_fence_exact_five_logical_physical_slots')\n"
        "            typed_identity(entry.get('physicalFull9'))\n"
        "        metadata=doc.get('registeredMetadataFileBindings')\n")
    fence=once(fence,"        d=self.doc;identities=0;absences=0\n",
        "        d=self.doc;identities=0;absences=0\n"
        "        for entry in d['sdkPhysicalReadProvenance']['binding']['entries']:\n"
        "            current=Path(entry['physicalPath']).lstat()\n"
        "            need(stat.S_ISREG(current.st_mode) and current.st_uid==501 and current.st_gid==20\n"
        "                 and stat.S_IMODE(current.st_mode)==0o600 and current.st_nlink==1\n"
        "                 and ident(current)==typed_identity(entry['physicalFull9']),\n"
        "                 'source_fence_original_readonly_clone_full9_still_exact')\n")
    compile(fence,str(directory/'main3_source_fence.py'),'exec')
    (directory/'main3_source_fence.py').write_text(fence)
    manifest['owners'].append({'ordinal': ordinal-1, 'captureRoot': capture_root, 'stageRoot': stage_root,
        'sourcePins': sources, 'payloadPin': pin(raw_payload),
        'inlineAdapterPin':pin(inline.encode()),
        'sourceFencePin':pin(fence.encode()),
        'workerPin': pin(derived_payload['worker'].encode()),
        'registryReaderPin': pin(derived_payload['registryChild'].encode())})
    if ordinal == 1:
        (DEST/'launcher-r4-to-clone-r1.diff').write_text(''.join(difflib.unified_diff(
            launcher.decode().splitlines(keepends=True),source.splitlines(keepends=True),
            fromfile='qualified-sdk-r4/main3_capture_launcher.py',tofile='prepared-clone-r1/main3_capture_launcher.py')))
        (DEST/'worker-r4-to-clone-r1.diff').write_text(''.join(difflib.unified_diff(
            old_worker.splitlines(keepends=True),derived_payload['worker'].splitlines(keepends=True),
            fromfile='qualified-sdk-r4/owner_read.mjs',tofile='prepared-clone-r1/owner_read.mjs')))
        (DEST/'inline-r4-to-clone-r1.diff').write_text(''.join(difflib.unified_diff(
            inline_original.splitlines(keepends=True),inline.splitlines(keepends=True),
            fromfile='qualified-sdk-r4/main3_inline_capture.py',tofile='prepared-clone-r1/main3_inline_capture.py')))
        (DEST/'fence-r4-to-clone-r1.diff').write_text(''.join(difflib.unified_diff(
            source_fence_original.splitlines(keepends=True),fence.splitlines(keepends=True),
            fromfile='qualified-sdk-r4/main3_source_fence.py',tofile='prepared-clone-r1/main3_source_fence.py')))
        (DEST/'registry-r4-to-clone-r1.diff').write_text(''.join(difflib.unified_diff(
            payload['registryChild'].splitlines(keepends=True),derived_payload['registryChild'].splitlines(keepends=True),
            fromfile='qualified-sdk-r4/registry_read.py',tofile='prepared-clone-r1/registry_read.py')))
(DEST/'derivation.public.json').write_text(json.dumps(manifest,indent=2)+'\n')
(HERE/'mac_refresh_capture_authority_r1.py').write_text(
    '# Generated by derive_quiesced_clone_captures_r1.py; public code pins only.\n'
    'OWNER_CAPTURES = '+repr(manifest['owners'])+'\n'
    'QUALIFIED_WHOLE_BACKUP_SHA256 = '+repr(WHOLE_SHA)+'\n')
print(json.dumps({'ok':True,'preparedOwners':3,'payloadPartsPerOwner':len(derived_parts),
                  'actualMacQualified':False,'manifest':str(DEST/'derivation.public.json')},separators=(',',':')))
