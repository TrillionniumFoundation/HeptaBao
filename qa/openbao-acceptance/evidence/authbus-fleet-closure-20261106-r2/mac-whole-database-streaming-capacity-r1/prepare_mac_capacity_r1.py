#!/usr/bin/env python3
"""Freeze the separate measured-largest-database capacity campaign; do not run it."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SMALL = HERE.parent / "mac-whole-sqlite-streaming-r1-work"
HELPERS = HERE.parent / "main3-sdk-outer-r4-work/source-sdk-r4"
OLD_ROOT = "heptabao-authbus-whole-database-streaming-small-20261106-r1"
NEW_ROOT = "heptabao-authbus-whole-database-streaming-capacity-20261106-r1"
MINIMUM_PRIMARY_BYTES = 2469126144
MAXIMUM_PRIMARY_BYTES = MINIMUM_PRIMARY_BYTES + 32 * 1048576
MINIMUM_FREE_DISK_BYTES = 8 * MAXIMUM_PRIMARY_BYTES + 6 * 1073741824
MINIMUM_FREE_MEMORY_BYTES = 1073741824
CORE_SHA = "6a6a6630204687c56e12bc0e616e062b4e574c0665bb177d938409e739b30f4a"
HELPER_PINS = {
    "mac_owned_commands_r1.py": "71a11bf9a0510c991b78c9bc3f094f315bf4914485b9cfda81c6e501eaf73530",
    "mac_owned_unreaped_r1.py": "d735a9e9330e1260d44ad9e4c854d50094e20d85fe5633ddd9042281b3346298",
    "mac_native_process_observer_r1.py": "cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def once(source, old, new):
    assert source.count(old) == 1, (old, source.count(old))
    return source.replace(old, new)


def assignment(source, name):
    nodes = [node.value for node in ast.parse(source).body if isinstance(node, ast.Assign)
             and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    assert len(nodes) == 1, name
    return ast.literal_eval(nodes[0])


core = (HERE / "whole_sqlite_streaming_r1.py").read_bytes()
assert sha(core) == CORE_SHA == sha((SMALL / "whole_sqlite_streaming_r1.py").read_bytes())
worker = (SMALL / "mac_whole_sqlite_streaming_worker_r1.py").read_text()
worker = worker.replace(OLD_ROOT, NEW_ROOT)
worker = worker.replace("qualify_whole_sqlite_streaming_r1", "qualify_whole_sqlite_capacity_r1")
worker = worker.replace("mac_whole_sqlite_streaming_worker_r1", "mac_whole_sqlite_capacity_worker_r1")
worker = once(worker, "from qualify_whole_sqlite_capacity_r1 import run_qualification, run_snapshot_mechanism",
              "from qualify_whole_sqlite_capacity_r1 import run_capacity_qualification")
worker = worker.replace("qualification-worker.streaming.r1", "qualification-worker.capacity.r1")
worker = worker.replace("whole-sqlite-plan.streaming.r1", "whole-sqlite-plan.capacity.r1")
worker = once(worker, "START < UNTIL <= START + 30", "START < UNTIL <= START + 540")
worker = once(worker, 'and plan["sourceVfs"] == "unix-posix" and plan["maximumDatabaseBytes"] == 4294967296,',
              'and plan["sourceVfs"] == "unix-posix" and plan["maximumDatabaseBytes"] == 4294967296\n'
              '         and plan["minimumPrimaryBytes"] == 2469126144\n'
              '         and plan["maximumPrimaryBytes"] == 2502680576\n'
              '         and plan["workerSeconds"] == 540 and plan["sharedSeconds"] == 600,')
worker = once(worker, 'result = run_qualification(ROOT / "output/fixture",',
              'result = run_capacity_qualification(ROOT / "output/fixture",')
before = '''    mechanism = run_snapshot_mechanism(ROOT / "output/snapshot-mechanism", until=UNTIL,
                                       source_vfs="unix-posix")
    report["snapshotMechanism"] = mechanism
    need(mechanism["ok"] and len(mechanism["cases"]) == 5,
         "whole_streaming_snapshot_mechanism_complete")
'''
after = '''    need(len(result["cases"]) == 17 and all(item["passed"] is True for item in result["cases"])
         and result["capacity"]["minimumRequiredBytes"] == plan["minimumPrimaryBytes"]
         and plan["minimumPrimaryBytes"] <= result["capacity"]["logicalBytes"] <= plan["maximumPrimaryBytes"]
         and result["capacity"]["allRestoredPayloadRowsComparedToOriginalSyntheticInput"] is True,
         "complete_actual_largest_database_capacity_lifecycle")
    report["capacityScope"] = "largest_current_database_plus_six_database_lifecycle"
    report["allCurrentSixDatabaseSizesReproduced"] = False
    report["rssThresholdIsPostRunAcceptanceNotOsEnforcedLimit"] = True
'''
worker = once(worker, before, after)
worker_name = "mac_whole_sqlite_capacity_worker_r1.py"
compile(worker, worker_name, "exec")
(HERE / worker_name).write_text(worker)

template = (SMALL / "launch_mac_whole_sqlite_streaming_small_r1.template.py").read_text()
template = template.replace(OLD_ROOT, NEW_ROOT)
template = template.replace("qualify_whole_sqlite_streaming_r1", "qualify_whole_sqlite_capacity_r1")
template = template.replace("mac_whole_sqlite_streaming_worker_r1", "mac_whole_sqlite_capacity_worker_r1")
template = template.replace("qualification-launch.streaming.r1", "qualification-launch.capacity.r1")
template = template.replace("whole-sqlite-plan.streaming.r1", "whole-sqlite-plan.capacity.r1")
template = once(template, "START=time.monotonic();UNTIL=START+45", "START=time.monotonic();UNTIL=START+600")
template = once(template, "codes=set();fds=[];owner=None;child=None;created=False",
                "codes=set();fds=[];owner=None;child=None;commands=None;created=False")
template = template.replace("'sharedSeconds':45,'workerSeconds':30", "'sharedSeconds':600,'workerSeconds':540")
template = template.replace("'supervisorSeconds':70", "'supervisorSeconds':630")
template = once(template, "def remaining(cap=45):", "def remaining(cap=600):")
template = once(template, "'/usr/bin/sandbox-exec':'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a'}",
    "'/usr/bin/sandbox-exec':'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a',\n"
    " '/usr/bin/vm_stat':'0127fec1de1d99c7f0b0cf185fec048c7fe92d1f1b2ad380882c583f0c921df7',\n"
    " '/bin/ps':'3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c'}\n"
    "VM_STAT='/usr/bin/vm_stat'\nMINIMUM_PRIMARY_BYTES=2469126144\nMAXIMUM_PRIMARY_BYTES=2502680576\n"
    "MINIMUM_FREE_DISK_BYTES=26463895552\nMINIMUM_FREE_MEMORY_BYTES=1073741824")
assert MINIMUM_FREE_DISK_BYTES == 26463895552
template = once(template, "need(set(PAYLOAD['sources'])=={'whole_sqlite_streaming_r1.py','qualify_whole_sqlite_capacity_r1.py','mac_whole_sqlite_capacity_worker_r1.py'},'three_exact_whole_modules')",
    "need(set(PAYLOAD['sources'])=={'whole_sqlite_streaming_r1.py','qualify_whole_sqlite_capacity_r1.py','mac_whole_sqlite_capacity_worker_r1.py',\n"
    "  'mac_owned_commands_r1.py','mac_owned_unreaped_r1.py','mac_native_process_observer_r1.py'},'six_exact_whole_and_command_modules')")
template = once(template, "'sourcePins':PAYLOAD['sourcePins'],'schemaPins':PAYLOAD['schemaPins'],'installedSchemaSourcePins':PAYLOAD['installedSchemaSourcePins'],",
    "'sourcePins':PAYLOAD['workerSourcePins'],'helperSourcePins':PAYLOAD['helperSourcePins'],\n"
    "  'schemaPins':PAYLOAD['schemaPins'],'installedSchemaSourcePins':PAYLOAD['installedSchemaSourcePins'],\n"
    "  'minimumPrimaryBytes':MINIMUM_PRIMARY_BYTES,'maximumPrimaryBytes':MAXIMUM_PRIMARY_BYTES,\n"
    "  'minimumFreeDiskBytes':MINIMUM_FREE_DISK_BYTES,'minimumFreeMemoryBytes':MINIMUM_FREE_MEMORY_BYTES,")
template = once(template, "sys.path.insert(0,str(QUAL/'qa'));import kv2_dr_process_custody as custody",
    "sys.path[:0]=[str(ROOT/'code'),str(QUAL/'qa')]\n"
    " from mac_owned_commands_r1 import Commands,Signals\n"
    " import mac_owned_commands_r1,mac_owned_unreaped_r1,mac_native_process_observer_r1\n"
    " for module in (mac_owned_commands_r1,mac_owned_unreaped_r1,mac_native_process_observer_r1):\n"
    "  need(Path(module.__file__).resolve()==ROOT/'code'/(module.__name__+'.py'),'exact_staged_command_module_import')\n"
    " signals=Signals();signals.install();commands=Commands(signals)\n"
    " report['resourceAdmission']=resource_admission()\n"
    " public_fence();own_fence();remaining()\n"
    " import kv2_dr_process_custody as custody")
template = template.replace("remaining(30)", "remaining(540)")
template = once(template, "len(qualified['cases'])==14", "len(qualified['cases'])==17")
template = once(template, '''   and value['snapshotMechanism']['ok'] and len(value['snapshotMechanism']['cases'])==5
   and all(value['snapshotMechanism']['resources'][k] for k in ('allFileDescriptorsClosedOnce',
    'allSqliteHandlesClosedOnce','allExplicitCursorsClosed'))
''', '''   and all(item['passed'] is True for item in qualified['cases'])
   and MINIMUM_PRIMARY_BYTES<=qualified['capacity']['logicalBytes']<=MAXIMUM_PRIMARY_BYTES
   and qualified['capacity']['minimumRequiredBytes']==MINIMUM_PRIMARY_BYTES
   and qualified['capacity']['allRestoredPayloadRowsComparedToOriginalSyntheticInput'] is True
''')
template = once(template, "report.update(ok=True,allOriginalSourcePinsUnchanged=True,createdOnlyNewSyntheticRoot=True)",
    "report.update(ok=True,allOriginalSourcePinsUnchanged=True,createdOnlyNewSyntheticRoot=True,\n"
    "  largeDatabaseCapacityQualified=True,capacityScope='largest_current_database_plus_six_database_lifecycle',\n"
    "  allCurrentSixDatabaseSizesReproduced=False,productionDiskBudgetAdmitted=False,\n"
    "  rssThresholdIsPostRunAcceptanceNotOsEnforcedLimit=True)\n"
    " report['diskAfterQualification']=disk_observation()")
resource_code = '''def disk_observation():
 remaining();s=ROOT.lstat();home=ROOT.parent.lstat();fs=os.statvfs(ROOT)
 need(stat.S_ISDIR(s.st_mode) and s.st_uid==501 and stat.S_IMODE(s.st_mode)==0o700
  and s.st_dev==home.st_dev,'capacity_owned_same_home_filesystem')
 need(all(type(value) is int and value>0 for value in (fs.f_frsize,fs.f_blocks))
  and type(fs.f_bavail) is int and 0<=fs.f_bavail<=fs.f_blocks,'capacity_statvfs_numeric_bounds')
 return {'method':'fresh_statvfs_owned_home_fixture','availableBytes':fs.f_bavail*fs.f_frsize,
  'fragmentBytes':fs.f_frsize,'device':s.st_dev,'observationIsDiscreteNotAReservation':True}
def resource_admission():
 disk=disk_observation()
 need(disk['availableBytes']>=MINIMUM_FREE_DISK_BYTES,'capacity_synthetic_disk_headroom')
 row,out,err=commands.run('capacity-memory-vm-stat',[VM_STAT],until=min(UNTIL,time.monotonic()+3),maximum=32768)
 private(ROOT/'output/memory-observation.stdout.private',out);private(ROOT/'output/memory-observation.stderr.private',err)
 need(row.get('outcomeUnknown') is False and type(row.get('exitCode')) is int
  and row['exitCode']==0 and not err,'capacity_original_memory_command_known_closed_zero')
 lines=out.decode('ascii','strict').splitlines()
 header=re.fullmatch(r'Mach Virtual Memory Statistics: \\(page size of ([0-9]{1,6}) bytes\\)',lines[0] if lines else '')
 need(header is not None,'capacity_actual_vm_page_size_header')
 page_size=int(header.group(1));need(page_size in (4096,16384,65536),'capacity_actual_vm_page_size')
 names={'Pages free':'free','Pages active':'active','Pages inactive':'inactive',
  'Pages speculative':'speculative','Pages wired down':'wired','Pages occupied by compressor':'compressor'}
 pages={}
 for line in lines[1:]:
  match=re.fullmatch(r'([^:]{1,64}):\\s+([0-9]{1,20})\\.',line.strip())
  need(match is not None,'capacity_complete_numeric_vm_stat_line')
  if match.group(1) in names:
   key=names[match.group(1)];need(key not in pages,'capacity_unique_vm_stat_field');pages[key]=int(match.group(2))
 need(set(pages)==set(names.values()) and all(0<=v*page_size<=34359738368 for v in pages.values()),
  'capacity_bounded_observed_memory_pages')
 need(pages['free']*page_size>=MINIMUM_FREE_MEMORY_BYTES,'capacity_actual_current_free_memory_headroom')
 need(commands.public()['allOwnedCommandsStopped'] and commands.public()['unknownCommandCount']==0,
  'capacity_original_admission_helpers_closed_before_large_child')
 # Reobserve disk after the memory command; neither observation reserves resources.
 disk=disk_observation();need(disk['availableBytes']>=MINIMUM_FREE_DISK_BYTES,'capacity_fresh_disk_before_large_child')
 return {'disk':disk,'memory':{'method':'one_pinned_original_vm_stat','pageSize':page_size,
  'observedPages':pages,'currentlyFreeBytes':pages['free']*page_size,
  'inactivePagesCountedAsGuaranteedAvailable':False,'totalPhysicalMemoryCountedAsAvailable':False,
  'observationIsDiscreteNotAReservation':True},'minimumFreeDiskBytes':MINIMUM_FREE_DISK_BYTES,
  'minimumFreeMemoryBytes':MINIMUM_FREE_MEMORY_BYTES,'budgetScope':'new_synthetic_largest_database_fixture_only',
  'productionWholeSixDatabaseDiskBudgetAdmitted':False}
def safe_command_rows():
 if commands is None:return []
 return [{key:row['public'][key] for key in ('label','pid','exitCode','completeBeforeDeadline',
  'cleanup','stdoutBytes','stderrBytes','streamsClosed','outcomeUnknown')}
  if row.get('public') is not None else {'label':row['label'],'outcomeUnknown':True} for row in commands.rows]
'''
template = once(template, "def close_streams():", resource_code + "def close_streams():")
template = once(template, "if owner is not None:report['custody']=owner.receipt()",
    "if owner is not None:report['custody']=owner.receipt()\n"
    " report['originalAdmissionCommands']=safe_command_rows()\n"
    " report['allOriginalAdmissionCommandsClosed']=commands is None or commands.public()['allOwnedCommandsStopped']\n"
    " report['unknownAdmissionCommandCount']=0 if commands is None else commands.public()['unknownCommandCount']")
template = once(template, "if not report['allParentFileDescriptorsClosedOnce'] or time.monotonic()>=UNTIL:report['ok']=False",
    "if (not report['allParentFileDescriptorsClosedOnce'] or not report['allOriginalAdmissionCommandsClosed']\n"
    "  or report['unknownAdmissionCommandCount'] or time.monotonic()>=UNTIL):report['ok']=False\n"
    " if not report['ok']:report['largeDatabaseCapacityQualified']=False")
template_name = "launch_mac_whole_sqlite_capacity_r1.template.py"
compile(template, template_name, "exec")
(HERE / template_name).write_text(template)

source_names = ("whole_sqlite_streaming_r1.py", "qualify_whole_sqlite_capacity_r1.py", worker_name)
sources = {name: (HERE / name).read_text() for name in source_names}
for name, pin in HELPER_PINS.items():
    content = (HELPERS / name).read_text()
    assert sha(content.encode()) == pin, name
    sources[name] = content
for name, source in sources.items():
    tree = ast.parse(source)
    for node in ast.walk(tree):
        assert not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("serialize", "deserialize")), (name, "materialization")
        if isinstance(node, ast.ImportFrom) and node.module and "whole_sqlite" in node.module:
            assert node.module + ".py" in source_names, (name, node.module)
small_source = (SMALL / "launch_mac_whole_sqlite_streaming_small_r1.py").read_text()
assert sha(small_source.encode()) == "9fa7d557315d014bda2960282febfe6123d08607462ddddd27e369d226a3fc6c"
small_payload = assignment(small_source, "PAYLOAD")
payload = {key: small_payload[key] for key in ("schemas", "schemaPins", "installedSchemaSourcePins", "custodyQualificationAuthority")}
payload.update(sources=sources, sourcePins={name: sha(source.encode()) for name, source in sources.items()},
               workerSourcePins={name: sha(sources[name].encode()) for name in source_names}, helperSourcePins=HELPER_PINS)
assert template.count("# PAYLOAD_PLACEHOLDER") == 1
assembled = template.replace("# PAYLOAD_PLACEHOLDER", "PAYLOAD=" + repr(payload))
compile(assembled, "launch_mac_whole_sqlite_capacity_r1.py", "exec")
assert assignment(assembled, "PAYLOAD") == payload
(HERE / "launch_mac_whole_sqlite_capacity_r1.py").write_text(assembled)
manifest = {"schema": "heptabao.whole-sqlite-capacity-mac-preparation.r1",
    "sourcePins": payload["sourcePins"], "schemaPins": payload["schemaPins"],
    "installedSchemaSourcePins": payload["installedSchemaSourcePins"],
    "launcherBytes": len(assembled.encode()), "launcherSha256": sha(assembled.encode()),
    "smallActualJobId": "1a1b347c2f5-fc05-81b8", "sameCoreSha256": CORE_SHA,
    "root": "/Users/qianqi/" + NEW_ROOT, "sourceVfs": "unix-posix",
    "sharedSeconds": 600, "workerSeconds": 540, "supervisorSeconds": 630,
    "originalLargeChildren": 1, "originalMemoryCommands": 1, "memoryCommandSeconds": 3,
    "wholeBundleCases": 17, "databaseByteLimit": 4294967296,
    "minimumPrimaryBytes": MINIMUM_PRIMARY_BYTES, "maximumPrimaryBytes": MAXIMUM_PRIMARY_BYTES,
    "minimumFreeDiskBytes": MINIMUM_FREE_DISK_BYTES, "minimumFreeMemoryBytes": MINIMUM_FREE_MEMORY_BYTES,
    "streamBlockBytes": 1048576, "sqliteHeapLimitBytes": 268435456,
    "maximumProcessRssBytes": 536870912, "rssThresholdIsPostRunAcceptanceNotOsEnforcedLimit": True,
    "capacityScope": "largest_current_database_plus_six_database_lifecycle",
    "allCurrentSixDatabaseSizesReproduced": False, "productionWholeSixDatabaseDiskBudgetAdmitted": False,
    "directSourcePageOracleClaimed": False, "productionSourceReads": 0,
    "productionWrites": 0, "productionRollbackQualified": False, "actualExecuted": False}
(HERE / "capacity-mac-manifest.public.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
diff = "".join(difflib.unified_diff((SMALL / "mac_whole_sqlite_streaming_worker_r1.py").read_text().splitlines(True),
    worker.splitlines(True), fromfile="small/worker.py", tofile="capacity/worker.py"))
diff += "".join(difflib.unified_diff((SMALL / "launch_mac_whole_sqlite_streaming_small_r1.template.py").read_text().splitlines(True),
    template.splitlines(True), fromfile="small/launcher.template.py", tofile="capacity/launcher.template.py"))
(HERE / "small-to-capacity-worker-parent.diff").write_text(diff)
print(json.dumps(manifest, sort_keys=True))
