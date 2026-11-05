from pathlib import Path
import hashlib,json,os,platform,re,select,signal,stat,subprocess,sys,time,tomllib
ACTUAL_INPUTS_READY=False
if not ACTUAL_INPUTS_READY:
 raise RuntimeError('unresolved exact H2 QA artifact transport input metadata')
os.umask(0o077)
START=time.monotonic()
UNTIL=START+90
HEAD='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c'
TREE='424463ccd2310ddc1e7b2bbcd7b7af29ae58c825'
FILES=[
 {
  "role": "executable",
  "path": "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/artifacts/heptabao-native-h2-qa",
  "name": "heptabao-native-h2-qa",
  "bytes": None,
  "sha256": None,
  "source_mode": 320,
  "target_mode": 320,
  "version": None
 },
 {
  "role": "rust_source",
  "path": "/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r3/inputs/native_h2_client.rs",
  "name": "native_h2_client.rs",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "test_source",
  "path": "/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r3/inputs/native_h2_client_tests.rs",
  "name": "native_h2_client_tests.rs",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "cargo_manifest",
  "path": "/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r3/inputs/Cargo.toml",
  "name": "Cargo.toml",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "cargo_lock",
  "path": "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/artifacts/Cargo.lock",
  "name": "Cargo.lock",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "canonical_lock",
  "path": "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/artifacts/canonical.Cargo.lock",
  "name": "canonical.Cargo.lock",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "build_receipt",
  "path": "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/result.public.json",
  "name": "build-result.public.json",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "build_controller",
  "path": "/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r3/build_native_h2_client_r1.py",
  "name": "build_native_h2_client_r1.py",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "build_binding",
  "path": "/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r3/build-binding.private.json",
  "name": "build-binding.private.json",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "component_stdout",
  "path": "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/components.stdout",
  "name": "components.stdout",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "component_record",
  "path": "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/components.public.json",
  "name": "components.public.json",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 },
 {
  "role": "component_list_stdout",
  "path": "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/components-list.stdout",
  "name": "components-list.stdout",
  "bytes": None,
  "sha256": None,
  "source_mode": 384,
  "target_mode": 256,
  "version": None
 }
]
protected=0
pending_signal=None
children=[]
result={'schema':'heptabao.df026.fixed-public-h2-qa-endpoint.v1','status':'failed',
        'request_seconds':90,'git_operations':0,'server_started':False,'compiler_started':False}
class Cancelled(BaseException):pass
def handler(sig,_frame):
 global pending_signal
 pending_signal=sig
 if not protected:raise Cancelled()
for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,handler)
def remaining():
 value=UNTIL-time.monotonic()
 assert value>0,'original endpoint deadline exhausted'
 return value
def identity(s):
 return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def stop_active(p):
 if p.poll() is None:
  try:os.killpg(p.pid,signal.SIGTERM)
  except ProcessLookupError:pass
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:
   try:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   p.wait(timeout=5)
def snapshot():
 q=subprocess.run(['/bin/ps','-axo','pid=,ppid=,pgid=,stat='],stdin=subprocess.DEVNULL,
      stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=True)
 rows=[]
 for line in q.stdout.decode('ascii').splitlines():
  v=line.split()
  if len(v)>=4:rows.append({'pid':int(v[0]),'ppid':int(v[1]),'pgid':int(v[2]),'state':v[3]})
 return rows
def read_file(fd,size,expected,retain=False):
 os.lseek(fd,0,os.SEEK_SET)
 h=hashlib.sha256();n=0;parts=[]
 while True:
  remaining();b=os.read(fd,65536)
  if not b:break
  n+=len(b);assert n<=size;h.update(b)
  if retain:parts.append(b)
 assert n==size and h.hexdigest()==expected
 return {'bytes':n,'sha256':h.hexdigest()},b''.join(parts) if retain else None
def dir_fsync(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def run_and_report(operation):
 try:
  operation()
  remaining()
  result['status']='complete'
 except BaseException as e:
  result['status']='failed';result['error_type']=type(e).__name__
  frames=[];tb=e.__traceback__
  while tb is not None:
   frames.append({'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno});tb=tb.tb_next
  result['failure_frames']=frames
 finally:
  for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,signal.SIG_IGN)
  errors=[]
  for p in reversed(children):
   try:stop_active(p)
   except BaseException as e:errors.append(type(e).__name__)
  rows=None
  try:rows=snapshot() if children else []
  except BaseException as e:errors.append(type(e).__name__)
  result['cleanup']=[{'pid':p.pid,'direct_child_reaped':p.returncode is not None,
       'exit_code':p.returncode,'remaining':None if rows is None else [r for r in rows if r['pgid']==p.pid]}
       for p in children]
  result['cleanup_errors']=errors
  result['all_owned_stopped']=not errors and all(r['direct_child_reaped'] and r['remaining']==[] for r in result['cleanup'])
  result['elapsed_seconds']=time.monotonic()-START
  result['within_original_deadline']=time.monotonic()<UNTIL
  if pending_signal is not None or not result['all_owned_stopped'] or not result['within_original_deadline']:result['status']='failed'
  sys.stderr.write(json.dumps(result,sort_keys=True)+'\n');sys.stderr.flush()
 sys.exit(0 if result['status']=='complete' and time.monotonic()<UNTIL else 1)

H2_COMPONENT_TESTS = [
    "component_tests::native_h2_client_accepts_complete_data_eos",
    "component_tests::native_h2_client_accepts_complete_empty_trailers_eos",
    "component_tests::native_h2_client_rejects_rst_no_error_after_exact_body_before_eos",
    "component_tests::native_h2_client_rejects_eof_after_exact_body_before_eos",
    "component_tests::native_h2_client_rejects_short_eos_and_duplicate_content_length",
    "component_tests::native_h2_client_refuses_expired_or_extended_original_deadline"
]
H2_BUILD_CONTROLLER_SHA = "7ea25347f71764f1ed3d459d24b92750ef82c361878e9c856c7a7e8fe699bc15"
H2_BUILD_CAPS = {
    "total_seconds": 600,
    "git_seconds": 15,
    "tool_seconds": 15,
    "lock_seconds": 20,
    "build_seconds": 180,
    "components_build_seconds": 180,
    "list_seconds": 15,
    "components_seconds": 30,
    "cleanup_term_seconds": 5,
    "cleanup_kill_seconds": 5
}
H2_SOURCE_PINS = {
    "rust_source": [
        19382,
        "41347a71055e5c7086a256549f25f20d52ba8361e16926b4470f3448425f90dd"
    ],
    "test_source": [
        8942,
        "7f23470287fe953f0271e974d6eda759b7daf9f15bc363d522a02d3633e012c2"
    ],
    "cargo_manifest": [
        957,
        "960de7b19776cda4bd8a00561a417f72b08ca320efb93ec05028a3be0e7315e5"
    ]
}
CANONICAL_LOCK_SHA = "d2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5"
PROFILE = {"debug_assertions": True, "debuginfo": 0, "opt_level": "3",
           "overflow_checks": True, "test": False}
NORMAL_DF026_COMBINED_SHA = "84d763e6ff948df27964f373e834f869d7b22eeb0d7efb929fbd5c299c528f1b"

class BindingError(RuntimeError):
    pass

def need(ok: bool, code: str) -> None:
    if not ok:
        raise BindingError(code)

def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def duplicate_free(pairs: list[tuple[str, object]]) -> dict:
    out = {}
    for key, value in pairs:
        need(key not in out, "duplicate_json_key")
        out[key] = value
    return out

def parse(raw: bytes) -> object:
    return json.loads(raw.decode(), object_pairs_hook=duplicate_free)

def lock_subset(actual_raw: bytes, canonical_raw: bytes) -> dict:
    actual = tomllib.loads(actual_raw.decode("utf-8"))
    canonical = tomllib.loads(canonical_raw.decode("utf-8"))
    need(type(actual) is dict and set(actual) == {"version", "package"}
         and type(actual["version"]) is int
         and actual["version"] == canonical.get("version"), "qa_lock_top_level")
    package_list = canonical.get("package")
    need(type(package_list) is list and type(actual["package"]) is list
         and 1 < len(actual["package"]) <= len(package_list), "qa_lock_package_bound")
    allowed = {}
    for item in package_list:
        key = (item["name"], item["version"], item.get("source"))
        need(key not in allowed, "canonical_lock_duplicate_package")
        allowed[key] = item.get("checksum")
    seen, members, own = set(), [], 0
    for item in actual["package"]:
        need(type(item) is dict and set(item) <=
             {"name", "version", "source", "checksum", "dependencies"}, "qa_lock_package_fields")
        need(type(item.get("name")) is str and type(item.get("version")) is str
             and type(item.get("dependencies", [])) is list
             and all(type(value) is str for value in item.get("dependencies", [])),
             "qa_lock_package_types")
        key = (item["name"], item["version"], item.get("source"))
        need(key not in seen, "qa_lock_duplicate_package")
        seen.add(key)
        if item["name"] == "heptabao-native-h2-qa":
            need(item["version"] == "0.1.0" and "source" not in item
                 and "checksum" not in item, "only_owned_qa_root_package")
            own += 1
            continue
        need(item.get("source") == "registry+https://github.com/rust-lang/crates.io-index"
             and type(item.get("checksum")) is str
             and re.fullmatch(r"[0-9a-f]{64}", item["checksum"]) is not None
             and key in allowed and item["checksum"] == allowed[key],
             "qa_dependency_not_exact_canonical_lock_member")
        members.append({"name": item["name"], "version": item["version"],
                        "source": item["source"], "checksum": item["checksum"]})
    need(own == 1, "one_owned_qa_root_package")
    members.sort(key=lambda item: (item["name"], item["version"], item["source"]))
    return {"schema": "heptabao.native-h2-qa.lock-subset.v1",
            "canonical_sha256": sha(canonical_raw), "qa_lock_sha256": sha(actual_raw),
            "registry_package_count": len(members), "owned_qa_package_count": own,
            "packages": members, "exact_version_source_checksum_subset": True}

def verify_h2_qa(raw: dict) -> dict:
    pins = {item['role']: item for item in FILES}
    for role, (size, digest) in H2_SOURCE_PINS.items():
        need(pins[role]["bytes"] == size
             and pins[role]["sha256"] == digest, "exact_reviewed_h2_qa_source")
    need(type(H2_BUILD_CONTROLLER_SHA) is str
         and re.fullmatch(r"[0-9a-f]{64}", H2_BUILD_CONTROLLER_SHA) is not None
         and pins["build_controller"]["sha256"] == H2_BUILD_CONTROLLER_SHA,
         "exact_reviewed_h2_qa_builder")
    subset = lock_subset(raw["cargo_lock"], raw["canonical_lock"])
    need(subset["canonical_sha256"] == CANONICAL_LOCK_SHA, "canonical_dependency_source")
    build = parse(raw["build_receipt"])
    original_binding = parse(raw["build_binding"])
    component = parse(raw["component_record"])
    need(type(build) is dict and build.get("schema") == "heptabao.native-h2-qa.build.v3"
         and build.get("status") == "passed"
         and build.get("candidate_commit") == HEAD and build.get("candidate_tree") == TREE
         and build.get("controller_sha256") == H2_BUILD_CONTROLLER_SHA
         and build.get("binding_sha256") == pins["build_binding"]["sha256"]
         and build.get("normal_product_result_sha256") == NORMAL_DF026_COMBINED_SHA
         and build.get("normal_product_runner_sha256")
         == "1a3fdc3a7cf6504447feb7d7dadf2f365b292512f6d0cf8cdfb4a2ea63d33d40"
         and build.get("caps") == H2_BUILD_CAPS
         and build.get("all_owned_stopped") is True
         and build.get("all_input_fds_closed") is True
         and build.get("command_outcome_unknown") is False
         and build.get("incomplete_command_labels") == []
         and build.get("completed_within_original_build_deadline") is True
         and build.get("source_before") == build.get("source_after")
         == {"commit": HEAD, "tree": TREE, "status": ""}
         and build.get("lock_subset") == subset
         and build.get("offline_only") is True
         and build.get("product_modified") is False
         and build.get("product_or_http_requests") == 0, "actual_qa_build_provenance")
    need(type(original_binding) is dict
         and original_binding.get("schema") == "heptabao.native-h2-qa.build-binding.v1"
         and original_binding.get("candidate_commit") == HEAD
         and original_binding.get("candidate_tree") == TREE
         and original_binding.get("ready") is True
         and original_binding.get("caps") == H2_BUILD_CAPS,
         "original_actual_qa_build_binding")
    expected_sources = {role: {"bytes": size, "sha256": digest}
                        for role, (size, digest) in H2_SOURCE_PINS.items()}
    need(build.get("reviewed_sources") == expected_sources, "qa_compiled_source_identity")
    executable = build.get("executable")
    need(type(executable) is dict
         and executable.get("sha256") == pins["executable"]["sha256"]
         and executable.get("bytes") == pins["executable"]["bytes"]
         and executable.get("features") == []
         and executable.get("profile") == PROFILE,
         "qa_actual_binary_from_release_event")
    need(build.get("component_names") == H2_COMPONENT_TESTS
         and build.get("component_record_sha256") == pins["component_record"]["sha256"]
         and component.get("stdout_sha256") == pins["component_stdout"]["sha256"]
         and component.get("exit_code") == 0 and component.get("timed_out") is False
         and component.get("direct_child_reaped") is True and component.get("remaining") == []
         and component.get("completed_within_deadline") is True,
         "six_actual_qa_components_and_owned_terminal")
    listed = [line[:-6] for line in raw["component_list_stdout"].decode("utf-8").splitlines()
              if line.endswith(": test")]
    need(len(listed) == 6 and set(listed) == set(H2_COMPONENT_TESTS),
         "exact_qa_component_listing")
    output = raw["component_stdout"].decode("utf-8")
    executed = [line[5:-7] for line in output.splitlines()
                if line.startswith("test ") and line.endswith(" ... ok")]
    need(len(executed) == 6 and set(executed) == set(H2_COMPONENT_TESTS)
         and output.count("test result: ok. 6 passed; 0 failed; 0 ignored;") == 1,
         "six_actual_qa_component_results")
    commands = build.get("commands")
    cleanup = build.get("owned_cleanup")
    need(type(commands) is list and 5 <= len(commands) <= 24
         and all(item.get("exit_code") == 0 and item.get("timed_out") is False
                 and item.get("direct_child_reaped") is True and item.get("remaining") == []
                 and item.get("completed_within_deadline") is True for item in commands)
         and type(cleanup) is list and len(cleanup) == len(commands)
         and all(item.get("direct_child_reaped") is True and item.get("remaining") == []
                 and item.get("owned_stopped") is True for item in cleanup),
         "all_actual_qa_commands_and_cleanup")
    remaining()
    return {"candidate_commit": HEAD, "candidate_tree": TREE,
            "executable_sha256": executable["sha256"],
            "actual_build_receipt_sha256": pins["build_receipt"]["sha256"],
            "reviewed_sources": expected_sources,
            "component_names": H2_COMPONENT_TESTS,
            "component_count": 6, "component_status": "passed",
            "lock_subset": subset, "offline_only": True,
            "http_or_product_qualification": False,
            "new_qa_components_not_added_to_product_44_7_9": True}

ROOT=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-native-h2-qa-shared-artifacts-r1')
DESTINATION=ROOT/'incoming'
def receive():
 assert (platform.system(),platform.machine(),os.getuid())==('Linux','x86_64',1000)
 assert ROOT.resolve(strict=True)==ROOT and ROOT.is_dir() and ROOT.stat().st_uid==1000
 assert stat.S_IMODE(ROOT.stat().st_mode)==0o700
 assert not DESTINATION.exists() and not DESTINATION.is_symlink()
 DESTINATION.mkdir(mode=0o700);dir_fsync(ROOT)
 result['partial_directory_retained_on_failure']=True
 results=[];qa_bytes={}
 for item in FILES:
  remaining();path=DESTINATION/item['name']
  fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   count=0;h=hashlib.sha256()
   while count<item['bytes']:
    assert select.select([0],[],[],remaining())[0]
    try:block=os.read(0,min(65536,item['bytes']-count))
    except (BlockingIOError,InterruptedError):continue
    assert block,'truncated artifact stream'
    count+=len(block);h.update(block);view=memoryview(block)
    while view:
     remaining();n=os.write(fd,view);assert n>0;view=view[n:]
   assert count==item['bytes'] and h.hexdigest()==item['sha256']
   os.fchmod(fd,item['target_mode']);os.fsync(fd)
   before=os.fstat(fd)
   assert stat.S_ISREG(before.st_mode) and before.st_uid==1000 and before.st_nlink==1
   assert before.st_size==item['bytes'] and stat.S_IMODE(before.st_mode)==item['target_mode']
   same_fd,raw=read_file(fd,item['bytes'],item['sha256'],item['role']!='executable')
   assert identity(before)==identity(os.fstat(fd))==identity(path.lstat())
   if raw is not None:qa_bytes[item['role']]=raw
   results.append({'name':item['name'],'path':str(path),'bytes':count,'sha256':h.hexdigest(),
        'mode':item['target_mode'],'create_only':True,'fsynced':True,
        'identity':identity(before),'same_fd_readback':same_fd})
  finally:os.close(fd)
 assert select.select([0],[],[],remaining())[0]
 assert os.read(0,1)==b'','unexpected artifact stream trailer'
 qa_provenance=verify_h2_qa(qa_bytes)
 assert sorted(os.listdir(DESTINATION))==sorted(x['name'] for x in FILES)
 dirfd=os.open(DESTINATION,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fchmod(dirfd,0o500);os.fsync(dirfd)
 finally:os.close(dirfd)
 dir_fsync(ROOT);remaining()
 result.update(role='receiver',source_commit=HEAD,source_tree=TREE,files=results,
      destination_created_exclusive=True,destination_directory_mode=0o500,
      destination_fsynced=True,raw_receipts_preserved=True,qa_build_provenance_verified=True,
      qa_build_provenance=qa_provenance)
run_and_report(receive)
