#!/usr/bin/env python3
"""One actual SDK-selected local private capsule; no provider, refresh or production write."""
import contextlib,hashlib,json,os,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic();PARENT_COMMAND_UNTIL=float(sys.argv[1]);UNTIL=min(PARENT_COMMAND_UNTIL,START+45.0)
ROOT=Path("/Users/qianqi/heptabao-authbus-main3-sdk-inline-capsule-20261106-r3")
LIVE=Path("/Users/qianqi/.openclaw")
QUAL=Path("/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2")
SDK=Path("/opt/homebrew/lib/node_modules/openclaw")
BINDING=Path("/Users/qianqi/heptabao-authbus-current-source-20261106-r1/output/current-source-binding.private.json")
CREDENTIAL_ROOT=Path("/Users/qianqi/heptabao-authbus-current-credentials-20261106-r1")
CONFIG_ROOT=Path("/Users/qianqi/heptabao-authbus-current-source-20261106-r1")
ORDER_ROOT=Path("/Users/qianqi/heptabao-authbus-current-sdk-order-20261106-r1")
PYTHON="/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
AGENTS=("main","trnm","hepta-ui","hepta","hepta-backend")
INPUT_PATHS={BINDING,ORDER_ROOT/"output/owner-mapping.private.json",*[CREDENTIAL_ROOT/"output"/("credentials-"+agent+".private.json") for agent in AGENTS]}

import ast,base64
CAPTURE_QA=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r3/qa')
PAYLOAD_PART_PINS={'main3_capture_payload_0.py': {'bytes': 60008, 'sha256': '220e0620b337f3ab1f800e043a935bbdb8ee1a4eb4da92c820c6dde575e52eb8'}, 'main3_capture_payload_1.py': {'bytes': 60008, 'sha256': '8b92d7bee773ba63f9e7d9e8ad1cc94f522baad298421f5269bc79a1d76d9184'}, 'main3_capture_payload_2.py': {'bytes': 60008, 'sha256': '6d561461f75354b985f23297e8f5a79bf974fe64e7dd9c666be7bcab365d92c8'}, 'main3_capture_payload_3.py': {'bytes': 36668, 'sha256': '742338b1acbc9ca240eab49d34f4ae586628c68773f48bb13c2ed15f51d9ef1e'}}
def read_payload():
    need_deadline=lambda: time.monotonic()<UNTIL
    values=[]
    for name,pin in PAYLOAD_PART_PINS.items():
        assert need_deadline()
        path=CAPTURE_QA/name
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            before=os.fstat(fd)
            identity=lambda s:tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
            assert stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
            raw=os.read(fd,65537)
            assert len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'] and os.read(fd,1)==b''
            assert identity(before)==identity(os.fstat(fd))==identity(path.lstat())
        finally:os.close(fd)
        node=ast.parse(raw)
        assert len(node.body)==1 and isinstance(node.body[0],ast.Assign) and len(node.body[0].targets)==1
        assert isinstance(node.body[0].targets[0],ast.Name) and node.body[0].targets[0].id=='DATA'
        value=ast.literal_eval(node.body[0].value);assert isinstance(value,str)
        values.append(value)
    raw=base64.b64decode(''.join(values),validate=True)
    assert len(raw)<=262144 and hashlib.sha256(raw).hexdigest()=='1787e925b8013a3fdbfd060a670cbc52e575f3c9b7dc6c4d4e3d551a54e39fdd' and need_deadline()
    return json.loads(raw)
PAYLOAD=read_payload()


PINS={
"authbus_current_auth_wal.py":"ad443869e259da06de2be71131e5d1854680477d1cf77248e05a3c1704160f8c",
"mac_guarded_current_capture_r3.py":"606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693",
"mac_registry_readonly_wal_r1.py":"60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed",
"kv2_dr_process_custody.py":"669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008",
"owned_process.py":"0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0"}
report={"schema":"heptabao.current-sdk-selected-capsule-inline-owned-observation.sdk-r3","ok":False,
"credentialValuesOrDigestsIncluded":False,"rawClientConfigHashIncluded":False,"profileIdsPublished":False,
"providerCalled":False,"refreshDispatched":False,"j3160Contacted":False,
"productionConfigurationChanged":False,"productionDatabaseChanged":False,"serviceActions":0,
"credentialExportedOffHost":False,"migrationAllowlistAuthorized":False,"sharedSeconds":45,
"supervisorSeconds":None,"parentCommandSeconds":45,"applicationRetries":0,"productBinaryExecuted":False,
"candidateCommit":"4bde9aee03fcd27c59e13607e529b1cee594b249",
"candidateTree":"f08493a23f8ea0637073651231865ea9607b790e"}
owner=None;child=None;source=None;created=False;bundles=[];node_pin=None
registry_guard=None;registry_bundle=None;metadata_files=[]
def need(value,code):
    if not value:raise RuntimeError(code)
def sha(data):return hashlib.sha256(data).hexdigest()
def remaining(cap=45):
    value=UNTIL-time.monotonic();need(value>0,"original_actual_sdk_owner_deadline")
    return min(value,cap)
def public_read(path,cap=1024*1024):
    path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,"bounded_public_source")
        parts=[];count=0
        while count<=cap:
            remaining();part=os.read(fd,min(65536,cap+1-count))
            if not part:break
            parts.append(part);count+=len(part)
        identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(count==before.st_size and identity(before)==identity(os.fstat(fd))==identity(os.lstat(path)),"same_public_source")
        return b"".join(parts)
    finally:os.close(fd)
def public_pin(path,cap):
    path=Path(path).resolve(strict=True)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1
             and 0<before.st_size<=cap and not stat.S_IMODE(before.st_mode)&0o022,"public_runtime_custody")
        h=hashlib.sha256();count=0
        while count<=before.st_size:
            remaining();part=os.read(fd,min(1024*1024,before.st_size+1-count))
            if not part:break
            count+=len(part);h.update(part)
        identity=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(count==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),"same_public_runtime")
        return {"path":str(path),"bytes":count,"sha256":h.hexdigest(),"mode":stat.S_IMODE(before.st_mode)}
    finally:os.close(fd)
def private(path,value):
    raw=value if isinstance(value,bytes) else value.encode()
    need(len(raw)<=2*1024*1024,"bounded_owned_output")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)
def read_private(path,cap=262144):
    path=Path(path)
    need(path in INPUT_PATHS,"exact_original_private_source_path")
    parents=[];parent_fd=None;fd=None
    try:
        for current in [Path("/"),*list(reversed(path.parent.parents))[1:],path.parent]:
            if parent_fd is None:
                current_fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            else:
                current_fd=os.open(current.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
            info=os.fstat(current_fd)
            need(stat.S_ISDIR(info.st_mode) and not stat.S_IMODE(info.st_mode)&0o022,
                 "private_allowlist_parent_custody")
            parents.append(current_fd);parent_fd=current_fd
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_gid==20
             and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and 0<before.st_size<=cap,
             "private_allowlist_custody")
        raw=b""
        while len(raw)<=cap:
            remaining();part=os.read(fd,min(65536,cap+1-len(raw)))
            if not part:break
            raw+=part
        named=os.stat(path.name,dir_fd=parent_fd,follow_symlinks=False)
        need(len(raw)==before.st_size and auth.base.identity(before)==auth.base.identity(os.fstat(fd))
             ==auth.base.identity(named),"private_allowlist_unchanged")
        return raw
    finally:
        if fd is not None:os.close(fd)
        for item in reversed(parents):os.close(item)

def validate_authority(value,job):
    need(value["job_id"]==job and value["state"]=="succeeded" and value["exit_code"]==0
         and all(value[k] is True for k in ("output_complete","output_durable","terminal_publication_confirmed"))
         and all(value[k] is False for k in ("timed_out","cancelled","automatic_retry")),"original_public_authority")
def source_fence():
    source.verify()
    for bundle in bundles:auth.verify_auth_bundle(source,bundle,until=UNTIL)
    if registry_guard is not None:
        registry_guard.verify();auth.wal.verify_bundle(registry_guard,registry_bundle,until=UNTIL)
try:
    os.umask(0o077)
    need(len(sys.argv)==2 and 0<PARENT_COMMAND_UNTIL-START<=45.0,"same_parent_original_capture_allocation")
    need(sys.platform=="darwin" and os.getuid()==501 and os.path.realpath(sys.executable)==PYTHON,"actual_mac_python_owner")
    validate_authority(PAYLOAD["qualificationAuthority"],"1a1b141ef40-fc05-7750")
    raw=public_read(QUAL/"result.public.json",65536)
    need(len(raw)==58701 and sha(raw)=="67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e","same_auth_generation_qualification")
    proof=json.loads(raw)
    need(proof["ok"] and proof["allCasesMatched"] and proof["allOwnedClosed"]
         and proof["custody"]["passed_process_custody"] and proof["custody"]["original_count"]==18,"complete_actual_18_case_qualification")
    validate_authority(PAYLOAD["configAuthority"],"1a1b137a21d-fc05-76f8")
    validate_authority(PAYLOAD["credentialAuthority"],"1a1b153b77b-fc05-77c3")
    need(public_read(CONFIG_ROOT/"result.public.json",32768)==PAYLOAD["configStdout"].encode()
         and public_read(CREDENTIAL_ROOT/"result.public.json",32768)==PAYLOAD["credentialStdout"].encode(),"exact_original_current_source_receipts")
    for name,pin in PINS.items():need(sha(public_read(QUAL/"qa"/name))==pin,"same_qualified_custody_source")
    need(sha(public_read(Path(PYTHON),1048576))==proof["runtime"]["pythonExecutableSha256"],"same_python_runtime")
    sys.path.insert(0,str(QUAL/"qa"))
    import authbus_current_auth_wal as auth
    import kv2_dr_process_custody as custody
    node_pin=public_pin("/opt/homebrew/bin/node",256*1024*1024)
    report["nodeRuntimePin"]=node_pin
    package=public_read(SDK/"package.json",262144)
    need(json.loads(package)["version"]=="2026.7.1-2","actual_current_sdk_version")
    report["sdkPackagePin"]={"bytes":len(package),"sha256":sha(package),"version":"2026.7.1-2"}
    for relative,expected in PAYLOAD["sdkPins"].items():
        need(sha(public_read(SDK/relative))==expected,"same_actual_installed_sdk_module")
    registry_proof=PAYLOAD["registryProof"].encode();registry_authority_raw=PAYLOAD["registryAuthority"].encode()
    need(len(registry_proof)==62662 and sha(registry_proof)=="7d08a18c21a5d754ea9fbe7711e6315daf8fbd80c7b5a6937756fea7ba4d1c82"
         and len(registry_authority_raw)==733 and sha(registry_authority_raw)=="b564093e2300cdc44b2ae4724e869d5b24bfe3d94d269f8ebfa977e08b07505f",
         "same_registry_original_qualification_bytes")
    validate_authority(json.loads(registry_authority_raw),"1a1aaaaa6cd-fc05-45dd")
    registry_qualification=json.loads(registry_proof)
    need(registry_qualification["ok"] and registry_qualification["allCasesMatched"]
         and registry_qualification["allOwnedClosed"] and registry_qualification["sourceAndRuntimeAfterVerified"]
         and registry_qualification["caseIds"]==["W%02d"%number for number in range(1,11)],
         "same_actual_registry_wal_qualification")
    compile(PAYLOAD["registryChild"],"registry_read.py","exec")
    ROOT.mkdir(mode=0o700,exist_ok=False);created=True
    (ROOT/"code").mkdir(mode=0o700);(ROOT/"output").mkdir(mode=0o700)
    (ROOT/"output/tmp").mkdir(mode=0o700);(ROOT/"output/tmp/openclaw-501").mkdir(mode=0o700)
    private(ROOT/"code/owner_read.mjs",PAYLOAD["worker"]);private(ROOT/"code/authbus_sdk_read_guard.mjs",PAYLOAD["guard"])
    private(ROOT/"write-fence","owned kernel write refusal probe\n")
    private(ROOT/"code/registry_read.py",PAYLOAD["registryChild"])
    private(ROOT/"code/registry-proof.stdout.public.json",registry_proof)
    private(ROOT/"code/registry-proof.authority.public.json",registry_authority_raw)
    binding=auth.strict_json(read_private(BINDING))
    need(binding["sourceHost"]=="mac" and binding["sourceRoot"]==str(LIVE)
         and [item["agent"] for item in binding["agents"]]==list(AGENTS),"same_five_registered_agents")
    source=auth.AuthInputs(until=UNTIL,critical=contextlib.nullcontext,cancelled=lambda:False)
    raw_config=source.read(LIVE/"openclaw.json")
    need(sha(raw_config)==binding["configurationSha256"]
         and list(source.files[str(LIVE/"openclaw.json")]["expected"])==binding["configurationIdentity"],
         "original_configuration_generation_still_current")
    cfg=auth.strict_json(raw_config)
    registered={row["profileId"] for row in binding["registeredProfiles"]}
    need(set(cfg.get("auth",{}).get("profiles",{}))==registered,"original_current_registration_scope")
    source_generations=[];prior_source_generations=[];changed_auth_generations=0
    for agent in AGENTS:
        # The prior empty registered-ID capture binds historical scope only.
        # Current bytes are read afresh by the actual SDK under new held files.
        packet=auth.strict_json(read_private(CREDENTIAL_ROOT/"output"/("credentials-"+agent+".private.json")))
        need(packet["schema"]=="heptabao.current-auth-registered-generation.private.r1"
             and packet["host"]=="mac" and packet["agent"]==agent
             and packet["configurationSha256"]==binding["configurationSha256"],"original_agent_generation_capsule")
        prior={"agent":agent,"sourceIdentities":packet["sourceIdentities"],"sourceAbsences":packet["sourceAbsences"]}
        prior_source_generations.append(prior)
        bundle=auth.auth_wal_database(source,agent);bundles.append(bundle)
        present={row["path"] for row in (bundle["main"],bundle["wal"],bundle["shm"]) if row is not None}
        absent={bundle["main"]["path"]+suffix for suffix,key in (("-wal","wal"),("-shm","shm")) if bundle[key] is None}
        absent.add(bundle["journal"])
        allowed={bundle["main"]["path"]+suffix for suffix in ("","-wal","-shm","-journal")}
        need(present|absent==allowed and not present&absent
             and set(packet["sourceIdentities"])|set(packet["sourceAbsences"])==allowed,
             "same_fixed_auth_namespace_new_generation")
        current={"agent":agent,
                 "sourceIdentities":{pathname:list(source.files[pathname]["expected"]) for pathname in sorted(present)},
                 "sourceAbsences":sorted(absent)}
        if current["sourceIdentities"]!=prior["sourceIdentities"] or set(current["sourceAbsences"])!=set(prior["sourceAbsences"]):
            changed_auth_generations+=1
        source_generations.append(current)
    report.update(freshSourceGenerationCapture=True,authGenerationsChangedSinceOriginalCapture=changed_auth_generations,
                  previousSourceObservationUsedOnlyForScope=True,full9GenerationComparisonWeakened=False,
                  sourceCaptureReason="prior_capsule_registry_full9_changed")
    source_fence()
    validate_authority(PAYLOAD["orderAuthority"],"1a1b197fa0e-fc05-79c0")
    need(public_read(ORDER_ROOT/"result.public.json",65536)==PAYLOAD["orderStdout"].encode(),
         "exact_original_actual_sdk_selection_receipt")
    selected_mapping=auth.strict_json(read_private(ORDER_ROOT/"output/owner-mapping.private.json",1048576))
    need(selected_mapping["schema"]=="heptabao.actual-sdk-owned-profile-mapping.private.r1"
         and selected_mapping["host"]=="mac"
         and selected_mapping["configurationSha256"]==binding["configurationSha256"]
         and selected_mapping["configurationIdentity"]==binding["configurationIdentity"]
         and selected_mapping["sourceGenerations"]==prior_source_generations
         and selected_mapping["sdkSourcePins"]==PAYLOAD["sdkPins"]
         and selected_mapping["constraints"]["selectionOrderExecuted"] is True
         and selected_mapping["constraints"]["containsCredentialValues"] is False,
         "original_actual_sdk_selection_private_binding")
    selected=selected_mapping["selectedOwners"]
    need(isinstance(selected,list) and len(selected)==3
         and len({(row["ownerAgentDir"],row["profileId"]) for row in selected})==3
         and all(row["ownerAgent"]=="main" and row["ownerAgentDir"]==str(LIVE/"agents/main/agent")
                 and row["actualProvider"]=="openai" and isinstance(row["profileId"],str)
                 and 0<len(row["profileId"])<=256 for row in selected),
         "exact_observed_three_main_owner_selection_only")
    private_input={"schema":"heptabao.current-sdk-owner-input.private.r1","host":"mac",
         "configurationSha256":binding["configurationSha256"],"configurationIdentity":binding["configurationIdentity"],
         "agents":binding["agents"],"registeredProfileIds":sorted(registered),
         "sourceGenerations":source_generations,"sdkPins":PAYLOAD["sdkPins"],
         "selectedOwnerAllowlist":selected,
         "sourceSelectionAuthority":{"jobId":"1a1b197fa0e-fc05-79c0",
                                    "source":"actual_sdk_persisted_store_explicit_order",
                                    "originalResultSha256":sha(PAYLOAD["orderStdout"].encode())}}
    def make_policy(*,registry=False,metadata_paths=()):
        paths={ROOT,ROOT/"code",ROOT/"output",ROOT/"write-fence",ROOT/"input.private.json",LIVE/"openclaw.json"}
        paths.update(ROOT.parents);paths.update((LIVE/"openclaw.json").parents)
        if registry:
            paths.add(BINDING);paths.update(BINDING.parents)
            database=LIVE/"state/openclaw.sqlite"
            for suffix in ("","-wal","-shm","-journal"):
                candidate=Path(str(database)+suffix);paths.add(candidate);paths.update(candidate.parents)
        else:
            for agent in AGENTS:
                database=LIVE/"agents"/agent/"agent/openclaw-agent.sqlite"
                for suffix in ("","-wal","-shm","-journal"):
                    candidate=Path(str(database)+suffix);paths.add(candidate);paths.update(candidate.parents)
            for value in metadata_paths:
                candidate=Path(value);paths.add(candidate);paths.update(candidate.parents)
        lines=["(version 1)","(deny default)","(allow process*)","(allow signal (target children))",
               "(allow sysctl-read)","(allow mach-lookup)","(allow file-read-metadata)"]
        for pathname in ("/System","/usr","/bin","/sbin","/Library","/private/etc","/opt/homebrew","/dev/fd"):
            lines.append("(allow file-read* (subpath "+json.dumps(pathname)+"))")
        subpaths=[ROOT/"code",ROOT/"output"]
        if registry:subpaths.append(QUAL/"qa")
        for pathname in subpaths:lines.append("(allow file-read* (subpath "+json.dumps(str(pathname))+"))")
        for pathname in sorted(paths,key=str):lines.append("(allow file-read* (literal "+json.dumps(str(pathname))+"))")
        for pathname in ("/dev/null","/dev/urandom","/dev/random"):
            lines.append("(allow file-read* (literal "+json.dumps(pathname)+"))")
        lines.append("(allow file-write* (subpath "+json.dumps(str(ROOT/"output"))+"))")
        lines.append('(allow file-write* (literal "/dev/null"))')
        return "\n".join(lines)+"\n"
    registry_policy=make_policy(registry=True)
    private(ROOT/"registry-reader.sb",registry_policy)
    environment={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":"/Users/qianqi",
         "NODE_NO_WARNINGS":"1","TMPDIR":str(ROOT/"output/tmp"),"OPENCLAW_STATE_DIR":str(LIVE),
         "OPENCLAW_CONFIG_PATH":str(LIVE/"openclaw.json"),"OPENCLAW_AUTH_STORE_READONLY":"1"}
    original_popen=subprocess.Popen;original_killpg=os.killpg
    with custody.activated() as owner:
        child=subprocess.Popen(["/usr/bin/sandbox-exec","-f",str(ROOT/"registry-reader.sb"),
            PYTHON,"-I","-S","-B",str(ROOT/"code/registry_read.py"),str(UNTIL)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,cwd=str(ROOT),
            env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","PYTHONDONTWRITEBYTECODE":"1"})
        registry_stdout,registry_stderr=child.communicate(timeout=remaining(10))
        need(len(registry_stdout)<=32768 and not registry_stderr,"bounded_registry_prerequisite_output")
        private(ROOT/"output/registry-child.stdout.public.json",registry_stdout)
        registry_observation=json.loads(registry_stdout);report["registryObservation"]=registry_observation
        need(child.returncode==0 and registry_observation.get("ok") is True,"current_registry_prerequisite_complete")
        for pipe in (child.stdout,child.stderr):
            if not pipe.closed:pipe.close()
        registry_path=ROOT/"output/registry.private.json"
        ri=registry_path.lstat()
        need(stat.S_ISREG(ri.st_mode) and ri.st_uid==501 and ri.st_nlink==1 and stat.S_IMODE(ri.st_mode)==0o600,
             "private_registry_projection_custody")
        registry_packet=auth.strict_json(public_read(registry_path,262144))
        need(registry_packet["schema"]=="heptabao.current-sdk-registry.private.r2"
             and registry_packet["configurationSha256"]==binding["configurationSha256"]
             and registry_packet["configurationIdentity"]==binding["configurationIdentity"],
             "registry_and_auth_config_same_generation")
        registry_guard=auth.wal.WalInputs(until=UNTIL,critical=contextlib.nullcontext,cancelled=lambda:False)
        registry_bundle=auth.wal.registry_wal_database(registry_guard)
        need({key:list(item["expected"]) for key,item in registry_guard.files.items()}==registry_packet["sourceIdentities"]
             and set(registry_guard.absent)==set(registry_packet["sourceAbsences"]),
             "actual_registry_generation_still_exact")
        registry_values=dict(zip(registry_packet["registry"]["columns"],registry_packet["registry"]["row"]))
        plugins=auth.strict_json(registry_values["plugins_json"])
        need(isinstance(plugins,list) and 0<len(plugins)<=256,"bounded_actual_installed_plugin_list")
        metadata_paths=set()
        for item in plugins:
            rootdir=Path(item["rootDir"]).resolve(strict=True)
            need(rootdir.is_dir(),"registered_plugin_root_exists")
            manifest=Path(item["manifestPath"])
            need(manifest.is_absolute(),"registered_manifest_absolute")
            real_manifest=manifest.resolve(strict=True)
            need(real_manifest.is_relative_to(rootdir),"registered_manifest_within_actual_root")
            file_pairs=[(manifest,real_manifest)]
            package=item.get("packageJson")
            if package is not None:
                need(isinstance(package,dict) and isinstance(package.get("path"),str)
                     and package["path"] and len(package["path"])<=4096,"registered_package_path_shape")
                package_path=Path(os.path.abspath(rootdir/package["path"]))
                need(package_path.is_relative_to(rootdir),"sdk_package_relative_containment")
                real_package=package_path.resolve(strict=True)
                need(real_package.is_relative_to(rootdir),"sdk_real_package_containment")
                file_pairs.append((package_path,real_package))
            for nominal,real in file_pairs:
                si=real.lstat()
                need(stat.S_ISREG(si.st_mode) and si.st_uid in (0,501) and si.st_nlink==1
                     and not stat.S_IMODE(si.st_mode)&0o022,"registered_public_metadata_custody")
                raw_metadata=public_read(real,1048576)
                metadata_files.append({"nominal":str(nominal),"path":str(real),
                    "identity":list(auth.base.identity(si)),"sha256":sha(raw_metadata)})
                metadata_paths.update((str(nominal),str(real)))
        private_input.update(registry=registry_packet["registry"],registryPluginCount=len(plugins),
            registryGeneration={"sourceIdentities":registry_packet["sourceIdentities"],
                                "sourceAbsences":registry_packet["sourceAbsences"]},
            registeredMetadataFileBindings=metadata_files)
        private(ROOT/"input.private.json",json.dumps(private_input,sort_keys=True).encode()+b"\n")
        policy=make_policy(metadata_paths=metadata_paths);private(ROOT/"node-reader.sb",policy)
        source_fence()
        child=subprocess.Popen([node_pin["path"],"--check",str(ROOT/"code/owner_read.mjs")],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,cwd=str(ROOT),env=environment)
        stdout,stderr=child.communicate(timeout=remaining(5))
        need(child.returncode==0 and stdout==b"" and stderr==b"","actual_node_syntax_check")
        for pipe in (child.stdout,child.stderr):
            if not pipe.closed:pipe.close()
        source_fence()
        child=subprocess.Popen(["/usr/bin/sandbox-exec","-f",str(ROOT/"node-reader.sb"),node_pin["path"],
            "--no-warnings",str(ROOT/"code/owner_read.mjs"),str(int(remaining(30)*1000))],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,cwd=str(ROOT),env=environment)
        stdout,stderr=child.communicate(timeout=remaining(30))
        need(len(stdout)<=65536 and len(stderr)<=16384,"bounded_actual_sdk_public_output")
        private(ROOT/"output/child.stdout.public.json",stdout);private(ROOT/"output/child.stderr.private.txt",stderr)
        value=json.loads(stdout);report["observation"]=value
        report["childExitCode"]=child.returncode;report["stderrBytes"]=len(stderr)
        for pipe in (child.stdout,child.stderr):
            if not pipe.closed:pipe.close()
        owner.assert_retired()
    report["custody"]=owner.receipt()
    need(report["custody"]["passed_process_custody"] and report["custody"]["original_count"]==3
         and subprocess.Popen is original_popen and os.killpg is original_killpg,"all_original_sdk_children_retired")
    source_fence()
    for item in metadata_files:
        need(str(Path(item["nominal"]).resolve(strict=True))==item["path"]
             and list(auth.base.identity(Path(item["path"]).lstat()))==item["identity"]
             and sha(public_read(Path(item["path"]),1048576))==item["sha256"],"actual_registry_metadata_unchanged_after_sdk")
    closed_names=[(name,tuple(item["expected"])) for source_guard in (source,registry_guard)
                  for name,item in source_guard.files.items()]
    closed_absences=[name for source_guard in (source,registry_guard) for name in source_guard.absent]
    registry_guard.close()
    need(registry_guard.public()["allOwnedDescriptorsClosed"],"all_original_registry_guard_descriptors_closed")
    source.close()
    need(source.public()["allOwnedDescriptorsClosed"],"all_original_sdk_source_descriptors_closed")
    for name,expected in closed_names:
        remaining();need(tuple(auth.base.identity(Path(name).lstat()))==expected,"closed_source_full9_exact")
    for name in closed_absences:
        remaining()
        try:Path(name).lstat()
        except FileNotFoundError:continue
        raise RuntimeError("closed_source_absence_changed")
    for item in metadata_files:
        remaining();need(str(Path(item["nominal"]).resolve(strict=True))==item["path"]
            and list(auth.base.identity(Path(item["path"]).lstat()))==item["identity"],"closed_metadata_namespace_exact")
    report["closedSourceNamesAndAbsencesReverified"]=True
    need(child.returncode==0 and value.get("ok") is True and not stderr,"actual_sdk_owner_observation_complete")
    for name,pin in PINS.items():need(sha(public_read(QUAL/"qa"/name))==pin,"qualified_sources_unchanged_after")
    need(public_pin(node_pin["path"],256*1024*1024)==node_pin,"same_node_runtime_after")
    need(public_read(ROOT/"code/owner_read.mjs")==PAYLOAD["worker"].encode()
         and public_read(ROOT/"code/authbus_sdk_read_guard.mjs")==PAYLOAD["guard"].encode(),"same_sdk_read_guard_sources_after")
    remaining()
    report.update(ok=True,currentConfigAndAllFiveSourceGenerationsStillExact=True,
        originalDeadlineAfterClosure=True,sourcePins=PINS,sdkPins=PAYLOAD["sdkPins"],
        workerSourceSha256=sha(PAYLOAD["worker"].encode()),guardSourceSha256=sha(PAYLOAD["guard"].encode()),
        sandboxProfileSha256=sha(policy.encode()),privateOwnerMappingRoot=str(ROOT/"output"),
        sdkTransitiveDependencyClosureClaimed=False,actualRegistryGenerationStillExact=True,
        registeredMetadataFilesVerified=len(metadata_files),registryReaderSourceSha256=sha(PAYLOAD["registryChild"].encode()),
        privateSelectedCredentialCapsule=str(ROOT/"output/selected-owner-credentials.private.json"),
        privateSelectedCredentialCapsuleQualified=True,providerValidityQualified=False)
except BaseException as error:
    report["errorType"]=type(error).__name__
    if isinstance(error,RuntimeError):report["errorCode"]=str(error)
finally:
    if child is not None:
        for pipe in (child.stdout,child.stderr):
            if pipe is not None and not pipe.closed:pipe.close()
    if owner is not None:report["custody"]=owner.receipt()
    if source is not None:
        source.close();report["sourceGuardClosure"]=source.public()
    if registry_guard is not None:
        registry_guard.close()
        rp=registry_guard.public()
        report["registryGuardClosure"]={key:rp[key] for key in
            ("allOwnedDescriptorsClosed","allHeldDescriptorsClosed","allReturnedConnectionsClosed",
             "allExplicitCursorsClosed","allPublicCodeDescriptorsClosed","closeErrors")}
    report["elapsedSeconds"]=round(time.monotonic()-START,6)
    if created:
        try:private(ROOT/"result.public.json",json.dumps(report,sort_keys=True).encode()+b"\n")
        except BaseException:report["ok"]=False
    print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report["ok"] else 1)
