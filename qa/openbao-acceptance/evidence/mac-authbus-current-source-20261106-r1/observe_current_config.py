#!/usr/bin/env python3
"""Create-only owner for one current registered-profile configuration observation."""
import hashlib,json,os,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+45.0
ROOT=Path("/Users/qianqi/heptabao-authbus-current-source-20261106-r1")
QUAL=Path("/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r1")
PYTHON="/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
PAYLOAD=json.loads("{\"child\":\"#!/usr/bin/env python3\\n\\\"\\\"\\\"One current config observation; no SQLite or credential-source read.\\\"\\\"\\\"\\nfrom __future__ import annotations\\nimport contextlib, errno, hashlib, json, os, socket, sys, time\\nfrom pathlib import Path\\nSTART=time.monotonic()\\nROOT=Path(\\\"/Users/qianqi/heptabao-authbus-current-source-20261106-r1\\\")\\nQUAL=Path(\\\"/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r1\\\")\\nsys.path.insert(0,str(QUAL/\\\"qa\\\"))\\nimport authbus_current_auth_wal as auth\\nuntil=float(sys.argv[1])\\nreport={\\\"schema\\\":\\\"heptabao.authbus-current-config-allowlist-observation.r1\\\",\\\"ok\\\":False,\\n        \\\"productionConfigurationChanged\\\":False,\\\"credentialDatabaseOpened\\\":False,\\n        \\\"providerCalled\\\":False,\\\"refreshDispatched\\\":False,\\\"j3160Contacted\\\":False,\\n        \\\"credentialValuesOrDigestsIncluded\\\":False,\\\"rawClientConfigHashIncluded\\\":False,\\n        \\\"profileIdsPublished\\\":False,\\\"privateAllowlistPublished\\\":False,\\n        \\\"activeGatewayCredentialBindingProven\\\":False,\\\"currentCredentialProviderValidated\\\":False,\\n        \\\"kernelDenials\\\":[]}\\ninputs=None\\ndef need(value,code):\\n    if not value:raise RuntimeError(code)\\ndef private(path,value):\\n    raw=(json.dumps(value,sort_keys=True,separators=(\\\",\\\",\\\":\\\"))+\\\"\\\\n\\\").encode()\\n    need(len(raw)<=262144,\\\"bounded_private_allowlist\\\")\\n    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\\n    try:\\n        with os.fdopen(fd,\\\"wb\\\",closefd=False) as stream:\\n            stream.write(raw);stream.flush();os.fsync(fd)\\n    finally:os.close(fd)\\n    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\\n    try:os.fsync(directory)\\n    finally:os.close(directory)\\ntry:\\n    need(time.monotonic()<until<=START+45,\\\"one_original_config_deadline\\\")\\n    for name,path,flags in (\\n        (\\\"owned_probe_write\\\",ROOT/\\\"write-fence\\\",os.O_WRONLY),\\n        (\\\"owned_sidecar_create\\\",ROOT/\\\"write-fence-sidecar\\\",os.O_WRONLY|os.O_CREAT|os.O_EXCL)):\\n        try:fd=os.open(path,flags,0o600)\\n        except OSError as error:\\n            need(error.errno in (errno.EACCES,errno.EPERM),\\\"kernel_write_refusal\\\")\\n            report[\\\"kernelDenials\\\"].append({\\\"case\\\":name,\\\"denied\\\":True,\\\"errno\\\":error.errno})\\n        else:os.close(fd);raise RuntimeError(\\\"kernel_write_allowed\\\")\\n    sock=None\\n    try:\\n        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM);sock.settimeout(0.25)\\n        sock.connect((\\\"127.0.0.1\\\",9))\\n    except OSError as error:\\n        need(error.errno in (errno.EACCES,errno.EPERM),\\\"kernel_network_refusal\\\")\\n        report[\\\"kernelDenials\\\"].append({\\\"case\\\":\\\"loopback_connect\\\",\\\"denied\\\":True,\\\"errno\\\":error.errno})\\n    else:raise RuntimeError(\\\"kernel_network_allowed\\\")\\n    finally:\\n        if sock is not None:sock.close()\\n    inputs=auth.AuthInputs(until=until,critical=contextlib.nullcontext,cancelled=lambda:False)\\n    path=auth.LIVE/\\\"openclaw.json\\\"\\n    raw=inputs.read(path)\\n    cfg=auth.strict_json(raw)\\n    need(isinstance(cfg,dict),\\\"current_config_object\\\")\\n    agents=cfg.get(\\\"agents\\\",{}).get(\\\"list\\\")\\n    need(isinstance(agents,list) and [item.get(\\\"id\\\") for item in agents]==list(auth.base.AGENTS),\\n         \\\"same_five_registered_agents\\\")\\n    private_agents=[];model_counts={}\\n    defaults=cfg.get(\\\"agents\\\",{}).get(\\\"defaults\\\",{})\\n    for agent in agents:\\n        name=agent[\\\"id\\\"];directory=auth.LIVE/\\\"agents\\\"/name/\\\"agent\\\"\\n        need(Path(agent.get(\\\"agentDir\\\",directory))==directory,\\\"registered_agent_directory\\\")\\n        selected=agent.get(\\\"model\\\",defaults.get(\\\"model\\\"))\\n        model=selected.get(\\\"primary\\\") if isinstance(selected,dict) else selected\\n        provider=model.split(\\\"/\\\",1)[0] if isinstance(model,str) and \\\"/\\\" in model else None\\n        category=provider if provider in (\\\"openai\\\",\\\"openai-codex\\\",\\\"anthropic\\\",\\\"google\\\",\\\"ollama\\\") else \\\"other\\\"\\n        model_counts[category]=model_counts.get(category,0)+1\\n        private_agents.append({\\\"agent\\\":name,\\\"agentDir\\\":str(directory),\\\"declaredModel\\\":selected})\\n    auth_config=cfg.get(\\\"auth\\\",{})\\n    need(isinstance(auth_config,dict),\\\"auth_config_object\\\")\\n    profiles=auth_config.get(\\\"profiles\\\",{})\\n    need(isinstance(profiles,dict) and len(profiles)<=128,\\\"bounded_current_profile_registration\\\")\\n    registered=[];provider_counts={};oauth_count=0\\n    for profile,definition in profiles.items():\\n        need(isinstance(profile,str) and 1<=len(profile)<=256 and isinstance(definition,dict),\\n             \\\"registered_profile_shape\\\")\\n        provider=definition.get(\\\"provider\\\")\\n        mode=definition.get(\\\"mode\\\",definition.get(\\\"type\\\"))\\n        need(isinstance(provider,str) and 1<=len(provider)<=80\\n             and (mode is None or isinstance(mode,str) and len(mode)<=80),\\n             \\\"registered_profile_provider_mode\\\")\\n        registered.append({\\\"profileId\\\":profile,\\\"provider\\\":provider,\\\"mode\\\":mode})\\n        category=provider if provider in (\\\"openai\\\",\\\"openai-codex\\\",\\\"anthropic\\\",\\\"google\\\",\\\"ollama\\\") else \\\"other\\\"\\n        provider_counts[category]=provider_counts.get(category,0)+1\\n        oauth_count+=mode==\\\"oauth\\\"\\n    inputs.verify()\\n    plugin=cfg.get(\\\"plugins\\\",{}).get(\\\"entries\\\",{}).get(\\\"openclaw-authbus\\\",{})\\n    connection=plugin.get(\\\"config\\\",{}) if isinstance(plugin,dict) else {}\\n    from urllib.parse import urlsplit\\n    address=connection.get(\\\"address\\\",\\\"\\\")\\n    hostname=urlsplit(address).hostname if isinstance(address,str) else None\\n    binding={\\\"schema\\\":\\\"heptabao.authbus-current-source-allowlist.private.r1\\\",\\n             \\\"sourceHost\\\":\\\"mac\\\",\\\"sourceRoot\\\":str(auth.LIVE),\\\"capturedWallNs\\\":time.time_ns(),\\n             \\\"configurationIdentity\\\":list(inputs.files[str(path)][\\\"expected\\\"]),\\n             \\\"configurationSha256\\\":hashlib.sha256(raw).hexdigest(),\\n             \\\"registrationSource\\\":\\\"current-config-auth-profiles\\\",\\n             \\\"registeredProfiles\\\":registered,\\\"agents\\\":private_agents,\\n             \\\"credentialDatabaseRead\\\":False,\\\"sourceGenerationCaptured\\\":False,\\n             \\\"activeGatewayBindingProven\\\":False,\\\"providerValidationPerformed\\\":False,\\n             \\\"refreshOwnerProven\\\":False,\\\"productionCutoverAuthorizedByThisArtifact\\\":False}\\n    private(ROOT/\\\"output/current-source-binding.private.json\\\",binding)\\n    inputs.verify()\\n    report.update(configAgentCount=len(agents),allFiveAgentPathsMatched=True,\\n        authProfileRegistrationCount=len(registered),oauthRegistrationCount=oauth_count,\\n        registrationProviderCounts=provider_counts,declaredModelProviderCounts=model_counts,\\n        currentAuthBusEnabled=plugin.get(\\\"enabled\\\") is True if isinstance(plugin,dict) else False,\\n        currentAuthBusEndpointStillJ3160=hostname in (\\\"j3160\\\",\\\"100.66.117.33\\\"),\\n        registrationSource=\\\"current-config-auth-profiles\\\",\\n        currentPrivateAllowlistNonempty=bool(registered),privateAllowlistPublished=True,\\n        sourceConfigurationUnchangedThroughPrivatePublication=True)\\n    inputs.close()\\n    need(inputs.public()[\\\"allOwnedDescriptorsClosed\\\"],\\\"all_original_config_descriptors_closed\\\")\\n    need(time.monotonic()<until,\\\"original_config_deadline_after_closure\\\")\\n    report[\\\"ok\\\"]=True\\nexcept BaseException as error:\\n    report[\\\"errorType\\\"]=type(error).__name__\\n    if isinstance(error,(RuntimeError,auth.base.CaptureRefused)):report[\\\"errorCode\\\"]=str(error)\\nfinally:\\n    if inputs is not None:\\n        inputs.close()\\n        report[\\\"resourceClosure\\\"]=inputs.public()\\n    report[\\\"elapsedSeconds\\\"]=round(time.monotonic()-START,6)\\n    print(json.dumps(report,sort_keys=True))\\nraise SystemExit(0 if report[\\\"ok\\\"] else 1)\\n\",\"qualification\":{\"at_unix_ms\":1793974032929,\"audit_recorded\":true,\"automatic_retry\":false,\"cancelled\":false,\"exit_code\":0,\"job_id\":\"1a1b12f53ba-fc05-76b3\",\"launch_nonce\":\"9f4455cc50a48f852a9718351c67d9e5\",\"log_bytes\":{\"stderr\":{\"seen\":0,\"stored\":0},\"stdout\":{\"seen\":31967,\"stored\":31967}},\"log_errors\":{\"stderr\":null,\"stdout\":null},\"log_synced\":{\"stderr\":true,\"stdout\":true},\"log_truncated\":{\"stderr\":false,\"stdout\":false},\"output_complete\":true,\"output_durable\":true,\"state\":\"succeeded\",\"terminal_publication_confirmed\":true,\"terminal_publication_protocol\":1,\"timed_out\":false}}")
PINS={
"authbus_current_auth_wal.py":"e125a1626e1293a682e63ee426926695ec74c4d23eab715c7cc1b64b1a4575e0",
"mac_guarded_current_capture_r3.py":"606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693",
"mac_registry_readonly_wal_r1.py":"60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed",
"kv2_dr_process_custody.py":"669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008",
"owned_process.py":"0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0"}
report={"schema":"heptabao.mac-authbus-current-config-owned-observation.r1","ok":False,
"productionConfigurationChanged":False,"credentialDatabaseOpened":False,
"providerCalled":False,"refreshDispatched":False,"j3160Contacted":False,
"credentialValuesOrDigestsIncluded":False,"rawClientConfigHashIncluded":False,
"profileIdsPublished":False,"serviceActions":0,"sharedSeconds":45,"supervisorSeconds":70,
"applicationRetries":0,"candidateCommit":"4bde9aee03fcd27c59e13607e529b1cee594b249",
"candidateTree":"f08493a23f8ea0637073651231865ea9607b790e",
"productBinaryExecuted":False}
owner=None;child=None;created=False
def need(value,code):
    if not value:raise RuntimeError(code)
def sha(data):return hashlib.sha256(data).hexdigest()
def remaining(cap=45):
    value=UNTIL-time.monotonic();need(value>0,"original_config_outer_deadline")
    return min(value,cap)
def read(path,cap=1024*1024):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=cap,"bounded_public_source")
        data=b""
        while len(data)<=cap:
            chunk=os.read(fd,min(65536,cap+1-len(data)))
            if not chunk:break
            data+=chunk
        key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(len(data)==before.st_size and key(before)==key(os.fstat(fd))==key(os.lstat(path)),"same_public_source")
        return data
    finally:os.close(fd)
def private(path,data):
    raw=data if isinstance(data,bytes) else data.encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parent)
    finally:os.close(parent)
try:
    os.umask(0o077)
    need(sys.platform=="darwin" and os.getuid()==501 and os.path.realpath(sys.executable)==PYTHON,"exact_mac_python_owner")
    authority=PAYLOAD["qualification"]
    need(authority["job_id"]=="1a1b12f53ba-fc05-76b3" and authority["state"]=="succeeded"
         and authority["exit_code"]==0 and not authority["timed_out"] and not authority["cancelled"]
         and all(authority[k] is True for k in ("output_complete","output_durable","terminal_publication_confirmed")),
         "actual_auth_wal_authoritative_qualification")
    proof_raw=read(QUAL/"result.public.json",65536)
    need(len(proof_raw)==31967 and sha(proof_raw)=="0cfe1f4614fd0d309a27215431464e1b00e09b38f9a075f22e0ca8568ccb4713",
         "exact_actual_auth_wal_qualification_stdout")
    proof=json.loads(proof_raw)
    need(proof["ok"] and proof["allCasesMatched"] and proof["allOwnedClosed"]
         and proof["originalDeadlineAfterClosure"] and not proof["productionInputsRead"]
         and proof["custody"]["passed_process_custody"] and proof["custody"]["original_count"]==10,
         "complete_same_source_wal_qualification")
    for name,pin in PINS.items():need(sha(read(QUAL/"qa"/name))==pin,"same_qualified_source")
    need(sha(read(Path(PYTHON),16*1024*1024))==proof["runtime"]["pythonExecutableSha256"],"same_python_runtime")
    ROOT.mkdir(mode=0o700,exist_ok=False);created=True
    (ROOT/"code").mkdir(mode=0o700);(ROOT/"output").mkdir(mode=0o700)
    private(ROOT/"code/current_config.py",PAYLOAD["child"]);private(ROOT/"write-fence","owned kernel fence\n")
    source=Path("/Users/qianqi/.openclaw/openclaw.json")
    paths={ROOT,ROOT/"code",ROOT/"output",ROOT/"write-fence",QUAL,QUAL/"qa",source}
    paths.update(source.parents);paths.update(ROOT.parents);paths.update(QUAL.parents)
    lines=["(version 1)","(deny default)","(allow process*)","(allow signal (target children))",
           "(allow sysctl-read)","(allow mach-lookup)","(allow file-read-metadata)"]
    for p in ("/System","/usr","/bin","/sbin","/Library","/private/etc","/opt/homebrew","/dev/fd"):
        lines.append("(allow file-read* (subpath "+json.dumps(p)+"))")
    for p in (QUAL/"qa",ROOT/"code",ROOT/"output"):
        lines.append("(allow file-read* (subpath "+json.dumps(str(p))+"))")
    for p in sorted(paths,key=str):lines.append("(allow file-read* (literal "+json.dumps(str(p))+"))")
    for p in ("/dev/null","/dev/urandom","/dev/random"):
        lines.append("(allow file-read* (literal "+json.dumps(p)+"))")
    lines.append("(allow file-write* (subpath "+json.dumps(str(ROOT/"output"))+"))")
    lines.append('(allow file-write* (literal "/dev/null"))')
    policy="\n".join(lines)+"\n";private(ROOT/"config-reader.sb",policy)
    sys.path.insert(0,str(QUAL/"qa"))
    import _sqlite3,kv2_dr_process_custody as custody
    need(sha(read(Path(_sqlite3.__file__),16*1024*1024))==proof["runtime"]["sqliteExtensionSha256"],"same_sqlite_extension")
    original_popen=subprocess.Popen;original_killpg=os.killpg
    with custody.activated() as owner:
        child=subprocess.Popen(["/usr/bin/sandbox-exec","-f",str(ROOT/"config-reader.sb"),PYTHON,
            "-I","-S","-B",str(ROOT/"code/current_config.py"),str(UNTIL)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,
            env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","PYTHONDONTWRITEBYTECODE":"1"})
        stdout,stderr=child.communicate(timeout=remaining(30))
        need(len(stdout)<=32768 and len(stderr)<=16384,"bounded_current_config_public_output")
        private(ROOT/"child.stdout.public.json",stdout);private(ROOT/"child.stderr.txt",stderr)
        value=json.loads(stdout);report["observation"]=value
        report["childExitCode"]=child.returncode;report["stderrBytes"]=len(stderr)
        need(child.returncode==0 and value.get("ok") is True and not stderr,"current_config_observation_complete")
        for pipe in (child.stdout,child.stderr):
            if not pipe.closed:pipe.close()
        owner.assert_retired()
    report["custody"]=owner.receipt()
    need(report["custody"]["passed_process_custody"] and report["custody"]["original_count"]==1
         and subprocess.Popen is original_popen and os.killpg is original_killpg,"original_current_config_child_retired")
    for name,pin in PINS.items():need(sha(read(QUAL/"qa"/name))==pin,"qualified_sources_unchanged_after")
    need(read(ROOT/"code/current_config.py")==PAYLOAD["child"].encode(),"current_config_source_unchanged")
    need(sha(read(Path(PYTHON),16*1024*1024))==proof["runtime"]["pythonExecutableSha256"]
         and sha(read(Path(_sqlite3.__file__),16*1024*1024))==proof["runtime"]["sqliteExtensionSha256"],
         "runtime_unchanged_after")
    remaining()
    report.update(ok=True,sourcePins=PINS,childSourceSha256=sha(PAYLOAD["child"].encode()),
                  sandboxProfileSha256=sha(policy.encode()),
                  privateBindingPath=str(ROOT/"output/current-source-binding.private.json"),
                  originalDeadlineAfterClosure=True)
except BaseException as error:
    report["errorType"]=type(error).__name__
    if isinstance(error,RuntimeError):report["errorCode"]=str(error)
finally:
    if child is not None:
        for pipe in (child.stdout,child.stderr):
            if pipe is not None and not pipe.closed:pipe.close()
    if owner is not None:report["custody"]=owner.receipt()
    report["elapsedSeconds"]=round(time.monotonic()-START,6)
    if created:
        try:private(ROOT/"result.public.json",json.dumps(report,sort_keys=True).encode()+b"\n")
        except BaseException:report["ok"]=False
    print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report["ok"] else 1)
