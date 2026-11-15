#!/usr/bin/env python3
"""Capture only the current installed-plugin registry row for SDK alias inspection."""
from __future__ import annotations
import contextlib, errno, hashlib, json, os, socket, stat, sys, time
from pathlib import Path
START=time.monotonic()
ROOT=Path("/Users/qianqi/heptabao-authbus-current-sdk-capsule-20261106-r2")
QUAL=Path("/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2")
BINDING=Path("/Users/qianqi/heptabao-authbus-current-source-20261106-r1/output/current-source-binding.private.json")
sys.path.insert(0,str(QUAL/"qa"))
import authbus_current_auth_wal as auth
wal=auth.wal
until=float(sys.argv[1])
report={"schema":"heptabao.authbus-current-sdk-registry-observation.r2","ok":False,
"productionConfigurationChanged":False,"productionDatabaseChanged":False,
"credentialDatabaseOpened":False,"credentialValuesOrDigestsIncluded":False,
"rawClientConfigHashIncluded":False,"profileIdsPublished":False,
"providerCalled":False,"refreshDispatched":False,"j3160Contacted":False,
"gatewayCredentialBindingProven":False,"actualSdkBehaviorQualified":False,
"registryPrivateProjectionPublished":False,"wholeDatabaseCopied":False,"kernelDenials":[]}
guard=None;inputs=None;private_bytes=0
def need(value,code):
    if not value:raise RuntimeError(code)
def remaining():
    need(time.monotonic()<until,"one_original_registry_observation_deadline")
def read_private(path,cap=262144):
    need(path==BINDING,"exact_original_private_allowlist_path")
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
def private(path,value):
    global private_bytes
    raw=auth.base.encoded(value);private_bytes+=len(raw)
    need(private_bytes<=4*1024*1024,"original_combined_private_capsule_bound")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)

def closure(value):
    return {key:value[key] for key in (
        "allOwnedDescriptorsClosed","allHeldDescriptorsClosed","allReturnedConnectionsClosed",
        "allExplicitCursorsClosed","allPublicCodeDescriptorsClosed","closeErrors","allHeldNamesVerified")
        if key in value}
try:
    os.umask(0o077)
    need(time.monotonic()<until<=START+45,"one_original_registry_observation_deadline")
    for name,path,flags in (
        ("owned_probe_write",ROOT/"write-fence",os.O_WRONLY),
        ("owned_sidecar_create",ROOT/"write-fence-sidecar",os.O_WRONLY|os.O_CREAT|os.O_EXCL)):
        try:fd=os.open(path,flags,0o600)
        except OSError as error:
            need(error.errno in (errno.EACCES,errno.EPERM),"kernel_write_refusal")
            report["kernelDenials"].append({"case":name,"denied":True,"errno":error.errno})
        else:os.close(fd);raise RuntimeError("kernel_write_allowed")
    sock=None
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM);sock.settimeout(0.25)
        sock.connect(("127.0.0.1",9))
    except OSError as error:
        need(error.errno in (errno.EACCES,errno.EPERM),"kernel_network_refusal")
        report["kernelDenials"].append({"case":"loopback_connect","denied":True,"errno":error.errno})
    else:raise RuntimeError("kernel_network_allowed")
    finally:
        if sock is not None:sock.close()
    binding=auth.strict_json(read_private(BINDING))
    need(binding.get("schema")=="heptabao.authbus-current-source-allowlist.private.r1"
         and binding.get("sourceHost")=="mac" and binding.get("sourceRoot")==str(auth.LIVE),
         "actual_current_allowlist_schema")
    guard=auth.AuthInputs(until=until,critical=contextlib.nullcontext,cancelled=lambda:False)
    config_path=auth.LIVE/"openclaw.json"
    raw_config=guard.read(config_path);cfg=auth.strict_json(raw_config)
    need(hashlib.sha256(raw_config).hexdigest()==binding["configurationSha256"]
         and list(guard.files[str(config_path)]["expected"])==binding["configurationIdentity"],
         "original_current_configuration_still_exact")
    need(set(cfg.get("auth",{}).get("profiles",{}))==
         {row["profileId"] for row in binding["registeredProfiles"]},"current_registration_still_exact")
    inputs=wal.WalInputs(until=until,critical=contextlib.nullcontext,cancelled=lambda:False)
    runtime=wal.observed_runtime(inputs)
    with (ROOT/"code/registry-proof.stdout.public.json").open("rb") as proof_stream:
        proof_raw=proof_stream.read(65537)
    need(len(proof_raw)==62662,"bounded_same_original_registry_proof")
    wal.validate_wal_proof(inputs,proof_raw,"7d08a18c21a5d754ea9fbe7711e6315daf8fbd80c7b5a6937756fea7ba4d1c82",runtime)
    bundle=wal.registry_wal_database(inputs)
    registry=wal.readonly_wal_query(inputs,bundle)
    values=dict(zip(registry["columns"],registry["row"]))
    need(values.get("index_key")=="installed-plugin-index","one_fixed_registry_key")
    plugins=auth.strict_json(values["plugins_json"])
    need(isinstance(plugins,list) and 0<len(plugins)<=256,"bounded_registered_plugin_list")
    origin_counts={};shape_counts={"manifest":{},"packageJson":{},"packagePath":{},"rootDir":{}}
    def path_shape(value):
        if value is None:return "missing"
        if not isinstance(value,str):return "nonstring"
        if value=="":return "empty"
        if any(ord(char)<32 or ord(char)==127 for char in value):return "control_character"
        if len(value)>4096:return "oversize"
        return "absolute" if value.startswith("/") else "relative"
    def count(field,shape):
        shape_counts[field][shape]=shape_counts[field].get(shape,0)+1
    for item in plugins:
        need(isinstance(item,dict),"registered_plugin_object")
        category=item.get("origin") if item.get("origin") in ("bundled","global","workspace","config") else "other"
        origin_counts[category]=origin_counts.get(category,0)+1
        count("manifest",path_shape(item.get("manifestPath")))
        count("rootDir",path_shape(item.get("rootDir")))
        package=item.get("packageJson")
        count("packageJson","object" if isinstance(package,dict) else "missing" if package is None else "other")
        count("packagePath",path_shape(package.get("path") if isinstance(package,dict) else None))
    inputs.verify();wal.verify_bundle(inputs,bundle,until=until);guard.verify()
    packet={"schema":"heptabao.current-sdk-registry.private.r2","host":"mac",
            "createdWallNs":time.time_ns(),"configurationSha256":binding["configurationSha256"],
            "configurationIdentity":binding["configurationIdentity"],"registry":registry,
            "sourceIdentities":{key:list(item["expected"]) for key,item in inputs.files.items()},
            "sourceAbsences":list(inputs.absent),"publicManifestPathAdmissionDeferred":True,
            "registrationSource":"actual-current-installed-plugin-index-fixed-row",
            "constraints":{"actualSdkBehaviorQualified":False,"providerValidationPerformed":False,
                           "credentialValuesCaptured":False,"productionCutover":False}}
    private(ROOT/"output/registry.private.json",packet)
    inputs.verify();wal.verify_bundle(inputs,bundle,until=until);guard.verify()
    inputs.close();guard.close()
    need(inputs.public()["allOwnedDescriptorsClosed"] and guard.public()["allOwnedDescriptorsClosed"],
         "all_original_registry_descriptors_closed")
    report.update(ok=True,registryPrivateProjectionPublished=True,
        registrySourceUnchangedThroughPrivatePublication=True,
        currentConfigurationStillOriginal=True,installedPluginCount=len(plugins),
        installedPluginOriginCounts=origin_counts,registryPathFieldShapes=shape_counts,
        manifestPathAdmissionQualified=False,
        registryTransactionCount=1,registryDataRowCount=1,registryWalWasNonempty=True,
        registryRoute="qualified_named_readonly_wal_transaction",
        registryProofSha256="7d08a18c21a5d754ea9fbe7711e6315daf8fbd80c7b5a6937756fea7ba4d1c82",
        queryBudgetSeconds=3,privateProjectionBytes=private_bytes,
        authProfileRowsRead=0,sharedSeconds=45,registryRuntime=runtime)
    remaining()
except BaseException as error:
    report["errorType"]=type(error).__name__
    if isinstance(error,(RuntimeError,auth.base.CaptureRefused)):report["errorCode"]=str(error)
finally:
    if inputs is not None:
        inputs.close();report["registryClosure"]=closure(inputs.public())
        report["registryConnectionAttemptCount"]=len(inputs.connect_attempts)
        report["registryReturnedConnectionCount"]=len(inputs.connections)
        report["registryCursorCount"]=len(inputs.cursors)
        report["queryLedger"]=[dict(row) for row in inputs.queries]
    if guard is not None:
        guard.close();report["configResourceClosure"]=closure(guard.public())
    report["elapsedSeconds"]=round(time.monotonic()-START,6)
    print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report["ok"] else 1)
