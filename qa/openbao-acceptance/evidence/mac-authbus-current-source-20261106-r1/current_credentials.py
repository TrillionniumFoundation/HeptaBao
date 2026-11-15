#!/usr/bin/env python3
"""One bounded current registered-profile capture; all credential values stay private."""
from __future__ import annotations
import contextlib, errno, hashlib, json, math, os, socket, stat, sys, time
from pathlib import Path
START=time.monotonic()
ROOT=Path("/Users/qianqi/heptabao-authbus-current-credentials-20261106-r1")
QUAL=Path("/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2")
BINDING=Path("/Users/qianqi/heptabao-authbus-current-source-20261106-r1/output/current-source-binding.private.json")
sys.path.insert(0,str(QUAL/"qa"))
import authbus_current_auth_wal as auth
until=float(sys.argv[1])
report={"schema":"heptabao.authbus-current-registered-credential-capture.r1","ok":False,
"productionConfigurationChanged":False,"productionDatabaseChanged":False,
"credentialValuesOrDigestsIncluded":False,"rawClientConfigHashIncluded":False,
"profileIdsPublished":False,"providerCalled":False,"refreshDispatched":False,
"j3160Contacted":False,"gatewayCredentialBindingProven":False,
"actualSdkInheritanceProven":False,"crossAgentAtomicSnapshotClaimed":False,
"wholeDatabaseBackupQualified":False,"sourceConfigurationUnchangedThroughoutObservation":False,"captures":[],"kernelDenials":[]}
guard=None;private_bytes=0
def need(value,code):
    if not value:raise RuntimeError(code)
def remaining():
    need(time.monotonic()<until,"one_original_current_capture_deadline")
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
def profile_counts(profiles,registered):
    result={"literalAuthValuePresentCount":0,"secretReferencePresentCount":0,
            "noLiteralOrReferenceAuthValueCount":0,"oauthProfileCount":0,
            "oauthFutureDatedCount":0,"oauthExpiredCount":0,"oauthExpiryUnknownCount":0,
            "oauthRefreshFieldPresentCount":0,"declaredProviderMismatchCount":0,
            "providerValidityQualified":False,"providerUnavailableCount":None}
    now=time.time()*1000
    for key,value in profiles.items():
        literal=any(isinstance(value.get(name),str) and bool(value[name]) for name in ("key","access","token"))
        reference=any(value.get(name) is not None for name in ("keyRef","accessRef","tokenRef"))
        result["literalAuthValuePresentCount"]+=literal
        result["secretReferencePresentCount"]+=reference
        result["noLiteralOrReferenceAuthValueCount"]+=not literal and not reference
        result["declaredProviderMismatchCount"]+=value.get("provider")!=registered[key]["provider"]
        if value.get("type")=="oauth":
            result["oauthProfileCount"]+=1
            expiry=value.get("expires")
            if type(expiry) in (int,float) and math.isfinite(expiry):
                result["oauthFutureDatedCount" if expiry>now else "oauthExpiredCount"]+=1
            else:result["oauthExpiryUnknownCount"]+=1
            result["oauthRefreshFieldPresentCount"]+=isinstance(value.get("refresh"),str) and bool(value["refresh"])
    return result
try:
    os.umask(0o077)
    need(time.monotonic()<until<=START+45,"one_original_current_capture_deadline")
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
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM);sock.settimeout(0.25);sock.connect(("127.0.0.1",9))
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
    registered={item["profileId"]:item for item in binding["registeredProfiles"]}
    actual=cfg.get("auth",{}).get("profiles",{})
    need(isinstance(actual,dict) and 1<=len(actual)<=128 and set(registered)==set(actual),
         "current_registered_allowlist_complete")
    for key,value in actual.items():
        need(isinstance(value,dict) and registered[key]["provider"]==value.get("provider")
             and registered[key]["mode"]==value.get("mode",value.get("type")),
             "current_registration_metadata_exact")
    declared=cfg.get("agents",{}).get("list",[])
    need([item.get("id") for item in declared]==list(auth.base.AGENTS)
         and [item.get("agent") for item in binding["agents"]]==list(auth.base.AGENTS),
         "current_five_registered_agent_scope")
    for item in declared:
        name=item["id"]
        need(Path(item.get("agentDir",auth.LIVE/"agents"/name/"agent"))==
             auth.LIVE/"agents"/name/"agent","current_agent_directory_exact")
    report["registrationCount"]=len(registered)
    report["registeredOAuthCount"]=sum(value["mode"]=="oauth" for value in registered.values())
    aggregate=set();all_success=True
    for agent in auth.base.AGENTS:
        remaining();guard.verify()
        inputs=auth.AuthInputs(until=until,critical=contextlib.nullcontext,cancelled=lambda:False)
        started_ns=time.time_ns()
        value,public=auth.attempt_auth(inputs,agent=agent,authorized_profiles=list(registered),
                                      requested_profiles=list(registered),registered_present=True)
        row={"agent":agent,"capture":public,"directStoreCaptured":public["ok"],
             "effectiveSdkProfileCount":None,"inheritedProfileCount":None,
             "actualSdkInheritanceProven":False,"privateGenerationPublished":False}
        report["captures"].append(row)
        if value is not None and public["ok"]:
            aggregate.update(value["profiles"])
            row["credentialShapeCounts"]=profile_counts(value["profiles"],registered)
            packet={"schema":"heptabao.current-auth-registered-generation.private.r1",
                    "host":"mac","agent":agent,"capturedStartWallNs":started_ns,"capturedEndWallNs":time.time_ns(),
                    "registrationSource":"current-config-auth-profiles","configurationSha256":binding["configurationSha256"],
                    "configurationIdentity":binding["configurationIdentity"],
                    "sourceIdentities":{key:list(item["expected"]) for key,item in inputs.files.items()},
                    "sourceAbsences":list(inputs.absent),"observation":value,
                    "constraints":{"providerValidityQualified":False,"refreshOwnerProven":False,
                                   "requiresRecheckBeforePublication":True,"gatewayBindingProven":False,
                                   "crossAgentAtomicSnapshotClaimed":False}}
            private(ROOT/"output"/("credentials-"+agent+".private.json"),packet)
            row["privateGenerationPublished"]=True
        else:all_success=False
        guard.verify();remaining()
    guard.verify();guard.close()
    need(guard.public()["allOwnedDescriptorsClosed"],"original_config_guard_closed")
    report["uniqueRegisteredProfilesSeenInDirectStores"]=len(aggregate)
    report["registeredProfilesMissingFromAllDirectStores"]=len(set(registered)-aggregate)
    report["allFiveDirectStoresCaptured"]=all_success
    report["sourceConfigurationUnchangedThroughoutObservation"]=True
    report["privateCapsuleBytes"]=private_bytes
    remaining()
    report["ok"]=all_success
except BaseException as error:
    report["errorType"]=type(error).__name__
    if isinstance(error,(RuntimeError,auth.base.CaptureRefused)):report["errorCode"]=str(error)
finally:
    if guard is not None:
        guard.close();report["configResourceClosure"]=guard.public()
    report["elapsedSeconds"]=round(time.monotonic()-START,6)
    print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report["ok"] else 1)
