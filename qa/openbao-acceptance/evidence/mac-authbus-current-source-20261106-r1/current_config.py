#!/usr/bin/env python3
"""One current config observation; no SQLite or credential-source read."""
from __future__ import annotations
import contextlib, errno, hashlib, json, os, socket, sys, time
from pathlib import Path
START=time.monotonic()
ROOT=Path("/Users/qianqi/heptabao-authbus-current-source-20261106-r1")
QUAL=Path("/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r1")
sys.path.insert(0,str(QUAL/"qa"))
import authbus_current_auth_wal as auth
until=float(sys.argv[1])
report={"schema":"heptabao.authbus-current-config-allowlist-observation.r1","ok":False,
        "productionConfigurationChanged":False,"credentialDatabaseOpened":False,
        "providerCalled":False,"refreshDispatched":False,"j3160Contacted":False,
        "credentialValuesOrDigestsIncluded":False,"rawClientConfigHashIncluded":False,
        "profileIdsPublished":False,"privateAllowlistPublished":False,
        "activeGatewayCredentialBindingProven":False,"currentCredentialProviderValidated":False,
        "kernelDenials":[]}
inputs=None
def need(value,code):
    if not value:raise RuntimeError(code)
def private(path,value):
    raw=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
    need(len(raw)<=262144,"bounded_private_allowlist")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as stream:
            stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)
try:
    need(time.monotonic()<until<=START+45,"one_original_config_deadline")
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
    inputs=auth.AuthInputs(until=until,critical=contextlib.nullcontext,cancelled=lambda:False)
    path=auth.LIVE/"openclaw.json"
    raw=inputs.read(path)
    cfg=auth.strict_json(raw)
    need(isinstance(cfg,dict),"current_config_object")
    agents=cfg.get("agents",{}).get("list")
    need(isinstance(agents,list) and [item.get("id") for item in agents]==list(auth.base.AGENTS),
         "same_five_registered_agents")
    private_agents=[];model_counts={}
    defaults=cfg.get("agents",{}).get("defaults",{})
    for agent in agents:
        name=agent["id"];directory=auth.LIVE/"agents"/name/"agent"
        need(Path(agent.get("agentDir",directory))==directory,"registered_agent_directory")
        selected=agent.get("model",defaults.get("model"))
        model=selected.get("primary") if isinstance(selected,dict) else selected
        provider=model.split("/",1)[0] if isinstance(model,str) and "/" in model else None
        category=provider if provider in ("openai","openai-codex","anthropic","google","ollama") else "other"
        model_counts[category]=model_counts.get(category,0)+1
        private_agents.append({"agent":name,"agentDir":str(directory),"declaredModel":selected})
    auth_config=cfg.get("auth",{})
    need(isinstance(auth_config,dict),"auth_config_object")
    profiles=auth_config.get("profiles",{})
    need(isinstance(profiles,dict) and len(profiles)<=128,"bounded_current_profile_registration")
    registered=[];provider_counts={};oauth_count=0
    for profile,definition in profiles.items():
        need(isinstance(profile,str) and 1<=len(profile)<=256 and isinstance(definition,dict),
             "registered_profile_shape")
        provider=definition.get("provider")
        mode=definition.get("mode",definition.get("type"))
        need(isinstance(provider,str) and 1<=len(provider)<=80
             and (mode is None or isinstance(mode,str) and len(mode)<=80),
             "registered_profile_provider_mode")
        registered.append({"profileId":profile,"provider":provider,"mode":mode})
        category=provider if provider in ("openai","openai-codex","anthropic","google","ollama") else "other"
        provider_counts[category]=provider_counts.get(category,0)+1
        oauth_count+=mode=="oauth"
    inputs.verify()
    plugin=cfg.get("plugins",{}).get("entries",{}).get("openclaw-authbus",{})
    connection=plugin.get("config",{}) if isinstance(plugin,dict) else {}
    from urllib.parse import urlsplit
    address=connection.get("address","")
    hostname=urlsplit(address).hostname if isinstance(address,str) else None
    binding={"schema":"heptabao.authbus-current-source-allowlist.private.r1",
             "sourceHost":"mac","sourceRoot":str(auth.LIVE),"capturedWallNs":time.time_ns(),
             "configurationIdentity":list(inputs.files[str(path)]["expected"]),
             "configurationSha256":hashlib.sha256(raw).hexdigest(),
             "registrationSource":"current-config-auth-profiles",
             "registeredProfiles":registered,"agents":private_agents,
             "credentialDatabaseRead":False,"sourceGenerationCaptured":False,
             "activeGatewayBindingProven":False,"providerValidationPerformed":False,
             "refreshOwnerProven":False,"productionCutoverAuthorizedByThisArtifact":False}
    private(ROOT/"output/current-source-binding.private.json",binding)
    inputs.verify()
    report.update(configAgentCount=len(agents),allFiveAgentPathsMatched=True,
        authProfileRegistrationCount=len(registered),oauthRegistrationCount=oauth_count,
        registrationProviderCounts=provider_counts,declaredModelProviderCounts=model_counts,
        currentAuthBusEnabled=plugin.get("enabled") is True if isinstance(plugin,dict) else False,
        currentAuthBusEndpointStillJ3160=hostname in ("j3160","100.66.117.33"),
        registrationSource="current-config-auth-profiles",
        currentPrivateAllowlistNonempty=bool(registered),privateAllowlistPublished=True,
        sourceConfigurationUnchangedThroughPrivatePublication=True)
    inputs.close()
    need(inputs.public()["allOwnedDescriptorsClosed"],"all_original_config_descriptors_closed")
    need(time.monotonic()<until,"original_config_deadline_after_closure")
    report["ok"]=True
except BaseException as error:
    report["errorType"]=type(error).__name__
    if isinstance(error,(RuntimeError,auth.base.CaptureRefused)):report["errorCode"]=str(error)
finally:
    if inputs is not None:
        inputs.close()
        report["resourceClosure"]=inputs.public()
    report["elapsedSeconds"]=round(time.monotonic()-START,6)
    print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report["ok"] else 1)
