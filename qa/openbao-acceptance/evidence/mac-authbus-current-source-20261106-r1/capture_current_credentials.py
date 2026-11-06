#!/usr/bin/env python3
"""Create-only owner for one current registered credential-source capture."""
import hashlib,json,os,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+45.0
ROOT=Path("/Users/qianqi/heptabao-authbus-current-credentials-20261106-r1")
QUAL=Path("/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2")
PYTHON="/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
PAYLOAD=json.loads("{\"child\":\"#!/usr/bin/env python3\\n\\\"\\\"\\\"One bounded current registered-profile capture; all credential values stay private.\\\"\\\"\\\"\\nfrom __future__ import annotations\\nimport contextlib, errno, hashlib, json, math, os, socket, stat, sys, time\\nfrom pathlib import Path\\nSTART=time.monotonic()\\nROOT=Path(\\\"/Users/qianqi/heptabao-authbus-current-credentials-20261106-r1\\\")\\nQUAL=Path(\\\"/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2\\\")\\nBINDING=Path(\\\"/Users/qianqi/heptabao-authbus-current-source-20261106-r1/output/current-source-binding.private.json\\\")\\nsys.path.insert(0,str(QUAL/\\\"qa\\\"))\\nimport authbus_current_auth_wal as auth\\nuntil=float(sys.argv[1])\\nreport={\\\"schema\\\":\\\"heptabao.authbus-current-registered-credential-capture.r1\\\",\\\"ok\\\":False,\\n\\\"productionConfigurationChanged\\\":False,\\\"productionDatabaseChanged\\\":False,\\n\\\"credentialValuesOrDigestsIncluded\\\":False,\\\"rawClientConfigHashIncluded\\\":False,\\n\\\"profileIdsPublished\\\":False,\\\"providerCalled\\\":False,\\\"refreshDispatched\\\":False,\\n\\\"j3160Contacted\\\":False,\\\"gatewayCredentialBindingProven\\\":False,\\n\\\"actualSdkInheritanceProven\\\":False,\\\"crossAgentAtomicSnapshotClaimed\\\":False,\\n\\\"wholeDatabaseBackupQualified\\\":False,\\\"sourceConfigurationUnchangedThroughoutObservation\\\":False,\\\"captures\\\":[],\\\"kernelDenials\\\":[]}\\nguard=None;private_bytes=0\\ndef need(value,code):\\n    if not value:raise RuntimeError(code)\\ndef remaining():\\n    need(time.monotonic()<until,\\\"one_original_current_capture_deadline\\\")\\ndef read_private(path,cap=262144):\\n    need(path==BINDING,\\\"exact_original_private_allowlist_path\\\")\\n    parents=[];parent_fd=None;fd=None\\n    try:\\n        for current in [Path(\\\"/\\\"),*list(reversed(path.parent.parents))[1:],path.parent]:\\n            if parent_fd is None:\\n                current_fd=os.open(\\\"/\\\",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\\n            else:\\n                current_fd=os.open(current.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)\\n            info=os.fstat(current_fd)\\n            need(stat.S_ISDIR(info.st_mode) and not stat.S_IMODE(info.st_mode)&0o022,\\n                 \\\"private_allowlist_parent_custody\\\")\\n            parents.append(current_fd);parent_fd=current_fd\\n        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)\\n        before=os.fstat(fd)\\n        need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_gid==20\\n             and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and 0<before.st_size<=cap,\\n             \\\"private_allowlist_custody\\\")\\n        raw=b\\\"\\\"\\n        while len(raw)<=cap:\\n            remaining();part=os.read(fd,min(65536,cap+1-len(raw)))\\n            if not part:break\\n            raw+=part\\n        named=os.stat(path.name,dir_fd=parent_fd,follow_symlinks=False)\\n        need(len(raw)==before.st_size and auth.base.identity(before)==auth.base.identity(os.fstat(fd))\\n             ==auth.base.identity(named),\\\"private_allowlist_unchanged\\\")\\n        return raw\\n    finally:\\n        if fd is not None:os.close(fd)\\n        for item in reversed(parents):os.close(item)\\ndef private(path,value):\\n    global private_bytes\\n    raw=auth.base.encoded(value);private_bytes+=len(raw)\\n    need(private_bytes<=4*1024*1024,\\\"original_combined_private_capsule_bound\\\")\\n    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\\n    try:\\n        with os.fdopen(fd,\\\"wb\\\",closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(fd)\\n    finally:os.close(fd)\\n    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\\n    try:os.fsync(directory)\\n    finally:os.close(directory)\\ndef profile_counts(profiles,registered):\\n    result={\\\"literalAuthValuePresentCount\\\":0,\\\"secretReferencePresentCount\\\":0,\\n            \\\"noLiteralOrReferenceAuthValueCount\\\":0,\\\"oauthProfileCount\\\":0,\\n            \\\"oauthFutureDatedCount\\\":0,\\\"oauthExpiredCount\\\":0,\\\"oauthExpiryUnknownCount\\\":0,\\n            \\\"oauthRefreshFieldPresentCount\\\":0,\\\"declaredProviderMismatchCount\\\":0,\\n            \\\"providerValidityQualified\\\":False,\\\"providerUnavailableCount\\\":None}\\n    now=time.time()*1000\\n    for key,value in profiles.items():\\n        literal=any(isinstance(value.get(name),str) and bool(value[name]) for name in (\\\"key\\\",\\\"access\\\",\\\"token\\\"))\\n        reference=any(value.get(name) is not None for name in (\\\"keyRef\\\",\\\"accessRef\\\",\\\"tokenRef\\\"))\\n        result[\\\"literalAuthValuePresentCount\\\"]+=literal\\n        result[\\\"secretReferencePresentCount\\\"]+=reference\\n        result[\\\"noLiteralOrReferenceAuthValueCount\\\"]+=not literal and not reference\\n        result[\\\"declaredProviderMismatchCount\\\"]+=value.get(\\\"provider\\\")!=registered[key][\\\"provider\\\"]\\n        if value.get(\\\"type\\\")==\\\"oauth\\\":\\n            result[\\\"oauthProfileCount\\\"]+=1\\n            expiry=value.get(\\\"expires\\\")\\n            if type(expiry) in (int,float) and math.isfinite(expiry):\\n                result[\\\"oauthFutureDatedCount\\\" if expiry>now else \\\"oauthExpiredCount\\\"]+=1\\n            else:result[\\\"oauthExpiryUnknownCount\\\"]+=1\\n            result[\\\"oauthRefreshFieldPresentCount\\\"]+=isinstance(value.get(\\\"refresh\\\"),str) and bool(value[\\\"refresh\\\"])\\n    return result\\ntry:\\n    os.umask(0o077)\\n    need(time.monotonic()<until<=START+45,\\\"one_original_current_capture_deadline\\\")\\n    for name,path,flags in (\\n        (\\\"owned_probe_write\\\",ROOT/\\\"write-fence\\\",os.O_WRONLY),\\n        (\\\"owned_sidecar_create\\\",ROOT/\\\"write-fence-sidecar\\\",os.O_WRONLY|os.O_CREAT|os.O_EXCL)):\\n        try:fd=os.open(path,flags,0o600)\\n        except OSError as error:\\n            need(error.errno in (errno.EACCES,errno.EPERM),\\\"kernel_write_refusal\\\")\\n            report[\\\"kernelDenials\\\"].append({\\\"case\\\":name,\\\"denied\\\":True,\\\"errno\\\":error.errno})\\n        else:os.close(fd);raise RuntimeError(\\\"kernel_write_allowed\\\")\\n    sock=None\\n    try:\\n        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM);sock.settimeout(0.25);sock.connect((\\\"127.0.0.1\\\",9))\\n    except OSError as error:\\n        need(error.errno in (errno.EACCES,errno.EPERM),\\\"kernel_network_refusal\\\")\\n        report[\\\"kernelDenials\\\"].append({\\\"case\\\":\\\"loopback_connect\\\",\\\"denied\\\":True,\\\"errno\\\":error.errno})\\n    else:raise RuntimeError(\\\"kernel_network_allowed\\\")\\n    finally:\\n        if sock is not None:sock.close()\\n    binding=auth.strict_json(read_private(BINDING))\\n    need(binding.get(\\\"schema\\\")==\\\"heptabao.authbus-current-source-allowlist.private.r1\\\"\\n         and binding.get(\\\"sourceHost\\\")==\\\"mac\\\" and binding.get(\\\"sourceRoot\\\")==str(auth.LIVE),\\n         \\\"actual_current_allowlist_schema\\\")\\n    guard=auth.AuthInputs(until=until,critical=contextlib.nullcontext,cancelled=lambda:False)\\n    config_path=auth.LIVE/\\\"openclaw.json\\\"\\n    raw_config=guard.read(config_path);cfg=auth.strict_json(raw_config)\\n    need(hashlib.sha256(raw_config).hexdigest()==binding[\\\"configurationSha256\\\"]\\n         and list(guard.files[str(config_path)][\\\"expected\\\"])==binding[\\\"configurationIdentity\\\"],\\n         \\\"original_current_configuration_still_exact\\\")\\n    registered={item[\\\"profileId\\\"]:item for item in binding[\\\"registeredProfiles\\\"]}\\n    actual=cfg.get(\\\"auth\\\",{}).get(\\\"profiles\\\",{})\\n    need(isinstance(actual,dict) and 1<=len(actual)<=128 and set(registered)==set(actual),\\n         \\\"current_registered_allowlist_complete\\\")\\n    for key,value in actual.items():\\n        need(isinstance(value,dict) and registered[key][\\\"provider\\\"]==value.get(\\\"provider\\\")\\n             and registered[key][\\\"mode\\\"]==value.get(\\\"mode\\\",value.get(\\\"type\\\")),\\n             \\\"current_registration_metadata_exact\\\")\\n    declared=cfg.get(\\\"agents\\\",{}).get(\\\"list\\\",[])\\n    need([item.get(\\\"id\\\") for item in declared]==list(auth.base.AGENTS)\\n         and [item.get(\\\"agent\\\") for item in binding[\\\"agents\\\"]]==list(auth.base.AGENTS),\\n         \\\"current_five_registered_agent_scope\\\")\\n    for item in declared:\\n        name=item[\\\"id\\\"]\\n        need(Path(item.get(\\\"agentDir\\\",auth.LIVE/\\\"agents\\\"/name/\\\"agent\\\"))==\\n             auth.LIVE/\\\"agents\\\"/name/\\\"agent\\\",\\\"current_agent_directory_exact\\\")\\n    report[\\\"registrationCount\\\"]=len(registered)\\n    report[\\\"registeredOAuthCount\\\"]=sum(value[\\\"mode\\\"]==\\\"oauth\\\" for value in registered.values())\\n    aggregate=set();all_success=True\\n    for agent in auth.base.AGENTS:\\n        remaining();guard.verify()\\n        inputs=auth.AuthInputs(until=until,critical=contextlib.nullcontext,cancelled=lambda:False)\\n        started_ns=time.time_ns()\\n        value,public=auth.attempt_auth(inputs,agent=agent,authorized_profiles=list(registered),\\n                                      requested_profiles=list(registered),registered_present=True)\\n        row={\\\"agent\\\":agent,\\\"capture\\\":public,\\\"directStoreCaptured\\\":public[\\\"ok\\\"],\\n             \\\"effectiveSdkProfileCount\\\":None,\\\"inheritedProfileCount\\\":None,\\n             \\\"actualSdkInheritanceProven\\\":False,\\\"privateGenerationPublished\\\":False}\\n        report[\\\"captures\\\"].append(row)\\n        if value is not None and public[\\\"ok\\\"]:\\n            aggregate.update(value[\\\"profiles\\\"])\\n            row[\\\"credentialShapeCounts\\\"]=profile_counts(value[\\\"profiles\\\"],registered)\\n            packet={\\\"schema\\\":\\\"heptabao.current-auth-registered-generation.private.r1\\\",\\n                    \\\"host\\\":\\\"mac\\\",\\\"agent\\\":agent,\\\"capturedStartWallNs\\\":started_ns,\\\"capturedEndWallNs\\\":time.time_ns(),\\n                    \\\"registrationSource\\\":\\\"current-config-auth-profiles\\\",\\\"configurationSha256\\\":binding[\\\"configurationSha256\\\"],\\n                    \\\"configurationIdentity\\\":binding[\\\"configurationIdentity\\\"],\\n                    \\\"sourceIdentities\\\":{key:list(item[\\\"expected\\\"]) for key,item in inputs.files.items()},\\n                    \\\"sourceAbsences\\\":list(inputs.absent),\\\"observation\\\":value,\\n                    \\\"constraints\\\":{\\\"providerValidityQualified\\\":False,\\\"refreshOwnerProven\\\":False,\\n                                   \\\"requiresRecheckBeforePublication\\\":True,\\\"gatewayBindingProven\\\":False,\\n                                   \\\"crossAgentAtomicSnapshotClaimed\\\":False}}\\n            private(ROOT/\\\"output\\\"/(\\\"credentials-\\\"+agent+\\\".private.json\\\"),packet)\\n            row[\\\"privateGenerationPublished\\\"]=True\\n        else:all_success=False\\n        guard.verify();remaining()\\n    guard.verify();guard.close()\\n    need(guard.public()[\\\"allOwnedDescriptorsClosed\\\"],\\\"original_config_guard_closed\\\")\\n    report[\\\"uniqueRegisteredProfilesSeenInDirectStores\\\"]=len(aggregate)\\n    report[\\\"registeredProfilesMissingFromAllDirectStores\\\"]=len(set(registered)-aggregate)\\n    report[\\\"allFiveDirectStoresCaptured\\\"]=all_success\\n    report[\\\"sourceConfigurationUnchangedThroughoutObservation\\\"]=True\\n    report[\\\"privateCapsuleBytes\\\"]=private_bytes\\n    remaining()\\n    report[\\\"ok\\\"]=all_success\\nexcept BaseException as error:\\n    report[\\\"errorType\\\"]=type(error).__name__\\n    if isinstance(error,(RuntimeError,auth.base.CaptureRefused)):report[\\\"errorCode\\\"]=str(error)\\nfinally:\\n    if guard is not None:\\n        guard.close();report[\\\"configResourceClosure\\\"]=guard.public()\\n    report[\\\"elapsedSeconds\\\"]=round(time.monotonic()-START,6)\\n    print(json.dumps(report,sort_keys=True))\\nraise SystemExit(0 if report[\\\"ok\\\"] else 1)\\n\",\"qualification\":{\"at_unix_ms\":1793975259508,\"audit_recorded\":true,\"automatic_retry\":false,\"cancelled\":false,\"exit_code\":0,\"job_id\":\"1a1b141ef40-fc05-7750\",\"launch_nonce\":\"6ee37ff3af8195a8d1bef14099a8e948\",\"log_bytes\":{\"stderr\":{\"seen\":0,\"stored\":0},\"stdout\":{\"seen\":58701,\"stored\":58701}},\"log_errors\":{\"stderr\":null,\"stdout\":null},\"log_synced\":{\"stderr\":true,\"stdout\":true},\"log_truncated\":{\"stderr\":false,\"stdout\":false},\"output_complete\":true,\"output_durable\":true,\"state\":\"succeeded\",\"terminal_publication_confirmed\":true,\"terminal_publication_protocol\":1,\"timed_out\":false},\"configAuthority\":{\"at_unix_ms\":1793974583163,\"audit_recorded\":true,\"automatic_retry\":false,\"cancelled\":false,\"exit_code\":0,\"job_id\":\"1a1b137a21d-fc05-76f8\",\"launch_nonce\":\"a239982bdb0254dcddfc7c14f7d347b7\",\"log_bytes\":{\"stderr\":{\"seen\":0,\"stored\":0},\"stdout\":{\"seen\":5091,\"stored\":5091}},\"log_errors\":{\"stderr\":null,\"stdout\":null},\"log_synced\":{\"stderr\":true,\"stdout\":true},\"log_truncated\":{\"stderr\":false,\"stdout\":false},\"output_complete\":true,\"output_durable\":true,\"state\":\"succeeded\",\"terminal_publication_confirmed\":true,\"terminal_publication_protocol\":1,\"timed_out\":false},\"configStdout\":\"{\\\"applicationRetries\\\": 0, \\\"candidateCommit\\\": \\\"4bde9aee03fcd27c59e13607e529b1cee594b249\\\", \\\"candidateTree\\\": \\\"f08493a23f8ea0637073651231865ea9607b790e\\\", \\\"childExitCode\\\": 0, \\\"childSourceSha256\\\": \\\"2f5e9f99cab4f7c9c051507c6078b3df448d5df57cc22f8a456f8ef17fc75e20\\\", \\\"credentialDatabaseOpened\\\": false, \\\"credentialValuesOrDigestsIncluded\\\": false, \\\"custody\\\": {\\\"children\\\": [{\\\"argv_sha256\\\": \\\"86d2558a62720779244062a853d819469f82acef91e169347cdf9f795c83aab7\\\", \\\"birth\\\": {\\\"pgid\\\": 94296, \\\"pid\\\": 94296, \\\"ppid\\\": 94294, \\\"sid\\\": 94296, \\\"state\\\": \\\"R\\\", \\\"uid\\\": 501}, \\\"darwin_waitable_zombie_anchor\\\": {\\\"live_birth\\\": {\\\"pgid\\\": 94296, \\\"pid\\\": 94296, \\\"ppid\\\": 94294, \\\"sid\\\": 94296, \\\"state\\\": \\\"R\\\", \\\"uid\\\": 501}, \\\"observed\\\": {\\\"pgid\\\": 94296, \\\"pid\\\": 94296, \\\"ppid\\\": 94294, \\\"sid\\\": 94296, \\\"sid_basis\\\": \\\"admitted_immutable_unreaped_session_leader\\\", \\\"state\\\": \\\"Z\\\", \\\"uid\\\": 501}, \\\"waitid\\\": {\\\"si_code\\\": 1, \\\"si_pid\\\": 94296, \\\"si_signo\\\": 20, \\\"si_status\\\": 0, \\\"si_uid\\\": 0, \\\"si_uid_used_as_authority\\\": false}}, \\\"exec_admitted\\\": true, \\\"gaps\\\": [], \\\"members_at_leader_exit\\\": [{\\\"pgid\\\": 94296, \\\"pid\\\": 94296, \\\"ppid\\\": 94294, \\\"sid\\\": 94296, \\\"sid_basis\\\": \\\"zombie_in_original_anchored_group\\\", \\\"state\\\": \\\"Z\\\", \\\"uid\\\": 501}], \\\"members_before_original_reap\\\": [{\\\"pgid\\\": 94296, \\\"pid\\\": 94296, \\\"ppid\\\": 94294, \\\"sid\\\": 94296, \\\"sid_basis\\\": \\\"zombie_in_original_anchored_group\\\", \\\"state\\\": \\\"Z\\\", \\\"uid\\\": 501}], \\\"no_live_members_before_reap\\\": true, \\\"original_wait_completed\\\": true, \\\"original_wait_count\\\": 1, \\\"pid\\\": 94296, \\\"returncode\\\": 0, \\\"signals\\\": []}], \\\"controls\\\": [], \\\"escaped_session_containment_claim\\\": false, \\\"failed\\\": false, \\\"finished\\\": true, \\\"interrupted\\\": false, \\\"original_count\\\": 1, \\\"passed_process_custody\\\": true, \\\"platform\\\": \\\"darwin\\\", \\\"schema\\\": \\\"heptabao.dr-original-process-custody.v1\\\", \\\"storage_or_production_authority\\\": false, \\\"unreaped_original_is_signal_anchor\\\": true}, \\\"elapsedSeconds\\\": 0.096661, \\\"j3160Contacted\\\": false, \\\"observation\\\": {\\\"activeGatewayCredentialBindingProven\\\": false, \\\"allFiveAgentPathsMatched\\\": true, \\\"authProfileRegistrationCount\\\": 70, \\\"configAgentCount\\\": 5, \\\"credentialDatabaseOpened\\\": false, \\\"credentialValuesOrDigestsIncluded\\\": false, \\\"currentAuthBusEnabled\\\": true, \\\"currentAuthBusEndpointStillJ3160\\\": true, \\\"currentCredentialProviderValidated\\\": false, \\\"currentPrivateAllowlistNonempty\\\": true, \\\"declaredModelProviderCounts\\\": {\\\"openai\\\": 5}, \\\"elapsedSeconds\\\": 0.011695, \\\"j3160Contacted\\\": false, \\\"kernelDenials\\\": [{\\\"case\\\": \\\"owned_probe_write\\\", \\\"denied\\\": true, \\\"errno\\\": 1}, {\\\"case\\\": \\\"owned_sidecar_create\\\", \\\"denied\\\": true, \\\"errno\\\": 1}, {\\\"case\\\": \\\"loopback_connect\\\", \\\"denied\\\": true, \\\"errno\\\": 1}], \\\"oauthRegistrationCount\\\": 69, \\\"ok\\\": true, \\\"privateAllowlistPublished\\\": true, \\\"productionConfigurationChanged\\\": false, \\\"profileIdsPublished\\\": false, \\\"providerCalled\\\": false, \\\"rawClientConfigHashIncluded\\\": false, \\\"refreshDispatched\\\": false, \\\"registrationProviderCounts\\\": {\\\"google\\\": 1, \\\"openai\\\": 65, \\\"other\\\": 4}, \\\"registrationSource\\\": \\\"current-config-auth-profiles\\\", \\\"resourceClosure\\\": {\\\"allBundlesVerified\\\": false, \\\"allExplicitCursorsClosed\\\": true, \\\"allHeldDescriptorsClosed\\\": true, \\\"allHeldNamesVerified\\\": true, \\\"allOwnedDescriptorsClosed\\\": true, \\\"allPublicCodeDescriptorsClosed\\\": true, \\\"allReturnedConnectionsClosed\\\": true, \\\"closeErrors\\\": [], \\\"connectionAttemptCount\\\": 0, \\\"credentialValuesOrDigestsIncluded\\\": false, \\\"crossAgentAtomicSnapshotClaimed\\\": false, \\\"cursorCount\\\": 0, \\\"gatewayCredentialBindingProven\\\": false, \\\"nonprimaryRowsRead\\\": false, \\\"originalImmutableRouteInvoked\\\": false, \\\"phase\\\": \\\"auth_before_input_admission\\\", \\\"providerCalled\\\": false, \\\"queryCount\\\": 0, \\\"rawClientConfigHashIncluded\\\": false, \\\"refreshDispatched\\\": false, \\\"registryWalRouteQualifiedByThisResult\\\": false, \\\"returnedConnectionCount\\\": 0, \\\"schema\\\": \\\"heptabao.authbus-current-auth-wal-projection.r1\\\", \\\"sourceDatabaseCopied\\\": false, \\\"unselectedProfileValuesReturned\\\": false, \\\"wholeDatabaseBackupQualified\\\": false}, \\\"schema\\\": \\\"heptabao.authbus-current-config-allowlist-observation.r1\\\", \\\"sourceConfigurationUnchangedThroughPrivatePublication\\\": true}, \\\"ok\\\": true, \\\"originalDeadlineAfterClosure\\\": true, \\\"privateBindingPath\\\": \\\"/Users/qianqi/heptabao-authbus-current-source-20261106-r1/output/current-source-binding.private.json\\\", \\\"productBinaryExecuted\\\": false, \\\"productionConfigurationChanged\\\": false, \\\"profileIdsPublished\\\": false, \\\"providerCalled\\\": false, \\\"rawClientConfigHashIncluded\\\": false, \\\"refreshDispatched\\\": false, \\\"sandboxProfileSha256\\\": \\\"eeb13bffaa82e0fb9fe4c454cc9051934bd0902108f055a924de7c34dbdd53f5\\\", \\\"schema\\\": \\\"heptabao.mac-authbus-current-config-owned-observation.r1\\\", \\\"serviceActions\\\": 0, \\\"sharedSeconds\\\": 45, \\\"sourcePins\\\": {\\\"authbus_current_auth_wal.py\\\": \\\"e125a1626e1293a682e63ee426926695ec74c4d23eab715c7cc1b64b1a4575e0\\\", \\\"kv2_dr_process_custody.py\\\": \\\"669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008\\\", \\\"mac_guarded_current_capture_r3.py\\\": \\\"606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693\\\", \\\"mac_registry_readonly_wal_r1.py\\\": \\\"60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed\\\", \\\"owned_process.py\\\": \\\"0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0\\\"}, \\\"stderrBytes\\\": 0, \\\"supervisorSeconds\\\": 70}\\n\"}")
PINS={
"authbus_current_auth_wal.py":"ad443869e259da06de2be71131e5d1854680477d1cf77248e05a3c1704160f8c",
"mac_guarded_current_capture_r3.py":"606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693",
"mac_registry_readonly_wal_r1.py":"60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed",
"kv2_dr_process_custody.py":"669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008",
"owned_process.py":"0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0"}
report={"schema":"heptabao.mac-authbus-current-credentials-owned-capture.r1","ok":False,
"productionConfigurationChanged":False,"credentialDatabaseOpened":None,"credentialDatabaseOutcomeKnown":False,
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
    need(authority["job_id"]=="1a1b141ef40-fc05-7750" and authority["state"]=="succeeded"
         and authority["exit_code"]==0 and not authority["timed_out"] and not authority["cancelled"]
         and all(authority[k] is True for k in ("output_complete","output_durable","terminal_publication_confirmed")),
         "actual_auth_wal_authoritative_qualification")
    proof_raw=read(QUAL/"result.public.json",65536)
    need(len(proof_raw)==58701 and sha(proof_raw)=="67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e",
         "exact_actual_auth_wal_qualification_stdout")
    proof=json.loads(proof_raw)
    need(proof["ok"] and proof["allCasesMatched"] and proof["allOwnedClosed"]
         and proof["originalDeadlineAfterClosure"] and not proof["productionInputsRead"]
         and proof["custody"]["passed_process_custody"] and proof["custody"]["original_count"]==18,
         "complete_same_source_wal_qualification")
    config_authority=PAYLOAD["configAuthority"]
    need(config_authority["job_id"]=="1a1b137a21d-fc05-76f8"
         and config_authority["state"]=="succeeded" and config_authority["exit_code"]==0
         and not config_authority["timed_out"]
         and all(config_authority[k] is True for k in ("output_complete","output_durable","terminal_publication_confirmed")),
         "actual_current_config_authoritative_observation")
    config_root=Path("/Users/qianqi/heptabao-authbus-current-source-20261106-r1")
    need(read(config_root/"result.public.json",32768)==PAYLOAD["configStdout"].encode(),
         "exact_original_current_config_public_observation")
    for name,pin in PINS.items():need(sha(read(QUAL/"qa"/name))==pin,"same_qualified_source")
    need(sha(read(Path(PYTHON),16*1024*1024))==proof["runtime"]["pythonExecutableSha256"],"same_python_runtime")
    ROOT.mkdir(mode=0o700,exist_ok=False);created=True
    (ROOT/"code").mkdir(mode=0o700);(ROOT/"output").mkdir(mode=0o700)
    private(ROOT/"code/current_credentials.py",PAYLOAD["child"]);private(ROOT/"write-fence","owned kernel fence\n")
    source=Path("/Users/qianqi/.openclaw/openclaw.json")
    paths={ROOT,ROOT/"code",ROOT/"output",ROOT/"write-fence",QUAL,QUAL/"qa",source}
    paths.update(source.parents);paths.update(ROOT.parents);paths.update(QUAL.parents)
    binding=config_root/"output/current-source-binding.private.json"
    paths.add(binding);paths.update(binding.parents)
    for agent in ("main","trnm","hepta-ui","hepta","hepta-backend"):
        database=Path("/Users/qianqi/.openclaw/agents")/agent/"agent/openclaw-agent.sqlite"
        for suffix in ("","-wal","-shm","-journal"):
            candidate=Path(str(database)+suffix);paths.add(candidate);paths.update(candidate.parents)
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
            "-I","-S","-B",str(ROOT/"code/current_credentials.py"),str(UNTIL)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,
            env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","PYTHONDONTWRITEBYTECODE":"1"})
        stdout,stderr=child.communicate(timeout=remaining(30))
        need(len(stdout)<=65536 and len(stderr)<=16384,"bounded_current_credentials_public_output")
        private(ROOT/"child.stdout.public.json",stdout);private(ROOT/"child.stderr.txt",stderr)
        value=json.loads(stdout);report["observation"]=value
        report["credentialDatabaseOpened"]=any(row.get("capture",{}).get("returnedConnectionCount",0)>0
            for row in value.get("captures",[]))
        report["credentialDatabaseOutcomeKnown"]=True
        report["childExitCode"]=child.returncode;report["stderrBytes"]=len(stderr)
        need(child.returncode==0 and value.get("ok") is True and not stderr,"current_credentials_capture_complete")
        for pipe in (child.stdout,child.stderr):
            if not pipe.closed:pipe.close()
        owner.assert_retired()
    report["custody"]=owner.receipt()
    need(report["custody"]["passed_process_custody"] and report["custody"]["original_count"]==1
         and subprocess.Popen is original_popen and os.killpg is original_killpg,"original_current_config_child_retired")
    for name,pin in PINS.items():need(sha(read(QUAL/"qa"/name))==pin,"qualified_sources_unchanged_after")
    need(read(ROOT/"code/current_credentials.py")==PAYLOAD["child"].encode(),"current_config_source_unchanged")
    need(sha(read(Path(PYTHON),16*1024*1024))==proof["runtime"]["pythonExecutableSha256"]
         and sha(read(Path(_sqlite3.__file__),16*1024*1024))==proof["runtime"]["sqliteExtensionSha256"],
         "runtime_unchanged_after")
    remaining()
    report.update(ok=True,sourcePins=PINS,childSourceSha256=sha(PAYLOAD["child"].encode()),
                  sandboxProfileSha256=sha(policy.encode()),
                  privateCredentialCapsuleRoot=str(ROOT/"output"),
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
