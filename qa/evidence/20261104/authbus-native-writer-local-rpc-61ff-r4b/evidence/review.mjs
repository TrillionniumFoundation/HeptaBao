import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';

function reviewNativeBaseline(files, hash) {
  const checks=[];
  const need=(name,value)=>{checks.push({case:name,passed:value===true});if(value!==true)throw Error(name);};
  const read=p=>{if(typeof files[p]!=="string")throw Error("missing "+p);return files[p];};
  const json=p=>JSON.parse(read(p));
  const canon=x=>x===null||typeof x!=="object"?JSON.stringify(x):Array.isArray(x)?"["+x.map(canon).join(",")+"]":"{"+Object.keys(x).sort().map(k=>JSON.stringify(k)+":"+canon(x[k])).join(",")+"}";
  const equal=(a,b)=>canon(a)===canon(b);
  const terminal=json("live-terminal.original.json"),stageTerminal=json("stage-terminal.original.json"),syntaxTerminal=json("syntax-terminal.original.json");
  for(const [label,t,id]of[["live",terminal,"1a1a8265bf5-fc05-2dd3"],["stage",stageTerminal,"1a1a8231282-fc05-2dcb"],["syntax",syntaxTerminal,"1a1a81e4348-fc05-2dbd"]]){
    need(label+".authoritative_complete",t.job_id===id&&t.state==="succeeded"&&t.exit_code===0&&t.timed_out===false&&t.output_complete===true&&t.output_durable===true&&t.terminal_publication_confirmed===true);
  }
  const outer=json("raw/execution.result.public.json"), core=json("raw/live/result.public.json"), stage=json("stage.public.json");
  need("raw.core_exact_hash",hash(read("raw/live/result.public.json"))===outer.coreResultSha256);
  need("raw.intent_exact_hash",hash(read("raw/intent.public.json"))===outer.intentSha256);
  need("stdout.outer_exact_hash",JSON.parse(json("live-process-read.original.json").stdout.text).sha256===hash(read("raw/execution.result.public.json")));
  need("stage.original_and_control_pins",stage.ok===true&&stage.candidateMode==="baseline"&&Object.keys(stage.pins).length===47&&stage.payloadSha256==="807b084575bb06d5ba9d5a006992b0cced01474ec82160c6ad55fd00965c2875");
  need("outer.complete_success_and_cleanup",outer.ok===true&&outer.returnCode===0&&outer.timedOut===false&&outer.outcomeUnknown===false&&outer.ownedNamespaceProcessExited===true&&outer.pidNamespaceTeardownEnforced===true&&outer.ownedServerStopped===true);
  need("outer.production_boundary",outer.productionChanged===false&&outer.productionTrafficCutover===false&&outer.productionUnitUnchanged===true&&outer.protectedInputsUnchanged===true&&outer.frozenInputsUnchanged===true&&equal(outer.productionUnitBefore,outer.productionUnitAfter));
  need("core.experiment_success_baseline_failure",core.ok===true&&core.candidateMode==="baseline"&&core.singleWriterGatePassed===false&&core.baselineActualConcurrencyRegressionObserved===true&&outer.singleWriterGatePassed===false);
  need("core.original_64_checks",core.checks.length===64&&core.checks.every(x=>x.passed===true));
  need("core.authority_scope",["providerCalled","refreshDispatched","modelCalled","newLoginAttempted","j3160Contacted","productionChanged","productionTrafficCutover","productionGatewaySelectionQualified","fullReplacementQualified","allAccountsQualified"].every(k=>core[k]===false));
  need("core.formal_storage_cold_restart",core.actualServerProcessColdRestartQualified===true&&["formal_format2","actual_sigkill_waited","cold_sealed","cold_unseal"].every(k=>core.checks.some(c=>c.case===k&&c.passed===true)));
  need("core.original_sdk_source_and_rollback",core.actualOriginalSdkExplicitProfileQualified===true&&core.actualMissingProfileRecovered===true&&core.privateWholeLogicalStoreRollbackQualified===true&&core.originalOrderAndExclusionsPreserved===true);
  const names=["active-lease","pending-initialize","pending-before-client"],summary=[];
  need("core.exact_six_phases",core.phases.length===6&&new Set(core.phases.map(p=>p.phase)).size===6&&core.phases.every(p=>names.includes(p.phase.replace(/\.rollback$/,""))));
  for(const name of names){
    const p=json("raw/live/consumer-"+name+"/result.public.json"),b=json("raw/live/consumer-"+name+"/rollback-result.public.json"),n=p.native,e=n.events;
    need(name+".embedded_phase_exact",equal(p,core.phases.find(x=>x.phase===name))&&equal(b,core.phases.find(x=>x.phase===name+".rollback")));
    need(name+".consumer_68",p.ok===true&&p.returnCode===0&&p.timedOut===false&&p.checks.length===68&&p.checks.every(x=>x.passed===true));
    need(name+".actual_original_factory",n.actualFactory===true&&n.patchedExpected===false&&n.factorySha256==="bff60f1bb2cb73ad44c7f9c9d779576a2ffd9836b22ecba0bd5b6046e7ce9103");
    need(name+".two_responding_channels",n.evidenceCompleted===true&&n.twoInitializedNativeRpcChannelsObserved===true&&n.twoReadyLeasesObserved===true&&n.secondFactoryInitialized===true&&n.secondProcessSpawned===true&&n.secondSpawnPriorNativeAlive===true&&n.singleWriterInvariantPassed===false);
    need(name+".monotonic_events",e.every((v,i)=>v.sequence===i+1&&(i===0||v.monotonicMs>=e[i-1].monotonicMs)));
    const ev=(kind,ordinal)=>e.find(x=>x.kind===kind&&(ordinal===undefined||x.ordinal===ordinal));
    const overlap=ev("regression_two_initialized_native_rpc_channels"),release=ev("old_original_lease_released"),gone=ev("old_actual_writer_and_wrapper_gone_before_cleanup"),cleanup=ev("owned_harness_cleanup_started");
    const oldExit=e.find(x=>x.kind==="wrapper_exit"&&x.ordinal===1);
    need(name+".ready_before_old_release",overlap.oldActiveLeases===1&&ev("initialize_completed",1).sequence<overlap.sequence&&ev("initialize_completed",2).sequence<overlap.sequence&&overlap.sequence<release.sequence);
    need(name+".actual_local_rpc_on_both",new Set(e.filter(x=>x.kind==="actual_local_loaded_threads_read"&&x.sequence<release.sequence&&x.loadedThreadCount===0&&x.nextCursorNull===true&&x.provesAccountIdentity===false).map(x=>x.ordinal)).size===2);
    need(name+".old_exit_classified_before_cleanup",oldExit.cleanupStarted===false&&oldExit.code===null&&oldExit.signal==="SIGKILL"&&release.sequence<oldExit.sequence&&oldExit.sequence<gone.sequence&&gone.sequence<cleanup.sequence);
    need(name+".actual_two_pid_pairs",n.transports.length===2&&n.transports.every(x=>x.native.ppid===x.wrapper.pid&&x.native.startTicks&&x.wrapper.startTicks&&x.wrapper.executable==="/usr/bin/node")&&new Set(n.transports.flatMap(x=>[x.wrapper.pid,x.native.pid])).size===4);
    need(name+".exact_native_generation_checkpoints",n.generationsUnchanged===true&&n.nativeCheckpoints.length>=9&&n.nativeCheckpoints.every(x=>x.exact===true&&x.generationSha256==="6f5bcf6e72e50f6ff757823239de74050f4a2841b0b4040829bb550a75572133"));
    need(name+".per_identity_cleanup",n.cleanup.allOwnedStopped===true&&n.cleanup.everySpawnTracked===true&&n.cleanup.actualSpawnCount===2&&n.cleanup.ownerRegistryCount===2&&n.cleanup.identities.length===2&&n.cleanup.identities.every(x=>x.nativeObserved&&x.wrapperObserved&&x.nativeGone&&x.wrapperGone));
    need(name+".both_promise_layers_settled",n.cleanup.acquirePromisesSettled===true&&n.cleanup.startupPromisesSettled===true&&n.cleanup.allOwnedLeasesReleased===true&&n.cleanup.sharedStartupCoverage.length===2&&n.cleanup.sharedStartupCoverage.every(x=>x.covered&&x.originalStartupCaptured&&x.originalStartupSettled&&!x.retainedBarrierOnly)&&n.cleanup.sharedStartupPromises.every(x=>x.promiseCaptured&&x.settled&&!x.replaced&&!x.observationFailed));
    need(name+".exact_tls_approle_profile_read_write",p.wire.length===6&&p.wire.every(x=>x.status===200&&x.tlsVerified===true)&&new Set(p.wire.map(x=>x.peerSha256)).size===1&&p.wire.some(x=>x.path==="/v1/auth/approle/login")&&p.wire.some(x=>x.path==="/v1/openclaw-auth/data/profiles/sha256-131b8515d48433365dd84555e7659297d4d62de631f9a526a8a4293f03396175")&&p.wire.some(x=>x.method==="POST"&&x.path.startsWith("/v1/openclaw-auth/data/inbox/rog-native-retirement/")));
    need(name+".policy_renew_revoke_actual_status",Object.entries({unassigned_denied:403,renew:200,revoke:204,revoked_denied:403}).every(([k,status])=>core.checks.some(x=>x.case===name+"."+k&&x.status===status&&x.passed===true)));
    need(name+".rollback_51_and_whole_logical",b.ok===true&&b.returnCode===0&&b.timedOut===false&&b.checks.length===51&&b.checks.every(x=>x.passed===true)&&["installed_sdk_atomic_rollback","rollback_logical_store_exact"].every(k=>b.checks.some(x=>x.case===k&&x.passed===true))&&core.rollbackOutcomes[name]==="success");
    need(name+".explicit_scope_limits",n.accountReadAttempted===false&&n.nativeAccountReadQualified===false&&n.credentialMutationExercised===false&&n.credentialOverwriteObserved===false&&n.modelCalled===false&&n.providerCalled===false&&n.nativeSourceAdoptedByAuthBus===false&&n.productionGatewaySelectionQualified===false&&n.externalNetworkKernelDenied===true&&n.harnessCleanupUsedAsRetirementProof===false);
    const progress=read("raw/live/consumer-"+name+"/native/progress.initial.public.ndjson").trim().split("\n").map(x=>JSON.parse(x));
    need(name+".progress_complete",progress.length>0&&progress.at(-1).stage==="consumer_cleanup_finished"&&progress.at(-1).nativeOwnedStopped===true);
    if(name.startsWith("pending-")){
      need(name+".second_ready_before_original_initialize",n.secondReadyWhileOriginalStartupPending===true&&ev("actual_local_loaded_threads_read",2).sequence<ev("initialize_dispatched",1).sequence);
    }
    if(name==="pending-before-client")need(name+".original_recycler_pre_client_boundary",ev("actual_recycler_at_spawn_before_onStarted").clientAbsent===true&&ev("actual_recycler_at_spawn_before_onStarted").sequence<ev("factory_onStarted",1).sequence&&n.earlyRecycler.retired===1&&n.earlyRecycler.deferred===1);
    summary.push({scenario:name,consumerChecks:68,rollbackChecks:51,twoInitializedNativeRpcChannelsObserved:true,oldRetirementWrapperSignal:"SIGKILL",oldNativeGoneBeforeHarnessCleanup:true,allOwnedStopped:true,productSingleWriterGatePassed:false});
  }
  return {schema:"heptabao.native-baseline-local-r4b-independent-recomputation.v1",evidenceConsistent:true,reviewChecks:checks.length,checks,actualDynamicChecks:64+3*68+3*51,actualDynamicPassed:64+3*68+3*51,baselineActualConcurrencyRegressionObserved:true,productSingleWriterGatePassed:false,coreSha256:hash(read("raw/live/result.public.json")),outerSha256:hash(read("raw/execution.result.public.json")),scenarios:summary,accountReadQualified:false,providerAvailabilityQualified:false,nativeCredentialMutationExercised:false,nativeCredentialOverwriteObserved:false,productionGatewayQualified:false,productionChanged:false,fullReplacementQualified:false};
}

const base=process.argv[2]??path.dirname(fileURLToPath(import.meta.url));
const manifest=JSON.parse(fs.readFileSync(path.join(base,'manifest.public.json'),'utf8'));
const files={};
const hash=s=>createHash('sha256').update(s).digest('hex');
for(const item of manifest.files){const bytes=fs.readFileSync(path.join(base,item.path));if(bytes.length!==item.bytes||hash(bytes)!==item.sha256)throw Error('input digest '+item.path);files[item.path]=bytes.toString('utf8');}
process.stdout.write(JSON.stringify(reviewNativeBaseline(files,hash),null,2)+'\n');
