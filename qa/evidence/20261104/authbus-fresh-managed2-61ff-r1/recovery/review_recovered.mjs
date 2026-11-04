import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
const root=path.dirname(fileURLToPath(import.meta.url));
const read=p=>fs.readFileSync(path.join(root,p),'utf8');
const hash=s=>createHash('sha256').update(s).digest('hex');
function reviewManaged2(read,hash){
  const checks=[];const json=p=>JSON.parse(read(p));const ck=(name,v)=>{checks.push({name,ok:!!v});if(!v)throw Error(name);};
  const payload=json("stage-input.json");
  for(const [name,sha]of Object.entries(payload.filePins))ck("executed_source_"+name,hash(read(name))===sha&&payload.files[name]===read(name));
  const prep=json("evidence/prepare-capsule.public.json"),provider=json("evidence/provider-capsule.public.json");
  for(const c of [prep,provider])for(const f of c.files)ck("original_file_"+f.relative,read("raw/"+f.relative)===f.text&&hash(f.text)===f.sha256);
  ck("prepare_capsule_original_hash",hash(read("evidence/prepare-capsule.public.json"))==="180eddd9b833b983c16b562cf2d92bf956412b1aa2d4c1fabc38b1283ac796f5");
  ck("provider_capsule_original_hash",hash(read("evidence/provider-capsule.public.json"))==="b623c8d609523f9cddfed6ab34c8f0cfb33d71fc6a35b7ea29261363329b5e78");
  const expected={stage:"1a1a7716fc9-fc05-2b74",resolve:"1a1a771eaeb-fc05-2b75",usage_stage:"1a1a773225e-fc05-2b7c",get:"1a1a776065f-fc05-2b85",export:"1a1a77923e9-fc05-2b90"};
  for(const [name,id]of Object.entries(expected)){
    const t=json("jobs/"+name+".terminal.public.json"),identity=json("jobs/"+name+".identity.public.json"),request=json("jobs/"+name+".request.public.json");
    ck("original_terminal_"+name,t.job_id===id&&t.exit_code===0&&t.state==="succeeded"&&!t.timed_out&&!t.automatic_retry&&t.output_complete&&t.output_durable&&t.terminal_publication_confirmed);
    ck("request_identity_"+name,identity.job_id===id&&identity.idempotency_key===request.idempotency_key&&request.host==="rog"&&identity.request_digest.length===64);
    ck("complete_durable_output_"+name,t.log_bytes.stderr.seen===0&&t.log_bytes.stderr.stored===0&&!t.log_truncated.stdout&&!t.log_truncated.stderr&&t.log_synced.stdout&&t.log_synced.stderr);
  }
  const stage=json("raw/control/resolve-stage.public.json"),usageStage=json("raw/control/usage-stage.public.json");
  ck("stage_original_payload",hash(read("stage-input.json"))===stage.payloadSha256&&Object.keys(stage.pins).length===19);
  ck("single_get_stage",Object.keys(usageStage.pins).length===23&&usageStage.requestsAllowed===1&&usageStage.noRefresh&&usageStage.noModel&&!usageStage.automaticRetry&&!usageStage.actualAuthbusMigrationClaimed);
  const resolver=json("raw/resolve-r1/result.public.json"),resOuter=json("raw/resolve-r1/outer-result.public.json"),core=json("raw/managed2-r1/result.public.json"),outer=json("raw/managed2-r1/outer-result.public.json"),ledger=json("raw/managed2-r1/request-started.public.json"),plan=json("raw/control/managed2-r1.plan.json");
  ck("actual_sdk_69_checks",resolver.ok&&resolver.actualCurrentSdkExplicitSelectionQualified&&resolver.checks.length===69&&resolver.checks.every(c=>c.ok===true));
  ck("actual_sdk_source_generation",resolver.sourceBinding.credentialSha256==="131b8515d48433365dd84555e7659297d4d62de631f9a526a8a4293f03396175"&&resolver.sourceBinding.profileOrdinal===2);
  ck("actual_sdk_no_network_or_child",resolver.unexpectedOperations===0&&!resolver.providerCalled&&!resolver.refreshAttempted&&!resolver.modelCalled);
  ck("full_auth_rows_conserved",resolver.sourceFullAuthRowsUnchanged&&resolver.sourceAuthRowsBeforeSha256===resolver.sourceAuthRowsAfterSha256);
  ck("selection_private_exact_hash",resolver.selectionSha256===plan.selectionFileSha256&&plan.selectionFileSha256==="f7e2aa66fd939d3f280dd835b9d826a5f710bd248ebf792158badba9d2e1a293"&&core.sourceBindingBefore.actualSdkCurrentSelectionSha256===resolver.selectionSha256);
  ck("resolver_custody",hash(read("raw/resolve-r1/result.public.json"))===plan.resolverReceiptSha256&&hash(read("raw/resolve-r1/outer-result.public.json"))===plan.resolverOuterSha256&&resOuter.resultSha256===plan.resolverReceiptSha256);
  ck("one_fresh_get200",core.ok&&core.providerCalled&&core.requestCount===1&&core.httpStatus===200&&core.freshReadOnlyProviderValidityQualified&&core.sourceKind==="managed-profile2-current-sdk-explicit");
  ck("tls_and_durable_sdk_parse",core.tlsVerified&&core.tlsConnected&&core.responseDurableBeforeSdkParse&&core.sdkParsed&&core.usageWindowCount===1&&core.usageWindowStructureValid&&!core.sdkErrorPresent);
  ck("private_body_hash_rechecked",provider.providerBodyRetainedPrivate&&provider.responseFileHashIndependentlyVerified&&!provider.providerCalled&&core.responseBytes===1568&&core.responseSha256==="6838e4d96f03ca2c7ffddf1d5d481da5c6d34ea74390dc04a0219e456356581a");
  ck("request_ledger_exact",hash(read("raw/managed2-r1/request-started.public.json"))===core.requestLedgerSha256&&core.requestLedgerSha256==="051623b9ecac2dcc6b76d03390b4c240f2c36cb5eddcb14f46e9235024c241df");
  ck("current_generation_before_after",core.currentSourceBoundImmediatelyBeforeDispatch&&core.currentSourceGenerationUnchangedAfterResponse&&JSON.stringify(core.sourceBindingBefore)===JSON.stringify(core.sourceBindingAfter)&&core.sourceBindingBefore.credentialSha256===resolver.sourceBinding.credentialSha256);
  ck("native_unmanaged_generation_preserved",core.sourceBindingBefore.nativeFileSha256==="f4aee2935351eaa6d56ce99166a0123c3c9e3260ae8737e6d7ad8ce2c8c12b78"&&core.sourceBindingBefore.nativeSourceGeneration==="6f5bcf6e72e50f6ff757823239de74050f4a2841b0b4040829bb550a75572133"&&!core.nativeSourceAdoptedByAuthBus);
  for(const [name,r,n]of [["resolver",resOuter,0],["provider",outer,1]])ck("owned_cleanup_"+name,r.ok&&r.returnCode===0&&r.requestCount===n&&!r.timedOut&&!r.providerOutcomeUnknown&&r.ownedNamespaceProcessExited&&r.pidNamespaceTeardownEnforced&&r.sourcePinsUnchanged&&r.productionUnitUnchanged&&JSON.stringify(r.productionUnitBefore)===JSON.stringify(r.productionUnitAfter)&&!r.productionChanged&&!r.productionTrafficCutover);
  ck("provider_result_chain",outer.resultSha256===hash(read("raw/managed2-r1/result.public.json"))&&outer.httpStatus===200&&!outer.automaticRetry);
  ck("scope_preserved",!core.authbusMigrationClaimed&&!core.providerMutationAttempted&&!core.refreshAttempted&&!core.modelCalled&&!core.productionChanged&&!core.productionCutover&&!core.j3160Contacted&&!core.credentialValuesPublished&&!core.accountIdentitiesPublished&&!core.allAccountsQualified&&!core.productionGatewaySelectionQualified&&!core.modelAvailabilityQualified&&!core.automaticRetry&&core.unexpectedOperations===0);
  return {schema:"heptabao.managed2-controller-recovery-review.v1",evidenceConsistent:true,checksPassed:checks.length,checksTotal:checks.length,checks,originalSdkDynamicChecks:69,originalLocalReviewerRecovered:false,originalLocalManifestRecovered:false,providerResult:{sourceKind:core.sourceKind,credentialSha256:core.sourceBindingBefore.credentialSha256,httpStatus:200,requests:1,responseBodyPublished:false},scope:"Original actual installed SDK explicit managed profile 2 selection and one read-only provider GET; source conservation and owned namespace cleanup. No new provider invocation or production action during recovery.",productionGatewayCutoverQualified:false,authbusMigrationQualifiedByThisRun:false,managed1Current401Overridden:false,nativeOriginal4Adopted:false};
}
const report=reviewManaged2(read,hash);
process.stdout.write(JSON.stringify(report,null,2)+'\n');
