/**
 * UNBOUND SOURCE COMPONENT. No executable entry point or dispatch request.
 * A later reviewed parent must bind the public configuration/catalog, fixed
 * SDK imports, actual OS sandbox and one retained worker lineage. This file
 * alone proves none of those runtime conditions. No SDK import occurs here.
 */
import { createHash } from 'node:crypto';
import { posix } from 'node:path';
export const BINDING_READY = false;
export const AGENTS = Object.freeze(['main','trnm','hepta-ui','hepta','hepta-backend']);
export const CONFIG_SOURCE_SHA256 = 'ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d';
export const DECLARED_MODEL_SHA256 = '8c19b031ba91d45f4eb2dec6fc9453cbcb69aaf8c151a4219f3a84fc0a8849d1';
export const MODEL = Object.freeze({provider:'openai',id:'gpt-5.6-sol'});
export const SDK_MODULES = Object.freeze({
  loader:{name:'dist/runtime-registry-loader-Duw3fvRO.js',bytes:6047,
    sha256:'bd6a9f363bc7aac2fb0503640e339ffce52e0eab15336e6489b6f8129df748fb'},
  selector:{name:'dist/selection-JInn13lc.js',bytes:673468,
    sha256:'ccff13111aa60369ac9d88b526a58a7df1f733f1d99d205c01c6186036957e66'},
  registry:{name:'dist/registry-DtLZ3rba.js',bytes:3135,
    sha256:'a845875a1998c2a6bdd9fe4c824a0a7c3e7da0f3ee75ec56dc6163d4327f7ff0'}
});
export const MISSING_BINDING = Object.freeze({
  publicConfigurationBytesSha256:null,
  publicConfigurationEquivalenceReview:null,
  completeCapturedCandidateCatalogSha256:null,
  everyLoadableOwnerManifestAndEntryPins:null,
  samePolicyKernelDenialProof:null,
  completeOwnedParentAndWorkerBinding:null
});
const MAX_CATALOG=8, MAX_REGISTRATIONS=32, MAX_PUBLIC_CONFIG_BYTES=65536, MAX_REPORT_BYTES=32768;
const PUBLIC_SDK_ROOT='/opt/homebrew/lib/node_modules/openclaw';
const KNOWN_CODEX_ROOT='/Users/qianqi/.openclaw/npm/projects/openclaw-codex-8902d781d4__openclaw-generation__g-49fd4dbfde2c5057/node_modules/@openclaw/codex';
const MAX_OWNER_PIN_ROWS=32;
const ID=/^[a-z0-9][a-z0-9_.-]{0,79}$/, HEX=/^[0-9a-f]{64}$/;
function need(value,code) {
  if (!value) { const error=new Error(code);error.publicCode=code;throw error; }
}
function sha(raw) { return createHash('sha256').update(raw).digest('hex'); }
function canonical(value,depth=0) {
  need(depth<=48,'bounded_public_json_depth');
  if (value===null || typeof value==='string' || typeof value==='boolean') return JSON.stringify(value);
  if (typeof value==='number') { need(Number.isFinite(value),'finite_public_json_number');return JSON.stringify(value); }
  if (Array.isArray(value)) return '['+value.map(x=>canonical(x,depth+1)).join(',')+']';
  need(value && typeof value==='object' && Object.getPrototypeOf(value)===Object.prototype,'plain_public_json_object');
  return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k],depth+1)).join(',')+'}';
}
function publicId(value) { return typeof value==='string' && ID.test(value) ? value : null; }
function publicCodePath(value,root=null) {
  if (typeof value!=='string' || Buffer.byteLength(value)>4096
      || !/^\/[A-Za-z0-9_.@+~\/-]{1,4095}$/.test(value) || posix.normalize(value)!==value) return false;
  const within=(base)=>value===base || value.startsWith(base+'/');
  return root===null ? within(PUBLIC_SDK_ROOT) || within(KNOWN_CODEX_ROOT) : within(root);
}
function publicSourcePin(value,root) {
  need(value && publicCodePath(value.path,root) && HEX.test(value.sha256)
    && Number.isSafeInteger(value.bytes) && value.bytes>=0
    && Array.isArray(value.identity) && value.identity.length===9
    && value.identity.every(v=>typeof v==='string' && /^(0|[1-9][0-9]*)$/.test(v)),
    'typed_public_owner_source_pin');
  return {path:value.path,bytes:value.bytes,sha256:value.sha256,identity:[...value.identity]};
}
function recordView(entry) {
  need(entry && typeof entry==='object' && entry.harness && typeof entry.harness==='object','typed_registry_record');
  return {harnessRef:entry.harness,harnessId:publicId(entry.harness.id),
    ownerPluginId:publicId(entry.ownerPluginId),harnessPluginId:publicId(entry.harness.pluginId),
    ownerFieldPresent:entry.ownerPluginId!==undefined,harnessPluginFieldPresent:entry.harness.pluginId!==undefined};
}
function snapshot(registry) {
  const entries=registry.i();
  need(Array.isArray(entries) && entries.length<=MAX_REGISTRATIONS,'bounded_actual_registered_harnesses');
  return entries.map(recordView);
}
function stableSnapshots(before,after) {
  return before.length===after.length && before.every((x,i)=>
    x.harnessRef===after[i].harnessRef && x.harnessId===after[i].harnessId
    && x.ownerPluginId===after[i].ownerPluginId && x.harnessPluginId===after[i].harnessPluginId
    && x.ownerFieldPresent===after[i].ownerFieldPresent && x.harnessPluginFieldPresent===after[i].harnessPluginFieldPresent);
}
function metadataOnly(entries) {
  return entries.map(({harnessId,ownerPluginId,harnessPluginId,ownerFieldPresent,harnessPluginFieldPresent})=>
    ({harnessId,ownerPluginId,harnessPluginId,ownerFieldPresent,harnessPluginFieldPresent}));
}
/**
 * ONE agent per fresh parent-owned Node process. Modules must be unchanged
 * namespaces from exact fixed imports admitted by the parent. remaining()
 * consumes the parent's single absolute deadline; it never creates a new
 * per-agent budget. This unbound version refuses before touching inputs or SDK.
 */
export async function observeOneAgent({agentId,publicConfig,catalog,plan,modules,remaining}) {
  need(BINDING_READY && Object.values(MISSING_BINDING).every(x=>x!==null),
    'unbound_source_candidate_no_sdk_execution');
  need(AGENTS.includes(agentId) && plan.agentIds.join('\0')===AGENTS.join('\0'),'exact_five_agent_scope');
  need(plan.configSourceSha256===CONFIG_SOURCE_SHA256
    && plan.model?.provider===MODEL.provider && plan.model?.id===MODEL.id
    && plan.declaredModelSha256===DECLARED_MODEL_SHA256,'actual_captured_model_binding');
  need(typeof remaining==='function','one_parent_absolute_deadline');remaining();
  // No raw capsule, auth rows/cache, OAuth profile, native home, RoleID,
  // SecretID, token or refresh state is an accepted input. Config projection
  // needs an actual source-equivalence review; arbitrary redaction is forbidden.
  need(typeof plan.publicConfigurationEquivalenceReview==='string'
    && plan.publicConfigurationEquivalenceReview===MISSING_BINDING.publicConfigurationEquivalenceReview
    && HEX.test(plan.publicConfigurationSha256)
    && plan.publicConfigurationSha256===MISSING_BINDING.publicConfigurationBytesSha256,
    'bound_public_configuration_proof');
  const configBefore=canonical(publicConfig);
  need(Buffer.byteLength(configBefore)<=MAX_PUBLIC_CONFIG_BYTES
    && sha(configBefore)===plan.publicConfigurationSha256,'exact_approved_public_configuration');
  need(Array.isArray(catalog) && catalog.length>=1 && catalog.length<=MAX_CATALOG
    && catalog.length===plan.originalEnabledCandidateCount,'complete_original_enabled_candidate_count');
  const seen=new Set();
  for (const row of catalog) {
    need(row && publicId(row.pluginId)!==null && !seen.has(row.pluginId)
      && Number.isInteger(row.registryOrdinal) && row.registryOrdinal>=0
      && HEX.test(row.originalIdentifierValueSha256) && HEX.test(row.originalRootValueSha256)
      && row.originalEnabledStartupAgentHarnesses===true && publicCodePath(row.codeRoot),
      'typed_complete_captured_candidate');
    // No prefix filter or guessed "unused" label removes a candidate.
    need(sha(JSON.stringify(row.pluginId))===row.originalIdentifierValueSha256
      && sha(JSON.stringify(row.codeRoot))===row.originalRootValueSha256,'same_captured_candidate_values');
    need(Array.isArray(row.sourcePins) && row.sourcePins.length>=2
      && row.sourcePins.length<=MAX_OWNER_PIN_ROWS,'declared_owner_source_pins_present');
    for (const pin of row.sourcePins) publicSourcePin(pin,row.codeRoot);
    seen.add(row.pluginId);
  }
  const onlyPluginIds=[...new Set(['openai',...catalog.map(x=>x.pluginId)])].sort();
  need(Array.isArray(plan.harnessOwnerPluginIds)
    && JSON.stringify(plan.harnessOwnerPluginIds)===JSON.stringify(onlyPluginIds),'unchanged_original_owner_scope');
  const {loader,selector,registry}=modules;
  need(typeof loader?.t==='function' && typeof selector?.o==='function'
    && typeof registry?.r==='function' && typeof registry?.i==='function','actual_export_contract');
  const beforeLoad=snapshot(registry);
  remaining();
  await loader.t({scope:'all',config:publicConfig,activationSourceConfig:publicConfig,
    workspaceDir:plan.workspace,onlyPluginIds});
  remaining();
  const beforeSelection=snapshot(registry);
  // Actual installed selector: no runtime override, comparator/supports
  // replacement, registry clearing, expected-winner injection or factory.
  const selected=selector.o({provider:plan.model.provider,modelId:plan.model.id,config:publicConfig,agentId});
  remaining();
  const selectedId=publicId(selected?.id);
  const registered=selectedId===null ? undefined : registry.r(selectedId);
  const sameRegisteredInstance=!!registered && registered.harness===selected;
  const view=registered ? recordView(registered) : null;
  const afterSelection=snapshot(registry);
  const owners=view?.ownerPluginId===null || view?.ownerPluginId===undefined
    ? [] : catalog.filter(x=>x.pluginId===view.ownerPluginId);
  const output={
    schema:'heptabao.mac-selected-harness-owner-observation.unbound-r1',
    agentId,model:{provider:MODEL.provider,id:MODEL.id},configSourceSha256:CONFIG_SOURCE_SHA256,
    publicConfigurationSha256:plan.publicConfigurationSha256,
    loaderCalled:true,selectorCalled:true,actualSelectedHarnessId:selectedId,
    sameRegisteredInstance,selectedRecordOwnerPluginId:view?.ownerPluginId ?? null,
    selectedHarnessPluginId:view?.harnessPluginId ?? null,
    ownerAndHarnessPluginIdsEqual:view!==null && view.ownerPluginId!==null && view.ownerPluginId===view.harnessPluginId,
    ownerCatalogMatchCount:owners.length,
    selectedOwnerRoot:owners.length===1 ? owners[0].codeRoot : null,
    selectedOwnerDeclaredSourcePins:owners.length===1
      ? owners[0].sourcePins.map(x=>publicSourcePin(x,owners[0].codeRoot)) : [],
    registryBeforeLoad:metadataOnly(beforeLoad),registryBeforeSelection:metadataOnly(beforeSelection),
    registryAfterSelection:metadataOnly(afterSelection),
    registryStableAcrossSelector:stableSnapshots(beforeSelection,afterSelection),
    publicConfigUnchanged:canonical(publicConfig)===configBefore,
    wouldSatisfyOriginalCodexIdPredicate:selectedId==='codex',
    wouldSatisfyOriginalRegisteredInstancePredicate:sameRegisteredInstance,
    factoryCalledByObserver:false,nativeClientCalledByObserver:false,runAttemptCalledByObserver:false,
    providerOrRefreshCalledByObserver:false,rawPrivateCapsuleReceived:false,credentialMaterialReceived:false,
    syscallAttemptsNotProvenAbsent:true,actualSandboxAndChildClosureMustComeFromParent:true,
    currentConsumerQualified:false,productionQualified:false
  };
  need(Buffer.byteLength(JSON.stringify(output))<=MAX_REPORT_BYTES,'bounded_public_owner_observation');
  remaining();return output;
}
