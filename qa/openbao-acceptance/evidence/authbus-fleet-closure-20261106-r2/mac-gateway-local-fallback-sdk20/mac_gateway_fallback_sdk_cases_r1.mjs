/** Original installed SDK policy/path calls on synthetic values only.
 * This is not a gateway launch, config-loader integration, or memory proof. */
import {pathToFileURL} from "node:url";
import {isDeepStrictEqual} from "node:util";

export const SDK_ROOT="/opt/homebrew/lib/node_modules/openclaw";
export const SDK_PINS=Object.freeze({
 "dist/index.js":"9832720dcaf85519d315dda624497e352588f0d65c5607390df0501cc2358985",
 "dist/paths-BMBAvkNf.js":"099ff305aa7662710b2b0f1f925c99b203f30d283ab6b2ada34233a8188fab77",
 "dist/config-state-CtMlHVRM.js":"af2e3bc003048755d820284d3e01a777fae907aff3be8bc4e281dee663f409c5",
 "dist/config-normalization-shared-w2iz0aeC.js":"c3b7bccc26f72ac0ab79ef0635daaa5931d23f86d9bc7e21f4ae8b60ce80f7c2",
 "dist/installed-plugin-index-N4jxqS0-.js":"695dc3196348aa176780979d8c3a75428e9029890470670bcb77cf1a7fa03719"
});
export const ROOT="/Users/qianqi/heptabao-authbus-gateway-fallback-sdk-qualification-20261106-r1";
const STATE=ROOT+"/output/state/initial",CONFIG=ROOT+"/output/config.json";
const ACTUAL_STATE="/Users/qianqi/.openclaw";
const ACTUAL_FALLBACK="/Users/qianqi/heptabao-authbus-writer-maintenance-20261106-r1/local-sdk-fallback.private.json";
const ID="openclaw-authbus";

export async function runOriginalSdkCases({check,need,sourceFence,report}){
 sourceFence();
 const paths=await import(pathToFileURL(SDK_ROOT+"/dist/paths-BMBAvkNf.js").href);
 const states=await import(pathToFileURL(SDK_ROOT+"/dist/config-state-CtMlHVRM.js").href);
 const index=await import(pathToFileURL(SDK_ROOT+"/dist/installed-plugin-index-N4jxqS0-.js").href);
 sourceFence();
 report.actualPolicyAndPathModulesImported=true;
 report.gatewayEntrypointImported=false;
 const environment={HOME:"/Users/qianqi",OPENCLAW_STATE_DIR:STATE,OPENCLAW_CONFIG_PATH:CONFIG};
 const original={plugins:{enabled:true,entries:{[ID]:{enabled:true,config:{
  address:"https://synthetic.invalid:8200",publishNew:true,leader:true}},
  "synthetic-unrelated-plugin":{enabled:true}},allow:[]},
  gateway:{port:18789,auth:{token:"synthetic-fixture-only"}},
  agents:{defaults:{model:{primary:"openai/synthetic-model"}}}};
 const disabled=structuredClone(original);disabled.plugins.entries[ID].enabled=false;
 const unchanged=structuredClone(disabled);
 function state(config=disabled,extra={}){
  return states.f({id:ID,origin:"global",config:states.s(config.plugins),rootConfig:config,...extra});
 }
 function disabledState(value){
  need(value.enabled===false&&value.activated===false&&value.source==="disabled"
    &&value.reason==="disabled in config","fallback_sdk_exact_explicit_disable_decision");
 }
 await check("P02_original_module_exports",()=>{
  need([paths.v,paths.s,paths.c,paths.l,paths.o,states.s,states.f,index.n,index.h]
    .every(x=>typeof x==="function"),"fallback_sdk_exact_original_exports");
 });
 await check("P03_explicit_state_overrides_default",()=>{
  need(paths.v(environment)===STATE&&paths.v({...environment,OPENCLAW_STATE_DIR:ACTUAL_STATE})===ACTUAL_STATE,
    "fallback_sdk_original_state_override");
 });
 await check("P04_explicit_config_overrides_existing_state_config",()=>{
  need(paths.s(environment,STATE)===CONFIG&&paths.c(environment)===CONFIG,
    "fallback_sdk_original_explicit_config_override");
 });
 await check("P05_explicit_candidates_do_not_include_old_default",()=>{
  need(isDeepStrictEqual(paths.l(environment),[CONFIG]),"fallback_sdk_explicit_candidate_only");
 });
 await check("P06_missing_explicit_config_stays_explicit",()=>{
  const env={...environment,OPENCLAW_CONFIG_PATH:ROOT+"/output/missing-explicit.json"};
  need(paths.c(env)===env.OPENCLAW_CONFIG_PATH&&paths.s(env,STATE)===env.OPENCLAW_CONFIG_PATH,
    "fallback_sdk_missing_explicit_no_default_fallback");
 });
 await check("P07_actual_registered_paths_are_resolution_only",()=>{
  const env={...environment,OPENCLAW_STATE_DIR:ACTUAL_STATE,OPENCLAW_CONFIG_PATH:ACTUAL_FALLBACK};
  need(paths.s(env,ACTUAL_STATE)===ACTUAL_FALLBACK&&isDeepStrictEqual(paths.l(env),[ACTUAL_FALLBACK]),
    "fallback_sdk_exact_registered_maintenance_resolution");
  report.actualRegisteredPathsResolvedWithoutOpening=true;
 });
 await check("P08_runtime_path_repin_retains_explicit_scope",()=>{
  need(isDeepStrictEqual(paths.o({...environment}),{configPath:CONFIG,stateDir:STATE})
    &&paths.r===STATE&&paths.t===CONFIG,"fallback_sdk_runtime_path_repin");
 });
 await check("P09_false_survives_original_normalization",()=>{
  need(states.s(disabled.plugins).entries[ID].enabled===false,"fallback_sdk_exact_false_normalized");
  disabledState(state());
 });
 await check("P10_explicit_false_overrides_allowlist",()=>{
  const cfg=structuredClone(disabled);cfg.plugins.allow=[ID];disabledState(state(cfg));
 });
 await check("P11_explicit_false_overrides_memory_slot",()=>{
  const cfg=structuredClone(disabled);cfg.plugins.slots={memory:ID};disabledState(state(cfg));
 });
 await check("P12_explicit_false_overrides_context_engine_slot",()=>{
  const cfg=structuredClone(disabled);cfg.plugins.slots={contextEngine:ID};disabledState(state(cfg));
 });
 await check("P13_explicit_false_overrides_auto_reason",()=>{
  disabledState(state(disabled,{autoEnabledReason:"synthetic earlier auto-enable"}));
 });
 await check("P14_explicit_false_overrides_older_activation_source",()=>{
  disabledState(state(disabled,{activationSource:{plugins:states.s(original.plugins),rootConfig:original}}));
 });
 await check("P15_explicit_false_overrides_origin_defaults",()=>{
  for(const origin of ["global","config","workspace","bundled"])
   disabledState(state(disabled,{origin,enabledByDefault:true}));
 });
 await check("P16_old_persisted_enabled_record_cannot_override_false",()=>{
  const persisted={plugins:[{pluginId:ID,origin:"global",enabled:true,enabledByDefault:true}]};
  need(index.n(persisted,ID,disabled)===false,"fallback_sdk_cached_index_true_is_not_activation");
 });
 await check("P17_original_enabled_positive_control",()=>{
  const persisted={plugins:[{pluginId:ID,origin:"global",enabled:true}]};
  need(state(original).enabled===true&&state(original).activated===true
    &&index.n(persisted,ID,original)===true,"fallback_sdk_original_enabled_positive_control");
 });
 await check("P18_policy_hash_changes_for_single_boolean",()=>{
  need(index.h(original)!==index.h(disabled),"fallback_sdk_current_policy_invalidates_old_hash");
  report.privateOrSyntheticConfigurationHashesPublished=false;
 });
 await check("P19_integer_zero_does_not_disable_original_sdk",()=>{
  const cfg=structuredClone(original);cfg.plugins.entries[ID].enabled=0;
  const persisted={plugins:[{pluginId:ID,origin:"global",enabled:true}]};
  need(states.s(cfg.plugins).entries[ID].enabled===undefined
    &&state(cfg).enabled===true&&index.n(persisted,ID,cfg)===true,
    "fallback_sdk_zero_is_not_false_negative_control");
 });
 await check("P20_original_functions_do_not_mutate_input",()=>{
  need(isDeepStrictEqual(disabled,unchanged),"fallback_sdk_input_configuration_unchanged");
 });
 sourceFence();
 report.gatewayStarted=false;report.pluginRegisterInvoked=false;
 report.gatewayRegistrationChainQualified=false;
 report.runningGatewayMemoryFlagsProven=false;
 report.actualSdkPolicyAndPathsQualified=true;
}
