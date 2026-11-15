/** Original pre-bootstrap selectors and normal gateway registration in a new fixture. */
import fs from 'node:fs';
import {isDeepStrictEqual} from 'node:util';

export const ROOT='/Users/qianqi/heptabao-authbus-gateway-registration-qualification-20261106-r3';
export const SDK='/opt/homebrew/lib/node_modules/openclaw';
export const STATE=ROOT+'/output/home/.openclaw';
export const HOME=ROOT+'/output/home';
export const CONFIG=ROOT+'/output/maintenance/fallback.json';
export const WORKSPACE=ROOT+'/output/workspace';
export const AUTHBUS='openclaw-authbus';
export const CONTROL='heptabao-qualification-control';
export const IDS=[AUTHBUS,CONTROL];
export const CONTROL_SYMBOL='heptabao.gateway.registration.qualification.r1';
export const AUTHBUS_ROOT=ROOT+'/code/disabled-authbus';
export const CONTROL_ROOT=ROOT+'/code/control';

export async function runGatewayCases({check,need,report,load,sourceFence,recordPrivate}){
 let paths,pre,configApi,runtimeHooks,configEnv,selectionSnapshot,preparedRead;
 const errors=[],exits=[];
 const captureError=value=>{const message=String(value);need(message.length<=16384&&errors.length<32,
  'gateway_bounded_private_runtime_error');errors.push(message);};
 const runtime={error:captureError,exit:code=>{exits.push(code);}};
 try{
 function selectorsExact(){
  return process.env.HOME===HOME&&process.env.OPENCLAW_STATE_DIR===STATE&&process.env.OPENCLAW_CONFIG_PATH===CONFIG;
 }
 function snapshotExact(snapshot){
  need(snapshot?.valid===true&&snapshot.path===CONFIG&&snapshot.sourceConfig?.plugins?.entries?.[AUTHBUS]?.enabled===false
   &&snapshot.config?.plugins?.entries?.[AUTHBUS]?.enabled===false,'gateway_original_snapshot_selected_disabled_fallback');
 }
 await check('S01_explicit_private_selectors_before_sdk_import',()=>{
  need(selectorsExact()&&!process.env.VITEST&&!process.env.OPENCLAW_TEST_FAST&&!process.env.OPENCLAW_GATEWAY_MINIMAL,
   'gateway_no_test_fast_or_minimal_startup_override');
  const own=JSON.parse(fs.readFileSync(CONFIG,'utf8'));
  need(own.plugins.entries[AUTHBUS].enabled===false&&own.plugins.entries[CONTROL].enabled===true,
   'gateway_only_synthetic_fallback_configuration');
 });
 await check('S02_actual_prebootstrap_and_config_modules_imported',async()=>{
  sourceFence();
  paths=await load('dist/paths-C6ahtu79.js');
  pre=await load('dist/pre-bootstrap-8G8HyMEQ.js');
  configApi=await load('dist/config/config.js');
  runtimeHooks=await load('dist/runtime-hooks-Dp2OHV46.js');
  configEnv=await load('dist/env-vars-CxBOhHoc.js');
  need(Object.keys(runtimeHooks.t()).length===0,'gateway_no_installed_external_runtime_hooks');
  need(paths.resolveConfigPath(process.env,STATE)===CONFIG&&paths.resolveStateDir(process.env)===STATE,
   'gateway_actual_alias_selectors_choose_fallback');
 });
 await check('S03_original_select_environment_ignores_conflicting_dotenv_and_config_vars',async()=>{
  const selected=await pre.selectGatewayRunEnvironment({opts:{},runtime});
  selectionSnapshot=await configApi.readConfigFileSnapshot({isolateEnv:true,observe:false});
  recordPrivate('selection',{selected,selectorsExact:selectorsExact(),path:selectionSnapshot.path,
   exists:selectionSnapshot.exists,valid:selectionSnapshot.valid,issues:selectionSnapshot.issues,
   warnings:selectionSnapshot.warnings,legacyIssues:selectionSnapshot.legacyIssues});
  need(selected===true&&selectorsExact(),'gateway_original_environment_selection_complete');
  snapshotExact(selectionSnapshot);
  need(isDeepStrictEqual(selectionSnapshot.warnings,[{path:'plugins.entries.'+AUTHBUS,
   message:'plugin disabled (disabled in config) but config is present'}]),
   'gateway_exact_original_disabled_config_warning');
  report.originalDisabledConfigWarningExact=true;
  need(report.originalDotenvReads.state>0&&report.originalDotenvReads.gateway>0
   &&process.env.HEPTABAO_STATE_ENV_MARKER==='state-original-read'
   &&process.env.HEPTABAO_GATEWAY_ENV_MARKER==='gateway-original-read'
   &&process.env.HEPTABAO_CONFIG_ENV_MARKER==='config-original-applied',
   'gateway_actual_conflicting_dotenv_reads_and_harmless_markers');
  report.actualStateAndGatewayDotenvReadsObserved=true;
  const invalid=structuredClone(selectionSnapshot.sourceConfig);
  invalid.plugins.entries[AUTHBUS].config={};
  const invalidResult=configApi.validateConfigObjectWithPlugins(invalid,{env:process.env});
  recordPrivate('empty-config',{ok:invalidResult.ok,issues:invalidResult.issues,warnings:invalidResult.warnings});
  need(invalidResult.ok===false&&Array.isArray(invalidResult.issues)&&invalidResult.issues.length>0
   &&invalidResult.issues.every(issue=>issue.path.startsWith('plugins.entries.'+AUTHBUS+'.config')),
   'gateway_original_validator_rejects_previous_empty_disabled_plugin_config');
  report.previousEmptyDisabledConfigRejectedByOriginalValidator=true;
  need(errors.length===0&&exits.length===0,'gateway_no_initial_selector_refusal');
 });
 await check('S04_original_prepare_bootstrap_preserves_same_selected_file',async()=>{
  need(await pre.prepareGatewayRunBootstrap({opts:{},runtime})===true&&selectorsExact(),
   'gateway_original_prepared_bootstrap');
  preparedRead=await configApi.readConfigFileSnapshotWithPluginMetadata({isolateEnv:true,observe:false,recoverSuspicious:false});
  snapshotExact(preparedRead.snapshot);
  need(isDeepStrictEqual(preparedRead.snapshot.sourceConfig,selectionSnapshot.sourceConfig),
   'gateway_selected_source_unchanged_through_prepare');
 });
 await check('S05_original_prestartup_snapshot_recheck',async()=>{
  need(await pre.recheckGatewayRunBootstrap({opts:{},runtime,snapshot:preparedRead.snapshot})===true,
   'gateway_original_rechecked_startup_snapshot');
 });
 await check('S06_original_trusted_dotenv_reload_keeps_explicit_target',async()=>{
  need(await pre.reloadTrustedGatewayRunEnvironment({runtime})===true&&selectorsExact(),
   'gateway_original_trusted_reload_target_exact');
 });
 await check('S07_original_final_config_env_and_actual_snapshot_choose_fallback',async()=>{
  const finalRead=await configApi.readConfigFileSnapshotWithPluginMetadata({isolateEnv:true,observe:false,recoverSuspicious:false});
  snapshotExact(finalRead.snapshot);
  need(await pre.applyFinalGatewayRunConfigEnv({runtime,snapshot:finalRead.snapshot,lowerPrecedenceEnv:{}})===true,
   'gateway_original_final_environment_accepted');
  need(selectorsExact()&&paths.resolveConfigPath(process.env,STATE)===CONFIG&&paths.resolveStateDir(process.env)===STATE,
   'gateway_final_runtime_paths_stay_explicit');
  need(isDeepStrictEqual(finalRead.snapshot.sourceConfig,selectionSnapshot.sourceConfig)&&!errors.length&&!exits.length,
   'gateway_final_startup_snapshot_source_exact');
  preparedRead=finalRead;
  report.actualPreBootstrapFinalFallbackSelected=true;
 });
 let manifestRegistry,registration,registries,hooks,loader;
 globalThis[Symbol.for(CONTROL_SYMBOL)]={registrations:0,gatewayStartHooks:0};
 await check('R01_original_manifest_parser_has_disabled_onstartup_authbus_and_enabled_control',async()=>{
  const manifest=await load('dist/manifest-registry--UiRn6nq.js');
  manifestRegistry=manifest.t({config:preparedRead.snapshot.config,env:process.env,
   candidates:[
    {idHint:AUTHBUS,rootDir:AUTHBUS_ROOT,source:AUTHBUS_ROOT+'/index.js',origin:'global'},
    {idHint:CONTROL,rootDir:CONTROL_ROOT,source:CONTROL_ROOT+'/index.cjs',origin:'global'}],
   diagnostics:[],installRecords:{}});
  need(manifestRegistry.plugins.length===2&&IDS.every(id=>manifestRegistry.plugins.filter(p=>p.id===id).length===1),
   'gateway_exact_nonempty_original_manifest_scope');
  const auth=manifestRegistry.plugins.find(p=>p.id===AUTHBUS);
  need(auth.channels.length===0&&auth.setupSource===undefined&&auth.source===AUTHBUS_ROOT+'/index.js',
   'gateway_authbus_has_no_disabled_setup_channel_exception');
  need(JSON.parse(fs.readFileSync(AUTHBUS_ROOT+'/openclaw.plugin.json','utf8')).activation.onStartup===true,
   'gateway_actual_authbus_on_startup_manifest_retained');
  need(!manifestRegistry.diagnostics.some(d=>d.level==='error'),'gateway_original_manifest_parse_without_errors');
 });
 await check('R02_original_normal_gateway_startup_registers_nonempty_scope',async()=>{
  registries=await load('dist/runtime-D0xGMZdc.js');
  hooks=await load('dist/hook-runner-global-BmIrGlLG.js');
  loader=await load('dist/loader-D8d2EvVh.js');
  const startup=await load('dist/server-plugin-bootstrap-CtU_XTUf.js');
  need(registries.c()===null||registries.c()?.plugins.length===0,'gateway_no_prior_active_plugin_registry');
  registration=startup.loadGatewayStartupPlugins({cfg:preparedRead.snapshot.config,
   activationSourceConfig:preparedRead.snapshot.sourceConfig,workspaceDir:WORKSPACE,
   log:{info:()=>{},error:captureError},baseMethods:[],pluginIds:IDS,
   pluginLookUpTable:{manifestRegistry},coreGatewayHandlers:{},coreGatewayMethodNames:[],
   preferSetupRuntimeForChannelPlugins:false,suppressPluginInfoLogs:true});
  need(registration.pluginRegistry.plugins.length===2,'gateway_nonempty_original_registration_completed');
  const control=globalThis[Symbol.for(CONTROL_SYMBOL)];
  need(control.registrations===1,'gateway_positive_control_register_really_called_once');
 });
 await check('R03_real_authbus_disabled_before_module_import_and_registration',()=>{
  const registry=registration.pluginRegistry;
  const auth=registry.plugins.find(p=>p.id===AUTHBUS),control=registry.plugins.find(p=>p.id===CONTROL);
  need(auth?.status==='disabled'&&control?.status==='loaded'&&!registry.plugins.some(p=>p.status==='error'),
   'gateway_actual_disabled_and_loaded_registration_records');
  need(report.authbusModuleLoadAttempts===0&&report.controlModuleLoadAttempts===1,
   'gateway_disabled_authbus_never_imported_and_control_imported_once');
  need(isDeepStrictEqual([...registries.m()].sort(),[CONTROL]),'gateway_only_positive_control_runtime_import_record');
  for(const name of ['tools','hooks','typedHooks','channels','providers','services','httpRoutes','commands']){
   need(Array.isArray(registry[name])&&!registry[name].some(row=>row?.pluginId===AUTHBUS||row?.id===AUTHBUS),
    'gateway_no_authbus_registration_surface_'+name);
  }
  need(registry.services.length===0&&registry.providers.length===0,'gateway_no_started_service_or_provider_registration');
 });
 await check('R04_original_active_channel_session_and_hook_memory_bound',()=>{
  const registry=registration.pluginRegistry;
  need(registries.c()===registry&&registries.n()===registry&&registries.p()===registry&&registries.B(registry),
   'gateway_original_active_and_pinned_registries_same_object');
  need(hooks.n()===registry&&hooks.t()!==null&&hooks.r('gateway_start')===true,
   'gateway_original_global_hook_runner_activated');
 });
 await check('R05_positive_control_original_gateway_start_hook_fires_once',async()=>{
  await hooks.t().runGatewayStart({port:1},{port:1});
  need(globalThis[Symbol.for(CONTROL_SYMBOL)].gatewayStartHooks===1&&report.authbusModuleLoadAttempts===0,
   'gateway_original_global_hook_dispatch_only_positive_control');
 });
 await check('S08_original_final_env_rejects_new_selector_and_restores_target',async()=>{
  need(process.env.OPENCLAW_PROFILE===undefined&&configEnv.isConfigRuntimeEnvVarAllowed('OPENCLAW_PROFILE','qa-selector-drift'),
   'gateway_selector_negative_is_allowed_new_config_env_key');
  const bad=structuredClone(preparedRead.snapshot);
  bad.sourceConfig.env={...(bad.sourceConfig.env??{}),vars:{...(bad.sourceConfig.env?.vars??{}),OPENCLAW_PROFILE:'qa-selector-drift'}};
  const errorsBefore=errors.length,exitsBefore=exits.length;
  need(await pre.applyFinalGatewayRunConfigEnv({runtime,snapshot:bad,lowerPrecedenceEnv:{}})===false,
   'gateway_actual_final_selector_drift_rejected');
  need(errors.length===errorsBefore+1&&exits.length===exitsBefore+1&&exits.at(-1)===1&&selectorsExact()
   &&process.env.OPENCLAW_PROFILE===undefined,'gateway_original_selector_refusal_restores_environment');
 });
 await check('R06_original_registration_memory_cleanup_without_service_start',()=>{
  pre.clearGatewayRunConfigEnvironment();
  registries.y(registration.pluginRegistry);registries.x(registration.pluginRegistry);
  loader.t();registries.D(registries.O(),undefined,'gateway-bindable',WORKSPACE);hooks.a();
  need(registries.c().plugins.length===0&&hooks.t()===null,'gateway_own_registration_memory_retired');
  need(selectorsExact(),'gateway_cleanup_keeps_explicit_private_selectors');
 });
 delete globalThis[Symbol.for(CONTROL_SYMBOL)];
 sourceFence();
 report.actualNormalGatewayRegistrationFunctionQualified=true;
 report.actualIsolatedActiveRegistryQualified=true;
 report.actualProductionGatewayMemoryQualified=false;
 report.fullGatewayServerStarted=false;
 report.productionFallbackConfigurationQualified=false;
 report.gatewayServiceMutationAttempted=false;
 }finally{recordPrivate('runtime',{errors,exits});}
}
