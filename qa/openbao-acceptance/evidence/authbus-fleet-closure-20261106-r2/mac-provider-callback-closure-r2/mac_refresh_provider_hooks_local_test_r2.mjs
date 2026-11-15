/** Local source-bound overlay/registry faults. No SDK import, DNS, TLS or OAuth.
 * Dispatcher and native fetch are explicit synthetic objects. */
import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {fileURLToPath} from "node:url";
import vm from "node:vm";
import {observeOriginalDispatcherClosure as oldObserver} from "./mac_refresh_provider_hooks_r1.mjs";
import {TOKEN_URL,CLIENT_ID,PROVIDER_SOURCE_PINS,ProviderOnceRefused,patchProviderSource,makeProviderRegistry,observeOriginalDispatcherClosure} from "./mac_refresh_provider_hooks_r2.mjs";
const here=path.dirname(fileURLToPath(import.meta.url)),start=process.hrtime.bigint(),results=[];
const fakeCredential={type:"oauth",provider:"openai",refresh:"synthetic-refresh-only",accountId:"synthetic-owner"};
function fixture({until=process.hrtime.bigint()+10000000000n,clock=()=>process.hrtime.bigint(),capture=()=>{},fence=()=>{}}={}){
  const events=[],signal=new AbortController().signal,receipt={flowEntrypointChecks:0,postFormEntries:0,guardEntries:0,runtimeEntries:0,
    finalNativeSendEntries:0,originalNativeFetchInvocations:0,originalNativeFetchSettlements:0,completeBodyCaptures:0,
    originalDispatcherMethodCalls:0,originalDispatcherReleaseCompletions:0};
  const ctx={oldCredential:fakeCredential,until,signal,closed:false,receipt,dispatcherObservers:[],nativePromises:[],
    assertLive(){events.push("authority");},finalDispatch(send){events.push("durable-latch");return send();},
    responseCapture(value){events.push("raw-fsync");capture(value);}};
  const registry=makeProviderRegistry({current:()=>ctx,clock,sourceFence(){events.push("source");fence();}});
  const body=new URLSearchParams({grant_type:"refresh_token",refresh_token:fakeCredential.refresh,client_id:CLIENT_ID});
  const init={method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body};
  const params={url:TOKEN_URL,init,timeoutMs:5000,signal,auditContext:"openai-chatgpt-oauth-token"};
  const dispatcher={closed:false,destroyed:false,close(){this.closed=true;return Promise.resolve();},destroy(){this.destroyed=true;return Promise.resolve();}};
  const wire={...init,redirect:"manual",signal,dispatcher};
  return {ctx,receipt,events,registry,body,init,params,dispatcher,wire,
    prepare(){this.ticket=registry.prepare(params);return this.ticket;},
    enter(){this.prepare();registry.enterRuntime(this.ticket,TOKEN_URL,wire);},
    async send(callback=()=>Promise.resolve(new Response("{}",{status:200}))){return registry.dispatch(this.ticket,TOKEN_URL,wire,callback,true);},
    async close(){await dispatcher.close();registry.releaseKnown(this.ticket,dispatcher);await Promise.all(ctx.dispatcherObservers.flatMap(x=>x.originalPromises));for(const o of ctx.dispatcherObservers)o.restore();}};
}
function refused(fn,code){assert.throws(fn,e=>e instanceof ProviderOnceRefused&&(!code||e.code===code));}
async function test(id,fn){try{await fn();results.push({id,passed:true});}catch(e){results.push({id,passed:false,errorType:e?.name??"Error",code:e instanceof ProviderOnceRefused?e.code:null});}}
await test("P01_exact_original_sources_and_three_overlays",async()=>{
  const out=path.join(here,"provider-overlays-r2");fs.mkdirSync(out,{recursive:true});let changed=0;
  for(const relative of Object.keys(PROVIDER_SOURCE_PINS)){
    const name=path.basename(relative),source=fs.readFileSync(name.startsWith("openai-chatgpt-oauth-flow")?
      path.join(here,"../HeptaBao-current-924b/qa/openbao-acceptance/evidence/mac-authbus-current-sdk-20261106-r1/sdk-source",name):path.join(here,"reference",name),"utf8");
    const next=patchProviderSource(relative,source);if(source!==next)changed++;fs.writeFileSync(path.join(out,name+".mjs"),next);
    refused(()=>patchProviderSource(relative,source+"\n"),"provider_original_source_pin");
  }
  assert.equal(changed,3);
});
await test("P02_original_final_send_then_capture_then_close",async()=>{
  const f=fixture();f.registry.assertEntry(fakeCredential.refresh);f.registry.assertEntry(fakeCredential.refresh);
  const options=f.registry.postOptions(f.body,{timeoutMs:30000});assert(options.timeoutMs<=10000&&options.timeoutMs>0);
  f.enter();const response=await f.send(()=>{f.events.push("native-send");return Promise.resolve(new Response("{}",{status:200}));});
  f.registry.captureResponse(response,Buffer.from("{}"));f.events.push("sdk-parser");
  assert(f.events.indexOf("durable-latch")<f.events.indexOf("native-send"));assert(f.events.indexOf("raw-fsync")<f.events.indexOf("sdk-parser"));
  await f.close();assert.equal(f.receipt.originalNativeFetchInvocations,1);assert.equal(f.receipt.originalNativeFetchSettlements,1);assert.equal(f.receipt.originalDispatcherMethodCalls,1);
  assert.equal(f.ctx.dispatcherObservers[0].known(),true);assert.equal(f.receipt.originalCloseHelperReturned,true);
});
await test("P03_foreign_refresh_entry",async()=>{const f=fixture();refused(()=>f.registry.assertEntry("synthetic-other"),"provider_exact_selected_refresh_entry");});
await test("P04_duplicate_form_fields",async()=>{const f=fixture();f.body.append("refresh_token","synthetic-other");refused(()=>f.prepare(),"provider_exact_selected_refresh_form");});
await test("P05_changed_origin_refused",async()=>{const f=fixture();f.params.url="https://example.invalid/oauth/token";refused(()=>f.prepare(),"provider_exact_native_endpoint_method");});
await test("P06_extra_authorization_header_refused",async()=>{const f=fixture();f.init.headers.Authorization="synthetic";refused(()=>f.prepare(),"provider_exact_token_headers");});
await test("P07_foreign_abort_context",async()=>{const f=fixture();refused(()=>f.registry.postOptions(f.body,{signal:new AbortController().signal}),"provider_original_flow_options");});
await test("P08_absolute_remaining_budget_clamp",async()=>{const f=fixture({until:6000000000n,clock:()=>1000000000n});assert.equal(f.registry.postOptions(f.body,{timeoutMs:30000}).timeoutMs,5000);});
await test("P09_original_thirty_second_limit",async()=>{const f=fixture();refused(()=>f.registry.postOptions(f.body,{timeoutMs:30001}),"provider_original_30_second_budget");});
await test("P10_original_post_form_only_once",async()=>{const f=fixture();f.registry.postOptions(f.body,{});refused(()=>f.registry.postOptions(f.body,{}),"provider_only_one_original_post_form");});
await test("P11_custom_fetch_parameter_denied",async()=>{const f=fixture();f.params.fetchImpl=()=>{};refused(()=>f.prepare(),"provider_original_ssrf_guard_parameters");});
await test("P12_direct_global_route_has_no_owned_dispatcher",async()=>{const f=fixture();f.enter();refused(()=>f.registry.dispatch(f.ticket,TOKEN_URL,f.wire,()=>Promise.resolve(),false),"provider_final_native_send_requires_owned_dispatcher");await f.close();assert.equal(f.receipt.originalNativeFetchInvocations,0);});
await test("P13_second_native_fetch_refused",async()=>{const f=fixture();f.enter();await f.send();refused(()=>f.registry.dispatch(f.ticket,TOKEN_URL,f.wire,()=>Promise.resolve(),true),"provider_final_native_send_requires_owned_dispatcher");assert.equal(f.receipt.originalNativeFetchInvocations,1);await f.close();});
await test("P14_deadline_after_dns_before_send",async()=>{let now=1n;const f=fixture({until:100n,clock:()=>now});f.enter();now=100n;refused(()=>f.registry.dispatch(f.ticket,TOKEN_URL,f.wire,()=>Promise.resolve(),true),"provider_original_absolute_deadline_or_context");await f.close();assert.equal(f.receipt.originalNativeFetchInvocations,0);});
await test("P15_source_changed_at_final_dispatch",async()=>{let changed=false;const f=fixture({fence:()=>{if(changed)throw new ProviderOnceRefused("provider_synthetic_source_changed");}});f.enter();changed=true;refused(()=>f.registry.dispatch(f.ticket,TOKEN_URL,f.wire,()=>Promise.resolve(),true),"provider_synthetic_source_changed");await f.close();});
await test("P16_forged_ticket",async()=>{const f=fixture();f.prepare();refused(()=>f.registry.enterRuntime({},TOKEN_URL,f.wire),"provider_original_private_ticket");});
await test("P17_capture_before_original_native_send",async()=>{const f=fixture();f.enter();refused(()=>f.registry.captureResponse(new Response("{}"),Buffer.from("{}")),"provider_response_before_original_release_once");await f.close();});
await test("P18_original_response_limit",async()=>{const f=fixture();f.enter();const r=await f.send();refused(()=>f.registry.captureResponse(r,Buffer.alloc(1048577)),"provider_original_one_mib_response_limit");await f.close();});
await test("P19_private_capture_failure_cannot_reach_parser",async()=>{const f=fixture({capture:()=>{throw new ProviderOnceRefused("provider_synthetic_fsync");}});f.enter();const r=await f.send();refused(()=>f.registry.captureResponse(r,Buffer.from("{}")),"provider_synthetic_fsync");assert.equal(f.receipt.completeBodyCaptures,0);await f.close();});
await test("P20_original_close_promise_pending_not_closure",async()=>{
  let finish;const receipt={originalDispatcherMethodCalls:0},d={closed:false,destroyed:false,close(){return new Promise(r=>{finish=()=>{this.closed=true;r();};});},destroy(){this.destroyed=true;return Promise.resolve();}};
  const o=observeOriginalDispatcherClosure(d,receipt),p=d.close();assert.equal(o.known(),false);let observed=false;Promise.all(o.originalPromises).then(()=>{observed=true;});await Promise.resolve();assert.equal(observed,false);
  finish();await p;await Promise.all(o.originalPromises);assert.equal(o.known(),true);o.restore();assert.equal(receipt.originalDispatcherMethodCalls,1);
});
await test("P21_original_close_rejection_unknown",async()=>{
  const receipt={originalDispatcherMethodCalls:0},d={closed:true,destroyed:false,close(){return Promise.reject(Error("synthetic close acknowledgement"));},destroy(){return Promise.resolve();}},o=observeOriginalDispatcherClosure(d,receipt);
  await assert.rejects(d.close());await Promise.all(o.originalPromises);assert.equal(o.known(),false);o.restore();
});
await test("P22_cleanup_calls_observed_without_added_calls",async()=>{const f=fixture();f.enter();await f.dispatcher.close();await f.dispatcher.close();f.registry.releaseKnown(f.ticket,f.dispatcher);await f.ctx.dispatcherObservers[0].settleOriginalPromises();assert.equal(f.ctx.dispatcherObservers[0].known(),true);f.ctx.dispatcherObservers[0].restore();assert.equal(f.receipt.originalDispatcherMethodCalls,2);});
await test("P23_original_destroy_completion_observed",async()=>{const f=fixture();f.enter();await f.dispatcher.destroy();f.registry.releaseKnown(f.ticket,f.dispatcher);await Promise.all(f.ctx.dispatcherObservers[0].originalPromises);assert.equal(f.ctx.dispatcherObservers[0].known(),true);f.ctx.dispatcherObservers[0].restore();});
await test("P24_cleanup_observation_after_business_deadline",async()=>{const f=fixture();f.enter();await f.send();f.ctx.closed=true;await f.close();assert.equal(f.receipt.originalCloseHelperReturned,true);refused(()=>f.registry.assertEntry(fakeCredential.refresh),"provider_original_absolute_deadline_or_context");});
await test("P25_dispatcher_close_replaced_before_capture",async()=>{const f=fixture();f.enter();const r=await f.send();f.dispatcher.close=()=>Promise.resolve();refused(()=>f.registry.captureResponse(r,Buffer.from("{}")),"provider_original_dispatcher_observer_replaced");refused(()=>f.ctx.dispatcherObservers[0].restore(),"provider_original_dispatcher_observer_replaced");});
await test("P26_native_rejection_settles_once",async()=>{const f=fixture();f.enter();await assert.rejects(f.send(()=>Promise.reject(Error("synthetic network"))));await Promise.all(f.ctx.nativePromises);assert.equal(f.receipt.originalNativeFetchInvocations,1);assert.equal(f.receipt.originalNativeFetchSettlements,1);await f.close();});
await test("P27_redirect_send_url_cannot_change",async()=>{const f=fixture();f.enter();refused(()=>f.registry.dispatch(f.ticket,"https://auth.openai.com/other",f.wire,()=>Promise.resolve(),true),"provider_exact_native_endpoint_method");await f.close();});
await test("P28_release_must_match_original_dispatcher",async()=>{const f=fixture();f.enter();refused(()=>f.registry.releaseKnown(f.ticket,{}),"provider_original_dispatcher_release");await f.close();});
await test("P29_modified_dispatcher_state_without_method_promise_is_not_closure",async()=>{const f=fixture();f.enter();f.dispatcher.closed=true;f.registry.releaseKnown(f.ticket,f.dispatcher);assert.equal(f.ctx.dispatcherObservers[0].known(),false);f.ctx.dispatcherObservers[0].restore();});
await test("P30_response_after_release_refused",async()=>{const f=fixture();f.enter();const r=await f.send();await f.close();refused(()=>f.registry.captureResponse(r,Buffer.from("{}")),"provider_response_before_original_release_once");});

// Verbatim installed DispatcherBase + original SDK close helper. Dependencies
// are explicit local harness stubs; these cases are not installed-Mac imports.
function actualBaseFixture({pendingClose=false}={}){
 const source=fs.readFileSync(path.join(here,"reference/undici-dispatcher-base.js"),"utf8");
 assert.equal(crypto.createHash("sha256").update(source).digest("hex"),"88d306b49e472f4fac61b5fae1320ff8fb01a41ef211e7c2d9992782a297bb0e");
 const symbols=Object.fromEntries(["kDestroy","kClose","kClosed","kDestroyed","kDispatch"].map(k=>[k,Symbol(k)]));
 const module={exports:{}};
 const stubRequire=name=>{
  if(name==="./dispatcher")return class Dispatcher{};
  if(name==="../core/symbols")return symbols;
  if(name==="../core/errors")return {ClientDestroyedError:class extends Error{},ClientClosedError:class extends Error{},InvalidArgumentError:class extends Error{}};
  throw new Error("unexpected_harness_dependency");
 };
 vm.runInNewContext(source,{require:stubRequire,module,exports:module.exports,queueMicrotask,Promise,Symbol});
 const base=new module.exports();let finishClose;const counts={close:0,destroy:0};
 base[symbols.kClose]=()=>{counts.close++;return pendingClose?new Promise(resolve=>{finishClose=resolve;}):Promise.resolve();};
 base[symbols.kDestroy]=()=>{counts.destroy++;return Promise.resolve();};
 return {base,counts,finishClose:()=>finishClose()};
}
function actualHelper(){
 const source=fs.readFileSync(path.join(here,"reference/ssrf-BayeDjCv.js"),"utf8");
 assert.equal(crypto.createHash("sha256").update(source).digest("hex"),"dd29e02505654eb7aac62519013fe9cdd883b56f78855806f6d643aadadc4295");
 const start=source.indexOf("function destroyDispatcher(candidate) {"),end=source.indexOf("async function assertPublicHostname",start);
 assert(start>0&&end>start);
 return vm.runInNewContext("const DISPATCHER_CLOSE_TIMEOUT_MS=100;\n"+source.slice(start,end)+"\ncloseDispatcher",{setTimeout,clearTimeout,Promise});
}
await test("P31_actual_base_promise_callback_close_shape",async()=>{
 const f=actualBaseFixture(),r={originalDispatcherMethodCalls:0},o=observeOriginalDispatcherClosure(f.base,r);
 await actualHelper()(f.base);await o.settleOriginalPromises();assert.equal(o.known(),true);
 assert.equal(r.originalDispatcherMethodCalls,4);assert.equal(r.originalDispatcherPromiseCalls,2);assert.equal(r.originalDispatcherInternalCallbackCalls,2);
 assert.deepEqual(f.counts,{close:1,destroy:1});o.restore();
});
await test("P32_actual_base_promise_callback_destroy_shape",async()=>{
 const f=actualBaseFixture(),r={},o=observeOriginalDispatcherClosure(f.base,r);
 await f.base.destroy();await o.settleOriginalPromises();assert.equal(o.known(),true);
 assert.equal(r.originalDispatcherMethodCalls,2);assert.equal(r.originalDispatcherPromiseCalls,1);assert.equal(r.originalDispatcherInternalCallbackCalls,1);o.restore();
});
await test("P33_original_helper_100ms_return_not_close_settlement",async()=>{
 const f=actualBaseFixture({pendingClose:true}),r={},o=observeOriginalDispatcherClosure(f.base,r);
 const keepAlive=setTimeout(()=>{},1000);
 try{
  await actualHelper()(f.base);assert.equal(o.known(),false);assert.equal(f.counts.destroy,1);
  let settled=false;const p=o.settleOriginalPromises().then(()=>{settled=true;});await Promise.resolve();assert.equal(settled,false);
  f.finishClose();await p;assert.equal(o.known(),true);assert.equal(r.originalDispatcherPromiseCalls,3);
  assert.equal(r.originalDispatcherInternalCallbackCalls,3);assert.equal(r.originalDispatcherMethodCalls,6);
  // Original base destroys its storage only once despite two public destroy calls.
  assert.deepEqual(f.counts,{close:1,destroy:1});o.restore();
 }finally{clearTimeout(keepAlive);}
});
await test("P34_actual_base_duplicate_destroy_is_observed_not_replayed",async()=>{
 const f=actualBaseFixture(),r={},o=observeOriginalDispatcherClosure(f.base,r);
 await f.base.destroy();await f.base.destroy();await o.settleOriginalPromises();assert.equal(o.known(),true);
 assert.equal(r.originalDispatcherMethodCalls,4);assert.equal(f.counts.destroy,1);o.restore();
});
await test("P35_external_callback_shape_preserved_but_not_admitted",async()=>{
 const f=actualBaseFixture(),r={},o=observeOriginalDispatcherClosure(f.base,r);
 await new Promise((resolve,reject)=>{assert.equal(f.base.close(error=>error?reject(error):resolve()),undefined);});
 await o.settleOriginalPromises();assert.equal(o.known(),false);assert.deepEqual(f.counts,{close:1,destroy:1});o.restore();
});
await test("P36_original_throw_identity_preserved",async()=>{
 const error=new Error("synthetic original throw"),r={},d={close(){throw error;},destroy(){return Promise.resolve();},closed:false,destroyed:false};
 const o=observeOriginalDispatcherClosure(d,r);assert.throws(()=>d.close(),e=>e===error);assert.equal(o.known(),false);o.restore();
});
await test("P37_observation_cap_does_not_interrupt_original_cleanup",async()=>{
 const f=actualBaseFixture(),r={},o=observeOriginalDispatcherClosure(f.base,r);
 for(let i=0;i<18;i++)await f.base.destroy();await o.settleOriginalPromises();assert.equal(o.known(),false);
 assert.equal(r.originalDispatcherMethodCalls,36);assert.equal(f.counts.destroy,1);o.restore();
});
await test("P38_original_descriptors_restored_after_internal_calls",async()=>{
 const f=actualBaseFixture(),close=f.base.close,destroy=f.base.destroy,r={},o=observeOriginalDispatcherClosure(f.base,r);
 await f.base.close();await o.settleOriginalPromises();o.restore();assert.equal(f.base.close,close);assert.equal(f.base.destroy,destroy);
 assert.equal(Object.hasOwn(f.base,"close"),false);assert.equal(Object.hasOwn(f.base,"destroy"),false);
});
await test("P39_actual_package_metadata_bound_without_import",async()=>{
 const files={"undici-package.json":"4eed584bdf6a1545381c24674dfe8938421f7c66313c8960fb40f28f3a55c306","undici-index.js":"93fc85c00a59b58f410c901e5477d56770de3816bfbe183e751624aeb4a5e6a5"};
 for(const [name,pin]of Object.entries(files))assert.equal(crypto.createHash("sha256").update(fs.readFileSync(path.join(here,"reference",name))).digest("hex"),pin);
 assert.equal(JSON.parse(fs.readFileSync(path.join(here,"reference/undici-package.json"))).version,"8.5.0");
});
await test("P40_old_observer_rejects_verbatim_internal_callback",async()=>{
 const f=actualBaseFixture(),r={originalDispatcherMethodCalls:0},o=oldObserver(f.base,r);
 await assert.rejects(f.base.close(),e=>e.code==="provider_original_dispatcher_call_not_replayed");
 await Promise.all(o.originalPromises);assert.equal(o.known(),false);assert.deepEqual(f.counts,{close:0,destroy:0});o.restore();
});
const result={schema:"heptabao.provider-hooks-local-qualification.r2",ok:results.every(x=>x.passed),executed:results.length,passed:results.filter(x=>x.passed).length,
  cases:results,actualSdkModulesImported:false,actualProviderCalls:0,productionWrites:0,networkRequests:0,
  qualificationScope:"source-bound overlays, synthetic registry faults, and verbatim DispatcherBase/close helper under explicit harness dependencies; no installed SDK import",
  sourceSha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(here,"mac_refresh_provider_hooks_r2.mjs"))).digest("hex"),
  elapsedSeconds:Number(process.hrtime.bigint()-start)/1e9};process.stdout.write(JSON.stringify(result)+"\n");if(!result.ok)process.exitCode=1;
