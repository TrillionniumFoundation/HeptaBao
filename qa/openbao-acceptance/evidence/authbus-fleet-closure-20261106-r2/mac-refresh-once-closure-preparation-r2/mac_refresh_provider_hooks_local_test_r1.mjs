/** Local source-bound overlay/registry faults. No SDK import, DNS, TLS or OAuth.
 * Dispatcher and native fetch are explicit synthetic objects. */
import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {fileURLToPath} from "node:url";
import {TOKEN_URL,CLIENT_ID,PROVIDER_SOURCE_PINS,ProviderOnceRefused,patchProviderSource,makeProviderRegistry,observeOriginalDispatcherClosure} from "./mac_refresh_provider_hooks_r1.mjs";
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
  const out=path.join(here,"provider-overlays-r1");fs.mkdirSync(out,{recursive:true});let changed=0;
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
await test("P22_original_close_never_replayed",async()=>{const f=fixture();f.enter();await f.dispatcher.close();refused(()=>f.dispatcher.close(),"provider_original_dispatcher_call_not_replayed");f.registry.releaseKnown(f.ticket,f.dispatcher);await Promise.all(f.ctx.dispatcherObservers[0].originalPromises);f.ctx.dispatcherObservers[0].restore();assert.equal(f.receipt.originalDispatcherMethodCalls,1);});
await test("P23_original_destroy_completion_observed",async()=>{const f=fixture();f.enter();await f.dispatcher.destroy();f.registry.releaseKnown(f.ticket,f.dispatcher);await Promise.all(f.ctx.dispatcherObservers[0].originalPromises);assert.equal(f.ctx.dispatcherObservers[0].known(),true);f.ctx.dispatcherObservers[0].restore();});
await test("P24_cleanup_observation_after_business_deadline",async()=>{const f=fixture();f.enter();await f.send();f.ctx.closed=true;await f.close();assert.equal(f.receipt.originalCloseHelperReturned,true);refused(()=>f.registry.assertEntry(fakeCredential.refresh),"provider_original_absolute_deadline_or_context");});
await test("P25_dispatcher_close_replaced_before_capture",async()=>{const f=fixture();f.enter();const r=await f.send();f.dispatcher.close=()=>Promise.resolve();refused(()=>f.registry.captureResponse(r,Buffer.from("{}")),"provider_original_dispatcher_observer_replaced");refused(()=>f.ctx.dispatcherObservers[0].restore(),"provider_original_dispatcher_observer_replaced");});
await test("P26_native_rejection_settles_once",async()=>{const f=fixture();f.enter();await assert.rejects(f.send(()=>Promise.reject(Error("synthetic network"))));await Promise.all(f.ctx.nativePromises);assert.equal(f.receipt.originalNativeFetchInvocations,1);assert.equal(f.receipt.originalNativeFetchSettlements,1);await f.close();});
await test("P27_redirect_send_url_cannot_change",async()=>{const f=fixture();f.enter();refused(()=>f.registry.dispatch(f.ticket,"https://auth.openai.com/other",f.wire,()=>Promise.resolve(),true),"provider_exact_native_endpoint_method");await f.close();});
await test("P28_release_must_match_original_dispatcher",async()=>{const f=fixture();f.enter();refused(()=>f.registry.releaseKnown(f.ticket,{}),"provider_original_dispatcher_release");await f.close();});
await test("P29_modified_dispatcher_state_without_method_promise_is_not_closure",async()=>{const f=fixture();f.enter();f.dispatcher.closed=true;f.registry.releaseKnown(f.ticket,f.dispatcher);assert.equal(f.ctx.dispatcherObservers[0].known(),false);f.ctx.dispatcherObservers[0].restore();});
await test("P30_response_after_release_refused",async()=>{const f=fixture();f.enter();const r=await f.send();await f.close();refused(()=>f.registry.captureResponse(r,Buffer.from("{}")),"provider_response_before_original_release_once");});
const result={schema:"heptabao.provider-hooks-local-qualification.r1",ok:results.every(x=>x.passed),executed:results.length,passed:results.filter(x=>x.passed).length,
  cases:results,actualSdkModulesImported:false,actualProviderCalls:0,productionWrites:0,networkRequests:0,
  qualificationScope:"source-bound overlay construction and synthetic registry/dispatcher fault semantics only",
  sourceSha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(here,"mac_refresh_provider_hooks_r1.mjs"))).digest("hex"),
  elapsedSeconds:Number(process.hrtime.bigint()-start)/1e9};process.stdout.write(JSON.stringify(result)+"\n");if(!result.ok)process.exitCode=1;
