/** Source-bound, in-memory provider hooks. Prepared; no top-level provider call.
 * Production must run in a fresh owned process and install these hooks before
 * importing any SDK module. No installed SDK file is modified.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import * as moduleApi from "node:module";
import {pathToFileURL} from "node:url";
import {isDeepStrictEqual} from "node:util";
export const PROVIDER_SDK_ROOT="/opt/homebrew/lib/node_modules/openclaw";
export const TOKEN_URL="https://auth.openai.com/oauth/token";
export const CLIENT_ID="app_EMoamEEZ73f0CkXaXp7hrann";
export const REGISTRY_SYMBOL="heptabao.main3.refresh-once.provider.r1";
export const PROVIDER_SOURCE_PINS=Object.freeze({
  "dist/openai-chatgpt-oauth-flow.runtime-DOVvnAqe.js":"e3852eb201e21b907beed38facea3b115f1058a80ba66436dc7202d36c6df07d",
  "dist/fetch-guard-6VNcgVVc.js":"ef4befea09e2fbf0bece7bfc5cc46102843ee1070182fdab5b98f3c632a88bfc",
  "dist/runtime-fetch-k5Zth7kk.js":"9bf76247c5901725af5db78bbab2830a5e0fd7caf19953b095be74d4382db611",
  "dist/http-body-CHWaxK2e.js":"3098bc392de8510aea95e96088472712f474db9600104e54e764571221f83d77",
  "dist/provider-oauth-runtime-Bl5CxvHn.js":"72815eec3eb285768cd7fbe1495e9e3e34f309e6d828cc844322b1e411fb0b64",
  "dist/openai-chatgpt-auth-identity-DrQLjrg2.js":"94d48f2fee6a6fc139438d53d1adbadb61dd9791febe11ea0ec1c960e30e3765"
});
export class ProviderOnceRefused extends Error {
  constructor(code){super(code);this.name="ProviderOnceRefused";this.code=code;}
}
const need=(x,c)=>{if(!x)throw new ProviderOnceRefused(c);};
const sha=x=>crypto.createHash("sha256").update(x).digest("hex");
const full=s=>["dev","ino","uid","gid","mode","nlink","size","mtimeNs","ctimeNs"].map(k=>String(s[k]));
function once(source,before,after){const at=source.indexOf(before);need(at>=0&&source.indexOf(before,at+before.length)<0,"provider_exact_source_boundary");return source.slice(0,at)+after+source.slice(at+before.length);}
const helper=`function heptabaoMain3ProviderOnce() {
  const value = globalThis[Symbol.for("${REGISTRY_SYMBOL}")];
  if (!value || typeof value.assertEntry !== "function" || typeof value.prepare !== "function" ||
      typeof value.dispatch !== "function" || typeof value.captureResponse !== "function")
    throw Object.assign(new Error("provider_once_registry_unavailable"), { code: "provider_once_registry_unavailable" });
  return value;
}
`;

/** Observe original SDK calls only. No extra close/destroy call or retry is
 * issued. The owning wrapper must await originalPromises before admitting the
 * next ordinal. Original helper return is recorded separately from closure. */
export function observeOriginalDispatcherClosure(dispatcher,receipt){
  need(dispatcher&&typeof dispatcher.close==="function"&&typeof dispatcher.destroy==="function","provider_original_owned_dispatcher_methods");
  const saved=new Map(),wrappers=new Map(),calls=[],originalPromises=[];let restored=false;
  for(const name of ["close","destroy"]){
    const descriptor=Object.getOwnPropertyDescriptor(dispatcher,name),original=dispatcher[name];saved.set(name,{descriptor,original});
    const wrapper=function(...args){
      need(this===dispatcher&&!restored&&calls.filter(x=>x.name===name).length===0,"provider_original_dispatcher_call_not_replayed");
      const row={name,returnedPromise:false,settled:false,fulfilled:false};calls.push(row);receipt.originalDispatcherMethodCalls++;
      let result;try{result=original.apply(dispatcher,args);}catch(e){row.settled=true;throw e;}
      need(result&&typeof result.then==="function","provider_original_dispatcher_promise_required");row.returnedPromise=true;
      originalPromises.push(Promise.resolve(result).then(()=>{row.settled=true;row.fulfilled=true;},()=>{row.settled=true;}));
      return result;
    };
    wrappers.set(name,wrapper);
    try{Object.defineProperty(dispatcher,name,{value:wrapper,writable:true,configurable:true});}
    catch(e){
      for(const [old,record]of saved){if(dispatcher[old]===wrappers.get(old)){if(record.descriptor)Object.defineProperty(dispatcher,old,record.descriptor);else delete dispatcher[old];}}
      throw new ProviderOnceRefused("provider_original_dispatcher_observer_install");
    }
  }
  return Object.freeze({
    originalPromises,
    verifyInstalled(){need(!restored&&[...wrappers].every(([name,value])=>dispatcher[name]===value),"provider_original_dispatcher_observer_replaced");},
    known(){return calls.length>0&&calls.every(x=>x.returnedPromise&&x.settled&&x.fulfilled)&&(dispatcher.closed===true||dispatcher.destroyed===true);},
    restore(){
      need(!restored,"provider_dispatcher_observer_restore_once");
      const unchanged=[...wrappers].every(([name,value])=>dispatcher[name]===value);
      for(const [name,record]of saved){if(dispatcher[name]===wrappers.get(name)){if(record.descriptor)Object.defineProperty(dispatcher,name,record.descriptor);else delete dispatcher[name];}}
      restored=true;need(unchanged,"provider_original_dispatcher_observer_replaced");
    }
  });
}

export function patchProviderSource(relative,original){
  need(Object.hasOwn(PROVIDER_SOURCE_PINS,relative)&&sha(original)===PROVIDER_SOURCE_PINS[relative],"provider_original_source_pin");
  let source=original;
  if(relative.endsWith("openai-chatgpt-oauth-flow.runtime-DOVvnAqe.js")){
    source=once(source,"async function refreshOpenAICodexToken(refreshToken) {\n",
      "async function refreshOpenAICodexToken(refreshToken) {\n\theptabaoMain3ProviderOnce().assertEntry(refreshToken);\n");
    source=once(source,"async function refreshAccessToken(refreshToken, options = {}) {\n",
      "async function refreshAccessToken(refreshToken, options = {}) {\n\theptabaoMain3ProviderOnce().assertEntry(refreshToken);\n");
    source=once(source,"async function postTokenForm(body, options = {}) {\n",
      "async function postTokenForm(body, options = {}) {\n\toptions = heptabaoMain3ProviderOnce().postOptions(body, options);\n");
    source=once(source,"\t\treturn new Response(new Uint8Array(responseBody), {\n",
      "\t\theptabaoMain3ProviderOnce().captureResponse(response, responseBody);\n\t\treturn new Response(new Uint8Array(responseBody), {\n");
    return helper+source;
  }
  if(relative.endsWith("fetch-guard-6VNcgVVc.js")){
    source=once(source,"async function fetchWithSsrFGuardInternal(params) {\n",
      "async function fetchWithSsrFGuardInternal(params) {\n\tconst heptaOnceTicket = heptabaoMain3ProviderOnce().prepare(params);\n");
    source=once(source,"\t\tawait closeDispatcher(dispatcher ?? void 0);\n",
      "\t\tawait closeDispatcher(dispatcher ?? void 0);\n\t\theptabaoMain3ProviderOnce().releaseKnown(heptaOnceTicket, dispatcher);\n");
    source=once(source,"\t\t\tconst response = shouldUseRuntimeFetch ? await fetchWithRuntimeDispatcher(parsedUrl.toString(), init) : await defaultFetch(parsedUrl.toString(), init);",
      "\t\t\tconst response = shouldUseRuntimeFetch ? await fetchWithRuntimeDispatcher(parsedUrl.toString(), init, heptaOnceTicket) : await heptabaoMain3ProviderOnce().dispatch(heptaOnceTicket, parsedUrl.toString(), init, defaultFetch, false);");
    source=once(source,"\t\t\tawait captureGuardedFetchExchange({",
      "\t\t\tif (!heptaOnceTicket) await captureGuardedFetchExchange({");
    source=once(source,"\t\t\tif (isRedirectStatus(response.status)) {\n",
      "\t\t\tif (isRedirectStatus(response.status)) {\n\t\t\t\tawait response.body?.cancel();\n\t\t\t\tawait release(dispatcher);\n\t\t\t\tthrow new Error(\"provider_once_redirect_refused\");\n");
    return helper+source;
  }
  if(relative.endsWith("runtime-fetch-k5Zth7kk.js")){
    source=once(source,"async function fetchWithRuntimeDispatcher(input, init) {\n",
      "async function fetchWithRuntimeDispatcher(input, init, heptaOnceTicket) {\n\theptabaoMain3ProviderOnce().enterRuntime(heptaOnceTicket, input, init);\n");
    source=once(source,"\treturn await runtimeFetch(input, normalizeRuntimeRequestInit(init, runtimeDeps.FormData));",
      "\treturn await heptabaoMain3ProviderOnce().dispatch(heptaOnceTicket, input, normalizeRuntimeRequestInit(init, runtimeDeps.FormData), runtimeFetch, true);");
    return helper+source;
  }
  return source;
}

/** Pure registry factory is exported for synthetic fault qualification. Its
 * context is supplied only by loadQualifiedMacProvider's private closure. */
export function makeProviderRegistry({current,clock=()=>process.hrtime.bigint(),sourceFence}){
  const tickets=new WeakMap();
  const active=()=>{
    const ctx=current();need(ctx&&!ctx.closed&&typeof ctx.until==="bigint"&&clock()<ctx.until&&!ctx.signal.aborted,"provider_original_absolute_deadline_or_context");
    sourceFence();ctx.assertLive();need(clock()<ctx.until&&!ctx.signal.aborted,"provider_original_absolute_deadline_or_context");return ctx;
  };
  const shape=(ctx,url,init)=>{
    need(url===TOKEN_URL&&init&&init.method==="POST","provider_exact_native_endpoint_method");
    need(init.body instanceof URLSearchParams||typeof init.body==="string","provider_original_form_body");
    const entries=[...new URLSearchParams(init.body).entries()];
    need(isDeepStrictEqual(entries,[["grant_type","refresh_token"],["refresh_token",ctx.oldCredential.refresh],["client_id",CLIENT_ID]]),"provider_exact_selected_refresh_form");
    const headers=[...new Headers(init.headers).entries()];
    need(headers.length===1&&headers[0][0]==="content-type"&&headers[0][1]==="application/x-www-form-urlencoded","provider_exact_token_headers");
  };
  const ticketContext=ticket=>{
    const ctx=active(),entry=tickets.get(ticket);need(entry?.ctx===ctx,"provider_original_private_ticket");return {ctx,entry};
  };
  return Object.freeze({
    assertEntry(refreshToken){const ctx=active();need(refreshToken===ctx.oldCredential.refresh,"provider_exact_selected_refresh_entry");ctx.receipt.flowEntrypointChecks++;},
    postOptions(body,options){
      const ctx=active();shape(ctx,TOKEN_URL,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body});
      need(options&&Object.getPrototypeOf(options)===Object.prototype&&Object.keys(options).every(k=>["signal","timeoutMs"].includes(k))&&
        (options.signal===undefined||options.signal===ctx.signal),"provider_original_flow_options");
      const left=Number((ctx.until-clock())/1000000n);need(left>0,"provider_original_absolute_deadline_or_context");
      const requested=options.timeoutMs??30000;need(Number.isFinite(requested)&&requested>0&&requested<=30000,"provider_original_30_second_budget");
      ctx.receipt.postFormEntries++;need(ctx.receipt.postFormEntries===1,"provider_only_one_original_post_form");
      return {...options,signal:ctx.signal,timeoutMs:Math.max(1,Math.min(requested,left))};
    },
    prepare(params){
      const ctx=active();shape(ctx,params.url,params.init);
      need(Object.keys(params).every(k=>["url","init","timeoutMs","signal","auditContext"].includes(k))&&params.signal===ctx.signal&&
        params.auditContext==="openai-chatgpt-oauth-token"&&Number.isFinite(params.timeoutMs)&&params.timeoutMs>0&&params.timeoutMs<=30000,
        "provider_original_ssrf_guard_parameters");
      need(typeof globalThis.fetch==="function"&&typeof globalThis.fetch.mock!=="object","provider_no_mocked_or_custom_global_fetch");
      ctx.receipt.guardEntries++;need(ctx.receipt.guardEntries===1,"provider_one_ssrf_guard_preparation");
      const ticket=Object.freeze({});tickets.set(ticket,{ctx,runtimeEntries:0,dispatches:0,dispatcher:null,released:false});ctx.ticket=ticket;return ticket;
    },
    enterRuntime(ticket,url,init){
      const {ctx,entry}=ticketContext(ticket);shape(ctx,url,init);entry.runtimeEntries++;ctx.receipt.runtimeEntries++;
      need(entry.runtimeEntries===1&&init.redirect==="manual"&&init.dispatcher&&typeof init.dispatcher.close==="function"&&
        typeof init.dispatcher.destroy==="function"&&init.signal&&!init.signal.aborted,"provider_one_owned_dispatcher_runtime_entry");
      entry.dispatcher=init.dispatcher;
      entry.observer=observeOriginalDispatcherClosure(init.dispatcher,ctx.receipt);ctx.dispatcherObservers.push(entry.observer);
    },
    dispatch(ticket,url,init,send,runtime){
      const {ctx,entry}=ticketContext(ticket);shape(ctx,url,init);
      need(runtime===true&&entry.runtimeEntries===1&&entry.dispatches===0&&typeof send==="function"&&
        init.redirect==="manual"&&init.dispatcher===entry.dispatcher&&init.signal&&!init.signal.aborted,
        "provider_final_native_send_requires_owned_dispatcher");
      entry.dispatches++;ctx.receipt.finalNativeSendEntries++;
      // All preceding SDK DNS/proxy/dispatcher awaits have completed. The
      // controller persists its UNKNOWN latch, performs sync source/mutex/
      // writer/ledger checks, then invokes this exact original native fetch.
      entry.observer.verifyInstalled();
      return ctx.finalDispatch(()=>{
        ctx.receipt.originalNativeFetchInvocations++;let result;
        try{result=send(url,init);}catch(e){ctx.receipt.originalNativeFetchSettlements++;throw e;}
        need(result&&typeof result.then==="function","provider_original_native_fetch_promise_required");
        ctx.nativePromises.push(Promise.resolve(result).then(()=>{ctx.receipt.originalNativeFetchSettlements++;},()=>{ctx.receipt.originalNativeFetchSettlements++;}));
        return result;
      });
    },
    captureResponse(response,body){
      const ctx=active(),entry=tickets.get(ctx.ticket);
      need(entry?.ctx===ctx&&entry.dispatches===1&&!entry.released&&ctx.receipt.completeBodyCaptures===0,
        "provider_response_before_original_release_once");
      need(response&&Number.isInteger(response.status)&&response.status>=100&&response.status<=599&&
        (body instanceof ArrayBuffer||ArrayBuffer.isView(body)),"provider_complete_body_type");
      const bytes=Buffer.from(body instanceof ArrayBuffer?new Uint8Array(body):new Uint8Array(body.buffer,body.byteOffset,body.byteLength));
      need(bytes.length<=1048576,"provider_original_one_mib_response_limit");
      const headers=[...response.headers.entries()];need(headers.length<=128&&Buffer.byteLength(JSON.stringify(headers))<=65536,"provider_bounded_private_response_headers");
      entry.observer.verifyInstalled();ctx.responseCapture({status:response.status,headers,bytes});ctx.receipt.completeBodyCaptures++;ctx.receipt.rawResponseFsyncedBeforeSdkParser=true;
    },
    releaseKnown(ticket,dispatcher){
      // Release is cleanup, so it may record completion after the business
      // deadline. It neither permits a send nor writes source/credential data.
      const ctx=current(),entry=tickets.get(ticket);need(ctx&&entry?.ctx===ctx&&!entry.released,"provider_original_release_context_once");
      need(entry.dispatcher===null||dispatcher===entry.dispatcher,"provider_original_dispatcher_release");
      entry.released=true;ctx.receipt.originalDispatcherReleaseCompletions++;
      // This is only the original close helper's return. Actual dispatcher
      // method promises and terminal state are checked in refresh finally.
      ctx.receipt.originalCloseHelperReturned=true;
    }
  });
}

function readPublic(filename){
  const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{
    const s=fs.fstatSync(fd,{bigint:true});need(s.isFile()&&s.nlink===1n&&[0n,501n].includes(s.uid)&&(s.mode&18n)===0n&&s.size>0n&&s.size<=1048576n,"provider_public_source_custody");
    const b=Buffer.alloc(Number(s.size)+1);let n=0;
    while(n<b.length){const k=fs.readSync(fd,b,n,b.length-n,null);if(!k)break;n+=k;}
    need(n===Number(s.size)&&isDeepStrictEqual(full(s),full(fs.fstatSync(fd,{bigint:true})))&&isDeepStrictEqual(full(s),full(fs.lstatSync(filename,{bigint:true}))),"provider_public_source_stable");
    return b.subarray(0,n);
  }finally{fs.closeSync(fd);}
}

export async function loadQualifiedMacProvider(report={}){
  need(process.platform==="darwin"&&process.getuid()===501&&typeof moduleApi.registerHooks==="function","provider_exact_mac_fresh_runtime");
  const symbol=Symbol.for(REGISTRY_SYMBOL);need(!Object.hasOwn(globalThis,symbol),"provider_no_previous_registry_context");
  let ctx=null,disposed=false,flow=null;
  const sourceFence=()=>{for(const [relative,pin]of Object.entries(PROVIDER_SOURCE_PINS))need(sha(readPublic(path.join(PROVIDER_SDK_ROOT,relative)))===pin,"provider_current_source_pin");};
  sourceFence();const sources=new Map();
  Object.assign(report,{schema:"heptabao.main3-provider-hook-source.public.r1",modules:[],installedSourceModified:false,
    actualSdkModuleHooks:true,sourcePins:PROVIDER_SOURCE_PINS,contextsStarted:0,successfulSdkRefreshCalls:0,disposed:false});
  for(const [relative,pin]of Object.entries(PROVIDER_SOURCE_PINS)){
    const original=readPublic(path.join(PROVIDER_SDK_ROOT,relative)).toString("utf8"),source=patchProviderSource(relative,original);
    const row={relative,originalSha256:pin,overlaySha256:sha(source),changed:source!==original,loaded:false};report.modules.push(row);
    sources.set(pathToFileURL(path.join(PROVIDER_SDK_ROOT,relative)).href,{source,row});
  }
  const registry=makeProviderRegistry({current:()=>ctx,sourceFence});
  Object.defineProperty(globalThis,symbol,{value:registry,writable:false,configurable:true,enumerable:false});
  const hook=moduleApi.registerHooks({load(url,context,nextLoad){const candidate=sources.get(url);if(!candidate)return nextLoad(url,context);candidate.row.loaded=true;return {format:"module",source:candidate.source,shortCircuit:true};}});
  const dispose=()=>{
    need(!disposed&&!ctx,"provider_dispose_after_original_context_closed");need(globalThis[symbol]===registry,"provider_registry_unchanged_before_dispose");
    hook.deregister();delete globalThis[symbol];disposed=true;report.disposed=true;sourceFence();
  };
  try{
    flow=await import(pathToFileURL(path.join(PROVIDER_SDK_ROOT,"dist/openai-chatgpt-oauth-flow.runtime-DOVvnAqe.js")).href);
    need(typeof flow.r==="function"&&flow.n?.id==="openai"&&report.modules.every(x=>x.loaded),"provider_all_current_modules_loaded_through_hook");sourceFence();
  }catch(e){try{dispose();}catch{}throw new ProviderOnceRefused(e instanceof ProviderOnceRefused?e.code:"provider_actual_sdk_import_refused");}
  return Object.freeze({sourceFence,dispose,contextIsClosed:()=>ctx===null,
    async refresh(params,receipt={}){
      need(!disposed&&!ctx&&params&&params.oldCredential?.type==="oauth"&&params.oldCredential?.provider==="openai"&&
        typeof params.oldCredential.refresh==="string"&&params.oldCredential.refresh.length>0&&typeof params.until==="bigint"&&
        typeof params.finalDispatch==="function"&&typeof params.responseCapture==="function"&&typeof params.assertLive==="function"&&params.signal instanceof AbortSignal,
        "provider_one_original_selected_context");
      const now=process.hrtime.bigint();need(now<params.until&&!params.signal.aborted,"provider_original_absolute_deadline_or_context");
      const until=params.until<now+30000000000n?params.until:now+30000000000n;
      const timerAbort=new AbortController(),timer=setTimeout(()=>timerAbort.abort(),Math.max(1,Number((until-now)/1000000n)));timer.unref?.();
      const signal=AbortSignal.any([params.signal,timerAbort.signal]);
      Object.assign(receipt,{schema:"heptabao.main3-provider-once.public.r1",ok:false,flowEntrypointChecks:0,postFormEntries:0,guardEntries:0,
        runtimeEntries:0,finalNativeSendEntries:0,originalNativeFetchInvocations:0,originalNativeFetchSettlements:0,
        completeBodyCaptures:0,originalDispatcherReleaseCompletions:0,originalDispatcherMethodCalls:0,
        ownedDispatcherReleaseKnown:false,rawResponseFsyncedBeforeSdkParser:false,original30SecondBudget:true,
        retries:0,redirectsFollowed:0,credentialValuesOrDigestsPublished:false,contextClosed:false});
      ctx={...params,until,signal,receipt,closed:false,dispatcherObservers:[],nativePromises:[]};report.contextsStarted++;
      try{
        sourceFence();const value=await flow.r(params.oldCredential.refresh);
        need(process.hrtime.bigint()<until&&!signal.aborted&&receipt.flowEntrypointChecks===2&&receipt.postFormEntries===1&&receipt.guardEntries===1&&
          receipt.runtimeEntries===1&&receipt.finalNativeSendEntries===1&&receipt.originalNativeFetchInvocations===1&&receipt.completeBodyCaptures===1&&receipt.originalDispatcherReleaseCompletions===1&&
          receipt.originalCloseHelperReturned,"provider_complete_original_transport_and_parser");
        sourceFence();params.assertLive();receipt.ok=true;report.successfulSdkRefreshCalls++;return value;
      }catch(e){receipt.errorCode=e instanceof ProviderOnceRefused?e.code:"provider_original_sdk_refresh_refused";throw new ProviderOnceRefused(receipt.errorCode);}
      finally{
        ctx.closed=true;receipt.originalFunctionSettled=true;
        // Do not race an abort against these original promises. If one never
        // settles, the original owned supervisor retains its existing deadline;
        // no next ordinal or mutex release is admitted from this wrapper.
        await Promise.all(ctx.nativePromises);
        await Promise.all(ctx.dispatcherObservers.flatMap(x=>x.originalPromises));
        receipt.ownedDispatcherReleaseKnown=ctx.dispatcherObservers.length===1&&ctx.dispatcherObservers.every(x=>x.known())&&
          receipt.originalDispatcherReleaseCompletions===1;
        receipt.noNativeTransportOpened=receipt.guardEntries===0&&receipt.originalNativeFetchInvocations===0&&ctx.dispatcherObservers.length===0;
        receipt.transportClosureKnown=(receipt.noNativeTransportOpened||receipt.ownedDispatcherReleaseKnown)&&
          receipt.originalNativeFetchInvocations===receipt.originalNativeFetchSettlements;
        let restoreKnown=true;
        for(const observer of ctx.dispatcherObservers){try{observer.restore();}catch{restoreKnown=false;}}
        receipt.dispatcherObserversRestored=restoreKnown;
        if(!restoreKnown)receipt.transportClosureKnown=false;
        ctx=null;clearTimeout(timer);timerAbort.abort();receipt.contextClosed=true;
        if(!receipt.transportClosureKnown){receipt.ok=false;receipt.errorCode="provider_original_transport_closure_unknown";}
      }
    }
  });
}
