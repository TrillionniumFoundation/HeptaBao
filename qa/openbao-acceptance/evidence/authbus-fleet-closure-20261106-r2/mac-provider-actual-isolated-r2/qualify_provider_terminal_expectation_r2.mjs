import fs from "node:fs";
import vm from "node:vm";
import crypto from "node:crypto";
import assert from "node:assert/strict";
const p=new URL("./mac_refresh_provider_qualification_r2.mjs",import.meta.url),source=fs.readFileSync(p,"utf8");
const start=source.indexOf("function agentRow(agent,kind){"),end=source.indexOf("async function check",start);
assert(start>0&&end>start);
const report={agents:[]};const fn=vm.runInNewContext(source.slice(start,end)+"\nagentRow",{report,need:(x,c)=>{if(!x)throw new Error(c);}});
const cases=[];
function test(id,body){body();cases.push({id,passed:true});}
test("T01_actual_destroy_only_flags_remain_truthful",()=>{const r=fn({closed:false,destroyed:true},"destroy-only");r.finish(false);assert.equal(r.row.terminalClosed,false);assert.equal(r.row.terminalDestroyed,true);assert.equal(r.row.terminalFlagsMatchedExpectation,true);});
test("T02_original_close_requires_both_flags",()=>{assert.throws(()=>fn({closed:false,destroyed:true},"close").finish());});
test("T03_no_terminal_state_cannot_pass",()=>{assert.throws(()=>fn({closed:false,destroyed:false},"destroy-only").finish(false));});
test("T04_actual_close_flags_pass",()=>{const r=fn({closed:true,destroyed:true},"close");r.finish();assert.equal(r.row.terminalFlagsMatchedExpectation,true);});
const m04=source.slice(source.indexOf('await check("M04_'),source.indexOf('await check("M05_'));
assert(m04.includes("v.known&&")&&m04.includes("a.finish(false)")&&m04.includes("originalDispatcherPromiseCalls===1"));
process.stdout.write(JSON.stringify({schema:"heptabao.provider-terminal-expectation-local.r2",ok:true,executed:4,passed:4,cases,
 sourceSha256:crypto.createHash("sha256").update(source).digest("hex"),actualMacExecution:false,productionProviderCalls:0,
 originalPromiseAcknowledgementGateRetained:true})+"\n");
