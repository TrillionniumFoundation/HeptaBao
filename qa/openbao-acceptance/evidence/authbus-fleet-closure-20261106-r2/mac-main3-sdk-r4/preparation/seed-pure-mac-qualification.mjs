#!/usr/bin/env node
import fs from 'node:fs';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {buildPrivateSeed} from 'file:///Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r4/qa/main3_sdk_seed_r1.mjs';
import {normalizeLeaseAssignments} from 'file:///Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r4/plugin/lease-assignments.js';

const plugin=fs.readFileSync('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r4/plugin/index.js','utf8');
const checks=[];
const base=()=>({schema:'heptabao.actual-sdk-selected-owner-credentials.private.r1',host:'mac',
  constraints:{selectedOwnerCount:3,containsUnselectedCredentials:false},
  ownerEntries:[1,2,3].map(n=>({ownerAgent:'main',actualProvider:'openai',profileId:'synthetic-private-owner-'+n,
    credential:{provider:'openai',type:'oauth',access:'synthetic-access-'+n,refresh:'synthetic-refresh-'+n,
      expires:1790000000000,email:'synthetic@example.invalid',accountId:'synthetic-account-'+n,
      extra:{unicode:'中文é\u2028',number:1e-7,negativeZero:-0,integerLookingFloat:1.0}}}))});
const check=(name,run)=>{run();checks.push({case:name,passed:true});};
check('actual_pinned_plugin_pure_functions_generate_three_private_packets',()=>{
  const source=base(),seed=buildPrivateSeed(plugin,source);
  assert.equal(seed.payloads.length,3);assert.equal(seed.manifest.profiles.length,3);
  seed.payloads.forEach((row,i)=>assert.deepEqual(row.data.credential,source.ownerEntries[i].credential));
  assert.equal(seed.actualCentralOrderPolicyCopied,false);assert.equal(seed.syntheticControlPolicy,true);
});
check('wire_digest_uses_javascript_number_unicode_and_sorted_key_semantics',()=>{
  const source=base(),seed=buildPrivateSeed(plugin,source);
  const stable=v=>Array.isArray(v)?v.map(stable):v&&typeof v==='object'
    ?Object.fromEntries(Object.keys(v).sort().map(key=>[key,stable(v[key])])):v;
  const digest=v=>crypto.createHash('sha256').update(JSON.stringify(stable(v))).digest('hex');
  assert.equal(seed.payloads[0].data.digest,digest(source.ownerEntries[0].credential));
  assert.equal(seed.payloads[0].data.identity,digest({provider:'openai',type:'oauth',email:'synthetic@example.invalid',
    accountId:'synthetic-account-1',projectId:null}));
  assert.equal(seed.manifest.profiles[0].digest,seed.orderPolicy.providers.openai.candidates[0].digest);
});
check('explicit_empty_scheduler_document_normalizes_in_original_plugin',()=>{
  const seed=buildPrivateSeed(plugin,base());
  assert.deepEqual(seed.schedulerAssignments,{schemaVersion:1,generation:1,scopes:[],assignments:[],refreshLeases:[]});
  const normalized=normalizeLeaseAssignments(seed.schedulerAssignments,{hostId:'mac',now:1790000000000});
  assert.equal(normalized.generation,1);assert.deepEqual(normalized.scopes,[]);
  assert.equal(normalized.assignments.size,0);assert.equal(normalized.refreshLeases.size,0);
  assert.equal(normalized.now,1790000000000);
});
check('original_source_change_is_refused_before_private_packet',()=>assert.throws(()=>buildPrivateSeed(plugin+'\n',base())));
check('duplicate_owner_and_wrong_owner_are_refused',()=>{
  const duplicate=base();duplicate.ownerEntries[1].profileId=duplicate.ownerEntries[0].profileId;
  assert.throws(()=>buildPrivateSeed(plugin,duplicate));
  const foreign=base();foreign.ownerEntries[1].ownerAgent='trnm';assert.throws(()=>buildPrivateSeed(plugin,foreign));
});
check('wrong_count_and_unselected_credentials_are_refused',()=>{
  const count=base();count.ownerEntries.pop();assert.throws(()=>buildPrivateSeed(plugin,count));
  const unselected=base();unselected.constraints.containsUnselectedCredentials=true;
  assert.throws(()=>buildPrivateSeed(plugin,unselected));
});
check('actual_plugin_credential_shape_limits_are_enforced',()=>{
  const invalid=base();invalid.ownerEntries[0].credential.refresh='short';
  assert.throws(()=>buildPrivateSeed(plugin,invalid));
  const oversize=base();oversize.ownerEntries[0].credential.extra.padding='x'.repeat(131072);
  assert.throws(()=>buildPrivateSeed(plugin,oversize));
});
process.stdout.write(JSON.stringify({schema:'heptabao.main3-sdk-seed-mac-pure-qualification.r4',ok:true,
  platform:process.platform,node:process.version,passed:checks.length,failed:0,checks,
  actualMacExecuted:true,actualSdkExecuted:false,productionCredentialsRead:false,providerCalled:false})+'\n');
