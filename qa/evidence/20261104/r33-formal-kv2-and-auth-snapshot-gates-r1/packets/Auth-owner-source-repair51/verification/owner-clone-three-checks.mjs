import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import crypto from 'node:crypto';
const [oldPath, newPath] = process.argv.slice(2);
function extract(file) {
  const source = fs.readFileSync(file, 'utf8');
  const start = source.indexOf('function actualHarnessOwnerWitness(');
  const end = source.indexOf('\nfunction privateRead(file)', start);
  if (start < 0 || end < 0) throw new Error('fixed selected function missing');
  const selected = source.slice(start, end);
  const fn = vm.runInNewContext('(' + selected + ')', {
    path: path.posix, need(ok, code) { if (!ok) throw new Error(code); }
  });
  return {fn, pin:{bytes:Buffer.byteLength(source),sha256:crypto.createHash('sha256').update(source).digest('hex')},
    functionPin:{bytes:Buffer.byteLength(selected),sha256:crypto.createHash('sha256').update(selected).digest('hex')}};
}
const before = extract(oldPath), after = extract(newPath);
const pin = 'a'.repeat(64), root = '/approved/public/codex';
function fixture() {
  const supports=()=>true, runAttempt=()=>{};
  const local={id:'codex',pluginId:'implementation-metadata',supports,runAttempt};
  const selected={...local};
  const registered={harness:selected,ownerPluginId:'codex'};
  const plugin={id:'codex',enabled:true,status:'loaded',agentHarnessIds:['codex'],
    rootDir:root,source:root+'/dist/index.js',origin:'global'};
  const entry={pluginId:'codex',rootDir:root,source:plugin.source,harness:local};
  const binding={pluginId:'codex',rootDir:root,layout:'npm',entries:[{path:plugin.source,sha256:pin}],
    manifest:{path:root+'/openclaw.plugin.json',sha256:pin},package:{path:root+'/package.json',sha256:pin}};
  return {active:{plugins:[plugin],agentHarnesses:[entry]},registered,selected,local,entry,
    bindings:[binding],pins:Object.fromEntries([plugin.source,binding.manifest.path,binding.package.path].map(p=>[p,pin]))};
}
function invoke(candidate,x) {
  try {return {value:candidate.fn(x.active,x.registered,x.selected,x.bindings,x.pins),code:null};}
  catch(e) {return {value:null,code:e.message};}
}
const cases=[];
{
  const x=fixture(), old=invoke(before,x), next=invoke(after,x);
  if(old.code!=='actual_harness_owner_identity'||next.code!==null
     ||next.value.public.ownerPluginId!=='codex'||next.value.public.harnessPluginIdMatchesLocal!==true
     ||next.value.public.harnessPluginIdEqualsOwner!==false||'harnessPluginId' in next.value.public
     ||next.value.selected!==x.selected||x.local===x.selected) throw new Error('genuine distinct metadata clone');
  cases.push({name:'genuine_owner_differs_from_harness_plugin_id',oldCode:old.code,newCode:next.code,
    globalInstanceEqual:true,localCloneFieldEqual:true,equalsOwner:false,rawHarnessPluginIdPublished:false,passed:true});
}
{
  const x=fixture();x.local.pluginId='changed-metadata';const r=invoke(after,x);
  if(r.code!=='actual_registered_harness_callable_lineage')throw new Error('clone mismatch not refused');
  cases.push({name:'local_global_plugin_id_mismatch',code:r.code,passed:true});
}
{
  const x=fixture();x.registered.ownerPluginId='other';const r=invoke(after,x);
  if(r.code!=='one_admitted_selected_owner')throw new Error('owner mismatch not refused');
  cases.push({name:'wrong_actual_registration_owner',code:r.code,passed:true});
}
process.stdout.write(JSON.stringify({schema:'heptabao.owner-clone-three-pure-cases.v1',before:before.pin,
  after:after.pin,selectedFunction:after.functionPin,passed:cases.length,cases,
  sourceContracts:{implementationRegistry:'42ea640e392714881fcf908094d691913efb174f',
    globalRegistry:'9f5042ec5442239f12975e3680c0568b3c85bdf8'},
  scope:{actualRuntimeCalls:0,installedSdkImports:0,actualRegistry:0,factories:0,nativeProcesses:0,
    privateInput:0,realSignals:0,fullCandidateModulesExecuted:false,onlySelectedPureFunction:true}},null,2)+'\n');
