import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import crypto from 'node:crypto';
const candidatePath = process.argv[2];
const source = fs.readFileSync(candidatePath, 'utf8');
const start = source.indexOf('function actualHarnessOwnerWitness(');
const end = source.indexOf('\nfunction privateRead(file)', start);
if (start < 0 || end < 0) throw new Error('selected function missing');
const actual = source.slice(start, end);
const fn = vm.runInNewContext('(' + actual + ')', {
  path: path.posix,
  need(ok, code) { if (!ok) throw new Error(code); }
});
const pin = 'a'.repeat(64), root = '/approved/public/codex';
function fixture() {
  const supports = () => true, runAttempt = () => {};
  const local = {id:'codex', pluginId:'codex', supports, runAttempt};
  const selected = {...local};
  const registered = {harness:selected, ownerPluginId:'codex'};
  const plugin = {id:'codex', enabled:true,status:'loaded',agentHarnessIds:['codex'],
    rootDir:root,source:root+'/dist/index.js',origin:'global'};
  const entry = {pluginId:'codex',rootDir:root,source:plugin.source,harness:local};
  const binding = {pluginId:'codex',rootDir:root,layout:'npm',
    entries:[{path:plugin.source,sha256:pin}],
    manifest:{path:root+'/openclaw.plugin.json',sha256:pin},
    package:{path:root+'/package.json',sha256:pin}};
  const active={plugins:[plugin],agentHarnesses:[entry]};
  const pins=Object.fromEntries([plugin.source,binding.manifest.path,binding.package.path].map(p=>[p,pin]));
  return {active,registered,selected,bindings:[binding],pins,local,plugin,entry};
}
const cases=[];
function invoke(x) { return fn(x.active,x.registered,x.selected,x.bindings,x.pins); }
function passes(name, change, expected) {
  const x=fixture(); if(change) change(x);
  let actualCode=null, value=null;
  try { value=invoke(x); } catch(e) { actualCode=e.message; }
  if(actualCode!==expected) throw new Error(name+': expected '+expected+' got '+actualCode);
  if(expected===null && !(x.local!==x.selected && value.public.globalInstanceEqual
      && value.public.localCallableLineageEqual && value.selected===x.selected))
    throw new Error(name+': genuine clone equality failed');
  cases.push({name,expectedCode:expected,observedCode:actualCode,passed:true});
}
passes('genuine_global_shallow_copy_is_accepted',null,null);
passes('same_id_different_selected_object',x=>x.selected={...x.selected},'actual_selected_global_registration');
passes('harness_plugin_id_differs_from_owner',x=>x.selected.pluginId='other','actual_harness_owner_identity');
passes('active_owner_root_drift',x=>x.plugin.rootDir='/different/root','actual_owner_record_root_and_source');
passes('local_registration_source_drift',x=>x.entry.source='/different/source.js','actual_owner_record_root_and_source');
passes('actual_entry_lacks_admitted_pin',x=>delete x.pins[x.plugin.source],'actual_owner_source_has_exact_admitted_pin');
passes('local_callable_differs_from_global_clone',x=>x.entry.harness.supports=()=>true,'actual_registered_harness_callable_lineage');
passes('manifest_pin_mismatch',x=>x.pins[x.bindings[0].manifest.path]='b'.repeat(64),'actual_owner_manifest_and_package_pins');
passes('selected_owner_not_admitted',x=>x.bindings[0].pluginId='other','one_admitted_selected_owner');
passes('duplicate_active_owner_record',x=>x.active.plugins.push({...x.plugin}),'one_actual_plugin_and_harness_registration');
process.stdout.write(JSON.stringify({schema:'heptabao.owner-witness.selected-pure-tests.v1',
 candidateBytes:Buffer.byteLength(source),candidateSha256:crypto.createHash('sha256').update(source).digest('hex'),
 selectedFunctionBytes:Buffer.byteLength(actual),selectedFunctionSha256:crypto.createHash('sha256').update(actual).digest('hex'),
 passed:cases.length,cases,scope:{actualFileDescriptors:0,actualSdkImports:0,actualRegistry:0,
 actualFactory:0,actualNativeProcess:0,hostCalls:0,privateInput:0,
 fullCandidateModuleExecuted:false,sourceTextReadOnly:true}},null,2)+'\n');
