#!/usr/bin/env python3
"""Offline public-source AST and eight synthetic projection boundaries only."""
import ast, copy, difflib, hashlib, json, os, pathlib, re, sys
root=pathlib.Path(sys.argv[1])
data=json.loads((root/"inputs.public.json").read_text())
before,after,observer=(data[x] for x in ("before","after","observer"))
checks=[]
def check(name,value):
    if not value: raise AssertionError(name)
    checks.append({"case":name,"passed":True})
def digest(raw): return hashlib.sha256(raw).hexdigest()
def dump(node): return ast.dump(node,include_attributes=False)
def module_defs(tree): return {n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
old,new=ast.parse(before),ast.parse(after)
compile(old,"original_public_source","exec");compile(new,"candidate_public_source","exec")
check("both_sources_parse_and_compile_without_execution",True)
od,nd=module_defs(old),module_defs(new)
check("top_level_definition_names_unchanged",set(od)==set(nd))
same=[]
for name in od:
    if name in ("main","predicate_projection"): continue
    check("unchanged_definition_"+name,ast.get_source_segment(before,od[name])==ast.get_source_segment(after,nd[name]))
    same.append(name)
oldmain=ast.get_source_segment(before,od["main"])
newmain=ast.get_source_segment(after,nd["main"])
check("main_only_report_schema_diff",newmain.replace("heptabao.mac-captured-public-harness-catalog.r2","heptabao.mac-captured-harness-predicate-observation.r1")==oldmain)
check("main_guard_and_exit_suffix_unchanged",before[before.index('if __name__ == "__main__":'):]==after[after.index('if __name__ == "__main__":'):])
def assigns(tree):
    return {n.targets[0].id:n for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
oa,na=assigns(old),assigns(new)
check("every_original_top_level_binding_AST_unchanged",all(dump(node)==dump(na[name]) for name,node in oa.items()))
check("only_two_added_public_projection_constants",set(na)-set(oa)=={"PUBLIC_SDK_ROOT","CATALOG_RECORD_PINS"})
check("imports_unchanged",[dump(x) for x in old.body if isinstance(x,(ast.Import,ast.ImportFrom))]==[dump(x) for x in new.body if isinstance(x,(ast.Import,ast.ImportFrom))])
op,np=od["predicate_projection"],nd["predicate_projection"]
needcalls=lambda n:[dump(x) for x in ast.walk(n) if isinstance(x,ast.Call) and isinstance(x.func,ast.Name) and x.func.id=="need"]
check("all_original_projection_refusal_guards_AST_unchanged",needcalls(op)==needcalls(np))
def local_assigns(fn):
    return {x.targets[0].id:x for x in ast.walk(fn) if isinstance(x,ast.Assign) and len(x.targets)==1 and isinstance(x.targets[0],ast.Name)}
opa,npa=local_assigns(op),local_assigns(np)
check("all_original_projection_assignments_AST_unchanged",all(dump(v)==dump(npa[k]) for k,v in opa.items()))
def rowdict(fn):
    for n in ast.walk(fn):
        if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=="output" and n.func.attr=="append":
            return {ast.literal_eval(k):v for k,v in zip(n.args[0].keys,n.args[0].values)}
    raise AssertionError("rowdict")
oro,nro=rowdict(op),rowdict(np)
check("every_original_per_owner_output_expression_AST_unchanged",all(dump(v)==dump(nro[k]) for k,v in oro.items()))
check("only_four_per_owner_catalog_fields_added",set(nro)-set(oro)=={"publicCatalogPluginId","publicCatalogCodeRoot","publicCatalogScope","catalogMetadataOnlyNotCodeAdmission"})
check("original_id_path_normalization_namespace_composite_AST_unchanged",all(dump(opa[k])==dump(npa[k]) for k in ("identifier","raw_root","root_constructible","root","id_matches","absolute","normalized","namespace","known_root")))
ret=lambda fn:{ast.literal_eval(k):v for k,v in zip(fn.body[-1].value.keys,fn.body[-1].value.values)}
orr,nrr=ret(op),ret(np)
changed_return={"originalNativeWorkerContract","pluginIdsPublished","unknownCodePathsPublished"}
check("original_aggregate_outputs_unchanged_except_three_declared_fields",all(dump(v)==dump(nrr[k]) for k,v in orr.items() if k not in changed_return))
check("worker_contract_corrects_description_only_loader_t",ast.literal_eval(nrr["originalNativeWorkerContract"]).replace("loader.t(","loader.r(")==ast.literal_eval(orr["originalNativeWorkerContract"]))
catalog_pins=ast.literal_eval(na["CATALOG_RECORD_PINS"].value)
observed=data["actualPredicatePublic"]["predicateProjection"]["enabledHarnessOwners"]
expected={str(x["registryOrdinal"]):[x["identifierValueSha256"],x["rootValueSha256"],x["agentHarnessesMetadataSha256"]] for x in observed}
check("catalog_value_allowlist_exact_original_two_public_hash_triples",catalog_pins==expected and set(catalog_pins)=={"22","68"})
check("actual_owner_remains_unobserved",all(x["actualSelectedForCurrentAgents"] is None for x in observed))
check("old_caps_preserved",all(ast.literal_eval(na[k].value)==v for k,v in {"NEW_SOFT_SECONDS":5.0,"MAX_METADATA_CALLS":80,"MAX_DESCRIPTORS":9,"MAX_READ_CALLS":4,"MAX_READ_BYTES":195156,"MAX_OUTPUT_BYTES":16384}.items()))
check("planned_metadata_count_72_within_original_80",8*2+2+3*9*2==72 and 72<=80)
request_old,request_new=copy.deepcopy(data["originalRequest"]),copy.deepcopy(data["candidateRequest"])
check("exact_request_source_before",request_old["args"][-1]==before)
check("exact_request_source_after",request_new["args"][-1]==after)
request_old["args"][-1]=request_new["args"][-1]="SOURCE"
request_old["idempotency_key"]=request_new["idempotency_key"]="OBSERVER_KEY"
check("only_request_source_and_observer_key_change",request_old==request_new)
diff="".join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile="before/predicate_reader.py",tofile="after/public_catalog_reader.py"))
(root/"catalog.review.diff").write_text(diff)
def apply(base,delta,reverse=False):
    lines=base.splitlines(True); rows=delta.splitlines(True); i=2; pos=0; result=[]
    while i<len(rows):
        m=re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*\n",rows[i])
        if not m: raise AssertionError("hunk header")
        a,ac,b,bc=(int(m[1]),int(m[2] or 1),int(m[3]),int(m[4] or 1))
        start=(b if reverse else a)-1
        if start<pos: raise AssertionError("overlap")
        result.extend(lines[pos:start]); pos=start; consumed=emitted=0; i+=1
        while i<len(rows) and not rows[i].startswith("@@ "):
            marker,raw=rows[i][0],rows[i][1:]
            if reverse and marker in "+-": marker="+" if marker=="-" else "-"
            if marker in " -":
                if pos>=len(lines) or lines[pos]!=raw: raise AssertionError("context")
                pos+=1;consumed+=1
            if marker in " +":result.append(raw);emitted+=1
            if marker not in " +-":raise AssertionError("marker")
            i+=1
        if (consumed,emitted)!=((bc,ac) if reverse else (ac,bc)):raise AssertionError("hunk count")
    result.extend(lines[pos:]);return "".join(result)
check("strict_diff_apply_whole_equal",apply(before,diff)==after)
check("strict_diff_inverse_whole_equal",apply(after,diff,True)==before)
check("observer_stays_literal_unbound","export const BINDING_READY = false;" in observer and "Object.values(MISSING_BINDING).every(x=>x!==null)" in observer)
check("observer_no_dynamic_sdk_import","import(" not in observer and "from 'node:crypto'" in observer and "from 'node:path'" in observer)
check("observer_preserves_original_loader_selector_shapes","await loader.t({scope:'all',config:publicConfig,activationSourceConfig:publicConfig," in observer and "selector.o({provider:plan.model.provider,modelId:plan.model.id,config:publicConfig,agentId})" in observer)
check("observer_same_registered_instance_and_separate_owner_fields","registered.harness===selected" in observer and "selectedRecordOwnerPluginId" in observer and "selectedHarnessPluginId" in observer)
check("observer_has_no_factory_native_or_run_attempt_call",not re.search(r"\.(?:runAttempt|createClient|createFactory|login|refresh|revoke|renew|disposeAll|resetAll)\s*\(",observer))
check("observer_model_and_pin_output_do_not_spread_arbitrary_input","model:{...plan.model}" not in observer and "model:{provider:MODEL.provider,id:MODEL.id}" in observer and "sourcePins.map(x=>publicSourcePin(x,owners[0].codeRoot))" in observer)
# Execute only actual pure projection definitions on synthetic documents.
def pure_namespace(tree):
    ns={"json":json,"hashlib":hashlib,"os":os,"re":re,"Path":pathlib.Path}
    constants={"AGENTS","LIVE","KNOWN_CODEX_ROOT","PUBLIC_SDK_ROOT","PUBLIC_EXPECTED_MODEL","CONFIG_SHA256","CATALOG_RECORD_PINS"}
    defs={"Refused","need","sha","encoded","exact_json","predicate_projection"}
    selected=[n for n in tree.body if (isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in defs)
              or (isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in constants)]
    exec(compile(ast.Module(body=selected,type_ignores=[]),"selected_public_projection_only","exec"),ns)
    return ns
oldns,newns=pure_namespace(old),pure_namespace(new)
secret="SYNTHETIC_CREDENTIAL_NEVER_PUBLIC"
def encoded(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
def fixture(plugin_id,code_root):
    plugin={"enabled":True,"pluginId":plugin_id,"rootDir":code_root,"startup":{"agentHarnesses":["fixture-harness"]},
            "auth":{"token":secret},"cache":secret,"description":secret,"extraFreeText":secret}
    model={a:{"sourceConfigSha256":newns["CONFIG_SHA256"],"declaredModelSha256":"8c19b031ba91d45f4eb2dec6fc9453cbcb69aaf8c151a4219f3a84fc0a8849d1","provider":"openai","id":"gpt-5.6-sol","privateExtra":secret} for a in newns["AGENTS"]}
    doc={"schema":"heptabao.mac-guarded-current-inputs.private.r1","sourceConfigSha256":newns["CONFIG_SHA256"],
         "agentIds":list(newns["AGENTS"]),"registry":{"columns":["plugins_json"]+[f"fixture_{i}" for i in range(12)],
         "row":[encoded([plugin]).decode("ascii")]+[None]*12},"models":model,"authStores":[secret],"cache":secret,"token":secret}
    return plugin,encoded(doc)
sdk=str(newns["PUBLIC_SDK_ROOT"])
cases=[
 ("public_sdk_metadata_only","fixture-harness",sdk+"/extensions/fixture-harness",True,False),
 ("already_pinned_code_root_metadata","fixture-codex",newns["KNOWN_CODEX_ROOT"],True,False),
 ("sibling_prefix_does_not_disclose","fixture-harness",sdk+"-shadow/extensions/fixture",False,False),
 ("dotdot_does_not_disclose","fixture-harness",sdk+"/../private",False,False),
 ("mismatched_captured_value_hash_does_not_disclose","fixture-harness",sdk+"/extensions/fixture",False,True),
 ("invalid_id_does_not_disclose","fixture bad id",sdk+"/extensions/fixture",False,False),
 ("control_character_path_does_not_disclose","fixture-harness",sdk+"/extensions/fixture\n"+secret,False,False),
 ("noncanonical_raw_path_does_not_disclose","fixture-harness",sdk+"/extensions/./fixture",False,False)]
case_results=[]
new_only={"publicCatalogPluginId","publicCatalogCodeRoot","publicCatalogScope","catalogMetadataOnlyNotCodeAdmission"}
for name,ident,path,disclose,badpin in cases:
    plugin,raw=fixture(ident,path)
    pins=[digest(encoded(ident)),digest(encoded(path)),digest(encoded(plugin["startup"]["agentHarnesses"]))]
    if badpin:pins[0]="0"*64
    # Fixture hash allowlist replacement in selected function namespace only.
    # Actual source constants above remain independently exact to actual public records.
    newns["CATALOG_RECORD_PINS"]={"0":pins}
    previous=oldns["predicate_projection"](raw); current=newns["predicate_projection"](raw)
    row=current["enabledHarnessOwners"][0]
    check(name+"_disclosure",(row["publicCatalogPluginId"] is not None)==disclose and (row["publicCatalogCodeRoot"] is not None)==disclose)
    check(name+"_no_credential_or_free_text_output",secret not in json.dumps(current))
    stripped=copy.deepcopy(current)
    for item in stripped["enabledHarnessOwners"]:
        for key in new_only:item.pop(key)
    for key in ("publicCatalogDisclosureScope","newFilesystemPathsRead","sdkOrLoaderExecuted"):stripped.pop(key)
    stripped["pluginIdsPublished"]=False;stripped["unknownCodePathsPublished"]=False
    stripped["originalNativeWorkerContract"]=stripped["originalNativeWorkerContract"].replace("loader.t(","loader.r(")
    check(name+"_old_predicates_and_outputs_unchanged",stripped==previous)
    case_results.append({"case":name,"disclosureExpected":disclose,"originalCompositePredicate":row["originalCompositePredicate"],"passed":True})
result={"schema":"heptabao.mac-captured-catalog-source-review.r1","ok":True,
 "sourcePins":{"before":{"bytes":len(before.encode()),"sha256":digest(before.encode())},
 "after":{"bytes":len(after.encode()),"sha256":digest(after.encode())},"observer":{"bytes":len(observer.encode()),"sha256":digest(observer.encode())}},
 "strictDiffHunks":sum(x.startswith("@@ ") for x in diff.splitlines()),"unchangedDefinitions":same,
 "checks":checks,"checkCount":len(checks),"projectionFixtureCases":case_results,"projectionFixtureCount":len(cases),
 "fixtureAllowlistWasReplacedInMemory":True,"originalSourceAllowlistComparedToActualPublicHashes":True,
 "fullModuleExecuted":False,"candidateReaderMethodsExecuted":False,"actualFDsUsedByCandidate":0,
 "actualPrivateCapsuleRead":False,"runtimeCalls":0,"sdkExecuted":False,
 "localInputOutputFilesContainOnlyPublicSourcesAndSyntheticFixtures":True}
raw=json.dumps(result,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n"
(root/"result.public.json").write_text(raw)
print(raw,end="")
