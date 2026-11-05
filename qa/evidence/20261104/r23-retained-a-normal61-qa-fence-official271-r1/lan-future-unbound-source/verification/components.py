import ast, copy, hashlib, json, pathlib, sys, types
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
checks=[]
def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append({"name":name,"passed":True})
def assign(source,name):
    node=next(n for n in ast.parse(source).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets))
    return ast.literal_eval(node.value)
def definition(source,name):
    return next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name==name)
for name, source in data["after"].items():
    compile(ast.parse(source,filename=name),name,"exec")
    check("compile_only:"+name,True)
oldL=data["before"][data["old_launcher"]]
newL=data["after"][data["new_launcher"]]
oldR=data["before"][data["old_runner"]]
newR=data["after"][data["new_runner"]]
oldF=assign(oldL,"COMPARISON_PINS")
newF=assign(newL,"COMPARISON_PINS")
check("old32fences_all_exact_and_four_added",len(oldF)==32 and len(newF)==36 and all(newF[k]==v for k,v in oldF.items()))
check("12postcold_names_order_exact",assign(oldL,"POSTCOLD_CHECKS")==assign(newL,"POSTCOLD_CHECKS")==assign(oldR,"POSTCOLD_CHECKS")==assign(newR,"POSTCOLD_CHECKS") and len(assign(newL,"POSTCOLD_CHECKS"))==12)
check("product_source_exact",assign(newL,"COMMIT")==assign(newR,"COMMIT")==data["expected_commit"] and assign(newL,"TREE")==assign(newR,"TREE")==data["expected_tree"])
check("original_canonical_QA5_whole_pins_exact",assign(oldL,"QA_PINS")==assign(newL,"QA_PINS")=={k:v["sha256"] for k,v in data["canonical_qa_pins"].items()})
check("original_private_deadline_overlay4_exact",assign(oldL,"DEADLINE_QA_PINS")==assign(newL,"DEADLINE_QA_PINS")==assign(oldR,"DEADLINE_QA_PINS")==assign(newR,"DEADLINE_QA_PINS"))
check("original_postcold_300_constant",assign(oldR,"POSTCOLD_SECONDS")==assign(newR,"POSTCOLD_SECONDS")==300.0)
class NormalizeMetadata(ast.NodeTransformer):
    def visit_Constant(self,node):
        if isinstance(node.value,str):
            node=copy.deepcopy(node)
            node.value=node.value.replace("heptabao.normal-same-root-publication-","heptabao.normal-cold-h2-").replace("same-root-publication-pocket3-mac1-postrecovery-cold-node","cold-h2-pocket3-mac1-postrecovery-cold-node")
        return node
def normalized_definitions(source):
    found={}
    for node in ast.parse(source).body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
            found[node.name]=ast.dump(NormalizeMetadata().visit(copy.deepcopy(node)),include_attributes=False)
    return found
for newName,proof in data["proofs"].items():
    oldSource=data["before"][proof["original_name"]]
    newSource=data["after"][newName]
    check("all_definition_bodies_same_after_metadata_literals:"+newName,normalized_definitions(oldSource)==normalized_definitions(newSource))
builds=assign(newL,"BUILDS")
check("10artifactpins_explicit_unbound",len([p for v in builds.values() for p in v["files"].values()])==10 and all(p is None for v in builds.values() for p in v["files"].values()))
class NoIOPath(pathlib.PurePosixPath):
    def resolve(self,strict=False): return self
ns={"BUILDS":copy.deepcopy(builds),"COMPARISON_PINS":copy.deepcopy(newF),"Path":NoIOPath}
guard=definition(newL,"require_bound_artifact_pins")
exec(compile(ast.Module(body=[guard],type_ignores=[]),"<selected-original-bound-guard>","exec"),ns)
def rejected(name):
    try: ns["require_bound_artifact_pins"]()
    except AssertionError: checks.append({"name":name,"passed":True})
    else: raise AssertionError(name)
rejected("unbound_all10_rejected")
bound=copy.deepcopy(builds)
for config in bound.values():
    for filename in config["files"]: config["files"][filename]="0"*64
for host,config in bound.items():
    for filename in config["files"]:
        ns["BUILDS"]=copy.deepcopy(bound)
        ns["BUILDS"][host]["files"][filename]=None
        rejected("one_missing_pin_rejected:"+host+":"+filename)
ns["BUILDS"]=copy.deepcopy(bound)
ns["require_bound_artifact_pins"]()
check("synthetic_shape_only_positive_not_actual_admission",True)
ns["BUILDS"]["linux"]["cargo"]="relative/cargo"
rejected("relative_cargo_rejected")
ns["BUILDS"]=copy.deepcopy(bound)
ns["COMPARISON_PINS"][next(iter(newF))]=None
rejected("missing_prior_fence_rejected")
tree=ast.parse(newL)
guard_index=next(i for i,n in enumerate(tree.body) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=="require_bound_artifact_pins")
probe_index=next(i for i,n in enumerate(tree.body) if isinstance(n,ast.Assign) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=="build_probes")
check("unbound_guard_precedes_any_probe_call",guard_index<probe_index)
constants={}
for n in tree.body:
    if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ("ROOT","CONTROL","WORK","SOURCE"):
        exec(compile(ast.Module(body=[n],type_ignores=[]),"<selected-pure-path-constants>","exec"),{"Path":NoIOPath},constants)
nsPath={"Path":NoIOPath,**constants}
self_assert=next(n for n in tree.body if isinstance(n,ast.Assert) and "__file__" in ast.unparse(n))
for name,expected in ((data["new_launcher"],True),(data["old_launcher"],False),("unexpected.py",False)):
    nsPath["__file__"]=str(constants["CONTROL"]/name)
    try: exec(compile(ast.Module(body=[self_assert],type_ignores=[]),"<selected-entry-assert>","exec"),nsPath); passed=True
    except AssertionError: passed=False
    check("actual_self_basename_guard:"+name,passed==expected)
report={"schema":"heptabao.same-root-lan-source-selected-component-review.v1","status":"passed","checks":checks,"passed":len(checks),"failed":0,"compiled_sources":9,"main_or_qa_module_executed":False,"selected_original_guard_only":True,"synthetic_digest_positive_is_qualification":False,"actual_host_calls":0,"product_children":0,"native_os_api_calls":0,"cloud_filesystem_scope":"read this public input JSON and this verification script only; stdlib Python import","source_commit":data["expected_commit"],"source_tree":data["expected_tree"],"unbound10_preserved":True,"original32_fences_plus4":36,"original98_and_extra12_not_executed_or_requalified":True}
print(json.dumps(report,sort_keys=True,indent=2))
