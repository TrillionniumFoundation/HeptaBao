import ast, copy, difflib, hashlib, json
from pathlib import Path

ROOT = Path(__file__).parent
names = json.loads((ROOT / "name-map.json").read_text())
bindings = json.loads((ROOT / "binding-template.json").read_text())
dispatch = json.loads((ROOT / "DISPATCH.proposed.json").read_text())
checks = []
def check(name, condition):
    assert condition, name
    checks.append({"name": name, "passed": True})
def source(path):
    return path.read_text()
def assignments(text):
    parsed = ast.parse(text)
    return {n.targets[0].id:n.value for n in parsed.body
            if isinstance(n, ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
def functions(text):
    result = {}
    def walk(body,prefix=""):
        for node in body:
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                result[prefix+node.name] = node
            elif isinstance(node,ast.ClassDef):
                walk(node.body,prefix+node.name+".")
    walk(ast.parse(text).body)
    return result
diffs = {}
for role,(old,new) in names.items():
    a=source(ROOT/"before"/old)
    b=source(ROOT/"candidate"/new)
    diffs[role+".review.diff"]="".join(difflib.unified_diff(a.splitlines(True),b.splitlines(True),
                                    fromfile="a/"+old,tofile="b/"+new))
    check(role+"_changed_only_source_candidate",a!=b)
    ast.parse(b,filename=new)
    compile(b,new,"exec",dont_inherit=True)
    if role in ("numeric","cipher"):
        fa,fb=functions(a),functions(b)
        check(role+"_all_function_ast_unchanged",
              fa.keys()==fb.keys() and all(ast.dump(fa[k])==ast.dump(fb[k]) for k in fa))
a=source(ROOT/"before"/"inert_carrier_r2.py")
b=source(ROOT/"carrier.py")
diffs["carrier.review.diff"]="".join(difflib.unified_diff(a.splitlines(True),b.splitlines(True),
                                 fromfile="a/inert_carrier_r2.py",tofile="b/inert_carrier_df026_r1.py"))
fa,fb=functions(a),functions(b)
check("carrier_all_function_ast_unchanged",
      fa.keys()==fb.keys() and all(ast.dump(fa[k])==ast.dump(fb[k]) for k in fa))
for path in sorted((ROOT/"candidate").rglob("*.py")):
    text=source(path)
    ast.parse(text,filename=str(path))
    compile(text,str(path),"exec",dont_inherit=True)
check("nine_candidates_ast_compile_only",len(list((ROOT/"candidate").rglob("*.py")))==9)
compile(b,"carrier.py","exec",dont_inherit=True)

old_runner=source(ROOT/"before"/names["runner"][0])
new_runner=source(ROOT/"candidate"/names["runner"][1])
fr_old,fr_new=functions(old_runner),functions(new_runner)
check("runner_function_name_set_preserved",fr_old.keys()==fr_new.keys())
changed=[k for k in fr_old if ast.dump(fr_old[k])!=ast.dump(fr_new[k])]
check("runner_only_init_metadata_changed",changed==["PocketSourcePostRecoveryColdRun.__init__"])
class RestoreMetadata(ast.NodeTransformer):
    def visit_Constant(self,node):
        table={
            "heptabao.normal-cold-h2-pocket-source-postrecovery-cold.v1":
            "heptabao.normal-r10-pocket-source-postrecovery-cold.v1",
            "e56cf706615bbe93d9034e5a11373df5eae87ee846d6e2286f6a29ca8bdfa060":
            "ab2819fdcf4deed633fa2b2413a0de0990fa258ef2f1fffcdd8de0f4dc38fc5a"}
        if isinstance(node.value,str) and node.value in table:
            return ast.copy_location(ast.Constant(value=table[node.value]),node)
        return node
restored=RestoreMetadata().visit(copy.deepcopy(fr_new[changed[0]]))
check("runner_init_only_schema_and_prior_failure_literals",
      ast.dump(restored)==ast.dump(fr_old[changed[0]]))
old_launcher=source(ROOT/"before"/names["launcher"][0])
new_launcher=source(ROOT/"candidate"/names["launcher"][1])
fl_old,fl_new=functions(old_launcher),functions(new_launcher)
check("launcher_only_args_function_changes",
      fl_old.keys()==fl_new.keys() and [k for k in fl_old if ast.dump(fl_old[k])!=ast.dump(fl_new[k])]==["args"])
class RestoreNodeRoots(ast.NodeTransformer):
    def visit_Constant(self,node):
        if isinstance(node.value,str):
            value=node.value
            for index in (1,2,3):
                value=value.replace("cold-h2-pocket3-mac1-postrecovery-cold-node"+str(index)+"-r1",
                                    "r10-pocket3-mac1-postrecovery-cold-node"+str(index)+"-r2")
            return ast.copy_location(ast.Constant(value=value),node)
        return node
check("launcher_args_only_three_fresh_node_root_literals",
      ast.dump(RestoreNodeRoots().visit(copy.deepcopy(fl_new["args"])))==ast.dump(fl_old["args"]))
la=assignments(new_launcher)
ra=assignments(new_runner)
check("actual_canonical_commit_tree_literal",
      ast.literal_eval(la["COMMIT"])==ast.literal_eval(ra["COMMIT"])==bindings["source_commit"]
      and ast.literal_eval(la["TREE"])==ast.literal_eval(ra["TREE"])==bindings["source_tree"])
check("old28_fences_preserved_append4",
      len(bindings["oldcomparisons"])==28 and len(bindings["comparisons"])==32
      and all(bindings["comparisons"][k]==v for k,v in bindings["oldcomparisons"].items()))
check("extra12_names_order_preserved",
      ast.literal_eval(la["POSTCOLD_CHECKS"])==ast.literal_eval(assignments(old_launcher)["POSTCOLD_CHECKS"])
      ==ast.literal_eval(ra["POSTCOLD_CHECKS"]) and len(ast.literal_eval(la["POSTCOLD_CHECKS"]))==12)
check("overlay_pins_and_qa_pins_unchanged",
      ast.literal_eval(la["DEADLINE_QA_PINS"])==ast.literal_eval(assignments(old_launcher)["DEADLINE_QA_PINS"])
      and ast.literal_eval(la["QA_PINS"])==ast.literal_eval(assignments(old_launcher)["QA_PINS"]))
check("original_budget_constants_preserved",
      ast.literal_eval(ra["POSTCOLD_SECONDS"])==300.0
      and dispatch["live"]["inner_seconds"]==2400 and dispatch["live"]["timeout_seconds"]==3000
      and dispatch["live"]["role_preparation_seconds"]==60
      and dispatch["live"]["original_http_seconds"]==15
      and dispatch["live"]["original_admission_seconds"]==8)
entry=[n for n in ast.parse(new_launcher).body if isinstance(n,ast.Assert)
       and isinstance(n.test,ast.Compare) and ast.unparse(n.test.left)=="Path(__file__).resolve(strict=True)"]
check("unique_entry_self_identity_assertion",len(entry)==1)
check("entry_basename_matches_payload_and_dispatch",
      ast.unparse(entry[0].test.comparators[0])=="CONTROL / "+repr(names["launcher"][1])
      and dispatch["prepare"]["args"][3]==bindings["control"]+"/"+names["launcher"][1]
      and dispatch["live"]["args_template"][3]==dispatch["prepare"]["args"][3])
node=fl_new["require_bound_artifact_pins"]
env={"Path":Path,"BUILDS":copy.deepcopy(ast.literal_eval(la["BUILDS"])),
     "COMPARISON_PINS":copy.deepcopy(ast.literal_eval(la["COMPARISON_PINS"]))}
exec(compile(ast.Module(body=[copy.deepcopy(node)],type_ignores=[]),"<selected-pure-guard>","exec"),env)
try:env["require_bound_artifact_pins"]()
except AssertionError as error:
    check("actual_unbound_linux_rejected_before_host_probes",str(error)=="actual_R10_build_pins_not_bound")
else:raise AssertionError("unbound admitted")
for key in env["BUILDS"]["linux"]["files"]:env["BUILDS"]["linux"]["files"][key]="a"*64
env["require_bound_artifact_pins"]()
check("synthetic_full_pins_pass_pure_shape_guard",True)
env["BUILDS"]["linux"]["files"]["artifacts/heptabao-server"]="g"*64
try:env["require_bound_artifact_pins"]()
except AssertionError:check("malformed_digest_rejected",True)
else:raise AssertionError("malformed admitted")
(ROOT/"diffs").mkdir()
for name,text in diffs.items():(ROOT/"diffs"/name).write_text(text)
report={"schema":"heptabao.df026-lan-template-selected-source-checks.r1",
        "checks":checks,"passed":len(checks),"failed":0,
        "diffs":diffs,"source_only":True,"whole_module_executed":False,
        "selected_function_execution":"require_bound_artifact_pins only; synthetic dictionaries",
        "host_operations":0,"children_started":0,"http_requests":0,"product_runs":0,
        "local_effect":"Read newly materialized public source and wrote five local diff files"}
print(json.dumps(report,sort_keys=True,indent=2))
