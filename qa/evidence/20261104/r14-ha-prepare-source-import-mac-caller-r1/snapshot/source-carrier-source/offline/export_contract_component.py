import ast,base64,copy,hashlib,json,sys
d=json.loads(sys.argv[1]);src=d["receiver"];t=ast.parse(src)
fn=next(n for n in t.body if isinstance(n,ast.FunctionDef) and n.name=="receive")
start=next(i for i,n in enumerate(fn.body) if isinstance(n,ast.Assign) and any(isinstance(v,ast.Name) and v.id=="exported" for v in n.targets))
stop=next(i for i,n in enumerate(fn.body) if isinstance(n,ast.Assert) and "sorted(os.listdir" in ast.get_source_segment(src,n))
selected=fn.body[start:stop]
for n in ast.walk(ast.Module(body=selected,type_ignores=[])):
 if isinstance(n,ast.Call):
  assert (isinstance(n.func,ast.Name) and n.func.id in ("len","all")) or (isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=="json" and n.func.attr=="loads"),ast.dump(n)
code=compile(ast.Module(body=selected,type_ignores=[]),"<exact-selected-export-contract>","exec")
original=json.loads(d["core"]);rows=[]
def evaluate(value):
 env={"json":json,"json_bytes":{"source-export.result.public.json":json.dumps(value).encode()},"HEAD":d["head"],"TREE":d["tree"],"FILES":d["files"],"len":len,"all":all}
 exec(code,env)
evaluate(original);rows.append({"case":"actual_original_export_receipt","accepted":True})
for name,mut in (
 ("wrong_commit",lambda x:x.__setitem__("canonical_commit","0"*40)),
 ("wrong_source_tree",lambda x:x["source_before"].__setitem__("tree","0"*40)),
 ("wrong_full_history_count",lambda x:x["canonical_proof"].__setitem__("commit_count",3754)),
 ("nonempty_prerequisite",lambda x:x["bundle"]["header"].__setitem__("prerequisites",["0"*40])),
 ("wrong_controller_pin",lambda x:x["controller"].__setitem__("sha256","0"*64)),
 ("wrong_bundle_pin",lambda x:x["bundle"].__setitem__("sha256","0"*64)),
 ("child_remaining",lambda x:x["cleanup"][0].__setitem__("remaining",[{"pid":123}])),
 ("elapsed_at_deadline",lambda x:x.__setitem__("elapsed_seconds",300)),
 ("source_after_changed",lambda x:x["source_after"].__setitem__("head","0"*40)),
 ("runtime_claim_true",lambda x:x.__setitem__("runtime_qualification",True)),
):
 v=copy.deepcopy(original);mut(v)
 try:evaluate(v)
 except (AssertionError,KeyError,TypeError):rows.append({"case":name,"rejected":True})
 else:raise AssertionError("bad evidence accepted: "+name)
print(json.dumps({"schema":"heptabao.phaseb3cb.source-carrier-export-contract-components.v1","status":"passed","checks_passed":len(rows),"cases":rows,"candidate_top_level_executed":False,"selected_pure_receipt_assertions_executed":True,"candidate_network":False,"candidate_filesystem":False,"candidate_child_processes":False,"actual_transport_tested":False},sort_keys=True))
