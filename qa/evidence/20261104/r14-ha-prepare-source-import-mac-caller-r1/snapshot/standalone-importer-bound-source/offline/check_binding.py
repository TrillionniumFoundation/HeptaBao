import ast,difflib,hashlib,json,sys
d=json.loads(sys.argv[1]);a=ast.parse(d["before"]);b=ast.parse(d["after"]);compile(b,"bound-importer.py","exec")
def defs(t,s):
 return {n.name:ast.get_source_segment(s,n) for n in t.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
old=defs(a,d["before"]);new=defs(b,d["after"])
assert old==new
allowed={"ACTUAL_INPUTS_READY","FILES","TRANSFER"}
def strip(t):
 return [ast.dump(n,include_attributes=False) for n in t.body if not (isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in allowed)]
assert strip(a)==strip(b)
values={n.targets[0].id:ast.literal_eval(n.value) for n in b.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in allowed}
assert values["ACTUAL_INPUTS_READY"] is True and values["FILES"]==d["actual"]["files"] and values["TRANSFER"]==d["actual"]["transfer"]
inverse=d["after"]
for e in reversed(d["edits"]):
 assert inverse.count(e["after"])==1
 inverse=inverse.replace(e["after"],e["before"])
assert inverse==d["before"]
diff="".join(difflib.unified_diff(d["before"].splitlines(True),d["after"].splitlines(True),fromfile="unbound/import_standalone_phaseb_3cb_r1.py",tofile="bound/import_standalone_phaseb_3cb_r1.py"))
print(json.dumps({"schema":"heptabao.phaseb3cb.importer-actual-binding-source-check.v1","status":"passed","unchanged_definition_count":len(old),"only_three_assignments_changed":True,"five_actual_fields_plus_ready_flag":True,"exact_inverse_whole_bytes":True,"other_top_level_ast_equal":True,"ast_compile_only":True,"candidate_top_level_executed":False,"actual_import_executed":False,"candidate_bytes":len(d["after"].encode()),"candidate_sha256":hashlib.sha256(d["after"].encode()).hexdigest(),"diff":diff},sort_keys=True))
