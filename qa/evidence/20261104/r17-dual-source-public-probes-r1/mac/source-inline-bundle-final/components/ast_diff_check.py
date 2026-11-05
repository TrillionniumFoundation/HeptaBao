import ast, base64, difflib, hashlib, json
d=json.loads(base64.b64decode(PAYLOAD))
for key in ("old_mac","before","after"):
    compile(ast.parse(d[key]),key,"exec")
old=ast.parse(d["before"]); new=ast.parse(d["after"])
defs=lambda t:{n.name:ast.dump(n, include_attributes=False) for n in t.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
assert defs(old)==defs(new)
def delta(a,b,an,bn):
    return "".join(difflib.unified_diff(a.splitlines(True),b.splitlines(True),fromfile=an,tofile=bn,n=3))
out={"schema":"heptabao.mac-source-inband-bundle-source-check.v1","status":"passed","whole_ast_compile_only":3,"all_top_level_function_and_class_asts_unchanged":True,"definitions":len(defs(old)),"module_execution":False,"host_actions":0,
"diff_r2_to_r3":delta(d["before"],d["after"],"before/mac-stage-r2.py","after/mac-stage-r3.py"),
"diff_actual_mac_to_r3":delta(d["old_mac"],d["after"],"actual-mac-r10-3b012a9/stage_mac_r10.py","candidate-mac-cold-h2-r3/stage_source_cold_h2.py")}
print(json.dumps(out,sort_keys=True))
