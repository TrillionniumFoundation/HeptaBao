import ast,difflib,hashlib,json,sys
d=json.loads(sys.argv[1]);old=d["before"];new=d["after"]
a=ast.parse(old);b=ast.parse(new);compile(b,"standalone_importer_draft_r1.py","exec")
def defs(t,s):
 return {n.name:ast.get_source_segment(s,n) for n in t.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
x=defs(a,old);y=defs(b,new)
removed=sorted(set(x)-set(y));added=sorted(set(y)-set(x))
changed=sorted(k for k in x.keys()&y.keys() if x[k]!=y[k]);same=sorted(k for k in x.keys()&y.keys() if x[k]==y[k])
assert removed==["receive_files","recheck_artifacts"]
assert added==["check_input_directories","check_source_directory","create_source_directory","directory_key","hold_fixed_inputs","hold_input_directories","recheck_held_inputs"]
assert changed==["verify_receipts"]
assert all(k in same for k in ["owned_argv","owned","freeze","prove_canonical","verify_materialized_and_fsync","bundle_header","read_file","stop_owned","stop_active"])
def expr(t,name):
 return next(n.value for n in t.body if isinstance(n,ast.Assign) and any(isinstance(v,ast.Name) and v.id==name for v in n.targets))
assert ast.dump(expr(a,"environment"))==ast.dump(expr(b,"environment"))
assert ast.dump(expr(a,"UNTIL"))==ast.dump(expr(b,"UNTIL"))
assert ast.literal_eval(expr(b,"ACTUAL_INPUTS_READY")) is False
inputs=ast.literal_eval(expr(b,"FILES"));transfer=ast.literal_eval(expr(b,"TRANSFER"))
assert len(inputs)==2 and all(z["version"] is None for z in inputs)
assert all(transfer[k] is None for k in ["bytes","sha256","version"])
top=next(n for n in reversed(b.body) if isinstance(n,ast.Try))
gate=next(i for i,n in enumerate(top.body) if isinstance(n,ast.Assert) and "ACTUAL_INPUTS_READY" in ast.get_source_segment(new,n))
before=top.body[:gate]
assert not any(isinstance(n,ast.Call) and ((isinstance(n.func,ast.Name) and n.func.id in ("open","owned","owned_argv","git","hold_fixed_inputs")) or (isinstance(n.func,ast.Attribute) and n.func.attr in ("mkdir","lstat","stat","resolve","Popen"))) for n in ast.walk(ast.Module(body=before,type_ignores=[])))
for name,append in [("hold_fixed_inputs","input_handles"),("hold_input_directories","input_directories")]:
 fn=next(n for n in b.body if isinstance(n,ast.FunctionDef) and n.name==name)
 protected=next(n for n in ast.walk(fn) if isinstance(n,ast.Try) and any(isinstance(m,ast.AugAssign) and isinstance(m.target,ast.Name) and m.target.id=="protected" and isinstance(m.op,ast.Sub) for m in n.finalbody))
 calls=[n for n in ast.walk(ast.Module(body=protected.body,type_ignores=[])) if isinstance(n,ast.Call)]
 assert any(isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=="os" and n.func.attr=="open" for n in calls)
 assert any(isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id==append and n.func.attr=="append" for n in calls)
diff="".join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile="reference/x230_standalone_receiver_r2.py",tofile="draft/import_standalone_phaseb_3cb_r1.py"))
print(json.dumps({"schema":"heptabao.phaseb3cb.local-importer-source-invariance.v1","status":"passed","bytes":len(new.encode()),"sha256":hashlib.sha256(new.encode()).hexdigest(),"same_definitions":same,"changed_definitions":changed,"removed_definitions":removed,"new_definitions":added,"git_environment_unchanged":True,"original_absolute300_unchanged":True,"metadata_guard_before_filesystem_or_git":True,"fd_open_and_registration_defer_cancellation":True,"unresolved_metadata_fields":5,"candidate_top_level_executed":False,"compiled_not_executed":True,"diff":diff},sort_keys=True))