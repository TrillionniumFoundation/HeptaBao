import ast,hashlib,json,stat,sys,types
d=json.loads(sys.argv[1]);s=d["source"];tree=ast.parse(s);compile(s,"inactive-fence","exec")
values={}
for n in tree.body:
 if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
  try:values[n.targets[0].id]=ast.literal_eval(n.value)
  except (ValueError,TypeError):pass
assert values["BINDING_READY"] is True
assert values["SOFT_SECONDS"]==15 and values["READ_CAP"]==131072 and values["TOMBSTONE_CAP"]==8192 and values["OUTPUT_CAP"]==32768
actual=json.loads(d["metadata_raw"])
dirs={n["path"]:n["identity_before"] for n in actual["nodes"] if n["directory"]}
assert values["EXPECTED_DIRECTORIES"]==dirs
for name,v in values["EXPECTED_CONTROLS"].items():
 n=next(n for n in actual["nodes"] if n["name"]==name)
 assert v["identity"]==n["identity_before"]==n["identity_after"]
 assert v["sha256"]==d["control_pins"][name]["sha256"] and v["blob"]==d["control_pins"][name]["blob"] and v["bytes"]==d["control_pins"][name]["bytes"]
assert values["METADATA_EVIDENCE_SHA256"]==hashlib.sha256(d["metadata_raw"].encode()).hexdigest()
nodes=[n for n in tree.body if (isinstance(n,ast.ClassDef) and n.name=="Refused") or (isinstance(n,ast.FunctionDef) and n.name in ("require_invocation","validate_binding"))]
assert len(nodes)==3
env=dict(values,stat=stat,hashlib=hashlib)
env['CONTROLS']=values['BASE']+'/normal-cold-h2-x230-transfer-controls-r1'
exec(compile(ast.Module(body=nodes,type_ignores=[]),"pure-guards","exec"),env)
env["BINDING_READY"]=False
try:env["validate_binding"]()
except env["Refused"] as e:assert str(e)=="actual_metadata_binding_unresolved"
else:raise AssertionError("inactive source admitted")
env["BINDING_READY"]=True;env["validate_binding"]()
sha=hashlib.sha256(s.encode()).hexdigest()
env["sys"]=types.SimpleNamespace(argv=["-c",sha],orig_argv=["/usr/bin/python3","-I","-S","-B","-c",s,sha])
assert env["require_invocation"]()==sha
negatives=0
for argv,orig in [
 (["-c"],["/usr/bin/python3","-I","-S","-B","-c",s]),
 (["-c","0"*64],["/usr/bin/python3","-I","-S","-B","-c",s,"0"*64]),
 (["-c",sha,"extra"],["/usr/bin/python3","-I","-S","-B","-c",s,sha,"extra"])]:
 env["sys"]=types.SimpleNamespace(argv=argv,orig_argv=orig)
 try:env["require_invocation"]()
 except env["Refused"]:negatives+=1
 else:raise AssertionError("invalid argv admitted")
calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=="os"]
names={n.func.attr for n in calls}
assert not (names & {"remove","unlink","rmdir","rename","replace","kill","killpg","system","fork","posix_spawn","execv","listdir","scandir"})
assert sum(n.func.attr=="mkdir" for n in calls)==1
print(json.dumps({"ok":True,"false_ready_negative_refuses":True,"source_only_ready_pure_guard_passes":True,"exact_directories":len(dirs),"exact_control_full_identities":3,"positive_invocation":1,"negative_invocations":negatives,"mkdir_call_sites":1,"filesystem_or_main_executed":False,"original_job_outcome":"UNKNOWN"},sort_keys=True))
