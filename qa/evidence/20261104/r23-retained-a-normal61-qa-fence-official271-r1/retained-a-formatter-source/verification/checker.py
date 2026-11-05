import ast,hashlib,json,sys
from pathlib import Path
data=json.loads(Path(sys.argv[1]).read_text())
checks=[]
def check(name,value):
    if not value: raise AssertionError(name)
    checks.append(name)
before=ast.parse(data["before"]); after=ast.parse(data["after"])
compile(after,"frozen-format-controller","exec")
check("new_controller_ast_compile_only",True)
olddefs={n.name:ast.dump(n,include_attributes=False) for n in before.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
newdefs={n.name:ast.dump(n,include_attributes=False) for n in after.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
check("five_helpers_ast_identical",olddefs==newdefs and len(newdefs)==5)
def assignment(module,name):
    return next(n for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets))
excluded={"ROOT","EXPECTED","report"}
def rest(module):
    return [ast.dump(n,include_attributes=False) for n in module.body if not (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in excluded for t in n.targets))]
check("all_remaining_module_nodes_exact",rest(before)==rest(after))
expected=ast.literal_eval(assignment(after,"EXPECTED").value)
name="service_native_v6_ha_same_root_republication_tests.rs"
check("one_fixed_filename",list(expected)==[name])
candidate=data["candidate"].encode()
check("candidate_pin",expected[name][1]==hashlib.sha256(candidate).hexdigest()==data["source_proof"]["after"]["sha256"])
check("original_pin",expected[name][0]==data["source_proof"]["before"]["sha256"])
check("controller_sha",hashlib.sha256(data["after"].encode()).hexdigest()==data["proof"]["after"]["sha256"])
q=data["request"]
check("request_fields",set(q)=={"host","executable","args","cwd","stdin","timeout_seconds","idempotency_key"})
check("request_exact_argv",q["host"]=="rog" and q["executable"]=="/usr/bin/python3" and q["args"]==["-I","-S","-B","-c",data["after"]] and q["cwd"]=="/home/qian-qi")
check("outer60",q["timeout_seconds"]==60)
check("key_binds_source",q["idempotency_key"]=="heptabao-same-root-retained-a-rustfmt-20261105-r1-"+data["proof"]["after"]["sha256"][:8])
payload=json.loads(q["stdin"])
check("stdin_one_exact_source",payload=={name:data["candidate"]})
check("stdin_original_bound",len(q["stdin"].encode())<=262144)
check("stdin_whole_sha",hashlib.sha256(q["stdin"].encode()).hexdigest()==data["proof"]["payload"]["sha256"])
check("root_fresh_literal",ast.literal_eval(assignment(after,"ROOT").value.args[0])==data["output_plan"]["root"] and ast.literal_eval(assignment(before,"ROOT").value.args[0])!=data["output_plan"]["root"])
check("tool_pin_unchanged",ast.dump(assignment(before,"FMT"),include_attributes=False)==ast.dump(assignment(after,"FMT"),include_attributes=False) and ast.literal_eval(assignment(after,"FMT_SHA").value)=="5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877")
check("format_configuration_exact",ast.literal_eval(assignment(after,"FORMAT_CONFIG").value)==b'edition = "2024"\n' and ast.literal_eval(assignment(after,"FORMAT_CONFIG_SHA").value)=="f32d2f03b3f4b1e295c79ed49d543f1205c7dac7c3dc74f05a5a27af4fea0584")
meta=ast.literal_eval(assignment(after,"report").value)
check("base_identity_and_no_execution_claim",meta["sourceCommit"]=="1c66541993662f92cf717154e33717abedb2ea74" and meta["sourceTree"]=="94ced21a63ff9aaca4538c0d4796efea2150e632" and meta["sourceIdentityIsBaseOnly"] and meta["uncommittedCandidateInputs"] and not meta["compileExecuted"] and not meta["productExecuted"])
check("original_controller_and_child_limits",meta["internalSeconds"]==50 and meta["newRemoteSupervisorSeconds"]==60 and "timeout=min(10.0,remain())" in data["after"])
check("six_fixed_output_contract",data["output_plan"]["fixed_outputs"]==["candidate/"+name,"formatted/"+name,name+".rustfmt.stdout",name+".rustfmt.stderr","rustfmt.toml","result.public.json"])
print(json.dumps({"schema":"heptabao.retained-a-formatter-offline-source-check.v1","status":"passed","check_count":len(checks),"checks":checks,"host_calls":0,"subprocesses_created_by_verifier":0,"candidate_module_executed":False,"rustfmt_executed":False,"rust_compiled":False,"cloud_io_scope":"reads this public JSON input and Python script/stdlib only"},sort_keys=True,indent=2))
