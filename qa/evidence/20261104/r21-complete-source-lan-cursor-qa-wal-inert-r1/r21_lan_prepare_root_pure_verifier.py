import ast,json,sys,types
from pathlib import Path
d=json.loads(sys.argv[1]);p=json.loads(d["prepared_raw"]);tree=ast.parse(d["launcher"])
first=min(n.lineno for n in tree.body if isinstance(n,ast.FunctionDef))
constants=[n for n in tree.body if isinstance(n,ast.Assign) and n.lineno<first and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)]
functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ("args","require_bound_artifact_pins")]
assert len(functions)==2
env={"Path":Path,"sys":types.SimpleNamespace(executable="/usr/bin/python3")}
exec(compile(ast.Module(body=constants+functions,type_ignores=[]),"selected-original-pure-prepare-contract","exec"),env)
env["require_bound_artifact_pins"]()
assert env["args"]()==p["argv"]
for key,name in [("build_pins","BUILDS"),("comparison_pins","COMPARISON_PINS"),("qa_pins","QA_PINS"),("deadline_qa_pins","DEADLINE_QA_PINS"),("required_extra_checks","POSTCOLD_CHECKS"),("source_commit","COMMIT"),("source_tree","TREE"),("runner_sha256","RUNNER_SHA256"),("numeric_helper_sha256","NUMERIC_HELPER_SHA256"),("cipher_helper_sha256","CIPHER_HELPER_SHA256")]:
 assert p[key]==env[name],key
assert len(p["comparison_pins"])==32
assert len(p["direction_contract"]["required_checks"])==98 and len(set(p["direction_contract"]["required_checks"]))==98
assert p["direction_contract"]["required_extra_checks"]==p["required_extra_checks"] and len(p["required_extra_checks"])==12
assert p["direction_contract"]["controlled_stop_order"]==[2,1,3]
assert p["direction_contract"]["requested_cipher_source_node"]==3 and p["direction_contract"]["requested_actual_empty_leader_node"]==1
assert p["direction_contract"]["leader_selection_forced"] is False and p["direction_contract"]["actual_election_required"] is True
assert p["original_controller_seconds"]==2400 and p["new_shared_postrecovery_seconds"]==300 and p["ordinary_http_seconds"]==15 and p["native_admission_seconds"]==8
assert p["fixture_started"] is False and p["production_changed"] is False and p["formal_qualification"] is False
print(json.dumps({"ok":True,"original_pure_functions":2,"argv_exact":True,"original_98_unique":98,"separate_extra":12,"prior_comparison_pins":32,"original_limits_unchanged":True,"fixture_started":False,"main_or_host_code_executed":False},sort_keys=True))
