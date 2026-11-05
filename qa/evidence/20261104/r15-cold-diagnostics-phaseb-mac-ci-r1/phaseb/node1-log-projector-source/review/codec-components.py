import ast, difflib, hashlib, json, re, sys
data=json.loads(sys.argv[1]); old=data["before"]; new=data["after"]
insert='    ("codec", "open_committed_read"),\n'
assert new.count(insert)==1 and new.replace(insert,"",1)==old
trees=[ast.parse(source) for source in (old,new)]
for tree in trees: compile(tree,"fixed-node1-observer-source","exec")
defs=[{node.name:ast.get_source_segment(source,node) for node in tree.body if isinstance(node,(ast.FunctionDef,ast.ClassDef))} for source,tree in zip((old,new),trees)]
assert defs[0]==defs[1]
names={"PHASES","CODES","U128_MAX","SYNC","UNSEAL","TIMING_PREFIX","MAX_TIMING_LINE","U64_MAX","TIMING_KEYS","BUCKET_KEYS","COUNT_KEYS","TIME_KEYS","TIMING_PAIRS"}
functions={"Refused","timing_object_pairs","timing_integer","timing_noninteger","checked_timing_uint","parse_timing_marker","parse_marker"}
def selected(tree):
    nodes=[node for node in tree.body if (isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in names) or (isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in functions)]
    scope={"hashlib":hashlib,"json":json,"re":re}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),"only-pure-parser-definitions","exec"),scope)
    return scope
before,after=map(selected,trees)
bucket={"scope":"codec","phase":"open_committed_read","calls":1,"advanced":0,"completed":1,"failed":0,"elapsed_us":40,"maximum_elapsed_us":40,"first_entry_remaining_ns":500,"last_exit_remaining_ns":400,"minimum_entry_remaining_ns":500,"minimum_exit_remaining_ns":400}
report={"schema":"heptabao.native-ha.request-failure-timing.v1","request_class":"ordinary","forwarded":False,"status":503,"elapsed_us":100,"entry_remaining_ns":500,"exit_remaining_ns":400,"bucket_limit":64,"bucket_bound_reached":False,"phases":[bucket]}
def line(value):return b"HBHA-REQUEST-TIMING-FAIL "+json.dumps(value,separators=(",",":")).encode()+b"\n"
checks=[]
def reject(scope,name,raw):
    try: scope["parse_marker"](raw,1)
    except scope["Refused"]:checks.append(name);return
    raise AssertionError(name)
reject(before,"preserved_r1_refuses_normal_codec_pair",line(report))
actual=after["parse_marker"](line(report),1)
assert actual["phases"][0]["scope"]=="codec" and actual["phases"][0]["phase"]=="open_committed_read"; checks.append("successor_accepts_exact_normal_codec_pair")
bucket["scope"]="fresh_ingress_permission";reject(after,"codec_phase_under_wrong_scope_refused",line(report));bucket["scope"]="codec"
bucket["phase"]="open_other_read";reject(after,"unknown_codec_phase_refused",line(report));bucket["phase"]="open_committed_read"
report["phases"]=[bucket,bucket];reject(after,"duplicate_codec_pair_refused",line(report));report["phases"]=[bucket]
reject(after,"duplicate_json_key_refused",line(report).replace(b'"status":503',b'"status":503,"status":503'))
assert len(after["PHASES"])==41 and len(after["CODES"])==6 and len(after["TIMING_PAIRS"])==50;checks.append("closed_label_counts_41_6_50")
assert all(("fresh_ingress_permission",phase) in after["TIMING_PAIRS"] for phase in data["fresh_steps"]+["scope_total"]) and "fresh_ingress_read_refused" in after["CODES"];checks.append("fresh_ingress_original_labels_preserved")
out={"schema":"heptabao.phaseb-3cb-codec-pair-components.v1","status":"passed","checks":checks,"checks_count":len(checks),"all_function_class_definitions_byte_identical":list(defs[0]),"main_called":False,"target_file_access":False,"candidate_filesystem_called":False,"network_or_child_activity":False,"actual_log_content_used":False,"inverse_exact":True,"before_sha256":hashlib.sha256(old.encode()).hexdigest(),"after_sha256":hashlib.sha256(new.encode()).hexdigest(),"diff":"".join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile="preserved-r1/phaseb_3cb_node1_normal_log_projection.py",tofile="candidate/phaseb_3cb_node1_normal_log_projection_r2.py")),"full_reference_diff":"".join(difflib.unified_diff(data["reference"].splitlines(True),new.splitlines(True),fromfile="reference/ha_node2_normal_timing.py",tofile="candidate/phaseb_3cb_node1_normal_log_projection_r2.py"))}
print(json.dumps(out,sort_keys=True,indent=2))
