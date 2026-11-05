import ast,difflib,hashlib,json,re,sys
d=json.loads(sys.argv[1]); old=d["before"]; new=d["after"]
o=ast.parse(old); n=ast.parse(new); compile(n,"new-fixed-node1-observer","exec")
olddefs={x.name:ast.get_source_segment(old,x) for x in o.body if isinstance(x,(ast.FunctionDef,ast.ClassDef))}
newdefs={x.name:ast.get_source_segment(new,x) for x in n.body if isinstance(x,(ast.FunctionDef,ast.ClassDef))}
unchanged=[name for name in olddefs if name!="main" and olddefs[name]==newdefs[name]]
assert set(olddefs)==set(newdefs) and len(unchanged)==len(olddefs)-1
names={"PHASES","CODES","U128_MAX","SYNC","UNSEAL","TIMING_PREFIX","MAX_TIMING_LINE","U64_MAX","TIMING_KEYS","BUCKET_KEYS","COUNT_KEYS","TIME_KEYS","TIMING_PAIRS"}
defs={"Refused","timing_object_pairs","timing_integer","timing_noninteger","checked_timing_uint","parse_timing_marker","parse_marker"}
selected=[x for x in n.body if isinstance(x,ast.Assign) and len(x.targets)==1 and isinstance(x.targets[0],ast.Name) and x.targets[0].id in names or isinstance(x,(ast.FunctionDef,ast.ClassDef)) and x.name in defs]
g={"hashlib":hashlib,"json":json,"re":re}; exec(compile(ast.Module(body=selected,type_ignores=[]),"selected-pure-parser","exec"),g)
checks=[]
def ok(name,fn):
    assert fn(),name;checks.append(name)
def refused(name,line):
    try:g["parse_marker"](line,1)
    except g["Refused"]:checks.append(name);return
    raise AssertionError(name)
for step in d["fresh_steps"]:
    line=("HBHA-NATIVE-SYNC-FAIL step="+step+" code=fresh_ingress_read_refused reason_sha="+"0"*64+" elapsed_us=100 step_elapsed_us=20 original_deadline_expired=false original_remaining_ns=500 panicking=false\n").encode()
    ok("fresh_sync_"+step,lambda line=line,step=step:g["parse_marker"](line,1)["step"]==step)
bucket={"scope":"fresh_ingress_permission","phase":"scope_total","calls":1,"advanced":0,"completed":0,"failed":1,"elapsed_us":100,"maximum_elapsed_us":100,"first_entry_remaining_ns":500,"last_exit_remaining_ns":400,"minimum_entry_remaining_ns":500,"minimum_exit_remaining_ns":400}
report={"schema":"heptabao.native-ha.request-failure-timing.v1","request_class":"ordinary","forwarded":False,"status":503,"elapsed_us":100,"entry_remaining_ns":500,"exit_remaining_ns":400,"bucket_limit":64,"bucket_bound_reached":False,"phases":[bucket]}
def line(value):return b"HBHA-REQUEST-TIMING-FAIL "+json.dumps(value,separators=(",",":")).encode()+b"\n"
for phase in d["fresh_steps"]+["scope_total"]:
    bucket["phase"]=phase
    ok("fresh_timing_"+phase,lambda phase=phase:g["parse_marker"](line(report),1)["phases"][0]["phase"]==phase)
bucket["scope"]="committed_read_entry";bucket["phase"]=d["fresh_steps"][0];refused("fresh_phase_wrong_scope",line(report));bucket["scope"]="fresh_ingress_permission";bucket["phase"]="scope_total"
bucket["phase"]="fresh_ingress_not_a_static_label";refused("unknown_fresh_timing_phase",line(report));bucket["phase"]="scope_total"
report["phases"]=[bucket,bucket];refused("duplicate_pair_rejected",line(report));report["phases"]=[bucket]
bad=line(report).replace(b'"status":503',b'"status":503,"status":503')
refused("duplicate_json_key_rejected",bad)
ok("closed_label_counts",lambda:len(g["PHASES"])==41 and len(g["CODES"])==6 and len(g["TIMING_PAIRS"])==49)
diff="".join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile="reference/ha-node2-normal-timing.py",tofile="candidate/phaseb_3cb_node1_normal_log_projection.py"))
out={"schema":"heptabao.phaseb-3cb-node1-marker-source-components.v1","candidate_sha256":hashlib.sha256(new.encode()).hexdigest(),"status":"passed","checks":checks,"checks_count":len(checks),"unchanged_definitions":unchanged,"all_nonmain_definitions_byte_identical":True,"main_or_filesystem_code_called":False,"target_file_access":False,"network_or_child_activity":False,"actual_log_content_used":False,"source_compiled_not_main_executed":True,"diff":diff}
print(json.dumps(out,sort_keys=True,indent=2))
