import ast,hashlib,json,re,sys,types
data=json.load(sys.stdin)
before=data["before"];after=data["after"]
bt=ast.parse(before);at=ast.parse(after)
compile(after,"locator-first-window-r3.py","exec")
checks=[]
def check(name,ok):
    if not ok: raise AssertionError(name)
    checks.append({"case":name,"passed":True})
insert='        if scope == "desktop-fence":\n            ceiling = min(ceiling, 1793868160140)\n'
check("exact_two_inserted_lines_inverse_whole_equal",after.count(insert)==1 and after.replace(insert,"")==before)
def cfg(tree):
    node=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=="CONFIGS" for x in n.targets))
    return json.loads(ast.literal_eval(node.value.args[0]))
config=cfg(at)
check("both_original_configs_exact",cfg(bt)==config)
main=next(n for n in at.body if isinstance(n,ast.FunctionDef) and n.name=="main")
body=next(n for n in main.body if isinstance(n,ast.Try)).body
position=next(i for i,n in enumerate(body) if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=="ceiling" for x in n.targets))
nodes=body[position:position+3]
check("selected_actual_sample_clamp_and_original_gate",isinstance(nodes[0],ast.Assign) and isinstance(nodes[1],ast.If) and isinstance(nodes[2],ast.Expr))
defs=[n for n in at.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in ("Refused","need","canonical_job_time")]
scope_globals={"re":re,"JOB_NAME":re.compile(r"([0-9a-f]{1,32})-([0-9a-f]{1,8})-([0-9a-f]{1,16})\Z")}
exec(compile(ast.Module(body=defs,type_ignores=[]),"selected-pure-defs","exec"),scope_globals)
selected=compile(ast.Module(body=nodes,type_ignores=[]),"selected-time-only","exec")
floor=1793864424254;cut=1793868160140;old_ceiling=1793871896027
check("midpoint_and_unsearched_remainder_contiguous",cut==(floor+old_ceiling)//2 and cut+1<=old_ceiling)
cases=[
 ("later_now_clamps_to_fixed_end","desktop-fence",old_ceiling,cut,False),
 ("equal_now_uses_same_end","desktop-fence",cut,cut,False),
 ("earlier_now_is_never_exceeded","desktop-fence",floor+1,floor+1,False),
 ("anchor_boundary_keeps_original_gate","desktop-fence",floor,floor,False),
 ("clock_before_anchor_refuses","desktop-fence",floor-1,floor-1,True),
 ("unselected_rog_branch_remains_dynamic","rog-source",old_ceiling,old_ceiling,False)]
for name,scope,now,expected,refuses in cases:
    samples=[]
    def now_ns():
        samples.append(now);return now*1000000
    g=dict(scope_globals,scope=scope,config=config[scope],time=types.SimpleNamespace(time_ns=now_ns))
    error=None
    try:exec(selected,g)
    except scope_globals["Refused"] as e:error=e.code
    check(name,len(samples)==1 and g["ceiling"]==expected and expected<=now and (error=="observation_time_window" if refuses else error is None))
result={"schema":"heptabao.desktop-locator-fixed-window.pure-time-checks.r3",
 "status":"passed","count":len(checks),"checks":checks,
 "base_sha256":hashlib.sha256(before.encode()).hexdigest(),
 "candidate_sha256":hashlib.sha256(after.encode()).hexdigest(),
 "scope":{"whole_source_AST_compile_only":True,"actual_selected_time_statements_only":True,
 "whole_module_executed":False,"prior_25_components_rerun":False,"host_calls":0,
 "actual_file_or_directory_IO":0,"actual_children_network_or_signals":0}}
print(json.dumps(result,sort_keys=True,indent=2))
