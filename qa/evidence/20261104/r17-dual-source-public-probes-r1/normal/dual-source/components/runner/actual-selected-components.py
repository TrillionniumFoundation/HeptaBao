import ast, hashlib, json, types
def check(cond, name):
    if not cond:
        raise AssertionError(name)
    checks.append(name)
checks=[]
old_s=data["before"]; new_s=data["after"]
old_t=ast.parse(old_s); new_t=ast.parse(new_s)
def defs(tree):
    return {n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
o=defs(old_t); n=defs(new_t)
for name in ("sha","write","git","freeze","group_members","terminate_owned","signal_received"):
    check(ast.dump(o[name],include_attributes=False)==ast.dump(n[name],include_attributes=False),"unchanged_helper_"+name)
old_loop=next(x for x in ast.walk(old_t) if isinstance(x,ast.For) and isinstance(x.target,ast.Name) and x.target.id=="group" and isinstance(x.iter,ast.Name) and x.iter.id=="groups")
new_loop=next(x for x in ast.walk(new_t) if isinstance(x,ast.For) and isinstance(x.target,ast.Name) and x.target.id=="group" and isinstance(x.iter,ast.Name) and x.iter.id=="groups")
check(ast.dump(old_loop,include_attributes=False)==ast.dump(new_loop,include_attributes=False),"original_44_loop_AST_identical")
def assigned(tree,name):
    for x in tree.body:
        if isinstance(x,ast.Assign) and any(isinstance(y,ast.Name) and y.id==name for y in x.targets):
            return ast.literal_eval(x.value)
    raise AssertionError(name)
new7=assigned(new_t,"INGRESS_OBSERVER_TESTS"); new9=assigned(new_t,"COLD_H2_TESTS")
check(list(new7)==data["seven"],"original_seven_names_exact")
check(list(new9)==data["nine"],"new_nine_names_exact")
check(len(set(data["original44"]+list(new7)+list(new9)))==60,"all_60_distinct")
check(assigned(new_t,"ORIGINAL_OUTER_SECONDS")==data["outer"],"original_outer_seconds_exact")
# Select the real function definitions; never execute either module.
def harness(tree, new, *, now=10.0, open_advance=0.0, wait_advance=0.0, until=1000.0):
    state={"now":now,"calls":[],"opened":0,"closed":0,"fsync":0,"records":[]}
    class File:
        def __enter__(self):
            state["opened"]+=1; state["now"]+=open_advance; return self
        def __exit__(self,*unused):
            state["closed"]+=1
        def flush(self): state["calls"].append("flush")
        def fileno(self): return 7
    class Out:
        def __truediv__(self,name):
            return self
        def open(self,mode):
            state["calls"].append(["open",mode]); return File()
    class Timeout(Exception): pass
    class Proc:
        pid=1234
        returncode=None
        def wait(self,timeout):
            state["calls"].append(["wait",timeout]); state["now"]+=wait_advance
            self.returncode=0; return 0
        def poll(self):
            state["calls"].append("poll"); return self.returncode
    def spawn(*a,**kw):
        state["calls"].append(["spawn",list(a[0]),kw["start_new_session"]])
        return Proc()
    def fsync(fd):
        state["fsync"]+=1
    def write(name,value):
        state["records"].append([name,value])
    def stop(p):
        state["calls"].append("stop")
        p.returncode=-15
        return []
    env={"time":types.SimpleNamespace(monotonic=lambda:state["now"]),
         "output":Out(),"protected":0,"pending_signal":None,"children":[],
         "source":"/synthetic-source","environment":{},"Cancelled":type("Cancelled",(BaseException,),{}),
         "subprocess":types.SimpleNamespace(Popen=spawn,DEVNULL=-3,TimeoutExpired=Timeout),
         "os":types.SimpleNamespace(fsync=fsync),"group_members":lambda pgid:[],
         "write":write,"sha":lambda p:"0"*64,"terminate_owned":stop,"OUTER_UNTIL":until}
    d=defs(tree)
    selected=[d[x] for x in (("bounded_remaining","owned") if new else ("owned",))]
    exec(compile(ast.Module(body=selected,type_ignores=[]),"<actual-selected-definitions>","exec"),env)
    return env,state
oldenv,olds=harness(old_t,False,wait_advance=2)
newenv,news=harness(new_t,True,wait_advance=2)
ro=oldenv["owned"]("sample",["synthetic-command"],30)
rn=newenv["owned"]("sample",["synthetic-command"],30)
check(ro==rn and olds["calls"]==news["calls"] and olds["fsync"]==news["fsync"],"None_default_actual_function_equivalent")
check(olds["opened"]==olds["closed"]==news["opened"]==news["closed"]==2,"None_default_streams_closed")
def refused_before_spawn(env,state,deadline,name):
    try:
        env["owned"]("sample",["synthetic-command"],30,deadline=deadline)
    except AssertionError:
        pass
    else:
        raise AssertionError(name+"_accepted")
    check(not any(isinstance(x,list) and x[0]=="spawn" for x in state["calls"]),name+"_no_spawn")
    check(not env["children"] and env["protected"]==0,name+"_no_child_or_guard_leak")
    check(state["opened"]==state["closed"],name+"_streams_closed")
env,state=harness(new_t,True)
refused_before_spawn(env,state,9.0,"expired_at_entry")
env,state=harness(new_t,True,open_advance=0.75)
refused_before_spawn(env,state,11.0,"expired_after_capture_open")
env,state=harness(new_t,True,until=12.0)
r=env["owned"]("sample",["synthetic-command"],30,deadline=100.0)
check(next(x[1] for x in state["calls"] if isinstance(x,list) and x[0]=="wait")==2.0,"wait_clamped_to_original_outer")
check(r["exit_code"]==0 and not r["timed_out"],"within_cap_known_success")
env,state=harness(new_t,True,until=1000.0)
r=env["owned"]("sample",["synthetic-command"],30,deadline=11.0)
check(next(x[1] for x in state["calls"] if isinstance(x,list) and x[0]=="wait")==1.0,"wait_clamped_to_group_deadline")
env,state=harness(new_t,True,wait_advance=2)
r=env["owned"]("sample",["synthetic-command"],30,deadline=11.0)
check(r["exit_code"]==0 and r["timed_out"],"late_zero_exit_cannot_be_qualified")
check(r["direct_child_reaped"] and state["opened"]==state["closed"]==2,"late_child_reaped_and_streams_closed")
# Additional loops must actually pass the absolute deadline to each owned call.
for method,deadline in (("extra_remaining","extra_until"),("increment_remaining","increment_until")):
    calls=[]
    for node in ast.walk(new_t):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="owned":
            for kw in node.keywords:
                if kw.arg=="deadline" and isinstance(kw.value,ast.Name) and kw.value.id==deadline:
                    calls.append(node)
    check(len(calls)==2,method+"_listing_and_execution_share_deadline")
print(json.dumps({"schema":"heptabao.cold-h2-normal-runner-pure-components.v1",
 "host_profile":data["host"],"source_sha256":hashlib.sha256(new_s.encode()).hexdigest(),
 "before_sha256":hashlib.sha256(old_s.encode()).hexdigest(),"checks":checks,"passed":len(checks),
 "module_execution":False,"actual_subprocesses":0,"actual_files":0,"network":0,
 "scope":"AST-selected real owned/bounded_remaining against synthetic time/process/file objects; original helper and 44-loop AST equality"},sort_keys=True))
