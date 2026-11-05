#!/usr/bin/env python3
import ast, __future__, contextlib, copy, hashlib, json, shlex, types
from pathlib import Path
from collections import namedtuple
ROOT=Path("/tmp/heptabao_postcold_qa_source_review_r1")
CHECKS=[];SOURCES={}
harness=(ROOT/"components_draft1.py").read_text()
allowed=("check","FixtureError","Refusal","Clock","source","tree","node","selected","norm","refused")
body=[x for x in ast.parse(harness).body if isinstance(x,(ast.FunctionDef,ast.ClassDef)) and x.name in allowed]
exec(compile(ast.Module(body=body,type_ignores=[]),"<component-definitions-only>","exec"),globals())
names=("ha_multihost_live.py","native_v6_ha_multihost_live.py","native_v6_ha_direct_lan_live.py")
old={n:source("base/deadline_qa/"+n) for n in names}
new={n:source("candidate/deadline_qa/"+n) for n in names}
runner=source("candidate/native_v6_pocket_source_postrecovery_cold_r10_r1.py")
Node=namedtuple("Node","node_id alias root")
mac=Node(1,"mac","/synthetic/mac");linux=Node(2,"linux","/synthetic/linux")
def native_env(src):
    clock=Clock();trace=[]
    base=types.SimpleNamespace(FixtureError=FixtureError)
    bn={"FixtureError":FixtureError,"time":clock};selected(new[names[0]],bn,functions=("parent_remaining",))
    base.parent_remaining=bn["parent_remaining"]
    base.wait_listener=lambda *a,**k:trace.append(("listener",a,k))
    ns={"base":base,"time":clock,"REQUEST_SECONDS":15.0,"json":json}
    ns["process_action"]=lambda *a,**k:(trace.append(("owned_action",a,k)) or 123)
    ns["assert_stopped"]=lambda *a,**k:trace.append(("assert_stopped",a,k))
    selected(src,ns,classes={"NativeRun":("owned_process_action","start","stop","unseal")})
    x=ns["NativeRun"]();x.run_id="fresh";x.context="ctx";x.unseal_key="synthetic";x.started=set()
    x.event=lambda *a,**k:trace.append(("event",a,k))
    x.request=lambda *a,**k:(trace.append(("request",a,k)) or (200,{"sealed":False}))
    return x,ns,trace
a,an,at=native_env(old[names[1]]);b,bn,bt=native_env(new[names[1]])
check("native_start_none_same_behavior",a.start(mac)==b.start(mac) and a.started==b.started and norm(at)==norm(bt))
at.clear();bt.clear()
check("native_stop_none_same_behavior",a.stop(mac)==b.stop(mac) and a.started==b.started==set() and norm(at)==norm(bt))
at.clear();bt.clear();a.unseal(mac);b.unseal(mac)
check("native_unseal_none_same_behavior",norm(at)==norm(bt))
bt.clear();b.start(mac,parent_deadline=103);b.stop(mac,parent_deadline=103);b.unseal(mac,parent_deadline=103)
calls=[r for r in bt if r[0] in ("owned_action","assert_stopped","listener","request")]
check("native_start_stop_unseal_forward_same_absolute_parent",len(calls)==5 and all(r[2]["parent_deadline"]==103 for r in calls))
# Actual direct override selects a real foreground-session interface only on Mac.
def direct_env(src):
    clock=Clock();trace=[]
    class Parent:
        def owned_process_action(self,*a,**k):trace.append(("parent",a,k));return 456
    class Session:
        def __init__(self,*a,**k):trace.append(("session",a,k));self.receipt={"synthetic":True}
        def start(self,**k):trace.append(("fg_start",k));return 789
        def stop(self,**k):trace.append(("fg_stop",k));return 789
    ns={"native":types.SimpleNamespace(NativeRun=Parent),
        "foreground":types.SimpleNamespace(ForegroundSession=Session,Refusal=Refusal),
        "base":types.SimpleNamespace(FixtureError=FixtureError),"time":clock}
    q={"FixtureError":FixtureError,"time":clock};selected(new[names[0]],q,functions=("parent_remaining",))
    ns["base"].parent_remaining=q["parent_remaining"]
    selected(src,ns,classes={"DirectLanRun":("owned_process_action",)})
    x=ns["DirectLanRun"]();x.foreground_nodes=[mac];x.foreground_sessions={}
    x.run_id="fresh";x.work="synthetic";x.expected={"1":"digest"};x.foreground_helper="helper"
    x.args=types.SimpleNamespace(source_commit="c",source_tree="t",darwin_watchdog_python="python",darwin_watchdog_python_sha256="pin")
    x.hosts={"mac":{"system":"Darwin"}};x.report={"foreground_sessions":[]}
    return x,trace
a,at=direct_env(old[names[2]]);b,bt=direct_env(new[names[2]])
check("direct_mac_start_none_exact_call",a.owned_process_action(mac,"start")==b.owned_process_action(mac,"start") and norm(at)==norm(bt))
at.clear();bt.clear()
check("direct_mac_stop_none_exact_call",a.owned_process_action(mac,"stop")==b.owned_process_action(mac,"stop") and norm(at)==norm(bt))
at.clear();bt.clear()
check("direct_linux_none_exact_call",a.owned_process_action(linux,"start")==b.owned_process_action(linux,"start") and norm(at)==norm(bt))
b,bt=direct_env(new[names[2]])
check("direct_parent_expired_before_session_or_super",refused(b.owned_process_action,mac,"start",parent_deadline=99) and bt==[] and b.foreground_sessions=={})
b.owned_process_action(mac,"start",parent_deadline=103);b.owned_process_action(mac,"stop",parent_deadline=103)
check("direct_same_absolute_parent_to_start_stop",[r for r in bt if r[0] in ("fg_start","fg_stop")]==[("fg_start",{"parent_deadline":103}),("fg_stop",{"parent_deadline":103})])
b.owned_process_action(linux,"start",parent_deadline=103)
check("direct_linux_parent_reaches_original_owner",bt[-1][0]=="parent" and bt[-1][2]["parent_deadline"]==103)
# New phase clamps itself to both clocks and refuses before opening a reference.
clock=Clock();q={"FixtureError":FixtureError,"time":clock};selected(new[names[0]],q,functions=("parent_remaining",))
base=types.SimpleNamespace(FixtureError=FixtureError,parent_remaining=q["parent_remaining"])
ns={"time":clock,"base":base,"direct":types.SimpleNamespace(DirectLanRun=object),"POSTCOLD_SECONDS":300.0}
selected(runner,ns,classes={"PocketSourcePostRecoveryColdRun":("_postcold_remaining",)})
p=ns["PocketSourcePostRecoveryColdRun"]()
# Execute the actual entry's first four statements: the phase stores min(300,parent)
# once; the remaining helper then consumes that already-clamped absolute value.
entry=copy.deepcopy(node(runner,"post_recovery_cold","PocketSourcePostRecoveryColdRun"))
assert len(entry.body)>4 and isinstance(entry.body[2],ast.Assign)
entry.body=entry.body[:4]
exec(compile(ast.fix_missing_locations(ast.Module(body=[entry],type_ignores=[])),"<actual-cold-entry-prefix>","exec"),ns)
p.controller_until=120
ns["post_recovery_cold"](p,None,None)
check("new_phase_entry_clamps_original_controller",p.postcold_until==120 and p._postcold_remaining(300)==20)
p.controller_until=1000
ns["post_recovery_cold"](p,None,None)
check("new_phase_entry_clamps_shared_300",p.postcold_until==400 and p._postcold_remaining(300)==300)
p.controller_until=105
ns["post_recovery_cold"](p,None,None)
check("new_phase_remaining_respects_leaf_limit",p._postcold_remaining(2)==2)
check("new_phase_remaining_respects_nested_until",p._postcold_remaining(15,until=102)==2)
p.controller_until=99
check("new_phase_expired_entry_before_reference_or_child",refused(ns["post_recovery_cold"],p,None,None))
# Original runner execute chain is recovered by removing precisely one new scope call.
cls0=next(x for x in ast.parse(source("base/native_v6_pocket_source_direct98_r10_r3.py")).body if isinstance(x,ast.ClassDef))
cls1=next(x for x in ast.parse(runner).body if isinstance(x,ast.ClassDef))
old_execute=next((x for x in cls0.body if isinstance(x,ast.FunctionDef) and x.name=="execute"),None)
new_execute=next(x for x in cls1.body if isinstance(x,ast.FunctionDef) and x.name=="execute")
check("new_execute_contains_one_extra_cold_call",sum(isinstance(x,ast.Call) and isinstance(x.func,ast.Attribute) and x.func.attr=="post_recovery_cold" for x in ast.walk(new_execute))==1)
original_native=node(old[names[1]],"execute","NativeRun")
copy_exec=copy.deepcopy(new_execute)
copy_exec.body=[x for x in copy_exec.body if not(isinstance(x,ast.Assign) and isinstance(x.value,ast.Call) and isinstance(x.value.func,ast.Attribute) and x.value.func.attr=="post_recovery_cold")]
check("new_execute_other_business_sequence_is_original",ast.dump(copy_exec,include_attributes=False)==ast.dump(original_native,include_attributes=False))
print(json.dumps({"schema":"heptabao.postrecovery-cold-callchain-components.v1","source_tree":"e9a5f1f673f18a4d2b7162f4188a6bbc221e29ac","checks":CHECKS,"passed":len(CHECKS),"failed":0,"sources":SOURCES,"physical_host_access":False,"real_child_processes":0,"real_network_requests":0,"real_product_operations":0,"scope":"AST-selected actual opt-in methods with synthetic process/session/caller; default traces normalize only absent-versus-None parent_deadline"},sort_keys=True))
