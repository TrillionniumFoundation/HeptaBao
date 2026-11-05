#!/usr/bin/env python3
"""Pure selected-function components. Reads only the frozen local source copies."""
import ast, __future__, base64, contextlib, copy, hashlib, json, math, re, shlex, stat, types
from pathlib import Path
from urllib import parse as urlparse, error as urlerror
ROOT=Path("/tmp/heptabao_postcold_qa_source_review_r1")
CHECKS=[]
SOURCES={}
def check(name,value,**facts):
    assert value,(name,facts)
    CHECKS.append({"name":name,"passed":True,**facts})
class FixtureError(RuntimeError):pass
class Refusal(RuntimeError):pass
class Clock:
    def __init__(self):self.value=100.0;self.sleeps=[]
    def monotonic(self):return self.value
    def sleep(self,n):
        assert n>=0
        self.sleeps.append(n);self.value+=n
def source(path):
    raw=(ROOT/path).read_bytes();text=raw.decode()
    SOURCES[path]={"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
    ast.parse(text);compile(text,str(path),"exec")
    return text
def tree(s):return ast.parse(s)
def node(s,name,cls=None):
    scope=tree(s).body
    if cls:scope=next(x for x in scope if isinstance(x,ast.ClassDef) and x.name==cls).body
    return next(x for x in scope if isinstance(x,(ast.FunctionDef,ast.ClassDef)) and x.name==name)
def selected(s,ns,functions=(),classes=None,assignments=()):
    body=[]
    for x in tree(s).body:
        if isinstance(x,(ast.FunctionDef,ast.ClassDef)) and x.name in functions:
            body.append(copy.deepcopy(x))
        elif isinstance(x,ast.ClassDef) and classes and x.name in classes:
            y=copy.deepcopy(x)
            y.body=[m for m in y.body if isinstance(m,ast.FunctionDef) and m.name in classes[x.name]]
            body.append(y)
        elif isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id in assignments for t in x.targets):
            body.append(copy.deepcopy(x))
    m=ast.fix_missing_locations(ast.Module(body=body,type_ignores=[]))
    exec(compile(m,"<selected-actual-functions>","exec",flags=__future__.annotations.compiler_flag),ns)
    return ns
def norm(v):
    if isinstance(v,dict):return {k:norm(x) for k,x in v.items() if not(k=="parent_deadline" and x is None)}
    if isinstance(v,(list,tuple)):return [norm(x) for x in v]
    if isinstance(v,types.SimpleNamespace):return norm(vars(v))
    if isinstance(v,BaseException):return [type(v).__name__,str(v)]
    return v
def refused(fn,*args,code=None,**kwargs):
    try:fn(*args,**kwargs)
    except (FixtureError,Refusal) as e:
        if code is not None:assert str(e)==code,(code,str(e))
        return True
    raise AssertionError("expected refusal")
names=("ha_multihost_live.py","native_v6_ha_multihost_live.py","native_v6_ha_direct_lan_live.py","native_ha_foreground_watchdog.py")
old={n:source("base/deadline_qa/"+n) for n in names}
new={n:source("candidate/deadline_qa/"+n) for n in names}
runner_old=source("base/native_v6_pocket_source_direct98_r10_r3.py")
runner_new=source("candidate/native_v6_pocket_source_postrecovery_cold_r10_r1.py")
reader=source("candidate/read_stopped_recovered_cipher_r1.py")
for p in ("candidate/read_stopped_postrecovery_frontier_r1.py","candidate/launch_normal_r10_pocket_postrecovery_cold_r1.py","candidate/probe_normal_build_r10_r1.py","base/launch_normal_r10_pocket_direct98_r3.py","base/read_stopped_direction_frontier_r3.py"):
    source(p)
check("sixteen_frozen_sources_ast_and_compile_only",len(SOURCES)==16)
# The original business methods and affine foreground custody are not rewritten.
for name in ("prepare","bootstrap_v5","activate_and_grow","failover_and_quorum","full_cold_restart","missing_cipher_leader","finish_application","execute","cleanup","check","event","checkpoint"):
    check("native_original_ast_"+name,ast.dump(node(old[names[1]],name,"NativeRun"),include_attributes=False)==ast.dump(node(new[names[1]],name,"NativeRun"),include_attributes=False))
for name in ("require_waitid","exit_observation","ps_rows","stable","verify_unreaped","live_group","stop_unreaped"):
    check("foreground_custody_ast_"+name,ast.dump(node(old[names[3]],name),include_attributes=False)==ast.dump(node(new[names[3]],name),include_attributes=False))
# The same original foreground stop budget and the new phase/controller caps are literals.
cap_ns={}
selected(new[names[3]],cap_ns,assignments=("START_SECONDS","STOP_SECONDS"))
check("foreground_original_60_5_caps",cap_ns=={"__builtins__":__builtins__,"START_SECONDS":60.0,"STOP_SECONDS":5.0} or (cap_ns.get("START_SECONDS")==60 and cap_ns.get("STOP_SECONDS")==5))
# Actual base functions with all child/network operations replaced.
def base_env(s):
    clock=Clock();calls=[]
    def run(*args,**kw):calls.append(("run",args,kw));return types.SimpleNamespace(stdout=b"synthetic\n",returncode=0)
    sp=types.SimpleNamespace(PIPE="PIPE",run=run)
    ns={"FixtureError":FixtureError,"time":clock,"subprocess":sp,"json":json,"re":re,"MAX_BODY":1024,"NoRedirect":lambda:"no-redirect"}
    ns["ssl"]=types.SimpleNamespace(SSLError=type("SSLError",(OSError,),{}))
    selected(s,ns,functions=("parent_remaining","checked_run","ssh","api","wait_listener"))
    return ns,clock,calls,sp
B0,C0,T0,P0=base_env(old[names[0]]);B1,C1,T1,P1=base_env(new[names[0]])
N=types.SimpleNamespace(alias="synthetic-node",root="/synthetic/root",node_id=1,api_origin="https://synthetic")
for kw in ({},{"input_bytes":b"x","timeout":7,"stdout":"sink"}):
    T0.clear();T1.clear();a=B0["checked_run"](["command"],**kw);b=B1["checked_run"](["command"],**kw)
    check("checked_run_none_exact_call_"+str(len(CHECKS)),norm(T0)==norm(T1) and norm(a)==norm(b))
T0.clear();T1.clear()
check("ssh_none_exact_text",B0["ssh"](N,"synthetic-script")==B1["ssh"](N,"synthetic-script") and norm(T0)==norm(T1))
T1.clear();check("expired_checked_run_no_child",refused(B1["checked_run"],["command"],parent_deadline=99) and T1==[])
T1.clear();check("expired_ssh_no_child",refused(B1["ssh"],N,"script",parent_deadline=99) and T1==[])
T1.clear();B1["checked_run"](["command"],timeout=120,parent_deadline=103)
check("checked_run_actual_child_timeout_clamped",T1[-1][2]["timeout"]==3)
def late_run(*args,**kw):T1.append(("late_run",args,kw));C1.value=104;return types.SimpleNamespace(stdout=b"")
P1.run=late_run;C1.value=100
check("late_child_return_cannot_pass",refused(B1["checked_run"],["command"],parent_deadline=103));C1.value=100
for value in (True,float("nan"),float("inf"),-1,0):
    check("invalid_parent_refused_"+str(value),refused(B1["parent_remaining"],value,15))
# urllib request and response are synthetic; no opener performs any I/O.
def add_http(ns,clock,trace,*,late=0):
    class Response:
        status=200
        def __enter__(self):trace.append(("enter",));return self
        def __exit__(self,*a):trace.append(("exit",))
        def read(self,n):trace.append(("read",n));clock.value+=late;return b'{"data":{"ok":true}}'
    def request(*a,**k):trace.append(("request",a,k));return ("request",a,k)
    def open_(*a,**k):trace.append(("open",a,k));return Response()
    request_ns=types.SimpleNamespace(Request=request,ProxyHandler=lambda x:("proxy",x),HTTPSHandler=lambda **k:("https",k),build_opener=lambda *x:types.SimpleNamespace(open=open_))
    ns["urllib"]=types.SimpleNamespace(request=request_ns,error=urlerror)
H0=[];H1=[];add_http(B0,C0,H0);add_http(B1,C1,H1)
check("api_none_exact_calls_and_result",B0["api"]("ctx",N,"POST","secret/data/x",{"x":1},"synthetic",timeout=7)==B1["api"]("ctx",N,"POST","secret/data/x",{"x":1},"synthetic",timeout=7) and norm(H0)==norm(H1))
H1.clear();C1.value=100;add_http(B1,C1,H1)
check("api_expired_never_dispatches",refused(B1["api"],"ctx",N,"GET","sys/health",parent_deadline=99) and not any(x[0]=="open" for x in H1))
H1.clear();C1.value=100;add_http(B1,C1,H1,late=4)
check("api_late_body_cannot_pass",refused(B1["api"],"ctx",N,"GET","sys/health",timeout=15,parent_deadline=103) and next(x for x in H1 if x[0]=="open")[2]["timeout"]==3)
for B,C,T in ((B0,C0,T0),(B1,C1,T1)):
    C.value=100;T.clear()
    B["api"]=lambda *a,_T=T,**k:(_T.append(("api",a,k)) or (200,{"sealed":True}))
check("wait_listener_none_exact",B0["wait_listener"]("ctx",N)==B1["wait_listener"]("ctx",N) and norm(T0)==norm(T1))
T1.clear();C1.value=100
check("wait_listener_expired_no_api",refused(B1["wait_listener"],"ctx",N,parent_deadline=99) and T1==[])
# Native functions use the real original script builders, never execute their output.
def native_env(s,base_source):
    clock=Clock();trace=[]
    base=types.SimpleNamespace(FixtureError=FixtureError)
    bns={"FixtureError":FixtureError,"time":clock};selected(new[names[0]],bns,functions=("parent_remaining",))
    base.parent_remaining=bns["parent_remaining"]
    q={};selected(base_source,q,assignments=("REMOTE_PROCESS_SCRIPT",));base.REMOTE_PROCESS_SCRIPT=q["REMOTE_PROCESS_SCRIPT"]
    def ssh(node,script,**kw):
        trace.append(("ssh",node,script,kw))
        if "CIPHER" in script:return "{}"
        return "123\n"
    base.ssh=ssh
    ns={"base":base,"time":clock,"json":json,"shlex":shlex,"REQUEST_SECONDS":15.0,"hashlib":hashlib,"urllib":types.SimpleNamespace(parse=urlparse)}
    fs=("canonical","data_digest","native_process_script","bounded_native_process_script","process_action","assert_stopped","captured_cipher_reference_script","cipher_inventory")
    methods=("request","owned_process_action","start","stop","unseal","read_data","exact_read","small_reads","history_reads","metadata","absent")
    selected(s,ns,functions=fs,classes={"NativeRun":methods},assignments=("STOPPED_CHECK","CIPHER_INVENTORY_SCRIPT"))
    return ns,base,clock,trace
V0,Q0,K0,U0=native_env(old[names[1]],old[names[0]]);V1,Q1,K1,U1=native_env(new[names[1]],new[names[0]])
script0=V0["native_process_script"]();script1=V1["native_process_script"]()
check("native_process_default_script_byte_identical",script0==script1)
for action in ("start","stop"):
    U0.clear();U1.clear()
    check("native_process_action_none_"+action,V0["process_action"](N,"synthetic",action)==V1["process_action"](N,"synthetic",action) and norm(U0)==norm(U1))
U0.clear();U1.clear();V0["assert_stopped"](N);V1["assert_stopped"](N)
check("assert_stopped_none_exact_script",norm(U0)==norm(U1))
U1.clear();check("native_process_expired_no_ssh",refused(V1["process_action"],N,"synthetic","start",parent_deadline=99) and U1==[])
U1.clear();check("assert_stopped_expired_no_ssh",refused(V1["assert_stopped"],N,parent_deadline=99) and U1==[])
for Q,U in ((Q0,U0),(Q1,U1)):
    Q.ssh=lambda *a,_U=U,**k:(_U.append(("ssh",a,k)) or '{"restored_count":1,"restored_bytes":3}')
U0.clear();U1.clear()
check("cipher_none_original_scan_script_exact",V0["cipher_inventory"](N,"synthetic","recovered")==V1["cipher_inventory"](N,"synthetic","recovered") and norm(U0)==norm(U1))
for action,parent in (("quarantine",110),("empty",110),("recovered",None)):
    U1.clear()
    check("capture_requires_same_recovered_scan_"+action+"_"+str(parent),refused(V1["cipher_inventory"],N,"synthetic",action,capture_reference=True,parent_deadline=parent) and U1==[])
generated={"native_default":script1,"native_bounded":V1["bounded_native_process_script"](4),"captured_reference":V1["captured_cipher_reference_script"](V1["CIPHER_INVENTORY_SCRIPT"].replace("    __STOPPED_CHECK__","\n".join("    "+l for l in V1["STOPPED_CHECK"].splitlines())),4)}
for name,s in generated.items():
    ast.parse(s);compile(s,"<generated-"+name+">","exec")
    check("actual_generated_script_compiles_"+name,True,bytes=len(s.encode()),sha256=hashlib.sha256(s.encode()).hexdigest())
for bad in (True,0,-1,float("inf"),61):
    check("generated_process_invalid_allocation_"+str(bad),refused(V1["bounded_native_process_script"],bad))
# Request intent/response behavior of unchanged-default adapter and parent refusal.
def instance(V,Q,K,trace):
    x=V["NativeRun"]()
    x.context="ctx";x.root_token="synthetic";x.unseal_key="synthetic-key";x.stage="test";x.run_id="synthetic"
    x.started=set();x.path="history";x.history={1:"a",2:"b"};x.retired={};x.acknowledged={}
    class Recovery:
        def begin(self,*a,**k):trace.append(("intent",a,k));return 1
        def outcome(self,*a,**k):trace.append(("outcome",a,k))
    x.recovery=Recovery();x.event=lambda *a,**k:trace.append(("event",a,k))
    Q.api=lambda *a,**k:(trace.append(("api",a,k)) or (200,{"ok":True}))
    return x
R0=[];R1=[];X0=instance(V0,Q0,K0,R0);X1=instance(V1,Q1,K1,R1)
for method in ("GET","POST"):
    R0.clear();R1.clear()
    check("native_request_none_"+method,X0.request(N,method,"synthetic",{"x":1})==X1.request(N,method,"synthetic",{"x":1}) and norm(R0)==norm(R1))
R1.clear()
check("native_expired_before_intent_or_api",refused(X1.request,N,"POST","synthetic",{"x":1},parent_deadline=99) and R1==[])
R1.clear();X1.request(N,"POST","synthetic",{"x":1},parent_deadline=103)
check("native_request_intent_cap_is_remaining",R1[0][0]=="intent" and R1[0][2]["timeout"]==3 and next(r for r in R1 if r[0]=="api")[2]["timeout"]==3)
# Parent None is carried only as an opt-in value; original externally visible routes/results remain exact.
def read_helpers(V):
    x=V["NativeRun"]();trace=[];x.path="history";x.history={1:"a",2:"b"};x.retired={}
    x.request=lambda *a,**k:(trace.append((a,k)) or (200,{"data":{"current_version":2,"versions":{"1":{},"2":{}}}}))
    return x,trace
Y0,L0=read_helpers(V0);Y1,L1=read_helpers(V1)
check("read_data_none_route_exact",Y0.read_data(N,"history",version=2)==Y1.read_data(N,"history",version=2) and norm(L0)==norm(L1))
L0.clear();L1.clear()
check("metadata_none_result_exact",Y0.metadata(N)==Y1.metadata(N) and norm(L0)==norm(L1))
# Foreground selected methods: no actual subprocess, file or signal.
Fclass={"ForegroundSession":("_send","start")}
def foreground_env(s):
    clock=Clock();writes=[];ns={"time":clock,"STOP_SECONDS":5.0,"START_SECONDS":60.0,"Refusal":Refusal,
      "canonical":lambda v:(json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode(),
      "need":lambda v,c:None if v else (_ for _ in ()).throw(Refusal(c)),
      "os":types.SimpleNamespace(write=lambda fd,raw:(writes.append((fd,raw)) or len(raw))),
      "require_waitid":lambda:(_ for _ in ()).throw(AssertionError("waitid must not be reached"))}
    selected(s,ns,classes=Fclass);return ns,clock,writes
F0,FC0,FW0=foreground_env(old[names[3]]);F1,FC1,FW1=foreground_env(new[names[3]])
def foreground_obj(ns):
    x=ns["ForegroundSession"].__new__(ns["ForegroundSession"])
    x._send_lock=contextlib.nullcontext();x._heartbeat=True;x.kill_sent=False;x.launch_id="synthetic"
    x.child=types.SimpleNamespace(stdin=types.SimpleNamespace(fileno=lambda:99));return x
Z0=foreground_obj(F0);Z1=foreground_obj(F1);Z0._send("kill");Z1._send("kill")
check("foreground_none_exact_command",FW0==FW1 and Z0.kill_sent==Z1.kill_sent)
Z1=foreground_obj(F1);FW1.clear()
check("foreground_expired_no_channel_write",refused(Z1._send,"kill",parent_deadline=99) and FW1==[])
Z1.child=None;Z1.receipt={"submission_count":0}
check("foreground_expired_start_before_waitid_or_child",refused(Z1.start,parent_deadline=99))
# New cipher reader: closed reference and all operations use synthetic OS tables.
clock=Clock();ns={"time":clock,"json":json,"hashlib":hashlib,"stat":stat,"re":re}
assign=("ROOT","UID","COMMIT","TREE","MAX_REFERENCE","MAX_OUTPUT","MAX_LEAVES","MAX_LEAF","MAX_TOTAL","MAX_SECONDS","IDENTITY_KEYS","LEAF","HEX")
selected(reader,ns,functions=("Refused","need","within","no_duplicate","reject_constant","canonical","identity","parse_reference","execute"),assignments=assign)
class FakePath:
    def __init__(self,s):self.s=s
    def resolve(self,strict=False):return self
    def __eq__(self,other):return isinstance(other,FakePath) and self.s==other.s
    def __str__(self):return self.s
ns["Path"]=FakePath
leaf="v6-"+"a"*64+".blob";extra="v6-"+"b"*64+".blob";root=ns["ROOT"]
def fact(ino,mode,data=b"",directory=False):
    return types.SimpleNamespace(st_dev=1,st_ino=ino,st_uid=501,st_mode=(stat.S_IFDIR if directory else stat.S_IFREG)|mode,st_nlink=1,st_size=len(data),st_mtime_ns=100000000001,st_ctime_ns=100000000002)
def filesystem():
    marker=json.dumps({"run_id":"fresh","root":root,"production_authority":False,"root_device":1,"root_inode":10}).encode()
    rows={root:(fact(10,0o700,directory=True),b""),root+"/raft":(fact(11,0o700,directory=True),b""),root+"/raft/native-v6-ciphertext":(fact(12,0o700,directory=True),b""),root+"/native-ha-fixture.json":(fact(13,0o600,marker),marker),root+"/raft/native-v6-ciphertext/"+leaf:(fact(14,0o600,b"abc"),b"abc"),root+"/raft/native-v6-ciphertext/"+extra:(fact(15,0o600,b"xyz"),b"xyz")}
    return rows
class FakeOS:
    O_RDONLY=0;O_NOFOLLOW=1;O_DIRECTORY=2;O_NONBLOCK=4
    def __init__(self,rows):self.rows=rows;self.fds={};self.next=100;self.opened=[];self.closed=[];self.stats={};self.rename_raft=False;self.close_fail=None
    def geteuid(self):return 501
    def path(self,name,parent):return name if parent is None else self.fds[parent][0]+"/"+name
    def stat(self,name,dir_fd=None,follow_symlinks=False):
        assert follow_symlinks is False
        p=self.path(name,dir_fd);self.stats[p]=self.stats.get(p,0)+1
        if p not in self.rows:raise FileNotFoundError(p)
        v=self.rows[p][0]
        if self.rename_raft and p==root+"/raft" and self.stats[p]>=3:
            v=copy.copy(v);v.st_ino+=100
        return v
    def open(self,name,flags,dir_fd=None):
        assert flags & self.O_NOFOLLOW
        p=self.path(name,dir_fd)
        if p not in self.rows:raise FileNotFoundError(p)
        self.next+=1;self.fds[self.next]=[p,0];self.opened.append(p);return self.next
    def fstat(self,fd):return self.rows[self.fds[fd][0]][0]
    def read(self,fd,n):
        p,pos=self.fds[fd];raw=self.rows[p][1][pos:pos+n];self.fds[fd][1]+=len(raw);return raw
    def close(self,fd):
        self.closed.append(fd)
        if self.close_fail==fd:raise OSError("synthetic close")
        del self.fds[fd]
rows=filesystem()
value={"schema":"heptabao.postrecovery-captured-cipher-reference.v1","fixture_run_id":"fresh","source_commit":ns["COMMIT"],"source_tree":ns["TREE"],"node_id":1,"root":root,"captured_from_same_recovered_scan":True,"inventory_sha256":"c"*64,"restored_count":1,"restored_bytes":3,
 "directories":[{"name":name,"identity":ns["identity"](rows[p][0])} for name,p in ((root,root),("raft",root+"/raft"),("native-v6-ciphertext",root+"/raft/native-v6-ciphertext"))],
 "leaves":{leaf:{"sha256":hashlib.sha256(b"abc").hexdigest(),"bytes":3,"identity":ns["identity"](rows[root+"/raft/native-v6-ciphertext/"+leaf][0])}}}
raw=ns["canonical"](value)
check("captured_reference_schema_positive",ns["parse_reference"](raw,"fresh",hashlib.sha256(raw).hexdigest())==value)
for label,modify in (("wrong_run",lambda v:v.update(fixture_run_id="old")),("empty_set",lambda v:v.update(leaves={},restored_count=0,restored_bytes=0)),("wrong_source",lambda v:v.update(source_commit="0"*40)),("missing_scan_binding",lambda v:v.update(captured_from_same_recovered_scan=False)),("bad_leaf_mode",lambda v:v["leaves"][leaf]["identity"].update(mode=0o644))):
    v=copy.deepcopy(value);modify(v);r=ns["canonical"](v)
    try:ns["parse_reference"](r,"fresh",hashlib.sha256(r).hexdigest());raise AssertionError(label)
    except ns["Refused"]:check("captured_reference_refuses_"+label,True)
fake=FakeOS(filesystem());ns["os"]=fake
result=ns["execute"](value,"fresh",115)
check("same_captured_leaf_identity_and_hash",result["all_captured_leaves_match"] and result["actual_reference_count"]==1 and result["actual_reference_bytes"]==3)
check("unreferenced_leaf_never_opened",not any(p.endswith(extra) for p in fake.opened))
check("reader_all_synthetic_fds_closed",fake.fds=={})
for label,change in (("changed_leaf_inode",lambda f:setattr(f.rows[root+"/raft/native-v6-ciphertext/"+leaf][0],"st_ino",55)),("changed_leaf_bytes_same_length",lambda f:f.rows.__setitem__(root+"/raft/native-v6-ciphertext/"+leaf,(f.rows[root+"/raft/native-v6-ciphertext/"+leaf][0],b"abd"))),("missing_leaf",lambda f:f.rows.pop(root+"/raft/native-v6-ciphertext/"+leaf)),("renamed_held_raft",lambda f:setattr(f,"rename_raft",True))):
    fake=FakeOS(filesystem());change(fake);ns["os"]=fake
    try:ns["execute"](value,"fresh",115);raise AssertionError(label)
    except (ns["Refused"],FileNotFoundError):check("fixed_reader_refuses_"+label,True)
    check("fixed_reader_failure_closes_fds_"+label,fake.fds=={})
fake=FakeOS(filesystem());ns["os"]=fake
try:ns["execute"](value,"fresh",99);raise AssertionError("expired")
except ns["Refused"]:check("fixed_reader_expired_before_open",fake.opened==[] and fake.fds=={})
print(json.dumps({"schema":"heptabao.postrecovery-cold-source-components.v1","source_tree":"e9a5f1f673f18a4d2b7162f4188a6bbc221e29ac","scope":"AST-selected actual functions with synthetic child, HTTP, clock and filesystem adapters; no product or remote helper executed","sources":SOURCES,"checks":CHECKS,"passed":len(CHECKS),"failed":0,"physical_host_access":False,"real_child_processes":0,"real_network_requests":0,"real_product_operations":0},sort_keys=True))
