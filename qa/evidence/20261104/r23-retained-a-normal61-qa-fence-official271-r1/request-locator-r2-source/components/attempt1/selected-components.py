import ast
import hashlib
import json
import re
import stat
import sys
import types

data = json.load(sys.stdin)
before = data["before"]
after = data["after"]
ast.parse(before)
ast.parse(after)
compile(after, "candidate-r2.py", "exec")
results = []
def check(name, value):
    if not value:
        raise AssertionError(name)
    results.append({"case": name, "passed": True})

def audit(event, args):
    if event in ("open", "os.listdir", "os.scandir", "os.remove", "os.rename",
                 "os.mkdir", "os.rmdir", "subprocess.Popen", "os.system",
                 "socket.__new__", "socket.connect", "socket.bind"):
        raise RuntimeError("candidate_real_io_forbidden")
sys.addaudithook(audit)

class Clock:
    def __init__(self):
        self.value = 0
        self.wall = 1793868000000
    def monotonic_ns(self):
        return self.value
    def time_ns(self):
        return self.wall * 1000000

class FakeIterator:
    def __init__(self, names=(), error=False):
        self.names = iter(names)
        self.closes = 0
        self.error = error
    def __iter__(self):
        return self
    def __next__(self):
        return types.SimpleNamespace(name=next(self.names))
    def close(self):
        self.closes += 1
        if self.error:
            raise OSError(5, "synthetic-no-dynamic-export")
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        self.close()

def info(kind, ino, size):
    return types.SimpleNamespace(
        st_dev=1, st_ino=ino, st_uid=1000, st_gid=1000,
        st_mode=kind, st_nlink=1, st_size=size,
        st_mtime_ns=1, st_ctime_ns=1)

class FakeOS:
    O_RDONLY=0
    O_DIRECTORY=1
    O_NOFOLLOW=2
    O_CLOEXEC=4
    def __init__(self, clock, raw=b'{"x":1}', tail=b"", names=()):
        self.clock=clock
        self.raw=raw
        self.tail=tail
        self.declared_size=len(raw)
        self.nextfd=10
        self.fds={}
        self.opened=[]
        self.close_calls=[]
        self.read_calls=[]
        self.close_errors=set()
        self.open_error=False
        self.on_read=None
        self.iterator=FakeIterator(names)
        self.directory=info(stat.S_IFDIR|0o700, 3, 1)
    def geteuid(self):
        return 1000
    def open(self, path, flags, dir_fd=None):
        if self.open_error:
            raise OSError(13, "synthetic")
        fd=self.nextfd
        self.nextfd+=1
        self.fds[fd]={"path":path, "offset":0,
            "stat": info(stat.S_IFREG|0o600, 7, self.declared_size)
            if path=="request.json" else self.directory}
        self.opened.append((fd,path))
        return fd
    def stat(self, name, dir_fd=None, follow_symlinks=False):
        if name=="request.json":
            return info(stat.S_IFREG|0o600, 7, self.declared_size)
        return self.directory
    def fstat(self, fd):
        return self.fds[fd]["stat"]
    def read(self, fd, amount):
        self.read_calls.append((fd,amount))
        record=self.fds[fd]
        raw=self.raw+self.tail
        offset=record["offset"]
        out=raw[offset:offset+amount]
        record["offset"]+=len(out)
        if self.on_read is not None:
            hook=self.on_read
            self.on_read=None
            hook()
        return out
    def close(self, fd):
        self.close_calls.append(fd)
        if fd in self.close_errors:
            raise OSError(5, "synthetic")
        self.fds.pop(fd)
    def scandir(self, _fd):
        return self.iterator
    @staticmethod
    def fsencode(value):
        return value.encode("utf-8")

allowed_defs={"Refused","need","sha","encode","full_identity",
 "directory_identity","canonical_job_time","strict_json","equal_typed",
 "verify_request","Cancelled","Signals","protected_call","public_errno",
 "Reader","main"}
def build(source, osfake, clock, name):
    tree=ast.parse(source)
    constants={}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    try:
                        constants[target.id]=ast.literal_eval(node.value)
                    except (ValueError,TypeError):
                        pass
    cfg_node=next(n for n in tree.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id=="CONFIGS" for t in n.targets))
    constants["CONFIGS"]=json.loads(ast.literal_eval(cfg_node.value.args[0]))
    constants["JOB_NAME"]=re.compile(r"([0-9a-f]{1,32})-([0-9a-f]{1,8})-([0-9a-f]{1,16})\Z")
    globals_={"hashlib":hashlib,"json":json,"re":re,"stat":stat,
        "os":osfake,"time":clock,"sys":types.SimpleNamespace(),
        "signal":types.SimpleNamespace(SIGTERM=15,SIGINT=2,
             signal=lambda *_args: None), **constants}
    selected=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))
              and n.name in allowed_defs]
    exec(compile(ast.Module(body=selected,type_ignores=[]),name,"exec"),globals_)
    return globals_,tree

def r2(raw=b'{"x":1}',tail=b"",names=()):
    clock=Clock()
    osfake=FakeOS(clock,raw,tail,names)
    g,t=build(after,osfake,clock,"candidate-r2.py")
    signals=g["Signals"]()
    reader=g["Reader"](0,signals)
    return g,reader,osfake,clock,signals,t

def expect_error(g, fn, code):
    try:
        fn()
    except g["Refused"] as e:
        check(code,e.code==code)
    else:
        raise AssertionError(code+"_not_refused")

job="1a1aaa6db3e-fc05-45a6"
clock=Clock(); oldos=FakeOS(clock)
old,_=build(before,oldos,clock,"before-r1.py")
oldreader=old["Reader"](0)
fired=[False]
def old_trace(frame,event,arg):
    if event=="call" and frame.f_code.co_name=="register" and not fired[0]:
        fired[0]=True
        raise KeyboardInterrupt()
    return old_trace
try:
    sys.settrace(old_trace)
    oldreader.open_fixed_ancestors()
except KeyboardInterrupt:
    pass
finally:
    sys.settrace(None)
    oldreader.close_all_once()
check("old_open_to_register_interrupt_reproduces_unregistered_fd",
      fired[0] and len(oldos.opened)==1 and oldos.close_calls==[]
      and len(oldreader.fds)==0)

g,r,o,c,s,t=r2()
row_line=next(n.lineno for n in ast.walk(t) if isinstance(n,ast.Assign)
    and any(isinstance(x,ast.Name) and x.id=="row" for x in n.targets)
    and isinstance(n.value,ast.Dict))
fired=[False]
def new_trace(frame,event,arg):
    if (event=="line" and frame.f_code.co_name=="open_fd"
            and frame.f_lineno==row_line and not fired[0]):
        fired[0]=True
        s.handler(2,None)
    return new_trace
try:
    sys.settrace(new_trace)
    r.open_fixed_ancestors()
except g["Cancelled"]:
    pass
finally:
    sys.settrace(None)
    r.close_all_once()
check("new_open_registration_signal_deferred_then_fd_closed_once",
      fired[0] and s.pending==2 and r.opened==r.closed==1
      and o.close_calls==[10] and not r.fds and not r.open_registration_unknown)

g,r,o,c,s,t=r2()
fd=r.open_fd("/",o.O_RDONLY,"ancestor")
close_line=next(n.lineno for n in ast.walk(t) if isinstance(n,ast.Expr)
    and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute)
    and isinstance(n.value.func.value,ast.Name)
    and n.value.func.value.id=="os" and n.value.func.attr=="close")
fired=[False]
def close_trace(frame,event,arg):
    if (event=="line" and frame.f_code.co_name=="close_once"
            and frame.f_lineno==close_line and not fired[0]):
        fired[0]=True
        s.handler(15,None)
    return close_trace
try:
    sys.settrace(close_trace); r.close_once(fd)
finally:
    sys.settrace(None); r.close_all_once()
check("close_attempt_marker_signal_does_not_skip_close",
      fired[0] and s.pending==15 and o.close_calls==[fd]
      and r.fd_rows[0]["closed"] and r.fd_rows[0]["close_attempted"])

g,r,o,c,s,t=r2()
a=r.open_fd("/",0,"ancestor"); b=r.open_fd("request.json",0,"candidate_request")
o.close_errors.add(a)
r.close_all_once(); r.close_all_once()
check("fd_close_failure_once_preserves_failed_row_and_closes_other",
      o.close_calls==[b,a] and r.closed==1 and r.close_failures==1
      and r.fd_rows[0]["close_attempted"] and not r.fd_rows[0]["closed"]
      and r.fd_rows[0]["close_errno"]==5 and not r.fds)

g,r,o,c,s,t=r2();o.open_error=True
try:
    r.open_fd("/",0,"ancestor")
except OSError:
    pass
r.close_all_once()
check("ordinary_open_refusal_has_no_registered_fd",
      r.opened==0 and not r.open_registration_unknown and not o.close_calls)

g,r,o,c,s,t=r2()
class BadMap(dict):
    def __setitem__(self,_key,_value):
        raise MemoryError("synthetic")
r.fds=BadMap()
try:
    r.open_fd("/",0,"ancestor")
except MemoryError:
    pass
r.close_all_once()
check("registration_failure_remains_explicit_unknown",
      len(o.opened)==1 and r.open_registration_unknown and r.opened==0)

g,r,o,c,s,t=r2()
r.total_request_bytes=g["MAX_TOTAL_REQUEST_BYTES"]-len(o.raw)
expect_error(g,lambda:r.read_request(900,job,"candidate"),
             "total_request_bytes_admission")
r.close_all_once()
check("aggregate_pre_admission_performs_no_request_open_or_read",
      o.opened==[(10,job)] and not o.read_calls and o.close_calls==[10])

g,r,o,c,s,t=r2()
r.total_request_bytes=g["MAX_TOTAL_REQUEST_BYTES"]-(len(o.raw)+1)
value,size,digest=r.read_request(900,job,"candidate")
r.close_all_once()
check("original_aggregate_budget_accepts_exact_reserved_remaining",
      value=={"x":1} and size==7 and r.total_request_bytes==g["MAX_TOTAL_REQUEST_BYTES"]-1
      and o.close_calls==[11,10] and r.closed==2)

g,r,o,c,s,t=r2(tail=b"x")
r.total_request_bytes=g["MAX_TOTAL_REQUEST_BYTES"]-8
expect_error(g,lambda:r.read_request(900,job,"candidate"),"request_trailing_bytes")
r.close_all_once()
check("returned_eof_probe_byte_counted_before_refusal",
      r.total_request_bytes==g["MAX_TOTAL_REQUEST_BYTES"]
      and o.close_calls==[11,10])

g,r,o,c,s,t=r2()
o.declared_size=g["MAX_REQUEST_BYTES"]
expect_error(g,lambda:r.read_request(900,job,"candidate"),"unsafe_request_file")
r.close_all_once()
check("single_request_cap_reserves_probe_without_any_payload_read",
      len(o.opened)==1 and not o.read_calls and r.total_request_bytes==0)

g,r,o,c,s,t=r2()
o.on_read=lambda:s.handler(2,None)
try:
    r.read_request(900,job,"candidate")
except g["Cancelled"]:
    pass
finally:
    r.close_all_once()
check("cancel_after_returned_chunk_counts_bytes_and_closes_both",
      r.total_request_bytes==7 and o.close_calls==[11,10] and r.closed==2)

g,r,o,c,s,t=r2()
o.iterator=FakeIterator([],error=True)
try:
    r.candidates(900,0,2**63)
except OSError:
    pass
r.close_all_once()
check("iterator_close_failure_is_once_and_not_closed",
      o.iterator.closes==1 and r.scandir_close_attempted
      and not r.scandir_closed and r.scandir_close_error["errno"]==5)

g,r,o,c,s,t=r2(names=[job])
line=next(n.lineno for n in ast.walk(t) if isinstance(n,ast.Assign)
    and any(isinstance(x,ast.Attribute) and x.attr=="scandir_created" for x in n.targets)
    and isinstance(n.value,ast.Constant) and n.value.value is True)
fired=[False]
def scan_trace(frame,event,arg):
    if (event=="line" and frame.f_code.co_name=="candidates"
            and frame.f_lineno==line and not fired[0]):
        fired[0]=True;s.handler(2,None)
    return scan_trace
try:
    sys.settrace(scan_trace)
    r.candidates(900,0,2**63)
except g["Cancelled"]:
    pass
finally:
    sys.settrace(None);r.close_all_once()
check("iterator_return_registration_cancel_closes_once",
      fired[0] and r.scandir_created and r.scandir_closed
      and o.iterator.closes==1)

g,r,o,c,s,t=r2(names=[job,job])
expect_error(g,lambda:r.candidates(900,0,2**63),"duplicate_candidate_name")
r.close_all_once()
check("duplicate_observed_candidate_does_not_duplicate_matches",
      o.iterator.closes==1 and r.scandir_closed)

old_name="1-1-1"; future_name="ffffffffffff-1-1"
g,r,o,c,s,t=r2(names=[old_name,job,future_name])
names,count,namebytes=r.candidates(900,1793864424254,1793868000000)
r.close_all_once()
check("single_window_excludes_old_and_future_without_opening_requests",
      names==[job] and count==3 and not o.opened and not o.read_calls)

def run_fake_main(mode):
    g,r,o,c,s,t=r2()
    source="public-source-only"
    digest=hashlib.sha256(source.encode()).hexdigest()
    fields={"executable":"/usr/bin/python3","cwd":"/owned",
       "env":{},"timeout_seconds":60,"nice":0,"cpu_quota_percent":None,
       "memory_max_bytes":None,"has_stdin":False,"args_count":1,
       "args_json_sha256":hashlib.sha256(b'["safe"]').hexdigest()}
    cfg={"host":"desktop","floor_unix_ms":1793864424254,
      "anchor_job_id":job,"anchor_digest":"a"*64,"anchor_fields":fields,
      "target_digest":"b"*64,"target_fields":fields}
    other="1a1aaa6db3f-fc05-45a7"
    class FakeReader:
        def __init__(self,start,signals):
            self.signals=signals;self.start=start;self.until=15000000000
            self.fds={};self.fd_rows=[];self.open_registration_unknown=False
            self.close_failures=0;self.opened=0;self.closed=0
            self.scandir_closed=True;self.scandir_created=True
            self.scandir_open_unknown=False;self.scandir_close_attempted=True
            self.scandir_close_error=None
            self.request_files_read=0;self.total_request_bytes=0
        def open_fixed_ancestors(self): return 900
        def read_request(self,_fd,name,_role):
            self.request_files_read+=1
            if name==job:
                return ({"job_id":job,"job_dir":g["JOBS_PATH"]+"/"+job,
                 "unit":"hepta-runtime-job-"+job,"request_digest":"a"*64,
                 "request_fingerprint":"a"*64,"args":["safe"],
                 **{k:fields[k] for k in ("executable","cwd","env","timeout_seconds",
                      "nice","cpu_quota_percent","memory_max_bytes")}},101,"c"*64)
            return ({"request_digest":"d"*64,"args":["synthetic-private-argv-canary"]},
                    100,"e"*64)
        def candidates(self,*_args): return [job,other],2,20
        def verify_ancestors(self): pass
        def remaining(self): pass
        def close_all_once(self):
            if mode=="closure_failure":
                self.scandir_closed=False
                self.scandir_close_error={"code":"scandir_close_not_confirmed",
                                          "errno":5}
            if mode=="late_close": c.value=15000000001
            if mode=="pending_close": self.signals.pending=2
    output=[]
    def fake_print(value,**_kwargs):
        output.append(value)
        if mode=="late_flush": c.value=15000000001
    g.update(Reader=FakeReader,CONFIGS={"desktop-fence":cfg},
      sys=types.SimpleNamespace(argv=["-c","--scope","desktop-fence",
                                    "--self-sha256",digest],
          orig_argv=["python","-I","-S","-B","-c",source]),
      print=fake_print)
    code=g["main"]()
    return code,json.loads(output[0]),output[0]

code,report,raw=run_fake_main("normal")
check("actual_main_hides_nonmatching_argv_and_preserves_no_replay",
      code==0 and report["status"]=="bounded_read_completed"
      and "synthetic-private-argv-canary" not in raw
      and report["replay_authorized"] is False
      and report["absence_proven"] is False)
code,report,raw=run_fake_main("closure_failure")
check("actual_main_iterator_closure_failure_prevents_green",
      code==1 and report["status"]=="failed"
      and report["all_registered_resources_closed"] is False)
code,report,raw=run_fake_main("late_close")
check("actual_main_original_deadline_includes_cleanup",
      code==1 and report["status"]=="failed"
      and report["within_original_deadline_after_closure"] is False)
code,report,raw=run_fake_main("pending_close")
check("actual_main_cancel_during_cleanup_prevents_green",
      code==1 and report["status"]=="failed" and report["cancel_signal"]==2)
code,report,raw=run_fake_main("late_flush")
check("actual_main_postflush_deadline_rejects_candidate_success",
      code==1 and report["status"]=="bounded_read_completed")

result={"schema":"heptabao.bounded-job-locator.selected-offline-components.r2",
 "status":"passed","checks":results,"count":len(results),
 "candidateSha256":hashlib.sha256(after.encode()).hexdigest(),
 "baseSha256":hashlib.sha256(before.encode()).hexdigest(),
 "scope":{"astSelectedDefinitionsOnly":True,"completeCandidateModuleExecuted":False,
   "realCandidateFileDescriptors":0,"realSignals":0,"realDirectoryScan":0,
   "targetHostCalls":0,"childOrNetworkCalls":0,"old30ComponentsRepeated":False,
   "sysSettraceUsedOnlyForSyntheticInterruptionBoundaries":True}}
print(json.dumps(result,sort_keys=True,indent=2))
