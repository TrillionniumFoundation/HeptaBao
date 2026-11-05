import ast, hashlib, json
from pathlib import Path
source=fixture["source"]
tree=ast.parse(source)
names={"BindingError","Cancelled","Signals","need","remaining","read_cargo_binary"}
nodes=[x for x in tree.body if isinstance(x,(ast.FunctionDef,ast.ClassDef)) and x.name in names]
class FakeTime:
    def monotonic_ns(self): return 10
owner_calls=[]
def original_owner(signum,frame):
    owner_calls.append(signum)
    raise RuntimeError("synthetic owner cancellation")
class FakeSignal:
    SIGTERM=15
    SIGINT=2
    def __init__(self):
        self.handlers={15:original_owner,2:original_owner}
        self.injected=False
    def getsignal(self,n): return self.handlers[n]
    def signal(self,n,handler):
        if handler is original_owner and not self.injected:
            self.injected=True
            self.handlers[n](n,None)
        old=self.handlers[n]
        self.handlers[n]=handler
        return old
signal=FakeSignal()
readers=[]
class FakeReader:
    def __init__(self,target,target_pin,maximum,until,signals):
        self.signals=signals
        self.summary={"sha256":"synthetic-only"}
        self.fd_rows=[]
        self.opened=0
        self.closed=0
        self.fds={}
        self.close_failures=0
        self.open_registration_unknown=False
        self.scandir_open_unknown=False
        self.scandir_created=False
        self.scandir_close_attempted=False
        self.scandir_closed=False
        self.scandir_close_error=None
        self.body_bytes_read=0
        self.eof_probe_calls=0
        self.eof_bytes_read=0
        self.bytes_read=0
        self.cleanup_calls=0
        readers.append(self)
    def inspect(self): return (b"synthetic bytes", {"sha256":"synthetic-only"})
    def close_all_once(self): self.cleanup_calls+=1
    def closures_proven(self): return True
ns={"signal":signal,"time":FakeTime(),"CargoBinaryRead":FakeReader,
    "FD_CLOSE_FAILED":False,"fixed_error":lambda x:type(x).__name__}
exec(compile(ast.Module(body=nodes,type_ignores=[]),"selected-actual-read-cargo-binary.py","exec"),ns)
report={}
target=Path("/synthetic-owned-target")
output=ns["read_cargo_binary"](target/"release"/"heptabao-native-h2-qa",
                              target,{},1,100,report)
assert signal.injected and len(readers)==1
assert readers[0].signals.pending==15 and readers[0].cleanup_calls==1
assert report["status"]=="observed_two_aliases" and report["cancel_signal"] is None
assert output is not None and owner_calls==[]
assert all(v is original_owner for v in signal.handlers.values())
print(json.dumps({"schema":"heptabao.qa-reader-pending-signal-counterexample.v1",
 "source_sha256":hashlib.sha256(source.encode()).hexdigest(),
 "counterexample_reproduced":True,
 "injected_point":"fake signal.signal restoring first original handler, after final report pending check",
 "actual_temporary_handler_pending":readers[0].signals.pending,
 "report_cancel_signal":report["cancel_signal"],
 "report_status":report["status"],
 "returned_output_after_cancel":output is not None,
 "old_owner_handler_calls":len(owner_calls),
 "old_handlers_restored":True,
 "fake_cleanup_calls":readers[0].cleanup_calls,
 "actual_signals":0,"actual_fds":0,"actual_children":0,"actual_host_calls":0,
 "full_module_executed":False},indent=2,sort_keys=True))
