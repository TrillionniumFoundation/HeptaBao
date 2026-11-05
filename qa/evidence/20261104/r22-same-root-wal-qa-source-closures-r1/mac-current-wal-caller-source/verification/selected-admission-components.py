import ast,copy,hashlib,json,math,sys
from pathlib import Path
v=json.load(sys.stdin)
tree=ast.parse(v["entry"],filename="mac_current_capture_entry_wal_r1.py")
names={"Refused","need","sha","encoded","admitted_wal","library_resources_closed","capture_envelope"}
constants={"ROOT","CAPTURE_SOURCE_SHA","NATIVE_BINDING","WAL_BINDING"}
nodes=[]
for node in tree.body:
    if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in names:nodes.append(node)
    elif isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in constants:nodes.append(node)
scope={"json":json,"math":math,"hashlib":hashlib,"Path":Path}
exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),"selected-current-wal-admission","exec"),scope)
checks=[]
def check(name,value):
    assert value,name
    checks.append({"name":name,"passed":True})
class MemoryGuard:
    def __init__(self):self.reads=[];self.checked=0
    def read(self,path,maximum):
        relative=str(path.relative_to(scope["ROOT"]))
        values={"proofs/registry-wal-r1.stdout.public.json":v["proof"].encode(),
                "proofs/registry-wal-r1.authority.public.json":v["authority"].encode()}
        raw=values[relative];assert len(raw)<=maximum
        self.reads.append(relative);return raw
    def check(self):self.checked+=1
guard=MemoryGuard()
raw,proof=scope["admitted_wal"](guard,scope["WAL_BINDING"])
check("actual_public_stdout_authority_exact_admitted",raw==v["proof"].encode() and proof["ok"] is True and guard.checked==1 and len(guard.reads)==2)
library=v["attempt"]
check("actual_closed_library_record_accepted",scope["library_resources_closed"](library) is True)
missing=copy.deepcopy(library);missing.pop("connections")
check("missing_connection_ledger_refused",scope["library_resources_closed"](missing) is False)
broken=copy.deepcopy(library);broken["connections"][0]["closed"]=False
check("one_unclosed_connection_refused_even_if_aggregate_flag_true",scope["library_resources_closed"](broken) is False)
broken=copy.deepcopy(library);broken["publicCodeDescriptors"][0]["closed"]=False
check("one_unclosed_public_code_fd_refused_even_if_aggregate_flag_true",scope["library_resources_closed"](broken) is False)
envelope=copy.deepcopy(library)
envelope.update(libraryFailureLedgerAvailable=True,originalFiveAgentRouteUnchanged=True,
                privateResultPublished=False,ok=True,observationComplete=True,
                observationUnknown=False,originalDeadlineMetAfterClosure=True,error=None)
check("well_typed_success_envelope_accepted",scope["capture_envelope"](envelope) is envelope)
bad=copy.deepcopy(envelope);bad["observationUnknown"]=True
try:scope["capture_envelope"](bad)
except scope["Refused"]:pass
else:raise AssertionError("success with unknown accepted")
check("success_unknown_contradiction_refused",True)
failed=copy.deepcopy(envelope)
failed.update(ok=False,observationComplete=False,observationUnknown=True,error={"code":"synthetic_component_failure"})
check("failure_envelope_retained_without_reclassifying_success",scope["capture_envelope"](failed) is failed)
print(json.dumps({"schema":"heptabao.mac-current-wal-selected-admission-components.r1",
 "passed":len(checks),"checks":checks,"scope":"AST-selected functions, public actual proof and memory guards only",
 "whole_module_imported":False,"candidate_file_io":0,"sqlite_calls":0,"children":0,"network":0,
 "current_or_private_inputs_read":False,"library_four_ledger_tests_repeated":False},sort_keys=True))
