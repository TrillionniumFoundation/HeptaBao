import ast,base64,hashlib,json,stat,types
d=json.loads(base64.b64decode(PAYLOAD))
tree=ast.parse(d["source"]); lines=d["source"].splitlines()
checks=[]
def record(name,passed):
    assert passed,name
    checks.append({"name":name,"passed":True})
ns={"hashlib":hashlib,"base64":base64,"COMMIT":"df026fe323dd7cf0f0ec57d7d2d9c5a79897053c","OLD_COMMIT":"49503322c7f446e5eb41e7744f1fdbd7f1192ecc"}
for name in ("digest","canonical_bundle_header"):
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name)
    exec(compile(ast.Module(body=[node],type_ignores=[]),name,"exec"),ns)
start=next(i for i,x in enumerate(lines,1) if x=="assert isinstance(data['canonical_bundle_base64'], str)")
end=next(i for i,x in enumerate(lines,1) if x=="canonical_header = canonical_bundle_header(canonical_raw)")
selected=[n for n in tree.body if start<=n.lineno<=end]
entry=compile(ast.Module(body=selected,type_ignores=[]),"actual_bundle_entry","exec")
expected_sha="5e5e662ad369f3f94bdb0a844507d0305ebd0b4a661845c16be50475a4df16e2"
raw=base64.b64decode(d["bundle"],validate=True)
assert len(raw)==24337 and hashlib.sha256(raw).hexdigest()==expected_sha
def validate(name,encoded,size=24337,sha=expected_sha,expected=True):
    x=dict(ns,data={"canonical_bundle_base64":encoded},args=types.SimpleNamespace(canonical_bundle_bytes=size,canonical_bundle_sha256=sha))
    ok=True
    try: exec(entry,x)
    except (AssertionError,TypeError,ValueError): ok=False
    record(name,ok==expected)
    return x
v=validate("actual_bundle_entry_accepts_exact_export",d["bundle"])
validate("entry_rejects_non_text",None,expected=False)
validate("entry_rejects_invalid_base64","!!!!",expected=False)
validate("entry_rejects_one_byte_change",base64.b64encode(raw[:-1]+bytes([raw[-1]^1])).decode(),expected=False)
validate("entry_rejects_wrong_declared_size",d["bundle"],size=24338,expected=False)
validate("entry_rejects_wrong_declared_sha",d["bundle"],sha="0"*64,expected=False)
trynode=next(n for n in tree.body if isinstance(n,ast.Try) and any(isinstance(q,ast.Assign) and any(isinstance(t,ast.Subscript) and isinstance(t.slice,ast.Constant) and t.slice.value=="external_volume_uuid" for t in q.targets) for q in n.body))
cut=next(i for i,n in enumerate(trynode.body) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and isinstance(n.value.func.value,ast.Name) and n.value.func.value.id=="ROOT" and n.value.func.attr=="mkdir")
prefix=compile(ast.Module(body=trynode.body[:cut],type_ignores=[]),"actual_guard_then_bundle_prefix","exec")
class File:
    def lstat(self):
        trace.append("lstat")
        return types.SimpleNamespace(st_mode=0o100644 if failure=="mode" else 0o100600)
class Parent:
    def __truediv__(self,name):
        assert name=="canonical-cold-h2-df026-from495.bundle"
        return fixed_file
fixed_file=File(); parent=Parent()
def trial(name,fail=None,expected=True):
    global trace,failure
    trace=[];failure=fail;calls={"clock":0}
    def remaining():
        calls["clock"]+=1;trace.append("remaining")
        if fail=="expired_before_guard" and calls["clock"]==1: raise AssertionError("expired")
        if fail=="expired_after_guard" and calls["clock"]==2: raise AssertionError("expired")
        return 300
    def guard():
        trace.append("guard")
        if fail=="guard": raise OSError("guard")
        return "FB804D1B-24CB-4D6E-AEA7-A9E180807758"
    def exists(path):
        assert path is fixed_file;trace.append("lexists");return fail=="exists"
    def create(path,content):
        assert path is fixed_file and content==raw;trace.append("create")
        if fail=="create": raise FileExistsError()
    def sync(path):
        assert path is parent;trace.append("fsync")
        if fail=="fsync": raise OSError("fsync")
    def read(path,limit,size,sha):
        assert path is fixed_file and limit==4*1024*1024 and size==len(raw) and sha==expected_sha
        trace.append("stable_read")
        return b"drift" if fail=="readback" else raw
    x=dict(v,stage_remaining=remaining,prewrite_volume_guard=guard,ROOT=types.SimpleNamespace(parent=parent),
           os=types.SimpleNamespace(path=types.SimpleNamespace(lexists=exists)),create=create,fsync_dir=sync,stable_read=read,
           identity=lambda i:(i.st_mode,),stat=stat,result={})
    ok=True
    try: exec(prefix,x)
    except (AssertionError,OSError): ok=False
    record(name,ok==expected)
    if fail in ("guard","expired_before_guard","expired_after_guard","exists"):
        record(name+"_no_write","create" not in trace)
    if expected:
        record("guard_precedes_create_and_fsync_readback",trace.index("guard")<trace.index("create")<trace.index("fsync")<trace.index("stable_read"))
        record("publication_field_only_after_verified_readback",x["result"].get("canonical_bundle_published_after_volume_guard") is True)
    else:
        record(name+"_no_verified_publication",x["result"].get("canonical_bundle_published_after_volume_guard") is not True)
trial("actual_prefix_accepts_exact_owned_bundle")
trial("uuid_guard_failure_stops_before_write","guard",False)
trial("expired_entry_stops_before_guard","expired_before_guard",False)
trial("expired_after_guard_stops_before_write","expired_after_guard",False)
trial("existing_fixed_destination_refused","exists",False)
trial("exclusive_create_failure_refused","create",False)
trial("parent_fsync_failure_refused","fsync",False)
trial("full_readback_mismatch_refused","readback",False)
trial("mode_mismatch_refused","mode",False)
print(json.dumps({"schema":"heptabao.mac-source-inband-bundle-pure-components.v1","status":"passed","source_sha256":hashlib.sha256(d["source"].encode()).hexdigest(),"checks":checks,"checks_passed":len(checks),"actual_selected_ast":True,"actual_bundle_bytes":len(raw),"host_io":0,"actual_sockets":0,"actual_filesystem_writes":0,"actual_children":0,"whole_module_executed":False,"guard_and_filesystem_mocks":True},sort_keys=True))
