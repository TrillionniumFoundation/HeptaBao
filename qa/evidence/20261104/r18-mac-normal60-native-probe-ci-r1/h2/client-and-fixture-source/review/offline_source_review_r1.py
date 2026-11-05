import ast,hashlib,json,pathlib,tomllib,difflib
root=pathlib.Path("/workspace/scratch/f86faac821c4/native-h2-qa-review-r1")
result={"scope":"offline source parse and selected pure lock-subset components","product_main_executed":False,"cargo_executed":False,"network_or_child_component_calls":0}
for path in sorted((root/"candidate").glob("*.py")):
    raw=path.read_bytes(); tree=ast.parse(raw,str(path)); compile(tree,str(path),"exec")
    result.setdefault("python",[]).append({"file":path.name,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"ast":True,"compile_only":True})
binder=(root/"candidate/native_h2_binding_r1.py").read_text()
module=ast.parse(binder)
selection=[node for node in module.body if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in {"BindingError","need","sha","lock_subset"}]
ns={"hashlib":hashlib,"tomllib":tomllib,"re":__import__("re")}
exec(compile(ast.Module(body=selection,type_ignores=[]),"<selected pure functions>","exec"),ns)
canonical=(root/"reference/canonical.Cargo.lock").read_bytes()
source=tomllib.loads(canonical.decode())
packages=[p for p in source["package"] if p["name"] in ("bytes","h2") and "checksum" in p]
assert len(packages)==2
def encoded(items,version=None,extra=""):
    s="version = "+str(source["version"] if version is None else version)+"\n"+extra
    for item in items:
        s+="\n[[package]]\n"
        for key,value in item.items():
            s+=key+" = "+json.dumps(value)+"\n"
    return s.encode()
own={"name":"heptabao-native-h2-qa","version":"0.1.0","dependencies":["bytes","h2"]}
minimal=[{k:v for k,v in p.items() if k in ("name","version","source","checksum")} for p in packages]
good=[own,*minimal]
positive=ns["lock_subset"](encoded(good),canonical)
assert positive["exact_version_source_checksum_subset"] and positive["registry_package_count"]==2
tests=[{"name":"exact_real_canonical_registry_subset","passed":True}]
def bad(name,items=None,raw=None):
    try: ns["lock_subset"](encoded(items) if raw is None else raw,canonical)
    except (ns["BindingError"],tomllib.TOMLDecodeError): tests.append({"name":name,"passed":True})
    else: raise AssertionError(name)
def change(index,**kw):
    copy=[dict(p) for p in good];copy[index].update(kw);return copy
bad("version_not_canonical",change(1,version="999.0.0"))
bad("wrong_checksum",change(1,checksum="0"*64))
bad("foreign_registry",change(1,source="registry+https://example.invalid/index"))
bad("duplicate_package",good+[minimal[0]])
bad("unchecksummed_path_package",good+[{"name":"foreign","version":"0.1.0"}])
bad("two_owned_qa_packages",good+[own])
bad("foreign_package_field",change(1,replace="foreign"))
bad("non_string_dependency",change(0,dependencies=[7]))
bad("unknown_top_level",raw=encoded(good,extra='foreign = "value"\n'))
bad("only_owned_root",[own])
bad("wrong_owned_package_version",change(0,version="0.2.0"))
result["selected_pure_lock_subset_components"]=tests
result["component_count"]=len(tests)
def defs(source):
    tree=ast.parse(source);out={}
    def scan(nodes,prefix=""):
        for n in nodes:
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                key=prefix+n.name
                out[key]=ast.get_source_segment(source,n)
                scan(n.body,key+".")
    scan(tree.body);return out
old=(root/"reference/phaseb_controller_r3.py").read_text(); new=(root/"candidate/native_h2_gate_r1.py").read_text()
a,b=defs(old),defs(new)
same=sorted(k for k in a.keys()&b.keys() if a[k]==b[k])
changed=sorted(k for k in a.keys()&b.keys() if a[k]!=b[k])
for key in ("owner_class","neutral_environment","readonly_runner","make_fixture.PhaseB.setup_phase","make_fixture.PhaseB.request","make_fixture.PhaseB.spawn"):
    assert key in same,key
result["controller_definition_source_comparison"]={"byte_identical":same,"changed":changed,"removed":sorted(a.keys()-b.keys()),"new":sorted(b.keys()-a.keys())}
for oldname,newname,diffname in [("phaseb_controller_r3.py","native_h2_gate_r1.py","controller-reference-to-h2.review.diff"),("phaseb_binding_r3.py","native_h2_binding_r1.py","binding-reference-to-h2.review.diff")]:
    before=(root/"reference"/oldname).read_text();after=(root/"candidate"/newname).read_text()
    diff="".join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile="reference/"+oldname,tofile="candidate/"+newname))
    p=root/diffname
    with p.open("x") as f: f.write(diff)
    result.setdefault("diffs",[]).append({"path":str(p),"bytes":len(diff.encode()),"sha256":hashlib.sha256(diff.encode()).hexdigest()})
with (root/"offline-source-components.public.json").open("x") as f:json.dump(result,f,sort_keys=True,indent=2);f.write("\n")
print(json.dumps(result,sort_keys=True))
