import ast,difflib,hashlib,json,pathlib
root=pathlib.Path("/workspace/scratch/f86faac821c4/native-h2-qa-review-r1")
def tree_text(path):
    raw=path.read_bytes();source=raw.decode();tree=ast.parse(source);compile(tree,str(path),"exec")
    return raw,source,tree
result={"scope":"source-only AST and exact function bytes; no main or Rust execution","network_or_child_component_calls":0}
for name in ("native_h2_binding_r1.py","build_native_h2_client_r1.py"):
    raw,_,_=tree_text(root/"draft2"/name)
    result.setdefault("current_sources",[]).append({"file":name,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"ast":True,"compile_only":True})
def extract(source,name):
    return ast.get_source_segment(source,next(n for n in ast.parse(source).body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name==name))
old_binding=(root/"reference/phaseb_binding_r3.py").read_text()
first_binding=(root/"candidate/native_h2_binding_r1.py").read_text()
current_binding=(root/"draft2/native_h2_binding_r1.py").read_text()
builder=(root/"draft2/build_native_h2_client_r1.py").read_text()
assert extract(first_binding,"lock_subset")==extract(current_binding,"lock_subset")==extract(builder,"lock_subset")
result["selected_12_lock_subset_components_retain_exact_function_bytes"]=True
identical=[]
for name in ("need","remaining","sha","identity","exact_path","no_symlink_ancestors","duplicate_free","parse","pin_file","load_verified_module"):
    assert extract(old_binding,name)==extract(builder,name),name
    identical.append(name)
before=extract(old_binding,"read_file");after=extract(builder,"read_file")
assert after.replace("fd = open_fd(","fd = os.open(").replace("close_fd(fd)","os.close(fd)")==before
result["builder_reused_definition_bytes"]={"identical":identical,"read_file_only_delta":"tracked open_fd/close_fd calls; same original custody, fullhash and deadline code"}
for a,b,name in [(root/"candidate/build_native_h2_client_r1.py",root/"draft2/build_native_h2_client_r1.py","builder-draft1-to-draft2.review.diff"),(root/"candidate/native_h2_binding_r1.py",root/"draft2/native_h2_binding_r1.py","binding-draft1-to-draft2.review.diff"),(root/"reference/phaseb_binding_r3.py",root/"draft2/native_h2_binding_r1.py","binding-reference-to-h2-final.review.diff")]:
    old=a.read_text();new=b.read_text()
    delta="".join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile=str(a.relative_to(root)),tofile=str(b.relative_to(root))))
    with (root/name).open("x") as f:f.write(delta)
    result.setdefault("diffs",[]).append({"path":name,"bytes":len(delta.encode()),"sha256":hashlib.sha256(delta.encode()).hexdigest()})
with (root/"offline-source-draft2.public.json").open("x") as f:json.dump(result,f,sort_keys=True,indent=2);f.write("\n")
print(json.dumps(result,sort_keys=True))
