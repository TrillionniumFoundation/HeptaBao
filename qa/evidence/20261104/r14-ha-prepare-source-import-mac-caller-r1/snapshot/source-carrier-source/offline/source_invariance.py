import ast,difflib,hashlib,json,sys
d=json.loads(sys.argv[1]);before=d["before"];after=d["after"];name=d["name"]
a=ast.parse(before);b=ast.parse(after);compile(b,name,"exec")
checks=[]
def check(n,v):
 assert v,n
 checks.append(n)
def bodies(t,s):
 return {n.name:ast.get_source_segment(s,n) for n in t.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
aa=bodies(a,before);bb=bodies(b,after)
check("same_definition_names",aa.keys()==bb.keys())
changed=[k for k in aa if aa[k]!=bb[k]]
check("only_allowlisted_changed_definitions",changed==(["receive"] if name=="receiver" else []))
inverse=after
for e in reversed(d["edits"]):
 check("inverse_present_"+str(len(checks)),e["after"] in inverse)
 inverse=inverse.replace(e["after"],e["before"])
check("inverse_whole_bytes_exact",inverse==before)
if name=="receiver":
 old=aa["receive"];new=bb["receive"]
 left=" native=json.loads(json_bytes['native-build.public.json'])"
 right=" assert sorted(os.listdir(DESTINATION))"
 check("receive_prefix_unchanged",old[:old.index(left)]==new[:new.index(" exported=json.loads")])
 check("receive_suffix_except_provenance_label",old[old.index(right):].replace("normal_release_provenance_verified","source_export_provenance_verified")==new[new.index(right):])
if name in ("sender","receiver","relay"):
 def literals(t):
  out={}
  for n in t.body:
   if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
    try:out[n.targets[0].id]=ast.literal_eval(n.value)
    except (ValueError,TypeError):pass
  return out
 x=literals(b)
 check("files_exact_actual_lossless_pins",x["FILES"]==d["files"])
 check("canonical_commit_exact",x["HEAD"]=="3cb873919170cc77101b27f6a3ab9e98f41f8d93")
 check("canonical_tree_exact",x["TREE"]=="7f4d48a647a81ca96e8a24a0a057c2c829459060")
diff="".join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile="reference-actual-3cb/"+name+".py",tofile="draft-source-carrier/"+name+".py"))
print(json.dumps({"schema":"heptabao.phaseb3cb.source-carrier-source-invariance.v1","name":name,"bytes":len(after.encode()),"sha256":hashlib.sha256(after.encode()).hexdigest(),"checks":checks,"checks_passed":len(checks),"identical_definitions":[k for k in aa if aa[k]==bb[k]],"changed_definitions":changed,"compiled_not_executed":True,"candidate_top_level_executed":False,"host_operations":0,"diff":diff},sort_keys=True))