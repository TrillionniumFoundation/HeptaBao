import ast,difflib,hashlib,json,sys
p=json.loads(sys.argv[1])
out={"schema":"heptabao.phaseb-3cb-local-stage-offline-source-check.v1","product_executed":False,"target_module_executed":False,"network_calls":0,"files_written":0,"rows":[]}
for row in p:
 a,b=row["before"],row["after"]
 r={"label":row["label"],"before_sha256":hashlib.sha256(a.encode()).hexdigest(),"after_sha256":hashlib.sha256(b.encode()).hexdigest(),"diff":"".join(difflib.unified_diff(a.splitlines(True),b.splitlines(True),fromfile="reference/"+row["label"],tofile="candidate/"+row["label"]))}
 if row["python"]:
  old,new=ast.parse(a),ast.parse(b);compile(new,"<candidate local stager>","exec")
  def fs(tree,src):
   return [(n.name,ast.get_source_segment(src,n)) for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]
  f,g=fs(old,a),fs(new,b);assert f==g
  r.update(ast_parse_and_compile_only=True,functions_byte_equal=True,function_count=len(f))
 else:
  json.loads(a);json.loads(b);r["json_parse_only"]=True
 out["rows"].append(r)
print(json.dumps(out,sort_keys=True))
