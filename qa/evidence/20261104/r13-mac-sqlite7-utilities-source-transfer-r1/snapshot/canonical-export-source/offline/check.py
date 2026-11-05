import ast,difflib,hashlib,json,sys
p=json.loads(sys.argv[1]);a=p["before"];b=p["after"]
old,new=ast.parse(a),ast.parse(b);compile(new,"<source exporter candidate>","exec")
def fs(t,s):return [(n.name,ast.get_source_segment(s,n)) for n in ast.walk(t) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]
f,g=fs(old,a),fs(new,b);assert f==g
print(json.dumps({"schema":"heptabao.phaseb-3cb-export-source-invariance.v1","before_sha256":hashlib.sha256(a.encode()).hexdigest(),"after_sha256":hashlib.sha256(b.encode()).hexdigest(),"function_count":len(f),"all_functions_byte_equal":True,"parse_and_compile_only":True,"module_executed":False,"network_calls":0,"files_written":0,"diff":"".join(difflib.unified_diff(a.splitlines(True),b.splitlines(True),fromfile="reference/source_export_r10.py",tofile="candidate/source_export_phaseb_3cb_r1.py"))},sort_keys=True))
