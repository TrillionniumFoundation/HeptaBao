import ast,base64,hashlib,json,sys
v=json.load(sys.stdin);checks=[]
def check(name,value):
    assert value,name
    checks.append({"name":name,"passed":True})
def sha(raw):return hashlib.sha256(raw).hexdigest()
def literals(source):
    result={}
    for node in ast.parse(source).body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            try:result[node.targets[0].id]=ast.literal_eval(node.value)
            except (ValueError,TypeError):pass
    return result
sources=v["sources"];base=v["base"];compiled=[]
for name,raw in sources.items():
    if name.endswith(".py"):
        compile(ast.parse(raw,filename=name),name,"exec");compiled.append(name)
check("exact22_sources18_python4_javascript",len(sources)==22 and len(compiled)==18)
outer=literals(sources["mac_current_outer_wal_r1.py"])
entry=literals(sources["mac_current_capture_entry_wal_r1.py"])
check("outer_exact_source_set",set(outer["NAMES"])==set(sources) and len(outer["NAMES"])==22)
check("entry_seven_imported_pins",set(entry["NAMES"])==set(outer["ENTRY_NAMES"]) and len(entry["NAMES"])==7)
check("entry_outer_same_actual_wal_binding",entry["WAL_BINDING"]==outer["WAL_BINDING"]==v["candidate"]["walBinding"])
check("entry_outer_original_native_binding",entry["NATIVE_BINDING"]==outer["NATIVE_BINDING"]==v["candidate"]["nativeBinding"])
check("old_capture_entire_byte_exact",sources["mac_guarded_current_capture_r3.py"]==base["mac_guarded_current_capture_r3.py"])
check("new_library_exact_actual_qualified_source",sha(sources["mac_registry_readonly_wal_r1.py"].encode())==entry["WAL_BINDING"]["librarySha256"])
unchanged=[];root_only=[]
for name,old in base.items():
    if name in ("mac_current_capture_entry_native_r1.py","mac_current_outer_native_r1.py"):continue
    candidate=sources[name]
    inverse=candidate.replace("mac-authbus-df026-current-registry-wal-r1","mac-authbus-r10-current-native-custody-r1").replace("org.heptabao.qa.mac-authbus-df026-wal-r1.","org.heptabao.qa.mac-authbus-r10-native-r1.")
    check("unchanged_or_fixed_root_label_only."+name,inverse==old)
    (unchanged if candidate==old else root_only).append(name)
old_entry=base["mac_current_capture_entry_native_r1.py"]
old_outer=base["mac_current_outer_native_r1.py"]
def defs(source):
    lines=source.splitlines(keepends=True)
    return {n.name:"".join(lines[n.lineno-1:n.end_lineno]) for n in ast.parse(source).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
e0=defs(old_entry);e1=defs(sources["mac_current_capture_entry_wal_r1.py"])
o0=defs(old_outer);o1=defs(sources["mac_current_outer_wal_r1.py"])
for name,raw in e0.items():
    if name!="main":check("original_entry_definition_exact."+name,e1[name]==raw)
for name,raw in o0.items():
    if name not in ("Context","capture_once","main"):check("original_outer_definition_exact."+name,o1[name]==raw)
check("original_capture_profile_permission_body_exact",e1["capture_profile"]==e0["capture_profile"])
check("outer_budgets_unchanged",all(outer[k]==literals(old_outer)[k] for k in ("NEW_OUTER_SECONDS","NEW_OUTER_FAILURE_CLEANUP_SECONDS","NEW_LISTENER_READY_SECONDS","HTTP_SECONDS","CAPTURE_SECONDS","MAX_HTTP_BODY","MAX_PUBLIC_REPORT")))
candidate=v["candidate"]
check("candidate_exact_source_pins",candidate["sourcePins"]=={n:sha(raw.encode()) for n,raw in sources.items()})
payload=json.loads(v["inert"]["stdin"]);carrier=v["inert"]["args"][4];constants=literals(carrier)
compile(ast.parse(carrier,filename="inert.py"),"inert.py","exec")
check("inert_complete_payload_hash",len(v["inert"]["stdin"].encode())==constants["PAYLOAD_BYTES"] and sha(v["inert"]["stdin"].encode())==constants["PAYLOAD_SHA"])
check("inert_all22_b64_exact",set(payload["files"])==set(sources) and all(base64.b64decode(payload["files"][n],validate=True)==r.encode() for n,r in sources.items()))
check("inert_source_tuple_pins",constants["PINS"]=={n:[len(r.encode()),sha(r.encode())] for n,r in sources.items()})
check("inert_all8_documents_exact",len(payload["documents"])==8 and set(payload["documents"])==set(v["documents"]) and all(base64.b64decode(payload["documents"][n],validate=True)==r.encode() for n,r in v["documents"].items()))
check("inert_document_tuple_pins",constants["DOCUMENT_PINS"]=={n:[len(r.encode()),sha(r.encode())] for n,r in v["documents"].items()})
check("inert_anchor_exact",len(base64.b64decode(payload["anchorBase64"]))==967 and sha(base64.b64decode(payload["anchorBase64"]))==constants["ANCHOR_SHA"])
request=v["runtime"];args=request["args"]
def arg(flag):return args[args.index(flag)+1]
check("runtime_exact_fixed_wrapper",request["host"]=="mac" and request["executable"]=="/opt/homebrew/bin/python3" and request["cwd"]=="/Users/qianqi" and request["timeout_seconds"]==1080 and args[:3]==["-I","-S","-B"])
check("runtime_exact_candidate",sha(v["documents"]["candidate-current-manager-wal-r1.public.json"].encode())==arg("--candidate-sha256") and arg("--candidate").endswith("/mac-authbus-df026-current-registry-wal-r1/candidate-current-manager-wal-r1.public.json"))
raw=base64.b64decode(arg("--public-source-pins-base64"),validate=True)
check("runtime_exact22_pins",sha(raw)==arg("--public-source-pins-sha256") and json.loads(raw)==candidate["sourcePins"])
check("runtime_same_original_anchor",arg("--public-volume-anchor-base64")==payload["anchorBase64"] and arg("--public-volume-anchor-sha256")==constants["ANCHOR_SHA"])
check("public_wal_proof_docs_exact",sha(v["documents"]["proofs/registry-wal-r1.stdout.public.json"].encode())==candidate["walBinding"]["stdoutSha256"] and sha(v["documents"]["proofs/registry-wal-r1.authority.public.json"].encode())==candidate["walBinding"]["authoritySha256"])
check("entry_old_untracked_validation_removed", "capture.validate_synthetic_proof(" not in e1["main"])
check("outer_tracked_old_predicates_before_private_origins",o1["main"].index("validate_original_immutable_proof(")<o1["main"].index("inputs.project_frozen()"))
check("attempt_registered_before_commands_call",o1["capture_once"].index("ctx.capture_attempts.append(attempt)")<o1["capture_once"].index("commands.run("))
check("failure_public_record_precedes_zero_exit_gate",o1["capture_once"].index("attempt['report']=value")<o1["capture_once"].index("need(row['exitCode']==0"))
check("before_after_whole_capsule_equality_retained","canonical(after)==canonical(capsule_before)" in o1["main"])
check("no_runtime_module_import_or_execution",True)
print(json.dumps({"schema":"heptabao.mac-current-wal-complete-source-static.r1","checks":checks,"passed":len(checks),"compiled_python_sources":compiled,"compiled_inert":True,"unchanged_sources":unchanged,"fixed_root_or_label_only_sources":root_only,"module_imported_or_executed":False,"host_requests":0,"private_inputs":0,"sqlite_operations":0},sort_keys=True))
