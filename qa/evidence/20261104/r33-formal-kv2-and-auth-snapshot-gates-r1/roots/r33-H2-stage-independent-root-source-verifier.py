import ast, hashlib, json, re
from pathlib import Path

ROOT=Path("/workspace/scratch/f86faac821c4/r32_recovery")
IDX=json.loads(json.loads((ROOT/"r33-H2-stage-review-input-index.json").read_text())["text"])
checks=[]
def ok(name,value):
    if not value: raise AssertionError(name)
    checks.append(name)
def read(name):
    pin=IDX[name]
    text=json.loads((ROOT/("blob-"+pin["blob"]+".json")).read_text())["text"]
    b=text.encode()
    ok("whole:"+name,len(b)==pin["bytes"] and hashlib.sha256(b).hexdigest()==pin["sha256"] and hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()==pin["blob"])
    return text
base=read("reference/before-cli-stage.py")
candidate=read("candidate/stage_h2_r1.py")
patch=read("diff/stage.review.diff")
payload_text=read("payload/source-carrier.json")
binding_text=read("payload/files/binding.partially-resolved.json")
plan=json.loads(read("PLAN.public.json"))
table=json.loads(read("reference/source52-instrument12.public.json"))
members=json.loads(read("reference/H2-product-eight-members.public.json"))
old_payload=json.loads(read("reference/before-cli-source-carrier.json"))
dual=json.loads(read("reference/H2-dual49-root-review.public.json"))
ok("qualified-base-and-fixed-candidate",IDX["reference/before-cli-stage.py"]["blob"]=="45ceb135688a2002e845f31e010ca5c010551517" and IDX["candidate/stage_h2_r1.py"]["blob"]=="678e519f17c474b5610651bcbb93b43d186124c5")
def apply_unified(old,diff):
    src=old.splitlines(keepends=True); lines=diff.splitlines(keepends=True); out=[]; pos=0; i=2; count=0
    while i<len(lines):
        m=re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@",lines[i])
        if not m: raise AssertionError("invalid hunk header")
        start=int(m[1])-1; old_n=int(m[2] or 1); new_n=int(m[4] or 1)
        if start<pos: raise AssertionError("overlap")
        out.extend(src[pos:start]); pos=start; i+=1; consumed=produced=0
        while i<len(lines) and not lines[i].startswith("@@ "):
            line=lines[i]; tag=line[0]; body=line[1:]
            if tag in " -":
                if pos>=len(src) or src[pos]!=body: raise AssertionError("context mismatch")
                pos+=1; consumed+=1
            if tag in " +": out.append(body); produced+=1
            if tag not in " +-": raise AssertionError("unexpected diff line")
            i+=1
        if (consumed,produced)!=(old_n,new_n): raise AssertionError("hunk length")
        count+=1
    out.extend(src[pos:])
    return "".join(out),count
rebuilt,hunks=apply_unified(base,patch)
ok("independent-strict14-forward-diff-entire-candidate",rebuilt==candidate and hunks==14)
A,B=ast.parse(base),ast.parse(candidate)
def definitions(tree,text):
    lines=text.splitlines(keepends=True); result={}
    def walk(n,prefix=""):
        for child in ast.iter_child_nodes(n):
            if isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                path=prefix+child.name
                if isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    result[path]="".join(lines[child.lineno-1:child.end_lineno])
                walk(child,path+".")
            else: walk(child,prefix)
    walk(tree); return result
da,db=definitions(A,base),definitions(B,candidate)
ok("same18-definitions-no-new-layer",set(da)==set(db) and len(da)==18)
changed={name for name in da if da[name]!=db[name]}
ok("only-five-authorized-definitions-change",changed=={"NewDirectories.__init__","NewDirectories.create","NewDirectories.write","NewDirectories.copy","main"})
for name in sorted(set(da)-changed): ok("unchanged-definition:"+name,da[name]==db[name])
imports=lambda t:[ast.dump(n,include_attributes=False) for n in t.body if isinstance(n,(ast.Import,ast.ImportFrom))]
ok("imports-identical-no-new-runtime",imports(A)==imports(B))
marker='    except BaseException as error:\n        result.update(status="failed", error_type=type(error).__name__,'
ok("entire-original-failure-finally-stdout-deadline-tail-unchanged",candidate[candidate.index(marker):]==base[base.index(marker):])
def values(tree):
    result={}
    for n in tree.body:
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
            name=n.targets[0].id
            try:
                v=n.value
                if isinstance(v,ast.Call) and isinstance(v.func,ast.Attribute) and isinstance(v.func.value,ast.Name) and v.func.value.id=="json" and v.func.attr=="loads":
                    result[name]=json.loads(ast.literal_eval(v.args[0]))
                else: result[name]=ast.literal_eval(v)
            except (ValueError,TypeError,SyntaxError): pass
    return result
va,vb=values(A),values(B)
ok("original-three-product-copy-tuples",va["COPY"]==vb["COPY"] and len(vb["COPY"])==3)
ok("six-old-fences-and-machine-and-product-pins-unchanged",va["OLD_FENCES"]==vb["OLD_FENCES"] and len(vb["OLD_FENCES"])==6 and va["MACHINE_SHA"]==vb["MACHINE_SHA"] and va["HEAD"]==vb["HEAD"] and va["TREE"]==vb["TREE"])
payload=json.loads(payload_text); spec=json.loads(binding_text)
ok("exact-carrier-size-hash-original-cap",len(payload_text.encode())==vb["PAYLOAD_BYTES"]==321152 and hashlib.sha256(payload_text.encode()).hexdigest()==vb["PAYLOAD_SHA"]=="6700283209e4de4433d0ef562c696c9d95ea6a12a2f0c3926701e4cc11674883" and len(payload_text.encode())<1048576)
ok("exact-H2-carrier-and-eight-text-members",set(payload)=={"schema","files"} and payload["schema"]=="heptabao.normal-native-h2-gate.local-source-carrier.v1" and set(payload["files"])==set(vb["FILES"]) and len(vb["FILES"])==8)
for name,pin in vb["FILES"].items():
    text=read("payload/files/"+name)
    ok("carrier-exact-member:"+name,text==payload["files"][name] and len(text.encode())==pin["bytes"] and hashlib.sha256(text.encode()).hexdigest()==pin["sha256"])
expected_QA={"native_h2_gate_r1.py":"703e5ecfc9b88ce4d8cdaf81342597a12a7b42c92af583b54d87f4f8a37bcf13","native_h2_binding_r1.py":"6bbaa72dcb899d359f14c6e442c824c46a8c52aa74aa0d6be8b1820596c34cf4","phaseb_evidence_r3.py":"4fb452f9eabbbc9f66913e0b824f7f3db5b2a75848b2adf4186e76078f2c9024","native_fixture_reference_r8.py":"a0bac9972fbb9d65ed3edf537f732a08b5177864516b33ada0a6e98c4c6a0416","official_cli_reference_r4.py":"18318841d3538e60fddf951708055a206402f5bf1ecdacc2bfceabec4f998dd9"}
ok("five-original-H2-QA-contracts-byte-pinned",set(vb["QA_NAMES"])==set(expected_QA) and all(vb["FILES"][n]["sha256"]==h and spec["qa_files"][n]["sha256"]==h for n,h in expected_QA.items()))
ok("two-product-receipts-whole-unchanged",all(payload["files"][n]==old_payload["files"][n] for n in ["normal-release-tests-result.public.json","groups.json"]))
ok("unchanged-content-bound-template",IDX["payload/files/binding.partially-resolved.json"]["blob"]=="52ce20ef5c148ad5477b493ce43ac3b43d8569a8")
ok("dual-identities-and-no-official-cli-executable-field",spec["candidate_commit"]=="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec" and spec["candidate_tree"]=="eba5e650bd080b8ad41ea52a2bc68867f541d255" and spec["instrument_build_commit"]=="df026fe323dd7cf0f0ec57d7d2d9c5a79897053c" and spec["instrument_build_tree"]=="424463ccd2310ddc1e7b2bbcd7b7af29ae58c825" and "official_cli" not in spec and spec["ready_for_readonly_prepare"] is False)
ok("exact12-instrument-role-set",set(vb["H2_COPY"])=={x["role"] for x in table["rows"]} and len(vb["H2_COPY"])==12)
for row in table["rows"]:
    role=row["role"]; source=row["desktop_incoming_receiver"]; target=row["h2_planned_target"]
    ok("instrument-route-pin:"+role,vb["H2_COPY"][role]==(row["name"],row["content"]["bytes"],row["content"]["sha256"],source["mode"],target["mode"]) and spec["h2_client"][role]==target and row["h2_target_actual_identity"] is None)
ok("exact-current-eight-product-source-pins",set(vb["SOURCE_PINS"])=={x["path"] for x in members["members"]} and all(vb["SOURCE_PINS"][x["path"]][1]==x["expected_sha256"] for x in members["members"]) and members["commit"]==spec["candidate_commit"] and members["tree"]==spec["candidate_tree"])
ok("new-held-FD-registered-before-fstat",db["NewDirectories.create"].index("self.fds.append(fd)")<db["NewDirectories.create"].index("self.children.append((name, fd, directory_identity(os.fstat(fd))))"))
ok("fixed-copy-boolean-and-entire-tuple-route-before-I/O",db["NewDirectories.copy"].index('need(type(h2) is bool, "fixed_copy_route")')<db["NewDirectories.copy"].index("open_source(") and db["NewDirectories.copy"].index('need(member in (H2_COPY.values() if h2 else COPY), "fixed_copy_member")')<db["NewDirectories.copy"].index("open_source("))
ok("raw-writes-exclude-h2-FD", 'need(fd in (self.rootfd, self.qafd, self.artfd), "owned_destination_fd")' in db["NewDirectories.write"])
ok("copy-route-used-for-create-name-check-path-and-fsync",db["NewDirectories.copy"].count("dir_fd=destination")==2 and 'str(CONTROL / directory / name)' in db["NewDirectories.copy"] and "os.fsync(destination)" in db["NewDirectories.copy"])
ok("h2-actual-targets-bound-before-ready",db["main"].index('need(actual_h2 == spec["h2_client"], "actual_h2_targets_match_frozen_binding")')<db["main"].index('spec["ready_for_readonly_prepare"] = True'))
ok("exact-H2-and-root-membership-before-pass",db["main"].index('"exact_created_h2_members"')<db["main"].index('result.update(status="passed"') and db["main"].index('"exact_created_control_members"')<db["main"].index('result.update(status="passed"'))
ok("original-300s-and-isolation-stdin-cap", 'UNTIL = started + 300_000_000_000' in db["main"] and 'sys.stdin.buffer.read(1024 * 1024 + 1)' in db["main"] and 'sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode' in db["main"])
ok("binding-interface-exact14",len(spec)==14 and set(spec)=={"schema","candidate_commit","candidate_tree","host","layout","qa_files","artifacts","h2_client","utilities","old_fences","budgets","ready_for_readonly_prepare","instrument_build_commit","instrument_build_tree"})
ok("source-only-and-observation-gates-honest",plan["Runtime_calls"]==0 and plan["stage_dispatch_ready"] is False and plan["stage_process_request_constructed"] is False and plan["unresolved"]["five_incoming_info_indices"]==[7,8,9,10,11] and plan["unresolved"]["all_22_target_actual_identities"] is None)
result={"schema":"heptabao.root-H2-existing-stage-source-review.r33.v1","status":"PASS_SOURCE_AWAITING_FIVE_ACTUAL_INFOS_AND_EXACT_REQUEST","checks_passed":len(checks),"checks":checks,"source_packet":"9fa416e0d2bafa213bee8fee7dd82ddf3199484e","base_blob":IDX["reference/before-cli-stage.py"]["blob"],"candidate":IDX["candidate/stage_h2_r1.py"],"payload":IDX["payload/source-carrier.json"],"changed_definitions":sorted(changed),"unchanged_definitions":len(da)-len(changed),"diff_hunks":hunks,"root_semantic_read":"Five necessary structural categories independently read: own h2qa, two fixed copy routes, exact FD/name/member sets, H2 carrier schema and actual h2_client target binding. Source/no-symlink/nlink/hash/EOF/custody guards and original failure/closure/deadline tail retained. Durable receipt precedes directory closure; full stdout plus terminal authority is still required.","original_internal_seconds":300,"original_outer_seconds":330,"source_and_normal5_qualification_adopted":True,"dual49_QA_contract_adopted":True,"author118_fake17_not_rerun":True,"candidate_module_executed":False,"Runtime_calls":0,"five_infos_still_pending":True,"actual_target_identities_observed":0,"stage_authorized":False,"product_authorized":False,"production_authorized":False}
out=ROOT/"r33-H2-stage-root-review.actual.json"
out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n")
print(json.dumps({"status":result["status"],"checks":len(checks),"output":str(out)}))
