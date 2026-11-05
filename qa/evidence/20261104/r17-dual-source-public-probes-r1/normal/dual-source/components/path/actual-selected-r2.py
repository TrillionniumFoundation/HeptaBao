import ast,hashlib,json
checks=[]
def check(value,name):
    if not value: raise AssertionError(name)
    checks.append(name)
st=ast.parse(data["stager"]); lt=ast.parse(data["launcher"])
def assignments(nodes):
    out={}
    for n in nodes:
        if isinstance(n,ast.Assign):
            for t in n.targets:
                if isinstance(t,ast.Name): out[t.id]=n.value
    return out
sa=assignments(st.body)
def lit(name): return ast.literal_eval(sa[name])
check(lit("COMMIT")==data["commit"] and lit("TREE")==data["tree"],"stager_exact_canonical")
check(lit("PARENT")==data["parent"],"stager_sole_parent")
check(list(lit("ANCESTRY"))==[tuple(x) for x in data["ancestry"]],"five_fixed_real_parents")
check(lit("OLD_COMMIT")=="49503322c7f446e5eb41e7744f1fdbd7f1192ecc","actual_495_anchor")
check(lit("STAGE_SECONDS")==300.0,"stage_total_not_reset")
controls=lit("EXPECTED_CONTROLS")
check(controls=={k:tuple(v) for k,v in data["controls"].items()},"payload_all_exact_control_pins")
def eval_path(node,base=None):
    if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="Path" and len(node.args)==1:
        return ast.literal_eval(node.args[0])
    if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Div) and isinstance(node.left,ast.Name) and node.left.id=="BASE":
        return base+"/"+ast.literal_eval(node.right)
    raise AssertionError("unexpected path expression")
check(eval_path(sa["ROOT"])==data["root"],"source_root_exact")
profile=next(n for n in lt.body if isinstance(n,ast.If) and ast.unparse(n.test)=="args.host == 'mac'")
la=assignments(profile.body if data["host"]=="mac" else profile.orelse)
base=eval_path(la["BASE"])
check(eval_path(la["ROOT"],base)==data["root"],"launcher_same_source_root")
check(ast.literal_eval(la["RUNNER_NAME"])==data["runner_name"],"launcher_runner_basename_matches_payload")
top=assignments(lt.body)
check(ast.literal_eval(top["ORIGINAL_OUTER_SECONDS"])==data["outer"],"launcher_outer_exact")
check(ast.unparse(top["OUTER_STARTED"])=="time.monotonic()","launcher_clock_once_before_preflight")
check(ast.unparse(top["OUTER_UNTIL"])=="OUTER_STARTED + ORIGINAL_OUTER_SECONDS","single_carried_outer_deadline")
exec_call=[n for n in ast.walk(lt) if isinstance(n,ast.Call) and ast.unparse(n.func)=="os.execv"]
check(len(exec_call)==1 and ast.unparse(exec_call[0])=="os.execv(argv[0], argv)","exact_single_same_PID_exec")
argv_nodes=[n for n in ast.walk(lt) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="argv" for t in n.targets) and isinstance(n.value,ast.List) and n.value.elts and isinstance(n.value.elts[0],ast.Name) and n.value.elts[0].id=="PYTHON"]
check(len(argv_nodes)==1,"unique_runner_argv")
av=argv_nodes[0].value
check(isinstance(av,ast.List),"literal_runner_argv_structure")
avtext=[ast.unparse(x) for x in av.elts]
check(avtext[-4:]==["'--outer-started-monotonic'","repr(OUTER_STARTED)","'--launcher-pid'","str(os.getpid())"],"actual_argv_carries_original_clock_and_pid")
# Execute only the actual parser definition on synthetic bytes, with exact constants.
fn=next(n for n in st.body if isinstance(n,ast.FunctionDef) and n.name=="canonical_bundle_header")
env={"OLD_COMMIT":data["old_commit"],"COMMIT":data["commit"],"digest":lambda b:hashlib.sha256(b).hexdigest()}
exec(compile(ast.Module(body=[fn],type_ignores=[]),"<selected-bundle-header>","exec"),env)
old=data["old_commit"].encode(); new=data["commit"].encode()
valid=b"# v2 git bundle\n-"+old+b" fixed public subject\n"+new+b" HEAD\n\nPACK"
p=env["canonical_bundle_header"](valid)
check(p["prerequisites"]==[data["old_commit"]] and p["heads"]==[[data["commit"],"HEAD"]],"actual_parser_known_control")
bad={
 "wrong_prerequisite":valid.replace(old,b"0"*40),
 "wrong_head":valid.replace(new,b"0"*40),
 "extra_head":valid.replace(b"\n\nPACK",b"\n"+new+b" refs/heads/extra\n\nPACK"),
 "extra_prerequisite":valid.replace(b"\n\nPACK",b"\n-"+old+b" extra\n\nPACK"),
 "wrong_version":valid.replace(b"# v2",b"# v3"),
 "capability":valid.replace(b"# v2 git bundle\n",b"# v2 git bundle\n@object-format=sha1\n"),
 "missing_pack":valid[:-4]+b"NOPE"}
for name,value in bad.items():
    try: env["canonical_bundle_header"](value)
    except (AssertionError,UnicodeError,ValueError): pass
    else: raise AssertionError(name)
    checks.append("actual_parser_rejects_"+name)
if data["host"]=="mac":
    check(data["stager"].index("result['external_volume_uuid'] = prewrite_volume_guard()")<data["stager"].index("ROOT.mkdir(mode=0o700)"),"T5_UUID_guard_before_first_candidate_write")
    check("FB804D1B-24CB-4D6E-AEA7-A9E180807758" in data["stager"],"original_T5_UUID")
    check("'--no-write-fetch-head', str(canonical_path), 'HEAD'" in data["stager"],"Mac_fetch_fixed_local_bundle")
    check("'--no-write-fetch-head', 'origin', COMMIT" not in data["stager"],"Mac_no_public_fetch")
else:
    check("'--no-write-fetch-head', 'origin', COMMIT" in data["stager"],"ROG_fetch_exact_SHA_only")
    check("'HEAD', '^' + OLD_COMMIT" in data["stager"],"ROG_exact_bundle_cut")
print(json.dumps({"schema":"heptabao.cold-h2-source-path-contract-components.v1","host":data["host"],
 "checks":checks,"passed":len(checks),"stager_sha256":hashlib.sha256(data["stager"].encode()).hexdigest(),
 "launcher_sha256":hashlib.sha256(data["launcher"].encode()).hexdigest(),"actual_subprocesses":0,
 "actual_files":0,"network":0,"candidate_module_executed":False,
 "scope":"actual AST path/carry contracts and selected actual bundle-header parser; not Git or host execution"},sort_keys=True))
