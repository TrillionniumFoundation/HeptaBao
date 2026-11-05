import ast, hashlib, json
from pathlib import Path
ROOT=Path("/tmp/heptabao_auth_renewal_peer_r1")
pins={"before.py":("bce47fd194be7ec1d1ec340e24d8e759dbf7611ef3c75eca2adeb62e9b4ccf01",68348),"after.py":("72ecfcd586a4ab4c48fd95d2e15b4a44165a754570c699eae18dceaa02f3b262",71496)}
checks=[]
def check(name,value):
    checks.append({"name":name,"passed":bool(value)})
    if not value: raise AssertionError(name)
texts={};trees={}
for name,(pin,size) in pins.items():
    raw=(ROOT/name).read_bytes()
    check(name+"_whole",len(raw)==size and hashlib.sha256(raw).hexdigest()==pin)
    texts[name]=raw.decode()
    trees[name]=ast.parse(texts[name],filename=name)
    compile(trees[name],name,"exec")
def defs(tree): return {n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
def segment(name,node): return ast.get_source_segment(texts[name],node)
old=defs(trees["before.py"]);new=defs(trees["after.py"])
unchanged=[n for n in old if n in new and segment("before.py",old[n])==segment("after.py",new[n])]
check("exact_23_old_definitions_byte_unchanged",len(unchanged)==23)
check("only_two_existing_definitions_changed",set(old)-set(unchanged)=={"token_lifecycle","main"})
check("only_two_top_level_definitions_added",set(new)-set(old)=={"token_lookup_snapshot","token_lifecycle_before"})
before_other=[ast.dump(n,include_attributes=False) for n in trees["before.py"].body if not isinstance(n,(ast.FunctionDef,ast.ClassDef)) and not (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="BINDING_READY" for t in n.targets))]
after_other=[ast.dump(n,include_attributes=False) for n in trees["after.py"].body if not isinstance(n,(ast.FunctionDef,ast.ClassDef)) and not (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="BINDING_READY" for t in n.targets))]
check("all_other_top_level_statements_unchanged",before_other==after_other)
ready=next(n for n in trees["after.py"].body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="BINDING_READY" for t in n.targets))
check("ready_is_literal_false",isinstance(ready.value,ast.Constant) and ready.value.value is False)
main=new["main"]; first=main.body[0]
check("first_main_statement_refuses_unbound_before_any_setup",isinstance(first,ast.Expr) and isinstance(first.value,ast.Call) and ast.unparse(first.value)=="need(BINDING_READY is True, 'mac_normal61_binding_not_admitted')")
def calls(node,attr=None,owner=None):
    rows=[]
    for n in ast.walk(node):
        if not isinstance(n,ast.Call): continue
        if attr is not None and not (isinstance(n.func,ast.Attribute) and n.func.attr==attr): continue
        if owner is not None and not (isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id==owner): continue
        rows.append(n)
    return sorted(rows,key=lambda n:(n.lineno,n.col_offset))
def plain_calls(node,name):
    return sorted([n for n in ast.walk(node) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id==name],key=lambda n:n.lineno)
pre=new["token_lifecycle_before"];life=new["token_lifecycle"];snapshot=new["token_lookup_snapshot"]
guard_reads=calls(pre,"read","guard")
check("one_guard_token_read_with_original_limit",len(guard_reads)==1 and isinstance(guard_reads[0].args[1],ast.Constant) and guard_reads[0].args[1].value==65536)
check("original_token_read_prefix_exact",texts["before.py"].splitlines()[old["token_lifecycle"].lineno:old["token_lifecycle"].lineno+5]==texts["after.py"].splitlines()[pre.lineno:pre.lineno+5])
pre_http=calls(pre,"call","client");post_http=calls(life,"call","client")
check("one_pre_lookup",len(pre_http)==1 and ast.literal_eval(pre_http[0].args[1])=="GET" and ast.literal_eval(pre_http[0].args[2])=="auth/token/lookup-self")
routes=[ast.literal_eval(n.args[2]) for n in post_http]
check("exact_original_and_post_lookup_route_order",routes==["openclaw-auth/data/profiles/unassigned","auth/token/renew-self","auth/token/lookup-self","auth/token/revoke-self","openclaw-auth/data/manifest"])
check("all_six_calls_same_explicit_token",all(any(k.arg=="token" and isinstance(k.value,ast.Name) and k.value.id=="token" for k in n.keywords) for n in pre_http+post_http))
check("renew_body_empty_object",isinstance(post_http[1].args[3],ast.Dict) and post_http[1].args[3].keys==[])
check("revoke_body_empty_object",isinstance(post_http[3].args[3],ast.Dict) and post_http[3].args[3].keys==[])
check("original_status_403_204_403",all(any(k.arg=="expected" and ast.literal_eval(k.value)==want for k in post_http[idx].keywords) for idx,want in [(0,403),(3,204),(4,403)]))
check("no_loop_sleep_or_deadline_reset_in_new_functions",not any(isinstance(n,(ast.For,ast.While,ast.AsyncFor,ast.Await)) or isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in ("sleep","monotonic","time") for f in (pre,life,snapshot) for n in ast.walk(f)))
check("no_new_http_deadline_override",all(not any(k.arg=="until" for k in n.keywords) for n in pre_http+post_http))
check("pre_accessor_registered_in_secret_guard",any(ast.unparse(n)=="secrets.add(observed['accessor'])" for n in calls(pre,"add","secrets")))
snapshot_return=next(n for n in reversed(snapshot.body) if isinstance(n,ast.Return)).value
public=next(v for k,v in zip(snapshot_return.keys,snapshot_return.values) if ast.literal_eval(k)=="public")
check("snapshot_public_exact_three_fields",set(ast.literal_eval(k) for k in public.keys)=={"ttlSeconds","expiresAtUnix","renewable"})
returned=next(n for n in reversed(life.body) if isinstance(n,ast.Return)).value
expected={"phase","actualTokenCaptured","renewed","revoked","unassignedAndRevokedRequestsRejected","lookupBefore","lookupAfter","renewalLeaseTtlSeconds","sameCredentialAcrossLookupAndRenew","sameAccessorAcrossLookupAndRenew","expiryDeltaSeconds","expiryExtensionObserved","expiryObservation","successfulRenewResponseAloneIsNotExtensionQualification"}
check("lifecycle_public_exact_closed_field_set",set(ast.literal_eval(k) for k in returned.keys)==expected)
check("returned_lifecycle_excludes_private_fields",all(ast.literal_eval(k) not in {"token","accessor","creationTime","id","client_token"} for k in returned.keys))
pre_calls=plain_calls(main,"token_lifecycle_before");kv_calls=plain_calls(main,"canonical_and_inbox");life_calls=plain_calls(main,"token_lifecycle")
check("two_pre_lookup_and_lifecycle_callers",len(pre_calls)==len(kv_calls)==len(life_calls)==2)
check("pre_read_pre_lookup_before_original_kv_before_lifecycle",all(pre_calls[i].lineno<kv_calls[i].lineno<life_calls[i].lineno for i in range(2)))
phases=calls(main,"run_phase","manager")
check("all_original_four_phase_order", [ast.literal_eval(c.args[0]) for c in phases]==["initial","cold-new-process","initial-inverse","cold-new-process-inverse"])
extension_check=next(c for c in plain_calls(main,"check") if isinstance(c.args[0],ast.Constant) and c.args[0].value=="both_actual_renewal_expiries_increased")
finish=calls(main,"finish","manager")[0]
check("both_inverses_and_manager_finish_precede_extension_check",phases[2].lineno<phases[3].lineno<finish.lineno<extension_check.lineno)
life_needs=plain_calls(life,"need")
check("no_delta_qualification_failure_inside_token_chain",all("delta" not in ast.unparse(c) for c in life_needs))
check("final_existing_exception_and_cleanup_body_byte_unchanged",segment("before.py",old["main"]).split("    except BaseException as error:\n",1)[1]==segment("after.py",new["main"]).split("    except BaseException as error:\n",1)[1])
result={"schema":"heptabao.independent-renewal-peer-ast.v1","checks":checks,"checkCount":len(checks),"passed":all(c["passed"] for c in checks),"unchangedDefinitions":unchanged,"publicSnapshotKeys":sorted(ast.literal_eval(k) for k in public.keys),"publicLifecycleKeys":sorted(expected),"operationOrder":routes,"actualScope":{"scratchPublicFileReads":2,"fullModulesParsed":2,"fullModulesCompiledOnly":2,"fullModulesExecuted":0,"selectedFunctionsExecuted":0,"mockCasesRerun":0,"runtimeRequests":0,"sourceModified":False}}
print(json.dumps(result,sort_keys=True,indent=2))
