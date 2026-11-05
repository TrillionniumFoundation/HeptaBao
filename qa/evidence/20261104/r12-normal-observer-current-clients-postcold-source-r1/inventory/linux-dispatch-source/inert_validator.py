import ast, hashlib, json, sys, time
start=time.monotonic()
until=start+10.0
raw=sys.stdin.buffer.read(1048577)
assert len(raw)<=1048576
value=json.loads(raw)
assert set(value)=={"source","manifest"}
source=value["source"].encode("utf-8")
manifest=value["manifest"].encode("utf-8")
assert len(source)==45694 and hashlib.sha256(source).hexdigest()=="3f574f0b3a455a3e43ad1433d6ad0777495357c41cd65c5cfb71649fc9f30094"
assert len(manifest)==86481 and hashlib.sha256(manifest).hexdigest()=="3c3900c814ebf3e9a1cd0d58226dd6a99fe0edb0aeb42510c3dd7fe5b528af93"
tree=ast.parse(source,filename="finite_client_inventory_r2.py")
compile(tree,"finite_client_inventory_r2.py","exec",dont_inherit=True)
constants={n.targets[0].id:n.value.value for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and isinstance(n.value,ast.Constant)}
assert constants["MANIFEST_SHA"]==hashlib.sha256(manifest).hexdigest()
assert constants["SCHEMA"]=="heptabao.finite-client-inventory.result.r2"
m=json.loads(manifest)
assert m["limits"]=={"host_seconds":45,"outer_seconds":60,"child_seconds":10,"max_document_bytes":2097152,"max_total_read_bytes":8388608,"max_output_bytes":65536,"max_metadata_observations_per_pass":32,"max_backup_items":16}
expected={"mac":(38,15,7,31,357),"rog":(46,17,4,31,434),"x230":(18,5,6,32,112)}
rows=[]
for name,h in m["hosts"].items():
    by={e["id"]:e for e in h["entries"]}
    assert len(by)==len(h["entries"])==len({e["path"] for e in by.values()})
    seen=[]
    for p in h["passes"]:
        entries=[by[x] for x in p["entry_ids"]]
        parents=set()
        for e in entries:
            parts=e["path"].split("/")[1:-1]
            parents.add("/")
            parents.update("/"+"/".join(parts[:i+1]) for i in range(len(parts)))
        ordered=sorted(parents,key=lambda x:(len(x.split("/")),x))
        assert ordered==p["parents"]
        count=len(parents)*3+sum(2 if e["kind"]=="metadata" else 4 for e in entries)
        assert count==p["planned_observations"]<=32
        seen+=p["entry_ids"]
    assert len(seen)==len(set(seen))==len(by) and set(seen)==set(by)
    actual=(len(by),len(h["passes"]),len(h["queries"]),max(p["planned_observations"] for p in h["passes"]),sum(p["planned_observations"] for p in h["passes"]))
    assert actual==expected[name]
    rows.append({"host":name,"counts":actual})
docker=next(q for q in m["hosts"]["x230"]["queries"] if q["kind"]=="docker")
assert docker["argv"][:4]==["/usr/bin/docker","--host","unix:///var/run/docker.sock","inspect"]
assert time.monotonic()<until
result={"schema":"heptabao.finite-inventory-inert-validation.r1","status":"passed_inert_only","source_sha256":hashlib.sha256(source).hexdigest(),"manifest_sha256":hashlib.sha256(manifest).hexdigest(),"source_compiled_not_executed":True,"host_inventory_read":False,"children_started":False,"files_written":False,"pure_manifest_counts":rows,"new_inert_seconds":10,"new_outer_seconds":60,"elapsed_seconds":time.monotonic()-start,"authority_exit_zero_required":True}
print(json.dumps(result,sort_keys=True),flush=True)
sys.exit(0 if time.monotonic()<until else 1)
