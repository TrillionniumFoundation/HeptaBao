import ast,hashlib,json,sys
from pathlib import PurePosixPath
d=json.loads(sys.argv[1]);s=d["source"];t=ast.parse(s)
def value(n):
 return ast.literal_eval(next(x.value for x in t.body if isinstance(x,ast.Assign) and any(isinstance(v,ast.Name) and v.id==n for v in x.targets)))
g={n:value(n) for n in ("FILES","SOURCE_FILES","CANONICAL","TREE","PARENT","ROOT_COMMIT","CANONICAL_COUNT")}
g.update(json=json,CARRIER=PurePosixPath("/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-phaseb-ingress-observer-source-carrier-r1"),result={})
fn=next(x for x in t.body if isinstance(x,ast.FunctionDef) and x.name=="verify_receipts")
exec(compile(ast.Module(body=[fn],type_ignores=[]),"<exact-provenance-predicate>","exec"),g)
carrier=json.loads(d["carrier"])
observed=[{"name":r["name"],"identity":r["identity"],"same_fd_readback":r["same_fd_readback"]} for r in carrier["receiver"]["files"]]
g["verify_receipts"]({"source-export.result.public.json":d["export"].encode(),"source-carrier.result.public.json":d["carrier"].encode()},observed)
assert g["result"]=={"export_receipt_verified":True,"transport_receipt_verified":True,"raw_input_receipts_unchanged":True}
transfer=value("TRANSFER");assert len(d["carrier"].encode())==transfer["bytes"] and hashlib.sha256(d["carrier"].encode()).hexdigest()==transfer["sha256"]
for item,row in zip(g["FILES"],carrier["receiver"]["files"],strict=True):
 assert item["version"]==":".join(str(row["identity"][i]) for i in (0,1,6,7,8))
 assert item["path"]==row["path"] and item["bytes"]==row["bytes"] and item["sha256"]==row["sha256"]
assert value("ACTUAL_INPUTS_READY") is True
print(json.dumps({"schema":"heptabao.phaseb3cb.bound-importer-actual-receipt-predicate.v1","status":"passed","candidate_bytes":len(s.encode()),"candidate_sha256":hashlib.sha256(s.encode()).hexdigest(),"actual_export_and_carrier_receipts_used":True,"actual_receipt_shape_predicate_passed":True,"two_received_versions_lossless_exact":True,"carrier_whole_hash_exact":True,"held_rows_source":"already captured receiver identity facts for predicate test only","future_local_fd_custody_not_executed":True,"candidate_top_level_executed":False,"filesystem_operations":0,"network_operations":0,"child_processes":0,"actual_import_executed":False},sort_keys=True))
