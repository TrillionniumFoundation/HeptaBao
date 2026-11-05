import base64,hashlib,json,sys
d=json.loads(sys.argv[1]);rows=[]
p=json.loads(d["carrier"]);assert set(p)=={"schema","files"} and p["schema"]=="heptabao.phaseb3cb-source-carrier-inputs.v1"
assert set(p["files"])=={"sender.py","receiver.py","relay.py"}
for name,encoded in p["files"].items():
 raw=base64.b64decode(encoded,validate=True)
 assert raw==d["sources"][name].encode()
 assert len(raw)==d["pins"][name][0] and hashlib.sha256(raw).hexdigest()==d["pins"][name][1]
 rows.append({"case":"inert_carrier_exact_"+name,"accepted":True})
print(json.dumps({"schema":"heptabao.phaseb3cb.source-carrier-predicate-components.v1","status":"passed","checks_passed":len(rows),"cases":rows,"candidate_top_level_executed":False,"selected_pure_receipt_assertions_executed":False,"network":False,"filesystem":False,"child_processes":False,"actual_transport_tested":False},sort_keys=True))