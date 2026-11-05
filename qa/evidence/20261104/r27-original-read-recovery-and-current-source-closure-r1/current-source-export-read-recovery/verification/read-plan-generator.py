import hashlib,json
from pathlib import Path
W=Path("/workspace/scratch/f86faac821c4")
x=json.loads((W/"source4e808_export_result_recovered.json").read_text())
root="/home/qian-qi/heptabao-same-root-publication-source-export-20261105-r1"
rows=[]
for c in x["commands"]:
 label=c["label"]
 record=(json.dumps(c,indent=2,sort_keys=True)+"\n").encode()
 rows.append({"path":root+"/"+label+".public.json","role":"command_record","bytes":len(record),"sha256":hashlib.sha256(record).hexdigest(),"binding":"derived exact expected bytes from recovered original core row and original exporter json.dumps(indent=2,sort_keys=True); not an observed command file"})
 for stream in ("stdout","stderr"):
  rows.append({"path":root+"/"+label+"."+stream,"role":stream,"bytes":c[stream+"_bytes"],"sha256":c[stream+"_sha256"],"binding":"original recovered command row; independent stream file not yet read"})
assert len(rows)==81 and len({r["path"] for r in rows})==81 and all(r["bytes"]<=65536 for r in rows)
bundle={"idempotency_key":"heptabao-4e808-export-5122-bundle-info-r1","operation":{"tool":"file_info","arguments":{"host":"rog","path":root+"/canonical-4e808-full.bundle"}}}
requests=[{"name":"bundle-info","request":bundle}]
batches=[]
for n,at in enumerate(range(0,len(rows),15),1):
 selected=rows[at:at+15]
 req={"idempotency_key":f"heptabao-4e808-export-5122-commandlogs-{n:02d}-r1","operation":{"tool":"read_multiple_files","arguments":{"host":"rog","paths":[r["path"] for r in selected],"max_file_bytes":65536,"max_response_bytes":131072}}}
 requests.append({"name":f"commandlogs-{n:02d}","request":req})
 batches.append({"name":f"commandlogs-{n:02d}","paths":len(selected),"expected_body_bytes":sum(r["bytes"] for r in selected)})
plan={"schema":"heptabao.4e808-export.fixed-public-evidence-read-plan.v1","status":"SOURCE_ONLY_NOT_SUBMITTED_REQUIRES_ROOT_WINDOW","source_core_blob":"0109d7597b2754ee665367177ba1cd3e832d4b34","source_core_sha256":"47feb984dbda306b523071e09107ecade8bda10e712d74e5116a58d164eb027b","bundle_info":{"request":bundle,"reported_expected":x["bundle"],"expected_identity_scope":"Publisher full9 only; actual independent file_info pending. No binding-ready or transport eligibility."},"command_log_rows":rows,"batches":batches,"requests":requests,"rules":["Exactly one fixed bundle file_info, then six fixed small-file batches only after root grants window.","Native file_info computes whole hash; this is not pure stat.","One operation at a time unless root gives an explicit alternate concurrency window; preserve original SDK before parsing and every immutable original result page.","A metadata/read error never triggers product/export replay. Preserve the error and stop; read reconciliation follows same-key/same-ID contracts only when authorized.","read_multiple_files returns independent file versions and whole hashes, not an atomic snapshot across files.","The 27 commands are never rerun; no directory scan, arbitrary path, source mutation, carrier/importer, Cargo or product execution.","No host read has been submitted for any request in this plan."] }
def safe(v):
 if isinstance(v,dict):return{k:safe(w) for k,w in v.items()}
 if isinstance(v,list):return[safe(w) for w in v]
 if type(v) is int and abs(v)>9007199254740991:return str(v)
 return v
print(json.dumps(safe(plan),indent=2,sort_keys=True)+"\n",end="")
