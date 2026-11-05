import base64,hashlib,json,sys
d=json.loads(sys.argv[1]);req=d["request"];ack=json.loads(d["ack"]);a=json.loads(d["authority"]);streams=json.loads(d["streams"]);files=json.loads(d["files"])["files"];carrier=json.loads(d["carrier"]);checks=[]
def check(n,v):
 assert v,n
 checks.append(n)
job=ack["job"]
check("single_exact_ack",job["args"]==req["args"] and job["executable"]==req["executable"] and job["cwd"]==req["cwd"] and job["idempotency_key"]==req["idempotency_key"] and job["host"]==req["host"] and ack["reused"] is False and ack["launch"]["ok"])
check("authority_succeeded0",a["job_id"]==job["id"] and a["state"]=="succeeded" and a["exit_code"]==0 and a["output_complete"] and a["output_durable"] and not a["timed_out"] and not a["cancelled"])
out={}
for name in ("stdout","stderr"):
 s=streams[name];b=bytes.fromhex(s["bytes_hex"])
 check(name+"_hex_text_eof",s["offset"]==0 and s["eof"] and s["next_offset"]==s["size"]==len(b) and b==s["text"].encode())
 check(name+"_authority_bytes",a["log_bytes"][name]["seen"]==a["log_bytes"][name]["stored"]==len(b) and a["log_synced"][name] and not a["log_truncated"][name] and a["log_errors"][name] is None)
 out[name]=b
check("stderr_empty",out["stderr"]==b"")
r=json.loads(out["stdout"]);receipt=next(f for f in files if f["path"].endswith("/inert-stage.result.public.json"))
check("receipt_original_equals_terminal",json.loads(receipt["text"])==r)
check("prepared_scope",r["status"]=="prepared" and r["python_compile_only"] is True and all(r[k] is False for k in ["source_executed","git_started","compiler_started","service_started","artifact_transfer_started"]))
check("stdin_pin",r["stdin_bytes"]==len(d["carrier"].encode()) and r["stdin_sha256"]==hashlib.sha256(d["carrier"].encode()).hexdigest())
check("three_exact_sources",len(r["files"])==3 and len(files)==4 and set(carrier["files"])=={"sender.py","receiver.py","relay.py"})
for row in r["files"]:
 name=row["path"].split("/")[-1];f=next(x for x in files if x["path"]==row["path"]);raw=base64.b64decode(carrier["files"][name],validate=True);ident=row["identity"]
 check(name+"_whole_bytes",raw==f["text"].encode() and len(raw)==row["bytes"]==f["size"] and hashlib.sha256(raw).hexdigest()==row["sha256"]==f["sha256"])
 check(name+"_custody",row["mode"]=="0600" and row["publication"]=="created" and ident[2]==1000 and ident[4]==33152 and ident[5]==1 and ident[6]==len(raw))
 version=":".join(str(ident[i]) for i in (0,1,6,7,8))
 check(name+"_exact_version",version==f["version"])
check("original_inert_outer60",req["timeout_seconds"]==60)
elapsed=r["terminal_ns"]-r["started_ns"]
check("lossless_positive_elapsed",0<=elapsed<60000000000)
check("all_file_hashes",all(len(f["text"].encode())==f["size"] and hashlib.sha256(f["text"].encode()).hexdigest()==f["sha256"] for f in files))
print(json.dumps({"schema":"heptabao.phaseb3cb.source-carrier-inert-actual-review.v1","status":"passed","checks_passed":len(checks),"checks":checks,"job_id":job["id"],"elapsed_ns_decimal":str(elapsed),"source_count":3,"source_sha256":{x["path"].split("/")[-1]:x["sha256"] for x in r["files"]},"authority_exit_code":0,"stdout_bytes":len(out["stdout"]),"stderr_bytes":0,"actual_transfer_executed":False,"actual_import_executed":False,"product_executed":False},sort_keys=True))
