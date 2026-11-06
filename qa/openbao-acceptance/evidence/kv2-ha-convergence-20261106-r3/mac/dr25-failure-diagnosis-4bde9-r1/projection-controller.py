import json,os,re,signal,stat,sys,time
from pathlib import Path
START=time.monotonic()
WORK=Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/full34-dr25-r1")
REPORT={"schema":"heptabao.dr25-safe-failure-projection.v1","read_only":True,"services_started":False,"test_rerun":False,"private_raw_output_emitted":False}
def alarm(signum,frame):raise TimeoutError()
signal.signal(signal.SIGALRM,alarm);signal.setitimer(signal.ITIMER_REAL,52)
def read_json(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1 or before.st_size>8*1024*1024:raise RuntimeError("private_summary_metadata_rejected")
  chunks=[];total=0
  while True:
   data=os.read(fd,65536)
   if not data:break
   chunks.append(data);total+=len(data)
   if total>8*1024*1024:raise RuntimeError("private_summary_too_large")
  after=os.fstat(fd)
  if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise RuntimeError("private_summary_changed")
  obj=json.loads(b"".join(chunks))
  if not isinstance(obj,dict):raise RuntimeError("private_summary_not_object")
  return obj,{"exists":True,"regular":True,"bytes":total,"owner_uid":before.st_uid,"mode":stat.S_IMODE(before.st_mode),"link_count":before.st_nlink,"stable_while_read":True}
 finally:os.close(fd)
def label(value):
 return value if isinstance(value,str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}",value) else None
def status(value):
 return value if value in ("passed","failed","skipped","held","running","completed","succeeded","error","not_qualified","qualified") else None
def number(value):return value if type(value) in (int,float) else None
def boolean(value):return value if type(value) is bool else None
def numeric_identity(row):
 if not isinstance(row,dict):return {"object":False}
 out={k:row[k] for k in ("pid","ppid","pgid","sid","uid","start_ticks") if type(row.get(k)) is int}
 st=row.get("state")
 if isinstance(st,str) and re.fullmatch(r"[RSDTtXZIEWLNs+<lVs-]{1,10}",st):out["state"]=st
 return out
def members(rows,birth):
 if not isinstance(rows,list):return {"available":False}
 values=[numeric_identity(x) for x in rows]
 return {"available":True,"count":len(rows),"live_descendants":sum(1 for x in values if x.get("pid")!=birth.get("pid") and isinstance(x.get("state"),str) and not x["state"].startswith(("Z","X"))),"identities":values}
def custody(c):
 if not isinstance(c,dict):return {"available":False}
 out={"available":True,"schema":label(c.get("schema")),"platform":label(c.get("platform"))}
 for key in ("passed_process_custody","failed","finished","interrupted"):
  if key in c:out[key]=boolean(c[key])
 if type(c.get("original_count")) is int:out["original_count"]=c["original_count"]
 rows=c.get("children")
 out["children_count"]=len(rows) if isinstance(rows,list) else None
 out["children"]=[]
 if isinstance(rows,list):
  for i,row in enumerate(rows):
   if not isinstance(row,dict):out["children"].append({"index":i,"object":False});continue
   item={"index":i}
   for key in ("exec_admitted","original_wait_completed","no_live_members_before_reap"):
    if key in row:item[key]=boolean(row[key])
   for key in ("original_wait_count","returncode"):
    if key in row:item[key]=number(row[key])
   gaps=row.get("gaps")
   item["gaps_count"]=len(gaps) if isinstance(gaps,list) else None
   birth=numeric_identity(row.get("birth"));item["birth"]=birth
   for key in ("members_at_leader_exit","members_before_original_reap"):item[key]=members(row.get(key),birth)
   out["children"].append(item)
  out["all_children_original_wait_completed"]=all(x.get("original_wait_completed") is True for x in out["children"])
  out["all_children_wait_count_exactly_one"]=all(x.get("original_wait_count")==1 for x in out["children"])
  out["all_children_no_live_members_before_reap"]=all(x.get("no_live_members_before_reap") is True for x in out["children"])
  out["all_children_zero_gaps"]=all(x.get("gaps_count")==0 for x in out["children"])
 return out
def project(name,obj,metadata):
 result={"file_metadata":metadata,"schema":label(obj.get("schema")),"status":status(obj.get("status")),"failure_present":bool(obj.get("failure")),"failure_python_type":type(obj.get("failure")).__name__,"checks":[]}
 checks=obj.get("checks")
 if isinstance(checks,list):
  for row in checks:
   if not isinstance(row,dict):continue
   result["checks"].append({"case":label(row.get("case",row.get("name"))),"passed":boolean(row.get("passed"))})
 result["check_count"]=len(result["checks"])
 result["passed_check_count"]=sum(x["passed"] is True for x in result["checks"])
 result["failed_check_count"]=sum(x["passed"] is False for x in result["checks"])
 for key in ("qualified","baseline_qualified","passed","required_count","observed_count","passed_count","failed_count","expected_count","executed_count","elapsed_seconds","outer_budget_seconds","deadline_seconds","deadline_renewed","timed_out"):
  if key in obj and type(obj[key]) in (int,float,bool):result[key]=obj[key]
 failure=obj.get("failure")
 if isinstance(failure,dict):
  for key in ("type","error_type","exception_type"):
   if failure.get(key) in ("RuntimeError","AssertionError","TimeoutError","OSError","ValueError","KeyError","TypeError","PermissionError","FileNotFoundError"):
    result["failure_exception_type"]=failure[key]
  for key in ("case","label","reason"):
   value=failure.get(key)
   if value in [x["case"] for x in result["checks"]] and value is not None:result["failure_fixed_case"]=value
 elif isinstance(failure,str):
  match=re.match(r"^(RuntimeError|AssertionError|TimeoutError|OSError|ValueError|KeyError|TypeError|PermissionError|FileNotFoundError)(?:\b|:|\()",failure)
  if match:result["failure_exception_type"]=match.group(1)
  if failure in [x["case"] for x in result["checks"]]:result["failure_fixed_case"]=failure
 result["process_custody"]=custody(obj.get("process_custody"))
 if isinstance(obj.get("baseline"),dict):
  result["baseline"]={k:obj["baseline"][k] for k in ("qualified","passed","required_count","passed_count","failed_count","observed_count") if type(obj["baseline"].get(k)) in (bool,int)}
 if name=="dr":
  row=next((x for x in checks if isinstance(x,dict) and x.get("case")=="complete_v6_archive_seal_binding"),None) if isinstance(checks,list) else None
  if row:
   ev=row.get("evidence");ev=ev if isinstance(ev,dict) else {}
   details={};seals=[];present=[]
   for key in ("cli_archive","normal_http_archive"):
    a=ev.get(key);a=a if isinstance(a,dict) else {}
    md=a.get("metadata");md=md if isinstance(md,dict) else {}
    vals={k:(number(md[k]) if k in ("state_bytes","generation") else label(md[k])) for k in ("state_bytes","state_format","format","generation") if k in md}
    mem=a.get("members")
    vals["members"]=[]
    if isinstance(mem,list):
     for member in mem:
      if isinstance(member,dict):
       nm=member.get("name")
       if isinstance(nm,str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,127}",nm) and ".." not in nm.split("/"):
        vals["members"].append({"name":nm,"bytes":number(member.get("bytes",member.get("size")))})
    details[key]=vals;present.append("seal_identity" in md and md["seal_identity"] is not None);seals.append(md.get("seal_identity"))
   details["seal_identity_both_present"]=all(present)
   details["seal_identity_equal"]=seals[0]==seals[1] if all(present) else None
   result["archive_gate_safe_subobservations"]=details
 return result
try:
 for name,relative in (("dr","dr25-summary.json"),("baseline","baseline/summary.json")):
  try:
   obj,meta=read_json(WORK/relative)
   REPORT[name]=project(name,obj,meta)
  except BaseException as exc:
   REPORT[name]={"projection_error_type":type(exc).__name__}
 REPORT["projection_complete"]=all("projection_error_type" not in REPORT.get(k,{}) for k in ("dr","baseline"))
except BaseException as exc:REPORT["projection_error_type"]=type(exc).__name__
finally:
 signal.setitimer(signal.ITIMER_REAL,0)
 REPORT["elapsed_seconds"]=round(time.monotonic()-START,6)
 print(json.dumps(REPORT,sort_keys=True),flush=True)
sys.exit(0 if REPORT.get("projection_complete") else 1)
