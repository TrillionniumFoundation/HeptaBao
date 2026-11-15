import argparse,datetime,hashlib,json,os,re,shlex,subprocess,sys
parser=argparse.ArgumentParser()
parser.add_argument("--capsule-sha256",required=True)
options=parser.parse_args()
assert re.fullmatch("[0-9a-f]{64}",options.capsule_sha256)
from pathlib import Path
os.umask(0o077)
root=Path("/home/qian-qi/heptabao-next-gates-20261017")
capsule=root/"native-artifact55-07a3dda-main-capsule-20261019-r1"
raw=(capsule/"capsule.json").read_bytes()
assert len(raw)<=16*1024*1024 and hashlib.sha256(raw).hexdigest()==options.capsule_sha256
value=json.loads(raw)
assert value["source_commit"]=="07a3dda57c2996787825ced49e630bb0bf7a30b9" and value["source_tree"]=="8c2b23cd1c66ac16b466f16ea97c201e852125aa"
assert all(type(row["bytes"]) is int and row["bytes"]>=0 for row in value["files"])
actual_capsule_bytes=len(raw)+sum(row["bytes"] for row in value["files"])
script=root/"native-linux-artifact-tool-07a3dda-main-r1/native_linux_artifact_run.py"
assert hashlib.sha256(script.read_bytes()).hexdigest()=="45a898ca7f902b4f179ea7035bd17b77fa41e34a9844470597d84bdcd63cf634"
stage=root/"native-artifact55-07a3dda-x230-transfer-20261019-r1";stage.mkdir(mode=0o700)
xb="/home/qian/heptabao-continuation-20261019";xs=xb+"/native-artifact55-07a3dda-executor-20261019-r1-controller"
xc=xb+"/"+capsule.name
journal=dict(schema="heptabao.native-linux-artifact-once-handoff.v2",status="preflight_intent",started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),controller_pid=os.getpid(),source_capsule=str(capsule),source_capsule_sha256=hashlib.sha256(raw).hexdigest(),target_capsule=xc,ssh_alias="x230-ts",automatic_retry=False,operations=[])
def save():
 p=stage/"controller.json"
 with p.open("w") as f:json.dump(journal,f,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def operation(label,args,timeout):
 row={"label":label,"argv":args,"status":"intent_saved","submission_count":1,"timeout":timeout};journal["operations"].append(row);save()
 try:
  result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
  row.update(status="completed",exit_code=result.returncode,stdout=result.stdout[-12000:],stderr=result.stderr[-2000:]);save()
  assert result.returncode==0,label+" failed; inspect preserved controller before any further action"
  return result
 except BaseException as error:
  row.update(status="failed_or_unknown",error_type=type(error).__name__);journal.update(status="failed_or_unknown");save();raise
cfg={"stage":xs,"base":xb,"capsule":xc,"script_sha":"45a898ca7f902b4f179ea7035bd17b77fa41e34a9844470597d84bdcd63cf634","capsule_sha":options.capsule_sha256,"actual_capsule_bytes":actual_capsule_bytes}
preflight="""import json,os,platform,pwd,sys
from pathlib import Path
c=json.loads(sys.argv[1]);b=Path(c["base"]);s=Path(c["stage"]);p=Path(c["capsule"])
assert platform.node()=="qian-ThinkPad-X230" and platform.system()=="Linux" and platform.machine()=="x86_64"
assert os.geteuid()==1000 and pwd.getpwuid(os.geteuid()).pw_dir=="/home/qian"
assert b.resolve()==b and not os.path.lexists(s) and not os.path.lexists(p)
assert (b/"source-07a3dda").is_dir() and (b/"source-07a3dda-manifest.json").is_file()
v=os.statvfs(b);assert v.f_bavail*v.f_frsize>max(2400000000,c["actual_capsule_bytes"])
s.mkdir(mode=0o700)
print(json.dumps(dict(hostname=platform.node(),uid=os.geteuid(),available_bytes=v.f_bavail*v.f_frsize,controller=str(s),capsule_absent=True,actual_capsule_bytes=c["actual_capsule_bytes"])))
"""
operation("x230-fresh-owner-preflight",["ssh","-o","BatchMode=yes","-o","ConnectTimeout=10","x230-ts",shlex.join(["python3","-B","-c",preflight,json.dumps(cfg)])],30)
journal["status"]="transferring_unchanged_capsule";save()
operation("copy-exact-capsule",["scp","-r","-p","-q",str(capsule),"x230-ts:"+xb+"/"],300)
operation("copy-exact-executor",["scp","-p","-q",str(script),"x230-ts:"+xs+"/native_linux_artifact_run.py"],30)
remote="""import datetime,hashlib,json,os,subprocess,sys
from pathlib import Path
os.umask(0o077)
cfg=json.loads(sys.argv[1]);stage=Path(cfg["stage"]);base=Path(cfg["base"]);capsule=Path(cfg["capsule"])
script=stage/"native_linux_artifact_run.py"
assert hashlib.sha256(script.read_bytes()).hexdigest()==cfg["script_sha"]
assert hashlib.sha256((capsule/"capsule.json").read_bytes()).hexdigest()==cfg["capsule_sha"]
args=[sys.executable,"-B",str(script),"execute","--source",str(base/"source-07a3dda"),"--manifest",str(base/"source-07a3dda-manifest.json"),"--source-commit","07a3dda57c2996787825ced49e630bb0bf7a30b9","--source-tree","8c2b23cd1c66ac16b466f16ea97c201e852125aa","--producer-runner-sha256","587eb864f424b236fbc98e41fbc26c5e6c8713ded2e3dee0f2230df7447f66dd","--capsule",str(capsule),"--capsule-sha256",cfg["capsule_sha"],"--expected-executor-hostname","qian-ThinkPad-X230","--output",str(base/"native-artifact55-07a3dda-x230-actual-20261019-r1")]
journal=dict(schema="heptabao.x230-artifact-executor-once.v2",status="intent_saved",started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),argv=args,submission_count=0,automatic_retry=False,compiled_on_executor=False)
def save():
 with (stage/"launch.json").open("w") as f:json.dump(journal,f,indent=2);f.write(chr(10));f.flush();os.fsync(f.fileno())
assert not (stage/"launch.json").exists();save()
with (stage/"stdout.log").open("xb") as so,(stage/"stderr.log").open("xb") as se:
 p=subprocess.Popen(args,cwd=base/"source-07a3dda",stdin=subprocess.DEVNULL,stdout=so,stderr=se,start_new_session=True)
journal.update(status="running",submission_count=1,executor_pid=p.pid,executor_pgid=os.getpgid(p.pid));save()
print(json.dumps(dict(status="running",executor_pid=p.pid,launch=str(stage/"launch.json"),compiled_on_executor=False)),flush=True)
"""
compile(remote,"remote-executor-launch","exec")
journal["status"]="executor_launch_intent";save()
operation("x230-executor-launch-once",["ssh","-o","BatchMode=yes","-o","ConnectTimeout=10","x230-ts",shlex.join(["python3","-B","-c",remote,json.dumps(cfg)])],30)
journal.update(status="executor_launched",finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat());save()
print(json.dumps(dict(status=journal["status"],controller=str(stage/"controller.json"),executor_launch=journal["operations"][-1]["stdout"])),flush=True)

