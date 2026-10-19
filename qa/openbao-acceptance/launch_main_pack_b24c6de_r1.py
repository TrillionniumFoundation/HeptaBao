import argparse,datetime,hashlib,json,os,re,subprocess,sys
parser=argparse.ArgumentParser()
parser.add_argument("--summary-sha256",required=True)
options=parser.parse_args()
assert re.fullmatch("[0-9a-f]{64}",options.summary_sha256)
os.umask(0o077)
from pathlib import Path
root=Path("/home/qian-qi/heptabao-next-gates-20261017")
raw=(root/"source-b24c6de/qa/openbao-acceptance/native_linux_artifact_run.py").read_bytes()
summary_path=root/"native-full55-b24c6de-main-r1/summary.json"
assert hashlib.sha256(summary_path.read_bytes()).hexdigest()==options.summary_sha256
assert len(raw)==46980 and hashlib.sha256(raw).hexdigest()=="45a898ca7f902b4f179ea7035bd17b77fa41e34a9844470597d84bdcd63cf634"
stage=root/"native-linux-artifact-tool-b24c6de-main-r1";stage.mkdir(mode=0o700)
script=stage/"native_linux_artifact_run.py"
with open(script,"xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
script.chmod(0o600)
out=root/"native-artifact55-b24c6de-main-capsule-20261019-r1"
args=[sys.executable,"-B",str(script),"pack","--source",str(root/"source-b24c6de"),"--manifest",str(root/"source-b24c6de-manifest.json"),"--source-commit","b24c6de7831a7389e39ac069277a9e85e858ef98","--source-tree","3356f0a94616e9e1804f497239f33546e16db577","--producer-runner-sha256","587eb864f424b236fbc98e41fbc26c5e6c8713ded2e3dee0f2230df7447f66dd","--summary",str(root/"native-full55-b24c6de-main-r1/summary.json"),"--summary-sha256",options.summary_sha256,"--target-dir",str(root/"native55-target-20261019"),"--output",str(out)]
j=dict(schema="heptabao.native-linux-producer-once-controller.v1",status="intent_saved",argv=args,submission_count=0,automatic_retry=False,script_sha256=hashlib.sha256(raw).hexdigest(),started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),controller_pid=os.getpid())
def save():
 p=stage/"pack-controller.json"
 with open(p,"w") as f:json.dump(j,f,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
 p.chmod(0o600)
save()
with open(stage/"pack.stdout.log","xb") as so,open(stage/"pack.stderr.log","xb") as se:
 p=subprocess.Popen(args,cwd=stage,stdin=subprocess.DEVNULL,stdout=so,stderr=se,start_new_session=True)
 j.update(status="running",submission_count=1,packer_pid=p.pid);save()
 print(json.dumps({"status":"running","packer_pid":p.pid,"controller":str(stage/"pack-controller.json")}),flush=True)
 code=p.wait()
j.update(status="completed",exit_code=code,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
for name in ["pack.stdout.log","pack.stderr.log"]:
 b=(stage/name).read_bytes();j[name]={"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
if (out/"capsule.json").is_file():
 b=(out/"capsule.json").read_bytes();j["capsule"]={"path":str(out/"capsule.json"),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
save()
print(json.dumps({"status":"completed","exit_code":code,"capsule":j.get("capsule")}),flush=True);sys.exit(code)


