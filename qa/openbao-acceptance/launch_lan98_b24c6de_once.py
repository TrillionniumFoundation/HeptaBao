#!/usr/bin/env python3
"""One original LAN98 submission, using only actual same-b24 build receipts."""
import argparse,datetime,hashlib,importlib.util,json,os,platform,re,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
parser=argparse.ArgumentParser(description=__doc__)
for name in ("main-summary-sha256","mac-summary-sha256","main-binary-sha256","mac-binary-sha256","main-build-receipt-sha256","mac-build-receipt-sha256"):
 parser.add_argument("--"+name,required=True)
parser.add_argument("--mac-build-receipt-copy",type=Path,required=True)
options=parser.parse_args()
for key,value in vars(options).items():
 if key.endswith("sha256"):assert re.fullmatch("[0-9a-f]{64}",value),"actual_sha256_input_required"
assert (platform.node(),platform.system(),platform.machine())==("qian-qi","Linux","x86_64")
os.umask(0o077)
root=Path("/home/qian-qi/heptabao-next-gates-20261017")
driver=root/"source-b24c6de"
commit="b24c6de7831a7389e39ac069277a9e85e858ef98"
tree="3356f0a94616e9e1804f497239f33546e16db577"
manifest_sha="739ffe3589e8b8c6ddca5efe56b4ef3d33a2633fce4451853413b14a6be6c3e1"
runner_sha="587eb864f424b236fbc98e41fbc26c5e6c8713ded2e3dee0f2230df7447f66dd"
projector_sha="39ea2c6c4414b57cf0b9aa662905db1d3e829108e883fe62435401ed184bc0f0"
manifest_raw=(root/"source-b24c6de-manifest.json").read_bytes()
assert hashlib.sha256(manifest_raw).hexdigest()==manifest_sha
manifest=json.loads(manifest_raw)
assert (manifest["commit"],manifest["tree"],len(manifest["files"]))==(commit,tree,3142)
runner=driver/"qa/openbao-acceptance/native_candidate_host_run.py"
assert hashlib.sha256(runner.read_bytes()).hexdigest()==runner_sha
spec=importlib.util.spec_from_file_location("exact_b24_native55_checker",runner)
checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
source_before=checker.verify_tree(driver,manifest)
projector=driver/"qa/openbao-acceptance/native_build_receipt_from_host_run.py"
assert hashlib.sha256(projector.read_bytes()).hexdigest()==projector_sha
spec=importlib.util.spec_from_file_location("exact_b24_build_receipt_reader",projector)
projection=importlib.util.module_from_spec(spec);spec.loader.exec_module(projection)
def load_build_receipt(path,expected,summary_sha,binary_sha,abi):
 raw=projection.owned_bytes(path,1024*1024)
 assert hashlib.sha256(raw).hexdigest()==expected,"actual_build_receipt_digest_differs"
 value=json.loads(raw);p=value["provenance"]
 assert value["schema"]=="heptabao.native-build.v1" and value["source_commit"]==commit and value["source_tree"]==tree
 assert value["binary_sha256"]==binary_sha and value["native_abi"]==abi and value["build_exit_code"]==0 and value["source_freeze_verified"] is True
 assert p["actual_host_summary_sha256"]==summary_sha and p["actual_manifest_sha256"]==manifest_sha and p["actual_runner_sha256"]==runner_sha
 assert p["source_files_verified_before_and_after"]==3142 and p["original_scoped_host_status"] in ("passed_scoped_host_recovery","failed_or_blocked")
 return value
receipt=root/"native-lan98-preflight-b24c6de-20261019-r1/native-build-receipt.json"
main_receipt=load_build_receipt(receipt,options.main_build_receipt_sha256,options.main_summary_sha256,options.main_binary_sha256,"x86_64-unknown-linux-gnu")
mac_receipt=load_build_receipt(options.mac_build_receipt_copy,options.mac_build_receipt_sha256,options.mac_summary_sha256,options.mac_binary_sha256,"aarch64-apple-darwin")
runtime_paths=['qa/openbao-acceptance/native_v6_ha_direct_lan_live.py', 'qa/openbao-acceptance/native_v6_ha_multihost_live.py', 'qa/openbao-acceptance/native_ha_foreground_watchdog.py', 'qa/openbao-acceptance/ha_multihost_live.py', 'qa/openbao-acceptance/ha_three_host_loopback_live.py', 'qa/openbao-acceptance/native_fixture_recovery.py', 'qa/openbao-acceptance/fixture_mounts.py', 'tools/physical_ha_loopback_mesh.py', 'tools/physical_ha_peer_preflight.py']
source_index={row["path"]:row for row in manifest["files"]}
runtime_files=[]
for name in runtime_paths:
 raw=(driver/name).read_bytes();row=source_index[name]
 assert hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==row["sha"]
 runtime_files.append(dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),git_blob=row["sha"],mode=row["mode"]))
controller=root/"native-lan98-b24c6de-20261019-r1-controller"
controller.mkdir(mode=0o700)
work=controller/"work"
linux="local:"+str(root/"native-full55-b24c6de-main-r1/heptabao-server")
ls=options.main_binary_sha256
mb="/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261018"
mac="macbook-pro:"+mb+"/native-full55-b24c6de-mac-r1/heptabao-server"
ms=options.mac_binary_sha256
args=[sys.executable,"-B",str(driver/"qa/openbao-acceptance/native_v6_ha_direct_lan_live.py"),"--binary-source",linux,"--expected-binary-sha256",ls,
"--node-binary",",".join(["macbook-pro",mac,ms,commit,tree]),"--node-binary",",".join(["rog",linux,ls,commit,tree]),"--node-binary",",".join(["pocket4",linux,ls,commit,tree]),
"--native-build-receipt","macbook-pro,macbook-pro:"+mb+"/native-lan98-preflight-b24c6de-20261019-r1/native-build-receipt.json,"+options.mac_build_receipt_sha256,
"--native-build-receipt","rog,local:"+str(receipt)+","+options.main_build_receipt_sha256,
"--native-build-receipt","pocket4,local:"+str(receipt)+","+options.main_build_receipt_sha256,
"--source-commit",commit,"--source-tree",tree,
"--node","macbook-pro,192.168.0.7,"+mb+"/native-lan98-b24c6de-20261019-r1",
"--node","rog,192.168.0.10,/home/qian-qi/heptabao-native-lan98-b24c6de-20261019-r1",
"--node","pocket4,192.168.0.9,/home/alex/heptabao-native-lan98-b24c6de-20261019-r1",
"--api-port","46230","--raft-port","46231","--work-root",str(work),"--allow-private-lan",
"--darwin-watchdog-python","/opt/homebrew/opt/python@3.14/bin/python3.14",
"--darwin-watchdog-python-sha256","cbf84109626aa1013bbe408fbb9590bd0f1c1548f038b2221c6b8b87de26ca43"]
journal=dict(schema="heptabao.actual-lan98-once-controller.v1",started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),controller_pid=os.getpid(),status="intent_saved",submission_count=0,automatic_retry=False,argv=args,
product_source_commit=commit,product_source_tree=tree,driver_source_commit=commit,driver_source_tree=tree,driver_manifest_sha256=manifest_sha,
driver_git_clean_claimed=False,driver_source_files=runtime_files,driver_full_source_before=source_before,native_build_projector_sha256=projector_sha,
actual_main_summary_sha256=options.main_summary_sha256,actual_mac_summary_sha256=options.mac_summary_sha256,
actual_main_build_receipt_sha256=options.main_build_receipt_sha256,actual_mac_build_receipt_sha256=options.mac_build_receipt_sha256,
actual_main_binary_sha256=ls,actual_mac_binary_sha256=ms,
original_main_host_status=main_receipt["provenance"]["original_scoped_host_status"],original_mac_host_status=mac_receipt["provenance"]["original_scoped_host_status"],
required_direct_checks=98,original_seconds=dict(http=15,read_index=8,listener=45,election=60,quorum_loss=35),production_cutover=False)
def save():
 q=controller/"controller.json"
 with open(q,"w") as f:json.dump(journal,f,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
 q.chmod(0o600)
save()
environment=os.environ.copy();environment["PYTHONDONTWRITEBYTECODE"]="1"
try:
 with open(controller/"stdout.log","xb") as out,open(controller/"stderr.log","xb") as err:
  p=subprocess.Popen(args,cwd=driver,env=environment,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
  journal.update(status="running",submission_count=1,driver_pid=p.pid,driver_pgid=os.getpgid(p.pid));save()
  print(json.dumps({"status":"running","controller":str(controller/"controller.json"),"driver_pid":p.pid,"work_root":str(work)}),flush=True)
  code=p.wait()
 source_after=checker.verify_tree(driver,manifest)
 journal.update(status="completed",driver_exit_code=code,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),driver_full_source_after=source_after,driver_source_unchanged=True)
 for name in ["stdout.log","stderr.log"]:
  data=(controller/name).read_bytes();journal[name]={"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
 save()
except BaseException as error:
 journal.update(status="failed_or_unknown",error_type=type(error).__name__,automatic_retry=False);save();raise
print(json.dumps({"status":"completed","driver_exit_code":code,"controller":str(controller/"controller.json"),"source_unchanged":journal["driver_source_unchanged"]}),flush=True)
sys.exit(code)
