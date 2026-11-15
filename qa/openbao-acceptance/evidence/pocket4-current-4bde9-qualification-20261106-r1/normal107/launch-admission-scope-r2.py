from pathlib import Path
import datetime,hashlib,json,os,platform,re,shutil,stat,subprocess,sys
root=Path('/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1')
source=root/'source-4bde9';out=root/'build-test-r1';commit='4bde9aee03fcd27c59e13607e529b1cee594b249'
controller=out/'controller.py';selection=out/'test-selection.public.json'
def need(ok,label):
 if not ok:raise RuntimeError(label)
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
need(platform.node()=='alex-G1628-04' and platform.machine()=='x86_64' and sys.platform=='linux','exact_admitted_host_required')
need(root.resolve(strict=True)==root and out.resolve(strict=True)==out and stat.S_IMODE(out.stat().st_mode)==0o700,'new_private_owned_output_required')
need(digest(controller)=='c8ef09b133312149eecc1886322cc96dcecda18c637b0db9fc3a5e917b3f6564','approved_controller_pin')
need(digest(selection)=='869feff2d8672fe37a26a2fb671cdc853b3c9d7f889edfe76650eed8103f44e9','approved_selection_pin')
manifest=json.loads(selection.read_bytes())
for value in manifest['old_retained_artifacts'].values():
 p=Path(value['path']);need(p.is_file() and not p.is_symlink() and p.stat().st_size==value['bytes'] and digest(p)==value['sha256'],'current_host_retained_input_pin')
need(not (out/'progress.public.json').exists() and not (out/'result.public.json').exists() and not (out/'artifacts').exists(),'formal_output_must_be_new')
env={'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_OPTIONAL_LOCKS':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'}
def git(*args):return subprocess.check_output(['/usr/bin/git','-C',str(source),*args],env=env,stderr=subprocess.DEVNULL,timeout=15).decode().strip()
need(git('rev-parse','HEAD')==commit and git('rev-parse','HEAD^{tree}')=='f08493a23f8ea0637073651231865ea9607b790e','current_source_identity')
need(not git('status','--porcelain','--untracked-files=all'),'clean_current_source_required')
existing=[];compilers=[];process_observation_errors=[]
receipt_roots=(root,)
for base in receipt_roots:
 need(base.is_dir() and not base.is_symlink() and base.stat().st_uid==os.getuid(),'owned_current_receipt_root')
 for directory in base.iterdir():
  if not directory.is_dir() or directory.is_symlink() or not directory.name.startswith('build-test'):continue
  for name in ('progress.public.json','result.public.json'):
   p=directory/name
   if p.is_file() and not p.is_symlink() and p.stat().st_size<1048576:
    value=json.loads(p.read_bytes())
    if value.get('source_commit')==commit:
     existing.append({'path':str(p),'status':value.get('status')})
for p in Path('/proc').iterdir():
 if not p.name.isdigit() or int(p.name)==os.getpid():continue
 try:
  name=(p/'comm').read_text().strip()
  if name in {'cargo','rustc','rustfmt','rust-lld'}:compilers.append({'pid':int(p.name),'comm':name})
  args=[os.fsdecode(v) for v in (p/'cmdline').read_bytes().split(b'\0') if v]
  for arg in args:
   if not arg.startswith('/home/alex/') or not arg.endswith('controller.py'):continue
   path=Path(arg)
   try:
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size>=65536:
     process_observation_errors.append({'pid':int(p.name),'controller':str(path),'error_type':'UninspectableActiveControllerSource'})
    elif re.search(r"(?m)^COMMIT\s*=\s*['\"]"+commit+r"['\"]",path.read_text()):
     existing.append({'controller':str(path),'pid':int(p.name),'status':'process_present'})
   except OSError as error:
    if p.exists():process_observation_errors.append({'pid':int(p.name),'controller':str(path),'error_type':type(error).__name__})
 except (FileNotFoundError,ProcessLookupError):pass
 except (OSError,ValueError) as error:
  process_observation_errors.append({'pid':int(p.name),'error_type':type(error).__name__})
mem=dict((line.split(':')[0],int(line.split()[1])) for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemAvailable:','SwapFree:')))
resources={'disk_free_bytes':shutil.disk_usage(root).free,'mem_available_kib':mem['MemAvailable'],'swap_free_kib':mem['SwapFree'],'load_average':list(os.getloadavg()),'compiler_processes':compilers}
admitted=not existing and not compilers and not process_observation_errors and resources['disk_free_bytes']>=8*1024**3 and resources['mem_available_kib']>=12*1024**2
decision={'schema':'heptabao.pocket4-canonical107-launch-admission.v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'host':'pocket4','source_commit':commit,'source_tree':'f08493a23f8ea0637073651231865ea9607b790e','controller_sha256':digest(controller),'selection_sha256':digest(selection),'resources':resources,'other_canonical_campaigns':existing,'receipt_scan_roots':[str(p) for p in receipt_roots],'process_scan_scope':'whole visible /proc; original compiler comm set and original current-COMMIT controller argv rule','process_observation_errors':process_observation_errors,'prior_admission_job':{'job_id':'1a1b229e173-fc05-7cbe','observed_authoritative_state':'failed','exit_code':1,'controller_invoked':False,'source_sha256':'ad3c5e84ca0959337797a9e0990ab9a1bb16ab56404fa024f62a533ac05cca86'},'admitted_to_one_controller_invocation':admitted,'controller_invocation_planned':admitted,'formal_test_result_not_observed_by_admission':True,'supervisor_timeout_seconds':12000,'controller_original_budget_seconds':12000,'budget_renewed':False,'production_changed':False,'rog_unknown_preparation_replayed':False}
os.umask(0o077)
with (out/'launch-admission-r2.public.json').open('x') as f:json.dump(decision,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
print(json.dumps({'event':'launch_admission','admitted':admitted,'compiler_count':len(compilers),'other_canonical_campaigns':len(existing),'production_changed':False}),flush=True)
need(admitted,'original_resource_or_no_duplicate_gate_not_satisfied')
os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-S','-B',str(controller)])
