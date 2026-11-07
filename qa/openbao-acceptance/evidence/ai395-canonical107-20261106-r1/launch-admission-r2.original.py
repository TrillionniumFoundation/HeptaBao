from pathlib import Path
import datetime,hashlib,json,os,platform,re,shutil,stat,subprocess,sys
root=Path('/home/qq/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1')
source=root/'source-4bde9';out=root/'build-test-r1';commit='4bde9aee03fcd27c59e13607e529b1cee594b249'
controller=out/'controller.py';selection=out/'test-selection.public.json'
def need(ok,label):
 if not ok:raise RuntimeError(label)
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
need(platform.node()=='ai395' and platform.machine()=='x86_64' and sys.platform=='linux','exact_admitted_host_required')
need(root.resolve(strict=True)==root and out.resolve(strict=True)==out and stat.S_IMODE(out.stat().st_mode)==0o700,'new_private_owned_output_required')
need(digest(controller)=='2d5237fb1db25e6741f27685f99195f2e35afdeee7aa4b40adc094b0fa34fc1f','approved_controller_pin')
need(digest(selection)=='340e47e620fd963da419a0417a611ec3ba08a544b7962d908640fb14407569f9','approved_selection_pin')
manifest=json.loads(selection.read_bytes())
for value in manifest['old_retained_artifacts'].values():
 p=Path(value['path']);need(p.is_file() and not p.is_symlink() and p.stat().st_size==value['bytes'] and digest(p)==value['sha256'],'current_host_retained_input_pin')
need(not (out/'progress.public.json').exists() and not (out/'result.public.json').exists() and not (out/'artifacts').exists(),'formal_output_must_be_new')
env={'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_OPTIONAL_LOCKS':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'}
def git(*args):return subprocess.check_output(['/usr/bin/git','-C',str(source),*args],env=env,stderr=subprocess.DEVNULL,timeout=15).decode().strip()
need(git('rev-parse','HEAD')==commit and git('rev-parse','HEAD^{tree}')=='f08493a23f8ea0637073651231865ea9607b790e','current_source_identity')
need(not git('status','--porcelain','--untracked-files=all'),'clean_current_source_required')
existing=[];compilers=[]
for base in Path('/home/qq').iterdir():
 if not base.is_dir() or base.is_symlink() or not base.name.lower().startswith('heptabao'):continue
 for directory in base.iterdir():
  if not directory.is_dir() or directory.is_symlink() or not directory.name.startswith('build-test'):continue
  for name in ('progress.public.json','result.public.json'):
   p=directory/name
   if p.is_file() and not p.is_symlink() and p.stat().st_size<1048576:
    value=json.loads(p.read_bytes())
    if value.get('source_commit')==commit:existing.append({'path':str(p),'status':value.get('status')})
for p in Path('/proc').iterdir():
 if not p.name.isdigit() or int(p.name)==os.getpid():continue
 try:
  name=(p/'comm').read_text().strip()
  if name in {'cargo','rustc','rustfmt','rust-lld'}:compilers.append({'pid':int(p.name),'comm':name})
  args=[os.fsdecode(v) for v in (p/'cmdline').read_bytes().split(b'\0') if v]
  for arg in args:
   if not arg.startswith('/home/qq/') or not arg.endswith('controller.py'):continue
   path=Path(arg)
   if path.is_file() and path.stat().st_size<65536 and re.search(r"(?m)^COMMIT\s*=\s*['\"]"+commit+r"['\"]",path.read_text()):
    existing.append({'controller':str(path),'pid':int(p.name),'status':'process_present'})
 except (OSError,ValueError):pass
mem=dict((line.split(':')[0],int(line.split()[1])) for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemAvailable:','SwapFree:')))
resources={'disk_free_bytes':shutil.disk_usage(root).free,'mem_available_kib':mem['MemAvailable'],'swap_free_kib':mem['SwapFree'],'load_average':list(os.getloadavg()),'compiler_processes':compilers}
admitted=not existing and not compilers and resources['disk_free_bytes']>=8*1024**3 and resources['mem_available_kib']>=12*1024**2
decision={'schema':'heptabao.ai395-canonical107-launch-admission.v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'host':'ai395','source_commit':commit,'source_tree':'f08493a23f8ea0637073651231865ea9607b790e','controller_sha256':digest(controller),'selection_sha256':digest(selection),'resources':resources,'other_canonical_campaigns':existing,'admitted_to_one_controller_invocation':admitted,'controller_invocation_planned':admitted,'formal_test_result_not_observed_by_admission':True,'supervisor_timeout_seconds':12000,'controller_original_budget_seconds':12000,'budget_renewed':False,'production_changed':False,'rog_unknown_preparation_replayed':False}
os.umask(0o077)
with (out/'launch-admission-r2.public.json').open('x') as f:json.dump(decision,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
print(json.dumps({'event':'launch_admission','admitted':admitted,'compiler_count':len(compilers),'other_canonical_campaigns':len(existing),'production_changed':False}),flush=True)
need(admitted,'original_resource_or_no_duplicate_gate_not_satisfied')
os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-S','-B',str(controller)])
