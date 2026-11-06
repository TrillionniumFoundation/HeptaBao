"""Prepare only a new canonical source; no Rust build or Bao service execution."""
from pathlib import Path
import hashlib,json,os,stat,subprocess,sys,time
os.umask(0o077)
ROOT=Path('/home/qian-qi/heptabao-kv2-ha-convergence-20261106-r1')
OLD=ROOT/'source-09c14-r8'
SOURCE=ROOT/'source-6d456-r9'
OUT=ROOT/'build-test-r9'
COMMIT='6d4562e75d72bcd71d13addb72174440a87e8041'
TREE='ad2a5d2bd8c54c25d32917f391015b47b83990f0'
BASE='09c14eae7a3b52dee8ce3af3175dad5900ac59ec'
BASE_TREE='dfb0df97a2c74b1c0154f45342f3debb0ce438ab'
TEST='crates/heptabao-server/src/service_native_jwt_tests.rs'
ENV={'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_OPTIONAL_LOCKS':'0',
     'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0'}
START=time.monotonic()
REPORT={'schema':'heptabao.rog-canonical-source-preparation.v1','status':'running',
        'source_commit':COMMIT,'source_tree':TREE,'source':str(SOURCE),'base_source':str(OLD),
        'no_hardlinks':False,'steps':[],'production_changed':False,'rust_build_executed':False,
        'formal_107_qualified':False,'full_replacement_qualified':False,'automatic_retry':False}
def need(ok,label):
 if not ok: raise RuntimeError(label)
def digest(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def run(label,args,cap):
 so=OUT/(label+'.stdout');se=OUT/(label+'.stderr')
 started=time.monotonic()
 with so.open('xb') as out,se.open('xb') as err:
  p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=ENV,timeout=cap,cwd=OUT)
  out.flush();err.flush();os.fsync(out.fileno());os.fsync(err.fileno())
 REPORT['steps'].append({'label':label,'argv':args,'original_cap_seconds':cap,'exit_code':p.returncode,
   'seconds':round(time.monotonic()-started,6),'stdout_sha256':digest(so),'stderr_sha256':digest(se)})
 need(p.returncode==0,label+'_failed')
 return so.read_text().strip()
def git(source,*args):
 return subprocess.check_output(['/usr/bin/git','-C',str(source),*args],env=ENV,stderr=subprocess.DEVNULL,timeout=15).decode().strip()
def old_state():
 return {'commit':git(OLD,'rev-parse','HEAD'),'tree':git(OLD,'rev-parse','HEAD^{tree}'),
         'clean':not bool(git(OLD,'status','--porcelain','--untracked-files=all')),
         'test_file_sha256':digest(OLD/TEST)}
try:
 need(not os.path.lexists(SOURCE),'new_source_required')
 need(OUT.resolve(strict=True)==OUT and stat.S_IMODE(OUT.stat().st_mode)==0o700,'owned_private_control_required')
 need(not (OUT/'result.public.json').exists() and not (OUT/'progress.public.json').exists(),'formal_attempt_not_started')
 before=old_state()
 need(before['commit']==BASE and before['tree']==BASE_TREE and before['clean'],'clean_original_09_source_required')
 REPORT['base_source_before']=before
 original={'controller.py':'56b4696cc252d50d3ddeb9edad90465654e011045d2e3d9feba5919d42247c7f',
           'test-selection.public.json':'d7f6d0971e7a6b3e0096e50a1e3d607bff851ce2295563ad068b80adf2294bfd',
           'result.public.json':'9cf27fbf78f3f976fb6397a693b1fa18ec3965bbea84d58cb0f8773aa4f2a5ff'}
 for name,pin in original.items(): need(digest(ROOT/'build-test-r8'/name)==pin,'original_r8_input_changed')
 bundle=OUT/'candidate.bundle'
 need(bundle.stat().st_size==182406 and digest(bundle)=='a4215353a3db4a2a8fea4611d732c384df81543498d7fb17fb1bbd4bbe1ca35c','bundle_pin')
 run('prepare-clone09',['/usr/bin/git','clone','--no-hardlinks','--no-local','--no-checkout',str(OLD),str(SOURCE)],180)
 need(git(SOURCE,'rev-parse',BASE+'^{tree}')==BASE_TREE,'cloned_base_tree_mismatch')
 run('prepare-bundle-verify',['/usr/bin/git','-C',str(SOURCE),'bundle','verify',str(bundle)],30)
 run('prepare-fetch',['/usr/bin/git','-C',str(SOURCE),'fetch',str(bundle),'HEAD'],30)
 need(git(SOURCE,'rev-parse','FETCH_HEAD')==COMMIT,'fetched_commit_mismatch')
 run('prepare-checkout',['/usr/bin/git','-C',str(SOURCE),'checkout','--detach',COMMIT],30)
 run('prepare-fsck',['/usr/bin/git','-C',str(SOURCE),'fsck','--full','--strict'],60)
 need(git(SOURCE,'rev-parse','HEAD')==COMMIT and git(SOURCE,'rev-parse','HEAD^{tree}')==TREE,'candidate_identity_mismatch')
 need(git(SOURCE,'rev-parse','HEAD^')=='552f0142176e7999b3641ae0888da1ac5e310866','candidate_parent_mismatch')
 need(not git(SOURCE,'status','--porcelain','--untracked-files=all'),'candidate_source_dirty')
 need(digest(SOURCE/TEST)=='02272a5a0ec5fec7799cd7650e1626c4a3bc5de34c264cffbd8c587936785e88','candidate_test_file_mismatch')
 changed=git(SOURCE,'diff','--name-only',BASE,COMMIT).splitlines()
 product=[name for name in changed if not name.startswith(('qa/','docs/'))]
 need(product==[TEST],'unexpected_product_scope')
 objects=[p for p in (SOURCE/'.git/objects').rglob('*') if p.is_file()]
 need(objects and all(not p.is_symlink() and p.stat().st_nlink==1 for p in objects),'object_hardlink_refused')
 REPORT['no_hardlinks']=True
 REPORT['base_source_after']=old_state()
 need(REPORT['base_source_after']==before,'original_source_changed')
 for name,pin in original.items():need(digest(ROOT/'build-test-r8'/name)==pin,'original_r8_input_changed_after')
 REPORT.update(status='passed',source_at_exact_published_commit=True,source_clean=True,
   source_parent='552f0142176e7999b3641ae0888da1ac5e310866',product_changed=product,
   changed_test_sha256=digest(SOURCE/TEST),old_failed_receipt_preserved=True,old_source_09_preserved=True,
   original_r8_pins=original,bundle_sha256=digest(bundle))
except BaseException as error:
 REPORT['status']='failed'
 REPORT['failure']=str(error) if isinstance(error,RuntimeError) else type(error).__name__
finally:
 REPORT['elapsed_seconds']=round(time.monotonic()-START,6)
 REPORT['finished_at_unix']=time.time()
 REPORT['preparation_script_sha256']=digest(Path(__file__))
 path=OUT/'preparation.result.public.json'
 with path.open('x') as f:
  json.dump(REPORT,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 print(json.dumps({'status':REPORT['status'],'source_commit':COMMIT,'source_tree':TREE,
                   'rust_build_executed':False,'result':str(path)}),flush=True)
sys.exit(0 if REPORT['status']=='passed' else 1)
