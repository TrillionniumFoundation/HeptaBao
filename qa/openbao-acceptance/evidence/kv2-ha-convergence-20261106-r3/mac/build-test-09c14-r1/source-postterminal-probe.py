import hashlib,json,os,subprocess,sys,time
from pathlib import Path
start=time.monotonic()
source=Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/source-09c14-r1")
expected={'head':'09c14eae7a3b52dee8ce3af3175dad5900ac59ec','tree':'dfb0df97a2c74b1c0154f45342f3debb0ce438ab'}
report={'schema':'heptabao.mac-postterminal-source-preservation.v1','source':str(source),'read_only':True,'service_started':False,'test_rerun':False,'checks':{}}
def git(label,args):
 p=subprocess.run(['/usr/bin/git','--no-optional-locks','-c','core.hooksPath=/dev/null',*args],cwd=source,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=False)
 report['checks'][label]={'exit_code':p.returncode,'stderr_bytes':len(p.stderr),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()}
 if p.returncode or p.stderr: raise RuntimeError('git_'+label+'_failed')
 return p.stdout.decode().strip()
try:
 head=git('head',['rev-parse','HEAD']);tree=git('tree',['rev-parse','HEAD^{tree}'])
 clean=git('clean',['status','--porcelain=v1','--untracked-files=all'])
 report.update(head=head,tree=tree,clean=not clean,dirty_entry_count=len(clean.splitlines()))
 report['matches_candidate']=head==expected['head'] and tree==expected['tree'] and not clean
 report['status']='passed' if report['matches_candidate'] else 'failed'
except BaseException as e:
 report.update(status='failed',error_type=type(e).__name__)
finally:
 report['seconds']=round(time.monotonic()-start,6)
 print(json.dumps(report,sort_keys=True),flush=True)
sys.exit(0 if report['status']=='passed' else 1)
