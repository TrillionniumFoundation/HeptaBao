from pathlib import Path
import json,os,subprocess
source=Path('/home/alex/heptabao-replacement-unified-20261105-r5/source')
out=Path('/home/alex/heptabao-pocket4-normal107-readonly-preflight-20261106-r1/source-ancestry.public.json')
env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','GIT_OPTIONAL_LOCKS':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'}
p=subprocess.run(['/usr/bin/git','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-C',str(source),'log','--max-count=96','--format=%H'],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
assert p.returncode==0 and not p.stderr
commits=p.stdout.decode().splitlines();assert commits and commits[0]=='1f188df0f2affebb92702222e9fe5dfb4712194c'
r={'schema':'heptabao.pocket4-source-ancestry-readonly.v1','source':str(source),'commits':commits,'rust_compilation_executed':False,'production_changed':False}
os.umask(0o077)
with out.open('x') as f:json.dump(r,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
print(json.dumps({'result':str(out),'count':len(commits)}),flush=True)
