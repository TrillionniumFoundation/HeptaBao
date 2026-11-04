#!/usr/bin/env python3
"""Bind the unchanged 31-check full34 runner to the sealed normal R10 build."""
import hashlib,json,os,stat,subprocess,time
from pathlib import Path
SOURCE_TEXT=Path(__file__).read_text()
ROOT=Path('/home/qian/heptabao-blocker-closure-r10-49503322-20261104-r1');REPO=ROOT/'source';OUT=ROOT/'evidence/full34-r1'
HEAD='49503322c7f446e5eb41e7744f1fdbd7f1192ecc';TREE='1d4211f91e1b34a2ed087a3bbef2e2884bac88e9'
PIN='67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113';DRIVER='383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581'
def need(v,c):
 if not v:raise RuntimeError(c)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def save(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  v=memoryview(b)
  while v:
   n=os.write(fd,v);need(n>0,'short_write');v=v[n:]
  os.fsync(fd)
 finally:os.close(fd)
 need(p.read_bytes()==b,'save_readback');fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def enc(x):return (json.dumps(x,sort_keys=True,indent=2)+'\n').encode()
def git(*a):return subprocess.check_output(['/usr/bin/git','-C',str(REPO),*a],text=True).strip()
def source():return {'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'dirty':bool(git('status','--porcelain','--untracked-files=no')),'binary_sha256':sha(ROOT/'artifacts/heptabao-server')}
def main():
 os.umask(0o077);OUT.parent.mkdir(mode=0o700,exist_ok=True);OUT.mkdir(mode=0o700);(OUT/'tmp').mkdir(mode=0o700);start=time.monotonic()
 r={'schema':'heptabao.r10-x230-original-full34-assessment.v1','ok':False,'full_replacement_qualified':False,'production_cutover':False,'production_changed':False,'original_http_seconds':15,'original_migration_seconds':360}
 try:
  before=source();need(before=={'commit':HEAD,'tree':TREE,'dirty':False,'binary_sha256':PIN},'normal_source_and_binary_pin')
  runner=REPO/'qa/openbao-acceptance/kv2_271_lossless_native_live.py';need(sha(runner)==DRIVER,'unchanged_runner_pin');need(sha(REPO/'qa/openbao-acceptance/official_openbao_launcher.py')=='5c11b432e1180fb40394fab382da774cf4171bf51431aab7e5823068cfba01d6','oracle_launcher_pin')
  normal=ROOT/'artifacts/native-build.public.json';build=ROOT/'artifacts/result.public.json'
  need(sha(normal)=='0e3d1ae800820d33f0d5369968cbccbab8fa62b077b142f87c9f52b31cd09c77' and sha(build)=='75f858b280249dcc981eee3e4340982a58027e8ca40217244ae029bb8e9011ee','normal_build_receipt_pins')
  oracle=Path('/home/qian/heptabao-official-271-fresh-20261029-r1/bao');archive=oracle.with_name('official-openbao-2.7.1-linux-amd64.tar.gz')
  need(sha(oracle)=='535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea' and sha(archive)=='0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243','official271_pins')
  argv=['/usr/bin/python3','-I','-S','-B',str(runner),'--binary',str(ROOT/'artifacts/heptabao-server'),'--private-work-root',str(OUT/'private-run'),'--migration-lane','native-large','--profile','full34']
  env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C.UTF-8','TZ':'UTC','TMPDIR':str(OUT/'tmp'),'HB_ORACLE_BINARY':str(oracle),'HB_ORACLE_ARCHIVE':str(archive)}
  save(OUT/'controller.py',SOURCE_TEXT.encode());save(OUT/'intent.public.json',enc({'schema':'heptabao.r10-x230-full34-intent.v1','argv':argv,'source_before':before,'driver_sha256':DRIVER,'original_http_seconds':15,'original_migration_seconds':360,'normal_default_build_verified':True,'default_build_receipt_sha256':sha(normal),'default_build_result_sha256':sha(build),'new_private_synthetic_target':True,'network_scope':'X230 loopback only','full_replacement_qualified':False,'production_cutover':False}))
  with (OUT/'run.stdout').open('xb') as stdout,(OUT/'run.stderr').open('xb') as stderr:
   p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,env=env)
  raw=(OUT/'private-run/summary.json').read_bytes();summary=json.loads(raw);save(OUT/'summary.public.json',raw)
  after=source();checks=summary.get('checks',[]);passed=[x['case'] for x in checks if x.get('passed') is True]
  r.update(child_exit_code=p.returncode,source_before=before,source_after=after,source_unchanged=before==after,checks_total=len(checks),checks_passed=len(passed),full34_qualified=summary.get('full34_qualified') is True,owned_processes_stopped='owned_processes_stopped' in passed,summary_sha256=hashlib.sha256(raw).hexdigest(),summary_bytes=len(raw),reported_status=summary.get('status'),missing_checks=summary.get('missing_checks'),failure=summary.get('failure'),elapsed_seconds=round(time.monotonic()-start,3))
  need(p.returncode==0 and len(checks)==31 and len(passed)==31 and r['full34_qualified'] and r['owned_processes_stopped'] and before==after,'original_full34_not_qualified');r['ok']=True
 except Exception as e:r['error']=str(e) if isinstance(e,RuntimeError) else type(e).__name__
 raw=enc(r);save(OUT/'result.public.json',raw);print(json.dumps({'ok':r['ok'],'checks_passed':r.get('checks_passed'),'checks_total':r.get('checks_total'),'error':r.get('error'),'receipt':str(OUT/'result.public.json'),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}));return 0 if r['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
