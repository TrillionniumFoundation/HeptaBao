from pathlib import Path
import hashlib,json,os,subprocess,time
os.umask(0o077)
ROOT=Path('/home/qian/heptabao-blocker-closure-r10-49503322-20261104-r1')
SOURCE=ROOT/'source';OUT=ROOT/'evidence/comparison69-r1';ART=ROOT/'artifacts'
HEAD='49503322c7f446e5eb41e7744f1fdbd7f1192ecc';TREE='1d4211f91e1b34a2ed087a3bbef2e2884bac88e9'
BINARY_SHA='67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113'
DRIVER_SHA='fd88ed0b8f1c1010e79f9393dfbf6464cabcac48ece8c6e448a64b7ccc45272e'
MODULES=sorted('core,kv,token,transit,pki,totp,userpass,approle,identity,wrapping,edge_tls,system,operations'.split(','))
def need(x,label):
 if not x:raise RuntimeError(label)
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def save(path,value):
 raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 need(path.read_bytes()==raw,'receipt_readback')
 return hashlib.sha256(raw).hexdigest()
def git(*args):return subprocess.check_output(['/usr/bin/git','-C',str(SOURCE),*args],text=True,timeout=30).strip()
def source():
 return {'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'dirty_including_untracked':bool(git('status','--porcelain')),'binary_sha256':sha(ART/'heptabao-server')}
def main():
 OUT.parent.mkdir(mode=0o700,exist_ok=True);OUT.mkdir(mode=0o700);start=time.monotonic()
 report={'schema':'heptabao.r10-x230-original-comparison69-assessment.v1','ok':False,'execution_host':'x230','full_openbao_compatibility':False,'production_qualified':False,'production_changed':False,'original_modules_unmodified':True,'original_driver_unmodified':True}
 try:
  before=source();need(before=={'commit':HEAD,'tree':TREE,'dirty_including_untracked':False,'binary_sha256':BINARY_SHA},'source_and_binary_pin')
  driver=ROOT/'native271_comparison_final_r1.py';need(sha(driver)==DRIVER_SHA,'original69_driver_pin')
  pins={'native-build.public.json':'0e3d1ae800820d33f0d5369968cbccbab8fa62b077b142f87c9f52b31cd09c77','result.public.json':'75f858b280249dcc981eee3e4340982a58027e8ca40217244ae029bb8e9011ee','transfer.result.public.json':'725f9a7e51a202a2139618b933c55b1f387ef53af61035a3aa59d21394b0669a'}
  for name,pin in pins.items():need(sha(ART/name)==pin,'artifact_provenance_pin')
  oracle=Path('/home/qian/heptabao-official-271-fresh-20261029-r1/bao');archive=oracle.with_name('official-openbao-2.7.1-linux-amd64.tar.gz')
  need(sha(oracle)=='535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea','official_binary_pin')
  need(sha(archive)=='0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243','official_archive_pin')
  need(sha(SOURCE/'qa/openbao-acceptance/acceptance.py')=='8312c400ec5f0946f8a87fb3241bf8db832ddd04763010af7245d6557f55f94d','unchanged_69_acceptance_contract')
  argv=['/usr/bin/python3','-I','-S','-B',str(driver),'--binary',str(ART/'heptabao-server'),'--expected-binary-sha256',BINARY_SHA,'--expected-source-commit',HEAD,'--candidate-source',str(SOURCE),'--work-dir',str(OUT/'private-run'),'--build-log',str(ART/'result.public.json'),'--oracle-version','2.7.1']
  env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C.UTF-8','TZ':'UTC','HB_ORACLE_BINARY':str(oracle),'HB_ORACLE_ARCHIVE':str(archive)}
  intent={'schema':'heptabao.r10-x230-original-comparison69-intent.v1','argv':argv,'env':env,'source_before':before,'driver_sha256':DRIVER_SHA,'normal_receipt_pins':pins,'build_log_argument_is_immutable_normal_build_result_receipt':True,'modules_argument_omitted_to_preserve_original_13_module_default':True,'default_modules':MODULES,'controller_sha256':sha(Path(__file__)),'new_private_fixture_root':str(OUT/'private-run'),'network_scope':'X230 loopback only','full_openbao_compatibility':False,'production_qualified':False}
  report['intent_sha256']=save(OUT/'intent.public.json',intent)
  with (OUT/'run.stdout').open('xb') as so,(OUT/'run.stderr').open('xb') as se:
   p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=so,stderr=se,env=env)
   so.flush();se.flush();os.fsync(so.fileno());os.fsync(se.fileno())
  actual=OUT/'private-run/comparison-bound.json';raw=actual.read_bytes();summary=json.loads(raw)
  fd=os.open(OUT/'summary.public.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
  after=source()
  side_stats={}
  for side in ['candidate_results','oracle_results']:
   rows=summary[side]['cases'];side_stats[side]={'count':len(rows),'passed':sum(x.get('result')=='passed' for x in rows.values()),'not_run':sum(x.get('result')=='not_run' for x in rows.values()),'failed':sum(x.get('result')=='failed' for x in rows.values()),'cleanup':summary[side]['cleanup']['result']}
  report.update(child_exit_code=p.returncode,source_before=before,source_after=after,source_unchanged=before==after,side_stats=side_stats,status=summary.get('status'),cases_match=summary.get('cases_match'),mismatched_cases=summary.get('mismatched_cases'),scope=summary.get('scope'),uncovered=summary.get('uncovered'),owned_cleanup_completed=summary.get('owned_cleanup_completed'),cleanup_errors=summary.get('cleanup_errors'),summary_sha256=hashlib.sha256(raw).hexdigest(),summary_bytes=len(raw),summary_path=str(OUT/'summary.public.json'),elapsed_seconds=round(time.monotonic()-start,3))
  need(p.returncode==0 and summary['status']=='passed_scoped_cases' and summary['cases_match'] is True and summary['mismatched_cases']==[],'original69_scoped_cases_failed')
  need(all(s=={'count':69,'passed':69,'not_run':0,'failed':0,'cleanup':'passed'} for s in side_stats.values()),'original69_case_inventory_or_cleanup')
  need(sorted(summary['scope'])==MODULES and summary['owned_cleanup_completed'] is True and summary['cleanup_errors']==[],'original69_scope_or_owned_cleanup')
  need(before==after and summary['source_and_binary_unchanged'] is True,'source_or_binary_changed')
  need(summary['execution_binding']['runner_source_sha256']==DRIVER_SHA and summary['execution_binding']['candidate_source_sha']==HEAD and summary['execution_binding']['candidate_binary_sha256']==BINARY_SHA,'original69_execution_binding')
  need(summary['full_openbao_compatibility'] is False and summary['production_qualified'] is False,'bounded_scope_not_preserved')
  report['ok']=True
 except Exception as e:
  report['error']=str(e) if isinstance(e,RuntimeError) else type(e).__name__
 digest=save(OUT/'result.public.json',report)
 print(json.dumps({'ok':report['ok'],'error':report.get('error'),'side_stats':report.get('side_stats'),'owned_cleanup_completed':report.get('owned_cleanup_completed'),'receipt':str(OUT/'result.public.json'),'receipt_sha256':digest,'summary_sha256':report.get('summary_sha256')}))
 return 0 if report['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
