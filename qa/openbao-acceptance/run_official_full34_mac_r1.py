import sys,os,json,hashlib,pathlib,subprocess,importlib.util,time,signal,datetime
sys.dont_write_bytecode=True
os.umask(0o077)
root=pathlib.Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261018')
plain=root/'source-b24c6de';source=root/'source-b24c6de-object-git'
manifest_raw=(root/'source-b24c6de-manifest.json').read_bytes()
assert hashlib.sha256(manifest_raw).hexdigest()=='739ffe3589e8b8c6ddca5efe56b4ef3d33a2633fce4451853413b14a6be6c3e1'
manifest=json.loads(manifest_raw)
runner=plain/'qa/openbao-acceptance/native_candidate_host_run.py'
assert hashlib.sha256(runner.read_bytes()).hexdigest()=='587eb864f424b236fbc98e41fbc26c5e6c8713ded2e3dee0f2230df7447f66dd'
spec=importlib.util.spec_from_file_location('r5_full34_source_checker',runner);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
before=mod.verify_tree(plain,manifest)
built_raw=(root/'native-full55-b24c6de-mac-r1/summary.json').read_bytes();built=json.loads(built_raw)
assert hashlib.sha256(built_raw).hexdigest()=='2aabd021e20e5de6e640e4a88e1496dafb7e0a25d0a14de10a8efad9e322c79a'
assert built['status']=='passed_scoped_host_recovery' and built['runner_completed'] and built['source_unchanged']
assert built['source_commit']==manifest['commit'] and built['source_tree']==manifest['tree']
expected={x[0]:x[3] for x in mod.GROUPS}
actual={c['label']:c for c in built['commands'] if c['label'] in expected}
assert set(actual)==set(expected) and sum(expected.values())==55
for label,count in expected.items():
 c=actual[label];assert c['status']=='passed' and c['exit_code']==0 and c['expected_count']==count and len(c['selected_test_names'])==count
binary=root/'native-full55-b24c6de-mac-r1/heptabao-server'
br=next(c for c in built['commands'] if c['label']=='build-server')
assert br['binary_sha256']=='648698fdab9eedf33f0056a8d844ecfc34e9b401e0435ccd4dbca66f4b4b2ea4'
assert br['status']=='passed' and br['binary']==str(binary) and binary.stat().st_size==br['binary_bytes'] and mod.digest_file(binary)==br['binary_sha256']
driver=source/'qa/openbao-acceptance/kv2_271_lossless_native_live.py'
assert mod.digest_file(driver)=='83d9436f321b380f44504829c426ccf5d3e52830b223f584a84d5237b9c2323d'
env=os.environ.copy()
for k in list(env):
 if k.startswith('HB_ORACLE_') or k in ('PYTHONPATH','PYTHONHOME'):env.pop(k,None)
env.update(PYTHONDONTWRITEBYTECODE='1',PATH='/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
def git(*args):
 return subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null',*args],cwd=source,env=env,capture_output=True,check=True,timeout=30).stdout
assert git('rev-parse','HEAD').decode().strip()==manifest['commit']
assert git('rev-parse','HEAD^{tree}').decode().strip()==manifest['tree']
assert git('status','--porcelain','--untracked-files=all')==b''
oracle=root.parent/'official-openbao-271-macos-20261016'
bao=oracle/'bao';archive=oracle/'oracle-official.tar.gz'
assert bao.is_file() and not bao.is_symlink() and mod.digest_file(bao)=='50c3588e64271171cc2147bddeace8ec2b6742f94fd3fe53baa60f6d938cda0c'
assert archive.is_file() and not archive.is_symlink() and mod.digest_file(archive)=='15625b5f69aee5bb4578b4e76e856a2141647342b0f8e5969a8875b44e0fbf91'
env.update(HB_ORACLE_BINARY=str(bao),HB_ORACLE_ARCHIVE=str(archive))
control=root/'official271-full34-b24c6de-mac-r1-controller';control.mkdir(mode=0o700)
work=root/'official271-full34-b24c6de-mac-r1';assert not os.path.lexists(work)
argv=[sys.executable,'-B',str(driver),'--binary',str(binary),'--private-work-root',str(work),'--profile','full34','--migration-lane','native-large']
intent={'schema':'heptabao.actual-official271-full34-controller.v1','created_utc':mod.utc(),'source_commit':manifest['commit'],'source_tree':manifest['tree'],'source_manifest_sha256':hashlib.sha256(manifest_raw).hexdigest(),'completed_native55_summary_sha256':hashlib.sha256(built_raw).hexdigest(),'driver_sha256':mod.digest_file(driver),'binary_sha256':br['binary_sha256'],'oracle_binary_sha256':mod.digest_file(bao),'oracle_archive_sha256':mod.digest_file(archive),'argv':argv,'submission_count':1,'automatic_retry':False,'production_mutation':False}
mod.write_json(control/'intent.json',intent)
with (control/'stdout.log').open('xb') as stdout,(control/'stderr.log').open('xb') as stderr:
 child=subprocess.Popen(argv,cwd=source,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
 receipt={**intent,'status':'running','pid':child.pid,'pgid':os.getpgid(child.pid),'started_utc':mod.utc()}
 mod.write_json(control/'controller.json',receipt)
 code=child.wait()
 receipt.update(status='completed',exit_code=code,finished_utc=mod.utc(),owned_child_reaped=True)
 receipt['stdout_sha256']=mod.digest_file(control/'stdout.log');receipt['stderr_sha256']=mod.digest_file(control/'stderr.log')
 receipt['source_after']=mod.verify_tree(plain,manifest)
 receipt['git_source_unchanged']=(git('status','--porcelain','--untracked-files=all')==b'' and git('rev-parse','HEAD').decode().strip()==manifest['commit'])
 if (work/'summary.json').is_file():
  rr=(work/'summary.json').read_bytes();result=json.loads(rr);receipt['summary_sha256']=hashlib.sha256(rr).hexdigest();receipt['fixture_status']=result.get('status');receipt['full34_qualified']=result.get('full34_qualified');receipt['passed_checks']=sum(c.get('passed') is True for c in result.get('checks',[]));receipt['failure']=result.get('failure')
 mod.write_json(control/'controller.json',receipt)
print(json.dumps({k:receipt.get(k) for k in ('status','exit_code','fixture_status','full34_qualified','passed_checks','failure','summary_sha256','git_source_unchanged')}),flush=True)

