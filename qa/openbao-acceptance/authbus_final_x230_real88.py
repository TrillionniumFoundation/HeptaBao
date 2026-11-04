#!/usr/bin/env python3
"""Rebind the original real-credential 88 assertions to final normal candidate.

The original runner, source contract, actual Node child and transport criteria
remain unchanged. Only five literal version/build bindings change. Preparation
does no server or provider I/O. Execution needs a fresh captured ROG credential.
"""
import hashlib, json, os, stat, subprocess, sys, time
from pathlib import Path

ROOT = Path('/home/qian/heptabao-authbus-real88-36076-20261104-r1')
CANDIDATE = Path('/home/qian/heptabao-blocker-closure-20261104-r2')
REPO = CANDIDATE / 'source'
OLD = Path('/home/qian/heptabao-release-candidate-20261104-c138-r1/evidence/real88-r1')
HEAD = '36076db5f5afe00db75eba9b607dee7802dae554'
TREE = 'ae71c4b243afd4099db66e7d9882b3f28c777a95'
BINARY = '3d9fdf79e26abf4c33fa57568ae7a4c88c79c5def569d92d571c639b855f3df8'
BUILD = '68c2adac6ad5718cf3a4c21b445140b00fef9e53e2cdc041cd83c0b8957424d1'
BUILD_PATH = CANDIDATE / 'artifacts/native-build-result.main.public.json'
PINS = {'bounded-outbox.js':'77c86c49fca655d1c60112ce36ac9c3ef154f620b3e917f42ffa412307de9fa1', 'private-outbox-store.js':'e948edb2d461eedabd03e0acd83cc8b998553516e01ad41c16641360221c145d', 'production-client.js':'0dc35bf575c1933272a4c3351bb07d37358748d7add968d1c577755477a97ea2', 'strict-bao-client.js':'3c226b335257ff67c4f6e23091468d99cba97399eea40b396bb89a8e691e5294'}
PAIRS = [('0aed63910a14662ef1099c4de3572118aff01afb8d9644421cc66c53055c8b2e', BINARY, 1), ('c138ff874af70eb96cd369cb21fd37caea190f42', HEAD, 2), ('34719a51ad942d3bc839df3d78524e9cf4326f30', TREE, 1), ('e420cd3f84061b34faf96cf96f3616d69f1072af7639f38d4ea03f7bc3c9674b', BUILD, 1)]

class Refused(Exception): pass
def need(v,c):
    if not v: raise Refused(c)
def digest(b): return hashlib.sha256(b).hexdigest()
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''): h.update(b)
    return h.hexdigest()
def enc(v): return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def save(p,b):
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f: f.write(b); f.flush(); os.fsync(f.fileno())
    need(p.read_bytes()==b,'save_readback')
def code(p,pin):
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and not s.st_mode&0o022 and s.st_size<200000,'code_custody')
        b=os.read(fd,200000);need(digest(b)==pin and p.stat().st_ino==s.st_ino and p.stat().st_mtime_ns==s.st_mtime_ns,'code_pin');return b
    finally:os.close(fd)
def git(*args):return subprocess.check_output(['/usr/bin/git','-C',str(REPO),*args],text=True).strip()
def source():return {'head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'tracked_dirty':bool(git('status','--porcelain','--untracked-files=no'))}
def verify():
    need(source()=={'head':HEAD,'tree':TREE,'tracked_dirty':False},'candidate_source_pin')
    need(sha(CANDIDATE/'artifacts/heptabao-server')==BINARY,'normal_binary_pin')
    need(sha(BUILD_PATH)==BUILD,'normal_build_receipt_pin')
    need(sha('/usr/bin/node')=='fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48','node_pin')
def prepare():
    verify()
    original=code(OLD/'scripts/real_lifecycle_live.py','15a570d8e2415c68f0be1e15518cc1a0e51172560590c71c1c6c604ab8065145').decode()
    current=original
    for old,new,count in PAIRS:
        need(current.count(old)==count,'binding_literal_count'); current=current.replace(old,new)
    restored=current
    for old,new,count in PAIRS:
        need(restored.count(new)==count,'reverse_binding_literal_count');restored=restored.replace(new,old)
    need(restored==original,'only_five_bindings_changed')
    save(ROOT/'scripts/real_lifecycle_live.py',current.encode())
    save(ROOT/'scripts/source_contract.py',code(OLD/'scripts/source_contract.py','3fee1a181dc00c1556b4965a826dbedcd7309ae02c2ac410ba4cc3934561effd'))
    save(ROOT/'transport/tests/real-lifecycle-live-child.mjs',code(OLD/'transport/tests/real-lifecycle-live-child.mjs','9bf21f696d7b26f29ff20e22beb71de55f124982e1c4397045262ff19165da23'))
    for name,pin in PINS.items():
        b=code(REPO/'tools/authbus/production-transport/plugin'/name,pin)
        need(b==subprocess.check_output(['/usr/bin/git','-C',str(REPO),'show','HEAD:tools/authbus/production-transport/plugin/'+name]),'transport_current_git_blob')
        save(ROOT/'transport/plugin'/name,b)
    save(ROOT/'transport/package.json',code(REPO/'tools/authbus/production-transport/package.json','1239d4d885dcad42201a27ed9324f8f0f760b78700d8db9ced39a511cffe7eae'))
    pins={str(p.relative_to(ROOT)):sha(p) for base in ('scripts','transport') for p in (ROOT/base).rglob('*') if p.is_file()}
    save(ROOT/'intent.public.json',enc({'schema':'heptabao.final360-x230-real88-intent.v1','source':source(),'binary_sha256':BINARY,'normal_build_result_sha256':BUILD,'original_driver_sha256':digest(original.encode()),'current_files':pins,'driver_changes':'five exact version/build/binary literals only; all criteria unchanged','original_child_timeout_seconds':90,'original_request_deadline_milliseconds':30000,'original_token_ttl_seconds':10,'fresh_source_capture_required':True,'provider_called':False,'production_changed':False,'network_scope':'X230 loopback only','production_consumer_tested':False}))
    print(json.dumps({'prepared':True,'intent':str(ROOT/'intent.public.json'),'sha256':sha(ROOT/'intent.public.json')}))
def execute():
    started=time.monotonic();result={'schema':'heptabao.final360-x230-real88-assessment.v1','ok':False,'provider_called':False,'refresh_dispatched':False,'production_changed':False,'actual_x230_production_consumer_tested':False,'full_replacement_qualified':False}
    try:
        verify(); before=source();intent=json.loads((ROOT/'intent.public.json').read_text())
        for name,pin in intent['current_files'].items(): need(sha(ROOT/name)==pin,'prepared_code_changed')
        entry="import runpy,sys;sys.path.insert(0,sys.argv[1]);sys.argv=sys.argv[2:];runpy.run_path(sys.argv[0],run_name='__main__')"
        args=['/usr/bin/python3','-I','-S','-B','-c',entry,str(ROOT/'scripts'),str(ROOT/'scripts/real_lifecycle_live.py'),'--binary',str(CANDIDATE/'artifacts/heptabao-server'),'--work-dir',str(ROOT/'live-r1'),'--node','/usr/bin/node','--qa-root',str(REPO/'qa/openbao-acceptance'),'--transport-root',str(ROOT/'transport'),'--real-source',str(ROOT/'source-private/selected-credential.private.json'),'--provider-proof',str(ROOT/'source-private/provider-proof.public.json'),'--build-result',str(BUILD_PATH)]
        env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C.UTF-8','TZ':'UTC','TMPDIR':str(ROOT/'tmp')}
        with (ROOT/'run.stdout.private').open('xb') as out,(ROOT/'run.stderr.private').open('xb') as err:
            child=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=env,timeout=360)
        raw=(ROOT/'live-r1/result.public.json').read_bytes();r=json.loads(raw);checks=r.get('checks',[]);phases=r.get('phases',[]);all_checks=checks+[v for phase in phases for v in phase.get('checks',[])]
        count=len(all_checks);passed=sum(x.get('passed') is True for x in all_checks)
        after=source();result.update(child_exit_code=child.returncode,actual_result_ok=r.get('ok'),actual_result_sha256=digest(raw),parent_checks=len(checks),parent_passed=sum(x.get('passed') is True for x in checks),child_checks=len(all_checks)-len(checks),actual_checks_count=count,actual_checks_passed=passed,phase_check_shapes=[{'phase':p.get('phase'),'checks_count':len(p.get('checks',[])),'ok':p.get('ok')} for p in phases],owned_processes_stopped=r.get('owned_processes_stopped') is True,actual_cold_service_restarts=r.get('actual_cold_service_restarts'),real_provider_credentials=r.get('real_provider_credentials'),actual_real_credential_kv_rollback=r.get('actual_real_credential_kv_rollback'),source_unchanged=before==after,source_commit=HEAD,source_tree=TREE,binary_sha256=BINARY,build_receipt_sha256=BUILD)
        need(child.returncode==0 and r.get('ok') is True and count==88 and passed==88 and before==after and result['owned_processes_stopped'] and result['actual_cold_service_restarts']==2 and result['real_provider_credentials'] and result['actual_real_credential_kv_rollback'],'real88_not_qualified');result['ok']=True
    except Exception as e:result['error']=str(e) if isinstance(e,Refused) else type(e).__name__
    result['elapsed_seconds']=round(time.monotonic()-started,3);save(ROOT/'assessment.public.json',enc(result));print(json.dumps({'ok':result['ok'],'error':result.get('error'),'receipt':str(ROOT/'assessment.public.json'),'sha256':sha(ROOT/'assessment.public.json')}));return 0 if result['ok'] else 1
if __name__=='__main__':
    os.umask(0o077)
    if sys.argv[1:] == ['--prepare']:prepare()
    elif sys.argv[1:] == ['--execute']:raise SystemExit(execute())
    else:raise SystemExit('use --prepare or --execute')
