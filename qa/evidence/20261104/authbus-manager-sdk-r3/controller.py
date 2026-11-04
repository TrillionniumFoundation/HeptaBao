#!/usr/bin/env python3
"""Bounded real system-manager and actual-SDK lifecycle in one isolated fixture."""
from pathlib import Path
import argparse, ast, base64, hashlib, importlib.util, json, os, stat, subprocess, sys, time

BASE=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
CONTROL=BASE/'authbus-coordinator-manager-sdk-control-r3'
WORK=BASE/'authbus-coordinator-manager-sdk-live-r3'
SOURCE=BASE/'ha-root-pull-response-final-source-r1'
BUILD=BASE/'ha-root-pull-response-normal-build-rog-r1'
BINARY=BUILD/'artifacts/heptabao-server'
SDK=Path('/home/qian-qi/.npm-global/lib/node_modules/openclaw')
PLUGIN=Path('/home/qian-qi/.openclaw/extensions/openclaw-authbus')
COMMIT='33cafa4c6e29f0bde1553e041550d21b4c725d9c'
TREE='cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
BINARY_SHA='7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba'
BUILD_PINS={'result.public.json':'7fa76585e94fe2e60bbc3ce754f37e4d9d433e4cf576fcc2e39a1e95771f3f42',
'native-build.public.json':'2fa263744917e1d71658daa4f34e09ea448fe77ec0b2c0f8ec22c01e2cd84e8e'}
HELPERS=['qa/openbao-acceptance/owned_process.py','qa/openbao-acceptance/cert_auth_live.py',
'qa/openbao-acceptance/fixture_mounts.py','qa/openbao-acceptance/native_v6_authbus_client_live.py',
'qa/openbao-acceptance/native_v6_openclaw_authbus_live.py','qa/single-node/smoke.py','qa/openbao-acceptance/kv2_271_lossless_native_live.py']
SDK_PINS={'dist/plugin-sdk/agent-runtime.js':'7831532d17eeaddd62889b2e8bb7b65ea7a7851901f69ceec23607a8c579dd95',
'dist/profiles-DyU-YCq2.js':'075f9d6ecd43103c32a6908816bf42720076fd0aaedb2b5e7e96481d64a29ba5',
'dist/store-DH33UrUj.js':'25a5c7075e13b8fb32f498a90e5ee91d93b7e15972b3b74796f1325b5ba98ebf'}
PLUGIN_FILES=['index.js','order-policy.js','runtime-refresh-policy.js','codex-client-recycler.js',
'lease-assignments.js','provider-error-classifier.js','bad-refresh-quarantine.js']
PROTECTED=[Path('/home/qian-qi/.openclaw/openclaw.json'),Path('/home/qian-qi/.codex/auth.json'),
Path('/home/qian-qi/.codex/config.toml')]
DRIVER='qa/openbao-acceptance/native_v6_authbus_coordinator_live.py'
PLAN_SHA='4639629453be97064a34f643df3bc32e50bc3bd83ec55f26a3c05b9151d8d2a1'
os.umask(0o077)

def h(b): return hashlib.sha256(b).hexdigest()
def digest(p):
    s=p.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1: raise RuntimeError('regular_single_link_required')
    out=hashlib.sha256()
    with p.open('rb') as f:
        while b:=f.read(1048576): out.update(b)
    return out.hexdigest()
def write(p,b):
    p.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
def js(p,d):write(p,(json.dumps(d,indent=2,sort_keys=True)+'\n').encode())
def git(*args):
    return subprocess.check_output(['/usr/bin/git','-C',str(SOURCE),*args],timeout=15)
def boundary():
    if git('rev-parse','HEAD').decode().strip()!=COMMIT or git('rev-parse','HEAD^{tree}').decode().strip()!=TREE or git('status','--porcelain'):
        raise RuntimeError('frozen_source_changed')
    for name,pin in BUILD_PINS.items():
        if digest(BUILD/name)!=pin:raise RuntimeError('normal_build_receipt_changed')
    result=json.loads((BUILD/'result.public.json').read_bytes())
    artifact=result['artifacts']['heptabao-server']
    if result['normal_default_candidate'] is not True or result['build_exit_code']!=0 or result['timed_out'] is not False or result['owned_group_survivors_after_wait'] is not False:
        raise RuntimeError('normal_build_not_terminal')
    if result['source_commit']!=COMMIT or result['source_tree']!=TREE or artifact['features']!=['default','native-v6-ha','native-v6-storage']:
        raise RuntimeError('normal_source_features_changed')
    if artifact['profile']!={'debug_assertions':True,'debuginfo':0,'opt_level':'3','overflow_checks':True,'test':False}:
        raise RuntimeError('normal_profile_changed')
    if artifact['sha256']!=BINARY_SHA or digest(BINARY)!=BINARY_SHA:
        raise RuntimeError('normal_binary_changed')
    for name,pin in SDK_PINS.items():
        if digest(SDK/name)!=pin:raise RuntimeError('reviewed_sdk_source_changed')
    plugins={name:digest(PLUGIN/name) for name in PLUGIN_FILES}
    if plugins['index.js']!='b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b':
        raise RuntimeError('original_plugin_changed')
    sdkver=json.loads((SDK/'package.json').read_bytes())['version']
    if sdkver!='2026.7.1-2':raise RuntimeError('sdk_version_changed')
    return {'commit':COMMIT,'tree':TREE,'source_clean':True,'binary_sha256':BINARY_SHA,
            'build_receipts':BUILD_PINS,'sdk_version':sdkver,'sdk_source_sha256':SDK_PINS,'plugin_sha256':plugins}
def protected():
    return {str(p):{'bytes':p.stat().st_size,'sha256':digest(p)} for p in PROTECTED}
def finite_processes():
    found=[]
    for d in Path('/proc').iterdir():
        if not d.name.isdecimal():continue
        try:
            st=d.stat()
            if st.st_uid!=os.getuid():continue
            cmd=(d/'cmdline').read_bytes()
            if str(WORK).encode() not in cmd:continue
            raw=(d/'stat').read_text();parts=raw[raw.rfind(')')+2:].split()
            found.append({'pid':int(d.name),'state':parts[0],'pgid':int(parts[2]),'start_ticks':int(parts[19]),'argv_sha256':h(cmd)})
        except (FileNotFoundError,ProcessLookupError,PermissionError):continue
    return found
def stage():
    payload=json.load(sys.stdin)
    if CONTROL.exists() or CONTROL.is_symlink() or BASE.resolve(strict=True)!=BASE:
        raise RuntimeError('fresh_control_required')
    before=boundary()
    CONTROL.mkdir(mode=0o700)
    inputs={}
    for rel,b64 in payload['files'].items():
        if rel.startswith('/') or '..' in Path(rel).parts:raise RuntimeError('input_path')
        b=base64.b64decode(b64,validate=True)
        if h(b)!=payload['sha256'][rel]:raise RuntimeError('input_digest')
        write(CONTROL/rel,b);inputs[rel]=h(b)
    helpers={}
    for rel in HELPERS:
        b=(SOURCE/rel).read_bytes()
        if b!=git('show',COMMIT+':'+rel):raise RuntimeError('helper_not_exact_git_blob')
        write(CONTROL/rel,b);helpers[rel]=h(b)
    for p in CONTROL.rglob('*.py'):ast.parse(p.read_text())
    receipt={'schema':'heptabao.authbus-manager-sdk-stage.v1','boundary':before,'inputs':inputs,'helpers':helpers,
             'controller_sha256':digest(CONTROL/'controller.py'),'server_started':False,'production_changed':False}
    js(CONTROL/'stage.public.json',receipt)
    for d in sorted((p for p in CONTROL.rglob('*') if p.is_dir()),key=lambda x:len(x.parts),reverse=True)+[CONTROL,BASE]:
        fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    print(json.dumps(receipt,sort_keys=True))
def live():
    if WORK.exists() or WORK.is_symlink():raise RuntimeError('fresh_work_required')
    staged=json.loads((CONTROL/'stage.public.json').read_bytes())
    for name,pin in {**staged['inputs'],**staged['helpers']}.items():
        if digest(CONTROL/name)!=pin:raise RuntimeError('staged_source_changed')
    before=boundary(); private_before=protected()
    if digest(CONTROL/'manager-system-plan.public.json')!=PLAN_SHA:raise RuntimeError('fixed_manager_plan_changed')
    plan=json.loads((CONTROL/'manager-system-plan.public.json').read_bytes())
    if plan['workDir']!=str(WORK) or plan['actor']['uid']!=os.getuid() or plan['actor']['gid']!=os.getgid():raise RuntimeError('fixed_manager_plan_identity')
    for unit in plan['units']:
        if Path(unit['runtime']).exists() or Path(unit['runtime']).is_symlink():raise RuntimeError('fresh_runtime_unit_required')
    js(CONTROL/'live-intent.public.json',{'boundary':before,'protected_metadata':private_before,'work_root':str(WORK),
       'readiness_seconds':12,'http_seconds':10,'child_worker_seconds':75,'outer_seconds':900,
       'no_fixture_features':True,'formal_activate':'sys/storage/native-v6/activate','direct_core_api':False,
       'installed_entry_planned':True,'actual_manager_in_this_scope':True,'synthetic_provider_credentials':True,'production_changed':False})
    sys.path.insert(0,str(CONTROL/'qa/openbao-acceptance'))
    import owned_process
    argv=['/usr/bin/python3','-B',str(CONTROL/DRIVER),'--binary',str(BINARY),'--central-source',str(CONTROL/'tools/authbus/authbus_coordinator.py'),
          '--installed-entry-source',str(CONTROL/'tools/authbus/authbus_coordinator_installed.py'),
          '--system-plan',str(CONTROL/'manager-system-plan.public.json'),'--system-plan-sha256',PLAN_SHA,
          '--system-unit-helper',str(CONTROL/'tools/authbus/authbus_system_unit_runtime.py'),
          '--runtime-observer',str(CONTROL/'qa/openbao-acceptance/authbus_owned_proc_runtime_observer.py'),
          '--plugin-root',str(PLUGIN),'--openclaw-root',str(SDK),'--node','/usr/bin/node','--work-dir',str(WORK)]
    env={'PATH':'/usr/bin:/bin','HOME':'/home/qian-qi','PYTHONDONTWRITEBYTECODE':'1','LC_ALL':'C.UTF-8'}
    started=time.monotonic();code=None;error=None
    with (CONTROL/'driver.stdout.private.log').open('xb') as out,(CONTROL/'driver.stderr.private.log').open('xb') as err:
        try:
            r=owned_process.run(argv,cwd=CONTROL,env=env,stdout=out,stderr=err,timeout=900,label='root.authbus-manager-sdk')
            code=r.returncode
        except Exception as exc:error=type(exc).__name__
    remaining=finite_processes()
    unit_terminal=[]
    for unit in plan['units']:
        observed=subprocess.run(['/usr/bin/systemctl','--system','show',unit['name'],'--property=LoadState,ActiveState,MainPID'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        fields=dict(line.split('=',1) for line in observed.stdout.decode().splitlines() if '=' in line)
        unit_terminal.append({'name':unit['name'],'exit_code':observed.returncode,'fields':fields,'runtime_file_absent':not Path(unit['runtime']).exists() and not Path(unit['runtime']).is_symlink()})
    manager_cleanup=(all(u['exit_code'] in (0,1,4) and u['fields'].get('LoadState')=='not-found' and u['fields'].get('MainPID')=='0' and u['runtime_file_absent'] for u in unit_terminal))
    after=None;private_after=None;after_error=None
    try:after=boundary();private_after=protected()
    except Exception as exc:after_error=type(exc).__name__
    result_path=WORK/'public-receipt.json';result=json.loads(result_path.read_bytes()) if result_path.exists() else None
    good=(code==0 and not error and not remaining and after==before and private_after==private_before and result and result.get('ok') is True
          and result.get('installed_entry_executed') is True
          and result.get('installed_entry_sdk_same_fixture_qualified') is True
          and result.get('coordinator_execution_scope') == 'bound_installed_entry_api_and_system_manager'
          and result.get('actual_manager_qualified_in_this_scope') is True
          and result.get('installed_manager_sdk_same_fixture_qualified') is True
          and manager_cleanup)
    receipt={'schema':'heptabao.authbus-manager-sdk-outer.v1','ok':bool(good),'exit_code':code,'error_type':error,
      'elapsed_seconds':time.monotonic()-started,'remaining_owned_processes':remaining,'after_error_type':after_error,
      'boundary_before':before,'boundary_after':after,'protected_metadata_before':private_before,
      'protected_metadata_after':private_after,'protected_files_unchanged':private_before==private_after,
      'result_sha256':digest(result_path) if result_path.exists() else None,
      'result_bytes':result_path.stat().st_size if result_path.exists() else None,
      'checks':len(result.get('checks',[])) if result else None,'result_ok':result.get('ok') if result else None,
      'result_error':result.get('error') if result else None,'production_changed':False,
      'installed_entry_executed':bool(result and result.get('installed_entry_executed')),
      'same_fixture_sdk_entry_qualified':bool(result and result.get('installed_entry_sdk_same_fixture_qualified')),
      'same_fixture_manager_sdk_qualified':bool(result and result.get('installed_manager_sdk_same_fixture_qualified')),
      'actual_manager_qualified_in_this_scope':bool(result and result.get('actual_manager_qualified_in_this_scope')),
      'manager_cleanup_confirmed':manager_cleanup,'manager_units_terminal':unit_terminal}
    js(CONTROL/'outer-result.public.json',receipt)
    print(json.dumps(receipt,sort_keys=True))
    return 0 if good else 1
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--stage',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args()
    if a.stage:stage()
    elif a.live:raise SystemExit(live())
    else:raise SystemExit(2)

