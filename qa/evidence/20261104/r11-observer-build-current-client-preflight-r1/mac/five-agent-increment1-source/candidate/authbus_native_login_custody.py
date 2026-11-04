"""Frozen-program, sandbox and owned-process checks for native login staging.

The only external processes exercised by preparation are local metadata queries
and synthetic containment probes. No OAuth or provider endpoint is contacted.
"""
from __future__ import annotations
import hashlib, json, os, shlex, signal, stat, subprocess, sys, time
from pathlib import Path
from authbus_profile2_selector_live import need, put, file_sha


def pin(path):
    resolved = Path(path).resolve(strict=True)
    before = resolved.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.geteuid())
         and not before.st_mode & 0o022, 'pinned_file_custody')
    value = file_sha(resolved)
    after = resolved.stat()
    fields = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_uid, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    need(fields(before) == fields(after), 'pinned_file_changed')
    return {'path': str(resolved), 'sha256': value, 'size': before.st_size}


def verify_pins(pins):
    for item in pins.values():
        need(pin(item['path']) == item, 'frozen_source_or_runtime_changed')


def resolve_native(launcher, package):
    """Mirror only the reviewed launcher's local optional-package resolution."""
    node = Path('/opt/homebrew/bin/node').resolve(strict=True)
    query = r'''
const fs=require('node:fs'),path=require('node:path'),{createRequire}=require('node:module');
if(process.platform!=='darwin'||process.arch!=='arm64')throw new Error('unreviewed_platform');
const launcher=process.argv[1],requireFrom=createRequire(launcher),triple='aarch64-apple-darwin';
const moduleName='@openai/codex-darwin-arm64';
const resolveAt=root=>{for(const part of ['bin','codex']){const p=path.join(root,triple,part,'codex');if(fs.existsSync(p))return fs.realpathSync(p);}return null;};
let nativePackageJson=null,binary=null;
try{nativePackageJson=requireFrom.resolve(moduleName+'/package.json');binary=resolveAt(path.join(path.dirname(nativePackageJson),'vendor'));}
catch{binary=resolveAt(path.join(path.dirname(launcher),'..','vendor'));}
if(!binary)throw new Error('native_binary_absent');
process.stdout.write(JSON.stringify({platform:process.platform,arch:process.arch,nodeVersion:process.version,nativePackageJson,binary}));
'''
    proc = subprocess.run([str(node), '-e', query, str(launcher)], capture_output=True, timeout=8,
                          env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
    need(proc.returncode == 0, 'native_cli_resolution_failed')
    info = json.loads(proc.stdout)
    need(Path(info['binary']).is_relative_to(Path('/opt/homebrew/lib/node_modules/@openai')), 'native_binary_outside_installed_package')
    pins = {'pythonRuntime': pin(sys.executable), 'nodeRuntime': pin(node),
            'codexNative': pin(info['binary']), 'launcher': pin(launcher), 'package': pin(package)}
    if info['nativePackageJson']:
        native_pkg = Path(info['nativePackageJson'])
        need(str(json.loads(native_pkg.read_bytes())['version']).startswith('0.133.0'), 'native_package_version_mismatch')
        pins['nativePackage'] = pin(native_pkg)
    info['pins'] = pins
    return info


def group_members(pgid):
    output = subprocess.check_output(['/bin/ps', '-axo', 'pid=,pgid=,stat='], text=True, timeout=4)
    members = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) == 3 and int(fields[1]) == pgid:
            members.append({'pid': int(fields[0]), 'state': fields[2]})
    return members


def run_owned(argv, env, cwd, timeout, interrupt_probe=False):
    """Start a new session, always reap its leader and stop every owned group member."""
    proc = subprocess.Popen(argv, env=env, cwd=cwd, start_new_session=True)
    pgid = proc.pid
    result = {'ownedProcessGroup': pgid, 'timeout': False, 'interrupted': False,
              'exitCode': None, 'primaryReaped': False, 'noGroupSurvivors': False}
    try:
        if interrupt_probe:
            # Exercise exactly the KeyboardInterrupt cleanup path using a local
            # synthetic process; no native login is involved in this probe.
            time.sleep(0.35)
            raise KeyboardInterrupt
        result['exitCode'] = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        result['timeout'] = True
    except KeyboardInterrupt:
        result['interrupted'] = True
    finally:
        old_int = signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            # A successfully exited leader may still have children. Clean the
            # owned session group even on the success path before verification.
            members = group_members(pgid)
            if members:
                try:
                    os.killpg(pgid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 1.0
                while group_members(pgid) and time.monotonic() < deadline:
                    if proc.poll() is None:
                        try:
                            proc.wait(timeout=0.1)
                        except subprocess.TimeoutExpired:
                            pass
                    else:
                        time.sleep(0.05)
                if group_members(pgid):
                    try:
                        os.killpg(pgid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            proc.wait(timeout=5)
            result['primaryReaped'] = True
            result['finalReturnCode'] = proc.returncode
            deadline = time.monotonic() + 3.0
            remaining = group_members(pgid)
            while remaining and time.monotonic() < deadline:
                time.sleep(0.05)
                remaining = group_members(pgid)
            result['remainingGroupMembers'] = remaining
            result['noGroupSurvivors'] = not remaining
        finally:
            signal.signal(signal.SIGINT, old_int)
    result['outcomeUnknown'] = result['timeout'] or result['interrupted'] or not result['noGroupSurvivors']
    return result


def containment_probes(root, python_runtime):
    """Two targeted review checks: sandbox authority and timeout/interrupt cleanup."""
    probe = r'''
import json,os,sys
from pathlib import Path
r=Path(sys.argv[1]);checks={}
for folder in ['native-login-home','tmp']:
 p=r/folder/'synthetic-write-probe';fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,b'probe');os.close(fd);checks['canWrite.'+folder]=True
for name in ['prepared-intent.private.json','production-auth-rows.private.json','production-native-auth-backup.private.json']:
 for action,flags in [('read',os.O_RDONLY),('write',os.O_WRONLY)]:
  try:fd=os.open(r/name,flags);os.close(fd);checks['denied.'+action+'.'+name]=False
  except PermissionError:checks['denied.'+action+'.'+name]=True
try:fd=os.open(r/'interactive-attempt.private.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd);checks['denied.create.attempt']=False
except PermissionError:checks['denied.create.attempt']=True
print(json.dumps(checks))
sys.exit(0 if all(checks.values()) else 1)
'''
    proc = subprocess.run(['/usr/bin/sandbox-exec', '-f', str(root / 'login.sb'), python_runtime, '-I', '-c', probe, str(root)],
                          capture_output=True, timeout=10, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
    need(proc.returncode == 0, 'native_sandbox_boundaries_failed')
    sandbox_checks = json.loads(proc.stdout)
    need(all(sandbox_checks.values()) and not (root / 'interactive-attempt.private.json').exists(), 'sandbox_attempt_custody')
    synthetic = r'''
import json,os,signal,subprocess,sys,time
signal.signal(signal.SIGTERM,signal.SIG_IGN)
child=subprocess.Popen([sys.executable,'-I','-c','import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)'])
with open(sys.argv[1],'x') as f:json.dump({'childPid':child.pid,'processGroup':os.getpgrp()},f)
time.sleep(30)
'''
    groups = []
    for mode in ('timeout', 'interrupt'):
        ready = root / 'tmp' / ('synthetic-' + mode + '-ready.json')
        result = run_owned([python_runtime, '-I', '-c', synthetic, str(ready)], {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'},
                           str(root / 'tmp'), timeout=0.6, interrupt_probe=mode == 'interrupt')
        result['mode'] = mode
        need(ready.exists(), 'synthetic_child_was_not_spawned')
        observed_child = json.loads(ready.read_bytes())
        need(observed_child['processGroup'] == result['ownedProcessGroup'], 'synthetic_child_group_mismatch')
        result['syntheticChildPid'] = observed_child['childPid']
        need(result['primaryReaped'] and result['noGroupSurvivors']
             and result['timeout' if mode == 'timeout' else 'interrupted'], 'synthetic_owned_group_cleanup_failed')
        groups.append(result)
    receipt = {'schema': 'heptabao.native-login-containment-probes.v1', 'ok': True,
               'providerRequests': 0, 'oauthStarted': False, 'sandboxChecks': sandbox_checks, 'syntheticProcessGroups': groups}
    put(root / 'containment-probes.public.json', receipt)
    return receipt


def freeze_entry(root, runtime_pins, capture_path, own_path):
    frozen = root / 'frozen-program'
    frozen.mkdir(mode=0o700)
    source_map = {'authbus_profile3_login_prepare.py': own_path,
                  'authbus_native_login_custody.py': Path(__file__),
                  'authbus_profile2_selector_live.py': Path(__file__).with_name('authbus_profile2_selector_live.py'),
                  'authbus_current_credential_stage.py': capture_path}
    pins = dict(runtime_pins)
    for name, source in source_map.items():
        target = frozen / name
        put(target, Path(source).read_bytes())
        pins[name] = pin(target)
    for name in ('prepared-intent.private.json', 'login.sb', 'native-login-home/config.toml'):
        pins[name] = pin(root / name)
    bootstrap = '''import hashlib,json,os,runpy,stat,sys
from pathlib import Path
PINS = ''' + repr(pins) + '''
for name,item in PINS.items():
 p=Path(item['path']);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_uid not in (0,os.geteuid()) or s.st_mode&0o022:raise SystemExit('frozen_custody_refused')
  h=hashlib.sha256()
  with os.fdopen(os.dup(fd),'rb') as f:
   for b in iter(lambda:f.read(1048576),b''):h.update(b)
  a=os.fstat(fd);z=p.lstat()
  fields=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mode,x.st_uid,x.st_mtime_ns,x.st_ctime_ns)
  if fields(s)!=fields(a) or fields(s)!=fields(z) or h.hexdigest()!=item['sha256'] or s.st_size!=item['size']:raise SystemExit('frozen_pin_refused')
 finally:os.close(fd)
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
os.environ['HEPTABAO_LOGIN_BOOTSTRAP_VERIFIED']='1'
runpy.run_path(str(Path(__file__).with_name('authbus_profile3_login_prepare.py')),run_name='__main__')
'''
    put(frozen / 'bootstrap.py', bootstrap.encode())
    bootstrap_pin = pin(frozen / 'bootstrap.py')
    python = runtime_pins['pythonRuntime']
    # Hash bootstrap and interpreter before executing Python or importing any
    # task dependency. env -i prevents Perl/Python injection via shell env.
    wrapper = '#!/bin/sh\nset -eu\n'
    for entry in (python, bootstrap_pin):
        wrapper += 'ACTUAL=$(/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/shasum -a 256 ' + shlex.quote(entry['path']) + ' | /usr/bin/cut -d " " -f 1)\n'
        wrapper += '[ "$ACTUAL" = ' + shlex.quote(entry['sha256']) + ' ] || { echo frozen_entry_refused >&2; exit 1; }\n'
    wrapper += 'exec ' + shlex.quote(python['path']) + ' -I ' + shlex.quote(bootstrap_pin['path'])
    wrapper += ' --root ' + shlex.quote(str(root)) + ' --action login\n'
    put(root / 'run-native-login.sh', wrapper.encode())
    os.chmod(root / 'run-native-login.sh', 0o700)
    put(root / 'frozen-program-pins.public.json', {'schema': 'heptabao.native-login-frozen-program.v1',
        'pins': pins, 'bootstrap': bootstrap_pin, 'wrapper': pin(root / 'run-native-login.sh'),
        'sourceImportsGuardedBeforeExecution': True})
    return pins
