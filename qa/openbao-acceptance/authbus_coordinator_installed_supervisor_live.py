#!/usr/bin/env python3
"""Owned normal-V6/TLS + actual user-manager qualification of installed entry.

Synthetic credentials only. No SDK/provider/production service is used here.
The separate original SDK producer/follower qualification has its own scope.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time
import types
import uuid

BINARY_SHA = '7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba'
COMMIT = '33cafa4c6e29f0bde1553e041550d21b4c725d9c'
TREE = 'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
NATIVE_RECEIPT_SHA = '2fa263744917e1d71658daa4f34e09ea448fe77ec0b2c0f8ec22c01e2cd84e8e'
BUILD_RESULT_SHA = '7fa76585e94fe2e60bbc3ce754f37e4d9d433e4cf576fcc2e39a1e95771f3f42'
HELPERS = {
 'qa/single-node/smoke.py':'ced4e40a825d3d98a285598d40b58c61083cfc397d0859a783958d855a161971',
 'qa/openbao-acceptance/owned_process.py':'0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0',
 'qa/openbao-acceptance/kv2_271_lossless_native_live.py':'383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581',
}
PROFILE = 'openai:installed-owner-fixture'
SOURCE_HOST = 'installed-source-fixture'
WRITER = 'installed-owner-fixture'
PROCESS_SECONDS = 75
READINESS_SECONDS = 12
MANAGER_SECONDS = 15
NO_RESTART_SECONDS = 6
owned_process = None


class Failure(RuntimeError):
    pass


def need(ok, code):
    if not ok:
        raise Failure(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def private(path, value, replace=False):
    raw = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True) + '\n').encode()
    path = Path(path)
    temporary = path.with_name(path.name + '.new') if replace else path
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    if replace:
        os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def load(path, expected, name):
    path = Path(path)
    need(path.is_file() and not path.is_symlink() and file_sha(path) == expected, 'code_input_pin')
    raw = path.read_bytes()
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def fault_worker(path):
    config = json.loads(Path(path).read_bytes())
    entry = load(config['entry'], config['entrySha256'], 'installed_fault_entry')
    binding = entry.Binding(Path(config['binding']), config['bindingSha256'])
    client = entry.GuardedBao(binding)
    central = binding.central
    capture = Path(config['capture'])
    def save_token():
        token = client.delegate.token
        private(capture, {'tokens': [token] if token else []})
    try:
        if config['kind'] == 'event-crash':
            original = binding.worker
            def worker_with_observer(transport):
                worker = original(transport)
                def phase(name):
                    if name == 'manifest_committed_before_journal_reply':
                        save_token()
                        os._exit(73)
                worker.hook = phase
                return worker
            binding.worker = worker_with_observer
            entry.service_cycle(binding, client)
            raise Failure('expected_event_crash_not_observed')
        need(config['kind'] == 'operator-post-response-error', 'fault_kind')
        original_write = client.delegate.write
        def observed_write(key, value, cas):
            version = original_write(key, value, cas)
            need(key == 'manifest' and version == cas + 1, 'real_cas_response_before_injected_error')
            # Preserve the actual HTTP dispatch/response. This deliberately
            # injects a local validation failure after that real success.
            raise central.Error('kv_write_version_mismatch')
        client.delegate.write = observed_write
        entry.operator(binding, client, 'authorize',
                       version=config['expectedVersion'], head_sha=config['expectedManifestSha256'],
                       grant_path=Path(config['grantPath']), grant_sha=config['grantSha256'])
        raise Failure('expected_operator_error_not_observed')
    except Exception as exc:
        save_token()
        text, status = entry.error_result(binding, client, exc)
        print(text, flush=True)
        return status


class Run:
    def __init__(self, args):
        self.args = args
        self.root = args.work_dir
        self.created_root = False
        self.report = {
            'schema':'heptabao.authbus-installed-supervisor-normal-live.v1','ok':False,
            'productionChanged':False,'providerCalled':False,'realProviderCredentials':False,
            'sdkProducerFollowerTested':False,'realUserManagerTested':False,
            'realSystemManagerTested':False,'requestedManagerScope':args.service_manager,
            'formalNormalServerQualified':False,'pairedOwnerKvRestoreQualified':False,
            'checks':[],'mutations':[],'managerActions':[],'commands':[],
            'budgets':{'coordinatorRequestSeconds':10,'ownedWorkerSeconds':75,
                       'serverReadinessSeconds':12,'snapshotHttpSeconds':15,
                       'managerCommandSeconds':15,'noRestartObservationSeconds':6},
        }
        self.server = None
        self.units = []
        self.secrets = []
        self.phase_no = 0
        self.unit_no = 0
        self.system_plan = None
        self.root_helper_source = None
        self.root_observer_source = None

    def phase(self, name, details=None):
        self.phase_no += 1
        private(self.root / 'phases' / ('%04d-%s.json' % (self.phase_no, name)),
                {'phase':name,'details':details})

    def check(self, name, ok, **metadata):
        row = {'case':name,'passed':bool(ok),**metadata}
        self.report['checks'].append(row)
        self.phase('check', row)
        need(ok, name)

    def execute(self, name, argv, *, expected=0, timeout=PROCESS_SECONDS, env=None, input_bytes=None):
        result = owned_process.run(argv, cwd=self.root, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=timeout,
                                   input=input_bytes,
                                   label='installed-supervisor.' + name)
        self.check(name + '.bounded_output', len(result.stdout) + len(result.stderr) <= 1024 * 1024)
        self.check(name + '.no_credentials', not any(s.encode() in result.stdout + result.stderr for s in self.secrets))
        private(self.root / 'logs' / (name + '.stdout.private'), result.stdout)
        private(self.root / 'logs' / (name + '.stderr.private'), result.stderr)
        self.report['commands'].append({'case':name,'argv':list(map(str,argv)),
                                       'exitCode':result.returncode,'budgetSeconds':timeout,
                                       **({'inputSha256':sha(input_bytes)} if input_bytes is not None else {})})
        self.check(name + '.exit', result.returncode in expected if isinstance(expected, tuple)
                   else result.returncode == expected,
                   expected=expected, actual=result.returncode)
        return result

    def manager(self, name, argv, *, expected=0, timeout=MANAGER_SECONDS):
        env = {'PATH':'/usr/bin:/bin','HOME':str(Path.home()),
               'XDG_RUNTIME_DIR':'/run/user/' + str(os.geteuid()),
               'DBUS_SESSION_BUS_ADDRESS':'unix:path=/run/user/' + str(os.geteuid()) + '/bus'}
        command = (['/usr/bin/sudo','-n','/usr/bin/systemctl','--system']
                   if self.args.service_manager == 'system' else ['/usr/bin/systemctl','--user'])
        result = self.execute(name, [*command,*argv],
                              expected=expected, timeout=min(timeout, MANAGER_SECONDS), env=env)
        self.report['managerActions'].append({'case':name,'arguments':argv,'exitCode':result.returncode})
        return result.stdout.decode()

    def show(self, unit, label, *, timeout=MANAGER_SECONDS):
        keys = ('LoadState','ActiveState','SubState','MainPID','ExecMainStatus','Result',
                'NRestarts','FragmentPath','DropInPaths','ExecStart','InvocationID',
                'ControlGroup','NoNewPrivileges','PrivateUsers','PrivateTmp','ProtectSystem','ProtectHome',
                'ReadOnlyPaths','ReadWritePaths','Restart','RestartPreventExitStatus',
                'EnvironmentFiles','KillMode','TimeoutStopUSec','User','Group')
        output = self.manager(label, ['show',unit['name'],'--property=' + ','.join(keys)], timeout=timeout)
        fields = dict(line.split('=',1) for line in output.splitlines() if '=' in line)
        self.check(label + '.fragment_exact', Path(fields['FragmentPath']).resolve() == unit['path']
                   and file_sha(unit['path']) == unit['sha256'])
        self.check(label + '.no_dropins', fields.get('DropInPaths','') == '')
        self.check(label + '.execstart_entry_and_binding',
                   str(self.entry_path) in fields['ExecStart'] and 'service serve' in fields['ExecStart']
                   and str(unit['bindingPath']) in fields['ExecStart']
                   and ('HEPTABAO_BINDING_SHA256' in fields['ExecStart']
                        or unit['binding'] is not None and unit['binding'].expected in fields['ExecStart']))
        self.check(label + '.declared_hardening',
                   fields.get('NoNewPrivileges') == 'yes' and fields.get('PrivateUsers') in ('yes','true')
                   and fields.get('PrivateTmp') in ('yes','true')
                   and fields.get('ProtectSystem') == 'strict' and fields.get('ProtectHome') == 'read-only'
                   and str(unit['statePath']) in fields.get('ReadWritePaths','')
                   and fields.get('KillMode') == 'control-group')
        if self.args.service_manager == 'system':
            self.check(label + '.nonroot_system_unit_identity',
                       fields.get('User') == self.system_plan['actor']['user']
                       and fields.get('Group') == self.system_plan['actor']['group'])
        unit['last'] = fields
        return fields

    def failure_journal(self, unit, label, status):
        invocation = unit['last']['InvocationID']
        need(re.fullmatch(r'[a-f0-9]{32}', invocation) is not None, 'actual_manager_invocation_id')
        command = (['/usr/bin/sudo','-n','/usr/bin/journalctl'] if self.args.service_manager == 'system'
                   else ['/usr/bin/journalctl','--user'])
        result = self.execute(label + '.journal', [*command,'--no-pager',
                              '--unit',unit['name'],'--output=cat','_SYSTEMD_INVOCATION_ID=' + invocation],
                              timeout=MANAGER_SECONDS)
        reports = []
        for line in result.stdout.decode().splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and value.get('schema') == self.entry.SCHEMA + '.installed-result':
                reports.append(value)
        expected_error = ('installation_input_changed' if status == 2
                          else 'operator_pending_requires_reconciliation')
        self.check(label + '.actual_entry_error', len(reports) == 1 and reports[0].get('ok') is False
                   and reports[0].get('error') == expected_error
                   and reports[0].get('unknown_outcome') is (status == 3))
        self.report.setdefault('managerFailureReceipts', []).append(reports[0])

    def runtime_fence(self, unit, fields, *, deadline=None):
        if self.args.service_manager == 'system':
            return self.system_runtime_fence(unit, fields, deadline=deadline)
        pid = int(fields['MainPID'])
        need(pid > 1, 'manager_owned_main_pid')
        root = Path('/proc') / str(pid)
        def start():
            return (root / 'stat').read_text().rsplit(')',1)[1].split()[19]
        before = start()
        argv = [x.decode() for x in (root / 'cmdline').read_bytes().split(b'\0') if x]
        expected = ['/usr/bin/python3','-I','-S','-B',str(self.entry_path),'service','serve',
                    '--binding',str(unit['binding'].path),'--binding-sha256',unit['binding'].expected]
        self.check('actual_unit_argv_expands_exact_activation_' + str(self.phase_no), argv == expected)
        status = (root / 'status').read_text()
        self.check('actual_no_new_privileges_' + str(self.phase_no),
                   re.search(r'^NoNewPrivs:\s+1$', status, re.M) is not None)
        mounts = []
        for line in (root / 'mountinfo').read_text().splitlines():
            fields_ = line.split()
            mount = fields_[4]
            # All our fixed paths reject whitespace/percent expansion.
            mounts.append({'id':int(fields_[0]),'parentId':int(fields_[1]),'mountpoint':mount,
                           'flags':sorted(fields_[5].split(','))})
        def mode(path):
            matches = [m for m in mounts if str(path) == m['mountpoint']
                       or str(path).startswith(m['mountpoint'].rstrip('/') + '/')]
            selected = max(matches,key=lambda item:len(item['mountpoint']))
            return {'path':str(path),'matchingMounts':matches,'selectedMount':selected,
                    'statvfsReadOnly':bool(os.statvfs(str(root / 'root') + str(path)).f_flag & os.ST_RDONLY)}
        evidence = {'pid':pid,'startTimeBefore':before,
                    'userNamespace':os.readlink(root / 'ns/user'),
                    'observerUserNamespace':os.readlink('/proc/self/ns/user'),
                    'paths':{}}
        for name in ('Uid','Gid'):
            line = next(line for line in status.splitlines() if line.startswith(name + ':'))
            evidence[name] = list(map(int,line.split()[1:]))
        self.report.setdefault('runtimeFences',[]).append(evidence)
        for name, path in (('code',self.entry_path),('config',unit['binding'].path),
                           ('state',unit['binding'].state)):
            evidence['paths'][name] = mode(path)
        evidence['startTimeAfter'] = start()
        evidence['sameOriginalPid'] = evidence['startTimeAfter'] == before
        self.phase('runtime_fence',evidence)
        self.check('actual_operator_identity_' + str(self.phase_no),
                   evidence['Uid'] == [os.geteuid()] * 4 and evidence['Gid'] == [os.getegid()] * 4
                   and (self.args.service_manager != 'system' or os.geteuid() > 0 and os.getegid() > 0))
        self.check('actual_private_user_namespace_' + str(self.phase_no),
                   evidence['userNamespace'] != evidence['observerUserNamespace'])
        paths = evidence['paths']
        self.check('actual_filesystem_hardening_' + str(self.phase_no),
                   'ro' in paths['code']['selectedMount']['flags']
                   and 'ro' in paths['config']['selectedMount']['flags']
                   and 'rw' in paths['state']['selectedMount']['flags']
                   and paths['code']['statvfsReadOnly'] and paths['config']['statvfsReadOnly']
                   and not paths['state']['statvfsReadOnly'])
        self.check('actual_owned_pid_identity_' + str(self.phase_no),
                   evidence['sameOriginalPid'] and start() == before and Path(os.readlink(root / 'exe')).resolve()
                   == Path('/usr/bin/python3').resolve())
        unit['pid'] = pid
        unit['startTime'] = before

    def system_runtime_fence(self, unit, fields, *, deadline=None):
        deadline = min(deadline if deadline is not None else float('inf'),
                       time.monotonic() + MANAGER_SECONDS)
        def remaining():
            value = deadline - time.monotonic()
            need(value > 0, 'owned_runtime_observer_deadline')
            return value
        pid = int(fields['MainPID'])
        need(pid > 1 and unit['installedIdentity'] is not None, 'owned_system_pid_and_unit')
        proc = Path('/proc') / str(pid)
        before = (proc/'stat').read_text().rsplit(')',1)[1].split()[19]
        info = self.root.lstat()
        payload = {'plan':self.system_plan,'ordinal':unit['ordinal'],'pid':pid,'startTime':before,
                   'controlGroup':fields['ControlGroup'],'bindingSha256':unit['binding'].expected,
                   'unitIdentity':unit['installedIdentity'],
                   'observerUserNamespace':os.readlink('/proc/self/ns/user'),
                   'runIdentity':{'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,
                                  'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)}}
        body = self.root_observer_source + ('\nraise SystemExit(root_observer_main(json.loads(' +
                   repr(json.dumps(payload,sort_keys=True)) + ')))\n').encode()
        need(len(body) <= 131072, 'bounded_root_observer_payload')
        body_sha = sha(body)
        bootstrap = ('import hashlib,sys\nraw=sys.stdin.buffer.read(131073)\n'
                     'if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=' + repr(body_sha) +
                     ': raise SystemExit("root_observer_inline_sha_mismatch")\n'
                     'exec(compile(raw,"<bound-owned-proc-metadata>","exec"),{"__name__":"__main__"})\n')
        label = 'root_runtime_observer_' + str(self.phase_no)
        private(self.root/'logs'/(label+'.source.public.py'),body)
        command = ['/usr/bin/python3','-I','-S','-B','-c',bootstrap]
        self.execute(label+'.exact_sudo_policy',['/usr/bin/sudo','-n','-l','--',*command],
                     env={'PATH':'/usr/bin:/bin'},timeout=remaining())
        self.phase('root_runtime_observer_dispatch',{'unitName':unit['name'],'pid':pid,
                   'startTime':before,'sourceSha256':sha(self.root_observer_source),
                   'payloadSha256':body_sha,'readOnly':True})
        result = self.execute(label,['/usr/bin/sudo','-n',*command],env={'PATH':'/usr/bin:/bin'},
                              input_bytes=body,timeout=remaining(),expected=(0,1))
        evidence = json.loads(result.stdout)
        self.report.setdefault('runtimeFences',[]).append(evidence)
        self.phase('runtime_fence',evidence)
        self.check('actual_root_observer_identity_' + str(self.phase_no),
                   result.returncode == 0 and evidence.get('ok') is True
                   and evidence.get('schema') == 'heptabao.installed-owned-proc-metadata.v1'
                   and evidence.get('pid') == pid and evidence.get('unitName') == unit['name']
                   and evidence.get('startTimeBefore') == before)
        self.check('actual_unit_argv_expands_exact_activation_' + str(self.phase_no),
                   evidence['argvExact'] and evidence['executableExact'] and evidence['cgroupExact'])
        self.check('actual_no_new_privileges_' + str(self.phase_no),evidence['noNewPrivileges'])
        self.check('actual_operator_identity_' + str(self.phase_no),
                   evidence['Uid'] == [os.geteuid()] * 4 and evidence['Gid'] == [os.getegid()] * 4
                   and os.geteuid() > 0 and os.getegid() > 0)
        self.check('actual_private_user_namespace_' + str(self.phase_no),
                   evidence['userNamespace'] != evidence['observerUserNamespace'])
        paths = evidence['paths']
        self.check('actual_filesystem_hardening_' + str(self.phase_no),
                   'ro' in paths['code']['selectedMount']['flags']
                   and 'ro' in paths['config']['selectedMount']['flags']
                   and 'rw' in paths['state']['selectedMount']['flags']
                   and paths['code']['statvfsReadOnly'] and paths['config']['statvfsReadOnly']
                   and not paths['state']['statvfsReadOnly'])
        self.check('actual_owned_pid_identity_' + str(self.phase_no),
                   evidence['sameOriginalPid']
                   and evidence['startTimeAfter'] == before
                   and (proc/'stat').read_text().rsplit(')',1)[1].split()[19] == before)
        remaining()
        unit['pid'] = pid
        unit['startTime'] = before

    def privileged_unit_file(self, unit, action):
        info = self.root.lstat()
        identity = lambda st: {'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid,
                              'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode)}
        payload = {'plan':self.system_plan,'action':action,'ordinal':unit['ordinal'],
                   'runIdentity':identity(info)}
        if action == 'remove':
            need(unit['installedIdentity'] is not None, 'root_unit_original_identity_required')
            payload['expectedUnitIdentity'] = unit['installedIdentity']
            payload['stopConfirmed'] = unit['stopConfirmed']
        else:
            payload['startDispatched'] = unit['startAttempted']
        body = self.root_helper_source + ('\nraise SystemExit(root_main(json.loads(' +
                   repr(json.dumps(payload,sort_keys=True)) + ')))\n').encode()
        need(len(body) <= 131072, 'bounded_root_helper_payload')
        body_sha = sha(body)
        bootstrap = ('import hashlib,sys\nraw=sys.stdin.buffer.read(131073)\n'
                     'if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=' + repr(body_sha) +
                     ': raise SystemExit("root_inline_sha_mismatch")\n'
                     'exec(compile(raw,"<bound-root-unit-file>","exec"),{"__name__":"__main__"})\n')
        label = 'root_unit_file_' + action + '_' + str(unit['ordinal'])
        private(self.root/'logs'/(label+'.source.public.py'),body)
        command = ['/usr/bin/python3','-I','-S','-B','-c',bootstrap]
        self.execute(label+'.exact_sudo_policy',['/usr/bin/sudo','-n','-l','--',*command],
                     env={'PATH':'/usr/bin:/bin'},timeout=MANAGER_SECONDS)
        self.phase('root_unit_file_dispatch',{'action':action,'ordinal':unit['ordinal'],
                   'runtime':str(unit['runtime']),'unitSha256':unit['sha256'],'rootPayloadSha256':body_sha})
        unit['rootFileOutcomeUnknown'] = True
        result = self.execute(label,['/usr/bin/sudo','-n',*command],env={'PATH':'/usr/bin:/bin'},
                              input_bytes=body,timeout=MANAGER_SECONDS,expected=(0,1))
        receipt = json.loads(result.stdout)
        need(receipt.get('schema') == 'heptabao.installed-supervisor-root-unit-file.v1', 'root_unit_result_schema')
        self.report.setdefault('rootUnitFileReceipts',[]).append(receipt)
        if receipt.get('ok') is not True:
            unit['rootFileOutcomeUnknown'] = receipt.get('unknown_outcome') is not False
            raise Failure('root_unit_file_failed_' + action)
        self.check(label+'.exact_result',receipt.get('ok') is True and receipt.get('action') == action
                   and result.returncode == 0 and receipt.get('path') == str(unit['runtime'])
                   and receipt.get('sha256') == unit['sha256'])
        if action == 'install':
            original = receipt['identity']
            need(original['uid'] == original['gid'] == 0 and original['mode'] == 0o644,
                 'original_root_unit_custody')
            unit['installedIdentity'] = original
            need(identity(unit['runtime'].lstat()) == original, 'root_unit_changed_after_install_reply')
        unit['rootFileOutcomeUnknown'] = False
        return receipt

    def install_unit(self, directory, config, label):
        directory.mkdir(mode=0o700)
        config_path = directory / 'config.private.json'
        private(config_path, config)
        self.unit_no += 1
        name = 'heptabao-authbus-installed-qa-' + self.run_id + '-' + str(self.unit_no) + '.service'
        proposal = directory / name
        system = self.args.service_manager == 'system'
        runtime = (Path('/run/systemd/system') / name if system else
                   Path('/run/user') / str(os.geteuid()) / 'systemd/user' / name)
        path = runtime if system else proposal
        binding_path, pin = directory / 'installation.private.json', directory / 'binding-pin.env'
        # Execute the actual CLI preparation functions as separate processes.
        self.execute(label + '.unit_prepare', ['/usr/bin/python3','-I','-S','-B',str(self.entry_path),
                     'prepare-service-file','--config',str(config_path),'--config-sha256',file_sha(config_path),
                     '--binding',str(binding_path),'--activation-pin-file',str(pin),'--output',str(proposal)])
        need(not runtime.exists() and not runtime.is_symlink(), 'fresh_runtime_unit_name')
        unit = {'name':name,'path':path,'proposal':proposal,'sha256':file_sha(proposal),
                'ordinal':self.unit_no,'binding':None,'bindingPath':binding_path,
                'statePath':Path(config['state_dir']),'runtime':runtime,
                'installedIdentity':None,'rootFileOutcomeUnknown':False,
                'linked':False,'linkAttempted':False,'startAttempted':False,'stopConfirmed':False}
        self.units.append(unit)
        absent = self.manager(label + '.not_registered',
                              ['show',name,'--property=LoadState','--value'],expected=(0,1,4))
        self.check(label + '.unique_unit_name', absent.strip() == 'not-found')
        if system:
            planned = self.system_plan['units'][self.unit_no - 1]
            self.check(label + '.fixed_root_install_plan', planned['name'] == name
                       and planned['proposal'] == str(proposal) and planned['runtime'] == str(runtime)
                       and planned['unitSha256'] == unit['sha256'] and planned['unitText'].encode() == proposal.read_bytes())
            unit['linkAttempted'] = True
            self.privileged_unit_file(unit,'install')
        self.execute(label + '.binding_prepare', ['/usr/bin/python3','-I','-S','-B',str(self.entry_path),
                     'prepare-binding','--config',str(config_path),'--config-sha256',file_sha(config_path),
                     '--service-file',str(path),'--service-file-sha256',file_sha(path),
                     '--activation-pin-file',str(pin),'--output',str(binding_path)])
        unit['binding'] = self.entry.Binding(binding_path, file_sha(binding_path))
        if not system:
            unit['linkAttempted'] = True
            self.manager(label + '.link', ['link','--runtime',str(path)])
        unit['linked'] = True
        self.manager(label + '.reload', ['daemon-reload'])
        self.show(unit, label + '.manager_binding')
        return unit

    def prepare_inactive_unit(self, unit, label, fields=None):
        state = fields if fields is not None else self.show(unit, label + '.before')
        self.check(label + '.known_quiescent_state', state['LoadState'] == 'loaded'
                   and state['ActiveState'] in ('inactive','failed') and int(state['MainPID']) == 0)
        cgroup = state.get('ControlGroup')
        if cgroup:
            path = Path('/sys/fs/cgroup') / cgroup.lstrip('/') / 'cgroup.procs'
            self.check(label + '.cgroup_empty', not path.exists() or not path.read_text().strip())
        # reset-failed need not load a fresh inactive unit on the real manager.
        # Only a verified failed unit requires the reset operation.
        if state['ActiveState'] == 'failed':
            self.manager(label + '.reset', ['reset-failed',unit['name']])
            state = self.show(unit, label + '.after_reset')
        self.check(label + '.inactive_dead', state['LoadState'] == 'loaded'
                   and state['ActiveState'] == 'inactive' and state['SubState'] == 'dead'
                   and int(state['MainPID']) == 0)

    def start_unit(self, unit, label, *, failure=None):
        self.prepare_inactive_unit(unit, label + '.pre_start')
        unit['startAttempted'], unit['stopConfirmed'] = True, False
        self.manager(label + '.start', ['start',unit['name']])
        deadline = time.monotonic() + READINESS_SECONDS
        last = None
        while time.monotonic() < deadline:
            last = self.show(unit, label + '.state' + str(self.phase_no),
                             timeout=max(.01, deadline-time.monotonic()))
            if failure is None and last['ActiveState'] == 'active' and int(last['MainPID']) > 1:
                self.runtime_fence(unit, last, deadline=deadline)
                return
            if failure is not None and last['ActiveState'] == 'failed':
                break
            time.sleep(0.1)
        if failure is None:
            raise Failure('owned_manager_start_deadline')
        self.check(label + '.expected_exit', int(last['ExecMainStatus']) == failure
                   and last['ActiveState'] == 'failed' and int(last['MainPID']) == 0)
        before = int(last['NRestarts'])
        need(before == 0, 'unexpected_restart_before_observation')
        # Observe beyond the generated RestartSec=5s. No budget is extended.
        time.sleep(NO_RESTART_SECONDS)
        after = self.show(unit, label + '.after_no_restart_window')
        self.check(label + '.no_automatic_retry', after['ActiveState'] == 'failed'
                   and int(after['NRestarts']) == 0 and int(after['ExecMainStatus']) == failure)
        self.failure_journal(unit, label, failure)

    def stop_unit(self, unit, label):
        self.manager(label, ['stop',unit['name']])
        state = self.show(unit, label + '.stopped')
        self.check(label + '.no_owned_main', int(state['MainPID']) == 0
                   and state['ActiveState'] in ('inactive','failed'))
        cgroup = state.get('ControlGroup')
        if cgroup:
            path = Path('/sys/fs/cgroup') / cgroup.lstrip('/') / 'cgroup.procs'
            self.check(label + '.cgroup_empty', not path.exists() or not path.read_text().strip())
        unit['stopConfirmed'] = True

    def cli(self, unit, label, command, *, expected=0, grant=None):
        argv = ['/usr/bin/python3','-I','-S','-B',str(self.entry_path),'operator',command,
                '--binding',str(unit['binding'].path),'--binding-sha256',unit['binding'].expected]
        if command in ('initialize','authorize','revoke-authorization'):
            result = self.execute(label + '.inspect', ['/usr/bin/python3','-I','-S','-B',str(self.entry_path),
                   'operator','inspect','--binding',str(unit['binding'].path),
                   '--binding-sha256',unit['binding'].expected])
            head = json.loads(result.stdout)
            argv += ['--expected-manifest-version',str(head['manifestVersion']),
                     '--expected-manifest-sha256',head['manifestSha256']]
        if grant:
            argv += ['--authorization',str(grant),'--authorization-sha256',file_sha(grant)]
        result = self.execute(label, argv, expected=expected)
        value = json.loads(result.stdout)
        self.check(label + '.true_bound_configuration', value.get('production_configuration') is True)
        return value

    def head(self, budget=15):
        status, response = self.endpoint.call('GET','openclaw-auth/data/manifest', budget=budget)
        need(status == 200, 'manifest_read')
        return response['data']

    def wait_manifest(self, unit, digest, label):
        deadline = time.monotonic() + PROCESS_SECONDS
        while time.monotonic() < deadline:
            current = self.head(budget=min(15, deadline-time.monotonic()))
            need(time.monotonic() < deadline, 'original_worker_absolute_deadline')
            if current['data']['profiles'] and current['data']['profiles'][0]['digest'] == digest:
                self.check(label, True, version=current['metadata']['version'])
                return current
            fields = self.show(unit, label + '.running' + str(self.phase_no),
                               timeout=max(.01,deadline-time.monotonic()))
            need(fields['ActiveState'] == 'active', 'owner_exited_before_publication')
            time.sleep(0.2)
        raise Failure('original_worker_budget_before_publication')

    def event(self, credential):
        event_id = str(uuid.uuid4())
        value = {'schemaVersion':1,'eventId':event_id,'sourceHost':SOURCE_HOST,'reason':'new-profile',
                 'profileId':PROFILE,'credential':credential,'digest':self.central.digest(credential),
                 'identity':self.central.identity(credential)}
        status, _ = self.endpoint.call('POST','openclaw-auth/data/inbox/' + SOURCE_HOST + '/' + event_id,
                                     {'data':value,'options':{'cas':0}})
        self.check('synthetic_source_event_' + event_id, status == 200)
        return event_id

    def grant(self, credential, previous, name):
        value = {'authorizationId':str(uuid.uuid4()),'profileId':PROFILE,'sourceHost':SOURCE_HOST,
                 'provider':'openai','identityDigest':self.central.identity(credential),
                 'expectedCurrentDigest':previous,'nextDigest':self.central.digest(credential)}
        path = self.root / 'grants' / (name + '.private.json')
        private(path, value)
        return path

    def fault(self, unit, label, kind, *, grant=None):
        cfg = {'kind':kind,'entry':str(self.entry_path),'entrySha256':file_sha(self.entry_path),
               'binding':str(unit['binding'].path),'bindingSha256':unit['binding'].expected,
               'capture':str(self.root / 'logs' / (label + '.tokens.private.json'))}
        if grant:
            h = self.head()
            cfg.update(grantPath=str(grant),grantSha256=file_sha(grant),
                       expectedVersion=h['metadata']['version'],
                       expectedManifestSha256=self.central.digest(h['data']))
        packet = self.root / 'logs' / (label + '.packet.private.json')
        private(packet,cfg)
        result = self.execute(label, ['/usr/bin/python3','-I','-S','-B',str(Path(__file__).absolute()),
                                     '--fault-worker',str(packet)], expected=73 if kind == 'event-crash' else 3)
        tokens = json.loads(Path(cfg['capture']).read_bytes())['tokens']
        self.secrets.extend(tokens)
        return result

    def capture_pair(self, unit):
        backup = self.root / 'paired-backup'
        backup.mkdir(mode=0o700)
        owner = backup / 'owner'
        owner.mkdir(mode=0o700)
        with unit['binding'].lock('service_lock'), unit['binding'].lock():
            entries = sorted(unit['binding'].state.iterdir())
            self.check('backup_owner_flat_bounded', 3 <= len(entries) <= 128
                       and all(p.is_file() and not p.is_symlink() and p.stat().st_nlink == 1
                               and stat.S_IMODE(p.stat().st_mode) == 0o600
                               and p.stat().st_size <= 2 * 1024 * 1024 for p in entries))
            before = {p.name:file_sha(p) for p in entries}
            for p in entries:
                private(owner / p.name,p.read_bytes())
            archive = backup / 'native-snapshot.tar.gz'
            status, receipt = self.endpoint.call('GET','sys/storage/raft/snapshot',archive_out=archive)
            self.check('paired_snapshot_download', status == 200 and receipt['archive_bytes'] > 0)
            after = {p.name:file_sha(p) for p in unit['binding'].state.iterdir()}
            self.check('paired_owner_sources_unchanged_under_both_locks', after == before)
            self.check('paired_backup_exact_owner_bytes', {p.name:file_sha(p) for p in owner.iterdir()} == before)
            self.report['pairedCapture'] = {
                'bothOriginalLocksHeld':True,'serviceStopped':True,'sourceProducersQuiescent':True,
                'ownerFiles':before,'snapshotSha256':file_sha(archive),
                'snapshotBytes':archive.stat().st_size,'fixtureInboxRpo':'quiescent_exact_capture',
                'pendingEventPhase':json.loads((owner / 'pending.private.json').read_bytes())['phase']}
            private(backup / 'capture.public.json',self.report['pairedCapture'])
            # The backup directory entry itself must also be durable before
            # releasing either original lock, not only its files/children.
            fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
        return backup

    def cleanup(self):
        errors = []
        for unit in reversed(self.units):
            try:
                need(not unit['rootFileOutcomeUnknown'],
                     'root_unit_file_outcome_requires_independent_reconciliation')
                exists=unit['runtime'].exists() or unit['runtime'].is_symlink()
                if not exists:
                    # A link response may be lost. Its actual unique runtime
                    # path, not the prior local success flag, decides effect.
                    need(not unit['startAttempted'] or unit['stopConfirmed'],
                         'cleanup_missing_link_with_unconfirmed_service_stop')
                    unit['linked']=False
                    continue
                if self.args.service_manager == 'system':
                    need(unit['installedIdentity'] is not None,
                         'root_unit_file_identity_requires_independent_reconciliation')
                    observed = self.entry.service_unit_record(unit['runtime'],
                               {'manager':'system',**self.system_plan['actor']})
                    need(observed['sha256'] == unit['sha256']
                         and observed['custody'] == unit['installedIdentity'], 'cleanup_exact_owned_root_unit')
                else:
                    need(unit['runtime'].is_symlink() and unit['runtime'].resolve() == unit['path'],
                         'cleanup_exact_owned_runtime_link')
                self.stop_unit(unit,'cleanup.' + unit['name'])
                self.prepare_inactive_unit(unit,'cleanup.prepare.' + unit['name'],unit['last'])
                if self.args.service_manager == 'system':
                    self.privileged_unit_file(unit,'remove')
                else:
                    unit['runtime'].unlink()
                self.manager('cleanup.reload.' + unit['name'],['daemon-reload'])
                absent = self.manager('cleanup.absent.' + unit['name'],
                                      ['show',unit['name'],'--property=LoadState','--value'],expected=(0,1,4))
                self.check('cleanup.registration_absent.' + unit['name'],absent.strip() == 'not-found'
                           and not unit['runtime'].exists() and not unit['runtime'].is_symlink())
                unit['linked'] = False
            except Exception as exc:
                errors.append(str(exc) if isinstance(exc,Failure) else type(exc).__name__)
                if self.args.service_manager == 'system':
                    unit['rootReconciliationRequired'] = True
        if self.server is not None:
            try:
                self.server.stop()
            except Exception as exc:
                errors.append(type(exc).__name__)
        self.report['ownedCleanupComplete'] = not errors and all(not u['linked'] for u in self.units)
        self.report['cleanupErrors'] = errors
        self.report['rootUnitReconciliationRequired'] = any(
            u['rootFileOutcomeUnknown'] or u.get('rootReconciliationRequired',False) for u in self.units)

    def run(self):
        global owned_process
        self.root.mkdir(mode=0o700, parents=False)
        self.created_root = True
        self.run_id = uuid.uuid4().hex[:12]
        if self.args.service_manager == 'system':
            need(self.args.system_plan is not None and self.args.system_plan_sha256 is not None
                 and self.args.system_unit_helper is not None and self.args.runtime_observer is not None,
                 'system_plan_helpers_required')
            need(file_sha(self.args.system_plan) == self.args.system_plan_sha256, 'system_plan_pin')
            self.system_plan = json.loads(self.args.system_plan.read_bytes())
            plan = self.system_plan
            need(plan['schema'] == 'heptabao.installed-supervisor-system-plan.v1'
                 and plan['workDir'] == str(self.root)
                 and re.fullmatch(r'[a-f0-9]{12}',plan['runId']) is not None
                 and plan['entrySha256'] == self.args.entry_sha256
                 and plan['coreSha256'] == self.args.core_sha256 and len(plan['units']) == 2,
                 'system_plan_exact_scope')
            self.root_helper_source = self.args.system_unit_helper.read_bytes()
            need(sha(self.root_helper_source) == plan['helperSha256'], 'system_unit_helper_pin')
            self.root_observer_source = self.args.runtime_observer.read_bytes()
            need(sha(self.root_observer_source) == plan['runtimeObserverSha256'], 'runtime_observer_pin')
            self.run_id = plan['runId']
            self.report['systemInstallPlan'] = {'path':str(self.args.system_plan),
                    'sha256':self.args.system_plan_sha256,'helperSha256':plan['helperSha256'],
                    'runtimeObserverSha256':plan['runtimeObserverSha256'],
                    'actor':plan['actor'],'unitNames':[entry['name'] for entry in plan['units']]}
        for name in ('code','logs','phases','grants'):
            (self.root / name).mkdir(mode=0o700)
        for rel, expected in HELPERS.items():
            need(file_sha(self.args.source_root / rel) == expected, 'original_helper_pin')
        sys.path.insert(0,str(self.args.source_root / 'qa/openbao-acceptance'))
        import owned_process as owned
        owned_process = owned
        self.manager('actual_manager_preflight',['show','--property=Version'])
        smoke = load(self.args.source_root / 'qa/single-node/smoke.py',
                     HELPERS['qa/single-node/smoke.py'],'installed_normal_smoke')
        snapshot = load(self.args.source_root / 'qa/openbao-acceptance/kv2_271_lossless_native_live.py',
                        HELPERS['qa/openbao-acceptance/kv2_271_lossless_native_live.py'],'installed_snapshot_leaf')
        self.check('normal_binary_pin',file_sha(self.args.binary) == BINARY_SHA)
        self.check('normal_build_receipt_pins',file_sha(self.args.native_receipt)==NATIVE_RECEIPT_SHA
                   and file_sha(self.args.build_result)==BUILD_RESULT_SHA)
        native=json.loads(self.args.native_receipt.read_bytes())
        build=json.loads(self.args.build_result.read_bytes())
        self.check('normal_source_identity',native.get('source_commit')==COMMIT
                   and native.get('source_tree')==TREE and native.get('binary_sha256')==BINARY_SHA
                   and build.get('source_commit')==COMMIT and build.get('source_tree')==TREE)
        self.report['normalServer'] = {'commit':COMMIT,'tree':TREE,'binarySha256':BINARY_SHA,
                                      'fixtureOptions':False,'storage':'native_v6_file',
                                      'nativeReceiptSha256':NATIVE_RECEIPT_SHA,'buildResultSha256':BUILD_RESULT_SHA}
        need(file_sha(self.args.entry_source) == self.args.entry_sha256
             and file_sha(self.args.core_source) == self.args.core_sha256, 'reviewed_entry_source_pins')
        self.entry_path = self.root / 'code/authbus_coordinator_installed.py'
        core_path = self.root / 'code/authbus_coordinator.py'
        private(self.entry_path,self.args.entry_source.read_bytes())
        private(core_path,self.args.core_source.read_bytes())
        self.entry = load(self.entry_path,self.args.entry_sha256,'installed_live_entry')
        self.central = self.entry.load_core(self.args.core_sha256)
        if self.args.service_manager == 'system':
            need(self.system_plan['actor'] == self.entry.current_service_identity(), 'actual_nonroot_system_plan_actor')
        self.report['sourcePins'] = {'entry':self.args.entry_sha256,'core':self.args.core_sha256,
                                    'driver':file_sha(__file__),'helpers':HELPERS}

        run = self
        class Normal(smoke.Instance):
            def __init__(self,binary,root):
                super().__init__(binary,root)
                config = json.loads((root/'server.json').read_bytes())
                need('storage'not in config,'fresh_normal_storage_selection')
                config['storage']={'native_v6_file':{'path':config['data_dir']}}
                private(root/'server.json',config,replace=True)
            def start(self):
                self.log = open(self.root/'server.log','ab')
                self.process = owned_process.popen(
                    [str(self.binary),'--config',str(self.root/'server.json')],
                    stdout=self.log,stderr=self.log,label='installed.normal-server',action='KILL',stop_timeout=5)
                endpoint = snapshot.Endpoint(self.address,self.root/'ca.crt',self.token,run,'normal-server')
                deadline = time.monotonic() + READINESS_SECONDS
                try:
                    while time.monotonic()<deadline:
                        need(self.process.poll()is None,'normal_server_startup_exit')
                        try:
                            status,_ = endpoint.call('GET','sys/health',budget=min(2,deadline-time.monotonic()))
                            if status in (200,501,503):return
                        except snapshot.Failure:
                            pass
                        time.sleep(.05)
                    raise Failure('normal_server_original_startup_deadline')
                except BaseException:
                    self.stop();raise
        self.server = Normal(self.args.binary,self.root/'server')
        self.server.start()
        self.endpoint = snapshot.Endpoint(self.server.address,self.server.root/'ca.crt','',self,'target')
        status, value = self.endpoint.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
        self.check('formal_init',status==200)
        self.endpoint.token = self.server.token = value['root_token']
        unseal = value['keys_base64'][0]
        self.secrets.extend((self.endpoint.token,unseal))
        private(self.root/'recovery.private.json',{'rootToken':self.endpoint.token,'unsealKey':unseal})
        self.check('formal_unseal',self.endpoint.call('POST','sys/unseal',{'key':unseal})[0]==200)
        self.check('formal_activate',self.endpoint.call('POST','sys/storage/native-v6/activate',{})[0]==204)
        status,capacity=self.endpoint.call('GET','sys/internal/capacity')
        capacity=capacity.get('data',capacity)
        self.check('formal_native_capacity',status==200 and capacity.get('state_storage_format')=='heptabao-state-records-v6'
                   and capacity.get('native_kv2_reader_format')==2)
        self.check('authbus_mount',self.endpoint.call('POST','sys/mounts/openclaw-auth',
                   {'type':'kv','options':{'version':'2'}})[0]==204)
        self.check('approle_mount',self.endpoint.call('POST','sys/auth/approle',{'type':'approle'})[0]==204)
        policy = '\n'.join((
          'path "openclaw-auth/data/manifest" { capabilities=["create","read","update"] }',
          'path "openclaw-auth/data/profiles/*" { capabilities=["create","read"] }',
          'path "openclaw-auth/data/coordinator-receipts/*" { capabilities=["create","read"] }',
          'path "openclaw-auth/metadata/inbox/' + SOURCE_HOST + '" { capabilities=["list"] }',
          'path "openclaw-auth/data/inbox/' + SOURCE_HOST + '/*" { capabilities=["read"] }',
          'path "auth/token/renew-self" { capabilities=["update"] }',
          'path "auth/token/revoke-self" { capabilities=["update"] }'))
        self.check('writer_policy',self.endpoint.call('POST','sys/policies/acl/'+WRITER,{'policy':policy})[0]==204)
        route='auth/approle/role/'+WRITER
        self.check('writer_role',self.endpoint.call('POST',route,{'token_policies':[WRITER],'token_ttl':'1200s',
                   'token_max_ttl':'1800s','secret_id_ttl':'3600s','secret_id_num_uses':0})[0]==204)
        status,role=self.endpoint.call('GET',route+'/role-id')
        self.check('writer_role_id',status==200)
        status,sid=self.endpoint.call('POST',route+'/secret-id',{})
        self.check('writer_secret_id',status==200)
        role_id,secret=role['data']['role_id'],sid['data']['secret_id']
        self.secrets.extend((role_id,secret,sid['data']['secret_id_accessor']))
        credentials=self.root/'credentials';credentials.mkdir(mode=0o700)
        for name,data in (('ca.crt',(self.server.root/'ca.crt').read_bytes()),
                          ('role_id',role_id.encode()),('secret_id',secret.encode())):
            private(credentials/name,data)
        der=__import__('ssl').PEM_cert_to_DER_cert((self.server.root/'tls.crt').read_text())
        owner=str(uuid.uuid4());state=self.root/'owner-state-a'
        self.execute('prepare_owner_state',['/usr/bin/python3','-I','-S','-B',str(self.entry_path),
                     'prepare-state','--state-dir',str(state),'--owner-id',owner,'--source-host',SOURCE_HOST])
        config={'schema':self.entry.SCHEMA+'.config','production_cutover':True,'owner_id':owner,
                'service_scope':{'manager':self.args.service_manager,**self.entry.current_service_identity()},
                'source_hosts':[SOURCE_HOST],'state_dir':str(state),'address':self.server.address,
                'server_certificate_sha256':sha(der),'ca_file':str(credentials/'ca.crt'),
                'role_id_file':str(credentials/'role_id'),'secret_id_file':str(credentials/'secret_id'),
                'request_timeout_seconds':10,'poll_interval_seconds':15}
        unit=self.install_unit(self.root/'installation-a',config,'install_a')
        self.cli(unit,'initialize','initialize')
        a={'provider':'openai','type':'oauth','accountId':'synthetic-installed-owner-account',
           'access':'synthetic-installed-access-'+secrets.token_hex(16),
           'refresh':'synthetic-installed-refresh-'+secrets.token_hex(16),'expires':int(time.time()*1000)+86400000}
        b={**a,'access':'synthetic-installed-access-'+secrets.token_hex(16),
           'refresh':'synthetic-installed-refresh-'+secrets.token_hex(16),'expires':a['expires']+3600000}
        self.secrets.extend(c[k]for c in (a,b)for k in ('access','refresh'))
        self.event(a)
        self.start_unit(unit,'ungranted_unit')
        deadline=time.monotonic()+READINESS_SECONDS
        while time.monotonic()<deadline and not(state/'inbox-scan.private.json').exists():time.sleep(.1)
        self.check('ungranted_cycle_completed', (state/'inbox-scan.private.json').exists())
        self.check('ungranted_manifest_empty',self.head()['data']['profiles']==[])
        self.stop_unit(unit,'ungranted_stop')
        ga=self.grant(a,None,'enroll-a')
        self.cli(unit,'authorize_a','authorize',grant=ga)
        self.start_unit(unit,'publish_a_unit')
        ma=self.wait_manifest(unit,self.central.digest(a),'actual_unit_published_a')
        self.stop_unit(unit,'publish_a_stop')
        gb=self.grant(b,self.central.digest(a),'rotate-b')
        self.cli(unit,'authorize_b','authorize',grant=gb)
        self.event(b)
        self.fault(unit,'event_crash','event-crash')
        self.check('event_manifest_committed_before_ack',self.head()['data']['profiles'][0]['digest']==self.central.digest(b)
                   and json.loads((state/'pending.private.json').read_bytes())['phase']=='manifest_dispatched')
        backup=self.capture_pair(unit)
        original_head=self.head()
        self.start_unit(unit,'actual_manager_event_recovery')
        deadline=time.monotonic()+READINESS_SECONDS
        while time.monotonic()<deadline and(state/'pending.private.json').exists():time.sleep(.1)
        self.check('actual_manager_cleared_event_pending',not(state/'pending.private.json').exists())
        self.check('actual_manager_no_manifest_replay',self.head()['metadata']['version']==original_head['metadata']['version'])
        self.stop_unit(unit,'recovered_stop')
        gc=self.grant(a,self.central.digest(b),'post-snapshot-grant')
        self.cli(unit,'post_snapshot_mutation','authorize',grant=gc)
        self.check('post_snapshot_mutation_observed',self.head()['metadata']['version']==original_head['metadata']['version']+1)
        status,_=self.endpoint.call('POST','sys/storage/raft/snapshot',archive_in=backup/'native-snapshot.tar.gz')
        self.check('real_snapshot_restore_once',status==200)
        old=self.server.process;self.server.stop()
        self.check('actual_normal_sigkill_wait',old.returncode==-9)
        self.server.start()
        self.check('restored_cold_starts_sealed',self.endpoint.call('GET','sys/health')[0]==503)
        self.check('restored_cold_unseal',self.endpoint.call('POST','sys/unseal',{'key':unseal})[0]==200)
        self.check('restored_exact_remote_manifest',self.head()==original_head)
        restored=self.root/'owner-state-restored';restored.mkdir(mode=0o700)
        for path in sorted((backup/'owner').iterdir()):private(restored/path.name,path.read_bytes())
        cfg_restore={**config,'state_dir':str(restored)}
        restored_unit=self.install_unit(self.root/'installation-restored',cfg_restore,'install_restored')
        self.check('restored_original_owner_anchor',
                   file_sha(restored/'owner.private.json')==file_sha(backup/'owner/owner.private.json'))
        self.start_unit(restored_unit,'paired_actual_manager_recovery')
        deadline=time.monotonic()+READINESS_SECONDS
        while time.monotonic()<deadline and(restored/'pending.private.json').exists():time.sleep(.1)
        self.check('paired_pending_recovered',not(restored/'pending.private.json').exists())
        self.check('paired_original_manifest_not_replayed',self.head()==original_head)
        self.stop_unit(restored_unit,'paired_recovered_stop')
        config_path=Path(restored_unit['binding'].value['config']['path'])
        original_config=config_path.read_bytes()
        private(config_path,{**cfg_restore,'poll_interval_seconds':16},replace=True)
        self.start_unit(restored_unit,'known_binding_failure',failure=2)
        private(config_path,original_config,replace=True)
        unknown_grant=self.grant(a,self.central.digest(b),'unknown-admin')
        self.fault(restored_unit,'operator_post_response_error','operator-post-response-error',grant=unknown_grant)
        unknown_head=self.head()
        self.start_unit(restored_unit,'unknown_pending_failure',failure=3)
        reconciliation=self.cli(restored_unit,'explicit_readonly_admin_reconcile','reconcile')
        self.check('actual_readonly_reconciliation',reconciliation['resolution']=='desired_manifest_confirmed'
                   and reconciliation['remoteWrites']==0 and self.head()==unknown_head)
        self.cli(restored_unit,'explicit_revoke','revoke-authorization',grant=unknown_grant)
        self.start_unit(restored_unit,'final_owner_rearm')
        self.stop_unit(restored_unit,'final_owner_stop')
        self.check('sources_unchanged',file_sha(self.args.entry_source)==self.args.entry_sha256
                   and file_sha(self.args.core_source)==self.args.core_sha256
                   and all(file_sha(self.args.source_root/r)==h for r,h in HELPERS.items()))
        self.report.update(realUserManagerTested=self.args.service_manager == 'user',
                           realSystemManagerTested=self.args.service_manager == 'system',formalNormalServerQualified=True,
                           pairedOwnerKvRestoreQualified=True,ok=True)


def main():
    if len(sys.argv)==3 and sys.argv[1]=='--fault-worker':
        return fault_worker(Path(sys.argv[2]))
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source-root','binary','native-receipt','build-result','entry-source','core-source','work-dir'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--entry-sha256',required=True)
    parser.add_argument('--core-sha256',required=True)
    parser.add_argument('--service-manager',choices=('user','system'),default='user')
    parser.add_argument('--system-plan',type=Path)
    parser.add_argument('--system-plan-sha256')
    parser.add_argument('--system-unit-helper',type=Path)
    parser.add_argument('--runtime-observer',type=Path)
    args=parser.parse_args()
    os.umask(0o077)
    run=Run(args)
    try:
        run.run()
    except Exception as exc:
        run.report['ok']=False
        run.report['error']=str(exc)if isinstance(exc,Failure)else type(exc).__name__
    finally:
        if owned_process is not None and run.created_root:
            run.cleanup()
        if run.created_root:
            run.report['ok']=run.report['ok']and run.report.get('ownedCleanupComplete')is True
            rendered=json.dumps(run.report,sort_keys=True)
            if any(secret in rendered for secret in run.secrets):
                run.report={'schema':'heptabao.authbus-installed-supervisor-normal-live.v1','ok':False,
                            'error':'public_result_contains_secret','ownedCleanupComplete':run.report.get('ownedCleanupComplete')}
            private(run.root/'result.public.json',run.report)
    print(json.dumps({'ok':run.report['ok'],'checks':len(run.report.get('checks',[])),
                      'resultPath':str(run.root/'result.public.json'),'error':run.report.get('error'),
                      'ownedCleanupComplete':run.report.get('ownedCleanupComplete')},sort_keys=True))
    return 0 if run.report['ok']else 1


if __name__=='__main__':
    raise SystemExit(main())
