#!/usr/bin/env python3
"""Independent, once-only cleanup of a reconciled failed Mac QA registration.

No business replay, production mutation, original result overwrite, or data deletion.
"""
import ast
import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys
import time

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r1')
HOME = Path('/Users/qianqi/heptabao-mac-fresh-synthetic-launchd-20261106-r1')
LABEL = 'org.heptabao.qa.mac-fresh-synthetic-20261106-r1.server'
TARGET = 'gui/501/' + LABEL
PID = 19545
KERNEL_PYTHON = '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python'
LAUNCHER = '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
MANAGER_SHA = '045a93a547ba5237b2d787b6e1724ca9ae0c8529b43736d7f98f28cf46078cdf'
OBSERVER_SHA = 'cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b'

class Refused(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def safe_read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501
             and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
             'bounded_regular_owner_file')
        raw = os.read(fd, maximum + 1)
        need(len(raw) == before.st_size and not os.read(fd, 1), 'whole_file_read')
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             'stable_whole_file_identity')
        return raw, identity(before)
    finally:
        os.close(fd)

def walk(value):
    pending = [('$', value)]
    visited = 0
    while pending:
        path, item = pending.pop()
        visited += 1
        need(visited < 15000, 'bounded_public_json_tree')
        if isinstance(item, dict):
            yield path, item
            pending.extend((path + '.' + str(k), v) for k, v in item.items()
                           if isinstance(v, (dict, list)))
        elif isinstance(item, list):
            pending.extend((path + '[' + str(i) + ']', v) for i, v in enumerate(item)
                           if isinstance(v, (dict, list)))

def extract(raw, names, namespace):
    nodes = [n for n in ast.parse(raw).body
             if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
    need(len(nodes) == len(names) and {n.name for n in nodes} == set(names),
         'exact_pinned_pure_definitions')
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<pinned-readonly-definitions>', 'exec'), namespace)
    return namespace

import errno

RECOVERY_ROOT = Path('/Users/qianqi/heptabao-mac-fresh-synthetic-recovery-20261106-r1')
WRAPPER_SHA = 'bb489d899e7284d2d4eb31008d40f8a6bcc7025b8b1ac7628551a02d83a4668e'
EXPECTED_IDENTITY = {
    'pid': 19545, 'ppid': 1, 'pgid': 19545, 'uid': 501,
    'birthSec': 1793977415, 'birthUsec': 45274, 'executable': str(ROOT / 'bin/heptabao-server'),
}
CLEANUP_SECONDS = 60
OBSERVATION_GRACE_SECONDS = 20
KILL_GRACE_SECONDS = 10
QUERY_SECONDS = 10
PS_SECONDS = 4
POLL_SECONDS = 0.25
READONLY_JOB = '1a1b16b55a9-fc05-788b'
PRIOR_JOURNAL = Path('/Users/qianqi/heptabao-mac-fresh-synthetic-journal-20261106-r1')
PREPARATION = Path('/Users/qianqi/heptabao-mac-fresh-synthetic-recovery-preparation-20261106-r1')
PRIOR_JOURNAL_PINS = {'000-run-intent.public.json': '91b3f36a99641f6f109fe2db5ecc3ed7c9bdfff5bcf109397ecefb7378f0ac56', '001-mutation-intent.public.json': 'e6bb27f86f3828a3652b6ceedafe0a4953550fcc8ae557029bb4ed3aa2d5dd57', '002-mutation-result.public.json': 'f6834fdd5025ac64cc91d179a10bc1ab37e590b8a0bb8bc837daef4cc4715725', '003-bootstrap-cleanup-custody.public.json': '293c6f9411da1fc3c5cd2683bb273a95a66a3556d9010fde21007b8c36af8dc7', '004-mutation-observed.public.json': '45cf2638fb9d18fc1dcfe2b08fa9f272448a058efa502ac98c690ae7e9eb702c', '005-cleanup-refused.public.json': '9f0b73f3803749c8ea7a6ffe182b38f65063f646eb1ce6fa2b90e2fda3945545', '006-complete-command-batch.public.json': '0f38564fb5b6d2bb2cd43c6f91fb92316e80581e4192c8b79cc51a3857cd1673', '007-complete-command-batch.public.json': '608885d6695b1b128f8b98ba53c0ac5b471a3eed8e1e109c421d1776ff839fc3', '008-final-result.public.json': '5eb9d7c693b44964b75787103e17650e9d3816b15f152fc4e189d87b0301a1c8'}
PRIOR_TERMINAL_SHA = '0cb483064febed69d449e22049018144418d378842d1aa073aa97adf76cdfb2d'
PRIOR_STDOUT_SHA = 'fe56d76f0cc543abc476c3c7ea00f5dd717a608cbb1f02839456b79d51cb8bc4'


BINARY_SHA = '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
SYSTEM_PS_SHA = '3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c'
READONLY_TERMINAL_SHA = 'b8f3362e0677add0f7945a42251e8c028f02d7c2e055b5094f916911dcb83d5b'
READONLY_STDOUT_SHA = 'a8c70efe87ccc9942a7256eeb5a056272504e964718ced7c3e46d5c9391997f8'
WRAPPER_STDOUT_SHA = 'bf7dca3dd640e28fac7b1379dc8cb925fb5ef12c3d53af83435da17487b82d1e'
CONTROL_PINS = {'/Volumes/T5/hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r1/launchd/000-server-initial-bootstrap-intent.public.json': '883f36189ebfb5d2d66902a6ed3a2a1c559c8a9bdd3d0d9de43f69c3ba3a0f59', '/Volumes/T5/hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r1/launchd/001-server-initial-actual-wrapper-admitted.public.json': '0177ee20d282e69d8c70449b17c5d3b41fc2651e685760ff7402083f9cd910d1', '/Volumes/T5/hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r1/launchd/002-server-initial-actual-server-exec.public.json': '29f22a50a7af8951f2a4b3d27668bb03d484ff1df298eab8986667f7f1d4a89a', '/Volumes/T5/hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r1/launchd/server-initial.ready.public.json': 'e18736f90d1d0f0e1a3f2a8b6053aec7b257e3b5d2e203c8d1717b9c720727b1', '/Volumes/T5/hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r1/launchd/server-initial.admitted.private.json': '9c31cd3d155b010801e1983c7bbe01935f7a3f6ffbbbbdcc018fa0d3e24c8a2c', '/Volumes/T5/hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r1/launchd/server-initial.exec-ready.public.json': '03f6f88abf89b4abbd11c8d53c86784df50c5d043c7c2efc332c1bb7900b9a01', '/Volumes/T5/hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r1/launchd/server-initial.private.json': 'a6bb86cf3ee2a85310841568ae88f0c87c396e8000994342a8bb78f4a83d6ee5', '/Volumes/T5/hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r1/launchd/server-initial.cleanup-intent.public.json': '2a1a1fcedd5f9640e1d904dd37c97b9f0b1e36bf4d60912eb5d04dc3a775e559', '/Users/qianqi/heptabao-mac-fresh-synthetic-launchd-20261106-r1/server-initial.plist': 'e474f8965063e67336795a78e9371c43d84bf244fe055c6676e8dc67d98c69d4'}

class Journal:
    """One create-only recovery directory, held by fd; no resume or overwrite."""

    def __init__(self):
        self.fd = None
        self.closed = False
        self.written = []
        parent = os.open(RECOVERY_ROOT.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(parent)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == 501
                 and not info.st_mode & 0o022, 'private_operator_parent')
            os.mkdir(RECOVERY_ROOT.name, 0o700, dir_fd=parent)
            os.fsync(parent)
            self.fd = os.open(RECOVERY_ROOT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=parent)
        finally:
            os.close(parent)
        info = os.fstat(self.fd)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 501
             and stat.S_IMODE(info.st_mode) == 0o700, 'new_private_journal')
        self.bound = identity(info)[:5]
        self.check()

    def check(self):
        need(self.fd is not None and not self.closed, 'journal_fd_open')
        need(identity(os.fstat(self.fd))[:5] == identity(RECOVERY_ROOT.lstat())[:5] == self.bound,
             'held_named_journal_identity')

    def write_new(self, name, value):
        self.check()
        need(re.fullmatch(r'[0-9]{3}-[a-z0-9-]+\.public\.json', name) is not None
             and name not in self.written, 'once_fixed_journal_leaf')
        raw = (json.dumps(value, sort_keys=True) + '\n').encode()
        need(len(raw) <= 262144, 'bounded_journal_record')
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 501
                 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                 'private_regular_journal_leaf')
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                need(count > 0, 'journal_write_progress')
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self.fd)
        self.check()
        self.written.append(name)
        return sha(raw)

    def close_once(self):
        if self.fd is None or self.closed:
            return
        self.check()
        fd = self.fd
        self.fd = None
        os.close(fd)
        self.closed = True


class Recovery:
    """A new cleanup-only operation; never reopens the old business state machine."""

    def __init__(self):
        self.started = time.monotonic()
        self.until = self.started + CLEANUP_SECONDS
        self.journal = None
        self.bindings = []
        self.attempts = {}
        self.commands = []
        self.observation_count = 0
        self.report = {
            'schema': 'heptabao.mac-fresh-synthetic-r1-recovery-cleanup.r1',
            'failedSyntheticCampaignJob': '1a1b162f30c-fc05-7833',
            'newOperationAllowsTerm': False,
            'originalSyntheticFailurePreserved': True,
            'knownReadonlyDiagnosticFailureJob': '1a1b167bf27-fc05-7867',
            'originalQaSignalAndBootoutAttemptsWereEmpty': True,
            'executedHelperSha256': globals().get('__source_sha256__'),
            'ok': False, 'recoveryOutcomeUnknown': False, 'target': TARGET,
            'expectedCurrentIdentity': EXPECTED_IDENTITY, 'readOnlyReconciliationJob': READONLY_JOB,
            'cleanupSeconds': CLEANUP_SECONDS, 'freshObservationSeconds': OBSERVATION_GRACE_SECONDS,
            'killGraceSeconds': KILL_GRACE_SECONDS, 'querySeconds': QUERY_SECONDS,
            'psSeconds': PS_SECONDS, 'originalBusinessDeadlineRenewed': False,
            'originalFailedResultModified': False, 'oldManagerImported': False,
            'oldBirthIdentityReconstructed': False, 'originalRunSuccessClaimed': False,
            'businessExecutionStarted': False, 'providerRequested': False, 'j3160Contacted': False,
            'productionServiceOperationDispatched': False, 'dataFilesDeleted': False,
            'noNumericQaPidOrGroupSignals': True, 'credentialValuesOrDigestsIncluded': False,
            'hostileEscapedDescendantContainmentClaimed': False,
            'serviceMutationAttempts': self.attempts,
            'helperCommandReceipts': self.commands,
            'newJournalRoot': str(RECOVERY_ROOT),
        }

    def remaining(self, cap=None):
        value = self.until - time.monotonic()
        need(value > 0, 'single_recovery_cleanup_deadline')
        return value if cap is None else min(value, cap)

    def read_bound(self, path, maximum, public_name=None, required_sha=None):
        self.remaining()
        raw, bound = safe_read(path, maximum)
        self.remaining()
        digest = sha(raw)
        if required_sha is not None:
            need(digest == required_sha, 'pinned_immutable_public_source')
        self.bindings.append((path, maximum, bound, digest))
        if public_name is not None:
            self.report.setdefault('publicInputSha256', {})[public_name] = digest
        return raw

    def guard(self):
        self.remaining()
        for path, maximum, bound, digest in self.bindings:
            raw, current = safe_read(path, maximum)
            need(current == bound and sha(raw) == digest, 'original_input_changed')
            self.remaining()
        if getattr(self, 'prior_failure_verified', False):
            need(identity(PRIOR_JOURNAL.lstat()) == self.prior_journal_identity
                 and sorted(os.listdir(PRIOR_JOURNAL)) == sorted(PRIOR_JOURNAL_PINS),
                 'failed_campaign_journal_inventory_unchanged')
            need(identity(Path('/bin/ps').lstat()) == self.system_ps_identity,
                 'fixed_setuid_system_ps_identity_unchanged')
            need(identity((ROOT/'bin/heptabao-server').lstat()) == self.binary_identity,
                 'qualified_owned_binary_identity_unchanged')
            info=self.BsdInfo();ctypes.set_errno(0)
            count=self.reader.lib.proc_pidinfo(19659,3,0,ctypes.byref(info),ctypes.sizeof(info))
            need(count==0 and ctypes.get_errno()==errno.ESRCH,'prior_unknown_readonly_helper_still_absent')
        if self.journal is not None:self.journal.check()
        self.remaining()

    def call(self, label, argv, cap=QUERY_SECONDS):
        self.remaining()
        need(len(self.commands) < 384, 'finite_recovery_command_count')
        row = {'index': len(self.commands), 'label': label, 'attempted': True,
               'complete': False, 'outcomeUnknown': False}
        self.commands.append(row)
        try:
            proc = subprocess.run(argv, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.remaining(cap), check=False,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
            self.remaining()
            need(len(proc.stdout) <= 262144 and len(proc.stderr) <= 4096,
                 'bounded_helper_output')
            row.update(complete=True, exitCode=proc.returncode,
                       stdoutBytes=len(proc.stdout), stderrBytes=len(proc.stderr))
            return row, proc.stdout, proc.stderr
        except BaseException:
            row['outcomeUnknown'] = True
            self.report['recoveryOutcomeUnknown'] = True
            raise

    def preflight(self):
        need(sys.platform == 'darwin' and os.geteuid() == 501, 'fixed_mac_operator')
        need(re.fullmatch(r'[0-9a-f]{64}',str(globals().get('__source_sha256__'))) is not None,
             'source_hash_supplied_by_pinned_loader')
        manager=self.read_bound(ROOT/'qa/mac_owned_launchd_r3.py',65536,'pinnedSyntheticManager',MANAGER_SHA)
        self.parse=extract(manager,['parse_print'],{'need':need,'re':re})['parse_print']
        observer=self.read_bound(ROOT/'qa/mac_native_process_observer_r1.py',65536,'libprocObserver',OBSERVER_SHA)
        ns=extract(observer,['ObservationRefused','require','BsdInfo','ProcessReader'],
                   {'ctypes':ctypes,'Path':Path,'sys':sys})
        self.reader=ns['ProcessReader']();self.BsdInfo=ns['BsdInfo']
        for path in (ROOT/'qa/mac_current_server_owner_r1.py',HOME/'mac_current_server_owner_r1.py'):
            self.read_bound(path,65536,'wrapper-'+str(path),WRAPPER_SHA)
        self.verify_prior_recovery()
        self.plist_path=HOME/'server-initial.plist'
        plist_raw=self.read_bound(self.plist_path,65536,'originalPlist',CONTROL_PINS[str(self.plist_path)])
        plist=plistlib.loads(plist_raw);self.args=plist.get('ProgramArguments')
        need(isinstance(self.args,list) and self.args[:5]==[LAUNCHER,'-I','-S','-B',
             str(HOME/'mac_current_server_owner_r1.py')],'exact_python_wrapper_prefix')
        expected_plist={'Label':LABEL,'ProgramArguments':self.args,'RunAtLoad':True,'KeepAlive':False,
            'AbandonProcessGroup':False,'ProcessType':'Background','ExitTimeOut':10,'Umask':0o077,
            'WorkingDirectory':str(HOME),'StandardOutPath':str(HOME/'server-initial.stdout.private'),
            'StandardErrorPath':str(HOME/'server-initial.stderr.private'),
            'EnvironmentVariables':{'PATH':'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C'}}
        need(plist==expected_plist,'entire_original_plist_no_restart')
        for path,pin in CONTROL_PINS.items():
            if Path(path)!=self.plist_path:self.read_bound(Path(path),65536,'original-control-'+Path(path).name,pin)
        wrapper_raw=self.read_bound(HOME/'server-initial.stdout.private',65536,'actualWrapperTerminal',WRAPPER_STDOUT_SHA)
        wrapper=json.loads(wrapper_raw)
        wrapper_identity=dict(EXPECTED_IDENTITY,executable=KERNEL_PYTHON)
        need(wrapper['ok'] is True and wrapper['readyToExec'] is True and wrapper['outcomeUnknown'] is False
             and wrapper['wrapperIdentity']==wrapper_identity and wrapper['binarySha256']==BINARY_SHA
             and wrapper['elapsedSeconds']<30 and wrapper['volumeGuardClosed']['allDescriptorsClosed'] is True
             and wrapper['commands']['allOwnedCommandsStopped'] is True,'original_wrapper_completion_binding')
        ready=json.loads(safe_read(ROOT/'launchd/server-initial.ready.public.json',4096)[0])
        admission=json.loads(safe_read(ROOT/'launchd/server-initial.admitted.private.json',4096)[0])
        need(ready['wrapperIdentity']==admission['wrapperIdentity']==wrapper_identity
             and ready['planSha256']==admission['planSha256']=='a6bb86cf3ee2a85310841568ae88f0c87c396e8000994342a8bb78f4a83d6ee5',
             'existing_ready_admission_are_original_not_replayed')
        plan_raw=safe_read(ROOT/'launchd/server-initial.private.json',4096)[0]
        plan=json.loads(plan_raw)
        need(plan['binaryPath']==str(ROOT/'bin/heptabao-server') and plan['binarySha256']==BINARY_SHA
             and plan['binaryBytes']==92359328 and plan['workRoot']==str(ROOT),'exact_original_server_plan')
        self.read_bound(ROOT/'server/server.json',4096,'syntheticConfig',wrapper['configSha256'])
        self.binary_identity=self.pin_executable(ROOT/'bin/heptabao-server',501,0o500,92359328,BINARY_SHA)
        need(tuple(map(str,self.binary_identity))==tuple(wrapper['binaryIdentity']),'same_original_binary_file_identity')
        self.system_ps_identity=self.pin_executable(Path('/bin/ps'),0,0o4755,170432,SYSTEM_PS_SHA)
        self.prior_failure_verified=True
        self.guard();first=self.observe();second=self.observe()
        need(first['state'] in ('live','retired') and second['state'] in ('live','retired')
             and not(first['state']=='retired' and second['state']=='live'),'current_full_birth_or_known_retirement')
        self.report['initialObservation']=second
        self.journal=Journal()
        intent={'schema':'heptabao.mac-fresh-synthetic-independent-cleanup-intent.r1',
            'target':TARGET,'expectedCurrentIdentity':EXPECTED_IDENTITY,
            'publicInputSha256':self.report['publicInputSha256'],'readOnlyReconciliationJob':READONLY_JOB,
            'originalCampaignJob':'1a1b162f30c-fc05-7833','originalCampaignRemainsFailed':True,
            'originalBootstrapOnlyLedgerVerified':True,'priorUnknownPs19659NowAbsent':True,
            'cleanupSeconds':60,'freshObservationSeconds':20,'killGraceSeconds':10,
            'mutationOrder':['fresh-20-second-observation-if-live','optional-kill-once','bootout-once'],
            'noTermDispatchBranch':True,'noBusinessReplay':True,'noOriginalResultRewrite':True,
            'noNumericQaPidOrGroupSignals':True,'noDataFileDeletion':True,'initialObservation':second}
        self.report['durableInitialIntentSha256']=self.journal.write_new('001-intent.public.json',intent)
        self.guard()

    def pin_executable(self,path,uid,mode,size,digest):
        self.remaining();fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid==uid and before.st_nlink==1
                 and stat.S_IMODE(before.st_mode)==mode and before.st_size==size,'exact_executable_custody')
            seen=0;hasher=hashlib.sha256()
            while True:
                self.remaining();block=os.read(fd,1048576)
                if not block:break
                seen+=len(block);need(seen<=size,'bounded_executable_read');hasher.update(block)
            need(seen==size and hasher.hexdigest()==digest and identity(before)==identity(os.fstat(fd))
                 ==identity(path.lstat()),'whole_exact_executable_pin')
            return identity(before)
        finally:os.close(fd)


    def verify_prior_recovery(self):
        info=PRIOR_JOURNAL.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid==501 and stat.S_IMODE(info.st_mode)==0o700
             and sorted(os.listdir(PRIOR_JOURNAL))==sorted(PRIOR_JOURNAL_PINS),'exact_failed_campaign_journal')
        self.prior_journal_identity=identity(info);files={}
        for name,pin in PRIOR_JOURNAL_PINS.items():
            files[name]=json.loads(self.read_bound(PRIOR_JOURNAL/name,65536,'prior-'+name,pin))
        terminal=json.loads(self.read_bound(PREPARATION/'failed-campaign-status.public.json',8192,
            'authoritativeFailedCampaignTerminal',PRIOR_TERMINAL_SHA))
        raw=self.read_bound(PREPARATION/'failed-campaign-stdout.original',65536,'exactFailedCampaignStdout',PRIOR_STDOUT_SHA)
        prior=json.loads(raw)
        need(terminal['job_id']=='1a1b162f30c-fc05-7833' and terminal['state']=='failed' and terminal['exit_code']==1
             and terminal['output_complete'] is True and terminal['output_durable'] is True
             and terminal['terminal_publication_confirmed'] is True and terminal['timed_out'] is False
             and terminal['log_bytes']['stdout']=={'seen':len(raw),'stored':len(raw)}
             and terminal['log_bytes']['stderr']=={'seen':0,'stored':0},'known_failed_original_campaign_terminal')
        need(prior['ok'] is False and prior['errorCode']=='actual_complete_pinned_tls_health'
             and prior['manager']['completedOperationCount']==1 and prior['manager']['outcomeUnknown'] is True
             and prior['manager']['failureCleanupAttempted'] is True,'original_failure_preserved')
        entries=prior['manager']['registrations'];need(len(entries)==1,'single_original_registration')
        entry=entries[0];attempts=entry['attempts']
        need(entry['label']==LABEL and entry['generation']=='server-initial' and entry['execIdentity']==EXPECTED_IDENTITY
             and entry['knownOwnedGroups']==[PID] and not entry['registrationClosed'] and not entry['lineagesClosed']
             and set(attempts)=={'bootstrap'} and attempts['bootstrap']['attempted'] is True
             and attempts['bootstrap']['complete'] is True and attempts['bootstrap']['exitCode']==0
             and attempts['bootstrap']['command']['outcomeUnknown'] is False,'original_bootstrap_only_no_signal_ledger')
        commands=[]
        for name in ('006-complete-command-batch.public.json','007-complete-command-batch.public.json'):
            value=files[name]['value'];need(value['firstIndex']==len(commands),'original_command_order')
            commands.extend(value['commands'])
        unknown=[x for x in commands if x['outcomeUnknown']]
        need(len(commands)==17 and len(unknown)==1 and unknown[0] is commands[-1]
             and unknown[0]['argv']==['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,stat=']
             and unknown[0]['pid']==19659 and unknown[0]['cleanup']['errorCode']=='owned_child_scope_mismatch'
             and unknown[0]['cleanup']['signals']==[] and unknown[0]['streamsClosed'] is True,
             'exact_readonly_ps_unknown_not_qa_mutation')
        need(all(x['completeBeforeDeadline'] is True and x['outcomeUnknown'] is False for x in commands[:-1]),
             'all_prior_other_helpers_known')
        launch=[x for x in commands if x['argv'] and x['argv'][0]=='/bin/launchctl']
        need(sum(x['argv'][1]=='bootstrap' for x in launch)==1 and all(x['argv'][1] in ('print','bootstrap') for x in launch),
             'no_prior_qa_signal_or_bootout_command')
        intents=[x['value'] for x in files.values() if x['event']=='mutation-intent']
        need(len(intents)==1 and intents[0]['operation']=='bootstrap','only_bootstrap_durable_intent')
        self.report['priorCampaignLedger']={'commandCount':17,'priorUnknownReadonlyPsPid':19659,
            'bootstrapKnownExitZero':True,'termKillBootoutAttempts':0,'originalCampaignRemainsFailed':True}
        read_terminal=json.loads(self.read_bound(PREPARATION/'readonly-status.public.json',8192,
            'readonlyReconciliationTerminal',READONLY_TERMINAL_SHA))
        read_raw=self.read_bound(PREPARATION/'readonly-stdout.original',65536,'readonlyReconciliationStdout',READONLY_STDOUT_SHA)
        evidence=[json.loads(line) for line in read_raw.splitlines()]
        need(read_terminal['job_id']==READONLY_JOB and read_terminal['state']=='succeeded' and read_terminal['exit_code']==0
             and read_terminal['output_complete'] is True and read_terminal['output_durable'] is True
             and read_terminal['terminal_publication_confirmed'] is True and not read_terminal['timed_out']
             and read_terminal['log_bytes']['stdout']=={'seen':len(read_raw),'stored':len(read_raw)},
             'authoritative_readonly_reconciliation_terminal')
        actual=evidence[-1]
        need(len(evidence)==3 and actual['ok'] is True and actual['originalCampaignRemainsFailed'] is True
             and actual['knownServerIdentity']==EXPECTED_IDENTITY and actual['nativeChildren']==[]
             and actual['priorUnknownHelperFirst']==actual['priorUnknownHelperLast']=={'pid':19659,'bytes':0,'errno':3}
             and actual['serviceSignals']==[] and actual['bootoutAttempted'] is False,
             'readonly_current_birth_and_unknown_helper_absence')
        self.report['rootSetuidPsObserved']={'path':'/bin/ps','mode':0o4755,'uid':0,'sha256':SYSTEM_PS_SHA,
            'nativeReadDeniedIsNotOwnership':True,'serviceUidRemains501':True,
            'foregroundRunnerInheritedFromReviewedRecoveryR3':True}

    def query(self):
        row, out, err = self.call('launchctl-print', ['/bin/launchctl', 'print', TARGET])
        if row['exitCode'] in (3, 113) and not out:
            expected = 'Could not find service "' + LABEL + '" in domain for user gui: 501'
            lines = err.decode('utf-8', 'strict').splitlines()
            need(lines in ([expected], ['Bad request.', expected]), 'exact_absence_response')
            return None
        need(row['exitCode'] == 0 and not err, 'known_launchctl_query')
        depth = 0
        safe = {}
        for line in out.decode('utf-8', 'strict').splitlines():
            text = line.strip()
            if depth == 1 and ' = ' in text:
                name, value = text.split(' = ', 1)
                if name in ('pid', 'runs', 'state', 'last exit code', 'last terminating signal'):
                    need(len(value) <= 128 and value.isascii() and value.isprintable(),
                         'bounded_safe_launchctl_status_literal')
                    safe[name] = value
            depth += text.count('{') - text.count('}')
        self.report['lastLaunchctlSafeFields'] = safe
        try:
            state = self.parse(out, TARGET)
        except BaseException:
            self.report['launchctlParseFailureSafeFields'] = safe
            raise
        need(state.get('path') == str(self.plist_path) and state.get('program') == self.args[0]
             and state.get('arguments') == self.args and state.get('runs') == 1,
             'same_exact_registration_and_run')
        need(state.get('pid') in (None, PID), 'no_replacement_registration_pid')
        return state

    def related_rows(self):
        row, out, err = self.call('ps-fixed-metadata',
            ['/bin/ps', '-axo', 'pid=,ppid=,pgid=,uid=,stat='], PS_SECONDS)
        need(row['exitCode'] == 0 and not err, 'complete_process_metadata')
        rows = []
        for line in out.decode('ascii', 'strict').splitlines():
            fields = line.split()
            def refuse_row(code):
                # Only fixed numeric/STAT columns, never process arguments.
                self.report['rejectedProcessMetadataRow'] = {
                    'fields': [v[:64] for v in fields[:8]], 'fieldCount': len(fields),
                    'safeFixedColumnsOnly': True, 'fieldLengths': [len(v) for v in fields[:8]],
                    'relatedSelectors': fields[:3],
                }
                raise Refused(code)
            if not (len(fields) >= 3 and all(v.isdecimal() and len(v) <= 10 for v in fields[:3])):
                refuse_row('typed_process_selectors')
            pid, ppid, pgid = map(int, fields[:3])
            if not (pid == PID or ppid == PID or pgid == PID):
                continue
            if not (len(fields) == 5 and fields[3] == '501'
                    and re.fullmatch(r'[A-Za-z0-9+<>=-]{1,16}', fields[4]) is not None):
                refuse_row('typed_related_process_metadata')
            rows.append({'pid': pid, 'ppid': ppid, 'pgid': pgid, 'uid': 501, 'stat': fields[4]})
        self.report['lastRelatedProcessRows'] = rows
        return rows

    def native_absent(self):
        info = self.BsdInfo()
        ctypes.set_errno(0)
        count = self.reader.lib.proc_pidinfo(PID, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
        error = ctypes.get_errno()
        need(count == 0 and error == errno.ESRCH, 'native_original_pid_absent')
        return {'returnedBytes': count, 'errno': error, 'originalPidAbsent': True}

    def observe(self, allow_missing=False):
        self.guard()
        state = self.query()
        need(state is not None or allow_missing, 'no_unexplained_registration_disappearance')
        rows = self.related_rows()
        self.observation_count += 1
        record = {'index': self.observation_count, 'relatedProcessRows': rows,
                  'allRegisteredArgumentsExact': state is not None}
        if state is None:
            need(not rows, 'no_related_process_after_registration_absence')
            record.update(state='absent', nativePidAbsence=self.native_absent())
        elif state.get('pid') is None:
            need(not rows, 'no_pid_group_or_child_before_bootout')
            record.update(state='retired', nativePidAbsence=self.native_absent(),
                launchctlTerminal={k: state.get(k) for k in
                    ('runs', 'state', 'last exit code', 'last terminating signal')})
        elif not rows:
            record.update(state='retiring', nativePidAbsence=self.native_absent())
        else:
            need(len(rows) == 1 and rows[0]['pid'] == PID and rows[0]['ppid'] == 1
                 and rows[0]['pgid'] == PID and rows[0]['uid'] == 501,
                 'no_new_child_or_group_member')
            if 'Z' in rows[0]['stat']:
                info = self.BsdInfo()
                count = self.reader.lib.proc_pidinfo(PID, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
                need(count == ctypes.sizeof(info)
                     and (info.pid, info.ppid, info.pgid, info.uid, info.birth_sec, info.birth_usec)
                     == (PID, 1, PID, 501, EXPECTED_IDENTITY['birthSec'], EXPECTED_IDENTITY['birthUsec']),
                     'same_birth_retiring_zombie')
                record['state'] = 'retiring'
            else:
                current = self.reader.read(PID)
                need(current == EXPECTED_IDENTITY, 'exact_current_libproc_identity')
                children = self.reader.children(PID)
                need(children == [], 'no_new_direct_child')
                record.update(state='live', processIdentity=current, directChildPids=children)
        self.guard()
        return record

    def dispatch_once(self, operation):
        need(operation in ('kill', 'bootout') and operation not in self.attempts,
             'one_new_recovery_action_per_operation')
        need(not self.report['recoveryOutcomeUnknown']
             and all(c.get('complete') is True and not c.get('outcomeUnknown') for c in self.commands),
             'all_new_helper_outcomes_known_before_mutation')
        required_state = 'retired' if operation == 'bootout' else 'live'
        before = self.observe()
        need(before['state'] == required_state, 'mutation_precondition_exact_state')
        need(getattr(self, 'prior_failure_verified', False), 'pinned_failed_campaign_and_readonly_reconciliation_required')
        if operation == 'kill':
            need(self.report.get('newObservationGraceCompleted') is True
                 and self.report.get('newObservationGraceElapsedSeconds', 0) >= OBSERVATION_GRACE_SECONDS,
                 'kill_only_after_new_full_twenty_second_observation')
        if operation == 'bootout':
            need(all(a.get('complete') is True and a.get('exitCode') == 0 for a in self.attempts.values())
                 and self.report.get('retirementTerminalVerified') is True,
                 'bootout_only_after_known_retirement_and_mutations')
        number = {'kill': 20, 'bootout': 30}[operation]
        argv = {'kill': ['/bin/launchctl', 'kill', 'SIGKILL', TARGET],
                'bootout': ['/bin/launchctl', 'bootout', TARGET]}[operation]
        intent = {
            'schema': 'heptabao.mac-fresh-synthetic-cleanup-action-intent.r1',
            'operation': operation, 'argv': argv, 'expectedCurrentIdentity': EXPECTED_IDENTITY,
            'inputBindingsSha256': self.report['publicInputSha256'],
            'initialIntentSha256': self.report['durableInitialIntentSha256'],
            'before': before, 'remainingSecondsAtIntent': self.remaining(),
            'originalOperationWasNeverDispatched': True,
        }
        digest = self.journal.write_new('%03d-%s-intent.public.json' % (number, operation), intent)
        self.remaining()
        # The second observation occurs after the fsynced intent and before dispatch.
        second = self.observe()
        need(second['state'] == required_state, 'mutation_post_intent_state_unchanged')
        self.attempts[operation] = {'attempted': True, 'complete': False, 'intentSha256': digest}
        row, out, err = self.call('launchctl-' + operation, argv)
        self.attempts[operation].update(complete=True, exitCode=row['exitCode'])
        receipt = {'schema': 'heptabao.mac-fresh-synthetic-cleanup-command.r1',
                   'operation': operation, 'receipt': row,
                   'stdout': out.decode('utf-8', 'strict'), 'stderr': err.decode('utf-8', 'strict')}
        self.journal.write_new('%03d-%s-command.public.json' % (number + 1, operation), receipt)
        need(row['exitCode'] == 0 and not out and not err, 'known_empty_launchctl_mutation_success')
        self.guard()
        after = self.observe(allow_missing=operation == 'bootout')
        self.journal.write_new('%03d-%s-observed.public.json' % (number + 2, operation), after)
        self.report[operation + 'ImmediateAfter'] = after
        return after

    def wait_retired(self, seconds):
        grace_until = min(self.until, time.monotonic() + seconds)
        last = None
        while True:
            last = self.observe()
            need(last['state'] in ('live', 'retiring', 'retired'), 'finite_retirement_state')
            if last['state'] == 'retired':
                return last
            remaining = min(self.remaining(), grace_until - time.monotonic())
            if remaining <= 0:
                return last
            time.sleep(min(POLL_SECONDS, remaining))

    def new_observation_grace(self):
        need(self.remaining() >= OBSERVATION_GRACE_SECONDS, 'enough_budget_for_new_full_grace')
        started = time.monotonic()
        while True:
            current = self.observe()
            if current['state'] == 'retired':
                return current
            need(current['state'] in ('live', 'retiring'), 'bounded_new_observation_state')
            elapsed = time.monotonic() - started
            if elapsed >= OBSERVATION_GRACE_SECONDS:
                need(current['state'] == 'live', 'full_grace_same_live_birth_required_for_kill')
                self.report['newObservationGraceElapsedSeconds'] = elapsed
                self.report['newObservationGraceCompleted'] = True
                return current
            time.sleep(min(POLL_SECONDS, OBSERVATION_GRACE_SECONDS - elapsed, self.remaining()))

    def verify_retirement_terminal(self, retired):
        need(retired.get('state') == 'retired', 'known_original_wrapper_retired')
        terminal = retired.get('launchctlTerminal', {})
        self.report['retirementLaunchctlTerminal'] = terminal
        if 'kill' in self.attempts:
            need(self.attempts['kill'].get('complete') is True and self.attempts['kill'].get('exitCode') == 0
                 and terminal.get('last terminating signal') in ('9', 'SIGKILL', 'Killed: 9', '9 (Killed: 9)'),
                 'known_sigkill_retirement_terminal')
        else:
            signal_value = terminal.get('last terminating signal')
            exit_value = terminal.get('last exit code')
            need(signal_value is None and type(exit_value) is int,
                 'known_numeric_exit_without_unexplained_signal_required')
        self.report['retirementTerminalVerified'] = True

    def run(self):
        self.preflight()
        retired = self.report['initialObservation']
        if retired['state'] == 'live':
            retired = self.new_observation_grace()
        if retired['state'] == 'live':
            after = self.dispatch_once('kill')
            retired = after if after['state'] == 'retired' else self.wait_retired(KILL_GRACE_SECONDS)
        self.verify_retirement_terminal(retired)
        self.report['beforeBootout'] = retired
        after = self.dispatch_once('bootout')
        end = min(self.until, time.monotonic() + QUERY_SECONDS)
        while after['state'] != 'absent':
            need(after['state'] == 'retired', 'no_revival_after_bootout')
            need(time.monotonic() < end, 'bounded_bootout_absence_wait')
            time.sleep(min(POLL_SECONDS, self.remaining()))
            after = self.observe(allow_missing=True)
        second = self.observe(allow_missing=True)
        need(second['state'] == 'absent', 'stable_exact_label_and_process_absence')
        self.report['finalAbsence'] = second
        self.report['registrationClosedByThisRecovery'] = True
        self.report['knownOriginalPidGroupAndChildrenAbsent'] = True
        self.guard()
        self.report['ok'] = True
        self.report['observationCount'] = self.observation_count
        self.report['elapsedSecondsBeforeFinalJournal'] = time.monotonic() - self.started
        self.report['finalJournalReceiptIsCandidateUntilStdoutAndRuntimeTerminal'] = True
        self.report['finalJournalSha256'] = self.journal.write_new('900-result.public.json', self.report)
        self.remaining()


def main():
    recovery = Recovery()
    try:
        recovery.run()
    except Refused as error:
        recovery.report['ok'] = False
        recovery.report['recoveryOutcomeUnknown'] = True
        recovery.report['errorCode'] = str(error)
    except BaseException as error:
        recovery.report['ok'] = False
        recovery.report['recoveryOutcomeUnknown'] = True
        recovery.report['errorType'] = type(error).__name__
    finally:
        journal = recovery.journal
        if journal is not None:
            if not recovery.report['ok']:
                try:
                    journal.write_new('999-unknown.public.json', recovery.report)
                except BaseException as error:
                    recovery.report['unknownJournalErrorType'] = type(error).__name__
            try:
                journal.close_once()
                recovery.report['journalDescriptorClosed'] = journal.closed
            except BaseException as error:
                recovery.report['ok'] = False
                recovery.report['recoveryOutcomeUnknown'] = True
                recovery.report['journalCloseErrorType'] = type(error).__name__
        else:
            recovery.report['journalCreated'] = False
        recovery.report['elapsedSeconds'] = time.monotonic() - recovery.started
        print(json.dumps(recovery.report, sort_keys=True), flush=True)
    return 0 if recovery.report['ok'] and not recovery.report['recoveryOutcomeUnknown'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
