#!/usr/bin/env python3
"""Actual selected main3 API qualification on separately owned launchd lifetimes.

The inherited admission and executable-transition gates remain authoritative.
Bootstrap-only identity is a distinct cleanup authority, never readiness.
"""
from __future__ import annotations
import argparse
import base64
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time

ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-api-20261106-r4')
HOME=Path('/Users/qianqi/heptabao-mac-authbus-main3-api-20261106-r4')
PREP=Path('/Users/qianqi/heptabao-mac-authbus-main3-api-preparation-20261106-r4')
JOURNAL=Path('/Users/qianqi/heptabao-mac-authbus-main3-api-journal-20261106-r4')
QA=ROOT/'qa'
TARGET='gui/501/org.heptabao.qa.mac-authbus-main3-api-20261106-r4.server'
SOURCE_NAMES=('mac_owned_unreaped_r1.py', 'mac_owned_commands_r1.py', 'mac_t5_volume_guard_r1.py', 'mac_owned_launchd_r3.py', 'mac_native_process_observer_r1.py', 'mac_current_server_owner_r1.py', 'mac_public_code_pin_excerpt_r1.py', 'tls_complete_http_probe.py', 'main3_api_controller.py', 'test_main3_api_controller.py', 'test_suid_ps_tls_r2.py', 'main3_source_fence.py', 'main3_api_cycle.py', 'test_main3_api_guards.py', 'main3_source_authority.py', 'main3_capture_payload_0.py', 'main3_capture_payload_1.py', 'main3_capture_payload_2.py', 'main3_capture_payload_3.py', 'main3_capture_launcher.py', 'main3_inline_capture.py', 'test_main3_inline_capture.py')

def need(value,code):
    if not value:raise RuntimeError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def ident(s):return tuple(str(x) for x in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))
def stable_read(path,maximum=1048576):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
             and stat.S_IMODE(before.st_mode)==0o600 and 0<=before.st_size<=maximum,'read_exact_public_file_custody')
        raw=bytearray()
        while len(raw)<=maximum:
            block=os.read(fd,min(65536,maximum+1-len(raw)))
            if not block:break
            raw.extend(block)
        need(len(raw)==before.st_size and ident(before)==ident(os.fstat(fd))==ident(Path(path).lstat()),'read_stable_public_file')
        return bytes(raw)
    finally:os.close(fd)

def load_inputs():
    raw=stable_read(PREP/'plan.public.json',131072)
    plan=json.loads(raw)
    need(plan['schema']=='heptabao.mac-main3-api-preparation.r4'
         and plan['root']==str(ROOT) and plan['home']==str(HOME)
         and plan['journal']==str(JOURNAL) and plan['wrapperSeconds']==30
         and plan['execObservationSeconds']==10 and plan['managerSeconds']==600
         and plan['failureCleanupSeconds']==60 and plan['startupCustodyOnly'] is True,
         'fixed_fresh_synthetic_plan')
    need(set(plan['sourcePins'])==set(SOURCE_NAMES),'fixed_complete_source_inventory')
    for name,pin in plan['sourcePins'].items():
        source=stable_read(QA/name)
        need(len(source)==pin['bytes'] and sha(source)==pin['sha256'],'complete_pinned_fresh_source')
    config=json.loads(stable_read(ROOT/'server/server.json',131072))
    need(set(config)=={'listen','data_dir','audit_file','tls_cert_file','tls_key_file','storage'}
         and config['storage']=={'native_v6_file':{'path':str(ROOT/'server/data')}}
         and config['data_dir']==str(ROOT/'server/data') and config['listen']=='127.0.0.1:'+str(plan['port'])
         and config['tls_cert_file']==str(ROOT/'server/tls/server.crt')
         and config['tls_key_file']==str(ROOT/'server/tls/server.key')
         and config['audit_file']==str(ROOT/'server/audit.jsonl'), 'exact_normal_native_file_configuration_without_fixture_options')
    need(Path(__file__).resolve()==QA/'main3_api_controller.py','only_pinned_remote_controller')
    return plan,sha(raw)

class Journal:
    def __init__(self,signals):
        self.signals=signals;self.rows=[];self.closed=False;self.pending=False
        parent=os.open('/Users/qianqi',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            s=os.fstat(parent)
            need(stat.S_ISDIR(s.st_mode) and s.st_uid==501 and not stat.S_IMODE(s.st_mode)&0o022,'journal_parent_custody')
            need(ident(s)[:5]==ident(Path('/Users/qianqi').lstat())[:5],'journal_parent_name')
            with signals.critical():os.mkdir(JOURNAL.name,0o700,dir_fd=parent)
            self.fd=os.open(JOURNAL.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            self.root=ident(os.fstat(self.fd))[:5]
            need(self.root==ident(JOURNAL.lstat())[:5] and int(self.root[2])==501
                 and int(self.root[3])==20 and stat.S_IMODE(int(self.root[4]))==0o700,'journal_new_root_custody')
            os.fsync(parent)
        finally:os.close(parent)
    def check(self):
        need(not self.closed and not self.pending and self.root==ident(os.fstat(self.fd))[:5]
             ==ident(JOURNAL.lstat())[:5],'journal_same_root')
    def append(self,event,value):
        self.check()
        need(re.fullmatch(r'[a-z0-9-]{1,48}',event) and len(self.rows)<512,'journal_finite_events')
        raw=encoded({'schema':'heptabao.mac-main3-api-journal.r4','index':len(self.rows),'event':event,'value':value})
        need(len(raw)<=262144,'journal_bounded_record')
        name='%03d-%s.public.json'%(len(self.rows),event)
        with self.signals.critical():
            self.pending=True
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
            try:
                before=os.fstat(fd)
                need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_gid==20
                     and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600,'journal_new_regular_file')
                offset=0
                while offset<len(raw):
                    amount=os.write(fd,raw[offset:]);need(amount>0,'journal_write_progress');offset+=amount
                os.fsync(fd);os.fsync(self.fd)
                after=os.fstat(fd)
                need(ident(after)==ident(os.stat(name,dir_fd=self.fd,follow_symlinks=False))
                     and ident(after)[:6]==ident(before)[:6] and after.st_size==len(raw),'journal_exact_created_record')
            finally:os.close(fd)
            self.pending=False
            self.rows.append({'path':str(JOURNAL/name),'bytes':len(raw),'sha256':sha(raw)})
        self.check()
    def close(self):
        if self.closed:return
        self.check();os.close(self.fd);self.closed=True

class ProcessRowRefused(RuntimeError):
    def __init__(self,code,fields):
        super().__init__(code)
        self.safe_row={'fields':[x[:32] for x in fields[:5]],'fieldCount':len(fields)}

def select_related_rows(raw,groups):
    """Validate selectors globally; other metadata only for related processes."""
    need(isinstance(groups,set) and all(type(x) is int and x>1 for x in groups),'typed_owned_groups')
    values=[]
    for line in raw.decode('ascii','strict').splitlines():
        fields=line.split()
        if not (len(fields)>=3 and all(re.fullmatch(r'[0-9]+',x) for x in fields[:3])):
            raise ProcessRowRefused('strict_global_process_selectors',fields)
        pid,ppid,pgid=map(int,fields[:3])
        if pid not in groups and ppid not in groups and pgid not in groups:continue
        if not (len(fields)==5 and fields[3]=='501' and re.fullmatch(r'[A-Za-z0-9+<>=-]{1,16}',fields[4])):
            raise ProcessRowRefused('strict_related_process_metadata',fields)
        values.append({'pid':pid,'ppid':ppid,'pgid':pgid,'uid':501,'state':fields[4]})
    return values

def install_controller(base,reader_module):
    class SyntheticOwnedLaunchd(base.OwnedLaunchd):
        def __init__(self,*,journal,**kwargs):
            self.journal=journal;self.cleanup_observations=[]
            super().__init__(**kwargs)
        def _query(self,label,entry,*,until=None,cleanup=False):
            state=super()._query(label,entry,until=until,cleanup=cleanup)
            if (entry is not None and not cleanup and state is not None
                    and state.get('pid') is not None and entry['wrapperIdentity'] is None
                    and entry.get('bootstrapIdentity') is None):
                ledger=entry['attempts'].get('bootstrap',{})
                need(ledger.get('complete') is True and ledger.get('exitCode')==0
                     and ledger.get('command',{}).get('outcomeUnknown') is False,'known_bootstrap_before_cleanup_identity')
                current=self.reader.read(state['pid'])
                need(state.get('runs')==1 and current['uid']==501 and current['ppid']==1
                     and current['pid']==current['pgid'] and current['executable']==base.PYTHON_KERNEL_IMAGE,
                     'exact_bootstrap_python_birth_for_cleanup_only')
                need(self.reader.read(current['pid'])==current,'repeat_bootstrap_birth')
                entry['bootstrapIdentity']=current
                entry['groups'].add(current['pgid'])
                need(self.journal is not None,'durable_cleanup_custody_journal')
                self.journal.append('bootstrap-cleanup-custody',{'generation':entry['generation'],
                    'target':entry['target'],'identity':current,'plistSha256':entry['plistSha256'],
                    'planSha256':entry['planSha256'],'arguments':entry['arguments'],
                    'businessAdmissionGranted':False})
            return state
        def _rows(self,groups,*,until=None,cleanup=False):
            row,out,err=self._call('fresh-related-process-observation',
                ['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,stat='],until=until,cleanup=cleanup,ps=True)
            need(row['exitCode']==0 and not err,'known_related_process_observation')
            try:return select_related_rows(out,groups)
            except BaseException as error:
                safe=[]
                for line in out.decode('ascii','backslashreplace').splitlines():
                    f=line.split()
                    if len(f)>=3 and all(re.fullmatch(r'[0-9]+',x) for x in f[:3]):
                        p,pp,g=map(int,f[:3])
                        if p in groups or pp in groups or g in groups:
                            safe.append({'pid':f[0],'ppid':f[1],'pgid':f[2],
                                'uid':f[3][:24] if len(f)>3 else None,'stat':f[4][:32] if len(f)>4 else None,
                                'fieldCount':len(f)})
                if self.journal is not None:self.journal.append('related-metadata-refused',{'relatedRows':safe,
                    'offendingProjectionRow':getattr(error,'safe_row',None),'errorType':type(error).__name__})
                raise
        def _native_absent(self,pid):
            data=reader_module.BsdInfo();ctypes.set_errno(0)
            count=self.reader.lib.proc_pidinfo(pid,3,0,ctypes.byref(data),ctypes.sizeof(data))
            error=ctypes.get_errno()
            need(count==0 and error==errno.ESRCH,'exact_native_pid_esrch')
            return {'pid':pid,'bytes':count,'errno':error}
        def _known_ledger(self,entry):
            helper_state=self.commands.public()
            need(helper_state['unknownCommandCount']==0 and helper_state['allOwnedCommandsStopped'],
                 'all_previous_command_outcomes_known_before_mutation')
            for name,item in entry['attempts'].items():
                need(item.get('attempted') is True and item.get('complete') is True and item.get('exitCode')==0
                     and item.get('command',{}).get('outcomeUnknown') is False
                     and item['command'].get('completeBeforeDeadline') is True,'no_mutation_after_unknown_attempt')
        def _owned_live(self,entry,expected,*,cleanup=False,until=None):
            self._check_registration_files(entry)
            state=self._query(entry['label'],entry,cleanup=cleanup,until=until)
            need(state is not None and state.get('runs')==1 and state.get('pid')==expected['pid'], 'exact_registered_live_owner')
            need(self.reader.read(expected['pid'])==expected,'same_current_complete_birth')
            rows=self._rows(entry['groups'],cleanup=cleanup,until=until)
            need(len(rows)==1 and rows[0]['pid']==expected['pid'] and rows[0]['ppid']==expected['ppid']
                 and rows[0]['pgid']==expected['pgid'] and rows[0]['uid']==501 and not rows[0]['state'].startswith('Z'),
                 'one_live_owner_no_related_children')
            need(self.reader.children(expected['pid'])==[] and self.reader.read(expected['pid'])==expected,
                 'repeat_birth_and_no_native_children')
            return state
        def _retired(self,entry,expected,*,cleanup=False,until=None):
            self._check_registration_files(entry)
            state=self._query(entry['label'],entry,cleanup=cleanup,until=until)
            need(state is not None and state.get('pid') is None and state.get('runs')==1,'registered_owner_retired')
            signal_value=state.get('last terminating signal')
            if 'kill' in entry['attempts']:
                need(signal_value in ('9','SIGKILL','Killed: 9','9 (Killed: 9)'), 'exact_sigkill_terminal')
            else:
                need(type(state.get('last exit code')) is int or signal_value in
                     ('15','SIGTERM','Terminated: 15','15 (Terminated: 15)'), 'known_retired_terminal')
            absent=self._native_absent(expected['pid'])
            rows=self._rows(entry['groups'],cleanup=cleanup,until=until)
            need(rows==[] and self.reader.children(expected['pid'])==[],'retired_no_group_or_children')
            self._native_absent(expected['pid'])
            return {'pidAbsent':absent,'relatedRows':rows,'launchd':state}
        def _dispatch_once(self,entry,operation,argv,*,until=None,cleanup=False):
            need(entry['target']==TARGET and operation in ('bootstrap','term','kill','bootout'),'only_fixed_fresh_synthetic_mutation')
            self._known_ledger(entry)
            need(operation not in entry['attempts'],'one_mutation_attempt')
            expected=entry['execIdentity'] or entry['wrapperIdentity'] or entry.get('bootstrapIdentity')
            def check():
                self._remaining(until,cleanup=cleanup);self._check_registration_files(entry)
                if operation=='bootstrap':
                    need(self._query(entry['label'],entry,until=until,cleanup=cleanup) is None,'fresh_label_absent_before_bootstrap')
                elif operation in ('term','kill'):
                    need(expected is not None,'known_identity_before_signal')
                    self._owned_live(entry,expected,until=until,cleanup=cleanup)
                else:
                    need(expected is not None,'known_identity_before_bootout')
                    return self._retired(entry,expected,until=until,cleanup=cleanup)
            pre_observation=check()
            need(self.journal is not None,'durable_mutation_intent_required')
            self.journal.append('mutation-intent',{'generation':entry['generation'],'operation':operation,
                'target':entry['target'],'argv':argv,'expectedIdentity':expected,'cleanupOnly':cleanup,
                'plistSha256':entry['plistSha256'],'planSha256':entry['planSha256'],
                'retirementBeforeBootout':pre_observation})
            check()
            try:
                result=super()._dispatch_once(entry,operation,argv,until=until,cleanup=cleanup)
            finally:
                self.journal.append('mutation-result',{'generation':entry['generation'],'operation':operation,
                    'attempt':entry['attempts'].get(operation),'cleanupOnly':cleanup})
            # A second exact observation is required before any later mutation.
            state=self._query(entry['label'],entry,until=until,cleanup=cleanup)
            post_absence=None
            if operation=='bootout':
                need(state is None,'known_registration_absence_after_bootout')
                post_absence=self._native_absent(expected['pid'])
                need(self._rows(entry['groups'],until=until,cleanup=cleanup)==[]
                     and self.reader.children(expected['pid'])==[],'final_empty_lineage_after_bootout')
            elif operation!='bootstrap' and state is not None and state.get('pid') is not None:
                need(state['pid']==expected['pid'] and self.reader.read(expected['pid'])==expected,
                     'same_birth_after_signal')
            self.journal.append('mutation-observed',{'generation':entry['generation'],'operation':operation,
                'state':state,'cleanupOnly':cleanup,'nativePidAbsence':post_absence})
            return result
        def abort_cleanup_once(self):
            if self.failure_cleanup_attempted:return self.public()
            self.failure_cleanup_attempted=True;self.cleanup_until=time.monotonic()+60.0;self.unknown=True
            with self.signals.critical():
                for entry in reversed(self.entries):
                    if entry['registrationClosed']:continue
                    try:
                        self._known_ledger(entry)
                        expected=entry['execIdentity'] or entry['wrapperIdentity'] or entry.get('bootstrapIdentity')
                        need(expected is not None,'known_cleanup_only_birth_required')
                        state=self._query(entry['label'],entry,cleanup=True)
                        need(state is not None,'registration_present_before_cleanup')
                        if state.get('pid') is not None:
                            self._owned_live(entry,expected,cleanup=True)
                            if 'kill' not in entry['attempts'] and 'term' not in entry['attempts']:
                                op='kill' if entry['execIdentity'] is not None else 'term'
                                sig='SIGKILL' if op=='kill' else 'SIGTERM'
                                self._dispatch_once(entry,op,['/bin/launchctl','kill',sig,entry['target']],cleanup=True)
                            grace_started=time.monotonic()
                            grace=min(self.cleanup_until,grace_started+(10.0 if 'kill' in entry['attempts'] else 20.0))
                            while True:
                                state=self._query(entry['label'],entry,cleanup=True,until=grace)
                                need(state is not None,'registration_during_cleanup_grace')
                                if state.get('pid') is None:break
                                self._owned_live(entry,expected,cleanup=True,until=grace)
                                left=grace-time.monotonic()
                                if left<=0.3:break
                                time.sleep(min(0.25,left))
                            if state.get('pid') is not None:
                                # Never reuse a KILL or replenish a previous grace interval.
                                need('term' in entry['attempts'] and 'kill' not in entry['attempts'], 'no_repeat_signal_after_grace')
                                while time.monotonic()-grace_started<20.0:
                                    self._remaining(cleanup=True)
                                    time.sleep(min(0.05,20.0-(time.monotonic()-grace_started)))
                                self._owned_live(entry,expected,cleanup=True)
                                self._dispatch_once(entry,'kill',['/bin/launchctl','kill','SIGKILL',entry['target']],cleanup=True)
                                kill_until=min(self.cleanup_until,time.monotonic()+10.0)
                                while True:
                                    state=self._query(entry['label'],entry,cleanup=True,until=kill_until)
                                    need(state is not None,'registration_after_cleanup_kill')
                                    if state.get('pid') is None:break
                                    self._owned_live(entry,expected,cleanup=True,until=kill_until)
                                    time.sleep(min(0.25,self._remaining(kill_until,cleanup=True)))
                        retirement=self._retired(entry,expected,cleanup=True)
                        self.journal.append('cleanup-retirement',{'generation':entry['generation'],'proof':retirement})
                        self._bootout(entry,cleanup=True)
                        need(self._query(entry['label'],entry,cleanup=True) is None,'cleanup_label_absent')
                        self._native_absent(expected['pid'])
                        need(self._rows(entry['groups'],cleanup=True)==[],'cleanup_final_related_rows_empty')
                        entry['lineagesClosed']=True
                        entry['syntheticCleanupClosure']=True
                        self.journal.append('cleanup-closed',{'generation':entry['generation'],'expectedIdentity':expected,
                            'labelAbsent':True,'nativePidAbsent':True,'relatedRows':[],
                            'businessSuccessRestored':False,'oldR2Replayed':False})
                    except BaseException as error:
                        entry['cleanupErrorType']=type(error).__name__
                        entry['cleanupErrorCode']=str(error) if isinstance(error,(RuntimeError,base.ManagerRefused)) else None
                        self.journal.append('cleanup-refused',{'generation':entry['generation'],
                            'errorType':entry['cleanupErrorType'],'errorCode':entry['cleanupErrorCode']})
            return self.public()
        def public(self):
            result=super().public()
            result['bootstrapCleanupCustody']=[{'generation':e['generation'],'identity':e.get('bootstrapIdentity'),
                'businessAdmissionGrantedByBootstrap':False,'syntheticCleanupClosure':e.get('syntheticCleanupClosure',False)} for e in self.entries]
            result['startupCustodyOnly']=True
            return result
    return SyntheticOwnedLaunchd

def fixed_stages(entry):
    path=entry['stderr'];fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(ident(before)[:6]==entry['stderrInitialIdentity'][:6] and before.st_size<=65536,'fixed_stage_stdio_identity')
        raw=os.pread(fd,before.st_size,0)
        need(len(raw)==before.st_size and os.pread(fd,len(raw),0)==raw
             and ident(os.fstat(fd))[:6]==ident(path.lstat())[:6]==ident(before)[:6],'fixed_stage_stable_prefix')
        values=[]
        for line in raw.splitlines():
            try:value=json.loads(line)
            except (UnicodeError,json.JSONDecodeError):continue
            if isinstance(value,dict) and value.get('schema')=='heptabao.mac-wrapper-fixed-stage.r1':
                need(set(value)<= {'schema','stage','elapsedSeconds'} and isinstance(value.get('stage'),str)
                     and len(value['stage'])<=128,'fixed_stage_schema')
                values.append(value)
        return {'bytesRead':len(raw),'stages':values,'completeFileAtInitialStat':True,
                'rawServerDiagnosticsOrDigestsPublished':False}
    finally:os.close(fd)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--mode',choices=('preflight','run'),required=True)
    args=parser.parse_args();os.umask(0o077)
    need(sys.platform=='darwin' and os.geteuid()==501,'exact_mac_owner')
    plan,plan_sha=load_inputs();sys.path.insert(0,str(QA))
    import mac_owned_launchd_r3 as base
    import mac_native_process_observer_r1 as reader_module
    from mac_owned_commands_r1 import Signals,Commands
    from mac_t5_volume_guard_r1 import HeldT5
    import main3_api_cycle as api_cycle
    from main3_source_fence import CapsuleFence
    import main3_inline_capture as inline_capture
    signals=Signals();signals.install();commands=Commands(signals)
    started=time.monotonic();until=started+600.0
    def remaining():
        need(signals.pending is None,'outer_not_cancelled')
        left=until-time.monotonic();need(left>0,'original_outer_600_seconds');return left
    journal=None;guard=None;home=None;manager=None;active_api=None;active_fence=None;private_state=None
    result={'schema':'heptabao.mac-main3-current-api-qualification.r4','mode':args.mode,
        'ok':False,'planSha256':plan_sha,'startupCustodyOnly':False,'businessCredentialInputsRead':False,
        'providerValid':False,'providerCalled':False,'providerRefreshAttempted':False,
        'productionTrafficCutover':False,'credentialValuesOrDigestsPublished':False,
        'actualPluginSdkPhaseExecuted':False,'productionClientRollbackQualified':False,
        'normalNativeStorageConfigurationVerified':True,'fixtureOptionsEnabled':False,
        'normalActivationPath':'sys/storage/native-v6/activate',
        'j3160Contacted':False,'productionChanged':False,'oldR2Modified':False,
        'sourcePins':plan['sourcePins'],'canonicalProduct':plan['canonicalProduct'],
        'phases':[],'sourceFences':[],'stages':{},'mutationExecuted':False,'inlineCapture':None}
    try:
        anchor=base64.b64decode(plan['anchorBase64'],validate=True)
        guard=HeldT5(anchor,plan['anchorSha256'],remaining,signals.critical)
        row,out,err=commands.run('fresh-controller-t5-volume',['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
            until=min(until,time.monotonic()+30.0),maximum=262144)
        need(row['exitCode']==0 and row['completeBeforeDeadline'] and not row['outcomeUnknown'] and not err,'actual_t5_probe_complete')
        guard.accept_diskutil(out)
        home=base.HomeControl(remaining=remaining,critical=signals.critical,
            copy_pins={name:(pin['bytes'],pin['sha256']) for name,pin in plan['homeCopyPins'].items()},binding=plan['homeBinding'])
        if args.mode=='run':journal=Journal(signals)
        cls=install_controller(base,reader_module)
        manager=cls(journal=journal,guard=guard,commands=commands,signals=signals,until=until,
            anchor_raw=anchor,anchor_sha256=plan['anchorSha256'],
            qa_pins={name:pin['sha256'] for name,pin in plan['sourcePins'].items()},
            python_runtime=plan['pythonRuntime'],home_control=home)
        if args.mode=='preflight':
            result['inlineCapturePreflight']=inline_capture.preflight_inputs(plan,stable_read)
            result.update(ok=True,labelsInitiallyAbsent=True,mutationExecuted=False)
        else:
            result['inlineCapture']=inline_capture.run_capture(commands,plan,journal,until,remaining,stable_read)
            active_fence=CapsuleFence(min(until,time.monotonic()+45.0),admit_mode="qualify")
            result['businessCredentialInputsRead']=True
            active_fence.observe('preflight')
            result['sourceFences'].append(active_fence.public());active_fence=None
            journal.append('run-intent',{'planSha256':plan_sha,'sourcePins':plan['sourcePins'],
                'wrapperSeconds':30,'execObservationSeconds':10,'managerSeconds':600,
                'failureCleanupSeconds':60,'maximumTermGraceSeconds':20,'maximumKillGraceSeconds':10,
                'operationGraph':list(base.GRAPH),'realSelectedOwnerCount':3,
                'providerValid':False,'productionCutover':False})
            original_new_entry=manager._new_entry
            def new_entry(kind,generation):
                entry=original_new_entry(kind,generation)
                entry['stderrInitialIdentity']=ident(entry['stderr'].lstat())
                return entry
            manager._new_entry=new_entry
            for generation,phase in (('server-initial','initial'),('server-cold-new-process','cold-new-process')):
                phase_until=min(until,time.monotonic()+120.0)
                active_fence=CapsuleFence(phase_until)
                result['businessCredentialInputsRead']=True
                active_fence.observe('preflight')
                result['mutationExecuted']=True
                manager.start_server(generation)
                active_api=api_cycle.Api(plan,phase,phase_until,journal,guard)
                if phase=='initial':private_state=api_cycle.initial(active_api,active_fence)
                else:api_cycle.cold(active_api,active_fence,private_state)
                result['phases'].append(active_api.public());active_api=None
                result['sourceFences'].append(active_fence.public());active_fence=None
                need(time.monotonic()<phase_until,'business_phase_completed_within_original_120_seconds')
                manager.kill_server_for_cold_or_inverse(generation)
            identities=[e['execIdentity'] for e in manager.entries]
            need(len(identities)==2 and identities[0]['pid']!=identities[1]['pid']
                 and (identities[0]['birthSec'],identities[0]['birthUsec'])!=
                     (identities[1]['birthSec'],identities[1]['birthUsec']), 'two_distinct_actual_server_lifetimes')
            result['manager']=manager.finish();result['ok']=result['manager']['ok']
    except BaseException as error:
        result['errorType']=type(error).__name__
        result['errorCode']=str(error) if isinstance(error,(RuntimeError,base.ManagerRefused)) else None
        if manager is not None and args.mode=='run':
            try:result['manager']=manager.abort_cleanup_once()
            except BaseException as cleanup_error:result['outerCleanupErrorType']=type(cleanup_error).__name__
    finally:
        if active_api is not None:result['phases'].append(active_api.public())
        if active_fence is not None:result['sourceFences'].append(active_fence.public())
        for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,signal.SIG_IGN)
        if manager is not None:
            result['manager']=manager.public()
            for entry in manager.entries:
                if 'stderrInitialIdentity' in entry:
                    try:result['stages'][entry['generation']]=fixed_stages(entry)
                    except BaseException as error:result['stages'][entry['generation']]={'errorType':type(error).__name__}
        if guard is not None:
            guard.close();result['volumeClosure']=guard.public_state()
        if home is not None:result['homeClosure']=home.close()
        result['commands']=commands.public()
        closure=(guard is not None and result['volumeClosure']['allDescriptorsClosed']
            and not result['volumeClosure']['closeErrors'] and home is not None
            and result['homeClosure']['allReturnedDescriptorsClosed']
            and result['commands']['allOwnedCommandsStopped'] and result['commands']['unknownCommandCount']==0)
        result['closuresKnown']=bool(closure)
        result['ok']=bool(result['ok'] and closure and time.monotonic()<until
            and all(x['allReturnedDescriptorsClosed'] for x in result['sourceFences'])
            and all(x['allReturnedSocketsClosed'] and x['unknownHttpOutcomeCount']==0
                and x['allDispatchedResponsesComplete'] and all(c['passed'] for c in x['checks']) for x in result['phases']))
        result['elapsedSeconds']=time.monotonic()-started
        if journal is not None:
            try:
                # Retain complete command records once, in bounded independent files.
                # Final/stdout aggregates link them; no record is discarded or truncated.
                command_records=result['commands']['commands']
                batches=[]
                for first in range(0,len(command_records),16):
                    journal.append('complete-command-batch',{'firstIndex':first,
                        'commands':command_records[first:first+16]})
                    batches.append(journal.rows[-1])
                def command_summary(value):
                    return {k:v for k,v in value.items() if k!='commands'} | {
                        'completeCommandCount':len(value['commands']),'completeCommandBatchFiles':batches}
                result['commands']=command_summary(result['commands'])
                if 'manager' in result:
                    result['manager']['ownedCommands']=command_summary(result['manager']['ownedCommands'])
                journal.append('final-result',result);journal.close()
                result['journalRows']=journal.rows;result['journalClosed']=journal.closed
            except BaseException as error:
                result['ok']=False;result['journalErrorType']=type(error).__name__
        print(json.dumps(result,sort_keys=True),flush=True)
    return 0 if result['ok'] else 1

if __name__=='__main__':sys.exit(main())
