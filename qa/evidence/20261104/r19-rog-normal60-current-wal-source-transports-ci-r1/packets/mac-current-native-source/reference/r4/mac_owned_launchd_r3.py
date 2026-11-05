#!/usr/bin/env python3
"""Finite owned launchd control for the isolated five-agent Mac candidate.

Library only, source-only. Launchd owns wrappers; wrappers own their actual
Popen children. This manager never claims those children are its direct children
and never sends a signal to a numeric PID or process group. Unknown state stops
the operation graph. Failed cleanup cannot become a successful generation.
"""
from __future__ import annotations
import base64, hashlib, json, os, plistlib, re, stat, time
from pathlib import Path
from mac_native_process_observer_r1 import ProcessReader

ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1')
QA=ROOT/'qa'
DOMAIN='gui/501'
LABELS={'server':'org.heptabao.qa.mac-authbus-r10-r1.server',
        'consumer':'org.heptabao.qa.mac-authbus-r10-r1.consumer'}
SERVER=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-native-http-r10/normal-release-tests-r1/artifacts/heptabao-server')
SERVER_SHA='bc1fc6b8ded5a43a60ab4c562cd5e092e63ae9df77afd654c9af8c096c128c98'
GRAPH=(('server-start','server-initial'),('phase','initial'),
       ('server-kill','server-initial'),('server-start','server-cold-new-process'),
       ('phase','cold-new-process'),('server-kill','server-cold-new-process'),
       ('phase','initial-inverse'),('phase','cold-new-process-inverse'))
AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')
NEW_MANAGER_SECONDS=600.0
NEW_CLEANUP_SECONDS=60.0
NEW_WRAPPER_READY_SECONDS=30.0
NEW_EXEC_OBSERVATION_SECONDS=10.0
NEW_FAILURE_TERM_GRACE_SECONDS=20.0
MAX_COMMANDS=4096
NEW_MANAGER_POLL_SECONDS=0.25
QUERY_SECONDS=10.0
PS_SECONDS=4.0

class ManagerRefused(RuntimeError):pass
def need(value,code):
    if not value:raise ManagerRefused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def file_identity(s):
    return tuple(str(x) for x in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,
        s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))

def parse_print(raw,target):
    need(isinstance(raw,bytes) and len(raw)<=262144,'bounded_launchctl_print')
    lines=raw.decode('utf-8','strict').splitlines()
    need(1<=len(lines)<=4096 and lines[0].strip()==target+' = {','exact_launchctl_target')
    fields={};arguments=[];depth=1;in_arguments=False;arguments_seen=False
    allowed=('path','program','pid','state','runs','last exit code','last terminating signal')
    for line in lines[1:]:
        text=line.strip()
        if in_arguments:
            if text=='}':
                in_arguments=False;depth-=1;continue
            need(depth==2 and text and '{' not in text and '}' not in text
                 and len(text)<=16384,'plain_fixed_launchctl_argument')
            arguments.append(text)
            need(len(arguments)<=32,'bounded_launchctl_arguments')
            continue
        if depth==1 and text=='arguments = {':
            need(not arguments_seen,'one_launchctl_arguments_block')
            arguments_seen=True;in_arguments=True;depth+=1;continue
        if depth==1 and ' = ' in text and not text.endswith('{'):
            name,value=text.split(' = ',1)
            if name in allowed:
                need(name not in fields,'unique_launchctl_field');fields[name]=value
        depth+=text.count('{')-text.count('}')
        need(depth>=0,'balanced_launchctl_print')
        if depth==0:
            need(text=='}' and line==lines[-1],'one_complete_launchctl_record')
    need(depth==0 and not in_arguments and arguments_seen,'complete_launchctl_arguments')
    for name in ('pid','runs','last exit code'):
        if name in fields:
            need(re.fullmatch(r'-?[0-9]{1,10}',fields[name]) is not None,'typed_launchctl_integer')
            fields[name]=int(fields[name])
    need('pid' not in fields or fields['pid']>1,'actual_launchctl_pid')
    fields['arguments']=arguments
    return fields

def missing_service(code,out,err,label):
    if code not in (3,113) or out:return False
    try:lines=err.decode('utf-8','strict').splitlines()
    except UnicodeError:return False
    exact='Could not find service "'+label+'" in domain for user gui: 501'
    return lines in ([exact],['Bad request.',exact])

class OwnedLaunchd:
    def __init__(self,*,guard,commands,signals,until,anchor_raw,anchor_sha256,qa_pins,python_runtime):
        now=time.monotonic()
        need(now<until<=now+NEW_MANAGER_SECONDS,'one_new_manager_deadline')
        need(guard.uuid_verified and not guard.closed,'held_t5_before_manager')
        need(isinstance(anchor_raw,bytes) and sha(anchor_raw)==anchor_sha256,'exact_public_anchor')
        need(isinstance(qa_pins,dict) and all(isinstance(k,str) and isinstance(v,str)
             and re.fullmatch(r'[0-9a-f]{64}',v) for k,v in qa_pins.items()),'typed_qa_pins')
        self.guard=guard;self.commands=commands;self.signals=signals;self.until=until
        self.started=now;self.anchor_raw=anchor_raw;self.anchor_sha=anchor_sha256
        self.qa_pins=dict(qa_pins);self.reader=ProcessReader()
        self.entries=[];self.graph_index=0;self.events=[];self.unknown=False
        self.failure_cleanup_attempted=False;self.cleanup_until=None
        self.command_count=0;self.finished=False;self.fd_rows=[]
        self._remaining()
        from mac_guarded_current_capture_r3 import public_code_pin
        actual_python=public_code_pin('/opt/homebrew/bin/python3',remaining=self._remaining,
                                      critical=self.signals.critical)
        need(actual_python==python_runtime,'same_actual_synthetic_python_for_wrappers')
        self.python_runtime=dict(actual_python)
        for kind in ('server','consumer'):
            need(self._query(LABELS[kind],None) is None,'owned_label_initially_absent')

    def _remaining(self,until=None,*,cleanup=False):
        if not cleanup:need(self.signals.pending is None,'manager_cancelled')
        bound=self.cleanup_until if cleanup else self.until
        need(bound is not None,'cleanup_deadline_exists')
        if until is not None:bound=min(bound,until)
        left=bound-time.monotonic();need(left>0,'original_manager_or_cleanup_deadline')
        return left

    def _call(self,label,argv,*,until=None,cleanup=False,ps=False):
        self._remaining(until,cleanup=cleanup)
        need(self.command_count<MAX_COMMANDS,'finite_manager_command_count')
        self.command_count+=1
        limit=PS_SECONDS if ps else QUERY_SECONDS
        bound=min(self.cleanup_until if cleanup else self.until,time.monotonic()+limit)
        if until is not None:bound=min(bound,until)
        row,out,err=self.commands.run(label,argv,until=bound,
                                      allow_cancelled_cleanup=cleanup,maximum=262144)
        if row['outcomeUnknown'] or not row['completeBeforeDeadline']:
            self.unknown=True
            raise ManagerRefused('owned_manager_command_unknown')
        self._remaining(until,cleanup=cleanup)
        return row,out,err

    def _query(self,label,entry,*,until=None,cleanup=False):
        need(label in LABELS.values(),'only_two_owned_labels')
        target=DOMAIN+'/'+label
        row,out,err=self._call('launchd-print',['/bin/launchctl','print',target],
                              until=until,cleanup=cleanup)
        if missing_service(row['exitCode'],out,err,label):return None
        need(row['exitCode']==0 and not err,'known_launchctl_query')
        value=parse_print(out,target)
        if entry is not None:
            need(value.get('path')==str(entry['plist'])
                 and value.get('program')==entry['arguments'][0]
                 and value['arguments']==entry['arguments'],'exact_registered_generation')
            need(value.get('runs') in (0,1),'one_launchd_run_only')
        return value

    def _record(self,kind,generation,detail):
        self._remaining()
        value={'schema':'heptabao.mac-owned-launchd-event.r3','index':len(self.events),
               'kind':kind,'generation':generation,'detail':detail}
        path=ROOT/'launchd'/('%03d-%s-%s.public.json'%(len(self.events),generation,kind))
        binding=self.guard.write_new(path,encoded(value))
        self.events.append({'kind':kind,'generation':generation,'path':str(path),**binding})

    def _expect_action(self,kind,generation):
        self._remaining()
        need(not self.finished and self.graph_index<len(GRAPH)
             and GRAPH[self.graph_index]==(kind,generation),'finite_launchd_operation_graph')
        need(not self.unknown,'no_business_after_unknown')

    def _advance(self):
        self._remaining();self.graph_index+=1

    def _plan(self,generation):
        path=ROOT/'launchd'/(generation+'.private.json')
        named_before=file_identity(path.lstat())
        raw=self.guard.read(path)
        need(named_before==file_identity(path.lstat()),'plan_identity_around_whole_read')
        value=json.loads(raw)
        need(isinstance(value,dict) and value.get('generation')==generation,'fixed_generation_plan')
        return path,raw,value

    def _args(self,kind,path,plan_sha):
        common=['--plan',str(path),'--plan-sha256',plan_sha,
            '--public-volume-anchor-base64',base64.b64encode(self.anchor_raw).decode('ascii'),
            '--public-volume-anchor-sha256',self.anchor_sha]
        if kind=='consumer':
            wrapper=QA/'mac_current_phase_owner_r2.py'
            common+=['--volume-guard-source-sha256',self.qa_pins['mac_t5_volume_guard_r1.py']]
        else:
            wrapper=QA/'mac_current_server_owner_r1.py'
            names=('mac_owned_unreaped_r1.py','mac_owned_commands_r1.py',
                   'mac_t5_volume_guard_r1.py','mac_native_process_observer_r1.py')
            raw=encoded({n:self.qa_pins[n] for n in names})
            common+=['--public-source-pins-base64',base64.b64encode(raw).decode('ascii'),
                     '--public-source-pins-sha256',sha(raw)]
        need(sha(self.guard.read(wrapper,1024*1024))==self.qa_pins[wrapper.name],
             'exact_wrapper_before_registration')
        return ['/opt/homebrew/bin/python3','-I','-S','-B',str(wrapper),*common]

    def _new_entry(self,kind,generation):
        label=LABELS[kind]
        need(not any(e['label']==label and not e['registrationClosed'] for e in self.entries),
             'previous_owned_registration_closed')
        need(self._query(label,None) is None,'label_absent_before_new_generation')
        path,raw,plan=self._plan(generation)
        argv=self._args(kind,path,sha(raw))
        stdout=ROOT/'launchd'/(generation+'.stdout.private')
        stderr=ROOT/'launchd'/(generation+'.stderr.private')
        plist=ROOT/'launchd'/(generation+'.plist')
        expected={'Label':label,'ProgramArguments':argv,'RunAtLoad':True,'KeepAlive':False,
            'AbandonProcessGroup':False,'ProcessType':'Background','ExitTimeOut':10,'Umask':0o077,
            'WorkingDirectory':str(ROOT),'StandardOutPath':str(stdout),
            'StandardErrorPath':str(stderr),
            'EnvironmentVariables':{'PATH':'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
                                    'LANG':'C','LC_ALL':'C'}}
        self.guard.write_new(plist,plistlib.dumps(expected,fmt=plistlib.FMT_XML,sort_keys=True))
        named_before=file_identity(plist.lstat())
        actual=self.guard.read(plist)
        need(named_before==file_identity(plist.lstat()),'plist_identity_around_whole_read')
        need(plistlib.loads(actual)==expected,'exact_owned_plist_no_keepalive')
        # Precreate both append targets with exact private modes before launchd.
        self.guard.write_new(stdout,b'');self.guard.write_new(stderr,b'')
        # Mode, symlink, owner and stable whole-read checks are enforced by HeldT5.
        entry={'kind':kind,'generation':generation,'label':label,'target':DOMAIN+'/'+label,
            'plan':path,'planSha256':sha(raw),'plist':plist,'plistSha256':sha(actual),
            'arguments':argv,'stdout':stdout,'stderr':stderr,'wrapperIdentity':None,
            'execIdentity':None,'groups':set(),'registrationClosed':False,
            'lineagesClosed':False,'completeKnownSuccess':False,'attempts':{},
            'planIdentity':file_identity(path.lstat()),'plistIdentity':file_identity(plist.lstat())}
        cleanup_plan={'schema':'heptabao.mac-owned-launchd-cleanup-intent.r3',
            'generation':generation,'label':label,'target':entry['target'],
            'termArgv':['/bin/launchctl','kill','SIGTERM',entry['target']],
            'killArgv':['/bin/launchctl','kill','SIGKILL',entry['target']],
            'bootoutArgv':['/bin/launchctl','bootout',entry['target']],
            'newCleanupSeconds':NEW_CLEANUP_SECONDS,'noNumericPidOrGroupSignals':True}
        self.guard.write_new(ROOT/'launchd'/(generation+'.cleanup-intent.public.json'),
                             encoded(cleanup_plan))
        self._record('bootstrap-intent',generation,{'planSha256':entry['planSha256'],
            'plistSha256':entry['plistSha256'],'argv':['/bin/launchctl','bootstrap',DOMAIN,str(plist)]})
        self.entries.append(entry)
        return entry

    def _dispatch_once(self,entry,operation,argv,*,until=None,cleanup=False):
        need(operation in ('bootstrap','term','kill','bootout'),'fixed_manager_operation')
        expected={'bootstrap':['/bin/launchctl','bootstrap',DOMAIN,str(entry['plist'])],
            'term':['/bin/launchctl','kill','SIGTERM',entry['target']],
            'kill':['/bin/launchctl','kill','SIGKILL',entry['target']],
            'bootout':['/bin/launchctl','bootout',entry['target']]}[operation]
        need(argv==expected and operation not in entry['attempts'],'once_exact_manager_dispatch')
        with self.signals.critical():
            self._remaining(until,cleanup=cleanup)
            entry['attempts'][operation]={'attempted':True,'complete':False}
        try:
            row,out,err=self._call('launchd-'+operation,argv,until=until,cleanup=cleanup)
            entry['attempts'][operation].update(complete=True,exitCode=row['exitCode'],
                stdoutSha256=sha(out),stderrSha256=sha(err),command=row)
            need(row['exitCode']==0,'known_launchctl_mutation_success')
            return row
        except BaseException:
            self.unknown=True
            raise

    def _ready(self,entry):
        until=min(self.until,time.monotonic()+NEW_WRAPPER_READY_SECONDS)
        path=ROOT/'launchd'/(entry['generation']+'.ready.public.json')
        while True:
            self._remaining(until)
            state=self._query(entry['label'],entry,until=until)
            need(state is not None,'registration_present_while_waiting_ready')
            try:raw=self.guard.read(path)
            except FileNotFoundError:
                need(state.get('pid') is not None or state.get('runs')==0,'wrapper_did_not_exit_before_ready')
                time.sleep(min(NEW_MANAGER_POLL_SECONDS,self._remaining(until)));continue
            ready=json.loads(raw)
            expected_schema=('heptabao.mac-phase-wrapper-ready.r1' if entry['kind']=='consumer'
                             else 'heptabao.mac-server-wrapper-ready.r1')
            need(isinstance(ready,dict) and ready.get('schema')==expected_schema
                 and ready.get('generation')==entry['generation']
                 and ready.get('planSha256')==entry['planSha256'],'typed_wrapper_ready')
            identity=ready.get('wrapperIdentity')
            need(isinstance(identity,dict) and type(identity.get('pid')) is int
                 and state.get('pid')==identity['pid'] and state.get('runs')==1,
                 'launchd_actual_wrapper_pid')
            observed=self.reader.read(identity['pid'])
            need(observed==identity and observed['uid']==501
                 and observed['pid']==observed['pgid']
                 and observed['executable']==self.python_runtime['path'],
                 'actual_wrapper_birth_executable')
            entry['wrapperIdentity']=identity;entry['groups'].add(identity['pgid'])
            entry['readySha256']=sha(raw)
            admission={'schema':'heptabao.mac-owned-manager-admission.r1',
                'generation':entry['generation'],'planSha256':entry['planSha256'],
                'wrapperIdentity':identity}
            self.guard.write_new(ROOT/'launchd'/(entry['generation']+'.admitted.private.json'),
                                 encoded(admission))
            self._record('actual-wrapper-admitted',entry['generation'],
                         {'wrapperIdentity':identity,'readySha256':sha(raw)})
            return

    def _rows(self,groups,*,until=None,cleanup=False):
        row,out,err=self._call('owned-launchd-group-observation',
            ['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,stat='],until=until,cleanup=cleanup,ps=True)
        need(row['exitCode']==0 and not err,'complete_group_observation')
        values=[]
        for line in out.decode('ascii','strict').splitlines():
            fields=line.split()
            need(len(fields)==5 and all(x.isdecimal() for x in fields[:4]),'typed_process_row')
            pid,ppid,pgid,uid=map(int,fields[:4])
            if pgid in groups:values.append({'pid':pid,'ppid':ppid,'pgid':pgid,'uid':uid,'state':fields[4]})
        return values

    def _check_registration_files(self,entry):
        # Read-only metadata used in cleanup also: no expired private read,
        # no mutation, and no new business budget is granted.
        self.guard.check(check_deadline=False)
        need(file_identity(entry['plan'].lstat())==entry['planIdentity']
             and file_identity(entry['plist'].lstat())==entry['plistIdentity'],
             'registration_input_identity_unchanged')

    def _bootout(self,entry,*,cleanup=False,until=None):
        self._check_registration_files(entry)
        state=self._query(entry['label'],entry,until=until,cleanup=cleanup)
        if state is None:
            need('bootout' in entry['attempts'],'no_unexplained_registration_disappearance')
        elif 'bootout' not in entry['attempts']:
            if not cleanup:
                need(state.get('pid') is None,'known_wrapper_exit_before_bootout')
                self._record('bootout-intent',entry['generation'],{'argv':['/bin/launchctl','bootout',entry['target']]})
            self._dispatch_once(entry,'bootout',['/bin/launchctl','bootout',entry['target']],
                                until=until,cleanup=cleanup)
        while self._query(entry['label'],entry,until=until,cleanup=cleanup) is not None:
            self._remaining(until,cleanup=cleanup)
            time.sleep(min(NEW_MANAGER_POLL_SECONDS,self._remaining(until,cleanup=cleanup)))
        remaining=self._rows(entry['groups'],until=until,cleanup=cleanup)
        entry['remainingGroupRows']=remaining
        need(not remaining,'owned_group_empty_after_label_removal')
        entry['registrationClosed']=True
        if not cleanup:self._record('bootout-complete',entry['generation'],{'groupRows':remaining})

    def _server_stdout_prefix(self,entry):
        """Bind the completed wrapper record while the server may append logs.

        This proves only the first LF-terminated record, read twice through one
        held descriptor. It does not claim a whole stable live server log.
        """
        self._remaining()
        with self.guard.parent(entry['stdout']) as (parent,name):
            with self.signals.critical():
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                row={'fd':fd,'closeAttempted':False,'closed':False}
                self.fd_rows.append(row)
            try:
                first=os.fstat(fd)
                need(stat.S_ISREG(first.st_mode) and first.st_uid==501
                     and first.st_nlink==1 and stat.S_IMODE(first.st_mode)==0o600
                     and 0<first.st_size<=2*1024*1024,'server_stdout_private_bound')
                block=os.pread(fd,min(65536,first.st_size),0)
                position=block.find(b'\n')
                need(position>=0,'complete_wrapper_prefix')
                raw=block[:position+1]
                self._remaining()
                need(os.pread(fd,len(raw),0)==raw,'wrapper_prefix_same_fd_exact')
                after=os.fstat(fd);named=os.stat(name,dir_fd=parent,follow_symlinks=False)
                need(file_identity(first)[:6]==file_identity(after)[:6]==file_identity(named)[:6]
                     and first.st_size<=after.st_size<=2*1024*1024
                     and named.st_size>=len(raw),'server_stdout_name_and_prefix_fence')
                self.guard.check()
                return raw
            finally:
                with self.signals.critical():
                    row['closeAttempted']=True
                    os.close(fd);row['closed']=True

    def start_server(self,generation):
        self._expect_action('server-start',generation)
        entry=self._new_entry('server',generation)
        try:
            self._dispatch_once(entry,'bootstrap',['/bin/launchctl','bootstrap',DOMAIN,str(entry['plist'])])
            self._ready(entry)
            until=min(self.until,time.monotonic()+NEW_EXEC_OBSERVATION_SECONDS)
            original=entry['wrapperIdentity']
            while True:
                self._remaining(until)
                state=self._query(entry['label'],entry,until=until)
                need(state is not None and state.get('pid')==original['pid']
                     and state.get('runs')==1,'same_launchd_pid_before_server_exec')
                observed=self.reader.read(original['pid'])
                need(all(observed[k]==original[k] for k in
                     ('pid','ppid','pgid','uid','birthSec','birthUsec')),'server_exec_same_birth')
                if observed['executable']==str(SERVER.resolve()):break
                need(observed['executable']==original['executable'],'no_foreign_executable')
                time.sleep(min(NEW_MANAGER_POLL_SECONDS,self._remaining(until)))
            raw=self.guard.read(ROOT/'launchd'/(generation+'.exec-ready.public.json'))
            candidate=json.loads(raw)
            stdout=self._server_stdout_prefix(entry)
            terminal=json.loads(stdout)
            need(isinstance(candidate,dict) and isinstance(terminal,dict)
                 and candidate.get('schema')=='heptabao.mac-owned-launchd-server-wrapper.r1'
                 and terminal.get('schema')==candidate['schema']
                 and terminal.get('generation')==generation
                 and terminal.get('ok') is True and terminal.get('readyToExec') is True
                 and terminal.get('outcomeUnknown') is False
                 and terminal.get('candidateReceiptSha256')==sha(raw)
                 and terminal.get('wrapperIdentity')==original
                 and terminal.get('binaryPath')==str(SERVER) and terminal.get('binarySha256')==SERVER_SHA
                 and terminal.get('elapsedSeconds',31)<30,'server_wrapper_completion_before_exec')
            closure=terminal.get('volumeGuardClosed',{});commands=terminal.get('commands',{})
            need(closure.get('allDescriptorsClosed') is True
                 and closure.get('lastAnchorCheckPassed') is True and closure.get('closeErrors')==[]
                 and commands.get('allOwnedCommandsStopped') is True
                 and commands.get('unknownCommandCount')==0,'server_wrapper_closure')
            entry['execIdentity']=observed
            entry['serverWrapperClosed']=True
            entry['execReceiptSha256']=sha(raw)
            entry['wrapperTerminalPrefixSha256']=sha(stdout)
            self._record('actual-server-exec',generation,{'identity':observed,
                'binarySha256':SERVER_SHA,'execReceiptSha256':sha(raw)})
            self._advance()
            return {'generation':generation,'serverIdentity':observed,'execReceiptSha256':sha(raw)}
        except BaseException:
            self.unknown=True
            raise

    def kill_server_for_cold_or_inverse(self,generation):
        self._expect_action('server-kill',generation)
        entry=next((e for e in self.entries if e['generation']==generation),None)
        need(entry is not None and entry['execIdentity'] is not None,'actual_server_before_kill')
        state=self._query(entry['label'],entry)
        need(state is not None and state.get('pid')==entry['execIdentity']['pid']
             and self.reader.read(state['pid'])==entry['execIdentity'],'exact_server_before_sigkill')
        self._record('server-sigkill-intent',generation,{'argv':['/bin/launchctl','kill','SIGKILL',entry['target']]})
        self._dispatch_once(entry,'kill',['/bin/launchctl','kill','SIGKILL',entry['target']])
        until=min(self.until,time.monotonic()+QUERY_SECONDS)
        while True:
            state=self._query(entry['label'],entry,until=until)
            need(state is not None and state.get('runs')==1,'same_registration_after_sigkill')
            if state.get('pid') is None:break
            need(state['pid']==entry['execIdentity']['pid'],'no_server_restart')
            time.sleep(min(NEW_MANAGER_POLL_SECONDS,self._remaining(until)))
        need(state.get('last terminating signal') in ('9','SIGKILL','Killed: 9','9 (Killed: 9)'),
             'actual_launchd_sigkill_terminal')
        need(not self._rows(entry['groups'],until=until),'server_group_empty_after_sigkill')
        entry['lineagesClosed']=entry.get('serverWrapperClosed') is True
        entry['completeKnownSuccess']=True
        self._bootout(entry,until=until)
        self._record('server-sigkill-complete',generation,
                     {'actualSignal':'SIGKILL','samePid':entry['execIdentity']['pid'],'groupRows':[]})
        self._advance()

    def run_phase(self,generation):
        self._expect_action('phase',generation)
        entry=self._new_entry('consumer',generation)
        try:
            self._dispatch_once(entry,'bootstrap',['/bin/launchctl','bootstrap',DOMAIN,str(entry['plist'])])
            self._ready(entry)
            while True:
                state=self._query(entry['label'],entry)
                need(state is not None and state.get('runs')==1,'same_phase_registration')
                if state.get('pid') is None:break
                need(state['pid']==entry['wrapperIdentity']['pid']
                     and self.reader.read(state['pid'])==entry['wrapperIdentity'],'same_phase_process')
                time.sleep(min(NEW_MANAGER_POLL_SECONDS,self._remaining()))
            need(state.get('last exit code')==0,'actual_launchd_phase_exit_zero')
            raw=self.guard.read(ROOT/'launchd'/(generation+'.result.public.json'))
            result=json.loads(raw)
            stdout=self.guard.read(entry['stdout'])
            need(len(stdout.splitlines())==1,'one_final_phase_stdout_record')
            terminal=json.loads(stdout)
            need(isinstance(result,dict) and isinstance(terminal,dict)
                 and result.get('schema')=='heptabao.mac-five-agent-phase-owner.r2'
                 and result.get('generation')==generation and result.get('ok') is True
                 and result.get('outcomeUnknown') is False
                 and result.get('allOwnedStopped') is True
                 and result.get('allObserverClosuresAttemptedOnce') is True
                 and result.get('originalSharedPhaseSeconds')==120
                 and terminal.get('generation')==generation and terminal.get('ok') is True
                 and terminal.get('outcomeUnknown') is False
                 and terminal.get('allOwnedStopped') is True and terminal.get('resultSha256')==sha(raw)
                 and type(terminal.get('elapsedSeconds')) in (int,float)
                 and 0<=terminal['elapsedSeconds']<120,'phase_raw_result_terminal_exit_conjunction')
            closure=terminal.get('volumeGuardClosed',{})
            need(closure.get('allDescriptorsClosed') is True
                 and closure.get('lastAnchorCheckPassed') is True and closure.get('closeErrors')==[],
                 'phase_t5_closure_after_candidate_publication')
            inverse=generation.endswith('-inverse')
            records=result.get('records')
            expected=(['inverse-five-agents-and-six-caches'] if inverse else
                      ['authbus-five-agent-cycle',*['native-'+a for a in AGENTS]])
            need(isinstance(records,list) and [x.get('name') for x in records]==expected
                 and result.get('nativeWorkerCount')==(0 if inverse else 5),'exact_four_phase_matrix')
            for record in records:
                life=record.get('lifecycle',{});worker=record.get('report',{})
                need(life.get('exitCode')==0 and life.get('primaryReaped') is True
                     and life.get('noGroupSurvivors') is True and life.get('outcomeUnknown') is False
                     and life.get('remainingGroupMembers')==[]
                     and worker.get('ok') is True and worker.get('outcomeUnknown') is False,
                     'worker_known_and_actual_lineage_closed')
                pgid=life.get('ownedProcessGroup')
                need(type(pgid) is int and pgid>1,'typed_owned_worker_group')
                entry['groups'].add(pgid)
                if record.get('agentId') is not None:
                    observer=life.get('nativeProcessObserver',{})
                    need(observer.get('verified') is True and observer.get('requests')==1,
                         'separate_actual_single_native_observer')
            need(not self._rows(entry['groups']),'all_actual_phase_groups_empty')
            entry['lineagesClosed']=True;entry['completeKnownSuccess']=True
            entry['resultSha256']=sha(raw);entry['terminalSha256']=sha(stdout)
            entry['phaseRecordCount']=len(records)
            self._bootout(entry)
            self._record('phase-complete',generation,{'resultSha256':sha(raw),
                'terminalSha256':sha(stdout),'actualExitCode':0,'phaseRecords':len(records),
                'allKnownGroupsEmpty':True})
            self._advance()
            return result
        except BaseException:
            self.unknown=True
            raise

    def abort_cleanup_once(self):
        if self.failure_cleanup_attempted:return self.public()
        with self.signals.critical():
            self.failure_cleanup_attempted=True
            self.cleanup_until=time.monotonic()+NEW_CLEANUP_SECONDS
            self.unknown=True
            for entry in reversed(self.entries):
                if entry['registrationClosed']:continue
                try:
                    self._check_registration_files(entry)
                    state=self._query(entry['label'],entry,cleanup=True)
                    if state is None:
                        entry['registrationClosed']=True
                        entry['remainingGroupRows']=self._rows(entry['groups'],cleanup=True)
                        if entry['remainingGroupRows']:entry['registrationClosed']=False
                        continue
                    pid=state.get('pid')
                    expected=entry['execIdentity'] or entry['wrapperIdentity']
                    if pid is not None:
                        need(expected is not None and pid==expected['pid']
                             and self.reader.read(pid)==expected,'cleanup_exact_current_owned_identity')
                        operation='kill' if entry['kind']=='server' and entry['execIdentity'] else 'term'
                        if operation not in entry['attempts']:
                            signal_name='SIGKILL' if operation=='kill' else 'SIGTERM'
                            self._dispatch_once(entry,operation,
                                ['/bin/launchctl','kill',signal_name,entry['target']],cleanup=True)
                        grace=min(self.cleanup_until,time.monotonic()+NEW_FAILURE_TERM_GRACE_SECONDS)
                        while self._remaining(grace,cleanup=True):
                            state=self._query(entry['label'],entry,until=grace,cleanup=True)
                            if state is None or state.get('pid') is None:break
                            need(state['pid']==expected['pid'],'cleanup_no_replacement_pid')
                            time.sleep(min(NEW_MANAGER_POLL_SECONDS,self._remaining(grace,cleanup=True)))
                    self._bootout(entry,cleanup=True)
                    if entry['kind']=='server' and entry.get('serverWrapperClosed'):
                        entry['lineagesClosed']=not entry.get('remainingGroupRows')
                except BaseException as error:
                    entry['cleanupErrorType']=type(error).__name__
                    entry['cleanupErrorCode']=str(error) if isinstance(error,ManagerRefused) else None
            return self.public()

    def finish(self):
        self._remaining()
        need(self.graph_index==len(GRAPH) and not self.failure_cleanup_attempted
             and not self.unknown and all(e['registrationClosed'] and e['lineagesClosed']
             and e['completeKnownSuccess'] for e in self.entries),'entire_finite_manager_graph_complete')
        commands=self.commands.public()
        need(commands['allOwnedCommandsStopped'] and commands['unknownCommandCount']==0
             and all(r['closed'] for r in self.fd_rows),'all_manager_helpers_and_descriptors_closed')
        self.finished=True
        return self.public()

    def public(self):
        entries=[]
        for e in self.entries:
            entries.append({'kind':e['kind'],'generation':e['generation'],'label':e['label'],
                'planSha256':e['planSha256'],'plistSha256':e['plistSha256'],
                'wrapperIdentity':e['wrapperIdentity'],'execIdentity':e['execIdentity'],
                'knownOwnedGroups':sorted(e['groups']),'attempts':e['attempts'],
                'registrationClosed':e['registrationClosed'],'lineagesClosed':e['lineagesClosed'],
                'completeKnownSuccess':e['completeKnownSuccess'],
                'remainingGroupRows':e.get('remainingGroupRows'),
                'resultSha256':e.get('resultSha256'),'terminalSha256':e.get('terminalSha256'),
                'cleanupErrorType':e.get('cleanupErrorType'),'cleanupErrorCode':e.get('cleanupErrorCode')})
        commands=self.commands.public()
        return {'schema':'heptabao.mac-owned-launchd-manager.r3','ok':bool(self.finished and not self.unknown and time.monotonic()<self.until),
            'outcomeUnknown':self.unknown,'newManagerSeconds':NEW_MANAGER_SECONDS,
            'newFailureCleanupSeconds':NEW_CLEANUP_SECONDS,'originalPhaseSeconds':120,
            'pythonRuntime':dict(self.python_runtime),
            'operationGraph':list(GRAPH),'completedOperationCount':self.graph_index,
            'registrations':entries,'events':list(self.events),'ownedCommands':commands,
            'allRegistrationsClosed':all(e['registrationClosed'] for e in self.entries),
            'allKnownLineagesClosed':all(e['lineagesClosed'] for e in self.entries),
            'allOwnedCommandsStopped':commands['allOwnedCommandsStopped'],
            'allManagerReadDescriptorsClosed':all(r['closed'] for r in self.fd_rows),
            'newMaximumCommandCount':MAX_COMMANDS,'newManagerPollSeconds':NEW_MANAGER_POLL_SECONDS,
            'failureCleanupAttempted':self.failure_cleanup_attempted,
            'elapsedSeconds':time.monotonic()-self.started,
            'noNumericPidOrGroupSignals':True,'productionManagerQualification':False}
