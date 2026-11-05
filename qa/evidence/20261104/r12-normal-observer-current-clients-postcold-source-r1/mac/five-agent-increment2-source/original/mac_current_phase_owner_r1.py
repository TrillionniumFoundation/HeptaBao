#!/usr/bin/env python3
"""One launchd-owned wrapper, one original 120s phase, five real native lineages.

Launchd owns THIS wrapper. It really Popen()s sandbox-exec -> Node; each native
worker gets its own unchanged single-use anonymous-pipe observer. The outer
launchd manager cannot mint that observer ACK or claim Node as its own child.
This draft is source-only. It has not captured current credentials or run a job.
"""
from __future__ import annotations
import argparse, hashlib, json, os, plistlib, signal, stat, subprocess, sys, time
from pathlib import Path

START = time.monotonic()
UNTIL = START + 120
ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1')
AGENTS = ('main','trnm','hepta-ui','hepta','hepta-backend')
UUID = 'FB804D1B-24CB-4D6E-AEA7-A9E180807758'
NODE = '/opt/homebrew/bin/node'
protected = 0
pending_signal = None
owned = []
observers = []

class Refused(RuntimeError): pass
class Cancelled(BaseException): pass
def need(value, code):
    if not value: raise Refused(code)
def interrupt(signum, _frame):
    global pending_signal
    pending_signal = signum
    if protected == 0: raise Cancelled()
for sig in (signal.SIGTERM, signal.SIGINT): signal.signal(sig, interrupt)
def remaining(until=UNTIL):
    need(pending_signal is None, 'phase_interrupted')
    value = until - time.monotonic()
    need(value > 0, 'original_shared_phase_deadline_exhausted')
    return value
def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def identity(s):
    return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def private_read(path,maximum=2*1024*1024):
    path=Path(path)
    need(path.resolve(strict=True)==path and path.is_relative_to(ROOT),'owned_private_read_path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
             and stat.S_IMODE(before.st_mode)==0o600 and 0<=before.st_size<=maximum,'private_custody')
        raw=b''
        while len(raw)<=maximum:
            block=os.read(fd,min(65536,maximum+1-len(raw)))
            if not block: break
            raw+=block
        need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),
             'private_bytes_identity_stable')
        return raw
    finally: os.close(fd)
def put(path,value):
    path=Path(path)
    need(path.parent.resolve(strict=True)==path.parent and path.is_relative_to(ROOT),'new_owned_output_path')
    raw=value if isinstance(value,bytes) else encoded(value)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:
        out.write(raw);out.flush();os.fsync(out.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def file_sha(path,maximum=128*1024*1024):
    path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=maximum,'source_regular_bound')
        h=hashlib.sha256();size=0
        while True:
            remaining()
            block=os.read(fd,1024*1024)
            if not block:break
            size+=len(block);h.update(block)
        need(size==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'source_changed')
        return h.hexdigest()
    finally:os.close(fd)

def run_owned_capture(argv, env, cwd, until, stdout_path, stderr_path, native_observer=None):
    global protected
    from authbus_native_login_custody import group_members
    from authbus_native_process_observer import OwnedNativeObserver, ObservationRefused
    lifecycle = {'exitCode': None, 'timeout': False, 'interrupted': False, 'primaryReaped': False,
                 'noGroupSurvivors': False, 'outcomeUnknown': False}
    remaining(until)
    observer = None
    protected += 1
    try:
        observer = OwnedNativeObserver(native_observer) if native_observer else None
        if observer is not None: observers.append(observer)
    finally: protected -= 1
    if pending_signal is not None: raise Cancelled()
    child_env = dict(env)
    if observer:
        need(not any(k in child_env for k in observer.child_env), 'fresh_observer_pipe_environment')
        child_env.update(observer.child_env)
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        protected += 1
        try:
            remaining(until)
            proc = subprocess.Popen(argv, env=child_env, cwd=str(cwd), start_new_session=True,
                stdout=stdout, stderr=stderr, close_fds=True,
                pass_fds=observer.child_fds if observer else ())
            owned.append({'process': proc, 'stopAttempted': False, 'lifecycle': lifecycle})
        except BaseException:
            if observer: observer.close()
            raise
        finally: protected -= 1
        pgid = proc.pid; lifecycle['ownedProcessGroup'] = pgid
        try:
            if observer: observer.parent_after_spawn(proc)
            deadline = until
            if pending_signal is not None: raise Cancelled()
            while True:
                if time.monotonic() >= deadline:
                    lifecycle['timeout'] = True
                    break
                if observer: observer.poll(deadline)
                returncode = proc.poll()
                if returncode is not None:
                    lifecycle['exitCode'] = returncode
                    break
                if time.monotonic() >= deadline:
                    lifecycle['timeout'] = True
                    break
                time.sleep(0.025)
        except (KeyboardInterrupt, Cancelled): lifecycle['interrupted'] = True
        except Exception as observer_error:
            lifecycle['observationError'] = str(observer_error) if isinstance(observer_error, ObservationRefused) else type(observer_error).__name__
        finally:
            if observer:
                observer.close()
                lifecycle['nativeProcessObserver'] = observer.report
            previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
            previous_term = signal.signal(signal.SIGTERM, signal.SIG_IGN)
            owned[-1]['stopAttempted'] = True
            try:
                if group_members(pgid):
                    try: os.killpg(pgid, signal.SIGTERM)
                    except ProcessLookupError: pass
                    deadline = time.monotonic() + 1
                    while group_members(pgid) and time.monotonic() < deadline:
                        proc.poll(); time.sleep(0.05)
                    if group_members(pgid):
                        try: os.killpg(pgid, signal.SIGKILL)
                        except ProcessLookupError: pass
                proc.wait(timeout=5); lifecycle['primaryReaped'] = True
                lifecycle['finalReturnCode'] = proc.returncode
                deadline = time.monotonic() + 3
                remaining = group_members(pgid)
                while remaining and time.monotonic() < deadline:
                    time.sleep(0.05); remaining = group_members(pgid)
                lifecycle['remainingGroupMembers'] = remaining
                lifecycle['noGroupSurvivors'] = not remaining
                lifecycle['outcomeUnknown'] = lifecycle['timeout'] or lifecycle['interrupted'] or bool(remaining) or bool(lifecycle.get('observationError'))
            finally:
                signal.signal(signal.SIGINT, previous)
                signal.signal(signal.SIGTERM, previous_term)
    return lifecycle


def volume_before_private_state():
    """No T5 pathname is opened or written by this guard before UUID success."""
    global protected
    until=min(UNTIL,time.monotonic()+30)
    lifecycle={'exitCode':None,'timeout':False,'interrupted':False,'primaryReaped':False,
               'noGroupSurvivors':False,'outcomeUnknown':False}
    protected+=1
    try:
        remaining(until)
        proc=subprocess.Popen(['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
          env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C'},
          stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        row={'process':proc,'stopAttempted':False,'lifecycle':lifecycle};owned.append(row)
    finally:protected-=1
    out=err=b''
    try:
        if pending_signal is not None:raise Cancelled()
        out,err=proc.communicate(timeout=remaining(until))
        remaining(until)
        need(len(out)<=262144 and len(err)<=262144,'bounded_volume_output')
        lifecycle['exitCode']=proc.returncode
    except subprocess.TimeoutExpired:lifecycle['timeout']=True
    except (Cancelled,KeyboardInterrupt):lifecycle['interrupted']=True
    finally:
        previous=signal.signal(signal.SIGINT,signal.SIG_IGN)
        previous_term=signal.signal(signal.SIGTERM,signal.SIG_IGN)
        row['stopAttempted']=True
        try:
            if proc.poll() is None:
                try:os.killpg(proc.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                try:proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    try:os.killpg(proc.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    proc.wait(timeout=5)
            proc.wait(timeout=5)
            lifecycle['primaryReaped']=True;lifecycle['finalReturnCode']=proc.returncode
            # Only this exact owned group is retained. This fixed read-only ps
            # is reaped by subprocess.run; its existing four-second helper cap
            # is also subject to the enclosing phase success deadline.
            ps=subprocess.run(['/bin/ps','-axo','pid=,pgid=,stat='],stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4,check=True)
            members=[]
            for line in ps.stdout.decode('ascii').splitlines():
                fields=line.split()
                if len(fields)==3 and int(fields[1])==proc.pid:
                    members.append({'pid':int(fields[0]),'state':fields[2]})
            lifecycle['remainingGroupMembers']=members
            lifecycle['noGroupSurvivors']=not members
            lifecycle['outcomeUnknown']=lifecycle['timeout'] or lifecycle['interrupted'] or bool(members)
        finally:
            if proc.stdout:proc.stdout.close()
            if proc.stderr:proc.stderr.close()
            signal.signal(signal.SIGINT,previous);signal.signal(signal.SIGTERM,previous_term)
    need(lifecycle['exitCode']==0 and lifecycle['primaryReaped']
      and lifecycle['noGroupSurvivors'] and not lifecycle['outcomeUnknown'],'volume_probe_complete')
    info=plistlib.loads(out)
    need(info.get('VolumeUUID')==UUID and info.get('MountPoint')=='/Volumes/T5','exact_t5_before_phase')
    remaining()
    return {'lifecycle':lifecycle,'stdoutSha256':sha(out),'stderrSha256':sha(err),
            'volumeUUID':info['VolumeUUID'],'mountPoint':info['MountPoint']}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--plan-sha256',required=True)
    args=parser.parse_args()
    os.umask(0o077)
    report={'schema':'heptabao.mac-five-agent-phase-owner.r1','ok':False,
      'originalSharedPhaseSeconds':120,'nativeWorkerCount':0,'records':[],
      'productionChanged':False,'providerRequestSent':False,'j3160Contacted':False,
      'realLaunchdQualificationSuppliedByOuterManager':False,'outcomeUnknown':False}
    plan=None;generation=None
    try:
        need(sys.platform=='darwin' and os.getuid()==501,'exact_mac_owner')
        report['volumeGuard']=volume_before_private_state()
        raw=private_read(args.plan);need(sha(raw)==args.plan_sha256,'exact_phase_plan_pin')
        plan=json.loads(raw)
        need(plan['schema']=='heptabao.mac-five-agent-phase-plan.private.r1'
          and plan['phase'] in ('initial','cold-new-process') and plan['mode'] in ('consume','inverse')
          and plan['agentIds']==list(AGENTS) and plan['phaseSeconds']==120,'fixed_phase_contract')
        phase=ROOT/plan['phase'];generation=plan['generation']
        need(generation in ('initial','cold-new-process','initial-inverse','cold-new-process-inverse')
          and generation==plan['phase']+('-inverse' if plan['mode']=='inverse' else ''),
          'unique_phase_generation')
        need(Path(plan['phaseRoot'])==phase and Path(plan['stateRoot'])==phase/'state',
             'independent_initial_cold_state')
        q=ROOT/'qa'
        need(args.plan==ROOT/'launchd'/(generation+'.private.json'),'immutable_manager_phase_plan')
        for name in ('authbus_native_process_observer.py','authbus_native_login_custody.py',
                     'mac_current_phase_owner_r1.py','mac_current_cycle_r1.mjs','mac_single_native_r1.mjs',
                     'mac_auth_rows_cas_r1.mjs','mac_authbus_cache_cas_r1.mjs'):
            need(file_sha(q/name)==plan['qaPins'][name],'reviewed_qa_source.'+name)
        sys.path.insert(0,str(q))
        from authbus_native_process_observer import ProcessReader
        self_identity=ProcessReader().read(os.getpid())
        need(self_identity['uid']==501 and self_identity['executable']==str(Path(sys.executable).resolve()),
             'real_wrapper_process_identity')
        ready={'schema':'heptabao.mac-phase-wrapper-ready.r1','generation':generation,
               'planSha256':args.plan_sha256,'wrapperIdentity':self_identity,
               'phaseStartMonotonic':START,'originalPhaseDeadlineMonotonic':UNTIL}
        put(ROOT/'launchd'/(generation+'.ready.public.json'),ready)
        env={'PATH':'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
             'HOME':str(phase/'state/home'),'TMPDIR':str(phase/'tmp')}
        need(phase.stat().st_dev==Path('/Volumes/T5').stat().st_dev==plan['expectedVolumeDevice'],
             'phase_on_exact_current_t5_device')
        common=plan['workerCommon']
        need(common['workRoot']==str(ROOT) and common['phaseRoot']==str(phase)
          and common['stateRoot']==str(phase/'state'),'worker_common_owned_scope')
        # All environment fields outside original owned filesystem isolation are
        # passed from the reviewed fixed plan; no credential values are added.
        env.update(OPENCLAW_STATE_DIR=str(phase/'state'),
                   OPENCLAW_CONFIG_PATH=str(phase/'state/openclaw.json'),
                   OPENCLAW_OAUTH_DIR=str(phase/'state/oauth'),
                   OPENCLAW_HOME=str(phase/'state/home'))
        def invoke(label,mode,agent=None):
            remaining()
            worker={**common,'schema':'heptabao.mac-five-agent-worker.private.r1',
                    'mode':mode,'phase':plan['phase'],'phaseOwnerPid':os.getpid(),
                    'phaseRemainingMs':int(remaining()*1000)}
            if agent is not None:
                worker.update(plan['nativeWorkers'][agent]);worker['agentId']=agent
                need(worker['nativeHome']==str(phase/'state/agents'/agent/'agent/codex-home'),
                     'per_agent_native_home')
            worker_dir=phase/('inverse' if mode=='rollback' else 'workers')
            need(worker_dir.is_dir() and worker_dir.resolve(strict=True)==worker_dir,'precreated_owned_worker_directory')
            path=worker_dir/(label+'.plan.private.json')
            worker['custodyOutput']=str(worker_dir/(label+'.auth.private.json'))
            put(path,worker)
            executable=q/('mac_single_native_r1.mjs' if agent else 'mac_current_cycle_r1.mjs')
            out=worker_dir/(label+'.stdout.private');err=worker_dir/(label+'.stderr.private')
            child_env=dict(env)
            if agent is not None: child_env['TMPDIR']=worker['nativeTmp']
            life=run_owned_capture(['/usr/bin/sandbox-exec','-f',common['parentSandbox'],
                    NODE,str(executable),str(path)],child_env,phase,UNTIL,out,err,
                    native_observer=None if agent is None else {
                      'nodeExecutable':str(Path(NODE).resolve()),'nativeExecutable':worker['nativeBinary']})
            out_bytes=private_read(out);err_bytes=private_read(err)
            try: value=json.loads(out_bytes)
            except Exception: value={'ok':False,'error':'worker_report_unavailable'}
            record={'name':label,'mode':mode,'agentId':agent,'lifecycle':life,
                    'stdoutSha256':sha(out_bytes),'stderrSha256':sha(err_bytes),
                    'stdoutBytes':len(out_bytes),'stderrBytes':len(err_bytes),'report':value}
            report['records'].append(record)
            # No next worker, inverse, or cold action follows a timeout, unknown
            # response, missing report, surviving lineage, or unsuccessful gate.
            if (life['outcomeUnknown'] or value.get('outcomeUnknown')
                    or value.get('error')=='worker_report_unavailable'):
                report['outcomeUnknown']=True
            need(life['exitCode']==0 and life['primaryReaped'] and life['noGroupSurvivors']
                 and not life['outcomeUnknown'] and value.get('ok') is True
                 and value.get('outcomeUnknown') is not True,'worker_complete_known_success.'+label)
            if agent is not None:
                need(life.get('nativeProcessObserver',{}).get('verified') is True
                  and life['nativeProcessObserver']['requests']==1,'separate_one_shot_native_observer')
                report['nativeWorkerCount']+=1
            remaining()
        if plan['mode']=='consume':
            invoke('authbus-five-agent-cycle','cycle')
            for agent in AGENTS: invoke('native-'+agent,'native',agent)
            need(report['nativeWorkerCount']==5 and len(report['records'])==6,'one_cycle_and_five_native_lineages')
        else:
            invoke('inverse-five-agents-and-six-caches','rollback')
            need(report['nativeWorkerCount']==0 and len(report['records'])==1,'inverse_no_native_or_network')
        need(all(file_sha(q/name)==pin for name,pin in plan['qaPins'].items()),'all_qa_pins_after')
        remaining();report['ok']=True
    except BaseException as error:
        report['errorType']=type(error).__name__
        report['errorCode']=str(error) if isinstance(error,Refused) else None
        if isinstance(error,(Cancelled,KeyboardInterrupt)):report['outcomeUnknown']=True
    finally:
        signal.signal(signal.SIGINT,signal.SIG_IGN)
        signal.signal(signal.SIGTERM,signal.SIG_IGN)
        for observer in observers:
            try:observer.close()
            except Exception:report['ok']=False
        # Registered but not yet finalized children can occur at a cancellation
        # boundary. The once marker prevents giving any child a second cleanup.
        orphan_cleanup=[]
        for row in owned:
            if row['stopAttempted']:continue
            row['stopAttempted']=True;p=row['process']
            item={'pid':p.pid,'stopAttempted':True}
            try:
                if p.poll() is None:
                    try:os.killpg(p.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
                    try:p.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        try:os.killpg(p.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        p.wait(timeout=5)
                item['directChildReaped']=p.returncode is not None
                from authbus_native_login_custody import group_members
                item['remaining']=group_members(p.pid)
            except BaseException as error:item['cleanupErrorType']=type(error).__name__
            orphan_cleanup.append(item)
            report['ok']=False;report['outcomeUnknown']=True
        report['exceptionBoundaryCleanup']=orphan_cleanup
        report['allOwnedStopped']=all(row['lifecycle'].get('primaryReaped') is True
          and row['lifecycle'].get('noGroupSurvivors') is True for row in owned)
        if not report['allOwnedStopped'] or time.monotonic()>=UNTIL:report['ok']=False
        report['elapsedSeconds']=time.monotonic()-START
        report['authorityExitZeroAndOriginalPhaseDeadlineRequired']=True
        if plan is not None and generation is not None:
            put(ROOT/'launchd'/(generation+'.result.public.json'),report)
        print(json.dumps({'ok':report['ok'],'generation':generation,
          'allOwnedStopped':report['allOwnedStopped'],'outcomeUnknown':report['outcomeUnknown'],
          'elapsedSeconds':time.monotonic()-START},sort_keys=True),flush=True)
    return 0 if report['ok'] and time.monotonic()<UNTIL else 1

if __name__=='__main__':sys.exit(main())
