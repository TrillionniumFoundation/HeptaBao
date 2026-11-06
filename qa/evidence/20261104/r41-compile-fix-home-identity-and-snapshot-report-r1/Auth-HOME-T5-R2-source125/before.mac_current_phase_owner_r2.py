#!/usr/bin/env python3
"""One launchd-owned wrapper, one original 120s phase, five real native lineages.

Launchd owns THIS wrapper. It really Popen()s sandbox-exec -> Node; each native
worker gets its own unchanged single-use anonymous-pipe observer. The outer
launchd manager cannot mint that observer ACK or claim Node as its own child.
This draft is source-only. It has not captured current credentials or run a job.
"""
from __future__ import annotations
import argparse, base64, hashlib, json, os, plistlib, signal, stat, subprocess, sys, time
from pathlib import Path
from contextlib import contextmanager

START = time.monotonic()
UNTIL = START + 120
PYTHON_LAUNCHER = "/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
PYTHON_KERNEL_IMAGE = "/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python"
ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r1')
AGENTS = ('main','trnm','hepta-ui','hepta','hepta-backend')
UUID = 'FB804D1B-24CB-4D6E-AEA7-A9E180807758'
NODE = '/opt/homebrew/bin/node'
protected = 0
pending_signal = None
owned = []
observers = []
observer_close_results = {}
volume_guard = None

@contextmanager
def critical():
    global protected
    protected += 1
    try: yield
    finally: protected -= 1

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
    need(volume_guard is not None,'held_volume_before_private_read')
    return volume_guard.read(path,maximum,private=True)
def put(path,value):
    need(volume_guard is not None,'held_volume_before_private_write')
    raw=value if isinstance(value,bytes) else encoded(value)
    return volume_guard.write_new(path,raw)
def file_sha(path,maximum=128*1024*1024):
    path=Path(path)
    if volume_guard is not None and path.is_relative_to(ROOT):
        return sha(volume_guard.read(path,min(maximum,16*1024*1024),private=False))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
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

def close_observer_once(observer):
    key=id(observer)
    if key in observer_close_results:return observer_close_results[key]
    with critical():
        observer_close_results[key]=False
        try:
            observer_close_results[key]=observer.close() is True
        except BaseException:pass
    return observer_close_results[key]

def run_owned_capture(argv, env, cwd, until, stdout_path, stderr_path, native_observer=None):
    global protected
    from mac_owned_unreaped_r1 import (require_waitid, capture_child,
        exit_observation, observed_returncode, stop_once_unreaped)
    from mac_native_process_observer_r1 import OwnedNativeObserver, ObservationRefused
    lifecycle = {'exitCode':None,'timeout':False,'interrupted':False,'primaryReaped':False,
                 'noGroupSurvivors':False,'outcomeUnknown':False,
                 'directChildRetainedUntilGroupCleanup':True}
    remaining(until);require_waitid()
    observer=None;row=None
    with critical():
        observer=OwnedNativeObserver(native_observer,critical=critical) if native_observer else None
        if observer is not None:observers.append(observer)
    if pending_signal is not None:raise Cancelled()
    child_env=dict(env)
    if observer:
        need(not any(k in child_env for k in observer.child_env),'fresh_observer_pipe_environment')
        child_env.update(observer.child_env)
    need(volume_guard is not None,'held_volume_before_child_output')
    with volume_guard.capture_sink(stdout_path) as stdout, volume_guard.capture_sink(stderr_path) as stderr:
        with critical():
            remaining(until)
            proc=subprocess.Popen(argv,env=child_env,cwd=str(cwd),start_new_session=True,
                stdout=stdout,stderr=stderr,close_fds=True,
                pass_fds=observer.child_fds if observer else ())
            row={'process':proc,'stopAttempted':False,'lifecycle':lifecycle,'custody':None,
                 'worker':True,'deliveredReport':False}
            owned.append(row)
        lifecycle['ownedProcessGroup']=proc.pid
        try:
            if observer:
                with critical():observer.parent_after_spawn(proc)
            row['custody']=capture_child(proc,until=until)
            lifecycle['actualDirectChildCustody']=row['custody']
            if pending_signal is not None:raise Cancelled()
            while True:
                if time.monotonic()>=until:
                    lifecycle['timeout']=True;break
                if observer:observer.poll(until)
                event=exit_observation(proc)
                if time.monotonic()>=until:
                    lifecycle['timeout']=True;break
                if event is not None:
                    lifecycle['exitCode']=observed_returncode(event)
                    lifecycle['retainedExit']=event
                    break
                remaining(until)
                time.sleep(min(0.025,remaining(until)))
        except (KeyboardInterrupt,Cancelled):lifecycle['interrupted']=True
        except BaseException as error:
            lifecycle['observationError']=str(error) if isinstance(error,ObservationRefused) else type(error).__name__
        finally:
            previous=signal.signal(signal.SIGINT,signal.SIG_IGN)
            previous_term=signal.signal(signal.SIGTERM,signal.SIG_IGN)
            try:
                if observer:
                    if not close_observer_once(observer):lifecycle['observerCloseError']='ObserverCloseFailed'
                    lifecycle['nativeProcessObserver']=observer.report
                row['stopAttempted']=True
                cleanup=stop_once_unreaped(proc,row['custody'])
                lifecycle['retainedChildCleanup']=cleanup
                lifecycle['primaryReaped']=cleanup.get('directChildReaped') is True
                lifecycle['finalReturnCode']=cleanup.get('exitCode')
                lifecycle['remainingGroupMembers']=cleanup.get('remainingGroupRows')
                lifecycle['noGroupSurvivors']=cleanup.get('allGroupRowsEmptyAfterReap') is True
                lifecycle['outcomeUnknown']=bool(lifecycle['timeout'] or lifecycle['interrupted']
                    or lifecycle.get('observationError') or lifecycle.get('observerCloseError')
                    or cleanup.get('outcomeUnknown') or not lifecycle['primaryReaped']
                    or not lifecycle['noGroupSurvivors'])
            finally:
                signal.signal(signal.SIGINT,previous);signal.signal(signal.SIGTERM,previous_term)
    return lifecycle


def decode_worker_report(raw, phase, mode, agent):
    unavailable={'ok':False,'outcomeUnknown':True,'error':'worker_report_unavailable'}
    try:
        value=json.loads(raw)
        if not isinstance(value,dict):return False,unavailable
        expected=('heptabao.mac-five-agent-single-native-worker.r1' if agent is not None
                  else 'heptabao.mac-five-agent-authbus-cycle-and-inverse.r1')
        if (value.get('schema')!=expected or type(value.get('ok')) is not bool
            or type(value.get('outcomeUnknown')) is not bool or value.get('phase')!=phase):
            return False,unavailable
        if agent is not None:
            if mode!='native' or value.get('agentId')!=agent:return False,unavailable
        elif mode not in ('cycle','rollback') or value.get('mode')!=mode:
            return False,unavailable
        checks=value.get('checks')
        if (not isinstance(checks,list) or not 1<=len(checks)<=512
            or any(not isinstance(c,dict) or not isinstance(c.get('case'),str)
                   or not 1<=len(c['case'])<=256 or type(c.get('passed')) is not bool
                   for c in checks)):
            return False,unavailable
        if value['ok'] and (value['outcomeUnknown'] or any(not c['passed'] for c in checks)):
            return False,unavailable
        return True,value
    except Exception:
        return False,unavailable

def volume_before_private_state():
    """Actual diskutil under original 30s and phase120, with anchors already held."""
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
    need(volume_guard is not None,'held_anchors_before_diskutil')
    volume_guard.accept_diskutil(out)
    need(info.get('VolumeUUID')==UUID and info.get('MountPoint')=='/Volumes/T5','exact_t5_before_phase')
    remaining()
    return {'lifecycle':lifecycle,'stdoutSha256':sha(out),'stderrSha256':sha(err),
            'volumeUUID':info['VolumeUUID'],'mountPoint':info['MountPoint']}


def main():
    global volume_guard
    parser=argparse.ArgumentParser()
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--public-volume-anchor-base64',required=True)
    parser.add_argument('--public-volume-anchor-sha256',required=True)
    parser.add_argument('--volume-guard-source-sha256',required=True)
    args=parser.parse_args()
    os.umask(0o077)
    report={'schema':'heptabao.mac-five-agent-phase-owner.r2','ok':False,
      'originalSharedPhaseSeconds':120,'nativeWorkerCount':0,'records':[],
      'productionChanged':False,'providerRequestSent':False,'j3160Contacted':False,
      'realLaunchdQualificationSuppliedByOuterManager':False,'outcomeUnknown':False}
    plan=None;generation=None;published_result=None
    try:
        need(sys.platform=='darwin' and os.getuid()==501,'exact_mac_owner')
        q=ROOT/'qa'
        # Only public, exact source bytes are opened here. No private plan,
        # credential, owned output or ready file precedes the held volume gate.
        guard_module=q/'mac_t5_volume_guard_r1.py'
        need(file_sha(guard_module,1024*1024)==args.volume_guard_source_sha256,
             'exact_public_volume_guard_source')
        sys.path.insert(0,str(q))
        from mac_t5_volume_guard_r1 import HeldT5
        volume_guard=HeldT5(base64.b64decode(args.public_volume_anchor_base64,validate=True),
            args.public_volume_anchor_sha256,remaining,critical)
        report['volumeGuard']=volume_before_private_state()
        with volume_guard.parent(ROOT/'launchd') as (work_fd,_name):
            with critical():os.fchdir(work_fd)
            need(identity(os.stat('.'))==identity(os.fstat(work_fd))
                 and os.getcwd()==str(ROOT),'held_t5_business_working_directory')
        volume_guard.check();report['ownedBusinessWorkingDirectoryHeldT5']=True
        raw=private_read(args.plan);need(sha(raw)==args.plan_sha256,'exact_phase_plan_pin')
        plan=json.loads(raw)
        need(plan['schema']=='heptabao.mac-five-agent-phase-plan.private.r1'
          and plan['phase'] in ('initial','cold-new-process') and plan['mode'] in ('consume','inverse')
          and plan['agentIds']==list(AGENTS) and plan['phaseSeconds']==120,'fixed_phase_contract')
        phase=ROOT/plan['phase'];generation=plan['generation'];report['generation']=generation
        need(generation in ('initial','cold-new-process','initial-inverse','cold-new-process-inverse')
          and generation==plan['phase']+('-inverse' if plan['mode']=='inverse' else ''),
          'unique_phase_generation')
        need(Path(plan['phaseRoot'])==phase and Path(plan['stateRoot'])==phase/'state',
             'independent_initial_cold_state')
        need(str(plan['expectedVolumeDevice'])==volume_guard.expected['expectedVolumeDevice'],
             'phase_device_matches_public_startup_anchor')
        volume_guard.check()
        need(args.plan==ROOT/'launchd'/(generation+'.private.json'),'immutable_manager_phase_plan')
        for name in ('mac_native_process_observer_r1.py',
                     'mac_owned_unreaped_r1.py',
                     'mac_current_phase_owner_r2.py','mac_t5_volume_guard_r1.py',
                     'mac_current_cycle_r2.mjs','mac_single_native_r2.mjs',
                     'mac_auth_rows_cas_r1.mjs','mac_authbus_cache_cas_r1.mjs'):
            need(file_sha(q/name)==plan['qaPins'][name],'reviewed_qa_source.'+name)
        sys.path.insert(0,str(q))
        from mac_native_process_observer_r1 import ProcessReader
        self_identity=ProcessReader().read(os.getpid())
        need(self_identity['uid']==501 and self_identity['executable']==PYTHON_KERNEL_IMAGE
             and str(Path(sys.executable).resolve())==PYTHON_LAUNCHER,
             'real_wrapper_process_identity')
        ready={'schema':'heptabao.mac-phase-wrapper-ready.r1','generation':generation,
               'planSha256':args.plan_sha256,'wrapperIdentity':self_identity,
               'phaseStartMonotonic':START,'originalPhaseDeadlineMonotonic':UNTIL}
        put(ROOT/'launchd'/(generation+'.ready.public.json'),ready)
        # Node/native sandbox rules deny writes to ROOT/launchd. This message
        # therefore comes from the actual manager after it has read launchctl
        # and the wrapper's real process identity; it is not a native ACK.
        admission_path=ROOT/'launchd'/(generation+'.admitted.private.json')
        while not admission_path.exists():
            time.sleep(min(0.025,remaining()))
        admission=json.loads(private_read(admission_path))
        need(admission=={'schema':'heptabao.mac-owned-manager-admission.r1',
          'generation':generation,'planSha256':args.plan_sha256,'wrapperIdentity':self_identity},
          'one_exact_manager_admission_before_credentials')
        remaining()
        env={'PATH':'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
             'HOME':str(phase/'state/home'),'TMPDIR':str(phase/'tmp')}
        volume_guard.check()
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
            executable=q/('mac_single_native_r2.mjs' if agent else 'mac_current_cycle_r2.mjs')
            out=worker_dir/(label+'.stdout.private');err=worker_dir/(label+'.stderr.private')
            child_env=dict(env)
            if agent is not None: child_env['TMPDIR']=worker['nativeTmp']
            life=run_owned_capture(['/usr/bin/sandbox-exec','-f',common['parentSandbox'],
                    NODE,str(executable),str(path)],child_env,phase,UNTIL,out,err,
                    native_observer=None if agent is None else {
                      'nodeExecutable':str(Path(NODE).resolve()),'nativeExecutable':worker['nativeBinary']})
            out_bytes=private_read(out);err_bytes=private_read(err)
            report_available,value=decode_worker_report(out_bytes,plan['phase'],mode,agent)
            record={'name':label,'mode':mode,'agentId':agent,'lifecycle':life,
                    'stdoutSha256':sha(out_bytes),'stderrSha256':sha(err_bytes),
                    'stdoutBytes':len(out_bytes),'stderrBytes':len(err_bytes),'report':value}
            report['records'].append(record)
            owned[-1]['deliveredReport']=report_available
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
            if not close_observer_once(observer):
                report['ok']=False;report['outcomeUnknown']=True
        # Registered but not yet finalized children can occur at a cancellation
        # boundary. The once marker prevents giving any child a second cleanup.
        orphan_cleanup=[]
        for row in owned:
            if row['stopAttempted']:continue
            row['stopAttempted']=True;p=row['process']
            item={'pid':p.pid,'stopAttempted':True}
            try:
                from mac_owned_unreaped_r1 import stop_once_unreaped
                item.update(stop_once_unreaped(p,row.get('custody')))
                row['lifecycle']['primaryReaped']=item.get('directChildReaped') is True
                row['lifecycle']['noGroupSurvivors']=item.get('allGroupRowsEmptyAfterReap') is True
            except BaseException as error:item['cleanupErrorType']=type(error).__name__
            orphan_cleanup.append(item)
            report['ok']=False;report['outcomeUnknown']=True
        report['exceptionBoundaryCleanup']=orphan_cleanup
        if any(row.get('worker') and not row.get('deliveredReport') for row in owned):
            report['ok']=False;report['outcomeUnknown']=True
        report['allObserverClosuresAttemptedOnce']=all(observer_close_results.get(id(o)) is True for o in observers)
        report['allOwnedStopped']=all(row['lifecycle'].get('primaryReaped') is True
          and row['lifecycle'].get('noGroupSurvivors') is True for row in owned)
        if not report['allOwnedStopped'] or time.monotonic()>=UNTIL:report['ok']=False
        report['elapsedSeconds']=time.monotonic()-START
        report['authorityExitZeroAndOriginalPhaseDeadlineRequired']=True
        if volume_guard is not None:
            try:
                volume_guard.check(check_deadline=False)
                report['volumeGuardFinalBeforePublication']=volume_guard.public_state()
            except BaseException:
                report['ok']=False;report['outcomeUnknown']=True
        if plan is not None and generation is not None and volume_guard is not None:
            try:published_result=put(ROOT/'launchd'/(generation+'.result.public.json'),report)
            except BaseException:
                report['ok']=False;report['outcomeUnknown']=True
        if volume_guard is not None:
            volume_guard.close()
            report['volumeGuardClosed']=volume_guard.public_state()
            if (not report['volumeGuardClosed']['allDescriptorsClosed']
                or not report['volumeGuardClosed']['lastAnchorCheckPassed']):
                report['ok']=False;report['outcomeUnknown']=True
        print(json.dumps({'ok':report['ok'],'generation':generation,
          'allOwnedStopped':report['allOwnedStopped'],'outcomeUnknown':report['outcomeUnknown'],
          'elapsedSeconds':time.monotonic()-START,
          'volumeGuardClosed':report.get('volumeGuardClosed'),
          'resultSha256':None if published_result is None else published_result['sha256']},sort_keys=True),flush=True)
    return 0 if report['ok'] and time.monotonic()<UNTIL else 1

if __name__=='__main__':sys.exit(main())
