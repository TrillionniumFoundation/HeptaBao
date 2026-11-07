#!/usr/bin/env python3
"""Retained direct-child custody for Mac phase workers.

Derived from canonical native_ha_foreground_watchdog.py 74925449. No child is
started here. WNOWAIT observes exit; it never makes the numeric PGID reusable
before signaling. Cleanup keeps the previous wrapper's TERM1 / wait5 /
group3 limits and PS4 maximum. No stage grants business more than phase120.
"""
import hashlib, os, signal, stat, subprocess, time

MIB=1024*1024
class Refusal(RuntimeError): pass
def need(value,code):
    if not value:raise Refusal(code)

# Only this observed system helper may cross effective UID at exec. No target
# service, arbitrary argv, descendant, or unrelated command gets this exception.
FIXED_PS_ARGV=('/bin/ps','-axo','pid=,ppid=,pgid=,uid=,stat=')
FIXED_PS_SHA256='3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c'
FIXED_PS_BYTES=170432
FIXED_PS_IDENTITY=(16777233,1152921500312571399,0,0,35309,1,170432,
    1786589515000000000,1786589515000000000)

def fixed_ps_identity(value):
    return tuple(getattr(value,name) for name in ('st_dev','st_ino','st_uid','st_gid',
        'st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def fixed_ps_pin(*,until):
    need(os.getuid()==501 and os.geteuid()==501,'fixed_ps_requires_exact_caller')
    need(time.monotonic()<until,'original_command_deadline_exhausted')
    path=FIXED_PS_ARGV[0]
    before=os.lstat(path)
    need(fixed_ps_identity(before)==FIXED_PS_IDENTITY and stat.S_ISREG(before.st_mode)
         and stat.S_IMODE(before.st_mode)==0o4755,'fixed_ps_system_file_identity')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(fixed_ps_identity(os.fstat(fd))==FIXED_PS_IDENTITY,'fixed_ps_open_file_identity')
        raw=bytearray()
        while len(raw)<=FIXED_PS_BYTES:
            need(time.monotonic()<until,'original_command_deadline_exhausted')
            part=os.read(fd,min(65536,FIXED_PS_BYTES+1-len(raw)))
            if not part:break
            raw.extend(part)
        need(len(raw)==FIXED_PS_BYTES and hashlib.sha256(raw).hexdigest()==FIXED_PS_SHA256,
             'fixed_ps_whole_file_hash')
        need(fixed_ps_identity(os.fstat(fd))==fixed_ps_identity(os.lstat(path))==FIXED_PS_IDENTITY,
             'fixed_ps_named_file_unchanged')
        need(time.monotonic()<until,'original_command_deadline_exhausted')
        return {'identity':list(FIXED_PS_IDENTITY),'sha256':FIXED_PS_SHA256}
    finally:
        os.close(fd)

def prepare_fixed_ps_contract(argv,*,until):
    if not argv or argv[0]!=FIXED_PS_ARGV[0]:return None
    need(tuple(argv)==FIXED_PS_ARGV,'fixed_ps_exact_argv_before_launch')
    return {'schema':'heptabao.fixed-system-ps-child.r1','argv':list(FIXED_PS_ARGV),
        'launcherPid':os.getpid(),'callerUid':501,'pin':fixed_ps_pin(until=until)}

def verify_fixed_ps_contract(child,contract,*,until):
    need(isinstance(contract,dict) and set(contract)=={'schema','argv','launcherPid','callerUid','pin'}
         and contract['schema']=='heptabao.fixed-system-ps-child.r1'
         and contract['argv']==list(FIXED_PS_ARGV)
         and tuple(child.args)==FIXED_PS_ARGV
         and contract['launcherPid']==os.getpid() and contract['callerUid']==501
         and child.returncode is None and type(child.pid) is int and child.pid>1,
         'fixed_ps_direct_child_contract')
    need(contract['pin']==fixed_ps_pin(until=until),'fixed_ps_prelaunch_binding_changed')
    return True

def fixed_ps_group_uid(row,child,owner):
    if owner.get('fixedPsContract') is None:return row['uid']==os.geteuid()
    return row['pid']==child.pid and stable(row)==owner['ps'] and row['uid']==0

def require_waitid():
    need(all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT",
                                          "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED")),
         "wnowait_required_no_child_started")
    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
         "direct_child_reaping_policy_changed")

def exit_observation(child):
    """This is an observation, never Popen.poll/wait/communicate."""
    need(child.returncode is None, "child_already_reaped_no_signal")
    event = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if event is None:
        return None
    need(event.si_pid == child.pid and event.si_signo == signal.SIGCHLD
         and event.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED),
         "child_exit_identity_changed")
    # Darwin reports si_uid=0 even for an observed uid501 child. Actual UID is
    # bound independently by ps; si_uid never grants ownership here.
    return {"pid": event.si_pid, "signo": event.si_signo, "code": event.si_code, "status": event.si_status}

def stable(row):
    return {key: row[key] for key in ("pid", "ppid", "pgid", "uid", "start")}

def ps_rows(pid=None, *, seconds=4.0, until=None):
    if until is not None:
        remaining = until - time.monotonic()
        need(remaining > 0, "original_stop_deadline_expired")
        seconds = min(seconds, remaining)
    argv = ["/bin/ps"]
    argv += ["-p", str(pid)] if pid is not None else ["-ax"]
    argv += ["-o", "pid=,ppid=,pgid=,uid=,stat=,lstart="]
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C"),
                                timeout=seconds)
    except subprocess.TimeoutExpired as error:
        code = ("original_stop_deadline_expired" if until is not None and time.monotonic() >= until
                else "process_projection_deadline_expired")
        raise Refusal(code) from error
    if until is not None:
        need(time.monotonic() < until, "original_stop_deadline_expired")
    need(len(result.stdout) <= 2 * MIB and len(result.stderr) <= 65536,
         "process_projection_bound")
    if pid is not None and result.returncode == 1 and not result.stdout.strip():
        return []
    need(result.returncode == 0, "process_projection_unavailable")
    rows = []
    for line in result.stdout.decode("ascii").splitlines():
        fields = line.split(None, 5)
        need(len(fields) == 6, "process_projection_malformed")
        rows.append({"pid": int(fields[0]), "ppid": int(fields[1]),
                     "pgid": int(fields[2]), "uid": int(fields[3]),
                     "state": fields[4], "start": fields[5]})
    if pid is not None:
        need(len(rows) == 1 and rows[0]["pid"] == pid, "process_projection_ambiguous")
    return rows

def capture_child(child, *, until, fixed_ps_contract=None):
    require_waitid()
    rows = ps_rows(child.pid, until=until)
    need(len(rows) == 1, "owned_child_identity_missing")
    row = rows[0]
    special=fixed_ps_contract is not None
    if special:verify_fixed_ps_contract(child,fixed_ps_contract,until=until)
    need(row["ppid"] == os.getpid() and row["pgid"] == child.pid
         and row["uid"] == (0 if special else os.geteuid()), "owned_child_scope_mismatch")
    # Darwin keeps an unreaped zombie in ps but getpgid/getsid return ESRCH.
    # Use the real live APIs only for a still-live child; otherwise independently
    # repeat WNOWAIT and retain ps plus Popen direct-parent custody.
    event, live_sid = exit_observation(child), None
    if event is None and not row["state"].startswith("Z"):
        try:
            need(os.getpgid(child.pid) == child.pid and os.getsid(child.pid) == child.pid,
                 "owned_live_session_mismatch")
            live_sid = child.pid
        except ProcessLookupError:
            # A fast exit between the first ps/waitid and a live API call is
            # not loss of Popen custody, nor proof that the group is empty.
            event = exit_observation(child)
            need(event is not None, "owned_live_api_failed_without_retained_exit")
    if event is not None or row["state"].startswith("Z"):
        event = exit_observation(child)
        fresh = ps_rows(child.pid, until=until)
        need(event is not None and len(fresh) == 1 and stable(fresh[0]) == stable(row)
             and fresh[0]["state"].startswith("Z") and exit_observation(child) == event,
             "owned_exit_not_retained")
        row = fresh[0]
    return {"ps": stable(row), "sid_observed_while_live": live_sid,
            "captured_exit": event,"fixedPsContract":fixed_ps_contract}

def verify_unreaped(child, owner, *, until=None):
    if owner.get('fixedPsContract') is not None:
        need(until is not None,'fixed_ps_requires_existing_deadline')
        verify_fixed_ps_contract(child,owner['fixedPsContract'],until=until)
    event = exit_observation(child)
    rows = ps_rows(child.pid, until=until)
    need(len(rows) == 1 and stable(rows[0]) == owner["ps"]
         and rows[0]["ppid"] == os.getpid(), "owned_child_identity_changed_no_signal")
    if event is None and not rows[0]["state"].startswith("Z"):
        # Exact ps PGID/start plus direct Popen/WNOWAIT custody keeps the
        # originally observed session leader reserved. Do not race a normal
        # exit by consulting Darwin's zombie-unsupported getpgid/getsid here.
        need(owner["ps"]["pgid"] == child.pid, "owned_live_session_changed_no_signal")
    else:
        event = exit_observation(child)
        need(event is not None and rows[0]["state"].startswith("Z") and exit_observation(child) == event,
             "owned_zombie_identity_changed_no_signal")
    return event

def live_group(child, owner, *, until):
    need(time.monotonic() < until, "original_stop_deadline_expired")
    verify_unreaped(child, owner, until=until)
    rows = ps_rows(until=until)
    if owner.get("fixedPsContract") is not None:
        related=[row for row in rows if row["pgid"]==child.pid or row["ppid"]==child.pid]
        need(all(row["pid"]==child.pid and stable(row)==owner["ps"] for row in related),
             "fixed_ps_no_other_group_or_direct_child")
    selected = [row for row in rows if row["pgid"] == child.pid and not row["state"].startswith("Z")]
    need(all(fixed_ps_group_uid(row,child,owner) for row in selected), "owned_group_uid_changed_no_signal")
    need(time.monotonic() < until, "original_stop_deadline_expired")
    return [stable(row) for row in selected]

def observed_returncode(event):
    if event is None:return None
    return event['status'] if event['code']==os.CLD_EXITED else -event['status']

def stop_once_unreaped(child, owner, *, fixed_ps_contract=None):
    """Called once by the wrapper's protected ledger; never calls Popen.poll."""
    require_waitid()
    started=time.monotonic()
    receipt={'pid':child.pid,'pgid':child.pid,'stopAttempted':True,'signals':[],
             'directChildReaped':False,'ownedLiveGroupEmptyBeforeReap':False,
             'allGroupRowsEmptyAfterReap':False,'cleanupCaps':{'term':1,'wait':5,'group':3,'psMax':4},
             'postReapSignalSent':False,'custody':owner}
    try:
        need(child.returncode is None,'already_reaped_no_group_signal')
        term_until=time.monotonic()+1.0
        if owner is None:
            owner=capture_child(child,until=term_until,fixed_ps_contract=fixed_ps_contract)
            receipt['custody']=owner
        members=live_group(child,owner,until=term_until)
        receipt['initialLiveGroup']=members
        if members:
            verify_unreaped(child,owner,until=term_until)
            need(time.monotonic()<term_until,'original_stop_deadline_expired')
            os.killpg(child.pid,signal.SIGTERM);receipt['signals'].append('SIGTERM')
            while time.monotonic()<term_until:
                try:
                    members=live_group(child,owner,until=term_until)
                    if not members:break
                except Refusal as error:
                    if str(error)!='original_stop_deadline_expired' or time.monotonic()<term_until:
                        raise
                    break
                time.sleep(min(0.02,max(0,term_until-time.monotonic())))
        wait_until=time.monotonic()+5.0
        members=live_group(child,owner,until=wait_until)
        if members:
            verify_unreaped(child,owner,until=wait_until)
            need(time.monotonic()<wait_until,'original_stop_deadline_expired')
            os.killpg(child.pid,signal.SIGKILL);receipt['signals'].append('SIGKILL')
        event=exit_observation(child)
        while event is None:
            verify_unreaped(child,owner,until=wait_until)
            need(time.monotonic()<wait_until,'original_stop_deadline_expired')
            time.sleep(min(0.02,max(0,wait_until-time.monotonic())))
            event=exit_observation(child)
        need(time.monotonic()<wait_until,'original_stop_deadline_expired')
        receipt['retainedExit']=event
        # The old post-exit group3 interval now precedes the first reap.
        # This retains actual Popen PID custody while other live members leave.
        group_until=time.monotonic()+3.0
        while True:
            members=live_group(child,owner,until=group_until)
            if not members and exit_observation(child)==event:break
            need(time.monotonic()<group_until,'original_stop_deadline_expired')
            time.sleep(min(0.02,max(0,group_until-time.monotonic())))
        receipt['ownedLiveGroupEmptyBeforeReap']=True
        need(time.monotonic()<group_until,'original_stop_deadline_expired')
        child.wait(timeout=group_until-time.monotonic())
        receipt['directChildReaped']=True
        receipt['exitCode']=child.returncode
        need(child.returncode==observed_returncode(event),'actual_reap_matches_retained_exit')
        # After the first reap, only observe. No signal or ownership claim is
        # derived from this now-reusable numeric PGID.
        while True:
            rows=[row for row in ps_rows(until=group_until) if row['pgid']==child.pid]
            receipt['remainingGroupRows']=rows
            if not rows:break
            need(time.monotonic()<group_until,'original_stop_deadline_expired')
            time.sleep(min(0.02,max(0,group_until-time.monotonic())))
        receipt['allGroupRowsEmptyAfterReap']=True
        need(time.monotonic()<group_until,'original_stop_deadline_expired')
        receipt['ok']=True
    except BaseException as error:
        receipt['ok']=False
        receipt['errorType']=type(error).__name__
        receipt['errorCode']=str(error) if isinstance(error,Refusal) else None
        receipt['directChildReaped']=child.returncode is not None
        receipt['exitCode']=child.returncode
        # No second signal sequence, no renewed deadline, no automatic retry.
    receipt['elapsedSeconds']=time.monotonic()-started
    receipt['outcomeUnknown']=not(receipt.get('ok') is True
       and receipt['directChildReaped'] and receipt['allGroupRowsEmptyAfterReap'])
    return receipt
