#!/usr/bin/env python3
"""New public-probe custody adapter using scoped Darwin numeric projection.

The original QA helper remains unchanged. WNOWAIT/direct-Popen retention,
TERM1/wait5/group3 and signal-before-double-observation control flow are
preserved. The schema explicitly replaces ps lstart with second/microsecond
birth fields; this source alone is not actual Darwin runtime qualification.
"""
import os, signal, time
from mac_darwin_owned_projection_r1 import NativeProjection, NativeProjectionRefused, PROJECTION_SCHEMA

_projection=None
class Refusal(RuntimeError): pass
def need(value,code):
    if not value:raise Refusal(code)

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
    # bound independently by the native projection; si_uid never grants ownership here.
    return {"pid": event.si_pid, "signo": event.si_signo, "code": event.si_code, "status": event.si_status}

def stable(row):
    return {key: row[key] for key in ("pid", "ppid", "pgid", "uid", "birthSeconds", "birthMicroseconds")}

def bind_projection(api):
    global _projection
    need(_projection is None and type(api) is NativeProjection and api.self_qualified,
         "native_projection_once_actual_self_qualification")
    _projection=api

def native_rows(pid=None, *, pgid=None, seconds=4.0, until=None):
    need(_projection is not None and _projection.self_qualified,
         "native_projection_not_qualified")
    need(until is not None and type(seconds) in (int,float) and 0<seconds<=4.0,
         "native_projection_original_bound")
    remaining=until-time.monotonic()
    need(remaining>0,"original_stop_deadline_expired")
    end=min(until,time.monotonic()+seconds)
    need((pid is None)!=(pgid is None),"scoped_pid_or_pgid_required")
    try:
        rows=([_projection.pid_row(pid,until=end)] if pid is not None
              else _projection.group_rows(pgid,until=end))
    except NativeProjectionRefused as error:
        code=error.code
        if code=="original_projection_deadline_expired":
            code=("original_stop_deadline_expired" if time.monotonic()>=until
                  else "process_projection_deadline_expired")
        raise Refusal(code) from error
    need(time.monotonic()<end,"original_stop_deadline_expired")
    return rows

def capture_child(child, *, until):
    require_waitid()
    rows = native_rows(child.pid, until=until)
    need(len(rows) == 1, "owned_child_identity_missing")
    row = rows[0]
    need(row["ppid"] == os.getpid() and row["pgid"] == child.pid
         and row["uid"] == os.geteuid(), "owned_child_scope_mismatch")
    # Darwin keeps an unreaped zombie in the native arg=1 projection but getpgid/getsid return ESRCH.
    # Use the real live APIs only for a still-live child; otherwise independently
    # repeat WNOWAIT and retain native birth plus Popen direct-parent custody.
    event, live_sid = exit_observation(child), None
    if event is None and not row["isZombie"]:
        try:
            need(os.getpgid(child.pid) == child.pid and os.getsid(child.pid) == child.pid,
                 "owned_live_session_mismatch")
            live_sid = child.pid
        except ProcessLookupError:
            # A fast exit between the first native projection/waitid and a live API call is
            # not loss of Popen custody, nor proof that the group is empty.
            event = exit_observation(child)
            need(event is not None, "owned_live_api_failed_without_retained_exit")
    if event is not None or row["isZombie"]:
        event = exit_observation(child)
        fresh = native_rows(child.pid, until=until)
        need(event is not None and len(fresh) == 1 and stable(fresh[0]) == stable(row)
             and fresh[0]["isZombie"] and exit_observation(child) == event,
             "owned_exit_not_retained")
        row = fresh[0]
    return {"projection": stable(row), "projectionSchema": PROJECTION_SCHEMA,
            "sid_observed_while_live": live_sid,"captured_exit": event}

def verify_unreaped(child, owner, *, until=None):
    event = exit_observation(child)
    rows = native_rows(child.pid, until=until)
    need(len(rows) == 1 and stable(rows[0]) == owner["projection"]
         and rows[0]["ppid"] == os.getpid(), "owned_child_identity_changed_no_signal")
    if event is None and not rows[0]["isZombie"]:
        # Exact native PGID/birth plus direct Popen/WNOWAIT custody keeps the
        # originally observed session leader reserved. Do not race a normal
        # exit by consulting Darwin's zombie-unsupported getpgid/getsid here.
        need(owner["projection"]["pgid"] == child.pid, "owned_live_session_changed_no_signal")
    else:
        event = exit_observation(child)
        need(event is not None and rows[0]["isZombie"] and exit_observation(child) == event,
             "owned_zombie_identity_changed_no_signal")
    return event

def live_group(child, owner, *, until):
    need(time.monotonic() < until, "original_stop_deadline_expired")
    verify_unreaped(child, owner, until=until)
    rows = native_rows(pgid=child.pid, until=until)
    selected = [row for row in rows if row["pgid"] == child.pid and not row["isZombie"]]
    need(all(row["uid"] == os.geteuid() for row in selected), "owned_group_uid_changed_no_signal")
    need(time.monotonic() < until, "original_stop_deadline_expired")
    return [stable(row) for row in selected]

def observed_returncode(event):
    if event is None:return None
    return event['status'] if event['code']==os.CLD_EXITED else -event['status']

def stop_once_unreaped(child, owner):
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
            owner=capture_child(child,until=term_until)
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
            rows=[row for row in native_rows(pgid=child.pid,until=group_until) if row['pgid']==child.pid]
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
