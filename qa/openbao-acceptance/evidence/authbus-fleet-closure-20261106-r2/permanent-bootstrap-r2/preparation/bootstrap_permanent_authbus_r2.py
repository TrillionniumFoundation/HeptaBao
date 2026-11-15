#!/usr/bin/env python3
"""Initialize the new independent service once, prove its cold lifecycle, stop.

No installed service, current credential, provider, legacy service or client is
opened. Every actual API response is retained privately before parsing. A failed
or unknown request prevents the next phase; this program never retries it.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
import types

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-authbus-production')
CALLER_HOME = Path('/Users/qianqi')
CUSTODY = CALLER_HOME / 'heptabao-authbus-production-custody'
OPERATIONS = CUSTODY / 'bootstrap-r2'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
PRODUCT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
BINARY = ROOT / 'releases' / PRODUCT / 'heptabao-server'
BINARY_BYTES = 92359328
BINARY_SHA = '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
CA_SHA = '456ea07b02ead7ac3397507a4e41befeaad822dcdd74695f6a38239029aac01f'
LEAF_SHA = 'abaf8527105e19cbbe0da57a64c7a87d8e7f6e6ae15edc3636f5eee65eefd3bd'
PORT = 31080
CONFIG = ROOT / 'etc/server-bootstrap-r2.json'
ROLE = 'bootstrap-lifecycle-r1'
SECRET_PATH = '/v1/openclaw-auth/data/qualification/bootstrap-lifecycle-r1'
TOOL_PINS = {
    str(PYTHON): (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'),
    '/usr/sbin/diskutil': (1937776, '624a8601b97ddfaa4b18dd2854c299e084cd45eb18fc152011c97615c3b9da1f'),
    '/bin/ps': (170432, '3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c'),
}
PAYLOAD = {'sources': {'mac_owned_unreaped_r1.py': '#!/usr/bin/env python3\n"""Retained direct-child custody for Mac phase workers.\n\nDerived from canonical native_ha_foreground_watchdog.py 74925449. No child is\nstarted here. WNOWAIT observes exit; it never makes the numeric PGID reusable\nbefore signaling. Cleanup keeps the previous wrapper\'s TERM1 / wait5 /\ngroup3 limits and PS4 maximum. No stage grants business more than phase120.\n"""\nimport hashlib, os, signal, stat, subprocess, time\n\nMIB=1024*1024\nclass Refusal(RuntimeError): pass\ndef need(value,code):\n    if not value:raise Refusal(code)\n\n# Only this observed system helper may cross effective UID at exec. No target\n# service, arbitrary argv, descendant, or unrelated command gets this exception.\nFIXED_PS_ARGV=(\'/bin/ps\',\'-axo\',\'pid=,ppid=,pgid=,uid=,stat=\')\nFIXED_PS_SHA256=\'3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c\'\nFIXED_PS_BYTES=170432\nFIXED_PS_IDENTITY=(16777233,1152921500312571399,0,0,35309,1,170432,\n    1786589515000000000,1786589515000000000)\n\ndef fixed_ps_identity(value):\n    return tuple(getattr(value,name) for name in (\'st_dev\',\'st_ino\',\'st_uid\',\'st_gid\',\n        \'st_mode\',\'st_nlink\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\'))\n\ndef fixed_ps_pin(*,until):\n    need(os.getuid()==501 and os.geteuid()==501,\'fixed_ps_requires_exact_caller\')\n    need(time.monotonic()<until,\'original_command_deadline_exhausted\')\n    path=FIXED_PS_ARGV[0]\n    before=os.lstat(path)\n    need(fixed_ps_identity(before)==FIXED_PS_IDENTITY and stat.S_ISREG(before.st_mode)\n         and stat.S_IMODE(before.st_mode)==0o4755,\'fixed_ps_system_file_identity\')\n    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)\n    try:\n        need(fixed_ps_identity(os.fstat(fd))==FIXED_PS_IDENTITY,\'fixed_ps_open_file_identity\')\n        raw=bytearray()\n        while len(raw)<=FIXED_PS_BYTES:\n            need(time.monotonic()<until,\'original_command_deadline_exhausted\')\n            part=os.read(fd,min(65536,FIXED_PS_BYTES+1-len(raw)))\n            if not part:break\n            raw.extend(part)\n        need(len(raw)==FIXED_PS_BYTES and hashlib.sha256(raw).hexdigest()==FIXED_PS_SHA256,\n             \'fixed_ps_whole_file_hash\')\n        need(fixed_ps_identity(os.fstat(fd))==fixed_ps_identity(os.lstat(path))==FIXED_PS_IDENTITY,\n             \'fixed_ps_named_file_unchanged\')\n        need(time.monotonic()<until,\'original_command_deadline_exhausted\')\n        return {\'identity\':list(FIXED_PS_IDENTITY),\'sha256\':FIXED_PS_SHA256}\n    finally:\n        os.close(fd)\n\ndef prepare_fixed_ps_contract(argv,*,until):\n    if not argv or argv[0]!=FIXED_PS_ARGV[0]:return None\n    need(tuple(argv)==FIXED_PS_ARGV,\'fixed_ps_exact_argv_before_launch\')\n    return {\'schema\':\'heptabao.fixed-system-ps-child.r1\',\'argv\':list(FIXED_PS_ARGV),\n        \'launcherPid\':os.getpid(),\'callerUid\':501,\'pin\':fixed_ps_pin(until=until)}\n\ndef verify_fixed_ps_contract(child,contract,*,until):\n    need(isinstance(contract,dict) and set(contract)=={\'schema\',\'argv\',\'launcherPid\',\'callerUid\',\'pin\'}\n         and contract[\'schema\']==\'heptabao.fixed-system-ps-child.r1\'\n         and contract[\'argv\']==list(FIXED_PS_ARGV)\n         and tuple(child.args)==FIXED_PS_ARGV\n         and contract[\'launcherPid\']==os.getpid() and contract[\'callerUid\']==501\n         and child.returncode is None and type(child.pid) is int and child.pid>1,\n         \'fixed_ps_direct_child_contract\')\n    need(contract[\'pin\']==fixed_ps_pin(until=until),\'fixed_ps_prelaunch_binding_changed\')\n    return True\n\ndef fixed_ps_group_uid(row,child,owner):\n    if owner.get(\'fixedPsContract\') is None:return row[\'uid\']==os.geteuid()\n    return row[\'pid\']==child.pid and stable(row)==owner[\'ps\'] and row[\'uid\']==0\n\ndef require_waitid():\n    need(all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT",\n                                          "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED")),\n         "wnowait_required_no_child_started")\n    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,\n         "direct_child_reaping_policy_changed")\n\ndef exit_observation(child):\n    """This is an observation, never Popen.poll/wait/communicate."""\n    need(child.returncode is None, "child_already_reaped_no_signal")\n    event = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)\n    if event is None:\n        return None\n    need(event.si_pid == child.pid and event.si_signo == signal.SIGCHLD\n         and event.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED),\n         "child_exit_identity_changed")\n    # Darwin reports si_uid=0 even for an observed uid501 child. Actual UID is\n    # bound independently by ps; si_uid never grants ownership here.\n    return {"pid": event.si_pid, "signo": event.si_signo, "code": event.si_code, "status": event.si_status}\n\ndef stable(row):\n    return {key: row[key] for key in ("pid", "ppid", "pgid", "uid", "start")}\n\ndef ps_rows(pid=None, *, seconds=4.0, until=None):\n    if until is not None:\n        remaining = until - time.monotonic()\n        need(remaining > 0, "original_stop_deadline_expired")\n        seconds = min(seconds, remaining)\n    argv = ["/bin/ps"]\n    argv += ["-p", str(pid)] if pid is not None else ["-ax"]\n    argv += ["-o", "pid=,ppid=,pgid=,uid=,stat=,lstart="]\n    try:\n        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,\n                                stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C"),\n                                timeout=seconds)\n    except subprocess.TimeoutExpired as error:\n        code = ("original_stop_deadline_expired" if until is not None and time.monotonic() >= until\n                else "process_projection_deadline_expired")\n        raise Refusal(code) from error\n    if until is not None:\n        need(time.monotonic() < until, "original_stop_deadline_expired")\n    need(len(result.stdout) <= 2 * MIB and len(result.stderr) <= 65536,\n         "process_projection_bound")\n    if pid is not None and result.returncode == 1 and not result.stdout.strip():\n        return []\n    need(result.returncode == 0, "process_projection_unavailable")\n    rows = []\n    for line in result.stdout.decode("ascii").splitlines():\n        fields = line.split(None, 5)\n        need(len(fields) == 6, "process_projection_malformed")\n        rows.append({"pid": int(fields[0]), "ppid": int(fields[1]),\n                     "pgid": int(fields[2]), "uid": int(fields[3]),\n                     "state": fields[4], "start": fields[5]})\n    if pid is not None:\n        need(len(rows) == 1 and rows[0]["pid"] == pid, "process_projection_ambiguous")\n    return rows\n\ndef capture_child(child, *, until, fixed_ps_contract=None):\n    require_waitid()\n    rows = ps_rows(child.pid, until=until)\n    need(len(rows) == 1, "owned_child_identity_missing")\n    row = rows[0]\n    special=fixed_ps_contract is not None\n    if special:verify_fixed_ps_contract(child,fixed_ps_contract,until=until)\n    need(row["ppid"] == os.getpid() and row["pgid"] == child.pid\n         and row["uid"] == (0 if special else os.geteuid()), "owned_child_scope_mismatch")\n    # Darwin keeps an unreaped zombie in ps but getpgid/getsid return ESRCH.\n    # Use the real live APIs only for a still-live child; otherwise independently\n    # repeat WNOWAIT and retain ps plus Popen direct-parent custody.\n    event, live_sid = exit_observation(child), None\n    if event is None and not row["state"].startswith("Z"):\n        try:\n            need(os.getpgid(child.pid) == child.pid and os.getsid(child.pid) == child.pid,\n                 "owned_live_session_mismatch")\n            live_sid = child.pid\n        except ProcessLookupError:\n            # A fast exit between the first ps/waitid and a live API call is\n            # not loss of Popen custody, nor proof that the group is empty.\n            event = exit_observation(child)\n            need(event is not None, "owned_live_api_failed_without_retained_exit")\n    if event is not None or row["state"].startswith("Z"):\n        event = exit_observation(child)\n        fresh = ps_rows(child.pid, until=until)\n        need(event is not None and len(fresh) == 1 and stable(fresh[0]) == stable(row)\n             and fresh[0]["state"].startswith("Z") and exit_observation(child) == event,\n             "owned_exit_not_retained")\n        row = fresh[0]\n    return {"ps": stable(row), "sid_observed_while_live": live_sid,\n            "captured_exit": event,"fixedPsContract":fixed_ps_contract}\n\ndef verify_unreaped(child, owner, *, until=None):\n    if owner.get(\'fixedPsContract\') is not None:\n        need(until is not None,\'fixed_ps_requires_existing_deadline\')\n        verify_fixed_ps_contract(child,owner[\'fixedPsContract\'],until=until)\n    event = exit_observation(child)\n    rows = ps_rows(child.pid, until=until)\n    need(len(rows) == 1 and stable(rows[0]) == owner["ps"]\n         and rows[0]["ppid"] == os.getpid(), "owned_child_identity_changed_no_signal")\n    if event is None and not rows[0]["state"].startswith("Z"):\n        # Exact ps PGID/start plus direct Popen/WNOWAIT custody keeps the\n        # originally observed session leader reserved. Do not race a normal\n        # exit by consulting Darwin\'s zombie-unsupported getpgid/getsid here.\n        need(owner["ps"]["pgid"] == child.pid, "owned_live_session_changed_no_signal")\n    else:\n        event = exit_observation(child)\n        need(event is not None and rows[0]["state"].startswith("Z") and exit_observation(child) == event,\n             "owned_zombie_identity_changed_no_signal")\n    return event\n\ndef live_group(child, owner, *, until):\n    need(time.monotonic() < until, "original_stop_deadline_expired")\n    verify_unreaped(child, owner, until=until)\n    rows = ps_rows(until=until)\n    if owner.get("fixedPsContract") is not None:\n        related=[row for row in rows if row["pgid"]==child.pid or row["ppid"]==child.pid]\n        need(all(row["pid"]==child.pid and stable(row)==owner["ps"] for row in related),\n             "fixed_ps_no_other_group_or_direct_child")\n    selected = [row for row in rows if row["pgid"] == child.pid and not row["state"].startswith("Z")]\n    need(all(fixed_ps_group_uid(row,child,owner) for row in selected), "owned_group_uid_changed_no_signal")\n    need(time.monotonic() < until, "original_stop_deadline_expired")\n    return [stable(row) for row in selected]\n\ndef observed_returncode(event):\n    if event is None:return None\n    return event[\'status\'] if event[\'code\']==os.CLD_EXITED else -event[\'status\']\n\ndef stop_once_unreaped(child, owner, *, fixed_ps_contract=None):\n    """Called once by the wrapper\'s protected ledger; never calls Popen.poll."""\n    require_waitid()\n    started=time.monotonic()\n    receipt={\'pid\':child.pid,\'pgid\':child.pid,\'stopAttempted\':True,\'signals\':[],\n             \'directChildReaped\':False,\'ownedLiveGroupEmptyBeforeReap\':False,\n             \'allGroupRowsEmptyAfterReap\':False,\'cleanupCaps\':{\'term\':1,\'wait\':5,\'group\':3,\'psMax\':4},\n             \'postReapSignalSent\':False,\'custody\':owner}\n    try:\n        need(child.returncode is None,\'already_reaped_no_group_signal\')\n        term_until=time.monotonic()+1.0\n        if owner is None:\n            owner=capture_child(child,until=term_until,fixed_ps_contract=fixed_ps_contract)\n            receipt[\'custody\']=owner\n        members=live_group(child,owner,until=term_until)\n        receipt[\'initialLiveGroup\']=members\n        if members:\n            verify_unreaped(child,owner,until=term_until)\n            need(time.monotonic()<term_until,\'original_stop_deadline_expired\')\n            os.killpg(child.pid,signal.SIGTERM);receipt[\'signals\'].append(\'SIGTERM\')\n            while time.monotonic()<term_until:\n                try:\n                    members=live_group(child,owner,until=term_until)\n                    if not members:break\n                except Refusal as error:\n                    if str(error)!=\'original_stop_deadline_expired\' or time.monotonic()<term_until:\n                        raise\n                    break\n                time.sleep(min(0.02,max(0,term_until-time.monotonic())))\n        wait_until=time.monotonic()+5.0\n        members=live_group(child,owner,until=wait_until)\n        if members:\n            verify_unreaped(child,owner,until=wait_until)\n            need(time.monotonic()<wait_until,\'original_stop_deadline_expired\')\n            os.killpg(child.pid,signal.SIGKILL);receipt[\'signals\'].append(\'SIGKILL\')\n        event=exit_observation(child)\n        while event is None:\n            verify_unreaped(child,owner,until=wait_until)\n            need(time.monotonic()<wait_until,\'original_stop_deadline_expired\')\n            time.sleep(min(0.02,max(0,wait_until-time.monotonic())))\n            event=exit_observation(child)\n        need(time.monotonic()<wait_until,\'original_stop_deadline_expired\')\n        receipt[\'retainedExit\']=event\n        # The old post-exit group3 interval now precedes the first reap.\n        # This retains actual Popen PID custody while other live members leave.\n        group_until=time.monotonic()+3.0\n        while True:\n            members=live_group(child,owner,until=group_until)\n            if not members and exit_observation(child)==event:break\n            need(time.monotonic()<group_until,\'original_stop_deadline_expired\')\n            time.sleep(min(0.02,max(0,group_until-time.monotonic())))\n        receipt[\'ownedLiveGroupEmptyBeforeReap\']=True\n        need(time.monotonic()<group_until,\'original_stop_deadline_expired\')\n        child.wait(timeout=group_until-time.monotonic())\n        receipt[\'directChildReaped\']=True\n        receipt[\'exitCode\']=child.returncode\n        need(child.returncode==observed_returncode(event),\'actual_reap_matches_retained_exit\')\n        # After the first reap, only observe. No signal or ownership claim is\n        # derived from this now-reusable numeric PGID.\n        while True:\n            rows=[row for row in ps_rows(until=group_until) if row[\'pgid\']==child.pid]\n            receipt[\'remainingGroupRows\']=rows\n            if not rows:break\n            need(time.monotonic()<group_until,\'original_stop_deadline_expired\')\n            time.sleep(min(0.02,max(0,group_until-time.monotonic())))\n        receipt[\'allGroupRowsEmptyAfterReap\']=True\n        need(time.monotonic()<group_until,\'original_stop_deadline_expired\')\n        receipt[\'ok\']=True\n    except BaseException as error:\n        receipt[\'ok\']=False\n        receipt[\'errorType\']=type(error).__name__\n        receipt[\'errorCode\']=str(error) if isinstance(error,Refusal) else None\n        receipt[\'directChildReaped\']=child.returncode is not None\n        receipt[\'exitCode\']=child.returncode\n        # No second signal sequence, no renewed deadline, no automatic retry.\n    receipt[\'elapsedSeconds\']=time.monotonic()-started\n    receipt[\'outcomeUnknown\']=not(receipt.get(\'ok\') is True\n       and receipt[\'directChildReaped\'] and receipt[\'allGroupRowsEmptyAfterReap\'])\n    return receipt\n', 'mac_owned_commands_r1.py': '#!/usr/bin/env python3\n"""Bounded foreground commands with retained direct-child custody.\n\nNo import-time I/O. The caller supplies exact reviewed argv and an absolute\ncommand deadline. Pipe reads, exit observation and metadata capture share it.\nCleanup uses the separate once-only TERM1/wait5/group3 custody contract.\n"""\nfrom __future__ import annotations\nfrom contextlib import contextmanager\nimport hashlib, os, select, signal, subprocess, time\nfrom mac_owned_unreaped_r1 import require_waitid, capture_child, exit_observation, observed_returncode, stop_once_unreaped, prepare_fixed_ps_contract\n\nclass CommandRefused(RuntimeError):pass\ndef need(value,code):\n    if not value:raise CommandRefused(code)\ndef sha(raw):return hashlib.sha256(raw).hexdigest()\n\nclass Signals:\n    def __init__(self):\n        self.protected=0;self.pending=None\n    def receive(self,signum,_frame):\n        self.pending=signum\n        if not self.protected:raise KeyboardInterrupt()\n    def install(self):\n        signal.signal(signal.SIGTERM,self.receive);signal.signal(signal.SIGINT,self.receive)\n    @contextmanager\n    def critical(self):\n        self.protected+=1\n        try:yield\n        finally:self.protected-=1\n\nclass Commands:\n    def __init__(self,signals):\n        self.signals=signals;self.rows=[]\n    def run(self,label,argv,*,until,allow_cancelled_cleanup=False,maximum=2*1024*1024):\n        need(isinstance(label,str) and label.replace(\'-\',\'\').replace(\'_\',\'\').isalnum(),\'safe_command_label\')\n        need(type(maximum) is int and 0<maximum<=2*1024*1024,\'fixed_command_output_bound\')\n        need(isinstance(argv,list) and argv and all(isinstance(x,str) for x in argv),\'explicit_argv\')\n        def remaining():\n            if not allow_cancelled_cleanup:need(self.signals.pending is None,\'command_cancelled\')\n            n=until-time.monotonic();need(n>0,\'original_command_deadline_exhausted\');return n\n        require_waitid();remaining()\n        fixed_ps_contract=prepare_fixed_ps_contract(argv,until=until)\n        remaining()\n        started=time.monotonic();row=None;out=bytearray();err=bytearray()\n        try:\n            with self.signals.critical():\n                remaining()\n                p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,\n                    env={\'PATH\':\'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin\',\'LANG\':\'C\',\'LC_ALL\':\'C\'},\n                    start_new_session=True,close_fds=True)\n                row={\'label\':label,\'argv\':list(argv),\'process\':p,\'custody\':None,\n                     \'stopAttempted\':False,\'streamsCloseAttempted\':False,\'streamsClosed\':False,\n                     \'completeBeforeDeadline\':False,\'errorType\':None,\'errorCode\':None}\n                self.rows.append(row)\n            row[\'custody\']=capture_child(p,until=until,fixed_ps_contract=fixed_ps_contract)\n            streams={p.stdout.fileno():out,p.stderr.fileno():err}\n            for fd in streams:os.set_blocking(fd,False)\n            event=None\n            while streams or event is None:\n                left=remaining()\n                ready,_,_=select.select(list(streams),[],[],min(left,0.025))\n                for fd in ready:\n                    data=os.read(fd,65536)\n                    if not data:del streams[fd]\n                    else:\n                        target=streams[fd];target.extend(data)\n                        need(len(target)<=maximum,\'command_output_bound\')\n                event=exit_observation(p)\n            remaining()\n            row[\'completeBeforeDeadline\']=True\n            row[\'observedExit\']=event\n            row[\'observedExitCode\']=observed_returncode(event)\n        except BaseException as error:\n            if row is None:raise\n            row[\'errorType\']=type(error).__name__\n            row[\'errorCode\']=str(error) if isinstance(error,CommandRefused) else None\n        finally:\n            if row is not None:\n                with self.signals.critical():\n                    row[\'stopAttempted\']=True\n                    try:row[\'cleanup\']=stop_once_unreaped(row[\'process\'],row[\'custody\'],fixed_ps_contract=fixed_ps_contract)\n                    except BaseException as error:\n                        row[\'cleanup\']={\'ok\':False,\'outcomeUnknown\':True,\n                            \'errorType\':type(error).__name__,\'directChildReaped\':row[\'process\'].returncode is not None,\n                            \'allGroupRowsEmptyAfterReap\':False}\n                    row[\'streamsCloseAttempted\']=True\n                    errors=[]\n                    for stream in (row[\'process\'].stdout,row[\'process\'].stderr):\n                        try:stream.close()\n                        except BaseException as error:errors.append(type(error).__name__)\n                    row[\'streamsClosed\']=not errors\n                    row[\'streamCloseErrors\']=errors\n        p=row[\'process\'];cleanup=row[\'cleanup\']\n        public={\'label\':label,\'argv\':list(argv),\'pid\':p.pid,\'exitCode\':p.returncode,\n            \'completeBeforeDeadline\':row[\'completeBeforeDeadline\'],\n            \'commandDeadlineMonotonic\':until,\'elapsedSeconds\':time.monotonic()-started,\n            \'errorType\':row[\'errorType\'],\'errorCode\':row[\'errorCode\'],\'cleanup\':cleanup,\n            \'stdoutBytes\':len(out),\'stdoutSha256\':sha(out),\'stderrBytes\':len(err),\'stderrSha256\':sha(err),\n            \'streamsClosed\':row[\'streamsClosed\'],\n            \'outcomeUnknown\':not(row[\'completeBeforeDeadline\'] and cleanup.get(\'ok\') is True\n                and cleanup.get(\'directChildReaped\') is True and cleanup.get(\'allGroupRowsEmptyAfterReap\') is True\n                and row[\'streamsClosed\'] and row[\'errorType\'] is None)}\n        row[\'public\']=public\n        return public,bytes(out),bytes(err)\n    def public(self):\n        values=[r.get(\'public\') for r in self.rows]\n        return {\'commands\':values,\'allOwnedCommandsStopped\':all(v is not None\n            and v[\'cleanup\'].get(\'directChildReaped\') is True\n            and v[\'cleanup\'].get(\'allGroupRowsEmptyAfterReap\') is True\n            and v[\'streamsClosed\'] for v in values),\n            \'unknownCommandCount\':sum(v is None or v[\'outcomeUnknown\'] for v in values)}\n', 'mac_production_t5_guard_r1.py': '#!/usr/bin/env python3\n"""Held, observed T5 anchors and scoped descriptor-relative owned I/O.\n\nNo module-level I/O. No private path is opened before both the exact public\nanchor input and actual owned diskutil output have been checked. This module\ndoes not run diskutil or claim a volume-wide atomic snapshot.\n"""\nfrom __future__ import annotations\nfrom contextlib import contextmanager\nimport hashlib, json, os, plistlib, stat, time\nfrom pathlib import Path\n\nMOUNT = Path(\'/Volumes/T5\')\nROOT = MOUNT / \'hepta-vnext-recovery-20261013/heptabao-authbus-production\'\nUUID = \'FB804D1B-24CB-4D6E-AEA7-A9E180807758\'\nANCHOR_PATHS = (\'/\', \'/Volumes\', \'/Volumes/T5\')\n\nclass VolumeRefused(RuntimeError): pass\n\ndef require(value, code):\n    if not value: raise VolumeRefused(code)\n\ndef identity(info):\n    return tuple(str(x) for x in (info.st_dev, info.st_ino, info.st_uid,\n        info.st_gid, info.st_mode, info.st_nlink, info.st_size,\n        info.st_mtime_ns, info.st_ctime_ns))\n\ndef inode_identity(info):\n    return identity(info)[:5]\n\nclass HeldT5:\n    def __init__(self, raw_public, expected_sha256, remaining, critical):\n        require(isinstance(raw_public, bytes) and len(raw_public) <= 8192,\n                \'public_anchor_input_bound\')\n        require(hashlib.sha256(raw_public).hexdigest() == expected_sha256,\n                \'public_anchor_whole_sha\')\n        expected = json.loads(raw_public)\n        require(set(expected) == {\'schema\', \'source_inventory_sha256\', \'volumeUUID\',\n                  \'expectedVolumeDevice\', \'anchors\'}\n          and expected[\'schema\'] == \'heptabao.mac-current-t5-public-anchor.r1\'\n          and expected[\'volumeUUID\'] == UUID, \'public_anchor_schema\')\n        require([x.get(\'path\') for x in expected[\'anchors\']] == list(ANCHOR_PATHS),\n                \'exact_public_anchor_paths\')\n        require(all(set(x) == {\'path\',\'identity\'} and len(x[\'identity\']) == 9\n                    and all(isinstance(v,str) and v.isdecimal() for v in x[\'identity\'])\n                    for x in expected[\'anchors\']), \'public_anchor_identity_shape\')\n        require(isinstance(expected[\'expectedVolumeDevice\'],str)\n                and expected[\'expectedVolumeDevice\'].isdecimal()\n                and expected[\'expectedVolumeDevice\'] == expected[\'anchors\'][2][\'identity\'][0],\n                \'captured_volume_device\')\n        self.expected, self.remaining, self.critical = expected, remaining, critical\n        self.rows, self.anchors = [], []\n        self.uuid_verified = False\n        self.closed = False\n        self.close_errors = []\n        self.last_anchor_check = False\n        try:\n            parent = None\n            for index, item in enumerate(expected[\'anchors\']):\n                self.remaining()\n                name = \'/\' if index == 0 else Path(item[\'path\']).name\n                named = os.lstat(\'/\') if index == 0 else os.stat(\n                    name, dir_fd=parent[\'fd\'], follow_symlinks=False)\n                require(stat.S_ISDIR(named.st_mode) and identity(named) == tuple(item[\'identity\']),\n                        \'captured_anchor_named_identity\')\n                with self.critical():\n                    fd = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,\n                                 **({} if parent is None else {\'dir_fd\':parent[\'fd\']}))\n                    row = {\'fd\':fd,\'name\':name,\'parent\':parent,\'expected\':tuple(item[\'identity\']),\n                           \'close_attempted\':False,\'closed\':False,\'anchor\':True}\n                    self.rows.append(row);self.anchors.append(row)\n                require(identity(os.fstat(fd)) == row[\'expected\'], \'captured_anchor_fd_identity\')\n                parent = row\n            self.check()\n        except BaseException:\n            self.close()\n            raise\n\n    def check(self, *, check_deadline=True):\n        require(not self.closed, \'volume_guard_not_closed\')\n        if check_deadline: self.remaining()\n        self.last_anchor_check = False\n        for row in self.anchors:\n            named = os.lstat(\'/\') if row[\'parent\'] is None else os.stat(\n                row[\'name\'],dir_fd=row[\'parent\'][\'fd\'],follow_symlinks=False)\n            require(identity(named) == identity(os.fstat(row[\'fd\'])) == row[\'expected\'],\n                    \'held_t5_anchor_changed\')\n        require(os.fstat(self.anchors[-1][\'fd\']).st_dev ==\n                int(self.expected[\'expectedVolumeDevice\']), \'held_t5_device_changed\')\n        self.last_anchor_check = True\n        if check_deadline: self.remaining()\n\n    def accept_diskutil(self, raw):\n        self.check()\n        require(isinstance(raw,bytes) and len(raw) <= 262144, \'bounded_actual_diskutil_bytes\')\n        info = plistlib.loads(raw)\n        require(info.get(\'VolumeUUID\') == UUID and info.get(\'MountPoint\') == str(MOUNT),\n                \'actual_t5_uuid_mount\')\n        self.uuid_verified = True\n        self.check()\n\n    def _admit(self, path):\n        self.check()\n        require(self.uuid_verified, \'uuid_before_owned_private_io\')\n        path = Path(path)\n        require(path.is_absolute() and path == Path(os.path.normpath(str(path)))\n                and path.is_relative_to(ROOT), \'fixed_owned_t5_scope\')\n        return path\n\n    def _close_row(self, row):\n        if row[\'close_attempted\']: return\n        with self.critical():\n            row[\'close_attempted\'] = True\n            try:\n                os.close(row[\'fd\']);row[\'closed\'] = True\n            except BaseException as error:\n                self.close_errors.append(type(error).__name__)\n                raise\n\n    @contextmanager\n    def parent(self, path):\n        path = self._admit(path)\n        parts = path.relative_to(MOUNT).parts\n        require(parts and all(part not in (\'\',\'.\', \'..\') for part in parts),\n                \'owned_component_shape\')\n        previous = self.anchors[-1]\n        borrowed = []\n        try:\n            for component in parts[:-1]:\n                self.remaining()\n                named = os.stat(component,dir_fd=previous[\'fd\'],follow_symlinks=False)\n                require(stat.S_ISDIR(named.st_mode) and named.st_uid == 501\n                        and named.st_dev == int(self.expected[\'expectedVolumeDevice\'])\n                        and stat.S_IMODE(named.st_mode)&0o022 == 0, \'owned_parent_custody\')\n                with self.critical():\n                    fd = os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,\n                                 dir_fd=previous[\'fd\'])\n                    row = {\'fd\':fd,\'name\':component,\'parent\':previous,\n                           \'expected_inode\':inode_identity(named),\n                           \'close_attempted\':False,\'closed\':False,\'anchor\':False}\n                    self.rows.append(row);borrowed.append(row)\n                require(inode_identity(os.fstat(fd)) == row[\'expected_inode\'],\n                        \'owned_parent_fd_identity\')\n                previous = row\n            self.check()\n            yield previous[\'fd\'], parts[-1]\n            for row in borrowed:\n                named = os.stat(row[\'name\'],dir_fd=row[\'parent\'][\'fd\'],follow_symlinks=False)\n                require(inode_identity(named) == inode_identity(os.fstat(row[\'fd\']))\n                        == row[\'expected_inode\'], \'owned_parent_changed\')\n            self.check()\n        finally:\n            errors = []\n            for row in reversed(borrowed):\n                try:self._close_row(row)\n                except BaseException as error:errors.append(type(error).__name__)\n            if errors: raise VolumeRefused(\'owned_parent_close_failed\')\n\n    def read(self, path, maximum=2*1024*1024, *, private=True):\n        require(type(maximum) is int and 0 < maximum <= 16*1024*1024, \'bounded_owned_read\')\n        with self.parent(path) as (parent, name):\n            with self.critical():\n                fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)\n                row = {\'fd\':fd,\'close_attempted\':False,\'closed\':False,\'anchor\':False}\n                self.rows.append(row)\n            try:\n                before = os.fstat(fd)\n                require(stat.S_ISREG(before.st_mode) and before.st_uid == 501\n                        and before.st_nlink == 1 and before.st_dev == int(self.expected[\'expectedVolumeDevice\'])\n                        and 0 <= before.st_size <= maximum\n                        and (stat.S_IMODE(before.st_mode) == 0o600 if private else\n                             stat.S_IMODE(before.st_mode)&0o022 == 0), \'owned_file_custody\')\n                raw = bytearray()\n                while len(raw) <= maximum:\n                    self.remaining()\n                    block = os.read(fd,min(65536,maximum+1-len(raw)))\n                    if not block:break\n                    raw.extend(block)\n                named = os.stat(name,dir_fd=parent,follow_symlinks=False)\n                require(len(raw) == before.st_size and identity(before) ==\n                        identity(os.fstat(fd)) == identity(named), \'owned_file_stable_read\')\n                self.check()\n                return bytes(raw)\n            finally:self._close_row(row)\n\n    def write_new(self, path, raw):\n        require(isinstance(raw,bytes) and len(raw) <= 16*1024*1024, \'bounded_owned_write\')\n        with self.parent(path) as (parent, name):\n            with self.critical():\n                fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,\n                             0o600,dir_fd=parent)\n                row = {\'fd\':fd,\'close_attempted\':False,\'closed\':False,\'anchor\':False}\n                self.rows.append(row)\n            try:\n                before = os.fstat(fd)\n                require(stat.S_ISREG(before.st_mode) and before.st_uid == 501\n                        and before.st_nlink == 1 and before.st_dev == int(self.expected[\'expectedVolumeDevice\']),\n                        \'new_owned_file_inode\')\n                offset=0\n                while offset<len(raw):\n                    self.remaining()\n                    n=os.write(fd,raw[offset:offset+65536])\n                    require(n>0,\'new_owned_write_progress\');offset+=n\n                os.fchmod(fd,0o600);os.fsync(fd);os.fsync(parent)\n                after=os.fstat(fd);named=os.stat(name,dir_fd=parent,follow_symlinks=False)\n                require(identity(after)==identity(named) and after.st_size==len(raw)\n                        and inode_identity(before)==inode_identity(after), \'new_owned_file_name\')\n                self.check()\n                return {\'bytes\':len(raw),\'sha256\':hashlib.sha256(raw).hexdigest(),\n                        \'identity\':list(identity(after))}\n            finally:self._close_row(row)\n\n    @contextmanager\n    def capture_sink(self, path, maximum=2*1024*1024):\n        require(type(maximum) is int and 0<maximum<=2*1024*1024,\'bounded_capture_sink\')\n        with self.parent(path) as (parent,name):\n            with self.critical():\n                fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,\n                           0o600,dir_fd=parent)\n                row={\'fd\':fd,\'close_attempted\':False,\'closed\':False,\'anchor\':False}\n                self.rows.append(row)\n                stream=os.fdopen(fd,\'wb\',buffering=0,closefd=False)\n            before=os.fstat(fd)\n            try:\n                require(stat.S_ISREG(before.st_mode) and before.st_uid==501\n                        and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600\n                        and before.st_dev==int(self.expected[\'expectedVolumeDevice\']),\n                        \'capture_sink_custody\')\n                yield stream\n                os.fsync(fd);os.fsync(parent)\n                after=os.fstat(fd);named=os.stat(name,dir_fd=parent,follow_symlinks=False)\n                require(after.st_size<=maximum and identity(after)==identity(named)\n                        and inode_identity(before)==inode_identity(after),\'capture_sink_stable\')\n                self.check()\n            finally:\n                with self.critical():\n                    try:stream.close()\n                    finally:self._close_row(row)\n\n    def mkdir_new(self, path):\n        with self.parent(path) as (parent,name):\n            self.remaining()\n            os.mkdir(name,mode=0o700,dir_fd=parent)\n            info=os.stat(name,dir_fd=parent,follow_symlinks=False)\n            require(stat.S_ISDIR(info.st_mode) and info.st_uid==501\n                    and stat.S_IMODE(info.st_mode)==0o700\n                    and info.st_dev==int(self.expected[\'expectedVolumeDevice\']),\'new_owned_directory\')\n            os.fsync(parent);self.check()\n            return list(identity(info))\n\n    def public_state(self):\n        return {\'schema\':\'heptabao.held-t5-volume-state.r1\',\n                \'volumeUUIDVerified\':self.uuid_verified,\n                \'expectedVolumeDevice\':self.expected[\'expectedVolumeDevice\'],\n                \'anchors\':self.expected[\'anchors\'],\'lastAnchorCheckPassed\':self.last_anchor_check,\n                \'allDescriptorsClosed\':all(x[\'closed\'] for x in self.rows),\n                \'closeErrors\':list(self.close_errors)}\n\n    def close(self):\n        if self.closed:return\n        try:self.check(check_deadline=False)\n        except BaseException:\n            self.last_anchor_check=False\n        for row in reversed(self.rows):\n            try:self._close_row(row)\n            except BaseException:pass\n        self.closed=True\n', 'mac_public_code_pin_excerpt_r1.py': '#!/usr/bin/env python3\n"""Public-code pin excerpt only; no current config or credential capture code.\n\nBodies are byte-identical to the original guarded capture source. This excerpt\nhas not independently qualified a fresh manager; its caller must bind and test\nits actual use. The original full source SHA is recorded in provenance.\n"""\nimport hashlib, os, stat\nfrom pathlib import Path\n\nMIB=1024*1024\n\nclass CaptureRefused(RuntimeError):pass\ndef need(value,code):\n    if not value:raise CaptureRefused(code)\n\ndef identity(s):\n    return tuple(str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,\n                                 s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))\n\ndef public_code_pin(path,*,remaining,critical):\n    # Public interpreter/extension/source hashes have their own fixed 64MiB\n    # per-file bound. They do not pretend to be measured SQLite page I/O.\n    remaining();path=Path(path).resolve(strict=True)\n    with critical():\n        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\n    try:\n        before=os.fstat(fd)\n        need(stat.S_ISREG(before.st_mode) and 0<before.st_size<=64*MIB\n             and not stat.S_IMODE(before.st_mode)&0o022,\'public_runtime_code_custody\')\n        digest=hashlib.sha256();count=0\n        while count<=before.st_size:\n            remaining()\n            raw=os.read(fd,min(MIB,before.st_size+1-count))\n            if not raw:break\n            count+=len(raw);digest.update(raw)\n        need(count==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),\n             \'public_runtime_code_changed\')\n        remaining()\n        result={\'path\':str(path),\'bytes\':count,\'sha256\':digest.hexdigest()}\n    finally:\n        with critical():os.close(fd)\n    remaining()\n    return result\n\n', 'main3_http_complete.py': '#!/usr/bin/env python3\n"""Bounded, complete HTTP response framing for one already-owned TLS socket.\n\nNo connection, dispatch, retry, credential logging or socket ownership is added.\nThe caller supplies its original absolute deadline and closes the TLS socket.\n"""\nfrom __future__ import annotations\nimport http.client\nimport io\nimport re\n\nMAX_BODY = 1048576\nMAX_WIRE = 2 * MAX_BODY + 131072\nMAX_LINE = 8192\nMAX_HEADERS = 100\nMAX_HEADER_BYTES = 65536\nMAX_TRAILER_BYTES = 16384\nMAX_CHUNKS = 4096\n_TOKEN = rb"[!#$%&\'*+.^_`|~0-9A-Za-z-]+"\n_QUOTED = rb\'"(?:[\\t !#-\\[\\]-~\\x80-\\xff]|\\\\[\\t \\x21-\\x7e\\x80-\\xff])*"\'\n_CHUNK_LINE = re.compile(rb\'([0-9A-Fa-f]{1,16})(?:[ \\t]*;[ \\t]*\' + _TOKEN +\n                         rb\'(?:[ \\t]*=[ \\t]*(?:\' + _TOKEN + rb\'|\' + _QUOTED + rb\'))?)*[ \\t]*\')\n_HEADER_NAME = re.compile(_TOKEN)\n_FORBIDDEN_TRAILERS = frozenset((\n    b\'content-length\', b\'transfer-encoding\', b\'host\', b\'connection\', b\'trailer\',\n    b\'content-encoding\', b\'content-type\', b\'content-range\', b\'authorization\',\n    b\'proxy-authorization\', b\'www-authenticate\', b\'proxy-authenticate\', b\'set-cookie\'))\n\n\nclass HttpFramingRefused(Exception):\n    def __init__(self, code):\n        self.safe_code = code\n        super().__init__(code)\n\n\ndef require(value, code):\n    if not value:\n        raise HttpFramingRefused(code)\n\n\nclass _DeadlineRaw(io.RawIOBase):\n    def __init__(self, tls, remaining, projection):\n        super().__init__()\n        self.tls, self.remaining, self.projection = tls, remaining, projection\n        self.wire_bytes = 0\n\n    def readable(self):\n        return True\n\n    def readinto(self, buffer):\n        self.tls.settimeout(self.remaining())\n        require(self.wire_bytes < MAX_WIRE, \'http_wire_limit\')\n        data = self.tls.recv(min(len(buffer), 8192, MAX_WIRE - self.wire_bytes))\n        self.wire_bytes += len(data)\n        self.projection[\'receivedWireBytes\'] = self.wire_bytes\n        self.remaining()\n        buffer[:len(data)] = data\n        return len(data)\n\n\nclass DeadlineSocket:\n    """Only the response reader owns this file; the original caller owns TLS."""\n    def __init__(self, tls, remaining, projection):\n        self.raw = _DeadlineRaw(tls, remaining, projection)\n        self.reader = None\n\n    def makefile(self, mode):\n        require(mode == \'rb\' and self.reader is None, \'http_one_response_reader\')\n        self.reader = io.BufferedReader(self.raw, buffer_size=8192)\n        return self.reader\n\n    def close_reader(self):\n        if self.reader is not None:\n            self.reader.close()\n        else:\n            self.raw.close()\n\n\nclass CompleteHTTPResponse(http.client.HTTPResponse):\n    """Use stdlib status/headers/body parsing with strict bounded chunk endings."""\n    def __init__(self, stream, remaining, projection):\n        self.remaining, self.projection = remaining, projection\n        self.announced_bytes = self.data_chunks = self.trailer_count = 0\n        self.terminal_chunk_seen = self.trailers_complete = False\n        super().__init__(stream)\n\n    def _read_next_chunk_size(self):\n        self.remaining()\n        line = self.fp.readline(MAX_LINE + 1)\n        require(bool(line), \'http_chunk_size_missing\')\n        require(len(line) <= MAX_LINE and line.endswith(b\'\\r\\n\'), \'http_chunk_size_line\')\n        match = _CHUNK_LINE.fullmatch(line[:-2])\n        require(match is not None, \'http_chunk_size_grammar\')\n        size = int(match.group(1), 16)\n        require(self.announced_bytes + size <= MAX_BODY, \'http_decoded_body_limit\')\n        if size:\n            self.data_chunks += 1\n            require(self.data_chunks <= MAX_CHUNKS, \'http_chunk_count_limit\')\n            self.announced_bytes += size\n        else:\n            self.terminal_chunk_seen = True\n        self.projection.update(dataChunkCount=self.data_chunks,\n                               terminalChunkSeen=self.terminal_chunk_seen)\n        return size\n\n    def _read_and_discard_trailer(self):\n        total = 0\n        while True:\n            self.remaining()\n            line = self.fp.readline(MAX_LINE + 1)\n            require(bool(line), \'http_terminal_trailer_missing\')\n            total += len(line)\n            require(len(line) <= MAX_LINE and total <= MAX_TRAILER_BYTES,\n                    \'http_trailer_limit\')\n            require(line.endswith(b\'\\r\\n\'), \'http_trailer_line_ending\')\n            if line == b\'\\r\\n\':\n                self.trailers_complete = True\n                self.projection[\'trailersComplete\'] = True\n                return\n            self.trailer_count += 1\n            self.projection[\'trailerCount\'] = self.trailer_count\n            require(self.trailer_count <= MAX_HEADERS, \'http_trailer_count_limit\')\n            name, separator, value = line[:-2].partition(b\':\')\n            require(bool(separator) and _HEADER_NAME.fullmatch(name) is not None,\n                    \'http_trailer_field_grammar\')\n            require(name.lower() not in _FORBIDDEN_TRAILERS, \'http_forbidden_trailer\')\n            require(all(c == 9 or c >= 32 and c != 127 for c in value),\n                    \'http_trailer_value_grammar\')\n\n    def _get_chunk_left(self):\n        left = self.chunk_left\n        if not left:\n            if left is not None:\n                require(self._safe_read(2) == b\'\\r\\n\', \'http_chunk_data_terminator\')\n            left = self._read_next_chunk_size()\n            if left == 0:\n                self._read_and_discard_trailer()\n                self._close_conn()\n                left = None\n            self.chunk_left = left\n        return left\n\n\ndef read_complete_body(response, remaining, projection):\n    """No unbounded read, EOF inference, response replay or header-value logging."""\n    remaining()\n    headers = response.getheaders()\n    lengths = [v for k, v in headers if k.lower() == \'content-length\']\n    transfers = [v for k, v in headers if k.lower() == \'transfer-encoding\']\n    projection.update(contentLengthHeaderCount=len(lengths),\n                      transferEncodingHeaderCount=len(transfers),\n                      responseFraming=\'unadmitted\')\n    require(len(headers) <= MAX_HEADERS, \'http_header_count_limit\')\n    require(not getattr(response.headers, \'defects\', ()), \'http_header_grammar\')\n    size = 0\n    for name, value in headers:\n        require(_HEADER_NAME.fullmatch(name.encode(\'ascii\', \'strict\')) is not None,\n                \'http_header_name_grammar\')\n        require(all(c == \'\\t\' or ord(c) >= 32 and ord(c) != 127 for c in value),\n                \'http_header_value_grammar\')\n        size += len(name) + len(value) + 4\n        require(len(name) + len(value) + 4 <= MAX_LINE and size <= MAX_HEADER_BYTES,\n                \'http_header_bytes_limit\')\n    require(len(lengths) <= 1 and len(transfers) <= 1, \'http_duplicate_framing_header\')\n    require(not (lengths and transfers), \'http_ambiguous_transfer_and_length\')\n    require(response.version in (10, 11), \'http_response_version\')\n    length = lengths[0].strip(\' \\t\') if lengths else None\n    require(length is None or re.fullmatch(r\'[0-9]{1,9}\', length), \'http_length_grammar\')\n    if length is not None:\n        length = int(length)\n        projection[\'declaredContentLength\'] = length\n        require(length <= MAX_BODY, \'http_decoded_body_limit\')\n    if response.status == 204:\n        require(not transfers and length in (None, 0), \'http_empty_204_frame\')\n        projection[\'responseFraming\'] = \'no-body\'\n        expected = 0\n    elif transfers:\n        require(transfers[0].strip(\' \\t\').lower() == \'chunked\' and response.version == 11,\n                \'http_unsupported_transfer_encoding\')\n        # The stdlib compares TE literally; admit case/OWS only after rejecting\n        # all duplicate/ambiguous framing, then select its original chunk reader.\n        response.chunked, response.chunk_left, response.length = True, None, None\n        projection.update(responseFraming=\'chunked\', dataChunkCount=0,\n                          trailerCount=0, terminalChunkSeen=False, trailersComplete=False)\n        expected = None\n    else:\n        require(length is not None, \'http_content_length_required\')\n        projection[\'responseFraming\'] = \'content-length\'\n        expected = length\n    data = response.read(MAX_BODY + 1 if expected is None else expected + 1)\n    remaining()\n    require(len(data) <= MAX_BODY, \'http_decoded_body_limit\')\n    require(response.isclosed(), \'http_body_incomplete\')\n    if expected is None:\n        require(response.terminal_chunk_seen and response.trailers_complete and\n                len(data) == response.announced_bytes, \'http_chunked_body_incomplete\')\n    else:\n        require(len(data) == expected, \'http_body_incomplete\')\n    projection[\'decodedBodyBytes\'] = len(data)\n    return data\n\n\ndef safe_failure_code(error):\n    if isinstance(error, HttpFramingRefused):\n        return error.safe_code\n    if isinstance(error, http.client.IncompleteRead):\n        return \'http_body_incomplete\'\n    if isinstance(error, TimeoutError):\n        return \'http_original_deadline\'\n    if isinstance(error, http.client.HTTPException):\n        return \'http_status_or_header_grammar\'\n    return \'api_transport_or_guard_refused\'\n', 'permanent_bootstrap_api_r1.py': "import errno,hashlib,http.client,json,re,socket,ssl,time\nfrom pathlib import Path\nfrom main3_http_complete import DeadlineSocket,CompleteHTTPResponse,read_complete_body,safe_failure_code\nROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-authbus-production')\nMAX_HTTP=192\nMAX_BODY=1048576\nclass Refused(RuntimeError):pass\ndef need(value,code):\n    if not value:raise Refused(code)\nclass Api:\n    def __init__(self,plan,phase,phase_until,journal,guard):\n        need(phase in ('initial','cold-new-process'),'fixed_api_phase')\n        need(type(plan['port']) is int and 1024<=plan['port']<=65535\n             and re.fullmatch(r'[0-9a-f]{64}',plan['certificateLeafSha256']),'fixed_owned_tls_endpoint')\n        self.plan=plan;self.phase=phase;self.until=phase_until;self.journal=journal;self.guard=guard\n        self.context=ssl.create_default_context(cafile=str(ROOT/'tls/ca.crt'))\n        self.rows=[];self.checks=[];self.unknown=False;self.root_token=None;self.sensitive=[]\n    def remaining(self,cap):\n        left=self.until-time.monotonic();need(left>0,'original_api_phase_120_seconds');return min(left,cap)\n    def check(self,case,value):\n        need(re.fullmatch(r'[a-z0-9._-]{1,100}',case),'fixed_public_api_case')\n        self.checks.append({'case':case,'passed':value is True});need(value is True,case)\n    def call(self,case,method,route,body=None,*,expected=200,token=None,category,slot=0,readiness=False):\n        self.remaining(1)\n        self.guard.check()\n        need(not self.unknown and len(self.rows)<MAX_HTTP,'no_http_after_unknown_and_finite_requests')\n        need(re.fullmatch(r'[a-z0-9._-]{1,100}',case) and category in ('health','init','unseal','mount','activate','capacity','policy','role','role-id','secret-id','login','kv-read','kv-write','lookup','renew','revoke','secret-destroy','admin-denied'),\n             'fixed_public_route_category')\n        need(method in ('GET','POST','PUT') and isinstance(route,str) and route.startswith('/v1/')\n             and re.fullmatch(r'/[A-Za-z0-9/._-]+',route) and 0<=slot<=3,'fixed_owned_api_route')\n        if category=='activate':need(method=='POST' and route=='/v1/sys/storage/native-v6/activate','normal_configured_storage_activation_only')\n        need(not readiness or (method=='GET' and route=='/v1/sys/health' and body is None and token==''),'health_only_tcp_refusal_wait')\n        bearer=self.root_token if token is None else token\n        need(bearer is None or isinstance(bearer,str) and len(bearer)<=16384 and '\\r' not in bearer and '\\n' not in bearer,'private_single_line_bearer')\n        payload=b'' if body is None else json.dumps(body,separators=(',',':'),ensure_ascii=False).encode()\n        need(len(payload)<=MAX_BODY,'bounded_private_request_body')\n        row={'phase':self.phase,'ordinal':len(self.rows)+1,'case':case,'routeCategory':category,'slotOrdinal':slot,\n             'method':method,'dispatched':False,'responseComplete':False,'outcomeUnknown':False,\n             'responsePrivatelyDurable':False,'httpRequestCount':0,'connectionAttempts':0,'connectionRefusals':0,'tlsVerified':False,'socketsClosed':False}\n        self.rows.append(row)\n        self.journal.append('api-request-intent',dict(row))\n        deadline=time.monotonic()+self.remaining(15 if readiness else 10)\n        raw=tls=response=stream=None\n        def left():\n            remaining=min(self.until,deadline)-time.monotonic();need(remaining>0,'one_http_original_absolute_deadline');return remaining\n        try:\n            for _ in range(256 if readiness else 1):\n                row['connectionAttempts']+=1\n                try:raw=socket.create_connection(('127.0.0.1',self.plan['port']),timeout=min(5,left()));break\n                except ConnectionRefusedError as error:\n                    if not readiness or error.errno!=errno.ECONNREFUSED:raise\n                    row['connectionRefusals']+=1;time.sleep(min(0.1,left()))\n            need(raw is not None,'bounded_health_connection_attempts')\n            raw.settimeout(left());tls=self.context.wrap_socket(raw,server_hostname='localhost')\n            need(hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()==self.plan['certificateLeafSha256'],'actual_tls_leaf_pin')\n            row.update(tlsVerified=True,tlsVersion=tls.version())\n            headers=[method+' '+route+' HTTP/1.1','Host: localhost:'+str(self.plan['port']),'Accept: application/json','Connection: close']\n            if bearer:headers.append('X-Vault-Token: '+bearer)\n            if body is not None:headers+=['Content-Type: application/json','Content-Length: '+str(len(payload))]\n            request=('\\r\\n'.join(headers)+'\\r\\n\\r\\n').encode('ascii')+payload\n            tls.settimeout(left());row['dispatched']=True;row['httpRequestCount']=1\n            tls.sendall(request)\n            stream=DeadlineSocket(tls,left,row)\n            response=CompleteHTTPResponse(stream,left,row);response.begin()\n            row['status']=response.status\n            data=read_complete_body(response,left,row)\n            left();row.update(responseComplete=True,responseBytes=len(data))\n            self.journal.response_bytes(self.phase,row['ordinal'],data)\n            row['responsePrivatelyDurable']=True\n            left();value=json.loads(data) if data else {}\n        except BaseException as error:\n            row['outcomeUnknown']=bool(row['dispatched'] and not (row['responseComplete'] and row['responsePrivatelyDurable']))\n            self.unknown=True;row['errorType']=type(error).__name__\n            row['failureCode']=safe_failure_code(error)\n            if isinstance(error,Refused) and error.args==('one_http_original_absolute_deadline',):row['failureCode']='http_original_deadline'\n            if isinstance(error,json.JSONDecodeError):row['failureCode']='complete_body_json_invalid'\n            # Exception messages, response bodies and their hashes stay private.\n            raise Refused('api_transport_or_complete_response_failed') from None\n        finally:\n            if response is not None:response.close()\n            if stream is not None:stream.close_reader()\n            row['responseReaderClosed']=stream is None or stream.raw.closed\n            if tls is not None:tls.close()\n            elif raw is not None:raw.close()\n            row['socketsClosed']=True\n            self.journal.append('api-request-result',dict(row))\n        self.guard.check();self.remaining(1)\n        self.check(case,row['status']==expected)\n        return value\n    def public(self):\n        return {'phase':self.phase,'checks':self.checks,'requests':self.rows,'requestCount':len(self.rows),\n                'unknownHttpOutcomeCount':sum(r['outcomeUnknown'] for r in self.rows),\n                'allDispatchedResponsesComplete':all(not r['dispatched'] or r['responseComplete'] for r in self.rows),\n                'allReturnedSocketsClosed':all(r['socketsClosed'] for r in self.rows),\n                'allCompleteResponsesPrivatelyDurable':all(not r['responseComplete'] or r['responsePrivatelyDurable'] for r in self.rows),\n                'credentialValuesOrDigestsPublished':False,'providerValid':False,'providerCalled':False,\n                'providerRefreshAttempted':False,'productionCutover':False}\n"}, 'pins': {'mac_owned_unreaped_r1.py': {'bytes': 14877, 'sha256': 'd735a9e9330e1260d44ad9e4c854d50094e20d85fe5633ddd9042281b3346298'}, 'mac_owned_commands_r1.py': {'bytes': 6154, 'sha256': '71a11bf9a0510c991b78c9bc3f094f315bf4914485b9cfda81c6e501eaf73530'}, 'mac_production_t5_guard_r1.py': {'bytes': 13379, 'sha256': '9f0b032264c4dd5db45478f08c1cdbc92354ac3153b2ed4d18ef2aab30b139f1'}, 'mac_public_code_pin_excerpt_r1.py': {'bytes': 1792, 'sha256': '7ff262e7ff913eb97aab77855d988cb3a6af8cab5ea9c77940a2782afd91ca4f'}, 'main3_http_complete.py': {'bytes': 9110, 'sha256': 'ce02882b991e1abb1d135e05c571d2d112032e93a5857769a8b90d25425d5c96'}, 'permanent_bootstrap_api_r1.py': {'bytes': 7213, 'sha256': 'ce40d15a5b837e1f8fe12c8c925a16241c0bca8f3b751dc5c445bf36bec88b09'}}}
START = time.monotonic()
UNTIL = START + 300
FDS = []
CONTROL_SIGNALS = None
REPORT = {'schema': 'heptabao.permanent-bootstrap-lifecycle.r2', 'ok': False,
    'productCommit': PRODUCT, 'automaticRetry': False, 'currentCredentialReads': 0,
    'providerCalls': 0, 'productionClientChanges': 0, 'launchAgentInstalled': False,
    'legacyChanges': 0, 'j3160Requests': 0, 'rootKeyValuesOrDigestsPublished': False,
    'productionCutoverQualified': False, 'productionBackupQualified': False,
    'parentSeconds': 300, 'eachApiPhaseSeconds': 120, 'supervisorSeconds': 330,
    'priorKnownNoHttpBootstrapJob': '1a1b386a389-fc05-836f',
    'certificateCorrectionJob': '1a1b39336a2-fc05-83a7',
    'permanentStoreInitialized': False, 'serverProcesses': [], 'apiPhases': []}

class Refused(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def remaining():
    need(CONTROL_SIGNALS is None or CONTROL_SIGNALS.pending is None, 'bootstrap_cancelled')
    value = UNTIL - time.monotonic()
    need(value > 0, 'bootstrap_original_parent_deadline')
    return value

def full9(value):
    return tuple(str(getattr(value, name)) for name in ('st_dev', 'st_ino', 'st_uid',
        'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def own(fd, label):
    row = {'fd': fd, 'label': label, 'attempts': 0, 'closed': False}
    FDS.append(row)
    return row

def close(row):
    if row['attempts']:
        return
    row['attempts'] = 1
    os.close(row['fd'])
    row['closed'] = True

def open_fd(path, flags, label, *, dir_fd=None):
    remaining()
    return own(os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
        0o600, **({} if dir_fd is None else {'dir_fd': dir_fd})), label)

class PrivateOperations:
    def __init__(self):
        self.counter = 0
        self.dirs = []
        previous = None
        for path in (Path('/'), Path('/Users'), CALLER_HOME, CUSTODY):
            row = open_fd(path if previous is None else path.name, os.O_RDONLY | os.O_DIRECTORY,
                          'private-parent', dir_fd=None if previous is None else previous['fd'])
            info = os.fstat(row['fd'])
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == (0 if path in (Path('/'), Path('/Users')) else 501)
                 and not info.st_mode & 0o022 and full9(info) == full9(path.lstat()), 'bootstrap_private_parent')
            if path == CUSTODY:
                need(stat.S_IMODE(info.st_mode) == 0o700, 'bootstrap_custody_private')
            self.dirs.append((path, row, full9(info)[:5]))
            previous = row
        self.check()
        os.mkdir(OPERATIONS.name, 0o700, dir_fd=previous['fd'])
        os.fsync(previous['fd'])
        self.root = open_fd(OPERATIONS.name, os.O_RDONLY | os.O_DIRECTORY, 'operation-directory', dir_fd=previous['fd'])
        info = os.fstat(self.root['fd'])
        need(info.st_uid == 501 and info.st_gid == 20 and stat.S_IMODE(info.st_mode) == 0o700,
             'bootstrap_new_operation_directory')
        self.dirs.append((OPERATIONS, self.root, full9(info)[:5]))
        self.check()

    def check(self):
        remaining()
        for path, row, identity in self.dirs:
            need(full9(os.fstat(row['fd']))[:5] == full9(path.lstat())[:5] == identity,
                 'bootstrap_same_private_parent')

    def create(self, name):
        self.check()
        need(re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,120}', name), 'bootstrap_fixed_private_name')
        row = open_fd(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, name, dir_fd=self.root['fd'])
        before = os.fstat(row['fd'])
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600,
             'bootstrap_private_new_regular_file')
        os.fsync(row['fd']); os.fsync(self.root['fd'])
        return row

    def write(self, name, raw):
        need(isinstance(raw, bytes) and len(raw) <= 1048576, 'bootstrap_private_body_bound')
        row = self.create(name)
        try:
            start = full9(os.fstat(row['fd']))[:6]
            offset = 0
            while offset < len(raw):
                remaining()
                count = os.write(row['fd'], raw[offset:offset + 65536])
                need(count > 0, 'bootstrap_private_write_progress')
                offset += count
            os.fsync(row['fd']); os.fsync(self.root['fd'])
            after = os.fstat(row['fd'])
            need(full9(after)[:6] == start and after.st_size == len(raw)
                 and full9(after) == full9(os.stat(name, dir_fd=self.root['fd'], follow_symlinks=False)),
                 'bootstrap_private_write_generation')
        finally:
            close(row)
        self.check()

    def append(self, category, value):
        need(self.counter < 512 and category in ('api-request-intent', 'api-request-result',
             'server-start-intent', 'server-stop-result', 'bootstrap-recovery'), 'bootstrap_finite_journal')
        self.write('event-%04d.private.json' % self.counter, encoded({'category': category, 'value': value}))
        self.counter += 1

    def response_bytes(self, phase, ordinal, raw):
        need(phase in ('initial', 'cold-new-process') and 1 <= ordinal <= 192, 'bootstrap_exact_response_slot')
        self.write('%s-%03d.response.private.bin' % (phase, ordinal), raw)

def binary_pin():
    row = open_fd(BINARY, os.O_RDONLY, 'fixed-normal-binary')
    try:
        before = os.fstat(row['fd'])
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o500
             and before.st_size == BINARY_BYTES, 'bootstrap_exact_binary_metadata')
        digest, count = hashlib.sha256(), 0
        while True:
            remaining()
            raw = os.read(row['fd'], min(1048576, BINARY_BYTES + 1 - count))
            if not raw:
                break
            count += len(raw); digest.update(raw)
            need(count <= BINARY_BYTES, 'bootstrap_exact_binary_bound')
        need(count == BINARY_BYTES and digest.hexdigest() == BINARY_SHA
             and full9(before) == full9(os.fstat(row['fd'])) == full9(BINARY.lstat()),
             'bootstrap_exact_original_normal_binary')
        return full9(before)
    finally:
        close(row)

def main():
    global CONTROL_SIGNALS
    os.umask(0o077)
    sys.dont_write_bytecode = True
    guard = operations = commands = signals = None
    current = None
    process_rows = []
    apis = []
    sensitive = []
    try:
        need(sys.platform == 'darwin' and os.getuid() == 501 and os.getgid() == 20
             and Path(sys.executable).resolve(strict=True) == PYTHON, 'bootstrap_exact_mac_owner_runtime')
        for name, source in PAYLOAD['sources'].items():
            raw = source.encode()
            need(len(raw) == PAYLOAD['pins'][name]['bytes'] and hashlib.sha256(raw).hexdigest()
                 == PAYLOAD['pins'][name]['sha256'], 'bootstrap_complete_public_source_pin')
            ast.parse(source)
            module = types.ModuleType(Path(name).stem)
            module.__file__ = str(OPERATIONS / name)
            sys.modules[module.__name__] = module
            exec(compile(source, module.__file__, 'exec'), module.__dict__)
        from mac_owned_commands_r1 import Commands, Signals
        from mac_owned_unreaped_r1 import require_waitid, capture_child, stop_once_unreaped
        from mac_production_t5_guard_r1 import HeldT5
        from mac_public_code_pin_excerpt_r1 import public_code_pin
        from permanent_bootstrap_api_r1 import Api
        signals = Signals(); signals.install(); commands = Commands(signals)
        CONTROL_SIGNALS = signals
        pins = {}
        for name, expected in TOOL_PINS.items():
            value = public_code_pin(name, remaining=remaining, critical=signals.critical)
            need((value['bytes'], value['sha256']) == expected, 'bootstrap_exact_native_tool')
            pins[name] = value
        need(not OPERATIONS.exists() and not OPERATIONS.is_symlink(), 'bootstrap_original_slot_absent')
        anchor = {'schema': 'heptabao.mac-current-t5-public-anchor.r1', 'source_inventory_sha256': hashlib.sha256(encoded(PAYLOAD['pins'])).hexdigest(),
                  'volumeUUID': 'FB804D1B-24CB-4D6E-AEA7-A9E180807758',
                  'expectedVolumeDevice': str(Path('/Volumes/T5').lstat().st_dev),
                  'anchors': [{'path': path, 'identity': list(full9(Path(path).lstat()))} for path in ('/', '/Volumes', '/Volumes/T5')]}
        raw = encoded(anchor)
        guard = HeldT5(raw, hashlib.sha256(raw).hexdigest(), remaining, signals.critical)
        row, out, err = commands.run('bootstrap-t5-volume', ['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'],
                                     until=min(UNTIL, time.monotonic() + 15), maximum=262144)
        need(row['exitCode'] == 0 and not row['outcomeUnknown'] and not err, 'bootstrap_known_t5_volume')
        guard.accept_diskutil(out)
        expected_config = {'listen': '127.0.0.1:31080', 'data_dir': str(ROOT / 'data'),
            'audit_file': str(ROOT / 'log/audit.jsonl'), 'tls_cert_file': str(ROOT / 'tls/server-r2.crt'),
            'tls_key_file': str(ROOT / 'tls/server.key'), 'max_connections': 64, 'timeout_seconds': 15,
            'rate_limit_per_second': 2000, 'rate_limit_burst': 4000, 'rate_limit_entries': 512,
            'storage': {'native_v6_file': {'path': str(ROOT / 'data')}}}
        need(json.loads(guard.read(CONFIG, 16384)) == expected_config, 'bootstrap_exact_loopback_configuration')
        for name, expected in (('ca.crt', CA_SHA), ('server-r2.crt', LEAF_SHA)):
            raw = guard.read(ROOT / 'tls' / name, 16384)
            need(hashlib.sha256(ssl.PEM_cert_to_DER_cert(raw.decode('ascii'))).hexdigest() == expected,
                 'bootstrap_original_independent_certificate')
        key = (ROOT / 'tls/server.key').lstat()
        need(stat.S_ISREG(key.st_mode) and key.st_uid == 501 and key.st_gid == 20 and key.st_nlink == 1
             and stat.S_IMODE(key.st_mode) == 0o600, 'bootstrap_key_metadata_only')
        with guard.parent(ROOT / 'data') as (parent, name):
            directory = open_fd(name, os.O_RDONLY | os.O_DIRECTORY, 'initial-data-directory', dir_fd=parent)
            need(os.listdir(directory['fd']) == [], 'bootstrap_fresh_empty_permanent_data_directory')
            close(directory)
        before_bin = binary_pin()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(('127.0.0.1', PORT))
        operations = PrivateOperations()
        for name, source in PAYLOAD['sources'].items():
            operations.write(name, source.encode())
        operations.write('source-pins.public.json', encoded(PAYLOAD['pins']))
        operations.write('initial-config.private.json', encoded(expected_config))
        protected = {path: full9(path.lstat()) for path in
            (BINARY, CONFIG, ROOT / 'tls/ca.crt', ROOT / 'tls/server-r2.crt', ROOT / 'tls/server.key')}
        class BoundGuard:
            def check(self):
                guard.check(); operations.check()
                for path, expected in protected.items():
                    need(full9(path.lstat()) == expected, 'bootstrap_fixed_configuration_and_binary_generation')
        fence = BoundGuard()
        fence.check()
        need(json.loads(guard.read(CONFIG, 16384)) == expected_config, 'bootstrap_config_readback_before_start')
        need(binary_pin() == before_bin, 'bootstrap_same_original_binary_before_start')
        for name, expected in (('ca.crt', CA_SHA), ('server-r2.crt', LEAF_SHA)):
            raw = guard.read(ROOT / 'tls' / name, 16384)
            need(hashlib.sha256(ssl.PEM_cert_to_DER_cert(raw.decode('ascii'))).hexdigest() == expected,
                 'bootstrap_certificate_readback_before_start')
        fence.check()

        def start_server(phase):
            nonlocal current
            need(current is None and len(process_rows) < 2 and phase in ('initial', 'cold-new-process'), 'bootstrap_finite_server_start')
            require_waitid(); fence.check()
            outputs = [operations.create(phase + '.' + label + '.private.log') for label in ('stdout', 'stderr')]
            intent = {'phase': phase, 'argv': [str(BINARY), '--config', str(CONFIG)], 'state': 'dispatched_or_unknown'}
            operations.append('server-start-intent', intent)
            current = {'phase': phase, 'process': None, 'custody': None, 'stopAttempted': False, 'outputs': outputs}
            process_rows.append(current)
            with signals.critical():
                p = subprocess.Popen(intent['argv'], cwd=str(ROOT), stdin=subprocess.DEVNULL,
                    stdout=outputs[0]['fd'], stderr=outputs[1]['fd'], start_new_session=True, close_fds=True,
                    env={'HOME': str(CALLER_HOME), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'})
                current['process'] = p
            current['custody'] = capture_child(p, until=min(UNTIL, time.monotonic() + 15))
            api = Api({'port': PORT, 'certificateLeafSha256': LEAF_SHA}, phase,
                      min(UNTIL, time.monotonic() + 120), operations, fence)
            apis.append(api)
            return api

        def stop_server():
            nonlocal current
            if current is None:
                return
            need(not current['stopAttempted'], 'bootstrap_original_stop_once')
            current['stopAttempted'] = True
            with signals.critical():
                if current['process'] is not None:
                    current['cleanup'] = stop_once_unreaped(current['process'], current['custody'])
                else:
                    current['cleanup'] = {'ok': False, 'outcomeUnknown': True}
            row = {'phase': current['phase'], 'cleanup': current['cleanup'], 'logs': []}
            for descriptor in current['outputs']:
                os.fsync(descriptor['fd'])
                before = os.fstat(descriptor['fd'])
                need(before.st_size <= 2097152, 'bootstrap_bounded_original_server_log')
                os.lseek(descriptor['fd'], 0, os.SEEK_SET)
                content = bytearray()
                while True:
                    block = os.read(descriptor['fd'], min(65536, 2097153 - len(content)))
                    if not block:
                        break
                    content.extend(block)
                    need(len(content) <= 2097152, 'bootstrap_server_log_limit')
                need(len(content) == before.st_size and full9(before) == full9(os.fstat(descriptor['fd'])), 'bootstrap_stopped_original_log_stable')
                row['logs'].append({'bytes': len(content), 'containsCredentialPlaintext': any(value.encode() in content for value in sensitive if value)})
                close(descriptor)
            need(current['cleanup'].get('ok') is True and not any(item['containsCredentialPlaintext'] for item in row['logs']), 'bootstrap_original_server_closed_private_logs')
            operations.append('server-stop-result', row)
            REPORT['serverProcesses'].append(row)
            current = None

        api = start_server('initial')
        health = api.call('initial.health', 'GET', '/v1/sys/health', token='', expected=501, category='health', readiness=True)
        api.check('initial.uninitialized', health.get('initialized') is False and health.get('sealed') is True)
        initialized = api.call('initial.init_once', 'POST', '/v1/sys/init', {'secret_shares': 1, 'secret_threshold': 1}, token='', category='init')
        root_token, unseal = initialized.get('root_token'), initialized.get('keys_base64', [None])[0]
        need(isinstance(root_token, str) and len(root_token) >= 8 and isinstance(unseal, str) and len(unseal) >= 8, 'bootstrap_original_init_material')
        sensitive.extend((root_token, unseal))
        operations.append('bootstrap-recovery', {'rootToken': root_token, 'unsealKey': unseal})
        REPORT['permanentStoreInitialized'] = True
        api.root_token = root_token
        api.check('initial.unsealed', api.call('initial.unseal', 'POST', '/v1/sys/unseal', {'key': unseal}, token='', category='unseal').get('sealed') is False)
        api.call('initial.kv_mount', 'POST', '/v1/sys/mounts/openclaw-auth', {'type': 'kv', 'options': {'version': '2'}}, expected=204, category='mount')
        api.call('initial.approle_mount', 'POST', '/v1/sys/auth/approle', {'type': 'approle'}, expected=204, category='mount')
        api.call('initial.native_activate', 'POST', '/v1/sys/storage/native-v6/activate', {}, expected=204, category='activate')
        api.check('initial.native_format_two', api.call('initial.capacity', 'GET', '/v1/sys/internal/capacity', category='capacity').get('data', {}).get('native_kv2_reader_format') == 2)
        value = {'schema': 'heptabao.permanent-bootstrap-probe.r1', 'marker': os.urandom(16).hex()}
        api.check('initial.version_one', api.call('initial.seed', 'POST', SECRET_PATH, {'data': value, 'options': {'cas': 0}}, category='kv-write').get('data', {}).get('version') == 1)
        policy = 'path "openclaw-auth/data/qualification/bootstrap-lifecycle-r1" { capabilities=["read","update"] }\npath "auth/token/lookup-self" { capabilities=["read"] }\npath "auth/token/renew-self" { capabilities=["update"] }\npath "auth/token/revoke-self" { capabilities=["update"] }\n'
        api.call('initial.policy', 'PUT', '/v1/sys/policies/acl/' + ROLE, {'policy': policy}, expected=204, category='policy')
        base = '/v1/auth/approle/role/' + ROLE
        api.call('initial.role', 'POST', base, {'token_policies': [ROLE], 'token_ttl': '1200s', 'token_max_ttl': '3600s', 'secret_id_num_uses': 0, 'secret_id_ttl': '3600s'}, expected=204, category='role')
        role_id = api.call('initial.role_id', 'GET', base + '/role-id', category='role-id')['data']['role_id']
        secret_id = api.call('initial.secret_id', 'POST', base + '/secret-id', {}, category='secret-id')['data']['secret_id']
        sensitive.extend((role_id, secret_id))
        login = {'role_id': role_id, 'secret_id': secret_id}
        auth = api.call('initial.login', 'POST', '/v1/auth/approle/login', login, token='', category='login')['auth']
        token = auth['client_token']; sensitive.append(token)
        api.check('initial.renewable', auth.get('renewable') is True and ROLE in auth.get('policies', []))
        api.check('initial.scoped_read', api.call('initial.scoped_read', 'GET', SECRET_PATH, token=token, category='kv-read')['data']['data'] == value)
        api.check('initial.scoped_write', api.call('initial.scoped_write', 'POST', SECRET_PATH, {'data': value, 'options': {'cas': 1}}, token=token, category='kv-write')['data']['version'] == 2)
        api.call('initial.other_key_denied', 'GET', '/v1/openclaw-auth/data/qualification/other', token=token, expected=403, category='kv-read')
        api.call('initial.admin_denied', 'GET', '/v1/sys/mounts', token=token, expected=403, category='admin-denied')
        renewed = api.call('initial.renew', 'POST', '/v1/auth/token/renew-self', {'increment': '1200s'}, token=token, category='renew')['auth']
        api.check('initial.same_token_renewal', renewed.get('client_token') == token and renewed.get('renewable') is True and renewed.get('lease_duration', 0) > 0)
        operations.write('temporary-role.private.json', encoded({'roleId': role_id, 'secretId': secret_id, 'token': token}))
        stop_server()

        cold = start_server('cold-new-process'); cold.root_token = root_token
        health = cold.call('cold.health', 'GET', '/v1/sys/health', token='', expected=503, category='health', readiness=True)
        cold.check('cold.sealed_existing', health.get('initialized') is True and health.get('sealed') is True)
        cold.check('cold.unsealed', cold.call('cold.unseal', 'POST', '/v1/sys/unseal', {'key': unseal}, token='', category='unseal').get('sealed') is False)
        cold.check('cold.native_format_two', cold.call('cold.capacity', 'GET', '/v1/sys/internal/capacity', category='capacity').get('data', {}).get('native_kv2_reader_format') == 2)
        stored = cold.call('cold.old_token_read', 'GET', SECRET_PATH, token=token, category='kv-read')['data']
        cold.check('cold.version_and_value_persisted', stored['metadata']['version'] == 2 and stored['data'] == value)
        fresh = cold.call('cold.new_login', 'POST', '/v1/auth/approle/login', login, token='', category='login')['auth']['client_token']
        sensitive.append(fresh); cold.check('cold.distinct_new_token', fresh != token)
        cold.check('cold.new_token_read', cold.call('cold.new_token_read', 'GET', SECRET_PATH, token=fresh, category='kv-read')['data']['data'] == value)
        for ordinal, bearer in enumerate((token, fresh), 1):
            cold.call('cold.revoke_' + str(ordinal), 'POST', '/v1/auth/token/revoke-self', {}, token=bearer, expected=204, category='revoke')
            cold.call('cold.revoked_read_' + str(ordinal), 'GET', SECRET_PATH, token=bearer, expected=403, category='kv-read')
        cold.call('cold.destroy_sid', 'POST', base + '/secret-id/destroy', {'secret_id': secret_id}, expected=204, category='secret-destroy')
        cold.call('cold.destroyed_sid_denied', 'POST', '/v1/auth/approle/login', login, token='', expected=400, category='login')
        stop_server()
        need(binary_pin() == before_bin, 'bootstrap_original_binary_unchanged')
        for name in pins:
            need(public_code_pin(name, remaining=remaining, critical=signals.critical) == pins[name], 'bootstrap_native_tools_unchanged')
        need(full9(key) == full9((ROOT / 'tls/server.key').lstat()), 'bootstrap_original_private_key_metadata_unchanged')
        guard.check(); operations.check()
        REPORT.update(ok=True, independentPermanentTlsAppRoleKvPolicyRenewRevokeQualified=True,
                      actualColdRestartQualified=True, actualCurrentCredentialReadWriteQualified=False,
                      permanentServiceInstalled=False, finalServerRunning=False)
        operations.write('business-phase-complete.private.json', encoded({
            'schema': 'heptabao.permanent-bootstrap-business-phase.r1',
            'businessChecksComplete': True, 'finalResourceClosureNotYetObserved': True,
            'notSufficientForFurtherActionWithoutOriginalTerminalAndFreshState': True}))
    except BaseException as error:
        REPORT['errorType'] = type(error).__name__
        REPORT['errorCode'] = str(error) if isinstance(error, Refused) and re.fullmatch(r'[a-z0-9._-]{1,120}', str(error)) else 'bootstrap_failed_no_replay'
    finally:
        if current is not None:
            try:
                stop_server()
            except BaseException as error:
                REPORT['finalServerClosureError'] = type(error).__name__
                REPORT['ok'] = False
        REPORT['apiPhases'] = [api.public() for api in apis]
        REPORT['originalServerCleanupRecords'] = [{'phase': row['phase'], 'stopAttempted': row['stopAttempted'],
            'pid': row['process'].pid if row['process'] is not None else None,
            'cleanup': row.get('cleanup')} for row in process_rows]
        REPORT['allOriginalServersClosed'] = all(row['stopAttempted'] and row.get('cleanup', {}).get('ok') is True for row in process_rows)
        if guard is not None:
            try:
                guard.close()
            except BaseException:
                REPORT['ok'] = False
            REPORT['volumeClosure'] = guard.public_state()
        errors = []
        for row in reversed(FDS):
            try:
                close(row)
            except BaseException as error:
                errors.append(type(error).__name__)
        REPORT['allExplicitDescriptorsClosedOnce'] = all(row['attempts'] == 1 and row['closed'] for row in FDS)
        REPORT['explicitDescriptors'] = len(FDS)
        REPORT['descriptorCloseErrors'] = errors
        REPORT['commands'] = commands.public() if commands is not None else {'allOwnedCommandsStopped': True, 'unknownCommandCount': 0, 'commands': []}
        REPORT['deadlineAfterClosure'] = time.monotonic() < UNTIL
        REPORT['cancellationObserved'] = CONTROL_SIGNALS is not None and CONTROL_SIGNALS.pending is not None
        REPORT['ok'] = bool(REPORT['ok'] and REPORT['allOriginalServersClosed'] and REPORT['allExplicitDescriptorsClosedOnce']
            and not errors and REPORT['commands']['allOwnedCommandsStopped'] and REPORT['commands']['unknownCommandCount'] == 0
            and REPORT['deadlineAfterClosure'] and not REPORT['cancellationObserved']
            and REPORT.get('volumeClosure', {}).get('lastAnchorCheckPassed') and REPORT['volumeClosure']['allDescriptorsClosed'])
        REPORT['elapsedSeconds'] = time.monotonic() - START
        print(json.dumps(REPORT, sort_keys=True), flush=True)
    return 0 if REPORT['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
