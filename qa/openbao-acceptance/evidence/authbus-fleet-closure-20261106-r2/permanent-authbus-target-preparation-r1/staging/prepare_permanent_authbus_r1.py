#!/usr/bin/env python3
"""Create-only independent trust/runtime staging; no service or API dispatch."""
import ast
import hashlib
import json
import os
from pathlib import Path
import plistlib
import ssl
import stat
import sys
import time
import types

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-authbus-production')
HOME = Path('/Users/qianqi')
CUSTODY = HOME / 'heptabao-authbus-production-custody'
BACKUPS = HOME / 'heptabao-authbus-production-backups'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
SOURCE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/build-test-4bde9-r1/artifacts/heptabao-server')
PRODUCT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
BIN_SHA = '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
BIN_BYTES = 92359328
TOOL_PINS = {
    str(PYTHON): (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'),
    '/usr/bin/openssl': (1130832, 'f81b4fcec5048ea1eceb40fc08f4e06f1668181f0b5bacfa8be27d0da181dcb7'),
    '/usr/sbin/diskutil': (1937776, '624a8601b97ddfaa4b18dd2854c299e084cd45eb18fc152011c97615c3b9da1f'),
    '/bin/ps': (170432, '3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c'),
}
PAYLOAD = {'sources': {'mac_owned_unreaped_r1.py': '#!/usr/bin/env python3\n"""Retained direct-child custody for Mac phase workers.\n\nDerived from canonical native_ha_foreground_watchdog.py 74925449. No child is\nstarted here. WNOWAIT observes exit; it never makes the numeric PGID reusable\nbefore signaling. Cleanup keeps the previous wrapper\'s TERM1 / wait5 /\ngroup3 limits and PS4 maximum. No stage grants business more than phase120.\n"""\nimport hashlib, os, signal, stat, subprocess, time\n\nMIB=1024*1024\nclass Refusal(RuntimeError): pass\ndef need(value,code):\n    if not value:raise Refusal(code)\n\n# Only this observed system helper may cross effective UID at exec. No target\n# service, arbitrary argv, descendant, or unrelated command gets this exception.\nFIXED_PS_ARGV=(\'/bin/ps\',\'-axo\',\'pid=,ppid=,pgid=,uid=,stat=\')\nFIXED_PS_SHA256=\'3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c\'\nFIXED_PS_BYTES=170432\nFIXED_PS_IDENTITY=(16777233,1152921500312571399,0,0,35309,1,170432,\n    1786589515000000000,1786589515000000000)\n\ndef fixed_ps_identity(value):\n    return tuple(getattr(value,name) for name in (\'st_dev\',\'st_ino\',\'st_uid\',\'st_gid\',\n        \'st_mode\',\'st_nlink\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\'))\n\ndef fixed_ps_pin(*,until):\n    need(os.getuid()==501 and os.geteuid()==501,\'fixed_ps_requires_exact_caller\')\n    need(time.monotonic()<until,\'original_command_deadline_exhausted\')\n    path=FIXED_PS_ARGV[0]\n    before=os.lstat(path)\n    need(fixed_ps_identity(before)==FIXED_PS_IDENTITY and stat.S_ISREG(before.st_mode)\n         and stat.S_IMODE(before.st_mode)==0o4755,\'fixed_ps_system_file_identity\')\n    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)\n    try:\n        need(fixed_ps_identity(os.fstat(fd))==FIXED_PS_IDENTITY,\'fixed_ps_open_file_identity\')\n        raw=bytearray()\n        while len(raw)<=FIXED_PS_BYTES:\n            need(time.monotonic()<until,\'original_command_deadline_exhausted\')\n            part=os.read(fd,min(65536,FIXED_PS_BYTES+1-len(raw)))\n            if not part:break\n            raw.extend(part)\n        need(len(raw)==FIXED_PS_BYTES and hashlib.sha256(raw).hexdigest()==FIXED_PS_SHA256,\n             \'fixed_ps_whole_file_hash\')\n        need(fixed_ps_identity(os.fstat(fd))==fixed_ps_identity(os.lstat(path))==FIXED_PS_IDENTITY,\n             \'fixed_ps_named_file_unchanged\')\n        need(time.monotonic()<until,\'original_command_deadline_exhausted\')\n        return {\'identity\':list(FIXED_PS_IDENTITY),\'sha256\':FIXED_PS_SHA256}\n    finally:\n        os.close(fd)\n\ndef prepare_fixed_ps_contract(argv,*,until):\n    if not argv or argv[0]!=FIXED_PS_ARGV[0]:return None\n    need(tuple(argv)==FIXED_PS_ARGV,\'fixed_ps_exact_argv_before_launch\')\n    return {\'schema\':\'heptabao.fixed-system-ps-child.r1\',\'argv\':list(FIXED_PS_ARGV),\n        \'launcherPid\':os.getpid(),\'callerUid\':501,\'pin\':fixed_ps_pin(until=until)}\n\ndef verify_fixed_ps_contract(child,contract,*,until):\n    need(isinstance(contract,dict) and set(contract)=={\'schema\',\'argv\',\'launcherPid\',\'callerUid\',\'pin\'}\n         and contract[\'schema\']==\'heptabao.fixed-system-ps-child.r1\'\n         and contract[\'argv\']==list(FIXED_PS_ARGV)\n         and tuple(child.args)==FIXED_PS_ARGV\n         and contract[\'launcherPid\']==os.getpid() and contract[\'callerUid\']==501\n         and child.returncode is None and type(child.pid) is int and child.pid>1,\n         \'fixed_ps_direct_child_contract\')\n    need(contract[\'pin\']==fixed_ps_pin(until=until),\'fixed_ps_prelaunch_binding_changed\')\n    return True\n\ndef fixed_ps_group_uid(row,child,owner):\n    if owner.get(\'fixedPsContract\') is None:return row[\'uid\']==os.geteuid()\n    return row[\'pid\']==child.pid and stable(row)==owner[\'ps\'] and row[\'uid\']==0\n\ndef require_waitid():\n    need(all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT",\n                                          "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED")),\n         "wnowait_required_no_child_started")\n    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,\n         "direct_child_reaping_policy_changed")\n\ndef exit_observation(child):\n    """This is an observation, never Popen.poll/wait/communicate."""\n    need(child.returncode is None, "child_already_reaped_no_signal")\n    event = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)\n    if event is None:\n        return None\n    need(event.si_pid == child.pid and event.si_signo == signal.SIGCHLD\n         and event.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED),\n         "child_exit_identity_changed")\n    # Darwin reports si_uid=0 even for an observed uid501 child. Actual UID is\n    # bound independently by ps; si_uid never grants ownership here.\n    return {"pid": event.si_pid, "signo": event.si_signo, "code": event.si_code, "status": event.si_status}\n\ndef stable(row):\n    return {key: row[key] for key in ("pid", "ppid", "pgid", "uid", "start")}\n\ndef ps_rows(pid=None, *, seconds=4.0, until=None):\n    if until is not None:\n        remaining = until - time.monotonic()\n        need(remaining > 0, "original_stop_deadline_expired")\n        seconds = min(seconds, remaining)\n    argv = ["/bin/ps"]\n    argv += ["-p", str(pid)] if pid is not None else ["-ax"]\n    argv += ["-o", "pid=,ppid=,pgid=,uid=,stat=,lstart="]\n    try:\n        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,\n                                stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C"),\n                                timeout=seconds)\n    except subprocess.TimeoutExpired as error:\n        code = ("original_stop_deadline_expired" if until is not None and time.monotonic() >= until\n                else "process_projection_deadline_expired")\n        raise Refusal(code) from error\n    if until is not None:\n        need(time.monotonic() < until, "original_stop_deadline_expired")\n    need(len(result.stdout) <= 2 * MIB and len(result.stderr) <= 65536,\n         "process_projection_bound")\n    if pid is not None and result.returncode == 1 and not result.stdout.strip():\n        return []\n    need(result.returncode == 0, "process_projection_unavailable")\n    rows = []\n    for line in result.stdout.decode("ascii").splitlines():\n        fields = line.split(None, 5)\n        need(len(fields) == 6, "process_projection_malformed")\n        rows.append({"pid": int(fields[0]), "ppid": int(fields[1]),\n                     "pgid": int(fields[2]), "uid": int(fields[3]),\n                     "state": fields[4], "start": fields[5]})\n    if pid is not None:\n        need(len(rows) == 1 and rows[0]["pid"] == pid, "process_projection_ambiguous")\n    return rows\n\ndef capture_child(child, *, until, fixed_ps_contract=None):\n    require_waitid()\n    rows = ps_rows(child.pid, until=until)\n    need(len(rows) == 1, "owned_child_identity_missing")\n    row = rows[0]\n    special=fixed_ps_contract is not None\n    if special:verify_fixed_ps_contract(child,fixed_ps_contract,until=until)\n    need(row["ppid"] == os.getpid() and row["pgid"] == child.pid\n         and row["uid"] == (0 if special else os.geteuid()), "owned_child_scope_mismatch")\n    # Darwin keeps an unreaped zombie in ps but getpgid/getsid return ESRCH.\n    # Use the real live APIs only for a still-live child; otherwise independently\n    # repeat WNOWAIT and retain ps plus Popen direct-parent custody.\n    event, live_sid = exit_observation(child), None\n    if event is None and not row["state"].startswith("Z"):\n        try:\n            need(os.getpgid(child.pid) == child.pid and os.getsid(child.pid) == child.pid,\n                 "owned_live_session_mismatch")\n            live_sid = child.pid\n        except ProcessLookupError:\n            # A fast exit between the first ps/waitid and a live API call is\n            # not loss of Popen custody, nor proof that the group is empty.\n            event = exit_observation(child)\n            need(event is not None, "owned_live_api_failed_without_retained_exit")\n    if event is not None or row["state"].startswith("Z"):\n        event = exit_observation(child)\n        fresh = ps_rows(child.pid, until=until)\n        need(event is not None and len(fresh) == 1 and stable(fresh[0]) == stable(row)\n             and fresh[0]["state"].startswith("Z") and exit_observation(child) == event,\n             "owned_exit_not_retained")\n        row = fresh[0]\n    return {"ps": stable(row), "sid_observed_while_live": live_sid,\n            "captured_exit": event,"fixedPsContract":fixed_ps_contract}\n\ndef verify_unreaped(child, owner, *, until=None):\n    if owner.get(\'fixedPsContract\') is not None:\n        need(until is not None,\'fixed_ps_requires_existing_deadline\')\n        verify_fixed_ps_contract(child,owner[\'fixedPsContract\'],until=until)\n    event = exit_observation(child)\n    rows = ps_rows(child.pid, until=until)\n    need(len(rows) == 1 and stable(rows[0]) == owner["ps"]\n         and rows[0]["ppid"] == os.getpid(), "owned_child_identity_changed_no_signal")\n    if event is None and not rows[0]["state"].startswith("Z"):\n        # Exact ps PGID/start plus direct Popen/WNOWAIT custody keeps the\n        # originally observed session leader reserved. Do not race a normal\n        # exit by consulting Darwin\'s zombie-unsupported getpgid/getsid here.\n        need(owner["ps"]["pgid"] == child.pid, "owned_live_session_changed_no_signal")\n    else:\n        event = exit_observation(child)\n        need(event is not None and rows[0]["state"].startswith("Z") and exit_observation(child) == event,\n             "owned_zombie_identity_changed_no_signal")\n    return event\n\ndef live_group(child, owner, *, until):\n    need(time.monotonic() < until, "original_stop_deadline_expired")\n    verify_unreaped(child, owner, until=until)\n    rows = ps_rows(until=until)\n    if owner.get("fixedPsContract") is not None:\n        related=[row for row in rows if row["pgid"]==child.pid or row["ppid"]==child.pid]\n        need(all(row["pid"]==child.pid and stable(row)==owner["ps"] for row in related),\n             "fixed_ps_no_other_group_or_direct_child")\n    selected = [row for row in rows if row["pgid"] == child.pid and not row["state"].startswith("Z")]\n    need(all(fixed_ps_group_uid(row,child,owner) for row in selected), "owned_group_uid_changed_no_signal")\n    need(time.monotonic() < until, "original_stop_deadline_expired")\n    return [stable(row) for row in selected]\n\ndef observed_returncode(event):\n    if event is None:return None\n    return event[\'status\'] if event[\'code\']==os.CLD_EXITED else -event[\'status\']\n\ndef stop_once_unreaped(child, owner, *, fixed_ps_contract=None):\n    """Called once by the wrapper\'s protected ledger; never calls Popen.poll."""\n    require_waitid()\n    started=time.monotonic()\n    receipt={\'pid\':child.pid,\'pgid\':child.pid,\'stopAttempted\':True,\'signals\':[],\n             \'directChildReaped\':False,\'ownedLiveGroupEmptyBeforeReap\':False,\n             \'allGroupRowsEmptyAfterReap\':False,\'cleanupCaps\':{\'term\':1,\'wait\':5,\'group\':3,\'psMax\':4},\n             \'postReapSignalSent\':False,\'custody\':owner}\n    try:\n        need(child.returncode is None,\'already_reaped_no_group_signal\')\n        term_until=time.monotonic()+1.0\n        if owner is None:\n            owner=capture_child(child,until=term_until,fixed_ps_contract=fixed_ps_contract)\n            receipt[\'custody\']=owner\n        members=live_group(child,owner,until=term_until)\n        receipt[\'initialLiveGroup\']=members\n        if members:\n            verify_unreaped(child,owner,until=term_until)\n            need(time.monotonic()<term_until,\'original_stop_deadline_expired\')\n            os.killpg(child.pid,signal.SIGTERM);receipt[\'signals\'].append(\'SIGTERM\')\n            while time.monotonic()<term_until:\n                try:\n                    members=live_group(child,owner,until=term_until)\n                    if not members:break\n                except Refusal as error:\n                    if str(error)!=\'original_stop_deadline_expired\' or time.monotonic()<term_until:\n                        raise\n                    break\n                time.sleep(min(0.02,max(0,term_until-time.monotonic())))\n        wait_until=time.monotonic()+5.0\n        members=live_group(child,owner,until=wait_until)\n        if members:\n            verify_unreaped(child,owner,until=wait_until)\n            need(time.monotonic()<wait_until,\'original_stop_deadline_expired\')\n            os.killpg(child.pid,signal.SIGKILL);receipt[\'signals\'].append(\'SIGKILL\')\n        event=exit_observation(child)\n        while event is None:\n            verify_unreaped(child,owner,until=wait_until)\n            need(time.monotonic()<wait_until,\'original_stop_deadline_expired\')\n            time.sleep(min(0.02,max(0,wait_until-time.monotonic())))\n            event=exit_observation(child)\n        need(time.monotonic()<wait_until,\'original_stop_deadline_expired\')\n        receipt[\'retainedExit\']=event\n        # The old post-exit group3 interval now precedes the first reap.\n        # This retains actual Popen PID custody while other live members leave.\n        group_until=time.monotonic()+3.0\n        while True:\n            members=live_group(child,owner,until=group_until)\n            if not members and exit_observation(child)==event:break\n            need(time.monotonic()<group_until,\'original_stop_deadline_expired\')\n            time.sleep(min(0.02,max(0,group_until-time.monotonic())))\n        receipt[\'ownedLiveGroupEmptyBeforeReap\']=True\n        need(time.monotonic()<group_until,\'original_stop_deadline_expired\')\n        child.wait(timeout=group_until-time.monotonic())\n        receipt[\'directChildReaped\']=True\n        receipt[\'exitCode\']=child.returncode\n        need(child.returncode==observed_returncode(event),\'actual_reap_matches_retained_exit\')\n        # After the first reap, only observe. No signal or ownership claim is\n        # derived from this now-reusable numeric PGID.\n        while True:\n            rows=[row for row in ps_rows(until=group_until) if row[\'pgid\']==child.pid]\n            receipt[\'remainingGroupRows\']=rows\n            if not rows:break\n            need(time.monotonic()<group_until,\'original_stop_deadline_expired\')\n            time.sleep(min(0.02,max(0,group_until-time.monotonic())))\n        receipt[\'allGroupRowsEmptyAfterReap\']=True\n        need(time.monotonic()<group_until,\'original_stop_deadline_expired\')\n        receipt[\'ok\']=True\n    except BaseException as error:\n        receipt[\'ok\']=False\n        receipt[\'errorType\']=type(error).__name__\n        receipt[\'errorCode\']=str(error) if isinstance(error,Refusal) else None\n        receipt[\'directChildReaped\']=child.returncode is not None\n        receipt[\'exitCode\']=child.returncode\n        # No second signal sequence, no renewed deadline, no automatic retry.\n    receipt[\'elapsedSeconds\']=time.monotonic()-started\n    receipt[\'outcomeUnknown\']=not(receipt.get(\'ok\') is True\n       and receipt[\'directChildReaped\'] and receipt[\'allGroupRowsEmptyAfterReap\'])\n    return receipt\n', 'mac_owned_commands_r1.py': '#!/usr/bin/env python3\n"""Bounded foreground commands with retained direct-child custody.\n\nNo import-time I/O. The caller supplies exact reviewed argv and an absolute\ncommand deadline. Pipe reads, exit observation and metadata capture share it.\nCleanup uses the separate once-only TERM1/wait5/group3 custody contract.\n"""\nfrom __future__ import annotations\nfrom contextlib import contextmanager\nimport hashlib, os, select, signal, subprocess, time\nfrom mac_owned_unreaped_r1 import require_waitid, capture_child, exit_observation, observed_returncode, stop_once_unreaped, prepare_fixed_ps_contract\n\nclass CommandRefused(RuntimeError):pass\ndef need(value,code):\n    if not value:raise CommandRefused(code)\ndef sha(raw):return hashlib.sha256(raw).hexdigest()\n\nclass Signals:\n    def __init__(self):\n        self.protected=0;self.pending=None\n    def receive(self,signum,_frame):\n        self.pending=signum\n        if not self.protected:raise KeyboardInterrupt()\n    def install(self):\n        signal.signal(signal.SIGTERM,self.receive);signal.signal(signal.SIGINT,self.receive)\n    @contextmanager\n    def critical(self):\n        self.protected+=1\n        try:yield\n        finally:self.protected-=1\n\nclass Commands:\n    def __init__(self,signals):\n        self.signals=signals;self.rows=[]\n    def run(self,label,argv,*,until,allow_cancelled_cleanup=False,maximum=2*1024*1024):\n        need(isinstance(label,str) and label.replace(\'-\',\'\').replace(\'_\',\'\').isalnum(),\'safe_command_label\')\n        need(type(maximum) is int and 0<maximum<=2*1024*1024,\'fixed_command_output_bound\')\n        need(isinstance(argv,list) and argv and all(isinstance(x,str) for x in argv),\'explicit_argv\')\n        def remaining():\n            if not allow_cancelled_cleanup:need(self.signals.pending is None,\'command_cancelled\')\n            n=until-time.monotonic();need(n>0,\'original_command_deadline_exhausted\');return n\n        require_waitid();remaining()\n        fixed_ps_contract=prepare_fixed_ps_contract(argv,until=until)\n        remaining()\n        started=time.monotonic();row=None;out=bytearray();err=bytearray()\n        try:\n            with self.signals.critical():\n                remaining()\n                p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,\n                    env={\'PATH\':\'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin\',\'LANG\':\'C\',\'LC_ALL\':\'C\'},\n                    start_new_session=True,close_fds=True)\n                row={\'label\':label,\'argv\':list(argv),\'process\':p,\'custody\':None,\n                     \'stopAttempted\':False,\'streamsCloseAttempted\':False,\'streamsClosed\':False,\n                     \'completeBeforeDeadline\':False,\'errorType\':None,\'errorCode\':None}\n                self.rows.append(row)\n            row[\'custody\']=capture_child(p,until=until,fixed_ps_contract=fixed_ps_contract)\n            streams={p.stdout.fileno():out,p.stderr.fileno():err}\n            for fd in streams:os.set_blocking(fd,False)\n            event=None\n            while streams or event is None:\n                left=remaining()\n                ready,_,_=select.select(list(streams),[],[],min(left,0.025))\n                for fd in ready:\n                    data=os.read(fd,65536)\n                    if not data:del streams[fd]\n                    else:\n                        target=streams[fd];target.extend(data)\n                        need(len(target)<=maximum,\'command_output_bound\')\n                event=exit_observation(p)\n            remaining()\n            row[\'completeBeforeDeadline\']=True\n            row[\'observedExit\']=event\n            row[\'observedExitCode\']=observed_returncode(event)\n        except BaseException as error:\n            if row is None:raise\n            row[\'errorType\']=type(error).__name__\n            row[\'errorCode\']=str(error) if isinstance(error,CommandRefused) else None\n        finally:\n            if row is not None:\n                with self.signals.critical():\n                    row[\'stopAttempted\']=True\n                    try:row[\'cleanup\']=stop_once_unreaped(row[\'process\'],row[\'custody\'],fixed_ps_contract=fixed_ps_contract)\n                    except BaseException as error:\n                        row[\'cleanup\']={\'ok\':False,\'outcomeUnknown\':True,\n                            \'errorType\':type(error).__name__,\'directChildReaped\':row[\'process\'].returncode is not None,\n                            \'allGroupRowsEmptyAfterReap\':False}\n                    row[\'streamsCloseAttempted\']=True\n                    errors=[]\n                    for stream in (row[\'process\'].stdout,row[\'process\'].stderr):\n                        try:stream.close()\n                        except BaseException as error:errors.append(type(error).__name__)\n                    row[\'streamsClosed\']=not errors\n                    row[\'streamCloseErrors\']=errors\n        p=row[\'process\'];cleanup=row[\'cleanup\']\n        public={\'label\':label,\'argv\':list(argv),\'pid\':p.pid,\'exitCode\':p.returncode,\n            \'completeBeforeDeadline\':row[\'completeBeforeDeadline\'],\n            \'commandDeadlineMonotonic\':until,\'elapsedSeconds\':time.monotonic()-started,\n            \'errorType\':row[\'errorType\'],\'errorCode\':row[\'errorCode\'],\'cleanup\':cleanup,\n            \'stdoutBytes\':len(out),\'stdoutSha256\':sha(out),\'stderrBytes\':len(err),\'stderrSha256\':sha(err),\n            \'streamsClosed\':row[\'streamsClosed\'],\n            \'outcomeUnknown\':not(row[\'completeBeforeDeadline\'] and cleanup.get(\'ok\') is True\n                and cleanup.get(\'directChildReaped\') is True and cleanup.get(\'allGroupRowsEmptyAfterReap\') is True\n                and row[\'streamsClosed\'] and row[\'errorType\'] is None)}\n        row[\'public\']=public\n        return public,bytes(out),bytes(err)\n    def public(self):\n        values=[r.get(\'public\') for r in self.rows]\n        return {\'commands\':values,\'allOwnedCommandsStopped\':all(v is not None\n            and v[\'cleanup\'].get(\'directChildReaped\') is True\n            and v[\'cleanup\'].get(\'allGroupRowsEmptyAfterReap\') is True\n            and v[\'streamsClosed\'] for v in values),\n            \'unknownCommandCount\':sum(v is None or v[\'outcomeUnknown\'] for v in values)}\n', 'mac_public_code_pin_excerpt_r1.py': '#!/usr/bin/env python3\n"""Public-code pin excerpt only; no current config or credential capture code.\n\nBodies are byte-identical to the original guarded capture source. This excerpt\nhas not independently qualified a fresh manager; its caller must bind and test\nits actual use. The original full source SHA is recorded in provenance.\n"""\nimport hashlib, os, stat\nfrom pathlib import Path\n\nMIB=1024*1024\n\nclass CaptureRefused(RuntimeError):pass\ndef need(value,code):\n    if not value:raise CaptureRefused(code)\n\ndef identity(s):\n    return tuple(str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,\n                                 s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))\n\ndef public_code_pin(path,*,remaining,critical):\n    # Public interpreter/extension/source hashes have their own fixed 64MiB\n    # per-file bound. They do not pretend to be measured SQLite page I/O.\n    remaining();path=Path(path).resolve(strict=True)\n    with critical():\n        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\n    try:\n        before=os.fstat(fd)\n        need(stat.S_ISREG(before.st_mode) and 0<before.st_size<=64*MIB\n             and not stat.S_IMODE(before.st_mode)&0o022,\'public_runtime_code_custody\')\n        digest=hashlib.sha256();count=0\n        while count<=before.st_size:\n            remaining()\n            raw=os.read(fd,min(MIB,before.st_size+1-count))\n            if not raw:break\n            count+=len(raw);digest.update(raw)\n        need(count==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),\n             \'public_runtime_code_changed\')\n        remaining()\n        result={\'path\':str(path),\'bytes\':count,\'sha256\':digest.hexdigest()}\n    finally:\n        with critical():os.close(fd)\n    remaining()\n    return result\n\n', 'mac_production_t5_guard_r1.py': '#!/usr/bin/env python3\n"""Held, observed T5 anchors and scoped descriptor-relative owned I/O.\n\nNo module-level I/O. No private path is opened before both the exact public\nanchor input and actual owned diskutil output have been checked. This module\ndoes not run diskutil or claim a volume-wide atomic snapshot.\n"""\nfrom __future__ import annotations\nfrom contextlib import contextmanager\nimport hashlib, json, os, plistlib, stat, time\nfrom pathlib import Path\n\nMOUNT = Path(\'/Volumes/T5\')\nROOT = MOUNT / \'hepta-vnext-recovery-20261013/heptabao-authbus-production\'\nUUID = \'FB804D1B-24CB-4D6E-AEA7-A9E180807758\'\nANCHOR_PATHS = (\'/\', \'/Volumes\', \'/Volumes/T5\')\n\nclass VolumeRefused(RuntimeError): pass\n\ndef require(value, code):\n    if not value: raise VolumeRefused(code)\n\ndef identity(info):\n    return tuple(str(x) for x in (info.st_dev, info.st_ino, info.st_uid,\n        info.st_gid, info.st_mode, info.st_nlink, info.st_size,\n        info.st_mtime_ns, info.st_ctime_ns))\n\ndef inode_identity(info):\n    return identity(info)[:5]\n\nclass HeldT5:\n    def __init__(self, raw_public, expected_sha256, remaining, critical):\n        require(isinstance(raw_public, bytes) and len(raw_public) <= 8192,\n                \'public_anchor_input_bound\')\n        require(hashlib.sha256(raw_public).hexdigest() == expected_sha256,\n                \'public_anchor_whole_sha\')\n        expected = json.loads(raw_public)\n        require(set(expected) == {\'schema\', \'source_inventory_sha256\', \'volumeUUID\',\n                  \'expectedVolumeDevice\', \'anchors\'}\n          and expected[\'schema\'] == \'heptabao.mac-current-t5-public-anchor.r1\'\n          and expected[\'volumeUUID\'] == UUID, \'public_anchor_schema\')\n        require([x.get(\'path\') for x in expected[\'anchors\']] == list(ANCHOR_PATHS),\n                \'exact_public_anchor_paths\')\n        require(all(set(x) == {\'path\',\'identity\'} and len(x[\'identity\']) == 9\n                    and all(isinstance(v,str) and v.isdecimal() for v in x[\'identity\'])\n                    for x in expected[\'anchors\']), \'public_anchor_identity_shape\')\n        require(isinstance(expected[\'expectedVolumeDevice\'],str)\n                and expected[\'expectedVolumeDevice\'].isdecimal()\n                and expected[\'expectedVolumeDevice\'] == expected[\'anchors\'][2][\'identity\'][0],\n                \'captured_volume_device\')\n        self.expected, self.remaining, self.critical = expected, remaining, critical\n        self.rows, self.anchors = [], []\n        self.uuid_verified = False\n        self.closed = False\n        self.close_errors = []\n        self.last_anchor_check = False\n        try:\n            parent = None\n            for index, item in enumerate(expected[\'anchors\']):\n                self.remaining()\n                name = \'/\' if index == 0 else Path(item[\'path\']).name\n                named = os.lstat(\'/\') if index == 0 else os.stat(\n                    name, dir_fd=parent[\'fd\'], follow_symlinks=False)\n                require(stat.S_ISDIR(named.st_mode) and identity(named) == tuple(item[\'identity\']),\n                        \'captured_anchor_named_identity\')\n                with self.critical():\n                    fd = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,\n                                 **({} if parent is None else {\'dir_fd\':parent[\'fd\']}))\n                    row = {\'fd\':fd,\'name\':name,\'parent\':parent,\'expected\':tuple(item[\'identity\']),\n                           \'close_attempted\':False,\'closed\':False,\'anchor\':True}\n                    self.rows.append(row);self.anchors.append(row)\n                require(identity(os.fstat(fd)) == row[\'expected\'], \'captured_anchor_fd_identity\')\n                parent = row\n            self.check()\n        except BaseException:\n            self.close()\n            raise\n\n    def check(self, *, check_deadline=True):\n        require(not self.closed, \'volume_guard_not_closed\')\n        if check_deadline: self.remaining()\n        self.last_anchor_check = False\n        for row in self.anchors:\n            named = os.lstat(\'/\') if row[\'parent\'] is None else os.stat(\n                row[\'name\'],dir_fd=row[\'parent\'][\'fd\'],follow_symlinks=False)\n            require(identity(named) == identity(os.fstat(row[\'fd\'])) == row[\'expected\'],\n                    \'held_t5_anchor_changed\')\n        require(os.fstat(self.anchors[-1][\'fd\']).st_dev ==\n                int(self.expected[\'expectedVolumeDevice\']), \'held_t5_device_changed\')\n        self.last_anchor_check = True\n        if check_deadline: self.remaining()\n\n    def accept_diskutil(self, raw):\n        self.check()\n        require(isinstance(raw,bytes) and len(raw) <= 262144, \'bounded_actual_diskutil_bytes\')\n        info = plistlib.loads(raw)\n        require(info.get(\'VolumeUUID\') == UUID and info.get(\'MountPoint\') == str(MOUNT),\n                \'actual_t5_uuid_mount\')\n        self.uuid_verified = True\n        self.check()\n\n    def _admit(self, path):\n        self.check()\n        require(self.uuid_verified, \'uuid_before_owned_private_io\')\n        path = Path(path)\n        require(path.is_absolute() and path == Path(os.path.normpath(str(path)))\n                and path.is_relative_to(ROOT), \'fixed_owned_t5_scope\')\n        return path\n\n    def _close_row(self, row):\n        if row[\'close_attempted\']: return\n        with self.critical():\n            row[\'close_attempted\'] = True\n            try:\n                os.close(row[\'fd\']);row[\'closed\'] = True\n            except BaseException as error:\n                self.close_errors.append(type(error).__name__)\n                raise\n\n    @contextmanager\n    def parent(self, path):\n        path = self._admit(path)\n        parts = path.relative_to(MOUNT).parts\n        require(parts and all(part not in (\'\',\'.\', \'..\') for part in parts),\n                \'owned_component_shape\')\n        previous = self.anchors[-1]\n        borrowed = []\n        try:\n            for component in parts[:-1]:\n                self.remaining()\n                named = os.stat(component,dir_fd=previous[\'fd\'],follow_symlinks=False)\n                require(stat.S_ISDIR(named.st_mode) and named.st_uid == 501\n                        and named.st_dev == int(self.expected[\'expectedVolumeDevice\'])\n                        and stat.S_IMODE(named.st_mode)&0o022 == 0, \'owned_parent_custody\')\n                with self.critical():\n                    fd = os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,\n                                 dir_fd=previous[\'fd\'])\n                    row = {\'fd\':fd,\'name\':component,\'parent\':previous,\n                           \'expected_inode\':inode_identity(named),\n                           \'close_attempted\':False,\'closed\':False,\'anchor\':False}\n                    self.rows.append(row);borrowed.append(row)\n                require(inode_identity(os.fstat(fd)) == row[\'expected_inode\'],\n                        \'owned_parent_fd_identity\')\n                previous = row\n            self.check()\n            yield previous[\'fd\'], parts[-1]\n            for row in borrowed:\n                named = os.stat(row[\'name\'],dir_fd=row[\'parent\'][\'fd\'],follow_symlinks=False)\n                require(inode_identity(named) == inode_identity(os.fstat(row[\'fd\']))\n                        == row[\'expected_inode\'], \'owned_parent_changed\')\n            self.check()\n        finally:\n            errors = []\n            for row in reversed(borrowed):\n                try:self._close_row(row)\n                except BaseException as error:errors.append(type(error).__name__)\n            if errors: raise VolumeRefused(\'owned_parent_close_failed\')\n\n    def read(self, path, maximum=2*1024*1024, *, private=True):\n        require(type(maximum) is int and 0 < maximum <= 16*1024*1024, \'bounded_owned_read\')\n        with self.parent(path) as (parent, name):\n            with self.critical():\n                fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)\n                row = {\'fd\':fd,\'close_attempted\':False,\'closed\':False,\'anchor\':False}\n                self.rows.append(row)\n            try:\n                before = os.fstat(fd)\n                require(stat.S_ISREG(before.st_mode) and before.st_uid == 501\n                        and before.st_nlink == 1 and before.st_dev == int(self.expected[\'expectedVolumeDevice\'])\n                        and 0 <= before.st_size <= maximum\n                        and (stat.S_IMODE(before.st_mode) == 0o600 if private else\n                             stat.S_IMODE(before.st_mode)&0o022 == 0), \'owned_file_custody\')\n                raw = bytearray()\n                while len(raw) <= maximum:\n                    self.remaining()\n                    block = os.read(fd,min(65536,maximum+1-len(raw)))\n                    if not block:break\n                    raw.extend(block)\n                named = os.stat(name,dir_fd=parent,follow_symlinks=False)\n                require(len(raw) == before.st_size and identity(before) ==\n                        identity(os.fstat(fd)) == identity(named), \'owned_file_stable_read\')\n                self.check()\n                return bytes(raw)\n            finally:self._close_row(row)\n\n    def write_new(self, path, raw):\n        require(isinstance(raw,bytes) and len(raw) <= 16*1024*1024, \'bounded_owned_write\')\n        with self.parent(path) as (parent, name):\n            with self.critical():\n                fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,\n                             0o600,dir_fd=parent)\n                row = {\'fd\':fd,\'close_attempted\':False,\'closed\':False,\'anchor\':False}\n                self.rows.append(row)\n            try:\n                before = os.fstat(fd)\n                require(stat.S_ISREG(before.st_mode) and before.st_uid == 501\n                        and before.st_nlink == 1 and before.st_dev == int(self.expected[\'expectedVolumeDevice\']),\n                        \'new_owned_file_inode\')\n                offset=0\n                while offset<len(raw):\n                    self.remaining()\n                    n=os.write(fd,raw[offset:offset+65536])\n                    require(n>0,\'new_owned_write_progress\');offset+=n\n                os.fchmod(fd,0o600);os.fsync(fd);os.fsync(parent)\n                after=os.fstat(fd);named=os.stat(name,dir_fd=parent,follow_symlinks=False)\n                require(identity(after)==identity(named) and after.st_size==len(raw)\n                        and inode_identity(before)==inode_identity(after), \'new_owned_file_name\')\n                self.check()\n                return {\'bytes\':len(raw),\'sha256\':hashlib.sha256(raw).hexdigest(),\n                        \'identity\':list(identity(after))}\n            finally:self._close_row(row)\n\n    @contextmanager\n    def capture_sink(self, path, maximum=2*1024*1024):\n        require(type(maximum) is int and 0<maximum<=2*1024*1024,\'bounded_capture_sink\')\n        with self.parent(path) as (parent,name):\n            with self.critical():\n                fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,\n                           0o600,dir_fd=parent)\n                row={\'fd\':fd,\'close_attempted\':False,\'closed\':False,\'anchor\':False}\n                self.rows.append(row)\n                stream=os.fdopen(fd,\'wb\',buffering=0,closefd=False)\n            before=os.fstat(fd)\n            try:\n                require(stat.S_ISREG(before.st_mode) and before.st_uid==501\n                        and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600\n                        and before.st_dev==int(self.expected[\'expectedVolumeDevice\']),\n                        \'capture_sink_custody\')\n                yield stream\n                os.fsync(fd);os.fsync(parent)\n                after=os.fstat(fd);named=os.stat(name,dir_fd=parent,follow_symlinks=False)\n                require(after.st_size<=maximum and identity(after)==identity(named)\n                        and inode_identity(before)==inode_identity(after),\'capture_sink_stable\')\n                self.check()\n            finally:\n                with self.critical():\n                    try:stream.close()\n                    finally:self._close_row(row)\n\n    def mkdir_new(self, path):\n        with self.parent(path) as (parent,name):\n            self.remaining()\n            os.mkdir(name,mode=0o700,dir_fd=parent)\n            info=os.stat(name,dir_fd=parent,follow_symlinks=False)\n            require(stat.S_ISDIR(info.st_mode) and info.st_uid==501\n                    and stat.S_IMODE(info.st_mode)==0o700\n                    and info.st_dev==int(self.expected[\'expectedVolumeDevice\']),\'new_owned_directory\')\n            os.fsync(parent);self.check()\n            return list(identity(info))\n\n    def public_state(self):\n        return {\'schema\':\'heptabao.held-t5-volume-state.r1\',\n                \'volumeUUIDVerified\':self.uuid_verified,\n                \'expectedVolumeDevice\':self.expected[\'expectedVolumeDevice\'],\n                \'anchors\':self.expected[\'anchors\'],\'lastAnchorCheckPassed\':self.last_anchor_check,\n                \'allDescriptorsClosed\':all(x[\'closed\'] for x in self.rows),\n                \'closeErrors\':list(self.close_errors)}\n\n    def close(self):\n        if self.closed:return\n        try:self.check(check_deadline=False)\n        except BaseException:\n            self.last_anchor_check=False\n        for row in reversed(self.rows):\n            try:self._close_row(row)\n            except BaseException:pass\n        self.closed=True\n'}, 'pins': {'mac_owned_unreaped_r1.py': {'bytes': 14877, 'sha256': 'd735a9e9330e1260d44ad9e4c854d50094e20d85fe5633ddd9042281b3346298'}, 'mac_owned_commands_r1.py': {'bytes': 6154, 'sha256': '71a11bf9a0510c991b78c9bc3f094f315bf4914485b9cfda81c6e501eaf73530'}, 'mac_public_code_pin_excerpt_r1.py': {'bytes': 1792, 'sha256': '7ff262e7ff913eb97aab77855d988cb3a6af8cab5ea9c77940a2782afd91ca4f'}, 'mac_production_t5_guard_r1.py': {'bytes': 13379, 'sha256': '9f0b032264c4dd5db45478f08c1cdbc92354ac3153b2ed4d18ef2aab30b139f1'}}, 'plan': {'schema': 'heptabao.permanent-authbus-deployment-plan.r1', 'status': 'prepared_not_deployed', 'authorization': "Continue the user's existing Mac external-disk HeptaBao replacement and finite three-client migration.", 'product': {'commit': '4bde9aee03fcd27c59e13607e529b1cee594b249', 'macServerBytes': 92359328, 'macServerSha256': '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c', 'source': '/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/build-test-4bde9-r1/artifacts/heptabao-server'}, 'placement': {'host': 'mac', 'uid': 501, 'gid': 20, 'runtimeRoot': '/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-authbus-production', 'runtimeRootAbsenceMustBeCheckedAtCreate': True, 'selectedParentReason': 'Use the already observed owned recovery-work parent beneath the fixed T5 mount; do not change mount-root permissions or its directory entries.', 'volumeUUID': 'FB804D1B-24CB-4D6E-AEA7-A9E180807758', 'backupRoot': '/Users/qianqi/heptabao-authbus-production-backups', 'custodyRoot': '/Users/qianqi/heptabao-authbus-production-custody', 'launchAgentPath': '/Users/qianqi/Library/LaunchAgents/org.heptabao.authbus.plist', 'launchAgentLabel': 'org.heptabao.authbus', 'launchAgentDomain': 'gui/501', 'storageMode': 'native_v6_file', 'topology': 'One permanent Mac AuthBus service with separately qualified physical HA capability and independent recovery; this does not claim a deployed three-voter production cluster.', 'bootstrapAddress': 'https://127.0.0.1:31080', 'clientAddress': 'https://192.168.0.8:31080', 'endpointFreshBindAndActualTlsFromEveryRegisteredClientRequired': True, 'sourceKeyServiceDependencyOnJ3160': False}, 'trust': {'independentNewCa': True, 'caKey': 'custodyRoot/pki/ca.key', 'caCertificate': 'custodyRoot/pki/ca.crt', 'caValidityDays': 3650, 'leafValidityDays': 365, 'caKeyRsaBits': 3072, 'leafKeyRsaBits': 2048, 'certificateDnsSans': ['MacBook-Pro.local', 'localhost'], 'certificateIpSans': ['192.168.0.8', '127.0.0.1', '10.77.0.3', '100.77.61.24'], 'privateDirectoryMode': '0700', 'privateKeyAndStateMode': '0600', 'normalRuntimeBinaryMode': '0500', 'credentialValuesOrPrivateDigestsPublished': False, 'roles': 'One independent AppRole per registered host, with exact current source-bound policy.', 'rolesAndPoliciesMustBindActualProductionTransportContract': True}, 'clients': [{'host': 'mac', 'client': 'ai.openclaw.gateway', 'credentialDirectory': '/Users/qianqi/.openclaw/credentials/heptabao-authbus'}, {'host': 'rog', 'client': 'openclaw-gateway.service', 'credentialDirectory': '/home/qian-qi/.openclaw/credentials/heptabao-authbus'}, {'host': 'pocket4', 'client': 'openclaw-gateway.service', 'credentialDirectory': '/home/alex/.openclaw/credentials/heptabao-authbus'}], 'productionTransport': {'sourceRoot': 'tools/authbus/production-transport', 'currentlyInstalledInRegisteredClients': False, 'interface': 'ProductionTransportClient(config, ctx.stateDir)', 'integrationNeeds': ['Propagate normalized productionTransport configuration', 'Replace both actual BaoClient construction sites', 'Reconcile persisted original requests before new work', 'Stop admission, await the original operation tail, and close/revoke exactly once'], 'readScopes': ['openclaw-auth/data/manifest', 'openclaw-auth/data/profiles/<manifest-key>', 'openclaw-auth/data/order-policy', 'openclaw-auth/data/scheduler-assignments', 'openclaw-auth/data/transport-v1/control', 'exact own transport-v1 outbox/ack/report records'], 'writeScopes': ['exact own preallocated transport-v1 outbox slot', 'exact own transport-v1 report record'], 'oldInboxPathIsNotSubstitutedForTransportContract': True, 'newLocalDatabases': ['authbus/production-transport/state.sqlite', 'authbus/production-transport/operation.sqlite'], 'rollbackRule': 'An initially absent local database can be recorded as absent, but after dispatch the original outbox/operation history must remain in private custody. Never erase unknown requests, reset epoch, or issue a new-key replay while restoring credential databases.'}, 'backup': {'initialRegisteredHistoricalProducers': 0, 'chosenPermanentDestinationIsNotTheOldQaDr25Fixture': True, 'method': 'Native complete encrypted v6 snapshot plus the exact bound four-file seal seed; recovery keys retained separately in private custody.', 'dataAndBackupDifferentFilesystemObserved': True, 'productionBackupExecuted': False, 'productionRestoreExecuted': False, 'requiredRecovery': 'Create a fresh recovery directory from the actual permanent snapshot and bound seal material; verify complete latest credential state, ACL/AppRole/token semantics, cold start, and new writes without rewinding refreshed owner credentials.', 'retentionAndScheduledProducer': 'No new recurring schedule has been installed; a bounded explicit backup/restore entrypoint must be validated before cleanup.'}, 'observation': {'metadataJob': '1a1b345482c-fc05-819f', 'observedT5AvailableBytes': 107314339840, 'observedHomeAvailableBytes': 251798482944, 'observationsAreNotReservations': True, 'directMountChildWasOnlyAProbedAlternative': True, 'verifiedAbsentAtObservation': ['/Volumes/T5/heptabao-authbus-production', '/Users/qianqi/heptabao-authbus-production-backups', '/Users/qianqi/heptabao-authbus-production-custody', '/Users/qianqi/Library/LaunchAgents/org.heptabao.authbus.plist']}, 'stagedPreparationScope': {'createOnly': True, 'newCaAndLeaf': True, 'copyQualifiedNormalBinary': True, 'writeReviewableConfigsAndPlistInsidePrivateRuntimeRoot': True, 'installLaunchAgent': False, 'startServer': False, 'initializeService': False, 'readCurrentOwnerCredentials': False, 'providerCalls': 0, 'productionClientWrites': 0}, 'releaseRequirements': ['Complete the original fresh three-host HA128 profile at the unchanged budgets', 'Mac whole-database rollback at current real capacity, with complete active-consumer and actual fallback source closure', 'Fresh provider-valid owner credentials obtained independently of J3160 with once-only refresh/CAS if needed', 'Independent permanent CA/AppRole/TLS/KV/policy/renew/revoke and durable source-bound client transport', 'Per registered client actual credential I/O, restart, full rollback, then its cutover', 'Actual permanent backup/restore and finite legacy consumer retirement before cleanup'], 'currentlyQualifiedForFullReplacement': False, 'currentlyQualifiedForLegacyDeletion': False}}
START = time.monotonic()
UNTIL = START + 180
FDS = []
CODE_PIN_COMPLETIONS = []
report = {'schema': 'heptabao.permanent-authbus-create-only-preparation.r1', 'ok': False,
          'serviceActions': 0, 'apiRequests': 0, 'currentCredentialReads': 0,
          'providerCalls': 0, 'productionClientWrites': 0, 'legacyDeletions': 0,
          'privateKeyBytesOrDigestsPublished': False, 'productionReady': False,
          'automaticRetry': False, 'root': str(ROOT), 'custodyRoot': str(CUSTODY),
          'backupRoot': str(BACKUPS), 'productCommit': PRODUCT}

def need(value, code):
    if not value:
        raise RuntimeError(code)

def remaining():
    left = UNTIL - time.monotonic()
    need(left > 0, 'original_preparation_180_second_deadline')
    return left

def identity(info):
    return tuple(str(getattr(info, k)) for k in ('st_dev', 'st_ino', 'st_uid',
        'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

def open_fd(path, flags, *, dir_fd=None, mode=0o600):
    remaining()
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode,
                 **({} if dir_fd is None else {'dir_fd': dir_fd}))
    row = {'fd': fd, 'closeAttempts': 0, 'closed': False}
    FDS.append(row)
    return row

def close_fd(row):
    if row['closeAttempts']:
        return row['closed']
    row['closeAttempts'] = 1
    os.close(row['fd'])
    row['closed'] = True
    return True

def write_all(fd, raw):
    view = memoryview(raw)
    while view:
        remaining()
        count = os.write(fd, view)
        need(count > 0, 'complete_new_file_write')
        view = view[count:]

class HomeTrees:
    """Only two new fixed private roots under one held existing HOME."""
    def __init__(self):
        before = HOME.lstat()
        need(HOME.resolve(strict=True) == HOME and stat.S_ISDIR(before.st_mode)
             and before.st_uid == 501 and not before.st_mode & 0o022, 'protected_home_parent')
        self.home = open_fd(HOME, os.O_RDONLY | os.O_DIRECTORY)
        self.home_identity = identity(before)[:5]
        self.directories = {HOME: (self.home, self.home_identity)}
        self.check()

    def check(self):
        remaining()
        for path, (row, expected) in self.directories.items():
            need(identity(os.fstat(row['fd']))[:5] == identity(path.lstat())[:5] == expected,
                 'same_held_private_directory')

    def mkdir(self, path):
        self.check()
        need(path in (CUSTODY, BACKUPS, CUSTODY / 'pki', CUSTODY / 'operations')
             and path.parent in self.directories, 'finite_new_home_directory')
        parent = self.directories[path.parent][0]
        os.mkdir(path.name, mode=0o700, dir_fd=parent['fd'])
        os.fsync(parent['fd'])
        row = open_fd(path.name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent['fd'])
        info = os.fstat(row['fd'])
        need(info.st_uid == 501 and info.st_gid == 20 and stat.S_IMODE(info.st_mode) == 0o700
             and identity(info) == identity(os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False)),
             'new_private_home_directory')
        self.directories[path] = (row, identity(info)[:5])
        self.check()

    def write(self, path, raw):
        self.check()
        need(path.parent in self.directories and path.parent != HOME
             and isinstance(raw, bytes) and len(raw) <= 1048576, 'finite_private_new_file')
        parent = self.directories[path.parent][0]
        row = open_fd(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, dir_fd=parent['fd'])
        try:
            before = os.fstat(row['fd'])
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
                 and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600,
                 'new_private_file_metadata')
            write_all(row['fd'], raw)
            os.fsync(row['fd'])
            os.fsync(parent['fd'])
            after = os.fstat(row['fd'])
            need(identity(after) == identity(os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False))
                 and identity(before)[:6] == identity(after)[:6] and after.st_size == len(raw),
                 'new_private_file_generation')
        finally:
            close_fd(row)
        self.check()

    def public_certificate(self, path):
        self.check()
        need(path == CUSTODY / 'pki/ca.crt', 'only_public_ca_read')
        row = open_fd(path.name, os.O_RDONLY | os.O_NONBLOCK, dir_fd=self.directories[path.parent][0]['fd'])
        try:
            before = os.fstat(row['fd'])
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_nlink == 1
                 and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= 16384,
                 'private_custody_public_certificate')
            raw = os.read(row['fd'], 16385)
            need(len(raw) == before.st_size and identity(before) == identity(os.fstat(row['fd']))
                 == identity(path.lstat()), 'whole_public_ca_generation')
            return raw
        finally:
            close_fd(row)

def key_metadata(path):
    info = path.lstat()
    need(path in (CUSTODY / 'pki/ca.key', ROOT / 'tls/server.key') and path.resolve(strict=True) == path
         and stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
         and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
         and 0 < info.st_size <= 16384, 'new_private_key_metadata_only')
    return {'owner': 501, 'group': 20, 'mode': '0600', 'regularSingleLink': True}

def sync_generated_file(path):
    allowed = (CUSTODY / 'pki/ca.key', CUSTODY / 'pki/ca.crt', ROOT / 'tls/server.key',
               ROOT / 'tls/server.csr', ROOT / 'tls/server.crt')
    need(path in allowed and path.resolve(strict=True) == path, 'fixed_generated_file_to_sync')
    row = open_fd(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        before = os.fstat(row['fd'])
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
             and 0 < before.st_size <= 16384 and identity(before) == identity(path.lstat()),
             'exact_generated_file_before_sync')
        # In particular, private key bytes and digests are never read here.
        os.fsync(row['fd'])
        need(identity(before) == identity(os.fstat(row['fd'])) == identity(path.lstat()),
             'same_generated_file_after_sync')
    finally:
        close_fd(row)
    directory = open_fd(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory['fd'])
    finally:
        close_fd(directory)

def main():
    os.umask(0o077)
    guard = home = commands = signals = None
    code_before = {}
    try:
        need(sys.platform == 'darwin' and os.getuid() == 501 and os.getgid() == 20
             and Path(sys.executable).resolve(strict=True) == PYTHON, 'exact_mac_owner_and_interpreter')
        need(set(PAYLOAD) == {'sources', 'pins', 'plan'} and len(PAYLOAD['sources']) == 4,
             'four_fixed_public_libraries')
        for name, source in PAYLOAD['sources'].items():
            raw = source.encode()
            need(name in PAYLOAD['pins'] and len(raw) == PAYLOAD['pins'][name]['bytes']
                 and hashlib.sha256(raw).hexdigest() == PAYLOAD['pins'][name]['sha256'],
                 'whole_reviewed_library_pin')
            ast.parse(source)
        for name in ('mac_owned_unreaped_r1.py', 'mac_owned_commands_r1.py',
                     'mac_public_code_pin_excerpt_r1.py', 'mac_production_t5_guard_r1.py'):
            module = types.ModuleType(Path(name).stem)
            module.__file__ = str(ROOT / 'source' / name)
            sys.modules[module.__name__] = module
            exec(compile(PAYLOAD['sources'][name], module.__file__, 'exec'), module.__dict__)
        from mac_owned_commands_r1 import Signals, Commands
        from mac_public_code_pin_excerpt_r1 import public_code_pin
        from mac_production_t5_guard_r1 import HeldT5
        signals = Signals()
        signals.install()
        commands = Commands(signals)
        for path, expected in TOOL_PINS.items():
            actual = public_code_pin(path, remaining=remaining, critical=signals.critical)
            CODE_PIN_COMPLETIONS.append({'path': path, 'phase': 'before', 'originalDescriptorClosedBeforeReturn': True})
            need((actual['bytes'], actual['sha256']) == expected, 'exact_current_native_tool_pin')
            code_before[path] = actual
        for path in (ROOT, CUSTODY, BACKUPS):
            need(not path.exists() and not path.is_symlink(), 'every_new_stage_root_absent')
        need(not (HOME / 'Library/LaunchAgents/org.heptabao.authbus.plist').exists()
             and not (HOME / 'Library/LaunchAgents/org.heptabao.authbus.plist').is_symlink(),
             'proposed_registration_path_still_absent')
        anchor = {'schema': 'heptabao.mac-current-t5-public-anchor.r1',
                  'source_inventory_sha256': hashlib.sha256(encoded(PAYLOAD['pins'])).hexdigest(),
                  'volumeUUID': 'FB804D1B-24CB-4D6E-AEA7-A9E180807758',
                  'expectedVolumeDevice': str(Path('/Volumes/T5').lstat().st_dev),
                  'anchors': [{'path': path, 'identity': list(identity(Path(path).lstat()))}
                              for path in ('/', '/Volumes', '/Volumes/T5')]}
        anchor_raw = encoded(anchor)
        guard = HeldT5(anchor_raw, hashlib.sha256(anchor_raw).hexdigest(), remaining, signals.critical)
        row, out, err = commands.run('fixed-t5-volume', ['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'],
                                    until=min(UNTIL, time.monotonic() + 15), maximum=262144)
        need(row['exitCode'] == 0 and not row['outcomeUnknown'] and not err, 'known_actual_t5_volume')
        guard.accept_diskutil(out)
        home = HomeTrees()
        need(os.fstat(home.home['fd']).st_dev != int(anchor['expectedVolumeDevice']),
             'data_and_backup_distinct_filesystems')
        for path in (CUSTODY, CUSTODY / 'pki', CUSTODY / 'operations', BACKUPS):
            home.mkdir(path)
        home.write(CUSTODY / 'deployment-plan.private.json', encoded(PAYLOAD['plan']))
        for part in ('', 'releases', 'releases/' + PRODUCT, 'etc', 'data', 'tls', 'log', 'service', 'source'):
            guard.mkdir_new(ROOT / part)
        guard.write_new(ROOT / 'source/public-source-pins.json', encoded(PAYLOAD['pins']))
        for name, source in PAYLOAD['sources'].items():
            guard.write_new(ROOT / 'source' / name, source.encode())
        binary = ROOT / 'releases' / PRODUCT / 'heptabao-server'
        original = open_fd(SOURCE, os.O_RDONLY | os.O_NONBLOCK)
        try:
            before = os.fstat(original['fd'])
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_nlink == 1
                 and stat.S_IMODE(before.st_mode) == 0o700 and before.st_size == BIN_BYTES
                 and identity(before) == identity(SOURCE.lstat()), 'qualified_normal_source_binary')
            with guard.parent(binary) as (parent, name):
                target = open_fd(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, dir_fd=parent)
                try:
                    digest, count = hashlib.sha256(), 0
                    while True:
                        remaining()
                        block = os.read(original['fd'], 1048576)
                        if not block:
                            break
                        count += len(block)
                        need(count <= BIN_BYTES, 'normal_binary_copy_bound')
                        digest.update(block)
                        write_all(target['fd'], block)
                    need(count == BIN_BYTES and digest.hexdigest() == BIN_SHA
                         and identity(before) == identity(os.fstat(original['fd'])) == identity(SOURCE.lstat()),
                         'whole_qualified_source_binary_unchanged')
                    os.fchmod(target['fd'], 0o500)
                    os.fsync(target['fd'])
                    os.fsync(parent)
                    after = os.fstat(target['fd'])
                    need(after.st_uid == 501 and after.st_nlink == 1 and stat.S_IMODE(after.st_mode) == 0o500
                         and after.st_size == BIN_BYTES
                         and identity(after) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                         'new_normal_binary_generation')
                    os.lseek(target['fd'], 0, os.SEEK_SET)
                    copied_digest, copied_count = hashlib.sha256(), 0
                    while True:
                        remaining()
                        copied = os.read(target['fd'], 1048576)
                        if not copied:
                            break
                        copied_count += len(copied)
                        need(copied_count <= BIN_BYTES, 'bounded_copied_binary_readback')
                        copied_digest.update(copied)
                    need(copied_count == BIN_BYTES and copied_digest.hexdigest() == BIN_SHA
                         and identity(after) == identity(os.fstat(target['fd']))
                         == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                         'entire_new_normal_binary_readback')
                finally:
                    close_fd(target)
        finally:
            close_fd(original)
        ca_config = b'[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\nCN=HeptaBao AuthBus Independent CA\n[ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n'
        leaf_config = b'[req]\nprompt=no\ndistinguished_name=dn\nreq_extensions=server\n[dn]\nCN=MacBook-Pro.local\n[server]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:MacBook-Pro.local,DNS:localhost,IP:192.168.0.8,IP:127.0.0.1,IP:10.77.0.3,IP:100.77.61.24\n'
        home.write(CUSTODY / 'pki/ca.cnf', ca_config)
        guard.write_new(ROOT / 'tls/server.cnf', leaf_config)
        serial = '0x' + os.urandom(16).hex()
        argv = [
            ('new-independent-ca', ['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes', '-days', '3650', '-config', str(CUSTODY / 'pki/ca.cnf'), '-keyout', str(CUSTODY / 'pki/ca.key'), '-out', str(CUSTODY / 'pki/ca.crt')]),
            ('new-server-key-csr', ['/usr/bin/openssl', 'req', '-new', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-config', str(ROOT / 'tls/server.cnf'), '-keyout', str(ROOT / 'tls/server.key'), '-out', str(ROOT / 'tls/server.csr')]),
            ('sign-new-server-certificate', ['/usr/bin/openssl', 'x509', '-req', '-in', str(ROOT / 'tls/server.csr'), '-CA', str(CUSTODY / 'pki/ca.crt'), '-CAkey', str(CUSTODY / 'pki/ca.key'), '-set_serial', serial, '-days', '365', '-sha256', '-extfile', str(ROOT / 'tls/server.cnf'), '-extensions', 'server', '-out', str(ROOT / 'tls/server.crt')]),
            ('verify-new-certificate-chain', ['/usr/bin/openssl', 'verify', '-CAfile', str(CUSTODY / 'pki/ca.crt'), str(ROOT / 'tls/server.crt')]),
        ]
        for ordinal, (label, command) in enumerate(argv):
            home.check()
            guard.check()
            outputs = {0: (CUSTODY / 'pki/ca.key', CUSTODY / 'pki/ca.crt'),
                       1: (ROOT / 'tls/server.key', ROOT / 'tls/server.csr'),
                       2: (ROOT / 'tls/server.crt',), 3: ()}[ordinal]
            need(all(not path.exists() and not path.is_symlink() for path in outputs),
                 'original_crypto_output_names_absent')
            home.write(CUSTODY / 'operations' / ('%02d-intent.private.json' % ordinal), encoded({'label': label, 'argv': command, 'status': 'dispatched_or_unknown'}))
            row, out, err = commands.run(label, command, until=min(UNTIL, time.monotonic() + 30), maximum=262144)
            home.write(CUSTODY / 'operations' / ('%02d-completion.private.json' % ordinal), encoded(row))
            need(row['exitCode'] == 0 and not row['outcomeUnknown'], 'original_crypto_command_known_complete')
            home.check()
            guard.check()
        for generated in (CUSTODY / 'pki/ca.key', CUSTODY / 'pki/ca.crt', ROOT / 'tls/server.key',
                          ROOT / 'tls/server.csr', ROOT / 'tls/server.crt'):
            sync_generated_file(generated)
        report['generatedKeyAndCertificateFilesSyncedWithoutReadingPrivateKeys'] = 5
        report['privateKeyMetadata'] = {'ca': key_metadata(CUSTODY / 'pki/ca.key'), 'server': key_metadata(ROOT / 'tls/server.key')}
        ca = home.public_certificate(CUSTODY / 'pki/ca.crt')
        leaf = guard.read(ROOT / 'tls/server.crt', 16384)
        ca_der = ssl.PEM_cert_to_DER_cert(ca.decode('ascii'))
        leaf_der = ssl.PEM_cert_to_DER_cert(leaf.decode('ascii'))
        guard.write_new(ROOT / 'tls/ca.crt', ca)
        config = {'listen': '192.168.0.8:31080', 'data_dir': str(ROOT / 'data'),
                  'audit_file': str(ROOT / 'log/audit.jsonl'), 'tls_cert_file': str(ROOT / 'tls/server.crt'),
                  'tls_key_file': str(ROOT / 'tls/server.key'), 'max_connections': 64, 'timeout_seconds': 15,
                  'rate_limit_per_second': 2000, 'rate_limit_burst': 4000, 'rate_limit_entries': 512,
                  'storage': {'native_v6_file': {'path': str(ROOT / 'data')}}}
        guard.write_new(ROOT / 'etc/server.json', encoded(config))
        bootstrap = dict(config, listen='127.0.0.1:31080')
        guard.write_new(ROOT / 'etc/server-bootstrap.json', encoded(bootstrap))
        for name in ('server.stdout.log', 'server.stderr.log'):
            guard.write_new(ROOT / 'log' / name, b'')
        plist = {'Label': 'org.heptabao.authbus', 'ProgramArguments': [str(binary), '--config', str(ROOT / 'etc/server.json')],
                 'WorkingDirectory': str(ROOT), 'EnvironmentVariables': {'HOME': str(HOME), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'},
                 'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 10, 'ExitTimeOut': 30, 'Umask': 0o077,
                 'StandardOutPath': str(ROOT / 'log/server.stdout.log'), 'StandardErrorPath': str(ROOT / 'log/server.stderr.log')}
        guard.write_new(ROOT / 'service/org.heptabao.authbus.plist', plistlib.dumps(plist, sort_keys=True))
        report['staged'] = {'normalBinarySha256': BIN_SHA, 'normalBinaryBytes': BIN_BYTES,
                            'newCaDerSha256': hashlib.sha256(ca_der).hexdigest(),
                            'newLeafDerSha256': hashlib.sha256(leaf_der).hexdigest(),
                            'certificateChainVerified': True, 'servicePlistInstalled': False,
                            'bootstrapConfigOnlyLoopback': True, 'plannedClientAddress': 'https://192.168.0.8:31080',
                            'independentRootTrustCreated': True, 'dataBackupDifferentFilesystems': True}
        for path in TOOL_PINS:
            current = public_code_pin(path, remaining=remaining, critical=signals.critical)
            CODE_PIN_COMPLETIONS.append({'path': path, 'phase': 'after', 'originalDescriptorClosedBeforeReturn': True})
            need(current == code_before[path],
                 'original_native_tools_unchanged')
        home.check()
        guard.check()
        report['toolPins'] = {path: {'bytes': value[0], 'sha256': value[1]} for path, value in TOOL_PINS.items()}
        home.write(CUSTODY / 'staging-complete.private.json', encoded(report['staged']))
        report['ok'] = True
    except BaseException as error:
        report['errorClass'] = type(error).__name__
        report['errorCode'] = str(error) if isinstance(error, RuntimeError) else 'create_only_stage_failed'
    finally:
        if guard is not None:
            try:
                guard.close()
            except BaseException:
                report['ok'] = False
            report['volumeClosure'] = guard.public_state()
        close_errors = []
        for row in reversed(FDS):
            try:
                close_fd(row)
            except BaseException as error:
                close_errors.append(type(error).__name__)
        report['allExplicitDescriptorsClosedOnce'] = all(row['closeAttempts'] == 1 and row['closed'] for row in FDS)
        report['explicitDescriptorCount'] = len(FDS)
        report['descriptorCloseErrors'] = close_errors
        report['publicCodePinCompletions'] = CODE_PIN_COMPLETIONS
        report['commands'] = commands.public() if commands is not None else {'commands': [], 'allOwnedCommandsStopped': True, 'unknownCommandCount': 0}
        report['ok'] = bool(report['ok'] and report['allExplicitDescriptorsClosedOnce'] and not close_errors
                            and report.get('volumeClosure', {}).get('allDescriptorsClosed')
                            and report.get('volumeClosure', {}).get('lastAnchorCheckPassed')
                            and not report.get('volumeClosure', {}).get('closeErrors')
                            and report['commands']['allOwnedCommandsStopped']
                            and report['commands']['unknownCommandCount'] == 0)
        report['elapsedSeconds'] = time.monotonic() - START
        print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
