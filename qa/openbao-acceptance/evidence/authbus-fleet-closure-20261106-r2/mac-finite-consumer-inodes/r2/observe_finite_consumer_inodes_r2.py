#!/usr/bin/env python3
"""One finite live-PID to known-file inode observation; no credential/SQL reads."""
import ast
import hashlib
import json
import locale
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

START = time.monotonic()
UNTIL = START + 45
ROOT = Path('/Users/qianqi/heptabao-authbus-finite-consumer-inodes-20261107-r2')
CALLER_HOME = Path('/Users/qianqi')
LIVE = CALLER_HOME / '.openclaw'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
LSOF = '/usr/sbin/lsof'
RUNTIME_PINS = {
    str(PYTHON): (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'),
    '/bin/ps': (170432, '3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c'),
    LSOF: (306768, 'b1b9151bbc56f4749890dbe4e533af9a4f8700240ad431a6c9ddf70fe137c165'),
}
AGENTS = ('main', 'trnm', 'hepta-ui', 'hepta', 'hepta-backend')
CACHES = ('applied-profiles.json', 'publish-baseline.json', 'bad-refresh-quarantine.json',
          'refresh-backoff.json', 'lease-epochs.json', 'status.json')
LEGACY = ('auth-profiles.json', 'auth-state.json', 'auth.json')
PAYLOAD={'sources': {'mac_owned_unreaped_r1.py': '#!/usr/bin/env python3\n"""Retained direct-child custody for Mac phase workers.\n\nDerived from canonical native_ha_foreground_watchdog.py 74925449. No child is\nstarted here. WNOWAIT observes exit; it never makes the numeric PGID reusable\nbefore signaling. Cleanup keeps the previous wrapper\'s TERM1 / wait5 /\ngroup3 limits and PS4 maximum. No stage grants business more than phase120.\n"""\nimport hashlib, os, signal, stat, subprocess, time\n\nMIB=1024*1024\nclass Refusal(RuntimeError): pass\ndef need(value,code):\n    if not value:raise Refusal(code)\n\n# Only this observed system helper may cross effective UID at exec. No target\n# service, arbitrary argv, descendant, or unrelated command gets this exception.\nFIXED_PS_ARGV=(\'/bin/ps\',\'-axo\',\'pid=,ppid=,pgid=,uid=,stat=\')\nFIXED_PS_SHA256=\'3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c\'\nFIXED_PS_BYTES=170432\nFIXED_PS_IDENTITY=(16777233,1152921500312571399,0,0,35309,1,170432,\n    1786589515000000000,1786589515000000000)\n\ndef fixed_ps_identity(value):\n    return tuple(getattr(value,name) for name in (\'st_dev\',\'st_ino\',\'st_uid\',\'st_gid\',\n        \'st_mode\',\'st_nlink\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\'))\n\ndef fixed_ps_pin(*,until):\n    need(os.getuid()==501 and os.geteuid()==501,\'fixed_ps_requires_exact_caller\')\n    need(time.monotonic()<until,\'original_command_deadline_exhausted\')\n    path=FIXED_PS_ARGV[0]\n    before=os.lstat(path)\n    need(fixed_ps_identity(before)==FIXED_PS_IDENTITY and stat.S_ISREG(before.st_mode)\n         and stat.S_IMODE(before.st_mode)==0o4755,\'fixed_ps_system_file_identity\')\n    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)\n    try:\n        need(fixed_ps_identity(os.fstat(fd))==FIXED_PS_IDENTITY,\'fixed_ps_open_file_identity\')\n        raw=bytearray()\n        while len(raw)<=FIXED_PS_BYTES:\n            need(time.monotonic()<until,\'original_command_deadline_exhausted\')\n            part=os.read(fd,min(65536,FIXED_PS_BYTES+1-len(raw)))\n            if not part:break\n            raw.extend(part)\n        need(len(raw)==FIXED_PS_BYTES and hashlib.sha256(raw).hexdigest()==FIXED_PS_SHA256,\n             \'fixed_ps_whole_file_hash\')\n        need(fixed_ps_identity(os.fstat(fd))==fixed_ps_identity(os.lstat(path))==FIXED_PS_IDENTITY,\n             \'fixed_ps_named_file_unchanged\')\n        need(time.monotonic()<until,\'original_command_deadline_exhausted\')\n        return {\'identity\':list(FIXED_PS_IDENTITY),\'sha256\':FIXED_PS_SHA256}\n    finally:\n        os.close(fd)\n\ndef prepare_fixed_ps_contract(argv,*,until):\n    if not argv or argv[0]!=FIXED_PS_ARGV[0]:return None\n    need(tuple(argv)==FIXED_PS_ARGV,\'fixed_ps_exact_argv_before_launch\')\n    return {\'schema\':\'heptabao.fixed-system-ps-child.r1\',\'argv\':list(FIXED_PS_ARGV),\n        \'launcherPid\':os.getpid(),\'callerUid\':501,\'pin\':fixed_ps_pin(until=until)}\n\ndef verify_fixed_ps_contract(child,contract,*,until):\n    need(isinstance(contract,dict) and set(contract)=={\'schema\',\'argv\',\'launcherPid\',\'callerUid\',\'pin\'}\n         and contract[\'schema\']==\'heptabao.fixed-system-ps-child.r1\'\n         and contract[\'argv\']==list(FIXED_PS_ARGV)\n         and tuple(child.args)==FIXED_PS_ARGV\n         and contract[\'launcherPid\']==os.getpid() and contract[\'callerUid\']==501\n         and child.returncode is None and type(child.pid) is int and child.pid>1,\n         \'fixed_ps_direct_child_contract\')\n    need(contract[\'pin\']==fixed_ps_pin(until=until),\'fixed_ps_prelaunch_binding_changed\')\n    return True\n\ndef fixed_ps_group_uid(row,child,owner):\n    if owner.get(\'fixedPsContract\') is None:return row[\'uid\']==os.geteuid()\n    return row[\'pid\']==child.pid and stable(row)==owner[\'ps\'] and row[\'uid\']==0\n\ndef require_waitid():\n    need(all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT",\n                                          "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED")),\n         "wnowait_required_no_child_started")\n    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,\n         "direct_child_reaping_policy_changed")\n\ndef exit_observation(child):\n    """This is an observation, never Popen.poll/wait/communicate."""\n    need(child.returncode is None, "child_already_reaped_no_signal")\n    event = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)\n    if event is None:\n        return None\n    need(event.si_pid == child.pid and event.si_signo == signal.SIGCHLD\n         and event.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED),\n         "child_exit_identity_changed")\n    # Darwin reports si_uid=0 even for an observed uid501 child. Actual UID is\n    # bound independently by ps; si_uid never grants ownership here.\n    return {"pid": event.si_pid, "signo": event.si_signo, "code": event.si_code, "status": event.si_status}\n\ndef stable(row):\n    return {key: row[key] for key in ("pid", "ppid", "pgid", "uid", "start")}\n\ndef ps_rows(pid=None, *, seconds=4.0, until=None):\n    if until is not None:\n        remaining = until - time.monotonic()\n        need(remaining > 0, "original_stop_deadline_expired")\n        seconds = min(seconds, remaining)\n    argv = ["/bin/ps"]\n    argv += ["-p", str(pid)] if pid is not None else ["-ax"]\n    argv += ["-o", "pid=,ppid=,pgid=,uid=,stat=,lstart="]\n    try:\n        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,\n                                stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C"),\n                                timeout=seconds)\n    except subprocess.TimeoutExpired as error:\n        code = ("original_stop_deadline_expired" if until is not None and time.monotonic() >= until\n                else "process_projection_deadline_expired")\n        raise Refusal(code) from error\n    if until is not None:\n        need(time.monotonic() < until, "original_stop_deadline_expired")\n    need(len(result.stdout) <= 2 * MIB and len(result.stderr) <= 65536,\n         "process_projection_bound")\n    if pid is not None and result.returncode == 1 and not result.stdout.strip():\n        return []\n    need(result.returncode == 0, "process_projection_unavailable")\n    rows = []\n    for line in result.stdout.decode("ascii").splitlines():\n        fields = line.split(None, 5)\n        need(len(fields) == 6, "process_projection_malformed")\n        rows.append({"pid": int(fields[0]), "ppid": int(fields[1]),\n                     "pgid": int(fields[2]), "uid": int(fields[3]),\n                     "state": fields[4], "start": fields[5]})\n    if pid is not None:\n        need(len(rows) == 1 and rows[0]["pid"] == pid, "process_projection_ambiguous")\n    return rows\n\ndef capture_child(child, *, until, fixed_ps_contract=None):\n    require_waitid()\n    rows = ps_rows(child.pid, until=until)\n    need(len(rows) == 1, "owned_child_identity_missing")\n    row = rows[0]\n    special=fixed_ps_contract is not None\n    if special:verify_fixed_ps_contract(child,fixed_ps_contract,until=until)\n    need(row["ppid"] == os.getpid() and row["pgid"] == child.pid\n         and row["uid"] == (0 if special else os.geteuid()), "owned_child_scope_mismatch")\n    # Darwin keeps an unreaped zombie in ps but getpgid/getsid return ESRCH.\n    # Use the real live APIs only for a still-live child; otherwise independently\n    # repeat WNOWAIT and retain ps plus Popen direct-parent custody.\n    event, live_sid = exit_observation(child), None\n    if event is None and not row["state"].startswith("Z"):\n        try:\n            need(os.getpgid(child.pid) == child.pid and os.getsid(child.pid) == child.pid,\n                 "owned_live_session_mismatch")\n            live_sid = child.pid\n        except ProcessLookupError:\n            # A fast exit between the first ps/waitid and a live API call is\n            # not loss of Popen custody, nor proof that the group is empty.\n            event = exit_observation(child)\n            need(event is not None, "owned_live_api_failed_without_retained_exit")\n    if event is not None or row["state"].startswith("Z"):\n        event = exit_observation(child)\n        fresh = ps_rows(child.pid, until=until)\n        need(event is not None and len(fresh) == 1 and stable(fresh[0]) == stable(row)\n             and fresh[0]["state"].startswith("Z") and exit_observation(child) == event,\n             "owned_exit_not_retained")\n        row = fresh[0]\n    return {"ps": stable(row), "sid_observed_while_live": live_sid,\n            "captured_exit": event,"fixedPsContract":fixed_ps_contract}\n\ndef verify_unreaped(child, owner, *, until=None):\n    if owner.get(\'fixedPsContract\') is not None:\n        need(until is not None,\'fixed_ps_requires_existing_deadline\')\n        verify_fixed_ps_contract(child,owner[\'fixedPsContract\'],until=until)\n    event = exit_observation(child)\n    rows = ps_rows(child.pid, until=until)\n    need(len(rows) == 1 and stable(rows[0]) == owner["ps"]\n         and rows[0]["ppid"] == os.getpid(), "owned_child_identity_changed_no_signal")\n    if event is None and not rows[0]["state"].startswith("Z"):\n        # Exact ps PGID/start plus direct Popen/WNOWAIT custody keeps the\n        # originally observed session leader reserved. Do not race a normal\n        # exit by consulting Darwin\'s zombie-unsupported getpgid/getsid here.\n        need(owner["ps"]["pgid"] == child.pid, "owned_live_session_changed_no_signal")\n    else:\n        event = exit_observation(child)\n        need(event is not None and rows[0]["state"].startswith("Z") and exit_observation(child) == event,\n             "owned_zombie_identity_changed_no_signal")\n    return event\n\ndef live_group(child, owner, *, until):\n    need(time.monotonic() < until, "original_stop_deadline_expired")\n    verify_unreaped(child, owner, until=until)\n    rows = ps_rows(until=until)\n    if owner.get("fixedPsContract") is not None:\n        related=[row for row in rows if row["pgid"]==child.pid or row["ppid"]==child.pid]\n        need(all(row["pid"]==child.pid and stable(row)==owner["ps"] for row in related),\n             "fixed_ps_no_other_group_or_direct_child")\n    selected = [row for row in rows if row["pgid"] == child.pid and not row["state"].startswith("Z")]\n    need(all(fixed_ps_group_uid(row,child,owner) for row in selected), "owned_group_uid_changed_no_signal")\n    need(time.monotonic() < until, "original_stop_deadline_expired")\n    return [stable(row) for row in selected]\n\ndef observed_returncode(event):\n    if event is None:return None\n    return event[\'status\'] if event[\'code\']==os.CLD_EXITED else -event[\'status\']\n\ndef stop_once_unreaped(child, owner, *, fixed_ps_contract=None):\n    """Called once by the wrapper\'s protected ledger; never calls Popen.poll."""\n    require_waitid()\n    started=time.monotonic()\n    receipt={\'pid\':child.pid,\'pgid\':child.pid,\'stopAttempted\':True,\'signals\':[],\n             \'directChildReaped\':False,\'ownedLiveGroupEmptyBeforeReap\':False,\n             \'allGroupRowsEmptyAfterReap\':False,\'cleanupCaps\':{\'term\':1,\'wait\':5,\'group\':3,\'psMax\':4},\n             \'postReapSignalSent\':False,\'custody\':owner}\n    try:\n        need(child.returncode is None,\'already_reaped_no_group_signal\')\n        term_until=time.monotonic()+1.0\n        if owner is None:\n            owner=capture_child(child,until=term_until,fixed_ps_contract=fixed_ps_contract)\n            receipt[\'custody\']=owner\n        members=live_group(child,owner,until=term_until)\n        receipt[\'initialLiveGroup\']=members\n        if members:\n            verify_unreaped(child,owner,until=term_until)\n            need(time.monotonic()<term_until,\'original_stop_deadline_expired\')\n            os.killpg(child.pid,signal.SIGTERM);receipt[\'signals\'].append(\'SIGTERM\')\n            while time.monotonic()<term_until:\n                try:\n                    members=live_group(child,owner,until=term_until)\n                    if not members:break\n                except Refusal as error:\n                    if str(error)!=\'original_stop_deadline_expired\' or time.monotonic()<term_until:\n                        raise\n                    break\n                time.sleep(min(0.02,max(0,term_until-time.monotonic())))\n        wait_until=time.monotonic()+5.0\n        members=live_group(child,owner,until=wait_until)\n        if members:\n            verify_unreaped(child,owner,until=wait_until)\n            need(time.monotonic()<wait_until,\'original_stop_deadline_expired\')\n            os.killpg(child.pid,signal.SIGKILL);receipt[\'signals\'].append(\'SIGKILL\')\n        event=exit_observation(child)\n        while event is None:\n            verify_unreaped(child,owner,until=wait_until)\n            need(time.monotonic()<wait_until,\'original_stop_deadline_expired\')\n            time.sleep(min(0.02,max(0,wait_until-time.monotonic())))\n            event=exit_observation(child)\n        need(time.monotonic()<wait_until,\'original_stop_deadline_expired\')\n        receipt[\'retainedExit\']=event\n        # The old post-exit group3 interval now precedes the first reap.\n        # This retains actual Popen PID custody while other live members leave.\n        group_until=time.monotonic()+3.0\n        while True:\n            members=live_group(child,owner,until=group_until)\n            if not members and exit_observation(child)==event:break\n            need(time.monotonic()<group_until,\'original_stop_deadline_expired\')\n            time.sleep(min(0.02,max(0,group_until-time.monotonic())))\n        receipt[\'ownedLiveGroupEmptyBeforeReap\']=True\n        need(time.monotonic()<group_until,\'original_stop_deadline_expired\')\n        child.wait(timeout=group_until-time.monotonic())\n        receipt[\'directChildReaped\']=True\n        receipt[\'exitCode\']=child.returncode\n        need(child.returncode==observed_returncode(event),\'actual_reap_matches_retained_exit\')\n        # After the first reap, only observe. No signal or ownership claim is\n        # derived from this now-reusable numeric PGID.\n        while True:\n            rows=[row for row in ps_rows(until=group_until) if row[\'pgid\']==child.pid]\n            receipt[\'remainingGroupRows\']=rows\n            if not rows:break\n            need(time.monotonic()<group_until,\'original_stop_deadline_expired\')\n            time.sleep(min(0.02,max(0,group_until-time.monotonic())))\n        receipt[\'allGroupRowsEmptyAfterReap\']=True\n        need(time.monotonic()<group_until,\'original_stop_deadline_expired\')\n        receipt[\'ok\']=True\n    except BaseException as error:\n        receipt[\'ok\']=False\n        receipt[\'errorType\']=type(error).__name__\n        receipt[\'errorCode\']=str(error) if isinstance(error,Refusal) else None\n        receipt[\'directChildReaped\']=child.returncode is not None\n        receipt[\'exitCode\']=child.returncode\n        # No second signal sequence, no renewed deadline, no automatic retry.\n    receipt[\'elapsedSeconds\']=time.monotonic()-started\n    receipt[\'outcomeUnknown\']=not(receipt.get(\'ok\') is True\n       and receipt[\'directChildReaped\'] and receipt[\'allGroupRowsEmptyAfterReap\'])\n    return receipt\n', 'mac_owned_commands_r1.py': '#!/usr/bin/env python3\n"""Bounded foreground commands with retained direct-child custody.\n\nNo import-time I/O. The caller supplies exact reviewed argv and an absolute\ncommand deadline. Pipe reads, exit observation and metadata capture share it.\nCleanup uses the separate once-only TERM1/wait5/group3 custody contract.\n"""\nfrom __future__ import annotations\nfrom contextlib import contextmanager\nimport hashlib, os, select, signal, subprocess, time\nfrom mac_owned_unreaped_r1 import require_waitid, capture_child, exit_observation, observed_returncode, stop_once_unreaped, prepare_fixed_ps_contract\n\nclass CommandRefused(RuntimeError):pass\ndef need(value,code):\n    if not value:raise CommandRefused(code)\ndef sha(raw):return hashlib.sha256(raw).hexdigest()\n\nclass Signals:\n    def __init__(self):\n        self.protected=0;self.pending=None\n    def receive(self,signum,_frame):\n        self.pending=signum\n        if not self.protected:raise KeyboardInterrupt()\n    def install(self):\n        signal.signal(signal.SIGTERM,self.receive);signal.signal(signal.SIGINT,self.receive)\n    @contextmanager\n    def critical(self):\n        self.protected+=1\n        try:yield\n        finally:self.protected-=1\n\nclass Commands:\n    def __init__(self,signals):\n        self.signals=signals;self.rows=[]\n    def run(self,label,argv,*,until,allow_cancelled_cleanup=False,maximum=2*1024*1024):\n        need(isinstance(label,str) and label.replace(\'-\',\'\').replace(\'_\',\'\').isalnum(),\'safe_command_label\')\n        need(type(maximum) is int and 0<maximum<=2*1024*1024,\'fixed_command_output_bound\')\n        need(isinstance(argv,list) and argv and all(isinstance(x,str) for x in argv),\'explicit_argv\')\n        def remaining():\n            if not allow_cancelled_cleanup:need(self.signals.pending is None,\'command_cancelled\')\n            n=until-time.monotonic();need(n>0,\'original_command_deadline_exhausted\');return n\n        require_waitid();remaining()\n        fixed_ps_contract=prepare_fixed_ps_contract(argv,until=until)\n        remaining()\n        started=time.monotonic();row=None;out=bytearray();err=bytearray()\n        try:\n            with self.signals.critical():\n                remaining()\n                p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,\n                    env={\'PATH\':\'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin\',\'LANG\':\'C\',\'LC_ALL\':\'C\'},\n                    start_new_session=True,close_fds=True)\n                row={\'label\':label,\'argv\':list(argv),\'process\':p,\'custody\':None,\n                     \'stopAttempted\':False,\'streamsCloseAttempted\':False,\'streamsClosed\':False,\n                     \'completeBeforeDeadline\':False,\'errorType\':None,\'errorCode\':None}\n                self.rows.append(row)\n            row[\'custody\']=capture_child(p,until=until,fixed_ps_contract=fixed_ps_contract)\n            streams={p.stdout.fileno():out,p.stderr.fileno():err}\n            for fd in streams:os.set_blocking(fd,False)\n            event=None\n            while streams or event is None:\n                left=remaining()\n                ready,_,_=select.select(list(streams),[],[],min(left,0.025))\n                for fd in ready:\n                    data=os.read(fd,65536)\n                    if not data:del streams[fd]\n                    else:\n                        target=streams[fd];target.extend(data)\n                        need(len(target)<=maximum,\'command_output_bound\')\n                event=exit_observation(p)\n            remaining()\n            row[\'completeBeforeDeadline\']=True\n            row[\'observedExit\']=event\n            row[\'observedExitCode\']=observed_returncode(event)\n        except BaseException as error:\n            if row is None:raise\n            row[\'errorType\']=type(error).__name__\n            row[\'errorCode\']=str(error) if isinstance(error,CommandRefused) else None\n        finally:\n            if row is not None:\n                with self.signals.critical():\n                    row[\'stopAttempted\']=True\n                    try:row[\'cleanup\']=stop_once_unreaped(row[\'process\'],row[\'custody\'],fixed_ps_contract=fixed_ps_contract)\n                    except BaseException as error:\n                        row[\'cleanup\']={\'ok\':False,\'outcomeUnknown\':True,\n                            \'errorType\':type(error).__name__,\'directChildReaped\':row[\'process\'].returncode is not None,\n                            \'allGroupRowsEmptyAfterReap\':False}\n                    row[\'streamsCloseAttempted\']=True\n                    errors=[]\n                    for stream in (row[\'process\'].stdout,row[\'process\'].stderr):\n                        try:stream.close()\n                        except BaseException as error:errors.append(type(error).__name__)\n                    row[\'streamsClosed\']=not errors\n                    row[\'streamCloseErrors\']=errors\n        p=row[\'process\'];cleanup=row[\'cleanup\']\n        public={\'label\':label,\'argv\':list(argv),\'pid\':p.pid,\'exitCode\':p.returncode,\n            \'completeBeforeDeadline\':row[\'completeBeforeDeadline\'],\n            \'commandDeadlineMonotonic\':until,\'elapsedSeconds\':time.monotonic()-started,\n            \'errorType\':row[\'errorType\'],\'errorCode\':row[\'errorCode\'],\'cleanup\':cleanup,\n            \'stdoutBytes\':len(out),\'stdoutSha256\':sha(out),\'stderrBytes\':len(err),\'stderrSha256\':sha(err),\n            \'streamsClosed\':row[\'streamsClosed\'],\n            \'outcomeUnknown\':not(row[\'completeBeforeDeadline\'] and cleanup.get(\'ok\') is True\n                and cleanup.get(\'directChildReaped\') is True and cleanup.get(\'allGroupRowsEmptyAfterReap\') is True\n                and row[\'streamsClosed\'] and row[\'errorType\'] is None)}\n        row[\'public\']=public\n        return public,bytes(out),bytes(err)\n    def public(self):\n        values=[r.get(\'public\') for r in self.rows]\n        return {\'commands\':values,\'allOwnedCommandsStopped\':all(v is not None\n            and v[\'cleanup\'].get(\'directChildReaped\') is True\n            and v[\'cleanup\'].get(\'allGroupRowsEmptyAfterReap\') is True\n            and v[\'streamsClosed\'] for v in values),\n            \'unknownCommandCount\':sum(v is None or v[\'outcomeUnknown\'] for v in values)}\n', 'mac_native_process_observer_r1.py': '#!/usr/bin/env python3\n"""Read-only outer-parent custody of one Node -> launcher -> native process chain.\n\nNo credential, application-file or network reads. The response pipe\'s write end\nis retained exclusively by the outer parent; a shared run directory is not an\nauthority channel. Exact Apple public libproc declarations and proc_bsdinfo ABI:\n  xnu/bsd/sys/proc_info.h Git blob 718a69fcf5340f547893ed8dc85908f253c1ce81\n  xnu/libsyscall/wrappers/libproc/libproc.h 602e4fe897d1fc5a7ceacc372c78f184ea242bfe\n  xnu/libsyscall/wrappers/libproc/libproc.c c3e7369f886fbb7bbc8d77f8fca9ecc943bb5f4e\n"""\nfrom __future__ import annotations\n\nimport ctypes\nimport json\nimport os\nfrom pathlib import Path\nimport re\nimport select\nimport sys\nimport time\n\n\nfrom mac_owned_unreaped_r1 import exit_observation as retained_exit_observation\n\nclass ObservationRefused(RuntimeError):\n    pass\n\n\ndef require(value, code):\n    if not value:\n        raise ObservationRefused(code)\n\n\nclass BsdInfo(ctypes.Structure):\n    _fields_ = [(name, ctypes.c_uint32) for name in (\n        \'flags\', \'status\', \'xstatus\', \'pid\', \'ppid\', \'uid\', \'gid\',\n        \'ruid\', \'rgid\', \'svuid\', \'svgid\', \'reserved\',\n    )] + [\n        (\'comm\', ctypes.c_char * 16), (\'name\', ctypes.c_char * 32),\n        (\'nfiles\', ctypes.c_uint32), (\'pgid\', ctypes.c_uint32),\n        (\'jobc\', ctypes.c_uint32), (\'ttydev\', ctypes.c_uint32),\n        (\'tty_pgid\', ctypes.c_uint32), (\'nice\', ctypes.c_int32),\n        (\'birth_sec\', ctypes.c_uint64), (\'birth_usec\', ctypes.c_uint64),\n    ]\n\n\nclass ProcessReader:\n    def __init__(self):\n        require(sys.platform == \'darwin\' and ctypes.sizeof(BsdInfo) == 136,\n                \'exact_darwin_process_abi\')\n        self.lib = ctypes.CDLL(\'/usr/lib/libproc.dylib\', use_errno=True)\n        self.lib.proc_pidinfo.argtypes = [\n            ctypes.c_int, ctypes.c_int, ctypes.c_uint64,\n            ctypes.c_void_p, ctypes.c_int,\n        ]\n        self.lib.proc_pidinfo.restype = ctypes.c_int\n        self.lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]\n        self.lib.proc_pidpath.restype = ctypes.c_int\n        self.lib.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]\n        self.lib.proc_listchildpids.restype = ctypes.c_int\n\n    def read(self, pid):\n        require(type(pid) is int and pid > 1, \'exact_pid_required\')\n        info = BsdInfo()\n        count = self.lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))\n        require(count == ctypes.sizeof(info) and info.pid == pid, \'process_info_complete\')\n        executable = ctypes.create_string_buffer(4096)\n        length = self.lib.proc_pidpath(pid, executable, len(executable))\n        require(0 < length < len(executable), \'process_path_complete\')\n        actual_path = executable.value.decode(\'utf-8\', errors=\'strict\')\n        require(actual_path.startswith(\'/\'), \'absolute_process_path\')\n        # A second birth read binds path lookup to the same process lifetime.\n        again = BsdInfo()\n        count = self.lib.proc_pidinfo(pid, 3, 0, ctypes.byref(again), ctypes.sizeof(again))\n        require(count == ctypes.sizeof(again)\n                and (again.pid, again.ppid, again.pgid, again.uid,\n                     again.birth_sec, again.birth_usec)\n                == (info.pid, info.ppid, info.pgid, info.uid,\n                    info.birth_sec, info.birth_usec), \'process_identity_changed_during_read\')\n        return {\n            \'pid\': pid, \'ppid\': info.ppid, \'pgid\': info.pgid, \'uid\': info.uid,\n            \'birthSec\': info.birth_sec, \'birthUsec\': info.birth_usec,\n            \'executable\': str(Path(actual_path).resolve()),\n        }\n\n    def children(self, verified_pid):\n        # proc_listchildpids returns a PID count, not bytes. The fixed bound is\n        # fail-closed; it is not a process-wide command/argument enumeration.\n        buffer = (ctypes.c_int * 32)()\n        count = self.lib.proc_listchildpids(verified_pid, buffer, ctypes.sizeof(buffer))\n        require(0 <= count < len(buffer), \'bounded_owned_child_list\')\n        return [int(buffer[i]) for i in range(count) if buffer[i] > 1]\n\n\ndef stable_identity(first, second):\n    return first == second\n\n\nclass OwnedNativeObserver:\n    def __init__(self, expected, *, critical):\n        require(callable(critical), \'observer_fd_signal_guard_required\')\n        self.critical = critical\n        self.fd_closures = {}\n        self.expected = {\n            \'nodeExecutable\': str(Path(expected[\'nodeExecutable\']).resolve()),\n            \'nativeExecutable\': str(Path(expected[\'nativeExecutable\']).resolve()),\n        }\n        self.reader = ProcessReader()\n        self.request_read = self.response_write = None\n        self.child_fds = ()\n        self.child_ends_closed = False\n        self.report = {\n            \'required\': True, \'verified\': False,\n            \'ackAuthority\': \'outer_parent_only_anonymous_pipe_write_end\',\n            \'applicationFilesRead\': False, \'networkUsed\': False,\n            \'otherProcessArgumentsRead\': False, \'requests\': 0,\n        }\n        try:\n            with self.critical():\n                self.request_read, request_write = os.pipe()\n                for fd in (self.request_read, request_write):\n                    self.fd_closures[fd] = {\'fd\': fd, \'attempted\': False, \'closed\': False, \'errorType\': None}\n                response_read, self.response_write = os.pipe()\n                for fd in (response_read, self.response_write):\n                    self.fd_closures[fd] = {\'fd\': fd, \'attempted\': False, \'closed\': False, \'errorType\': None}\n                self.child_fds = (request_write, response_read)\n            self.child_env = {\n                \'HEPTABAO_NATIVE_OBSERVER_REQUEST_FD\': str(request_write),\n                \'HEPTABAO_NATIVE_OBSERVER_RESPONSE_FD\': str(response_read),\n            }\n            os.set_blocking(self.request_read, False)\n            os.set_blocking(self.response_write, False)\n            self.buffer = bytearray()\n            self.handled = False\n            self.rejected = False\n        except BaseException:\n            self.close()\n            raise\n\n    def close_fd_once(self, fd):\n        require(fd in self.fd_closures, \'unknown_observer_fd_no_close\')\n        row = self.fd_closures[fd]\n        if row[\'attempted\']:\n            return row[\'closed\']\n        with self.critical():\n            row[\'attempted\'] = True\n            try:\n                os.close(fd)\n                row[\'closed\'] = True\n            except OSError as error:\n                row[\'errorType\'] = type(error).__name__\n        return row[\'closed\']\n\n    def parent_after_spawn(self, proc):\n        closed = [self.close_fd_once(fd) for fd in self.child_fds]\n        self.child_ends_closed = all(closed)\n        require(self.child_ends_closed, \'observer_child_end_close_unconfirmed\')\n        self.proc = proc\n        self.outer_pid = os.getpid()\n\n    def verify_chain(self, request, deadline):\n        require(set(request) == {\'schema\', \'nonce\', \'nodePid\', \'launcherPid\'},\n                \'observer_request_shape\')\n        require(request[\'schema\'] == \'heptabao.owned-native-request.v1\'\n                and isinstance(request[\'nonce\'], str)\n                and re.fullmatch(r\'[0-9a-f]{64}\', request[\'nonce\']) is not None,\n                \'observer_request_nonce\')\n        require(type(request[\'nodePid\']) is int and request[\'nodePid\'] == self.proc.pid\n                and type(request[\'launcherPid\']) is int\n                and request[\'launcherPid\'] > 1, \'observer_owned_request_pids\')\n        node_pid, launcher_pid = self.proc.pid, request[\'launcherPid\']\n        node = self.reader.read(node_pid)\n        require(retained_exit_observation(self.proc) is None and node[\'ppid\'] == self.outer_pid\n                and node[\'pgid\'] == node_pid and node[\'uid\'] == os.geteuid()\n                and node[\'executable\'] == self.expected[\'nodeExecutable\'],\n                \'owned_node_birth_parent_group_executable\')\n        pinned_launcher = None\n        while time.monotonic() < deadline:\n            require(retained_exit_observation(self.proc) is None and stable_identity(node, self.reader.read(node_pid)),\n                    \'owned_node_lifetime_changed\')\n            launcher = self.reader.read(launcher_pid)\n            require(launcher[\'ppid\'] == node_pid and launcher[\'pgid\'] == node_pid\n                    and launcher[\'uid\'] == node[\'uid\']\n                    and (launcher[\'birthSec\'], launcher[\'birthUsec\'])\n                    >= (node[\'birthSec\'], node[\'birthUsec\']),\n                    \'launcher_real_parent_group_birth\')\n            # /usr/bin/env may briefly precede the pinned shebang Node runtime.\n            # No ACK is issued until the exact managed Node launcher is live.\n            if launcher[\'executable\'] != self.expected[\'nodeExecutable\']:\n                time.sleep(0.025)\n                continue\n            if pinned_launcher is None:\n                pinned_launcher = launcher\n            require(stable_identity(pinned_launcher, launcher), \'launcher_lifetime_changed\')\n            native_candidates = []\n            for pid in self.reader.children(launcher_pid):\n                try:\n                    child = self.reader.read(pid)\n                except ObservationRefused:\n                    continue\n                if child[\'executable\'] == self.expected[\'nativeExecutable\']:\n                    native_candidates.append(child)\n            require(len(native_candidates) <= 1, \'single_exact_native_child\')\n            if not native_candidates:\n                time.sleep(0.025)\n                continue\n            native = native_candidates[0]\n            require(native[\'ppid\'] == launcher_pid and native[\'pgid\'] == node_pid\n                    and native[\'uid\'] == node[\'uid\']\n                    and (native[\'birthSec\'], native[\'birthUsec\'])\n                    >= (launcher[\'birthSec\'], launcher[\'birthUsec\']),\n                    \'native_real_parent_group_birth\')\n            first = {\'node\': node, \'launcher\': launcher, \'native\': native}\n            time.sleep(0.02)\n            second = {key: self.reader.read(value[\'pid\']) for key, value in first.items()}\n            require(retained_exit_observation(self.proc) is None and first == second,\n                    \'entire_chain_birth_and_executable_recheck\')\n            require(time.monotonic() < deadline, \'observer_deadline_after_recheck\')\n            return first\n        raise ObservationRefused(\'owned_native_chain_observation_deadline\')\n\n    def poll(self, outer_deadline):\n        if self.handled:\n            return\n        require(time.monotonic() < outer_deadline, \'parent_deadline_before_observation\')\n        ready, _, _ = select.select([self.request_read], [], [], 0)\n        if not ready:\n            return\n        part = os.read(self.request_read, 8193)\n        if not part:\n            return\n        self.buffer.extend(part)\n        require(len(self.buffer) <= 8192, \'bounded_observer_request\')\n        if b\'\\n\' not in self.buffer:\n            return\n        self.handled = True\n        self.report[\'requests\'] = 1\n        nonce = None\n        observation_deadline = min(time.monotonic() + 3, outer_deadline)\n        try:\n            line, remaining = self.buffer.split(b\'\\n\', 1)\n            require(not remaining, \'single_observer_request\')\n            request = json.loads(line.decode(\'utf-8\'))\n            nonce = request.get(\'nonce\') if isinstance(request, dict) else None\n            chain = self.verify_chain(request, observation_deadline)\n            require(time.monotonic() < observation_deadline, \'observer_deadline_before_success_ack\')\n            ack = {\'schema\': \'heptabao.owned-native-ack.v1\',\n                   \'nonce\': nonce, \'verified\': True, \'identities\': chain}\n        except Exception as error:\n            self.rejected = True\n            safe_error = str(error) if isinstance(error, ObservationRefused) else type(error).__name__\n            self.report[\'error\'] = safe_error\n            ack = {\'schema\': \'heptabao.owned-native-ack.v1\',\n                   \'nonce\': nonce, \'verified\': False, \'error\': safe_error}\n        data = (json.dumps(ack, separators=(\',\', \':\')) + \'\\n\').encode()\n        require(len(data) <= 4096, \'bounded_atomic_observer_ack\')\n        if ack[\'verified\']:\n            require(time.monotonic() < observation_deadline, \'observer_deadline_at_success_ack\')\n        count = os.write(self.response_write, data)\n        require(count == len(data), \'complete_observer_ack\')\n        if ack[\'verified\']:\n            self.report.update(verified=True, identities=chain,\n                               birthMicrosecondsBound=True,\n                               beforeFirstNativeRpc=True,\n                               nativeObservationBudgetSeconds=3,\n                               parentAbsoluteDeadlinePreserved=True)\n        require(self.close_fd_once(self.response_write), \'observer_response_end_close_unconfirmed\')\n        self.response_write = None\n\n    def close(self):\n        for fd in self.fd_closures:\n            self.close_fd_once(fd)\n        self.child_ends_closed = all(self.fd_closures[fd][\'closed\'] for fd in self.child_fds)\n        self.request_read = None\n        self.response_write = None\n        self.report[\'pipeFdClosures\'] = [dict(row) for row in self.fd_closures.values()]\n        self.report[\'allPipeFdsClosed\'] = all(row[\'closed\'] for row in self.fd_closures.values())\n        return self.report[\'allPipeFdsClosed\']\n', 'mac_finite_lsof_fields_r1.py': '#!/usr/bin/env python3\n"""Parse only explicit numeric lsof -F fields; never request names or arguments."""\nimport re\n\n\nclass FieldRefused(RuntimeError):\n    pass\n\n\ndef need(value, code):\n    if not value:\n        raise FieldRefused(code)\n\n\ndef decimal(raw, *, positive=False):\n    need(type(raw) is bytes and re.fullmatch(rb"[0-9]{1,20}", raw) is not None,\n         "finite_lsof_decimal_field")\n    value = int(raw)\n    need(value <= 18446744073709551615 and (not positive or value > 0),\n         "finite_lsof_decimal_bound")\n    return value\n\n\ndef parse_fields(raw, expected_pids):\n    need(type(raw) is bytes and 0 < len(raw) <= 1048576\n         and raw.endswith(b"\\x00\\n"), "finite_lsof_complete_bounded_stream")\n    need(type(expected_pids) is set and 0 < len(expected_pids) <= 9\n         and all(type(pid) is int and pid > 1 for pid in expected_pids),\n         "finite_lsof_exact_pid_set")\n    processes = {}\n    current = None\n    total_files = 0\n    for record in raw.split(b"\\n")[:-1]:\n        need(record and record.endswith(b"\\x00"), "finite_lsof_record_terminator")\n        tokens = record[:-1].split(b"\\x00")\n        need(tokens and all(token and len(token) <= 128 for token in tokens),\n             "finite_lsof_field_size")\n        values = {}\n        for token in tokens:\n            tag, value = token[:1], token[1:]\n            need(tag in (b"p", b"u", b"f", b"a", b"t", b"D", b"i")\n                 and tag not in values, "finite_lsof_only_requested_unique_fields")\n            values[tag] = value\n        if tokens[0].startswith(b"p"):\n            need(set(values) == {b"p", b"u"}, "finite_lsof_process_record_shape")\n            pid = decimal(values[b"p"], positive=True)\n            uid = decimal(values[b"u"])\n            need(pid in expected_pids and pid not in processes and uid == 501,\n                 "finite_lsof_current_selected_process_owner")\n            current = {"pid": pid, "uid": uid, "files": []}\n            processes[pid] = current\n            continue\n        need(tokens[0].startswith(b"f") and current is not None\n             and b"f" in values and b"t" in values,\n             "finite_lsof_file_record_shape")\n        descriptor = values[b"f"]\n        need(re.fullmatch(rb"(?:[0-9]{1,7}|cwd|rtd|txt|mem|mmap|DEL|NOFD)", descriptor) is not None,\n             "finite_lsof_bounded_descriptor_kind")\n        file_type = values[b"t"]\n        need(re.fullmatch(rb"[A-Za-z0-9_? -]{1,24}", file_type) is not None,\n             "finite_lsof_file_type_scalar")\n        access = values.get(b"a", b"")\n        need(access in (b"", b"r", b"w", b"u"), "finite_lsof_known_access_mode")\n        regular = file_type in (b"REG", b"VREG")\n        device = inode = None\n        if regular:\n            need(b"D" in values and b"i" in values\n                 and re.fullmatch(rb"0x[0-9a-fA-F]{1,16}", values[b"D"]) is not None,\n                 "finite_lsof_hex_device")\n            device = int(values[b"D"], 16)\n            inode = decimal(values[b"i"], positive=True)\n        need(not regular or device is not None and inode is not None,\n             "finite_lsof_regular_inode_complete")\n        current["files"].append({"descriptor": descriptor.decode("ascii"),\n            "type": file_type.decode("ascii"), "access": access.decode("ascii"),\n            "device": device, "inode": inode, "regularFileIdentityComplete": regular,\n            "nonRegularMetadataNotUsedAsFileIdentity": not regular})\n        total_files += 1\n        need(total_files <= 16384, "finite_lsof_total_descriptor_bound")\n    need(set(processes) == expected_pids, "finite_lsof_every_selected_pid_reported")\n    return {"processes": list(processes.values()), "fileRecords": total_files,\n            "requestedPathOrCommandNameFields": False,\n            "kernelWideVisibilityClaimed": False}\n\n\ndef match_files(parsed, targets):\n    need(type(targets) is list and len(targets) <= 45, "finite_inode_target_bound")\n    by_inode = {}\n    for target in targets:\n        need(set(target) == {"ordinal", "kind", "member", "device", "inode"}\n             and type(target["ordinal"]) is int and 0 <= target["ordinal"] < 45\n             and target["kind"] in ("database", "cache", "legacy")\n             and target["member"] in ("base", "wal", "shm", "journal", "file")\n             and type(target["device"]) is type(target["inode"]) is int,\n             "finite_current_target_identity_shape")\n        key = (target["device"], target["inode"])\n        need(key not in by_inode, "finite_current_target_inodes_unique")\n        by_inode[key] = target\n    matches = []\n    for process in parsed["processes"]:\n        for item in process["files"]:\n            target = by_inode.get((item["device"], item["inode"]))\n            if target is not None:\n                need(item["regularFileIdentityComplete"], "matched_inode_is_complete_regular_file")\n                matches.append({"pid": process["pid"], "uid": process["uid"],\n                    "targetOrdinal": target["ordinal"], "targetKind": target["kind"],\n                    "member": target["member"], "descriptor": item["descriptor"],\n                    "access": item["access"], "type": item["type"],\n                    "deviceAndInodeExact": True})\n    return matches\n'}, 'sourcePins': {'mac_owned_unreaped_r1.py': 'd735a9e9330e1260d44ad9e4c854d50094e20d85fe5633ddd9042281b3346298', 'mac_owned_commands_r1.py': '71a11bf9a0510c991b78c9bc3f094f315bf4914485b9cfda81c6e501eaf73530', 'mac_native_process_observer_r1.py': 'cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b', 'mac_finite_lsof_fields_r1.py': '9e19a42760a60d94aa01bb89a038634eff34c9d291f69285e253578128b81bf1'}, 'processes': [{'identity': 'ps:Sun Oct  4 19:43:03 2026', 'name': '/Users/qianqi/.openclaw/authbus-relay/bin/cli-proxy-api', 'pid': 964, 'uid': 501}, {'identity': 'ps:Sun Oct  4 19:43:03 2026', 'name': '/Users/qianqi/.openclaw/authbus-relay/bin/authbus-relay-bridge', 'pid': 983, 'uid': 501}, {'identity': 'ps:Sun Oct  4 19:43:03 2026', 'name': '/Users/qianqi/.openclaw/authbus-relay/bin/egressguard', 'pid': 987, 'uid': 501}, {'identity': 'ps:Sun Oct  4 19:43:03 2026', 'name': '/Users/qianqi/.openclaw/authbus-relay/bin/relayfront', 'pid': 989, 'uid': 501}, {'identity': 'ps:Mon Oct  5 11:49:28 2026', 'name': '/opt/homebrew/opt/node/bin/node', 'pid': 18437, 'uid': 501}, {'identity': 'ps:Wed Nov  4 09:04:14 2026', 'name': '/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex', 'pid': 66414, 'uid': 501}, {'identity': 'ps:Wed Nov  4 09:04:46 2026', 'name': '/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex', 'pid': 66687, 'uid': 501}, {'identity': 'ps:Tue Nov  3 15:14:58 2026', 'name': 'node', 'pid': 89324, 'uid': 501}, {'identity': 'ps:Tue Nov  3 15:14:58 2026', 'name': '/opt/homebrew/lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex', 'pid': 89325, 'uid': 501}]}

codes, fds = set(), []
commands = None
write_directories = {}
report = {'schema': 'heptabao.actual-finite-consumer-inode-observation.r2', 'ok': False,
          'databaseContentsRead': False, 'credentialValuesRead': False, 'sqliteCalls': 0,
          'keychainReads': 0, 'otherProcessArgumentsRead': False, 'otherProcessEnvironmentRead': False,
          'networkRequests': 0, 'productionWrites': 0, 'serviceActions': 0,
          'processSignalsToObservedConsumers': 0, 'completeActiveConsumerClosure': False,
          'consumerQuiescenceQualified': False, 'kernelWideVisibilityClaimed': False,
          'noMatchingOpenFileImpliesNoCachedCredentialUse': False,
          'observationIsDiscreteNotAtomic': True, 'automaticRetry': False,
          'parentSeconds': 45, 'lsofSeconds': 10, 'supervisorSeconds': 70}


def need(value, code):
    if not value:
        codes.add(code)
        raise RuntimeError(code)


def remaining():
    left = UNTIL - time.monotonic()
    need(left > 0, 'finite_original_parent_deadline')
    return left


def full9(value):
    return tuple(str(getattr(value, name)) for name in ('st_dev', 'st_ino', 'st_uid',
        'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def opened(path, flags, *, dir_fd=None, mode=0o600):
    remaining()
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, mode,
                 **({} if dir_fd is None else {'dir_fd': dir_fd}))
    row = {'fd': fd, 'closeAttempts': 0, 'closed': False}
    fds.append(row)
    return row


def closed(row):
    if row['closeAttempts']:
        return row['closed']
    row['closeAttempts'] = 1
    os.close(row['fd'])
    row['closed'] = True
    return True


def private(path, raw):
    need(path.parent in (ROOT / 'code', ROOT / 'output') and isinstance(raw, bytes)
         and len(raw) <= 1048576, 'finite_create_only_output_scope')
    for directory, item in write_directories.items():
        named = os.stat(directory.name, dir_fd=item['parent']['fd'], follow_symlinks=False)
        need(full9(named)[:5] == full9(os.fstat(item['row']['fd']))[:5] == item['first5'],
             'finite_owned_output_directory_unchanged')
    parent = write_directories[path.parent]['row']
    row = opened(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, dir_fd=parent['fd'])
    try:
        offset = 0
        while offset < len(raw):
            remaining()
            count = os.write(row['fd'], raw[offset:offset + 65536])
            need(count > 0, 'finite_output_complete_write')
            offset += count
        os.fsync(row['fd'])
        info = os.fstat(row['fd'])
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
             and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
             and info.st_size == len(raw) and full9(info) == full9(os.stat(path.name,
                 dir_fd=parent['fd'], follow_symlinks=False)),
             'finite_private_output_generation')
        os.fsync(parent['fd'])
    finally:
        closed(row)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def public_file(path, expected):
    row = opened(path, os.O_RDONLY)
    try:
        before = os.fstat(row['fd'])
        need(stat.S_ISREG(before.st_mode) and before.st_uid in (0, 501)
             and not stat.S_IMODE(before.st_mode) & 0o022 and before.st_nlink == 1
             and before.st_size == expected[0] <= 1048576,
             'finite_exact_bounded_public_executable')
        content = bytearray()
        while len(content) <= before.st_size:
            remaining()
            block = os.read(row['fd'], min(65536, before.st_size + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        need(len(content) == before.st_size and hashlib.sha256(content).hexdigest() == expected[1]
             and full9(before) == full9(os.fstat(row['fd'])) == full9(Path(path).lstat()),
             'finite_whole_public_executable_unchanged')
        return full9(before)
    finally:
        closed(row)


class KnownFiles:
    def __init__(self):
        self.directories, self.files, self.absences = {}, [], []
        previous = None
        for path in (Path('/'), Path('/Users'), CALLER_HOME, LIVE):
            before = path.lstat() if previous is None else os.stat(path.name, dir_fd=previous['row']['fd'], follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode) and before.st_uid == (0 if path in (Path('/'), Path('/Users')) else 501)
                 and not stat.S_IMODE(before.st_mode) & 0o022, 'finite_known_parent_owner_and_mode')
            row = opened(str(path) if previous is None else path.name, os.O_RDONLY | os.O_DIRECTORY,
                         dir_fd=None if previous is None else previous['row']['fd'])
            need(full9(before) == full9(os.fstat(row['fd'])), 'finite_known_parent_open_identity')
            current = {'row': row, 'first5': full9(before)[:5], 'path': path, 'parent': previous}
            self.directories[path] = current
            previous = current

    def parent(self, path):
        need(path.is_relative_to(LIVE) and path != LIVE and '..' not in path.parts,
             'finite_source_file_path_scope')
        previous = self.directories[LIVE]
        current_path = LIVE
        for component in path.parent.relative_to(LIVE).parts:
            current_path = current_path / component
            if current_path in self.directories:
                previous = self.directories[current_path]
                continue
            try:
                named = os.stat(component, dir_fd=previous['row']['fd'], follow_symlinks=False)
            except FileNotFoundError:
                self.absences.append({'parent': previous, 'name': component})
                return None
            need(stat.S_ISDIR(named.st_mode) and named.st_uid == 501
                 and not stat.S_IMODE(named.st_mode) & 0o022, 'finite_source_directory_custody')
            row = opened(component, os.O_RDONLY | os.O_DIRECTORY, dir_fd=previous['row']['fd'])
            need(full9(named) == full9(os.fstat(row['fd'])), 'finite_source_directory_open_identity')
            current = {'row': row, 'first5': full9(named)[:5], 'path': current_path, 'parent': previous}
            self.directories[current_path] = current
            previous = current
        return previous

    def hold(self, path, ordinal, kind, member):
        parent = self.parent(path)
        public = {'ordinal': ordinal, 'kind': kind, 'member': member, 'present': False}
        if parent is None:
            self.files.append({'path': path, 'public': public, 'row': None, 'parent': None})
            return
        try:
            named = os.stat(path.name, dir_fd=parent['row']['fd'], follow_symlinks=False)
        except FileNotFoundError:
            self.absences.append({'parent': parent, 'name': path.name})
            self.files.append({'path': path, 'public': public, 'row': None, 'parent': parent})
            return
        need(stat.S_ISREG(named.st_mode) and named.st_uid == 501 and named.st_gid == 20
             and named.st_nlink == 1 and not stat.S_IMODE(named.st_mode) & 0o022,
             'finite_selected_regular_single_owner_file')
        row = opened(path.name, os.O_RDONLY, dir_fd=parent['row']['fd'])
        need(full9(named) == full9(os.fstat(row['fd'])), 'finite_metadata_only_held_file')
        public.update(present=True, device=named.st_dev, inode=named.st_ino, size=named.st_size)
        self.files.append({'path': path, 'public': public, 'row': row,
                           'parent': parent, 'full9': full9(named)})

    def verify(self):
        for path, item in self.directories.items():
            remaining()
            current = path.lstat() if item['parent'] is None else os.stat(path.name,
                dir_fd=item['parent']['row']['fd'], follow_symlinks=False)
            need(full9(current)[:5] == full9(os.fstat(item['row']['fd']))[:5] == item['first5'],
                 'finite_all_parent_inodes_unchanged')
        differences = []
        names = ('device', 'inode', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs')
        for item in self.files:
            if item['row'] is not None:
                current = os.stat(item['path'].name, dir_fd=item['parent']['row']['fd'], follow_symlinks=False)
                named, held = full9(current), full9(os.fstat(item['row']['fd']))
                if not named == held == item['full9']:
                    differences.append({'ordinal': item['public']['ordinal'],
                        'kind': item['public']['kind'], 'member': item['public']['member'],
                        'changedFields': [name for number, name in enumerate(names)
                            if named[number] != held[number] or named[number] != item['full9'][number]]})
        if differences:
            report['sourceGenerationDifferences'] = differences
        need(not differences, 'finite_known_file_full9_unchanged')
        for item in self.absences:
            try:
                os.stat(item['name'], dir_fd=item['parent']['row']['fd'], follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise RuntimeError('finite_known_absence_changed')

    def targets(self):
        return [{key: item['public'][key] for key in ('ordinal', 'kind', 'member', 'device', 'inode')}
                for item in self.files if item['public']['present']]

    def packet(self):
        return [{'path': str(item['path']), 'full9': item.get('full9'),
                 'metadata': item['public'], 'fileContentsRead': False} for item in self.files]


def match_prior_start(identity, previous):
    need(type(previous) is str and previous.startswith('ps:'), 'finite_native_start_identity_shape')
    actual = time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(identity['birthSec'])).split()
    wanted = previous[3:].split()
    need(len(actual) == len(wanted) == 5 and actual[:2] == wanted[:2]
         and int(actual[2]) == int(wanted[2]) and actual[3:] == wanted[3:],
         'finite_prior_native_start_second_matches_current_full_birth')


def safe_commands():
    if commands is None:
        return []
    return [{key: row['public'][key] for key in ('label', 'pid', 'exitCode', 'completeBeforeDeadline',
             'cleanup', 'stdoutBytes', 'stderrBytes', 'streamsClosed', 'outcomeUnknown')}
            if row.get('public') is not None else {'label': row['label'], 'outcomeUnknown': True}
            for row in commands.rows]


try:
    os.umask(0o077)
    sys.dont_write_bytecode = True
    locale.setlocale(locale.LC_TIME, 'C')
    need(sys.platform == 'darwin' and os.getuid() == 501 and os.getgid() == 20
         and Path(sys.executable).resolve(strict=True) == PYTHON, 'finite_exact_mac_runtime')
    before_runtime = {path: public_file(path, expected) for path, expected in RUNTIME_PINS.items()}
    need(set(PAYLOAD['sources']) == {'mac_owned_unreaped_r1.py', 'mac_owned_commands_r1.py',
         'mac_native_process_observer_r1.py', 'mac_finite_lsof_fields_r1.py'}, 'finite_four_source_modules')
    for name, source in PAYLOAD['sources'].items():
        need(hashlib.sha256(source.encode()).hexdigest() == PAYLOAD['sourcePins'][name],
             'finite_qualified_source_whole_pin')
        ast.parse(source)
    need({item['pid'] for item in PAYLOAD['processes']} == {964, 983, 987, 989, 18437, 66414, 66687, 89324, 89325}
         and len(PAYLOAD['processes']) == 9, 'finite_nine_observed_processes_only')
    files = KnownFiles()
    for path in (ROOT, ROOT / 'code', ROOT / 'output'):
        parent = files.directories[CALLER_HOME]['row'] if path == ROOT else write_directories[ROOT]['row']
        os.mkdir(path.name, mode=0o700, dir_fd=parent['fd'])
        row = opened(path.name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent['fd'])
        info = os.fstat(row['fd'])
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
             and stat.S_IMODE(info.st_mode) == 0o700 and full9(info) == full9(os.stat(
                 path.name, dir_fd=parent['fd'], follow_symlinks=False)), 'finite_new_private_output_directory')
        write_directories[path] = {'row': row, 'parent': parent, 'first5': full9(info)[:5]}
        os.fsync(parent['fd'])
    files.verify()
    for name, source in PAYLOAD['sources'].items():
        private(ROOT / 'code' / name, source.encode())
        module = types.ModuleType(Path(name).stem)
        module.__file__ = str(ROOT / 'code' / name)
        sys.modules[module.__name__] = module
        exec(compile(source, module.__file__, 'exec'), module.__dict__)
    from mac_owned_commands_r1 import Commands, Signals
    from mac_native_process_observer_r1 import ProcessReader
    from mac_finite_lsof_fields_r1 import parse_fields, match_files
    signals = Signals()
    signals.install()
    commands = Commands(signals)
    reader = ProcessReader()
    before_processes = {}
    for index, previous in enumerate(PAYLOAD['processes']):
        remaining()
        report['processAdmissionOrdinal'] = index
        current = reader.read(previous['pid'])
        need(current['uid'] == 501, 'finite_observed_process_still_same_owner')
        match_prior_start(current, previous['identity'])
        if previous['name'].startswith('/'):
            need(current['executable'] == str(Path(previous['name']).resolve(strict=True)),
                 'finite_observed_executable_path_same')
        before_processes[previous['pid']] = current
    report.pop('processAdmissionOrdinal')
    report['processAdmissionsComplete'] = len(before_processes)
    paths = [LIVE / 'agents' / agent / 'agent/openclaw-agent.sqlite' for agent in AGENTS]
    paths.append(LIVE / 'state/openclaw.sqlite')
    ordinal = 0
    for path in paths:
        for suffix, member in (('', 'base'), ('-wal', 'wal'), ('-shm', 'shm'), ('-journal', 'journal')):
            files.hold(Path(str(path) + suffix), ordinal, 'database', member)
            ordinal += 1
    for name in CACHES:
        files.hold(LIVE / 'authbus' / name, ordinal, 'cache', 'file')
        ordinal += 1
    for agent in AGENTS:
        for name in LEGACY:
            files.hold(LIVE / 'agents' / agent / 'agent' / name, ordinal, 'legacy', 'file')
            ordinal += 1
    need(ordinal == 45, 'finite_forty_five_file_metadata_targets')
    files.verify()
    private(ROOT / 'output/source-bindings.private.json', encoded(files.packet()))
    private(ROOT / 'output/process-before.private.json', encoded(before_processes))
    # The original known exit 1 established that this fixed Mac binary does not support -D.
    # -nP prevents name/service resolution; no device-cache-ignore claim is made.
    # Explicit fields omit n/c/L: no filenames, commands or login names.
    argv = [LSOF, '-nP', '-p', ','.join(str(pid) for pid in sorted(before_processes)), '-F0pufatDi']
    row, out, err = commands.run('finite-current-file-inodes', argv,
        until=min(UNTIL, time.monotonic() + 10), maximum=1048576)
    private(ROOT / 'output/lsof.stdout.original', out)
    private(ROOT / 'output/lsof.stderr.private', err)
    need(type(row.get('exitCode')) is int and row['exitCode'] == 0
         and row.get('outcomeUnknown') is False and not err,
         'finite_original_lsof_known_complete_without_visibility_warning')
    parsed = parse_fields(out, set(before_processes))
    report['matches'] = match_files(parsed, files.targets())
    after_processes = {pid: reader.read(pid) for pid in before_processes}
    private(ROOT / 'output/process-after.private.json', encoded(after_processes))
    report['changedProcessFields'] = [{'pid': pid, 'fields': [key for key in before_processes[pid]
        if before_processes[pid][key] != after_processes[pid][key]]} for pid in before_processes
        if before_processes[pid] != after_processes[pid]]
    need(after_processes == before_processes, 'finite_full_process_birth_and_executable_stable')
    files.verify()
    private(ROOT / 'output/source-after.private.json', encoded(files.packet()))
    after_runtime = {path: public_file(path, expected) for path, expected in RUNTIME_PINS.items()}
    need(after_runtime == before_runtime, 'finite_native_tools_full9_and_hash_unchanged')
    report['processes'] = [{key: row[key] for key in ('pid', 'ppid', 'pgid', 'uid', 'birthSec', 'birthUsec')}
                           for row in before_processes.values()]
    report['sourceMetadata'] = [item['public'] for item in files.files]
    report['observedProcesses'] = len(parsed['processes'])
    report['observedFileRecords'] = parsed['fileRecords']
    report['allFortyFiveKnownMetadataBindingsUnchanged'] = True
    report['allNineProcessBirthsAndExecutablesUnchanged'] = True
    report['nativeExecutablePins'] = {path: {'bytes': pin[0], 'sha256': pin[1]} for path, pin in RUNTIME_PINS.items()}
    report['sourcePins'] = PAYLOAD['sourcePins']
    report['ok'] = True
except BaseException as error:
    report['ok'] = False
    report['errorClass'] = type(error).__name__
    code = str(error)
    report['errorCode'] = code if code in codes or type(error).__name__ in (
        'ObservationRefused', 'FieldRefused', 'Refusal', 'CommandRefused') and re.fullmatch(
            r'[a-z][a-z0-9_]{0,127}', code) else 'finite_consumer_observation_refused'
finally:
    errors = []
    for row in reversed(fds):
        try:
            closed(row)
        except BaseException as error:
            errors.append(type(error).__name__)
    report['explicitDescriptors'] = [{key: row[key] for key in ('closeAttempts', 'closed')} for row in fds]
    report['allExplicitDescriptorsClosedOnce'] = all(row['closeAttempts'] == 1 and row['closed'] for row in fds)
    report['closeErrors'] = errors
    report['originalCommands'] = safe_commands()
    closure = commands.public() if commands is not None else {'allOwnedCommandsStopped': True, 'unknownCommandCount': 0}
    report['allOriginalCommandsClosed'] = closure['allOwnedCommandsStopped']
    report['unknownCommandCount'] = closure['unknownCommandCount']
    report['elapsedSeconds'] = time.monotonic() - START
    report['ok'] = bool(report['ok'] and report['allExplicitDescriptorsClosedOnce'] and not errors
        and report['allOriginalCommandsClosed'] and report['unknownCommandCount'] == 0 and time.monotonic() < UNTIL)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')), flush=True)
raise SystemExit(0 if report['ok'] else 1)
