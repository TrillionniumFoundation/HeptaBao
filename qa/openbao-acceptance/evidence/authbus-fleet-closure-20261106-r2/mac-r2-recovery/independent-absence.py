#!/usr/bin/env python3
"""Read-only reconciliation evidence for one failed, fixed Mac QA registration.

This does not authorize cleanup, import a manager, or renew an old deadline.
Private plans and launch arguments are compared in memory and never emitted.
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

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r2')
HOME = Path('/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r2')
LABEL = 'org.heptabao.qa.mac-authbus-4e808-home-r2.server'
TARGET = 'gui/501/' + LABEL
PID = 32527
KERNEL_PYTHON = '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python'
LAUNCHER = '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
MANAGER_SHA = '8feb3f9db05fa59986409c6c1306b48213102c7deaae6035219afa959add5ae4'
CANDIDATE_SHA = '59aa264489cc8ebea2943a0a7bab68c419da52d645532391ec369b973d555941'
OBSERVER_SHA = 'cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b'
OLD = """            typed_value=fields[name]
            if name=='last exit code' and typed_value=='78: EX_CONFIG':
"""
NEW = """            typed_value=fields[name]
            if name=='last exit code' and typed_value=='(never exited)':
                # An unexited registration has no successful exit observation.
                # Keep None so actual_launchd_phase_exit_zero still rejects it.
                fields[name]=None
                continue
            if name=='last exit code' and typed_value=='78: EX_CONFIG':
"""

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
START=time.monotonic();UNTIL=START+15
report={'schema':'heptabao.mac-authbus-r2-independent-absence.r1','ok':False,
        'target':TARGET,'rounds':[],'serviceMutationDispatched':False,
        'processArgumentsRead':False,'credentialValuesOrDigestsIncluded':False,
        'hostileEscapedDescendantContainmentClaimed':False,
        'genericSystemScopeServiceStatusUsedAsGuiProof':False}
def call(argv):
    left=UNTIL-time.monotonic();need(left>0,'bounded_independent_observation')
    p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
       timeout=min(4,left),check=False,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
    need(len(p.stdout)<=262144 and len(p.stderr)<=4096,'bounded_metadata_output')
    return p
def main():
    try:
        need(sys.platform=='darwin' and os.geteuid()==501,'actual_mac_operator')
        raw,_=safe_read(ROOT/'qa/mac_native_process_observer_r1.py',65536)
        need(sha(raw)==OBSERVER_SHA,'pinned_libproc_source')
        ns=extract(raw,['ObservationRefused','require','BsdInfo','ProcessReader'],
                   {'ctypes':ctypes,'Path':Path,'sys':sys})
        reader=ns['ProcessReader']();Bsd=ns['BsdInfo']
        for index in range(2):
            p=call(['/bin/launchctl','print',TARGET])
            expected='Could not find service "'+LABEL+'" in domain for user gui: 501'
            lines=p.stderr.decode('utf-8','strict').splitlines()
            need(p.returncode in (3,113) and not p.stdout
                 and lines in ([expected],['Bad request.',expected]),'exact_gui_label_absent')
            ps=call(['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,stat='])
            need(ps.returncode==0 and not ps.stderr,'complete_fixed_ps_metadata')
            related=[];count=0
            for line in ps.stdout.decode('ascii','strict').splitlines():
                count+=1;fields=line.split()
                if not(len(fields)>=3 and all(v.isdecimal() and len(v)<=10 for v in fields[:3])):
                    report['rejectedProcessMetadataRow']={'fields':[v[:64] for v in fields[:8]],'fieldCount':len(fields)}
                    raise Refused('strict_process_selectors')
                if any(int(v)==PID for v in fields[:3]):
                    related.append(fields)
            info=Bsd();ctypes.set_errno(0)
            size=reader.lib.proc_pidinfo(PID,3,0,ctypes.byref(info),ctypes.sizeof(info));err=ctypes.get_errno()
            row={'index':index,'guiQueryExitCode':p.returncode,'guiQueryExactStderr':p.stderr.decode(),
                'guiLabelAbsent':True,'processMetadataRowsExamined':count,
                'relatedPidGroupOrDirectChildRows':related,
                'nativePidInfoReturnedBytes':size,'nativePidInfoErrno':err}
            report['rounds'].append(row)
            need(not related and size==0 and err==errno.ESRCH,'independent_pid_group_and_direct_children_absent')
        report['ok']=True
    except Refused as error:report['errorCode']=str(error)
    except BaseException as error:report['errorType']=type(error).__name__
    report['elapsedSeconds']=time.monotonic()-START
    print(json.dumps(report,sort_keys=True),flush=True)
    return 0 if report['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
