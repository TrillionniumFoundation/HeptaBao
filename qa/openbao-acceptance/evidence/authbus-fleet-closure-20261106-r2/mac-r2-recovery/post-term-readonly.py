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

EXPECTED = {
 'pid':32527,'ppid':1,'pgid':32527,'uid':501,
 'birthSec':1793969379,'birthUsec':298893,'executable':KERNEL_PYTHON,
}
JOURNAL=Path('/Users/qianqi/heptabao-mac-authbus-r2-recovery-20261106-r2')
JOURNAL_PINS={"001-intent.public.json":"106b40bf0d702cd27d49fc75de6935b08360ac198149d19da97f81276b69467a","010-term-intent.public.json":"2718f9b2b28513753e3e6c80a8d7abef23a3597a44a12cee052538e52392b0bb","011-term-command.public.json":"16233386892496308f62f7faf0cf38d094cee47f02fe7a97f52cca59ec38a725","012-term-observed.public.json":"80c3d602b1b4473feabc5b7cef392cd276f883bdb9442535eb631afdef51f8b5","999-unknown.public.json":"c2b5af38d9b2196f8eef3ca746768e772d7c2b4fe2e4af60dc073264a0f5759a"}
START=time.monotonic()
UNTIL=START+25
report={'schema':'heptabao.mac-authbus-r2-post-term-readonly.r1','ok':False,
        'serviceMutationDispatched':False,'signalsDispatched':False,'businessRetryDispatched':False,
        'previousTermDispatchedOnceKnown':False,'r2FailedResultRewritten':False,
        'r2FailureOffendingRowWasNotRecorded':True,
        'credentialValuesOrDigestsIncluded':False,'samples':[],'currentObservations':[]}
def remaining(cap):
    value=UNTIL-time.monotonic()
    need(value>0,'bounded_readonly_diagnostic')
    return min(cap,value)
def command(argv,cap):
    p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                     timeout=remaining(cap),check=False,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
    need(len(p.stdout)<=262144 and len(p.stderr)<=4096,'bounded_metadata_response')
    return p
def main():
    try:
        need(sys.platform=='darwin' and os.geteuid()==501,'actual_mac_operator')
        names=sorted(os.listdir(JOURNAL))
        need(len(names)<=32 and all(re.fullmatch(r'[0-9]{3}-[a-z0-9-]+\.public\.json',n) for n in names),'bounded_public_journal_inventory')
        report['journalLeafNames']=names
        need(names==sorted(JOURNAL_PINS),'exact_original_r2_journal_inventory')
        values={}
        for name,digest in JOURNAL_PINS.items():
            raw,_=safe_read(JOURNAL/name,65536);need(sha(raw)==digest,'r2_journal_original_bytes')
            values[name]=json.loads(raw)
        original=values['999-unknown.public.json']
        attempts=original.get('serviceMutationAttempts',{})
        need(set(attempts)=={'term'} and attempts['term'].get('complete') is True
             and attempts['term'].get('exitCode')==0,'known_single_term_no_other_attempt')
        receipt=values['011-term-command.public.json']
        need(receipt.get('operation')=='term' and receipt['receipt'].get('complete') is True
             and receipt['receipt'].get('exitCode')==0 and receipt['receipt'].get('outcomeUnknown') is False,
             'known_term_command_receipt')
        report['previousTermDispatchedOnceKnown']=True
        report['priorR2MutationAttempts']=attempts
        report['priorR2JournalSha256']=JOURNAL_PINS
        report['killAndBootoutIntentAndAttemptAbsent']=True
        manager,_=safe_read(ROOT/'qa/mac_owned_launchd_r3.py',65536)
        need(sha(manager)==MANAGER_SHA,'same_original_manager')
        candidate=manager.decode().replace(OLD,NEW,1)
        need(sha(candidate.encode())==CANDIDATE_SHA,'same_parser_candidate')
        parse=extract(candidate,['parse_print'],{'need':need,'re':re})['parse_print']
        observer,_=safe_read(ROOT/'qa/mac_native_process_observer_r1.py',65536)
        need(sha(observer)==OBSERVER_SHA,'same_libproc_source')
        ns=extract(observer,['ObservationRefused','require','BsdInfo','ProcessReader'],
                   {'ctypes':ctypes,'Path':Path,'sys':sys})
        reader=ns['ProcessReader']();Bsd=ns['BsdInfo']
        plist_raw,_=safe_read(HOME/'server-initial.plist',65536)
        need(sha(plist_raw)==original['publicInputSha256']['originalPlist'],'same_original_plist')
        plist=plistlib.loads(plist_raw)
        def observe():
            p=command(['/bin/launchctl','print',TARGET],5)
            row={'queryExitCode':p.returncode}
            if p.returncode in (3,113) and not p.stdout:
                expected='Could not find service "'+LABEL+'" in domain for user gui: 501'
                lines=p.stderr.decode().splitlines()
                need(lines in ([expected],['Bad request.',expected]),'exact_label_absence')
                row['labelAbsent']=True
            else:
                need(p.returncode==0 and not p.stderr,'known_label_query')
                current=parse(p.stdout,TARGET)
                row.update(labelAbsent=False,registeredPathExact=current.get('path')==str(HOME/'server-initial.plist'),
                    registeredProgramExact=current.get('program')==plist['ProgramArguments'][0],
                    registeredAllArgumentsExact=current.get('arguments')==plist['ProgramArguments'],
                    safeFields={k:current.get(k) for k in ('pid','runs','state','last exit code','last terminating signal')})
                need(row['registeredPathExact'] and row['registeredProgramExact'] and row['registeredAllArgumentsExact'],
                     'unchanged_registered_source_arguments')
            info=Bsd();ctypes.set_errno(0)
            count=reader.lib.proc_pidinfo(PID,3,0,ctypes.byref(info),ctypes.sizeof(info));err=ctypes.get_errno()
            row['nativePidInfo']={'returnedBytes':count,'errno':err}
            if count==0 and err==errno.ESRCH:
                row['originalPidAbsent']=True
            else:
                need(count==ctypes.sizeof(info),'native_process_info_known')
                actual=reader.read(PID)
                row.update(originalPidAbsent=False,processIdentity=actual,
                    fullExpectedIdentityEqual=actual==EXPECTED,directChildren=reader.children(PID))
            report['currentObservations'].append(row)
        observe()
        bad={}
        for index in range(20):
            p=command(['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,stat='],4)
            need(p.returncode==0 and not p.stderr,'known_ps_metadata')
            related=[];all_selectors=True;count=0;bad_count=0
            for line in p.stdout.decode('ascii','strict').splitlines():
                count+=1;fields=line.split()
                selectors=len(fields)==5 and all(v.isdecimal() for v in fields[:3])
                all_selectors=all_selectors and selectors
                old_ok=selectors and (fields[3].isdecimal() or fields[3]=='-2') \
                    and re.fullmatch(r'[A-Za-z0-9+<>=-]{1,16}',fields[4]) is not None
                if not old_ok:
                    bad_count+=1
                    need(len(fields)<=8 and all(len(v)<=32 and v.isascii() and v.isprintable() for v in fields),
                         'bounded_safe_fixed_column_failure')
                    key=tuple(fields)
                    need(key in bad or len(bad)<32,'bounded_offending_metadata_rows')
                    bad.setdefault(key,{'fields':fields,'firstObservedSample':index,'occurrences':0,
                        'selectorsWellFormed':selectors,
                        'relatedBySelector':selectors and any(v=='32527' for v in fields[:3])})
                    bad[key]['occurrences']+=1
                if selectors and any(v=='32527' for v in fields[:3]):
                    related.append({'pid':fields[0],'ppid':fields[1],'pgid':fields[2],
                                    'uid':fields[3],'stat':fields[4]})
            report['samples'].append({'index':index,'rowCount':count,'metadataBytes':len(p.stdout),
                'allSelectorsWellFormed':all_selectors,'r2ParserRejectedRowCount':bad_count,'relatedRows':related})
            if index<19:time.sleep(min(0.25,remaining(0.25)))
        report['offendingRowsObservedNow']=list(bad.values())
        observe()
        report['originalAdmissionArtifactsAbsent']=all(not (ROOT/'launchd'/('server-initial.'+s)).exists()
                for s in ('ready.public.json','admitted.private.json','exec-ready.public.json'))
        need(sorted(os.listdir(JOURNAL))==names,'journal_inventory_unchanged')
        for name,digest in JOURNAL_PINS.items():
            raw,_=safe_read(JOURNAL/name,65536);need(sha(raw)==digest,'journal_bytes_unchanged_after_read')
        report['journalUnchangedThroughoutRead']=True
        report['ok']=True
    except Refused as error:report['errorCode']=str(error)
    except BaseException as error:report['errorType']=type(error).__name__
    report['elapsedSeconds']=time.monotonic()-START
    print(json.dumps(report,sort_keys=True),flush=True)
    return 0 if report['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
