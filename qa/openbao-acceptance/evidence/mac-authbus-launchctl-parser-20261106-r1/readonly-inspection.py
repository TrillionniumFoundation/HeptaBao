#!/usr/bin/env python3
"""Bounded read-only Mac launchctl observation; never imports a QA manager."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

SOURCE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r2/qa/mac_owned_launchd_r3.py')
SOURCE_SHA256 = '8feb3f9db05fa59986409c6c1306b48213102c7deaae6035219afa959add5ae4'
PATCHED_SHA256 = '59aa264489cc8ebea2943a0a7bab68c419da52d645532391ec369b973d555941'
LABELS = ('org.heptabao.qa.mac-authbus-4e808-owner-r1.server',
          'org.heptabao.qa.mac-authbus-4e808-home-r2.server')
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

class Refused(RuntimeError): pass

def need(value, code):
    if not value: raise Refused(code)

def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def parse_function(source):
    functions = [n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'parse_print']
    need(len(functions) == 1, 'one_known_parser')
    namespace = {'need': need, 're': re}
    exec(compile(ast.Module(body=functions, type_ignores=[]), '<source-pinned-parser>', 'exec'), namespace)
    return namespace['parse_print']

def safe_raw_fields(raw):
    result = {}; depth = 0
    names = ('pid', 'runs', 'state', 'last exit code', 'last terminating signal')
    for line in raw.decode('utf-8', 'strict').splitlines():
        text = line.strip()
        if depth == 1 and ' = ' in text:
            name, value = text.split(' = ', 1)
            if name in names:
                need(name not in result, 'unique_safe_status_field')
                need(re.fullmatch(r'[A-Za-z0-9(): _.+-]{1,64}', value) is not None, 'bounded_safe_status_literal')
                result[name] = value
        depth += text.count('{') - text.count('}')
    return result

def main():
    started = time.monotonic(); until = started + 25
    report = {'schema': 'heptabao.mac-launchctl-parser-readonly-inspection.r1',
              'ok': False, 'sourcePinned': False, 'candidatePinned': False, 'observations': [],
              'remoteSourceModified': False, 'managerImported': False, 'serviceMutationDispatched': False,
              'businessRetryDispatched': False, 'providerRequested': False, 'j3160Contacted': False,
              'priorRegistrationOrLineageReconciled': False, 'credentialValuesOrDigestsIncluded': False}
    try:
        need(sys.platform == 'darwin', 'actual_mac_only')
        fd = os.open(SOURCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 65536, 'bounded_regular_source')
            raw = os.read(fd, 65537)
            need(len(raw) == before.st_size and not os.read(fd, 1), 'whole_source_read')
            need(identity(before) == identity(os.fstat(fd)) == identity(SOURCE.lstat()), 'stable_source_identity')
        finally:
            os.close(fd)
        need(hashlib.sha256(raw).hexdigest() == SOURCE_SHA256, 'observed_source_hash_changed')
        report['sourcePinned'] = True; report['sourceSha256'] = SOURCE_SHA256
        source = raw.decode('utf-8', 'strict')
        need(source.count(OLD) == 1, 'one_exact_integer_patch')
        candidate = source.replace(OLD, NEW, 1)
        need(hashlib.sha256(candidate.encode()).hexdigest() == PATCHED_SHA256, 'same_candidate_hash')
        report['candidatePinned'] = True; report['candidateSha256'] = PATCHED_SHA256
        original_parse, patched_parse = parse_function(source), parse_function(candidate)
        for label in LABELS:
            target = 'gui/501/' + label
            remaining = until - time.monotonic(); need(remaining > 0, 'inspection_absolute_deadline')
            try:
                proc = subprocess.run(['/bin/launchctl', 'print', target], stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(8, remaining), check=False,
                    env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
            except subprocess.TimeoutExpired:
                report['observations'].append({'target': target, 'queryTimedOut': True})
                continue
            need(len(proc.stdout) <= 262144 and len(proc.stderr) <= 4096, 'bounded_launchctl_response')
            row = {'target': target, 'exitCode': proc.returncode, 'stdoutBytes': len(proc.stdout), 'stderrBytes': len(proc.stderr)}
            if proc.returncode in (3, 113) and not proc.stdout:
                expected = 'Could not find service "' + label + '" in domain for user gui: 501'
                lines = proc.stderr.decode('utf-8', 'strict').splitlines()
                row['currentAbsenceObserved'] = lines in ([expected], ['Bad request.', expected])
            elif proc.returncode == 0 and not proc.stderr:
                row['rawSafeFields'] = safe_raw_fields(proc.stdout)
                for key, parse in (('originalParser', original_parse), ('patchedParser', patched_parse)):
                    try:
                        value = parse(proc.stdout, target)
                        row[key] = {'ok': True, 'safeFields': {name: value[name] for name in row['rawSafeFields'] if name in value},
                                    'numericZeroExitObserved': value.get('last exit code') == 0}
                    except Refused as error:
                        row[key] = {'ok': False, 'errorCode': str(error)}
            report['observations'].append(row)
        report['ok'] = len(report['observations']) == len(LABELS)
    except Refused as error:
        report['errorCode'] = str(error)
    except BaseException as error:
        report['errorType'] = type(error).__name__
    report['elapsedSeconds'] = time.monotonic() - started
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report['ok'] else 1

if __name__ == '__main__': raise SystemExit(main())
