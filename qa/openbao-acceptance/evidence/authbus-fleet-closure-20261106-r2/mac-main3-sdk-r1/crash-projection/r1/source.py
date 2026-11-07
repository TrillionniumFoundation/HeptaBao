#!/usr/bin/env python3
"""Read-only exact failed Node PID crash projection; never emit raw reports."""
import datetime, errno, json, os, re, stat, time
from pathlib import Path

TARGET_PID = 38400
NODE = '/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
REPORTS = Path('/Users/qianqi/Library/Logs/DiagnosticReports')
START = 1793991827.673
END = 1793991843.637
LIMIT = 2 * 1024 * 1024
started = time.monotonic()
until = started + 20
opened = closed = 0
result = {
    'schema': 'heptabao.mac-main3-sdk-seed-crash-projection.r1',
    'originalJobId': '1a1b23ee0d9-fc05-7d25',
    'originalPid': TARGET_PID, 'originalExitCode': -6,
    'rawReportOrDiagnosticTextPublished': False,
    'credentialFilesRead': False, 'credentialValuesOrDigestsPublished': False,
    'serviceOrProviderAction': False, 'childStarted': False,
    'ok': False, 'matches': [],
}

def need(value, code):
    if not value:
        raise RuntimeError(code)

def ident(s):
    return tuple(str(getattr(s, key)) for key in (
        'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def observe(path):
    global opened, closed
    need(time.monotonic() < until, 'original_projection_deadline')
    s = path.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == 501
         and 0 < s.st_size <= LIMIT, 'exact_private_report_file_scope')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    opened += 1
    try:
        need(ident(s) == ident(os.fstat(fd)), 'report_open_identity')
        raw = bytearray()
        while True:
            need(time.monotonic() < until, 'original_projection_deadline')
            part = os.read(fd, min(65536, LIMIT + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
            need(len(raw) <= LIMIT, 'report_bound')
        need(ident(s) == ident(os.fstat(fd)) == ident(path.lstat()), 'report_namespace_unchanged')
        return bytes(raw)
    finally:
        os.close(fd)
        closed += 1

def enum(value, allowed):
    return value if value in allowed else None

def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)

try:
    need(os.getuid() == os.geteuid() == 501, 'exact_caller_uid')
    if not REPORTS.exists():
        result['reportsDirectoryAbsent'] = True
    else:
        directory = REPORTS.lstat()
        need(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 501,
             'exact_reports_directory')
        entries = []
        with os.scandir(REPORTS) as scan:
            for ordinal, entry in enumerate(scan):
                need(ordinal < 2048 and time.monotonic() < until, 'bounded_report_inventory')
                if (entry.name.startswith('node-') or entry.name.startswith('node_')) and entry.name.endswith('.ips'):
                    s = entry.stat(follow_symlinks=False)
                    if START - 30 <= s.st_mtime <= END + 600:
                        entries.append((s.st_mtime_ns, REPORTS / entry.name))
        need(len(entries) <= 16, 'bounded_exact_time_candidates')
        result['candidateCount'] = len(entries)
        decoder = json.JSONDecoder()
        for _, path in sorted(entries):
            raw = observe(path)
            text = raw.decode('utf-8')
            values = []
            cursor = 0
            while cursor < len(text):
                while cursor < len(text) and text[cursor].isspace():
                    cursor += 1
                if cursor == len(text):
                    break
                value, cursor = decoder.raw_decode(text, cursor)
                values.append(value)
                need(len(values) <= 3, 'bounded_report_json_values')
            bodies = [v for v in values if isinstance(v, dict) and v.get('pid') == TARGET_PID]
            if not bodies:
                continue
            need(len(bodies) == 1, 'one_exact_pid_body')
            body = bodies[0]
            need(body.get('procName') == 'node' and body.get('procPath') == NODE,
                 'exact_failed_pid_and_executable')
            capture = body.get('captureTime')
            need(isinstance(capture, str) and len(capture) <= 64, 'exact_capture_time_format')
            when = datetime.datetime.fromisoformat(capture.replace('Z', '+00:00')).timestamp()
            need(START - 2 <= when <= END + 10, 'same_original_failure_interval')
            ex = body.get('exception', {})
            term = body.get('termination', {})
            projection = {
                'pid': TARGET_PID, 'exactExecutableMatched': True,
                'captureWithinOriginalFailureInterval': True,
                'exceptionType': enum(ex.get('type'), {'EXC_CRASH', 'EXC_BAD_ACCESS', 'EXC_BREAKPOINT', 'EXC_GUARD'}),
                'exceptionSignal': enum(ex.get('signal'), {'SIGABRT', 'SIGSEGV', 'SIGTRAP', 'SIGKILL', 'SIGBUS'}),
                'terminationNamespace': enum(term.get('namespace'), {'LIBSYSTEM', 'SIGNAL', 'DYLD', 'SANDBOX', 'CODESIGNING', 'GUARD'}),
                'terminationCode': term.get('code') if type(term.get('code')) is int else None,
                'terminationFlags': term.get('flags') if type(term.get('flags')) is int else None,
            }
            # Only presence of fixed public terms is projected; report strings,
            # arbitrary frame symbols, paths, identifiers, and hashes never leave.
            markers = ('sandbox', 'uv_cwd', 'getcwd', 'uv_os_homedir',
                       'Operation not permitted', 'Permission denied',
                       'Library not loaded', 'ERR_ACCESS_DENIED',
                       'dynamic-code-generation', 'mach-lookup',
                       'file-read-data', 'file-read-metadata', 'uv_interface_addresses')
            messages = list(strings(body.get('asi', {}))) + list(strings(term))
            projection['fixedDiagnosticMarkers'] = [m for m in markers if any(m in t for t in messages)]
            known_symbols = {'abort', '__abort_with_payload', 'abort_with_payload',
                'abort_with_reason', '__pthread_kill', 'pthread_kill', 'raise',
                'uv_cwd', 'uv_os_homedir', 'getcwd', 'sandbox_init',
                'sandbox_init_with_parameters', 'sandbox_apply'}
            fault = body.get('faultingThread')
            threads = body.get('threads', [])
            projection['fixedFaultingSymbols'] = []
            if type(fault) is int and 0 <= fault < len(threads):
                projection['fixedFaultingSymbols'] = [f.get('symbol') for f in threads[fault].get('frames', [])
                    if isinstance(f, dict) and f.get('symbol') in known_symbols][:32]
            result['matches'].append(projection)
        need(len(result['matches']) <= 1, 'unique_original_failure_report')
    result['causeIdentified'] = False
    result['ok'] = True
except BaseException as error:
    result['errorType'] = type(error).__name__
    result['errorCode'] = str(error) if type(error) is RuntimeError else None
finally:
    result['openedReportDescriptors'] = opened
    result['closedReportDescriptors'] = closed
    result['allReportDescriptorsClosed'] = opened == closed
    result['elapsedSeconds'] = time.monotonic() - started
    print(json.dumps(result, sort_keys=True, separators=(',', ':')), flush=True)
raise SystemExit(0 if result['ok'] and opened == closed else 1)
