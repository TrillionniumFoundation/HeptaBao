import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time

BASE = Path('/home/alex/heptabao-android-autofill-20261106-r1')
ADB = '/home/alex/.local/bin/adb'
AUTHORIZED = '41ad305f8562a6c47710afe71fabf30cb8692a71d3de1a47ca9949b669bcc6c1'
START = '11-06 17:03:20.000'
END = '11-06 17:04:12.000'
OWN = r'org\.heptabao\.(personal\.preview|synthetic\.(fixture|decoy))'


def command(args):
    r = subprocess.run(args, capture_output=True, timeout=30, check=False)
    assert r.returncode == 0 and len(r.stdout) <= 2 * 1024 * 1024, 'readonly_query_failed'
    return r.stdout.decode('utf-8', 'replace')


devices = [line.split()[0] for line in command([ADB, 'devices']).splitlines()[1:]
           if len(line.split()) == 2 and line.split()[1] == 'device']
assert len(devices) == 1 and hashlib.sha256(devices[0].encode()).hexdigest() == AUTHORIZED


def shell(args):
    return command([ADB, '-s', devices[0], 'shell', ' '.join(shlex.quote(arg) for arg in args)])


def rows(raw):
    for line in raw.splitlines():
        m = re.match(r'^(\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+([^: ]+)\s*:\s*(.*)$', line)
        if m and START <= m.group(1) <= END:
            yield m


raw = shell(['logcat', '-d', '-b', 'system', '-b', 'main', '-v', 'threadtime',
             '-T', START, '--regex=' + OWN, 'ActivityManager:I', '*:S'])
pids = {}
for m in rows(raw):
    found = re.search(r'\bStart proc (\d+):(org\.heptabao\.(?:personal\.preview|synthetic\.(?:fixture|decoy)))/', m.group(6))
    if found:
        pids[int(found.group(1))] = found.group(2)

categories = {
    'SendIntentException': 'intent_sender_exception',
    'CanceledException': 'pending_intent_canceled_exception',
    'Error launching auth intent': 'auth_intent_launch_error',
    'Error launching authentication': 'authentication_launch_error',
    'startIntentSender': 'start_intent_sender_message',
    'Background activity': 'background_activity_message',
    'BAL_BLOCK': 'background_activity_block',
    'Permission Denial': 'permission_denial',
    'Permission denied': 'permission_denied',
}
events = []
for pid, package in sorted(pids.items()):
    raw = shell(['logcat', '-d', '-b', 'main', '-b', 'system', '-v', 'threadtime',
                 '-T', START, '--pid=' + str(pid), 'AutofillManager:V',
                 'AutofillClientController:V', 'Activity:V', 'HeptaBaoPreview:V', '*:S'])
    for m in rows(raw):
        found = sorted({value for pattern, value in categories.items() if pattern in m.group(6)})
        allowed = {'ui_hidden_notification', 'memory_pressure_locked', 'auth_context_bound'} | {'auth_rejected_' + code for code in {'request_expired', 'wrong_result_recipient', 'request_changed', 'wrong_package', 'wrong_certificate', 'missing_structure', 'wrong_activity', 'unsupported_windows', 'structure_too_large', 'webview_unsupported', 'wrong_fields'}}
        fixed = m.group(6) if m.group(6) in allowed else None
        if found or fixed:
            events.append({'time': m.group(1), 'pid': pid, 'package': package,
                           'tag': m.group(5), 'categories': found, 'fixed_code': fixed})

result = {'schema': 1, 'scope': 'r6_exact_window_owned_process_framework_diagnostic',
          'causal_case_proof': False, 'no_device_mutation': True,
          'started_unix_ns': time.time_ns(), 'time_window_device_clock': [START, END],
          'owned_processes': [{'pid': pid, 'package': package} for pid, package in sorted(pids.items())],
          'events': events}
os.umask(0o077)
path = BASE / 'r6-owned-process-framework-diagnostic.json'
with path.open('x', encoding='utf-8') as output:
    json.dump(result, output, sort_keys=True, indent=2)
    output.write('\n')
    output.flush()
    os.fsync(output.fileno())
print(json.dumps({'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'result': result}, sort_keys=True))
