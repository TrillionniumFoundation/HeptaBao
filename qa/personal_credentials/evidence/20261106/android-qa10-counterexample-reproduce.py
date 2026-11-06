#!/usr/bin/env python3
"""Internal QA10 source review reproduction, using only synthetic host fixtures."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
import unittest.mock  # Load SSL/asyncio before replacing socket creation.

sys.dont_write_bytecode = True
parser = argparse.ArgumentParser()
parser.add_argument('--input-dir', type=Path, default=Path('/workspace/scratch/848006513f75/android_qa10_qualification'))
args = parser.parse_args()
base = args.input_dir
pins = {
    'android_live.py': '8fc8ddff71ef534fc95d7c5fae1fcb707e7ee0c687a234212aab68fdbd5905f2',
    'android_popup_guard_tests.py': '62be4f817e7d4ad45922040a4b37178146a81702caa5ed644abd400a5249da5f',
}
for name, digest in pins.items():
    if hashlib.sha256((base/name).read_bytes()).hexdigest() != digest:
        raise SystemExit('frozen_source_mismatch')
calls = []
def forbidden(*args, **kwargs):
    calls.append('blocked_external_call')
    raise AssertionError('external_calls_forbidden_in_host_review')
subprocess.run = forbidden
subprocess.Popen = forbidden
socket.socket = forbidden
suite = unittest.TestSuite()
modules = []
for index, name in enumerate(('android_popup_guard_tests.py', 'android_driver_guard_tests.py', 'android_diagnostic_guard_tests.py')):
    sys.argv = [str(base/name), '--driver', str(base/'android_live.py')]
    spec = importlib.util.spec_from_file_location('qa10_internal_audit_' + str(index), base/name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    modules.append(module)
    suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
stream = io.StringIO()
result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
popup = modules[0]
case = popup.PopupGuards()
case.setUp()
fake = (
    'ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n'
    'Display #0 (activities from top to bottom):\n'
    '      CLIENT: synthetic client begins its own output\n'
    '  ResumedActivity: ' + popup.ACTIVITY + '\n'
    '      synthetic client output ends\n'
)
accepted = case.evaluate(activities=fake)
summary = {
    'schema': 1,
    'scope': 'independent_internal_host_review_only',
    'source_sha256': pins,
    'tests_run': result.testsRun,
    'failures': len(result.failures),
    'errors': len(result.errors),
    'external_calls_attempted': len(calls),
    'two_space_client_resumed_counterexample_accepted': accepted.get('available') is True,
    'counterexample_sha256': hashlib.sha256(fake.encode()).hexdigest(),
    'counterexample': fake,
    'counterexample_source': 'Entire body is synthetic; the only ResumedActivity line is modeled as client-origin text, without a real server resumed record.',
    'finding': 'Indentation does not establish AMS provenance when -p enables client output.',
    'disposition': 'QA10_popup_admission_hold',
    'android_runtime_tested': False,
    'production_qualified': False,
    'external_review': False,
}
print(json.dumps(summary, sort_keys=True))
if not result.wasSuccessful() or calls or not summary['two_space_client_resumed_counterexample_accepted']:
    raise SystemExit(1)
