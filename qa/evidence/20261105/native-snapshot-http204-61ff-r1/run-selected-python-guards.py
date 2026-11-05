from pathlib import Path
import contextlib
import hashlib
import importlib.metadata
import json
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parent
ISOLATION = ROOT / 'python_guard_isolation'
PINS = json.loads((ISOLATION / 'dependency-scan.public.json').read_text())
SOURCE = json.loads((ROOT / 'candidate-file-manifest.json').read_text())
FROZEN = '54cc1662cc21420047c740314950d8af5c95da4f0c7c07e89275af22990bd095'
PREFIX = 'test_native_snapshot_ha_restore_live.HaRestoreGuards.'
SELECTED = [
    PREFIX + 'test_publication_requires_exact_204_and_independently_observed_generation_and_epoch',
    PREFIX + 'test_phase_epoch_drift_is_rejected_before_upload_and_cannot_mimic_progress',
    PREFIX + 'test_restore_204_uses_actual_response_buffer_and_rejects_hidden_tail_once',
]

def verify_files(directory, expected):
    rows = []
    for item in expected:
        raw = (directory / item['path']).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if digest != item['sha256'] or blob != item['git_blob'] or len(raw) != item['bytes']:
            raise RuntimeError('fixed source bytes changed: ' + item['path'])
        rows.append({'path': item['path'], 'bytes': len(raw), 'sha256': digest, 'git_blob': blob})
    return rows

before_dependencies = verify_files(ISOLATION, PINS['files'])
before_source = verify_files(ROOT / 'candidate', SOURCE['files'])
freeze = hashlib.sha256(''.join(item['path'] + '\0' + item['sha256'] + '\n'
                                for item in before_source).encode()).hexdigest()
if freeze != FROZEN or len(before_dependencies) != 30:
    raise RuntimeError('unexpected dependency or candidate freeze')

for directory in [ISOLATION / 'clients/python', ISOLATION / 'qa/single-node',
                  ISOLATION / 'qa/openbao-acceptance', ISOLATION / 'qa/openbao-acceptance/tests']:
    sys.path.insert(0, str(directory))

blocked_events = []
def no_external_actions(event, args):
    if (event.startswith('socket.') or event == 'subprocess.Popen'
            or event in {'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.spawn'}):
        blocked_events.append(event)
        raise RuntimeError('guard runner forbids external action: ' + event)
sys.addaudithook(no_external_actions)

class RecordedResult(unittest.TextTestResult):
    def startTest(self, test):
        self.actual_test_names.append(test.id())
        super().startTest(test)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.actual_test_names = []

started = time.monotonic()
output_path = ROOT / 'python-guards.stdout.log'
error_path = ROOT / 'python-guards.stderr.log'
with output_path.open('w') as output, error_path.open('w') as errors:
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
        suite = unittest.defaultTestLoader.loadTestsFromNames(SELECTED)
        result = unittest.TextTestRunner(stream=errors, verbosity=2, resultclass=RecordedResult).run(suite)
elapsed = time.monotonic() - started

after_dependencies = verify_files(ISOLATION, PINS['files'])
after_source = verify_files(ROOT / 'candidate', SOURCE['files'])
if after_dependencies != before_dependencies or after_source != before_source:
    raise RuntimeError('guard run modified fixed source')

imported = []
for name, module in sorted(sys.modules.items()):
    filename = getattr(module, '__file__', None)
    if not filename:
        continue
    path = Path(filename).resolve()
    if path.is_relative_to(ISOLATION):
        relative = path.relative_to(ISOLATION).as_posix()
        row = next((item for item in after_dependencies if item['path'] == relative), None)
        if row is None:
            raise RuntimeError('unrecorded isolated module: ' + relative)
        imported.append({'module': name, **row})

success = (result.wasSuccessful() and result.testsRun == 3
           and result.actual_test_names == SELECTED and not blocked_events)
record = {
    'schema': 'heptabao.snapshot-wire-204.local-python-guards.v1',
    'source_commit': '0e3237fe287553c49e14109ddfbdf33b674e8a64',
    'source_tree': '3b9e1fa2c40d211c5fb04bbb6d1d559ab7c89bae',
    'freeze_sha256': FROZEN,
    'interpreter': sys.executable,
    'python_version': sys.version,
    'cryptography_version': importlib.metadata.version('cryptography'),
    'command': [sys.executable, '-I', '-B', str(Path(__file__).resolve())],
    'selected_tests': SELECTED,
    'actual_test_names': result.actual_test_names,
    'tests_run': result.testsRun,
    'failures': len(result.failures),
    'errors': len(result.errors),
    'skipped': len(result.skipped),
    'success': success,
    'exit_code': 0 if success else 1,
    'elapsed_seconds': elapsed,
    'fixed_dependency_files_verified_before_and_after': len(after_dependencies),
    'candidate_source_files_verified_before_and_after': len(after_source),
    'fixed_source_unchanged': True,
    'actual_imported_isolated_modules': imported,
    'full_modules_imported': True,
    'ast_test_extraction_or_stub_modules': False,
    'audit_hook_blocked_events': blocked_events,
    'real_network_or_child_process_started': False,
    'real_tls_or_ha_executed': False,
    'rust_compiled_or_tested': False,
    'physical_host_tested': False,
    'wire_parity_qualified': False,
    'full_replacement_qualified': False,
    'stdout': {'path': output_path.name, 'bytes': output_path.stat().st_size,
               'sha256': hashlib.sha256(output_path.read_bytes()).hexdigest()},
    'stderr': {'path': error_path.name, 'bytes': error_path.stat().st_size,
               'sha256': hashlib.sha256(error_path.read_bytes()).hexdigest()},
}
(ROOT / 'python-guards-result.public.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({key: value for key, value in record.items()
                  if key not in {'actual_imported_isolated_modules', 'command'}}, indent=2))
sys.exit(record['exit_code'])
