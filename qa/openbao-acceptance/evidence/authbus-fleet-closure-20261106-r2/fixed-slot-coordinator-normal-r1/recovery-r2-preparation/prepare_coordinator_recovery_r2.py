#!/usr/bin/env python3
"""Derive a recovery-only attempt for the one already initialized QA fixture."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'fixed-slot-coordinator-actual-work'
sha = lambda raw: hashlib.sha256(raw).hexdigest()
original_raw = (BASE / 'launch_coordinator_actual_r1.py').read_bytes()
assert len(original_raw) == 242236 and sha(original_raw) == '0399270ee35c5c47d3431e263d9a338028393c1b4ebf09babbb23d9fa7923752'
tree = ast.parse(original_raw)
payload = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == 'PAYLOAD' for target in node.targets))
for category, pins in (('sources', 'pins'), ('assets', 'assetPins')):
    for name, value in payload[category].items():
        assert len(value.encode()) == payload[pins][name]['bytes'] and sha(value.encode()) == payload[pins][name]['sha256']
old_api = payload['sources'].pop('fixedslot_actual_api_r1.py')
old_api_pin = payload['pins'].pop('fixedslot_actual_api_r1.py')
assert old_api.count("('health','init','unseal'") == 1
api = old_api.replace("('health','init','unseal'", "('health','unseal'")
needle = "        self.guard.check()\n        need(not self.unknown"
assert api.count(needle) == 1
api = api.replace(needle, "        self.guard.check()\n        need(isinstance(route,str) and route!='/v1/sys/init'\n"
    "             and not route.startswith('/v1/sys/init/') and category!='init','recovery_initialization_forbidden')\n"
    "        need(not self.unknown")
api_name = 'fixedslot_recovery_api_r2.py'
payload['sources'][api_name] = api
payload['pins'][api_name] = {'bytes': len(api.encode()), 'sha256': sha(api.encode())}
body_original = (BASE / 'coordinator_actual_parent_r1.body.py').read_text()
assert sha(body_original.encode()) == '17a24012c8aa07609f5151f664799caa1f79e4ce93ff6459269952a7d3b0d9b9'
body = body_original


def change(before, after):
    global body
    assert body.count(before) == 1, (before[:100], body.count(before))
    body = body.replace(before, after)


first = body.index('"""')
last = body.index('"""', first + 3)
body = body[:first] + '"""Recover only the initialized, failed fixed-slot QA attempt.\n\nThe original request and all failed receipts remain unchanged. This new attempt\nuses its one existing store, original unseal key and complete pinned sources.\nNo initialization, cryptographic generation, current credentials or production\nservice action is available; remaining QA phases are new, once-journaled operations.\n"""' + body[last + 3:]
change("OPERATIONS = CUSTODY / 'custody'", "OPERATIONS = CUSTODY / 'custody-recovery-r2'")
change("'schema': 'heptabao.fixed-slot-normal-qualification.r1'", "'schema': 'heptabao.fixed-slot-normal-recovery-qualification.r2'")
change("    'serverProcesses': [],", "    'originalAttemptStillFailed': True, 'initializationRequests': 0, 'nativeCryptoCommands': 0,\n"
    "    'sameInitializedStoreAndOriginalKey': True, 'newIndependentRecoveryBudget': True,\n"
    "    'originalExecutionKeyReplayed': False, 'recoveryExecutionKey': 'heptabao-mac-fixed-slot-coordinator-recovery-20261107-r2',\n"
    "    'serverProcesses': [],")
nodes = {node.name: node for node in ast.parse(body).body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
new_home = ast.get_source_segment(body, nodes['new_home_root'])
change(new_home, (HERE / 'original_initialized_fixture_r2.fragment.py').read_text().rstrip())
change('    volume = operations = commands = signals = files = None',
       '    volume = operations = commands = signals = files = evidence = None')
change('        from fixedslot_actual_api_r1 import Api', '        from fixedslot_recovery_api_r2 import Api')
change("        need(not ROOT.exists() and not ROOT.is_symlink() and not CLIENT_ROOT.exists() and not CLIENT_ROOT.is_symlink(),\n"
       "             'fixture_create_only_new_roots')",
       "        need(ROOT.is_dir() and not ROOT.is_symlink() and CLIENT_ROOT.is_dir() and not CLIENT_ROOT.is_symlink()\n"
       "             and not OPERATIONS.exists() and not OPERATIONS.is_symlink(), 'recovery_existing_fixture_new_journal_only')")
begin = body.index('        new_home_root(); operations = PrivateOperations(); files = FixtureFiles(operations)')
end = body.index('        class BoundGuard:', begin)
setup = '''        # This create-only journal is the only new directory. Its existence is
        # a once barrier, including if a later dispatch or receipt is unknown.
        operations = PrivateOperations(); files = FixtureFiles(operations)
        for path in (CODE, CODE / 'transport', STATE, STATE / 'coordinator', STATE / 'producer', PKI, INPUT, RESULTS):
            files._hold(path)
        evidence = OriginalInitializedFixture()
        root_token, unseal = evidence.admit()
        sensitive.extend((root_token, unseal))
        REPORT['originalAdmission'] = evidence.public()
        before_binary = binary_pin(volume)
        for name, source in PAYLOAD['sources'].items():
            operations.write(name, source.encode())
        operations.write('source-pins.public.json', encoded({'python': PAYLOAD['pins'], 'node': PAYLOAD['assetPins']}))
        need(len(PAYLOAD['assets']) == 11 and set(PAYLOAD['assets']) == set(PAYLOAD['assetPins']), 'fixture_exact_eleven_node_sources')
        for name, source in PAYLOAD['assets'].items():
            raw = source.encode(); pin = PAYLOAD['assetPins'][name]
            need(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256']
                 and not Path(name).is_absolute() and '..' not in Path(name).parts, 'fixture_node_original_source_pin')
            need(evidence.read(CODE / name, 1048576, size=pin['bytes'], public_sha=pin['sha256']) == raw,
                 'recovery_original_node_asset_exact_bytes')
        for name in ('protected-read', 'protected-write'):
            need(evidence.read(CLIENT_ROOT / name, 1024) == b'SYNTHETIC KERNEL DENIAL PROBE\\n',
                 'recovery_original_synthetic_probes')
        need(evidence.read(SANDBOX, 16384) == node_sandbox(), 'recovery_original_node_sandbox_unchanged')
        ca = evidence.read(PKI / 'ca.crt', 16384)
        leaf = evidence.read(PKI / 'server.crt', 16384)
        evidence.read(PKI / 'ca.key', 16384, metadata_only=True)
        evidence.read(PKI / 'server.key', 16384, metadata_only=True)
        ca_pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.decode('ascii'))).hexdigest()
        leaf_pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf.decode('ascii'))).hexdigest()
        need(ca_pin == '71960988ed45d2b9816802081b2fc8ea3681942157350543119666df4f693bd9'
             and leaf_pin == 'd69f73aaa8aefe0afcd0f61c89908c31f7af5a5f7c0503ee86ee10eff5ca613e',
             'recovery_original_ca_and_server_leaf_der_pins')
        REPORT['caCertificateDerSha256'] = ca_pin; REPORT['leafCertificateDerSha256'] = leaf_pin
        config = {'listen': '127.0.0.1:' + str(PORT), 'data_dir': str(ROOT / 'data'), 'audit_file': str(ROOT / 'log/audit.jsonl'),
            'tls_cert_file': str(PKI / 'server.crt'), 'tls_key_file': str(PKI / 'server.key'), 'max_connections': 64, 'timeout_seconds': 15,
            'rate_limit_per_second': 2000, 'rate_limit_burst': 4000, 'rate_limit_entries': 512,
            'storage': {'native_v6_file': {'path': str(ROOT / 'data')}}}
        need(evidence.read(CONFIG, 16384) == encoded(config) and volume.read(CONFIG, 16384) == encoded(config),
             'recovery_original_server_config_exact_bytes')
        config_receipt = {'identity': list(full9(CONFIG.lstat()))}
        t5_directories = dict(evidence.current_directories)
        evidence.check(); evidence._time()
        operations.append('recovery-admission', evidence.public())
        operations.append('bootstrap-recovery', {'rootToken': root_token, 'unsealKey': unseal,
            'source': 'original-r1-initial-002-complete-response', 'newInitialization': False})

'''
body = body[:begin] + setup + body[end:]
change('                volume.check(); files.check()', '                volume.check(); files.check(); evidence.check()')
begin = body.index("        health = api.call('initial.health_strict_before_init'")
end = body.index('        api.root_token = root_token', begin)
body = body[:begin] + "        health = api.call('initial.health_strict_existing_store', 'GET', '/v1/sys/health', token='', expected=503, category='health', readiness=True)\n" + \
    "        api.check('initial.exact_initialized_and_sealed', health.get('initialized') is True and health.get('sealed') is True)\n" + body[end:]
change("        if volume is not None:\n            try:\n                volume.close()",
       "        if evidence is not None:\n            try:\n                evidence.check()\n                REPORT['originalClosedEvidenceAndPublishedDirectoriesUnchanged'] = True\n"
       "            except BaseException:\n                REPORT['originalClosedEvidenceAndPublishedDirectoriesUnchanged'] = False; REPORT['ok'] = False\n"
       "        if volume is not None:\n            try:\n                volume.close()")
change("            and not REPORT['nodeBusinessOutcomeUnknown'] and REPORT['deadlineAfterClosurePassed']",
       "            and REPORT.get('originalClosedEvidenceAndPublishedDirectoriesUnchanged') is True\n"
       "            and not REPORT['nodeBusinessOutcomeUnknown'] and REPORT['deadlineAfterClosurePassed']")
original_template = (BASE / 'coordinator_actual_parent_r1.template.py').read_text()
definition_names = ('Refused', 'need', 'remaining', 'full9', 'encoded', 'own', 'close', 'open_fd', 'PrivateOperations')
original_nodes = {n.name: n for n in ast.parse(original_template).body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
operations = '\n\n'.join(ast.get_source_segment(original_template, original_nodes[name]) for name in definition_names)
needle = "'crypto-intent', 'crypto-result', 'node-request-intent', 'node-request-result')"
assert operations.count(needle) == 1
operations = operations.replace(needle, "'crypto-intent', 'crypto-result', 'node-request-intent', 'node-request-result', 'recovery-admission')")
template = body.replace('# ORIGINAL_OPERATIONS_PLACEHOLDER', operations)
assembled = template.replace('# PAYLOAD_PLACEHOLDER', 'PAYLOAD = ' + repr(payload))
compile(assembled, 'launch_coordinator_recovery_r2.py', 'exec')
parsed = ast.parse(assembled)
again = next(ast.literal_eval(n.value) for n in parsed.body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == 'PAYLOAD' for t in n.targets))
assert again == payload
assert not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == 'call'
               and any(isinstance(a, ast.Constant) and a.value == '/v1/sys/init' for a in n.args)
               for n in ast.walk(parsed))
assert payload['assets'] == next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
    and any(isinstance(t, ast.Name) and t.id == 'PAYLOAD' for t in n.targets))['assets']
(HERE / 'python-source').mkdir(exist_ok=True)
for name, text in payload['sources'].items():
    (HERE / 'python-source' / name).write_text(text)
(HERE / 'coordinator_recovery_r2.body.py').write_text(body)
(HERE / 'coordinator_recovery_r2.template.py').write_text(template)
(HERE / 'launch_coordinator_recovery_r2.py').write_text(assembled)
(HERE / 'actual-r1-to-recovery-r2.diff').write_text(''.join(difflib.unified_diff(
    body_original.splitlines(True), body.splitlines(True), fromfile='original-failed-r1-body', tofile='recovery-only-r2-body')))
(HERE / 'api-init-forbidden-r2.diff').write_text(''.join(difflib.unified_diff(
    old_api.splitlines(True), api.splitlines(True), fromfile='original-r1-api', tofile=api_name)))
plan = {'schema': 'heptabao.fixed-slot-recovery-only-preparation.r2', 'executed': False,
    'executionKey': 'heptabao-mac-fixed-slot-coordinator-recovery-20261107-r2',
    'originalExecutionKeyNotReplayed': 'heptabao-mac-fixed-slot-coordinator-normal-20261107-r1',
    'originalNativeJob': '1a1b3e976fc-fc05-8575', 'originalStatus': 'failed',
    'originalLauncher': {'bytes': 242236, 'sha256': sha(original_raw)},
    'originalReadonlyPreflight': {'job': '1a1b40a9813-fc05-85f4',
        'stdoutSha256': '3ecaf1e19fa5489d5c35b455ce7da1b4981fc4c10c69161786d59b8dac114177'},
    'launcher': {'bytes': len(assembled.encode()), 'sha256': sha(assembled.encode())},
    'body': {'bytes': len(body.encode()), 'sha256': sha(body.encode())},
    'template': {'bytes': len(template.encode()), 'sha256': sha(template.encode())},
    'pythonSourcePins': payload['pins'], 'nodeAssetPins': payload['assetPins'],
    'allElevenOriginalNodeAssetBytesUnchanged': True,
    'originalApi': old_api_pin, 'apiChange': 'init removed from categories and forbidden before journal/dispatch',
    'sameExistingInitializedStore': True, 'sameOriginalKeyAndCertificates': True,
    'newJournalOnly': '/Users/qianqi/heptabao-fixed-slot-coordinator-normal-20261107-r1/custody-recovery-r2',
    'originalJournalUnchanged': True, 'originalFailedResultUnchanged': True,
    'originalObservedDirectoryInodes': [72788478, 72788485, 72788480],
    'originalPreInitDirectoryInodeNotClaimed': True,
    'parentSeconds': 600, 'nodePhaseSeconds': 120, 'apiPhaseSeconds': 120,
    'originalEvidenceAdmissionSeconds': 20, 'coordinatorOperationMs': 30000,
    'strictClientRequestMs': 15000, 'pythonHttpSeconds': 10, 'readinessSeconds': 15,
    'supervisorSeconds': 630, 'independentNewBudgetNotExtensionOfFailedR1': True,
    'initializationRequests': 0, 'cryptoCommands': 0, 'originalNodeWorkers': 2,
    'rustGenerations': 2, 'providerCalls': 0, 'currentCredentialReads': 0,
    'productionClientChanges': 0, 'serviceRegistrationChanges': 0,
    'automaticRetry': False, 'actualCoordinatorBusinessQualified': False}
(HERE / 'recovery-plan.public.json').write_text(json.dumps(plan, indent=2) + '\n')
print(json.dumps(plan, sort_keys=True))
