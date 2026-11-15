#!/usr/bin/env python3
"""Derive the first init dispatch after r1's known zero HTTP requests."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
source = (ROOT / 'bootstrap_permanent_authbus_r1.py').read_bytes()
assert len(source) == 82208 and hashlib.sha256(source).hexdigest() == '709e228b497f84ed93df0b30bc484d60350a76b9d44944bdd951b0bb077482c7'
payload = next(ast.literal_eval(n.value) for n in ast.parse(source).body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'PAYLOAD' for t in n.targets))
before = (ROOT / 'bootstrap_permanent_authbus_r1.template.py').read_text()
after = before
def change(old, new, count=1):
    global after
    assert after.count(old) == count, (old, after.count(old))
    after = after.replace(old, new)

change("OPERATIONS = CUSTODY / 'bootstrap-r1'", "OPERATIONS = CUSTODY / 'bootstrap-r2'")
change("LEAF_SHA = '44b6927479f25f2eb9b2a1d0fb9b522066f03200ad03e0400dee76132c7e589c'", "LEAF_SHA = 'abaf8527105e19cbbe0da57a64c7a87d8e7f6e6ae15edc3636f5eee65eefd3bd'")
change("CONFIG = ROOT / 'etc/server-bootstrap.json'", "CONFIG = ROOT / 'etc/server-bootstrap-r2.json'")
change("'heptabao.permanent-bootstrap-lifecycle.r1'", "'heptabao.permanent-bootstrap-lifecycle.r2'")
change("'tls/server.crt'", "'tls/server-r2.crt'", 2)
change("('server.crt', LEAF_SHA)", "('server-r2.crt', LEAF_SHA)", 2)
change("'permanentStoreInitialized': False,", "'priorKnownNoHttpBootstrapJob': '1a1b386a389-fc05-836f',\n    'certificateCorrectionJob': '1a1b39336a2-fc05-83a7',\n    'permanentStoreInitialized': False,")
ast.parse(after)
assert after.count('# PAYLOAD_PLACEHOLDER') == 1
assembled = after.replace('# PAYLOAD_PLACEHOLDER', 'PAYLOAD = ' + repr(payload))
ast.parse(assembled)
(ROOT / 'bootstrap_permanent_authbus_r2.template.py').write_text(after)
(ROOT / 'bootstrap_permanent_authbus_r2.py').write_text(assembled)
(ROOT / 'bootstrap-r1-to-r2.diff').write_text(''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile='bootstrap-r1-template', tofile='bootstrap-r2-template')))
manifest = {'schema': 'heptabao.permanent-bootstrap-source.r2', 'actualExecuted': False,
    'launcher': {'bytes': len(assembled.encode()), 'sha256': hashlib.sha256(assembled.encode()).hexdigest()},
    'sourcesUnchanged': payload['pins'], 'previousActualJob': '1a1b386a389-fc05-836f',
    'previousOutcomeKnown': True, 'previousHttpRequests': 0, 'previousInitRequests': 0,
    'previousOriginalServersAndResourcesClosed': True,
    'correctionActualJob': '1a1b39336a2-fc05-83a7',
    'correctionNativeStrictMemoryTls': 'old-leaf-known-85-denied; corrected-leaf-TLSv1.3-success',
    'existingPermanentStoreConfirmedEmpty': True, 'sameExistingStoreRetained': True,
    'firstInitDispatchStillRequiresFreshEmptyDataDirectoryAndStrictTls501Uninitialized': True,
    'parentSeconds': 300, 'eachApiPhaseSeconds': 120, 'supervisorSeconds': 330,
    'noRelaxedTlsOrDeadline': True, 'noClientOrLegacyOrProviderOperation': True}
(ROOT / 'bootstrap-r2-source-manifest.public.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest))
