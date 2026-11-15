#!/usr/bin/env python3
"""Assemble the reviewed create-once bootstrap source, without remote execution."""
from pathlib import Path
import ast
import difflib
import hashlib
import json

WORK = Path(__file__).resolve().parent
QUALIFIED = WORK.parent / 'main3-authbus-work/source-api-r5'
source = (QUALIFIED / 'main3_api_cycle.py').read_text()
node = [n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name == 'Api']
assert len(node) == 1
old = ast.get_source_segment(source, node[0]) + '\n'

def once(text, before, after):
    assert text.count(before) == 1, before[:100]
    return text.replace(before, after, 1)

new = once(old, "ROOT/'server/tls/server.crt'", "ROOT/'tls/ca.crt'")
new = once(new, "'httpRequestCount':0,'connectionAttempts':0", "'responsePrivatelyDurable':False,'httpRequestCount':0,'connectionAttempts':0")
new = once(new, "            value=json.loads(data) if data else {}", "            self.journal.response_bytes(self.phase,row['ordinal'],data)\n            row['responsePrivatelyDurable']=True\n            left();value=json.loads(data) if data else {}")
new = once(new, "bool(row['dispatched'] and not row['responseComplete'])", "bool(row['dispatched'] and not (row['responseComplete'] and row['responsePrivatelyDurable']))")
new = once(new, "'allReturnedSocketsClosed':all(r['socketsClosed'] for r in self.rows),", "'allReturnedSocketsClosed':all(r['socketsClosed'] for r in self.rows),\n                'allCompleteResponsesPrivatelyDurable':all(not r['responseComplete'] or r['responsePrivatelyDurable'] for r in self.rows),")
header = '''import errno,hashlib,http.client,json,re,socket,ssl,time
from pathlib import Path
from main3_http_complete import DeadlineSocket,CompleteHTTPResponse,read_complete_body,safe_failure_code
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-authbus-production')
MAX_HTTP=192
MAX_BODY=1048576
class Refused(RuntimeError):pass
def need(value,code):
    if not value:raise Refused(code)
'''
api_source = header + new
ast.parse(api_source)
(WORK / 'permanent_bootstrap_api_r1.py').write_text(api_source)
(WORK / 'api-r5-to-permanent-bootstrap-r1.diff').write_text(''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile='qualified-r5-Api', tofile='permanent-r1-Api')))
sources = {}
for name in ('mac_owned_unreaped_r1.py', 'mac_owned_commands_r1.py', 'mac_production_t5_guard_r1.py', 'mac_public_code_pin_excerpt_r1.py'):
    path = WORK / name if name == 'mac_production_t5_guard_r1.py' else QUALIFIED / name
    sources[name] = path.read_text()
sources['main3_http_complete.py'] = (QUALIFIED / 'main3_http_complete.py').read_text()
sources['permanent_bootstrap_api_r1.py'] = api_source
pins = {name: {'bytes': len(value.encode()), 'sha256': hashlib.sha256(value.encode()).hexdigest()} for name, value in sources.items()}
payload = {'sources': sources, 'pins': pins}
template = (WORK / 'bootstrap_permanent_authbus_r1.template.py').read_text()
assert template.count('# PAYLOAD_PLACEHOLDER') == 1
launcher = template.replace('# PAYLOAD_PLACEHOLDER', 'PAYLOAD = ' + repr(payload))
ast.parse(launcher)
(WORK / 'bootstrap_permanent_authbus_r1.py').write_text(launcher)
manifest = {'schema': 'heptabao.permanent-bootstrap-source.r1', 'actualExecuted': False,
    'launcher': {'bytes': len(launcher.encode()), 'sha256': hashlib.sha256(launcher.encode()).hexdigest()},
    'sources': pins, 'parentSeconds': 300, 'eachApiPhaseSeconds': 120, 'supervisorSeconds': 330,
    'serviceInstalled': False, 'currentCredentialsRead': False, 'providerCalls': 0,
    'realNewPermanentStoreInitializedIfExecuted': True,
    'apiDelta': 'Original strict wire reader, per-request deadlines and owned socket closure; new independent CA; complete responses fsynced privately before JSON parsing.',
    'postRunServerStopped': True, 'newOriginalOnceSlot': '/Users/qianqi/heptabao-authbus-production-custody/bootstrap-r1'}
(WORK / 'bootstrap-source-manifest.public.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
print(json.dumps(manifest))
