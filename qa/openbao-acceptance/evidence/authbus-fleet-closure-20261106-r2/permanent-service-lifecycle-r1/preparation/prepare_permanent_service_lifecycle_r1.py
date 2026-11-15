#!/usr/bin/env python3
"""Freeze launchd lifecycle validation of the already initialized permanent store.

Local preparation only. Reuse the actual qualified normal server, original
separate key custody and four preserve-absent launchd primitives. No remote I/O.
"""
import ast
import difflib
import hashlib
import json
from pathlib import Path

WORK = Path(__file__).resolve().parent
AUDIT = WORK.parent / 'authbus-refresh-work'
original = (WORK / 'bootstrap_permanent_authbus_r2.py').read_bytes()
assert len(original) == 82341 and hashlib.sha256(original).hexdigest() == \
    '2780c5fcef1aebd7b7fffa406af39521dc9cab02c372321df9ef4322bab46422'


def payload_of(raw):
    return next(ast.literal_eval(node.value) for node in ast.parse(raw).body
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
            and target.id == 'PAYLOAD' for target in node.targets))


payload = payload_of(original)
original_api = payload['sources'].pop('permanent_bootstrap_api_r1.py')
payload['pins'].pop('permanent_bootstrap_api_r1.py')
api = original_api


def api_change(old, new):
    global api
    assert api.count(old) == 1, (old, api.count(old))
    api = api.replace(old, new)


api_change("phase in ('initial','cold-new-process')", "phase in ('first','recovery')")
api_change("'original_api_phase_120_seconds'", "'original_service_shared_45_seconds'")
api_change("('health','init','unseal','mount','activate','capacity','policy','role','role-id','secret-id','login','kv-read','kv-write','lookup','renew','revoke','secret-destroy','admin-denied')",
           "('health','unseal','capacity','policy','role','role-id','secret-id','login','kv-read','kv-write','lookup','renew','revoke','secret-destroy','admin-denied')")
api_change("if category=='activate':need(method=='POST' and route=='/v1/sys/storage/native-v6/activate','normal_configured_storage_activation_only')",
           "need(route not in ('/v1/sys/init','/v1/sys/storage/native-v6/activate'),'existing_store_never_initialized_or_activated_again')")
api_change("socket.create_connection(('127.0.0.1',self.plan['port'])",
           "socket.create_connection(('192.168.0.8',self.plan['port'])")
api_change("server_hostname='localhost'", "server_hostname='192.168.0.8'")
api_change("'Host: localhost:'", "'Host: 192.168.0.8:'")
ast.parse(api)
(WORK / 'permanent_service_api_r1.py').write_text(api)
(WORK / 'bootstrap-to-service-api-r1.diff').write_text(''.join(difflib.unified_diff(
    original_api.splitlines(True), api.splitlines(True),
    fromfile='actual-qualified-bootstrap-api-r2', tofile='prepared-permanent-lan-service-api-r1')))
payload['sources']['permanent_service_api_r1.py'] = api
preserve = (AUDIT / 'launch_preserve_absent_primitives_r1.py').read_bytes()
assert len(preserve) == 126346 and hashlib.sha256(preserve).hexdigest() == \
    '75ee27ae3c3ea5d3e248ce3da8e47b9d0e56a4598402949f11400761622868fe'
qualified_preserve = WORK.parent / 'HeptaBao-current-924b/qa/openbao-acceptance/evidence/authbus-fleet-closure-20261106-r2/preserve-absent-mac-r1/code/launch_preserve_absent_primitives_r1.py'
assert preserve == qualified_preserve.read_bytes()
prior = payload_of(preserve)
for name in ('mac_owned_unreaped_r1.py', 'mac_owned_commands_r1.py'):
    assert payload['sources'][name] == prior['sources'][name]['text']
for name in ('mac_native_process_observer_r1.py', 'mac_owned_launchd_r3.py'):
    value = prior['sources'][name]
    assert len(value['text'].encode()) == value['bytes']
    assert hashlib.sha256(value['text'].encode()).hexdigest() == value['sha256']
    payload['sources'][name] = value['text']
core = (WORK / 'mac_permanent_service_primitives_r1.py').read_bytes()
assert len(core) == 16940 and hashlib.sha256(core).hexdigest() == \
    '70526d9b15be50122119640f6c9b2385183bae4263667575efee58676ccd8343'
payload['sources']['mac_permanent_service_primitives_r1.py'] = core.decode()
payload['pins'] = {name: {'bytes': len(source.encode()),
    'sha256': hashlib.sha256(source.encode()).hexdigest()}
    for name, source in payload['sources'].items()}
prefix = (WORK / 'bootstrap_permanent_authbus_r2.template.py').read_text().split('def main():', 1)[0]
start = prefix.index('"""'); end = prefix.index('"""', start + 3)
prefix = prefix[:start] + '''"""Validate two launchd cold generations of the initialized permanent store.

The four once-only launchd actions retain original absent disabled override.
Each exact bound birth uses strict original CA/leaf and the LAN IP SAN. Existing
separate HOME custody supplies explicit unseal; initialization and storage
activation are forbidden. The plist stays outside autoload and the final
registration is absent. No provider refresh or registered client action.
"""''' + prefix[end + 3:]
prefix = prefix.replace("OPERATIONS = CUSTODY / 'bootstrap-r2'",
                        "OPERATIONS = CUSTODY / 'service-lifecycle-r1'")
prefix = prefix.replace("CONFIG = ROOT / 'etc/server-bootstrap-r2.json'",
                        "CONFIG = ROOT / 'etc/server-r2.json'")
prefix = prefix.replace("ROLE = 'bootstrap-lifecycle-r1'", "ROLE = 'service-lifecycle-r1'")
prefix = prefix.replace("SECRET_PATH = '/v1/openclaw-auth/data/qualification/bootstrap-lifecycle-r1'",
    "OLD_SECRET_PATH = '/v1/openclaw-auth/data/qualification/bootstrap-lifecycle-r1'\n"
    "SECRET_PATH = '/v1/openclaw-auth/data/qualification/service-lifecycle-r1'")
prefix = prefix.replace("    '/bin/ps': (170432,",
    "    '/bin/launchctl': (363488, 'b4dbf509754d8e1117f7851baa93ede75bc75218c48d6ddf19fbb1505d261be7'),\n"
    "    '/bin/ps': (170432,")
prefix = prefix.replace('UNTIL = START + 300', 'UNTIL = START + 45')
prefix = prefix.replace("phase in ('initial', 'cold-new-process')", "phase in ('first', 'recovery')")
start = prefix.index('REPORT = {'); end = prefix.index('\n\nclass Refused', start)
prefix = prefix[:start] + '''REPORT = {'schema': 'heptabao.permanent-launchd-service-lifecycle.r1', 'ok': False,
    'productCommit': PRODUCT, 'automaticRetry': False, 'initializationRequests': 0,
    'currentCredentialReads': 0, 'providerCalls': 0, 'legacyChanges': 0,
    'productionClientChanges': 0, 'autoloadPlistInstalled': False, 'j3160Requests': 0,
    'rootKeyValuesOrDigestsPublished': False, 'productionCutoverQualified': False,
    'parentSeconds': 45, 'supervisorSeconds': 70, 'phaseDeadlineIsOriginalParent': True,
    'originalPermanentBootstrapJob': '1a1b396b21c-fc05-83b9',
    'originalPreserveAbsentJob': '1a1b3d6ebd5-fc05-8503',
    'independentLanClientQualified': False, 'apiPhases': []}
''' + prefix[end:]
assert 'UNTIL = START + 45' in prefix
source = prefix + (WORK / 'permanent_service_lifecycle_r1.body.py').read_text()
ast.parse(source)
assert source.count('# PAYLOAD_PLACEHOLDER') == 1
assembled = source.replace('# PAYLOAD_PLACEHOLDER', 'PAYLOAD = ' + repr(payload))
ast.parse(assembled)
(WORK / 'permanent_service_lifecycle_r1.template.py').write_text(source)
(WORK / 'permanent_service_lifecycle_r1.py').write_text(assembled)
manifest = {'schema': 'heptabao.permanent-service-lifecycle-preparation.r1',
    'preparedOnly': True, 'actualExecuted': False,
    'launcher': {'bytes': len(assembled.encode()), 'sha256': hashlib.sha256(assembled.encode()).hexdigest()},
    'sources': payload['pins'], 'parentSeconds': 45, 'supervisorSeconds': 70,
    'normalProductCommit': '4bde9aee03fcd27c59e13607e529b1cee594b249',
    'twoGenerationSameOriginalPlist': True, 'disabledOverrideMustRemainAbsent': True,
    'automaticUnsealDaemonIntroduced': False, 'apiInitializationAndActivationForbidden': True,
    'sameHostLanIpSanTlsRequired': True, 'independentLanClientQualified': False,
    'registeredClientsChanged': 0, 'providerCalls': 0, 'legacyDeletion': 0,
    'sharedAbsoluteDeadlineForAllPhases': True,
    'launchctlUnknownAllowsAutomaticFailureMutation': False,
    'onlyKnownOriginalBirthMayBeClosedAfterApiFailure': True,
    'productionCutoverQualified': False}
(WORK / 'permanent-service-lifecycle-r1.manifest.public.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, sort_keys=True))
