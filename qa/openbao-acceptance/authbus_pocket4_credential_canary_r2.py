#!/usr/bin/env python3
"""Retry Pocket4 with its unchanged 0.3.3 scoped-report contract.

Run this controller on main as the existing credential owner. Only the selected
Google API key crosses the already authorized SSH connection, through private
stdin. Each target independently verifies the official provider and creates its
own source candidate. The pinned R9 driver consumes each target's original
plugin and installed SDK. No production configuration or binary is replaced.

Stdout is a bounded public summary. Detailed child output and all credential
material remain mode 0600 inside new mode 0700 directories on their owner host.
Existing attempt directories are never reused. A lost SSH reply is an unknown
outcome; the controller does not retry the operation.

The R1 controller and all eight R9 QA dependencies remain frozen. The only
candidate change is a new, isolated shadow scheduler scope naming the exact
Google profile consumed by the unchanged R9 fixture. AuthBus 0.3.3 intentionally
reports only scheduler resources; the empty policy used in R1 produced no inbox
events. This retry retains every original LIST-200, profile, TLS, restart,
rollback, backup and revocation assertion. It enables no enforced assignments.
"""
from __future__ import annotations

import argparse
import ast
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import signal
import stat
import subprocess
import sys


MAIN_HOME = Path('/home/qian-qi')
MAIN_ROOT = MAIN_HOME / 'heptabao-next-gates-20261017'
SOURCE_ROOT = MAIN_ROOT / 'source-r8e'
MANIFEST = MAIN_ROOT / 'r8e-source-manifest.json'
MANIFEST_SHA = '277f334743f08c6929e3f688378a38533b3bc55ec76ebfd18d81fe7efd463b2d'
SOURCE_COMMIT = '147c450a198f4ea5ada0ee6af7c23d5368172390'
SOURCE_TREE = '4d878c6ee3eb29ae648efa6ea4f52ec240ee9e1e'
MAIN_CANDIDATE = MAIN_ROOT / 'authbus-google-source-20261017-r1/candidate.private.json'
MAIN_CANDIDATE_SHA = '80eefc93f15d596933658d25d7c4a3c666bfcbda6c1d498c46b60af1d7995c76'
MAIN_SOURCE = MAIN_HOME / '.openclaw/gateway.systemd.env'
CREDENTIAL_SHA = '16900c8f2203da5c2a0a3de7aaf2edd0288d7b0e097b827646ca8bef6a5000dc'
MAIN_PROFILE = 'google:authbus-source-main'
BASE_CONTROLLER_SHA = '8c7ef51b1fb9978b07302151645b343bdf2f4c8303d6d4b490f248ae5a4537a1'
FIXTURE_HOST = 'authbus-isolated-main'
MAX_PACKET = 2 * 1024 * 1024
FILES = {
    'qa/openbao-acceptance/native_v6_openclaw_authbus_live.py': '6d785c4d69ad800b7c9ac5f8510397031362ff5bca9947be024700e91235c98a',
    'qa/openbao-acceptance/native_v6_openclaw_authbus_consumer.mjs': 'dde1f8097c190379b88f70292abf4c0a5fb45ba3db7a6c8c805843321b7c4cab',
    'qa/openbao-acceptance/native_v6_authbus_client_live.py': '2357c3486d9312da65617705b13e42b70434231efe5b3812c6131f71d3735a0e',
    'qa/openbao-acceptance/cert_auth_live.py': '17da3c53ccb5379b6b63790fb34dc0502666662ae5528dfad97eccfb3ac1acc9',
    'qa/openbao-acceptance/owned_process.py': '0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0',
    'qa/openbao-acceptance/fixture_mounts.py': '55075ee436c22816a176dfb06cec387df37fdadd581c16acc07dabc837ba85b5',
    'qa/single-node/smoke.py': 'ced4e40a825d3d98a285598d40b58c61083cfc397d0859a783958d855a161971',
    'qa/openbao-acceptance/authbus_google_source_prepare.py': 'cc01ece1da77a0ac4c4c935b98a1bb59731d2d7fbcbcca09abaec2eca0d4336a',
}
PLUGIN_SHARED = {
    'index.js': 'b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b',
    'order-policy.js': '16bddaa7d18600f9f09dac7b5fb4999a141c86aab1fb15d3e9d6abc24e1cf301',
    'runtime-refresh-policy.js': '8257a6d2ee04868f3a7de5ff8ffaa7fdd3b37bb12a07ac993a3e9c7480c83547',
    'codex-client-recycler.js': 'd3fffe4c401af1dd997017a22930da241d2a4a899c518ce6d25c7047f1b3a13d',
    'lease-assignments.js': '24192dc82ddd682e836ea2df717b065b76773c0a1f4b0905f6764e4d498d77e7',
    'provider-error-classifier.js': '3f9470edea686a0eb46400efecc4c12a284e7fdef018565c34185b0cff102d77',
    'bad-refresh-quarantine.js': '916617f296bd2e4b97b240a13418ac6220bb6513a1a0b83f5ee21854edc62286',
}
LINUX_BINARY_SHA = 'cc7e7a1de7deb6e184b1559b60d292072826384ef23fabe55265360a8f5e6c8f'
TARGETS = {
    'macbook-pro': {
        'home': '/Users/qianqi', 'platform': 'Darwin', 'node': '/opt/homebrew/bin/node',
        'sdk': '/opt/homebrew/lib/node_modules/openclaw', 'plugin_version': '0.3.1',
        'root_base': '/Volumes/T5/hepta-vnext-recovery-20261013/authbus-native-host-',
        'binary': '/Volumes/T5/hepta-vnext-recovery-20261013/next-gates-loopback-20261017-r1-node1/heptabao-server',
        'binary_sha256': '52d2b0c75fa87cfc7a18f5bb02518e4ebc7efad0f0555f35d9626dd10e3c0baa',
    },
    'rog': {
        'home': '/home/qian-qi', 'platform': 'Linux', 'node': '/usr/bin/node',
        'sdk': '/home/qian-qi/.npm-global/lib/node_modules/openclaw', 'plugin_version': '0.3.1',
        'root_base': '/home/qian-qi/heptabao-authbus-native-host-',
        'binary': '/home/qian-qi/heptabao-next-gates-loopback-20261017-r1-node2/heptabao-server',
        'binary_sha256': LINUX_BINARY_SHA,
    },
    'pocket4': {
        'home': '/home/alex', 'platform': 'Linux', 'node': '/usr/bin/node',
        'sdk': '/home/alex/.npm-global/lib/node_modules/openclaw', 'plugin_version': '0.3.3',
        'root_base': '/home/alex/heptabao-authbus-native-host-',
        'binary': '/home/alex/heptabao-next-gates-loopback-20261017-r1-node3/heptabao-server',
        'binary_sha256': LINUX_BINARY_SHA,
    },
}
SSH_OPTIONS = ['-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
               '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2',
               '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes']
ESSENTIAL_CHECKS = (
    'source.fingerprint_current', 'server.reader_format2', 'bootstrap.exact_real_credential',
    'initial.actual_sdk_store_exact', 'initial.real_verified_tls', 'initial.fresh_full_tls_per_request',
    'acl.profile_write_denied', 'acl.other_host_inbox_denied',
    'token.actual_plugin_renew_self', 'token.actual_plugin_renewable',
    'backup.database_present', 'cold_restart.real_profile_exact',
    'cold_restart.actual_client_sqlite_survived', 'rollback.bad_ca_did_not_authenticate',
    'rollback.failed_binding_kept_exact_profile', 'rollback.binding_exact_bytes',
    'backup.actual_sdk_restore', 'revoke.actual_plugin_relogin_denied',
    'plugin.actual_inbox_list', 'plugin.actual_host_reports_persisted',
    'revoke.persisted_token_denial.0', 'revoke.persisted_sid_exact_error',
    'source.environment_unchanged', 'source.candidate_unchanged',
    'plugin.production_code_unchanged', 'evidence.no_secret_values',
)


class Failure(Exception):
    """Only fixed machine-readable diagnostic codes may be constructed here."""


class Interrupted(BaseException):
    """A termination signal must close our active child before reporting."""


def interrupted(_signum, _frame):
    raise Interrupted()


def require(condition, code):
    if not condition:
        raise Failure(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def read_file(path, maximum=MAX_PACKET, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'bounded_regular_file_required')
        if private:
            require(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600,
                    'owned_mode600_file_required')
        chunks, size = [], 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            require(size <= maximum, 'file_exceeded_bound')
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'file_changed_during_read')
        return b''.join(chunks), before
    finally:
        os.close(fd)


def file_sha(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 1024 * 1024 * 1024,
                'bounded_regular_binary_required')
        state, count = hashlib.sha256(), 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            state.update(block)
            count += len(block)
            require(count <= 1024 * 1024 * 1024, 'binary_exceeded_bound')
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'binary_changed_during_read')
        return state.hexdigest()
    finally:
        os.close(fd)


def directory(path, new=False):
    if new:
        path.mkdir(mode=0o700, parents=False, exist_ok=False)
    status = path.lstat()
    require(stat.S_ISDIR(status.st_mode) and status.st_uid == os.geteuid() and
            stat.S_IMODE(status.st_mode) == 0o700, 'owned_mode700_directory_required')


def write_private(path, payload):
    if not isinstance(payload, bytes):
        payload = canonical(payload) + b'\n'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_json(path, private=True):
    payload, _ = read_file(path, private=private)
    return json.loads(payload)


def no_secrets(payload, secrets):
    require(all(not value or value.encode() not in payload for value in secrets), 'public_evidence_contains_secret')


def target(host, attempt):
    require(host == 'pocket4' and re.fullmatch(r'r[1-9][0-9]{0,3}', attempt), 'invalid_target_or_attempt')
    result = dict(TARGETS[host])
    result.update(host=host, attempt=attempt, root=result['root_base'] + attempt,
                  plugin=result['home'] + '/.openclaw/extensions/openclaw-authbus')
    result['plugin_hashes'] = dict(PLUGIN_SHARED)
    if host == 'pocket4':
        result['plugin_hashes'].update({
            'index.js': '8e10c52df53d6d16d0e5890a6ccdaaff9515469e4419b46270b9bdc62b9be7af',
            'order-policy.js': 'a1a9923368a1a6bd9adf691aa1beba02d443cf511232e17118c9868160a96e82',
        })
    return result


def clean_environment(spec=None):
    env = dict(os.environ)
    for name in ('GOOGLE_API_KEY', 'GEMINI_API_KEY', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY',
                 'OPENCLAW_GATEWAY_TOKEN', 'NODE_OPTIONS', 'NODE_PATH', 'PYTHONPATH',
                 'PYTHONSTARTUP', 'PYTHONHOME'):
        env.pop(name, None)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    if spec and spec['platform'] == 'Darwin':
        env['PATH'] = '/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin'
    return env


def run_child(argv, log_root, name, timeout, *, env=None, payload=None):
    """An owned session bounds only our disposable child and its descendants."""
    paths = [log_root / (name + '.stdout.private.log'), log_root / (name + '.stderr.private.log')]
    streams = []
    try:
        for path in paths:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            streams.append(os.fdopen(fd, 'wb'))
        proc = subprocess.Popen(argv, cwd=str(log_root), env=env, stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
                                stdout=streams[0], stderr=streams[1], start_new_session=True)
        timed_out = False
        try:
            proc.communicate(input=payload, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            # Popen is still unreaped here; no PID lookup, service-name match,
            # or unrelated process can supply this ownership reference.
            try:
                if os.getpgid(proc.pid) == proc.pid:
                    os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=5)
        except BaseException:
            try:
                if os.getpgid(proc.pid) == proc.pid:
                    os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=5)
            raise
        return {'exit_code': proc.returncode, 'timed_out': timed_out,
                'stdout_path': str(paths[0]), 'stderr_path': str(paths[1])}
    finally:
        for stream in streams:
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()


def load_prepare(source_root):
    path = source_root / 'qa/openbao-acceptance/authbus_google_source_prepare.py'
    require(file_sha(path) == FILES['qa/openbao-acceptance/authbus_google_source_prepare.py'], 'source_prepare_hash_mismatch')
    spec = importlib.util.spec_from_file_location('fleet_source_prepare', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_candidate(path, source_root, expected_env, expected_profile, expected_candidate_sha=None):
    payload, meta = read_file(path, private=True)
    candidate_sha = hashlib.sha256(payload).hexdigest()
    require(expected_candidate_sha is None or candidate_sha == expected_candidate_sha, 'candidate_fingerprint_changed')
    value = json.loads(payload)
    require(value.get('schema') == 'authbus-private-bootstrap-candidate-v1' and value.get('mount') == 'openclaw-auth', 'candidate_schema_mismatch')
    data = value['profile']['data']
    credential = data['credential']
    require(set(credential) == {'type', 'provider', 'key'} and credential['type'] == 'api_key' and
            credential['provider'] == 'google' and re.fullmatch(r'[A-Za-z0-9_-]{8,512}', credential['key']), 'candidate_credential_shape_mismatch')
    require(digest(credential) == CREDENTIAL_SHA and data['digest'] == CREDENTIAL_SHA and
            data['profileId'] == expected_profile, 'candidate_credential_or_profile_changed')
    identity = {field: credential.get(field) for field in ('provider', 'type', 'email', 'accountId', 'projectId')}
    require(data['identity'] == digest(identity), 'candidate_identity_digest_mismatch')
    entry = {'profileId': expected_profile, 'key': 'sha256-' + CREDENTIAL_SHA, 'digest': CREDENTIAL_SHA,
             'provider': 'google', 'type': 'api_key'}
    require(value['manifest']['data'] == {'schemaVersion': 1, 'generation': 1, 'profiles': [entry]} and
            value['manifest']['cas'] == 0 and value['profile']['cas'] == 0 and
            value['profile']['path'] == 'profiles/' + entry['key'], 'candidate_manifest_mismatch')
    proof = value['verification']
    negative, positive = proof['unauthenticated_control'], proof['authenticated_probe']
    require(negative.get('http_status') in (400, 401, 403) and negative.get('tls_verified') is True and
            positive.get('http_status') == 200 and positive.get('tls_verified') is True and
            positive.get('models_array') is True and positive.get('body_within_bound') is True,
            'candidate_official_verification_missing')
    require(value['source']['path'] == str(expected_env), 'candidate_source_path_mismatch')
    _, source_stat = read_file(expected_env, maximum=65536, private=True)
    prepare = load_prepare(source_root)
    values, source_meta = prepare.read_source(expected_env)
    require(source_meta['sha256'] == value['source']['sha256'] and
            source_meta['uid'] == value['source']['uid'] and stat.S_IMODE(source_stat.st_mode) == 0o600,
            'candidate_original_source_changed')
    selected = value['selected_field']
    require(selected in ('GOOGLE_API_KEY', 'GEMINI_API_KEY') and selected in values and
            hmac.compare_digest(values[selected], credential['key']), 'candidate_source_value_mismatch')
    return credential['key'], {
        'candidate_path': str(path), 'candidate_sha256': candidate_sha, 'candidate_uid': meta.st_uid,
        'candidate_mode': '0o600', 'source_path': str(expected_env), 'source_sha256': source_meta['sha256'],
        'source_uid': source_meta['uid'], 'source_mode': '0o600', 'selected_field': selected,
        'credential_digest': CREDENTIAL_SHA, 'profile_id': expected_profile,
        'official_negative_status': negative['http_status'], 'official_positive_status': positive['http_status'],
    }


def build_packet():
    payload, _ = read_file(MANIFEST)
    require(hashlib.sha256(payload).hexdigest() == MANIFEST_SHA, 'source_manifest_fingerprint_changed')
    manifest = json.loads(payload)
    require(manifest['source_commit'] == SOURCE_COMMIT and manifest['source_tree'] == SOURCE_TREE, 'source_manifest_revision_changed')
    files = {}
    for relative, expected in FILES.items():
        data, _ = read_file(SOURCE_ROOT / relative, maximum=262144)
        require(manifest['files'].get(relative) == expected and hashlib.sha256(data).hexdigest() == expected and
                manifest['modes'].get(relative) in ('100644', '100755'), 'qa_manifest_or_file_mismatch')
        if relative.endswith('.py'):
            ast.parse(data, feature_version=(3, 9))
        files[relative] = base64.b64encode(data).decode('ascii')
    controller, _ = read_file(Path(__file__), maximum=262144)
    return {'schema': 'authbus-code-only-deployment-v1', 'manifest_sha256': MANIFEST_SHA,
            'source_commit': SOURCE_COMMIT, 'source_tree': SOURCE_TREE, 'files': files,
            'controller_sha256': hashlib.sha256(controller).hexdigest(),
            'controller': base64.b64encode(controller).decode('ascii')}


# The initial SSH payload contains only pinned code. The command argument is a
# hash, never a credential. A pre-existing target root fails before any write.
BOOTSTRAP = r'''
import base64,hashlib,json,os,pathlib,stat,sys
try:
 root=pathlib.Path(sys.argv[1]); expected=sys.argv[2]; host=sys.argv[3]; attempt=sys.argv[4]
 data=sys.stdin.buffer.read(2097153)
 if len(data)>2097152: raise ValueError()
 packet=json.loads(data); code=base64.b64decode(packet['controller'],validate=True)
 if hashlib.sha256(code).hexdigest()!=expected or packet['controller_sha256']!=expected: raise ValueError()
 if not root.is_absolute() or root.is_symlink(): raise ValueError()
 root.mkdir(mode=0o700,parents=False,exist_ok=False)
 s=root.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700: raise ValueError()
 for name,value in [('fleet-controller.py',code),('deployment.private.json',data)]:
  fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as f: f.write(value);f.flush();os.fsync(f.fileno())
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 os.execv(sys.executable,[sys.executable,str(root/'fleet-controller.py'),'_install','--host',host,'--attempt',attempt])
except BaseException as e:
 print(json.dumps({'schema':'authbus-fleet-bootstrap-failure-v1','ok':False,'error_class':type(e).__name__}))
 sys.exit(70)
'''


def verify_target_files(spec):
    require(platform.system() == spec['platform'] and str(Path.home()) == spec['home'], 'ssh_target_identity_mismatch')
    require(Path(spec['home']).stat().st_uid == os.geteuid(), 'target_home_owner_mismatch')
    require(file_sha(Path(spec['binary'])) == spec['binary_sha256'] and os.access(spec['binary'], os.X_OK), 'target_binary_fingerprint_changed')
    actual = {}
    for name, expected in spec['plugin_hashes'].items():
        payload, _ = read_file(Path(spec['plugin']) / name, maximum=262144)
        actual[name] = hashlib.sha256(payload).hexdigest()
        require(actual[name] == expected, 'target_original_plugin_fingerprint_changed')
    require(Path(spec['node']).is_file() and os.access(spec['node'], os.X_OK), 'target_node_missing')
    package = read_json(Path(spec['sdk']) / 'package.json', private=False)
    require(package.get('name') == 'openclaw' and isinstance(package.get('version'), str) and
            re.fullmatch(r'[A-Za-z0-9.+_-]{1,80}', package['version']), 'target_sdk_package_mismatch')
    return {'binary_sha256': spec['binary_sha256'], 'plugin_source_sha256': actual,
            'sdk_path': spec['sdk'], 'sdk_version': package.get('version'),
            'node_path': spec['node'], 'python_version': platform.python_version(),
            'platform': platform.system(), 'home': spec['home'], 'uid': os.geteuid()}


def install_worker(spec, report):
    root = Path(spec['root'])
    directory(root)
    require(Path(__file__).resolve() == root / 'fleet-controller.py', 'worker_location_mismatch')
    packet = read_json(root / 'deployment.private.json')
    require(packet.get('schema') == 'authbus-code-only-deployment-v1' and packet['manifest_sha256'] == MANIFEST_SHA and
            packet['source_commit'] == SOURCE_COMMIT and packet['source_tree'] == SOURCE_TREE and
            set(packet['files']) == set(FILES), 'deployment_contract_mismatch')
    require(file_sha(Path(__file__)) == packet['controller_sha256'], 'worker_fingerprint_changed')
    source = root / 'source'
    for relative in ('source', 'source/qa', 'source/qa/openbao-acceptance', 'source/qa/single-node'):
        directory(root / relative, new=True)
    for relative, expected in FILES.items():
        data = base64.b64decode(packet['files'][relative], validate=True)
        require(len(data) <= 262144 and hashlib.sha256(data).hexdigest() == expected, 'deployed_qa_fingerprint_mismatch')
        if relative.endswith('.py'):
            ast.parse(data, feature_version=(3, 9))
        write_private(source / relative, data)
    report.update(verify_target_files(spec))
    env = clean_environment(spec)
    probe = run_child([spec['node'], '--version'], root, 'node-version', 15, env=env)
    node_version, _ = read_file(Path(probe['stdout_path']), maximum=256, private=True)
    require(probe['exit_code'] == 0 and re.fullmatch(rb'v[0-9]+\.[0-9]+\.[0-9]+\s*', node_version), 'target_node_version_failed')
    report['node_version'] = node_version.decode().strip()
    checked = run_child([spec['node'], '--check', str(source / 'qa/openbao-acceptance/native_v6_openclaw_authbus_consumer.mjs')],
                        root, 'node-syntax', 15, env=env)
    require(checked['exit_code'] == 0 and not checked['timed_out'], 'target_node_consumer_syntax_failed')
    # Real target Python imports the unchanged R9 closure and constructs only
    # disposable TLS files. No server starts and no key has been sent yet.
    code = ("import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);"
            "import native_v6_openclaw_authbus_live as x;"
            "i=x.NativeInstance(Path(sys.argv[2]),Path(sys.argv[3]));"
            "assert i.process is None;print('target_compatibility_ok')")
    compat = run_child(['/usr/bin/python3', '-c', code, str(source / 'qa/openbao-acceptance'), spec['binary'], str(root / 'compatibility-tls')],
                       root, 'python-runtime-and-openssl', 45, env=env)
    require(compat['exit_code'] == 0 and not compat['timed_out'], 'target_python_or_openssl_compatibility_failed')
    report.update(ok=True, source_key_received=False, qa_files=FILES, source_manifest_sha256=MANIFEST_SHA,
                  controller_sha256=packet['controller_sha256'], python_runtime_import_and_tls_files=True,
                  owned_process_mode='standalone_original_popen_handles', canonical_linux_process_owner_qualified=False)


def private_secrets(root, key):
    values = [key]
    recovery = root / 'recovery.private.json'
    if recovery.exists():
        value = read_json(recovery)
        values.extend(value.get(name) for name in ('root_token', 'unseal_key'))
    for name in ('role_id', 'secret_id'):
        path = root / 'credentials' / name
        if path.exists():
            values.append(read_file(path, maximum=8192, private=True)[0].decode())
    for cycle in ('initial', 'cold_restart', 'bad_ca', 'binding_restored', 'backup_restored', 'sid_revoked'):
        path = root / 'runs' / cycle / 'auth.private.json'
        if path.exists():
            for item in read_json(path).get('tokens', []):
                values.extend(item.get(field) for field in ('token', 'accessor'))
    return [value for value in values if isinstance(value, str) and value]


def validate_canary(receipt, spec):
    checks = receipt.get('checks', [])
    require(receipt.get('schema') == 'native-v6-actual-openclaw-authbus-live-v1' and
            receipt.get('ok') is True and len(checks) >= 100 and
            all(item.get('passed') is True for item in checks), 'target_r9_canary_failed')
    names = {item['case'] for item in checks}
    require(set(ESSENTIAL_CHECKS) <= names, 'target_r9_required_evidence_missing')
    require(receipt.get('binary_sha256') == spec['binary_sha256'] and
            receipt.get('plugin_source_sha256') == spec['plugin_hashes'] and
            receipt.get('credential_digest') == CREDENTIAL_SHA and
            receipt.get('harness_sha256') == FILES['qa/openbao-acceptance/native_v6_openclaw_authbus_live.py'] and
            receipt.get('node_harness_sha256') == FILES['qa/openbao-acceptance/native_v6_openclaw_authbus_consumer.mjs'],
            'target_r9_provenance_mismatch')
    require(receipt.get('production_cutover') is False and receipt.get('j3160_contacted') is False and
            receipt.get('ha_qualification') is False and receipt.get('legacy_oauth_migrated') is False,
            'target_r9_scope_mismatch')
    cycles = {item['case']: item for item in receipt.get('client_cycles', [])}
    for name in ('initial', 'cold_restart', 'binding_restored', 'backup_restored'):
        require(cycles.get(name, {}).get('plugin', {}).get('schedulerReports') == 1,
                'target_original_033_scoped_report_missing')
    for name in ('initial', 'backup_restored'):
        cycle = cycles.get(name, {})
        require(cycle.get('ok') is True and cycle.get('actualSdkReadbackMatches') is True,
                'target_official_consumer_evidence_missing')
        probes = [item for item in cycle.get('observations', []) if item.get('service') == 'google_models']
        # The unchanged consumer also verifies these probes before ok=true;
        # keep the whole safe public child receipt as the precise contract.
        require(len(probes) == 2 and all(item.get('tlsAuthorized') is True for item in probes) and
                {item.get('status') for item in probes} == {200, 403}, 'target_official_provider_probe_missing')
        control, authenticated = cycle.get('providerControl', {}), cycle.get('providerProbe', {})
        require(control.get('httpStatus') == 403 and control.get('tlsAuthorized') is True and
                authenticated.get('httpStatus') == 200 and authenticated.get('modelsArray') is True and
                authenticated.get('tlsAuthorized') is True, 'target_official_key_readback_proof_missing')
    return len(checks)


def prepare_scoped_report_candidate(base_path, root, spec, profile_id):
    """Change fixture policy only; preserve independently verified source proof."""
    require(spec['host'] == 'pocket4' and spec['plugin_version'] == '0.3.3' and
            spec['plugin_hashes']['index.js'] == '8e10c52df53d6d16d0e5890a6ccdaaff9515469e4419b46270b9bdc62b9be7af' and
            spec['plugin_hashes']['order-policy.js'] == 'a1a9923368a1a6bd9adf691aa1beba02d443cf511232e17118c9868160a96e82',
            'scoped_report_requires_exact_pocket_plugin')
    original_bytes, _ = read_file(base_path, private=True)
    original = json.loads(original_bytes)
    require(original['profile']['data']['profileId'] == profile_id and
            original['profile']['data']['digest'] == CREDENTIAL_SHA,
            'scoped_report_profile_binding_mismatch')
    require(original['order_policy'] == {'path': 'order-policy', 'data': {
                'schemaVersion': 1, 'generation': 1, 'providers': {}}, 'cas': 0},
            'scoped_report_requires_original_empty_fixture_policy')
    require(original['constraints'] == {'leader': False, 'publishNew': False,
                'manageOrder': False, 'schedulerMode': 'shadow'},
            'scoped_report_fixture_constraints_changed')
    value = json.loads(original_bytes)
    value['order_policy']['data']['providers'] = {
        'google': {'candidates': [], 'activeProfile': None, 'enforceManagedOrder': False,
                   'scheduler': {'schemaVersion': 2, 'enabled': True,
                       'strategy': 'strict-lease-v1', 'mode': 'shadow',
                       'scopes': [{'hostId': FIXTURE_HOST, 'agentIds': ['main'],
                                   'model': 'authbus-isolated-metadata-canary',
                                   'resources': [{'profileId': profile_id, 'maxAssignments': 1}],
                                   'enforceLastGood': False}]}}}
    # Check the exact structural delta before creating any private derivative.
    unchanged = json.loads(canonical(value))
    unchanged['order_policy']['data']['providers'] = {}
    require(unchanged == original, 'fixture_candidate_changed_outside_order_policy')
    destination = root / 'scoped-report-candidate.private.json'
    write_private(destination, value)
    require(file_sha(base_path) == hashlib.sha256(original_bytes).hexdigest(),
            'original_source_candidate_changed_during_derivation')
    public = {
        'schema': 'authbus-isolated-scoped-report-candidate-v1',
        'reason': 'original_authbus_0_3_3_reports_enabled_scheduler_resources_only',
        'base_candidate_path': str(base_path),
        'base_candidate_sha256': hashlib.sha256(original_bytes).hexdigest(),
        'candidate_path': str(destination), 'candidate_sha256': file_sha(destination),
        'candidate_mode': '0o600', 'changed_path': 'order_policy.data.providers',
        'order_policy_sha256': digest(value['order_policy']['data']),
        'order_policy': value['order_policy']['data'],
        'source_proof_preserved': True, 'source_credential_preserved': True,
        'original_candidate_preserved': True, 'plugin_version': spec['plugin_version'],
        'plugin_index_sha256': spec['plugin_hashes']['index.js'],
        'plugin_order_policy_sha256': spec['plugin_hashes']['order-policy.js'],
        'r9_driver_sha256': FILES['qa/openbao-acceptance/native_v6_openclaw_authbus_live.py'],
        'r9_consumer_sha256': FILES['qa/openbao-acceptance/native_v6_openclaw_authbus_consumer.mjs'],
        'r1_controller_sha256': BASE_CONTROLLER_SHA,
        'scheduler_mode': 'shadow', 'enforced_assignments': False,
        'production_plugin_changed': False, 'production_cutover': False,
        'production_coordinator_replacement': False,
    }
    write_private(root / 'scoped-report-candidate-public.json', public)
    return destination, public


def execute_worker(spec, report, secrets):
    root = Path(spec['root'])
    directory(root)
    install = read_json(root / 'install-public-receipt.json')
    require(install.get('ok') is True and install.get('host') == spec['host'] and
            install.get('controller_sha256') == file_sha(Path(__file__)) and
            install.get('source_manifest_sha256') == MANIFEST_SHA, 'successful_target_preflight_required')
    for relative, expected in FILES.items():
        require(file_sha(root / 'source' / relative) == expected, 'target_qa_changed_after_preflight')
    report['original_files_before_transfer'] = verify_target_files(spec)
    payload = sys.stdin.buffer.read(65537)
    require(len(payload) <= 65536, 'private_transfer_exceeds_bound')
    transfer = json.loads(payload)
    require(set(transfer) == {'google_api_key', 'origin'}, 'private_transfer_fields_mismatch')
    key = transfer['google_api_key']
    require(isinstance(key, str) and re.fullmatch(r'[A-Za-z0-9_-]{8,512}', key), 'private_transfer_key_shape_invalid')
    secrets.append(key)
    require(digest({'type': 'api_key', 'provider': 'google', 'key': key}) == CREDENTIAL_SHA, 'transferred_credential_fingerprint_changed')
    origin = transfer['origin']
    require(origin.get('candidate_path') == str(MAIN_CANDIDATE) and origin.get('candidate_sha256') == MAIN_CANDIDATE_SHA and
            origin.get('source_path') == str(MAIN_SOURCE) and origin.get('credential_digest') == CREDENTIAL_SHA and
            origin.get('source_mode') == '0o600' and origin.get('candidate_mode') == '0o600', 'source_transfer_provenance_mismatch')
    report['phase'] = 'source_transfer'
    env_path = root / 'source.env'
    env_bytes = ('GOOGLE_API_KEY=' + key + '\n').encode()
    write_private(env_path, env_bytes)
    env_sha = hashlib.sha256(env_bytes).hexdigest()
    provenance = {'schema': 'authbus-authorized-source-transfer-v1', 'created_at': now(),
                  'source_host': 'main', 'origin': origin, 'destination_host': spec['host'],
                  'destination_source_path': str(env_path), 'destination_source_sha256': env_sha,
                  'transport': 'SSH_private_stdin_BatchMode_StrictHostKeyChecking', 'fields_transferred': ['GOOGLE_API_KEY'],
                  'purpose': 'authorized_isolated_physical_host_credential_canary',
                  'credential_digest': CREDENTIAL_SHA, 'production_cutover': False,
                  'j3160_contacted': False, 'target_official_verification_required': True}
    no_secrets(canonical(provenance), secrets)
    write_private(root / 'source-transfer-public.json', provenance)
    report.update(source_transfer=provenance, source_key_received=True)
    source = root / 'source'
    profile_id = 'google:authbus-source-' + spec['host']
    report['phase'] = 'target_official_source_validation'
    prepared = run_child(['/usr/bin/python3', str(source / 'qa/openbao-acceptance/authbus_google_source_prepare.py'),
                          '--env-file', str(env_path), '--env-key', 'GOOGLE_API_KEY', '--work-dir', str(root / 'source-proof'),
                          '--provider', 'google', '--profile-id', profile_id, '--expected-source-sha256', env_sha],
                         root, 'source-prepare', 90, env=clean_environment(spec))
    report['source_prepare_exit_code'] = prepared['exit_code']
    report['source_prepare_timed_out'] = prepared['timed_out']
    require(prepared['exit_code'] == 0 and not prepared['timed_out'], 'target_official_source_validation_failed')
    candidate = root / 'source-proof/candidate.private.json'
    target_key, candidate_public = validate_candidate(candidate, source, env_path, profile_id)
    require(hmac.compare_digest(target_key, key), 'target_candidate_key_mismatch')
    report['target_source'] = candidate_public
    report['target_source_public_receipt'] = str(root / 'source-proof/public-receipt.json')
    candidate, fixture_public = prepare_scoped_report_candidate(candidate, root, spec, profile_id)
    fixture_key, fixture_candidate_public = validate_candidate(candidate, source, env_path, profile_id)
    require(hmac.compare_digest(fixture_key, key), 'fixture_candidate_key_mismatch')
    report['fixture_policy_derivation'] = fixture_public
    report['fixture_candidate'] = fixture_candidate_public
    report['phase'] = 'target_r9_actual_plugin_and_sdk'
    child = run_child(['/usr/bin/python3', str(source / 'qa/openbao-acceptance/native_v6_openclaw_authbus_live.py'),
                       '--binary', spec['binary'], '--candidate', str(candidate), '--work-dir', str(root / 'canary'),
                       '--plugin-root', spec['plugin'], '--openclaw-root', spec['sdk'], '--node', spec['node']],
                      root, 'actual-openclaw-r9', 480, env=clean_environment(spec))
    report.update(canary_exit_code=child['exit_code'], canary_timed_out=child['timed_out'],
                  canary_public_receipt=str(root / 'canary/public-receipt.json'))
    secrets.extend(private_secrets(root / 'canary', key))
    receipt_path = root / 'canary/public-receipt.json'
    if receipt_path.exists():
        public_bytes, _ = read_file(receipt_path, private=True)
        no_secrets(public_bytes, secrets)
        receipt = json.loads(public_bytes)
        report['canary_checks'] = len(receipt.get('checks', []))
        report['canary_failed_checks'] = [item['case'] for item in receipt.get('checks', []) if item.get('passed') is not True]
        report['canary_report_ok'] = receipt.get('ok') is True
    else:
        receipt = {}
    for process in (prepared, child):
        for field in ('stdout_path', 'stderr_path'):
            data, _ = read_file(Path(process[field]), maximum=4 * 1024 * 1024, private=True)
            no_secrets(data, secrets)
    require(child['exit_code'] == 0 and not child['timed_out'], 'target_r9_process_failed')
    report['canary_checks'] = validate_canary(receipt, spec)
    require(receipt.get('source_candidate_sha256') == fixture_candidate_public['candidate_sha256'],
            'r9_did_not_consume_exact_derived_candidate')
    require(file_sha(root / 'source-proof/candidate.private.json') == candidate_public['candidate_sha256'],
            'original_target_candidate_changed_after_canary')
    report['original_files_after'] = verify_target_files(spec)
    require(file_sha(env_path) == env_sha, 'target_source_changed_after_canary')
    report.update(ok=True, phase='completed', diagnostics_secret_scan_passed=True,
                  local_server_stopped_by_original_handle=True, source_proof_is_target_local=True,
                  production_coordinator_replacement=False, production_cutover=False,
                  all_legacy_profiles_migrated=False, next_step_requires_per_client_production_plan=True)


def worker(args):
    spec = target(args.host, args.attempt)
    root = Path(spec['root'])
    report = {'schema': 'authbus-physical-host-credential-canary-v1', 'ok': False,
              'host': args.host, 'attempt': args.attempt, 'created_at': now(), 'work_root': str(root),
              'phase': 'preflight' if args.command == '_install' else 'preflight_receipt_check',
              'production_cutover': False, 'production_coordinator_replacement': False,
              'j3160_contacted': False, 'inference_called': False, 'oauth_refreshed': False}
    receipt_path = root / ('install-public-receipt.json' if args.command == '_install' else 'fleet-public-receipt.json')
    report['public_receipt_path'] = str(receipt_path)
    secrets = []
    try:
        if args.command == '_install':
            install_worker(spec, report)
        else:
            execute_worker(spec, report, secrets)
    except Failure as exc:
        report['error'] = str(exc)
    except BaseException as exc:
        report['error'] = 'unexpected_' + type(exc).__name__
    try:
        no_secrets(canonical(report), secrets)
        write_private(receipt_path, report)
    except BaseException as exc:
        report = {'schema': 'authbus-physical-host-credential-canary-v1', 'ok': False,
                  'host': args.host, 'attempt': args.attempt, 'phase': 'public_receipt_persistence',
                  'error': str(exc) if isinstance(exc, Failure) else type(exc).__name__,
                  'production_cutover': False, 'j3160_contacted': False}
    # Return only public, already secret-scanned metadata; full R9 evidence is
    # left on the target at its public receipt path.
    print(json.dumps(report, sort_keys=True))
    return 0 if report['ok'] else 1


def ssh_result(root, spec, phase, command, payload, timeout, secrets):
    result = run_child(['/usr/bin/ssh'] + SSH_OPTIONS + [spec['host'], shlex.join(command)],
                       root, spec['host'] + '-' + phase, timeout, env=clean_environment(), payload=payload)
    for name in ('stdout_path', 'stderr_path'):
        data, _ = read_file(Path(result[name]), maximum=MAX_PACKET, private=True)
        no_secrets(data, secrets)
    if result['timed_out']:
        raise Failure('ssh_reply_timeout_target_outcome_unknown_no_retry')
    stdout, _ = read_file(Path(result['stdout_path']), maximum=MAX_PACKET, private=True)
    try:
        value = json.loads(stdout)
    except (ValueError, UnicodeDecodeError):
        raise Failure('ssh_reply_not_public_json_target_outcome_unknown_no_retry') from None
    require(isinstance(value, dict), 'ssh_reply_schema_invalid')
    value['ssh_exit_code'] = result['exit_code']
    if value.get('ok') is True:
        require(result['exit_code'] == 0 and value.get('host') == spec['host'] and
                value.get('attempt') == spec['attempt'], 'ssh_success_binding_mismatch')
    return value


def controller(args):
    root = args.work_dir
    report = {'schema': 'authbus-physical-fleet-credential-canary-v1', 'ok': False,
              'created_at': now(), 'controller_host': 'main', 'attempt': args.attempt,
              'controller_variant': 'pocket4-original-033-scoped-report-r2',
              'r1_controller_sha256': BASE_CONTROLLER_SHA,
              'production_cutover': False, 'production_coordinator_replacement': False,
              'all_legacy_profiles_migrated': False, 'j3160_contacted': False, 'hosts': []}
    secrets = []
    try:
        require(str(Path.home()) == str(MAIN_HOME) and platform.system() == 'Linux', 'controller_must_run_on_main_owner_host')
        require(root.is_absolute() and root.parent == MAIN_ROOT and not root.is_symlink(), 'controller_work_root_must_be_new_main_child')
        directory(root, new=True)
        packet = build_packet()
        key, origin = validate_candidate(MAIN_CANDIDATE, SOURCE_ROOT, MAIN_SOURCE, MAIN_PROFILE, MAIN_CANDIDATE_SHA)
        secrets.append(key)
        report.update(source_origin=origin, source_manifest_sha256=MANIFEST_SHA,
                      source_commit=SOURCE_COMMIT, source_tree=SOURCE_TREE,
                      controller_sha256=packet['controller_sha256'])
        write_private(root / 'controller-source-public.json', {
            'source_origin': origin, 'source_manifest_sha256': MANIFEST_SHA,
            'controller_sha256': packet['controller_sha256'], 'qa_files': FILES,
            'authorized_hosts': args.hosts, 'production_cutover': False})
        code_packet = canonical(packet)
        require(len(code_packet) <= MAX_PACKET, 'code_packet_exceeds_bound')
        for host in args.hosts:
            spec = target(host, args.attempt)
            entry = {'host': host, 'work_root': spec['root'], 'ok': False, 'phase': 'code_install_and_preflight'}
            report['hosts'].append(entry)
            try:
                install = ssh_result(root, spec, 'install',
                    ['/usr/bin/python3', '-c', BOOTSTRAP, spec['root'], packet['controller_sha256'], host, args.attempt],
                    code_packet, 120, secrets)
                entry['preflight'] = install
                require(install.get('ok') is True, 'target_preflight_failed_before_key_transfer')
                entry['phase'] = 'private_source_transfer_and_actual_canary'
                # Recheck the original source immediately before each transfer.
                # Nothing except the selected key and public provenance crosses.
                fresh_key, fresh_origin = validate_candidate(MAIN_CANDIDATE, SOURCE_ROOT, MAIN_SOURCE, MAIN_PROFILE, MAIN_CANDIDATE_SHA)
                require(hmac.compare_digest(key, fresh_key) and fresh_origin == origin, 'main_source_changed_between_hosts')
                value = ssh_result(root, spec, 'canary',
                    ['/usr/bin/python3', str(Path(spec['root']) / 'fleet-controller.py'), '_run', '--host', host, '--attempt', args.attempt],
                    canonical({'google_api_key': key, 'origin': origin}), 630, secrets)
                entry.update(result=value, ok=value.get('ok') is True, phase=value.get('phase', 'target_result'))
            except Interrupted:
                entry['error'] = 'controller_interrupted_target_outcome_unknown_no_retry'
                raise
            except Failure as exc:
                entry['error'] = str(exc)
            except BaseException as exc:
                entry['error'] = 'unexpected_' + type(exc).__name__
            no_secrets(canonical(entry), secrets)
            write_private(root / (host + '-public-result.json'), entry)
        report['ok'] = len(report['hosts']) == len(args.hosts) and all(row['ok'] for row in report['hosts'])
    except Failure as exc:
        report['error'] = str(exc)
    except BaseException as exc:
        report['error'] = 'unexpected_' + type(exc).__name__
    public_path = root / 'public-receipt.json'
    try:
        no_secrets(canonical(report), secrets)
        directory(root)
        write_private(public_path, report)
    except BaseException as exc:
        report['ok'] = False
        report['receipt_error'] = str(exc) if isinstance(exc, Failure) else type(exc).__name__
    summary = {'schema': report['schema'], 'ok': report['ok'], 'public_receipt_path': str(public_path),
               'production_cutover': False, 'j3160_contacted': False,
               'hosts': [{'host': row['host'], 'ok': row['ok'], 'phase': row['phase'],
                          'checks': row.get('result', {}).get('canary_checks'),
                          'public_receipt_path': row.get('result', {}).get('public_receipt_path'),
                          'error': row.get('error') or row.get('result', {}).get('error')}
                         for row in report['hosts']]}
    if 'error' in report:
        summary['error'] = report['error']
    if 'receipt_error' in report:
        summary['receipt_error'] = report['receipt_error']
    no_secrets(canonical(summary), secrets)
    print(json.dumps(summary, sort_keys=True))
    return 0 if report['ok'] else 1


def main():
    os.umask(0o077)
    sys.dont_write_bytecode = True
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    control = sub.add_parser('run')
    control.add_argument('--attempt', default='r2')
    control.add_argument('--hosts', nargs='+', choices=['pocket4'], default=['pocket4'])
    control.add_argument('--work-dir', type=Path, default=MAIN_ROOT / 'authbus-fleet-controller-r2')
    for name in ('_install', '_run'):
        worker_parser = sub.add_parser(name)
        worker_parser.add_argument('--host', required=True, choices=['pocket4'])
        worker_parser.add_argument('--attempt', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'r[1-9][0-9]{0,3}', args.attempt):
        parser.error('attempt must have the form r1 through r9999')
    if args.command == 'run':
        if len(args.hosts) != len(set(args.hosts)):
            parser.error('duplicate hosts are not allowed')
        return controller(args)
    return worker(args)


if __name__ == '__main__':
    sys.exit(main())
