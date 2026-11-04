#!/usr/bin/env python3
"""Real Mac installed-plugin consumption of one provider-validated native account.

All newly issued AppRoles, KV documents, SDK stores and relay output live under
one newly created private directory. The existing account identity is preserved.
The production config, databases, relay, VPN and refresh owners are not modified.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
import traceback

CORE_COMMIT = 'c138ff874af70eb96cd369cb21fd37caea190f42'
CORE_TREE = '34719a51ad942d3bc839df3d78524e9cf4326f30'
PLUGIN_FILES = ('index.js', 'bad-refresh-quarantine.js', 'codex-client-recycler.js',
                'lease-assignments.js', 'order-policy.js', 'provider-error-classifier.js',
                'runtime-refresh-policy.js', 'package.json')
SDK_FILES = ('package.json', 'dist/plugin-sdk/agent-runtime.js', 'dist/store-DH33UrUj.js',
             'dist/source-check-ZSz5NzGW.js', 'dist/oauth-B4aOCsid.js',
             'dist/order-CeBlX0NH.js', 'dist/model-auth-CJEm9SNp.js', 'dist/sqlite-wal-Bhk2Ro-u.js')


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def digest(value):
    return sha(encoded(value))


def read_private(path, maximum=2 * 1024 * 1024):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
             info.st_nlink == 1 and not stat.S_IMODE(info.st_mode) & 0o077 and info.st_size <= maximum,
             'private_input_custody')
        raw = os.read(fd, maximum + 1)
        after, current = os.fstat(fd), path.lstat()
        ident = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_uid, x.st_mode, x.st_mtime_ns, x.st_ctime_ns)
        need(ident(info) == ident(after) == ident(current) and len(raw) == info.st_size, 'private_input_changed')
        return raw
    finally:
        os.close(fd)


def put(path, value):
    data = value if isinstance(value, bytes) else encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def sandbox(root, ports):
    rules = ['(version 1)', '(deny default)', '(allow process*)', '(allow sysctl-read)',
             '(allow mach-lookup)', '(allow file-read*)',
             '(allow file-write* (subpath ' + json.dumps(str(root)) + '))',
             '(allow file-write* (literal "/dev/null"))']
    for port in ports:
        rules.append('(allow network-outbound (remote ip ' + json.dumps('localhost:' + str(port)) + '))')
    return ('\n'.join(rules) + '\n').encode()


def guard_observation():
    try:
        conn = http.client.HTTPConnection('127.0.0.1', 8819, timeout=3)
        try:
            conn.request('GET', '/healthz')
            response = conn.getresponse()
            value = json.loads(response.read(8192))
            return {'status': response.status, 'allowed': value.get('allowed') is True,
                    'reason': value.get('reason'), 'checkedAt': value.get('checkedAt')}
        finally:
            conn.close()
    except Exception as error:
        return {'status': None, 'allowed': False, 'errorClass': type(error).__name__}


def service_pids():
    result = {}
    for name in ('bridge', 'egressguard', 'proxy', 'front'):
        proc = subprocess.run(['/bin/launchctl', 'print', 'gui/' + str(os.geteuid()) + '/ai.openclaw.authbus-relay.' + name],
                              capture_output=True, timeout=5)
        match = re.search(rb'^\s*pid = (\d+)\s*$', proc.stdout, re.M)
        result[name] = int(match[1]) if match else None
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('work-dir', 'source', 'binary', 'build-result', 'native-source', 'native-proof', 'native-capture',
                 'live-state', 'sdk', 'live-plugin', 'bridge', 'usage-module'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--config-sha256', required=True)
    parser.add_argument('--node', default='/opt/homebrew/bin/node')
    parser.add_argument('--expected-commit', default=CORE_COMMIT)
    parser.add_argument('--expected-tree', default=CORE_TREE)
    parser.add_argument('--reuse-provider-root', type=Path,
                        help='Bind a prior actual default-selected provider proof to byte-identical current credential.')
    args = parser.parse_args()
    os.umask(0o077)
    root = args.work_dir
    root.mkdir(mode=0o700)
    (root / 'tmp').mkdir(mode=0o700)
    report = {'schema': 'heptabao.actual-profile2-selector-consumer.v1', 'ok': False,
              'startedUnixMs': int(time.time() * 1000), 'checks': [], 'productionChanged': False,
              'productionTrafficCutover': False, 'allAccountsQualified': False,
              'j3160Contacted': False, 'providerRefreshAttempted': False, 'modelCalled': False,
              'credentialValuesPublished': False, 'accountIdentitiesPublished': False,
              'sourceCommit': args.expected_commit, 'sourceTree': args.expected_tree, 'phases': [], 'bridgePhases': []}
    server = None
    secrets_seen = []
    diagnostics = []

    def check(code, value, **detail):
        report['checks'].append({'case': code, 'passed': bool(value), **detail})
        need(value, code)

    try:
        receipt_bytes = args.build_result.read_bytes()
        receipt = json.loads(receipt_bytes)
        check('normal_build_source_identity', receipt.get('source_commit') == args.expected_commit
              and receipt.get('source_tree') == args.expected_tree and receipt.get('build_exit_code') == 0
              and receipt.get('normal_default_candidate') is True and receipt.get('source_freeze_verified') is True)
        actual_commit = subprocess.check_output(['git', '-C', str(args.source), 'rev-parse', 'HEAD'], text=True).strip()
        actual_tree = subprocess.check_output(['git', '-C', str(args.source), 'rev-parse', 'HEAD^{tree}'], text=True).strip()
        check('helper_source_identity', actual_commit == args.expected_commit and actual_tree == args.expected_tree)
        check('helper_source_tracked_clean', subprocess.run(['git', '-C', str(args.source), 'diff', '--quiet']).returncode == 0
              and subprocess.run(['git', '-C', str(args.source), 'diff', '--cached', '--quiet']).returncode == 0)
        expected_binary = receipt['artifacts']['heptabao-server']['sha256']
        check('normal_binary_identity', file_sha(args.binary) == expected_binary)
        report.update(binarySha256=expected_binary, buildReceiptSha256=sha(receipt_bytes))
        proof_bytes = read_private(args.native_proof)
        proof = json.loads(proof_bytes)
        native_bytes = read_private(args.native_source)
        check('current_provider_verified_generation', proof.get('ok') is True
              and proof.get('singleCurrentNativeCredentialValidated') is True and proof.get('httpStatus') == 200
              and proof.get('tlsVerified') is True and proof.get('requestCount') == 1
              and sha(native_bytes) == proof.get('sourceSha256') == file_sha(args.native_capture))
        auth = json.loads(native_bytes)
        tokens = auth['tokens']
        claims = json.loads(base64.urlsafe_b64decode(tokens['access_token'].split('.')[1] + '==='))
        check('native_account_and_expiry', auth.get('auth_mode') == 'chatgpt'
              and claims['https://api.openai.com/auth']['chatgpt_account_id'] == tokens['account_id']
              and claims['exp'] > time.time() + 900)
        qa = args.source / 'qa/openbao-acceptance'
        spec = importlib.util.spec_from_file_location('profile2_stage_helper', qa / 'authbus_current_credential_stage.py')
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        captured = helper.capture(args.live_state, args.config_sha256)
        main_doc = next(doc for doc in captured if doc['agent'] == 'main')
        original_store = json.loads(main_doc['rows']['store'][0][1])
        profiles = original_store['profiles']
        selected = [pid for pid, cred in profiles.items() if cred.get('type') == 'oauth'
                    and cred.get('provider') == 'openai' and cred.get('accountId') == tokens['account_id']]
        check('unique_existing_native_account_match', len(selected) == 1)
        selected_id = selected[0]
        check('original_profile_two_identity', list(profiles).index(selected_id) == 1)
        credential = {**profiles[selected_id], 'access': tokens['access_token'], 'refresh': tokens['refresh_token'],
                      'expires': claims['exp'] * 1000, 'accountId': tokens['account_id'], 'idToken': tokens['id_token']}
        for cred in profiles.values():
            secrets_seen.extend(v for k, v in cred.items() if isinstance(v, str) and len(v) >= 8 and k not in ('provider', 'type', 'chatgptPlanType'))
        secrets_seen.extend(v for k, v in credential.items() if isinstance(v, str) and len(v) >= 8 and k not in ('provider', 'type', 'chatgptPlanType'))
        secrets_seen.extend(profiles)
        selected_digest = digest(credential)
        identity = digest({key: credential.get(key) for key in ('provider', 'type', 'email', 'accountId', 'projectId')})
        selector = sha(selected_id.encode())[:12]
        report.update(selectedProfileOrdinal=2, sourceNativeSha256=sha(native_bytes),
                      priorProviderProofSha256=sha(proof_bytes), selectedCredentialSha256=selected_digest,
                      selectedProfileSelectorSha256=sha(selector.encode()), sourceProfileCount=len(profiles))
        check('legacy_bridge_selector_absent', all(not sha(pid.encode()).startswith('a96c1647e34a') for pid in profiles))
        original_cfg = json.loads(args.live_state.joinpath('openclaw.json').read_bytes())
        model_string = original_cfg['agents']['defaults']['model']
        if isinstance(model_string, dict):
            model_string = model_string['primary']
        model_provider, model_id = model_string.split('/', 1)
        check('actual_current_default_model_provider', model_provider == 'openai')
        model = {'id': model_id, 'provider': model_provider, 'api': original_cfg['models']['providers']['openai']['api']}
        report['actualDefaultModel'] = model_string
        live_pids = service_pids()
        plugin = root / 'installed-plugin-copy'
        plugin.mkdir(mode=0o700)
        source_pins = {}
        for name in PLUGIN_FILES:
            data = (args.live_plugin / name).read_bytes()
            put(plugin / name, data)
            source_pins[str(args.live_plugin / name)] = sha(data)
            source_pins[str(plugin / name)] = sha(data)
        (plugin / 'node_modules').mkdir(mode=0o700)
        (plugin / 'node_modules/openclaw').symlink_to(args.sdk)
        for name in SDK_FILES:
            source_pins[str(args.sdk / name)] = file_sha(args.sdk / name)
        for name in ('authbus_profile2_consumer.mjs', 'authbus_selected_usage.mjs'):
            source_pins[str(Path(__file__).with_name(name))] = file_sha(Path(__file__).with_name(name))
        source_pins[str(Path(__file__))] = file_sha(Path(__file__))
        source_pins[str(args.bridge)] = file_sha(args.bridge)
        report['sourcePins'] = source_pins
        sys.path.insert(0, str(qa))
        from native_v6_authbus_client_live import smoke
        from cert_auth_live import cert_sha256
        server = smoke.Instance(args.binary, root / 'server')
        server_config = json.loads((server.root / 'server.json').read_bytes())
        server_config['storage'] = {'native_v6_file': {'path': server_config['data_dir']}}
        (server.root / 'server.json').write_bytes(encoded(server_config))
        server.start()

        def call(name, method, route, body=None, token=None, expected=200):
            status, data = server.call(method, route, body, token=token)
            check(name, status == expected, status=status)
            return data

        init = call('initialize', 'POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1}, token='')
        server.token, unseal = init['root_token'], init['keys_base64'][0]
        secrets_seen.extend((server.token, unseal))
        put(root / 'recovery.private.json', {'rootToken': server.token, 'unsealKey': unseal})
        call('unseal', 'POST', 'sys/unseal', {'key': unseal}, token='')
        call('kv2_mount', 'POST', 'sys/mounts/openclaw-auth', {'type': 'kv', 'options': {'version': '2'}}, expected=204)
        call('approle_mount', 'POST', 'sys/auth/approle', {'type': 'approle'}, expected=204)
        call('formal_activation', 'POST', 'sys/storage/native-v6/activate', {}, expected=204)
        check('formal_format2', call('capacity', 'GET', 'sys/internal/capacity')['data']['native_kv2_reader_format'] == 2)
        profile_key = 'sha256-' + selected_digest
        payload = {'schemaVersion': 1, 'profileId': selected_id, 'credential': credential, 'digest': selected_digest, 'identity': identity}
        entry = {key: value for key, value in payload.items() if key not in ('credential', 'schemaVersion')}
        entry.update(key=profile_key, provider=credential['provider'], type=credential['type'], expires=credential['expires'], quarantined=False, status='active')
        manifest = {'schemaVersion': 1, 'generation': 1, 'profiles': [entry]}
        empty_order = {'schemaVersion': 1, 'generation': 1, 'providers': {}}
        empty_assignments = {'schemaVersion': 1, 'generation': 1, 'assignments': []}
        for name, data in [('profiles/' + profile_key, payload), ('order-policy', empty_order),
                           ('scheduler-assignments', empty_assignments), ('manifest', manifest)]:
            call('publish.' + name.split('/')[0], 'POST', 'openclaw-auth/data/' + name, {'data': data, 'options': {'cas': 0}})
        common_policy = '\n'.join('path "openclaw-auth/data/' + name + '" { capabilities=["read"] }'
                                   for name in ('manifest', 'order-policy', 'scheduler-assignments', 'profiles/' + profile_key))
        policies = {'bridge': common_policy,
                    'consumer': common_policy + '\npath "openclaw-auth/data/inbox/profile2-canary/*" { capabilities=["create","update"] }\n'
                    + '\n'.join('path "auth/token/' + name + '" { capabilities=["' + verb + '"] }'
                                for name, verb in [('lookup-self', 'read'), ('renew-self', 'update'), ('revoke-self', 'update')])}
        plugin_configs = {}
        for name, policy in policies.items():
            role_name = 'profile2-' + name
            call(name + '.policy', 'PUT', 'sys/policies/acl/' + role_name, {'policy': policy}, expected=204)
            route = 'auth/approle/role/' + role_name
            call(name + '.role', 'POST', route, {'token_policies': [role_name], 'token_ttl': '180s', 'token_max_ttl': '600s',
                                               'secret_id_ttl': '1200s', 'secret_id_num_uses': 0}, expected=204)
            role = call(name + '.role_id', 'GET', route + '/role-id')['data']['role_id']
            secret = call(name + '.secret_id', 'POST', route + '/secret-id', {})['data']['secret_id']
            secrets_seen.extend((role, secret))
            directory = root / ('credentials-' + name)
            directory.mkdir(mode=0o700)
            put(directory / 'role_id', role.encode()); put(directory / 'secret_id', secret.encode())
            put(directory / 'ca.crt', (server.root / 'ca.crt').read_bytes())
            plugin_configs[name] = {'address': server.address, 'caFile': str(directory / 'ca.crt'),
                                    'roleIdFile': str(directory / 'role_id'), 'secretIdFile': str(directory / 'secret_id'),
                                    'hostId': 'profile2-canary', 'leader': False, 'publishNew': False, 'manageOrder': True,
                                    'schedulerMode': 'shadow', 'pollIntervalMs': 300000, 'maxRefreshesPerCycle': 1}
        port = int(server.address.rsplit(':', 1)[1])
        put(root / 'consumer.sb', sandbox(root, [port]))
        put(root / 'bridge.sb', sandbox(root, [port, 8819]))
        env = {'PATH': '/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'TMPDIR': str(root / 'tmp'),
               'HOME': os.environ['HOME']}
        report['guardBefore'] = guard_observation()

        def bridge_phase(name, selector_arg):
            work = root / ('bridge-' + name)
            work.mkdir(mode=0o700)
            (work / 'auth-dir').mkdir(mode=0o700)
            internal_key = secrets.token_hex(32)
            secrets_seen.append(internal_key)
            put(work / 'internal.key', internal_key.encode())
            put(work / 'openclaw.json', {'plugins': {'entries': {'openclaw-authbus': {'config': plugin_configs['bridge']}}}})
            quarantine = args.live_state / 'authbus/bad-refresh-quarantine.json'
            if quarantine.exists():
                put(work / 'quarantine.json', read_private(quarantine))
            argv = ['/usr/bin/sandbox-exec', '-f', str(root / 'bridge.sb'), str(args.bridge), '-once',
                    '-openclaw-config', str(work / 'openclaw.json'), '-quarantine-file', str(work / 'quarantine.json'),
                    '-internal-key-file', str(work / 'internal.key'), '-auth-dir', str(work / 'auth-dir'),
                    '-state-output', str(work / 'state.json'), '-config-output', str(work / 'config.yaml')]
            if selector_arg is not None:
                argv += ['-selector', selector_arg]
            proc = subprocess.run(argv, env=env, capture_output=True, timeout=35)
            put(work / 'stdout.private', proc.stdout); put(work / 'stderr.private', proc.stderr)
            diagnostics.extend((proc.stdout, proc.stderr))
            state_file = work / 'state.json'
            if state_file.exists():
                state = json.loads(read_private(state_file))
            else:
                need(proc.stderr.strip() == b'authbus-relay-bridge: unsafe runtime options',
                     'unexpected_bridge_startup_failure')
                state = {'ready': False, 'reason': 'runtime_options_refused'}
            result = {'phase': name, 'exitCode': proc.returncode, 'ready': state.get('ready'), 'reason': state.get('reason'),
                      'credentialDigestMatches': state.get('credentialDigest') == selected_digest,
                      'stateFileWritten': state_file.exists(), 'stderrSha256': sha(proc.stderr)}
            report['bridgePhases'].append(result)
            return result

        old_bridge = bridge_phase('legacy-default', None)
        check('legacy_selector_rejected_by_actual_bridge', old_bridge['ready'] is False)
        new_bridge = bridge_phase('exact-owned-profile2', selector)
        report['actualBridgeSelectorMatched'] = new_bridge['reason'] in ('ready', 'credential_rejected')
        report['actualBridgeProviderReady'] = new_bridge['ready'] is True
        # Provider egress health is an independent production dependency. The
        # consumer below uses the application's already configured native route.
        report['guardAfter'] = guard_observation()
        managed_order = {'schemaVersion': 1, 'generation': 2, 'providers': {'openai': {
            'candidates': [{'profileId': selected_id, 'digest': selected_digest, 'enrolledAt': int(time.time() * 1000)}],
            'activeProfile': selected_id, 'enforceManagedOrder': True}}}
        call('publish.managed_order', 'POST', 'openclaw-auth/data/order-policy', {'data': managed_order, 'options': {'cas': 1}})
        plans = {}

        def consumer_phase(name):
            work = root / ('consumer-' + name)
            work.mkdir(mode=0o700)
            state = work / 'state'
            helper.materialize(state, [copy.deepcopy(main_doc)])
            cfg = {'agents': {'defaults': {'model': original_cfg['agents']['defaults']['model']},
                              'list': [{'id': 'main', 'agentDir': str(state / 'agents/main/agent')}]},
                   'auth': copy.deepcopy(original_cfg.get('auth', {})),
                   'models': {'providers': {'openai': copy.deepcopy(original_cfg['models']['providers']['openai'])}}}
            (state / 'openclaw.json').write_bytes(encoded(cfg))
            (state / 'home').mkdir(mode=0o700)
            plan = {'mode': 'initial', 'workRoot': str(root), 'stateRoot': str(state), 'sdkRoot': str(args.sdk),
                    'pluginEntry': str(plugin / 'index.js'), 'pluginConfig': plugin_configs['consumer'],
                    'expectedProfileId': selected_id, 'expectedAccountId': tokens['account_id'],
                    'expectedCredentialSha256': selected_digest, 'expectedProfileKey': profile_key,
                    'serverCertificateSha256': cert_sha256(server.root / 'tls.crt'), 'model': model,
                    'sourcePins': source_pins, 'selectionOutput': str(work / 'runtime-selection.private.json'),
                    'baselineOutput': str(work / 'baseline-store.private.json'), 'custodyOutput': str(work / 'auth.private.json')}
            put(work / 'plan.private.json', plan)
            child_env = {**env, 'OPENCLAW_STATE_DIR': str(state), 'OPENCLAW_CONFIG_PATH': str(state / 'openclaw.json'),
                         'OPENCLAW_OAUTH_DIR': str(state / 'oauth'), 'OPENCLAW_HOME': str(state / 'home')}
            proc = subprocess.run(['/usr/bin/sandbox-exec', '-f', str(root / 'consumer.sb'), args.node,
                                   str(Path(__file__).with_name('authbus_profile2_consumer.mjs')), str(work / 'plan.private.json')],
                                  env=child_env, capture_output=True, timeout=70)
            put(work / 'stdout.private', proc.stdout); put(work / 'stderr.private', proc.stderr)
            diagnostics.extend((proc.stdout, proc.stderr))
            result = json.loads(proc.stdout)
            put(work / 'result.public.json', result)
            report['phases'].append({'phase': name, 'resultSha256': file_sha(work / 'result.public.json'), **result})
            check('consumer.' + name, proc.returncode == 0 and result.get('ok') is True)
            plans[name] = (work, plan, child_env)
            return work

        first = consumer_phase('initial')
        access_tokens = json.loads(read_private(first / 'auth.private.json'))['tokens']
        check('consumer.real_approle_token_captured', len(access_tokens) == 1)
        current_token = access_tokens[0]; secrets_seen.append(current_token)
        call('consumer.denied_unassigned_profile', 'GET', 'openclaw-auth/data/profiles/unassigned', token=current_token, expected=403)
        call('consumer.renew_self', 'POST', 'auth/token/renew-self', {}, token=current_token)
        call('consumer.revoke_self', 'POST', 'auth/token/revoke-self', {}, token=current_token, expected=204)
        call('consumer.revoked_token_rejected', 'GET', 'openclaw-auth/data/manifest', token=current_token, expected=403)
        usage_receipt = root / 'selected-account-provider-read.public.json'
        usage_sha = file_sha(args.usage_module)
        check('original_usage_module_pin', usage_sha == proof['sdkUsageModuleSha256'])
        # The payload comes from the installed default resolver after its live
        # AuthBus import, not from the source credential or a requested profileId.
        put(root / 'provider-read-intent.public.json', {'schema': 'heptabao.selected-account-read-intent.v1',
            'inputSha256': file_sha(first / 'runtime-selection.private.json'),
            'operation': 'link_prior_provider_proof' if args.reuse_provider_root else 'single_provider_read',
            'requestLimit': 0 if args.reuse_provider_root else 1,
            'method': 'GET', 'endpoint': 'https://chatgpt.com/backend-api/wham/usage', 'refresh': False,
            'source': 'installed_default_resolver_after_authbus', 'productionChanged': False})
        if args.reuse_provider_root:
            prior = args.reuse_provider_root
            usage_bytes = read_private(prior / 'selected-account-provider-read.public.json')
            usage = json.loads(usage_bytes)
            previous_selection_bytes = read_private(prior / 'consumer-initial/runtime-selection.private.json')
            previous_selection = json.loads(previous_selection_bytes)
            current_selection = json.loads(read_private(first / 'runtime-selection.private.json'))
            check('prior_actual_selected_provider_proof', usage.get('ok') is True and usage.get('httpStatus') == 200
                  and usage.get('tlsVerified') is True and usage.get('requestCount') == 1
                  and usage.get('sdkUsageModuleSha256') == usage_sha
                  and usage.get('selectionSha256') == sha(previous_selection_bytes)
                  and previous_selection.get('source') == current_selection.get('source')
                  == 'actual_installed_sdk_default_model_resolver_after_actual_authbus_cycle')
            check('prior_actual_selected_provider_exact_binding', all(previous_selection.get(key) == current_selection.get(key)
                  for key in ('profileId', 'credential', 'resolvedApiKey', 'credentialSha256', 'model')))
            report['providerValidationLink'] = {'reused': True, 'priorRoot': str(prior),
                'proofSha256': sha(usage_bytes), 'priorSelectionSha256': sha(previous_selection_bytes),
                'currentSelectionSha256': file_sha(first / 'runtime-selection.private.json'),
                'credentialAndResolvedAccessByteIdentical': True,
                'scope': 'Prior real provider success for the byte-identical actual default-selected credential; not a fresh provider connectivity test.'}
            put(root / 'linked-prior-provider-read.public.json', usage)
            report['providerReadPerformedThisRun'] = False
            provider_validated = True
        else:
            proc = subprocess.run([args.node, str(Path(__file__).with_name('authbus_selected_usage.mjs')),
                                   str(first / 'runtime-selection.private.json'), str(args.usage_module), usage_sha, str(usage_receipt)],
                                  env=env, capture_output=True, timeout=25)
            put(root / 'usage.stdout.private', proc.stdout); put(root / 'usage.stderr.private', proc.stderr)
            diagnostics.extend((proc.stdout, proc.stderr))
            usage = json.loads(read_private(usage_receipt))
            report['providerReadPerformedThisRun'] = True
            provider_validated = proc.returncode == 0 and usage.get('ok') is True
        report['priorActualDefaultSelectedProviderRead' if args.reuse_provider_root
               else 'actualDefaultSelectedProviderRead'] = usage
        original_process = server.process
        server.stop()
        check('actual_sigkill_and_wait', original_process.returncode == -9)
        server.start()
        call('cold_sealed', 'GET', 'sys/health', expected=503)
        call('cold_unseal', 'POST', 'sys/unseal', {'key': unseal}, token='')
        consumer_phase('cold-new-process')
        for name, (work, plan, child_env) in plans.items():
            rollback = {**plan, 'mode': 'rollback', 'custodyOutput': str(work / 'rollback-auth.private.json')}
            put(work / 'rollback-plan.private.json', rollback)
            proc = subprocess.run(['/usr/bin/sandbox-exec', '-f', str(root / 'consumer.sb'), args.node,
                                   str(Path(__file__).with_name('authbus_profile2_consumer.mjs')), str(work / 'rollback-plan.private.json')],
                                  env=child_env, capture_output=True, timeout=35)
            put(work / 'rollback.stdout.private', proc.stdout); put(work / 'rollback.stderr.private', proc.stderr)
            diagnostics.extend((proc.stdout, proc.stderr))
            result = json.loads(proc.stdout)
            put(work / 'rollback-result.public.json', result)
            report['phases'].append({'phase': name + '.rollback', **result})
            check('rollback.' + name, proc.returncode == 0 and result.get('ok') is True)
        after = helper.capture(args.live_state, args.config_sha256)
        check('original_live_auth_rows_unchanged', all(a['rows'] == b['rows'] for a, b in zip(captured, after)))
        check('native_source_unchanged', file_sha(args.native_source) == sha(native_bytes))
        check('all_installed_sources_unchanged', all(file_sha(Path(p)) == expected for p, expected in source_pins.items()))
        check('production_relay_pids_unchanged', service_pids() == live_pids)
        check('normal_binary_unchanged', file_sha(args.binary) == expected_binary)
        disk_files = [p for p in (server.root / 'data').rglob('*') if p.is_file()]
        literal_secrets = [credential[k].encode() for k in ('access', 'refresh')]
        check('formal_server_disk_no_provider_plaintext', bool(disk_files)
              and all(all(secret not in p.read_bytes() for secret in literal_secrets) for p in disk_files))
        diagnostics.extend([(server.root / 'server.log').read_bytes(), encoded(report)])
        check('diagnostics_no_credential_values', all(all(secret.encode() not in data for secret in secrets_seen) for data in diagnostics))
        report.update(actualInstalledPluginImportedCredential=True, actualInstalledDefaultResolverQualified=True,
                      singleCurrentAccountValidated=provider_validated and not args.reuse_provider_root,
                      freshProviderReadQualified=provider_validated if not args.reuse_provider_root else None,
                      priorProviderCredentialBindingQualified=provider_validated if args.reuse_provider_root else None,
                      actualServerColdRestartQualified=True,
                      privateLogicalStoreRollbackQualified=True,
                      productionGatewaySelectionQualified=False, productionRolloutQualified=False)
        if args.reuse_provider_root:
            report['qualificationScope'] = 'Formal V6 and installed consumer lifecycle only; prior provider proof is linked separately and does not certify current connectivity.'
            check('prior_selected_provider_credential_binding', provider_validated)
        else:
            report['qualificationScope'] = 'Formal V6 and installed consumer lifecycle with one fresh default-selected provider read; production gateway and rollout excluded.'
            check('actual_default_selected_provider_read', provider_validated)
        report['ok'] = True
    except Exception as error:
        report['error'] = str(error) if isinstance(error, Refused) else type(error).__name__
        report['errorClass'] = type(error).__name__
        report['errorFrames'] = [{'file': Path(f.filename).name, 'line': f.lineno}
                                 for f in traceback.extract_tb(error.__traceback__)[-5:]]
    finally:
        if server is not None and server.process is not None:
            original_process = server.process
            server.stop()
            report['ownedServerStopped'] = original_process.returncode is not None
        report['finishedUnixMs'] = int(time.time() * 1000)
        put(root / 'result.public.json', report)
    print(json.dumps({'ok': report['ok'], 'error': report.get('error'), 'checks': len(report['checks']),
                      'result': str(root / 'result.public.json')}))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
