#!/usr/bin/env python3
"""Real same-account HeptaBao sources through installed AuthBus and local native Codex.

Uses the actual installed SDK order established by authbus_multisource_order.
Carries observed quota state; kernel blocks native external egress, with attempts not assumed zero.
Every service, credential, database and changed order is private to the fresh run.
"""
from __future__ import annotations
import argparse, copy, importlib.util, json, os, signal, sqlite3, subprocess, sys, time, traceback
from pathlib import Path
from authbus_profile2_selector_live import (
    need, encoded, sha, digest, file_sha, read_private, put, sandbox,
    service_pids, PLUGIN_FILES, SDK_FILES, Refused,
)

BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013')
WORK = BASE / 'authbus-profile2-selector-c138-20261104-r1'
FINAL = BASE / 'continuation-20261104-blocker-closure-r1'
SOURCE = FINAL / 'source'
BINARY = FINAL / 'build-normal-r2/artifacts/heptabao-server'
BUILD = FINAL / 'build-normal-r2/result.public.json'
SDK = Path('/opt/homebrew/lib/node_modules/openclaw')
LIVE = Path('/Users/qianqi/.openclaw')
PLUGIN = LIVE / 'extensions/openclaw-authbus'
NATIVE = Path('/Users/qianqi/.codex/auth.json')
COMMIT = '36076db5f5afe00db75eba9b607dee7802dae554'
TREE = 'ae71c4b243afd4099db66e7d9882b3f28c777a95'
CODEX = LIVE / 'npm/projects/openclaw-codex-8902d781d4__openclaw-generation__g-49fd4dbfde2c5057/node_modules/@openclaw/codex'
RUNTIME_RECEIPTS = WORK / 'runtime-contract-source-r1'
NODE = Path('/opt/homebrew/bin/node')
NATIVE_HOME = LIVE / 'agents/main/agent/codex-home'




def native_home_baseline():
    result = {}
    for name in ('auth.json', 'config.toml', 'requirements.toml'):
        path = NATIVE_HOME / name
        result[name] = {'exists': path.exists(), 'sha256': file_sha(path) if path.is_file() else None}
    return result


def read_pinned_native_config(path, expected):
    import stat
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and before.st_size < 1024 * 1024, 'native_config_custody')
        data = os.read(fd, 1024 * 1024)
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
             and len(data) == before.st_size and sha(data) == expected, 'native_config_pin')
        return data
    finally: os.close(fd)


def capture_registry():
    connection = sqlite3.connect('file:' + str(LIVE / 'state/openclaw.sqlite') + '?mode=ro', uri=True)
    try:
        connection.execute('PRAGMA query_only=ON'); connection.execute('BEGIN')
        schema = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='installed_plugin_index'").fetchone()[0]
        cursor = connection.execute("SELECT * FROM installed_plugin_index WHERE index_key='installed-plugin-index'")
        columns = [c[0] for c in cursor.description]; rows = cursor.fetchall()
        need(len(rows) == 1, 'single_installed_registry_row')
        return {'schema': schema, 'columns': columns, 'row': rows[0]}
    finally:
        connection.rollback(); connection.close()


def restore_registry(state, captured):
    folder = state / 'state'; folder.mkdir(mode=0o700, exist_ok=True)
    connection = sqlite3.connect(str(folder / 'openclaw.sqlite'))
    try:
        connection.execute(captured['schema'])
        placeholders = ','.join('?' for _ in captured['columns'])
        connection.execute('INSERT INTO installed_plugin_index VALUES (' + placeholders + ')', captured['row'])
        connection.commit()
    finally: connection.close()


def parent_sandbox(root, port, source_pins):
    # macOS refuses nested sandbox_apply. One kernel policy is inherited by
    # Node, its installed launcher and the actual native process. They share
    # this fresh run and its exact Bao port; no per-native-file authority is
    # claimed. Everything else under BASE is excluded except exact QA/pin files.
    qa_paths = sorted(path for path in source_pins if Path(path).is_relative_to(BASE)
                      and not Path(path).is_relative_to(root))
    rules = ['(version 1)', '(deny default)', '(allow process*)', '(allow signal (target children))', '(allow sysctl-read)',
             '(allow mach-lookup)', '(allow file-read-metadata)',
             '(allow file-read* (require-not (subpath ' + json.dumps(str(BASE)) + ')))',
             '(allow file-read* (subpath ' + json.dumps(str(root)) + '))',
             '(allow file-write* (subpath ' + json.dumps(str(root)) + '))',
             '(allow file-write* (literal "/dev/null"))',
             '(allow network-outbound (remote ip ' + json.dumps('localhost:' + str(port)) + '))']
    if qa_paths:
        rules.append('(allow file-read* ' + ' '.join('(literal ' + json.dumps(path) + ')' for path in qa_paths) + ')')
    for path in (LIVE / 'agents', LIVE / 'state', LIVE / 'credentials', NATIVE.parent):
        rules.append('(deny file-read* (subpath ' + json.dumps(str(path)) + '))')
    rules.append('(deny file-read* (literal ' + json.dumps(str(LIVE / 'openclaw.json')) + '))')
    return ('\n'.join(rules) + '\n').encode()


def run_owned_capture(argv, env, cwd, timeout, stdout_path, stderr_path, native_observer=None):
    from authbus_native_login_custody import group_members
    from authbus_native_process_observer import OwnedNativeObserver, ObservationRefused
    lifecycle = {'exitCode': None, 'timeout': False, 'interrupted': False, 'primaryReaped': False,
                 'noGroupSurvivors': False, 'outcomeUnknown': False}
    observer = OwnedNativeObserver(native_observer) if native_observer else None
    child_env = dict(env)
    if observer:
        need(not any(k in child_env for k in observer.child_env), 'fresh_observer_pipe_environment')
        child_env.update(observer.child_env)
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        try:
            proc = subprocess.Popen(argv, env=child_env, cwd=str(cwd), start_new_session=True,
                stdout=stdout, stderr=stderr, close_fds=True,
                pass_fds=observer.child_fds if observer else ())
        except Exception:
            if observer: observer.close()
            raise
        pgid = proc.pid; lifecycle['ownedProcessGroup'] = pgid
        try:
            if observer: observer.parent_after_spawn(proc)
            deadline = time.monotonic() + timeout
            while True:
                if time.monotonic() >= deadline:
                    lifecycle['timeout'] = True
                    break
                if observer: observer.poll(deadline)
                returncode = proc.poll()
                if returncode is not None:
                    lifecycle['exitCode'] = returncode
                    break
                if time.monotonic() >= deadline:
                    lifecycle['timeout'] = True
                    break
                time.sleep(0.025)
        except KeyboardInterrupt: lifecycle['interrupted'] = True
        except Exception as observer_error:
            lifecycle['observationError'] = str(observer_error) if isinstance(observer_error, ObservationRefused) else type(observer_error).__name__
        finally:
            if observer:
                observer.close()
                lifecycle['nativeProcessObserver'] = observer.report
            previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                if group_members(pgid):
                    try: os.killpg(pgid, signal.SIGTERM)
                    except ProcessLookupError: pass
                    deadline = time.monotonic() + 1
                    while group_members(pgid) and time.monotonic() < deadline:
                        proc.poll(); time.sleep(0.05)
                    if group_members(pgid):
                        try: os.killpg(pgid, signal.SIGKILL)
                        except ProcessLookupError: pass
                proc.wait(timeout=5); lifecycle['primaryReaped'] = True
                lifecycle['finalReturnCode'] = proc.returncode
                deadline = time.monotonic() + 3
                remaining = group_members(pgid)
                while remaining and time.monotonic() < deadline:
                    time.sleep(0.05); remaining = group_members(pgid)
                lifecycle['remainingGroupMembers'] = remaining
                lifecycle['noGroupSurvivors'] = not remaining
                lifecycle['outcomeUnknown'] = lifecycle['timeout'] or lifecycle['interrupted'] or bool(remaining) or bool(lifecycle.get('observationError'))
            finally: signal.signal(signal.SIGINT, previous)
    return lifecycle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--prepared', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.work_dir
    root.mkdir(mode=0o700)
    (root / 'tmp').mkdir(mode=0o700)
    report = {'schema': 'heptabao.actual-two-source-installed-native-codex-consumer.v1', 'ok': False,
              'sourceCommit': COMMIT, 'sourceTree': TREE, 'checks': [], 'phases': [],
              'productionChanged': False, 'productionTrafficCutover': False,
              'allAccountsQualified': False, 'businessAvailabilityQualified': False,
              'externalNetworkEgressAllowed': False, 'providerResponseObtained': False,
              'nativeBackgroundNetworkAttemptCount': None, 'nativeBackgroundNetworkAttemptsNotMeasured': True,
              'explicitModelRpcDispatched': False,
              'j3160Contacted': False, 'credentialValuesPublished': False,
              'accountIdentitiesPublished': False, 'startedUnixMs': int(time.time() * 1000)}
    server = None
    sensitive = []
    diagnostics = []
    plans = {}
    captured = None
    native_sha = None
    agent_native_baseline = None
    registry_capture = None
    helper = None
    rolled_back = set()
    rollback_attempted = set()

    def check(code, value, **detail):
        report['checks'].append({'case': code, 'passed': bool(value), **detail})
        need(value, code)

    try:
        build_bytes = BUILD.read_bytes()
        build = json.loads(build_bytes)
        check('normal_build_source_identity', build.get('source_commit') == COMMIT
              and build.get('source_tree') == TREE and build.get('build_exit_code') == 0
              and build.get('normal_default_candidate') is True and build.get('source_freeze_verified') is True)
        check('source_identity', subprocess.check_output(['git', '-C', str(SOURCE), 'rev-parse', 'HEAD'], text=True).strip() == COMMIT
              and subprocess.check_output(['git', '-C', str(SOURCE), 'rev-parse', 'HEAD^{tree}'], text=True).strip() == TREE)
        check('source_tracked_clean', subprocess.run(['git', '-C', str(SOURCE), 'diff', '--quiet']).returncode == 0
              and subprocess.run(['git', '-C', str(SOURCE), 'diff', '--cached', '--quiet']).returncode == 0)
        binary_sha = build['artifacts']['heptabao-server']['sha256']
        check('normal_binary_identity', file_sha(BINARY) == binary_sha)
        prepared = json.loads(read_private(args.prepared / 'prepare.public.json'))
        ordered = json.loads(read_private(args.prepared / 'order.public.json'))
        check('prepared_current_sources_and_actual_sdk_order', prepared.get('ok') is True and ordered.get('ok') is True
              and prepared['sourceCommit'] == COMMIT and ordered['providerCalls'] == ordered['refreshCalls'] == 0)
        bundle = json.loads(read_private(args.prepared / 'source-bundle.private.json'))
        docs = json.loads(read_private(args.prepared / 'seed-documents.private.json'))
        binding = json.loads(read_private(args.prepared / 'order-binding.private.json'))
        check('frozen_private_source_bundle', file_sha(args.prepared / 'source-bundle.private.json') == prepared['sourceBundleSha256']
              and file_sha(args.prepared / 'seed-documents.private.json') == ordered['seedDocumentsSha256']
              and file_sha(args.prepared / 'order-binding.private.json') == ordered['orderBindingSha256'])
        check('two_exact_profiles_and_original_managed_order', len(docs['manifest']['profiles']) == 2
              and docs['order-policy']['providers']['openai']['candidates']
              and [v['profileId'] for v in docs['order-policy']['providers']['openai']['candidates']] == binding['projectedManagedOrder'])
        report.update(binarySha256=binary_sha, buildReceiptSha256=sha(build_bytes),
                      prepareReceiptSha256=file_sha(args.prepared / 'prepare.public.json'),
                      orderReceiptSha256=file_sha(args.prepared / 'order.public.json'),
                      sources=prepared['sources'], originalSdkOrderOrdinals=ordered['originalSdkOrderOrdinals'],
                      actualFinalOrderOrdinals=ordered['actualFinalOrderOrdinals'],
                      profile1QuotaState=prepared['profile1QuotaState'],
                      profile2QuotaClassification=prepared['profile2QuotaClassification'])
        qa = SOURCE / 'qa/openbao-acceptance'
        spec = importlib.util.spec_from_file_location('multi_stage', qa / 'authbus_current_credential_stage.py')
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        captured = helper.capture(LIVE, prepared['productionConfigSha256'])
        expected_rows = json.loads(read_private(args.prepared / 'captured-auth-rows.private.json'))
        check('production_rows_still_exact_prepared_source', all(a['rows'] == b['rows'] for a, b in zip(captured, expected_rows))
              and len(captured) == len(expected_rows))
        main_doc = next(d for d in captured if d['agent'] == 'main')
        original_cfg = json.loads(read_private(args.prepared / 'original-config.private.json'))
        native_sha = file_sha(NATIVE)
        pids = service_pids()
        agent_native_baseline = native_home_baseline()
        check('production_agent_native_auth_absent', not agent_native_baseline['auth.json']['exists'])
        check('production_agent_native_config_pin', agent_native_baseline['config.toml']['sha256'] == '72438589c5b165a2f41d6a5a163a6dcb26698884529f1c64a4c2253d72ee35e7')
        registry_capture = capture_registry()
        put(root / 'installed-registry.private.json', registry_capture)
        registered_plugins = json.loads(registry_capture['row'][registry_capture['columns'].index('plugins_json')])
        harness_plugins = [p for p in registered_plugins if p.get('enabled') is True and p.get('startup', {}).get('agentHarnesses')]
        harness_ids = sorted(set(p['pluginId'] for p in harness_plugins) | {'openai'})
        check('actual_registered_enabled_harness_set', harness_ids == ['codex', 'google', 'openai'])
        report['installedRegistrySha256'] = digest(registry_capture)
        report['actualEnabledHarnessOwnerIds'] = harness_ids
        report['productionLiveProcessRegistryObserved'] = False
        report['productionLiveSessionRuntimeOverrideObserved'] = False
        original_profiles = json.loads(main_doc['rows']['store'][0][1])['profiles']
        for credentials in (original_profiles, bundle['credentials']):
            sensitive.extend(credentials)
            for credential in credentials.values():
                sensitive.extend(v for k, v in credential.items() if isinstance(v, str) and len(v) >= 8
                                 and k not in ('provider', 'type', 'chatgptPlanType'))
        model_string = original_cfg['agents']['defaults']['model']
        if isinstance(model_string, dict):
            model_string = model_string['primary']
        provider, model_id = model_string.split('/', 1)
        check('unchanged_actual_default_model', provider == 'openai' and model_string == 'openai/gpt-5.6-sol')
        model = {'id': model_id, 'provider': provider, 'api': original_cfg['models']['providers'][provider]['api']}
        report['actualDefaultModel'] = model_string
        plugin = root / 'installed-plugin-copy'
        plugin.mkdir(mode=0o700)
        pins = {}
        for name in PLUGIN_FILES:
            data = (PLUGIN / name).read_bytes()
            put(plugin / name, data)
            pins[str(PLUGIN / name)] = pins[str(plugin / name)] = sha(data)
        (plugin / 'node_modules').mkdir(mode=0o700)
        (plugin / 'node_modules/openclaw').symlink_to(SDK)
        for name in SDK_FILES:
            pins[str(SDK / name)] = file_sha(SDK / name)
        for name in ('authbus_native_codex_consumer.mjs', 'authbus_native_codex_live.py', 'authbus_profile2_selector_live.py', 'authbus_native_login_custody.py', 'authbus_native_process_observer.py'):
            pins[str(Path(__file__).with_name(name))] = file_sha(Path(__file__).with_name(name))
        native_pin = json.loads((RUNTIME_RECEIPTS / 'native-pin.public.json').read_bytes())
        check('reviewed_native_pin_receipt', file_sha(RUNTIME_RECEIPTS / 'native-pin.public.json') == 'fce8536b33a83b920accd7264991759a13011057cac3502b0ce14fffc075339e')
        for kind in ('launcher', 'native', 'package', 'nativePackage'):
            item = native_pin[kind]; check('actual_native_source.' + kind, file_sha(Path(item['path'])) == item['sha256'])
            pins[item['path']] = item['sha256']
        pins[str(NODE.resolve())] = file_sha(NODE.resolve())
        for name in ('dist/shared-client-4ICy3U6d.js', 'dist/config-CYEDnLJ2.js', 'dist/index.js', 'dist/harness.js', 'openclaw.plugin.json', 'package.json'):
            pins[str(CODEX / name)] = file_sha(CODEX / name)
        for name in ('runtime-registry-loader-Duw3fvRO.js', 'runtime-registry-loader-d7xui8oD.js', 'selection-JInn13lc.js', 'registry-DtLZ3rba.js',
                     'windows-spawn-C5RDaB22.js', 'plugin-sdk/windows-spawn.js'):
            pins[str(SDK / 'dist' / name)] = file_sha(SDK / 'dist' / name)
        for item in harness_plugins:
            plugin_root = Path(item['rootDir'])
            for candidate in (plugin_root / 'openclaw.plugin.json', plugin_root / 'package.json', plugin_root / 'dist/index.js'):
                if candidate.is_file(): pins[str(candidate)] = file_sha(candidate)
        check('reviewed_actual_factory_source', pins[str(CODEX / 'dist/shared-client-4ICy3U6d.js')] == 'bff60f1bb2cb73ad44c7f9c9d779576a2ffd9836b22ecba0bd5b6046e7ce9103')
        check('reviewed_actual_selector_source', pins[str(SDK / 'dist/selection-JInn13lc.js')] == 'ccff13111aa60369ac9d88b526a58a7df1f733f1d99d205c01c6186036957e66')
        report['sourcePins'] = pins
        sys.path.insert(0, str(qa))
        from native_v6_authbus_client_live import smoke
        from cert_auth_live import cert_sha256
        server = smoke.Instance(BINARY, root / 'server')
        cfg_path = server.root / 'server.json'
        server_config = json.loads(cfg_path.read_bytes())
        server_config['storage'] = {'native_v6_file': {'path': server_config['data_dir']}}
        cfg_path.write_bytes(encoded(server_config))
        server.start()

        def call(name, method, route, body=None, token=None, expected=200):
            status, data = server.call(method, route, body, token=token)
            check(name, status == expected, status=status)
            return data

        init = call('initialize', 'POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1}, token='')
        server.token, unseal = init['root_token'], init['keys_base64'][0]
        sensitive.extend((server.token, unseal))
        put(root / 'recovery.private.json', {'rootToken': server.token, 'unsealKey': unseal})
        call('unseal', 'POST', 'sys/unseal', {'key': unseal}, token='')
        call('kv2_mount', 'POST', 'sys/mounts/openclaw-auth', {'type': 'kv', 'options': {'version': '2'}}, expected=204)
        call('approle_mount', 'POST', 'sys/auth/approle', {'type': 'approle'}, expected=204)
        call('formal_activation', 'POST', 'sys/storage/native-v6/activate', {}, expected=204)
        check('formal_format2', call('capacity', 'GET', 'sys/internal/capacity')['data']['native_kv2_reader_format'] == 2)
        for name, data in docs.items():
            call('publish.' + name.split('/')[0], 'POST', 'openclaw-auth/data/' + name, {'data': data, 'options': {'cas': 0}})
        policy = '\n'.join('path "openclaw-auth/data/' + name + '" { capabilities=["read"] }' for name in docs)
        policy += '\npath "openclaw-auth/data/inbox/multisource-canary/*" { capabilities=["create","update"] }\n'
        policy += '\n'.join('path "auth/token/' + n + '" { capabilities=["' + v + '"] }'
                            for n, v in [('lookup-self', 'read'), ('renew-self', 'update'), ('revoke-self', 'update')])
        call('consumer.policy', 'PUT', 'sys/policies/acl/multisource-consumer', {'policy': policy}, expected=204)
        route = 'auth/approle/role/multisource-consumer'
        call('consumer.role', 'POST', route, {'token_policies': ['multisource-consumer'], 'token_ttl': '180s',
             'token_max_ttl': '600s', 'secret_id_ttl': '1200s', 'secret_id_num_uses': 0}, expected=204)
        role = call('consumer.role_id', 'GET', route + '/role-id')['data']['role_id']
        secret = call('consumer.secret_id', 'POST', route + '/secret-id', {})['data']['secret_id']
        sensitive.extend((role, secret))
        credentials_dir = root / 'credentials-consumer'
        credentials_dir.mkdir(mode=0o700)
        put(credentials_dir / 'role_id', role.encode())
        put(credentials_dir / 'secret_id', secret.encode())
        put(credentials_dir / 'ca.crt', (server.root / 'ca.crt').read_bytes())
        plugin_config = {'address': server.address, 'caFile': str(credentials_dir / 'ca.crt'),
            'roleIdFile': str(credentials_dir / 'role_id'), 'secretIdFile': str(credentials_dir / 'secret_id'),
            'hostId': 'multisource-canary', 'leader': False, 'publishNew': False, 'manageOrder': True,
            'schedulerMode': 'shadow', 'pollIntervalMs': 300000, 'maxRefreshesPerCycle': 1}
        put(root / 'consumer.sb', parent_sandbox(root, int(server.address.rsplit(':', 1)[1]), pins))
        pins[str(root / 'consumer.sb')] = file_sha(root / 'consumer.sb')
        report['kernelContainment'] = {'sharedByNodeAndNative': True, 'baseReadDefaultDenied': True,
            'signalsAllowedOnlyToChildren': True,
            'exactQaAndPinFileReadExceptions': [p for p in pins if Path(p).is_relative_to(BASE) and not Path(p).is_relative_to(root)],
            'freshRunSharedReadWriteScope': str(root), 'onlyNetworkException': server.address,
            'nativeMayAccessBaoLoopback': True, 'nativeMayAccessFreshRunFiles': True,
            'nativeExclusiveHomeTmpSandbox': False, 'allProviderExternalEgressDenied': True}
        expected = {e['profileId']: {'credentialSha256': e['digest'], 'profileKey': e['key'],
                    'accountId': bundle['credentials'][e['profileId']]['accountId']} for e in docs['manifest']['profiles']}
        check('prepared_order_all_sources_trusted', set(binding['actualFinalOrder']) == set(expected))
        env = {'PATH': '/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'TMPDIR': str(root / 'tmp'), 'HOME': os.environ['HOME']}

        def invoke(work, plan, child_env, rollback=False):
            if rollback:
                need(work.name not in rollback_attempted, 'rollback_already_attempted_no_replay')
                rollback_attempted.add(work.name)
            suffix = 'rollback-' if rollback else ''
            plan_path = work / (suffix + 'plan.private.json')
            put(plan_path, plan)
            lifecycle = run_owned_capture(['/usr/bin/sandbox-exec', '-f', str(root / 'consumer.sb'), str(NODE),
                str(Path(__file__).with_name('authbus_native_codex_consumer.mjs')), str(plan_path)],
                child_env, work, 120, work / (suffix + 'stdout.private'), work / (suffix + 'stderr.private'),
                native_observer=None if rollback else {'nodeExecutable': str(NODE.resolve()),
                    'nativeExecutable': plan['nativeBinary']})
            put(work / (suffix + 'process-lifecycle.public.json'), lifecycle)
            stdout = (work / (suffix + 'stdout.private')).read_bytes()
            stderr = (work / (suffix + 'stderr.private')).read_bytes()
            diagnostics.extend((stdout, stderr))
            try:
                result = json.loads(stdout)
            except Exception:
                result = {'ok': False, 'error': 'child_public_report_unavailable', 'checks': []}
            put(work / (suffix + 'result.public.json'), result)
            report['phases'].append({'phase': work.name + ('.rollback' if rollback else ''),
                                    'lifecycle': lifecycle, **result})
            check(('rollback.' if rollback else 'consumer.') + work.name,
                  lifecycle['exitCode'] == 0 and lifecycle['noGroupSurvivors'] and result.get('ok') is True
                  and (rollback or lifecycle.get('nativeProcessObserver', {}).get('verified') is True))
            if rollback: rolled_back.add(work.name)

        def consume(name):
            need(name in ('initial', 'cold-new-process') and name not in plans,
                 'unique_named_consumer_phase')
            work = root / ('consumer-' + name)
            work.mkdir(mode=0o700)
            state = work / 'state'
            helper.materialize(state, [copy.deepcopy(main_doc)])
            # Retain every actual plugin/config runtime and provider/default value.
            # Only private filesystem roots and nonstarted messaging/cron surface
            # are scoped; the loader is limited to actual harness owners + openai.
            cfg = copy.deepcopy(original_cfg)
            main_agent = next((copy.deepcopy(a) for a in cfg['agents'].get('list', []) if a.get('id') == 'main'), {'id': 'main'})
            main_agent['agentDir'] = str(state / 'agents/main/agent')
            main_agent['workspace'] = str(work / 'synthetic-workspace')
            cfg['agents']['list'] = [main_agent]
            cfg['agents']['defaults']['workspace'] = main_agent['workspace']
            cfg['channels'] = {}; cfg['cron'] = {'enabled': False}; cfg['bindings'] = []
            (work / 'synthetic-workspace').mkdir(mode=0o700)
            (state / 'openclaw.json').write_bytes(encoded(cfg))
            (state / 'home').mkdir(mode=0o700)
            restore_registry(state, registry_capture)
            native_home = state / 'agents/main/agent/codex-home'; native_home.mkdir(mode=0o700)
            native_tmp = work / 'native-tmp'; native_tmp.mkdir(mode=0o700)
            for config_name in ('config.toml', 'requirements.toml'):
                if agent_native_baseline[config_name]['exists']:
                    put(native_home / config_name, read_pinned_native_config(NATIVE_HOME / config_name, agent_native_baseline[config_name]['sha256']))
            local_pins = dict(pins)
            for config_name in ('config.toml', 'requirements.toml'):
                if (native_home / config_name).is_file(): local_pins[str(native_home / config_name)] = file_sha(native_home / config_name)
            plan = {'mode': 'initial', 'workRoot': str(root), 'stateRoot': str(state), 'sdkRoot': str(SDK),
                'pluginEntry': str(plugin / 'index.js'), 'pluginConfig': plugin_config,
                'expectedProfiles': expected,
                'projectedManagedOrder': binding['projectedManagedOrder'], 'actualFinalOrder': binding['actualFinalOrder'],
                'excludedProfileIds': bundle['excludedProfileIds'], 'observedUsageByProfile': bundle['observedUsageByProfile'],
                'serverCertificateSha256': cert_sha256(server.root / 'tls.crt'), 'model': model, 'sourcePins': local_pins,
                'selectionOutput': str(work / 'runtime-selection.private.json'),
                'rollbackCheckpointOutput': str(work / 'rollback-checkpoint.private.json'),
                'baselineOutput': str(work / 'baseline-store.private.json'), 'custodyOutput': str(work / 'auth.private.json'),
                'codexRoot': str(CODEX), 'nativeCommand': str(CODEX / 'node_modules/.bin/codex'),
                'nativeLauncher': native_pin['launcher']['path'], 'nativeBinary': native_pin['native']['path'],
                'nativeHome': str(native_home), 'nativeTmp': str(native_tmp), 'parentSandbox': str(root / 'consumer.sb'),
                'nativeDiagnosticOutput': str(work / 'native-diagnostics.private.json'),
                'nativeErrorOutput': str(work / 'native-error.private.json'),
                'nativeIdentityOutput': str(work / 'native-runtime-identity.private.json'),
                'nativeAccountOutput': str(work / 'native-account.private.json'),
                'workspace': str(work / 'synthetic-workspace'), 'harnessOwnerPluginIds': harness_ids}
            child_env = {**env, 'OPENCLAW_STATE_DIR': str(state), 'OPENCLAW_CONFIG_PATH': str(state / 'openclaw.json'),
                         'OPENCLAW_OAUTH_DIR': str(state / 'oauth'), 'OPENCLAW_HOME': str(state / 'home'),
                         'TMPDIR': str(native_tmp)}
            plans[name] = (work, plan, child_env)
            invoke(work, plan, child_env)
            return work

        first = consume('initial')
        tokens = json.loads(read_private(first / 'auth.private.json'))['tokens']
        check('real_approle_token_captured', len(tokens) == 1)
        current = tokens[0]
        sensitive.append(current)
        call('consumer.denied_unassigned', 'GET', 'openclaw-auth/data/profiles/unassigned', token=current, expected=403)
        call('consumer.renew_self', 'POST', 'auth/token/renew-self', {}, token=current)
        call('consumer.revoke_self', 'POST', 'auth/token/revoke-self', {}, token=current, expected=204)
        call('consumer.revoked_token_rejected', 'GET', 'openclaw-auth/data/manifest', token=current, expected=403)
        process = server.process
        server.stop()
        check('actual_sigkill_and_wait', process.returncode == -9)
        server.start()
        call('cold_sealed', 'GET', 'sys/health', expected=503)
        call('cold_unseal', 'POST', 'sys/unseal', {'key': unseal}, token='')
        consume('cold-new-process')
        check('both_consumer_phase_plans_registered', len(plans) == 2
              and list(plans) == ['initial', 'cold-new-process']
              and [work.name for work, _, _ in plans.values()] == ['consumer-initial', 'consumer-cold-new-process'])
        for work, plan, child_env in plans.values():
            invoke(work, {**plan, 'mode': 'rollback', 'custodyOutput': str(work / 'rollback-auth.private.json')}, child_env, rollback=True)
        expected_work_names = {'consumer-initial', 'consumer-cold-new-process'}
        check('both_full_store_rollbacks_attempted_once_and_succeeded',
              rollback_attempted == expected_work_names and rolled_back == expected_work_names)
        check('exact_four_successful_phase_records', [phase['phase'] for phase in report['phases']] ==
              ['consumer-initial', 'consumer-cold-new-process', 'consumer-initial.rollback', 'consumer-cold-new-process.rollback']
              and all(phase.get('ok') is True for phase in report['phases']))
        after = helper.capture(LIVE, prepared['productionConfigSha256'])
        check('original_all_auth_rows_unchanged', len(captured) == len(after) and all(a['rows'] == b['rows'] for a, b in zip(captured, after)))
        check('native_source_unchanged', file_sha(NATIVE) == native_sha)
        check('all_installed_and_qa_sources_unchanged', all(file_sha(Path(p)) == expected_sha for p, expected_sha in pins.items()))
        check('production_relay_pids_unchanged', service_pids() == pids)
        check('normal_binary_unchanged', file_sha(BINARY) == binary_sha)
        disk_files = [p for p in (server.root / 'data').rglob('*') if p.is_file()]
        literal = [c[k].encode() for c in bundle['credentials'].values() for k in ('access', 'refresh')]
        check('formal_server_disk_no_provider_plaintext', bool(disk_files) and all(all(v not in p.read_bytes() for v in literal) for p in disk_files))
        native_files = [p for work, plan, _ in plans.values() for p in Path(plan['nativeHome']).rglob('*') if p.is_file()]
        check('all_native_auth_json_files_absent', all(not (Path(plan['nativeHome']) / 'auth.json').exists()
              for _, plan, _ in plans.values()))
        check('native_ephemeral_tokens_not_written_to_home_files', all(not p.is_symlink() and
              all(v not in p.read_bytes() for v in literal) for p in native_files))
        diagnostics.extend([(server.root / 'server.log').read_bytes(), encoded(report)])
        check('diagnostics_no_credential_values', all(all(v.encode() not in b for v in sensitive) for b in diagnostics))
        report.update(ok=True, twoSameAccountSourcesImported=True, actualInstalledNativeLocalConsumerQualified=True,
            sourceQuotaStatePreserved=True, actualServerColdRestartQualified=True,
            privateLogicalStoreRollbackQualified=True, productionRolloutQualified=False,
            qualificationScope='Two-source HeptaBao/AuthBus lifecycle plus actual installed loader/default native selector and local native auth RPCs under denied external egress, SIGKILL cold restart and full-store CAS rollback; no model availability or production gateway cutover proof.')
    except Exception as error:
        report['error'] = str(error) if isinstance(error, Refused) else type(error).__name__
        report['errorClass'] = type(error).__name__
        report['errorFrames'] = [{'file': Path(f.filename).name, 'line': f.lineno} for f in traceback.extract_tb(error.__traceback__)[-5:]]
    finally:
        # A native/loader failure still gets the exact captured committed-store
        # rollback. No failed assertion is changed to a successful run.
        for work, plan, child_env in plans.values():
            if work.name not in rollback_attempted and Path(plan['rollbackCheckpointOutput']).is_file():
                try:
                    invoke(work, {**plan, 'mode': 'rollback', 'custodyOutput': str(work / 'rollback-auth.private.json')}, child_env, rollback=True)
                except Exception as rollback_error:
                    report.setdefault('cleanupErrors', []).append({'phase': work.name, 'errorClass': type(rollback_error).__name__})
        if helper is not None and captured is not None:
            try:
                after_final = helper.capture(LIVE, prepared['productionConfigSha256'])
                report['allProductionAuthRowsUnchangedAtTerminal'] = len(captured) == len(after_final) and all(a['rows'] == b['rows'] for a, b in zip(captured, after_final))
                report['productionNativeSourceUnchangedAtTerminal'] = file_sha(NATIVE) == native_sha
                report['productionAgentNativeInputsUnchangedAtTerminal'] = native_home_baseline() == agent_native_baseline
                report['productionRelayPidsUnchangedAtTerminal'] = service_pids() == pids
                if not all(report.get(k) is True for k in ['allProductionAuthRowsUnchangedAtTerminal', 'productionNativeSourceUnchangedAtTerminal', 'productionAgentNativeInputsUnchangedAtTerminal', 'productionRelayPidsUnchangedAtTerminal']): report['ok'] = False
            except Exception as terminal_error:
                report['terminalPreservationError'] = type(terminal_error).__name__; report['ok'] = False
        if server is not None and server.process is not None:
            process = server.process
            server.stop()
            report['ownedServerStopped'] = process.returncode is not None
        report['rollbackScopeAccounting'] = {'registeredPlanKeys': list(plans),
            'attemptedWorkNames': sorted(rollback_attempted), 'succeededWorkNames': sorted(rolled_back),
            'actualPhaseRecords': [phase['phase'] for phase in report['phases']]}
        report['finishedUnixMs'] = int(time.time() * 1000)
        put(root / 'result.public.json', report)
    print(json.dumps({'ok': report['ok'], 'error': report.get('error'), 'checks': len(report['checks']), 'result': str(root / 'result.public.json')}))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
