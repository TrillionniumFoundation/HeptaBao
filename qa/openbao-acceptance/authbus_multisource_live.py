#!/usr/bin/env python3
"""Two real same-account sources through normal HeptaBao and installed AuthBus.

Uses the actual installed SDK order established by authbus_multisource_order.
Carries observed quota state; never makes a provider request or refreshes OAuth.
Every service, credential, database and changed order is private to the fresh run.
"""
from __future__ import annotations
import argparse, copy, importlib.util, json, os, subprocess, sys, time, traceback
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--prepared', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.work_dir
    root.mkdir(mode=0o700)
    (root / 'tmp').mkdir(mode=0o700)
    report = {'schema': 'heptabao.actual-two-source-installed-consumer.v1', 'ok': False,
              'sourceCommit': COMMIT, 'sourceTree': TREE, 'checks': [], 'phases': [],
              'productionChanged': False, 'productionTrafficCutover': False,
              'allAccountsQualified': False, 'businessAvailabilityQualified': False,
              'providerCalled': False, 'providerRefreshAttempted': False, 'modelCalled': False,
              'j3160Contacted': False, 'credentialValuesPublished': False,
              'accountIdentitiesPublished': False, 'startedUnixMs': int(time.time() * 1000)}
    server = None
    sensitive = []
    diagnostics = []
    plans = {}

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
        for name in ('authbus_multisource_consumer.mjs', 'authbus_multisource_live.py', 'authbus_profile2_selector_live.py'):
            pins[str(Path(__file__).with_name(name))] = file_sha(Path(__file__).with_name(name))
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
        put(root / 'consumer.sb', sandbox(root, [int(server.address.rsplit(':', 1)[1])]))
        expected = {e['profileId']: {'credentialSha256': e['digest'], 'profileKey': e['key'],
                    'accountId': bundle['credentials'][e['profileId']]['accountId']} for e in docs['manifest']['profiles']}
        selected = binding['actualFinalOrder'][0]
        check('quota_based_default_is_trusted_profile2', list(original_profiles).index(selected) == 1)
        env = {'PATH': '/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'TMPDIR': str(root / 'tmp'), 'HOME': os.environ['HOME']}

        def invoke(work, plan, child_env, rollback=False):
            suffix = 'rollback-' if rollback else ''
            plan_path = work / (suffix + 'plan.private.json')
            put(plan_path, plan)
            proc = subprocess.run(['/usr/bin/sandbox-exec', '-f', str(root / 'consumer.sb'), '/opt/homebrew/bin/node',
                str(Path(__file__).with_name('authbus_multisource_consumer.mjs')), str(plan_path)],
                env=child_env, capture_output=True, timeout=70)
            put(work / (suffix + 'stdout.private'), proc.stdout)
            put(work / (suffix + 'stderr.private'), proc.stderr)
            diagnostics.extend((proc.stdout, proc.stderr))
            result = json.loads(proc.stdout)
            put(work / (suffix + 'result.public.json'), result)
            report['phases'].append({'phase': work.name + ('.rollback' if rollback else ''), **result})
            check(('rollback.' if rollback else 'consumer.') + work.name, proc.returncode == 0 and result.get('ok') is True)

        def consume(name):
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
            plan = {'mode': 'initial', 'workRoot': str(root), 'stateRoot': str(state), 'sdkRoot': str(SDK),
                'pluginEntry': str(plugin / 'index.js'), 'pluginConfig': plugin_config,
                'expectedProfiles': expected, 'expectedProfileId': selected,
                'expectedAccountId': expected[selected]['accountId'],
                'expectedCredentialSha256': expected[selected]['credentialSha256'],
                'projectedManagedOrder': binding['projectedManagedOrder'], 'actualFinalOrder': binding['actualFinalOrder'],
                'excludedProfileIds': bundle['excludedProfileIds'], 'observedUsageByProfile': bundle['observedUsageByProfile'],
                'serverCertificateSha256': cert_sha256(server.root / 'tls.crt'), 'model': model, 'sourcePins': pins,
                'selectionOutput': str(work / 'runtime-selection.private.json'),
                'baselineOutput': str(work / 'baseline-store.private.json'), 'custodyOutput': str(work / 'auth.private.json')}
            child_env = {**env, 'OPENCLAW_STATE_DIR': str(state), 'OPENCLAW_CONFIG_PATH': str(state / 'openclaw.json'),
                         'OPENCLAW_OAUTH_DIR': str(state / 'oauth'), 'OPENCLAW_HOME': str(state / 'home')}
            invoke(work, plan, child_env)
            plans[name] = (work, plan, child_env)
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
        for work, plan, child_env in plans.values():
            invoke(work, {**plan, 'mode': 'rollback', 'custodyOutput': str(work / 'rollback-auth.private.json')}, child_env, rollback=True)
        after = helper.capture(LIVE, prepared['productionConfigSha256'])
        check('original_all_auth_rows_unchanged', len(captured) == len(after) and all(a['rows'] == b['rows'] for a, b in zip(captured, after)))
        check('native_source_unchanged', file_sha(NATIVE) == native_sha)
        check('all_installed_and_qa_sources_unchanged', all(file_sha(Path(p)) == expected_sha for p, expected_sha in pins.items()))
        check('production_relay_pids_unchanged', service_pids() == pids)
        check('normal_binary_unchanged', file_sha(BINARY) == binary_sha)
        disk_files = [p for p in (server.root / 'data').rglob('*') if p.is_file()]
        literal = [c[k].encode() for c in bundle['credentials'].values() for k in ('access', 'refresh')]
        check('formal_server_disk_no_provider_plaintext', bool(disk_files) and all(all(v not in p.read_bytes() for v in literal) for p in disk_files))
        diagnostics.extend([(server.root / 'server.log').read_bytes(), encoded(report)])
        check('diagnostics_no_credential_values', all(all(v.encode() not in b for v in sensitive) for b in diagnostics))
        report.update(ok=True, twoSameAccountSourcesImported=True, actualInstalledDefaultResolverQualified=True,
            sourceQuotaStatePreserved=True, actualServerColdRestartQualified=True,
            privateLogicalStoreRollbackQualified=True, productionRolloutQualified=False,
            qualificationScope='Two-source HeptaBao storage and installed AuthBus/default-resolver lifecycle with original SDK order and observed quotas; no new provider availability proof and no production cutover.')
    except Exception as error:
        report['error'] = str(error) if isinstance(error, Refused) else type(error).__name__
        report['errorClass'] = type(error).__name__
        report['errorFrames'] = [{'file': Path(f.filename).name, 'line': f.lineno} for f in traceback.extract_tb(error.__traceback__)[-5:]]
    finally:
        if server is not None and server.process is not None:
            process = server.process
            server.stop()
            report['ownedServerStopped'] = process.returncode is not None
        report['finishedUnixMs'] = int(time.time() * 1000)
        put(root / 'result.public.json', report)
    print(json.dumps({'ok': report['ok'], 'error': report.get('error'), 'checks': len(report['checks']), 'result': str(root / 'result.public.json')}))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
