#!/usr/bin/env python3
"""Prepare, optionally run, and verify one isolated native Codex login.

Preparing never starts a login. The operator runs the generated local wrapper
only when ready to complete the native device flow. CODEX_HOME is passed only
in the native CLI child's environment. Production authentication is untouched.
"""
from __future__ import annotations
import argparse, base64, hashlib, importlib.util, json, os, shlex, subprocess, sys, time
from pathlib import Path
from authbus_profile2_selector_live import need, encoded, digest, sha, file_sha, read_private, put
from authbus_native_login_custody import resolve_native, verify_pins, run_owned, containment_probes, freeze_entry

BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013')
LIVE = Path('/Users/qianqi/.openclaw')
NATIVE = Path('/Users/qianqi/.codex/auth.json')
NATIVE_CONFIG = NATIVE.with_name('config.toml')
SDK_PACKAGE = Path('/opt/homebrew/lib/node_modules/@openai/codex/package.json')
LAUNCHER = SDK_PACKAGE.parent / 'bin/codex.js'
SOURCE = BASE / 'continuation-20261104-blocker-closure-r1/source'
REFRESH = BASE / 'authbus-profile3-native-refresh-36076-20261104-r1'
TARGET_ACCOUNT_SHA = 'dfe45608d591590e55167d33f097a2a7f7119cd2256d8ebdc149e06d1befd1ae'
FAILED_REFRESH_SHA = 'f55df16272e5266b983b3f40ba64f7ed406671e234ea6083e8c6ec1ce8d6ac26'


def capture_path():
    if Path(__file__).parent.name == 'frozen-program':
        return Path(__file__).with_name('authbus_current_credential_stage.py')
    return SOURCE / 'qa/openbao-acceptance/authbus_current_credential_stage.py'


def stage_helper():
    spec = importlib.util.spec_from_file_location('profile3_stage', capture_path())
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def claims(token):
    return json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '==='))


def verify_baseline(root, intent, helper):
    need(file_sha(NATIVE) == intent['nativeAuthSha256'], 'production_native_auth_changed')
    need(file_sha(NATIVE_CONFIG) == intent['nativeConfigSha256'], 'production_native_config_changed')
    need(file_sha(LAUNCHER) == intent['launcherSha256'] and file_sha(SDK_PACKAGE) == intent['packageSha256'], 'installed_cli_changed')
    verify_pins(intent['runtimePins'])
    current = helper.capture(LIVE, intent['openclawConfigSha256'])
    baseline = json.loads(read_private(root / 'production-auth-rows.private.json'))
    need(len(current) == len(baseline) and all(a['rows'] == b['rows'] for a, b in zip(current, baseline)), 'production_auth_rows_changed')


def prepare(root):
    root.mkdir(mode=0o700)
    home = root / 'native-login-home'
    home.mkdir(mode=0o700)
    (root / 'tmp').mkdir(mode=0o700)
    helper = stage_helper()
    cfg_sha = file_sha(LIVE / 'openclaw.json')
    rows = helper.capture(LIVE, cfg_sha)
    main = next(d for d in rows if d['agent'] == 'main')
    store = json.loads(main['rows']['store'][0][1])
    matches = [(pid, c) for pid, c in store['profiles'].items() if c.get('provider') == 'openai' and c.get('type') == 'oauth'
               and sha(str(c.get('accountId', '')).encode()) == TARGET_ACCOUNT_SHA]
    need(len(matches) == 1 and list(store['profiles']).index(matches[0][0]) == 2, 'target_profile3_exact_unique_identity')
    pid, credential = matches[0]
    need(sha(credential['refresh'].encode()) == FAILED_REFRESH_SHA, 'failed_generation_changed_reassess_before_login')
    rejection = json.loads(read_private(REFRESH / 'terminal-classification.public.json'))
    need(rejection.get('providerErrorCode') == 'invalid_refresh_token' and rejection.get('outcomeUnknown') is False, 'known_terminal_refresh_required')
    package = json.loads(SDK_PACKAGE.read_bytes())
    need(package['version'] == '0.133.0', 'reviewed_cli_version')
    native = read_private(NATIVE)
    current_account = json.loads(native)['tokens']['account_id']
    need(sha(current_account.encode()) != TARGET_ACCOUNT_SHA, 'keep_existing_other_native_account')
    put(root / 'production-native-auth-backup.private.json', native)
    put(root / 'production-auth-rows.private.json', rows)
    put(home / 'config.toml', b'cli_auth_credentials_store = "file"\n')
    native_runtime = resolve_native(LAUNCHER, SDK_PACKAGE)
    native_binary = native_runtime['pins']['codexNative']['path']
    version = subprocess.run([native_binary, '--version'], capture_output=True, timeout=8,
                             env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'CODEX_HOME': str(home)})
    need(version.returncode == 0 and version.stdout.strip() == b'codex-cli 0.133.0', 'native_binary_version')
    intent = {'schema': 'heptabao.profile3-native-login-preparation.v2', 'createdUnixMs': int(time.time() * 1000),
        'profileId': pid, 'oldCredential': credential, 'targetAccountIdSha256': TARGET_ACCOUNT_SHA,
        'oldCredentialSha256': digest(credential), 'nativeAuthSha256': sha(native),
        'nativeConfigSha256': file_sha(NATIVE_CONFIG), 'openclawConfigSha256': cfg_sha,
        'packageSha256': file_sha(SDK_PACKAGE), 'launcherSha256': file_sha(LAUNCHER),
        'cliVersion': package['version'], 'nativeLoginHome': str(home),
        'runtimePins': native_runtime['pins'], 'nativeBinary': native_binary,
        'refreshRejectionReceiptSha256': file_sha(REFRESH / 'terminal-classification.public.json'),
        'productionWriteAllowed': False, 'automaticRetryAllowed': False}
    put(root / 'prepared-intent.private.json', intent)
    rules = ['(version 1)', '(deny default)', '(allow process*)', '(allow sysctl-read)', '(allow mach-lookup)',
        '(allow file-read*)', '(allow file-write* (subpath ' + json.dumps(str(home)) + '))',
        '(allow file-write* (subpath ' + json.dumps(str(root / 'tmp')) + '))',
        '(allow file-write* (literal "/dev/null"))',
        '(allow network-outbound (remote tcp "*:443"))',
        '(allow network-outbound (remote unix-socket (literal "/private/var/run/mDNSResponder")))',
        '(allow network-outbound (remote unix-socket (literal "/var/run/mDNSResponder")))',
        '(deny file-read* (literal ' + json.dumps(str(NATIVE)) + '))',
        '(deny file-read* (subpath ' + json.dumps(str(LIVE / 'agents')) + '))']
    for protected in ('production-auth-rows.private.json', 'production-native-auth-backup.private.json', 'prepared-intent.private.json'):
        rules.append('(deny file-read* (literal ' + json.dumps(str(root / protected)) + '))')
    put(root / 'login.sb', ('\n'.join(rules) + '\n').encode())
    need(subprocess.run(['/usr/bin/sandbox-exec', '-f', str(root / 'login.sb'), '/usr/bin/true'],
                        capture_output=True, timeout=5).returncode == 0, 'login_sandbox_syntax')
    frozen_pins = freeze_entry(root, native_runtime['pins'], capture_path(), Path(__file__))
    probes = containment_probes(root, native_runtime['pins']['pythonRuntime']['path'])
    verify_pins(frozen_pins)
    verify_baseline(root, intent, helper)
    receipt = {'schema': 'heptabao.profile3-native-login-prepared.v2', 'ok': True,
        'cliVersion': package['version'], 'loginStarted': False, 'providerRequests': 0,
        'productionChanged': False, 'keychainRead': False, 'existingNativeAuthBackedUp': True,
        'allProductionAuthRowsBackedUp': len(rows), 'expectedProfileOrdinal': 3,
        'targetAccountIdSha256': TARGET_ACCOUNT_SHA, 'nativeLoginHome': str(home),
        'authBackend': 'file', 'environmentScope': 'CODEX_HOME only in explicit native CLI child environment',
        'nativeCommand': [native_binary, '-c', 'cli_auth_credentials_store="file"', 'login', '--device-auth'],
        'nativeInvocation': 'Direct exact installed native CLI resolved by the reviewed npm launcher; no second dynamic Node package resolution at login.',
        'runtimePins': native_runtime['pins'], 'frozenProgramPinsSha256': file_sha(root / 'frozen-program-pins.public.json'),
        'containmentProbesSha256': file_sha(root / 'containment-probes.public.json'),
        'nativeChildWritesOnlyLoginHomeAndTmp': True, 'nativeChildCannotReadOldCredentialBackups': True,
        'syntheticTimeoutAndInterruptGroupsFullyStopped': probes['ok'],
        'humanAction': 'Run the private local wrapper when ready; complete the native device login using the original profile 3 account. No token is pasted into chat.',
        'wrapper': str(root / 'run-native-login.sh'), 'wrapperSha256': file_sha(root / 'run-native-login.sh'),
        'preparationIntentSha256': file_sha(root / 'prepared-intent.private.json'),
        'verification': 'Require exact previous profile 3 accountId and JWT identity, a different nonempty refresh token, future access expiry, and unchanged production native/config/all auth rows before sealing any new generation.',
        'unknownOutcomePolicy': 'Create-only attempt ledger prevents an automatic second login; preserve all native artifacts for review.'}
    put(root / 'prepared.public.json', receipt)
    return receipt


def login(root):
    need(sys.stdin.isatty() and sys.stdout.isatty(), 'human_local_tty_required')
    need(Path(__file__).parent.name == 'frozen-program'
         and os.environ.get('HEPTABAO_LOGIN_BOOTSTRAP_VERIFIED') == '1', 'verified_frozen_entry_required')
    preparation = json.loads(read_private(root / 'prepared.public.json'))
    need(preparation.get('ok') is True and preparation.get('syntheticTimeoutAndInterruptGroupsFullyStopped') is True
         and file_sha(root / 'containment-probes.public.json') == preparation.get('containmentProbesSha256')
         and file_sha(root / 'frozen-program-pins.public.json') == preparation.get('frozenProgramPinsSha256'),
         'complete_reviewed_preparation_required')
    intent = json.loads(read_private(root / 'prepared-intent.private.json'))
    helper = stage_helper()
    verify_baseline(root, intent, helper)
    need(not (root / 'interactive-attempt.private.json').exists(), 'prior_login_attempt_must_be_reviewed_not_replayed')
    task_login_home = root / 'native-login-home'
    need(not (task_login_home / 'auth.json').exists(), 'unreviewed_native_auth_already_present')
    # This is shown only in the human's local TTY, never in a public receipt.
    if intent['oldCredential'].get('email'):
        print('Choose the original profile 3 account in the native login: ' + intent['oldCredential']['email'], flush=True)
    put(root / 'interactive-attempt.private.json', {'startedUnixMs': int(time.time() * 1000),
         'preparedIntentSha256': file_sha(root / 'prepared-intent.private.json'), 'automaticRetry': False})
    # Only this child receives CODEX_HOME. No shell environment is modified.
    env = {'PATH': '/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': os.environ['HOME'],
           'TMPDIR': str(root / 'tmp'), 'CODEX_HOME': str(task_login_home), 'TERM': os.environ.get('TERM', 'xterm-256color')}
    argv = ['/usr/bin/sandbox-exec', '-f', str(root / 'login.sb'), intent['nativeBinary'],
            '-c', 'cli_auth_credentials_store="file"', 'login', '--device-auth']
    execution = {'exitCode': None, 'outcomeUnknown': True, 'noGroupSurvivors': False, 'primaryReaped': False}
    try:
        execution = run_owned(argv, env=env, cwd=str(task_login_home), timeout=1200)
    finally:
        production_unchanged = False
        try:
            verify_baseline(root, intent, helper)
            production_unchanged = True
        except Exception:
            pass
        put(root / 'interactive-terminal.public.json', {**execution,
            'completeProcessResult': execution['exitCode'] is not None and not execution['outcomeUnknown'] and execution['noGroupSurvivors'],
            'loginWasSingleNativeInvocation': True, 'automaticRetry': False,
            'productionBaselineVerifiedUnchanged': production_unchanged})
        verify_baseline(root, intent, helper)
    need(execution['exitCode'] == 0 and execution['primaryReaped'] and execution['noGroupSurvivors']
         and not execution['outcomeUnknown'], 'native_login_did_not_complete_do_not_retry_automatically')
    return verify(root)


def verify(root):
    intent = json.loads(read_private(root / 'prepared-intent.private.json'))
    helper = stage_helper()
    verify_baseline(root, intent, helper)
    terminal = json.loads(read_private(root / 'interactive-terminal.public.json'))
    need(terminal.get('exitCode') == 0 and terminal.get('completeProcessResult') is True, 'native_login_terminal_success_required')
    auth_bytes = read_private(root / 'native-login-home/auth.json')
    auth = json.loads(auth_bytes)
    tokens = auth['tokens']
    old = intent['oldCredential']
    access = claims(tokens['access_token'])
    need(auth.get('auth_mode') == 'chatgpt' and tokens['account_id'] == old['accountId']
         and access.get('https://api.openai.com/auth', {}).get('chatgpt_account_id') == old['accountId'], 'native_login_wrong_account')
    need(access['exp'] > time.time() + 600, 'new_access_not_current')
    need(isinstance(tokens.get('refresh_token'), str) and len(tokens['refresh_token']) > 20
         and sha(tokens['refresh_token'].encode()) != FAILED_REFRESH_SHA, 'rejected_refresh_generation_reused')
    if tokens.get('id_token'):
        ident = claims(tokens['id_token'])
        claimed_account = ident.get('https://api.openai.com/auth', {}).get('chatgpt_account_id')
        need(claimed_account is None or claimed_account == old['accountId'], 'id_token_account_mismatch')
        if ident.get('email') and old.get('email'):
            need(ident['email'].casefold() == old['email'].casefold(), 'id_token_email_mismatch')
    credential = {**old, 'access': tokens['access_token'], 'refresh': tokens['refresh_token'],
                  'expires': access['exp'] * 1000, 'accountId': tokens['account_id']}
    if tokens.get('id_token'):
        credential['idToken'] = tokens['id_token']
    put(root / 'same-account-generation.private.json', {'schema': 'heptabao.native-login-verified-generation.v1',
        'profileId': intent['profileId'], 'credential': credential, 'credentialSha256': digest(credential),
        'nativeAuthSha256': sha(auth_bytes), 'oldCredentialSha256': intent['oldCredentialSha256'],
        'publishedToProduction': False})
    receipt = {'schema': 'heptabao.profile3-native-login-verified.v1', 'ok': True, 'sameAccount': True,
        'newGenerationSha256': digest(credential), 'nativeAuthSha256': sha(auth_bytes),
        'originalNativeAuthAndAllProductionRowsUnchanged': True, 'publishedToProduction': False,
        'providerBusinessAvailabilityQualified': False, 'newProviderProbe': False}
    put(root / 'verified.public.json', receipt)
    return receipt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--action', choices=('prepare', 'login', 'verify'), default='prepare')
    args = p.parse_args()
    os.umask(0o077)
    try:
        result = {'prepare': prepare, 'login': login, 'verify': verify}[args.action](args.root)
        print(json.dumps({'ok': result['ok'], 'action': args.action, 'root': str(args.root), 'productionChanged': False}))
        return 0
    except Exception as error:
        print(json.dumps({'ok': False, 'action': args.action,
            'error': str(error) if type(error).__name__ == 'Refused' else type(error).__name__, 'automaticRetry': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
