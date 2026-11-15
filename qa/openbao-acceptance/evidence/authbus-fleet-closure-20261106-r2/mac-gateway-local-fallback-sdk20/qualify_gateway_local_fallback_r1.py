#!/usr/bin/env python3
"""Synthetic pure-transform negatives; no SDK, gateway, file mutation or network."""
import copy
import hashlib
import json
from pathlib import Path
import plistlib
import time
import mac_gateway_local_fallback_r1 as M

started = time.monotonic()
rows = []


def fixture(*, flags='-ec', script='ulimit -n 65536; exec "$0" "$@"',
            environment=None, configuration=None):
    cfg = configuration if configuration is not None else {
        'plugins': {'entries': {M.PLUGIN: {'enabled': True, 'config': {
            'address': 'https://synthetic.invalid:8200', 'publishNew': True,
            'leader': False}}, 'other-synthetic-plugin': {'enabled': True}}},
        'auth': {'profiles': {'synthetic-registered': {'provider': 'openai'}}},
        'agents': {'list': [{'id': 'synthetic-agent', 'model': {'primary': 'openai/synthetic'}}]},
        'gateway': {'auth': {'token': 'synthetic-private-fixture-only'}, 'port': 18789},
        'unrelated': {'enabled': True, 'values': [0, 1, None, 'synthetic']}}
    argv = ['/bin/sh', flags, script, '/opt/homebrew/opt/node/bin/node',
            M.SDK + '/dist/index.js', 'gateway', '--port', '18789']
    plist = {'Label': M.LABEL, 'ProgramArguments': argv, 'KeepAlive': True,
             'RunAtLoad': True, 'EnvironmentVariables': environment or {'PATH': '/usr/bin:/bin'},
             'StandardOutPath': M.HOME + '/synthetic.stdout',
             'StandardErrorPath': M.HOME + '/synthetic.stderr'}
    config_bytes = M.canonical_json(cfg)
    plist_bytes = plistlib.dumps(plist, fmt=plistlib.FMT_XML)
    binding = {'schema': 'heptabao.current-gateway-private-restore-inputs.r1',
               'target': M.TARGET, 'configPath': M.CONFIG, 'plistPath': M.PLIST,
               'configSha256': M.sha(config_bytes), 'plistSha256': M.sha(plist_bytes),
               'arguments': argv, 'loadedFirst': {'arguments': copy.deepcopy(argv)},
               'loadedSecond': {'arguments': copy.deepcopy(argv)},
               'environment': copy.deepcopy(plist['EnvironmentVariables'])}
    return config_bytes, plist_bytes, binding, cfg, plist


def check(name, fn, expected=None):
    try:
        value = fn()
    except M.Refused as error:
        assert expected is not None and str(error) == expected, (name, str(error), expected)
        rows.append({'case': name, 'ok': True, 'refused': str(error)})
    else:
        assert expected is None and value is not False, (name, expected)
        rows.append({'case': name, 'ok': True})


def prepare(**kwargs):
    values = fixture(**kwargs)
    return M.make_fallback(*values[:3])


def changed_binding(key, value):
    c, p, b, _, _ = fixture()
    b[key] = value
    return M.make_fallback(c, p, b)


def changed_config(fn):
    c, p, b, cfg, _ = fixture()
    fn(cfg)
    c = M.canonical_json(cfg)
    b['configSha256'] = M.sha(c)
    return M.make_fallback(c, p, b)


def validate_changed_config(fn):
    c, p, b, cfg, plist = fixture()
    made = M.make_fallback(c, p, b)
    altered = json.loads(made['configBytes'])
    fn(altered)
    return M.validate_fallback(cfg, plist, M.canonical_json(altered), made['plistBytes'])


def validate_changed_plist(fn):
    c, p, b, cfg, plist = fixture()
    made = M.make_fallback(c, p, b)
    altered = plistlib.loads(made['plistBytes'])
    fn(altered)
    return M.validate_fallback(cfg, plist, made['configBytes'], plistlib.dumps(altered))


def retention():
    c, p, b, cfg, plist = fixture()
    before = copy.deepcopy((cfg, plist, b))
    made = M.make_fallback(c, p, b)
    out = json.loads(made['configBytes'])
    assert out['auth'] == cfg['auth'] and out['agents'] == cfg['agents']
    assert out['gateway'] == cfg['gateway'] and out['unrelated'] == cfg['unrelated']
    assert (cfg, plist, b) == before
    assert made['public']['actualSdkDisabledSemanticsQualified'] is False
    assert made['public']['runningConfigurationObserved'] is False
    assert made['public']['providerCalls'] == made['public']['serviceMutations'] == 0
    assert 'synthetic-private-fixture-only' not in json.dumps(made['public'])
    return True


check('F01_preserves_all_other_values_and_inputs', retention)
check('F02_and_exec_wrapper', lambda: prepare(script='ulimit -n 65536 && exec "$0" "$@"'))
check('F03_plain_quoted_exec', lambda: prepare(flags='-c', script='exec "$0" "$@"'))
check('F04_matching_explicit_original_scope', lambda: prepare(environment={
    'HOME': M.HOME, 'OPENCLAW_STATE_DIR': M.LIVE, 'OPENCLAW_CONFIG_PATH': M.CONFIG}))
check('F05_config_generation_changed', lambda: changed_binding('configSha256', '0' * 64),
      'fallback_exact_original_private_bytes')
check('F06_plist_generation_changed', lambda: changed_binding('plistSha256', '0' * 64),
      'fallback_exact_original_private_bytes')
check('F07_other_registered_label', lambda: changed_binding('target', 'gui/501/synthetic-other'),
      'fallback_exact_registered_private_restore_scope')
check('F08_login_shell_rejected', lambda: prepare(flags='-lc'), 'fallback_nonlogin_finite_shell_switches')
check('F09_xtrace_rejected', lambda: prepare(flags='-xc'), 'fallback_nonlogin_finite_shell_switches')
check('F10_environment_assignment_rejected', lambda: prepare(script='OPENCLAW_CONFIG_PATH=/tmp/wrong exec "$0" "$@"'),
      'fallback_exact_transparent_exec_script')
check('F11_single_quoted_arguments_rejected', lambda: prepare(script="exec '$0' '$@'"),
      'fallback_exact_quoted_argument_forwarding')
check('F12_unquoted_arguments_rejected', lambda: prepare(script='exec $0 $@'),
      'fallback_exact_quoted_argument_forwarding')
check('F13_command_substitution_rejected', lambda: prepare(script='exec "$(echo node)" "$@"'),
      'fallback_exact_transparent_exec_script')
check('F14_conflicting_state_root_rejected', lambda: prepare(environment={'OPENCLAW_STATE_DIR': '/tmp/synthetic-other'}),
      'fallback_original_registered_environment_scope')
check('F15_profile_selector_rejected', lambda: prepare(environment={'OPENCLAW_PROFILE': 'synthetic-other'}),
      'fallback_original_registered_environment_scope')
check('F16_unqualified_preload_rejected', lambda: prepare(environment={'NODE_OPTIONS': '--require /tmp/synthetic'}),
      'fallback_no_unqualified_runtime_override')
check('F17_original_disabled_entry_not_relabelled', lambda: changed_config(
    lambda c: c['plugins']['entries'][M.PLUGIN].update(enabled=False)),
      'fallback_original_enabled_authbus_entry')
check('F18_missing_authbus_entry_rejected', lambda: changed_config(
    lambda c: c['plugins']['entries'].pop(M.PLUGIN)), 'fallback_original_enabled_authbus_entry')
check('F19_enabled_false_is_not_integer_zero', lambda: validate_changed_config(
    lambda c: c['plugins']['entries'][M.PLUGIN].update(enabled=0)),
      'fallback_only_authbus_enabled_field_changes')
check('F20_untargeted_auth_change_rejected', lambda: validate_changed_config(
    lambda c: c['auth'].update(profiles={})), 'fallback_only_authbus_enabled_field_changes')
check('F21_untargeted_provider_destination_change_rejected', lambda: validate_changed_config(
    lambda c: c['plugins']['entries'][M.PLUGIN]['config'].update(address='https://other.invalid')),
      'fallback_only_authbus_enabled_field_changes')
check('F22_untargeted_boolean_type_change_rejected', lambda: validate_changed_config(
    lambda c: c['unrelated'].update(enabled=1)), 'fallback_only_authbus_enabled_field_changes')
check('F23_old_config_reintroduced_rejected', lambda: validate_changed_plist(
    lambda p: p['EnvironmentVariables'].update(OPENCLAW_CONFIG_PATH=M.CONFIG)),
      'fallback_only_exact_environment_scope_changes')
check('F24_label_change_rejected', lambda: validate_changed_plist(
    lambda p: p.update(Label='synthetic-other')), 'fallback_only_exact_environment_scope_changes')
check('F25_keepalive_type_change_rejected', lambda: validate_changed_plist(
    lambda p: p.update(KeepAlive=1)), 'fallback_only_exact_environment_scope_changes')


def duplicate_json():
    c, p, b, _, _ = fixture()
    c = b'{"plugins":{},"plugins":{}}'
    b['configSha256'] = M.sha(c)
    return M.make_fallback(c, p, b)


check('F26_duplicate_json_rejected', duplicate_json, 'fallback_duplicate_json_key')
source = Path(M.__file__).read_bytes()
print(json.dumps({'schema': 'heptabao.gateway-local-fallback-pure-qualification.r1',
                  'ok': True, 'passed': len(rows), 'cases': rows,
                  'sourceBytes': len(source), 'sourceSha256': hashlib.sha256(source).hexdigest(),
                  'actualSdkExecuted': False, 'productionConfigurationRead': False,
                  'serviceMutations': 0, 'providerCalls': 0,
                  'elapsedSeconds': round(time.monotonic() - started, 6)}, sort_keys=True))
