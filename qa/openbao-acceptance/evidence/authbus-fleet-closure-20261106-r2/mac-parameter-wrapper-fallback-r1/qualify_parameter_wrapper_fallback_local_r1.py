#!/usr/bin/env python3
"""Finite synthetic qualification of the newly observed wrapper form.

The two shell cases execute only a temporary synthetic wrapper/environment and
this interpreter as their child. No installed SDK, gateway, database, provider,
or production path is opened. Output contains case names and counters only.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import time

import mac_gateway_parameter_wrapper_fallback_r1 as target

WRAPPER = b'''#!/bin/sh
set -eu
input_file="$1"
shift
if [ -f "$input_file" ]; then
  . "$input_file"
fi
exec "$@"
'''
ENVIRONMENT = b'''# Entirely synthetic environment.
export HOME=/Users/qianqi
export SYNTHETIC_00=alpha
SYNTHETIC_01='not exported'
export SYNTHETIC_02='literal;semicolon'
export SYNTHETIC_03='double"quote'
export SYNTHETIC_04=escaped\\ space
export SYNTHETIC_05='literal#hash'
export SYNTHETIC_06='back\\slash'
SYNTHETIC_07=local
export SYNTHETIC_08=a=b
export SYNTHETIC_09=*.literal
export SYNTHETIC_10=''
export SYNTHETIC_11="joined"value
'''


def inputs():
    args = ['/bin/sh', '/Users/qianqi/synthetic-wrapper.sh',
            '/Users/qianqi/synthetic-environment.private',
            '/opt/homebrew/opt/node/bin/node', target.original.SDK + '/dist/index.js',
            'gateway', '--port', '18789']
    config = {'plugins': {'entries': {target.original.PLUGIN:
              {'enabled': True, 'config': {'syntheticOnly': True}},
              'unchanged': {'enabled': True}}}, 'other': {'keep': [1, False, 'same']}}
    plist = {'Label': target.original.LABEL, 'ProgramArguments': args,
             'KeepAlive': True, 'RunAtLoad': True,
             'EnvironmentVariables': {'HOME': target.original.HOME, 'SYNTHETIC_PLIST': 'same'}}
    raw_config = target.original.canonical_json(config) + b'\n'
    raw_plist = plistlib.dumps(plist, fmt=plistlib.FMT_BINARY)
    binding = {'schema': 'heptabao.current-gateway-private-restore-inputs.r1',
        'observationSchema': 'heptabao.current-gateway-observation.private.r2',
        'target': target.original.TARGET, 'configPath': target.original.CONFIG,
        'plistPath': target.original.PLIST, 'configSha256': target.sha(raw_config),
        'plistSha256': target.sha(raw_plist), 'arguments': copy.deepcopy(args),
        'environment': copy.deepcopy(plist['EnvironmentVariables']),
        'loadedFirst': {'arguments': copy.deepcopy(args)},
        'loadedSecond': {'arguments': copy.deepcopy(args),
                        'observedEnvironmentScope': {'registered': {'HOME': target.original.HOME}}}}
    source = {'schema': 'heptabao.current-parameter-wrapper.private.r1',
              'arguments': copy.deepcopy(args), 'wrapperPath': args[1], 'environmentPath': args[2],
              'wrapperSha256': target.sha(WRAPPER), 'environmentSha256': target.sha(ENVIRONMENT)}
    return raw_config, raw_plist, binding, WRAPPER, ENVIRONMENT, source


def refused(fn):
    try:
        fn()
    except (target.WrapperRefused, target.original.Refused):
        return
    raise AssertionError('expected_fixed_refusal')


def main():
    started = time.monotonic()
    cases = []
    children = []

    def case(name, fn):
        fn()
        cases.append({'name': name, 'passed': True})

    def same_13_and_prefix():
        prepared = target.make_parameter_wrapper_fallback(*inputs())
        assert prepared['environmentBytes'].startswith(ENVIRONMENT)
        assert len(prepared['originalLiteralValues']) == 13
        assert prepared['public']['productionFallbackQualified'] is False
        assert prepared['public']['actualCurrentSdkSelectionQualified'] is False

    case('original_thirteen_assignments_and_byte_prefix_preserved', same_13_and_prefix)

    def exact_delta():
        original = inputs()
        prepared = target.make_parameter_wrapper_fallback(*original)
        expected_config = json.loads(original[0])
        expected_config['plugins']['entries'][target.original.PLUGIN]['enabled'] = False
        assert json.loads(prepared['configBytes']) == expected_config
        expected_plist = plistlib.loads(original[1])
        expected_plist['ProgramArguments'][2] = target.SAFE_ENVIRONMENT
        expected_plist['EnvironmentVariables'].update(target.SELECTORS)
        assert plistlib.loads(prepared['plistBytes']) == expected_plist
        assert prepared['wrapperSourceBytes'] == WRAPPER

    case('only_authbus_config_field_and_env_argument_selectors_change', exact_delta)
    case('different_source_variable_refused', lambda: refused(lambda:
         target.parameter_wrapper_shape(WRAPPER.replace(b'. "$input_file"', b'. "$other_file"'))))
    case('extra_source_or_exec_line_refused', lambda: refused(lambda:
         target.parameter_wrapper_shape(WRAPPER + b'exec anything\n')))
    case('unquoted_argument_forwarding_refused', lambda: refused(lambda:
         target.parameter_wrapper_shape(WRAPPER.replace(b'exec "$@"', b'exec $@'))))
    case('unicode_line_separator_is_not_shell_newline', lambda: refused(lambda:
         target.parameter_wrapper_shape(WRAPPER.replace(b'\n', '\u2028'.encode()))))
    case('unquoted_semicolon_refused', lambda: refused(lambda:
         target.literal_environment(ENVIRONMENT.replace(b'SYNTHETIC_00=alpha', b'SYNTHETIC_00=alpha;true'))))
    case('command_substitution_refused', lambda: refused(lambda:
         target.literal_environment(ENVIRONMENT.replace(b'SYNTHETIC_00=alpha', b'SYNTHETIC_00=$(true)'))))
    case('quoted_assignment_name_refused', lambda: refused(lambda:
         target.literal_environment(ENVIRONMENT.replace(b'HOME=', b'"HOME"='))))
    case('adjacent_hash_does_not_truncate_actual_home', lambda: refused(lambda:
         target.literal_environment(ENVIRONMENT.replace(b'HOME=/Users/qianqi', b'HOME=/Users/qianqi#different'))))
    case('unqualified_inline_comment_refused', lambda: refused(lambda:
         target.literal_environment(ENVIRONMENT.replace(b'SYNTHETIC_00=alpha', b'SYNTHETIC_00=alpha # comment'))))
    case('duplicate_assignment_refused', lambda: refused(lambda:
         target.literal_environment(ENVIRONMENT + b'export HOME=/Users/qianqi\n')))
    case('missing_assignment_refused', lambda: refused(lambda:
         target.literal_environment(ENVIRONMENT.replace(b'export SYNTHETIC_00=alpha\n', b''))))
    case('preexisting_config_selector_refused', lambda: refused(lambda:
         target.literal_environment(ENVIRONMENT.replace(b'SYNTHETIC_00=alpha', b'OPENCLAW_CONFIG_PATH=/synthetic'))))
    case('runtime_node_override_refused', lambda: refused(lambda:
         target.literal_environment(ENVIRONMENT.replace(b'SYNTHETIC_00=alpha', b'NODE_OPTIONS=--inspect'))))

    def changed_private_bytes():
        values = list(inputs())
        values[4] += b'# appended\n'
        refused(lambda: target.make_parameter_wrapper_fallback(*values))

    case('private_source_whole_bytes_binding_refused_when_changed', changed_private_bytes)

    def changed_loaded_argv():
        values = list(inputs())
        values[2]['loadedSecond']['arguments'][2] = '/Users/qianqi/other.private'
        refused(lambda: target.make_parameter_wrapper_fallback(*values))

    case('same_parent_two_loaded_arguments_required', changed_loaded_argv)

    def hidden_runtime_selector():
        values = list(inputs())
        values[2]['loadedSecond']['observedEnvironmentScope']['registered']['OPENCLAW_PROFILE'] = 'other'
        refused(lambda: target.make_parameter_wrapper_fallback(*values))

    case('loaded_runtime_profile_override_refused', hidden_runtime_selector)

    def malformed_private_config():
        values = list(inputs())
        values[0] = b'{"plugins":{},"plugins":{}}'
        values[2]['configSha256'] = target.sha(values[0])
        refused(lambda: target.make_parameter_wrapper_fallback(*values))

    case('duplicate_json_keys_refused', malformed_private_config)

    def shell_case(with_final_newline):
        values = list(inputs())
        if not with_final_newline:
            values[4] = values[4].rstrip(b'\n')
            values[5]['environmentSha256'] = target.sha(values[4])
        prepared = target.make_parameter_wrapper_fallback(*values)
        decoded, exported = target.literal_environment(values[4])
        expected = {name: value for name, value in decoded.items() if exported[name]}
        expected.update(target.SELECTORS)
        probe = ('import json,os,sys; keys=json.loads(sys.argv[1]); '
                 'print(json.dumps({"environment":{k:os.environ[k] for k in keys if k in os.environ},'
                 '"arguments":sys.argv[2:]},sort_keys=True))')
        with tempfile.TemporaryDirectory(prefix='heptabao-wrapper-synthetic-') as tmp:
            root = Path(tmp)
            script = root / 'wrapper.sh'
            environment = root / 'environment.private'
            script.write_bytes(WRAPPER)
            environment.write_bytes(prepared['environmentBytes'])
            environment.chmod(0o600)
            argv = ['/bin/sh', str(script), str(environment), sys.executable, '-c', probe,
                    json.dumps(sorted(set(decoded) | set(target.SELECTORS))),
                    'argument with spaces', '*.literal', 'semicolon;literal']
            complete = subprocess.run(argv, env={'PATH': '/usr/bin:/bin'}, cwd=root,
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, timeout=5, check=False)
            assert complete.returncode == 0 and complete.stderr == b''
            output = json.loads(complete.stdout)
            assert output == {'environment': expected,
                              'arguments': ['argument with spaces', '*.literal', 'semicolon;literal']}
            children.append({'originalWaitKnown': True, 'returncode': complete.returncode,
                             'stdoutComplete': True, 'stderrBytes': 0,
                             'syntheticShellExecOnly': True})

    case('actual_local_sh_literal_exports_and_quoted_forwarding', lambda: shell_case(True))
    case('actual_local_sh_no_final_newline_selector_suffix', lambda: shell_case(False))
    result = {'schema': 'heptabao.parameter-wrapper-fallback.local-qualification.r1',
              'ok': True, 'passed': len(cases), 'cases': cases, 'children': children,
              'elapsedSeconds': time.monotonic() - started, 'actualMacQualified': False,
              'actualSdkQualified': False, 'currentPrivateInputsRead': False,
              'productionServiceActions': 0, 'providerCalls': 0, 'sqlConnections': 0}
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
