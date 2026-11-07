#!/usr/bin/env python3
"""Pure fallback for the one observed parameter-file shell wrapper.

This accepts only the measured eight-line program: set -eu, a quoted $1
assignment, one shift, a regular-file conditional source, then exec "$@".
The original environment file is copied privately without changing its bytes;
four literal selectors are appended, and only argv[2] points to that fixed copy.
There is no general shell interpreter, subprocess, filesystem or network call.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import PurePosixPath
import plistlib
import re
import shlex

import mac_gateway_local_fallback_r1 as original

ROOT = '/Users/qianqi/heptabao-authbus-writer-maintenance-20261106-r1'
SAFE_ENVIRONMENT = ROOT + '/local-sdk-fallback.environment.private'
SELECTORS = {
    'HOME': '/Users/qianqi',
    'OPENCLAW_HOME': '/Users/qianqi',
    'OPENCLAW_STATE_DIR': '/Users/qianqi/.openclaw',
    'OPENCLAW_CONFIG_PATH': ROOT + '/local-sdk-fallback.private.json',
}
FORBIDDEN = ('OPENCLAW_PROFILE', 'NODE_OPTIONS', 'NODE_PATH', 'OPENCLAW_AUTH_STORE_READONLY',
             'OPENCLAW_TEST_FAST', 'OPENCLAW_INCLUDE_ROOTS', 'OPENCLAW_PACKAGE_DIR',
             'OPENCLAW_AGENT_DIR', 'OPENCLAW_WORKSPACE_DIR', 'PI_CODING_AGENT_DIR',
             'OPENCLAW_LOAD_SHELL_ENV', 'OPENCLAW_DEFER_SHELL_ENV_FALLBACK')


class WrapperRefused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise WrapperRefused(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def normalized_home_path(value):
    return (isinstance(value, str) and 0 < len(value) <= 4096 and '\x00' not in value
            and value.startswith('/Users/qianqi/') and str(PurePosixPath(value)) == value
            and '..' not in PurePosixPath(value).parts)


def parameter_wrapper_shape(raw):
    need(isinstance(raw, bytes) and 0 < len(raw) <= 65536 and b'\x00' not in raw and b'\r' not in raw,
         'wrapper_bounded_literal_source')
    try:
        lines = raw.decode('utf-8', 'strict').split('\n')
        if lines[-1] == '':
            lines.pop()
        lines = [line.strip(' \t') for line in lines]
    except UnicodeError as error:
        raise WrapperRefused('wrapper_utf8_source') from error
    need(len(lines) == 8 and lines[0] == '#!/bin/sh' and lines[1] == 'set -eu'
         and lines[3] == 'shift' and lines[6] == 'fi' and lines[7] == 'exec "$@"',
         'wrapper_exact_eight_line_original_program')
    match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]{0,63})="\$1"', lines[2])
    need(match is not None, 'wrapper_exact_quoted_first_argument')
    variable = match.group(1)
    need(lines[4] == 'if [ -f "$' + variable + '" ]; then'
         and lines[5] == '. "$' + variable + '"',
         'wrapper_exact_regular_file_source_same_variable')
    return {'lineCount': 8, 'quotedFirstArgumentOnly': True, 'shiftsOnce': True,
            'sourcesOneRegularFile': True, 'executesRemainingQuotedArguments': True,
            'generalShellSupport': False}


def literal_environment(raw, *, expected_count=13):
    need(isinstance(raw, bytes) and 0 < len(raw) <= 65536 and b'\x00' not in raw and b'\r' not in raw,
         'wrapper_bounded_literal_environment')
    try:
        text = raw.decode('utf-8', 'strict')
    except UnicodeError as error:
        raise WrapperRefused('wrapper_utf8_environment') from error
    values, exported, autoexport = {}, {}, False
    for line in text.split('\n'):
        line = line.strip(' \t')
        if not line or line.startswith('#'):
            continue
        if line in ('set -a', 'set +a'):
            autoexport = line == 'set -a'
            continue
        # Conservatively reject expansion even inside quotes. No observed
        # current line needs shell expansion, command substitution or tilde.
        need(not any(char in line for char in ('$', '`', '~')), 'wrapper_no_dynamic_environment_expansion')
        assignment = re.fullmatch(r'(?:(export)[ \t]+)?([A-Za-z_][A-Za-z0-9_]{0,255})=(.*)', line)
        need(assignment is not None, 'wrapper_literal_unquoted_assignment_name')
        lexer = shlex.shlex(line, posix=True, punctuation_chars=';&|()<>')
        lexer.whitespace_split = True
        # In a shell assignment, an adjacent # is part of the word. Treating
        # it as a shlex comment could admit a different actual HOME value.
        # Full-line comments are already handled; inline comment syntax is
        # conservatively refused instead of erasing quote provenance.
        lexer.commenters = ''
        try:
            tokens = list(lexer)
        except ValueError as error:
            raise WrapperRefused('wrapper_environment_literal_lexing') from error
        export = autoexport
        if tokens and tokens[0] == 'export':
            export = True
            tokens = tokens[1:]
        need(len(tokens) == 1 and '=' in tokens[0], 'wrapper_only_single_literal_assignment')
        name, value = tokens[0].split('=', 1)
        need(name == assignment.group(2)
             and name not in values and len(value.encode()) <= 16384,
             'wrapper_unique_bounded_literal_variable')
        values[name], exported[name] = value, export
    need(len(values) == expected_count, 'wrapper_current_thirteen_literal_assignments')
    need(values.get('HOME') == SELECTORS['HOME'] and not any(name in values for name in FORBIDDEN),
         'wrapper_original_literal_home_and_no_runtime_override')
    # Current evidence has no other selector. Do not silently overwrite a new
    # alternate selector if this fixed source generation has since changed.
    need(not any(name in values for name in ('OPENCLAW_HOME', 'OPENCLAW_STATE_DIR', 'OPENCLAW_CONFIG_PATH')),
         'wrapper_original_absent_additional_selectors')
    return values, exported


def make_parameter_wrapper_fallback(config_bytes, plist_bytes, gateway_binding,
                                    wrapper_bytes, environment_bytes, source_binding):
    need(isinstance(gateway_binding, dict)
         and gateway_binding.get('schema') == 'heptabao.current-gateway-private-restore-inputs.r1'
         and gateway_binding.get('observationSchema') == 'heptabao.current-gateway-observation.private.r2'
         and gateway_binding.get('target') == original.TARGET
         and gateway_binding.get('configPath') == original.CONFIG
         and gateway_binding.get('plistPath') == original.PLIST,
         'wrapper_exact_current_gateway_binding')
    need(isinstance(config_bytes, bytes) and 0 < len(config_bytes) <= 1048576
         and isinstance(plist_bytes, bytes) and 0 < len(plist_bytes) <= 262144,
         'wrapper_bounded_original_configuration_and_plist')
    need(sha(config_bytes) == gateway_binding.get('configSha256')
         and sha(plist_bytes) == gateway_binding.get('plistSha256'),
         'wrapper_same_private_original_configuration_and_plist')
    need(isinstance(source_binding, dict)
         and source_binding.get('schema') == 'heptabao.current-parameter-wrapper.private.r1',
         'wrapper_exact_private_source_binding_schema')
    cfg, plist = original.strict_json(config_bytes), plistlib.loads(plist_bytes)
    need(isinstance(plist, dict) and plist.get('Label') == original.LABEL,
         'wrapper_same_original_registered_label')
    args = plist.get('ProgramArguments')
    need(isinstance(args, list) and len(args) == 8 and all(isinstance(item, str) for item in args)
         and args == gateway_binding.get('arguments')
         == gateway_binding.get('loadedFirst', {}).get('arguments')
         == gateway_binding.get('loadedSecond', {}).get('arguments')
         == source_binding.get('arguments'), 'wrapper_same_loaded_original_arguments')
    need(args[0] == '/bin/sh' and plist.get('Program', args[0]) == '/bin/sh'
         and normalized_home_path(args[1]) and args[1].endswith('.sh')
         and normalized_home_path(args[2])
         and args[3:] == ['/opt/homebrew/opt/node/bin/node', original.SDK + '/dist/index.js',
                         'gateway', '--port', '18789'], 'wrapper_exact_registered_script_and_node_tail')
    need(source_binding.get('wrapperPath') == args[1]
         and source_binding.get('environmentPath') == args[2]
         and source_binding.get('wrapperSha256') == sha(wrapper_bytes)
         and source_binding.get('environmentSha256') == sha(environment_bytes),
         'wrapper_same_private_complete_script_and_environment_bytes')
    shape = parameter_wrapper_shape(wrapper_bytes)
    values, exported = literal_environment(environment_bytes)
    env = plist.get('EnvironmentVariables', {})
    need(isinstance(env, dict) and env == gateway_binding.get('environment')
         and all(isinstance(key, str) and isinstance(value, str) for key, value in env.items()),
         'wrapper_same_original_plist_environment')
    expected_old = {'HOME': original.HOME, 'OPENCLAW_HOME': original.HOME,
                    'OPENCLAW_STATE_DIR': original.LIVE, 'OPENCLAW_CONFIG_PATH': original.CONFIG}
    layers = gateway_binding.get('loadedSecond', {}).get('observedEnvironmentScope')
    need(isinstance(layers, dict) and all(isinstance(value, dict) for value in layers.values()),
         'wrapper_original_loaded_environment_layers')
    for layer in (env, *layers.values()):
        need(not any(name in layer for name in FORBIDDEN)
             and all(name not in layer or layer[name] == expected for name, expected in expected_old.items()),
             'wrapper_current_loaded_environment_selector_scope')
    entries = cfg.get('plugins', {}).get('entries')
    need(isinstance(entries, dict) and isinstance(entries.get(original.PLUGIN), dict)
         and entries[original.PLUGIN].get('enabled') is True,
         'wrapper_original_enabled_authbus_entry')
    new_cfg = copy.deepcopy(cfg)
    new_cfg['plugins']['entries'][original.PLUGIN]['enabled'] = False
    new_plist = copy.deepcopy(plist)
    new_plist['ProgramArguments'][2] = SAFE_ENVIRONMENT
    new_plist.setdefault('EnvironmentVariables', {}).update(SELECTORS)
    suffix = ''.join('export ' + key + '=' + shlex.quote(value) + '\n' for key, value in SELECTORS.items()).encode()
    safe_environment = environment_bytes + (b'' if environment_bytes.endswith(b'\n') else b'\n') + suffix
    safe_config = original.canonical_json(new_cfg) + b'\n'
    safe_plist = plistlib.dumps(new_plist, fmt=plistlib.FMT_XML, sort_keys=True)
    need(len(safe_environment) <= 65536 and len(safe_config) <= 1048576 and len(safe_plist) <= 262144,
         'wrapper_bounded_safe_private_outputs')
    return {'configBytes': safe_config, 'plistBytes': safe_plist, 'environmentBytes': safe_environment,
            'wrapperSourceBytes': wrapper_bytes, 'originalLiteralValues': values,
            'originalLiteralExportFlags': exported,
            'public': {'schema': 'heptabao.parameter-wrapper-fallback.prepared.public.r1',
                       'preparedOnly': True, 'originalWrapperShape': shape,
                       'originalEnvironmentBytePrefixPreserved': True,
                       'originalLiteralEnvironmentCount': 13, 'fixedSelectorExportCount': 4,
                       'onlyOriginalEnvironmentArgumentRebound': True,
                       'nodeSdkEntryAndPortArgumentsUnchanged': True,
                       'otherConfigurationValuesUnchanged': True,
                       'authbusExplicitlyDisabled': True,
                       'actualShellExecutionQualified': False,
                       'actualCurrentSdkSelectionQualified': False,
                       'productionFallbackQualified': False,
                       'serviceMutations': 0, 'providerCalls': 0,
                       'credentialOrConfigurationValuesOrDigestsPublished': False}}

