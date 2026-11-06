#!/usr/bin/env python3
"""Pure, bounded preparation for the one registered Mac gateway's local fallback.

No file, process, provider, or service operation occurs in this module. The
production owner must bind the exact private original bytes, qualify the actual
SDK's disabled-plugin semantics, and publish the returned bytes under its own
once journal before any service action. A prepared plan is not a deployed or
observed runtime configuration.
"""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import PurePosixPath
import plistlib
import re
import shlex

LIVE = '/Users/qianqi/.openclaw'
HOME = '/Users/qianqi'
LABEL = 'ai.openclaw.gateway'
TARGET = 'gui/501/' + LABEL
PLIST = HOME + '/Library/LaunchAgents/' + LABEL + '.plist'
CONFIG = LIVE + '/openclaw.json'
SDK = '/opt/homebrew/lib/node_modules/openclaw'
MAINTENANCE = HOME + '/heptabao-authbus-writer-maintenance-20261106-r1'
FALLBACK_CONFIG = MAINTENANCE + '/local-sdk-fallback.private.json'
PLUGIN = 'openclaw-authbus'


class Refused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(',', ':')).encode()


def strict_json(raw):
    need(isinstance(raw, bytes) and 0 < len(raw) <= 1048576,
         'fallback_bounded_private_json_bytes')

    def unique(items):
        out = {}
        for key, value in items:
            need(key not in out, 'fallback_duplicate_json_key')
            out[key] = value
        return out

    def invalid_constant(_):
        raise Refused('fallback_nonfinite_json_constant')

    try:
        value = json.loads(raw.decode('utf-8', 'strict'),
                           object_pairs_hook=unique,
                           parse_constant=invalid_constant)
    except Refused:
        raise
    except Exception as error:
        raise Refused('fallback_private_json_parse') from error
    need(isinstance(value, dict), 'fallback_private_json_object')
    return value


def transparent_gateway_argv(arguments):
    """Match only the previously observed eight-position public entry shape.

    The private script is lexed in memory and is never returned in a receipt.
    No shell startup file or environment assignment is admitted. This function
    does not infer the shape from the unresolved argv R3 invocation.
    """
    need(isinstance(arguments, list) and len(arguments) == 8
         and all(isinstance(x, str) and len(x) <= 16384 for x in arguments),
         'fallback_exact_registered_eight_arguments')
    need(arguments[0] == '/bin/sh', 'fallback_exact_shell_program')
    flags = arguments[1]
    need(2 <= len(flags) <= 8 and flags.startswith('-')
         and 'c' in flags[1:] and set(flags[1:]) <= set('cef')
         and len(set(flags[1:])) == len(flags[1:]),
         'fallback_nonlogin_finite_shell_switches')
    lexer = shlex.shlex(arguments[2], posix=True, punctuation_chars=';&|()<>')
    lexer.whitespace_split = True
    lexer.commenters = ''
    try:
        tokens = list(lexer)
    except ValueError as error:
        raise Refused('fallback_shell_lexing') from error
    accepted = (
        ['ulimit', '-n', '65536', ';', 'exec', '$0', '$@'],
        ['ulimit', '-n', '65536', '&&', 'exec', '$0', '$@'],
        ['exec', '$0', '$@'],
    )
    need(tokens in accepted, 'fallback_exact_transparent_exec_script')
    # shlex erases quote provenance: single-quoted '$0' is a literal, and an
    # unquoted $@ has different argument semantics. Preserve the exact safe
    # double-quoted expansion contract instead of admitting token equality.
    need(re.fullmatch(r'\s*(?:ulimit\s+-n\s+65536\s*(?:;|&&)\s*)?'
                      r'exec\s+"\$0"\s+"\$@"\s*', arguments[2]) is not None,
         'fallback_exact_quoted_argument_forwarding')
    need(arguments[3] == '/opt/homebrew/opt/node/bin/node'
         and arguments[4] == SDK + '/dist/index.js'
         and arguments[5:] == ['gateway', '--port', '18789'],
         'fallback_exact_registered_node_entry_port')
    return {'argumentCount': 8, 'knownNonloginShell': True,
            'transparentExecPattern': True,
            'setsFiniteFileDescriptorLimit': tokens[0] == 'ulimit',
            'explicitGatewayPort': 18789,
            'privateArgumentsPublished': False}


def make_fallback(original_config, original_plist, original_binding):
    """Return private config/plist bytes after exact source-record comparison.

    original_binding is the original private lineage record. Its hashes remain
    private and are never included in this module's public projection.
    """
    need(isinstance(original_binding, dict)
         and original_binding.get('schema') ==
         'heptabao.current-gateway-private-restore-inputs.r1'
         and original_binding.get('target') == TARGET
         and original_binding.get('configPath') == CONFIG
         and original_binding.get('plistPath') == PLIST,
         'fallback_exact_registered_private_restore_scope')
    need(isinstance(original_plist, bytes) and 0 < len(original_plist) <= 262144,
         'fallback_bounded_original_plist')
    need(isinstance(original_config, bytes) and 0 < len(original_config) <= 1048576,
         'fallback_bounded_original_configuration')
    need(sha(original_config) == original_binding.get('configSha256')
         and sha(original_plist) == original_binding.get('plistSha256'),
         'fallback_exact_original_private_bytes')
    cfg = strict_json(original_config)
    try:
        plist = plistlib.loads(original_plist)
    except Exception as error:
        raise Refused('fallback_original_plist_parse') from error
    need(isinstance(plist, dict) and plist.get('Label') == LABEL,
         'fallback_exact_plist_label')
    argv = plist.get('ProgramArguments')
    need(argv == original_binding.get('arguments')
         == original_binding.get('loadedFirst', {}).get('arguments')
         == original_binding.get('loadedSecond', {}).get('arguments'),
         'fallback_same_original_loaded_arguments')
    need(plist.get('Program', argv[0] if isinstance(argv, list) and argv else None)
         == '/bin/sh', 'fallback_same_original_loaded_program')
    argv_projection = transparent_gateway_argv(argv)
    env = plist.get('EnvironmentVariables', {})
    need(isinstance(env, dict)
         and all(isinstance(k, str) and isinstance(v, str)
                 for k, v in env.items())
         and env == original_binding.get('environment'),
         'fallback_original_environment_private_binding')
    expected = {'HOME': HOME, 'OPENCLAW_STATE_DIR': LIVE,
                'OPENCLAW_CONFIG_PATH': CONFIG, 'OPENCLAW_HOME': HOME}
    need(all(k not in env or env[k] == value for k, value in expected.items())
         and 'OPENCLAW_PROFILE' not in env,
         'fallback_original_registered_environment_scope')
    # Reject a hidden preload or alternate configuration-selector capability.
    # Existing unrelated original environment values are otherwise preserved.
    need('NODE_OPTIONS' not in env and 'NODE_PATH' not in env
         and 'OPENCLAW_AUTH_STORE_READONLY' not in env,
         'fallback_no_unqualified_runtime_override')
    plugins = cfg.get('plugins')
    need(isinstance(plugins, dict) and isinstance(plugins.get('entries'), dict)
         and isinstance(plugins['entries'].get(PLUGIN), dict)
         and plugins['entries'][PLUGIN].get('enabled') is True,
         'fallback_original_enabled_authbus_entry')
    fallback = copy.deepcopy(cfg)
    fallback['plugins']['entries'][PLUGIN]['enabled'] = False
    safe_plist = copy.deepcopy(plist)
    safe_plist.setdefault('EnvironmentVariables', {}).update({
        'HOME': HOME, 'OPENCLAW_STATE_DIR': LIVE,
        'OPENCLAW_CONFIG_PATH': FALLBACK_CONFIG})
    config_bytes = (json.dumps(fallback, ensure_ascii=False, allow_nan=False,
                               sort_keys=True, separators=(',', ':')) + '\n').encode()
    plist_bytes = plistlib.dumps(safe_plist, fmt=plistlib.FMT_XML, sort_keys=True)
    need(len(config_bytes) <= 1048576 and len(plist_bytes) <= 262144,
         'fallback_bounded_generated_private_artifacts')
    validate_fallback(cfg, plist, config_bytes, plist_bytes)
    return {'configBytes': config_bytes, 'plistBytes': plist_bytes,
            'public': {'schema': 'heptabao.gateway-local-fallback-prepared.r1',
                       'preparedOnly': True, 'configurationChangeCount': 1,
                       'authbusExplicitlyDisabled': True,
                       'otherConfigurationValuesUnchanged': True,
                       'originalArgumentsPreserved': True,
                       'explicitCurrentLocalSdkState': True,
                       'safePrivateConfigurationPathBound': True,
                       'originalPlistOtherFieldsPreserved': True,
                       'actualSdkDisabledSemanticsQualified': False,
                       'runningConfigurationObserved': False,
                       'serviceMutations': 0, 'providerCalls': 0,
                       'credentialValuesOrDigestsPublished': False,
                       'configurationValuesOrDigestsPublished': False,
                       'argv': argv_projection}}


def validate_fallback(original_config_value, original_plist_value,
                      fallback_config, fallback_plist):
    cfg = strict_json(fallback_config)
    try:
        plist = plistlib.loads(fallback_plist)
    except Exception as error:
        raise Refused('fallback_generated_plist_parse') from error
    expected_cfg = copy.deepcopy(original_config_value)
    need(isinstance(expected_cfg, dict)
         and isinstance(expected_cfg.get('plugins'), dict)
         and isinstance(expected_cfg['plugins'].get('entries'), dict)
         and isinstance(expected_cfg['plugins']['entries'].get(PLUGIN), dict),
         'fallback_validation_original_entry_shape')
    expected_cfg['plugins']['entries'][PLUGIN]['enabled'] = False
    need(canonical_json(cfg) == canonical_json(expected_cfg)
         and cfg['plugins']['entries'][PLUGIN].get('enabled') is False,
         'fallback_only_authbus_enabled_field_changes')
    expected_plist = copy.deepcopy(original_plist_value)
    need(isinstance(expected_plist, dict)
         and isinstance(expected_plist.get('EnvironmentVariables', {}), dict),
         'fallback_validation_original_environment_shape')
    expected_plist.setdefault('EnvironmentVariables', {}).update({
        'HOME': HOME, 'OPENCLAW_STATE_DIR': LIVE,
        'OPENCLAW_CONFIG_PATH': FALLBACK_CONFIG})
    need(plistlib.dumps(plist, fmt=plistlib.FMT_BINARY, sort_keys=True)
         == plistlib.dumps(expected_plist, fmt=plistlib.FMT_BINARY, sort_keys=True)
         and plist.get('Label') == LABEL
         and str(PurePosixPath(FALLBACK_CONFIG)) == FALLBACK_CONFIG,
         'fallback_only_exact_environment_scope_changes')
    transparent_gateway_argv(plist.get('ProgramArguments'))
    return True
