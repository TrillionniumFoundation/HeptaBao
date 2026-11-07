#!/usr/bin/env python3
"""Synthetic framing/privacy checks; no actual process observation."""
import json
from pathlib import Path
import struct
from mac_procargs_selectors_r3 import parse_procargs, SelectorRefused, MAX_BYTES

SECRET = 'SYNTHETIC_CREDENTIAL_AND_PROMPT_MUST_NOT_BE_RETAINED'
results = []


def block(args, env=(), *, tail=b'\0\0', executable=b'/synthetic/codex'):
    return struct.pack('=i', len(args)) + executable + b'\0\0\0' + b'\0'.join(args) + b'\0' + b'\0'.join(env) + (b'\0' if env else b'') + tail


def check(name, callback):
    callback()
    results.append({'case': name, 'passed': True})


def refused(raw):
    try:
        parse_procargs(raw)
    except SelectorRefused:
        return
    raise AssertionError('expected refusal')


def explicit():
    result = parse_procargs(block([b'codex', b'app-server', SECRET.encode()],
        [b'HOME=/synthetic/home', b'CODEX_HOME=/synthetic/private-client',
         b'OPENAI_API_KEY=' + SECRET.encode(), b'UNRELATED=' + SECRET.encode()]))
    assert result['private']['candidateHome']['path'] == '/synthetic/private-client'
    assert result['public']['exactAppServerArgumentObserved'] is True
    assert result['public']['credentialEnvironmentPresence']['OPENAI_API_KEY'] is True
    assert SECRET not in json.dumps(result)
    assert '/synthetic/private-client' not in json.dumps(result['public'])


def default():
    result = parse_procargs(block([b'codex'], [b'HOME=/synthetic/home']))
    assert result['private']['candidateHome'] == {'kind':'default_candidate_from_observed_home','path':'/synthetic/home/.codex'}
    assert result['public']['effectiveCredentialBackendQualified'] is False


def omitted():
    result = parse_procargs(block([b'codex', b'app-server'], tail=b''))
    assert result['private']['candidateHome'] is None
    assert all(value is None for value in result['public']['selectorPresence'].values())
    assert result['public']['environmentSectionState'] == 'unavailable_or_empty'


def overrides():
    result = parse_procargs(block([b'codex', b'-c', b'cli_auth_credentials_store_mode="file"',
                                  b'--config=unknown_private_key=' + SECRET.encode()], [b'HOME=/s']))
    assert result['public']['recognizedStorageModeOverride'] == 'file'
    assert result['public']['otherConfigurationOverrides'] == 1
    assert SECRET not in json.dumps(result)


def terminator():
    result = parse_procargs(block([b'codex', b'--', b'--profile', SECRET.encode(), b'app-server']))
    assert result['private']['profileSelector'] is None
    assert result['public']['exactAppServerArgumentObserved'] is False
    assert SECRET not in json.dumps(result)


def relative():
    result = parse_procargs(block([b'codex'], [b'HOME=/s', b'CODEX_HOME=relative-client']))
    assert result['private']['candidateHome'] is None


def unrelated_utf8():
    result = parse_procargs(block([b'codex', b'\xff\xfe'], [b'HOME=/s', b'UNRELATED=\xff\xfe']))
    assert result['private']['selectors'] == {'HOME':'/s'}


def last_nul_at_eof():
    result = parse_procargs(block([b'codex'], [b'HOME=/s'], tail=b''))
    assert result['public']['environmentEntriesReturned'] == 1


def profile_private():
    result = parse_procargs(block([b'codex', b'--profile', b'synthetic-profile']))
    assert result['private']['profileSelector'] == 'synthetic-profile'
    assert 'synthetic-profile' not in json.dumps(result['public'])


def padded_empty():
    result = parse_procargs(block([b'codex']))
    assert result['private']['candidateHome'] is None
    assert all(value is None for value in result['public']['selectorPresence'].values())


check('explicit_selector_and_unrelated_secret_discard', explicit)
check('default_is_only_candidate_from_returned_HOME', default)
check('restricted_or_empty_environment_is_unknown', omitted)
check('no_environment_with_zero_tail_is_unknown', padded_empty)
check('duplicate_CODEX_HOME_refused', lambda: refused(block([b'codex'], [b'CODEX_HOME=/a',b'CODEX_HOME=/b'])))
check('missing_argument_refused', lambda: refused(struct.pack('=i',2)+b'/synthetic/codex\0codex\0'))
check('unterminated_environment_refused', lambda: refused(block([b'codex'],tail=b'HOME=/s')))
check('nonzero_after_environment_terminator_refused', lambda: refused(block([b'codex'],[b'HOME=/s'])+b'opaque'))
check('over_limit_refused', lambda: refused(b'x'*(MAX_BYTES+1)))
check('zero_argc_refused', lambda: refused(struct.pack('=i',0)+b'/x\0'))
check('only_exact_storage_enum_and_unknown_override_discard', overrides)
check('double_dash_prevents_prompt_as_selector', terminator)
check('duplicate_storage_mode_refused', lambda: refused(block([b'codex',b'-c',b'cli_auth_credentials_store_mode="file"',b'-c',b'cli_auth_credentials_store_mode="keyring"'])))
check('relative_CODEX_HOME_is_unresolved', relative)
check('unrelated_non_utf8_never_decoded_or_retained', unrelated_utf8)
check('complete_last_environment_nul_may_end_buffer', last_nul_at_eof)
check('profile_value_private_only', profile_private)
check('duplicate_presence_selector_refused', lambda: refused(block([b'codex'],[b'OPENAI_API_KEY=a',b'OPENAI_API_KEY=b'])))
check('saved_executable_must_be_absolute', lambda: refused(block([b'codex'],executable=b'codex')))
check('unknown_storage_enum_refused_without_value', lambda: refused(block([b'codex',b'-c',b'cli_auth_credentials_store_mode='+SECRET.encode()])))
report = {'schema':'heptabao.procargs-selector-local-qualification.r1','ok':True,'cases':results,
          'passed':len(results),'total':len(results),'actualMac':False,'processReads':0,'credentialReads':0}
raw = json.dumps(report,sort_keys=True,separators=(',',':'))+'\n'
(Path(__file__).parent/'selectors-local20.original.json').write_text(raw)
print(raw,end='')
