"""Bounded Darwin procargs parsing, retaining only finite source selectors.

Layout references (not copied implementations): Apple's adv_cmds ps/print.c
getproclline, blob a6f02a86eb29dec5dc39e54ff3692f191c203879, and XNU
bsd/kern/kern_sysctl.c, blob 1e9baecfcbe6e56d8deac42fe59022266ab7db46.
The latter may omit all environment strings for restricted signed processes.
An absent environment section therefore never proves a missing selector.
No filesystem, process, credential-store, or network operation occurs here.
"""
from __future__ import annotations

import re
import struct

# The kernel string budget plus the KERN_PROCARGS2 argc word.
MAX_BYTES = 262144 + 4
MAX_ARGC = 512
MAX_ENVIRON = 4096
PATH_KEYS = (b'HOME', b'CODEX_HOME', b'OPENCLAW_STATE_DIR', b'OPENCLAW_CONFIG_PATH')
PRESENCE_KEYS = (b'OPENAI_API_KEY', b'CODEX_API_KEY', b'CODEX_ACCESS_TOKEN',
                 b'CODEX_MANAGED_BY_NPM', b'CODEX_MANAGED_BY_BUN')
STORAGE_MODES = frozenset(('file', 'keyring', 'auto', 'ephemeral'))
NODE_ENTRY = '/opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js'


class SelectorRefused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise SelectorRefused(code)


def text(raw, *, maximum=4096):
    need(isinstance(raw, bytes) and len(raw) <= maximum, 'selector_value_bound')
    try:
        result = raw.decode('utf-8', errors='strict')
    except UnicodeError:
        raise SelectorRefused('selector_value_utf8') from None
    need(not any(ord(c) < 32 or ord(c) == 127 for c in result), 'selector_value_no_control')
    return result


def parse_procargs(raw):
    need(type(raw) is bytes and 6 <= len(raw) <= MAX_BYTES, 'selector_procargs_bounded_bytes')
    argc = struct.unpack_from('=i', raw)[0]
    need(1 <= argc <= MAX_ARGC, 'selector_procargs_argc_bound')
    at = 4

    def take():
        nonlocal at
        end = raw.find(b'\0', at)
        need(end >= at, 'selector_procargs_complete_nul_string')
        value = raw[at:end]
        at = end + 1
        return value

    executable = text(take())
    need(executable.startswith('/'), 'selector_saved_executable_absolute')
    while at < len(raw) and raw[at] == 0:
        at += 1
    need(at < len(raw), 'selector_procargs_first_argument_present')
    argv = [take() for _ in range(argc)]
    need(bool(argv[0]), 'selector_procargs_nonempty_argv0')
    selectors, presence = {}, {}
    environ_count = 0
    while at < len(raw) and raw[at] != 0:
        value = take()
        environ_count += 1
        need(environ_count <= MAX_ENVIRON, 'selector_environment_count_bound')
        key, separator, contents = value.partition(b'=')
        need(separator == b'=' and bool(key), 'selector_environment_entry_shape')
        if key in PATH_KEYS:
            decoded_key = key.decode('ascii')
            need(decoded_key not in selectors, 'selector_duplicate_path_environment_key')
            selectors[decoded_key] = text(contents)
        elif key in PRESENCE_KEYS:
            decoded_key = key.decode('ascii')
            need(decoded_key not in presence, 'selector_duplicate_presence_environment_key')
            presence[decoded_key] = True
        # All other key names and all credential-bearing values are discarded.
    # XNU's restricted-process path can end immediately after argv. With a
    # returned environment section, every entry must terminate within the
    # returned buffer. Its last NUL may end the buffer; any remaining padding
    # must be zero. No heuristic reads beyond an ambiguous envelope.
    need(not any(raw[at:]), 'selector_procargs_zero_tail')

    overrides = []
    unknown_override_count = 0
    profile = None
    exact_app_server = False
    exact_node_entry = False
    other_arguments = 0
    i = 1
    while i < len(argv):
        value = argv[i]
        assignment = None
        if value == b'--':
            other_arguments += len(argv) - i - 1
            break
        if value in (b'-c', b'--config'):
            i += 1
            need(i < len(argv), 'selector_config_override_value_present')
            assignment = argv[i]
        elif value.startswith(b'--config='):
            assignment = value[len(b'--config='):]
        elif value.startswith(b'-c') and len(value) > 2 and b'=' in value[2:]:
            assignment = value[2:]
        elif value in (b'-p', b'--profile') or value.startswith(b'--profile='):
            if value.startswith(b'--profile='):
                selected = value[len(b'--profile='):]
            else:
                i += 1
                need(i < len(argv), 'selector_profile_value_present')
                selected = argv[i]
            need(profile is None, 'selector_duplicate_profile_selection')
            profile = text(selected, maximum=256)
            need(bool(profile), 'selector_profile_nonempty')
        elif value == b'app-server':
            exact_app_server = True
        elif value == NODE_ENTRY.encode():
            exact_node_entry = True
        else:
            other_arguments += 1
        if assignment is not None:
            key, separator, contents = assignment.partition(b'=')
            if key.strip() == b'cli_auth_credentials_store_mode' and separator:
                try:
                    mode = contents.strip().decode('ascii')
                except UnicodeError:
                    mode = ''
                if len(mode) >= 2 and mode[0] == mode[-1] and mode[0] in ('\"', "'"):
                    mode = mode[1:-1]
                need(mode in STORAGE_MODES, 'selector_storage_mode_override_exact_enum')
                overrides.append(mode)
            else:
                unknown_override_count += 1
        i += 1
    need(len(overrides) <= 1, 'selector_storage_mode_override_unambiguous')

    available = environ_count > 0
    selected = selectors.get('CODEX_HOME') if available else None
    home = selectors.get('HOME') if available else None
    candidate = None
    if selected and selected.startswith('/') and '..' not in selected.split('/'):
        candidate = {'kind': 'observed_absolute_codex_home', 'path': selected}
    elif available and not selected and home and home.startswith('/') and '..' not in home.split('/'):
        candidate = {'kind': 'default_candidate_from_observed_home', 'path': home.rstrip('/') + '/.codex'}
    # Candidate strings are not filesystem opens or proof of active credential
    # storage. Native version/config/backend validation remains a later gate.
    public = {
        'argc': argc, 'environmentEntriesReturned': environ_count,
        'environmentSectionState': 'entries_returned' if available else 'unavailable_or_empty',
        'missingEnvironmentTreatedAsDefault': False,
        'selectorPresence': {key.decode(): (key.decode() in selectors if available else None) for key in PATH_KEYS},
        'credentialEnvironmentPresence': {key.decode(): (key.decode() in presence if available else None) for key in PRESENCE_KEYS[:3]},
        'exactAppServerArgumentObserved': exact_app_server,
        'exactInstalledNodeWrapperArgumentObserved': exact_node_entry,
        'recognizedStorageModeOverride': overrides[0] if overrides else None,
        'otherConfigurationOverrides': unknown_override_count,
        'profileSelectionPresent': profile is not None,
        'otherArgumentsNotRetained': other_arguments,
        'candidateHomeKind': candidate['kind'] if candidate else 'unresolved',
        'effectiveCredentialBackendQualified': False,
        'selectedCredentialFileOpened': False,
    }
    private = {
        'savedExecutable': executable, 'selectors': selectors, 'presenceOnly': presence,
        'profileSelector': profile, 'storageModeOverride': overrides[0] if overrides else None,
        'candidateHome': candidate,
    }
    return {'private': private, 'public': public}
