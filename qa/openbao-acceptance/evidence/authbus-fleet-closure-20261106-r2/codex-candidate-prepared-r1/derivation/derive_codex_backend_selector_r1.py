#!/usr/bin/env python3
"""Narrow source-derived correction; original R4 evidence is unchanged."""
from pathlib import Path
import difflib
import hashlib
import json

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'mac-finite-codex-selectors-r4-work/mac_procargs_selectors_r4.py'
EXPECTED = '95ef98e789b17c4d66e4603f2c93d7f96844f6fbcbbba0ae2b997c0752aff8a9'
raw = SOURCE.read_bytes()
assert hashlib.sha256(raw).hexdigest() == EXPECTED
source = raw.decode()

def replace(old, new):
    global source
    assert source.count(old) == 1
    source = source.replace(old, new)

replace("    profile = None\n", "    profile = None\n    profile_v2 = None\n")
replace("        elif value == b'app-server':\n", """        elif value == b'--profile-v2' or value.startswith(b'--profile-v2='):
            if value.startswith(b'--profile-v2='):
                selected = value[len(b'--profile-v2='):]
            else:
                i += 1
                need(i < len(argv), 'selector_profile_v2_value_present')
                selected = argv[i]
            need(profile_v2 is None, 'selector_duplicate_profile_v2_selection')
            profile_v2 = text(selected, maximum=256)
            need(bool(profile_v2), 'selector_profile_v2_nonempty')
        elif value == b'app-server':
""")
replace("if key.strip() == b'cli_auth_credentials_store_mode' and separator:",
        "if key.strip() == b'cli_auth_credentials_store' and separator:")
replace("        'profileSelectionPresent': profile is not None,\n",
        "        'profileSelectionPresent': profile is not None,\n"
        "        'profileV2SelectionPresent': profile_v2 is not None,\n"
        "        'configurationKeyBoundToOfficialV0133Source': True,\n")
replace("        'profileSelector': profile, 'storageModeOverride': overrides[0] if overrides else None,\n",
        "        'profileSelector': profile, 'profileV2Selector': profile_v2,\n"
        "        'storageModeOverride': overrides[0] if overrides else None,\n")
source = source.replace('No filesystem, process, credential-store, or network operation occurs here.',
    'No filesystem, process, credential-store, or network operation occurs here.\n'
    'Backend selector correction: official openai/codex rust-v0.133.0,\n'
    'config_toml.rs a4d384b5f39e3d56d252afa6dd0437c02469aab8 and\n'
    'cli/main.rs 95873191b936aa338043e57c59a86c411c7bee96. The previous\n'
    'R4 report remains candidate-only and is never retroactively upgraded.')
target = HERE / 'mac_codex_backend_procargs_r1.py'
assert not target.exists()
target.write_text(source)
compile(source, str(target), 'exec')
(HERE / 'codex-backend-procargs-r4-to-r1.diff').write_text(''.join(difflib.unified_diff(
    raw.decode().splitlines(True), source.splitlines(True), fromfile=SOURCE.name, tofile=target.name)))
print(json.dumps({'source': target.name, 'bytes': len(source.encode()),
    'sha256': hashlib.sha256(source.encode()).hexdigest(), 'originalR4Unchanged': True,
    'actualProcessesObserved': 0, 'authFilesRead': 0}))
