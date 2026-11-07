#!/usr/bin/env python3
"""Keep the original copier and admit explicitly pinned public executables."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
before = (ROOT / 'complete_cold_tree_backup_r1.py').read_text()
assert len(before.encode()) == 17361
assert hashlib.sha256(before.encode()).hexdigest() == '18c3e53d8bc1e0c068dd5ad0a1f0438f89abca705c54af20e61152d985916a38'
after = before

def replace(old, new):
    global after
    assert after.count(old) == 1, old
    after = after.replace(old, new)

replace('expected_manifest=None, max_files=4096, max_directories=256,',
        'expected_manifest=None, public_executables=None, max_files=4096, max_directories=256,')
replace('        self.expected = expected_manifest\n', '''        self.expected = expected_manifest
        self.public_executables = dict(public_executables or {})
        need(len(self.public_executables) <= 1 and all(
            isinstance(name, str) and name and not name.startswith('/')
            and all(part not in ('', '.', '..') for part in name.split('/'))
            and type(pin) is tuple and len(pin) == 2 and type(pin[0]) is int
            and 0 < pin[0] <= 128 * 1024 * 1024 and isinstance(pin[1], str)
            and len(pin[1]) == 64 and all(c in '0123456789abcdef' for c in pin[1])
            for name, pin in self.public_executables.items()), 'one_explicit_public_executable_pin')
''')
replace("                need(self.private_file(info), 'private_regular_unlinked_data_file')", '''                public_executable = selected in self.public_executables
                executable_ok = public_executable and stat.S_ISREG(info.st_mode) \\
                    and info.st_uid == os.geteuid() and info.st_gid == os.getegid() \\
                    and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o500 \\
                    and info.st_size == self.public_executables[selected][0]
                need(executable_ok if public_executable else self.private_file(info),
                     'private_data_or_explicit_pinned_public_executable')''')
replace("            entry['sha256'] = digest.hexdigest()", '''            if relative in self.public_executables:
                need((copied, digest.hexdigest()) == self.public_executables[relative],
                     'complete_public_executable_source_pin')
            entry['sha256'] = digest.hexdigest()''')
replace("            need(self.entries, 'complete_encrypted_store_not_empty')", '''            need(self.entries, 'complete_encrypted_store_not_empty')
            need(set(self.public_executables).issubset(self.entries), 'every_pinned_executable_present')''')
replace("'heptabao.complete-cold-copy-public.r1'", "'heptabao.complete-cold-copy-public.r2'")
replace("'keyMaterialClaim': 'Encrypted server data only; caller separately binds original seal/unseal custody.'", "'keyMaterialClaim': 'Caller-selected private runtime tree; seal/unseal custody is separate and required.'")
ast.parse(after)
(ROOT / 'complete_cold_tree_backup_r2.py').write_text(after)
(ROOT / 'complete-cold-tree-r1-to-r2.diff').write_text(''.join(difflib.unified_diff(
    before.splitlines(True), after.splitlines(True), fromfile='copy-core-r1', tofile='copy-core-r2')))
print(json.dumps({'bytes': len(after.encode()), 'sha256': hashlib.sha256(after.encode()).hexdigest(),
                  'onlyNewAuthority': 'one exact pathname/size/SHA256 public executable in mode 0500',
                  'allOtherCopyLockReadbackClosureMechanismsUnchanged': True}))
