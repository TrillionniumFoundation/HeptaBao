"""Reproduce the exact byte boundaries used by the original inline check.

No source text is stripped or whitespace-normalized. The two separator LFs
outside the 3163-byte module block are explicit in the reconstruction.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

base = Path('/tmp/heptabao-product-ci-fix-20261106-r1')
work = Path('/tmp/heptabao-ci-observer-order-20261106-r1')
commit = '9c68b95b152a468ab378b68730e9e3f04e6a7100'
rel = 'crates/heptabao-server/src/service_snapshot_v6_ha_restore.rs'
env = dict(os.environ, GIT_NO_LAZY_FETCH='1')
before = subprocess.check_output(['git', 'show', commit + ':' + rel], cwd=base, env=env)
after = (work / rel).read_bytes()
start = b'// Test-only observation at either an existing original-source gate or after\n'
assert before.count(start) == after.count(start) == 1
at = before.index(start)
end = before.index(b'\n\nimpl Service {', at)
block = before[at:end]
prefix = before[:at]
suffix = before[end + 2:]
assert suffix.count(b'impl Service {') == 2
assert after == prefix + suffix + b'\n' + block + b'\n'
assert before[:at] + before[end + 2:] == after[:after.index(start) - 1]
assert after.endswith(block + b'\n')

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

report = {
    'schema': 'heptabao.observer-relocation-exact-byte-boundaries.v1',
    'source_before': pin(before),
    'source_after': pin(after),
    'block_excludes_terminating_lf': pin(block),
    'block_including_original_two_lf_separator': pin(before[at:end + 2]),
    'new_tail_including_final_lf': pin(after[after.index(start):]),
    'prefix': pin(prefix),
    'suffix_two_production_impls_including_its_original_final_lf': pin(suffix),
    'original_block_start_offset': at,
    'original_block_exclusive_end_offset': end,
    'original_suffix_start_offset': end + 2,
    'new_block_start_offset': after.index(start),
    'original_reconstruction': 'prefix + block + b"\\n\\n" + suffix',
    'new_reconstruction': 'prefix + suffix + b"\\n" + block + b"\\n"',
    'prefix_and_suffix_bytes_and_order_unchanged': True,
    'module_bytes_unchanged': True,
    'entire_new_file_matches_explicit_byte_reconstruction': True,
    'separator_bytes_explicitly_relocated': True,
    'strip_or_whitespace_normalization_used': False,
    'claim_direct_remove_block_gives_identical_residual_bytes': False,
    'rust_parser_or_toolchain_executed': False,
}
print(json.dumps(report, sort_keys=True, indent=2))
