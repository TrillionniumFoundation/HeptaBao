#!/usr/bin/env python3
"""Accommodate actual kernel ARG_MAX without increasing the read buffer cap."""
import difflib
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / 'mac-finite-codex-selectors-r1-work'
old = (OLD / 'observe_finite_codex_selectors_r1.py').read_bytes()
assert hashlib.sha256(old).hexdigest() == 'ad55a151f09da806f10c261c0783ec0f030d899f743c3612930101b68983c417'
before = (OLD / 'observe_finite_codex_selectors_r1.template.py').read_text()
after = before.replace('finite-codex-selectors-20261107-r1', 'finite-codex-selectors-20261107-r2')
after = after.replace('heptabao.finite-codex-selector-observation.r1', 'heptabao.finite-codex-selector-observation.r2')
old_guard = """        need(length.value == 4 and 4096 <= maximum.value <= 262144,
             'selector_exact_bounded_kernel_argument_budget')
        self.maximum = maximum.value + 4
        report['kernelArgumentBudget'] = maximum.value"""
new_guard = """        need(length.value == 4 and maximum.value == 1048576,
             'selector_actual_kernel_argument_budget')
        # Preserve the original 256 KiB + argc allocation. XNU's insufficient
        # buffer branch returns exactly the supplied size; reject that size
        # rather than accepting possibly truncated data or enlarging the cap.
        self.maximum = 262144 + 4
        report['kernelArgumentBudget'] = maximum.value
        report['maximumArgumentReadBytesIncludingArgc'] = self.maximum
        report['kernelBudgetDiagnosticJob'] = '1a1b398a4c8-fc05-83c2'
        report['originalReadAllocationCeilingUnchanged'] = True"""
assert after.count(old_guard) == 1
after = after.replace(old_guard,new_guard)
old_length = "need(6 <= length.value <= self.maximum, 'selector_complete_returned_procargs_bound')"
assert after.count(old_length) == 1
after = after.replace(old_length,"need(6 <= length.value < self.maximum, 'selector_complete_returned_procargs_strictly_below_cap')")
(HERE / 'observe_finite_codex_selectors_r2.template.py').write_text(after)
(HERE / 'r1-to-r2-minimal.diff').write_text(''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='selector-r1-template',tofile='selector-r2-template')))
for name in ('mac_procargs_selectors_r1.py','selector-admission.public.json','qualify_procargs_selectors_r1.py','selectors-local20.original.json'):
    (HERE / name).write_bytes((OLD / name).read_bytes())
preparer = (OLD / 'prepare_finite_codex_selectors_r1.py').read_text()
preparer = preparer.replace('observe_finite_codex_selectors_r1','observe_finite_codex_selectors_r2').replace('heptabao.finite-codex-selector-preparation.r1','heptabao.finite-codex-selector-preparation.r2')
(HERE / 'prepare_finite_codex_selectors_r2.py').write_text(preparer)
print('created selector r2 source; original read ceiling unchanged')
