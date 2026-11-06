"""One-field repair for the stopped, never-initialized candidate.

Importing this module performs no I/O. The caller must bind the actual failed
attempt, completed read-only r2, and original exact-label retirement, then
observe label absence again before calling publish(). This module never
starts/stops a manager, invokes an endpoint, or changes a plist/guard/config.
"""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path

import manager_runtime as runtime

need = runtime.need
BASE_PYTHON_PATH = '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
BASE_PYTHON_BYTES = 34640
BASE_PYTHON_SHA256 = 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
SERVICE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1/formal-kv2-current-20261106-r1')
OLD_PYTHON_PATH = '/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-python-env-50-0-2-r3/venv/bin/python3'


def replacement(initial, actual_base_launcher):
    """Require exact source/target roles and change only files.python."""
    need(type(initial) is dict and set(initial) == {
        'schema', 'state', 'manager', 'roots', 'files', 'data_pin', 'seal_file', 'normal_config'},
        'original_initial_binding_shape')
    need(initial['schema'] == 'heptabao.normal-kv2-launch-binding.private.v1'
         and initial['state'] == 'initial_empty' and initial['seal_file'] is None
         and initial['manager'] == {'domain': 'gui/501', 'label': 'org.heptabao.kv2', 'uid': 501, 'gid': 20}
         and initial['data_pin']['path'] == str(SERVICE / 'data'), 'only_stopped_preinit_binding_repair')
    old = initial['files']['python']
    need(old['path'] == OLD_PYTHON_PATH and old['bytes'] == BASE_PYTHON_BYTES
         and old['sha256'] == BASE_PYTHON_SHA256, 'original_controller_python_binding')
    target = actual_base_launcher
    need(type(target) is dict and set(target) == {'path', 'bytes', 'sha256', 'identity'}
         and target['path'] == BASE_PYTHON_PATH and target['bytes'] == BASE_PYTHON_BYTES
         and target['sha256'] == BASE_PYTHON_SHA256, 'actual_qualified_base_launcher_pin')
    pin = target['identity']
    need(set(pin) == runtime.guard.FILE_KEYS and all(type(v) is int for v in pin.values())
         and pin['bytes'] == BASE_PYTHON_BYTES and pin['file_type'] == 32768
         and pin['uid'] == 501 and pin['gid'] == 80 and pin['mode'] == 0o755
         and pin['nlink'] == 1, 'actual_base_launcher_full_identity_shape')
    out = copy.deepcopy(initial)
    out['files']['python'] = copy.deepcopy(target)
    unchanged = copy.deepcopy(out)
    unchanged['files']['python'] = copy.deepcopy(old)
    need(unchanged == initial and out != initial, 'only_python_role_changes')
    return out


def publish(io, manager, current_pin, retained_initial_pin, actual_base_launcher,
            retirement_observation, ledger):
    """Publish once, preserving the initial archive and original current FD.

The caller supplies the *actual* typed observation from its just-completed
exact-label absence query. Its full original command and durable retirement
terminals must already have been bound by the controller; no passed-only flag
is accepted here. Any failure after the mutation intent remains unknown until
a separate read-only reconciliation. This function does not retry it.
"""
    need(type(retirement_observation) is dict and retirement_observation == {
        'domain': 'gui/501', 'label': 'org.heptabao.kv2',
        'argv': ['/bin/launchctl', 'print', 'gui/501/org.heptabao.kv2'],
        'returncode': 113, 'stdout_bytes': 0,
        'stderr': 'Bad request.\nCould not find service "org.heptabao.kv2" in domain for user gui: 501\n',
    }, 'actual_exact_label_absence_before_binding_publication')
    need(manager['path'] == SERVICE / 'manager'
         and current_pin['path'] == str(SERVICE / 'manager/launch-binding.private.json')
         and retained_initial_pin['path'] == str(SERVICE / 'manager/launch-binding.initial-empty.original.private.json'),
         'only_current_binding_target')
    old_raw = io.read_file(current_pin, maximum=131072)
    need(io.read_file(retained_initial_pin, maximum=131072) == old_raw,
         'original_current_matches_unchanged_initial_archive')
    initial = runtime.parsed(old_raw)
    updated = replacement(initial, actual_base_launcher)
    io.read_file(actual_base_launcher, maximum=1048576, private=False, materialize=False)
    body = runtime.encoded(updated)
    preserved = io.put(manager, 'launch-binding.before-base-launcher-repair.original.private.json', old_raw)
    pending = io.put(manager, 'launch-binding.base-launcher-repair.pending.private.json', body, remember=False)
    old_path, pending_path = Path(current_pin['path']), Path(pending['path'])
    io.recheck()
    need(runtime.file_identity(old_path.lstat()) == current_pin['identity']
         and runtime.file_identity(pending_path.lstat()) == pending['identity'], 'binding_repair_original_prepublication_identity')
    ledger.update(operation='one_field_initial_binding_python_role_repair',
                  publication_attempted=True, publication_outcome_unknown=True,
                  original_current=current_pin, retained_initial=retained_initial_pin,
                  preserved_current=preserved, pending=pending)
    intent = io.put(manager, 'launch-binding.base-launcher-repair.intent.private.json',
                    runtime.encoded(ledger))
    ledger['durable_prepublication_intent'] = intent
    # Registration/retirement are protected from termination handlers. A
    # process crash is still possible and never changes unknown into success.
    with io.clock.critical():
        os.replace(pending_path.name, old_path.name, src_dir_fd=manager['fd'], dst_dir_fd=manager['fd'])
        os.fsync(manager['fd'])
        after = runtime.file_identity(old_path.lstat())
        expected = dict(pending['identity'])
        # Rename may update ctime; all other original new-file identity fields
        # and content must match the already-created pending inode.
        expected['ctime_ns'] = after['ctime_ns']
        need(after == expected, 'binding_repair_original_pending_inode_published')
        retired = []
        for row in list(io.files):
            if row['path'] == old_path:
                info = os.fstat(row['fd'])
                need(info.st_dev == current_pin['identity']['dev']
                     and info.st_ino == current_pin['identity']['inode'] and info.st_nlink == 0,
                     'original_current_binding_inode_unlinked')
                io.files.remove(row)
                retired.append(row['fd'])
        need(bool(retired), 'original_current_binding_fd_retained_until_close')
    result = {'path': str(old_path), 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'identity': after}
    need(io.read_file(result, maximum=131072) == body, 'binding_repair_actual_full_readback')
    need(io.read_file(retained_initial_pin, maximum=131072) == old_raw, 'retained_initial_archive_still_unchanged')
    io.recheck()
    ledger.update(publication_outcome_unknown=False, published=result,
                  original_current_fd_count_retained=len(retired), exact_one_field_difference_verified=True,
                  manager_restart_performed=False, initialization_performed=False,
                  os_privacy_permission_changed=False, formal_kv2_qualified=False)
    return result
