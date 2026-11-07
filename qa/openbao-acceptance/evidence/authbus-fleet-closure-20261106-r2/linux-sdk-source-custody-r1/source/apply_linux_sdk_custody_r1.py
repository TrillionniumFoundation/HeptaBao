#!/usr/bin/env python3
"""One finite permission-only operation on the already inventoried public SDK.

All original modes, ACL bytes and file hashes are retained on the owning host.
Every fchmod has a durable intent and completion. A partial/unknown operation
never retries or restores automatically. No SDK, service or credential access.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

TARGETS = {
    'pocket4': ('/home/alex', 'r1', 33856, 33853, 3),
    'rog': ('/home/qian-qi', 'r2', 33850, 33849, 1),
}
START = time.monotonic()
UNTIL = START + 240
OPEN = {}
FD_ROWS = []
CODES = set()
TOTAL_HASH_BYTES = 0
MAX_HASH_BYTES = 2 * 1024 * 1024 * 1024
report = {'schema': 'heptabao.linux-selected-sdk-permission-hardening.r1', 'ok': False,
          'sdkExecutions': 0, 'credentialReads': 0, 'serviceActions': 0, 'providerCalls': 0,
          'children': 0, 'networkOperations': 0, 'automaticRetry': False,
          'productionClientQualified': False, 'rollbackExecuted': False,
          'permissionCallsAttempted': 0, 'permissionCallsKnownComplete': 0}

def need(value, code):
    if not value:
        CODES.add(code)
        raise RuntimeError(code)

def remaining():
    need(time.monotonic() < UNTIL, 'original_permission_operation_deadline')

def identity(info):
    return [str(getattr(info, k)) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid',
            'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]

def open_file(path, flags, mode=0o600):
    remaining()
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, mode)
    need(fd not in OPEN, 'newly_owned_file_descriptor')
    row = {'fd': fd, 'attempts': 0, 'closed': False}
    OPEN[fd] = row
    FD_ROWS.append(row)
    return fd

def close(fd):
    row = OPEN.pop(fd)
    need(row['attempts'] == 0, 'original_descriptor_close_once')
    row['attempts'] = 1
    os.close(fd)
    row['closed'] = True

def write_all(fd, raw):
    view = memoryview(raw)
    while view:
        remaining()
        count = os.write(fd, view)
        need(count > 0, 'complete_durable_private_record')
        view = view[count:]

def create(path, raw):
    fd = open_file(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        write_all(fd, raw)
        os.fsync(fd)
    finally:
        close(fd)

def read_private(path):
    fd = open_file(path, os.O_RDONLY)
    try:
        old = os.fstat(fd)
        need(stat.S_ISREG(old.st_mode) and old.st_uid == old.st_gid == 1000
             and stat.S_IMODE(old.st_mode) == 0o600 and old.st_nlink == 1
             and 0 < old.st_size <= 32 * 1024 * 1024, 'exact_private_plan_file')
        raw = bytearray()
        while len(raw) <= old.st_size:
            remaining()
            part = os.read(fd, min(65536, old.st_size + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        need(len(raw) == old.st_size and identity(old) == identity(os.fstat(fd)) == identity(path.lstat()),
             'complete_original_private_plan')
        return bytes(raw)
    finally:
        close(fd)

def hash_fd(fd, info):
    global TOTAL_HASH_BYTES
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and 0 <= info.st_size <= 256 * 1024 * 1024, 'bounded_regular_public_source')
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    total = 0
    while True:
        remaining()
        part = os.read(fd, 1048576)
        if not part:
            break
        total += len(part)
        TOTAL_HASH_BYTES += len(part)
        need(total <= info.st_size and TOTAL_HASH_BYTES <= MAX_HASH_BYTES, 'finite_original_public_code_bytes')
        h.update(part)
    need(total == info.st_size, 'whole_public_file_hashed')
    return h.hexdigest()

def access_acl(fd):
    names = os.listxattr(fd)
    need('system.posix_acl_default' not in names, 'no_unqualified_default_acl')
    return os.getxattr(fd, 'system.posix_acl_access').hex() if 'system.posix_acl_access' in names else None

def inspect(row, expected, *, ancestor=False, expected_acl=None, hash_content=True):
    path = Path(row['path'])
    info = path.lstat()
    length = 5 if ancestor else 9
    need(identity(info)[:length] == expected[:length], 'original_named_input_generation')
    if not ancestor and row['kind'] == 'symlink':
        need(stat.S_ISLNK(info.st_mode) and os.readlink(path) == row['target']
             and str(path.resolve(strict=True)) == row['resolvedPath']
             and path.resolve(strict=True).is_relative_to(SDK), 'original_internal_sdk_alias')
        return identity(info)
    need(path.resolve(strict=True) == path and (stat.S_ISDIR(info.st_mode) if ancestor or row['kind'] == 'directory'
                                              else stat.S_ISREG(info.st_mode)),
         'original_public_source_kind')
    fd = open_file(path, os.O_RDONLY | (os.O_DIRECTORY if stat.S_ISDIR(info.st_mode) else 0))
    try:
        need(identity(os.fstat(fd))[:length] == expected[:length], 'same_held_public_source')
        need(access_acl(fd) == expected_acl, 'original_access_acl_exact')
        if stat.S_ISREG(info.st_mode) and hash_content:
            need(hash_fd(fd, info) == row['sha256'], 'original_public_file_content_unchanged')
        need(identity(os.fstat(fd)) == identity(path.lstat()) == identity(info), 'source_stable_during_inspection')
        return identity(info)
    finally:
        close(fd)

try:
    need(len(sys.argv) == 2 and sys.argv[1] in TARGETS, 'explicit_registered_permission_target')
    host = sys.argv[1]
    home_text, version, operation_count, row_changes, ancestor_changes = TARGETS[host]
    HOME = Path(home_text)
    SDK = HOME / '.npm-global/lib/node_modules/openclaw'
    PLUGIN = HOME / '.openclaw/extensions/openclaw-authbus/package.json'
    PLAN = HOME / ('heptabao-' + host + '-sdk-custody-plan-20261106-' + version)
    ROOT = HOME / ('heptabao-' + host + '-sdk-custody-apply-20261106-r1')
    need(sys.platform == 'linux' and os.getuid() == os.getgid() == 1000 and Path.home() == HOME,
         'exact_permission_operation_owner')
    os.umask(0o077)
    sys.dont_write_bytecode = True
    hs, ps = HOME.lstat(), PLAN.lstat()
    need(HOME.resolve(strict=True) == HOME and stat.S_ISDIR(hs.st_mode) and hs.st_uid == 1000
         and not hs.st_mode & 0o022 and PLAN.resolve(strict=True) == PLAN and stat.S_ISDIR(ps.st_mode)
         and ps.st_uid == ps.st_gid == 1000 and stat.S_IMODE(ps.st_mode) == 0o700, 'private_original_plan_custody')
    raw = read_private(PLAN / 'plan.private.json')
    original_raw = read_private(PLAN / 'original-inventory.private.json')
    plan, original = json.loads(raw), json.loads(original_raw)
    need(plan['schema'] == 'heptabao.linux-sdk-custody-plan.private.' + version
         and plan['host'] == host and plan['sdk'] == str(SDK) and plan['permissionWrites'] == 0
         and hashlib.sha256(original_raw).hexdigest() == plan['sourceInventorySha256'], 'bound_original_plan')
    original_rows = original['rows'] + [original['publicPluginPackage']]
    original_map = {row['path']: row for row in original_rows}
    rows, ancestors = plan['rows'], plan['ancestors']
    need(len(rows) == len(original_map) == 33870 and len({r['path'] for r in rows}) == 33870
         and set(original_map) == {r['path'] for r in rows}, 'exact_original_finite_source_set')
    ancestor_paths = {str(p) for p in [*SDK.parents, *PLUGIN.parents]}
    need(len(ancestors) == len(ancestor_paths) == 9 and {r['path'] for r in ancestors} == ancestor_paths,
         'exact_finite_code_ancestors')
    for row in rows:
        path = Path(row['path'])
        need(path == SDK or path.is_relative_to(SDK) or path == PLUGIN, 'fixed_public_code_only_scope')
        need(row['identity'] == original_map[row['path']]['identity'], 'original_source_identity_bound')
        old_mode = stat.S_IMODE(int(row['identity'][4]))
        need(row['oldMode'] == old_mode and row['newMode'] == (old_mode if row['kind'] == 'symlink'
                                                           else old_mode & ~0o022), 'only_remove_group_other_write')
        if row['oldMode'] != row['newMode']:
            need(int(row['identity'][2]) == int(row['identity'][3]) == 1000, 'change_only_callers_owned_public_code')
        inspect(row, row['identity'])
    for row in ancestors:
        need(row['oldMode'] == stat.S_IMODE(int(row['identityFirstFive'][4]))
             and row['newMode'] == row['oldMode'] & ~0o022, 'only_remove_ancestor_write')
        if row['oldMode'] != row['newMode']:
            need(Path(row['path']).is_relative_to(HOME) and int(row['identityFirstFive'][2]) == 1000,
                 'change_only_owned_code_ancestors')
        inspect(row, row['identityFirstFive'], ancestor=True, expected_acl=row.get('originalAccessAclHex'))
    pending_ancestors = [r for r in ancestors if r['oldMode'] != r['newMode']]
    pending_rows = [r for r in rows if r['oldMode'] != r['newMode']]
    need(len(pending_ancestors) == ancestor_changes and len(pending_rows) == row_changes
         and len(pending_ancestors) + len(pending_rows) == operation_count, 'exact_approved_operation_count')
    # Restrict the outer directory permissions before processing descendants.
    pending_ancestors.sort(key=lambda r: (len(Path(r['path']).parts), r['path']))
    pending_rows.sort(key=lambda r: (0 if r['kind'] == 'directory' else 1,
                                    len(Path(r['path']).parts), r['path']))
    operations = [(r, True) for r in pending_ancestors] + [(r, False) for r in pending_rows]
    need(identity(HOME.lstat())[:5] == identity(hs)[:5] and identity(PLAN.lstat())[:5] == identity(ps)[:5],
         'private_parent_bindings_still_original')
    ROOT.mkdir(mode=0o700, exist_ok=False)
    root_ident = identity(ROOT.lstat())[:5]
    create(ROOT / 'original-plan.private.json', raw)
    create(ROOT / 'original-inventory.private.json', original_raw)
    intentions = [{'ordinal': i, 'path': r['path'], 'oldMode': r['oldMode'],
                   'newMode': r['newMode'], 'ancestor': ancestor}
                  for i, (r, ancestor) in enumerate(operations)]
    create(ROOT / 'intents.private.json', (json.dumps(intentions, separators=(',', ':')) + '\n').encode())
    journal = open_file(ROOT / 'journal.private.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    root_fd = open_file(ROOT, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(root_fd)
    close(root_fd)
    home_fd = open_file(HOME, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(home_fd)
    close(home_fd)
    after = {}
    after_ancestors = {}
    for ordinal, (row, ancestor) in enumerate(operations):
        remaining()
        path = Path(row['path'])
        expected = row['identityFirstFive'] if ancestor else row['identity']
        length = 5 if ancestor else 9
        info = path.lstat()
        need(identity(info)[:length] == expected[:length] and info.st_uid == 1000,
             'original_inode_before_permission_intent')
        fd = open_file(path, os.O_RDONLY | (os.O_DIRECTORY if stat.S_ISDIR(info.st_mode) else 0))
        try:
            need(identity(os.fstat(fd)) == identity(info) and access_acl(fd) == row.get('originalAccessAclHex'),
                 'original_held_inode_and_acl_before_permission_change')
            event = {'ordinal': ordinal, 'state': 'intent', 'identity': identity(info),
                     'newMode': row['newMode']}
            write_all(journal, (json.dumps(event, separators=(',', ':')) + '\n').encode())
            os.fsync(journal)
            report['permissionCallsAttempted'] += 1
            os.fchmod(fd, row['newMode'])
            os.fsync(fd)
            new = os.fstat(fd)
            old_ident, new_ident = identity(info), identity(new)
            need(new_ident[:4] == old_ident[:4] and stat.S_IMODE(new.st_mode) == row['newMode']
                 and stat.S_IFMT(new.st_mode) == stat.S_IFMT(info.st_mode)
                 and new_ident[5:8] == old_ident[5:8] and identity(path.lstat()) == new_ident,
                 'only_original_mode_and_ctime_changed')
            need(access_acl(fd) == row.get('plannedAccessAclHex'), 'only_expected_access_acl_mask_change')
            if stat.S_ISREG(new.st_mode):
                need(hash_fd(fd, new) == row['sha256'], 'whole_public_content_unchanged_after_chmod')
            need(identity(os.fstat(fd)) == identity(path.lstat()) == new_ident, 'same_post_change_original_inode')
            event = {'ordinal': ordinal, 'state': 'complete', 'identity': new_ident}
            write_all(journal, (json.dumps(event, separators=(',', ':')) + '\n').encode())
            os.fsync(journal)
            report['permissionCallsKnownComplete'] += 1
            (after_ancestors if ancestor else after)[row['path']] = new_ident
        finally:
            close(fd)
    for row in rows:
        inspect(row, after.get(row['path'], row['identity']), hash_content=False)
    for row in ancestors:
        expected = after_ancestors.get(row['path'], row['identityFirstFive'])
        inspect(row, expected, ancestor=True, expected_acl=row.get('plannedAccessAclHex'))
    need(identity(ROOT.lstat())[:5] == root_ident and ROOT.resolve(strict=True) == ROOT,
         'private_once_ledger_still_bound')
    create(ROOT / 'after-identities.private.json',
           (json.dumps({'sdk': after, 'ancestors': after_ancestors}, sort_keys=True, separators=(',', ':')) + '\n').encode())
    root_fd = open_file(ROOT, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(root_fd)
    close(root_fd)
    close(journal)
    report.update(ok=True, host=host, originalPublicSdkEntries=33869, regularFiles=31939,
                  allOriginalBytesAndInodesPreserved=True, allNamedMetadataFencesExact=True,
                  allOriginalModesAndAclsRetainedPrivately=True, finitePermissionPlanCompleted=True,
                  expectedOperationCount=operation_count, groupAndOtherWriteRemoved=True,
                  plannedAncestorAclMaskChanges=1 if host == 'rog' else 0,
                  allInternalSymlinksPreserved=True, originalDeadlineSeconds=240,
                  fullClientRestartAndRollbackQualified=False)
except BaseException as error:
    report['errorType'] = type(error).__name__
    report['errorCode'] = str(error) if str(error) in CODES else 'sdk_permission_operation_refused'
    report['partialStateRetainedWithoutAutomaticRetryOrRollback'] = True
finally:
    for fd in list(OPEN):
        try:
            close(fd)
        except BaseException:
            report['ok'] = False
    report['descriptorCounts'] = {'opened': len(FD_ROWS),
                                 'attemptedOnce': sum(r['attempts'] for r in FD_ROWS),
                                 'knownClosed': sum(r['closed'] for r in FD_ROWS)}
    report['allDescriptorsClosedOnce'] = all(r['attempts'] == 1 and r['closed'] for r in FD_ROWS)
    report['bytesHashedPrivately'] = TOTAL_HASH_BYTES
    report['elapsedSeconds'] = time.monotonic() - START
    if not report['allDescriptorsClosedOnce'] or time.monotonic() >= UNTIL:
        report['ok'] = False
    print(json.dumps(report, sort_keys=True, separators=(',', ':')), flush=True)
raise SystemExit(0 if report['ok'] else 1)
