#!/usr/bin/env python3
"""Prepare a finite, host-private permission plan from the original SDK inventory.

This operation never chmods, imports the SDK, reads credential databases, or
changes services. Every regular SDK file is hashed privately, including assets;
the public result contains counts and non-secret code ancestor paths only.
"""
import hashlib
import json
import os
import struct
from pathlib import Path
import stat
import sys
import time

TARGETS = {'rog': '/home/qian-qi'}
UNTIL = time.monotonic() + 90
MAX_TOTAL = 1024 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024
counts = {'opened': 0, 'closeAttempts': 0, 'closed': 0}
errors = set()
report = {'schema': 'heptabao.linux-sdk-custody-plan.r2', 'ok': False,
          'permissionWrites': 0, 'sdkExecutions': 0, 'credentialDatabaseReads': 0,
          'serviceActions': 0, 'providerCalls': 0, 'children': 0,
          'actualDependencyClosureQualified': False, 'executionAuthorizedByReceipt': False}

def need(value, code):
    if not value:
        errors.add(code)
        raise RuntimeError(code)

def remaining():
    need(time.monotonic() < UNTIL, 'original_plan_deadline')

def ident(info):
    return [str(getattr(info, key)) for key in
            ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]

def open_owned(path, flags):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    counts['opened'] += 1
    return fd

def close(fd):
    counts['closeAttempts'] += 1
    os.close(fd)
    counts['closed'] += 1

def read_private(path):
    fd = open_owned(path, os.O_RDONLY)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 1000 and info.st_gid == 1000
             and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
             and 0 < info.st_size <= 32 * 1024 * 1024, 'original_private_inventory_custody')
        out = bytearray()
        while len(out) <= info.st_size:
            remaining()
            part = os.read(fd, min(65536, info.st_size + 1 - len(out)))
            if not part:
                break
            out.extend(part)
        need(len(out) == info.st_size and ident(info) == ident(os.fstat(fd)) == ident(path.lstat()),
             'complete_stable_original_private_inventory')
        return bytes(out)
    finally:
        close(fd)

def create_private(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    counts['opened'] += 1
    try:
        view = memoryview(raw)
        while view:
            remaining()
            number = os.write(fd, view)
            need(number > 0, 'private_plan_write_progress')
            view = view[number:]
        os.fsync(fd)
    finally:
        close(fd)


def ancestor_acl(fd, info, new_mode):
    """Preserve an existing POSIX access ACL, changing only its chmod mask.

    Named users/groups are subject to ACL_MASK. The old ACL is retained in the
    private plan and the prospective ACL must grant no write to non-owners.
    Default ACLs are outside this observed, finite case and remain refused.
    """
    names = os.listxattr(fd)
    need('system.posix_acl_default' not in names, 'no_default_acl_in_fixed_code_ancestors')
    if 'system.posix_acl_access' not in names:
        return None, None
    raw = os.getxattr(fd, 'system.posix_acl_access')
    need(4 <= len(raw) <= 4096 and (len(raw) - 4) % 8 == 0
         and struct.unpack_from('<I', raw)[0] == 2, 'exact_posix_access_acl_encoding')
    entries = [struct.unpack_from('<HHI', raw, i) for i in range(4, len(raw), 8)]
    need(all(tag in (1, 2, 4, 8, 16, 32) and perm <= 7 for tag, perm, uid in entries)
         and len({(tag, uid) for tag, perm, uid in entries}) == len(entries),
         'unique_known_access_acl_entries')
    basic = {tag: [(perm, uid) for t, perm, uid in entries if t == tag] for tag in (1, 4, 16, 32)}
    need(all(len(basic[tag]) == 1 and basic[tag][0][1] == 4294967295 for tag in (1, 4, 32))
         and len(basic[16]) <= 1 and all(uid != 4294967295 for tag, perm, uid in entries if tag in (2, 8))
         and all(uid == 4294967295 for tag, perm, uid in entries if tag in (1, 4, 16, 32)),
         'complete_posix_access_acl_owner_group_other')
    need(not any(tag in (2, 8) for tag, perm, uid in entries) or len(basic[16]) == 1,
         'extended_access_acl_requires_mask')
    group_bits = basic[16][0][0] if basic[16] else basic[4][0][0]
    old_mode = stat.S_IMODE(info.st_mode)
    need(basic[1][0][0] == (old_mode >> 6) & 7 and group_bits == (old_mode >> 3) & 7
         and basic[32][0][0] == old_mode & 7, 'kernel_access_acl_matches_mode')
    planned = []
    for tag, perm, uid in entries:
        if tag == 1:
            perm = (new_mode >> 6) & 7
        elif tag == 32:
            perm = new_mode & 7
        elif tag == 16 or (tag == 4 and not basic[16]):
            perm = (new_mode >> 3) & 7
        planned.append((tag, perm, uid))
    mask = next((perm for tag, perm, uid in planned if tag == 16), 7)
    need(all(not ((perm if tag == 32 else perm & mask) & 2)
             for tag, perm, uid in planned if tag in (2, 4, 8, 32)),
         'planned_acl_has_no_nonowner_write')
    after = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in planned)
    return raw.hex(), after.hex()

try:
    need(len(sys.argv) == 2 and sys.argv[1] in TARGETS, 'explicit_registered_linux_host')
    host = sys.argv[1]
    home = Path(TARGETS[host])
    sdk = home / '.npm-global/lib/node_modules/openclaw'
    inventory = home / ('heptabao-' + host + '-sdk-permissions-20261106-r1')
    root = home / ('heptabao-' + host + '-sdk-custody-plan-20261106-r2')
    need(sys.platform == 'linux' and os.getuid() == os.getgid() == 1000 and Path.home() == home,
         'exact_registered_linux_owner')
    os.umask(0o077)
    sys.dont_write_bytecode = True
    before_dir = inventory.lstat()
    need(stat.S_ISDIR(before_dir.st_mode) and before_dir.st_uid == before_dir.st_gid == 1000
         and stat.S_IMODE(before_dir.st_mode) == 0o700 and inventory.resolve(strict=True) == inventory,
         'original_inventory_private_directory')
    original = read_private(inventory / 'baseline.private.json')
    baseline = json.loads(original)
    need(baseline['schema'] == 'heptabao.linux-sdk-permission-baseline.private.r1'
         and baseline['host'] == host and baseline['sdk'] == str(sdk)
         and baseline['permissionsChanged'] is False and baseline['sdkExecuted'] is False,
         'original_selected_sdk_inventory')
    need(len(baseline['rows']) == 33869 and len({r['path'] for r in baseline['rows']}) == 33869,
         'same_finite_original_sdk_tree')
    rows = []
    ancestors = {}
    total = 0
    hashes = 0
    max_file = 0
    inherited_pins = 0
    acl_checked = 0
    symlinks = 0
    for old in baseline['rows'] + [baseline['publicPluginPackage']]:
        remaining()
        path = Path(old['path'])
        plugin = path == home / '.openclaw/extensions/openclaw-authbus/package.json'
        need(plugin or path == sdk or path.is_relative_to(sdk), 'exact_public_code_scope')
        info = path.lstat()
        need(ident(info) == old['identity'] and info.st_uid in (0, 1000), 'original_sdk_generation_unchanged')
        row = {'path': str(path), 'identity': ident(info), 'kind': 'symlink' if stat.S_ISLNK(info.st_mode)
               else 'directory' if stat.S_ISDIR(info.st_mode) else 'regular',
               'oldMode': stat.S_IMODE(info.st_mode), 'newMode': stat.S_IMODE(info.st_mode) & ~0o022}
        if stat.S_ISLNK(info.st_mode):
            need(not plugin and os.readlink(path) == old['symlinkTarget']
                 and str(path.resolve(strict=True)) == old['resolvedPath']
                 and path.resolve(strict=True).is_relative_to(sdk), 'same_internal_sdk_alias')
            row.update(target=old['symlinkTarget'], resolvedPath=old['resolvedPath'])
            row['newMode'] = row['oldMode']
            symlinks += 1
        else:
            need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'no_special_sdk_file')
            fd = open_owned(path, os.O_RDONLY | (os.O_DIRECTORY if stat.S_ISDIR(info.st_mode) else 0))
            try:
                need(ident(os.fstat(fd)) == old['identity'], 'same_original_public_inode')
                attrs = os.listxattr(fd)
                need('system.posix_acl_access' not in attrs and 'system.posix_acl_default' not in attrs,
                     'no_alternate_write_acl_on_sdk')
                acl_checked += 1
                if stat.S_ISREG(info.st_mode):
                    need(info.st_nlink == 1 and info.st_size <= MAX_FILE, 'bounded_single_link_public_file')
                    h = hashlib.sha256()
                    size = 0
                    while True:
                        remaining()
                        part = os.read(fd, 1048576)
                        if not part:
                            break
                        size += len(part)
                        total += len(part)
                        need(size <= info.st_size and total <= MAX_TOTAL, 'finite_total_public_sdk_bytes')
                        h.update(part)
                    need(size == info.st_size, 'complete_public_sdk_file')
                    row['sha256'] = h.hexdigest()
                    if 'sha256' in old:
                        need(row['sha256'] == old['sha256'], 'same_original_public_code_bytes')
                        inherited_pins += 1
                    hashes += 1
                    max_file = max(max_file, size)
                need(ident(os.fstat(fd)) == ident(path.lstat()) == old['identity'], 'public_inode_stable_after_read')
            finally:
                close(fd)
            if row['oldMode'] != row['newMode']:
                need(info.st_uid == 1000, 'permission_plan_changes_only_callers_code')
        rows.append(row)
    for path in [*sdk.parents, *(home / '.openclaw/extensions/openclaw-authbus/package.json').parents]:
        if str(path) in ancestors:
            continue
        remaining()
        info = path.lstat()
        need(path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode)
             and info.st_uid in (0, 1000) and not info.st_mode & 0o002, 'trusted_public_code_ancestor')
        old = next((r for r in baseline['ancestors'] if r['path'] == str(path)), None)
        if old:
            need(ident(info)[:5] == old['identity'][:5], 'same_original_ancestor_ownership')
        fd = open_owned(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            need(ident(os.fstat(fd))[:5] == ident(info)[:5], 'same_held_public_ancestor')
            original_acl, planned_acl = ancestor_acl(fd, info, stat.S_IMODE(info.st_mode) & ~0o022)
            need(ident(os.fstat(fd))[:5] == ident(path.lstat())[:5] == ident(info)[:5],
                 'same_ancestor_after_acl_observation')
            acl_checked += 1
        finally:
            close(fd)
        new_mode = stat.S_IMODE(info.st_mode) & ~0o022
        if new_mode != stat.S_IMODE(info.st_mode):
            need(path.is_relative_to(home) and info.st_uid == 1000, 'only_owned_home_ancestor_mode_change')
        ancestors[str(path)] = {'path': str(path), 'identityFirstFive': ident(info)[:5],
                                 'oldMode': stat.S_IMODE(info.st_mode), 'newMode': new_mode,
                                 'originalAccessAclHex': original_acl, 'plannedAccessAclHex': planned_acl}
    for row in rows:
        remaining()
        need(ident(Path(row['path']).lstat()) == row['identity'], 'whole_sdk_generation_still_unchanged')
    for row in ancestors.values():
        path = Path(row['path'])
        info = path.lstat()
        need(ident(info)[:5] == row['identityFirstFive'], 'ancestor_ownership_still_unchanged')
        fd = open_owned(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            old_acl, new_acl = ancestor_acl(fd, info, row['newMode'])
            need(old_acl == row['originalAccessAclHex'] and new_acl == row['plannedAccessAclHex'],
                 'original_access_acl_still_exact')
        finally:
            close(fd)
    need(ident(inventory.lstat())[:5] == ident(before_dir)[:5], 'private_inventory_binding_unchanged')
    hs = home.lstat()
    need(hs.st_uid == 1000 and stat.S_ISDIR(hs.st_mode) and not hs.st_mode & 0o022, 'private_plan_parent')
    root.mkdir(mode=0o700, exist_ok=False)
    plan = {'schema': 'heptabao.linux-sdk-custody-plan.private.r2', 'host': host, 'sdk': str(sdk),
            'rows': rows, 'ancestors': list(ancestors.values()), 'sourceInventoryIdentity': ident(before_dir),
            'permissionWrites': 0, 'sourceInventorySha256': hashlib.sha256(original).hexdigest()}
    create_private(root / 'original-inventory.private.json', original)
    create_private(root / 'plan.private.json', (json.dumps(plan, sort_keys=True, separators=(',', ':')) + '\n').encode())
    fd = open_owned(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        close(fd)
    changes = [r for r in rows if r['oldMode'] != r['newMode']]
    ancestor_changes = [r for r in ancestors.values() if r['oldMode'] != r['newMode']]
    report.update(ok=True, host=host, sdkEntryCount=33869, privatePlanCreated=True,
                  regularFilesHashed=hashes, bytesHashed=total, maximumFileBytes=max_file,
                  originalPublicPinsMatched=inherited_pins, aclChecks=acl_checked, internalSymlinks=symlinks,
                  proposedRegularChanges=sum(r['kind'] == 'regular' for r in changes),
                  proposedDirectoryChanges=sum(r['kind'] == 'directory' for r in changes),
                  proposedAncestorChanges=[{'path': r['path'], 'oldMode': oct(r['oldMode']),
                                            'newMode': oct(r['newMode'])} for r in ancestor_changes],
                  allOriginalSdkIdentitiesUnchanged=True, privateRollbackModesSaved=True,
                  accessAclsPrivatelyRetained=sum(r['originalAccessAclHex'] is not None for r in ancestors.values()),
                  proposedAccessAclMaskChanges=sum(r['originalAccessAclHex'] != r['plannedAccessAclHex'] for r in ancestors.values()))
except BaseException as error:
    report['errorType'] = type(error).__name__
    report['errorCode'] = str(error) if str(error) in errors else 'sdk_custody_plan_refused'
finally:
    report['descriptorCounts'] = counts
    report['allDescriptorsClosedOnce'] = counts['opened'] == counts['closeAttempts'] == counts['closed']
    if not report['allDescriptorsClosedOnce'] or time.monotonic() >= UNTIL:
        report['ok'] = False
    print(json.dumps(report, sort_keys=True, separators=(',', ':')), flush=True)
raise SystemExit(0 if report['ok'] else 1)
