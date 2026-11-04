#!/usr/bin/env python3
"""Two bounded root file operations for an externally pinned fresh QA plan.

This is never a service, sudoers rule, arbitrary-path installer or credential
reader. The caller sends these exact bytes plus a fixed plan to a SHA-pinned
stdin bootstrap; root does not import a service-writable Python file.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import re
import stat


class Refused(Exception):
    pass


class FileMutationFailed(Exception):
    def __init__(self, result):
        super().__init__('root_unit_file_mutation_failed')
        self.result = result


def need(ok, code):
    if not ok:
        raise Refused(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(st):
    return {'device': st.st_dev, 'inode': st.st_ino, 'uid': st.st_uid,
            'gid': st.st_gid, 'mode': stat.S_IMODE(st.st_mode)}


def directory(path, owners):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute_directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            need(info.st_uid in owners and not stat.S_IMODE(info.st_mode) & 0o022,
                 'directory_custody')
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_regular(parent, name, uid, gid, mode):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (uid, gid, mode)
             and 0 < before.st_size <= 65536, 'file_custody')
        raw = bytearray()
        while len(raw) <= 65536:
            block = os.read(fd, min(65537 - len(raw), 65536))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(fd)
        signature = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                                s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(signature(before) == signature(after) and len(raw) == before.st_size, 'file_changed')
        return bytes(raw), identity(after)
    finally:
        os.close(fd)


def binding_absent(source_fd):
    for name in ('installation.private.json', 'binding-pin.env'):
        try:
            os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        return False
    return True


def root_operation(payload, progress=None):
    progress = {} if progress is None else progress
    need(os.geteuid() == 0 and os.getegid() == 0, 'root_file_operator_required')
    plan, action, ordinal = payload['plan'], payload['action'], payload['ordinal']
    need(plan['schema'] == 'heptabao.installed-supervisor-system-plan.v1'
         and action in ('install', 'remove') and ordinal in (1, 2), 'fixed_plan_scope')
    actor = plan['actor']
    need(actor['uid'] > 0 and actor['gid'] > 0
         and int(os.environ.get('SUDO_UID', '-1')) == actor['uid']
         and int(os.environ.get('SUDO_GID', '-1')) == actor['gid']
         and pwd.getpwuid(actor['uid']).pw_name == actor['user']
         and grp.getgrgid(actor['gid']).gr_name == actor['group'], 'original_nonroot_operator')
    need(re.fullmatch(r'[0-9a-f]{12}', plan['runId']) is not None, 'fixed_run_identity')
    root = Path(plan['workDir'])
    need(root.is_absolute() and '..' not in root.parts
         and re.fullmatch(r'[A-Za-z0-9_./-]+', str(root)) is not None, 'fixed_work_path')
    entry = plan['units'][ordinal - 1]
    name = 'heptabao-authbus-installed-qa-' + plan['runId'] + '-' + str(ordinal) + '.service'
    installation = 'installation-a' if ordinal == 1 else 'installation-restored'
    target = Path('/run/systemd/system') / name
    need(entry['ordinal'] == ordinal and entry['name'] == name
         and entry['proposal'] == str(root / installation / name)
         and entry['runtime'] == str(target), 'exact_plan_paths')
    expected = entry['unitText'].encode()
    need(digest(expected) == entry['unitSha256'], 'fixed_unit_digest')
    # These additional checks protect the privileged manager independently of
    # the later nonroot entry binding; there is only one nonroot ExecStart.
    lines = expected.decode().splitlines()
    need(lines.count('User=' + actor['user']) == 1 and lines.count('Group=' + actor['group']) == 1
         and lines.count('NoNewPrivileges=yes') == 1 and lines.count('PrivateUsers=yes') == 1
         and lines.count('ProtectSystem=strict') == 1 and lines.count('ProtectHome=read-only') == 1,
         'nonroot_hardening_contract')
    starts = [line for line in lines if line.startswith('Exec')]
    exact = (f'ExecStart=/usr/bin/python3 -I -S -B {root}/code/authbus_coordinator_installed.py'
             f' service serve --binding {root}/{installation}/installation.private.json'
             ' --binding-sha256 ${HEPTABAO_BINDING_SHA256}')
    need(starts == [exact] and not any(line.startswith(('RootDirectory=', 'RootImage=', 'PermissionsStartOnly='))
                                     for line in lines), 'exact_nonroot_command')
    run_fd = directory(root, (0, actor['uid']))
    target_fd = None
    try:
        need(identity(os.fstat(run_fd)) == payload['runIdentity']
             and payload['runIdentity']['uid'] == actor['uid']
             and payload['runIdentity']['mode'] == 0o700, 'original_fresh_run_directory')
        target_fd = directory(target.parent, (0,))
        if action == 'install':
            source_fd = os.open(installation, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=run_fd)
            try:
                source_info = os.fstat(source_fd)
                need(source_info.st_uid == actor['uid'] and stat.S_IMODE(source_info.st_mode) == 0o700,
                     'proposal_parent_custody')
                raw, _ = read_regular(source_fd, name, actor['uid'], actor['gid'], 0o600)
                need(raw == expected, 'exact_proposal_bytes')
                need(payload['startDispatched'] is False and binding_absent(source_fd),
                     'installation_must_precede_binding_and_start')
                fd = None
                original = None
                try:
                    progress['mutationDispatched'] = True
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=target_fd)
                    original = identity(os.fstat(fd))
                    with os.fdopen(fd, 'wb', closefd=False) as stream:
                        stream.write(raw)
                        stream.flush()
                    os.fchown(fd, 0, 0)
                    os.fchmod(fd, 0o644)
                    os.fsync(fd)
                    installed = identity(os.fstat(fd))
                    os.fsync(target_fd)
                    raw, observed = read_regular(target_fd, name, 0, 0, 0o644)
                    need(raw == expected and observed == installed, 'installed_exact_root_unit')
                    return {'action': action, 'path': str(target), 'sha256': digest(raw), 'identity': observed}
                except BaseException as exc:
                    cleanup = {'attempted': False, 'complete': False, 'removedOriginalInode': False,
                               'parentSynced': False, 'startDispatched': False}
                    no_file_created = fd is None and isinstance(exc, FileExistsError)
                    if fd is not None:
                        cleanup['attempted'] = True
                        try:
                            held = os.fstat(fd)
                            original = original or identity(held)
                            named = os.stat(name, dir_fd=target_fd, follow_symlinks=False)
                            need(stat.S_ISREG(held.st_mode) and held.st_nlink == 1 and held.st_uid == 0
                                 and (held.st_dev, held.st_ino) == (original['device'], original['inode'])
                                 and (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino)
                                 and binding_absent(source_fd), 'failure_cleanup_original_unstarted_inode')
                            os.unlink(name, dir_fd=target_fd)
                            cleanup['removedOriginalInode'] = True
                            os.fsync(target_fd)
                            cleanup['parentSynced'] = cleanup['complete'] = True
                        except BaseException as cleanup_error:
                            cleanup['error'] = (str(cleanup_error) if isinstance(cleanup_error, Refused)
                                                else type(cleanup_error).__name__)
                    raise FileMutationFailed({'action': action, 'path': str(target),
                          'sha256': entry['unitSha256'], 'error': 'root_unit_install_failed',
                          'cause': type(exc).__name__, 'createdIdentity': original,
                          'noFileCreated': no_file_created, 'selfFailureCleanup': cleanup,
                          'unknown_outcome': not (no_file_created or cleanup['complete'])}) from None
                finally:
                    if fd is not None:
                        os.close(fd)
            finally:
                os.close(source_fd)
        need(payload['stopConfirmed'] is True, 'removal_requires_confirmed_manager_stop')
        raw, observed = read_regular(target_fd, name, 0, 0, 0o644)
        need(raw == expected and observed == payload['expectedUnitIdentity'], 'exact_owned_unit_removal')
        need(identity(os.stat(name, dir_fd=target_fd, follow_symlinks=False)) == observed,
             'unit_changed_before_unlink')
        removed = False
        try:
            progress['mutationDispatched'] = True
            os.unlink(name, dir_fd=target_fd)
            removed = True
            os.fsync(target_fd)
        except BaseException as exc:
            raise FileMutationFailed({'action': action, 'path': str(target),
                  'sha256': entry['unitSha256'], 'error': 'root_unit_remove_failed',
                  'cause': type(exc).__name__, 'unknown_outcome': True,
                  'removedOriginalInode': removed, 'originalIdentity': observed}) from None
        return {'action': action, 'path': str(target), 'sha256': digest(raw),
                'removedIdentity': observed, 'removed': True}
    finally:
        if target_fd is not None:
            os.close(target_fd)
        os.close(run_fd)


def root_main(payload):
    progress = {}
    try:
        result = root_operation(payload, progress)
        print(json.dumps({'schema': 'heptabao.installed-supervisor-root-unit-file.v1',
                          'ok': True, **result}, sort_keys=True), flush=True)
        return 0
    except FileMutationFailed as exc:
        print(json.dumps({'schema': 'heptabao.installed-supervisor-root-unit-file.v1',
                          'ok': False, **exc.result}, sort_keys=True), flush=True)
        return 1
    except Exception as exc:
        print(json.dumps({'schema': 'heptabao.installed-supervisor-root-unit-file.v1',
                          'ok': False, 'unknown_outcome': progress.get('mutationDispatched', False),
                          'fileMutationDispatched': progress.get('mutationDispatched', False),
                          'error': str(exc) if isinstance(exc, Refused) else type(exc).__name__},
                         sort_keys=True), flush=True)
        return 1
