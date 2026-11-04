#!/usr/bin/env python3
"""Read only the fixed fresh system unit's process/namespace metadata.

No credential, target environment, memory, config contents, process control or host
configuration is read or changed. Exact source plus fixed plan is supplied on
stdin to a separately SHA-pinned root bootstrap, never imported as root.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat


class Refused(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Refused(code)


def identity(info):
    return {'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,
            'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)}


def read_at(parent, name, cap):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        chunks, size = [], 0
        while size <= cap:
            block = os.read(fd, min(65536, cap + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
        need(size <= cap, 'bounded_metadata')
        return b''.join(chunks)
    finally:
        os.close(fd)


def directory(path, owners):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute_directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            need(info.st_uid in owners and not stat.S_IMODE(info.st_mode) & 0o022,
                 'directory_custody')
        return fd
    except BaseException:
        os.close(fd)
        raise


def observe(payload, result):
    need(os.geteuid() == os.getegid() == 0, 'root_metadata_observer_required')
    plan, ordinal, pid = payload['plan'], payload['ordinal'], payload['pid']
    actor = plan['actor']
    need(plan['schema'] == 'heptabao.installed-supervisor-system-plan.v1'
         and ordinal in (1,2) and isinstance(pid,int) and pid > 1
         and re.fullmatch(r'[0-9a-f]{12}',plan['runId']) is not None,
         'fixed_plan_scope')
    need(actor['uid'] > 0 and actor['gid'] > 0
         and int(os.environ.get('SUDO_UID','-1')) == actor['uid']
         and int(os.environ.get('SUDO_GID','-1')) == actor['gid'], 'original_nonroot_observer')
    work = Path(plan['workDir'])
    need(work.is_absolute() and '..' not in work.parts
         and re.fullmatch(r'[A-Za-z0-9_./-]+',str(work)) is not None, 'fixed_work_path')
    installation = 'installation-a' if ordinal == 1 else 'installation-restored'
    state = 'owner-state-a' if ordinal == 1 else 'owner-state-restored'
    name = 'heptabao-authbus-installed-qa-' + plan['runId'] + '-' + str(ordinal) + '.service'
    unit = plan['units'][ordinal - 1]
    target = Path('/run/systemd/system') / name
    need(unit['name'] == name and unit['ordinal'] == ordinal
         and unit['runtime'] == str(target)
         and unit['proposal'] == str(work / installation / name), 'exact_unit_paths')
    need(re.fullmatch(r'[0-9a-f]{64}',payload['bindingSha256']) is not None
         and re.fullmatch(r'[0-9]+',payload['startTime']) is not None, 'fixed_process_identity')
    expected_argv = ['/usr/bin/python3','-I','-S','-B',
                     str(work/'code/authbus_coordinator_installed.py'),'service','serve',
                     '--binding',str(work/installation/'installation.private.json'),
                     '--binding-sha256',payload['bindingSha256']]
    cgroup = '/system.slice/' + name
    need(payload['controlGroup'] == cgroup, 'fixed_system_unit_cgroup')
    fds = []
    try:
        run_fd = directory(work,(0,actor['uid'])); fds.append(run_fd)
        need(identity(os.fstat(run_fd)) == payload['runIdentity'], 'original_fresh_run_directory')
        unit_dir = directory(target.parent,(0,)); fds.append(unit_dir)
        before_unit = os.stat(name,dir_fd=unit_dir,follow_symlinks=False)
        need(stat.S_ISREG(before_unit.st_mode) and before_unit.st_nlink == 1
             and identity(before_unit) == payload['unitIdentity']
             and before_unit.st_uid == before_unit.st_gid == 0
             and stat.S_IMODE(before_unit.st_mode) == 0o644, 'original_root_unit_identity')
        raw = read_at(unit_dir,name,65536)
        need(raw == unit['unitText'].encode()
             and hashlib.sha256(raw).hexdigest() == unit['unitSha256'], 'original_root_unit_bytes')
        proc_fd = os.open('/proc/' + str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); fds.append(proc_fd)
        result.update(pid=pid,unitName=name,ordinal=ordinal,
                      procDirectoryIdentityBefore=identity(os.fstat(proc_fd)),paths={})
        def start():
            return read_at(proc_fd,'stat',65536).decode().rsplit(')',1)[1].split()[19]
        before = start()
        result['startTimeBefore'] = before
        need(before == payload['startTime'], 'original_pid_start_time')
        argv = [v.decode() for v in read_at(proc_fd,'cmdline',16384).split(b'\0') if v]
        result['argvExact'] = argv == expected_argv
        result['argvSha256'] = hashlib.sha256(b'\0'.join(v.encode() for v in argv)).hexdigest()
        need(result['argvExact'], 'actual_expanded_argv')
        exe = os.readlink('exe',dir_fd=proc_fd)
        result['executableExact'] = exe == str(Path('/usr/bin/python3').resolve())
        need(result['executableExact'], 'actual_python_executable')
        process_groups = read_at(proc_fd,'cgroup',65536).decode().splitlines()
        result['cgroupExact'] = process_groups == ['0::' + cgroup]
        need(result['cgroupExact'], 'actual_owned_cgroup')
        cgroup_fd = directory('/sys/fs/cgroup' + cgroup,(0,)); fds.append(cgroup_fd)
        members = [int(v) for v in read_at(cgroup_fd,'cgroup.procs',65536).split()]
        need(pid in members, 'actual_owned_cgroup_member')
        status = read_at(proc_fd,'status',65536).decode().splitlines()
        for key in ('Uid','Gid'):
            values = next(line for line in status if line.startswith(key + ':'))
            result[key] = list(map(int,values.split()[1:]))
        need(result['Uid'] == [actor['uid']] * 4 and result['Gid'] == [actor['gid']] * 4,
             'actual_nonroot_identity')
        result['noNewPrivileges'] = any(re.fullmatch(r'NoNewPrivs:\s+1',line) for line in status)
        result['userNamespace'] = os.readlink('ns/user',dir_fd=proc_fd)
        result['observerUserNamespace'] = os.readlink('/proc/self/ns/user')
        need(result['observerUserNamespace'] == payload['observerUserNamespace'], 'original_observer_namespace')
        mounts = []
        for line in read_at(proc_fd,'mountinfo',1024*1024).decode().splitlines():
            fields = line.split()
            mounts.append({'id':int(fields[0]),'parentId':int(fields[1]),
                           'mountpoint':fields[4],'flags':sorted(fields[5].split(','))})
        for key, path in (('code',work/'code/authbus_coordinator_installed.py'),
                          ('config',work/installation/'installation.private.json'),('state',work/state)):
            matches = [m for m in mounts if str(path) == m['mountpoint']
                       or str(path).startswith(m['mountpoint'].rstrip('/') + '/')]
            need(bool(matches), 'exact_path_mount_present')
            selected = max(matches,key=lambda m:len(m['mountpoint']))
            row = {'path':str(path),'matchingMounts':matches,'selectedMount':selected}
            result['paths'][key] = row
            # This is a metadata-only path open through the already held proc
            # directory; no auth/config/state file bytes are opened for reading.
            path_fd = os.open('root' + str(path),os.O_PATH,dir_fd=proc_fd)
            try:
                row['statvfsReadOnly'] = bool(os.fstatvfs(path_fd).f_flag & os.ST_RDONLY)
                row['pathIdentity'] = identity(os.fstat(path_fd))
            finally:
                os.close(path_fd)
        result['startTimeAfter'] = start()
        result['procDirectoryIdentityAfter'] = identity(os.fstat(proc_fd))
        result['sameOriginalPid'] = result['startTimeAfter'] == before
        need(result['sameOriginalPid']
             and result['procDirectoryIdentityAfter'] == result['procDirectoryIdentityBefore']
             and os.readlink('exe',dir_fd=proc_fd) == exe
             and read_at(proc_fd,'cmdline',16384) == b'\0'.join(v.encode() for v in argv) + b'\0'
             and read_at(proc_fd,'cgroup',65536).decode().splitlines() == ['0::' + cgroup]
             and identity(os.stat(name,dir_fd=unit_dir,follow_symlinks=False)) == payload['unitIdentity']
             and identity(os.fstat(run_fd)) == payload['runIdentity'], 'ending_original_identity_fence')
        result['ok'] = True
    finally:
        for fd in reversed(fds):
            os.close(fd)


def root_observer_main(payload):
    result = {'schema':'heptabao.installed-owned-proc-metadata.v1','ok':False,
              'rootObserver':True,'readOnly':True,'credentialsRead':False,'targetEnvironmentRead':False}
    try:
        observe(payload,result)
    except Exception as exc:
        result['ok'] = False
        result['error'] = str(exc) if isinstance(exc,Refused) else type(exc).__name__
    print(json.dumps(result,sort_keys=True),flush=True)
    return 0 if result['ok'] else 1
