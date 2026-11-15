"""Create only the two fixed empty directories for one public source delivery."""
import json, os, platform, stat, time
from pathlib import Path

PARENT = Path('/home/alex')
ROOT = PARENT / 'heptabao-kv2-ha-convergence-49d3b-authbus-20261107-r1'
END = time.monotonic() + 10
FDS = []
REPORT = {'schema': 'heptabao.pocket4-source-control-create.v1', 'ok': False,
          'sourceOrBuildExecuted': False, 'productionChanged': False, 'automaticRetry': False}

class Refused(Exception):
    pass

def need(ok, code):
    if not ok:
        raise Refused(code)

def identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode'))

def opened(name, parent=None):
    need(time.monotonic() < END, 'original_deadline')
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                 **({} if parent is None else {'dir_fd': parent}))
    FDS.append({'fd': fd, 'attempted': False, 'closed': False})
    return fd

def new_directory(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise Refused('new_directory_must_be_absent')
    os.mkdir(name, 0o700, dir_fd=parent)
    fd = opened(name, parent)
    info = os.fstat(fd)
    need(info.st_uid == os.getuid() and info.st_gid == os.getgid()
         and stat.S_IMODE(info.st_mode) == 0o700
         and identity(info) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
         and not os.listdir(fd), 'new_owned_empty_private_directory')
    os.fsync(fd); os.fsync(parent)
    return fd

try:
    os.umask(0o077)
    need(platform.node() == 'alex-G1628-04' and platform.system() == 'Linux'
         and platform.machine() == 'x86_64' and os.getuid() == 1000, 'exact_pocket4_account')
    fd = opened('/')
    paths = []
    path = Path('/')
    for name in ('home', 'alex'):
        path = path / name
        fd = opened(name, fd)
        info = os.fstat(fd)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
             and not info.st_mode & 0o022 and identity(info) == identity(path.lstat()),
             'owned_unchanged_parent')
        paths.append((path, fd, identity(info)))
    need(os.fstat(fd).st_uid == os.getuid(), 'owned_home_parent')
    root = new_directory(fd, ROOT.name)
    out = new_directory(root, 'build-test-r1')
    need(os.listdir(root) == ['build-test-r1'] and not os.listdir(out), 'exact_new_membership')
    for path, parent, expected in paths:
        need(identity(os.fstat(parent)) == identity(path.lstat()) == expected, 'held_parent_unchanged')
    need(time.monotonic() < END, 'original_deadline')
    REPORT.update(ok=True, root=str(ROOT), control=str(ROOT / 'build-test-r1'),
                  createdDirectories=2, createdFiles=0, originalInputsModified=False)
except BaseException as error:
    REPORT['error'] = str(error) if isinstance(error, Refused) else type(error).__name__
finally:
    for row in reversed(FDS):
        row['attempted'] = True
        try:
            os.close(row['fd']); row['closed'] = True
        except BaseException:
            REPORT['ok'] = False
    REPORT['descriptorCount'] = len(FDS)
    REPORT['allDescriptorsClosedOnce'] = all(x['attempted'] and x['closed'] for x in FDS)
    REPORT['ok'] = REPORT['ok'] and REPORT['allDescriptorsClosedOnce'] and time.monotonic() < END
    print(json.dumps(REPORT, sort_keys=True), flush=True)
raise SystemExit(0 if REPORT['ok'] else 1)
