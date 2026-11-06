"""Create new private Linux share/backup receivers; no secret or product I/O.

One create-only operation on an explicitly configured host. Existing parents
are opened without following links. Failure leaves only newly created paths,
records a fixed public code, and never deletes or retries an existing object.
"""
import json
import os
import pathlib
import pwd
import signal
import stat
import sys
import time

ENTRY = time.monotonic()
WORK = 52
TOTAL = 60
ROOT_NAME = "heptabao-formal-kv2-custody-20261106-r1"
HOSTS = {"rog": ("/home/qian-qi", 1000, "share-2"),
         "pocket4": ("/home/alex", 1000, "share-3")}
owned = []
identities = []
created = []
primary = None
cleanup = []
report = {"schema": "heptabao.formal-kv2-private-receiver-preparation.v1",
          "runtime_seconds": TOTAL, "work_seconds": WORK,
          "secret_material_written_or_read": False, "product_executed": False,
          "network_called": False, "old_assets_modified": False,
          "automatic_retry": False, "formal_kv2_qualified": False,
          "independent_backup_qualified": False, "split_key_custody_qualified": False,
          "child_processes_started": 0, "status": "not_completed"}


class Rejected(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Rejected(code)


def deadline(_signum=None, _frame=None):
    raise Rejected("original_work_deadline")


def now():
    need(time.monotonic() - ENTRY < WORK, "original_work_deadline")


def ident(st):
    return {"dev": st.st_dev, "inode": st.st_ino, "uid": st.st_uid,
            "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode),
            "kind": "directory" if stat.S_ISDIR(st.st_mode) else "other"}


def admit(fd, path, expected_uid, private=False):
    now()
    st = os.fstat(fd)
    need(stat.S_ISDIR(st.st_mode), "directory_required")
    need(st.st_uid == expected_uid, "directory_owner_mismatch")
    need(not stat.S_IMODE(st.st_mode) & 0o022, "writable_parent_rejected")
    if private:
        need(stat.S_IMODE(st.st_mode) == 0o700, "private_directory_mode")
    need(pathlib.Path(path).resolve(strict=True) == pathlib.Path(path), "canonical_directory_required")
    need(ident(os.lstat(path)) == ident(st), "directory_path_fd_mismatch")
    identities.append((path, fd, ident(st)))
    return fd


def open_child(parent, name, path, expected_uid, private=False):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    owned.append(fd)
    return admit(fd, path, expected_uid, private)


def create_child(parent, name, path):
    now()
    os.mkdir(name, 0o700, dir_fd=parent)
    created.append(path)
    os.fsync(parent)
    fd = open_child(parent, name, path, 1000, True)
    os.fsync(fd)
    return fd


def write_exact(parent, name, content):
    now()
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    owned.append(fd)
    try:
        left = memoryview(content)
        while left:
            now()
            count = os.write(fd, left)
            need(count > 0, "receipt_short_write")
            left = left[count:]
        os.fsync(fd)
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == 1000
             and stat.S_IMODE(st.st_mode) == 0o600 and st.st_size == len(content), "receipt_file_metadata")
    finally:
        os.close(fd)
        owned.remove(fd)
    os.fsync(parent)


try:
    need(len(sys.argv) == 2 and sys.argv[1] in HOSTS, "fixed_host_role_required")
    host = sys.argv[1]
    home, uid, share_role = HOSTS[host]
    need(sys.platform.startswith("linux"), "linux_receiver_required")
    need(os.getuid() == uid and os.geteuid() == uid, "receiver_effective_owner_mismatch")
    account = pwd.getpwuid(uid)
    need(account.pw_dir == home, "receiver_home_mismatch")
    os.umask(0o077)
    signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, WORK - (time.monotonic() - ENTRY)))
    rootfd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    owned.append(rootfd)
    admit(rootfd, "/", 0)
    homeparent = open_child(rootfd, "home", "/home", 0)
    homefd = open_child(homeparent, home.rsplit("/", 1)[1], home, uid)
    newroot = home + "/" + ROOT_NAME
    receiverfd = create_child(homefd, ROOT_NAME, newroot)
    children = {}
    for role in ("unseal-share", "encrypted-archives", "evidence"):
        path = newroot + "/" + role
        fd = create_child(receiverfd, role, path)
        children[role] = {"path": path, "identity": ident(os.fstat(fd))}
    for path, fd, before in identities:
        need(ident(os.fstat(fd)) == before and ident(os.lstat(path)) == before, "owned_directory_changed")
    report.update({"host": host, "uid": uid, "home": home, "share_role": share_role,
                   "receiver_root": newroot, "root_identity": ident(os.fstat(receiverfd)),
                   "directories": children, "created_directory_count": len(created),
                   "receiver_directories_empty": all(not os.listdir(row["path"]) for row in children.values()),
                   "owned_directory_count": len(identities), "point_in_time_directory_admission": True,
                   "status": "prepared"})
    need(report["receiver_directories_empty"], "unexpected_receiver_contents")
    write_exact(receiverfd, "PREPARED.public.json", (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    now()
except Rejected as exc:
    primary = str(exc)
except FileExistsError:
    primary = "create_only_destination_already_exists"
except BaseException as exc:
    primary = "unexpected_" + type(exc).__name__
finally:
    signal.setitimer(signal.ITIMER_REAL, 0)
    for fd in reversed(owned):
        try:
            os.close(fd)
        except OSError:
            cleanup.append("owned_fd_close_failed")
    closed = len(owned)
    owned.clear()
    report.update({"primary_failure_code": primary, "cleanup_failure_codes": cleanup,
                   "all_owned_fds_closed": not cleanup, "final_closed_fd_count": closed,
                   "created_paths": created, "elapsed_seconds": time.monotonic() - ENTRY,
                   "succeeded": primary is None and not cleanup})
    print(json.dumps(report, sort_keys=True), flush=True)
sys.exit(0 if primary is None and not cleanup else 1)
