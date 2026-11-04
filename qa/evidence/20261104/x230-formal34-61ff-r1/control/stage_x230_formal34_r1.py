#!/usr/bin/env python3
"""Stage the exact Linux normal candidate and independent full34 controls."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

BASE = Path("/home/qian")
ROOT = BASE / "heptabao-kv2-formal34-61ff-7071-20261104-r1"
SOURCE = ROOT / "source"
CONTROL = ROOT / "control"
ARTIFACTS = ROOT / "artifacts"
HEAD = "70714605c39014bea93545f7f6aa4217d2a23544"
TREE = "ef0ae63704a06b7dda1038e02abcc3233a2a438f"
REMOTE_SOURCE = "/home/qian-qi/heptabao-bao-acceptance-unified-61ff-20261104-r1/source"
REMOTE_BINARY = "/home/qian-qi/heptabao-bao-acceptance-unified-61ff-20261104-r1/normal-build-r6/retained-heptabao-server"
PYTHON = Path("/usr/bin/python3.12")
PYTHON_SHA = "e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f"
BINARY_SHA = "199e2b6a91346db2b61a6066827a0b4ee658991758926ed9c6b50a8f1ea98a71"
BINARY_BYTES = 110846072
STAGE_SECONDS = 240
EXPECTED_FILES = {
    "control/frozen-source.public.json": "ad59fb02e3affc08720c13f7349d93a99df646ca7616f9a10e41e1cc6ddbeff1",
    "control/kv2_271_lossless_native_live_derived_r1.py": "d9e9f2a379f1fa326a61b8fa29585751223a669424ffe28f6b171b18526a4b68",
    "control/run_x230_full34_r1.py": "a7b97a452d4064c02dd64c52a1e3e99e8af120598506a215d8fabde9e06399d8",
    "artifacts/normal-build-result.public.json": "caad94cd4f0e6ed2028cf5742479bda0b4521490fc7912d461f40bad3da5cc33",
    "artifacts/production-build.public.json": "3e7f2694ae8994812546acd778c03731bd02a5313177d98e6e2943ada34bfedd",
    "artifacts/server-cargo-artifact.public.json": "94c2bdf2072931c65759a1266096375084aac7a2b6024623ada73779f4582594",
}
creating = False
pending_signal = None


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def remaining(until):
    left = until - time.monotonic()
    need(left > 0, 'original_absolute_deadline')
    return left


def read_owned(path, limit=4 * 1024 * 1024):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 1000
             and before.st_nlink == 1 and before.st_size <= limit, 'file_custody')
        chunks, count = [], 0
        while count <= limit:
            data = os.read(fd, min(65536, limit + 1 - count))
            if not data:
                break
            chunks.append(data)
            count += len(data)
        need(count == before.st_size
             and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             'file_changed')
        return b''.join(chunks)
    finally:
        os.close(fd)


def hash_owned(path, until=None, limit=1024 * 1024 * 1024, single_link=True, owner=1000):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == owner
             and (not single_link or before.st_nlink == 1)
             and before.st_size <= limit, 'hash_file_custody')
        digest, count = hashlib.sha256(), 0
        while True:
            if until is not None:
                remaining(until)
            data = os.read(fd, 1024 * 1024)
            if not data:
                break
            digest.update(data)
            count += len(data)
        need(count == before.st_size
             and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             'hashed_file_changed')
        return digest.hexdigest()
    finally:
        os.close(fd)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_raw(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    sync_dir(path.parent)
    return sha(raw)


def write_json(path, value):
    return write_raw(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


def directory(path, device, mount=False):
    need(path.resolve(strict=True) == path, 'directory_symlink')
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_dev == device, 'directory_device')
    need(info.st_uid in (0, 1000) if mount else info.st_uid == 1000, 'directory_owner')
    return info


def owned_ancestors(path, device):
    need(path == BASE or BASE in path.parents, 'outside_owned_base')
    for item in reversed((path, *path.parents)):
        if item == BASE or BASE in item.parents:
            directory(item, device)


def interrupted(signum, frame):
    global pending_signal
    if creating:
        pending_signal = signum
    else:
        raise RuntimeError('owned_job_interrupted')


def group_members(pgid):
    proc = subprocess.Popen(['/bin/ps', '-axo', 'pid=,pgid='],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        output, unused = proc.communicate(timeout=5)
    except BaseException:
        proc.kill()
        proc.communicate(timeout=5)
        raise
    need(proc.returncode == 0, 'group_observation_failed')
    return [int(fields[0]) for row in output.splitlines()
            if len(fields := row.split()) == 2 and int(fields[1]) == pgid]


class OwnedRunner:
    """Only a still-unreaped direct child authorizes group cleanup."""
    def __init__(self, output, environment):
        self.output = output
        self.environment = environment
        self.child = None
        self.reaped = True
        self.records = []

    def exited(self):
        need(self.child is not None and not self.reaped, 'owned_unreaped_child_required')
        event = os.waitid(os.P_PID, self.child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        need(event is None or event.si_pid == self.child.pid, 'unexpected_waitid_identity')
        return event is not None

    def signal(self, signum):
        exited = self.exited()
        if not exited:
            try:
                need(os.getpgid(self.child.pid) == self.child.pid, 'owned_group_changed')
            except ProcessLookupError:
                need(self.exited(), 'live_owned_group_missing')
        try:
            os.killpg(self.child.pid, signum)
        except ProcessLookupError:
            pass

    def cleanup(self):
        if self.child is None:
            return None
        if self.reaped:
            return {'pid': self.child.pid, 'returncode': self.child.returncode,
                    'already_reaped': True, 'forced': False,
                    'remaining': group_members(self.child.pid),
                    'group_signalled_after_reap': False}
        exited = self.exited()
        others = [pid for pid in group_members(self.child.pid) if pid != self.child.pid]
        forced = False
        if not exited or others:
            self.signal(signal.SIGTERM)
            stop = time.monotonic() + 5
            while time.monotonic() < stop:
                exited = self.exited()
                others = [pid for pid in group_members(self.child.pid) if pid != self.child.pid]
                if exited and not others:
                    break
                time.sleep(0.025)
            if not exited or others:
                self.signal(signal.SIGKILL)
                forced = True
                stop = time.monotonic() + 5
                while time.monotonic() < stop:
                    exited = self.exited()
                    others = [pid for pid in group_members(self.child.pid) if pid != self.child.pid]
                    if exited and not others:
                        break
                    time.sleep(0.025)
        # No later group signal is allowed once this original anchor is reaped.
        code = self.child.wait(timeout=5)
        self.reaped = True
        return {'pid': self.child.pid, 'returncode': code, 'already_reaped': False,
                'forced': forced, 'remaining': group_members(self.child.pid),
                'group_cleanup_before_reap': True, 'group_signalled_after_reap': False}

    def run(self, label, argv, until, cwd=SOURCE, expect_zero=True):
        global creating
        remaining(until)
        need(self.child is None or self.reaped, 'one_owned_child')
        need(re.fullmatch('[a-z0-9_-]+', label), 'closed_command_label')
        stdout_path = self.output / (label + '.stdout')
        stderr_path = self.output / (label + '.stderr')
        began = time.monotonic()
        record = {'label': label, 'argv': argv, 'cwd': str(cwd),
                  'timed_out': False, 'exit_code': None,
                  'remaining_at_start_seconds': remaining(until)}
        self.records.append(record)
        error = None
        with stdout_path.open('xb') as so, stderr_path.open('xb') as se:
            try:
                creating = True
                try:
                    self.child = subprocess.Popen(
                        argv, cwd=cwd, env=self.environment,
                        stdin=subprocess.DEVNULL, stdout=so, stderr=se,
                        start_new_session=True)
                    self.reaped = False
                    record['owned_pgid'] = self.child.pid
                finally:
                    creating = False
                if pending_signal is not None:
                    raise RuntimeError('interrupted_during_spawn')
                while not self.exited():
                    if time.monotonic() >= until:
                        record['timed_out'] = True
                        raise RuntimeError('original_absolute_deadline')
                    time.sleep(min(0.025, max(0, until - time.monotonic())))
            except BaseException as exc:
                error = exc
                record['error_class'] = type(exc).__name__
                record['error_code'] = str(exc) if isinstance(exc, RuntimeError) else None
            finally:
                cleanup = self.cleanup()
                record['cleanup'] = cleanup
                if cleanup is not None:
                    record['exit_code'] = cleanup['returncode']
                    record['remaining'] = cleanup['remaining']
                so.flush()
                se.flush()
                os.fsync(so.fileno())
                os.fsync(se.fileno())
        record.update(elapsed_seconds=time.monotonic() - began,
                      remaining_at_end_seconds=max(0, until - time.monotonic()),
                      stdout_sha256=hash_owned(stdout_path),
                      stderr_sha256=hash_owned(stderr_path),
                      stdout_bytes=stdout_path.stat().st_size,
                      stderr_bytes=stderr_path.stat().st_size)
        write_json(self.output / (label + '.public.json'), record)
        if error is not None:
            raise error
        need(not record['timed_out'] and not record.get('remaining')
             and not record['cleanup']['forced'], 'command_cleanup_or_deadline_failed')
        if expect_zero:
            need(record['exit_code'] == 0, 'command_nonzero_' + label)
        remaining(until)
        return read_owned(stdout_path, 64 * 1024 * 1024)

    def git(self, label, until, *args, directory_path=SOURCE):
        return self.run(label, ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null',
                                '-c', 'commit.gpgsign=false', '-C', str(directory_path),
                                *args], until).decode('utf-8', 'strict').strip()



stage_started = False

def main():
    global stage_started
    os.umask(0o077)
    began = time.monotonic()
    until = began + STAGE_SECONDS
    need(len(sys.argv) == 3 and all(re.fullmatch("[0-9a-f]{64}", s) for s in sys.argv[1:]),
         "stage_source_and_packet_pins")
    packet_raw = ADMITTED_PACKET_RAW
    need(len(packet_raw) <= 1024 * 1024 and sha(packet_raw) == sys.argv[1], "stage_packet_pin")
    packet = json.loads(packet_raw)
    need(set(packet) == {"schema", "stage_source", "files", "file_pins"}
         and packet["schema"] == "heptabao.x230-formal34-stage-input.v1", "closed_stage_packet")
    need(sha(packet["stage_source"].encode()) == sys.argv[2], "stage_source_pin")
    need(set(packet["files"]) == set(packet["file_pins"]) == set(EXPECTED_FILES),
         "closed_file_set")
    for name, expected in EXPECTED_FILES.items():
        raw = packet["files"][name].encode()
        need(sha(raw) == packet["file_pins"][name] == expected, "control_file_pin")
        if name.endswith(".py"):
            compile(raw, str(ROOT / name), "exec")
    frozen = json.loads(packet["files"]["control/frozen-source.public.json"])
    need(frozen["source"] == HEAD and frozen["tree"] == TREE
         and frozen["source_path"] == REMOTE_SOURCE and len(frozen["files"]) == 62,
         "frozen_source_binding")
    need(platform.system() == "Linux" and platform.machine() == "x86_64"
         and platform.node() == "qian-ThinkPad-X230"
         and os.getuid() == os.geteuid() == 1000, "actual_x230_operator")
    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
         and all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")),
         "sole_nonreaping_owner")
    need(Path(sys.executable).resolve(strict=True) == PYTHON
         and hash_owned(PYTHON, until, owner=0) == PYTHON_SHA, "fixed_python")
    need(BASE.resolve(strict=True) == BASE, "home_symlink")
    device = BASE.lstat().st_dev
    directory(BASE, device)
    need(not BASE.stat().st_mode & 0o022 and not ROOT.exists() and not ROOT.is_symlink(),
         "fresh_owned_root")
    need(shutil.disk_usage(BASE).free >= 2 * 1024 * 1024 * 1024, "stage_disk_reserve")
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8", "TZ": "UTC",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
           "GIT_SSH_COMMAND": "/usr/bin/ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -o ConnectionAttempts=1"}
    if "SSH_AUTH_SOCK" in os.environ:
        env["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
    remaining(until)
    stage_started = True
    ROOT.mkdir(mode=0o700)
    for path in (CONTROL, SOURCE, ARTIFACTS, ROOT / "evidence"):
        path.mkdir(mode=0o700)
    runner = OwnedRunner(CONTROL, env)
    result = {"schema": "heptabao.x230-formal34-source-artifacts-stage.v1",
              "status": "failed", "source_commit": HEAD, "source_tree": TREE,
              "source_path": str(SOURCE), "root": str(ROOT),
              "stage_source_sha256": sys.argv[2], "stage_packet_sha256": sys.argv[1],
              "original_stage_seconds": STAGE_SECONDS, "python_sha256": PYTHON_SHA,
              "new_binary_executed": False, "product_service_started": False,
              "production_changed": False, "full_replacement_qualified": False,
              "source_clean": False, "all_owned_commands_stopped": False}
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        write_raw(CONTROL / "source-stage-input.public.json", packet_raw)
        write_raw(CONTROL / "stage_x230_formal34_r1.py", packet["stage_source"].encode(), 0o500)
        for name in sorted(EXPECTED_FILES):
            path = ROOT / name
            owned_ancestors(path.parent, device)
            raw = packet["files"][name].encode()
            write_raw(path, raw, 0o500 if name.endswith(".py") else 0o600)
            need(sha(read_owned(path)) == EXPECTED_FILES[name], "control_write_readback")
        runner.git("git-init", until, "init", "--quiet")
        runner.git("git-fetch-fixed", until, "fetch", "--no-tags", "--depth=1",
                   "--no-recurse-submodules", "rog:" + REMOTE_SOURCE, HEAD)
        runner.git("git-checkout-fixed", until, "checkout", "--detach", HEAD)
        need(runner.git("git-head", until, "rev-parse", "HEAD") == HEAD, "source_head")
        need(runner.git("git-tree", until, "rev-parse", "HEAD^{tree}") == TREE, "source_tree")
        need(runner.git("git-clean-before", until, "status", "--porcelain=v1",
                        "--untracked-files=all") == "", "source_clean_before")
        verified, seen = [], set()
        for pin in frozen["files"]:
            remaining(until)
            rel = Path(pin["path"])
            need(not rel.is_absolute() and ".." not in rel.parts
                 and str(rel) not in seen, "frozen_source_path")
            seen.add(str(rel))
            path = SOURCE / rel
            owned_ancestors(path.parent, device)
            raw = read_owned(path)
            need(path.lstat().st_dev == device and len(raw) == pin["bytes"]
                 and sha(raw) == pin["sha256"] and blob(raw) == pin["git_blob"], "frozen_source_file")
            verified.append({"path": str(rel), "bytes": len(raw), "sha256": sha(raw),
                             "git_blob": blob(raw)})
        need(len(verified) == 62, "frozen_source_denominator")
        temporary = ARTIFACTS / "heptabao-server.transfer"
        binary = ARTIFACTS / "heptabao-server"
        need(not os.path.lexists(temporary) and not os.path.lexists(binary), "fresh_binary_paths")
        runner.run("copy-fixed-binary",
                   ["/usr/bin/scp", "-B", "-p", "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
                    "-o", "ConnectionAttempts=1", "rog:" + REMOTE_BINARY, str(temporary)],
                   until, cwd=ROOT)
        need(hash_owned(temporary, until) == BINARY_SHA and temporary.stat().st_size == BINARY_BYTES,
             "copied_binary_pin")
        temporary.chmod(0o700)
        os.rename(temporary, binary)
        sync_dir(ARTIFACTS)
        need(hash_owned(binary, until) == BINARY_SHA and binary.stat().st_size == BINARY_BYTES,
             "retained_binary_pin")
        need(runner.git("git-clean-after", until, "status", "--porcelain=v1",
                        "--untracked-files=all") == "", "source_clean_after")
        remaining(until)
        result.update(status="staged_exact_7071", source_clean=True,
                      binary_sha256=BINARY_SHA, binary_bytes=BINARY_BYTES,
                      verified_source_files=verified, control_file_pins=EXPECTED_FILES,
                      remote_source_readonly="rog:" + REMOTE_SOURCE,
                      remote_binary_readonly="rog:" + REMOTE_BINARY)
    except BaseException as error:
        result["failure_class"] = type(error).__name__
        result["failure_code"] = str(error) if isinstance(error, RuntimeError) else None
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        result["commands"] = runner.records
        try:
            result["last_owned_cleanup"] = runner.cleanup()
            complete = bool(runner.records) and all(
                record.get("exit_code") == 0 and not record.get("remaining")
                and not record.get("timed_out") and not record.get("cleanup", {}).get("forced")
                and not record.get("cleanup", {}).get("group_signalled_after_reap")
                for record in runner.records)
            result["all_owned_commands_stopped"] = (
                complete and not result["last_owned_cleanup"].get("remaining"))
            if not result["all_owned_commands_stopped"]:
                result["status"] = "failed"
        except Exception as error:
            result["status"] = "failed"
            result["cleanup_error"] = type(error).__name__
        result["elapsed_seconds"] = time.monotonic() - began
        if result["elapsed_seconds"] >= STAGE_SECONDS:
            result.update(status="failed", failure_code="original_stage_deadline")
        digest = write_json(CONTROL / "source-artifacts-stage.public.json", result)
        sync_dir(ROOT)
        print(json.dumps({"status": result["status"],
                          "result": str(CONTROL / "source-artifacts-stage.public.json"),
                          "sha256": digest, "source_commit": HEAD, "source_tree": TREE,
                          "new_binary_executed": False, "full_replacement_qualified": False},
                         sort_keys=True), flush=True)
    return 0 if result["status"] == "staged_exact_7071" else 1

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"status": "failed_after_stage_started" if stage_started else "refused_before_stage",
                          "error_class": type(error).__name__,
                          "error_code": str(error) if isinstance(error, RuntimeError) else None,
                          "full_replacement_qualified": False}, sort_keys=True), flush=True)
        raise SystemExit(2) from None
