#!/usr/bin/env python3
"""Run pinned full34 business checks against a fresh formal native V6 fixture."""
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import sys
import time

ROOT = Path("/home/qian/heptabao-kv2-formal34-61ff-7071-20261104-r1")
SOURCE = ROOT / "source"
CONTROL = ROOT / "control"
ARTIFACTS = ROOT / "artifacts"
OUT = ROOT / "evidence" / "full34-r1"
PYTHON = Path("/usr/bin/python3.12")
PYTHON_SHA = "e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f"
HEAD = "70714605c39014bea93545f7f6aa4217d2a23544"
TREE = "ef0ae63704a06b7dda1038e02abcc3233a2a438f"
BINARY_SHA = "199e2b6a91346db2b61a6066827a0b4ee658991758926ed9c6b50a8f1ea98a71"
BINARY_BYTES = 110846072
HELPER_SHA = "d9e9f2a379f1fa326a61b8fa29585751223a669424ffe28f6b171b18526a4b68"
ORIGINAL_HELPER_SHA = "383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581"
BUILD_SHA = "caad94cd4f0e6ed2028cf5742479bda0b4521490fc7912d461f40bad3da5cc33"
ARTIFACT_SHA = "94c2bdf2072931c65759a1266096375084aac7a2b6024623ada73779f4582594"
ORACLE = Path("/home/qian/heptabao-official-271-fresh-20261029-r1/bao")
ARCHIVE = ORACLE.with_name("official-openbao-2.7.1-linux-amd64.tar.gz")
ORACLE_SHA = "535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea"
ARCHIVE_SHA = "0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243"
TOTAL_SECONDS = 1800
ORIGINAL_POPEN = subprocess.Popen
ORIGINAL_KILLPG = os.killpg
children = []
signals = []
creating = False
pending_signal = None
expired = False
until = None

def need(value, label):
    if not value:
        raise RuntimeError(label)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def remaining():
    left = until - time.monotonic()
    need(not expired and left > 0, "original_outer_absolute_deadline")
    return left

def read_file(path, maximum=1024 * 1024, owner=1000):
    path = Path(path)
    need(path.resolve(strict=True) == path, "input_path_symlink")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == owner
             and before.st_nlink == 1 and before.st_size <= maximum, "input_file_custody")
        chunks, count = [], 0
        while count <= maximum:
            data = os.read(fd, min(65536, maximum + 1 - count))
            if not data:
                break
            chunks.append(data)
            count += len(data)
        need(count == before.st_size
             and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             "input_file_changed")
        return b"".join(chunks)
    finally:
        os.close(fd)

def hash_file(path, owner=1000):
    path = Path(path)
    need(path.resolve(strict=True) == path, "hash_path_symlink")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == owner
             and before.st_nlink == 1, "hash_file_custody")
        h, count = hashlib.sha256(), 0
        while True:
            remaining()
            data = os.read(fd, 1048576)
            if not data:
                break
            h.update(data)
            count += len(data)
        need(count == before.st_size
             and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             "hashed_file_changed")
        return {"sha256": h.hexdigest(), "bytes": count}
    finally:
        os.close(fd)

def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def enc(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()

def owned_directory(path):
    need(path.resolve(strict=True) == path, "directory_symlink")
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 1000
         and not info.st_mode & 0o022, "directory_custody")

def birth(pid):
    root = Path("/proc") / str(pid)
    raw = (root / "stat").read_text()
    tail = raw[raw.rfind(") ") + 2:].split()
    return {"pid": pid, "ppid": int(tail[1]), "pgid": int(tail[2]),
            "sid": int(tail[3]), "starttick": int(tail[19]),
            "uid": root.stat().st_uid}

def group_members(pgid):
    result = []
    for item in Path("/proc").iterdir():
        if not item.name.isdigit():
            continue
        try:
            raw = (item / "stat").read_text()
            tail = raw[raw.rfind(") ") + 2:].split()
            if int(tail[2]) == pgid:
                result.append({"pid": int(item.name), "sid": int(tail[3]),
                               "starttick": int(tail[19]), "state": tail[0]})
        except FileNotFoundError:
            continue
    return result

def interrupted(signum, frame):
    global expired, pending_signal
    expired = True
    if creating:
        pending_signal = signum
    else:
        raise RuntimeError("outer_deadline_or_interruption")

class TrackedPopen(ORIGINAL_POPEN):
    def __init__(self, *args, **kwargs):
        global creating
        remaining()
        need(not creating and not kwargs.get("shell", False), "closed_original_spawn")
        creating = True
        row = None
        try:
            super().__init__(*args, **kwargs)
            row = {"process": self, "own_group": kwargs.get("start_new_session") is True}
            children.append(row)
            row["birth"] = birth(self.pid)
            need(row["birth"]["ppid"] == os.getpid() and row["birth"]["uid"] == 1000,
                 "original_child_birth")
            if row["own_group"]:
                need(row["birth"]["pgid"] == row["birth"]["sid"] == self.pid,
                     "original_child_session")
        finally:
            creating = False
        if pending_signal is not None:
            raise RuntimeError("interrupted_during_owned_spawn")

def child_exited_unreaped(child):
    need(child.returncode is None, "unreaped_original_required")
    event = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    need(event is None or event.si_pid == child.pid, "original_waitid_identity")
    return event is not None

def checked_killpg(pgid, signum):
    matches = [row for row in children
               if row["own_group"] and row["process"].pid == pgid
               and row["process"].returncode is None]
    need(len(matches) == 1, "unanchored_group_signal_refused")
    child = matches[0]["process"]
    child_exited_unreaped(child)
    current = birth(pgid)
    original = matches[0]["birth"]
    need(current == original and current["pgid"] == current["sid"] == pgid,
         "original_group_identity_changed")
    row = {"pid": pgid, "signal": int(signum), "original_child_unreaped": True,
           "sent": False, "group_signalled_after_reap": False}
    signals.append(row)
    try:
        ORIGINAL_KILLPG(pgid, signum)
        row["sent"] = True
    except ProcessLookupError:
        row["group_already_absent"] = True

def cleanup_all():
    records = []
    for item in reversed(children):
        child, own_group = item["process"], item["own_group"]
        record = {"pid": child.pid, "birth": item.get("birth"), "own_group": own_group,
                  "already_reaped": child.returncode is not None,
                  "forced_by_outer": False, "group_signalled_after_reap": False}
        try:
            if child.returncode is None:
                record["forced_by_outer"] = True
                child_exited_unreaped(child)
                if own_group:
                    checked_killpg(child.pid, signal.SIGKILL)
                    stop = time.monotonic() + 5
                    while time.monotonic() < stop:
                        others = [row for row in group_members(child.pid) if row["pid"] != child.pid]
                        if child_exited_unreaped(child) and not others:
                            break
                        time.sleep(0.025)
                    record["remaining_before_reap"] = group_members(child.pid)
                else:
                    child.kill()
                child.wait(timeout=5)
            record["returncode"] = child.returncode
            record["remaining"] = group_members(child.pid) if own_group else []
            record["original_wait_completed"] = child.returncode is not None
        except Exception as error:
            record["cleanup_error"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
            record["original_wait_completed"] = child.returncode is not None
        records.append(record)
    return records

def git(*args):
    return subprocess.check_output(
        ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-C", str(SOURCE), *args],
        stdin=subprocess.DEVNULL, stderr=subprocess.PIPE,
        timeout=min(30, remaining())).decode().strip()

def source_snapshot():
    return {"source_commit": git("rev-parse", "HEAD"),
            "source_tree": git("rev-parse", "HEAD^{tree}"),
            "source_dirty": bool(git("status", "--porcelain=v1", "--untracked-files=all")),
            "binary": hash_file(ARTIFACTS / "heptabao-server"),
            "original_helper_sha256": sha(read_file(
                SOURCE / "qa/openbao-acceptance/kv2_271_lossless_native_live.py"))}

def main():
    global until
    began = time.monotonic()
    until = began + TOTAL_SECONDS
    os.umask(0o077)
    need(len(sys.argv) == 2 and len(sys.argv[1]) == 64
         and all(c in "0123456789abcdef" for c in sys.argv[1]), "actual_stage_receipt_pin_required")
    stage_pin = sys.argv[1]
    need(os.getuid() == os.geteuid() == 1000 and platform.node() == "qian-ThinkPad-X230"
         and platform.system() == "Linux" and platform.machine() == "x86_64", "actual_x230_operator")
    need(Path(sys.executable).resolve(strict=True) == PYTHON
         and hash_file(PYTHON, owner=0)["sha256"] == PYTHON_SHA, "fixed_python")
    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "sole_original_reaper")
    for path in (ROOT, SOURCE, CONTROL, ARTIFACTS, ROOT / "evidence"):
        owned_directory(path)
    stage_raw = read_file(CONTROL / "source-artifacts-stage.public.json")
    need(sha(stage_raw) == stage_pin, "actual_stage_receipt_pin")
    stage = json.loads(stage_raw)
    need(stage["status"] == "staged_exact_7071" and stage["source_commit"] == HEAD
         and stage["source_tree"] == TREE and stage["binary_sha256"] == BINARY_SHA
         and stage["source_clean"] is True and stage["all_owned_commands_stopped"] is True,
         "actual_stage_receipt_not_successful")
    helper_path = CONTROL / "kv2_271_lossless_native_live_derived_r1.py"
    helper_raw = read_file(helper_path)
    need(sha(helper_raw) == HELPER_SHA, "derived_helper_pin")
    compile(helper_raw, str(helper_path), "exec")
    build_raw = read_file(ARTIFACTS / "normal-build-result.public.json")
    artifact_raw = read_file(ARTIFACTS / "server-cargo-artifact.public.json")
    need(sha(build_raw) == BUILD_SHA and sha(artifact_raw) == ARTIFACT_SHA, "actual_normal_build_pins")
    build, artifact = json.loads(build_raw), json.loads(artifact_raw)
    need(build["source"] == HEAD and build["tree"] == TREE and build["source_unchanged"] is True
         and build["production_build"]["exit_code"] == 0
         and build["production_build"]["timed_out"] is False
         and build["production_build"]["remaining"] == [], "actual_normal_build_success")
    need(artifact["features"] == ["default", "native-v6-ha", "native-v6-storage"]
         and artifact["profile"]["opt_level"] == "3"
         and artifact["profile"]["debug_assertions"] is True
         and artifact["profile"]["overflow_checks"] is True
         and artifact["profile"]["test"] is False, "actual_normal_artifact_profile")
    need(any(row["sha256"] == BINARY_SHA and row["bytes"] == BINARY_BYTES
             for row in build["production_artifacts"]), "actual_artifact_bytes_bound")
    need(hash_file(ORACLE)["sha256"] == ORACLE_SHA
         and hash_file(ARCHIVE)["sha256"] == ARCHIVE_SHA, "official_271_exact_artifacts")
    need(not os.path.lexists(OUT), "fresh_full34_output_required")
    OUT.mkdir(mode=0o700)
    (OUT / "tmp").mkdir(mode=0o700)
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8", "TZ": "UTC",
                   "TMPDIR": str(OUT / "tmp"), "HB_ORACLE_BINARY": str(ORACLE),
                   "HB_ORACLE_ARCHIVE": str(ARCHIVE), "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"}
    os.environ.clear()
    os.environ.update(environment)
    subprocess.Popen = TrackedPopen
    os.killpg = checked_killpg
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(signum, interrupted)
    signal.setitimer(signal.ITIMER_REAL, remaining())
    report = {"schema": "heptabao.x230-normal-7071-formal34-controller.v1",
              "status": "failed", "source_commit": HEAD, "source_tree": TREE,
              "binary_sha256": BINARY_SHA, "helper_sha256": HELPER_SHA,
              "original_helper_sha256": ORIGINAL_HELPER_SHA,
              "stage_receipt_sha256": stage_pin,
              "original_http_seconds": 15, "original_migration_seconds": 360,
              "native_large_http_seconds": 5, "outer_absolute_seconds": TOTAL_SECONDS,
              "profile": "full34", "retained_live_payload_bytes": 17 * 2 * 1024 * 1024,
              "migration_lane": "native-large", "synthetic_only": True,
              "production_changed": False, "full_replacement_qualified": False,
              "full34_qualified": False, "v6_ha_qualified": False}
    namespace = None
    try:
        before = source_snapshot()
        need(before == {"source_commit": HEAD, "source_tree": TREE, "source_dirty": False,
                        "binary": {"sha256": BINARY_SHA, "bytes": BINARY_BYTES},
                        "original_helper_sha256": ORIGINAL_HELPER_SHA}, "exact_frozen_source")
        report["source_before"] = before
        argv = [str(helper_path), "--binary", str(ARTIFACTS / "heptabao-server"),
                "--private-work-root", str(OUT / "private-run"),
                "--profile", "full34", "--migration-lane", "native-large"]
        write_new(OUT / "intent.public.json", enc({**report, "argv": [str(PYTHON), "-I", "-S", "-B", *argv],
                  "execution_mode": "same-process exec of exact compiled helper with tracked original Popen",
                  "original_checks": 31, "candidate_fixture_options": False,
                  "network_scope": "two newly owned literal loopback TLS endpoints"}))
        sys.argv = argv
        namespace = {"__name__": "__main__", "__file__": str(helper_path)}
        code = 0
        try:
            exec(compile(helper_raw, str(helper_path), "exec"), namespace, namespace)
        except SystemExit as error:
            code = error.code
        report["helper_exit_code"] = code
        raw_summary = read_file(OUT / "private-run" / "summary.json", maximum=4 * 1024 * 1024)
        summary = json.loads(raw_summary)
        checks = summary.get("checks", [])
        required = set(namespace["CHECKS"])
        names = [row.get("case") for row in checks]
        all_passed = (len(required) == 31 and len(checks) == 31
                      and len(set(names)) == 31 and set(names) == required
                      and all(row.get("passed") is True for row in checks))
        report.update(checks_total=len(checks),
                      checks_passed=sum(row.get("passed") is True for row in checks),
                      exact_required_inventory_passed=all_passed,
                      summary_status=summary.get("status"),
                      summary_failure=summary.get("failure"),
                      summary_sha256=sha(raw_summary), summary_bytes=len(raw_summary),
                      helper_full34_qualified=summary.get("full34_qualified") is True)
        need(any(row["case"] == "report_excludes_runtime_credentials" and row["passed"] is True
                 for row in checks), "public_summary_secret_check")
        write_new(OUT / "summary.public.json", raw_summary)
        after = source_snapshot()
        report["source_after"] = after
        report["source_unchanged"] = before == after
        need(code == 0 and all_passed and summary.get("status") == "passed"
             and summary.get("full34_qualified") is True
             and summary.get("target_storage_precision_qualified") is True
             and summary.get("api_history_qualified") is True
             and before == after and sha(read_file(helper_path)) == HELPER_SHA,
             "full34_business_or_custody_failed")
        remaining()
        report["status"] = "business_passed_pending_cleanup"
    except BaseException as error:
        report["failure"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, signal.SIG_IGN)
        report["expired_or_interrupted"] = expired
        report["owned_children"] = cleanup_all()
        report["group_signal_observations"] = signals
        subprocess.Popen = ORIGINAL_POPEN
        os.killpg = ORIGINAL_KILLPG
    complete = bool(report["owned_children"]) and all(
        row.get("original_wait_completed") is True and not row.get("remaining")
        and not row.get("cleanup_error") and not row["forced_by_outer"]
        and row["group_signalled_after_reap"] is False for row in report["owned_children"])
    report["all_owned_children_stopped"] = complete
    report["elapsed_seconds"] = time.monotonic() - began
    if (report["status"] == "business_passed_pending_cleanup" and complete
            and not expired and report["elapsed_seconds"] < TOTAL_SECONDS):
        report["status"] = "passed"
        report["full34_qualified"] = True
    else:
        report["status"] = "failed"
    raw = enc(report)
    write_new(OUT / "result.public.json", raw)
    print(json.dumps({"status": report["status"], "checks_total": report.get("checks_total"),
                      "checks_passed": report.get("checks_passed"),
                      "full34_qualified": report["full34_qualified"],
                      "result": str(OUT / "result.public.json"), "bytes": len(raw),
                      "sha256": sha(raw), "all_owned_children_stopped": complete,
                      "full_replacement_qualified": False}, sort_keys=True), flush=True)
    return 0 if report["status"] == "passed" else 1

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"status": "refused_before_full34",
                          "failure": str(error) if isinstance(error, RuntimeError) else type(error).__name__,
                          "full_replacement_qualified": False}, sort_keys=True), flush=True)
        raise SystemExit(2) from None
