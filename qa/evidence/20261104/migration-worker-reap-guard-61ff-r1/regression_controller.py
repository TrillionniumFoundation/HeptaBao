#!/usr/bin/env python3
"""Exercise original and corrected migration cleanup with real owned children."""
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
from types import SimpleNamespace

ROOT = Path("/home/qian/heptabao-kv2-worker-reap-guard-61ff-20261104-r1")
PYTHON = Path("/usr/bin/python3.12")
PYTHON_SHA = "e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f"
BASE_SHA = "383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581"
FIXED_SHA = "33377bc52b520c53aa2195ee68556581ea78036fbb887ffc2e5bb6fd4d985e47"
ORIGINAL_POPEN = subprocess.Popen
ORIGINAL_KILLPG = os.killpg
children = []
attempts = []
creating = False
pending_signal = None

def need(value, label):
    if not value:
        raise RuntimeError(label)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())

def group_members(pgid):
    found = []
    for item in Path("/proc").iterdir():
        if not item.name.isdigit():
            continue
        try:
            raw = (item / "stat").read_text()
            tail = raw[raw.rfind(") ") + 2:].split()
            if int(tail[2]) == pgid:
                found.append({"pid": int(item.name), "state": tail[0],
                              "ppid": int(tail[1]), "sid": int(tail[3]),
                              "starttick": int(tail[19])})
        except FileNotFoundError:
            continue
    return found

def interrupted(signum, frame):
    global pending_signal
    if creating:
        pending_signal = signum
    else:
        raise RuntimeError("regression_interrupted")

class TrackedPopen(ORIGINAL_POPEN):
    def __init__(self, *args, **kwargs):
        global creating
        need(not creating, "nested_creation")
        creating = True
        try:
            super().__init__(*args, **kwargs)
            children.append(self)
        finally:
            creating = False
        if pending_signal is not None:
            raise RuntimeError("interrupted_during_creation")

def checked_killpg(pgid, signum):
    matches = [p for p in children if p.pid == pgid]
    need(len(matches) == 1, "foreign_or_reused_group_rejected")
    child = matches[0]
    row = {"pid": pgid, "signal": int(signum), "returncode_at_attempt": child.returncode,
           "reaped_attempt_blocked": child.returncode is not None, "sent": False}
    attempts.append(row)
    if child.returncode is not None:
        raise RuntimeError("reaped_group_signal_blocked_by_regression")
    witness = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    need(witness is None or witness.si_pid == child.pid, "original_child_waitid")
    need(os.getpgid(child.pid) == child.pid, "original_child_group")
    ORIGINAL_KILLPG(pgid, signum)
    row["sent"] = True

def cleanup():
    rows = []
    for child in children:
        forced = False
        if child.returncode is None:
            witness = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            need(witness is None or witness.si_pid == child.pid, "cleanup_original_child")
            checked_killpg(child.pid, signal.SIGKILL)
            forced = True
            child.communicate(timeout=5)
        rows.append({"pid": child.pid, "returncode": child.returncode,
                     "forced_by_outer": forced, "remaining": group_members(child.pid)})
    return rows

def run_case(name, helper_raw, mode):
    case = ROOT / (name + "-" + mode)
    case.mkdir(mode=0o700)
    (case / "phases").mkdir(mode=0o700)
    worker_dir = case / "worker-source" / "tools" / "migration"
    worker_dir.mkdir(mode=0o700, parents=True)
    worker = {
        "success": 'import json\nprint(json.dumps({"operation":"export","lane":"native-large"}))\n',
        "nonzero": 'import sys\nprint("owned deliberate worker failure",file=sys.stderr)\nraise SystemExit(7)\n',
        "timeout": 'import time\ntime.sleep(30)\n',
    }[mode]
    write_new(worker_dir / "openbao271_kv2_native_large_migrate.py", worker.encode())
    namespace = {"__name__": "owned_migration_regression",
                 "__file__": str(ROOT / (name + ".py"))}
    exec(compile(helper_raw, namespace["__file__"], "exec"), namespace, namespace)
    namespace["ROOT"] = case / "worker-source"
    # These are test-only, stricter deadlines for worker lifecycle branches.
    # No full34 business operation is executed by this regression controller.
    namespace["MIGRATION_SECONDS"] = 0.25 if mode == "timeout" else 2
    run = namespace["Run"](SimpleNamespace(private_work_root=case, profile="full34",
                                          migration_lane="native-large"))
    endpoint = SimpleNamespace(address="https://127.0.0.1:1", ca_file=case / "unused-ca.crt")
    previous_attempts, previous_children = len(attempts), len(children)
    failure = None
    started = time.monotonic()
    try:
        run.migration("export", endpoint, case / "unused-token", case / "unused-bundle")
    except Exception as error:
        failure = str(error) if type(error).__name__ in ("Failure", "RuntimeError") else type(error).__name__
    scoped_attempts = attempts[previous_attempts:]
    scoped_children = children[previous_children:]
    need(len(scoped_children) == 1, "one_original_worker")
    child = scoped_children[0]
    row = {"implementation": name, "mode": mode, "elapsed_seconds": time.monotonic() - started,
           "failure": failure, "worker_pid": child.pid, "returncode": child.returncode,
           "original_wait_completed": child.returncode is not None,
           "signal_attempts": scoped_attempts, "remaining": group_members(child.pid),
           "migration_row": run.report["migration_invocations"][0],
           "test_only_migration_seconds": namespace["MIGRATION_SECONDS"]}
    expected_block = name == "baseline" and mode != "success"
    row["regression_expectation_met"] = (
        any(item["reaped_attempt_blocked"] for item in scoped_attempts) == expected_block
        and child.returncode is not None and not row["remaining"]
        and ((failure is None) == (mode == "success"))
        and sum(item["sent"] for item in scoped_attempts) == (1 if mode == "timeout" else 0))
    return row

def main():
    os.umask(0o077)
    need(os.getuid() == os.geteuid() == 1000 and platform.node() == "qian-ThinkPad-X230",
         "actual_x230_operator")
    need(Path(sys.executable).resolve(strict=True) == PYTHON
         and sha(PYTHON.read_bytes()) == PYTHON_SHA, "fixed_python")
    need(len(sys.argv) == 2, "packet_pin_argument")
    raw = sys.stdin.buffer.read(262145)
    need(len(raw) <= 262144 and sha(raw) == sys.argv[1], "packet_pin")
    packet = json.loads(raw)
    need(set(packet) == {"baseline", "fixed"}, "packet_fields")
    sources = {key: value.encode() for key, value in packet.items()}
    need(sha(sources["baseline"]) == BASE_SHA and sha(sources["fixed"]) == FIXED_SHA,
         "source_pins")
    need(ROOT.parent.resolve(strict=True) == ROOT.parent and not os.path.lexists(ROOT),
         "fresh_root")
    parent = ROOT.parent.stat()
    need(parent.st_uid == 1000 and stat.S_ISDIR(parent.st_mode)
         and not parent.st_mode & 0o022, "owned_parent")
    ROOT.mkdir(mode=0o700)
    for name, value in sources.items():
        write_new(ROOT / (name + ".py"), value)
    report = {"schema": "heptabao.migration-unreaped-worker-real-regression.v1",
              "status": "failed", "baseline_sha256": BASE_SHA, "fixed_sha256": FIXED_SHA,
              "cases": [], "full34_executed": False, "production_changed": False,
              "full_replacement_qualified": False,
              "scope": "Actual Popen success, nonzero, timeout; attempted stale signals are blocked before dispatch."}
    subprocess.Popen = TrackedPopen
    os.killpg = checked_killpg
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        for name in ("baseline", "fixed"):
            for mode in ("success", "nonzero", "timeout"):
                report["cases"].append(run_case(name, sources[name], mode))
        need(len(report["cases"]) == 6 and all(row["regression_expectation_met"]
                                              for row in report["cases"]), "regression_failed")
        report["status"] = "passed"
    except BaseException as error:
        report["failure"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            report["cleanup"] = cleanup()
            need(len(report["cleanup"]) == 6
                 and all(row["returncode"] is not None and not row["remaining"]
                         and not row["forced_by_outer"] for row in report["cleanup"]), "cleanup_failed")
        except Exception as error:
            report["status"] = "failed"
            report["cleanup_failure"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        subprocess.Popen = ORIGINAL_POPEN
        os.killpg = ORIGINAL_KILLPG
    final = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    write_new(ROOT / "result.public.json", final)
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]),
                      "result": str(ROOT / "result.public.json"), "sha256": sha(final),
                      "bytes": len(final), "full34_executed": False}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1

if __name__ == "__main__":
    raise SystemExit(main())
