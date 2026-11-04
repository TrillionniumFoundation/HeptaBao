#!/usr/bin/env python3
"""Exercise exact native-large CLI supervise cleanup with real owned dummy workers."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import sys
import time
from types import SimpleNamespace, ModuleType

ROOT = Path("/home/qian/heptabao-native-cli-reap-guard-61ff-20261104-r1")
PYTHON = Path("/usr/bin/python3.12")
PYTHON_SHA = "e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f"
BASE_SHA = "4df0d5eaf069905e5a5bfd9e0e699391ba104ac27d54c5cbb18a79a9d8b1284d"
FIXED_SHA = "8043bce5e2443ca10f09d88dc854fc1a850ae4ac8b904763fbfc1ae3fa2de52a"
LEGACY_SHA = "7d49451fc876040ad1887de5170b6255a0a569d79894141e34c201d6d369f607"
DECODER_SHA = "633470fd47ca5d402fb2e175ecf57aaf43d9fa6c27b8ba4885d9fc43d4a989d2"
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

def run_case(name, source_raw, mode):
    case = ROOT / (name + "-" + mode)
    case.mkdir(mode=0o700)
    worker_path = case / "owned_worker.py"
    worker = {
        "success": 'print("owned deliberate worker success")\n',
        "nonzero": 'import sys\nprint("owned deliberate worker failure",file=sys.stderr)\nraise SystemExit(7)\n',
        "timeout": 'import time\ntime.sleep(30)\n',
    }[mode]
    write_new(worker_path, worker.encode())
    module_name = "owned_native_supervise_regression_" + name + "_" + mode
    module = ModuleType(module_name)
    module.__file__ = str(ROOT / (name + ".py"))
    sys.modules[module_name] = module
    # Load the complete exact CLI plus its exact adjacent legacy/decoder modules.
    # The module's __main__ branch does not run. Only the real supervise()
    # function is exercised, with an owned dummy worker at its self-spawn path.
    exec(compile(source_raw, module.__file__, "exec"), module.__dict__, module.__dict__)
    module.__file__ = str(worker_path)
    captured_out, captured_err = io.BytesIO(), io.BytesIO()
    module.sys = SimpleNamespace(executable=str(PYTHON),
                                 stdout=SimpleNamespace(buffer=captured_out),
                                 stderr=SimpleNamespace(buffer=captured_err))
    seconds = 0.25 if mode == "timeout" else 2.0
    began = time.monotonic()
    deadline = began + seconds
    previous_attempts, previous_children = len(attempts), len(children)
    failure, returned = None, None
    try:
        returned, _ = module.supervise(["owned-regression"], end=deadline)
    except Exception as error:
        failure = str(error) if type(error).__name__ in ("DecodeError", "RuntimeError") else type(error).__name__
    scoped_attempts = attempts[previous_attempts:]
    scoped_children = children[previous_children:]
    need(len(scoped_children) == 1, "one_original_worker")
    child = scoped_children[0]
    out, err = captured_out.getvalue(), captured_err.getvalue()
    expected_block = name == "baseline" and mode != "success"
    expected_error = expected_block or mode == "timeout"
    expected_code = None if expected_error else 7 if mode == "nonzero" else 0
    row = {"implementation": name, "mode": mode, "elapsed_seconds": time.monotonic() - began,
           "failure": failure, "returned_code": returned, "worker_pid": child.pid,
           "returncode": child.returncode, "original_wait_completed": child.returncode is not None,
           "signal_attempts": scoped_attempts, "remaining": group_members(child.pid),
           "supervisor_lifecycle": dict(module.supervise.last_lifecycle),
           "captured_stdout_sha256": sha(out), "captured_stderr_sha256": sha(err),
           "test_only_deadline_seconds": seconds,
           "production_deadline_constant_unchanged": module.DEADLINE == 360,
           "actual_supervise_function_executed": True,
           "full_migration_or_http_executed": False}
    row["regression_expectation_met"] = (
        any(item["reaped_attempt_blocked"] for item in scoped_attempts) == expected_block
        and child.returncode == {"success":0, "nonzero":7, "timeout":-9}[mode]
        and not row["remaining"] and ((failure is not None) == expected_error)
        and returned == expected_code
        and sum(item["sent"] for item in scoped_attempts) == (1 if mode == "timeout" else 0)
        and out == (b"owned deliberate worker success\n" if mode == "success" else b"")
        and err == (b"owned deliberate worker failure\n" if mode == "nonzero" else b"")
        and module.DEADLINE == 360)
    del sys.modules[module_name]
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
    need(set(packet) == {"baseline", "fixed", "legacy", "decoder"}, "packet_fields")
    sources = {key: value.encode() for key, value in packet.items()}
    need(sha(sources["baseline"]) == BASE_SHA and sha(sources["fixed"]) == FIXED_SHA
         and sha(sources["legacy"]) == LEGACY_SHA and sha(sources["decoder"]) == DECODER_SHA,
         "source_pins")
    need(ROOT.parent.resolve(strict=True) == ROOT.parent and not os.path.lexists(ROOT),
         "fresh_root")
    parent = ROOT.parent.stat()
    need(parent.st_uid == 1000 and stat.S_ISDIR(parent.st_mode)
         and not parent.st_mode & 0o022, "owned_parent")
    ROOT.mkdir(mode=0o700)
    for name, value in sources.items():
        filename = {"legacy":"openbao270_kv2_migrate.py", "decoder":"kv2_lossless_raw.py"}.get(name, name + ".py")
        write_new(ROOT / filename, value)
    report = {"schema": "heptabao.native-cli-unreaped-worker-real-regression.v1",
              "status": "failed", "baseline_sha256": BASE_SHA, "fixed_sha256": FIXED_SHA,
              "legacy_sha256": LEGACY_SHA, "decoder_sha256": DECODER_SHA,
              "cases": [], "full34_executed": False, "production_changed": False,
              "full_replacement_qualified": False,
              "scope": "Exact native-large supervise(), actual Popen success/nonzero/timeout dummy workers; stale signals blocked before dispatch. No HTTP or full migration."}
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
