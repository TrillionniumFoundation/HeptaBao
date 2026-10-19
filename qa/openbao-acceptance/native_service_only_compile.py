#!/usr/bin/env python3
"""Compile the pinned native-Service-only configuration after its host cohort.

This controller executes no Rust tests and starts no HeptaBao server. Its two
compiler commands have the original 1800-second budget, independently. It uses
the same nonblocking target lock and the candidate's exact verify_tree helper.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import re
import shlex
import signal
import stat
import subprocess
import sys
import time
import traceback
import types


SOURCE_COMMIT = "9770bdd4ca77aa832ec8083a054760637e92cfa1"
SOURCE_TREE = "f32f1acf9a794844719b6df225df3d23f2389e02"
MANIFEST_SHA256 = "9e167d20256e2d59c9ce57c73b90a0976403cf7a20db3e1d6b5de011c9d3cb0c"
RUNNER_PATH = "qa/openbao-acceptance/native_candidate_host_run.py"
FEATURE = "fixture-native-v6-service"
COMMAND_BUDGET = 1800
LOCK_NAME = "heptabao-owned-candidate-run.lock"


class TargetBusy(RuntimeError):
    pass


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_file(path):
    value = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_json(path, data):
    temporary = path.with_name(path.name + ".new")
    with temporary.open("w", encoding="utf-8") as stream:
        stream.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_pinned_runner(source, manifest_path):
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("manifest is not a regular nonsymlink file")
    raw = manifest_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError("manifest SHA256 differs from the pinned candidate")
    manifest = json.loads(raw)
    if (manifest.get("commit"), manifest.get("tree"), len(manifest.get("files", []))) != (
            SOURCE_COMMIT, SOURCE_TREE, 2979):
        raise ValueError("manifest source identity differs from the pinned candidate")
    entries = [item for item in manifest["files"] if item["path"] == RUNNER_PATH]
    if len(entries) != 1:
        raise ValueError("candidate has no unique native host runner")
    path = source / RUNNER_PATH
    if path.is_symlink() or not path.is_file():
        raise ValueError("candidate host runner is not a regular nonsymlink file")
    content = path.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
    if blob != entries[0]["sha"]:
        raise ValueError("candidate host runner blob differs from the manifest")
    # Compile these exact, manifest-bound bytes without writing __pycache__ into
    # the immutable source closure. The runner's guarded main is not invoked.
    module = types.ModuleType("heptabao_pinned_native_candidate_runner")
    module.__file__ = str(path)
    exec(compile(content, str(path), "exec"), module.__dict__)
    return manifest, module, {"path": RUNNER_PATH, "git_blob": blob,
                              "sha256": hashlib.sha256(content).hexdigest()}


def acquire_target_lock(target, receipt):
    path = target / LOCK_NAME
    descriptor = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    stream = os.fdopen(descriptor, "r+", encoding="utf-8")
    try:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("target lock is not a regular file")
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise TargetBusy("owned target is in use; no command was started") from error
        # A busy target never has its prior owner's receipt truncated.
        stream.seek(0)
        stream.truncate()
        stream.write(json.dumps(receipt) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
        return stream
    except BaseException:
        stream.close()
        raise


def process_rows(pid=None, timeout=2, with_start=False):
    command = ["/bin/ps", "-A" if pid is None else "-p"]
    if pid is not None:
        command.append(str(pid))
    command += ["-o", "pid=,ppid=,pgid=,stat=" + (",uid=,lstart=" if with_start else "")]
    # lstart is an opaque, stable identity component. Keep ps's rendering
    # independent of the controller account's locale (the actual Mac uses zh).
    observation_env = os.environ.copy()
    observation_env.update(LC_ALL="C", LANG="C")
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False,
                            env=observation_env if with_start else None)
    if result.returncode != 0:
        raise RuntimeError("owned process observation failed: exit=" + str(result.returncode)
                           + " stderr=" + result.stderr[:1024].decode(errors="replace"))
    rows = []
    for line in result.stdout.decode("ascii", errors="strict").splitlines():
        fields = line.split(None, 5) if with_start else line.split()
        if len(fields) != (6 if with_start else 4):
            raise RuntimeError("owned process observation framing differs")
        rows.append({"pid": int(fields[0]), "ppid": int(fields[1]),
                     "pgid": int(fields[2]), "state": fields[3]})
        if with_start:
            rows[-1]["uid"] = int(fields[4])
            stamp = " ".join(fields[5].split())
            if not re.fullmatch(r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
                                r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
                                r"\d{1,2} \d{2}:\d{2}:\d{2} \d{4}", stamp):
                raise RuntimeError("owned process start identity is unavailable")
            rows[-1]["lstart"] = stamp
    return rows


def exited_without_reaping(process, timeout=2):
    if all(hasattr(os, key) for key in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")):
        try:
            return os.waitid(os.P_PID, process.pid,
                             os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
        except (NotImplementedError, OSError):
            pass
    # Darwin need not expose waitid. A zombie still reserves this child's PID;
    # do not call Popen.poll/wait until the original group has been observed.
    rows = process_rows(process.pid, timeout=timeout)
    if len(rows) != 1 or rows[0]["pid"] != process.pid:
        raise RuntimeError("owned leader disappeared before reaping")
    return rows[0]["state"].startswith("Z")


def darwin_owned_group(process, timeout=2):
    """Keep custody of our unreaped Popen when Darwin rejects zombie syscalls."""
    original = getattr(process, "_heptabao_darwin_leader_identity", None)

    def observe():
        rows = process_rows(timeout=timeout, with_start=True)
        leaders = [row for row in rows if row["pid"] == process.pid]
        if len(leaders) != 1:
            raise RuntimeError("owned Darwin leader disappeared before reaping")
        leader = leaders[0]
        identity = {key: leader[key] for key in ("pid", "ppid", "pgid", "uid", "lstart")}
        if (identity["pid"], identity["ppid"], identity["pgid"], identity["uid"]) != (
                process.pid, os.getpid(), process.pid, os.geteuid()):
            raise RuntimeError("owned Darwin leader parent, group or uid identity differs")
        if original is not None and original != identity:
            raise RuntimeError("owned Darwin leader start identity differs")
        return rows, leader, identity

    def wait_event():
        if not all(hasattr(os, key) for key in (
                "waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")):
            raise RuntimeError("owned Darwin zombie requires WNOWAIT custody")
        # Actual Darwin 3.14 WNOWAIT reports si_uid=0 for our uid501 child.
        # The fresh ps uid is bound above; the exit event proves child custody,
        # never the owner UID. Keep every other event field stable below.
        event = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if (event is None or event.si_pid != process.pid
                or event.si_signo != signal.SIGCHLD
                or event.si_code not in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)):
            raise RuntimeError("owned Darwin zombie has no matching child exit event")
        return tuple(event)

    rows, leader, identity = observe()
    if not leader["state"].startswith("Z"):
        try:
            if os.getpgid(process.pid) != process.pid or os.getsid(process.pid) != process.pid:
                raise RuntimeError("owned leader no longer binds its original PGID and SID")
        except ProcessLookupError:
            # It can exit between ps and the live-child syscalls. ESRCH is
            # never evidence of an empty group: reobserve and require Z plus
            # the original child's unchanged, non-reaping exit event below.
            rows, leader, changed = observe()
            if changed != identity or not leader["state"].startswith("Z"):
                raise RuntimeError("owned Darwin live leader identity became unresolved")
    if leader["state"].startswith("Z"):
        before = wait_event()
        rows, leader, changed = observe()
        after = wait_event()
        if (before != after or changed != identity or not leader["state"].startswith("Z")
                or process.returncode is not None):
            raise RuntimeError("owned Darwin zombie custody changed before group observation")
    # Bind on the original Popen object, including fast children first seen as
    # zombies. No poll/wait has occurred; WNOWAIT proves this is our child and
    # its reserved PID continues to identify the original process group.
    process._heptabao_darwin_leader_identity = identity
    return [row for row in rows if row["pgid"] == process.pid]


def owned_group(process, timeout=2):
    if process.returncode is not None:
        raise RuntimeError("owned leader was reaped before group observation")
    if sys.platform == "darwin":
        return darwin_owned_group(process, timeout=timeout)
    if os.getpgid(process.pid) != process.pid or os.getsid(process.pid) != process.pid:
        raise RuntimeError("owned leader no longer binds its original PGID and SID")
    return [row for row in process_rows(timeout=timeout) if row["pgid"] == process.pid]


def live_group(rows):
    return [row for row in rows if not row["state"].startswith("Z")]


def finish_owned(process, must_stop):
    """Signal only while our unreaped session leader still reserves its PID."""
    before = owned_group(process)
    unexpected = [row for row in live_group(before) if row["pid"] != process.pid]
    receipt = {"group_before_reap": before, "signals": [],
               "unexpected_live_descendants_after_exit": bool(unexpected) and not must_stop}
    if must_stop or live_group(before):
        for sig, budget in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
            if not live_group(owned_group(process)):
                break
            # There has been no poll/wait since Popen returned. Even if the
            # leader exited, its zombie prevents numeric PGID reuse here.
            os.killpg(process.pid, sig)
            receipt["signals"].append(sig.name)
            deadline = time.monotonic() + budget
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if not live_group(owned_group(process, timeout=min(1, remaining))):
                    break
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    after = owned_group(process)
    receipt["group_before_final_wait"] = after
    receipt["original_group_observed_without_live_members"] = not live_group(after)
    if not exited_without_reaping(process):
        raise RuntimeError("owned leader did not exit within its cleanup budget")
    code = process.wait(timeout=1)
    receipt.update(leader_reaped=True, exit_code=code)
    return receipt


def root_cfg_observations(path):
    observations = []
    for line in path.read_text(errors="replace").splitlines():
        text = line.strip()
        if not text.startswith("Running "):
            continue
        text = text[len("Running "):].strip()
        if text.startswith("`") and text.endswith("`"):
            text = text[1:-1]
        try:
            argv = shlex.split(text)
        except ValueError:
            continue
        if "--crate-name" not in argv:
            continue
        index = argv.index("--crate-name")
        if index + 1 >= len(argv) or argv[index + 1] != "heptabao_server":
            continue
        active = []
        for index, value in enumerate(argv):
            if value == "--cfg" and index + 1 < len(argv):
                active.append(argv[index + 1])
            elif value.startswith("--cfg="):
                active.append(value[len("--cfg="):])
        features = []
        for item in active:
            match = re.fullmatch(r'feature="?([^"\s]+)"?', item)
            if match:
                features.append(match.group(1))
        observations.append({"test_target": "--test" in argv,
                             "source": [item for item in argv if item.endswith(".rs")],
                             "active_features": sorted(set(features))})
    return observations


def run_logged(label, argv, source, env, output, records, save, budget=COMMAND_BUDGET):
    log = output / (label + ".log")
    record = {"label": label, "argv": [str(item) for item in argv],
              "started_utc": utc(), "status": "running", "budget_seconds": budget,
              "log": log.name}
    records.append(record)
    save()
    started = time.monotonic()
    deadline = started + budget
    process = None
    interrupted = None
    with log.open("xb") as stream:
        try:
            process = subprocess.Popen(record["argv"], cwd=source, env=env,
                                       stdin=subprocess.DEVNULL, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            record.update(pid=process.pid, pgid=process.pid, sid=process.pid)
            save()
            if sys.platform == "darwin":
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("owned Darwin capture reached the original command deadline")
                owned_group(process, timeout=min(2, remaining))
                record["darwin_leader_identity"] = process._heptabao_darwin_leader_identity
                save()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    record["timed_out"] = True
                    break
                observed = exited_without_reaping(process, timeout=min(1, remaining))
                if time.monotonic() >= deadline:
                    record["timed_out"] = True
                    break
                if observed:
                    break
                time.sleep(min(0.2, max(0, deadline - time.monotonic())))
        except BaseException as error:
            interrupted = error
            record["execution_error"] = str(error)
            if time.monotonic() >= deadline:
                record["timed_out"] = True
        finally:
            if process is not None:
                try:
                    record["cleanup"] = finish_owned(process, bool(interrupted or record.get("timed_out")))
                    record["exit_code"] = record["cleanup"]["exit_code"]
                except BaseException as error:
                    record["cleanup_error"] = str(error)
            stream.flush()
            os.fsync(stream.fileno())
    record.update(finished_utc=utc(), elapsed_seconds=round(time.monotonic() - started, 3),
                  log_sha256=sha256_file(log), log_bytes=log.stat().st_size)
    observations = root_cfg_observations(log)
    record["root_rustc_cfg_observations"] = observations
    record["root_rustc_cfg_observed"] = bool(observations)
    cfg_bad = any(item["active_features"] != [FEATURE] for item in observations)
    cleanup = record.get("cleanup", {})
    good = (record.get("exit_code") == 0 and not interrupted and not record.get("timed_out")
            and cleanup.get("leader_reaped")
            and cleanup.get("original_group_observed_without_live_members")
            and not cleanup.get("unexpected_live_descendants_after_exit") and not cfg_bad)
    record["status"] = "passed" if good else "failed"
    if cfg_bad:
        record["cfg_error"] = "observed root compiler features differ from native-Service-only"
    save()
    print(json.dumps({"label": label, "status": record["status"],
                      "exit_code": record.get("exit_code")}), flush=True)
    if interrupted is not None:
        raise interrupted
    if record.get("cleanup_error") or not cleanup.get("original_group_observed_without_live_members"):
        raise RuntimeError("owned compiler group cleanup is unresolved; later commands were not started")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "manifest", "output", "cargo", "rustc", "cargo-home", "target-dir"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    parser.add_argument("--build-jobs", type=int, required=True)
    args = parser.parse_args()
    for name in ("source", "manifest", "output", "cargo", "rustc", "cargo_home", "target_dir"):
        if not getattr(args, name).is_absolute():
            parser.error(name + " must be absolute")
    if not 1 <= args.build_jobs <= min(16, os.cpu_count() or 1):
        parser.error("build-jobs is outside the existing resource profile")
    if args.source.is_symlink() or not args.source.is_dir():
        parser.error("source must be an existing nonsymlink directory")
    if args.target_dir.is_symlink() or not args.target_dir.is_dir():
        parser.error("target-dir must be the existing owned warm target")
    for left, right in ((args.source, args.output), (args.source, args.target_dir),
                        (args.output, args.target_dir)):
        a, b = left.resolve(), right.resolve()
        if a == b or a in b.parents or b in a.parents:
            parser.error("source, output and target must be disjoint")
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    records = []
    summary = {"schema": "heptabao.native-service-only-compile.v1", "status": "running",
               "started_utc": utc(), "runner_pid": os.getpid(),
               "controller_sha256": sha256_file(pathlib.Path(__file__)),
               "source": str(args.source), "source_commit": SOURCE_COMMIT,
               "source_tree": SOURCE_TREE, "manifest_sha256": MANIFEST_SHA256,
               "target_dir": str(args.target_dir), "target_lock_acquired": False,
               "hostname": platform.node(), "platform": platform.platform(),
               "machine": platform.machine(), "uname": list(os.uname()),
               "python": platform.python_version(), "commands": records,
               "feature": FEATURE, "compiler_command_budget_seconds": COMMAND_BUDGET,
               "rust_tests_executed": 0, "original_host_cohort_test_count": 55,
               "server_started": False, "physical_lan_validation_performed": False,
               "real_credential_validation_performed": False,
               "production_cutover_performed": False,
               "full_openbao_271_replacement_proven": False}

    def save():
        write_json(args.output / "summary.json", summary)

    def interrupted(signum, _frame):
        raise KeyboardInterrupt("controller received signal " + str(signum))

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    manifest = runner = lock = None
    save()
    try:
        manifest, runner, summary["source_verifier"] = load_pinned_runner(args.source, args.manifest)
        lock = acquire_target_lock(args.target_dir, {"pid": os.getpid(), "source_commit": SOURCE_COMMIT,
                                                    "output": str(args.output), "scope": "native-only compile"})
        summary["target_lock_acquired"] = True
        summary["source_before"] = runner.verify_tree(args.source, manifest)
        env = os.environ.copy()
        cleared = ("CARGO_BUILD_TARGET", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                   "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")
        for key in cleared:
            env.pop(key, None)
        env.update(PATH=str(args.rustc.parent) + ":/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                   CARGO_HOME=str(args.cargo_home), CARGO_TARGET_DIR=str(args.target_dir), RUSTC=str(args.rustc),
                   CARGO_BUILD_JOBS=str(args.build_jobs), CMAKE_BUILD_PARALLEL_LEVEL=str(args.build_jobs),
                   CARGO_TERM_COLOR="never", CARGO_NET_OFFLINE="true")
        summary["compiler_resource_profile"] = {"cargo_build_jobs": args.build_jobs,
            "cmake_build_parallel_level": args.build_jobs,
            "dev_debug": env.get("CARGO_PROFILE_DEV_DEBUG"), "test_debug": env.get("CARGO_PROFILE_TEST_DEBUG"),
            "incremental": env.get("CARGO_INCREMENTAL"), "cleared_environment_keys": list(cleared)}
        for label, executable in (("cargo", args.cargo), ("rustc", args.rustc)):
            observed = run_logged(label + "-version", [executable, "--version", "--verbose"],
                                  args.source, env, args.output, records, save, budget=15)
            text = (args.output / observed["log"]).read_text(errors="replace")
            if observed["status"] != "passed" or not re.search(r"^" + label + r" 1\.98\.0\b", text, re.MULTILINE):
                raise RuntimeError("actual " + label + " version differs from Rust 1.98.0")
        common = ["--locked", "--offline", "-p", "heptabao-server", "--no-default-features",
                  "--features", FEATURE]
        commands = [
            ("check-native-service-only", [args.cargo, "check"] + common
             + ["--lib", "--bin", "heptabao-server", "--verbose"]),
            ("compile-native-service-only-tests", [args.cargo, "test"] + common
             + ["--lib", "--no-run", "--verbose"]),
        ]
        for label, command in commands:
            result = run_logged(label, command, args.source, env, args.output, records, save)
            if result.get("timed_out"):
                raise RuntimeError("compiler command reached the original budget; later commands were not started")
        summary["controller_completed"] = True
    except TargetBusy as error:
        summary.update(blocked_reason=str(error))
    except BaseException as error:
        summary.update(error=str(error), error_type=type(error).__name__)
        (args.output / "controller-error.txt").write_text(traceback.format_exc(), encoding="utf-8")
    finally:
        if runner is not None and manifest is not None:
            try:
                summary["source_after"] = runner.verify_tree(args.source, manifest)
                summary["source_unchanged"] = summary.get("source_before", {}).get("tree") == summary["source_after"]["tree"]
            except BaseException as error:
                summary.update(source_unchanged=False, source_after_error=str(error))
        passed = (summary.get("controller_completed") and summary.get("source_unchanged")
                  and not summary.get("error") and len(records) == 4
                  and all(item["status"] == "passed" for item in records))
        summary.update(status="passed_native_service_only_compile" if passed else "failed_or_blocked",
                       finished_utc=utc())
        save()
        if lock is not None:
            lock.close()
    print(json.dumps({"status": summary["status"], "summary": str(args.output / "summary.json")}), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
