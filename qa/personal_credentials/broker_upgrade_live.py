#!/usr/bin/env python3
"""Same-format, synthetic broker upgrade/rollback rehearsal on one Unix host.

Only the two previously qualified executable digests below are admitted. This
does not install software, migrate a format, qualify other versions, or use a
real credential. All state is created beneath an initially absent private root.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import stat
import subprocess
import threading
import time


PINS = {
    "old": {"sha256": "389cc15a0926ef9f30cd149b56424a484dfad600a308252ed111f2869b5b9175",
            "source_commit": "a1b6ff4506f52082a0893b7167fafb4ff95610be",
            "artifact_receipt_sha256": "fa166952072d99490164cb355e1b9784e14791faf39cb48a2f226aed627ccdd4"},
    "new": {"sha256": "6fe0b6c78213e4bb1184ca4c4be7fc3e44dce4117f22097aab14efa567ac8a08",
            "source_commit": "c447536ae0343731d84c18291d2dcd712b3bea08",
            "artifact_receipt_sha256": "d29fff92ecbcdab6e52c905e6a4a96217d4c712f2c453dd5c63214e47c0e88bb"},
}
IDS = ("completed-old", "unknown-old", "completed-new", "completed-rollback",
       "revoked-operation", "expired-operation")
EXPECTED_CHECKS = (
    "old_completed_real_authenticated_request", "old_revocation_acknowledged",
    "unknown_target_contact_observed_before_kill", "unknown_durably_visible_before_kill",
    "real_sigkill_and_client_failure_observed", "upgrade_status_preserves_completed_receipt",
    "upgrade_execute_returns_cached_receipt", "upgrade_preserves_unknown_status",
    "upgrade_unknown_execute_nonzero_without_retry", "upgrade_preserves_revocation",
    "upgrade_preserves_expiry", "upgrade_preserves_exact_target", "upgrade_new_operation_real_effect",
    "rollback_preserves_old_receipt", "rollback_preserves_new_receipt",
    "rollback_preserves_unknown_status", "rollback_unknown_execute_nonzero_without_retry",
    "rollback_preserves_revocation", "rollback_preserves_expiry", "rollback_preserves_exact_target",
    "rollback_new_operation_real_effect", "reupgrade_preserves_rollback_receipt",
    "reupgrade_preserves_new_receipt", "reupgrade_unknown_never_redispatched",
    "exact_upstream_effect_counts_across_all_generations", "wrong_target_trap_never_contacted",
    "no_credential_in_persisted_operation_ledger",
)


class CheckFailed(Exception):
    pass


def require(value, code):
    if not value:
        raise CheckFailed(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, data):
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def authorization_denied(value):
    return value == {"ok": False, "error": "authorization_denied"}


class Upstream:
    """Real loopback fixture; its only effects are counted synthetic requests."""
    def __init__(self, secret):
        self.secret = secret
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.target = "http://127.0.0.1:" + str(self.listener.getsockname()[1])
        self.counts = {name: 0 for name in IDS}
        self.authenticated = 0
        self.errors = []
        self.unknown_received = threading.Event()
        self.release_unknown = threading.Event()
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.run, name="owned-synthetic-upstream")
        self.thread.start()

    def run(self):
        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self.stopping.is_set():
                    self.errors.append("unexpected_listener_error")
                return
            try:
                with connection:
                    connection.settimeout(5)
                    header = b""
                    while b"\r\n\r\n" not in header:
                        part = connection.recv(1)
                        require(bool(part) and len(header) < 8192, "fixture_header_incomplete")
                        header += part
                    lines = header[:-4].split(b"\r\n")
                    require(lines[0] == b"POST /execute HTTP/1.1", "fixture_wrong_request_line")
                    headers = {}
                    for line in lines[1:]:
                        key, value = line.split(b":", 1)
                        key = key.lower()
                        require(key not in headers, "fixture_duplicate_header")
                        headers[key] = value.strip()
                    require(headers.get(b"authorization") == b"Bearer " + self.secret,
                            "fixture_missing_expected_authorization")
                    count = int(headers[b"content-length"])
                    require(0 < count <= 128, "fixture_body_limit")
                    body = b""
                    while len(body) < count:
                        part = connection.recv(count - len(body))
                        require(bool(part), "fixture_body_incomplete")
                        body += part
                    name = body.decode("ascii")
                    require(name in self.counts, "fixture_unknown_operation")
                    self.counts[name] += 1
                    self.authenticated += 1
                    if name == "unknown-old":
                        self.unknown_received.set()
                        require(self.release_unknown.wait(10), "fixture_unknown_release_timeout")
                    else:
                        response_body = b"synthetic-upstream-echo:" + self.secret
                        connection.sendall(b"HTTP/1.1 200 OK\r\nX-Synthetic-Secret: " + self.secret
                                           + b"\r\nContent-Length: " + str(len(response_body)).encode()
                                           + b"\r\nConnection: close\r\n\r\n" + response_body)
            except Exception as error:
                code = str(error) if isinstance(error, CheckFailed) else "fixture_io_or_parse_error"
                self.errors.append(code)

    def close(self):
        self.release_unknown.set()
        self.stopping.set()
        self.listener.close()
        self.thread.join(6)
        require(not self.thread.is_alive(), "fixture_thread_not_joined")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--old-bin", type=Path, required=True)
    parser.add_argument("--new-bin", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.root
    require(root.is_absolute() and root.resolve() == root and not root.exists(), "fresh_absolute_root_required")
    parent = root.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
            and stat.S_IMODE(parent.st_mode) == 0o700, "owned_private_parent_required")
    inputs = {"old": args.old_bin, "new": args.new_bin}
    for name, path in inputs.items():
        info = path.lstat()
        require(path.is_absolute() and stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and not info.st_mode & 0o022 and file_digest(path) == PINS[name]["sha256"], "fixed_binary_required")
    root.mkdir(mode=0o700)
    for name in ("bin", "input", "public"):
        (root / name).mkdir(mode=0o700)
    private = root / "input"
    public = root / "public"
    owner = root / "owner"
    binaries = {}
    for name, source in inputs.items():
        destination = root / "bin" / ("broker-" + name)
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o500)
        require(file_digest(destination) == PINS[name]["sha256"], "frozen_copy_changed")
        binaries[name] = destination
    secret = ("SYNTHETIC-" + os.urandom(32).hex()).encode("ascii")
    upstream = None
    trap = None
    processes = []
    launches = []
    collected = set()
    commands = []
    checks = []
    failure = None
    originals = []
    before = {name: {"source_path": str(inputs[name]), "frozen_path": str(binaries[name]), **PINS[name]}
              for name in PINS}

    def check(name, value):
        require(value, name)
        checks.append(name)

    def assert_binaries():
        for name in PINS:
            require(file_digest(inputs[name]) == PINS[name]["sha256"]
                    and file_digest(binaries[name]) == PINS[name]["sha256"], "binary_identity_changed")

    def start(name, argv, stdin=None):
        require(re.fullmatch(r"[a-z0-9-]+", name), "unsafe_observation_name")
        assert_binaries()
        process = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        processes.append(process)
        item = {"name": name, "argv": [str(x) for x in argv], "process": process,
                "stdin": stdin, "started_unix_ns": time.time_ns()}
        launches.append(item)
        return item

    def collect(item, expected_exit, timeout=12):
        process = item["process"]
        stdout, stderr = process.communicate(input=item["stdin"], timeout=timeout)
        collected.add(process)
        require(secret not in stdout and secret not in stderr, "credential_found_in_cli_output")
        assert_binaries()
        for label, data in (("stdout", stdout), ("stderr", stderr)):
            name = item["name"] + "." + label + ".original"
            save(public / name, data)
            originals.append({"path": name, "bytes": len(data), "sha256": digest(data)})
        commands.append({"label": item["name"], "argv": item["argv"], "exit_code": process.returncode,
                         "expected_exit_code": expected_exit, "started_unix_ns": item["started_unix_ns"],
                         "finished_unix_ns": time.time_ns(), "stdout_sha256": digest(stdout),
                         "stderr_sha256": digest(stderr), "stdin_recorded": False})
        require(process.returncode == expected_exit, "unexpected_exit_" + item["name"])
        return json.loads(stdout) if stdout else None

    def call(version, name, command, operation=None, expected_exit=0, grant=None):
        argv = [str(binaries[version]), command, str(owner)]
        if operation is not None:
            if command != "revoke":
                argv.append(str(private / (operation + ".operation.json")))
            argv.append(str(private / ((grant or operation) + ".grant.json")))
        return collect(start(name, argv), expected_exit)

    def issue(version, name, ttl):
        operation = {"operation_id": name, "task_id": "synthetic-upgrade-rehearsal", "run_id": "r1",
                     "credential_id": "api", "target": upstream.target, "method": "POST", "path": "/execute",
                     "body_base64": base64.urlsafe_b64encode(name.encode()).decode().rstrip("=")}
        save(private / (name + ".operation.json"), encoded(operation))
        argv = [str(binaries[version]), "issue", str(owner), str(private / (name + ".operation.json")),
                str(private / (name + ".grant.json")), str(ttl)]
        return collect(start("issue-" + name, argv), 0)

    def server(version, name, count):
        socket_path = owner / "broker.sock"
        def identity():
            try:
                item = socket_path.lstat()
                require(stat.S_ISSOCK(item.st_mode) and stat.S_IMODE(item.st_mode) == 0o600,
                        "unexpected_socket_type_or_mode")
                return item.st_dev, item.st_ino, item.st_ctime_ns
            except FileNotFoundError:
                return None
        old = identity()
        item = start(name, [str(binaries[version]), "serve", str(owner), str(count)])
        deadline = time.monotonic() + 6
        while identity() in (None, old):
            require(item["process"].poll() is None, "server_exited_before_ready")
            require(time.monotonic() < deadline, "server_readiness_timeout")
            time.sleep(0.01)
        return item

    try:
        upstream = Upstream(secret)
        trap = socket.socket()
        trap.bind(("127.0.0.1", 0))
        trap.listen(4)
        trap.setblocking(False)
        bootstrap = {"synthetic_only": True, "credentials": [{"id": "api", "kind": "loopback_http",
                     "target": upstream.target, "method": "POST", "path": "/execute", "secret": secret.decode()}]}
        collect(start("initialize-old", [str(binaries["old"]), "init", str(owner)], encoded(bootstrap)), 0)
        for name in IDS:
            if name not in {"completed-new", "completed-rollback"}:
                issue("old", name, 1 if name == "expired-operation" else 3600)
        old = server("old", "serve-old-before-crash", 100)
        initial = call("old", "old-completed", "execute", "completed-old")
        check("old_completed_real_authenticated_request", initial["ok"] and initial["receipt"]["outcome"] == "completed"
              and initial["receipt"]["http_status"] == 200 and upstream.counts["completed-old"] == 1)
        revoked = call("old", "old-revoke", "revoke", "revoked-operation")
        check("old_revocation_acknowledged", revoked["receipt"]["outcome"] == "revoked")
        pending = start("old-client-interrupted", [str(binaries["old"]), "execute", str(owner),
                        str(private / "unknown-old.operation.json"), str(private / "unknown-old.grant.json")])
        check("unknown_target_contact_observed_before_kill", upstream.unknown_received.wait(6))
        state = json.loads((owner / "state.json").read_bytes())
        check("unknown_durably_visible_before_kill", state["operations"]["unknown-old"]["receipt"]["outcome"] == "outcome_unknown")
        old["process"].kill()
        collect(old, -9)
        collect(pending, 1)
        upstream.release_unknown.set()
        check("real_sigkill_and_client_failure_observed", old["process"].returncode == -9)
        issue("new", "completed-new", 3600)
        expired = json.loads((private / "expired-operation.grant.json").read_bytes())["grant"]["expires_at"]
        deadline = time.monotonic() + 3
        while time.time() <= expired:
            require(time.monotonic() < deadline, "expiry_wait_bound")
            time.sleep(0.05)
        wrong = json.loads((private / "completed-old.operation.json").read_bytes())
        wrong["target"] = "http://127.0.0.1:" + str(trap.getsockname()[1])
        save(private / "wrong-target.operation.json", encoded(wrong))
        new = server("new", "serve-upgraded", 8)
        check("upgrade_status_preserves_completed_receipt", call("new", "upgrade-completed-status", "status", "completed-old") == initial)
        check("upgrade_execute_returns_cached_receipt", call("new", "upgrade-completed-replay", "execute", "completed-old") == initial)
        unknown = call("new", "upgrade-unknown-status", "status", "unknown-old")
        check("upgrade_preserves_unknown_status", unknown["receipt"]["outcome"] == "outcome_unknown")
        check("upgrade_unknown_execute_nonzero_without_retry", call("new", "upgrade-unknown-replay", "execute", "unknown-old", 1) == unknown)
        check("upgrade_preserves_revocation", authorization_denied(call("new", "upgrade-revoked-denied", "execute", "revoked-operation", 1)))
        check("upgrade_preserves_expiry", authorization_denied(call("new", "upgrade-expired-denied", "execute", "expired-operation", 1)))
        check("upgrade_preserves_exact_target", authorization_denied(call("new", "upgrade-wrong-target-denied", "execute", "wrong-target", 1, "completed-old")))
        new_result = call("new", "upgrade-new-operation", "execute", "completed-new")
        check("upgrade_new_operation_real_effect", new_result["receipt"]["http_status"] == 200 and upstream.counts["completed-new"] == 1)
        collect(new, 0)
        issue("old", "completed-rollback", 3600)
        rollback = server("old", "serve-rollback", 8)
        check("rollback_preserves_old_receipt", call("old", "rollback-old-status", "status", "completed-old") == initial)
        check("rollback_preserves_new_receipt", call("old", "rollback-new-replay", "execute", "completed-new") == new_result)
        check("rollback_preserves_unknown_status", call("old", "rollback-unknown-status", "status", "unknown-old") == unknown)
        check("rollback_unknown_execute_nonzero_without_retry", call("old", "rollback-unknown-replay", "execute", "unknown-old", 1) == unknown)
        check("rollback_preserves_revocation", authorization_denied(call("old", "rollback-revoked-denied", "execute", "revoked-operation", 1)))
        check("rollback_preserves_expiry", authorization_denied(call("old", "rollback-expired-denied", "execute", "expired-operation", 1)))
        check("rollback_preserves_exact_target", authorization_denied(call("old", "rollback-wrong-target-denied", "execute", "wrong-target", 1, "completed-old")))
        rollback_result = call("old", "rollback-new-operation", "execute", "completed-rollback")
        check("rollback_new_operation_real_effect", rollback_result["receipt"]["http_status"] == 200 and upstream.counts["completed-rollback"] == 1)
        collect(rollback, 0)
        again = server("new", "serve-reupgrade", 3)
        check("reupgrade_preserves_rollback_receipt", call("new", "reupgrade-rollback-replay", "execute", "completed-rollback") == rollback_result)
        check("reupgrade_preserves_new_receipt", call("new", "reupgrade-new-status", "status", "completed-new") == new_result)
        check("reupgrade_unknown_never_redispatched", call("new", "reupgrade-unknown-replay", "execute", "unknown-old", 1) == unknown)
        collect(again, 0)
        expected = {name: int(name in {"completed-old", "unknown-old", "completed-new", "completed-rollback"}) for name in IDS}
        check("exact_upstream_effect_counts_across_all_generations", upstream.counts == expected and upstream.authenticated == 4)
        try:
            connection, _ = trap.accept()
        except BlockingIOError:
            check("wrong_target_trap_never_contacted", True)
        else:
            connection.close()
            check("wrong_target_trap_never_contacted", False)
        check("no_credential_in_persisted_operation_ledger", secret not in (owner / "state.json").read_bytes())
    except Exception as error:
        failure = str(error) if isinstance(error, CheckFailed) else "unexpected_" + type(error).__name__
    finally:
        for item in launches:
            process = item["process"]
            if process.poll() is None:
                process.kill()
            if process not in collected:
                stdout, stderr = process.communicate(timeout=6)
                if secret in stdout or secret in stderr:
                    failure = failure or "credential_found_in_uncollected_output"
                else:
                    for label, data in (("stdout", stdout), ("stderr", stderr)):
                        name = "cleanup-" + item["name"] + "." + label + ".original"
                        save(public / name, data)
                        originals.append({"path": name, "bytes": len(data), "sha256": digest(data)})
                commands.append({"label": item["name"], "argv": item["argv"], "exit_code": process.returncode,
                                 "cleanup_observation": True, "started_unix_ns": item["started_unix_ns"],
                                 "finished_unix_ns": time.time_ns(), "stdout_sha256": digest(stdout),
                                 "stderr_sha256": digest(stderr), "stdin_recorded": False})
        if upstream is not None:
            try:
                upstream.close()
            except Exception:
                failure = failure or "upstream_cleanup_failed"
        if trap is not None:
            trap.close()
    assert_binaries()
    all_terminal = all(process.poll() is not None for process in processes)
    fixture_errors = [] if upstream is None else upstream.errors
    report = {"schema": 1, "scope": "exact_two_binary_same_format_synthetic_upgrade_rollback",
              "synthetic_only": True, "production_qualified": False, "p5_qualified": False,
              "format_migration_exercised": False, "external_security_review": False,
              "host": {"system": platform.system(), "machine": platform.machine()},
              "qa_script_sha256": file_digest(Path(__file__).resolve()), "artifacts": before,
              "binary_identities_unchanged": True, "source_bindings_from_prior_receipts": True,
              "version_sequence": ["old", "new", "old", "new"], "actual_sigkill": True if "real_sigkill_and_client_failure_observed" in checks else False,
              "expected_checks": list(EXPECTED_CHECKS), "expected_count": len(EXPECTED_CHECKS),
              "checks_passed": len(checks), "checks": checks, "failure": failure,
              "missing_checks": [name for name in EXPECTED_CHECKS if name not in checks],
              "all_owned_processes_terminal": all_terminal, "fixture_errors": fixture_errors,
              "upstream_authenticated_requests": 0 if upstream is None else upstream.authenticated,
              "upstream_effect_counts": {} if upstream is None else upstream.counts,
              "commands": commands, "original_public_outputs": originals,
              "private_material_included": False,
              "limits": ["One trusted Unix owner and numeric loopback HTTP target.",
                         "Only these exact previously built executables and their current state format.",
                         "No installer, signed release, arbitrary version rollback, runtime identity isolation, physical power loss, or long-term stability qualification.",
                         "The target counts received synthetic requests; no remote production service or external account is used."]}
    report["passed"] = (failure is None and not fixture_errors and all_terminal
                        and tuple(checks) == EXPECTED_CHECKS)
    data = encoded(report)
    require(secret not in data, "credential_in_public_report")
    save(public / "receipt.public.json", data)
    directory = os.open(public, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({"receipt": str(public / "receipt.public.json"), "sha256": digest(data),
                      "passed": report["passed"], "checks_passed": len(checks), "failure": failure,
                      "all_owned_processes_terminal": all_terminal}, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CheckFailed as error:
        print(json.dumps({"passed": False, "preflight_error": str(error), "production_qualified": False}, sort_keys=True))
        raise SystemExit(1) from None
