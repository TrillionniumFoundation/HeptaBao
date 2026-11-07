#!/usr/bin/env python3
"""Finite real-process tests of the Firefox launch contract and shared native IPC.

No browser, user profile, native-host registry, portal, network or ADB is used.
Only a newly created private root and synthetic vault are touched. Public records
contain actual argv, exit codes and reaping evidence, never native frame payloads.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import struct
import subprocess
import sys
import time

ADDON = "heptabao-firefox-feasibility@heptabao.invalid"
HOST = "org.heptabao.personal_vault_firefox_feasibility"
ORIGIN = "https://login.example.test"
PASSWORD = "synthetic-firefox-cli-master-20261106"
SECRET = "synthetic-firefox-cli-login-secret-20261106"
USERNAME = "synthetic-firefox-user"
EXPECTED = (
    "firefox_real_launcher_status",
    "firefox_synthetic_origin_and_lock_scope",
    "firefox_actual_lease_expiry",
    "firefox_wrong_addon_rejected",
    "firefox_wrong_manifest_path_rejected",
    "firefox_missing_or_unknown_argv_rejected",
    "firefox_chrome_origin_not_substituted",
    "firefox_manifest_digest_tamper_rejected",
    "firefox_manifest_fields_rejected",
    "firefox_unsafe_or_unknown_config_rejected",
    "installer_existing_root_not_overwritten",
    "installer_wrong_addon_not_prepared",
    "chromium_legacy_entry_preserved",
)


class Failure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Failure(code)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_private(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


class Run:
    def __init__(self, args, report):
        self.args = args
        self.report = report
        self.binary = args.bin_dir / "heptabao-browser"
        self.vault_binary = args.bin_dir / "heptabao-vault"
        self.vault = args.root / "synthetic-vault.private"
        self.vault.mkdir(mode=0o700)
        self.number = 0
        self.case = "fixture_setup"

    def start(self, argv):
        row = {"case": self.case, "argv": [str(x) for x in argv],
               "started_monotonic_ns": time.monotonic_ns(), "reaped": False}
        self.report["children"].append(row)
        process = subprocess.Popen(row["argv"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        row["pid"] = process.pid
        return process, row

    def diagnostic(self, row, stdout, stderr):
        require(all(value.encode() not in stderr for value in (PASSWORD, SECRET, USERNAME)),
                "diagnostic_leaked_synthetic_value")
        row.update(stdout_bytes=len(stdout), stderr_bytes=len(stderr))
        codes = {b"", b"configuration_required\n", b"configuration_rejected\n",
                 b"caller_or_configuration_rejected\n", b"manifest_rejected\n"}
        if stderr in codes:
            row["stderr_closed_code"] = stderr.decode().strip()

    def command(self, argv, payload=b"", timeout=20):
        process, row = self.start(argv)
        timed_out = False
        try:
            try:
                out, err = process.communicate(payload, timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()  # This owned Popen only; never a PID/name lookup.
                out, err = process.communicate(timeout=3)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
            row.update(exit_code=process.returncode, reaped=True, timed_out=timed_out,
                       finished_monotonic_ns=time.monotonic_ns())
        self.diagnostic(row, out, err)
        require(not timed_out, "owned_command_timeout")
        return process.returncode, out, err

    def vault_call(self, command, value):
        code, out, err = self.command([self.vault_binary, self.vault, command], encoded(value))
        require(code == 0 and not err, "synthetic_vault_setup_failed")
        result = json.loads(out)
        require(result.get("ok") is True, "synthetic_vault_setup_failed")

    def setup(self):
        self.vault_call("init", {"password": PASSWORD,
            "output": str(self.args.root / "synthetic-recovery.private.json")})
        self.vault_call("put", {"password": PASSWORD, "expected_revision": 0,
            "item": {"id": "synthetic-login", "kind": "login", "title": "Synthetic Firefox",
                "username": USERNAME, "origin": ORIGIN, "secret": SECRET,
                "notes": "", "totp": None}})

    def prepare(self, seconds=60):
        self.number += 1
        root = self.args.root / ("installation-" + str(self.number))
        argv = [sys.executable, "-I", "-B", self.args.installer, "--binary", self.binary,
            "--vault", self.vault, "--install-root", root, "--unlock-seconds", str(seconds)]
        code, out, err = self.command(argv)
        require(code == 0 and not err, "installer_failed")
        data = json.loads(out)
        require(data.get("prepared") is True and data.get("browser_registered") is False,
                "installer_scope_invalid")
        return {"root": root, "argv": argv, "manifest": Path(data["manifest"]),
                "launcher": Path(data["launcher"]), "config": Path(data["config"])}

    @staticmethod
    def frame(process, request, number=1):
        raw = encoded({"id": number, "request": request})
        process.stdin.write(struct.pack("=I", len(raw)) + raw)
        process.stdin.flush()
        end = time.monotonic() + 10

        def exact(size):
            result = bytearray()
            while len(result) < size:
                remaining = end - time.monotonic()
                require(remaining > 0 and select.select([process.stdout], [], [], remaining)[0],
                        "native_reply_timeout")
                part = os.read(process.stdout.fileno(), size - len(result))
                require(part, "native_reply_incomplete")
                result.extend(part)
            return bytes(result)

        length = struct.unpack("=I", exact(4))[0]
        require(0 < length <= 131072, "native_reply_length")
        value = json.loads(exact(length))
        require(value.get("id") == number, "native_reply_identity")
        return value

    def session(self, argv, action):
        process, row = self.start(argv)
        killed = False
        try:
            action(process)
        finally:
            if not process.stdin.closed:
                process.stdin.close()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                killed = True
                process.kill()
                process.wait(timeout=3)
            err = process.stderr.read(131073)
            # Frame response bodies are deliberately never stored in public logs.
            row.update(exit_code=process.returncode, reaped=True, cleanup_kill=killed,
                       response_payloads_recorded=False,
                       finished_monotonic_ns=time.monotonic_ns())
            self.diagnostic(row, b"", err)
            row.pop("stdout_bytes")
            for stream in (process.stdin, process.stdout, process.stderr):
                if not stream.closed:
                    stream.close()
        require(process.returncode == 0 and not killed and not err, "native_session_exit")

    def deny(self, installation, args=None, error="caller_or_configuration_rejected"):
        argv = args or [installation["launcher"], installation["manifest"], ADDON]
        code, out, err = self.command(argv, timeout=5)
        require(code == 1 and out == b"" and err == (error + "\n").encode(),
                "caller_rejection_not_exact")

    @staticmethod
    def rewrite_config(installation, change):
        config = json.loads(installation["config"].read_bytes())
        change(config)
        installation["config"].write_bytes(encoded(config))

    def status(self, process):
        require(self.frame(process, {"op": "status"}) ==
                {"id": 1, "ok": True, "result": {"locked": True}}, "locked_status_failed")

    def firefox_real_launcher_status(self):
        i = self.prepare()
        self.session([i["launcher"], i["manifest"], ADDON], self.status)

    def firefox_synthetic_origin_and_lock_scope(self):
        i = self.prepare()
        def action(p):
            require(self.frame(p, {"op": "unlock", "password": PASSWORD})["result"]
                    == {"locked": False}, "unlock_failed")
            listing = self.frame(p, {"op": "list", "origin": ORIGIN})
            require(listing["ok"] is True and len(listing["result"]) == 1, "list_failed")
            fill = {"op": "fill", "origin": ORIGIN, "item_id": "synthetic-login", "top_frame": True}
            response = self.frame(p, fill)
            require(response["ok"] is True and response["result"]["username"] == USERNAME
                    and response["result"]["password"] == SECRET
                    and 0 < response["result"]["valid_for_ms"] <= 2000, "fill_failed")
            wrong = self.frame(p, dict(fill, origin="https://wrong.example.test"))
            require(wrong["ok"] is False, "wrong_origin_accepted")
            frame = self.frame(p, dict(fill, top_frame=False))
            require(frame["ok"] is False and frame["error"] == "origin_rejected", "frame_accepted")
            require(self.frame(p, {"op": "lock"})["result"] == {"locked": True}, "lock_failed")
            locked = self.frame(p, fill)
            require(locked["ok"] is False and locked["error"] == "locked_or_expired", "locked_fill_accepted")
        self.session([i["launcher"], i["manifest"], ADDON], action)

    def firefox_actual_lease_expiry(self):
        i = self.prepare(seconds=2)
        def action(p):
            require(self.frame(p, {"op": "unlock", "password": PASSWORD})["ok"] is True, "unlock_failed")
            time.sleep(2.2)
            self.status(p)
            value = self.frame(p, {"op": "fill", "origin": ORIGIN,
                "item_id": "synthetic-login", "top_frame": True})
            require(value["ok"] is False and value["error"] == "locked_or_expired", "expired_fill_accepted")
        self.session([i["launcher"], i["manifest"], ADDON], action)

    def firefox_wrong_addon_rejected(self):
        i = self.prepare()
        self.deny(i, [i["launcher"], i["manifest"], "unrelated@heptabao.invalid"])

    def firefox_wrong_manifest_path_rejected(self):
        i = self.prepare()
        other_parent = i["root"] / "other-manifest"
        other_parent.mkdir(mode=0o700)
        other = other_parent / (HOST + ".json")
        write_private(other, i["manifest"].read_bytes())
        self.deny(i, [i["launcher"], other, ADDON])

    def firefox_missing_or_unknown_argv_rejected(self):
        i = self.prepare()
        for suffix in ([], [i["manifest"]], [i["manifest"], ADDON, "--unknown"]):
            self.deny(i, [i["launcher"], *suffix], "configuration_required")
        self.deny(i, [self.binary, "--unknown", i["config"], i["manifest"], ADDON], "configuration_required")

    def firefox_chrome_origin_not_substituted(self):
        i = self.prepare()
        chrome = "chrome-extension://" + "a" * 32 + "/"
        self.deny(i, [i["launcher"], i["manifest"], chrome])
        self.deny(i, [i["launcher"], chrome], "configuration_required")

    def firefox_manifest_digest_tamper_rejected(self):
        i = self.prepare()
        i["manifest"].write_bytes(i["manifest"].read_bytes() + b" ")
        self.deny(i, error="manifest_rejected")

    def firefox_manifest_fields_rejected(self):
        variants = [{"allowed_extensions": [ADDON, "other@heptabao.invalid"]},
                    {"type": "socket"}, {"path": "/unrelated/native-host"},
                    {"allowed_origins": ["chrome-extension://" + "a" * 32 + "/"]}]
        for change in variants:
            i = self.prepare()
            manifest = json.loads(i["manifest"].read_bytes())
            manifest.update(change)
            i["manifest"].write_bytes(encoded(manifest))
            self.rewrite_config(i, lambda c: c.update(manifest_sha256=sha(i["manifest"])))
            self.deny(i, error="manifest_rejected")

    def firefox_unsafe_or_unknown_config_rejected(self):
        i = self.prepare()
        self.rewrite_config(i, lambda c: c.update(unrecognized=True))
        self.deny(i, error="configuration_rejected")
        i = self.prepare()
        i["manifest"].chmod(0o644)
        self.deny(i, error="manifest_rejected")
        i = self.prepare()
        other = i["root"] / "actual-manifest.private.json"
        i["manifest"].rename(other)
        i["manifest"].symlink_to(other)
        self.deny(i, error="manifest_rejected")
        i = self.prepare()
        self.rewrite_config(i, lambda c: c.update(addon_id="other@heptabao.invalid"))
        self.deny(i)

    def installer_existing_root_not_overwritten(self):
        i = self.prepare()
        before = {x: sha(i[x]) for x in ("manifest", "config", "launcher")}
        code, out, err = self.command(i["argv"])
        require(code == 1 and not err and json.loads(out).get("error") == "installation_exists",
                "existing_installation_accepted")
        require(before == {x: sha(i[x]) for x in before}, "existing_installation_changed")

    def installer_wrong_addon_not_prepared(self):
        root = self.args.root / "unaccepted-installation"
        code, out, err = self.command([sys.executable, "-I", "-B", self.args.installer,
            "--binary", self.binary, "--vault", self.vault, "--install-root", root,
            "--addon-id", "other@heptabao.invalid"])
        require(code == 1 and not err and json.loads(out).get("error") == "invalid_addon_or_expiry"
                and not os.path.lexists(root), "wrong_addon_installation_created")

    def chromium_legacy_entry_preserved(self):
        config = self.args.root / "chromium-config.private.json"
        write_private(config, encoded({"vault_root": str(self.vault),
            "extension_id": "a" * 32, "unlock_seconds": 60}))
        origin = "chrome-extension://" + "a" * 32 + "/"
        self.session([self.binary, "--config", config, origin], self.status)
        self.deny(None, [self.binary, "--config", config, "chrome-extension://" + "b" * 32 + "/"])


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    args.bin_dir = args.bin_dir.resolve(strict=True)
    args.installer = args.installer.resolve(strict=True)
    require(args.root.is_absolute() and not os.path.lexists(args.root), "new_private_root_required")
    args.root.mkdir(mode=0o700, exist_ok=False)
    require(args.report.is_absolute() and not os.path.lexists(args.report), "new_report_required")
    meta = args.report.parent.lstat()
    require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.geteuid()
            and stat.S_IMODE(meta.st_mode) == 0o700, "private_report_parent_required")
    inputs = [args.bin_dir / "heptabao-browser", args.bin_dir / "heptabao-vault",
              args.installer, Path(__file__)]
    before = {str(p): sha(p) for p in inputs}
    report = {"schema": 1, "scope": "real_native_cli_and_pipes_only", "synthetic_only": True,
        "expected": len(EXPECTED), "checks": [], "children": [], "input_sha256": before,
        "browser_started": False, "user_profile_accessed": False, "global_registration": False,
        "adb_used": False, "network_used": False, "caller_attestation_claimed": False,
        "firefox_end_to_end_qualified": False, "production_qualified": False,
        "started_unix_ns": time.time_ns()}
    try:
        run = Run(args, report)
        run.setup()
        for name in EXPECTED:
            run.case = name
            row = {"case": name, "passed": False}
            report["checks"].append(row)
            try:
                getattr(run, name)()
                row["passed"] = True
            except Exception as error:
                row["failure"] = str(error) if isinstance(error, Failure) else type(error).__name__
                break
    except Exception as error:
        report["setup_failure"] = str(error) if isinstance(error, Failure) else type(error).__name__
    report["inputs_unchanged"] = before == {str(p): sha(p) for p in inputs}
    report["all_started_children_reaped"] = all(x["reaped"] for x in report["children"])
    report["passed"] = sum(x["passed"] for x in report["checks"])
    report["failed"] = sum(not x["passed"] for x in report["checks"])
    report["missing"] = [x for x in EXPECTED if x not in {y["case"] for y in report["checks"]}]
    report["finished_unix_ns"] = time.time_ns()
    report["ok"] = (report["passed"] == len(EXPECTED) and report["inputs_unchanged"]
                    and report["all_started_children_reaped"])
    raw = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    require(all(x.encode() not in raw for x in (PASSWORD, SECRET, USERNAME)), "public_report_leak")
    write_private(args.report, raw)
    print(raw.decode(), end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
