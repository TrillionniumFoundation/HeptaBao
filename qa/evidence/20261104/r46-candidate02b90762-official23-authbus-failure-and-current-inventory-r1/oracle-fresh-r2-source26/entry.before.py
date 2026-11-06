#!/usr/bin/env python3
"""SOURCE proposal: one fixed official2.7.1 X230 ACL23 fixture.

The existing official launcher, Linux Owner, HTTP transport, 23-cell executor,
matrix and four-class component source are immutable inputs. No candidate is
started and no historical full34 wrapper is rerun. This entry has no Runtime GO.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time

ROOT = Path("/home/qian/heptabao-official271-acl23-oracle-20261106-r1")
PORT = 23623
RUN_ID = "official271-acl23-r1"
VERSION = "2.7.1"
BINARY = Path("/home/qian/heptabao-official-271-fresh-20261029-r1/bao")
ARCHIVE = Path("/home/qian/heptabao-official-271-fresh-20261029-r1/official-openbao-2.7.1-linux-amd64.tar.gz")
ARTIFACTS = (
    (BINARY, 181760103, 0o700,
     "535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea"),
    (ARCHIVE, 74865426, 0o600,
     "0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243"),
)
PAYLOAD_BYTES = 134374
PAYLOAD_SHA256 = "49e17724c2087cbc6f15fd5a37f8fc0e0d37c649ebc0273627540aabe75141d0"
INPUTS = [
  [
    "source/qa/openbao-acceptance/owned_process.py",
    28442,
    "0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0"
  ],
  [
    "source/qa/openbao-acceptance/official_openbao_launcher.py",
    20008,
    "5c11b432e1180fb40394fab382da774cf4171bf51431aab7e5823068cfba01d6"
  ],
  [
    "source/qa/openbao-acceptance/bao_http.py",
    2349,
    "6c617b587640ceacfcae0f91ee928ee068193ae012ecb305541e3007315c328f"
  ],
  [
    "source/qa/openbao-acceptance/raw_status_observer.py",
    13664,
    "1952270dba831b0e21e2291df8178e9557e7ff76fc83a2e8dc70cbf46eb7d4e9"
  ],
  [
    "source/qa/openbao-acceptance/acl23_executor.py",
    15599,
    "e96451d450224abfa7eeda34622b26b1d21493867b4344aa254709348515bfc4"
  ],
  [
    "source/qa/openbao-acceptance/current_record_component.py",
    5355,
    "660c8f55649861a3765b7b320d4c1abf2e7eba4ebac2f2290bee29eabeaff3f9"
  ],
  [
    "source/clients/python/heptabao/__init__.py",
    194,
    "6b48603fea77708df5e51b71cda53f488241b3c3f3cccb60158434cbdec219b2"
  ],
  [
    "source/clients/python/heptabao/transport.py",
    21936,
    "fbf797ed819364f39fca60fb1d61032d29a43feb3c275de8f6b37c2f9e88429f"
  ],
  [
    "source/clients/python/heptabao/consistency.py",
    4836,
    "657d81f48895ec4bb4e27199fcd3b7125d8fc2cb9899f777945ef2e831519abe"
  ],
  [
    "MATRIX23.original.public.json",
    14285,
    "59e3c9519e59e7ae26cde512a8171d39e2175e8bb24f12039222218570ebe6f8"
  ],
  [
    "PUBLIC-KEY.pem",
    451,
    "db4837a2caba18729628ca629eeb44f452a55d5a9aa1f7bad7c2357ed0217938"
  ]
]
DIRECTORIES = (
    "source", "source/qa", "source/qa/openbao-acceptance",
    "source/clients", "source/clients/python", "source/clients/python/heptabao",
    "private", "private/oracle-work",
)
OWNER_SECONDS = 360
ACL_REQUEST_CAP = 853
REPORT_CAP = 1048576
SOURCE_BYTES = 127119
FD_LIMIT = 12  # Eleven fixed source outputs plus the one public result.
START_NS = time.monotonic_ns()
UNTIL_NS = START_NS + OWNER_SECONDS * 1_000_000_000
FD_ROWS = []
PENDING_SIGNAL = None


class EntryFailure(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise EntryFailure(code)


def check_deadline():
    need(PENDING_SIGNAL is None, "entry_signal_pending")
    need(time.monotonic_ns() < UNTIL_NS, "original_360_second_deadline")


def full9(value):
    return [str(value.st_dev), str(value.st_ino), str(value.st_uid),
            str(value.st_gid), str(value.st_mode), str(value.st_nlink),
            str(value.st_size), str(value.st_mtime_ns), str(value.st_ctime_ns)]


def snapshot_artifacts():
    observed = []
    for path, size, mode, digest in ARTIFACTS:
        need(path.resolve(strict=True) == path and not path.is_symlink(),
             "fixed_artifact_canonical_path")
        first, second = path.lstat(), path.lstat()
        need(full9(first) == full9(second) and stat.S_ISREG(first.st_mode)
             and first.st_size == size and stat.S_IMODE(first.st_mode) == mode
             and first.st_uid == 1000 and first.st_gid == 1000
             and first.st_nlink == 1, "fixed_artifact_metadata")
        observed.append({"path": str(path), "full9_decimal": full9(first),
                         "expected_sha256": digest,
                         "whole_hash_checked_by_original_launcher": False})
    return observed


def write_exact(relative, data, *, expected_sha256=None):
    check_deadline()
    need(relative in {row[0] for row in INPUTS} | {"result.public.json"},
         "fixed_create_only_output")
    need(type(data) is bytes and len(data) <= REPORT_CAP, "bounded_public_output")
    if expected_sha256 is not None:
        need(hashlib.sha256(data).hexdigest() == expected_sha256, "input_whole_hash")
    need(len(FD_ROWS) < FD_LIMIT, "fixed_fd_count")
    row = {"relative": relative, "open_started": False, "opened": False,
           "close_attempts": 0, "closed": False}
    FD_ROWS.append(row)  # Record capacity before acquisition.
    fd = None
    try:
        row["open_started"] = True
        fd = os.open(ROOT / relative,
                     os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     os.O_CLOEXEC, 0o600)
        row["opened"] = True
        start = os.fstat(fd)
        need(stat.S_ISREG(start.st_mode) and stat.S_IMODE(start.st_mode) == 0o600
             and start.st_uid == os.geteuid() and start.st_gid == os.getegid()
             and start.st_nlink == 1 and start.st_size == 0, "new_output_identity")
        view = memoryview(data)
        while view:
            check_deadline()
            written = os.write(fd, view[:65536])
            need(written > 0, "short_owned_write")
            view = view[written:]
        os.fsync(fd)
        after_write = os.fstat(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        chunks, count = [], 0
        while count < len(data):
            check_deadline()
            block = os.read(fd, min(65536, len(data) - count))
            need(bool(block), "short_owned_readback")
            chunks.append(block)
            count += len(block)
        need(os.read(fd, 1) == b"" and b"".join(chunks) == data, "whole_owned_readback")
        after = os.fstat(fd)
        named = (ROOT / relative).lstat()
        need(full9(after_write) == full9(after) == full9(named)
             and after.st_size == len(data), "named_fd_final_identity")
        row["full9_decimal"] = full9(after)
        row["bytes"] = len(data)
        row["sha256"] = hashlib.sha256(data).hexdigest()
    finally:
        if fd is not None:
            row["close_attempts"] += 1
            try:
                os.close(fd)
                row["closed"] = True
            finally:
                fd = None  # A close failure is never retried.
    check_deadline()
    return {key: row[key] for key in
            ("relative", "full9_decimal", "bytes", "sha256", "closed")}


def signal_pending(number, frame):
    global PENDING_SIGNAL
    if PENDING_SIGNAL is None:
        PENDING_SIGNAL = number


def closed_fds():
    return all((not row["opened"] and row["close_attempts"] == 0)
               or (row["opened"] and row["closed"] and row["close_attempts"] == 1)
               for row in FD_ROWS)


def main():
    old_handlers, old_mask = {}, os.umask(0o077)
    source_rows, owner, oracle, executor = [], None, None, None
    root_created = False
    extra_live_health_attempted, extra_live_health_completed = 0, 0
    component, identity, capture, original_owner_receipt = None, None, None, None
    artifact_before, artifact_after, failure = None, None, None
    report_pin, stage = None, "self_and_fixed_payload"
    result = {}
    try:
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            old_handlers[number] = signal.getsignal(number)
            signal.signal(number, signal_pending)
        need(sys.platform.startswith("linux") and os.geteuid() == 1000
             and os.getegid() == 1000, "fixed_linux_owner")
        need(len(sys.orig_argv) == 7 and sys.orig_argv[1:5] == ["-I", "-S", "-B", "-c"]
             and len(sys.argv) == 2
             and hashlib.sha256(sys.orig_argv[5].encode("utf-8")).hexdigest() == sys.argv[1],
             "exact_inline_entry_self_sha")
        payload = sys.stdin.buffer.read(PAYLOAD_BYTES + 1)
        need(len(payload) == PAYLOAD_BYTES
             and hashlib.sha256(payload).hexdigest() == PAYLOAD_SHA256,
             "exact_fixed_payload")
        bundle = json.loads(payload)
        need(set(bundle) == {"schema", "files"}
             and bundle["schema"] == "heptabao.X230-official271-acl23-fixed-inputs.v1"
             and type(bundle["files"]) is dict
             and list(bundle["files"]) == [row[0] for row in INPUTS],
             "fixed_input_membership")
        source_bytes = {}
        for relative, size, digest in INPUTS:
            text = bundle["files"][relative]
            need(type(text) is str, "source_utf8_text")
            data = text.encode("utf-8")
            need(len(data) == size and hashlib.sha256(data).hexdigest() == digest,
                 "exact_source_member")
            source_bytes[relative] = data
        need(sum(map(len, source_bytes.values())) == SOURCE_BYTES, "source_total")
        check_deadline()
        stage = "fresh_owned_work_root"
        need(ROOT.parent.resolve(strict=True) == ROOT.parent
             and not ROOT.parent.is_symlink(), "fixed_parent_canonical")
        os.mkdir(ROOT, 0o700)  # Existing paths, including symlinks, are rejected.
        root_created = True
        need(stat.S_IMODE(ROOT.lstat().st_mode) == 0o700
             and ROOT.lstat().st_uid == 1000, "fresh_private_root_identity")
        for name in DIRECTORIES:
            check_deadline()
            os.mkdir(ROOT / name, 0o700)
        for relative, size, digest in INPUTS:
            source_rows.append(write_exact(relative, source_bytes[relative],
                                           expected_sha256=digest))
        need(closed_fds() and len(FD_ROWS) == 11, "source_fds_closed_before_import")
        qa = ROOT / "source/qa/openbao-acceptance"
        clients = ROOT / "source/clients/python"
        sys.path[:0] = [str(qa), str(clients)]
        os.environ.clear()
        os.environ.update({
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8", "TZ": "UTC", "TMPDIR": str(ROOT / "private"),
            "HB_ORACLE_BINARY": str(BINARY), "HB_ORACLE_ARCHIVE": str(ARCHIVE),
            "HB_ORACLE_WORK_ROOT": str(ROOT / "private/oracle-work"),
        })
        sys.dont_write_bytecode = True
        stage = "exact_fixed_imports_and_components"
        owned = importlib.import_module("owned_process")
        launcher = importlib.import_module("official_openbao_launcher")
        raw = importlib.import_module("raw_status_observer")
        acl = importlib.import_module("acl23_executor")
        components = importlib.import_module("current_record_component")
        for module, name in ((owned, "owned_process"), (launcher, "official_openbao_launcher"),
                             (raw, "raw_status_observer"), (acl, "acl23_executor"),
                             (components, "current_record_component")):
            need(Path(module.__file__) == qa / (name + ".py"), "fixed_import_origin")
        need(owned._CURRENT is None, "no_ambient_process_owner")
        component = components.run_current_record_failure_checks(
            raw, verified_source_sha256="1952270dba831b0e21e2291df8178e9557e7ff76fc83a2e8dc70cbf46eb7d4e9")
        need(component["classes"] == 4 and component["variants"] == 8
             and all(row["passed"] for row in component["results"]),
             "current_record_components")
        check_deadline()
        artifact_before = snapshot_artifacts()
        owner = owned.Owner(ROOT / "private", deadline_ns=UNTIL_NS,
                            profile="official271_acl23_oracle")
        stage = "original_launcher_and_acl23"
        with owned.activated(owner):
            try:
                oracle = launcher.start_oracle(PORT, version=VERSION,
                                                audit_file=False, raft_storage=False)
                from bao_http import Client, private_read
                token = private_read(oracle["token_file"], limit=8192).decode("utf-8").strip()
                client = Client(oracle["address"], oracle["ca_file"], token, timeout=15)
                owner.remaining()
                extra_live_health_attempted = 1
                health = client.health()
                extra_live_health_completed = 1
                identity = launcher.verify_selected_oracle(
                    oracle, health, version=VERSION, raft_storage=False)

                def remaining():
                    if executor is not None and len(executor.calls.records) >= ACL_REQUEST_CAP:
                        raise raw.BaoError("fixed_original_acl_request_cap")
                    return owner.remaining()

                executor = acl.FixedAcl23(
                    client, remaining, source_bytes["MATRIX23.original.public.json"],
                    source_bytes["PUBLIC-KEY.pem"].decode("ascii"), RUN_ID)
                capture = executor.run()
            finally:
                if oracle is not None:
                    launcher.stop_oracle(oracle)
        original_owner_receipt = owner.receipt
        stage = "post_owner_source_and_artifact_boundary"
        artifact_after = snapshot_artifacts()
        need(artifact_before == artifact_after, "fixed_artifacts_changed")
        for row in source_rows:
            path = ROOT / row["relative"]
            need(path.resolve(strict=True) == path and not path.is_symlink()
                 and full9(path.lstat()) == row["full9_decimal"],
                 "fixed_source_changed_after_owner")
        need(owned._CURRENT is None and owner.finished
             and owner.receipt["same_originals_closed"]
             and owner.receipt["passed_process_method"], "original_owner_not_qualified")
        need(capture["actual_case_records"] == 23
             and all(row["transition_checked"] and row["wire"]["complete"]
                     for row in capture["cases"]), "incomplete_original_23_capture")
        check_deadline()
    except BaseException as error:
        failure = {"stage": stage, "class": type(error).__name__}
        code = getattr(error, "code", None)
        if isinstance(code, str) and re.fullmatch("[a-z0-9_]{1,96}", code):
            failure["code"] = code
        # No exception string, token, private response, unseal key, or log is public.
    finally:
        if owner is not None and hasattr(owner, "receipt"):
            original_owner_receipt = owner.receipt
        result = {
            "schema": "heptabao.official271.acl23.oracle-only.actual.v1",
            "capture_complete": failure is None and capture is not None,
            "failure": failure, "official_version_requested": VERSION,
            "historical_artifact_presence_not_inherited": True,
            "source_inputs": source_rows, "artifact_metadata_before": artifact_before,
            "artifact_metadata_after": artifact_after, "live_identity": identity,
            "components": component, "component_product_cases": 0,
            "matrix_case_denominator": 23, "http12_product_cases_executed": 0,
            "acl": capture if capture is not None else (
                executor.public_partial() if executor is not None else None),
            "admin_and_case_wire_records": executor.calls.records if executor is not None else [],
            "acl_requests_observed": len(executor.calls.records) if executor is not None else 0,
            "acl_request_cap": ACL_REQUEST_CAP,
            "startup_source_upper_bound": 103,
            "extra_live_health_requests": {"maximum": 1,
                                           "attempted": extra_live_health_attempted,
                                           "completed": extra_live_health_completed},
            "startup_requests_actual_count": None,
            "original_owner": original_owner_receipt,
            "original_deadline_ns": UNTIL_NS, "deadline_reset": False,
            "parity_qualified": False, "status_normalization": False,
            "candidate_started": False, "fixtures_started_at_most": 1,
            "source_fd_rows_before_publication": FD_ROWS,
            "publication_close_verdict_is_in_terminal_stdout": True,
        }
        try:
            stage = "create_only_public_report"
            need(root_created and ROOT.is_dir() and closed_fds(),
                 "output_requires_new_owned_closed_boundary")
            data = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode("utf-8")
            need(len(data) <= REPORT_CAP, "bounded_public_report")
            report_pin = write_exact("result.public.json", data)
        except BaseException as error:
            if failure is None:
                failure = {"stage": stage, "class": type(error).__name__}
        finally:
            for number, previous in old_handlers.items():
                signal.signal(number, previous)
            os.umask(old_mask)
    passed = (failure is None and PENDING_SIGNAL is None and closed_fds()
              and time.monotonic_ns() < UNTIL_NS and report_pin is not None)
    terminal = {"schema": "heptabao.official271.acl23.oracle-only.terminal.v1",
                "capture_complete": passed, "failure": failure,
                "report": report_pin, "all_entry_file_descriptors_closed": closed_fds(),
                "entry_fd_count": len(FD_ROWS),
                "source_bytes": SOURCE_BYTES, "report_cap": REPORT_CAP,
                "pending_signal": PENDING_SIGNAL,
                "original_owner_receipt_present": original_owner_receipt is not None,
                "parity_qualified": False, "candidate_started": False,
                "matrix_case_denominator": 23, "component_product_cases": 0}
    print(json.dumps(terminal, sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
