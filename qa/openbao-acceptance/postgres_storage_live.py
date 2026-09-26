#!/usr/bin/env python3
"""Exercise the Rust physical-storage adapter against a fresh real PostgreSQL 17.

The probe is a Rust example built from the candidate. Credentials travel only on
stdin. This never opens an existing cluster or imports an OpenBao data directory.
It qualifies the adapter; server durable-storage selection remains separate.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import threading
import time

from postgres_live import Postgres, Instance, ROOT


CORPUS_CASE_IDS = (
    "fresh_postgresql_17_cluster_and_unprivileged_storage_owner",
    "opaque_binary_value_roundtrip",
    "shallow_ordered_hierarchical_listing",
    "multi_record_commit_publishes_together",
    "repeatable_read_retains_snapshot",
    "lost_commit/lost_commit_reply_reports_unknown_outcome",
    "lost_commit_effect_is_durable_at_postgresql",
    "wrong_password/untrusted_tls_or_credentials_rejected",
    "missing_primary_key/altered_storage_constraints_rejected",
    "committed_storage_survives_postgresql_sigkill_restart",
)


class DropServerReplyProxy:
    """One-client transparent TCP forwarder used to lose a commit reply.

    TLS remains end-to-end between the Rust probe and PostgreSQL.  Before
    ``drop_server_replies`` both byte streams are copied unchanged; afterwards
    bytes from PostgreSQL are consumed and counted while client-to-server bytes
    continue, allowing COMMIT to reach and finish at the real server.
    """

    def __init__(self, target_port, *, listen_port=0):
        self.target = ("127.0.0.1", target_port)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", listen_port))
        self.listener.listen(1)
        self.listener.settimeout(0.5)
        self.port = self.listener.getsockname()[1]
        self.origin = f"postgresql://localhost:{self.port}"
        self.drop = threading.Event()
        self.stop = threading.Event()
        self.accepted = threading.Event()
        self.lock = threading.Lock()
        self.server_bytes = 0
        self.dropped_bytes = 0
        self.client = None
        self.server = None
        self.workers = []
        self.thread = threading.Thread(target=self._serve, name="hb-pg-reply-drop", daemon=True)

    def start(self):
        self.thread.start()

    def drop_server_replies(self):
        self.drop.set()

    def _serve(self):
        try:
            while not self.stop.is_set():
                try:
                    client, _ = self.listener.accept()
                except socket.timeout:
                    continue
                self.client = client
                self.accepted.set()
                try:
                    server = socket.create_connection(self.target, timeout=5)
                    self.server = server
                    client.settimeout(None)
                    server.settimeout(None)
                    left = threading.Thread(target=self._copy, args=(client, server, False),
                                             name="hb-pg-client-to-server", daemon=True)
                    right = threading.Thread(target=self._copy, args=(server, client, True),
                                              name="hb-pg-server-to-client", daemon=True)
                    self.workers = [left, right]
                    left.start(); right.start()
                    while not self.stop.is_set() and (left.is_alive() or right.is_alive()):
                        left.join(.1); right.join(.1)
                finally:
                    try:
                        client.close()
                    except OSError:
                        pass
                    if self.server is not None:
                        try:
                            self.server.close()
                        except OSError:
                            pass
                return
        except OSError:
            return

    def _copy(self, source, target, from_server):
        try:
            while not self.stop.is_set():
                chunk = source.recv(65536)
                if not chunk:
                    return
                if from_server:
                    with self.lock:
                        self.server_bytes += len(chunk)
                    if self.drop.is_set():
                        with self.lock:
                            self.dropped_bytes += len(chunk)
                        continue
                target.sendall(chunk)
        except (OSError, socket.timeout):
            return

    def close(self):
        self.stop.set()
        try:
            self.listener.close()
        except OSError:
            pass
        for stream in (self.client, self.server):
            if stream is not None:
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    stream.close()
                except OSError:
                    pass
        self.thread.join(timeout=5)
        for worker in tuple(self.workers):
            worker.join(timeout=2)
        if self.thread.is_alive() or any(worker.is_alive() for worker in self.workers):
            raise RuntimeError("reply_drop_proxy_did_not_stop")


def run(probe, bin_dir, root, checks):
    certificates = Instance(probe, root / "certificates")
    pg = Postgres(bin_dir, root / "postgres", certificates.root / "tls.crt",
                  certificates.root / "tls.key", certificates.root / "ca.crt")

    def check(name, passed):
        checks.append({"case": name, "passed": passed is True})
        if passed is not True:
            raise RuntimeError(name)

    try:
        pg.start()
        created = pg.sql(
            "CREATE ROLE hb_storage LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS PASSWORD '" + pg.manager_password + "'; "
            "CREATE DATABASE app OWNER hb_storage;", database="postgres")
        check("fresh_postgresql_17_cluster_and_unprivileged_storage_owner", created.returncode == 0)
        config = dict(endpoint=dict(origin=pg.origin, address=f"127.0.0.1:{pg.port}",
                                    server_name="localhost",
                                    ca_pem=(certificates.root / "ca.crt").read_text()),
                      connection_url=pg.origin + "/app", username="hb_storage",
                      password=pg.manager_password, scope="fixture-one")

        def invoke(mode, *, override=None, label=None):
            data = dict(config if override is None else override, mode=mode)
            result = subprocess.run([str(probe)], input=json.dumps(data), text=True,
                                    capture_output=True, timeout=30)
            # Do not publish stderr or raw input: a panic/debug regression could
            # include synthetic credentials. The report records only case IDs.
            report = json.loads(result.stdout)
            for entry in report["checks"]:
                check((label + "/" if label else "") + entry["case"], entry["passed"])
            if result.returncode != 0:
                raise RuntimeError("rust_probe_failed_" + mode)

        invoke("basic")
        invoke("concurrency")

        # Commit outcome is intentionally made uncertain: the proxy drops all
        # PostgreSQL-to-client bytes only after the probe has entered its
        # transaction, while client-to-server bytes continue to the real PG.
        gate = root / "lost-commit-gate"
        gate.unlink(missing_ok=True)
        proxy = DropServerReplyProxy(pg.port)
        proxy.start()
        proxy_config = copy.deepcopy(config)
        proxy_config["endpoint"]["origin"] = proxy.origin
        proxy_config["endpoint"]["address"] = f"127.0.0.1:{proxy.port}"
        proxy_config["connection_url"] = proxy.origin + "/app"
        process = subprocess.Popen(
            [str(probe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True,
        )
        try:
            process.stdin.write(json.dumps(dict(
                proxy_config, mode="lost-commit", commit_gate=str(gate)
            )))
            process.stdin.close()
            process.stdin = None
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                events = ready.select(timeout=10)
                marker = process.stdout.readline().strip() if events else ""
            check("lost_commit_transaction_entered", marker == "commit_pending")
            proxy.drop_server_replies()
            gate.touch(mode=0o600)
            try:
                stdout, _ = process.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise RuntimeError("lost_commit_probe_timeout")
            if process.returncode != 0:
                raise RuntimeError("lost_commit_probe_failed")
            report = json.loads(stdout)
            for entry in report["checks"]:
                check("lost_commit/" + entry["case"], entry["passed"])
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            proxy.close()
            gate.unlink(missing_ok=True)
        with proxy.lock:
            dropped_bytes = proxy.dropped_bytes
        check("lost_commit_reply_was_dropped", dropped_bytes > 0)
        observed = pg.sql(
            "SELECT encode(value, 'hex') FROM heptabao_storage_v1.records_v1 "
            "WHERE scope='fixture-one' AND key='fixture/lost-commit'"
        )
        check(
            "lost_commit_effect_is_durable_at_postgresql",
            observed.returncode == 0
            and observed.stdout.strip() == b"committed-without-reply".hex(),
        )

        # Columns alone do not establish the key and format invariants.
        changed = pg.sql("ALTER TABLE heptabao_storage_v1.records_v1 SET UNLOGGED;")
        check("unlogged_table_installed_for_durability_fault", changed.returncode == 0)
        invoke("reject-schema", label="unlogged_table")
        changed = pg.sql("ALTER TABLE heptabao_storage_v1.records_v1 SET LOGGED;")
        check("logged_table_restored_after_durability_fault", changed.returncode == 0)
        changed = pg.sql("ALTER TABLE heptabao_storage_v1.records_v1 "
                         "DROP CONSTRAINT records_v1_pkey;")
        check("primary_key_removed_for_schema_fault", changed.returncode == 0)
        invoke("reject-schema", label="missing_primary_key")
        changed = pg.sql("ALTER TABLE heptabao_storage_v1.records_v1 "
                         "ADD PRIMARY KEY (scope, key);")
        check("primary_key_restored_after_schema_fault", changed.returncode == 0)
        changed = pg.sql("ALTER TABLE heptabao_storage_v1.records_v1 "
                         "DROP CONSTRAINT records_v1_format_version_check;")
        check("format_constraint_removed_for_schema_fault", changed.returncode == 0)
        invoke("reject-schema", label="missing_format_check")
        changed = pg.sql("ALTER TABLE heptabao_storage_v1.records_v1 "
                         "ADD CONSTRAINT records_v1_format_version_check CHECK ((format_version = 1) OR (revision > 0));")
        check("weakened_format_constraint_installed", changed.returncode == 0)
        invoke("reject-schema", label="weakened_format_check")
        changed = pg.sql("ALTER TABLE heptabao_storage_v1.records_v1 "
                         "DROP CONSTRAINT records_v1_format_version_check; "
                         "ALTER TABLE heptabao_storage_v1.records_v1 "
                         "ADD CONSTRAINT records_v1_format_version_check CHECK (format_version = 1);")
        check("format_constraint_restored_after_schema_fault", changed.returncode == 0)
        bad = copy.deepcopy(config)
        bad["password"] = "wrong-synthetic-password"
        invoke("reject-connect", override=bad, label="wrong_password")
        other_ca = Instance(probe, root / "other-ca")
        bad = copy.deepcopy(config)
        bad["endpoint"]["ca_pem"] = (other_ca.root / "ca.crt").read_text()
        invoke("reject-connect", override=bad, label="wrong_ca")

        for fault in ("client-kill", "postgres-kill"):
            process = subprocess.Popen([str(probe)], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       text=True)
            try:
                process.stdin.write(json.dumps(dict(config, mode="pending-write")))
                process.stdin.close()
                with selectors.DefaultSelector() as ready:
                    ready.register(process.stdout, selectors.EVENT_READ)
                    events = ready.select(timeout=10)
                    check(fault + "_transaction_entered", bool(events)
                          and process.stdout.readline().strip() == "transaction_pending")
                if fault == "postgres-kill":
                    pg.stop()
                process.kill()
                process.wait(timeout=5)
                if fault == "postgres-kill":
                    pg.start()
                invoke("after-crash", label=fault)
                check(fault + "_rolled_back_and_previous_commit_survived", True)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
        pg.stop()
        pg.start()
        invoke("after-crash", label="restart")
        check("committed_storage_survives_postgresql_sigkill_restart", True)
        return subprocess.check_output([str(bin_dir / "postgres"), "--version"], text=True).strip()
    finally:
        pg.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--postgres-bin", type=Path, default=Path("/usr/lib/postgresql/17/bin"))
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.work_dir.is_absolute() or not args.output.is_absolute():
        parser.error("absolute private work and receipt paths required")
    if not all((args.postgres_bin / name).is_file() for name in ("postgres", "initdb", "psql")):
        print(json.dumps({"status": "blocked", "reason": "real_postgresql_17_missing"}))
        return 77
    version = subprocess.check_output([str(args.postgres_bin / "postgres"), "--version"], text=True)
    if not version.startswith("postgres (PostgreSQL) 17."):
        parser.error("PostgreSQL 17 required by this fixture")
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.umask(0o077)
    report = dict(schema="heptabao.postgresql-physical-storage.v1", status="failed",
                  source_sha=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  source_dirty=bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
                  candidate_probe_sha256=hashlib.sha256(args.probe.read_bytes()).hexdigest(),
                  runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  observed_at_unix=int(time.time()), checks=[],
                  server_storage_integrated=False, full_openbao_compatibility=False,
                  production_qualified=False, independent_reproduction=False)
    try:
        report["postgresql_version"] = run(args.probe.resolve(), args.postgres_bin.resolve(),
                                           args.work_dir, report["checks"])
        observed_cases = {entry["case"] for entry in report["checks"] if entry.get("passed") is True}
        missing_cases = sorted(set(CORPUS_CASE_IDS) - observed_cases)
        if missing_cases:
            raise RuntimeError("corpus_case_missing:" + ",".join(missing_cases))
        report["status"] = "passed_scoped_adapter"
    except Exception as error:
        report["reason"] = "fixture_" + type(error).__name__
        if isinstance(error, RuntimeError):
            report["failed_case"] = str(error)
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]),
                      "failed_case": report.get("failed_case"), "output": str(args.output)}))
    return int(report["status"] != "passed_scoped_adapter")


if __name__ == "__main__":
    raise SystemExit(main())
