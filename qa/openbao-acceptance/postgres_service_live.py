#!/usr/bin/env python3
"""Exercise PostgreSQL persistence through a real HeptaBao TLS process.

Uses only a fresh private PostgreSQL 17 cluster and synthetic credentials.
Receipts contain case names, hashes and outcomes, never responses or secrets.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

from postgres_live import Instance, Postgres, ROOT
from postgres_durable_live import COMMIT_GATE, hold_commit_gate, release_commit_gate
from postgres_storage_live import DropServerReplyProxy


def lost_initialization_reply(binary, root, pg, config, check):
    """Commit the real server's import, discard its reply, then restart it."""
    instance = Instance(binary, root / "lost-init")
    proxy = DropServerReplyProxy(pg.port)
    gate_env = gate = None
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        proxy.start()
        own = json.loads((instance.root / "server.json").read_text())
        own["lifecycle_interval_seconds"] = 0
        own["postgres_durable"] = copy.deepcopy(config["postgres_durable"])
        storage = own["postgres_durable"]
        storage["scope"] = "lost-init-fixture"
        storage["endpoint"].update(origin=proxy.origin, address=f"127.0.0.1:{proxy.port}")
        storage["connection_url"] = proxy.origin + "/app"
        (instance.root / "server.json").write_text(json.dumps(own))
        installed = pg.sql(
            "CREATE FUNCTION hb_service_init_commit_gate() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN IF NEW.scope='lost-init-fixture' THEN "
            "PERFORM pg_advisory_xact_lock(hashtextextended('" + COMMIT_GATE + "',0)); "
            "END IF; RETURN NEW; END $$; "
            "CREATE CONSTRAINT TRIGGER hb_service_init_commit_gate AFTER INSERT "
            "ON heptabao_durable_v1.manifest_v1 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
            "EXECUTE FUNCTION hb_service_init_commit_gate();")
        check("lost_init_deferred_commit_gate_installed", installed.returncode == 0)
        instance.start()
        params = dict(secret_shares=1, secret_threshold=1, recovery_nonce=secrets.token_hex(32))
        gate_env, gate = hold_commit_gate(pg)
        request = pool.submit(instance.call, "POST", "sys/init", params)
        deadline = time.monotonic() + 5
        waiting = False
        while time.monotonic() < deadline:
            activity = pg.sql("SELECT count(*) FROM pg_stat_activity WHERE usename='hb_storage' "
                              "AND query LIKE 'COMMIT%' AND wait_event_type='Lock'")
            waiting = activity.returncode == 0 and activity.stdout.strip() == "1"
            if waiting or request.done():
                break
            time.sleep(.02)
        check("lost_init_reached_real_commit", waiting)
        proxy.drop_server_replies()
        release_commit_gate(gate_env, gate)
        gate_env = gate = None
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and proxy.dropped_bytes == 0:
            time.sleep(.02)
        check("lost_init_acknowledgement_actually_discarded", proxy.dropped_bytes > 0)
        port = proxy.port
        proxy.close()
        proxy = None
        check("lost_init_returns_unknown_without_keys", request.result(timeout=5)[0] == 503)
        committed = pg.sql("SELECT artifact,chunk_no,encode(bytes,'hex') "
                           "FROM heptabao_durable_v1.chunks_v1 WHERE scope='lost-init-fixture' "
                           "ORDER BY artifact,chunk_no")
        check("lost_init_artifacts_are_committed", committed.returncode == 0 and bool(committed.stdout.strip()))
        instance.stop()
        # Rebind the same test endpoint, preserving the target binding. The
        # PostgreSQL server and its committed scope remain untouched.
        proxy = DropServerReplyProxy(pg.port, listen_port=port)
        proxy.start()
        instance.start()
        status, initialized = instance.call("POST", "sys/init", params)
        check("lost_init_same_nonce_recovers_after_sigkill", status == 200 and bool(initialized.get("root_token")))
        recovered = pg.sql("SELECT artifact,chunk_no,encode(bytes,'hex') "
                           "FROM heptabao_durable_v1.chunks_v1 WHERE scope='lost-init-fixture' "
                           "ORDER BY artifact,chunk_no")
        check("lost_init_retry_preserves_exact_committed_bundle",
              recovered.returncode == 0 and recovered.stdout == committed.stdout)
        count = pg.sql("SELECT count(*) FROM heptabao_durable_v1.manifest_v1 WHERE scope='lost-init-fixture'")
        check("lost_init_exactly_one_manifest", count.returncode == 0 and count.stdout.strip() == "1")
    finally:
        if gate is not None:
            release_commit_gate(gate_env, gate)
        if proxy is not None:
            proxy.close()
        instance.stop()
        pool.shutdown(wait=True, cancel_futures=True)
        pg.sql("DROP TRIGGER IF EXISTS hb_service_init_commit_gate ON heptabao_durable_v1.manifest_v1; "
               "DROP FUNCTION IF EXISTS hb_service_init_commit_gate();")


def run(binary: Path, pg_bin: Path, root: Path, checks: list) -> None:
    instance = Instance(binary, root / "candidate")
    pg = None
    contender = None

    def check(name, condition):
        checks.append(dict(case=name, passed=condition is True))
        if condition is not True:
            raise RuntimeError(name)

    def configure(target, config):
        path = target.root / "server.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        path.chmod(0o600)

    try:
        pg = Postgres(pg_bin, root / "postgres", instance.root / "tls.crt",
                      instance.root / "tls.key", instance.root / "ca.crt")
        pg.start()
        created = pg.sql(
            "CREATE ROLE hb_storage LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS PASSWORD '" + pg.manager_password + "'; "
            "CREATE DATABASE app OWNER hb_storage;", database="postgres")
        check("fresh_postgresql_17_unprivileged_owner", created.returncode == 0)
        config = json.loads((instance.root / "server.json").read_text())
        config["lifecycle_interval_seconds"] = 0
        config["postgres_durable"] = dict(
            endpoint=dict(origin=pg.origin, address=f"127.0.0.1:{pg.port}",
                          server_name="localhost", ca_pem=(instance.root / "ca.crt").read_text()),
            connection_url=pg.origin + "/app", username="hb_storage",
            password=pg.manager_password, scope="server-fixture")
        configure(instance, config)
        instance.start()
        params = dict(secret_shares=1, secret_threshold=1)
        check("postgres_init_requires_recovery_nonce",
              instance.call("POST", "sys/init", params)[0] == 400)
        params["recovery_nonce"] = secrets.token_hex(32)
        # An unavailable database occurs after local preparation. Kill/restart
        # the server to prove the nonce and encrypted pending bundle survive.
        pg.stop()
        check("database_unavailable_init_retains_recoverable_pending_state",
              instance.call("POST", "sys/init", params)[0] == 503)
        instance.stop()
        pg.start()
        instance.start()
        wrong = dict(params, recovery_nonce=secrets.token_hex(32))
        check("pending_init_rejects_different_nonce",
              instance.call("POST", "sys/init", wrong)[0] >= 400)
        status, initialized = instance.call("POST", "sys/init", params)
        check("pending_init_recovers_after_process_restart", status == 200)
        instance.token = initialized.get("root_token", "")
        key = initialized.get("keys_base64", [""])[0]
        check("recovered_init_returns_keys", bool(instance.token) and bool(key))
        status, repeated = instance.call("POST", "sys/init", params)
        check("same_nonce_returns_identical_initialization_response",
              status == 200 and repeated == initialized)
        check("local_storage_contains_only_metadata",
              (instance.root / "data" / "durable-backend.json").is_file()
              and all(not (instance.root / "data" / leaf).exists()
                      for leaf in ("state.hbs", "ledger.hbl", "journal.hbj")))
        check("postgres_service_unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("initialization_ack", instance.call("POST", "sys/init/ack", {})[0] == 204)
        secret = "synthetic-postgres-secret-" + secrets.token_hex(20)
        check("kv_write_through_postgres_service", instance.call(
            "POST", "secret/data/postgres-item", {"data": {"value": secret}})[0] == 200)
        raw = pg.sql("SELECT encode(bytes,'hex') FROM heptabao_durable_v1.chunks_v1")
        check("postgres_stores_sealed_artifacts", raw.returncode == 0 and bool(raw.stdout.strip())
              and all(secret.encode() not in bytes.fromhex(row) for row in raw.stdout.splitlines()))
        # A distinct process has its own audit sink but points to the same
        # metadata and PostgreSQL scope. The live writer fence must reject it.
        contender = Instance(binary, root / "contender")
        second = json.loads((contender.root / "server.json").read_text())
        second.update(data_dir=config["data_dir"], postgres_durable=copy.deepcopy(config["postgres_durable"]),
                      lifecycle_interval_seconds=0)
        configure(contender, second)
        contender.start()
        check("second_service_cannot_acquire_live_writer_fence",
              contender.call("POST", "sys/unseal", {"key": key})[0] == 503)
        contender.stop()
        instance.stop()
        missing = copy.deepcopy(config)
        missing.pop("postgres_durable")
        configure(instance, missing)
        instance.start()
        check("restart_still_reports_initialized_without_pg_config",
              instance.call("GET", "sys/init")[1].get("initialized") is True)
        check("restart_without_pg_config_fails_closed",
              instance.call("POST", "sys/unseal", {"key": key})[0] == 503)
        check("no_filesystem_fallback_artifacts",
              not (instance.root / "data" / "state.hbs").exists())
        instance.stop()
        configure(instance, config)
        instance.start()
        check("restart_with_matching_pg_config_unseals",
              instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        status, body = instance.call("GET", "secret/data/postgres-item")
        check("kv_survives_server_sigkill_restart",
              status == 200 and body.get("data", {}).get("data", {}).get("value") == secret)
        lost_initialization_reply(binary, root, pg, config, check)
    finally:
        if contender is not None:
            contender.stop()
        instance.stop()
        if pg is not None:
            pg.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--postgres-bin", type=Path, default=Path("/usr/lib/postgresql/17/bin"))
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not all(path.is_absolute() for path in (args.binary, args.work_dir, args.output)):
        parser.error("absolute binary, private work directory and receipt paths required")
    if not all((args.postgres_bin / name).is_file() for name in ("postgres", "initdb", "psql")):
        print(json.dumps(dict(status="blocked", reason="real_postgresql_17_missing")))
        return 77
    version = subprocess.check_output([str(args.postgres_bin / "postgres"), "--version"], text=True)
    if not version.startswith("postgres (PostgreSQL) 17."):
        parser.error("PostgreSQL 17 required")
    os.umask(0o077)
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = dict(schema="heptabao.postgresql-service-live.v1", status="failed",
                  source_sha=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  source_dirty=bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
                  candidate_binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                  runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  observed_at_unix=int(time.time()), checks=[],
                  server_storage_integrated=False, full_openbao_compatibility=False,
                  production_qualified=False, independent_reproduction=False)
    try:
        run(args.binary, args.postgres_bin, args.work_dir, report["checks"])
        report["status"] = "passed_scoped_service"
        report["server_storage_integrated"] = True
    except Exception as error:
        # No exception message: remote diagnostics could contain credentials.
        report["failure_kind"] = type(error).__name__
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.output.chmod(0o600)
    print(json.dumps(dict(status=report["status"], checks=len(report["checks"]))))
    return 0 if report["status"] == "passed_scoped_service" else 1


if __name__ == "__main__":
    raise SystemExit(main())
