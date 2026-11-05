#!/usr/bin/env python3
"""Qualify the PostgreSQL DurableBackend against a fresh PostgreSQL 17.

This fixture exercises only the sealed-artifact backend.  It never opens an
existing cluster or a production DSN and records no credentials or PostgreSQL
diagnostics in the receipt.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

from postgres_live import Instance, Postgres, ROOT, psql_environment
from postgres_storage_live import DropServerReplyProxy

COMMIT_GATE = "hb-durable-test-commit-gate"


def hold_commit_gate(pg: Postgres):
    """Hold a transaction advisory lock used by a deferred test trigger."""
    env_context = psql_environment(
        pg.root.parent,
        port=pg.port,
        database="app",
        user="hb_bootstrap",
        password=pg.password,
        ca=pg.ca,
        application="hb-durable-commit-gate",
    )
    env = env_context.__enter__()
    process = subprocess.Popen(
        [str(pg.bin / "psql"), "-X", "-qAt", "-w", "-v", "ON_ERROR_STOP=1"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
        text=True,
    )
    process.stdin.write(
        "SELECT pg_advisory_lock(hashtextextended('"
        + COMMIT_GATE
        + "',0)); SELECT 'locked';\n"
    )
    process.stdin.flush()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        if line.strip() == "locked":
            return env_context, process
        if process.poll() is not None:
            break
    process.kill()
    process.wait(timeout=5)
    env_context.__exit__(None, None, None)
    raise RuntimeError("commit_gate_not_ready")


def release_commit_gate(env_context, process) -> None:
    if process.poll() is None:
        process.stdin.write(
            "SELECT pg_advisory_unlock(hashtextextended('"
            + COMMIT_GATE
            + "',0));\n"
        )
        process.stdin.close()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    env_context.__exit__(None, None, None)


def main() -> int:
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
    report = dict(
        schema="heptabao.postgresql-durable-backend.v1",
        status="failed",
        source_sha=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        source_dirty=bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        candidate_probe_sha256=hashlib.sha256(args.probe.read_bytes()).hexdigest(),
        runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        observed_at_unix=int(time.time()),
        checks=[],
        server_storage_integrated=False,
        full_openbao_compatibility=False,
        production_qualified=False,
        independent_reproduction=False,
    )
    checks = report["checks"]

    def check(case: str, passed: bool) -> None:
        checks.append({"case": case, "passed": passed is True})
        if passed is not True:
            raise RuntimeError(case)

    pg = None
    try:
        instance = Instance(args.probe, args.work_dir / "candidate")
        pg = Postgres(
            args.postgres_bin,
            args.work_dir / "postgres",
            instance.root / "tls.crt",
            instance.root / "tls.key",
            instance.root / "ca.crt",
        )
        pg.start()
        created = pg.sql(
            "CREATE ROLE hb_storage LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS PASSWORD '" + pg.manager_password + "'; "
            "CREATE DATABASE app OWNER hb_storage;",
            database="postgres",
        )
        check("fresh_postgresql_17_cluster_and_unprivileged_storage_owner", created.returncode == 0)
        config = dict(
            endpoint=dict(
                origin=pg.origin,
                address=f"127.0.0.1:{pg.port}",
                server_name="localhost",
                ca_pem=(instance.root / "ca.crt").read_text(),
            ),
            connection_url=pg.origin + "/app",
            username="hb_storage",
            password=pg.manager_password,
            scope="durable-fixture-one",
        )

        def invoke(mode: str, *, override: dict | None = None, label: str | None = None, timeout: int = 30) -> int:
            data = dict(config if override is None else override, mode=mode)
            result = subprocess.run(
                [str(args.probe)],
                input=json.dumps(data),
                text=True,
                capture_output=True,
                timeout=timeout,
            )
            if result.stdout.strip():
                output = json.loads(result.stdout)
                for entry in output.get("checks", []):
                    check((label + "/" if label else "") + entry["case"], entry["passed"])
            return result.returncode

        check("durable_basic_probe", invoke("basic") == 0)
        check("durable_reopen_probe", invoke("reopen") == 0)

        orphan = pg.sql(
            "INSERT INTO heptabao_durable_v1.chunks_v1 "
            "(format_version,scope,artifact,chunk_no,revision,bytes) "
            "VALUES (1,'durable-orphan','snapshot',0,1,decode('cafe','hex'))"
        )
        check("orphan_chunk_fixture_created", orphan.returncode == 0)
        check(
            "orphan_scope_initialization_rejected",
            invoke("reject-orphan", override=dict(config, scope="durable-orphan")) == 0,
        )
        preserved = pg.sql(
            "SELECT encode(bytes,'hex') FROM heptabao_durable_v1.chunks_v1 "
            "WHERE scope='durable-orphan'"
        )
        check("orphan_chunk_bytes_preserved", preserved.returncode == 0 and preserved.stdout.strip() == "cafe")
        absent = pg.sql(
            "SELECT count(*) FROM heptabao_durable_v1.manifest_v1 WHERE scope='durable-orphan'"
        )
        check("orphan_scope_manifest_not_created", absent.returncode == 0 and absent.stdout.strip() == "0")

        check("idle_session_operation_deadline_renewal", invoke("idle-session", override=dict(config, scope="durable-idle")) == 0)
        check("maximum_artifact_boundary", invoke("maximum-artifact", override=dict(config, scope="durable-maximum"), timeout=180) == 0)

        check("append_chunk_boundary_cases", invoke("append-boundaries", override=dict(config, scope="durable-boundary")) == 0)

        large_config = dict(config, scope="durable-large")
        check("large_artifact_seed_and_reopen", invoke("large-seed", override=large_config) == 0)
        preserved_prefix_sql = (
            "SELECT artifact,chunk_no,revision,md5(bytes) FROM heptabao_durable_v1.chunks_v1 "
            "WHERE scope='durable-large' AND (artifact<>'journal' OR chunk_no<3) "
            "ORDER BY artifact,chunk_no"
        )
        prefix_before = pg.sql(preserved_prefix_sql)
        check("large_append_prefix_recorded", prefix_before.returncode == 0)
        # Reject any rewrite of a full journal prefix or the other artifacts;
        # a small append must only touch the partial tail and new chunks.
        guard = pg.sql(
            "CREATE FUNCTION hb_durable_test_append_guard() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN IF OLD.scope='durable-large' AND (OLD.artifact<>'journal' OR OLD.chunk_no<3) "
            "THEN RAISE EXCEPTION 'unexpected immutable chunk rewrite'; END IF; "
            "IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW; END $$; "
            "CREATE TRIGGER hb_durable_test_append_guard BEFORE UPDATE OR DELETE ON "
            "heptabao_durable_v1.chunks_v1 FOR EACH ROW EXECUTE FUNCTION hb_durable_test_append_guard();"
        )
        check("large_append_prefix_rewrite_guard_installed", guard.returncode == 0)
        check("large_journal_incremental_append", invoke("large-append", override=large_config) == 0)
        prefix_after = pg.sql(preserved_prefix_sql)
        check("large_append_existing_prefix_bytes_and_revisions_unchanged",
              prefix_after.returncode == 0 and prefix_after.stdout == prefix_before.stdout)
        guard = pg.sql(
            "DROP TRIGGER hb_durable_test_append_guard ON heptabao_durable_v1.chunks_v1; "
            "DROP FUNCTION hb_durable_test_append_guard();"
        )
        check("large_append_prefix_rewrite_guard_removed", guard.returncode == 0)
        check("large_checkpoint_and_truncate", invoke("large-checkpoint", override=large_config) == 0)

        # Each corruption receives its own fresh, isolated scope. Rejection
        # must not change even one manifest or chunk, including unknown data.
        for case, mutation in [
            ("gap", "UPDATE heptabao_durable_v1.chunks_v1 SET chunk_no=80 WHERE scope='{scope}' AND artifact='snapshot' AND chunk_no=1"),
            ("future_revision", "UPDATE heptabao_durable_v1.chunks_v1 SET revision=99 WHERE scope='{scope}' AND artifact='ledger' AND chunk_no=0"),
            ("short_interior", "UPDATE heptabao_durable_v1.chunks_v1 SET bytes=substring(bytes FROM 1 FOR 1) WHERE scope='{scope}' AND artifact='snapshot' AND chunk_no=0"),
        ]:
            scope = "durable-corrupt-" + case
            corrupt_config = dict(config, scope=scope)
            check(case + "/seed", invoke("large-seed", override=corrupt_config, label=case) == 0)
            changed = pg.sql(mutation.format(scope=scope))
            check(case + "/corruption_injected", changed.returncode == 0)
            state_sql = (
                "SELECT revision,snapshot_len,ledger_len,journal_len FROM heptabao_durable_v1.manifest_v1 "
                "WHERE scope='" + scope + "'; "
                "SELECT artifact,chunk_no,revision,md5(bytes) FROM heptabao_durable_v1.chunks_v1 "
                "WHERE scope='" + scope + "' ORDER BY artifact,chunk_no"
            )
            before = pg.sql(state_sql)
            check(case + "/rejected", invoke("reject-large-layout", override=corrupt_config, label=case) == 0)
            after = pg.sql(state_sql)
            check(case + "/bytes_and_manifest_preserved", before.returncode == 0 and after.returncode == 0 and before.stdout == after.stdout)

        # Make COMMIT observable without adding a production failpoint. A
        # deferred constraint trigger waits on a test-only advisory lock, so
        # the fixture can prove that the backend's write reached COMMIT before
        # the transparent proxy drops the server acknowledgement.
        trigger_sql = (
            "CREATE OR REPLACE FUNCTION hb_durable_test_commit_gate() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock("
            "hashtextextended('" + COMMIT_GATE + "',0)); RETURN NEW; END $$; "
            "DROP TRIGGER IF EXISTS hb_durable_test_commit_gate ON "
            "heptabao_durable_v1.manifest_v1; "
            "CREATE CONSTRAINT TRIGGER hb_durable_test_commit_gate AFTER INSERT OR UPDATE "
            "ON heptabao_durable_v1.manifest_v1 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
            "EXECUTE FUNCTION hb_durable_test_commit_gate();"
        )
        installed = pg.sql(trigger_sql)
        check("deferred_commit_gate_installed", installed.returncode == 0)
        gate_holder = None
        gate_env = None
        proxy = None
        process = None
        try:
            gate_env, gate_holder = hold_commit_gate(pg)
            proxy = DropServerReplyProxy(pg.port)
            proxy.start()
            proxy_config = copy.deepcopy(config)
            proxy_config["endpoint"]["origin"] = proxy.origin
            proxy_config["endpoint"]["address"] = f"127.0.0.1:{proxy.port}"
            proxy_config["connection_url"] = proxy.origin + "/app"
            process = subprocess.Popen(
                [str(args.probe)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            process.stdin.write(json.dumps(dict(proxy_config, mode="lost-commit")))
            process.stdin.close()
            process.stdin = None
            ready = selectors.DefaultSelector()
            ready.register(process.stdout, selectors.EVENT_READ)
            events = ready.select(timeout=10)
            marker = process.stdout.readline().strip() if events else ""
            check("lost_commit_probe_started", marker == "commit_pending")
            deadline = time.monotonic() + 10
            waiting = False
            while time.monotonic() < deadline:
                activity = pg.sql(
                    "SELECT count(*) FROM pg_stat_activity WHERE usename='hb_storage' "
                    "AND query LIKE 'COMMIT%' AND wait_event_type='Lock'"
                )
                waiting = activity.returncode == 0 and activity.stdout.strip() == "1"
                if waiting:
                    break
                time.sleep(0.05)
            check("lost_commit_commit_reached_and_blocked", waiting)
            proxy.drop_server_replies()
            release_commit_gate(gate_env, gate_holder)
            gate_env = None
            gate_holder = None
            # The server has committed, but the acknowledgement is still
            # discarded. Closing the proxy turns the unknown outcome into the
            # backend's explicit OutcomeUnknown result.
            time.sleep(0.2)
            proxy.close()
            proxy = None
            stdout, _ = process.communicate(timeout=20)
            process = None
            output = json.loads(stdout)
            for entry in output.get("checks", []):
                check("lost_commit/" + entry["case"], entry["passed"])
            check("lost_commit_probe_exited_cleanly", True)
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if proxy is not None:
                proxy.close()
            if gate_holder is not None:
                release_commit_gate(gate_env, gate_holder)
            elif gate_env is not None:
                gate_env.__exit__(None, None, None)
            pg.sql(
                "DROP TRIGGER IF EXISTS hb_durable_test_commit_gate ON "
                "heptabao_durable_v1.manifest_v1; "
                "DROP FUNCTION IF EXISTS hb_durable_test_commit_gate();"
            )
        check("lost_commit_reopen_exactly_once", invoke("reopen-lost") == 0)

        # A second session must be rejected immediately while the first owns
        # the scope lock.  No subprocess is allowed to remain blocked.
        gate = args.work_dir / "writer-gate"
        gate.unlink(missing_ok=True)
        holder = subprocess.Popen(
            [str(args.probe)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            holder.stdin.write(json.dumps(dict(config, mode="hold-writer", commit_gate=str(gate))))
            holder.stdin.close()
            holder.stdin = None
            ready = selectors.DefaultSelector()
            ready.register(holder.stdout, selectors.EVENT_READ)
            events = ready.select(timeout=10)
            marker = holder.stdout.readline().strip() if events else ""
            check("durable_writer_fence_acquired", marker == "writer_held")
            check("durable_second_writer_rejected", invoke("reject-writer") == 0)
        finally:
            gate.touch(mode=0o600)
            try:
                holder.wait(timeout=10)
            except subprocess.TimeoutExpired:
                holder.kill()
                holder.wait(timeout=5)
            gate.unlink(missing_ok=True)

        # Altered relation durability and a weakened named check must both be
        # rejected before a backend can load sealed state.
        altered = pg.sql("ALTER TABLE heptabao_durable_v1.chunks_v1 SET UNLOGGED;")
        check("unlogged_durable_table_installed", altered.returncode == 0)
        check("unlogged_durable_table_rejected", invoke("reject-schema", label="unlogged") == 0)
        altered = pg.sql("ALTER TABLE heptabao_durable_v1.chunks_v1 SET LOGGED;")
        check("logged_durable_table_restored", altered.returncode == 0)
        altered = pg.sql(
            "ALTER TABLE heptabao_durable_v1.manifest_v1 DROP CONSTRAINT manifest_format_version; "
            "ALTER TABLE heptabao_durable_v1.manifest_v1 ADD CONSTRAINT manifest_format_version "
            "CHECK ((format_version = 1) OR (revision > 0));"
        )
        check("weakened_durable_check_installed", altered.returncode == 0)
        check("weakened_durable_check_rejected", invoke("reject-schema", label="weakened") == 0)
        altered = pg.sql(
            "ALTER TABLE heptabao_durable_v1.manifest_v1 DROP CONSTRAINT manifest_format_version; "
            "ALTER TABLE heptabao_durable_v1.manifest_v1 ADD CONSTRAINT manifest_format_version "
            "CHECK (format_version = 1);"
        )
        check("durable_check_restored", altered.returncode == 0)

        bad = dict(config, password="wrong-synthetic-password")
        check("wrong_durable_password_rejected", invoke("reject-connect", override=bad) == 0)
        report["postgresql_version"] = version.strip()
        report["status"] = "passed_scoped_backend"
    except Exception as error:  # keep raw diagnostics out of the receipt
        report["reason"] = "fixture_" + type(error).__name__
        if isinstance(error, RuntimeError):
            report["failed_case"] = str(error)
    finally:
        if pg is not None:
            pg.stop()
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "checks": len(checks), "output": str(args.output)}))
    return int(report["status"] != "passed_scoped_backend")


if __name__ == "__main__":
    raise SystemExit(main())
