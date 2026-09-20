#!/usr/bin/env python3
"""Qualify the PostgreSQL DurableBackend against a fresh PostgreSQL 17.

This fixture exercises only the sealed-artifact backend.  It never opens an
existing cluster or a production DSN and records no credentials or PostgreSQL
diagnostics in the receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

from postgres_live import Instance, Postgres, ROOT


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

        def invoke(mode: str, *, override: dict | None = None, label: str | None = None) -> int:
            data = dict(config if override is None else override, mode=mode)
            result = subprocess.run(
                [str(args.probe)],
                input=json.dumps(data),
                text=True,
                capture_output=True,
                timeout=30,
            )
            if result.stdout.strip():
                output = json.loads(result.stdout)
                for entry in output.get("checks", []):
                    check((label + "/" if label else "") + entry["case"], entry["passed"])
            return result.returncode

        check("durable_basic_probe", invoke("basic") == 0)
        check("durable_reopen_probe", invoke("reopen") == 0)

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
