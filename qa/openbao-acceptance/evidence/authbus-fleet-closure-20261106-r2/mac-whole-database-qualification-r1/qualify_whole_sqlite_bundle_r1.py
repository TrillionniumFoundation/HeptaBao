#!/usr/bin/env python3
"""Actual SQLite six-database lifecycle, with wholly synthetic values only.

The Mac launcher will supply the exact installed generated schema bytes and
new fixed fixture root. Local execution is explicitly not Mac qualification.
No SDK, gateway, provider or existing user database is opened by this module.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sqlite3
import time

from whole_sqlite_bundle_r1 import WholeStore, SnapshotRefused, need, page_image, sha

AGENTS = ("main", "trnm", "hepta-ui", "hepta", "hepta-backend")


def run_qualification(root, agent_schema, state_schema, *, until, source_vfs="unix-posix"):
    root = Path(root)
    root.mkdir(mode=0o700, exist_ok=False)
    for name in ("live", "archive", "live/agents", "live/state"):
        (root / name).mkdir(mode=0o700, exist_ok=False)
    paths = []
    for agent in AGENTS:
        (root / "live/agents" / agent).mkdir(mode=0o700, exist_ok=False)
        directory = root / "live/agents" / agent / "agent"
        directory.mkdir(mode=0o700, exist_ok=False)
        paths.append(directory / "openclaw-agent.sqlite")
    paths.append(root / "live/state/openclaw.sqlite")
    store = WholeStore(root=root / "archive", source_root=root / "live", until=until, source_vfs=source_vfs)
    report = {"schema": "heptabao.synthetic-whole-sqlite-bundle-qualification.r1", "ok": False,
              "syntheticOnly": True, "sourceDatabaseCount": 6, "productionReads": 0,
              "productionWrites": 0, "sdkImported": False, "providerCalls": 0,
              "serviceActions": 0, "gatewayRestartQualified": False,
              "productionRollbackQualified": False, "cases": []}
    report["sqliteSourceVfs"] = source_vfs
    started = time.monotonic()
    rows, keepers, baseline = [], [], []

    def check(name, value):
        need(value, "whole_qualification_" + name)
        report["cases"].append({"id": name, "passed": True})

    def script(row, sql):
        store.remaining()
        cursor = row["db"].cursor()
        row["cursorsOpened"] += 1
        try:
            cursor.executescript(sql)
        finally:
            cursor.close()
            row["cursorsClosed"] += 1

    try:
        for ordinal, path in enumerate(paths):
            store.create(path, b"")
            row = store.connect(path, readonly=False, role="original-rw")
            rows.append(row)
            need(store.query(row, "PRAGMA journal_mode=WAL") == [("wal",)], "synthetic_wal_mode")
            store.query(row, "PRAGMA wal_autocheckpoint=0")
            script(row, agent_schema if ordinal < 5 else state_schema)
            # An unknown extension, its index and trigger ensure recovery does
            # not silently regenerate only the application's known auth tables.
            script(row, """CREATE TABLE opaque_extension (id INTEGER PRIMARY KEY, value TEXT, payload BLOB);
CREATE INDEX opaque_extension_value ON opaque_extension(value);
CREATE TABLE opaque_extension_events (value TEXT);
CREATE TRIGGER opaque_extension_updated AFTER UPDATE ON opaque_extension
BEGIN INSERT INTO opaque_extension_events VALUES (NEW.value); END;
CREATE VIEW opaque_extension_view AS SELECT id,value FROM opaque_extension;""")
            store.query(row, "INSERT INTO opaque_extension VALUES(?,?,?)",
                        (1, "synthetic-before-provider", b"opaque\x00\xffnon-auth"))
            store.query(row, "PRAGMA user_version=101")
            store.query(row, "PRAGMA application_id=1212502098")
            if ordinal < 5:
                profiles = {"synthetic-main-" + str(i): {
                    "type": "oauth", "provider": "openai", "access": "old-synthetic-" + str(i),
                    "refresh": "old-refresh-synthetic-" + str(i), "expires": 1} for i in range(1, 4)}
                document = {"version": 1, "profiles": profiles, "unknownExtension": {"keep": [1, 2, 3]}}
                store.query(row, "INSERT INTO auth_profile_store VALUES('primary',?,11)",
                            (json.dumps(document),))
                store.query(row, "INSERT INTO auth_profile_state VALUES('primary',?,12)",
                            (json.dumps({"version": 1, "order": {"openai": list(profiles)}}),))
                store.query(row, "INSERT INTO cache_entries(scope,key,blob,updated_at) VALUES(?,?,?,?)",
                            ("synthetic-non-auth", "retained", b"full-library-backup", 19))
            else:
                for agent, agent_path in zip(AGENTS, paths):
                    store.query(row, "INSERT INTO agent_databases VALUES(?,?,?,?,?)",
                                (agent, str(agent_path), 1, 20, 4096))
            keeper = store.connect(path, readonly=True, role="old-readonly-keeper")
            keepers.append(keeper)
            store.query(keeper, "BEGIN")
            keeper["transaction"] = True
            need(store.query(keeper, "SELECT value FROM opaque_extension WHERE id=1")
                 == [("synthetic-before-provider",)], "actual_keeper_old_snapshot_established")
            store.query(row, "UPDATE opaque_extension SET value='synthetic-fresh-committed' WHERE id=1")
            if ordinal == 0:
                document = json.loads(store.query(row, "SELECT store_json FROM auth_profile_store WHERE store_key='primary'")[0][0])
                for number, credential in enumerate(document["profiles"].values(), 1):
                    credential.update(access="fresh-committed-synthetic-" + str(number),
                                      refresh="fresh-refresh-synthetic-" + str(number), expires=4102444800000)
                store.query(row, "UPDATE auth_profile_store SET store_json=?,updated_at=33 WHERE store_key='primary'",
                            (json.dumps(document),))
        check("six_actual_nonempty_wal_namespaces", all(store.namespace(p)["-wal"] is not None for p in paths))
        for ordinal, path in enumerate(paths):
            baseline.append(store.capture(path, store.namespace(path), slot=ordinal, phase="baseline"))
        check("six_fresh_independent_whole_snapshots", all(item["freshIndependentTransaction"]
              and item["backupCalls"] == 1 and not item["keeperUsedAsLatestSource"] for item in baseline))
        check("six_keepers_remain_old", all(store.query(k, "SELECT value FROM opaque_extension WHERE id=1")
              == [("synthetic-before-provider",)] for k in keepers))
        for item in baseline:
            archive = store.connect(Path(item["archivePath"]), readonly=True, immutable=True, role="verify-fresh-archive")
            try:
                need(store.query(archive, "SELECT value FROM opaque_extension WHERE id=1")
                     == [("synthetic-fresh-committed",)], "archive_current_wal_not_old_keeper")
                if item["slot"] == 0:
                    profiles = json.loads(store.query(archive, "SELECT store_json FROM auth_profile_store WHERE store_key='primary'")[0][0])["profiles"]
                    need(all(value["access"].startswith("fresh-committed-") for value in profiles.values()),
                         "fresh_synthetic_provider_epoch_in_whole_baseline")
            finally:
                store.close_connection(archive)
        check("archive_contains_latest_wal_and_three_fresh_tokens", True)
        for keeper in keepers:
            store.query(keeper, "ROLLBACK")
            keeper["transaction"] = False
            store.close_connection(keeper)
        for row in rows:
            store.close_connection(row)
        check("original_readers_and_writers_closed_once", all(r["closed"] and r["closeAttempts"] == 1 for r in rows + keepers))

        # A new synthetic candidate epoch changes data, schema and fresh tokens.
        # NO_CKPT_ON_CLOSE leaves real, valid WAL/SHM names after known closure,
        # so restore must retain all three files rather than only the main DB.
        candidates = []
        for ordinal, path in enumerate(paths):
            row = store.connect(path, readonly=False, role="candidate-rw")
            rows.append(row)
            row["db"].setconfig(sqlite3.SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, True)
            store.query(row, "PRAGMA wal_autocheckpoint=0")
            store.query(row, "UPDATE opaque_extension SET value='synthetic-candidate-mutated',payload=? WHERE id=1",
                        (b"candidate-content",))
            store.query(row, "DROP INDEX opaque_extension_value")
            store.query(row, "DROP VIEW opaque_extension_view")
            store.query(row, "PRAGMA user_version=202")
            if ordinal == 0:
                store.query(row, "UPDATE auth_profile_store SET store_json=?,updated_at=55 WHERE store_key='primary'",
                            ('{"version":1,"profiles":{"synthetic-candidate-only":{"type":"oauth"}}}',))
            candidates.append(store.capture(path, store.namespace(path), slot=ordinal, phase="candidate"))
            store.close_connection(row)
        candidate_names = [store.namespace(path) for path in paths]
        check("six_candidate_whole_archives_retained", all(item["phase"] == "candidate" for item in candidates))
        check("six_closed_candidate_wal_and_shm_names_retained", all(item["-wal"] and item["-shm"] for item in candidate_names))
        check("every_original_sqlite_handle_closed_before_restore", all(row["closed"] for row in store.connections))
        restored = store.restore(baseline, candidate_names)
        check("six_whole_files_restored_with_cold_sidecars_absent", all(item["-wal"] is None and item["-shm"] is None for item in restored))
        check("eighteen_old_namespace_files_retained", len(list((root / "archive/restore-once").glob("old-*.private"))) == 18)
        for ordinal, (path, item) in enumerate(zip(paths, baseline)):
            need(sha(store.bytes(path)) == item["archiveSha256"], "exact_closed_restored_baseline_bytes")
            read = store.connect(path, readonly=True, immutable=True, role="restored-cold-read")
            try:
                need(sha(page_image(read["db"].serialize(), store.maximum)) == item["pageImageSha256"],
                     "all_restored_page_bytes_and_schema_equal")
                need(store.query(read, "PRAGMA integrity_check", limit=1) == [("ok",)], "restored_database_integrity")
                need(store.query(read, "PRAGMA user_version", limit=1) == [(101,)], "restored_user_version")
                need(store.query(read, "SELECT value,payload FROM opaque_extension WHERE id=1")
                     == [("synthetic-fresh-committed", b"opaque\x00\xffnon-auth")], "full_non_auth_data_restored")
                need(store.query(read, "SELECT count(*) FROM opaque_extension_view") == [(1,)], "view_restored")
                if ordinal == 0:
                    profiles = json.loads(store.query(read, "SELECT store_json FROM auth_profile_store WHERE store_key='primary'")[0][0])["profiles"]
                    need(len(profiles) == 3 and all(value["access"].startswith("fresh-committed-") for value in profiles.values()),
                         "restore_does_not_rewind_fresh_provider_epoch")
            finally:
                store.close_connection(read)
        check("all_tables_indexes_triggers_views_pages_and_non_auth_data_match", True)
        check("three_synthetic_fresh_credentials_not_rewound", True)

        # An actual new SQLite writer epoch proves reopened trigger behavior.
        # This is explicitly not an installed SDK/gateway restart claim.
        for path in paths:
            row = store.connect(path, readonly=False, role="new-writer-after-restore")
            try:
                before = store.query(row, "SELECT count(*) FROM opaque_extension_events")[0][0]
                store.query(row, "UPDATE opaque_extension SET value='synthetic-new-writer' WHERE id=1")
                need(store.query(row, "SELECT count(*) FROM opaque_extension_events")[0][0] == before + 1,
                     "restored_trigger_active_in_new_writer_epoch")
            finally:
                store.close_connection(row)
        check("six_cold_reopened_writers_and_restored_trigger_effects", True)
        report.update(ok=True, wholeBaselineSnapshots=6, wholeCandidateSnapshots=6,
                      closedRestoredDatabases=6, retainedOriginalNamespaceFiles=18,
                      restoreDispatches=1, backupSourceIsFreshIndependentTransaction=True,
                      preProviderSnapshotUsedForRollback=False,
                      originalDeadlineAfterClosure=time.monotonic() < until)
    except BaseException as error:
        report["ok"] = False
        report["errorType"] = type(error).__name__
        code = str(error)
        report["errorCode"] = (code if isinstance(error, SnapshotRefused)
            and re.fullmatch(r"[a-z][a-z0-9_]{0,127}", code) else "whole_database_qualification_refused")
    finally:
        try:
            store.close()
        except BaseException:
            report["ok"] = False
            report["closureUnknown"] = True
        report["resources"] = store.public()
        report["elapsedSeconds"] = time.monotonic() - started
        if not all(report["resources"][name] for name in (
            "allFileDescriptorsClosedOnce", "allSqliteHandlesClosedOnce", "allExplicitCursorsClosed")):
            report["ok"] = False
    return report
