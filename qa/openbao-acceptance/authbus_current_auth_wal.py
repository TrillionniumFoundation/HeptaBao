#!/usr/bin/env python3
"""Read only registered AuthBus profile projections from current SQLite sources.

This library performs no import-time I/O, refresh, provider request, SDK import,
or private publication. Nonempty WAL always uses a named read-only transaction.
Only a separately fenced absent/empty WAL uses the qualified held-fd immutable
route; any source/sidecar change makes the observation fail without a value.
The executable caller must bind exact library/runtime/proof bytes, establish a
kernel deny-write/no-network sandbox, and supply a reviewed private profile
allowlist before a production attempt. A successful read is one bounded
transaction observation, not a gateway binding or a cross-agent snapshot.

Only the fixed primary auth_profile_store row is fetched. Registered profile
values are projected in memory; no database, nonprimary row, or unselected
credential is returned. Source identities and held main/WAL/SHM names must
remain unchanged through rollback, connection close and the final fence.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time

import mac_guarded_current_capture_r3 as base
import mac_registry_readonly_wal_r1 as wal

LIVE = Path("/Users/qianqi/.openclaw")
SYNTHETIC_ROOT = Path("/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2")
CASES = tuple("A%02d" % number for number in range(1, 19))
SCHEMA = "heptabao.authbus-current-auth-wal-projection.r2"
need = base.need


def validate_profiles(agent, authorized_profiles, requested_profiles):
    need(agent in base.AGENTS, "registered_agent_required")
    for value in (authorized_profiles, requested_profiles):
        need(isinstance(value, (list, tuple)) and 1 <= len(value) <= 128,
             "bounded_explicit_profile_list")
        need(all(isinstance(item, str) and 1 <= len(item) <= 256
                 and all(ord(char) >= 32 and ord(char) != 127 for char in item) for item in value),
             "typed_private_profile_ids")
        need(len(set(value)) == len(value), "unique_private_profile_ids")
    need(set(requested_profiles) <= set(authorized_profiles), "profile_not_authorized")
    return tuple(requested_profiles)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "ambiguous_duplicate_json_key")
            result[key] = value
        return result

    def reject_constant(_value):
        raise base.CaptureRefused("nonfinite_auth_json")

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)

    def finite(item):
        if isinstance(item, float):
            need(math.isfinite(item), "nonfinite_auth_json")
        elif isinstance(item, dict):
            for nested in item.values():
                finite(nested)
        elif isinstance(item, list):
            for nested in item:
                finite(nested)

    finite(value)
    return value


class AuthInputs(wal.WalInputs):
    def __init__(self, *, until, critical, cancelled, live=LIVE, synthetic=False):
        # This is a new namespace admission, not an alteration of the old
        # registry proof's closed ten-case namespace.
        need(callable(critical) and callable(cancelled), "descriptor_guards_required")
        live = Path(live)
        owned = {SYNTHETIC_ROOT / "cases" / name / "live" for name in CASES}
        need((not synthetic and live == LIVE) or (synthetic and live in owned),
             "exact_auth_wal_input_namespace")
        need(sys.platform == "darwin" and os.geteuid() == 501, "actual_mac_auth_owner")
        need(isinstance(until, (int, float)) and math.isfinite(until)
             and time.monotonic() < until <= time.monotonic() + 45, "one_auth_capture_deadline")
        self.live = live
        self.synthetic = synthetic
        self.until = until
        self.critical = critical
        self.cancelled = cancelled
        self.uid = os.geteuid()
        self.fds, self.parents, self.files, self.absent, self.connections = [], {}, {}, {}, []
        self.byte_count, self.closed, self.close_errors, self.verified = 0, False, [], False
        self.connect_attempts, self.cursors, self.queries, self.bundles = [], [], [], []
        self.code_fds, self.returned_rows = [], []
        self.current_phase, self.failure = "auth_before_input_admission", None
        self.original_immutable_route_invoked = False
        self.empty_wal_route_used = False

    def public(self):
        original = super().public()
        # Closed projection: no profile ID, auth bytes, credential digest or
        # client-configuration digest can enter the public receipt.
        return {
            "schema": SCHEMA,
            "phase": self.current_phase,
            "allOwnedDescriptorsClosed": original["allOwnedDescriptorsClosed"],
            "allHeldDescriptorsClosed": original["allHeldDescriptorsClosed"],
            "allReturnedConnectionsClosed": original["allReturnedConnectionsClosed"],
            "allExplicitCursorsClosed": original["allExplicitCursorsClosed"],
            "allPublicCodeDescriptorsClosed": original["allPublicCodeDescriptorsClosed"],
            "closeErrors": list(self.close_errors),
            "connectionAttemptCount": len(self.connect_attempts),
            "returnedConnectionCount": len(self.connections),
            "cursorCount": len(self.cursors),
            "queryCount": len(self.queries),
            "allHeldNamesVerified": self.verified,
            "allBundlesVerified": bool(self.bundles) and all(item["verified"] for item in self.bundles),
            "originalImmutableRouteInvoked": False,
            "emptyWalHeldFdRouteInvoked": self.empty_wal_route_used,
            "sourceDatabaseCopied": False,
            "nonprimaryRowsRead": False,
            "unselectedProfileValuesReturned": False,
            "credentialValuesOrDigestsIncluded": False,
            "rawClientConfigHashIncluded": False,
            "registryWalRouteQualifiedByThisResult": False,
            "gatewayCredentialBindingProven": False,
            "providerCalled": False,
            "refreshDispatched": False,
            "crossAgentAtomicSnapshotClaimed": False,
            "wholeDatabaseBackupQualified": False,
        }


def auth_wal_database(inputs, agent):
    inputs.current_phase = "auth_wal_input_admission"
    path = inputs.live / "agents" / agent / "agent" / "openclaw-agent.sqlite"
    main = inputs.hold(path)
    need(int(main["expected"][6]) >= 512, "auth_main_header_bound")
    journal = inputs.hold(Path(str(path) + "-journal"), optional=True, maximum=0)
    need(journal is None, "auth_rollback_journal_refused")
    log = inputs.hold(Path(str(path) + "-wal"), optional=True, maximum=wal.WAL_MAXIMUM)
    shared = inputs.hold(Path(str(path) + "-shm"), optional=True, maximum=8 * base.MIB)
    nonempty_wal = log is not None and int(log["expected"][6]) > 0
    if nonempty_wal:
        need(int(log["expected"][6]) >= 32, "auth_wal_header_bound")
        need(shared is not None and int(shared["expected"][6]) > 0, "auth_existing_shm_required")
    if log is None:
        need(shared is None, "auth_orphan_shm_refused")
    need(all(row["expected"][3] == "20" for row in (main, log, shared) if row is not None),
         "auth_exact_group")
    inputs.verify()
    wanted = set(path.parents)
    parents = [{"row": row, "expected": wal._full_parent(row)}
               for key, row in inputs.parents.items() if Path(key) in wanted]
    need(len(parents) == len(wanted), "auth_complete_parent_chain")
    bundle = {"main": main, "wal": log, "shm": shared, "parents": parents,
              "journal": str(path) + "-journal", "verified": False, "checks": 0,
              "nonemptyWal": nonempty_wal}
    inputs.bundles.append(bundle)
    verify_auth_bundle(inputs, bundle, until=inputs.until)
    return bundle


def verify_auth_bundle(inputs, bundle, *, until):
    if bundle["wal"] is not None and bundle["shm"] is not None:
        return wal.verify_bundle(inputs, bundle, until=until)
    inputs.remaining(until)
    bundle["verified"] = False
    for item in bundle["parents"]:
        need(wal._full_parent(item["row"]) == item["expected"], "auth_wal_full_parent_changed")
    main = bundle["main"]
    for key, suffix in (("main", ""), ("wal", "-wal"), ("shm", "-shm")):
        row = bundle[key]
        if row is not None:
            named = os.stat(row["name"], dir_fd=row["parent"]["fd"], follow_symlinks=False)
            need(base.identity(named) == base.identity(os.fstat(row["fd"])) == row["expected"],
                 "auth_wal_full_leaf_changed")
        else:
            missing = inputs.absent[main["path"] + suffix]
            try:
                os.stat(missing["name"], dir_fd=missing["parent"]["fd"], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise base.CaptureRefused("auth_absent_sidecar_appeared")
    absent = inputs.absent[bundle["journal"]]
    try:
        os.stat(absent["name"], dir_fd=absent["parent"]["fd"], follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise base.CaptureRefused("auth_rollback_journal_appeared")
    inputs.remaining(until)
    bundle["verified"] = True
    bundle["checks"] += 1


def read_profile_projection(inputs, connection, requested, *, until, registered_present=False):
    db = connection["db"]
    columns = {"store_key", "store_json", "updated_at"}

    def authorize(action, arg1, arg2, database, trigger):
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if (action == sqlite3.SQLITE_READ and database == "main" and trigger is None
                and arg1 == "auth_profile_store" and arg2 in columns):
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_TRANSACTION and arg1 == "ROLLBACK":
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    db.set_authorizer(authorize)
    sql = ("SELECT store_key,store_json,updated_at FROM auth_profile_store"
           " WHERE store_key=? LIMIT 2")
    plan = inputs.execute(connection, "EXPLAIN QUERY PLAN " + sql, ("primary",),
                          until=until, limit=4, label="auth-primary-index-plan")
    need(len(plan) == 1 and len(plan[0]) == 4
         and all(type(value) is int for value in plan[0][:3])
         and isinstance(plan[0][3], str) and re.fullmatch(
             r"SEARCH auth_profile_store USING (?:COVERING )?INDEX [A-Za-z0-9_]+ \(store_key=\?\)",
             plan[0][3]) is not None, "auth_primary_index_search_required")
    rows = inputs.execute(connection, sql, ("primary",), until=until, limit=2,
                          label="auth-primary-selected-profiles")
    if registered_present and not rows:
        return {"profiles": {}, "storeUpdatedAt": None, "storeRowPresent": False,
                "localProfileCount": 0, "registeredMissingCount": len(requested),
                "unregisteredLocalProfileCount": 0, "scope": "registered_profile_projection_only"}
    need(len(rows) == 1 and len(rows[0]) == 3 and rows[0][0] == "primary"
         and isinstance(rows[0][1], str) and len(rows[0][1].encode("utf-8")) <= base.MAX_ROW_BYTES
         and type(rows[0][2]) is int and 0 <= rows[0][2] <= 9007199254740991,
         "one_bounded_auth_primary_document")
    parsed = strict_json(rows[0][1])
    need(isinstance(parsed, dict) and isinstance(parsed.get("profiles"), dict)
         and len(parsed["profiles"]) <= 128, "bounded_auth_profile_dictionary")
    if not registered_present:
        need(all(profile in parsed["profiles"] for profile in requested), "authorized_profile_missing")
    profiles = {profile: parsed["profiles"][profile] for profile in requested if profile in parsed["profiles"]}
    need(all(isinstance(value, dict) for value in profiles.values()), "credential_object_required")
    value = {"profiles": profiles, "storeUpdatedAt": rows[0][2], "storeRowPresent": True,
             "localProfileCount": len(parsed["profiles"]),
             "registeredMissingCount": len(requested) - len(profiles),
             "unregisteredLocalProfileCount": len(set(parsed["profiles"]) - set(requested)),
             "scope": "registered_profile_projection_only"}
    need(len(base.encoded(value)) <= base.MAX_ROW_BYTES, "projected_auth_byte_cap")
    return value


def readonly_auth_query(inputs, bundle, requested, *, after_read=None, registered_present=False):
    need(after_read is None or inputs.synthetic, "no_production_auth_query_hook")
    started = time.monotonic()
    until = min(inputs.until, started + base.MAX_QUERY_SECONDS)
    route = "auth_named_readonly_wal" if bundle["nonemptyWal"] else "auth_empty_wal_held_fd"
    row = {"route": route, "success": False,
           "rolledBack": False, "queryClosureKnown": False, "error": None}
    inputs.queries.append(row)
    connection = None
    value = None
    error = None
    try:
        inputs.current_phase = "auth_wal_preconnect_fence"
        verify_auth_bundle(inputs, bundle, until=until)
        if bundle["nonemptyWal"]:
            uri = wal.uri_for(bundle)
            expected_path = bundle["main"]["path"]
        else:
            need(bundle["wal"] is None or int(bundle["wal"]["expected"][6]) == 0,
                 "immutable_requires_strictly_absent_or_empty_wal")
            expected_path = "/dev/fd/" + str(bundle["main"]["fd"])
            uri = "file:" + expected_path + "?mode=ro&immutable=1"
            inputs.empty_wal_route_used = True
        connection = inputs.connect(uri, until=until, label=route)
        wal.configure_connection(inputs, connection, until=until)
        actual = inputs.execute(connection, "PRAGMA database_list", until=until, limit=1,
                                label="auth-database-list")
        need(len(actual) == 1 and actual[0][1] == "main"
             and actual[0][2] == expected_path, "auth_exact_admitted_database_open")
        inputs.execute(connection, "BEGIN", until=until, label="auth-begin")
        verify_auth_bundle(inputs, bundle, until=until)
        inputs.current_phase = "auth_wal_primary_read"
        value = read_profile_projection(inputs, connection, requested, until=until,
                                        registered_present=registered_present)
        if after_read is not None:
            after_read(until, connection)
        inputs.current_phase = "auth_wal_postread_fence"
        verify_auth_bundle(inputs, bundle, until=until)
        inputs.execute(connection, "ROLLBACK", until=until, label="auth-rollback")
        row["rolledBack"] = True
    except BaseException as caught:
        error = caught
    finally:
        if connection is not None:
            inputs.close_connection_once(connection)
        row["queryClosureKnown"] = ((connection is None or connection["closed"])
                                   and all(cursor["closed"] for cursor in inputs.cursors))
    try:
        need(row["queryClosureKnown"], "auth_query_close_unconfirmed")
        if error is None:
            verify_auth_bundle(inputs, bundle, until=until)
    except BaseException as caught:
        if error is None:
            error = caught
    completed = time.monotonic()
    if (inputs.cancelled() or completed >= until) and error is None:
        error = base.CaptureRefused("auth_original_query_deadline_after_closure")
    if error is not None:
        row["error"] = wal.failure_record(error)
        raise error
    row["success"] = True
    return value


def attempt_auth(inputs, *, agent, authorized_profiles, requested_profiles, after_read=None,
                 registered_present=False):
    value = None
    error = None
    try:
        need(type(registered_present) is bool, "typed_registered_projection_mode")
        requested = validate_profiles(agent, authorized_profiles, requested_profiles)
        need(after_read is None or inputs.synthetic, "no_production_auth_query_hook")
        bundle = auth_wal_database(inputs, agent)
        value = readonly_auth_query(inputs, bundle, requested, after_read=after_read,
                                    registered_present=registered_present)
        inputs.verify()
        verify_auth_bundle(inputs, bundle, until=inputs.until)
    except BaseException as caught:
        error = caught
    finally:
        inputs.close()
    public = inputs.public()
    complete = time.monotonic()
    known = (error is None and public["allOwnedDescriptorsClosed"] and not public["closeErrors"]
             and complete < inputs.until and not inputs.cancelled())
    public.update(ok=known, observationComplete=known, observationUnknown=not known,
                  error=wal.failure_record(error) if error else None,
                  originalDeadlineMetAfterClosure=complete < inputs.until,
                  capturedProfileCount=len(value["profiles"]) if known else 0,
                  privateResultPublished=False, scope="one_bounded_current_auth_observation",
                  selectionMode="registered_present" if registered_present else "explicit_requested",
                  storeRowPresent=value["storeRowPresent"] if known else None,
                  localProfileCount=value["localProfileCount"] if known else None,
                  registeredMissingCount=value["registeredMissingCount"] if known else None,
                  unregisteredLocalProfileCount=value["unregisteredLocalProfileCount"] if known else None)
    return value if known else None, public
