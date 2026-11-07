#!/usr/bin/env python3
"""Bounded, private SQLite namespace inventory; no import-time I/O.

This is a new read-only query surface, not the old selected-profile projection.
The launcher must pin this file, the unmodified qualified auth/WAL libraries,
their actual-runtime proofs, and the source files. It must apply the existing
kernel deny-write/no-network policy before opening a production database.

Only sqlite_schema metadata and three agent_databases columns are returned.
All returned paths, identifiers, schema text and database pragmas are private.
No auth row, arbitrary application row, credential digest, backup, SDK import,
provider request, service action or production mutation is performed here.
"""
from __future__ import annotations

import re
import sqlite3
import time

SCHEMA = "heptabao.current-database-inventory.private.r1"
MAX_SCHEMA_OBJECTS = 1024
MAX_REGISTERED_DATABASES = 256
MAX_SCHEMA_SQL_BYTES = 65536
MAX_PRIVATE_PATH_BYTES = 4096
SCHEMA_COLUMNS = frozenset(("type", "name", "tbl_name", "rootpage", "sql"))
REGISTRY_COLUMNS = frozenset(("agent_id", "path", "schema_version"))
READ_PRAGMAS = (
    "schema_version", "user_version", "application_id", "page_count",
    "page_size", "freelist_count", "encoding", "auto_vacuum", "journal_mode",
)
AGENT_DATABASE_INFO = [
    (0, "agent_id", "TEXT", 1, None, 1),
    (1, "path", "TEXT", 1, None, 2),
    (2, "schema_version", "INTEGER", 1, None, 0),
    (3, "last_seen_at", "INTEGER", 1, None, 0),
    (4, "size_bytes", "INTEGER", 0, None, 0),
]
AGENT_DATABASE_SQL = """CREATE TABLE agent_databases (
  agent_id TEXT NOT NULL,
  path TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  size_bytes INTEGER,
  PRIMARY KEY (agent_id, path)
)"""


class InventoryRefused(RuntimeError):
    """Only fixed, non-sensitive codes may be passed to this exception."""


def need(value, code):
    if not value:
        raise InventoryRefused(code)


def plain_text(value, maximum):
    return (isinstance(value, str) and 0 < len(value.encode("utf-8")) <= maximum
            and all(ord(char) >= 32 and ord(char) != 127 for char in value))


def schema_authorizer(registry):
    """Deny arbitrary table reads, writes, attachments, SQL functions and views."""
    need(type(registry) is bool, "typed_registry_inventory_scope")

    def authorize(action, arg1, arg2, database, trigger):
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ and database == "main" and trigger is None:
            if arg1 == "sqlite_master" and arg2 in SCHEMA_COLUMNS:
                return sqlite3.SQLITE_OK
            if registry and arg1 == "agent_databases" and arg2 in REGISTRY_COLUMNS:
                return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_PRAGMA:
            if arg1 in READ_PRAGMAS and arg2 is None:
                return sqlite3.SQLITE_OK
            if registry and arg1 == "table_info" and arg2 == "agent_databases":
                return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_TRANSACTION and arg1 == "ROLLBACK":
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    return authorize


def read_private_inventory(inputs, connection, *, until, registry):
    """Run only the fixed metadata/mapping statements through qualified execute()."""
    need(type(registry) is bool, "typed_registry_inventory_scope")
    connection["db"].set_authorizer(schema_authorizer(registry))
    rows = inputs.execute(
        connection,
        "SELECT type,name,tbl_name,rootpage,sql FROM sqlite_schema "
        "ORDER BY type,name LIMIT ?",
        (MAX_SCHEMA_OBJECTS + 1,), until=until,
        limit=MAX_SCHEMA_OBJECTS + 1, label="inventory-schema-objects",
    )
    need(0 < len(rows) <= MAX_SCHEMA_OBJECTS, "bounded_schema_object_count")
    objects, seen = [], set()
    for row in rows:
        need(len(row) == 5 and row[0] in ("table", "index", "view", "trigger")
             and plain_text(row[1], 1024) and plain_text(row[2], 1024)
             and type(row[3]) is int and row[3] >= 0
             and (row[4] is None or isinstance(row[4], str)
                  and len(row[4].encode("utf-8")) <= MAX_SCHEMA_SQL_BYTES),
             "bounded_schema_object_shape")
        key = (row[0], row[1])
        need(key not in seen, "unique_schema_object_identity")
        seen.add(key)
        objects.append(dict(zip(("type", "name", "table", "rootPage", "sql"), row)))
    pragmas = {}
    for name in READ_PRAGMAS:
        found = inputs.execute(connection, "PRAGMA " + name, until=until,
                               limit=1, label="inventory-pragma-" + name)
        need(len(found) == 1 and len(found[0]) == 1
             and type(found[0][0]) in (int, str), "one_scalar_inventory_pragma")
        pragmas[name] = found[0][0]

    mappings = []
    if registry:
        actual = [item for item in objects if item["type"] == "table"
                  and item["name"] == "agent_databases"]
        normalize = lambda value: re.sub(r"\s+", " ", value).strip()
        need(len(actual) == 1 and isinstance(actual[0]["sql"], str)
             and normalize(actual[0]["sql"]) == normalize(AGENT_DATABASE_SQL),
             "actual_registered_database_table_matches_installed_schema")
        info = inputs.execute(connection, "PRAGMA table_info(agent_databases)",
                              until=until, limit=5, label="inventory-registry-columns")
        need(info == AGENT_DATABASE_INFO, "exact_registered_database_columns")
        found = inputs.execute(
            connection,
            "SELECT agent_id,path,schema_version FROM agent_databases "
            "ORDER BY agent_id,path LIMIT ?",
            (MAX_REGISTERED_DATABASES + 1,), until=until,
            limit=MAX_REGISTERED_DATABASES + 1, label="inventory-registered-databases",
        )
        need(len(found) <= MAX_REGISTERED_DATABASES, "bounded_registered_database_count")
        seen = set()
        for row in found:
            need(len(row) == 3 and plain_text(row[0], 256)
                 and plain_text(row[1], MAX_PRIVATE_PATH_BYTES)
                 and row[1].startswith("/")
                 and type(row[2]) is int and 0 <= row[2] <= 2147483647,
                 "typed_private_registered_database_mapping")
            key = (row[0], row[1])
            need(key not in seen, "unique_registered_database_mapping")
            seen.add(key)
            # This is private discovery only. The mapping never authorizes
            # opening a new path or expanding a kernel sandbox.
            mappings.append({"agentId": row[0], "path": row[1], "schemaVersion": row[2]})
    return {"schema": SCHEMA, "sqliteObjects": objects, "pragmas": pragmas,
            "registeredAgentDatabases": mappings,
            "registeredPathsOpenedByThisQuery": False,
            "credentialRowsRead": 0, "arbitraryApplicationRowsRead": 0}


def qualified_inventory_query(auth, inputs, bundle, *, registry):
    """Use the old connection/namespace/close mechanics with this new authorizer.

    The three-second SQL budget and caller's original absolute deadline are
    retained. A named WAL route is used whenever a nonempty WAL exists. Only
    the already-qualified absent/empty auth-WAL route may use its held FD.
    Registry never falls back to immutable mode.
    """
    wal, base = auth.wal, auth.base
    need(type(registry) is bool, "typed_registry_inventory_scope")
    started = time.monotonic()
    until = min(inputs.until, started + base.MAX_QUERY_SECONDS)
    verify = wal.verify_bundle if registry else auth.verify_auth_bundle
    named = registry or bundle["nonemptyWal"]
    row = {"route": "inventory_named_readonly_wal" if named else "inventory_auth_held_fd",
           "success": False, "rolledBack": False, "queryClosureKnown": False,
           "startedMonotonic": started, "deadlineMonotonic": until,
           "registryMappingsRequested": registry, "error": None}
    inputs.queries.append(row)
    connection, value, error = None, None, None
    try:
        verify(inputs, bundle, until=until)
        if named:
            expected_path, uri = bundle["main"]["path"], wal.uri_for(bundle)
        else:
            need(bundle["wal"] is None or int(bundle["wal"]["expected"][6]) == 0,
                 "inventory_immutable_requires_absent_or_empty_wal")
            expected_path = "/dev/fd/" + str(bundle["main"]["fd"])
            uri = "file:" + expected_path + "?mode=ro&immutable=1"
        connection = inputs.connect(uri, until=until, label=row["route"])
        wal.configure_connection(inputs, connection, until=until)
        actual = inputs.execute(connection, "PRAGMA database_list", until=until,
                                limit=1, label="inventory-database-list")
        need(len(actual) == 1 and actual[0][1:] == ("main", expected_path),
             "inventory_exact_admitted_database_open")
        inputs.execute(connection, "BEGIN", until=until, label="inventory-begin")
        verify(inputs, bundle, until=until)
        value = read_private_inventory(inputs, connection, until=until, registry=registry)
        verify(inputs, bundle, until=until)
        inputs.execute(connection, "ROLLBACK", until=until, label="inventory-rollback")
        row["rolledBack"] = True
    except BaseException as caught:
        error = caught
    finally:
        if connection is not None:
            inputs.close_connection_once(connection)
        row["queryClosureKnown"] = ((connection is None or connection["closed"])
                                   and all(item["closed"] for item in inputs.cursors))
    try:
        need(row["queryClosureKnown"], "inventory_query_close_unconfirmed")
        if error is None:
            verify(inputs, bundle, until=until)
        need(not inputs.cancelled() and time.monotonic() < until,
             "inventory_original_query_deadline_after_closure")
    except BaseException as caught:
        if error is None:
            error = caught
    if error is not None:
        row["error"] = {"code": str(error)} if isinstance(error, InventoryRefused) else wal.failure_record(error)
        raise error
    row["success"] = True
    return value


def public_inventory_counts(private):
    """Closed public projection; no identifier, path, schema text or content hash."""
    need(isinstance(private, dict) and private.get("schema") == SCHEMA,
         "private_inventory_schema")
    counts = {key: 0 for key in ("table", "index", "view", "trigger")}
    for item in private["sqliteObjects"]:
        need(item["type"] in counts, "closed_schema_object_category")
        counts[item["type"]] += 1
    pages = private["pragmas"]["page_count"]
    page_size = private["pragmas"]["page_size"]
    need(type(pages) is int and 0 <= pages <= 0x7fffffff
         and type(page_size) is int and page_size in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536),
         "bounded_observed_database_capacity")
    return {"sqliteObjectCounts": counts,
            "databasePageCount": pages, "databasePageSize": page_size,
            "logicalDatabaseBytes": pages * page_size,
            "registeredAgentDatabaseMappingCount": len(private["registeredAgentDatabases"]),
            "credentialRowsRead": 0, "arbitraryApplicationRowsRead": 0,
            "discoveredDatabaseContentsOpened": False,
            "allProductionConsumersCovered": False,
            "wholeDatabaseBackupOrRestoreQualified": False}
