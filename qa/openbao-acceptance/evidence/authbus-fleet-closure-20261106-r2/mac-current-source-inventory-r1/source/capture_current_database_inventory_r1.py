#!/usr/bin/env python3
"""Private current database/sidecar/schema discovery under a read-only sandbox.

This entry is launched only by the separately source-bound parent. Discovery
does not authorize opening additional database paths. No credential data row,
provider, SDK import, service action or production write is performed.
"""
from __future__ import annotations

import base64
import contextlib
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time

ROOT = Path("/Users/qianqi/heptabao-authbus-production-source-inventory-20261106-r1")
QUAL = Path("/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2")
LIVE = Path("/Users/qianqi/.openclaw")
AGENTS = ("main", "trnm", "hepta-ui", "hepta", "hepta-backend")
CACHES = ("applied-profiles.json", "publish-baseline.json", "bad-refresh-quarantine.json",
          "refresh-backoff.json", "lease-epochs.json", "status.json")
LEGACY = ("auth-profiles.json", "auth-state.json", "auth.json")
START = time.monotonic()
UNTIL = float(sys.argv[1])
sys.path.insert(0, str(QUAL / "qa"))
sys.path.insert(0, str(ROOT / "code"))
import authbus_current_auth_wal as auth
import mac_current_database_inventory_r1 as inventory

codes, guards, held = set(), [], []
observed_metadata = {}
selector_holders = []
report = {"schema": "heptabao.current-database-source-inventory.public.r1", "ok": False,
          "credentialRowsRead": 0, "providerCalls": 0, "sdkImported": False,
          "productionWrites": 0, "serviceActions": 0, "productionCutover": False,
          "wholeDatabaseBackupOrRestoreQualified": False,
          "allProductionConsumersCovered": False, "activeProcessConsumersObserved": False,
          "sdkConfiguredPathResolutionExecuted": False, "databaseObservations": []}


def need(value, code):
    if not value:
        codes.add(code)
        raise RuntimeError(code)


def remaining():
    need(time.monotonic() < UNTIL, "inventory_original_absolute_deadline")


def private(name, value):
    need(name in ("inventory.private.json", "configuration.original.private.json"),
         "fixed_private_inventory_outputs")
    raw = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True) + "\n").encode()
    need(len(raw) <= 4 * 1048576, "bounded_complete_private_inventory")
    fd = os.open(ROOT / "output" / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    row = {"fd": fd, "closeAttempts": 0, "closed": False}
    held.append(row)
    try:
        view = memoryview(raw)
        while view:
            remaining()
            count = os.write(fd, view)
            need(count > 0, "private_inventory_write_progress")
            view = view[count:]
        os.fsync(fd)
    finally:
        row["closeAttempts"] += 1
        os.close(fd)
        row["closed"] = True
    fd = os.open(ROOT / "output", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    row = {"fd": fd, "closeAttempts": 0, "closed": False}
    held.append(row)
    try:
        os.fsync(fd)
    finally:
        row["closeAttempts"] += 1
        os.close(fd)
        row["closed"] = True


def namespace_record(guard):
    return {"sourceIdentities": {path: list(row["expected"]) for path, row in guard.files.items()},
            "sourceAbsences": list(guard.absent)}


def public_database_sizes(bundle):
    return {"mainFileBytes": int(bundle["main"]["expected"][6]),
            "walFileBytes": None if bundle["wal"] is None else int(bundle["wal"]["expected"][6]),
            "shmFileBytes": None if bundle["shm"] is None else int(bundle["shm"]["expected"][6]),
            "backupMemoryBudgetSelected": False}


def final_named_fence(records, parents):
    remaining()
    for record in records:
        for path, expected in record["sourceIdentities"].items():
            need(list(auth.base.identity(Path(path).lstat())) == expected,
                 "inventory_closed_source_name_unchanged")
        for path in record["sourceAbsences"]:
            try:
                Path(path).lstat()
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError("inventory_closed_absence_changed")
    for path, expected in parents.items():
        need(list(auth.base.identity(Path(path).lstat())) == expected,
             "inventory_closed_source_parent_unchanged")
    for path, expected in observed_metadata.items():
        try:
            actual = list(auth.base.identity(Path(path).lstat()))
        except FileNotFoundError:
            actual = None
        need(actual == expected, "inventory_discovered_metadata_unchanged")


def read_home_gateway_env():
    """One source-proven path outside LIVE; no general HOME file admission."""
    path = Path("/Users/qianqi/.config/openclaw/gateway.env")
    current, parent_fd = Path("/"), None
    for number, name in enumerate(("/", *path.parts[1:])):
        leaf = number == len(path.parts) - 1
        if number:
            current /= name
        try:
            named = os.lstat("/") if not number else os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            observed_metadata[str(current)] = None
            observed_metadata[str(path)] = None
            return None
        need((stat.S_ISREG(named.st_mode) if leaf else stat.S_ISDIR(named.st_mode))
             and named.st_uid in (0, 501) and not stat.S_IMODE(named.st_mode) & 0o022,
             "fixed_selector_parent_and_leaf_custody")
        if current.is_relative_to(Path("/Users/qianqi")):
            need(named.st_uid == 501, "fixed_selector_current_user_owner")
        flags = os.O_RDONLY | os.O_NOFOLLOW | (os.O_NONBLOCK if leaf else os.O_DIRECTORY)
        fd = os.open(name, flags, **({} if parent_fd is None else {"dir_fd": parent_fd}))
        row = {"fd": fd, "closeAttempts": 0, "closed": False}
        held.append(row)
        need(auth.base.identity(named) == auth.base.identity(os.fstat(fd)), "fixed_selector_named_held_identity")
        expected = list(auth.base.identity(named))
        observed_metadata[str(current)] = expected
        selector_holders.append({"fd": fd, "path": str(current), "expected": expected})
        if not leaf:
            parent_fd = fd
            continue
        need(named.st_nlink == 1 and named.st_gid == 20 and 0 <= named.st_size <= 262144,
             "bounded_fixed_gateway_environment_file")
        result = bytearray()
        while len(result) <= named.st_size:
            remaining()
            part = os.read(fd, min(65536, named.st_size + 1 - len(result)))
            if not part:
                break
            result.extend(part)
        need(len(result) == named.st_size and expected == list(auth.base.identity(os.fstat(fd)))
             == list(auth.base.identity(path.lstat())), "complete_fixed_selector_bytes_unchanged")
        return bytes(result)
    raise RuntimeError("fixed_selector_leaf_unreached")


def verify_selector_holders():
    remaining()
    for row in selector_holders:
        need(row["expected"] == list(auth.base.identity(os.fstat(row["fd"])))
             == list(auth.base.identity(Path(row["path"]).lstat())), "fixed_selector_full9_unchanged")


def close_remaining_held():
    for row in reversed(held):
        if row["closeAttempts"]:
            continue
        row["closeAttempts"] = 1
        try:
            os.close(row["fd"])
            row["closed"] = True
        except BaseException:
            report["additionalDescriptorCloseUnknown"] = True


def directory_members(guard, path):
    directory = guard.directory(path, optional=True)
    if directory is None:
        return None
    # Directory names are private. Dirent classification matches the installed
    # plugin's non-symlink directory discovery; no discovered file is opened.
    fd = directory["fd"]
    before = list(auth.base.identity(os.fstat(fd)))
    observed_metadata[str(path)] = before
    with os.scandir(fd) as iterator:
        rows = []
        for entry in iterator:
            remaining()
            need(len(rows) < 256 and inventory.plain_text(entry.name, 1024),
                 "bounded_private_directory_members")
            info = entry.stat(follow_symlinks=False)
            observed_metadata[str(path / entry.name)] = list(auth.base.identity(info))
            rows.append({"name": entry.name, "directory": stat.S_ISDIR(info.st_mode),
                         "regular": stat.S_ISREG(info.st_mode), "symlink": stat.S_ISLNK(info.st_mode),
                         "full9": list(auth.base.identity(info))})
    need(before == list(auth.base.identity(os.fstat(fd)))
         == list(auth.base.identity(path.lstat())), "inventory_directory_members_stable")
    return rows


def bounded_proof_read():
    path = ROOT / "code/registry-proof.public.json"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    row = {"fd": fd, "closeAttempts": 0, "closed": False}
    held.append(row)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == 501
             and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size == 62662,
             "exact_owned_public_registry_proof_file")
        parts, count = [], 0
        while count <= before.st_size:
            remaining()
            part = os.read(fd, min(65536, before.st_size + 1 - count))
            if not part:
                break
            count += len(part)
            parts.append(part)
        need(count == before.st_size and auth.base.identity(before)
             == auth.base.identity(os.fstat(fd)) == auth.base.identity(path.lstat()),
             "complete_stable_original_registry_proof")
        return b"".join(parts)
    finally:
        row["closeAttempts"] += 1
        os.close(fd)
        row["closed"] = True


try:
    os.umask(0o077)
    need(sys.platform == "darwin" and os.getuid() == 501
         and START < UNTIL <= START + 45, "actual_inventory_mac_original_budget")
    for name, flags in (("protected-read", os.O_RDONLY), ("protected-write", os.O_WRONLY)):
        try:
            fd = os.open(ROOT / name, flags | os.O_NOFOLLOW)
        except OSError as error:
            need(error.errno in (errno.EACCES, errno.EPERM), "inventory_kernel_file_refusal")
        else:
            os.close(fd)
            raise RuntimeError("inventory_kernel_file_allowed")
    probe = socket.socket()
    try:
        probe.settimeout(min(1, UNTIL - time.monotonic()))
        try:
            probe.connect(("127.0.0.1", 9))
        except OSError as error:
            need(error.errno in (errno.EACCES, errno.EPERM), "inventory_kernel_network_refusal")
        else:
            raise RuntimeError("inventory_kernel_network_allowed")
    finally:
        probe.close()
    report["kernelReadWriteAndNetworkRefusalsObserved"] = True
    guard = auth.AuthInputs(until=UNTIL, critical=contextlib.nullcontext, cancelled=lambda: False)
    guards.append(guard)
    raw_config = guard.read(LIVE / "openclaw.json")
    config = auth.strict_json(raw_config)
    need(isinstance(config, dict), "current_inventory_configuration_object")
    live_dotenv = guard.read(LIVE / ".env", optional=True, maximum=262144, private=False)
    home_gateway_env = read_home_gateway_env()
    configured = config.get("agents", {}).get("list", [])
    need(isinstance(configured, list) and len(configured) <= 256,
         "bounded_current_configured_agent_entries")
    configured_private = []
    for item in configured:
        need(isinstance(item, dict) and inventory.plain_text(item.get("id"), 256),
             "typed_current_configured_agent_entry")
        value = item.get("agentDir")
        need(value is None or inventory.plain_text(value, 4096), "typed_private_configured_agent_path")
        configured_private.append({"agentId": item["id"], "configuredAgentDir": value,
                                   "actualSdkResolutionPending": True})
    agent_members = directory_members(guard, LIVE / "agents")
    cache_members = directory_members(guard, LIVE / "authbus")
    namespace_metadata = []
    known_bases = [LIVE / "agents" / agent / "agent/openclaw-agent.sqlite" for agent in AGENTS]
    known_bases.append(LIVE / "state/openclaw.sqlite")
    for ordinal, path in enumerate(known_bases):
        parent = guard.directory(path.parent)
        files = {}
        sizes = {}
        for suffix in ("", "-wal", "-shm", "-journal"):
            leaf = Path(str(path) + suffix)
            try:
                info = os.stat(leaf.name, dir_fd=parent["fd"], follow_symlinks=False)
            except FileNotFoundError:
                value = None
            else:
                need(stat.S_ISREG(info.st_mode), "known_database_metadata_regular_no_symlink")
                value = list(auth.base.identity(info))
            observed_metadata[str(leaf)] = value
            files[suffix] = value
            sizes["main" if not suffix else suffix[1:]] = None if value is None else int(value[6])
        namespace_metadata.append({"ordinal": ordinal + 1, "path": str(path), "files": files})
        report.setdefault("initialNamespaceByteSizes", []).append({"ordinal": ordinal + 1, "files": sizes})
    plugin_database_metadata = []
    for member in agent_members or []:
        if not member["directory"]:
            continue
        directory = LIVE / "agents" / member["name"] / "agent"
        # Additional discovered agents grant metadata observation only. The
        # sandbox is not widened to open their directories or database data.
        try:
            directory_info = directory.lstat()
        except FileNotFoundError:
            observed_metadata[str(directory)] = None
            continue
        directory_identity = list(auth.base.identity(directory_info))
        observed_metadata[str(directory)] = directory_identity
        if not stat.S_ISDIR(directory_info.st_mode):
            plugin_database_metadata.append({"path": str(directory), "full9": directory_identity,
                "regular": False, "symlink": stat.S_ISLNK(directory_info.st_mode),
                "kind": "unopened_non_directory_agent_entry", "contentsOpened": False})
            continue
        path = directory / "openclaw-agent.sqlite"
        try:
            info = path.lstat()
        except FileNotFoundError:
            observed_metadata[str(path)] = None
            continue
        need(directory_identity == list(auth.base.identity(directory.lstat())),
             "unopened_discovered_agent_directory_generation_unchanged")
        observed_metadata[str(path)] = list(auth.base.identity(info))
        plugin_database_metadata.append({"path": str(path), "full9": observed_metadata[str(path)],
                                         "regular": stat.S_ISREG(info.st_mode),
                                         "symlink": stat.S_ISLNK(info.st_mode),
                                         "kind": "unopened_database_metadata", "contentsOpened": False})
    known_metadata = []
    for agent in AGENTS:
        directory = LIVE / "agents" / agent / "agent"
        items = []
        for name in LEGACY:
            row = guard.hold(directory / name, optional=True)
            items.append({"name": name, "present": row is not None,
                          "full9": list(row["expected"]) if row else None,
                          "contentsRead": False})
        known_metadata.append({"agentId": agent, "legacyFiles": items})
    cache_metadata = []
    if cache_members is not None:
        for name in CACHES:
            row = guard.hold(LIVE / "authbus" / name, optional=True)
            cache_metadata.append({"name": name, "present": row is not None,
                                   "full9": list(row["expected"]) if row else None,
                                   "contentsRead": False})
    databases = []
    for ordinal, agent in enumerate(AGENTS):
        remaining()
        current = auth.AuthInputs(until=UNTIL, critical=contextlib.nullcontext, cancelled=lambda: False)
        guards.append(current)
        bundle = auth.auth_wal_database(current, agent)
        result = inventory.qualified_inventory_query(auth, current, bundle, registry=False)
        current.verify()
        databases.append({"slot": ordinal, "agentId": agent, "inventory": result,
                          "generation": namespace_record(current)})
        report["databaseObservations"].append({"ordinal": ordinal + 1,
                                               **public_database_sizes(bundle),
                                               **inventory.public_inventory_counts(result)})
    registry = auth.wal.WalInputs(until=UNTIL, critical=contextlib.nullcontext, cancelled=lambda: False)
    guards.append(registry)
    runtime = auth.wal.observed_runtime(registry)
    proof_raw = bounded_proof_read()
    auth.wal.validate_wal_proof(registry, proof_raw,
        "7d08a18c21a5d754ea9fbe7711e6315daf8fbd80c7b5a6937756fea7ba4d1c82", runtime)
    bundle = auth.wal.registry_wal_database(registry)
    result = inventory.qualified_inventory_query(auth, registry, bundle, registry=True)
    registry.verify()
    databases.append({"slot": 5, "kind": "shared-state", "inventory": result,
                      "generation": namespace_record(registry)})
    report["databaseObservations"].append({"ordinal": 6, **public_database_sizes(bundle),
                                           **inventory.public_inventory_counts(result)})
    known = {str(LIVE / "agents" / agent / "agent" / "openclaw-agent.sqlite") for agent in AGENTS}
    registered = result["registeredAgentDatabases"]
    unexpected = [item for item in registered if item["path"] not in known]
    packet = {"schema": "heptabao.current-production-source-inventory.private.r1",
              "configurationGeneration": namespace_record(guard),
              "configurationSha256": hashlib.sha256(raw_config).hexdigest(),
              "sourceSelectorFiles": {
                  str(LIVE / ".env"): {"present": live_dotenv is not None,
                    "base64": None if live_dotenv is None else base64.b64encode(live_dotenv).decode()},
                  "/Users/qianqi/.config/openclaw/gateway.env": {"present": home_gateway_env is not None,
                    "base64": None if home_gateway_env is None else base64.b64encode(home_gateway_env).decode()}},
              "initialDatabaseNamespaceMetadata": namespace_metadata,
              "discoveredMetadataIdentitiesAndAbsences": observed_metadata,
              "configuredAgentEntries": configured_private, "agentDirectoryMembers": agent_members,
              "pluginFilesystemDatabaseMetadata": plugin_database_metadata,
              "authbusDirectoryMembers": cache_members, "knownLegacyMetadata": known_metadata,
              "knownCacheMetadata": cache_metadata, "databases": databases,
              "unopenedAdditionalRegisteredPaths": unexpected,
              "scope": "metadata_and_registry_paths_not_active_consumer_or_full_state_backup"}
    records, parents = [], {}
    for current in guards:
        current.verify()
        for held_bundle in current.bundles:
            (auth.verify_auth_bundle if isinstance(current, auth.AuthInputs)
             else auth.wal.verify_bundle)(current, held_bundle, until=UNTIL)
        records.append(namespace_record(current))
        for path, row in current.parents.items():
            value = list(auth.wal._full_parent(row))
            need(path not in observed_metadata or observed_metadata[path] == value,
                 "inventory_observed_directory_generation_unchanged")
            need(path not in parents or parents[path] == value, "inventory_all_parent_generations_agree")
            parents[path] = value
    packet["closedSourceGenerations"] = records
    packet["closedParentGenerations"] = parents
    private("configuration.original.private.json", raw_config)
    private("inventory.private.json", packet)
    verify_selector_holders()
    for current in guards:
        current.verify()
        current.close()
        need(current.public()["allOwnedDescriptorsClosed"], "inventory_original_resources_closed")
    close_remaining_held()
    final_named_fence(records, parents)
    report.update(ok=True, completePrivateObservationPublished=True,
                  allSixDatabaseNamespacesBeforeAfterExact=True,
                  closeThenNamedGenerationVerified=True, configuredAgentEntryCount=len(configured_private),
                  additionalRegisteredDatabasePaths=len(unexpected),
                  selectorFilePresence={"liveDotenv": live_dotenv is not None,
                                        "homeGatewayEnv": home_gateway_env is not None},
                  pluginFilesystemDatabasePathCount=sum(item["kind"] == "unopened_database_metadata"
                                                       for item in plugin_database_metadata),
                  additionalPluginFilesystemDatabasePaths=sum(item["kind"] == "unopened_database_metadata"
                      and item["path"] not in known for item in plugin_database_metadata),
                  nonDirectoryAgentEntryCount=sum(item["kind"] == "unopened_non_directory_agent_entry"
                                                  for item in plugin_database_metadata),
                  discoveredAdditionalDatabaseContentsOpened=False)
except BaseException as error:
    report["error"] = ({"code": str(error)} if isinstance(error, inventory.InventoryRefused)
                       or isinstance(error, RuntimeError) and str(error) in codes
                       else auth.wal.failure_record(error))
finally:
    close_remaining_held()
    resources = []
    for current in guards:
        current.close()
        value = current.public()
        resources.append({key: value[key] for key in (
            "allOwnedDescriptorsClosed", "allHeldDescriptorsClosed", "allReturnedConnectionsClosed",
            "allExplicitCursorsClosed", "allPublicCodeDescriptorsClosed", "closeErrors",
            "connectionAttemptCount", "returnedConnectionCount", "cursorCount", "queryCount")})
    report["resources"] = resources
    report["outputDescriptors"] = [{key: row[key] for key in ("closeAttempts", "closed")} for row in held]
    report["allOwnedResourcesClosed"] = (all(item["allOwnedDescriptorsClosed"] for item in resources)
        and all(row["closed"] and row["closeAttempts"] == 1 for row in held))
    report["elapsedSeconds"] = time.monotonic() - START
    if not report["allOwnedResourcesClosed"] or time.monotonic() >= UNTIL:
        report["ok"] = False
    print(json.dumps(report, sort_keys=True, separators=(",", ":")), flush=True)
raise SystemExit(0 if report["ok"] else 1)
