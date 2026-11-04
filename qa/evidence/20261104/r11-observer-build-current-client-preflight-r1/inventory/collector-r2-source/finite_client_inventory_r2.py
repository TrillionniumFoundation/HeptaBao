#!/usr/bin/env python3
"""Finite read-only client/registration inventory. Source candidate; no runtime admission.

Only the fixed manifest is accepted. Every explicit lstat/fstat is charged to its
predeclared pass; all passes share ONE original 45 second deadline and 8 MiB
read ceiling. No SQLite, SDK, provider, J3160, shell, source(), directory scan,
service transition, archive, recovery key, or host output file is opened.
"""
import argparse
import errno
import hashlib
import json
import os
import plistlib
import re
import select
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

START = time.monotonic()
UNTIL = START + 45.0
MANIFEST_SHA = "3c3900c814ebf3e9a1cd0d58226dd6a99fe0edb0aeb42510c3dd7fe5b528af93"
MAX_DOC = 2 * 1024 * 1024
MAX_READ = 8 * 1024 * 1024
MAX_OUTPUT = 64 * 1024
MAX_OBSERVATIONS = 32
SCHEMA = "heptabao.finite-client-inventory.result.r2"
protected = 0
pending_signal = None
children = []
fd_records = []
byte_reads = 0
read_calls = 0


class Refused(RuntimeError):
    pass


class Cancelled(BaseException):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def interrupt(signum, _frame):
    global pending_signal
    pending_signal = signum
    if protected == 0:
        raise Cancelled()


for sig in (signal.SIGTERM, signal.SIGINT):
    signal.signal(sig, interrupt)


def remaining(deadline=UNTIL):
    if pending_signal is not None:
        raise Cancelled()
    value = deadline - time.monotonic()
    need(value > 0, "original_host_deadline_exhausted")
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, "duplicate_json_key")
        value[key] = item
    return value


def parse(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)


def identity(st):
    return [st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def fixed_path(value):
    need(type(value) is str and value.startswith("/") and len(value) <= 4096
         and "\0" not in value and "\n" not in value and "\r" not in value,
         "invalid_absolute_path")
    parts = value.split("/")
    need(value == "/" or (not value.endswith("/") and all(x not in ("", ".", "..") for x in parts[1:])),
         "noncanonical_path_spelling")
    return value


def parent_path(path):
    return path.rsplit("/", 1)[0] or "/"


def ancestor_paths(path):
    parts = path.split("/")[1:-1]
    return ["/"] + ["/" + "/".join(parts[:i + 1]) for i in range(len(parts))]


def safe_string(value, pattern, maximum=256):
    if type(value) is str and len(value) <= maximum and re.fullmatch(pattern, value):
        return value
    return {"unresolved": True, "type": type(value).__name__,
            "sha256": sha(encoded(value))}


def path_projection(value):
    if type(value) is not str:
        return {"unresolved": True, "type": type(value).__name__}
    try:
        need(re.fullmatch(r"/[A-Za-z0-9_./@+:\-]*", value) is not None,
             "public_path_requires_simple_literal")
        return {"path": fixed_path(value)}
    except Refused:
        return {"unresolved": True, "sha256": sha(value.encode()), "bytes": len(value.encode())}


def endpoint(value):
    if type(value) is not str:
        return {"configured": value is not None, "unresolved": True}
    result = {"configured": True, "complete_value_sha256": sha(value.encode()),
              "path_query_fragment_omitted": True, "userinfo_omitted": True}
    try:
        u = urlsplit(value)
        need(u.scheme in ("http", "https") and u.hostname is not None, "endpoint_shape")
        result.update(scheme=u.scheme,
                      host=safe_string(u.hostname, r"[A-Za-z0-9_.:\-]+", 253),
                      port=u.port, references_j3160=u.hostname == "100.66.117.33")
    except (ValueError, Refused):
        result["unresolved"] = True
    return result


def command_projection(value):
    need(type(value) is str and len(value.encode()) <= MAX_DOC, "command_string_bound")
    row = {"raw_sha256": sha(value.encode()), "executed": False}
    try:
        args = shlex.split(value, posix=True)
        need(len(args) <= 128, "command_argument_bound")
    except (ValueError, Refused):
        row["unresolved"] = True
        return row
    row["argument_count"] = len(args)
    row["arguments_sha256"] = sha(encoded(args))
    row["executable"] = path_projection(args[0].lstrip("-+!:@")) if args else None
    row["inline_code_present"] = any(x in args for x in ("-c", "-e", "-lc", "--eval", "--print"))
    # Only argv[0] has an established executable/path meaning. Even an argument
    # beginning with '/' can be a token or inline code; do not publish it.
    row["non_executable_argument_count"] = max(0, len(args) - 1)
    row["non_executable_arguments_sha256"] = sha(encoded(args[1:]))
    row["argument_dependencies_resolved"] = False
    return row


def environment_projection(raw):
    text = raw.decode("utf-8")
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        value = line.strip()
        if value.startswith("export "):
            value = value[7:].lstrip()
        if not value or value.startswith("#"):
            continue
        match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$", value)
        if match:
            key, assigned = match.groups()
            row = {"line": number, "key": key, "assignment_sha256": sha(assigned.encode())}
            if key.lower() in ("http_proxy", "https_proxy", "all_proxy"):
                # Static literal only. No interpolation, shell evaluation or request.
                try:
                    words = shlex.split(assigned, posix=True)
                except ValueError:
                    words = []
                row["proxy"] = endpoint(words[0]) if len(words) == 1 and "$" not in words[0] else {"unresolved": True}
            rows.append(row)
    need(len(rows) <= 64, "environment_key_bound")
    return {"assignments": rows, "source_or_exec_called": False, "raw_values_published": False}


def cron_projection(raw):
    rows = []
    for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if re.search(r"openbao|heptabao|authbus|openclaw", value, re.I):
            rows.append({"line": number, "sha256": sha(value.encode()),
                         "literal_match_only": True})
    need(len(rows) <= 32, "selected_cron_line_bound")
    return {"selected_application_lines": rows, "unmatched_lines_not_published": True,
            "manual_or_unregistered_paths_excluded_by_absence": False}


def plist_projection(raw):
    value = plistlib.loads(raw)
    need(type(value) is dict, "launchd_dictionary_required")
    out = {}
    if "Label" in value:
        out["label"] = safe_string(value["Label"], r"[A-Za-z0-9_.\-]+")
    for key in ("Program", "WorkingDirectory", "StandardOutPath", "StandardErrorPath"):
        if key in value:
            out[key] = path_projection(value[key])
    args = value.get("ProgramArguments")
    if args is not None:
        need(type(args) is list and len(args) <= 128
             and all(type(x) is str for x in args), "launchd_arguments_shape")
        out["ProgramArguments"] = {
            "count": len(args), "sha256": sha(encoded(args)),
            "executable": path_projection(args[0]) if args else None,
            "non_executable_argument_count": max(0, len(args) - 1),
            "non_executable_arguments_sha256": sha(encoded(args[1:])),
            "argument_dependencies_resolved": False,
            "inline_code_present": any(x in args for x in ("-c", "-e", "-lc", "--eval", "--print")),
        }
    env = value.get("EnvironmentVariables", {})
    need(type(env) is dict and len(env) <= 64, "launchd_environment_shape")
    out["environment_keys"] = [safe_string(x, r"[A-Za-z_][A-Za-z0-9_]*", 128) for x in sorted(env)]
    out["proxy_fields"] = {k: endpoint(v) for k, v in env.items()
                           if k.lower() in ("http_proxy", "https_proxy", "all_proxy")}
    for key in ("RunAtLoad", "KeepAlive", "StartInterval", "StartCalendarInterval", "WatchPaths", "QueueDirectories"):
        if key in value:
            v = value[key]
            out[key] = v if type(v) in (bool, int) else {"present": True, "sha256": sha(encoded(v))}
    return out


def unit_projection(raw):
    section = None
    out = {"commands": [], "path_references": [], "conditions": [], "environment_keys": [],
           "continuation_line_present": False, "executed": False}
    count = 0
    for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("#", ";")):
            continue
        if s.startswith("[") and s.endswith("]"):
            name = s[1:-1]
            section = name if name in ("Unit", "Service", "Install") else {
                "unresolved": True, "sha256": sha(name.encode())}
            continue
        if s.endswith("\\"):
            out["continuation_line_present"] = True
        if "=" not in s:
            continue
        key, value = s.split("=", 1)
        key = key.strip()
        if key in ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost"):
            out["commands"].append({"line": number, "section": section, "key": key,
                                    **command_projection(value)})
            count += 1
        elif key in ("WorkingDirectory", "EnvironmentFile"):
            v = value.lstrip("-") if key == "EnvironmentFile" else value
            out["path_references"].append({"line": number, "key": key, **path_projection(v)})
            count += 1
        elif key == "ConditionPathExists":
            out["conditions"].append({"line": number, "key": key, "negated": value.startswith("!"),
                                      **path_projection(value[1:] if value.startswith("!") else value)})
            count += 1
        elif key == "Environment":
            try:
                values = shlex.split(value)
            except ValueError:
                values = []
            out["environment_keys"].extend(safe_string(v.split("=", 1)[0], r"[A-Za-z_][A-Za-z0-9_]*", 128)
                                           for v in values if "=" in v)
            need(len(out["environment_keys"]) <= 64, "systemd_environment_bound")
        elif key in ("TimeoutStopSec", "KillMode", "KillSignal", "Restart", "Type"):
            out[key] = safe_string(value, r"[A-Za-z0-9_. +\-]+", 128)
    need(count <= 64, "systemd_projection_bound")
    return out


def openclaw_projection(raw, host):
    cfg = parse(raw)
    need(type(cfg) is dict, "config_dictionary")
    entry = cfg.get("plugins", {}).get("entries", {}).get("openclaw-authbus", {})
    need(type(entry) is dict and type(entry.get("config", {})) is dict, "authbus_config_shape")
    c = entry.get("config", {})
    out = {"enabled": entry.get("enabled"), "address": endpoint(c.get("address")),
           "connection_paths": {}, "flags": {}, "agents": [], "effective_sdk_resolution_executed": False}
    need(out["enabled"] is None or type(out["enabled"]) is bool, "authbus_enabled_boolean")
    for key in ("caFile", "roleIdFile", "secretIdFile"):
        out["connection_paths"][key] = {"present": key in c, **path_projection(c.get(key))}
    if "hostId" in c:
        out["host_id"] = safe_string(c["hostId"], r"[A-Za-z0-9_.\-]+", 128)
    for key in ("leader", "publishNew", "manageOrder", "enforceRefreshLeases", "releaseGeneration",
                "pollIntervalMs", "refreshMarginMs", "maxRefreshesPerCycle", "schedulerReportIntervalMs"):
        v = c.get(key)
        out["flags"][key] = {"present": key in c,
                             "value": v if v is None or type(v) in (bool, int) else {"unresolved": True, "sha256": sha(encoded(v))}}
    if "schedulerMode" in c:
        out["flags"]["schedulerMode"] = safe_string(c["schedulerMode"], r"[a-zA-Z_\-]+", 64)
    excluded = c.get("orderExcludeAgentIds")
    need(excluded is None or (type(excluded) is list and len(excluded) <= 32), "excluded_agents_bound")
    out["order_excluded_agents"] = None if excluded is None else [safe_string(x, r"[A-Za-z0-9_.\-]+", 128) for x in excluded]
    agents = cfg.get("agents", {}).get("list", [])
    need(type(agents) is list and len(agents) <= 32, "configured_agents_bound")
    defaults = cfg.get("agents", {}).get("defaults", {})
    for agent in agents:
        need(type(agent) is dict, "agent_shape")
        row = {"id": safe_string(agent.get("id"), r"[A-Za-z0-9_.\-]+", 128)}
        for key in ("agentDir", "workspace"):
            if key in agent:
                row[key] = path_projection(agent[key])
        model = agent.get("model", defaults.get("model"))
        if type(model) is dict:
            model = model.get("primary")
        row["model_primary"] = None if model is None else safe_string(model, r"[A-Za-z0-9_.:/+\-]+", 160)
        runtime = agent.get("agentRuntime", defaults.get("agentRuntime"))
        if type(runtime) is dict:
            row["agent_runtime"] = {k: safe_string(runtime[k], r"[A-Za-z0-9_.\-]+", 128)
                                    for k in ("id", "homeScope") if k in runtime}
        out["agents"].append(row)
    out["matches_prior_agent_ids"] = [x.get("id") for x in out["agents"]] == host["configured_agents"]
    providers = cfg.get("models", {}).get("providers", {})
    need(type(providers) is dict and len(providers) <= 64, "provider_count_bound")
    out["provider_endpoints"] = [{"provider": safe_string(k, r"[A-Za-z0-9_.\-]+", 128),
                                  "endpoint": endpoint(v.get("baseUrl"))}
                                 for k, v in providers.items() if type(v) is dict and "baseUrl" in v]
    return out


def projection(kind, raw, host):
    if kind == "hash_only":
        return None
    if kind == "openclaw_config":
        return openclaw_projection(raw, host)
    if kind == "launchd_plist":
        return plist_projection(raw)
    if kind == "systemd_unit":
        return unit_projection(raw)
    if kind == "environment_projection":
        return environment_projection(raw)
    if kind == "cron_projection":
        return cron_projection(raw)
    raise Refused("unrecognized_projection_kind")


def count_read(raw):
    global byte_reads, read_calls
    byte_reads += len(raw)
    read_calls += 1
    need(byte_reads <= MAX_READ, "original_host_total_read_bound")
    return raw


def registered_open(path, flags, *, dir_fd=None):
    global protected
    protected += 1
    try:
        remaining()
        fd = os.open(path, flags, dir_fd=dir_fd)
        row = {"fd": fd, "closed": False, "close_attempted": False}
        fd_records.append(row)
    finally:
        protected -= 1
    if pending_signal is not None:
        raise Cancelled()
    return row


def close_once(row):
    global protected
    protected += 1
    try:
        if row["close_attempted"]:
            return
        row["close_attempted"] = True
        try:
            os.close(row["fd"])
            row["closed"] = True
        except BaseException as error:
            row["close_error_type"] = type(error).__name__
    finally:
        protected -= 1


class Pass:
    def __init__(self, spec, entries, host):
        self.spec, self.entries, self.host = spec, entries, host
        self.count = 0
        self.used = set()
        self.allowed = set()
        self.parents = {}
        self.rows = []
        self.parent_rows = []
        self.errors = []
        for path in spec["parents"]:
            self.allowed.update(("parent.before:" + path, "parent.open:" + path, "parent.after:" + path))
        for e in entries:
            self.allowed.update(("file.before:" + e["id"], "file.after:" + e["id"]))
            if e["kind"] != "metadata":
                self.allowed.update(("file.open:" + e["id"], "file.closed_read:" + e["id"]))
        need(len(self.allowed) == spec["planned_observations"] <= MAX_OBSERVATIONS,
             "exact_predeclared_observation_count")

    def observe(self, key, operation):
        remaining()
        need(key in self.allowed and key not in self.used, "unplanned_or_repeated_metadata_observation")
        self.used.add(key)
        self.count += 1
        need(self.count <= MAX_OBSERVATIONS, "metadata_pass_limit")
        return operation()

    def lstat(self, key, name, parent_fd=None):
        try:
            return self.observe(key, lambda: os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
        except FileNotFoundError:
            return None

    def build_parents(self):
        for path in self.spec["parents"]:
            if path == "/":
                parent = None
                name = "/"
            else:
                parent = self.parents[parent_path(path)]
                name = path.rsplit("/", 1)[1]
            if parent is not None and parent.get("fd") is None:
                self.parents[path] = {"fd": None, "blocked_by": parent.get("blocked_by", parent_path(path)),
                                      "status": "ancestor_unavailable"}
                continue
            before = self.lstat("parent.before:" + path, name, None if parent is None else parent["fd"])
            row = {"path": path, "name": name, "parent": parent, "before": before, "fd": None}
            self.parents[path] = row
            if before is None:
                row.update(status="absent", blocked_by=path)
                continue
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                row.update(status="refused_nondirectory_or_symlink", blocked_by=path)
                self.errors.append({"code": "parent_not_plain_directory", "path": path})
                continue
            try:
                handle = registered_open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                         dir_fd=None if parent is None else parent["fd"])
                row["handle"] = handle
                row["fd"] = handle["fd"]
                opened = self.observe("parent.open:" + path, lambda: os.fstat(row["fd"]))
                need(identity(opened) == identity(before), "parent_open_identity_changed")
                need(opened.st_uid in (0, self.host["uid"]), "unreviewed_parent_owner")
                row["status"] = "opened"
            except (OSError, Refused) as error:
                row.update(status="parent_open_refused", blocked_by=path)
                self.errors.append({"code": "parent_open_refused", "path": path,
                                    "error_type": type(error).__name__, "errno": getattr(error, "errno", None)})
                if row.get("handle") is not None:
                    close_once(row["handle"])
                row["fd"] = None

    def read_one(self, e):
        row = {"id": e["id"], "path": e["path"], "kind": e["kind"], "status": "unobserved"}
        self.rows.append(row)
        parent = self.parents[parent_path(e["path"])]
        if parent.get("fd") is None:
            row.update(status="blocked_by_ancestor", ancestor=parent.get("blocked_by", parent_path(e["path"])),
                       ancestor_observation=parent["status"])
            return
        name = e["path"].rsplit("/", 1)[1]
        before = self.lstat("file.before:" + e["id"], name, parent["fd"])
        if before is None:
            after = self.lstat("file.after:" + e["id"], name, parent["fd"])
            row.update(status="absent" if after is None else "changed_during_observation", absence_stable=after is None)
            return
        row["identity"] = identity(before)
        if e["kind"] == "metadata":
            after = self.lstat("file.after:" + e["id"], name, parent["fd"])
            row.update(status="metadata_observed" if after is not None and identity(after) == identity(before)
                       else "changed_during_observation",
                       symlink=stat.S_ISLNK(before.st_mode), regular=stat.S_ISREG(before.st_mode),
                       directory=stat.S_ISDIR(before.st_mode), contents_opened=False)
            return
        handle = None
        try:
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "regular_single_link_file_required")
            need(before.st_uid in e["owner_uids"] and not stat.S_IMODE(before.st_mode) & 0o022,
                 "unreviewed_file_owner_or_writable_mode")
            need(0 <= before.st_size <= e["maximum_bytes"] <= MAX_DOC, "document_size_bound")
            handle = registered_open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent["fd"])
            opened = self.observe("file.open:" + e["id"], lambda: os.fstat(handle["fd"]))
            need(identity(opened) == identity(before), "file_open_identity_changed")
            chunks = []
            digest = hashlib.sha256()
            count = 0
            retain = e["kind"] != "hash_only"
            while count < before.st_size:
                remaining()
                allowance = min(65536, before.st_size - count, MAX_READ - byte_reads)
                need(allowance > 0, "file_or_host_read_bound")
                block = count_read(os.read(handle["fd"], allowance))
                need(bool(block), "short_regular_file_read")
                count += len(block)
                need(count <= e["maximum_bytes"], "document_grew_past_bound")
                digest.update(block)
                if retain:
                    chunks.append(block)
            closed_read = self.observe("file.closed_read:" + e["id"], lambda: os.fstat(handle["fd"]))
            after = self.lstat("file.after:" + e["id"], name, parent["fd"])
            need(after is not None and count == before.st_size
                 and identity(closed_read) == identity(before) == identity(after), "file_changed_during_read")
            row.update(status="read_verified", sha256=digest.hexdigest(), bytes=count,
                       expected_prior_sha256=e["expected_sha256"],
                       prior_sha_matches=e["expected_sha256"] is None or digest.hexdigest() == e["expected_sha256"])
            projected = projection(e["kind"], b"".join(chunks) if retain else b"", self.host)
            if projected is not None:
                row["projection"] = projected
        except (OSError, ValueError, TypeError, KeyError, Refused, plistlib.InvalidFileException) as error:
            row.update(status="read_or_projection_refused", error_type=type(error).__name__,
                       error_code=str(error) if isinstance(error, Refused) else None,
                       errno=getattr(error, "errno", None))
        finally:
            if handle is not None:
                close_once(handle)

    def finish_parents(self):
        for path in reversed(self.spec["parents"]):
            row = self.parents.get(path)
            if row is None:
                continue
            if "before" not in row:
                self.parent_rows.append({"path": path, "status": row["status"], "blocked_by": row.get("blocked_by")})
                continue
            try:
                parent = row["parent"]
                after = self.lstat("parent.after:" + path, row["name"],
                                   None if parent is None else parent["fd"])
                stable = (row["before"] is None and after is None) or (
                    row["before"] is not None and after is not None and identity(row["before"]) == identity(after))
                need(stable, "parent_name_changed")
                self.parent_rows.append({"path": path, "status": row["status"], "stable": stable,
                                         "identity": None if after is None else identity(after)})
            except BaseException as error:
                self.errors.append({"code": "parent_final_fence_unproven", "path": path,
                                    "error_type": type(error).__name__})
                # Preserve the partial pass and close all held directories.
                # remaining() refuses every further observation after cancellation.
            finally:
                if row.get("handle") is not None:
                    close_once(row["handle"])

    def run(self):
        failure = None
        try:
            self.build_parents()
            for e in self.entries:
                remaining()
                self.read_one(e)
        except BaseException as error:
            failure = {"error_type": type(error).__name__,
                       "code": str(error) if isinstance(error, Refused) else None}
        finally:
            self.finish_parents()
        for e in self.entries:
            if not any(r["id"] == e["id"] for r in self.rows):
                self.rows.append({"id": e["id"], "path": e["path"], "status": "unobserved", "reason": "pass_stopped"})
        return {"id": self.spec["id"], "planned_observations": len(self.allowed),
                "performed_observations": self.count,
                "performed_observation_ordinals": [i for i, key in enumerate(sorted(self.allowed)) if key in self.used],
                "parents": self.parent_rows, "entries": self.rows, "errors": self.errors, "failure": failure}


def stop_once(row):
    global protected
    protected += 1
    try:
        if row.get("stop_attempted"):
            return
        row["stop_attempted"] = True
        p = row["process"]
        if p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                p.wait(timeout=5)
        row["direct_child_reaped"] = p.returncode is not None
    except BaseException as error:
        row["cleanup_error_type"] = type(error).__name__
    finally:
        protected -= 1


def close_child_streams_once(row):
    global protected
    protected += 1
    try:
        if row.get("stream_close_attempted"):
            return
        row["stream_close_attempted"] = True
        errors = []
        for stream in (row["process"].stdout, row["process"].stderr):
            try:
                if stream is not None:
                    stream.close()
            except BaseException as error:
                errors.append(type(error).__name__)
        row["streams_closed"] = not errors and all(
            stream is None or stream.closed for stream in (row["process"].stdout, row["process"].stderr))
        if errors:
            row["stream_close_errors"] = errors
    finally:
        protected -= 1


def run_child(label, argv, host, *, cleanup_probe=False):
    global protected
    begin = time.monotonic()
    deadline = min(UNTIL, begin + (5.0 if cleanup_probe else 10.0))
    remaining(deadline)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": host["home"], "LANG": "C", "LC_ALL": "C"}
    if host["system"] == "Linux":
        env["XDG_RUNTIME_DIR"] = "/run/user/" + str(host["uid"])
        env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/run/user/" + str(host["uid"]) + "/bus"
    protected += 1
    try:
        remaining(deadline)
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, start_new_session=True)
        row = {"label": label, "process": p, "pid": p.pid, "stop_attempted": False}
        children.append(row)
    finally:
        protected -= 1
    if pending_signal is not None:
        raise Cancelled()
    chunks = {"stdout": [], "stderr": []}
    counts = {"stdout": 0, "stderr": 0}
    poller = None
    failure = None
    try:
        poller = selectors.DefaultSelector()
        for stream, name in ((p.stdout, "stdout"), (p.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            poller.register(stream, selectors.EVENT_READ, name)
        while poller.get_map():
            for key, _ in poller.select(remaining(deadline)):
                allowance = min(65536, MAX_DOC - sum(counts.values()), MAX_READ - byte_reads)
                need(allowance > 0, "query_or_host_output_bound")
                block = count_read(os.read(key.fileobj.fileno(), allowance))
                if not block:
                    poller.unregister(key.fileobj)
                    continue
                counts[key.data] += len(block)
                need(sum(counts.values()) <= MAX_DOC, "query_output_bound")
                chunks[key.data].append(block)
        p.wait(timeout=remaining(deadline))
        remaining(deadline)
    except BaseException as error:
        failure = {"error_type": type(error).__name__,
                   "code": str(error) if isinstance(error, Refused) else None}
    finally:
        try:
            if poller is not None:
                poller.close()
        finally:
            close_child_streams_once(row)
            stop_once(row)
    out, err = b"".join(chunks["stdout"]), b"".join(chunks["stderr"])
    row.update(exit_code=p.returncode, elapsed_seconds=time.monotonic() - begin,
               command_limit_seconds=5 if cleanup_probe else 10,
               stdout_bytes=len(out), stdout_sha256=sha(out),
               stderr_bytes=len(err), stderr_sha256=sha(err), failure=failure)
    if pending_signal is not None:
        raise Cancelled()
    return row, out, err


def query_projection(q, out, err, exit_code):
    kind = q["kind"]
    if kind == "crontab":
        if exit_code == 1 and err.decode("utf-8", "replace").strip() in (
                "no crontab for " + q["owner"], "crontab: no crontab for " + q["owner"]):
            return {"owner_crontab_absent": True, "known_no_crontab_diagnostic": True}
        need(exit_code == 0, "crontab_query_not_known_complete")
        return cron_projection(out)
    need(exit_code == 0, "query_nonzero_exit")
    if kind == "diskutil":
        info = plistlib.loads(out)
        need(type(info) is dict and info.get("VolumeUUID") == q["expected_volume_uuid"],
             "t5_volume_uuid_changed")
        return {"volume_uuid": info["VolumeUUID"],
                "mount_point": path_projection(info.get("MountPoint")),
                "device_identifier": safe_string(info.get("DeviceIdentifier"), r"[A-Za-z0-9_.\-]+"),
                "filesystem": safe_string(info.get("FilesystemType"), r"[A-Za-z0-9_.\-]+"),
                "mounted": info.get("Mounted"), "volume_read_only": info.get("ReadOnlyVolume")}
    if kind == "systemctl":
        allowed = set(q["argv"][-1].split("=", 1)[1].split(","))
        result = {}
        for line in out.decode("utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            need(key in allowed and key not in result, "systemctl_unexpected_property")
            if key in ("FragmentPath", "DropInPaths"):
                values = value.split()
                need(len(values) <= 32, "systemctl_path_bound")
                result[key] = [path_projection(x) for x in values]
            elif key in ("MainPID", "ControlPID"):
                need(value.isdigit(), "systemctl_pid_shape")
                result[key] = int(value)
            else:
                result[key] = safe_string(value, r"[A-Za-z0-9_.: /@+\-]*", 1024)
        need(result.get("Id") == q["unit"], "systemctl_wrong_unit")
        return result
    if kind == "launchctl":
        result = {"unit": q["unit"], "raw_sha256": sha(out), "fields": []}
        for line in out.decode("utf-8").splitlines():
            # Only known scalar field lines. Never print arguments/environment blocks.
            match = re.fullmatch(r"\s*(path|state|pid|program|working directory|stdout path|stderr path)\s*=\s*(.*?)\s*", line)
            if match:
                key, value = match.groups()
                projected = int(value) if key == "pid" and value.isdigit() else (
                    path_projection(value) if key in ("path", "program", "working directory", "stdout path", "stderr path")
                    else safe_string(value, r"[A-Za-z0-9_.\-]+", 128))
                result["fields"].append({"key": key, "value": projected})
        need(len(result["fields"]) <= 32, "launchctl_field_bound")
        return result
    if kind == "docker":
        obj = parse(out)
        need(type(obj) is dict and obj.get("Id") == q["container_id"], "exact_oracle_identity")
        mounts = obj.get("Mounts", [])
        need(type(mounts) is list and len(mounts) <= 32, "container_mount_bound")
        need(all(type(obj.get(k)) is bool for k in ("Running", "Paused", "Restarting"))
             and all(type(obj.get(k)) is int for k in ("ExitCode", "Pid")), "container_scalar_types")
        result = {k: obj.get(k) for k in ("Id", "Running", "Paused", "Restarting", "ExitCode", "Pid")}
        for k in ("Name", "Image", "StateStatus", "StartedAt", "FinishedAt", "NetworkMode"):
            result[k] = safe_string(obj.get(k), r"[A-Za-z0-9_./:@+\-]+", 256)
        result["mounts"] = [{k: path_projection(x[k]) if k in ("Source", "Destination")
                             else safe_string(x[k], r"[A-Za-z0-9_.+\-]+", 128)
                             for k in ("Type", "Source", "Destination", "Mode") if k in x}
                            for x in mounts]
        result["restart_policy_sha256"] = sha(encoded(obj.get("RestartPolicy")))
        ports = obj.get("Ports")
        need(ports is None or (type(ports) is dict and len(ports) <= 32), "container_port_bound")
        result["port_bindings"] = None if ports is None else {}
        for key, bindings in (ports or {}).items():
            need(re.fullmatch(r"[0-9]{1,5}/(tcp|udp|sctp)", key) is not None,
                 "container_port_key")
            need(bindings is None or (type(bindings) is list and len(bindings) <= 16),
                 "container_port_bindings")
            result["port_bindings"][key] = None if bindings is None else [
                {"host_ip": safe_string(x.get("HostIp"), r"[0-9A-Fa-f:.]*", 64),
                 "host_port": safe_string(x.get("HostPort"), r"[0-9]{1,5}", 5)}
                for x in bindings]
        result["no_disposable_or_deletion_inference"] = True
        return result
    raise Refused("unknown_query_kind")


def read_manifest():
    data = []
    count = 0
    while True:
        ready, _, _ = select.select([sys.stdin.fileno()], [], [], remaining())
        need(bool(ready), "manifest_input_not_ready")
        allowance = min(65536, MAX_DOC - count, MAX_READ - byte_reads)
        need(allowance > 0, "manifest_or_host_input_bound")
        block = count_read(os.read(sys.stdin.fileno(), allowance))
        if not block:
            break
        count += len(block)
        need(count <= MAX_DOC, "manifest_input_bound")
        data.append(block)
    raw = b"".join(data)
    need(sha(raw) == MANIFEST_SHA, "exact_reviewed_manifest_required")
    return parse(raw)

def validate_manifest(m, host_name):
    need(m["schema"] == "heptabao.finite-client-inventory.r1", "manifest_schema")
    need(m["limits"] == {"host_seconds": 45, "outer_seconds": 60, "child_seconds": 10,
                        "max_document_bytes": MAX_DOC, "max_total_read_bytes": MAX_READ,
                        "max_output_bytes": MAX_OUTPUT, "max_metadata_observations_per_pass": 32,
                        "max_backup_items": 16}, "unchanged_inventory_limits")
    host = m["hosts"][host_name]
    u = os.uname()
    need(os.getuid() == host["uid"] and u.sysname == host["system"] and u.machine == host["machine"],
         "expected_host_os_owner")
    entries = {e["id"]: e for e in host["entries"]}
    need(len(entries) == len(host["entries"])
         and len({e["path"] for e in entries.values()}) == len(entries), "unique_fixed_entries")
    seen = []
    for p in host["passes"]:
        selected = [entries[x] for x in p["entry_ids"]]
        pp = sorted({s for e in selected for s in ancestor_paths(fixed_path(e["path"]))},
                    key=lambda x: (len(x.split("/")), x))
        need(pp == p["parents"], "exact_fixed_parent_denominator")
        n = 3 * len(pp) + sum(2 if e["kind"] == "metadata" else 4 for e in selected)
        need(n == p["planned_observations"] <= 32, "pass_observation_count")
        seen.extend(p["entry_ids"])
    need(len(seen) == len(set(seen)) == len(entries) and set(seen) == set(entries),
         "complete_unique_entry_denominator")
    need(sum(e["category"] == "backup_metadata" for e in entries.values()) == host["backup_metadata_count"] <= 16,
         "backup_metadata_denominator")
    for q in host["queries"]:
        need(q["seconds"] == 10 and type(q["argv"]) is list and q["argv"]
             and q["argv"][0] in ("/bin/launchctl", "/usr/sbin/diskutil", "/usr/bin/systemctl",
                                  "/usr/bin/docker", "/usr/bin/crontab"), "fixed_readonly_query")
    return host, entries


def clean_children(host):
    for row in reversed(children):
        close_child_streams_once(row)
        stop_once(row)
    snapshot = None
    error = None
    probe = None
    try:
        if children:
            # A read-only process table is only retained in memory and filtered
            # to this controller's own groups. No process argv/env is requested.
            probe, out, _ = run_child("owned-group-final-snapshot",
                                     ["/bin/ps", "-axo", "pid=,ppid=,pgid=,stat="],
                                     host, cleanup_probe=True)
            need(probe["failure"] is None and probe["exit_code"] == 0
                 and probe["direct_child_reaped"], "final_group_snapshot_failed")
            snapshot = []
            for line in out.decode("ascii").splitlines():
                fields = line.split()
                need(len(fields) >= 4 and all(x.isdigit() for x in fields[:3]), "process_snapshot_shape")
                snapshot.append({"pid": int(fields[0]), "ppid": int(fields[1]),
                                 "pgid": int(fields[2]), "state": fields[3]})
    except BaseException as exc:
        error = type(exc).__name__
    result = []
    for row in children:
        stopped = row["process"].returncode is not None
        members = None if snapshot is None else [
            x for x in snapshot if x["pgid"] == row["pid"]
            and not (row is probe and stopped and x["pid"] == row["pid"])]
        result.append({"label": row["label"], "pid": row["pid"], "exit_code": row["process"].returncode,
                       "direct_child_reaped": stopped, "remaining": members,
                       "streams_closed": row.get("streams_closed") is True,
                       "stream_close_errors": row.get("stream_close_errors"),
                       "cleanup_error_type": row.get("cleanup_error_type"),
                       "snapshot_error_type": error})
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", choices=("mac", "rog", "x230"), required=True)
    args = parser.parse_args()
    report = {"schema": SCHEMA, "host": args.host, "manifest_sha256": MANIFEST_SHA,
              "status": "incomplete", "started_unix_ns": time.time_ns(), "passes": [], "queries": [],
              "production_changed": False, "credential_values_published": False,
              "sqlite_opened": False, "sdk_called": False, "provider_called": False,
              "j3160_contacted": False, "services_transitioned": False,
              "containers_changed": False, "encrypted_archive_or_recovery_key_read": False,
              "new_restore_executed": False, "whole_host_absence_qualified": False,
              "production_cutover_qualified": False, "current_consumer_runtime_qualified": False,
              "source_snapshot_atomic_across_entries": False, "automatic_retry": False,
              "access_time_unchanged_claimed": False,
              "hash_only_current_auth_and_role_files_explicitly_in_manifest": True}
    host = None
    entries = {}
    failure = None
    try:
        m = read_manifest()
        host, entries = validate_manifest(m, args.host)
        report["scope"] = {"entries": len(entries), "passes": len(host["passes"]),
                           "queries": len(host["queries"]), "backup_metadata": host["backup_metadata_count"]}
        for p in host["passes"]:
            remaining()
            report["passes"].append(Pass(p, [entries[x] for x in p["entry_ids"]], host).run())
            need(pending_signal is None, "interrupted")
        for q in host["queries"]:
            remaining()
            row, out, err = run_child(q["id"], q["argv"], host)
            public = {k: v for k, v in row.items() if k not in ("process", "stop_attempted")}
            public["kind"] = q["kind"]
            report["queries"].append(public)
            need(row["failure"] is None and row["direct_child_reaped"], "query_not_complete_or_reaped")
            try:
                public["projection"] = query_projection(q, out, err, row["exit_code"])
                public["projection_complete"] = True
            except (OSError, ValueError, TypeError, KeyError, Refused, plistlib.InvalidFileException) as error:
                public["projection_complete"] = False
                public["projection_error_type"] = type(error).__name__
                public["projection_error_code"] = str(error) if isinstance(error, Refused) else None
    except BaseException as error:
        failure = {"type": type(error).__name__, "code": str(error) if isinstance(error, Refused) else None}
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cleanup = clean_children(host) if host is not None else []
        for row in reversed(fd_records):
            close_once(row)
        report["all_owned_descriptors_closed"] = all(x["closed"] for x in fd_records)
        report["cleanup"] = cleanup
        report["all_owned_stopped"] = all(x["direct_child_reaped"] and x["remaining"] == []
                                           and x["streams_closed"] and x["stream_close_errors"] is None
                                           and x["cleanup_error_type"] is None
                                           and x["snapshot_error_type"] is None for x in cleanup)
        report["failure"] = failure
        report["byte_reads"] = byte_reads
        report["read_calls"] = read_calls
        observed = {r["id"]: r for p in report["passes"] for r in p["entries"]}
        report["unobserved_entries"] = [{"id": k, "path": e["path"], "reason": "original_operation_stopped"}
                                        for k, e in entries.items() if k not in observed]
        report["unobserved_queries"] = [] if host is None else [
            q["id"] for q in host["queries"] if not any(x["label"] == q["id"] for x in report["queries"])]
        read_ok = all(r["status"] in ("metadata_observed", "read_verified", "absent")
                      and (r["status"] != "absent" or not entries[r["id"]]["required"])
                      and r.get("prior_sha_matches", True) for r in observed.values())
        parent_ok = all(not p["errors"] and p["failure"] is None
                        and all(r.get("stable") is True for r in p["parents"]) for p in report["passes"])
        all_done = bool(host) and not report["unobserved_entries"] and not report["unobserved_queries"]
        all_queries = all(q.get("projection_complete") is True for q in report["queries"])
        before_output_deadline = time.monotonic() < UNTIL
        if (failure is None and pending_signal is None and all_done and read_ok and parent_ok
                and all_queries and report["all_owned_descriptors_closed"] and report["all_owned_stopped"]
                and before_output_deadline):
            report["status"] = "completed_finite_observation_only"
        report["deadline_before_output_passed"] = before_output_deadline
        report["elapsed_seconds"] = time.monotonic() - START
        report["authority_exit_zero_and_original_deadline_required"] = True
        raw = encoded(report) + b"\n"
        if len(raw) > MAX_OUTPUT:
            report = {"schema": SCHEMA, "host": args.host, "status": "incomplete",
                      "failure": {"code": "public_output_bound", "full_candidate_bytes": len(raw),
                                  "full_candidate_sha256": sha(raw)},
                      "planned_entry_ids": sorted(entries), "unobserved_entries": report["unobserved_entries"],
                      "all_owned_stopped": report["all_owned_stopped"],
                      "all_owned_descriptors_closed": report["all_owned_descriptors_closed"],
                      "complete_report_not_published": True, "automatic_retry": False,
                      "production_changed": False, "services_transitioned": False,
                      "current_consumer_runtime_qualified": False}
            raw = encoded(report) + b"\n"
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
    return 0 if report["status"] == "completed_finite_observation_only" and time.monotonic() < UNTIL else 1


if __name__ == "__main__":
    sys.exit(main())
