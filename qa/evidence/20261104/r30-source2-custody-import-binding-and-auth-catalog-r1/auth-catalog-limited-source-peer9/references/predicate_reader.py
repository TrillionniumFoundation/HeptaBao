#!/usr/bin/env python3
"""One exact already-captured private capsule; public predicate results only.

No current database, SDK, service, network, subprocess or filesystem write.
The old capture/runtime is not replayed. Actual selector execution is explicitly
unknown because that earlier runtime stopped before every worker.
"""
from contextlib import contextmanager
from pathlib import Path
import hashlib, json, os, re, signal, stat, sys, time

CAPSULE = json.loads("{\"bytes\":195155,\"identity\":[\"16777244\",\"72635869\",\"501\",\"20\",\"33152\",\"1\",\"195155\",\"1793881838780757114\",\"1793881838780765364\"],\"path\":\"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-registry-wal-r1/captures/before/output/capsule.private.json\",\"sha256\":\"f4e4f83ced4229302b85231628ebc1a797474389265e2005e44be0ae4aafae04\"}")
EXPECTED_ANCHORS = json.loads("[{\"identity\":[\"16777233\",\"2\",\"0\",\"0\",\"16877\",\"22\",\"704\",\"1786589515000000000\",\"1786589515000000000\"],\"path\":\"/\"},{\"identity\":[\"16777233\",\"18336\",\"0\",\"0\",\"16877\",\"5\",\"160\",\"1793100597756515591\",\"1793100597756515591\"],\"path\":\"/Volumes\"},{\"identity\":[\"16777244\",\"2\",\"0\",\"0\",\"16893\",\"12\",\"384\",\"1793152973144260495\",\"1793152973144260495\"],\"path\":\"/Volumes/T5\"}]")
PARENT_PATHS = ["/","/Volumes","/Volumes/T5","/Volumes/T5/hepta-vnext-recovery-20261013","/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-registry-wal-r1","/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-registry-wal-r1/captures","/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-registry-wal-r1/captures/before","/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-registry-wal-r1/captures/before/output"]
AGENTS = ("main", "trnm", "hepta-ui", "hepta", "hepta-backend")
LIVE = Path("/Users/qianqi/.openclaw")
KNOWN_CODEX_ROOT = "/Users/qianqi/.openclaw/npm/projects/openclaw-codex-8902d781d4__openclaw-generation__g-49fd4dbfde2c5057/node_modules/@openclaw/codex"
PUBLIC_EXPECTED_MODEL = {"provider":"openai","id":"gpt-5.6-sol"}
CONFIG_SHA256 = "ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d"
SOURCE_RUNTIME_JOB = "1a1abb090b9-fc05-4fc5"
SOURCE_RUNTIME_STDOUT_SHA256 = "8d3f357bf75b11c1ce37e34bb7304460271a1cb74d1bd5200031d2f2bd3f9302"
SOURCE_ENTRY_SHA256 = "88883315e4d9f343cbbc967224fc7a177f5cc8e216d09f811ef1c59c5de5fbd4"
NEW_SOFT_SECONDS = 5.0
MAX_METADATA_CALLS = 80
MAX_DESCRIPTORS = 9
MAX_READ_CALLS = 4
MAX_READ_BYTES = 195156
MAX_OUTPUT_BYTES = 16384

class Refused(RuntimeError):
    pass

class Cancelled(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def identity(value):
    return tuple(str(x) for x in (
        value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns))

def sha(value):
    return hashlib.sha256(value).hexdigest()

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")

def exact_json(raw):
    def pairs(items):
        output = {}
        for key, value in items:
            need(key not in output, "duplicate_json_member")
            output[key] = value
        return output
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Refused("nonfinite_json")))

class Signals:
    def __init__(self):
        self.pending = None
        self.protected = 0
        self.old = []
        self.restore_errors = []
    def receive(self, signum, _frame):
        self.pending = signum
        if not self.protected:
            raise Cancelled()
    def install(self):
        for signum in (signal.SIGTERM, signal.SIGINT):
            prior = signal.getsignal(signum)
            self.old.append((signum, prior))
            signal.signal(signum, self.receive)
    def check(self):
        if self.pending is not None:
            raise Cancelled()
    @contextmanager
    def critical(self):
        self.protected += 1
        try:
            yield
        finally:
            self.protected -= 1
    def restore(self):
        for signum, prior in reversed(self.old):
            try:
                signal.signal(signum, prior)
            except BaseException as error:
                self.restore_errors.append(type(error).__name__)
        self.old.clear()

class FixedReader:
    def __init__(self, signals, until):
        self.signals, self.until = signals, until
        self.rows = []
        self.metadata_calls = 0
        self.read_calls = 0
        self.read_bytes = 0
        self.close_errors = []
        self.last_named_fence = False
        self.closed = False
    def remaining(self):
        self.signals.check()
        need(time.monotonic() < self.until, "original_diagnostic_deadline")
        need(not self.closed, "reader_open")
    def metadata(self, function, *args, **kwargs):
        self.remaining()
        need(self.metadata_calls < MAX_METADATA_CALLS, "fixed_metadata_count")
        self.metadata_calls += 1
        return function(*args, **kwargs)
    def open_registered(self, name, flags, parent, path, expected, kind):
        self.remaining()
        need(len(self.rows) < MAX_DESCRIPTORS, "fixed_descriptor_count")
        row = {"path":path, "kind":kind, "name":name, "parent":parent,
               "fd":None, "created":False, "expected":tuple(expected),
               "closeAttempted":False, "closed":False, "closeError":None}
        self.rows.append(row)
        with self.signals.critical():
            fd = os.open(name, flags, **({} if parent is None else {"dir_fd":parent["fd"]}))
            row["fd"] = fd
            row["created"] = True
        self.remaining()
        actual = self.metadata(os.fstat, fd)
        need(identity(actual) == row["expected"], "held_full_nine")
        return row
    def named(self, row):
        if row["parent"] is None:
            return self.metadata(os.lstat, "/")
        return self.metadata(os.stat, row["name"], dir_fd=row["parent"]["fd"], follow_symlinks=False)
    def verify_all(self):
        self.last_named_fence = False
        self.remaining()
        for row in self.rows:
            if not row["created"]:
                continue
            need(not row["closeAttempted"], "fence_precedes_close")
            named = self.named(row)
            held = self.metadata(os.fstat, row["fd"])
            need(identity(named) == identity(held) == row["expected"], "same_named_held_full_nine")
        self.remaining()
        self.last_named_fence = True
    def read_exact_capsule(self):
        self.remaining()
        need(sys.platform == "darwin" and os.getuid() == 501, "fixed_mac_uid")
        need(len(PARENT_PATHS) == 8 and CAPSULE["bytes"] == 195155
             and CAPSULE["identity"][6] == "195155", "fixed_capture_binding")
        anchors = {item["path"]:tuple(item["identity"]) for item in EXPECTED_ANCHORS}
        parent = None
        for path in PARENT_PATHS:
            name = "/" if parent is None else Path(path).name
            named = self.metadata(os.lstat, "/") if parent is None else self.metadata(
                os.stat, name, dir_fd=parent["fd"], follow_symlinks=False)
            need(stat.S_ISDIR(named.st_mode), "ordinary_parent_directory")
            if path in anchors:
                need(identity(named) == anchors[path], "original_three_anchor_full_nine")
            else:
                need(named.st_dev == 16777244 and named.st_uid == 501
                     and stat.S_IMODE(named.st_mode) & 0o022 == 0,
                     "owned_t5_parent_no_external_write")
            parent = self.open_registered(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                parent, path, identity(named), "directory")
        named = self.metadata(os.stat, Path(CAPSULE["path"]).name,
            dir_fd=parent["fd"], follow_symlinks=False)
        need(identity(named) == tuple(CAPSULE["identity"])
             and stat.S_ISREG(named.st_mode) and named.st_uid == 501 and named.st_gid == 20
             and stat.S_IMODE(named.st_mode) == 0o600 and named.st_nlink == 1,
             "exact_original_capsule_identity")
        row = self.open_registered(Path(CAPSULE["path"]).name,
            os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, parent, CAPSULE["path"],
            CAPSULE["identity"], "private_capsule")
        self.verify_all()
        raw = bytearray()
        while True:
            self.remaining()
            need(self.read_calls < MAX_READ_CALLS, "fixed_read_count")
            want = min(65536, CAPSULE["bytes"] + 1 - len(raw))
            need(want > 0, "fixed_private_byte_bound")
            self.read_calls += 1
            block = os.read(row["fd"], want)
            self.read_bytes += len(block)
            need(self.read_bytes <= MAX_READ_BYTES, "aggregate_private_byte_bound")
            if not block:
                break
            raw.extend(block)
        self.remaining()
        need(len(raw) == CAPSULE["bytes"] and sha(raw) == CAPSULE["sha256"],
             "exact_whole_captured_capsule")
        self.verify_all()
        return bytes(raw)
    def close_once(self, row):
        if not row["created"] or row["closeAttempted"]:
            return
        with self.signals.critical():
            row["closeAttempted"] = True
            try:
                os.close(row["fd"])
                row["closed"] = True
            except BaseException as error:
                row["closeError"] = type(error).__name__
                self.close_errors.append(type(error).__name__)
    def close(self):
        with self.signals.critical():
            for row in reversed(self.rows):
                self.close_once(row)
            self.closed = True
    def public(self):
        return {
            "metadataCalls":self.metadata_calls, "readCalls":self.read_calls,
            "privateBytesRead":self.read_bytes,
            "descriptorsRegistered":len(self.rows),
            "allOwnedDescriptorsClosed":all((not r["created"]) or r["closed"] for r in self.rows),
            "closeErrors":list(self.close_errors), "lastNamedFullNineFence":self.last_named_fence,
            "descriptorLedger":[{k:r[k] for k in
                ("path","kind","created","closeAttempted","closed","closeError")}
                for r in self.rows],
            "parentObservations":[{"path":r["path"],"identity":list(r["expected"])}
                for r in self.rows if r["kind"] == "directory" and r["created"]],
            "capsuleIdentity":list(CAPSULE["identity"]),
            "t5UuidRemeasuredInThisDiagnostic":False,
            "t5Scope":"Exact original three full-nine anchors and whole original capsule identity/hash; no new diskutil or whole-volume claim.",
        }

def predicate_projection(raw):
    document = exact_json(raw)
    need(isinstance(document, dict)
         and document.get("schema") == "heptabao.mac-guarded-current-inputs.private.r1"
         and document.get("sourceConfigSha256") == CONFIG_SHA256
         and tuple(document.get("agentIds", ())) == AGENTS, "captured_document_scope")
    registry = document.get("registry")
    need(isinstance(registry, dict), "captured_registry_object")
    columns, row = registry.get("columns"), registry.get("row")
    need(isinstance(columns, list) and len(columns) == 13
         and all(isinstance(x, str) for x in columns) and len(set(columns)) == 13
         and columns.count("plugins_json") == 1
         and isinstance(row, list) and len(row) == 13, "captured_registry_thirteen_columns")
    plugins_raw = row[columns.index("plugins_json")]
    need(isinstance(plugins_raw, str), "plugins_json_original_string")
    plugins = exact_json(plugins_raw)
    need(isinstance(plugins, list) and len(plugins) <= 128, "bounded_actual_registry_plugins")
    # This is precisely the original enabled set, not a selected-harness set.
    enabled = [(i, p) for i, p in enumerate(plugins)
        if isinstance(p, dict) and p.get("enabled") is True
        and isinstance(p.get("startup"), dict) and p["startup"].get("agentHarnesses")]
    need(1 <= len(enabled) <= 8, "finite_actual_enabled_harness_roots")
    output = []
    for enabled_index, (registry_index, plugin) in enumerate(enabled):
        identifier = plugin.get("pluginId")
        raw_root = plugin.get("rootDir", "")
        root_constructible = isinstance(raw_root, str)
        root = Path(raw_root) if root_constructible else None
        id_matches = isinstance(identifier, str) and bool(re.fullmatch("[a-z0-9][a-z0-9_.-]{0,79}", identifier))
        absolute = bool(root is not None and root.is_absolute())
        normalized = bool(root is not None and root == Path(os.path.normpath(str(root))))
        namespace = bool(root is not None and root.is_relative_to(LIVE/"npm/projects"))
        known_root = bool(root is not None and root == Path(KNOWN_CODEX_ROOT))
        output.append({
            "enabledOrdinal":enabled_index, "registryOrdinal":registry_index,
            "originalEnabledStartupAgentHarnesses":True,
            "identifierIsString":isinstance(identifier, str),
            "identifierMatchesOriginalRegex":id_matches,
            "identifierValueSha256":sha(encoded(identifier)),
            "rootConstructionSupported":root_constructible,
            "rootIsAbsolute":absolute, "rootIsNormalized":normalized,
            "rootInOriginalNpmProjectsNamespace":namespace,
            "rootValueSha256":sha(encoded(raw_root)),
            "originalCompositePredicate":bool(id_matches and root_constructible and absolute and normalized and namespace),
            "rootEqualsAlreadyPinnedCodexRoot":known_root,
            "publicCodeRoot":KNOWN_CODEX_ROOT if known_root else None,
            "agentHarnessesMetadataSha256":sha(encoded(plugin["startup"]["agentHarnesses"])),
            "actualSelectedForCurrentAgents":None,
            "selectionEvidence":"NOT_OBSERVED_NO_NATIVE_WORKER_RAN",
        })
    models = document.get("models")
    need(isinstance(models, dict) and set(models) == set(AGENTS), "five_captured_models")
    agents = []
    for agent in AGENTS:
        value = models[agent]
        need(isinstance(value, dict) and value.get("sourceConfigSha256") == CONFIG_SHA256
             and isinstance(value.get("declaredModelSha256"), str)
             and re.fullmatch("[0-9a-f]{64}", value["declaredModelSha256"]),
             "captured_model_public_binding")
        same_public = value.get("provider") == PUBLIC_EXPECTED_MODEL["provider"] and value.get("id") == PUBLIC_EXPECTED_MODEL["id"]
        agents.append({"agentId":agent, "declaredModelSha256":value["declaredModelSha256"],
            "matchesAlreadyPublicConfigModel":same_public,
            "alreadyPublicModel":dict(PUBLIC_EXPECTED_MODEL) if same_public else None,
            "actualSelectedHarness":None, "selectorExecuted":False})
    first = next((x["enabledOrdinal"] for x in output if not x["originalCompositePredicate"]), None)
    return {
        "registryPluginCount":len(plugins), "originalEnabledHarnessOwnerCount":len(enabled),
        "enabledHarnessOwners":output, "firstCompositeRejectionOrdinal":first,
        "configuredFiveAgentModelBindings":agents,
        "enabledDoesNotMeanSelected":True,
        "unselectedHarnessClaimed":False,
        "actualSelectedHarnessSetKnown":False,
        "originalNativeWorkerContract":"After loader.r(onlyPluginIds), selector.o(provider/modelId) must equal the real registry.r('codex').harness. No worker/selector ran in this failed attempt.",
        "futureScopeRule":"Determine selected owners from the real selector and complete pinned sources before changing admission. Do not broaden npm namespace or classify another enabled owner as unused from this diagnostic.",
        "pluginIdsPublished":False, "unknownCodePathsPublished":False,
        "privateDocumentBodyPublished":False, "rootGuardRelaxed":False,
    }

def main():
    start = time.monotonic()
    until = start + NEW_SOFT_SECONDS
    signals = Signals()
    reader = None
    stage = "signal_setup"
    completed = False
    report = {
        "schema":"heptabao.mac-captured-harness-predicate-observation.r1",
        "sourceRuntimeJobId":SOURCE_RUNTIME_JOB,
        "sourceRuntimeStdoutSha256":SOURCE_RUNTIME_STDOUT_SHA256,
        "sourceEntryStdoutSha256":SOURCE_ENTRY_SHA256,
        "capsulePath":CAPSULE["path"], "capsuleBytes":CAPSULE["bytes"],
        "capsuleSha256":CAPSULE["sha256"],
        "newSoftSeconds":NEW_SOFT_SECONDS, "newSupervisorSeconds":60,
        "predicateProjection":None, "errorType":None, "errorCode":None, "errno":None,
        "observationComplete":False, "allOriginalPredicatesPassed":None,
        "authoritativeExitZeroAfterHandlerRestoreRequired":True,
        "currentProductionFilesOpened":False, "currentSqliteOpened":False,
        "captureOrFixtureReplayed":False, "libraryOrSdkImported":False,
        "subprocessStarted":False, "networkUsed":False, "filesystemWritesByProgram":False,
        "privateCapsuleBodyPublished":False, "providerOrJ3160":False,
        "historicalUnknownsChanged":False, "runtimeQualificationGranted":False,
    }
    try:
        signals.install()
        with signals.critical():
            try:
                stage = "fixed_capsule_read"
                reader = FixedReader(signals, until)
                raw = reader.read_exact_capsule()
                stage = "original_enabled_predicates"
                report["predicateProjection"] = predicate_projection(raw)
                stage = "final_full_nine_fence"
                reader.verify_all()
                reader.remaining()
                completed = True
            except BaseException as error:
                report["errorType"] = type(error).__name__
                report["errorCode"] = str(error) if type(error) is Refused else None
                value = getattr(error, "errno", None)
                report["errno"] = value if type(value) is int and 0 <= value <= 255 else None
            finally:
                stage_at_close = stage
                if reader is not None:
                    reader.close()
                report["failureStage"] = None if completed else stage_at_close
    except BaseException as error:
        report["errorType"] = type(error).__name__
        report["failureStage"] = stage
        completed = False
    finally:
        with signals.critical():
            if reader is not None and not reader.closed:
                reader.close()
            signals.restore()
    closure = None if reader is None else reader.public()
    completed_at = time.monotonic()
    report["closure"] = closure
    report["handlerRestoreErrors"] = list(signals.restore_errors)
    report["pendingSignal"] = signals.pending
    report["elapsedSeconds"] = completed_at - start
    report["deadlineMetAfterClosure"] = completed_at < until
    report["observationComplete"] = bool(completed and closure is not None
        and closure["allOwnedDescriptorsClosed"] and not closure["closeErrors"]
        and closure["lastNamedFullNineFence"] and not signals.restore_errors
        and signals.pending is None and completed_at < until)
    if report["predicateProjection"] is not None:
        report["allOriginalPredicatesPassed"] = all(
            x["originalCompositePredicate"]
            for x in report["predicateProjection"]["enabledHarnessOwners"])
    output = encoded(report) + b"\n"
    need(len(output) <= MAX_OUTPUT_BYTES, "fixed_public_output_bound")
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    signals.check()
    need(time.monotonic() < until, "original_deadline_after_public_flush")
    return 0 if report["observationComplete"] else 1

if __name__ == "__main__":
    try:
        exit_code = main()
    except BaseException:
        # Never write an exception message or private value to stderr.
        exit_code = 1
    sys.exit(exit_code)
