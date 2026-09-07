#!/usr/bin/env python3
"""Execute and semantically validate the complete H02 exact-head matrix.

The runner is deliberately read-only with respect to the repository. It binds
itself to the actual Git checkout, runs every required toolchain/seed/probe
combination without fail-fast truncation, preserves process and application
results, terminates timed-out process groups, and emits a digest-bound summary.

It does not grant qualification, dependency selection, compatibility, or any
operational authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, NamedTuple

SCHEMA_ID = "heptabao.h02-exact-head-matrix-summary.v1"
CANDIDATE_ID = "HB-DEP-RAFT-OPENRAFT"
CANDIDATE_VERSION = "0.10.0-alpha.33"
TOOLCHAINS = ("1.88.0", "1.98.0")
SEEDS = (
    "0x5eed20260828cafe",
    "0x8badf00d12345678",
    "0xd15ea5e5cafef00d",
)
EXPECTED_INMEMORY_CASES = {
    "raft-deterministic-apply-and-restart",
    "raft-committed-snapshot-conflict-rejected",
    "raft-joint-membership-single-writer",
    "raft-process-pause-plus-partition",
    "raft-quorum-loss-fail-closed",
    "raft-incomplete-run-replay-diagnostics",
}
EXPECTED_DURABLE_CASES = {
    "durable-three-node-fsync-and-replication",
    "durable-full-cluster-restart-and-read-index",
    "durable-post-restart-write-survives-second-restart",
    "durable-snapshot-state-atomic-generation-reopen",
    "durable-log-corruption-fails-closed",
    "durable-state-corruption-fails-closed",
    "durable-isolated-writer-does-not-advance-commit",
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MANIFEST = REPOSITORY_ROOT / "probes/h02/openraft-tokio/Cargo.toml"
APPLICATION_STATUSES = {
    "EXECUTED_PASS",
    "EXECUTED_FAIL",
    "BLOCKED",
    "UNKNOWN",
    "UNEXECUTED",
}


class ValidationError(RuntimeError):
    """A source binding or application result violated its contract."""


class Probe(NamedTuple):
    kind: str
    binary: str
    arguments: tuple[str, ...]
    validator: Callable[[str, str], str]
    status_extractor: Callable[[str], str | None]


class ProcessCapture(NamedTuple):
    process_started: bool
    exit_code: int | None
    timed_out: bool
    spawn_error: str | None
    stdout: bytes
    stderr: bytes


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return sha256_bytes(encoded)


def evidence_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return resolved.as_posix()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON members instead of silently choosing one."""

    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError(f"duplicate JSON object member: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> Any:
    """Reject NaN/Infinity extensions accepted by the stdlib decoder."""

    raise ValueError(f"non-standard JSON constant: {value}")


def strict_json(raw: str, label: str) -> Any:
    """Decode one unambiguous JSON value for probe application output."""

    try:
        return json.loads(
            raw,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError, ValidationError) as error:
        raise ValidationError(f"{label} is not unambiguous JSON: {error}") from error


def path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def git_text(*arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=REPOSITORY_ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise ValidationError(
            f"git {' '.join(arguments)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def verify_source_binding(
    *,
    repository: str,
    commit: str,
    tree: str,
    manifest: Path,
    output_dir: Path,
    target_root: Path,
) -> None:
    """Bind caller-supplied metadata to the actual immutable checkout."""

    require(repository == "TrillionniumFoundation/HeptaBao", "unexpected repository identity")
    require(HEX40.fullmatch(commit) is not None, "commit must be full lowercase 40-hex")
    require(HEX40.fullmatch(tree) is not None, "tree must be full lowercase 40-hex")

    actual_root = Path(git_text("rev-parse", "--show-toplevel")).resolve()
    require(actual_root == REPOSITORY_ROOT.resolve(), "script is not running from its Git root")
    require(git_text("rev-parse", "HEAD") == commit, "declared commit does not match HEAD")
    require(
        git_text("rev-parse", "HEAD^{tree}") == tree,
        "declared tree does not match HEAD tree",
    )
    require(
        git_text("status", "--porcelain=v1", "--untracked-files=all") == "",
        "repository checkout is not clean",
    )

    resolved_manifest = manifest.resolve()
    require(
        resolved_manifest == EXPECTED_MANIFEST.resolve(),
        "manifest path is not the canonical OpenRaft probe manifest",
    )
    require(resolved_manifest.is_file(), "canonical manifest is missing")
    require(resolved_manifest.with_name("Cargo.lock").is_file(), "committed lock is missing")

    require(
        not path_is_within(output_dir, REPOSITORY_ROOT),
        "output directory must be outside the repository",
    )
    require(
        not path_is_within(target_root, REPOSITORY_ROOT),
        "Cargo target root must be outside the repository",
    )


def require_authority_closed(value: dict[str, Any]) -> None:
    require(value.get("qualification") is False, "qualification must remain false")
    require(
        value.get("selection_effect") == "NONE",
        "selection_effect must remain NONE",
    )
    require(value.get("authority_effect") == "NONE", "authority_effect must remain NONE")


def parse_single_json(stdout: str) -> dict[str, Any]:
    value = strict_json(stdout, "stdout")
    require(isinstance(value, dict), "stdout JSON must be an object")
    return value


def parse_json_lines(stdout: str) -> list[dict[str, Any]]:
    lines = [line for line in stdout.splitlines() if line.strip()]
    require(lines, "stdout JSONL is empty")
    values: list[dict[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        value = strict_json(line, f"stdout JSONL line {index}")
        require(isinstance(value, dict), f"stdout JSONL line {index} is not an object")
        values.append(value)
    return values


def normalize_application_status(raw: Any) -> str | None:
    if raw == "PASS":
        return "EXECUTED_PASS"
    if raw == "FAIL":
        return "EXECUTED_FAIL"
    if isinstance(raw, str) and raw in APPLICATION_STATUSES:
        return raw
    return None


def combine_case_statuses(statuses: Iterable[Any]) -> str | None:
    normalized = [normalize_application_status(status) for status in statuses]
    if not normalized or any(status is None for status in normalized):
        return None
    values = set(normalized)
    for status in ("EXECUTED_FAIL", "BLOCKED", "UNKNOWN", "UNEXECUTED"):
        if status in values:
            return status
    return "EXECUTED_PASS" if values == {"EXECUTED_PASS"} else None


def extract_single_status(stdout: str) -> str | None:
    return normalize_application_status(parse_single_json(stdout).get("status"))


def extract_inmemory_status(stdout: str) -> str | None:
    values = parse_json_lines(stdout)
    if any(value.get("kind") == "harness_error" for value in values):
        return "BLOCKED"
    cases = [value for value in values if value.get("kind") == "case"]
    return combine_case_statuses(case.get("status") for case in cases)


def validate_identity(value: dict[str, Any], seed: str) -> None:
    require(value.get("candidate_id") == CANDIDATE_ID, "candidate_id drift")
    require(value.get("version") == CANDIDATE_VERSION, "candidate version drift")
    require(value.get("seed") == seed, "seed drift")
    require_authority_closed(value)


def validate_inmemory(stdout: str, seed: str) -> str:
    values = parse_json_lines(stdout)
    allowed_kinds = {"meta", "case", "harness_error"}
    unknown_kinds = [value.get("kind") for value in values if value.get("kind") not in allowed_kinds]
    require(not unknown_kinds, f"in-memory output contains unknown record kinds: {unknown_kinds!r}")
    meta = [value for value in values if value.get("kind") == "meta"]
    cases = [value for value in values if value.get("kind") == "case"]
    errors = [value for value in values if value.get("kind") == "harness_error"]
    require(len(meta) == 1, "in-memory output must contain exactly one meta object")
    require(not errors, "in-memory output contains a harness_error")
    validate_identity(meta[0], seed)
    require(
        meta[0].get("durability_class") == "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM",
        "in-memory durability boundary drift",
    )
    require(len(cases) == 6, "in-memory output must contain exactly six cases")
    case_ids = {str(case.get("case_id")) for case in cases}
    require(case_ids == EXPECTED_INMEMORY_CASES, "in-memory case set drift")
    failed = [case.get("case_id") for case in cases if case.get("status") != "PASS"]
    require(not failed, f"in-memory cases did not pass: {failed!r}")
    return "EXECUTED_PASS"


def validate_hostile(stdout: str, seed: str) -> str:
    value = parse_single_json(stdout)
    require(
        value.get("schema") == "heptabao.h02-openraft-hostile-snapshot-result.v1",
        "hostile result schema drift",
    )
    validate_identity(value, seed)
    status = normalize_application_status(value.get("status"))
    require(status == "EXECUTED_PASS", f"hostile application status is {status!r}")
    require(value.get("phase_reached") is True, "hostile injection phase was not reached")
    require(
        value.get("outcome") == "REJECTED_OR_ABORTED_AFTER_INJECTION",
        "hostile snapshot was not semantically rejected",
    )
    return status


def validate_blocker(stdout: str, seed: str) -> str:
    value = parse_single_json(stdout)
    require(
        value.get("schema") == "heptabao.h02-blocker-closure-result.v1",
        "blocker result schema drift",
    )
    validate_identity(value, seed)
    status = normalize_application_status(value.get("status"))
    require(status == "EXECUTED_PASS", f"blocker application status is {status!r}")
    components = value.get("components")
    require(isinstance(components, dict), "blocker components are missing")
    require(
        set(components) == {"os_suspend", "durable_faults", "clock_faults"},
        "blocker component set drift",
    )
    for name, component in components.items():
        require(isinstance(component, dict), f"blocker component {name} is not an object")
        require(
            normalize_application_status(component.get("status")) == "EXECUTED_PASS",
            f"blocker component {name} did not pass",
        )
        require_authority_closed(component)
    return status


def validate_durable(stdout: str, seed: str) -> str:
    value = parse_single_json(stdout)
    require(
        value.get("schema") == "heptabao.h02-openraft-durable-store-result.v1",
        "durable result schema drift",
    )
    validate_identity(value, seed)
    status = normalize_application_status(value.get("status"))
    require(status == "EXECUTED_PASS", f"durable application status is {status!r}")
    cases = value.get("cases")
    require(isinstance(cases, list) and len(cases) == 7, "durable result must contain seven cases")
    case_ids = {str(case.get("case_id")) for case in cases if isinstance(case, dict)}
    require(case_ids == EXPECTED_DURABLE_CASES, "durable case set drift")
    failed = [
        case.get("case_id")
        for case in cases
        if not isinstance(case, dict) or case.get("status") != "PASS"
    ]
    require(not failed, f"durable cases did not pass: {failed!r}")
    scope = value.get("scope")
    require(isinstance(scope, dict), "durable scope is missing")
    for key in (
        "raft_log_storage_implemented",
        "raft_state_machine_implemented",
        "state_machine_persisted_before_responder",
        "snapshot_state_atomic_bundle_publish",
        "state_publish_after_durable_write",
        "full_cluster_disk_restart",
        "read_index_after_restart",
        "corruption_rejected",
    ):
        require(scope.get(key) is True, f"durable scope flag not proven: {key}")
    require(
        type(scope.get("real_openraft_nodes")) is int
        and scope.get("real_openraft_nodes") == 3,
        "durable node count drift",
    )
    require(scope.get("kernel_power_loss") is False, "logical lab must not claim kernel power loss")
    require(scope.get("production_selected") is False, "durable candidate must remain unselected")
    return status


PROBES = (
    Probe(
        kind="inmemory",
        binary="heptabao-h02-openraft-inmemory-cluster",
        arguments=(),
        validator=validate_inmemory,
        status_extractor=extract_inmemory_status,
    ),
    Probe(
        kind="hostile",
        binary="heptabao-h02-openraft-fault-lab",
        arguments=("--mode", "hostile-snapshot-parent"),
        validator=validate_hostile,
        status_extractor=extract_single_status,
    ),
    Probe(
        kind="blocker",
        binary="heptabao-h02-openraft-blocker-closure-lab",
        arguments=("--mode", "all"),
        validator=validate_blocker,
        status_extractor=extract_single_status,
    ),
    Probe(
        kind="durable",
        binary="heptabao-h02-openraft-durable-store-lab",
        arguments=(),
        validator=validate_durable,
        status_extractor=extract_single_status,
    ),
)

# These values are deliberately derived from the ordered probe tuple above.
# Keeping the lookup keyed by ``kind`` makes the entry tuple contract explicit
# and gives downstream receipt validators one canonical matrix definition to
# import rather than accepting caller-supplied labels.
PROBES_BY_KIND = {probe.kind: probe for probe in PROBES}
CANONICAL_MANIFEST_RELATIVE = "probes/h02/openraft-tokio/Cargo.toml"
CANONICAL_LOCK_RELATIVE = "probes/h02/openraft-tokio/Cargo.lock"
SHA256_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
ENTRY_ID_PATTERN = re.compile(
    r"^(?P<kind>inmemory|hostile|blocker|durable)-"
    r"(?P<toolchain>1\.88\.0|1\.98\.0)-(?P<seed>[0-9a-f]{16})$"
)


def entry_id(probe: Probe, toolchain: str, seed: str) -> str:
    return f"{probe.kind}-{toolchain}-{seed.removeprefix('0x')}"


def parse_entry_id(value: Any) -> tuple[str, str, str]:
    """Parse and validate an exact-head matrix entry identifier.

    The hexadecimal suffix is not merely a shape check: it must be one of the
    three fixed seeds.  This prevents a syntactically valid, unplanned seed
    from being smuggled into a completion artifact.
    """

    require(isinstance(value, str), "entry_id must be a string")
    match = ENTRY_ID_PATTERN.fullmatch(value)
    require(match is not None, f"entry_id is not canonical: {value!r}")
    kind = match.group("kind")
    toolchain = match.group("toolchain")
    seed = "0x" + match.group("seed")
    require(kind in PROBES_BY_KIND, f"entry_id kind is not canonical: {kind}")
    require(toolchain in TOOLCHAINS, f"entry_id toolchain is not canonical: {toolchain}")
    require(seed in SEEDS, f"entry_id seed is not canonical: {seed}")
    return kind, toolchain, seed


def canonical_command(
    probe: Probe,
    toolchain: str,
    seed: str,
    *,
    manifest: Path | None = None,
) -> list[str]:
    """Build the argv used by the exact-head runner.

    ``manifest`` is optional only for small unit-test fixtures.  Production
    ``run_entry`` calls this with the resolved canonical manifest, so every
    emitted entry carries the complete reproducible argv.
    """

    command = [
        "cargo",
        f"+{toolchain}",
        "run",
        "--quiet",
        "--locked",
    ]
    if manifest is not None:
        # The runner executes with ``cwd=REPOSITORY_ROOT``.  Emit the
        # canonical repository-relative spelling when the supplied path is
        # that checkout's pinned manifest instead of leaking a per-runner
        # absolute workspace prefix into the digest-bound argv.  Receipts are
        # revalidated from a materialized source checkout during lane
        # arbitration; a relative spelling remains identical across those
        # roots while the separately bound manifest/lock digests still prove
        # which source bytes were executed.  Preserve custom absolute paths
        # for structural fixtures that intentionally exercise a non-canonical
        # temporary manifest.
        manifest_path = Path(manifest)
        try:
            is_canonical = manifest_path.resolve() == EXPECTED_MANIFEST.resolve()
        except (OSError, RuntimeError, ValueError):
            is_canonical = False
        manifest_argument = (
            CANONICAL_MANIFEST_RELATIVE if is_canonical else str(manifest)
        )
        command.extend(("--manifest-path", manifest_argument))
    command.extend(
        (
            "--bin",
            probe.binary,
            "--",
            *probe.arguments,
            "--seed",
            seed,
        )
    )
    return command


def _manifest_argument_is_canonical(value: str, expected_manifest: Path | None) -> bool:
    """Accept only the checkout-local canonical manifest path."""

    if not isinstance(value, str) or not value:
        return False
    try:
        candidate = Path(value)
        # Do not let ``../canonical/..`` or dot/symlink spellings collapse to
        # the expected path after resolution.  The runner emits the plain
        # relative spelling below; accepting only lexical components keeps the
        # command digest and its path binding deterministic.
        if any(part in {"", ".", ".."} for part in candidate.parts):
            return False
        if not candidate.parts:
            return False
        if not candidate.is_absolute():
            resolved = (REPOSITORY_ROOT / candidate).resolve()
            if resolved == (REPOSITORY_ROOT / CANONICAL_MANIFEST_RELATIVE).resolve():
                return True
            if expected_manifest is not None and resolved == expected_manifest.resolve():
                return True
            return False

        resolved = candidate.resolve()
        if expected_manifest is not None and resolved == expected_manifest.resolve():
            return True
        if resolved == EXPECTED_MANIFEST.resolve():
            return True
    except (OSError, RuntimeError, ValueError):
        return False

    # Do not accept an arbitrary path that merely ends in ``Cargo.toml``.  The
    # exact-head workflow validates the receipt in the same checkout that ran
    # the command, so an absolute path must resolve to that checkout's pinned
    # manifest (or the explicitly supplied expected manifest).
    return False


def validate_command_tuple(
    command: Any,
    probe: Probe,
    toolchain: str,
    seed: str,
    *,
    expected_manifest: Path | None = None,
    require_runner_flags: bool = False,
) -> None:
    """Validate argv semantics against one canonical matrix tuple.

    The command digest authenticates the exact list, while this parser binds
    the list's semantic fields to the probe/toolchain/seed.  Optional manifest
    and ``--quiet`` handling keeps legacy unit fixtures readable; completion
    receipt validation enables ``require_runner_flags`` for the production
    runner's full command shape.
    """

    require(isinstance(command, list), "command must be an argv list")
    require(command and all(isinstance(item, str) and item for item in command), "command argv is malformed")
    require(command[:3] == ["cargo", f"+{toolchain}", "run"], "command cargo/toolchain prefix drift")

    cursor = 3
    has_quiet = cursor < len(command) and command[cursor] == "--quiet"
    if has_quiet:
        cursor += 1
    require(not require_runner_flags or has_quiet, "command is missing canonical --quiet flag")

    require(cursor < len(command) and command[cursor] == "--locked", "command is missing canonical --locked flag")
    cursor += 1

    has_manifest = cursor < len(command) and command[cursor] == "--manifest-path"
    if has_manifest:
        require(cursor + 1 < len(command), "command manifest path is missing")
        require(
            _manifest_argument_is_canonical(command[cursor + 1], expected_manifest),
            "command manifest path is not canonical",
        )
        cursor += 2
    require(not require_runner_flags or has_manifest, "command is missing canonical --manifest-path")

    require(
        command[cursor : cursor + 2] == ["--bin", probe.binary],
        "command binary binding drift",
    )
    cursor += 2
    require(cursor < len(command) and command[cursor] == "--", "command is missing probe argument separator")
    cursor += 1
    expected_tail = [*probe.arguments, "--seed", seed]
    require(command[cursor:] == expected_tail, "command probe arguments or seed drift")


def validate_entry_tuple(
    entry: Mapping[str, Any],
    *,
    expected_manifest: Path | None = None,
    require_runner_flags: bool = False,
) -> tuple[str, str, str]:
    """Bind one retained entry's ID, labels, binary and command digest."""

    require(isinstance(entry, Mapping), "entry must be an object")
    kind, toolchain, seed = parse_entry_id(entry.get("entry_id"))
    probe = PROBES_BY_KIND[kind]
    require(entry.get("kind") == kind, "entry kind does not match entry_id")
    require(entry.get("toolchain") == toolchain, "entry toolchain does not match entry_id")
    require(entry.get("seed") == seed, "entry seed does not match entry_id")
    require(entry.get("binary") == probe.binary, "entry binary does not match canonical probe")

    command = entry.get("command")
    validate_command_tuple(
        command,
        probe,
        toolchain,
        seed,
        expected_manifest=expected_manifest,
        require_runner_flags=require_runner_flags,
    )
    require(
        entry.get("command_digest") == canonical_json_digest(command),
        "entry command_digest does not match exact argv",
    )
    return kind, toolchain, seed


def expected_entry_ids(
    toolchains: Iterable[str] = TOOLCHAINS,
    seeds: Iterable[str] = SEEDS,
    probes: Iterable[Probe] = PROBES,
) -> set[str]:
    return {
        entry_id(probe, toolchain, seed)
        for toolchain in toolchains
        for seed in seeds
        for probe in probes
    }


def validate_captured_result(
    probe: Probe,
    seed: str,
    stdout: str,
    exit_code: int | None,
    *,
    process_started: bool = True,
    timed_out: bool = False,
    spawn_error: str | None = None,
) -> tuple[str, str | None, list[str]]:
    """Return conclusion, application status and validation errors.

    Process exit status is necessary but not sufficient. Explicit BLOCKED,
    UNKNOWN and UNEXECUTED application states remain distinct instead of being
    collapsed into a generic process failure.
    """

    if spawn_error is not None or not process_started:
        detail = spawn_error or "process was not started"
        return "UNEXECUTED", None, [f"process could not be started: {detail}"]

    errors: list[str] = []
    application_status: str | None = None
    try:
        application_status = probe.status_extractor(stdout)
    except ValidationError as error:
        errors.append(f"application status extraction failed: {error}")

    try:
        validated_status = probe.validator(stdout, seed)
        if application_status is None:
            application_status = validated_status
        elif validated_status != application_status:
            errors.append(
                f"application status disagreement: extracted={application_status} "
                f"validated={validated_status}"
            )
    except ValidationError as error:
        errors.append(str(error))

    if timed_out:
        errors.append("process exceeded the bounded entry timeout")
    if exit_code is None:
        errors.append("process exit code is unavailable")
    elif type(exit_code) is not int:
        errors.append("process exit code is not a JSON integer")
    elif exit_code != 0:
        errors.append(f"process exit code was {exit_code}")

    if (
        not errors
        and application_status == "EXECUTED_PASS"
        and type(exit_code) is int
        and exit_code == 0
    ):
        return "PASS", application_status, []
    if timed_out or application_status == "BLOCKED":
        return "BLOCKED", application_status, errors
    if application_status == "UNEXECUTED":
        return "UNEXECUTED", application_status, errors
    if application_status == "UNKNOWN":
        return "UNKNOWN", application_status, errors
    return "FAIL", application_status, errors


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):
        process.kill()


def capture_process(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: int,
) -> ProcessCapture:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"),
        )
    except OSError as error:
        detail = f"{type(error).__name__}: {error}"
        return ProcessCapture(False, None, False, detail, b"", detail.encode("utf-8"))

    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        return ProcessCapture(True, process.returncode, False, None, stdout, stderr)
    except subprocess.TimeoutExpired:
        terminate_process_group(process)
        stdout, stderr = process.communicate()
        return ProcessCapture(True, process.returncode, True, None, stdout, stderr)


def run_entry(
    *,
    probe: Probe,
    toolchain: str,
    seed: str,
    manifest: Path,
    output_dir: Path,
    target_root: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    identifier = entry_id(probe, toolchain, seed)
    stdout_path = output_dir / f"{identifier}.stdout"
    stderr_path = output_dir / f"{identifier}.stderr"
    exit_path = output_dir / f"{identifier}.exit"
    command = canonical_command(probe, toolchain, seed, manifest=manifest)
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(Path(f"{target_root}-{toolchain}"))
    environment["CARGO_TERM_COLOR"] = "never"
    environment["RUST_BACKTRACE"] = "1"

    started_at = utc_now()
    started_monotonic = time.monotonic()
    captured = capture_process(
        command,
        cwd=REPOSITORY_ROOT,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )
    duration_ms = int((time.monotonic() - started_monotonic) * 1000)
    completed_at = utc_now()

    stdout_path.write_bytes(captured.stdout)
    stderr_path.write_bytes(captured.stderr)
    exit_path.write_text(
        "UNAVAILABLE\n" if captured.exit_code is None else f"{captured.exit_code}\n",
        encoding="utf-8",
    )
    # Keep a digest for the exit sidecar itself.  Recording only the numeric
    # ``exit_code`` is insufficient: a missing or substituted sidecar could
    # otherwise be presented alongside an otherwise valid stdout capture.
    # The completion validator re-reads this file and compares both its digest
    # and its canonical textual representation.
    exit_digest = sha256_file(exit_path)

    stdout = captured.stdout.decode("utf-8", errors="replace")
    conclusion, application_status, errors = validate_captured_result(
        probe,
        seed,
        stdout,
        captured.exit_code,
        process_started=captured.process_started,
        timed_out=captured.timed_out,
        spawn_error=captured.spawn_error,
    )
    return {
        "entry_id": identifier,
        "kind": probe.kind,
        "binary": probe.binary,
        "toolchain": toolchain,
        "seed": seed,
        "command": command,
        "command_digest": canonical_json_digest(command),
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_ms": duration_ms,
        "process_started": captured.process_started,
        "exit_code": captured.exit_code,
        "timed_out": captured.timed_out,
        "conclusion": conclusion,
        "application_status": application_status,
        "stdout_path": stdout_path.name,
        "stderr_path": stderr_path.name,
        "exit_path": exit_path.name,
        "stdout_digest": sha256_bytes(captured.stdout),
        "stderr_digest": sha256_bytes(captured.stderr),
        "exit_digest": exit_digest,
        "validation_errors": errors,
    }


def summarize_entries(entries: list[dict[str, Any]]) -> dict[str, int]:
    result = {"pass": 0, "fail": 0, "blocked": 0, "unknown": 0, "unexecuted": 0}
    for entry in entries:
        conclusion = entry.get("conclusion") if isinstance(entry, Mapping) else None
        if conclusion == "PASS":
            result["pass"] += 1
        elif conclusion == "FAIL":
            result["fail"] += 1
        elif conclusion == "BLOCKED":
            result["blocked"] += 1
        elif conclusion == "UNEXECUTED":
            result["unexecuted"] += 1
        else:
            result["unknown"] += 1
    return result


def _regular_evidence_file(root: Path, value: Any, label: str) -> Path:
    """Resolve one evidence path beneath ``root`` without following aliases.

    Matrix entries are uploaded as a directory tree.  A digest in the JSON is
    not useful if the path can escape that tree (or if a symlink is allowed to
    point at a different file), so path resolution is deliberately strict and
    fail-closed.  The canonical runner emits simple ``<entry_id>.<suffix>``
    names, but nested relative paths are accepted for downloaded artifact
    layouts as long as they remain beneath the supplied evidence root.
    """

    require(isinstance(root, Path), "evidence root must be a path")
    require(not root.is_symlink(), "evidence root must not be a symlink")
    require(root.is_dir(), "evidence root is missing or not a directory")
    require(isinstance(value, str) and value.strip(), f"{label} path is missing")
    relative = Path(value)
    require(not relative.is_absolute(), f"{label} path must be relative")
    require(".." not in relative.parts, f"{label} path may not contain '..'")
    candidate = root / relative
    require(not candidate.is_symlink(), f"{label} file must not be a symlink")
    resolved_root = root.resolve()
    resolved = candidate.resolve()
    require(path_is_within(resolved, resolved_root), f"{label} path escapes evidence root")
    require(resolved.is_file(), f"{label} file is missing or not a regular file")
    return resolved


def _safe_file_digest(path: Path, label: str) -> str:
    """Read one regular evidence file and return its SHA-256 digest."""

    require(not path.is_symlink(), f"{label} file must not be a symlink")
    require(path.is_file(), f"{label} file is missing or not a regular file")
    try:
        return sha256_file(path)
    except OSError as error:
        raise ValidationError(f"{label} file cannot be read: {error}") from error


def _digest_or_error(path: Path, label: str, errors: list[str]) -> str:
    """Return a schema-shaped digest while preserving a build error.

    ``build_summary`` is intentionally able to emit a partial, schema-valid
    failure summary when a runner loses an artifact.  A zero digest is never
    accepted as evidence by the receipt validator; it merely lets the partial
    summary retain a deterministic shape instead of crashing before writing
    diagnostics.
    """

    try:
        return _safe_file_digest(path, label)
    except ValidationError as error:
        errors.append(str(error))
        return "sha256:" + "0" * 64


def validate_artifact_files(
    summary: Mapping[str, Any],
    evidence_dir: Path | None,
    *,
    manifest: Path | None = None,
    lock: Path | None = None,
    require_all: bool = True,
) -> list[str]:
    """Recompute every H02 dependency and per-entry artifact digest.

    The function returns human-readable errors rather than raising so the
    matrix runner can preserve a complete partial summary.  A caller that is
    validating a completion receipt should reject any returned error.  Every
    entry must carry three regular files (stdout, stderr and exit), matching
    the stored digest; the exit sidecar is also checked against the recorded
    process exit code.  Dependency manifest/lock paths and digests are bound
    to the actual checkout files.
    """

    errors: list[str] = []
    if evidence_dir is None:
        return ["artifact evidence directory is required for H02 binding"]
    root = Path(evidence_dir)
    if not root.exists() or not root.is_dir() or root.is_symlink():
        return ["artifact evidence directory is missing, not a directory, or a symlink"]

    dependency = summary.get("dependency_binding")
    if not isinstance(dependency, Mapping):
        errors.append("dependency_binding is missing")
    else:
        expected_manifest_path = evidence_path(manifest or (REPOSITORY_ROOT / CANONICAL_MANIFEST_RELATIVE))
        expected_lock_path = evidence_path(lock or (REPOSITORY_ROOT / CANONICAL_LOCK_RELATIVE))
        for field, expected_path in (
            ("manifest_path", expected_manifest_path),
            ("lock_path", expected_lock_path),
        ):
            if dependency.get(field) != expected_path:
                errors.append(f"dependency {field} is not bound to the executed file")
        # Dependency files live in the checkout, not in the matrix output
        # directory.  Resolve from this runner's repository root and bind the
        # exact bytes used to produce the matrix.
        manifest = manifest or (REPOSITORY_ROOT / CANONICAL_MANIFEST_RELATIVE)
        lock = lock or (REPOSITORY_ROOT / CANONICAL_LOCK_RELATIVE)
        for path, digest_field, label in (
            (manifest, "manifest_digest", "H02 manifest"),
            (lock, "lock_digest", "H02 Cargo.lock"),
        ):
            expected = dependency.get(digest_field)
            if not isinstance(expected, str) or SHA256_DIGEST_PATTERN.fullmatch(expected) is None:
                errors.append(f"dependency {digest_field} is malformed")
                continue
            try:
                actual = _safe_file_digest(path, label)
            except ValidationError as error:
                errors.append(str(error))
            else:
                if actual != expected:
                    errors.append(f"{label} digest does not match summary")

    entries = summary.get("entries")
    if not isinstance(entries, list):
        return errors + ["entries is missing or not an array"]

    seen: set[Path] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            errors.append(f"entry[{index}] is not an object")
            continue
        identifier = entry.get("entry_id")
        if not isinstance(identifier, str) or not identifier:
            errors.append(f"entry[{index}] has no canonical entry_id")
            continue
        for suffix, path_field, digest_field in (
            ("stdout", "stdout_path", "stdout_digest"),
            ("stderr", "stderr_path", "stderr_digest"),
            ("exit", "exit_path", "exit_digest"),
        ):
            expected_name = f"{identifier}.{suffix}"
            declared_path = entry.get(path_field)
            if declared_path != expected_name:
                errors.append(
                    f"entry {identifier} {path_field} must be {expected_name!r}"
                )
            try:
                path = _regular_evidence_file(
                    root, declared_path, f"entry {identifier} {suffix}"
                )
            except ValidationError as error:
                errors.append(str(error))
                continue
            if path in seen:
                errors.append(f"entry {identifier} {suffix} path is duplicated")
            seen.add(path)
            expected_digest = entry.get(digest_field)
            if not isinstance(expected_digest, str) or SHA256_DIGEST_PATTERN.fullmatch(expected_digest) is None:
                errors.append(f"entry {identifier} {digest_field} is malformed")
                continue
            try:
                raw = path.read_bytes()
            except OSError as error:
                errors.append(f"entry {identifier} {suffix} file cannot be read: {error}")
                continue
            actual_digest = sha256_bytes(raw)
            if actual_digest != expected_digest:
                errors.append(f"entry {identifier} {suffix} digest does not match summary")
            if suffix == "exit":
                exit_code = entry.get("exit_code")
                if exit_code is not None and type(exit_code) is not int:
                    errors.append(f"entry {identifier} exit_code is not a JSON integer or null")
                    continue
                expected_exit = (
                    b"UNAVAILABLE\n"
                    if exit_code is None
                    else f"{exit_code}\n".encode("utf-8")
                )
                if raw != expected_exit:
                    errors.append(f"entry {identifier} exit sidecar content does not match exit_code")

    if require_all and len(seen) != 3 * len(entries):
        errors.append("H02 entry artifact paths are not unique")
    return errors


def build_summary(
    *,
    repository: str,
    ref: str,
    commit: str,
    tree: str,
    manifest: Path,
    lock: Path,
    entries: list[dict[str, Any]],
    started_at: str,
    completed_at: str,
    evidence_dir: Path | None = None,
    require_artifacts: bool = False,
    runner_errors: list[str] | None = None,
    clean_tree: bool = True,
) -> dict[str, Any]:
    """Build a schema-shaped matrix summary.

    ``require_artifacts=True`` is used by the executable runner and makes the
    result fail closed unless ``evidence_dir`` contains every sidecar.  The
    default keeps small structural/unit fixtures (which intentionally have no
    filesystem captures) usable; such summaries are never accepted by the
    digest-bound technical receipt validator, which always supplies an
    evidence root.
    """
    required_ids = expected_entry_ids()
    tuple_errors: list[str] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            tuple_errors.append(f"entry[{index}] tuple invalid: entry must be an object")
            continue
        try:
            validate_entry_tuple(
                entry,
                expected_manifest=manifest,
                require_runner_flags=True,
            )
        except ValidationError as error:
            tuple_errors.append(f"entry[{index}] tuple invalid: {error}")

    entry_ids = [
        str(entry.get("entry_id")) if isinstance(entry, Mapping) else "<invalid-entry>"
        for entry in entries
    ]
    actual_ids = set(entry_ids)
    counts = summarize_entries(entries)
    missing_ids = sorted(required_ids - actual_ids)
    unexpected_ids = sorted(actual_ids - required_ids)
    duplicate_ids = sorted({identifier for identifier in entry_ids if entry_ids.count(identifier) > 1})
    errors = list(runner_errors or [])
    errors.extend(tuple_errors)
    # Dependency bytes and every per-entry sidecar are part of the summary's
    # evidence contract.  Keep emitting a partial summary when a file is
    # missing, but never allow a complete matrix to become PASS without a
    # directory-level re-read of all artifacts.
    manifest_digest = _digest_or_error(manifest, "H02 manifest", errors)
    lock_digest = _digest_or_error(lock, "H02 Cargo.lock", errors)
    if evidence_dir is not None or require_artifacts:
        errors.extend(
            validate_artifact_files(
                {
                    "dependency_binding": {
                        "manifest_path": evidence_path(manifest),
                        "manifest_digest": manifest_digest,
                        "lock_path": evidence_path(lock),
                        "lock_digest": lock_digest,
                    },
                    "entries": entries,
                },
                evidence_dir,
                manifest=manifest,
                lock=lock,
            )
        )
    result = (
        "PASS"
        if len(entries) == len(required_ids)
        and not missing_ids
        and not unexpected_ids
        and not duplicate_ids
        and not errors
        and counts
        == {"pass": 24, "fail": 0, "blocked": 0, "unknown": 0, "unexecuted": 0}
        else "FAIL"
    )
    return {
        "schema": SCHEMA_ID,
        "source_binding": {
            "repository": repository,
            "ref": ref,
            "commit": commit,
            "tree": tree,
            # Source cleanliness is an independent Git fact.  Do not infer it
            # from semantic/entry validation errors: a dirty tree and a failed
            # probe are distinct execution-policy states.
            "clean_tree": clean_tree,
        },
        "dependency_binding": {
            "manifest_path": evidence_path(manifest),
            "manifest_digest": manifest_digest,
            "lock_path": evidence_path(lock),
            "lock_digest": lock_digest,
        },
        "matrix": {
            "toolchains": list(TOOLCHAINS),
            "seeds": list(SEEDS),
            "kinds": [probe.kind for probe in PROBES],
            "required_entry_count": len(required_ids),
            "executed_entry_count": sum(
                1
                for entry in entries
                if isinstance(entry, Mapping) and entry.get("process_started") is True
            ),
            "missing_entry_ids": missing_ids,
            "unexpected_entry_ids": unexpected_ids,
            "duplicate_entry_ids": duplicate_ids,
        },
        "started_at": started_at,
        "completed_at": completed_at,
        "entries": entries,
        "counts": counts,
        "runner_errors": errors,
        "result": result,
        "qualification": False,
        "compatibility_claim": False,
        "selection_effect": "NONE",
        "authority_effect": "NONE",
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cargo-target-root", type=Path, required=True)
    parser.add_argument("--entry-timeout-seconds", type=int, default=180)
    return parser.parse_args(argv)


def current_source_errors(commit: str, tree: str) -> list[str]:
    errors: list[str] = []
    try:
        if git_text("rev-parse", "HEAD") != commit:
            errors.append("HEAD changed during matrix execution")
        if git_text("rev-parse", "HEAD^{tree}") != tree:
            errors.append("HEAD tree changed during matrix execution")
        if git_text("status", "--porcelain=v1", "--untracked-files=all") != "":
            errors.append("repository became dirty during matrix execution")
    except ValidationError as error:
        errors.append(str(error))
    return errors


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.ref.strip():
        print("ref must be non-empty", file=sys.stderr)
        return 2
    if not 1 <= args.entry_timeout_seconds <= 900:
        print("entry timeout must be between 1 and 900 seconds", file=sys.stderr)
        return 2

    manifest = args.manifest.resolve()
    output_dir = args.output_dir.resolve()
    target_root = args.cargo_target_root.resolve()
    try:
        verify_source_binding(
            repository=args.repository,
            commit=args.commit,
            tree=args.tree,
            manifest=manifest,
            output_dir=output_dir,
            target_root=target_root,
        )
    except ValidationError as error:
        print(f"source binding failed: {error}", file=sys.stderr)
        return 2

    lock = manifest.with_name("Cargo.lock")
    output_dir.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    entries: list[dict[str, Any]] = []
    for toolchain in TOOLCHAINS:
        for seed in SEEDS:
            for probe in PROBES:
                entry = run_entry(
                    probe=probe,
                    toolchain=toolchain,
                    seed=seed,
                    manifest=manifest,
                    output_dir=output_dir,
                    target_root=target_root,
                    timeout_seconds=args.entry_timeout_seconds,
                )
                entries.append(entry)
                print(
                    f"{entry['entry_id']}: {entry['conclusion']} "
                    f"exit={entry['exit_code']} app={entry['application_status']}",
                    flush=True,
                )

    completed_at = utc_now()
    runner_errors = current_source_errors(args.commit, args.tree)
    try:
        clean_tree = git_text("status", "--porcelain=v1", "--untracked-files=all") == ""
    except ValidationError:
        clean_tree = False
    summary = build_summary(
        repository=args.repository,
        ref=args.ref,
        commit=args.commit,
        tree=args.tree,
        manifest=manifest,
        lock=lock,
        entries=entries,
        started_at=started_at,
        completed_at=completed_at,
        evidence_dir=output_dir,
        require_artifacts=True,
        runner_errors=runner_errors,
        clean_tree=clean_tree,
    )
    summary_path = output_dir / "matrix-summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "summary": str(summary_path),
                "result": summary["result"],
                "counts": summary["counts"],
                "runner_errors": summary["runner_errors"],
                "qualification": False,
                "authority_effect": "NONE",
            },
            sort_keys=True,
        )
    )
    return 0 if summary["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
