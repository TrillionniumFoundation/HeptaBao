#!/usr/bin/env python3
"""Bounded safety-outcome replay; never deterministic-scheduler equivalence.

Only six validated diagnostic leaves may differ. Raw bytes and V1 hashing are
never changed. Both complete streams must independently satisfy this contract.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

CONTRACT_ID = "heptabao.h02-inmemory-bounded-semantic-replay.v1"
CASES = (
    "raft-deterministic-apply-and-restart",
    "raft-committed-snapshot-conflict-rejected",
    "raft-joint-membership-single-writer",
    "raft-process-pause-plus-partition",
    "raft-quorum-loss-fail-closed",
    "raft-incomplete-run-replay-diagnostics",
)
ASSERTIONS = (4, 8, 3, 3, 2, 3)
RPC_KEYS = ("append_entries", "vote", "pre_vote", "full_snapshot")
ALLOWED_PATHS = frozenset((
    f"{CASES[3]}.detail.new_leader", f"{CASES[4]}.detail.isolated_leader",
    *(f"{CASES[5]}.detail.rpc_counts.{key}" for key in RPC_KEYS),
))
U64_MAX = (1 << 64) - 1
LOG_ID = re.compile(r"T([0-9]+)-N([0-9]+)\.([0-9]+)")
DETAIL_KEYS = (
    {"real_raft_nodes", "baseline_index", "replicated_before_restart", "fresh_state_machine_replayed"},
    {"snapshot_index", "full_snapshot_rpc_seen", "committed_index_monotonic", "lagging_node_converged", "hostile_snapshot_conflict_injection", "hostile_snapshot_phase_reached", "hostile_guarded_state_unchanged", "hostile_snapshot_observation"},
    {"voters", "leaders_reported", "read_index_linearizable"},
    {"transport_paused_node", "new_leader", "old_leader_write_rejected", "new_leader_write_committed", "os_process_pause"},
    {"isolated_leader", "write_rejected_or_timed_out", "committed_index_not_advanced"},
    {"seed", "fault_plan", "last_event_index", "rpc_counts"},
)
STATE_KEYS = {"last_log_index", "local_committed", "cluster_committed", "last_applied", "snapshot", "purged", "state_machine_last_applied", "client_status"}
OBSERVATION_KEYS = {"phase_reached", "outcome", "transport_outcome", "transport_detail", "guarded_state_unchanged", "metrics_unchanged", "state_machine_unchanged", "stale_snapshot_log_id", "original_snapshot_log_id", "before", "after"}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate-json-key:{key}")
        result[key] = value
    return result


def invalid_constant(value: str) -> Any:
    raise ValueError(f"non-json-constant:{value}")


def finite_float(value: str) -> float:
    result = float(value)
    require(math.isfinite(result), "non-finite-json-number")
    return result


def parse(raw: str) -> list[dict[str, Any]]:
    result = []
    for line in raw.splitlines():
        if line.strip():
            value = json.loads(line, object_pairs_hook=strict_object, parse_constant=invalid_constant, parse_float=finite_float)
            require(isinstance(value, dict), "record-not-object")
            result.append(value)
    return result


def positive_u64(value: Any, name: str) -> int:
    require(type(value) is int and 0 < value <= U64_MAX, f"invalid-positive-u64:{name}")
    return value


def log_id(value: Any, name: str, *, optional: bool = False) -> tuple[int, int, int] | None:
    if optional and value is None:
        return None
    match = LOG_ID.fullmatch(value) if isinstance(value, str) else None
    require(match is not None, f"invalid-log-id:{name}")
    assert match is not None
    result = tuple(int(part) for part in match.groups())
    require(all(part <= U64_MAX for part in result) and result[1] in {1, 2, 3}, f"invalid-log-id-domain:{name}")
    return result


def fault_plan(seed: str) -> list[int]:
    state = int(seed, 16) ^ 0x004348414F53
    result = [1, 2, 3, 4, 5, 6]
    for index in range(len(result) - 1, 0, -1):
        state = (state + 0x9E3779B97F4A7C15) & U64_MAX
        value = ((state ^ (state >> 30)) * 0xBF58476D1CE4E5B9) & U64_MAX
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & U64_MAX
        value ^= value >> 31
        swap = value % (index + 1)
        result[index], result[swap] = result[swap], result[index]
    return result


def validate(records: list[dict[str, Any]], seed: str) -> None:
    require(len(records) == 7, "expected-one-meta-and-six-ordered-cases")
    expected_meta = {
        "kind": "meta", "candidate_id": "HB-DEP-RAFT-OPENRAFT", "version": "0.10.0-alpha.33",
        "profile_id": "HB-H02-BEHAVIOR-RAFT-OPENRAFT-INMEMORY-0_10_0_ALPHA_33", "domain": "RAFT",
        "seed": seed, "execution_scope": "REAL_OPENRAFT_INMEMORY_CLUSTER_WITH_TEST_MEMSTORE",
        "durability_class": "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM", "qualification": False,
        "selection_effect": "NONE", "authority_effect": "NONE",
    }
    require(canonical(records[0]) == canonical(expected_meta), "meta-contract-mismatch")
    details = []
    for index, record in enumerate(records[1:]):
        require(set(record) == {"kind", "case_id", "status", "assertion_count", "detail"}, "case-envelope-keys")
        require(record["kind"] == "case" and record["case_id"] == CASES[index], "case-order-or-identity")
        require(record["status"] == "PASS", f"case-not-pass:{CASES[index]}")
        require(type(record["assertion_count"]) is int and record["assertion_count"] == ASSERTIONS[index], "assertion-count")
        detail = record["detail"]
        require(isinstance(detail, dict) and set(detail) == DETAIL_KEYS[index], f"detail-keys:{CASES[index]}")
        details.append(detail)
    restart, snapshot, membership, pause, quorum, diagnostics = details
    require(type(restart["real_raft_nodes"]) is int and restart["real_raft_nodes"] == 3, "real-node-count")
    baseline = positive_u64(restart["baseline_index"], "baseline-index")
    # Bootstrap commits initial membership, election blank, two learner
    # memberships, then joint/uniform voter memberships at indices >=0..5.
    require(baseline >= 9, "restart-missing-bootstrap-and-four-seeded-writes")
    require(restart["replicated_before_restart"] is True and restart["fresh_state_machine_replayed"] is True, "restart-safety")
    boundary = positive_u64(snapshot["snapshot_index"], "snapshot-index")
    require(boundary >= baseline + 6, "snapshot-missing-six-writes")
    for key in ("full_snapshot_rpc_seen", "committed_index_monotonic", "lagging_node_converged", "hostile_snapshot_phase_reached", "hostile_guarded_state_unchanged"):
        require(snapshot[key] is True, f"snapshot-safety:{key}")
    require(snapshot["hostile_snapshot_conflict_injection"] == "EXECUTED_REJECTED", "hostile-injection-not-rejected")
    observation = snapshot["hostile_snapshot_observation"]
    require(isinstance(observation, dict) and set(observation) == OBSERVATION_KEYS, "hostile-observation-keys")
    for key in ("phase_reached", "guarded_state_unchanged", "metrics_unchanged", "state_machine_unchanged"):
        require(observation[key] is True, f"hostile-safety:{key}")
    require(observation["outcome"] == "REJECTED", "hostile-outcome")
    require(observation["transport_outcome"] in {"ACKNOWLEDGED", "REJECTED_WITH_ERROR"}, "hostile-transport-outcome")
    require(isinstance(observation["transport_detail"], str) and bool(observation["transport_detail"]), "hostile-transport-detail")
    before, after = observation["before"], observation["after"]
    require(isinstance(before, dict) and isinstance(after, dict) and set(before) == set(after) == STATE_KEYS, "hostile-state-keys")
    require(canonical(before) == canonical(after), "hostile-before-after-state-changed")
    stale = log_id(observation["stale_snapshot_log_id"], "stale-snapshot")
    original = log_id(observation["original_snapshot_log_id"], "original-snapshot")
    assert stale is not None and original is not None
    # The native helper awaits one node-1 write, then six distinct writes,
    # before waiting for a snapshot covering the last write. Elections may add
    # entries, so this is a minimum gap, not a sample-specific exact offset.
    require(stale[1] == 1, "hostile-stale-write-not-from-node-one")
    require(stale[0] >= 1 and stale[2] >= 6, "hostile-stale-write-before-complete-bootstrap")
    require(original[2] >= stale[2] + 6, "hostile-snapshot-missing-six-subsequent-writes")
    last_index = positive_u64(before["last_log_index"], "last-log-index")
    require(last_index >= original[2], "original-snapshot-not-in-log")
    boundaries = {}
    for key in ("local_committed", "cluster_committed", "last_applied", "state_machine_last_applied"):
        value = log_id(before[key], key)
        assert value is not None
        require(original[2] <= value[2] <= last_index, f"hostile-boundary-outside-caught-up-log:{key}")
        boundaries[key] = value
    require(boundaries["last_applied"] == boundaries["state_machine_last_applied"], "hostile-applied-state-disagreement")
    require(boundaries["last_applied"][2] <= boundaries["local_committed"][2], "hostile-apply-commit-order")
    snapshot_id = log_id(before["snapshot"], "snapshot", optional=True)
    purged_id = log_id(before["purged"], "purged", optional=True)
    require(snapshot_id is None or snapshot_id[2] <= boundaries["last_applied"][2], "hostile-snapshot-ahead-of-applied")
    require(purged_id is None or (snapshot_id is not None and purged_id[2] <= snapshot_id[2]), "hostile-purge-without-covering-snapshot")
    # Log identities at the same index cannot contradict one another. This
    # contract requires a caught-up observation, not arbitrary follower lag.
    identities = {}
    for value in (stale, original, *boundaries.values(), snapshot_id, purged_id):
        if value is not None:
            require(value[2] not in identities or identities[value[2]] == value, "hostile-same-index-log-identity-disagreement")
            identities[value[2]] = value
    # The pinned memstore uses OpenRaft's advanced LeaderId, ordered by
    # (term, node_id). Different leaders in one term are legal; decreasing
    # leadership along this committed log is not. Comparing terms alone or
    # requiring one node per term would encode the wrong protocol contract.
    ordered = [identities[index] for index in sorted(identities)]
    require(all(left[:2] <= right[:2] for left, right in zip(ordered, ordered[1:])), "hostile-committed-leader-order-regression")
    require(canonical(before["client_status"]) == canonical({"heptabao-h02-linearizable-register": f"inmemory-latest-5-{seed[2:]}"}), "hostile-client-state-not-seed-bound")
    require(canonical(membership["voters"]) == b"[1,2,3]" and canonical(membership["leaders_reported"]) == b"[1]", "membership-leader-set")
    require(membership["read_index_linearizable"] is True, "read-index-not-linearizable")
    require(type(pause["transport_paused_node"]) is int and pause["transport_paused_node"] == 1, "paused-node")
    require(type(pause["new_leader"]) is int and pause["new_leader"] in {2, 3}, "successor-domain")
    require(pause["old_leader_write_rejected"] is True and pause["new_leader_write_committed"] is True, "partition-write-safety")
    require(pause["os_process_pause"] == "NOT_EXECUTED_PROMOTION_BLOCKER", "os-process-pause-claim")
    require(type(quorum["isolated_leader"]) is int and quorum["isolated_leader"] in {1, 2, 3}, "quorum-leader-domain")
    require(quorum["write_rejected_or_timed_out"] is True and quorum["committed_index_not_advanced"] is True, "quorum-safety")
    require(diagnostics["seed"] == seed, "diagnostic-seed")
    require(canonical(diagnostics["fault_plan"]) == canonical(fault_plan(seed)), "seeded-fault-plan")
    require(type(diagnostics["last_event_index"]) is int and diagnostics["last_event_index"] == int(seed, 16) % 6, "seeded-event-index")
    counts = diagnostics["rpc_counts"]
    require(isinstance(counts, dict) and set(counts) == set(RPC_KEYS), "rpc-counter-keys")
    for key in RPC_KEYS:
        positive_u64(counts[key], f"rpc-count:{key}")


def differences(first: Any, replay: Any, path: str = "") -> list[dict[str, Any]]:
    if canonical(first) == canonical(replay):
        return []
    if isinstance(first, dict) and isinstance(replay, dict) and set(first) == set(replay):
        return [row for key in sorted(first) for row in differences(first[key], replay[key], f"{path}.{key}" if path else key)]
    return [{"path": path, "first": first, "replay": replay}]


def compare(first_raw: str, replay_raw: str, seed: str) -> dict[str, Any]:
    sides = []
    violations = []
    raw_details = {}
    for label, raw in (("first", first_raw), ("replay", replay_raw)):
        records = []
        try:
            records = parse(raw)
            validate(records, seed)
        except (ValueError, TypeError, KeyError, OverflowError) as error:
            violations.append(f"{label}:{error}")
        sides.append(records)
        raw_details[label] = {record["case_id"]: digest(record["detail"]) for record in records if record.get("case_id") in CASES and "detail" in record}
    changes = []
    if not violations:
        changes = differences(sides[0][0], sides[1][0], "meta")
        for first, replay in zip(sides[0][1:], sides[1][1:]):
            changes.extend(differences(first, replay, first["case_id"]))
        for change in changes:
            if change["path"] not in ALLOWED_PATHS:
                violations.append(f"non-allowlisted-replay-drift:{change['path']}")
    return {
        "contract_id": CONTRACT_ID,
        "matched": not violations,
        "violations": violations,
        "permitted_differences": [change for change in changes if change["path"] in ALLOWED_PATHS],
        "raw_case_details_sha256": raw_details,
    }
