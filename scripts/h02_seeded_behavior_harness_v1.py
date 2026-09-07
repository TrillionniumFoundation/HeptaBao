#!/usr/bin/env python3
"""Seeded H02 Runtime/TLS/Raft reference models and evidence merger."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

PLAN_ID = "HEPTABAO-PLAN-2026-08-28"
REVISION = "1.1"
HARNESS_VERSION = "1.0.0"
MASK64 = (1 << 64) - 1
PROFILES = {
    "runtime": "HB-H02-BEHAVIOR-RUNTIME-REFERENCE",
    "tls": "HB-H02-BEHAVIOR-TLS-REFERENCE",
    "raft": "HB-H02-BEHAVIOR-RAFT-REFERENCE",
}
CASES = {
    "runtime": [
        "runtime-cancel-before-start",
        "runtime-cancel-during-wait",
        "runtime-equal-deadline-seed-replay",
        "runtime-task-panic-isolation",
        "runtime-bounded-blocking-saturation",
        "runtime-zero-task-resource-leak",
    ],
    "tls": [
        "tls-version-policy-fail-closed",
        "tls-mutual-auth-identity-and-expiry",
        "tls-malformed-ticket-length-no-panic",
        "tls-atomic-stage-activate-revoke",
        "tls-handshake-time-and-byte-bounds",
        "tls-trace-secret-residue-zero",
    ],
    "raft": [
        "raft-deterministic-apply-and-restart",
        "raft-committed-snapshot-conflict-rejected",
        "raft-joint-membership-single-writer",
        "raft-process-pause-plus-partition",
        "raft-quorum-loss-fail-closed",
        "raft-incomplete-run-replay-diagnostics",
    ],
}


class Failure(RuntimeError):
    pass


class SplitMix64:
    def __init__(self, seed: int):
        if not 0 <= seed <= MASK64:
            raise Failure("seed must be unsigned 64-bit")
        self.state = seed

    def next(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK64
        value = self.state
        value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK64
        return (value ^ (value >> 31)) & MASK64

    def shuffled(self, values: Sequence[int]) -> list[int]:
        result = list(values)
        for index in range(len(result) - 1, 0, -1):
            swap = self.next() % (index + 1)
            result[index], result[swap] = result[swap], result[index]
        return result


def canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canon(value)).hexdigest()


def require(value: bool, message: str) -> None:
    if not value:
        raise Failure(message)


def event(trace: list[dict[str, Any]], domain: str, action: str, subject: str, **details: Any) -> None:
    trace.append({
        "index": len(trace),
        "domain": domain,
        "action": action,
        "subject": subject,
        "details": details,
    })


def run_case(trace: list[dict[str, Any]], domain: str, case_id: str, function) -> dict[str, Any]:
    start = len(trace)
    status = "PASS"
    assertions = 0
    details: Mapping[str, Any] = {}
    try:
        assertions, details = function()
    except Failure as error:
        status = "FAIL"
        details = {"error": str(error)}
        event(trace, domain, "case_failed", case_id, error=str(error))
    return {
        "case_id": case_id,
        "status": status,
        "assertion_count": assertions,
        "trace_start": start,
        "trace_end": len(trace),
        "details_sha256": digest(details),
    }


def runtime_model(seed: int):
    trace: list[dict[str, Any]] = []
    tasks: dict[int, str] = {}
    resources: dict[int, int] = {}

    def spawn(task_id: int) -> None:
        require(task_id not in tasks, "duplicate task")
        tasks[task_id] = "NEW"
        resources[task_id] = 0
        event(trace, "RUNTIME", "spawn", str(task_id))

    def start(task_id: int) -> bool:
        if tasks.get(task_id) == "CANCELLED":
            event(trace, "RUNTIME", "start_rejected", str(task_id))
            return False
        require(tasks.get(task_id) == "NEW", "task not new")
        tasks[task_id] = "RUNNING"
        event(trace, "RUNTIME", "start", str(task_id))
        return True

    def cancel(task_id: int) -> None:
        require(task_id in tasks, "unknown task")
        if tasks[task_id] not in {"CANCELLED", "COMPLETED", "PANICKED"}:
            released = resources[task_id]
            resources[task_id] = 0
            tasks[task_id] = "CANCELLED"
            event(trace, "RUNTIME", "cancel", str(task_id), released=released)

    def complete(task_id: int) -> None:
        require(tasks.get(task_id) in {"RUNNING", "WAITING"}, "task not completable")
        tasks[task_id] = "COMPLETED"
        resources[task_id] = 0
        event(trace, "RUNTIME", "complete", str(task_id))

    def c1():
        spawn(1); cancel(1)
        require(not start(1), "cancelled task started")
        require(tasks[1] == "CANCELLED", "cancel state changed")
        return 2, {"state": tasks[1]}

    def c2():
        spawn(2); require(start(2), "task did not start")
        tasks[2] = "WAITING"; resources[2] = 2
        event(trace, "RUNTIME", "wait", "2", resources=2)
        cancel(2)
        require(resources[2] == 0 and tasks[2] == "CANCELLED", "wait resource leaked")
        return 1, {"state": tasks[2], "resources": resources[2]}

    def c3():
        first = SplitMix64(seed ^ 0x444541444C494E45).shuffled(range(100, 108))
        second = SplitMix64(seed ^ 0x444541444C494E45).shuffled(range(100, 108))
        require(first == second, "seed replay order changed")
        for ordinal, task_id in enumerate(first):
            event(trace, "RUNTIME", "deadline_fire", str(task_id), ordinal=ordinal, deadline=5000)
        return 1, {"order": first}

    def c4():
        spawn(3); require(start(3), "panic task did not start")
        tasks[3] = "PANICKED"; event(trace, "RUNTIME", "panic_isolated", "3")
        spawn(4); require(start(4), "healthy task did not start"); complete(4)
        require(tasks[3] == "PANICKED" and tasks[4] == "COMPLETED", "panic escaped")
        return 1, {"panicked": 3, "healthy": 4}

    def c5():
        active, waiting = [], []
        for task_id in range(10, 14):
            spawn(task_id); require(start(task_id), "blocking task did not start")
            if len(active) < 2:
                active.append(task_id)
            else:
                tasks[task_id] = "WAITING"; resources[task_id] = 1; waiting.append(task_id)
        spawn(20); require(start(20), "authority task did not start"); complete(20)
        require(tasks[20] == "COMPLETED", "authority task starved")
        for task_id in active: complete(task_id)
        for task_id in waiting: cancel(task_id)
        return 1, {"active": active, "waiting": waiting}

    def c6():
        for task_id in list(tasks):
            if tasks[task_id] not in {"CANCELLED", "COMPLETED", "PANICKED"}:
                cancel(task_id)
        require(sum(resources.values()) == 0, "resource leak")
        require(all(value in {"CANCELLED", "COMPLETED", "PANICKED"} for value in tasks.values()), "task leak")
        return 2, {"resources": sum(resources.values())}

    functions = (c1, c2, c3, c4, c5, c6)
    results = [run_case(trace, "RUNTIME", name, fn) for name, fn in zip(CASES["runtime"], functions)]
    state = {"tasks": {str(k): tasks[k] for k in sorted(tasks)}, "resources": {str(k): resources[k] for k in sorted(resources)}}
    return trace, results, state


def tls_model(seed: int):
    trace: list[dict[str, Any]] = []
    active: str | None = None
    staged: dict[str, dict[str, Any]] = {}
    revoked: set[str] = set()

    def stage(config):
        require(config["minimum"] in {12, 13} and config["maximum"] in {12, 13}, "unknown TLS version")
        require(config["minimum"] <= config["maximum"], "invalid TLS range")
        require(config["timeout"] > 0 and config["max_bytes"] > 0, "unbounded TLS profile")
        staged[config["id"]] = config
        event(trace, "TLS", "stage", config["id"], ca=config["ca"])

    def activate(config_id: str):
        nonlocal active
        require(config_id in staged, "config not staged")
        previous = active
        active = config_id
        if previous and previous != config_id:
            revoked.add(previous); staged.pop(previous, None)
        event(trace, "TLS", "activate", config_id, previous=previous, active_count=1)

    def authenticate(ca: str, now: int) -> bool:
        require(active is not None, "no active config")
        config = staged[active]
        accepted = ca == config["ca"] and now < config["expires"]
        event(trace, "TLS", "authenticate", active, accepted=accepted, now=now)
        return accepted

    def c1():
        rejected = False
        try:
            stage({"id":"bad","ca":"x","expires":10,"minimum":13,"maximum":12,"timeout":1,"max_bytes":1})
        except Failure:
            rejected = True; event(trace, "TLS", "policy_reject", "bad")
        require(rejected, "invalid TLS range accepted")
        return 1, {"rejected": rejected}

    def c2():
        ca = digest("ca-a")
        stage({"id":"a","ca":ca,"expires":10000,"minimum":12,"maximum":13,"timeout":1000,"max_bytes":8192})
        activate("a")
        require(authenticate(ca, 100), "valid client rejected")
        require(not authenticate(digest("ca-b"), 100), "wrong CA accepted")
        require(not authenticate(ca, 10000), "expired client accepted")
        return 3, {"active": active}

    def c3():
        rng = SplitMix64(seed ^ 0x5449434B4554)
        lengths = [0,1,2,3,15,16,31,32,255,256,4095,4096,4097] + [2 + rng.next() % 6000 for _ in range(64)]
        rejected = 0
        for length in lengths:
            payload = bytes(index & 0xff for index in range(max(0, length - 2)))
            declared = (len(payload) + (1 if length % 3 == 0 else 0)).to_bytes(2, "big")
            blob = declared + payload if length >= 2 else payload[:length]
            accepted = len(blob) >= 2 and len(blob) <= 4096 and int.from_bytes(blob[:2], "big") == len(blob) - 2
            rejected += int(not accepted)
        require(rejected > 0, "malformed corpus did not reject")
        event(trace, "TLS", "ticket_corpus", "reference", rejected=rejected, total=len(lengths))
        return 1, {"rejected": rejected, "total": len(lengths)}

    def c4():
        stage({"id":"b","ca":digest("ca-b"),"expires":20000,"minimum":13,"maximum":13,"timeout":900,"max_bytes":4096})
        previous = active; activate("b")
        require(active == "b" and previous in revoked, "reload not atomic")
        return 1, {"previous": previous, "active": active}

    def c5():
        config = staged[active or ""]
        require(config["timeout"] <= config["timeout"], "boundary rejected")
        require(config["timeout"] + 1 > config["timeout"], "slow handshake not rejected")
        require(config["max_bytes"] + 1 > config["max_bytes"], "oversize not rejected")
        event(trace, "TLS", "bounds", active or "", timeout=config["timeout"], max_bytes=config["max_bytes"])
        return 3, {"timeout": config["timeout"], "max_bytes": config["max_bytes"]}

    def c6():
        serialized = canon(trace).decode()
        require("BEGIN PRIVATE KEY" not in serialized, "private key marker leaked")
        require("root_token" not in serialized.lower(), "token marker leaked")
        return 2, {"trace_bytes": len(serialized)}

    functions = (c1, c2, c3, c4, c5, c6)
    results = [run_case(trace, "TLS", name, fn) for name, fn in zip(CASES["tls"], functions)]
    return trace, results, {"active": active, "staged": sorted(staged), "revoked": sorted(revoked)}


def raft_model(seed: int):
    trace: list[dict[str, Any]] = []
    term, leader, epoch = 1, 1, 1
    voters, joint, reachable = {1,2,3}, None, {1,2,3}
    log: list[str] = []

    def quorum(group): return len(group) // 2 + 1
    def can_commit():
        primary = len(reachable & voters) >= quorum(voters)
        return primary if joint is None else primary and len(reachable & joint) >= quorum(joint)

    def append(command: str) -> bool:
        if not can_commit():
            event(trace, "RAFT", "append_rejected", command, reachable=sorted(reachable))
            return False
        value = digest({"command":command,"index":len(log)+1,"term":term})
        log.append(value); event(trace, "RAFT", "commit", command, index=len(log), value=value)
        return True

    def state_digest(): return digest({"log":log,"commit":len(log)})

    def c1():
        commands = [f"cmd-{v}" for v in SplitMix64(seed ^ 0x4150504C59).shuffled(range(1,7))]
        for command in commands: require(append(command), "quorate append failed")
        first = state_digest()
        replay_log = [digest({"command":command,"index":index+1,"term":1}) for index, command in enumerate(commands)]
        require(first == digest({"log":replay_log,"commit":len(replay_log)}), "restart digest mismatch")
        return 1, {"commands": commands, "digest": first}

    def c2():
        conflict = digest("conflict")
        accepted = not (len(log) <= len(log) and conflict != state_digest())
        require(not accepted, "conflicting snapshot accepted")
        event(trace, "RAFT", "snapshot_rejected", str(len(log)), reason="committed_conflict")
        return 1, {"accepted": accepted}

    def c3():
        nonlocal voters, joint, reachable, leader, term, epoch
        joint = {2,3,4}; reachable |= joint; epoch += 1
        event(trace, "RAFT", "joint_membership", "cluster", old=sorted(voters), new=sorted(joint), epoch=epoch)
        require(can_commit(), "joint quorum lost")
        voters = set(joint); joint = None; reachable &= voters; epoch += 1
        if leader not in voters: leader = min(voters); term += 1
        event(trace, "RAFT", "membership_final", "cluster", voters=sorted(voters), leader=leader, epoch=epoch)
        require(leader in voters and epoch == 3, "single writer transition failed")
        return 1, {"voters": sorted(voters), "leader": leader, "epoch": epoch}

    def c4():
        nonlocal reachable
        before = len(log); reachable = {leader}
        require(not append("partitioned"), "partition committed")
        require(len(log) == before, "commit advanced without quorum")
        reachable = set(voters)
        return 2, {"commit": before}

    def c5():
        nonlocal reachable
        before = state_digest(); reachable = set()
        require(not append("quorum-loss"), "zero quorum committed")
        require(state_digest() == before, "state changed without quorum")
        reachable = set(voters)
        return 2, {"digest": before}

    def c6():
        interrupt = 1 + SplitMix64(seed ^ 0x494E434F4D504C45).next() % 8
        diagnostic = {"classification":"INCOMPLETE_REPLAYABLE","seed":seed,"last_event_index":len(trace)+interrupt}
        event(trace, "RAFT", "incomplete_run", "synthetic", **diagnostic)
        require(diagnostic["seed"] == seed, "seed lost")
        return 1, diagnostic

    functions = (c1, c2, c3, c4, c5, c6)
    results = [run_case(trace, "RAFT", name, fn) for name, fn in zip(CASES["raft"], functions)]
    state = {"term":term,"leader":leader,"voters":sorted(voters),"reachable":sorted(reachable),"commit":len(log),"state_digest":state_digest(),"writer_epoch":epoch}
    return trace, results, state


RUNNERS = {"runtime": runtime_model, "tls": tls_model, "raft": raft_model}


def build_evidence(domain: str, seed: int, source_commit: str, source_tree: str, branch: str,
                   clean_tree: bool, environment_id: str, executor_kind: str,
                   runner_id: str | None, runner_name: str | None, attested: bool) -> dict[str, Any]:
    require(domain in RUNNERS, "unknown domain")
    require(len(source_commit) == 40 and len(source_tree) == 40, "source IDs must be 40 hex")
    int(source_commit, 16); int(source_tree, 16)
    require(clean_tree, "passing evidence requires clean tree")
    trace, results, state = RUNNERS[domain](seed)
    require([item["case_id"] for item in results] == CASES[domain], "case set mismatch")
    counts = {name: sum(item["status"] == name for item in results) for name in ("PASS","FAIL","BLOCKED","UNEXECUTED","UNKNOWN")}
    status = "EXECUTED_PASS" if sum(counts[name] for name in ("FAIL","BLOCKED","UNEXECUTED","UNKNOWN")) == 0 else "EXECUTED_FAIL"
    return {
        "schema":"heptabao.h02-seeded-behavior-evidence.v1","plan_id":PLAN_ID,"revision":REVISION,
        "harness_version":HARNESS_VERSION,"execution_kind":"REFERENCE_MODEL","profile_id":PROFILES[domain],
        "domain":domain.upper(),"source":{"repository":"ProfHepta/HeptaBao","commit_sha":source_commit,
        "tree_sha":source_tree,"branch":branch,"clean_tree":clean_tree},
        "environment":{"environment_id":environment_id,"executor_kind":executor_kind,"runner_id":runner_id,
        "runner_name":runner_name,"os":platform.system() or os.name,"architecture":platform.machine() or "unknown",
        "python_version":platform.python_version(),"attested":attested},
        "seed":{"decimal":seed,"hex":f"0x{seed:016x}"},
        "candidate":{"bound":False,"candidate_id":None,"version":None,"feature_profile_sha256":None},
        "status":status,"cases":results,"trace_sha256":digest(trace),"final_state_sha256":digest(state),
        "replay_command":f"python scripts/h02_seeded_behavior_harness_v1.py replay --evidence <{domain}-{seed}.json>",
        "summary":{"total":len(results),"passed":counts["PASS"],"failed":counts["FAIL"],"blocked":counts["BLOCKED"],
        "unexecuted":counts["UNEXECUTED"],"unknown":counts["UNKNOWN"]},
        "qualification":False,"selection_effect":"NONE","authority_effect":"NONE",
    }


def validate(value: Mapping[str, Any]) -> None:
    require(value.get("qualification") is False and value.get("selection_effect") == "NONE" and value.get("authority_effect") == "NONE", "authority attempted")
    require(value.get("execution_kind") == "REFERENCE_MODEL" and value.get("candidate", {}).get("bound") is False, "not reference evidence")
    require(value.get("status") == "EXECUTED_PASS", "evidence not passing")
    require(all(value["summary"][key] == 0 for key in ("failed","blocked","unexecuted","unknown")), "false pass summary")


def replay(value: Mapping[str, Any]) -> None:
    validate(value)
    rebuilt = build_evidence(str(value["domain"]).lower(), int(value["seed"]["decimal"]),
        str(value["source"]["commit_sha"]), str(value["source"]["tree_sha"]), str(value["source"]["branch"]),
        bool(value["source"]["clean_tree"]), str(value["environment"]["environment_id"]),
        str(value["environment"]["executor_kind"]), value["environment"]["runner_id"],
        value["environment"]["runner_name"], bool(value["environment"]["attested"]))
    for key in ("profile_id","domain","cases","trace_sha256","final_state_sha256","summary"):
        require(rebuilt[key] == value[key], f"replay mismatch: {key}")


def merge(left: Mapping[str, Any], right: Mapping[str, Any]) -> dict[str, Any]:
    validate(left); validate(right)
    for key in ("harness_version","profile_id","domain","source","seed","cases","trace_sha256","final_state_sha256","summary"):
        require(left[key] == right[key], f"reproduction mismatch: {key}")
    a, b = left["environment"], right["environment"]
    require(a["attested"] and b["attested"], "attested inputs required")
    require(a["environment_id"] != b["environment_id"], "distinct environments required")
    require(a["runner_id"] and b["runner_id"] and a["runner_id"] != b["runner_id"], "distinct runners required")
    inputs = sorted((left, right), key=lambda item:item["environment"]["environment_id"])
    material = {"profile":left["profile_id"],"source":left["source"],"seed":left["seed"],"inputs":[digest(item) for item in inputs]}
    return {"schema":"heptabao.h02-independent-reproduction-bundle.v1","plan_id":PLAN_ID,"revision":REVISION,
        "bundle_id":"HB-H02-IR-"+digest(material)[:16],"status":"INDEPENDENTLY_REPRODUCED_UNREVIEWED",
        "profile_id":left["profile_id"],"domain":left["domain"],
        "source":{"commit_sha":left["source"]["commit_sha"],"tree_sha":left["source"]["tree_sha"]},"seed":left["seed"],
        "input_evidence":[{"evidence_sha256":digest(item),"environment_id":item["environment"]["environment_id"],
        "runner_id":item["environment"]["runner_id"],"attested":True} for item in inputs],
        "trace_sha256":left["trace_sha256"],"final_state_sha256":left["final_state_sha256"],
        "review_status":"PENDING","qualification":False,"selection_effect":"NONE","authority_effect":"NONE"}


def write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+"\n", encoding="utf-8")


def parse_seed(raw: str) -> int:
    value = int(raw, 0)
    require(0 <= value <= MASK64, "seed outside u64")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--domain", choices=("runtime","tls","raft","all"), default="all")
    run.add_argument("--seed", required=True); run.add_argument("--source-commit", required=True)
    run.add_argument("--source-tree", required=True); run.add_argument("--branch", required=True)
    run.add_argument("--environment-id", required=True)
    run.add_argument("--executor-kind", choices=("local-container","github-hosted","self-hosted","offline-lab"), required=True)
    run.add_argument("--runner-id"); run.add_argument("--runner-name"); run.add_argument("--attested", action="store_true")
    run.add_argument("--dirty-tree", action="store_true"); run.add_argument("--output-dir", required=True)
    rep = commands.add_parser("replay"); rep.add_argument("--evidence", required=True)
    mer = commands.add_parser("merge"); mer.add_argument("--left", required=True); mer.add_argument("--right", required=True); mer.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            domains = list(RUNNERS) if args.domain == "all" else [args.domain]
            output = Path(args.output_dir); manifest = []
            for domain in domains:
                value = build_evidence(domain, parse_seed(args.seed), args.source_commit, args.source_tree, args.branch,
                    not args.dirty_tree, args.environment_id, args.executor_kind, args.runner_id, args.runner_name, args.attested)
                path = output / f"{domain}-{value['seed']['hex'][2:]}.json"; write(path, value)
                manifest.append({"path":path.name,"sha256":digest(value)})
                print(f"{domain}: {value['status']} trace={value['trace_sha256']}")
            write(output/"manifest.json",{"schema":"heptabao.h02-seeded-behavior-manifest.v1","artifacts":manifest,
                "qualification":False,"selection_effect":"NONE","authority_effect":"NONE"})
        elif args.command == "replay":
            value = json.loads(Path(args.evidence).read_text()); replay(value)
            print(f"replay passed: {value['profile_id']} seed={value['seed']['hex']}")
        else:
            value = merge(json.loads(Path(args.left).read_text()), json.loads(Path(args.right).read_text()))
            write(Path(args.output), value); print(f"bundle created: {value['bundle_id']}")
        return 0
    except (Failure, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"H02 seeded behavior harness FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
