mod cluster {
    include!("openraft_fault_lab/cluster.rs");
    include!("openraft_fault_lab/hostile_snapshot_guard.rs");
}
#[path = "inmemory_cluster/network.rs"]
mod network;

use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::process::Command;
use tokio::time::timeout;

const CANDIDATE_ID: &str = "HB-DEP-RAFT-OPENRAFT";
const VERSION: &str = "0.10.0-alpha.33";
const PROFILE_ID: &str = "HB-H02-FAULT-LAB-OPENRAFT-0_10_0_ALPHA_33";
const HOSTILE_PHASE: &str = "ABOUT_TO_INSTALL_STALE_COMMITTED_SNAPSHOT";

fn argument(name: &str, default: &str) -> String {
    let args = std::env::args().collect::<Vec<_>>();
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .unwrap_or_else(|| default.to_owned())
}

fn parse_seed() -> u64 {
    let raw = argument("--seed", "0x5eed20260828cafe");
    let trimmed = raw.strip_prefix("0x").unwrap_or(&raw);
    u64::from_str_radix(trimmed, 16).unwrap_or_else(|_| panic!("invalid seed: {raw}"))
}

fn parse_json_lines(bytes: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

fn stderr_tail(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let characters = text.chars().collect::<Vec<_>>();
    let start = characters.len().saturating_sub(2048);
    characters[start..].iter().collect()
}

fn base_result(seed: u64) -> Value {
    json!({
        "schema": "heptabao.h02-openraft-hostile-snapshot-result.v1",
        "candidate_id": CANDIDATE_ID,
        "version": VERSION,
        "profile_id": PROFILE_ID,
        "seed": format!("0x{seed:016x}"),
        "status": "BLOCKED",
        "phase_reached": false,
        "outcome": "SETUP_OR_EXECUTION_BLOCKED",
        "child_exit_code": Value::Null,
        "child_signal": Value::Null,
        "stdout_lines": 0,
        "stderr_bytes": 0,
        "execution_scope": "ISOLATED_CHILD_REAL_OPENRAFT_STALE_COMMITTED_SNAPSHOT_INJECTION",
        "durability_class": "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM",
        "detail": {
            "reason": "uninitialized result",
        },
        "qualification": false,
        "selection_effect": "NONE",
        "authority_effect": "NONE",
    })
}

async fn execute_hostile_parent(seed: u64) -> Value {
    let mut result = base_result(seed);
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            result["detail"] = json!({"reason": format!("current_exe failed: {error}")});
            return result;
        }
    };

    let mut command = Command::new(executable);
    command
        .arg("--mode")
        .arg("hostile-snapshot-child")
        .arg("--seed")
        .arg(format!("0x{seed:016x}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let output = match timeout(Duration::from_secs(25), command.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            result["detail"] = json!({"reason": format!("child spawn/output failed: {error}")});
            return result;
        }
        Err(_) => {
            result["detail"] = json!({"reason": "child exceeded 25 second parent deadline"});
            return result;
        }
    };

    let values = parse_json_lines(&output.stdout);
    let phase_reached = values.iter().any(|value| {
        value.get("kind").and_then(Value::as_str) == Some("phase")
            && value.get("phase").and_then(Value::as_str) == Some(HOSTILE_PHASE)
    });
    let child_result = values.iter().rev().find(|value| {
        value.get("kind").and_then(Value::as_str) == Some("hostile_snapshot_child_result")
    });
    let child_outcome = child_result
        .and_then(|value| value.get("outcome"))
        .and_then(Value::as_str);
    let child_detail = child_result
        .and_then(|value| value.get("detail"))
        .cloned()
        .unwrap_or(Value::Null);

    let (status, outcome, reason) = if output.status.success() {
        match child_outcome {
            Some("REJECTED") => (
                "EXECUTED_PASS",
                "REJECTED_OR_ABORTED_AFTER_INJECTION",
                "candidate explicitly rejected the stale snapshot or proved that it was an idempotent no-op across every guarded state surface",
            ),
            Some("ACCEPTED") => (
                "EXECUTED_FAIL",
                "ACCEPTED",
                "candidate accepted a stale committed snapshot and changed guarded state",
            ),
            Some("TIMED_OUT_AFTER_INJECTION") => (
                "BLOCKED",
                "SETUP_OR_EXECUTION_BLOCKED",
                "candidate did not complete the hostile snapshot operation before the child deadline",
            ),
            _ => (
                "BLOCKED",
                "SETUP_OR_EXECUTION_BLOCKED",
                "child exited successfully without a recognized hostile snapshot outcome",
            ),
        }
    } else if phase_reached {
        (
            "EXECUTED_PASS",
            "REJECTED_OR_ABORTED_AFTER_INJECTION",
            "isolated child terminated only after reaching the stale committed snapshot injection boundary",
        )
    } else {
        (
            "BLOCKED",
            "SETUP_OR_EXECUTION_BLOCKED",
            "child terminated before the hostile snapshot injection boundary",
        )
    };

    result["status"] = json!(status);
    result["phase_reached"] = json!(phase_reached);
    result["outcome"] = json!(outcome);
    result["child_exit_code"] = output.status.code().map_or(Value::Null, |code| json!(code));
    result["stdout_lines"] = json!(String::from_utf8_lossy(&output.stdout).lines().count());
    result["stderr_bytes"] = json!(output.stderr.len());
    result["detail"] = json!({
        "reason": reason,
        "child_reported_outcome": child_outcome,
        "child_reported_detail": child_detail,
        "stderr_tail": stderr_tail(&output.stderr),
        "availability_note": if !output.status.success() && phase_reached {
            "process-fatal rejection preserves safety but remains an availability and production-promotion blocker"
        } else {
            "no additional process-fatal availability claim"
        },
        "os_process_suspend": "NOT_EXECUTED_PROMOTION_BLOCKER",
        "disk_and_clock_faults": "NOT_EXECUTED_PROMOTION_BLOCKER",
    });
    result
}

fn print_json(value: &Value) {
    println!("{value}");
}

fn exit_code_for_status(value: &Value) -> i32 {
    match value.get("status").and_then(Value::as_str) {
        Some("EXECUTED_PASS") => 0,
        Some("EXECUTED_FAIL") => 1,
        Some("BLOCKED") => 2,
        _ => 3,
    }
}

fn print_parent_result(value: &Value) {
    let exit_code = exit_code_for_status(value);
    print_json(value);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let seed = parse_seed();
    let mode = argument("--mode", "hostile-snapshot-parent");

    match mode.as_str() {
        "hostile-snapshot-parent" => {
            let result = execute_hostile_parent(seed).await;
            print_parent_result(&result);
        }
        "hostile-snapshot-child" => {
            match cluster::execute_hostile_snapshot_child_guarded(seed).await {
                Ok(result) => print_json(&result),
                Err(error) => {
                    print_json(&json!({
                        "kind": "hostile_snapshot_child_result",
                        "outcome": "SETUP_OR_EXECUTION_BLOCKED",
                        "detail": error.to_string(),
                        "qualification": false,
                        "selection_effect": "NONE",
                        "authority_effect": "NONE",
                    }));
                    std::process::exit(2);
                }
            }
        }
        "linearizability-history" => match cluster::execute_linearizability_history(seed).await {
            Ok(history) => print_json(&history),
            Err(error) => {
                print_json(&json!({
                    "schema": "heptabao.h02-linearizability-history-error.v1",
                    "status": "BLOCKED",
                    "candidate_id": CANDIDATE_ID,
                    "version": VERSION,
                    "profile_id": PROFILE_ID,
                    "seed": format!("0x{seed:016x}"),
                    "reason": error.to_string(),
                    "qualification": false,
                    "selection_effect": "NONE",
                    "authority_effect": "NONE",
                }));
                std::process::exit(2);
            }
        },
        _ => {
            print_json(&json!({
                "schema": "heptabao.h02-openraft-fault-lab-error.v1",
                "status": "BLOCKED",
                "reason": format!("unsupported mode: {mode}"),
                "qualification": false,
                "selection_effect": "NONE",
                "authority_effect": "NONE",
            }));
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::exit_code_for_status;

    #[test]
    fn hostile_application_failure_cannot_exit_successfully() {
        let failed = serde_json::json!({"status": "EXECUTED_FAIL"});
        let blocked = serde_json::json!({"status": "BLOCKED"});
        let passed = serde_json::json!({"status": "EXECUTED_PASS"});
        assert_eq!(exit_code_for_status(&failed), 1);
        assert_eq!(exit_code_for_status(&blocked), 2);
        assert_eq!(exit_code_for_status(&passed), 0);
    }
}
