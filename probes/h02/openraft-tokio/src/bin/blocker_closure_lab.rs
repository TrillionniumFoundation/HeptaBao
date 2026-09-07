#[path = "openraft_fault_lab/durable.rs"]
mod durable;
#[path = "inmemory_cluster/network.rs"]
mod network;
#[path = "openraft_fault_lab/os_clock.rs"]
mod os_clock;
#[path = "openraft_fault_lab/os_clock_cluster.rs"]
mod os_clock_cluster;

use std::path::PathBuf;

use serde_json::{Value, json};

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

fn blocked(seed: u64, scope: &str, reason: String) -> Value {
    json!({
        "schema": "heptabao.h02-blocker-closure-component-error.v1",
        "candidate_id": "HB-DEP-RAFT-OPENRAFT",
        "version": "0.10.0-alpha.33",
        "seed": format!("0x{seed:016x}"),
        "scope": scope,
        "status": "BLOCKED",
        "reason": reason,
        "qualification": false,
        "selection_effect": "NONE",
        "authority_effect": "NONE"
    })
}

fn print_and_exit(value: &Value) {
    println!("{value}");
    if value.get("status").and_then(Value::as_str) != Some("EXECUTED_PASS") {
        std::process::exit(2);
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let seed = parse_seed();
    let mode = argument("--mode", "all");

    match mode.as_str() {
        "os-suspend-parent" => {
            let value = os_clock::execute_os_suspend_parent(seed).await;
            print_and_exit(&value);
        }
        "os-suspend-child" => {
            let work_dir = PathBuf::from(argument("--work-dir", ""));
            if work_dir.as_os_str().is_empty() {
                let value = blocked(
                    seed,
                    "OS_SUSPEND_CHILD",
                    "--work-dir is required".to_owned(),
                );
                println!("{value}");
                std::process::exit(2);
            }
            if let Err(error) = os_clock_cluster::execute_os_suspend_child(seed, &work_dir).await {
                let value = blocked(seed, "OS_SUSPEND_CHILD", error.to_string());
                println!("{value}");
                std::process::exit(2);
            }
        }
        "durable-faults" => {
            let value = durable::execute_durable_faults(seed).await;
            print_and_exit(&value);
        }
        "clock-faults" => {
            let value = match os_clock_cluster::execute_clock_faults(seed).await {
                Ok(value) => value,
                Err(error) => blocked(seed, "CLOCK_FAULTS", error.to_string()),
            };
            print_and_exit(&value);
        }
        "all" => {
            let os_suspend = os_clock::execute_os_suspend_parent(seed).await;
            let durable = durable::execute_durable_faults(seed).await;
            let clock = match os_clock_cluster::execute_clock_faults(seed).await {
                Ok(value) => value,
                Err(error) => blocked(seed, "CLOCK_FAULTS", error.to_string()),
            };
            let all_pass = [&os_suspend, &durable, &clock]
                .into_iter()
                .all(|value| value.get("status").and_then(Value::as_str) == Some("EXECUTED_PASS"));
            let value = json!({
                "schema": "heptabao.h02-blocker-closure-result.v1",
                "candidate_id": "HB-DEP-RAFT-OPENRAFT",
                "version": "0.10.0-alpha.33",
                "seed": format!("0x{seed:016x}"),
                "status": if all_pass { "EXECUTED_PASS" } else { "BLOCKED" },
                "components": {
                    "os_suspend": os_suspend,
                    "durable_faults": durable,
                    "clock_faults": clock
                },
                "scope": {
                    "os_process_suspend_executed": true,
                    "heptabao_file_wal_faults_executed": true,
                    "openraft_real_writes_and_readindex_under_wall_projection": true,
                    "openraft_durable_store_integrated": false,
                    "per_node_kernel_clock_skew": false,
                    "independent_external_approvals": false
                },
                "promotion_effect": "BLOCK_PENDING_OPENRAFT_DURABLE_STORE_INTEGRATION_PER_NODE_KERNEL_CLOCK_AND_EXTERNAL_APPROVALS",
                "qualification": false,
                "selection_effect": "NONE",
                "authority_effect": "NONE"
            });
            print_and_exit(&value);
        }
        _ => {
            let value = blocked(seed, "DISPATCH", format!("unsupported mode: {mode}"));
            println!("{value}");
            std::process::exit(2);
        }
    }
}
