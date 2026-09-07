use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse {}: {error}", path.display()))
}

async fn wait_for_file(path: &Path, deadline: Duration) -> Result<Value, String> {
    timeout(deadline, async {
        loop {
            if path.is_file()
                && let Ok(value) = read_json(path)
            {
                return value;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| format!("timed out waiting for {}", path.display()))
}

async fn wait_for_progress(path: &Path, minimum: u64, deadline: Duration) -> Result<Value, String> {
    timeout(deadline, async {
        loop {
            if let Ok(value) = read_json(path)
                && value
                    .get("step")
                    .and_then(Value::as_u64)
                    .is_some_and(|step| step >= minimum)
            {
                return value;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| format!("timed out waiting for progress >= {minimum}"))
}

async fn signal(pid: u32, name: &str) -> Result<(), String> {
    let status = Command::new("kill")
        .arg(format!("-{name}"))
        .arg(pid.to_string())
        .status()
        .await
        .map_err(|error| format!("spawn kill -{name} {pid}: {error}"))?;
    if !status.success() {
        return Err(format!("kill -{name} {pid} returned {status}"));
    }
    Ok(())
}

fn proc_status_path(pid: u32) -> Result<PathBuf, String> {
    let direct = PathBuf::from(format!("/proc/{pid}/status"));
    if direct.is_file() {
        return Ok(direct);
    }

    // In a nested PID namespace (for example, the Codex sandbox),
    // `Child::id()` and `std::process::id()` are namespace-local values while
    // the mounted `/proc` is keyed by the outer namespace's PID.  Resolving
    // only `/proc/{pid}/status` therefore reports a false "No such file" even
    // though the child is alive.  Search the mounted procfs for the process
    // whose *innermost* NSpid matches and whose PID namespace is ours.  The
    // namespace check is important: unrelated nested sandboxes can reuse the
    // same local PID.
    let own_namespace = fs::read_link("/proc/self/ns/pid").map_err(|error| {
        format!("read /proc/self/ns/pid while resolving namespace PID {pid}: {error}")
    })?;
    let entries = fs::read_dir("/proc")
        .map_err(|error| format!("scan /proc while resolving namespace PID {pid}: {error}"))?;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let candidate = entry.path();
        let candidate_namespace = match fs::read_link(candidate.join("ns/pid")) {
            Ok(namespace) => namespace,
            Err(_) => continue,
        };
        if candidate_namespace != own_namespace {
            continue;
        }
        let status_path = candidate.join("status");
        let Ok(text) = fs::read_to_string(&status_path) else {
            continue;
        };
        let matches_namespace_pid = text
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:"))
            .and_then(|line| line.split_whitespace().last())
            .and_then(|value| value.parse::<u32>().ok())
            == Some(pid);
        if matches_namespace_pid {
            return Ok(status_path);
        }
    }

    Err(format!(
        "read {}: process was not found in the current PID namespace",
        direct.display()
    ))
}

fn proc_state(pid: u32) -> Result<String, String> {
    let status_path = proc_status_path(pid)?;
    let text = fs::read_to_string(&status_path)
        .map_err(|error| format!("read {}: {error}", status_path.display()))?;
    text.lines()
        .find_map(|line| {
            line.strip_prefix("State:")
                .map(str::trim)
                .map(str::to_owned)
        })
        .ok_or_else(|| format!("{} has no State line", status_path.display()))
}

async fn terminate(child: &mut Child, pid: u32) {
    let _ = signal(pid, "CONT").await;
    let _ = signal(pid, "TERM").await;
    if timeout(Duration::from_secs(3), child.wait()).await.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

pub async fn execute_os_suspend_parent(seed: u64) -> Value {
    let root = std::env::temp_dir().join(format!(
        "heptabao-h02-os-suspend-{}-{seed:016x}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    if let Err(error) = fs::create_dir_all(&root) {
        return blocked(seed, format!("create work directory failed: {error}"));
    }

    let stdout_path = root.join("child-stdout.jsonl");
    let stderr_path = root.join("child-stderr.log");
    let stdout = match File::create(&stdout_path) {
        Ok(file) => file,
        Err(error) => return blocked(seed, format!("create child stdout failed: {error}")),
    };
    let stderr = match File::create(&stderr_path) {
        Ok(file) => file,
        Err(error) => return blocked(seed, format!("create child stderr failed: {error}")),
    };
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => return blocked(seed, format!("current_exe failed: {error}")),
    };

    let mut command = Command::new(executable);
    command
        .arg("--mode")
        .arg("os-suspend-child")
        .arg("--seed")
        .arg(format!("0x{seed:016x}"))
        .arg("--work-dir")
        .arg(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return blocked(seed, format!("spawn OS-suspend child failed: {error}")),
    };
    let Some(pid) = child.id() else {
        return blocked(seed, "spawned child has no process id".to_owned());
    };

    let ready_path = root.join("ready.json");
    let progress_path = root.join("progress.json");
    let execution = async {
        let ready = wait_for_file(&ready_path, Duration::from_secs(30)).await?;
        if ready.get("real_openraft_nodes").and_then(Value::as_u64) != Some(3) {
            return Err(format!("unexpected child readiness payload: {ready}"));
        }
        let before = wait_for_progress(&progress_path, 2, Duration::from_secs(20)).await?;
        let before_step = before["step"].as_u64().ok_or("progress step is missing")?;

        signal(pid, "STOP").await?;
        sleep(Duration::from_millis(150)).await;
        let stopped_state = proc_state(pid)?;
        let state_is_stopped = stopped_state.starts_with('T');
        let frozen_a = read_json(&progress_path)?;
        sleep(Duration::from_millis(600)).await;
        let frozen_b = read_json(&progress_path)?;
        let frozen_step_a = frozen_a["step"].as_u64().ok_or("frozen progress A missing step")?;
        let frozen_step_b = frozen_b["step"].as_u64().ok_or("frozen progress B missing step")?;
        let progress_frozen = frozen_step_a == frozen_step_b;

        signal(pid, "CONT").await?;
        let resumed = wait_for_progress(
            &progress_path,
            frozen_step_b + 1,
            Duration::from_secs(40),
        )
        .await?;
        let resumed_step = resumed["step"].as_u64().ok_or("resumed progress missing step")?;
        let read_index_ok = resumed["read_index_ok"].as_bool() == Some(true);
        let commit_advanced = resumed_step > before_step;

        Ok::<Value, String>(json!({
            "schema": "heptabao.h02-os-suspend-result.v1",
            "candidate_id": "HB-DEP-RAFT-OPENRAFT",
            "version": "0.10.0-alpha.33",
            "seed": format!("0x{seed:016x}"),
            "status": if state_is_stopped && progress_frozen && commit_advanced && read_index_ok {
                "EXECUTED_PASS"
            } else {
                "EXECUTED_FAIL"
            },
            "pid": pid,
            "signal_sequence": ["SIGSTOP", "SIGCONT", "SIGTERM"],
            "proc_state_while_stopped": stopped_state,
            "progress_before": before_step,
            "progress_frozen_a": frozen_step_a,
            "progress_frozen_b": frozen_step_b,
            "progress_after_resume": resumed_step,
            "state_is_stopped": state_is_stopped,
            "progress_frozen": progress_frozen,
            "candidate_progress_resumed": commit_advanced,
            "read_index_after_resume": read_index_ok,
            "scope": {
                "real_openraft_nodes": 3,
                "topology": "SINGLE_OS_PROCESS_THREE_INPROCESS_RAFT_NODES",
                "os_process_suspend": true,
                "separate_process_majority_election": false,
                "composition_note": "PR22 separately exercises old-leader transport pause and majority re-election; this result executes real Linux process suspension without claiming a multi-process election topology"
            },
            "promotion_effect": "BLOCK_PENDING_MULTI_PROCESS_COMPOSITION_AND_INDEPENDENT_PLATFORM_REVIEW",
            "qualification": false,
            "selection_effect": "NONE",
            "authority_effect": "NONE"
        }))
    }
    .await;

    terminate(&mut child, pid).await;
    let value = execution.unwrap_or_else(|error| blocked(seed, error));
    let _ = fs::remove_dir_all(&root);
    value
}

fn blocked(seed: u64, reason: String) -> Value {
    json!({
        "schema": "heptabao.h02-os-suspend-result.v1",
        "candidate_id": "HB-DEP-RAFT-OPENRAFT",
        "version": "0.10.0-alpha.33",
        "seed": format!("0x{seed:016x}"),
        "status": "BLOCKED",
        "reason": reason,
        "promotion_effect": "BLOCK_PENDING_MULTI_PROCESS_COMPOSITION_AND_INDEPENDENT_PLATFORM_REVIEW",
        "qualification": false,
        "selection_effect": "NONE",
        "authority_effect": "NONE"
    })
}
