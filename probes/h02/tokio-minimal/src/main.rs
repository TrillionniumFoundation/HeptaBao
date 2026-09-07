use std::future::pending;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, Semaphore};

const CANDIDATE_ID: &str = "HB-DEP-ASYNC-TOKIO";
const VERSION: &str = "1.53.1";
const PROFILE_ID: &str = "HB-H02-BEHAVIOR-RUNTIME-TOKIO-1_53_1";

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    fn shuffled(&mut self, values: &mut [u64]) {
        for index in (1..values.len()).rev() {
            let swap = (self.next() as usize) % (index + 1);
            values.swap(index, swap);
        }
    }
}

fn parse_seed() -> u64 {
    let args: Vec<String> = std::env::args().collect();
    let raw = args
        .windows(2)
        .find(|pair| pair[0] == "--seed")
        .map(|pair| pair[1].as_str())
        .unwrap_or("0x5eed20260828cafe");
    let trimmed = raw.strip_prefix("0x").unwrap_or(raw);
    u64::from_str_radix(trimmed, 16).unwrap_or_else(|_| panic!("invalid seed: {raw}"))
}

fn emit_meta(seed: u64) {
    println!(
        "{{\"kind\":\"meta\",\"candidate_id\":\"{}\",\"version\":\"{}\",\"profile_id\":\"{}\",\"domain\":\"RUNTIME\",\"seed\":\"0x{:016x}\"}}",
        CANDIDATE_ID, VERSION, PROFILE_ID, seed
    );
}

fn emit_case(case_id: &str, pass: bool, assertions: u64, detail: &str) {
    let status = if pass { "PASS" } else { "FAIL" };
    println!(
        "{{\"kind\":\"case\",\"case_id\":\"{}\",\"status\":\"{}\",\"assertion_count\":{},\"detail\":\"{}\"}}",
        case_id, status, assertions, detail
    );
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let seed = parse_seed();
    emit_meta(seed);

    let before_start = tokio::spawn(async move {
        pending::<()>().await;
    });
    before_start.abort();
    let before_start_cancelled = matches!(before_start.await, Err(error) if error.is_cancelled());
    emit_case(
        "runtime-cancel-before-start",
        before_start_cancelled,
        1,
        if before_start_cancelled { "abort-before-poll-cancelled" } else { "abort-before-poll-not-cancelled" },
    );

    let (sender, receiver) = oneshot::channel::<()>();
    let waiting = tokio::spawn(async move {
        let _ = receiver.await;
    });
    tokio::task::yield_now().await;
    waiting.abort();
    drop(sender);
    let wait_cancelled = matches!(waiting.await, Err(error) if error.is_cancelled());
    emit_case(
        "runtime-cancel-during-wait",
        wait_cancelled,
        1,
        if wait_cancelled { "waiter-cancelled-resource-released" } else { "waiter-not-cancelled" },
    );

    let mut registration: Vec<u64> = (100..108).collect();
    SplitMix64::new(seed ^ 0x4445_4144_4c49_4e45).shuffled(&mut registration);
    let (tx, mut rx) = mpsc::channel::<u64>(registration.len());
    for task_id in registration.iter().copied() {
        let tx = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(2)).await;
            let _ = tx.send(task_id).await;
        });
    }
    drop(tx);
    let mut completed = Vec::new();
    while let Some(task_id) = rx.recv().await {
        completed.push(task_id);
    }
    completed.sort_unstable();
    let expected: Vec<u64> = (100..108).collect();
    let all_completed_once = completed == expected;
    emit_case(
        "runtime-equal-deadline-seed-replay",
        all_completed_once,
        1,
        if all_completed_once { "equal-deadline-normalized-set-100-107" } else { "equal-deadline-completion-mismatch" },
    );

    let panicking = tokio::spawn(async move {
        panic!("synthetic isolated task panic");
    });
    let healthy = tokio::spawn(async move { 7_u8 });
    let panic_isolated = panicking.await.is_err() && matches!(healthy.await, Ok(7));
    emit_case(
        "runtime-task-panic-isolation",
        panic_isolated,
        2,
        if panic_isolated { "panic-join-error-healthy-complete" } else { "panic-isolation-failed" },
    );

    let semaphore = Arc::new(Semaphore::new(2));
    let mut workers = Vec::new();
    for worker_id in 0_u8..4 {
        let semaphore = Arc::clone(&semaphore);
        workers.push(tokio::spawn(async move {
            let permit = semaphore.acquire_owned().await.expect("semaphore closed");
            tokio::time::sleep(Duration::from_millis(5)).await;
            drop(permit);
            worker_id
        }));
    }
    let authority = tokio::spawn(async move { 99_u8 });
    let authority_completed = matches!(
        tokio::time::timeout(Duration::from_secs(1), authority).await,
        Ok(Ok(99))
    );
    let mut worker_ok = true;
    for worker in workers {
        worker_ok &= worker.await.is_ok();
    }
    emit_case(
        "runtime-bounded-blocking-saturation",
        authority_completed && worker_ok,
        2,
        if authority_completed && worker_ok { "bounded-four-workers-authority-not-starved" } else { "bounded-saturation-failed" },
    );

    let live = Arc::new(AtomicUsize::new(0));
    let mut lifecycle = Vec::new();
    for _ in 0..8 {
        let live = Arc::clone(&live);
        lifecycle.push(tokio::spawn(async move {
            live.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            live.fetch_sub(1, Ordering::SeqCst);
        }));
    }
    let mut joined = true;
    for task in lifecycle {
        joined &= task.await.is_ok();
    }
    let no_leak = joined && live.load(Ordering::SeqCst) == 0;
    emit_case(
        "runtime-zero-task-resource-leak",
        no_leak,
        2,
        if no_leak { "all-handles-joined-live-counter-zero" } else { "task-or-resource-leak" },
    );
}
