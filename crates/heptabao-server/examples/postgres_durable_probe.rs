//! Real PostgreSQL qualification probe for the sealed durable backend.
//!
//! Input is bounded JSON on stdin and output contains only case names. The
//! fixture must use a fresh scope and an enrolled loopback PostgreSQL owner.
use heptabao_durable_service::{BackendBundle, BackendError, DurableBackend};
use heptabao_server::{
    outbound::EndpointConfig, postgres_durable::PostgresDurableBackend,
    postgres_storage::PgStorageConfig,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
    thread,
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    endpoint: EndpointConfig,
    connection_url: String,
    username: String,
    password: String,
    scope: String,
    mode: String,
    #[serde(default)]
    commit_gate: Option<PathBuf>,
}

fn config(input: &Input) -> PgStorageConfig {
    PgStorageConfig {
        endpoint: input.endpoint.clone(),
        connection_url: input.connection_url.clone(),
        username: input.username.clone(),
        password: input.password.clone(),
        scope: input.scope.clone(),
    }
}

fn check(checks: &mut Vec<Value>, name: &str, passed: bool) -> Result<(), &'static str> {
    checks.push(json!({"case": name, "passed": passed}));
    if passed {
        Ok(())
    } else {
        Err("durable probe assertion failed")
    }
}

fn basic(input: &Input, checks: &mut Vec<Value>) -> Result<(), Box<dyn std::error::Error>> {
    let mut backend = PostgresDurableBackend::initialize(config(input))?;
    let initial = BackendBundle::new(
        b"sealed-snapshot".to_vec(),
        b"sealed-ledger".to_vec(),
        b"HBJ2".to_vec(),
    )?;
    backend.initialize_or_match(&initial)?;
    check(checks, "durable_initialize_empty", true)?;
    check(
        checks,
        "durable_initialize_empty_rejects_existing_scope",
        backend.initialize_empty(&initial) == Err(BackendError::RootNotEmpty),
    )?;
    backend.close()?;
    let mut backend = PostgresDurableBackend::open(config(input))?;
    backend.initialize_or_match(&initial)?;
    check(
        checks,
        "durable_initialization_retry_matches_exact_bundle",
        true,
    )?;
    let conflicting = BackendBundle::new(
        b"different-initialization-snapshot".to_vec(),
        initial.ledger.clone(),
        initial.journal.clone(),
    )?;
    check(
        checks,
        "durable_initialization_retry_rejects_different_bundle",
        backend.initialize_or_match(&conflicting) == Err(BackendError::RootNotEmpty),
    )?;
    check(
        checks,
        "durable_initialization_conflict_preserves_bundle",
        backend.load()? == initial,
    )?;
    let loaded = backend.load()?;
    check(checks, "durable_bundle_roundtrip", loaded == initial)?;
    let next_len = backend.append_journal(loaded.journal.len(), b"frame-one")?;
    check(
        checks,
        "durable_append_returns_exact_length",
        next_len == loaded.journal.len() + 9,
    )?;
    let after = backend.load()?;
    check(
        checks,
        "durable_append_replay_bytes_exact",
        after.journal == b"HBJ2frame-one",
    )?;
    check(
        checks,
        "durable_append_rejects_stale_length",
        backend.append_journal(loaded.journal.len(), b"stale") == Err(BackendError::StaleWriter),
    )?;
    let replacement = BackendBundle::new(
        after.snapshot.clone(),
        after.ledger.clone(),
        after.journal.clone(),
    )?;
    backend.publish_checkpoint(&after, &replacement)?;
    check(
        checks,
        "durable_checkpoint_atomic_publish",
        backend.load()? == replacement,
    )?;
    backend.close()?;
    Ok(())
}

const PROBE_CHUNK_BYTES: usize = 768 * 1024;
const LARGE_APPEND: &[u8] = b"small-cross-boundary-frame";

fn large_bundle() -> Result<BackendBundle, BackendError> {
    BackendBundle::new(
        vec![0x53; 3 * 1024 * 1024 + 7],
        vec![0x4c; 3 * 1024 * 1024 + 11],
        vec![0x4a; PROBE_CHUNK_BYTES * 4 - 5],
    )
}

fn large(input: &Input, checks: &mut Vec<Value>) -> Result<(), Box<dyn std::error::Error>> {
    let mut expected = large_bundle()?;
    match input.mode.as_str() {
        "large-seed" => {
            let mut backend = PostgresDurableBackend::initialize(config(input))?;
            backend.initialize_empty(&expected)?;
            check(
                checks,
                "large_artifacts_above_wire_result_bound_roundtrip",
                backend.load()? == expected,
            )?;
            backend.close()?;
            let mut backend = PostgresDurableBackend::open(config(input))?;
            check(
                checks,
                "large_artifacts_fresh_session_reopen",
                backend.load()? == expected,
            )?;
            backend.close()?;
        }
        "large-append" => {
            let mut backend = PostgresDurableBackend::open(config(input))?;
            let before = expected.journal.len();
            let appended = backend.append_journal(before, LARGE_APPEND)?;
            expected.journal.extend_from_slice(LARGE_APPEND);
            check(
                checks,
                "large_journal_small_append_crosses_chunk_boundary",
                appended == expected.journal.len(),
            )?;
            check(
                checks,
                "large_journal_small_append_exact_bytes",
                backend.load()? == expected,
            )?;
            check(
                checks,
                "large_append_stale_length_rejected",
                backend.append_journal(before, b"stale") == Err(BackendError::StaleWriter),
            )?;
            check(
                checks,
                "large_append_empty_frame_no_change",
                backend.append_journal(appended, b"")? == appended && backend.load()? == expected,
            )?;
            backend.close()?;
            let mut backend = PostgresDurableBackend::open(config(input))?;
            check(
                checks,
                "large_append_fresh_session_reopen",
                backend.load()? == expected,
            )?;
            backend.close()?;
        }
        "large-checkpoint" => {
            expected.journal.extend_from_slice(LARGE_APPEND);
            let mut backend = PostgresDurableBackend::open(config(input))?;
            let replacement = BackendBundle::new(
                vec![0x73; 3 * 1024 * 1024 + 97],
                vec![0x6c; 3 * 1024 * 1024 + 101],
                vec![0x6a; PROBE_CHUNK_BYTES * 3 + 9],
            )?;
            backend.publish_checkpoint(&expected, &replacement)?;
            check(
                checks,
                "large_checkpoint_exact_bytes",
                backend.load()? == replacement,
            )?;
            check(
                checks,
                "large_checkpoint_stale_bundle_rejected",
                backend.publish_checkpoint(&expected, &replacement)
                    == Err(BackendError::StaleWriter),
            )?;
            backend.close()?;
            let mut backend = PostgresDurableBackend::open(config(input))?;
            check(
                checks,
                "large_checkpoint_fresh_session_reopen",
                backend.load()? == replacement,
            )?;
            let next_len = PROBE_CHUNK_BYTES * 3 - 7;
            backend.truncate_journal(replacement.journal.len(), next_len)?;
            let mut truncated = replacement;
            truncated.journal.truncate(next_len);
            check(
                checks,
                "large_journal_truncate_remains_readable",
                backend.load()? == truncated,
            )?;
            backend.close()?;
        }
        "reject-large-layout" => {
            let mut backend = PostgresDurableBackend::open(config(input))?;
            check(
                checks,
                "large_corrupt_layout_rejected_on_load",
                backend.load() == Err(BackendError::Corrupt),
            )?;
            check(
                checks,
                "large_corrupt_layout_rejected_on_append",
                backend.append_journal(expected.journal.len(), b"rejected")
                    == Err(BackendError::Corrupt),
            )?;
            backend.close()?;
        }
        _ => return Err("unknown large probe mode".into()),
    }
    Ok(())
}

fn append_boundaries(
    input: &Input,
    checks: &mut Vec<Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    for (index, (initial_len, frame_len)) in [
        (0, 0),
        (0, 1),
        (PROBE_CHUNK_BYTES, 1),
        (PROBE_CHUNK_BYTES - 1, 2 * PROBE_CHUNK_BYTES + 7),
    ]
    .into_iter()
    .enumerate()
    {
        let mut config = config(input);
        config.scope = format!("{}-{index}", config.scope);
        let mut backend = PostgresDurableBackend::initialize(config)?;
        let mut expected = BackendBundle::new(Vec::new(), Vec::new(), vec![0x4a; initial_len])?;
        backend.initialize_empty(&expected)?;
        let frame = vec![0x46; frame_len];
        check(
            checks,
            &format!("append_boundary_{index}_length"),
            backend.append_journal(initial_len, &frame)? == initial_len + frame_len,
        )?;
        expected.journal.extend_from_slice(&frame);
        check(
            checks,
            &format!("append_boundary_{index}_bytes"),
            backend.load()? == expected,
        )?;
        backend.close()?;
    }
    Ok(())
}

fn idle_session(input: &Input, checks: &mut Vec<Value>) -> Result<(), Box<dyn std::error::Error>> {
    let mut backend = PostgresDurableBackend::initialize(config(input))?;
    let mut expected = BackendBundle::new(vec![1], vec![2], vec![3])?;
    backend.initialize_empty(&expected)?;
    // Retain the same PostgreSQL session and advisory fence beyond its old
    // connection-wide 3s deadline; BEGIN must renew only the operation budget.
    thread::sleep(Duration::from_secs(4));
    check(
        checks,
        "idle_writer_session_can_append_after_old_deadline",
        backend.append_journal(1, &[4])? == 2,
    )?;
    expected.journal.push(4);
    check(
        checks,
        "idle_writer_session_load_preserves_appended_bytes",
        backend.load()? == expected,
    )?;
    backend.close()?;
    Ok(())
}

fn maximum_artifact(
    input: &Input,
    checks: &mut Vec<Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    const MAX_BYTES: usize = 64 * 1024 * 1024;
    let mut backend = PostgresDurableBackend::initialize(config(input))?;
    let expected = BackendBundle::new(Vec::new(), Vec::new(), vec![0x4a; MAX_BYTES])?;
    backend.initialize_empty(&expected)?;
    check(
        checks,
        "maximum_64mib_artifact_roundtrip",
        backend.load()? == expected,
    )?;
    check(
        checks,
        "maximum_journal_append_one_byte_rejected",
        backend.append_journal(MAX_BYTES, &[1]) == Err(BackendError::Capacity),
    )?;
    let oversized = BackendBundle {
        snapshot: Vec::new(),
        ledger: Vec::new(),
        journal: vec![0x4a; MAX_BYTES + 1],
    };
    check(
        checks,
        "maximum_plus_one_initialization_rejected",
        backend.initialize_or_match(&oversized) == Err(BackendError::Capacity),
    )?;
    check(
        checks,
        "maximum_plus_one_checkpoint_rejected",
        backend.publish_checkpoint(&expected, &oversized) == Err(BackendError::Capacity),
    )?;
    drop(oversized);
    backend.close()?;
    let mut backend = PostgresDurableBackend::open(config(input))?;
    check(
        checks,
        "maximum_64mib_artifact_reopen_unchanged_after_rejections",
        backend.load()? == expected,
    )?;
    backend.close()?;
    Ok(())
}

fn run(input: Input, checks: &mut Vec<Value>) -> Result<(), Box<dyn std::error::Error>> {
    if !input.endpoint.address.ip().is_loopback() || input.username != "hb_storage" {
        return Err("synthetic loopback fixture only".into());
    }
    match input.mode.as_str() {
        "basic" => basic(&input, checks),
        "append-boundaries" => append_boundaries(&input, checks),
        "idle-session" => idle_session(&input, checks),
        "maximum-artifact" => maximum_artifact(&input, checks),
        "large-seed" | "large-append" | "large-checkpoint" | "reject-large-layout" => {
            large(&input, checks)
        }
        "reject-orphan" => {
            let mut backend = PostgresDurableBackend::open(config(&input))?;
            let initial = BackendBundle::new(vec![1], vec![2], vec![3])?;
            check(
                checks,
                "durable_initialization_rejects_orphan_chunks",
                backend.initialize_or_match(&initial) == Err(BackendError::Corrupt),
            )?;
            backend.close()?;
            Ok(())
        }
        "reopen" => {
            let mut backend = PostgresDurableBackend::open(config(&input))?;
            let bundle = backend.load()?;
            check(
                checks,
                "durable_reopen_bundle_present",
                bundle.journal.starts_with(b"HBJ2"),
            )?;
            backend.close()?;
            Ok(())
        }
        "reopen-lost" => {
            let mut backend = PostgresDurableBackend::open(config(&input))?;
            let bundle = backend.load()?;
            let marker = b"lost-commit-frame";
            let occurrences = bundle
                .journal
                .windows(marker.len())
                .filter(|window| *window == marker)
                .count();
            check(
                checks,
                "durable_lost_commit_replayed_exactly_once",
                occurrences == 1,
            )?;
            backend.close()?;
            Ok(())
        }
        "reject-schema" => check(
            checks,
            "durable_schema_fault_rejected",
            PostgresDurableBackend::open(config(&input)).is_err(),
        )
        .map_err(Into::into),
        "reject-writer" => check(
            checks,
            "durable_second_writer_rejected_without_blocking",
            matches!(
                PostgresDurableBackend::open(config(&input)),
                Err(BackendError::WriterLocked)
            ),
        )
        .map_err(Into::into),
        "reject-connect" => check(
            checks,
            "durable_untrusted_connection_rejected",
            PostgresDurableBackend::open(config(&input)).is_err(),
        )
        .map_err(Into::into),
        "hold-writer" => {
            let mut backend = PostgresDurableBackend::open(config(&input))?;
            let _ = backend.load()?;
            println!("writer_held");
            io::stdout().flush()?;
            let gate = input
                .commit_gate
                .ok_or("hold-writer requires commit_gate")?;
            while !gate.exists() {
                thread::sleep(Duration::from_millis(20));
            }
            backend.close()?;
            Ok(())
        }
        "lost-commit" => {
            let mut backend = PostgresDurableBackend::open(config(&input))?;
            let current = backend.load()?;
            println!("commit_pending");
            io::stdout().flush()?;
            let result = backend.append_journal(current.journal.len(), b"lost-commit-frame");
            check(
                checks,
                "lost_commit_fences_unknown_outcome",
                result == Err(BackendError::OutcomeUnknown),
            )?;
            check(
                checks,
                "unknown_commit_session_cannot_be_renewed_or_reused",
                backend.append_journal(current.journal.len(), b"retry")
                    == Err(BackendError::OutcomeUnknown)
                    && backend.load() == Err(BackendError::OutcomeUnknown),
            )?;
            Ok(())
        }
        _ => Err("unknown durable probe mode".into()),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let input: Input = serde_json::from_str(&input)?;
    let mut checks = Vec::new();
    let result = run(input, &mut checks);
    if let Err(error) = result {
        eprintln!("durable probe failed: {error}");
        std::process::exit(1);
    }
    println!("{}", serde_json::to_string(&json!({"checks": checks}))?);
    Ok(())
}
