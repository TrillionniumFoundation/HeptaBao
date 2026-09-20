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

fn run(input: Input, checks: &mut Vec<Value>) -> Result<(), Box<dyn std::error::Error>> {
    if !input.endpoint.address.ip().is_loopback() || input.username != "hb_storage" {
        return Err("synthetic loopback fixture only".into());
    }
    match input.mode.as_str() {
        "basic" => basic(&input, checks),
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
