//! Synthetic qualification driver; configuration arrives only on bounded stdin.
//! Never use this example against an existing or production PostgreSQL database.
use heptabao_server::{
    outbound::EndpointConfig,
    postgres_storage::{PgStorageConfig, PostgresStorage, StorageError},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{Read, Write};
use zeroize::Zeroizing;

type ProbeResult = Result<(), Box<dyn std::error::Error>>;

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
    commit_gate: Option<std::path::PathBuf>,
}

fn check(checks: &mut Vec<Value>, case: &str, passed: bool) -> ProbeResult {
    checks.push(json!({"case": case, "passed": passed}));
    if passed {
        Ok(())
    } else {
        Err("storage assertion failed".into())
    }
}

fn run(input: Input, checks: &mut Vec<Value>) -> ProbeResult {
    if !input.endpoint.address.ip().is_loopback() || input.username != "hb_storage" {
        return Err("synthetic loopback fixture only".into());
    }
    let config = PgStorageConfig {
        endpoint: input.endpoint.clone(),
        connection_url: input.connection_url.clone(),
        username: input.username.clone(),
        password: input.password.clone(),
        scope: input.scope.clone(),
    };
    let store = PostgresStorage::new(config)?;
    if input.mode == "reject-connect" {
        return check(
            checks,
            "untrusted_tls_or_credentials_rejected",
            store.get("fixture/committed").is_err(),
        );
    }
    if input.mode == "reject-schema" {
        return check(
            checks,
            "altered_storage_constraints_rejected",
            store.get("fixture/committed").is_err(),
        );
    }
    if input.mode == "basic" {
        check(
            checks,
            "missing_schema_rejected_before_initialization",
            store.get("fixture/committed").is_err(),
        )?;
        store.initialize()?;
        store.initialize()?;
        check(checks, "schema_initialization_and_idempotent_reopen", true)?;
        let value: Vec<u8> = (0..=255).cycle().take(4096).collect();
        store.put("fixture/committed", &value)?;
        check(
            checks,
            "opaque_binary_value_roundtrip",
            store.get("fixture/committed")? == Some(value.clone()),
        )?;
        let boundary = vec![0xa5; 1024 * 1024];
        store.put("fixture/boundary", &boundary)?;
        check(
            checks,
            "maximum_value_roundtrip",
            store.get("fixture/boundary")? == Some(boundary),
        )?;
        check(
            checks,
            "oversized_value_preserves_previous_record",
            store
                .put("fixture/committed", &vec![0; 1024 * 1024 + 1])
                .is_err()
                && store.get("fixture/committed")? == Some(value.clone()),
        )?;
        store.put("fixture/empty", &[])?;
        check(
            checks,
            "empty_value_distinct_from_absence",
            store.get("fixture/empty")? == Some(Vec::new())
                && store.get("fixture/missing")?.is_none(),
        )?;
        for key in [
            "tree/a",
            "tree/a/child",
            "tree/branch/deep/item",
            "tree/b",
            "tree/z",
            "literal%_/child",
            "literalXX/other",
            "tree/中文",
        ] {
            store.put(key, b"opaque-test-value")?;
        }
        check(
            checks,
            "shallow_ordered_hierarchical_listing",
            store.list_page("tree/", "", 64)? == ["a", "a/", "b", "branch/", "z", "中文"],
        )?;
        check(
            checks,
            "keyset_pagination_after_is_exclusive",
            store.list_page("tree/", "a/", 2)? == ["b", "branch/"],
        )?;
        check(
            checks,
            "percent_underscore_prefix_are_literal",
            store.list_page("literal%_/", "", 64)? == ["child"],
        )?;
        let mut tx = store.begin(false)?;
        tx.put("atomic/one", b"one")?;
        tx.put("atomic/two", b"two")?;
        check(
            checks,
            "uncommitted_writes_are_invisible",
            store.get("atomic/one")?.is_none() && store.get("atomic/two")?.is_none(),
        )?;
        check(
            checks,
            "transaction_reads_its_writes",
            tx.get("atomic/one")? == Some(b"one".to_vec()),
        )?;
        tx.commit()?;
        check(
            checks,
            "multi_record_commit_publishes_together",
            store.get("atomic/one")? == Some(b"one".to_vec())
                && store.get("atomic/two")? == Some(b"two".to_vec()),
        )?;
        let mut tx = store.begin(false)?;
        tx.delete("atomic/one")?;
        tx.put("atomic/two", b"changed")?;
        tx.rollback()?;
        check(
            checks,
            "explicit_rollback_restores_all_records",
            store.get("atomic/one")? == Some(b"one".to_vec())
                && store.get("atomic/two")? == Some(b"two".to_vec()),
        )?;
        {
            let mut tx = store.begin(false)?;
            tx.put("fixture/dropped", b"never-commit")?;
        }
        check(
            checks,
            "dropped_transaction_is_rolled_back",
            store.get("fixture/dropped")?.is_none(),
        )?;
        let mut tx = store.begin(true)?;
        check(
            checks,
            "readonly_rejects_put_and_delete",
            tx.put("fixture/committed", b"bad").is_err() && tx.delete("fixture/committed").is_err(),
        )?;
        tx.rollback()?;
        let other = PostgresStorage::new(PgStorageConfig {
            endpoint: input.endpoint,
            connection_url: input.connection_url,
            username: input.username,
            password: input.password,
            scope: "fixture-two".into(),
        })?;
        check(
            checks,
            "separate_scope_cannot_read_first_scope",
            other.get("fixture/committed")?.is_none(),
        )?;
        other.put("fixture/committed", b"scope-two")?;
        check(
            checks,
            "same_key_in_other_scope_cannot_overwrite",
            store.get("fixture/committed")? == Some(value),
        )?;
        store.delete("fixture/empty")?;
        store.delete("fixture/empty")?;
        check(
            checks,
            "delete_is_idempotent",
            store.get("fixture/empty")?.is_none(),
        )?;
    } else if input.mode == "concurrency" {
        store.put("concurrent/key", b"before")?;
        let mut first = store.begin(false)?;
        check(
            checks,
            "transaction_initial_snapshot",
            first.get("concurrent/key")? == Some(b"before".to_vec()),
        )?;
        store.put("concurrent/key", b"after")?;
        check(
            checks,
            "repeatable_read_retains_snapshot",
            first.get("concurrent/key")? == Some(b"before".to_vec()),
        )?;
        check(
            checks,
            "stale_snapshot_update_is_rejected",
            first.put("concurrent/key", b"stale").is_err(),
        )?;
        check(
            checks,
            "failed_transaction_cannot_commit",
            first.commit().is_err(),
        )?;
        check(
            checks,
            "concurrent_commit_is_preserved",
            store.get("concurrent/key")? == Some(b"after".to_vec()),
        )?;
    } else if input.mode == "lost-commit" {
        let gate = input.commit_gate.ok_or("missing commit fixture gate")?;
        if !gate.is_absolute() || gate.exists() {
            return Err("invalid commit fixture gate".into());
        }
        let mut tx = store.begin(false)?;
        tx.put("fixture/lost-commit", b"committed-without-reply")?;
        println!("commit_pending");
        std::io::stdout().flush()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !gate.exists() {
            if std::time::Instant::now() >= deadline {
                return Err("commit fixture gate did not open".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        check(
            checks,
            "lost_commit_reply_reports_unknown_outcome",
            tx.commit() == Err(StorageError::OutcomeUnknown),
        )?;
    } else if input.mode == "pending-write" {
        let mut tx = store.begin(false)?;
        tx.put("fixture/uncommitted", b"must-not-survive")?;
        println!("transaction_pending");
        std::io::stdout()
            .flush()
            .map_err(|_| "fixture output failed")?;
        std::thread::sleep(std::time::Duration::from_secs(30));
        return Err("fault injector did not terminate pending transaction".into());
    } else if input.mode == "after-crash" {
        let value: Vec<u8> = (0..=255).cycle().take(4096).collect();
        check(
            checks,
            "committed_value_survives_reopen",
            store.get("fixture/committed")? == Some(value),
        )?;
        check(
            checks,
            "uncommitted_value_absent_after_crash",
            store.get("fixture/uncommitted")?.is_none(),
        )?;
    } else {
        return Err("unknown fixture mode".into());
    }
    Ok(())
}

fn main() {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut checks = Vec::new();
    let result = (|| -> ProbeResult {
        std::io::stdin()
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| "fixture input failed")?;
        if bytes.len() > 65536 {
            return Err("fixture input exceeds bound".into());
        }
        let input: Input = serde_json::from_slice(&bytes).map_err(|_| "invalid fixture input")?;
        run(input, &mut checks)
    })();
    println!("{}", json!({"checks":checks,"passed":result.is_ok()}));
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
