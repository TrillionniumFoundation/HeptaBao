//! Real SDK callbacks to HeptaBao's encrypted DurableService and mutation ledger.
//! The owner and authorization inputs are explicit test fixtures; no server API
//! catalog, namespace authority, seal/HA fencing or plugin ABI qualification.
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use heptabao_domain::{CanonicalPath, Id};
use heptabao_durable_service::{Barrier, BarrierError, DurableService, MutationOutcome};
use heptabao_plugin_host::{
    PluginMutationContext,
    sdk_backend::{SdkBackendHost, SdkBridgeError, SdkLaunch, SdkStorage, SdkStorageEntry},
    sdk_durable::{SdkDurableStorage, SdkStorageScope},
};
use ring::{
    aead,
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

/// Simulates loss of the acknowledgement after the real durable commit.
struct WriteThenUnknown<'a>(&'a mut dyn SdkStorage);
impl SdkStorage for WriteThenUnknown<'_> {
    fn get(
        &mut self,
        key: &str,
        deadline: Instant,
    ) -> Result<Option<SdkStorageEntry>, SdkBridgeError> {
        self.0.get(key, deadline)
    }
    fn put(&mut self, entry: SdkStorageEntry, deadline: Instant) -> Result<(), SdkBridgeError> {
        self.0.put(entry, deadline)?;
        Err(SdkBridgeError::OutcomeUnknown)
    }
    fn delete(&mut self, key: &str, deadline: Instant) -> Result<(), SdkBridgeError> {
        self.0.delete(key, deadline)
    }
    fn list_page(
        &mut self,
        prefix: &str,
        after: &str,
        limit: i64,
        deadline: Instant,
    ) -> Result<Vec<String>, SdkBridgeError> {
        self.0.list_page(prefix, after, limit, deadline)
    }
}

struct RealAead(aead::LessSafeKey);
impl RealAead {
    fn new(mut key: [u8; 32]) -> Result<Self, BarrierError> {
        let value = aead::UnboundKey::new(&aead::AES_256_GCM, &key)
            .map(|key| Self(aead::LessSafeKey::new(key)))
            .map_err(|_| BarrierError);
        key.zeroize();
        value
    }
}
impl Barrier for RealAead {
    fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BarrierError> {
        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| BarrierError)?;
        let mut bytes = Zeroizing::new(plaintext.to_vec());
        self.0
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(context),
                &mut *bytes,
            )
            .map_err(|_| BarrierError)?;
        let mut out = Vec::with_capacity(16 + bytes.len());
        out.extend_from_slice(b"HBA1");
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&bytes);
        Ok(out)
    }
    fn open(&self, context: &[u8], protected: &[u8]) -> Result<Vec<u8>, BarrierError> {
        if protected.len() < 32 || &protected[..4] != b"HBA1" {
            return Err(BarrierError);
        }
        let nonce: [u8; 12] = protected[4..16].try_into().map_err(|_| BarrierError)?;
        let mut bytes = Zeroizing::new(protected[16..].to_vec());
        self.0
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(context),
                &mut bytes,
            )
            .map(|v| v.to_vec())
            .map_err(|_| BarrierError)
    }
    fn sealed_len_bound(&self, length: usize) -> Option<usize> {
        length.checked_add(32)
    }
}
fn checksum(path: &Path) -> Result<[u8; 32], Box<dyn Error>> {
    digest(&SHA256, &std::fs::read(path)?)
        .as_ref()
        .try_into()
        .map_err(|_| "digest length".into())
}
fn check(ok: bool, label: &str, checks: &mut Vec<String>) -> Result<(), Box<dyn Error>> {
    if !ok {
        return Err(label.to_owned().into());
    }
    checks.push(label.to_owned());
    Ok(())
}
fn context(name: &str) -> Result<PluginMutationContext, Box<dyn Error>> {
    Ok(PluginMutationContext::new(
        Id::parse("actual-sdk-test-owner")?,
        Id::parse(name)?,
        [0x42; 32],
    )?)
}
fn config(
    companion: &Path,
    plugin: &Path,
    out: &Path,
    round: u8,
) -> Result<SdkLaunch, Box<dyn Error>> {
    let sockets = out.join(format!("s{round}"));
    std::fs::create_dir(&sockets)?;
    std::fs::set_permissions(&sockets, std::fs::Permissions::from_mode(0o700))?;
    Ok(SdkLaunch {
        companion: companion.to_owned(),
        companion_sha256: checksum(companion)?,
        plugin: plugin.to_owned(),
        plugin_sha256: checksum(plugin)?,
        plugin_args: vec!["--serve".to_owned()],
        socket_directory: sockets,
        private_log: out.join(format!("companion-{round}.private.log")),
        timeout: Duration::from_secs(10),
        default_ttl_seconds: 3600,
        max_ttl_seconds: 86400,
    })
}
fn value(response: Option<Value>) -> Option<String> {
    response?
        .get("data")?
        .get("value")?
        .as_str()
        .map(str::to_owned)
}
fn raw_files(
    root: &Path,
    visit: &mut impl FnMut(&[u8]) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    for child in std::fs::read_dir(root)? {
        let child = child?;
        let kind = child.file_type()?;
        if kind.is_dir() {
            raw_files(&child.path(), visit)?
        } else if kind.is_file() {
            visit(&std::fs::read(child.path())?)?
        } else {
            return Err("unexpected durable file kind".into());
        }
    }
    Ok(())
}
fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 4 {
        return Err("companion plugin fresh-output arguments".into());
    }
    let companion = PathBuf::from(&args[1]);
    let plugin = PathBuf::from(&args[2]);
    let out = PathBuf::from(&args[3]);
    std::fs::create_dir(&out)?;
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700))?;
    let mut key = Zeroizing::new([0u8; 32]);
    SystemRandom::new()
        .fill(&mut *key)
        .map_err(|_| "CSPRNG key")?;
    let cluster = Id::parse("sdk-durable-actual-test-cluster")?;
    let mount = Id::parse("actual-sdk-secret-mount")?;
    let scope = SdkStorageScope::new(&cluster, &CanonicalPath::parse("/sdk-owned")?, &mount, 7)?;
    let sibling =
        SdkStorageScope::new(&cluster, &CanonicalPath::parse("/sdk-sibling")?, &mount, 7)?;
    let next = SdkStorageScope::new(&cluster, &CanonicalPath::parse("/sdk-owned")?, &mount, 8)?;
    let data = out.join("encrypted-store");
    let mut durable = DurableService::create_new(&data, RealAead::new(*key)?, 2048)?;
    let mut checks = Vec::new();
    let text = "encrypted-Rust-SDK-broker-payload";
    let mut audit = Vec::new();
    let mut host = {
        let mut view =
            SdkDurableStorage::new(&mut durable, scope.clone(), context("owned-init-1")?)?;
        SdkBackendHost::launch(&config(&companion, &plugin, &out, 1)?, &mut view)?
    };
    check(
        true,
        "real-Hepta-Rust-AutoMTLS-SDK-Backend-Setup-Initialize",
        &mut checks,
    )?;
    {
        let mut view =
            SdkDurableStorage::new(&mut durable, scope.clone(), context("owned-write-1")?)?;
        host.handle_request("update", "item", json!({"value":text}), &mut view)?;
        check(
            view.mutations().len() == 1
                && matches!(
                    view.mutations()[0].outcome,
                    MutationOutcome::Committed { .. }
                ),
            "real-SDK-Storage-Put-commits-existing-encrypted-DurableService-ledger",
            &mut checks,
        )?;
        audit.push(format!("{:?}", view.mutations()));
    }
    let generation = durable.generation();
    let resource = format!(
        "entries/{}",
        digest(&SHA256, b"item")
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let independent = durable
        .get(scope.durable_namespace(), &resource)?
        .ok_or("actual encrypted entry")?;
    let record: Value = serde_json::from_slice(independent.expose())?;
    check(
        record["key"] == "item"
            && record["value_hex"]
                == text
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
        "independent-DurableService-Get-decrypts-actual-SDK-record",
        &mut checks,
    )?;
    let mut inspected = 0;
    raw_files(&data, &mut |bytes| {
        inspected += 1;
        if bytes.windows(text.len()).any(|v| v == text.as_bytes()) {
            return Err("plaintext SDK value on durable disk".into());
        }
        Ok(())
    })?;
    check(
        inspected > 0,
        "all-actual-durable-disk-files-exclude-plaintext-SDK-value",
        &mut checks,
    )?;
    {
        let mut view =
            SdkDurableStorage::new(&mut durable, scope.clone(), context("owned-close-1")?)?;
        host.close(&mut view)?;
    }
    drop(host);
    durable.close()?;
    let mut durable = DurableService::reopen(&data, RealAead::new(*key)?, 2048)?;
    check(
        durable.generation() == generation,
        "actual-encrypted-DurableService-reopen-preserves-ledger-generation",
        &mut checks,
    )?;
    let mut host = {
        let mut view =
            SdkDurableStorage::new(&mut durable, scope.clone(), context("owned-init-2")?)?;
        SdkBackendHost::launch(&config(&companion, &plugin, &out, 2)?, &mut view)?
    };
    {
        let mut view =
            SdkDurableStorage::new(&mut durable, scope.clone(), context("owned-read-2")?)?;
        check(
            value(host.handle_request("read", "item", json!({}), &mut view)?).as_deref()
                == Some(text),
            "fresh-real-SDK-process-reads-reopened-encrypted-Rust-storage",
            &mut checks,
        )?;
    }
    {
        let mut view =
            SdkDurableStorage::new(&mut durable, scope.clone(), context("owned-write-1")?)?;
        host.handle_request("update", "item", json!({"value":text}), &mut view)?;
        check(
            view.mutations().len() == 1
                && matches!(
                    view.mutations()[0].outcome,
                    MutationOutcome::Duplicate { .. }
                ),
            "real-SDK-storage-replay-is-existing-ledger-Duplicate",
            &mut checks,
        )?;
        audit.push(format!("{:?}", view.mutations()));
    }
    check(
        durable.generation() == generation,
        "duplicate-mutation-does-not-advance-durable-generation",
        &mut checks,
    )?;
    {
        let mut view =
            SdkDurableStorage::new(&mut durable, scope.clone(), context("owned-write-1")?)?;
        check(
            matches!(
                host.handle_request(
                    "update",
                    "item",
                    json!({"value":"conflicting-must-not-write"}),
                    &mut view
                ),
                Err(SdkBridgeError::Backend)
            ),
            "real-SDK-conflicting-ledger-identity-rejected",
            &mut checks,
        )?;
    }
    check(
        durable.generation() == generation,
        "conflicting-mutation-does-not-advance-durable-generation",
        &mut checks,
    )?;
    {
        let mut view =
            SdkDurableStorage::new(&mut durable, scope.clone(), context("owned-read-3")?)?;
        check(
            value(host.handle_request("read", "item", json!({}), &mut view)?).as_deref()
                == Some(text),
            "conflicting-storage-call-preserves-committed-value",
            &mut checks,
        )?;
    }
    for (round, other, label) in [
        (3, sibling, "namespace-scoped-SDK-storage-isolation"),
        (4, next, "mount-incarnation-scoped-SDK-storage-isolation"),
    ] {
        let mut view =
            SdkDurableStorage::new(&mut durable, other, context(&format!("isolated-{round}"))?)?;
        let mut other_host =
            SdkBackendHost::launch(&config(&companion, &plugin, &out, round)?, &mut view)?;
        check(
            other_host
                .handle_request("read", "item", json!({}), &mut view)?
                .is_none(),
            label,
            &mut checks,
        )?;
        other_host.close(&mut view)?;
    }
    {
        let mut view =
            SdkDurableStorage::new(&mut durable, scope.clone(), context("owned-parallel-1")?)?;
        host.handle_request("update", "parallel", json!({}), &mut view)?;
        check(
            view.mutations().len() == 16
                && view
                    .mutations()
                    .iter()
                    .all(|m| matches!(m.outcome, MutationOutcome::Committed { .. })),
            "sixteen-real-concurrent-SDK-Puts-commit-sixteen-owned-encrypted-ledger-records",
            &mut checks,
        )?;
        let response = host
            .handle_request("read", "parallel", json!({}), &mut view)?
            .ok_or("parallel list")?;
        check(
            response["data"]["page"] == json!(["00", "01", "02", "03", "04", "05", "06"])
                && response["data"]["next"] == json!(["07", "08", "09", "10", "11", "12", "13"]),
            "actual-encrypted-SDK-ListPage-prefix-after-limit",
            &mut checks,
        )?;
        audit.push(format!("{:?}", view.mutations()));
    }
    {
        let mut view =
            SdkDurableStorage::new(&mut durable, scope.clone(), context("owned-delete-1")?)?;
        host.handle_request("delete", "parallel", json!({}), &mut view)?;
        host.handle_request("delete", "item", json!({}), &mut view)?;
        check(
            view.mutations().len() == 17
                && view
                    .mutations()
                    .iter()
                    .all(|m| matches!(m.outcome, MutationOutcome::Committed { .. })),
            "real-SDK-Delete-and-sixteen-concurrent-Deletes-commit-owned-durable-ledger",
            &mut checks,
        )?;
        check(
            view.get("item", Instant::now() + Duration::from_secs(1))?
                .is_none(),
            "real-SDK-Delete-removes-actual-encrypted-storage-entry",
            &mut checks,
        )?;
        host.close(&mut view)?;
        audit.push(format!("{:?}", view.mutations()));
    }
    drop(host);
    let last_generation = durable.generation();
    durable.close()?;
    let mut durable = DurableService::reopen(&data, RealAead::new(*key)?, 2048)?;
    {
        let mut view =
            SdkDurableStorage::new(&mut durable, scope.clone(), context("owned-final-reopen")?)?;
        check(
            view.get("item", Instant::now() + Duration::from_secs(1))?
                .is_none()
                && view
                    .list_page("", "", 0, Instant::now() + Duration::from_secs(1))?
                    .is_empty(),
            "actual-encrypted-store-reopen-preserves-SDK-deletions",
            &mut checks,
        )?;
    }
    {
        let mut view =
            SdkDurableStorage::new(&mut durable, scope.clone(), context("owned-uncertain-1")?)?;
        let mut host = SdkBackendHost::launch(&config(&companion, &plugin, &out, 5)?, &mut view)?;
        let mut uncertain = WriteThenUnknown(&mut view);
        check(
            matches!(
                host.handle_request("update", "uncertain", json!({}), &mut uncertain),
                Err(SdkBridgeError::OutcomeUnknown)
            ),
            "actual-durable-commit-lost-ack-remains-OutcomeUnknown-even-if-plugin-swallows-storage-error",
            &mut checks,
        )?;
        check(
            matches!(
                host.handle_request("read", "item", json!({}), &mut uncertain),
                Err(SdkBridgeError::Fenced)
            ),
            "uncertain-storage-mutation-fences-same-SDK-host-next-call",
            &mut checks,
        )?;
        drop(host);
        check(
            view.mutations().len() == 1
                && matches!(
                    view.mutations()[0].outcome,
                    MutationOutcome::Committed { .. }
                ),
            "unknown-result-does-not-claim-durable-mutation-rollback",
            &mut checks,
        )?;
        audit.push(format!("{:?}", view.mutations()));
    }
    durable.close()?;
    let durable = DurableService::reopen(&data, RealAead::new(*key)?, 2048)?;
    let resource = format!(
        "entries/{}",
        digest(&SHA256, b"uncertain")
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let committed = durable
        .get(scope.durable_namespace(), &resource)?
        .ok_or("unknown mutation committed entry")?;
    let committed: Value = serde_json::from_slice(committed.expose())?;
    check(
        committed["key"] == "uncertain"
            && committed["value_hex"]
                == "committed-before-lost-ack"
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
        "independent-encrypted-reopen-retains-actual-write-after-unknown-SDK-result",
        &mut checks,
    )?;
    let final_generation = durable.generation();
    durable.close()?;
    let report = json!({"checks":checks,"passed":true,"actual_existing_DurableService_and_mutation_ledger":true,"actual_AES_256_GCM_and_CSPRNG_nonce":true,"owner_and_authorization_are_explicit_test_fixtures":true,"scope_namespace_mount_incarnation_bound":true,"disk_files_checked":inspected,"initial_generation":generation,"generation_after_deletes":last_generation,"final_generation":final_generation,"mutation_observations":audit,"HeptaBao_server_plugin_catalog_mount_API_qualified":false,"HeptaBao_plugin_ABI_qualified":false,"full_OpenBao_replacement":false});
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(out.join("Rust-SDK-encrypted-durable-result.original.json"))?;
    file.write_all(&serde_json::to_vec_pretty(&report)?)?;
    file.sync_all()?;
    println!(
        "Rust encrypted SDK host checks={} passed=true",
        checks.len()
    );
    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    run()
}
