use super::super::{Response, Service, erase_json};
use super::*;
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn request(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    service.handle(method, path, "", token, body)
}

type SeedSource = (
    super::super::tests::Root,
    Service,
    Zeroizing<String>,
    Zeroizing<String>,
);

fn source(configured_native: bool) -> Result<SeedSource, Box<dyn std::error::Error>> {
    let root = super::super::tests::Root::new();
    let mut service = root.service()?;
    if configured_native {
        service.configure_native_v6_storage(crate::configuration::NativeStorageProfile::File)?;
    }
    let mut initialized = request(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({
            "secret_shares": 1, "secret_threshold": 1
        }),
    );
    assert_eq!(initialized.status, 200);
    let key = Zeroizing::new(
        initialized.body["keys"][0]
            .as_str()
            .ok_or("actual Shamir share")?
            .to_owned(),
    );
    let token = Zeroizing::new(
        initialized.body["root_token"]
            .as_str()
            .ok_or("actual root token")?
            .to_owned(),
    );
    erase_json(&mut initialized.body);
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        request(&mut service, "POST", "sys/init/ack", &token, json!({})).status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/seed",
            &token,
            json!({"type":"kv", "options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "seed/data/proof",
            &token,
            json!({"data":{"value":"actual-shamir-seed-custody"}})
        )
        .status,
        200
    );
    assert!(service.record_root.is_some());
    assert!(service.native_root.is_none());
    Ok((root, service, key, token))
}

fn private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

fn private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn receipt_file(
    root: &Path,
    receipt: &SeedReceipt,
) -> Result<(PathBuf, String), Box<dyn std::error::Error>> {
    let mut bytes = serde_json::to_vec(receipt)?;
    bytes.push(b'\n');
    let path = root.join("export-receipt.json");
    private_file(&path, &bytes)?;
    Ok((path, hex(&crypto::digest(&bytes))))
}

#[test]
fn native_seed_actual_shamir_export_stage_and_cold_unseal() -> TestResult {
    let (root, service, key, token) = source(false)?;
    let cluster_id = service
        .state
        .as_ref()
        .ok_or("actual source state")?
        .cluster_id
        .clone();
    let source_path = service.data_dir.clone();
    drop(service);
    let bundle = root.path.join("bundle");
    let exported = export(&source_path, &bundle)?;
    assert_eq!(exported.operation, Operation::Export);
    assert!(!exported.cryptographic_state_admission_performed);
    assert!(!exported.ha_qualified);
    let public = serde_json::to_string(&exported)?;
    assert!(!public.contains(key.as_str()));
    assert!(!public.contains(token.as_str()));
    assert!(!public.contains("wrapped_barrier_key"));
    let (receipt, receipt_hash) = receipt_file(&root.path, &exported)?;
    let destination = root.path.join("cohort-state");
    let staged = stage(&bundle, &destination, &receipt, &receipt_hash)?;
    assert_eq!(staged.operation, Operation::Stage);
    assert_eq!(staged.seed, exported.seed);
    assert_ne!(
        staged.destination_directory.inode,
        exported.destination_directory.inode
    );
    for leaf in LEAVES {
        assert_eq!(
            crypto::digest(&fs::read(source_path.join(leaf))?),
            crypto::digest(&fs::read(destination.join(leaf))?)
        );
        assert_eq!(
            fs::metadata(destination.join(leaf))?.permissions().mode() & 0o7777,
            0o600
        );
    }
    let mut reopened = Service::new(destination, &root.path.join("staged-audit.jsonl"))?;
    assert_eq!(
        request(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        reopened
            .state
            .as_ref()
            .ok_or("actual destination state")?
            .cluster_id,
        cluster_id
    );
    assert_eq!(
        request(&mut reopened, "GET", "seed/data/proof", &token, json!({})).body["data"]["data"]["value"],
        "actual-shamir-seed-custody"
    );
    assert!(
        reopened.native_root.is_none(),
        "physical staging must not activate V6"
    );
    Ok(())
}

#[test]
fn native_seed_refuses_the_actual_running_file_writer_fence() -> TestResult {
    let (root, service, _key, _token) = source(false)?;
    let destination = root.path.join("must-not-exist");
    assert_eq!(
        export(&service.data_dir, &destination).err(),
        Some(SeedError::WriterActive)
    );
    assert!(!destination.exists());
    drop(service);
    export(&root.path.join("data"), &destination)?;
    Ok(())
}

#[test]
fn native_seed_refuses_unknown_native_provider_and_pending_leaves() -> TestResult {
    let (root, service, _key, _token) = source(false)?;
    let source_path = service.data_dir.clone();
    drop(service);
    for (index, leaf) in [
        "nv6.0000000000000000.00000000000000000000000000000000.hbo",
        "durable-backend.json",
        "init-recovery.hbe",
        "seal-rekey.json",
        "unknown-owner",
    ]
    .iter()
    .enumerate()
    {
        let extra = source_path.join(leaf);
        private_file(&extra, b"unadmitted owner marker")?;
        let destination = root.path.join(format!("rejected-{index}"));
        assert_eq!(
            export(&source_path, &destination).err(),
            Some(SeedError::SourceRejected)
        );
        assert!(!destination.exists());
        assert!(
            extra.exists(),
            "rejection must preserve the unknown source owner"
        );
        fs::remove_file(extra)?;
    }
    let spool = source_path.join("snapshot-spool");
    private_dir(&spool)?;
    assert_eq!(
        export(&source_path, &root.path.join("spool-rejected")).err(),
        Some(SeedError::SourceRejected)
    );
    assert!(spool.exists());
    Ok(())
}

#[test]
fn native_seed_refuses_missing_linked_or_public_source_files() -> TestResult {
    let (root, service, _key, _token) = source(false)?;
    let source_path = service.data_dir.clone();
    drop(service);
    let leaf = source_path.join("state.hbs");
    let retained = root.path.join("retained-checkpoint");
    fs::rename(&leaf, &retained)?;
    assert!(export(&source_path, &root.path.join("missing-rejected")).is_err());
    symlink(&retained, &leaf)?;
    assert!(export(&source_path, &root.path.join("symlink-rejected")).is_err());
    fs::remove_file(&leaf)?;
    fs::hard_link(&retained, &leaf)?;
    assert!(export(&source_path, &root.path.join("hardlink-rejected")).is_err());
    fs::remove_file(&leaf)?;
    fs::rename(&retained, &leaf)?;
    fs::set_permissions(&leaf, fs::Permissions::from_mode(0o644))?;
    assert!(export(&source_path, &root.path.join("public-rejected")).is_err());
    fs::set_permissions(&leaf, fs::Permissions::from_mode(0o600))?;
    let linked_root = root.path.join("linked-root");
    symlink(&source_path, &linked_root)?;
    assert!(export(&linked_root, &root.path.join("root-link-rejected")).is_err());
    Ok(())
}

#[test]
fn native_seed_original_directory_identity_survives_no_path_replacement() -> TestResult {
    let (root, service, _key, _token) = source(false)?;
    let source_path = service.data_dir.clone();
    drop(service);
    let mut captured = CapturedSeed::capture(&source_path)?;
    fs::rename(&source_path, root.path.join("retained-source"))?;
    private_dir(&source_path)?;
    assert!(captured.recheck().is_err());
    Ok(())
}

#[test]
fn native_seed_same_inode_content_change_cannot_reuse_the_captured_hash() -> TestResult {
    let (_root, service, _key, _token) = source(false)?;
    let source_path = service.data_dir.clone();
    drop(service);
    let mut captured = CapturedSeed::capture(&source_path)?;
    let leaf = source_path.join("state.hbs");
    let mut file = OpenOptions::new().read(true).write(true).open(&leaf)?;
    let inode = file.metadata()?.ino();
    let mut first = [0_u8; 1];
    file.read_exact(&mut first)?;
    first[0] ^= 1;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&first)?;
    file.sync_all()?;
    assert_eq!(file.metadata()?.ino(), inode);
    assert!(captured.recheck().is_err());
    Ok(())
}

#[test]
fn native_seed_atomic_publication_refuses_a_raced_empty_destination() -> TestResult {
    let (root, service, _key, _token) = source(false)?;
    let source_path = service.data_dir.clone();
    drop(service);
    let mut captured = CapturedSeed::capture(&source_path)?;
    let parent = DirectoryFence::acquire(&root.path)?;
    let mut staged = StagedSeed::create(&parent)?;
    staged.write(&mut captured)?;
    let destination = root.path.join("appeared-after-preflight");
    private_dir(&destination)?;
    let existing_inode = fs::metadata(&destination)?.ino();
    assert_eq!(
        publish_noreplace(&parent.handle, &staged.leaf, "appeared-after-preflight"),
        Err(SeedError::DestinationExists)
    );
    assert_eq!(fs::metadata(&destination)?.ino(), existing_inode);
    assert!(fs::read_dir(&destination)?.next().is_none());
    assert!(
        staged.path.exists(),
        "the exact staged source must remain for reconciliation"
    );
    staged.verify(&staged.path)?;
    Ok(())
}

#[test]
fn native_seed_stage_requires_the_exact_export_receipt_digest() -> TestResult {
    let (root, service, _key, _token) = source(false)?;
    let source_path = service.data_dir.clone();
    drop(service);
    let bundle = root.path.join("bundle");
    let exported = export(&source_path, &bundle)?;
    let (receipt, digest) = receipt_file(&root.path, &exported)?;
    let mut wrong = digest.clone();
    wrong.replace_range(..1, if digest.starts_with('0') { "1" } else { "0" });
    let destination = root.path.join("receipt-rejected");
    assert_eq!(
        stage(&bundle, &destination, &receipt, &wrong).err(),
        Some(SeedError::ReceiptRejected)
    );
    assert!(!destination.exists());
    Ok(())
}

#[test]
fn native_seed_stage_refuses_ciphertext_drift_after_export() -> TestResult {
    let (root, service, _key, _token) = source(false)?;
    let source_path = service.data_dir.clone();
    drop(service);
    let bundle = root.path.join("bundle");
    let exported = export(&source_path, &bundle)?;
    let (receipt, digest) = receipt_file(&root.path, &exported)?;
    let mut journal = OpenOptions::new()
        .append(true)
        .open(bundle.join("journal.hbj"))?;
    journal.write_all(b"changed ciphertext")?;
    journal.sync_all()?;
    drop(journal);
    let destination = root.path.join("drift-rejected");
    assert_eq!(
        stage(&bundle, &destination, &receipt, &digest).err(),
        Some(SeedError::ReceiptRejected)
    );
    assert!(!destination.exists());
    Ok(())
}

#[test]
fn native_seed_receipt_cannot_claim_crypto_or_ha_qualification() -> TestResult {
    let (root, service, _key, _token) = source(false)?;
    let source_path = service.data_dir.clone();
    drop(service);
    let bundle = root.path.join("bundle");
    let mut exported = export(&source_path, &bundle)?;
    exported.ha_qualified = true;
    let (receipt, digest) = receipt_file(&root.path, &exported)?;
    let destination = root.path.join("false-claim-rejected");
    assert_eq!(
        stage(&bundle, &destination, &receipt, &digest).err(),
        Some(SeedError::ReceiptRejected)
    );
    assert!(!destination.exists());
    Ok(())
}

#[test]
fn native_seed_rejects_actual_unacknowledged_initialization_recovery() -> TestResult {
    use base64::Engine;
    let root = super::super::tests::Root::new();
    let mut service = root.service()?;
    let nonce =
        Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(crypto::random::<32>()?));
    let mut initialized = request(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({
            "secret_shares":1,"secret_threshold":1,"recovery_nonce":nonce.as_str()
        }),
    );
    assert_eq!(initialized.status, 200);
    assert_eq!(initialized.body["init_ack_required"], true);
    erase_json(&mut initialized.body);
    let source_path = service.data_dir.clone();
    drop(service);
    assert!(super::super::initialization_recovery_pending(&source_path)?);
    let destination = root.path.join("pending-rejected");
    assert_eq!(
        export(&source_path, &destination).err(),
        Some(SeedError::SourceRejected)
    );
    assert!(!destination.exists());
    assert!(super::super::initialization_recovery_pending(&source_path)?);
    Ok(())
}

#[test]
fn native_seed_refuses_legacy_raw_seal_without_rewriting_its_envelope() -> TestResult {
    let (root, service, _key, _token) = source(false)?;
    let source_path = service.data_dir.clone();
    drop(service);
    let path = source_path.join("seal.json");
    let encoded = Zeroizing::new(fs::read(&path)?);
    let mut seal: SealMetadata = serde_json::from_slice(&encoded)?;
    seal.share_format = "raw-v1".into();
    seal.validate()?;
    let encoded = Zeroizing::new(serde_json::to_vec(&seal)?);
    let mut file = OpenOptions::new().write(true).truncate(true).open(&path)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);
    let before = crypto::digest(&fs::read(&path)?);
    let destination = root.path.join("raw-seal-rejected");
    assert_eq!(
        export(&source_path, &destination).err(),
        Some(SeedError::SourceRejected)
    );
    assert!(!destination.exists());
    assert_eq!(crypto::digest(&fs::read(&path)?), before);
    Ok(())
}

#[test]
fn native_seed_rejects_real_native_v6_objects_instead_of_dropping_them() -> TestResult {
    let (root, mut service, _key, token) = source(true)?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            super::super::native_storage::ACTIVATE_PATH,
            &token,
            json!({})
        )
        .status,
        204
    );
    assert!(service.native_root.is_some());
    let source_path = service.data_dir.clone();
    drop(service);
    let destination = root.path.join("v6-rejected");
    assert_eq!(
        export(&source_path, &destination).err(),
        Some(SeedError::SourceRejected)
    );
    assert!(!destination.exists());
    assert!(fs::read_dir(&source_path)?.any(|entry| {
        entry.is_ok_and(|entry| entry.file_name().to_string_lossy().starts_with("nv6."))
    }));
    Ok(())
}

#[test]
fn native_seed_enforces_the_original_durable_file_bound_before_reading() -> TestResult {
    let (root, service, _key, _token) = source(false)?;
    let source_path = service.data_dir.clone();
    drop(service);
    let journal = OpenOptions::new()
        .write(true)
        .open(source_path.join("journal.hbj"))?;
    journal.set_len(MAX_BACKEND_ARTIFACT_BYTES as u64 + 1)?;
    journal.sync_all()?;
    let destination = root.path.join("overbound-rejected");
    assert_eq!(
        export(&source_path, &destination).err(),
        Some(SeedError::SourceRejected)
    );
    assert!(!destination.exists());
    Ok(())
}
