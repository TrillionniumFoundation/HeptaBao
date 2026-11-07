#![cfg(unix)]
use heptabao_personal_vault::*;
use std::error::Error;
use std::fs::{self, DirBuilder};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
const PASSWORD: &[u8] = b"synthetic-only-passphrase-2026";
const TTL: Duration = Duration::from_secs(300);
struct Temp(PathBuf);
impl Temp {
    fn new() -> std::io::Result<Self> {
        let unique = format!(
            "hb-personal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(std::io::Error::other)?
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
    fn child(&self, name: &str) -> std::io::Result<PathBuf> {
        let p = self.0.join(name);
        DirBuilder::new().mode(0o700).create(&p)?;
        Ok(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn login(id: &str) -> VaultItem {
    VaultItem {
        id: id.into(),
        kind: ItemKind::Login,
        title: "Synthetic login".into(),
        username: Some("fixture-user".into()),
        origin: Some("https://example.test".into()),
        secret: "synthetic-secret-that-must-not-leak".into(),
        notes: "private synthetic note".into(),
        totp: Some(TotpConfig {
            secret_base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 8,
            period: 30,
        }),
    }
}
#[test]
fn ciphertext_reopen_recovery_and_password_rotation() -> std::result::Result<(), Box<dyn Error>> {
    let t = Temp::new()?;
    let root = t.child("original")?;
    let (mut s, recovery) = VaultSession::create(&root, PASSWORD, TTL)?;
    s.put(login("demo"), 0)?;
    let backup = s.encrypted_backup()?;
    assert!(!backup.windows(16).any(|x| x == b"synthetic-secret"));
    assert_eq!(s.get("demo")?.secret, "synthetic-secret-that-must-not-leak");
    assert_eq!(
        s.login_for_origin("demo", "https://example.test")?.id,
        "demo"
    );
    assert!(
        s.login_for_origin("demo", "https://example.test.evil.test")
            .is_err()
    );
    assert!(s.login_for_origin("demo", "https://other.test").is_err());
    assert!(
        s.login_for_origin("demo", "https://example.test/login")
            .is_err()
    );
    assert!(!format!("{:?}", s.get("demo")?).contains("synthetic-secret"));
    drop(s);
    assert!(matches!(
        VaultSession::open(&root, b"wrong-password-long-enough", TTL),
        Err(VaultError::WrongKeyOrCorrupt)
    ));
    let mut s = VaultSession::open(&root, PASSWORD, TTL)?;
    assert_eq!(s.metadata()?.revision, 1);
    s.change_password(b"new-synthetic-passphrase-2026", 1)?;
    drop(s);
    assert!(VaultSession::open(&root, PASSWORD, TTL).is_err());
    let s = VaultSession::open(&root, b"new-synthetic-passphrase-2026", TTL)?;
    assert_eq!(s.get("demo")?.notes, "private synthetic note");
    drop(s);
    let s = VaultSession::open_with_recovery(&root, &recovery, TTL)?;
    assert_eq!(s.metadata()?.revision, 2);
    drop(s);
    let recovered = t.child("replacement-device")?;
    let mut s = VaultSession::restore_with_recovery(&recovered, &backup, &recovery, TTL)?;
    assert_eq!(s.get("demo")?.secret, "synthetic-secret-that-must-not-leak");
    s.change_password(b"replacement-device-new-password", 1)?;
    drop(s);
    let s = VaultSession::open(&recovered, b"replacement-device-new-password", TTL)?;
    assert_eq!(s.metadata()?.revision, 2);
    Ok(())
}
#[test]
fn authenticated_header_and_ciphertext_tampering_fail() -> std::result::Result<(), Box<dyn Error>> {
    let t = Temp::new()?;
    let root = t.child("vault")?;
    let (s, recovery) = VaultSession::create(&root, PASSWORD, TTL)?;
    let backup = s.encrypted_backup()?;
    drop(s);
    for (i, field) in ["revision", "vault_id", "body", "kdf"].iter().enumerate() {
        let mut e: serde_json::Value = serde_json::from_slice(&backup)?;
        match *field {
            "revision" => e["revision"] = serde_json::json!(11),
            "vault_id" => e["vault_id"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAA"),
            "body" => e["body"]["ciphertext"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAA"),
            "kdf" => e["kdf"]["memory_kib"] = serde_json::json!(u32::MAX),
            _ => return Err("unknown fixture field".into()),
        }
        let dest = t.child(&format!("corrupt-{i}"))?;
        assert!(
            VaultSession::restore_with_recovery(&dest, &serde_json::to_vec(&e)?, &recovery, TTL)
                .is_err()
        );
        assert!(!dest.join("vault.hbv").exists());
    }
    Ok(())
}
#[test]
fn revision_fence_lock_expiry_and_orphan_recovery() -> std::result::Result<(), Box<dyn Error>> {
    let t = Temp::new()?;
    let root = t.child("vault")?;
    let (mut s, _) = VaultSession::create(&root, PASSWORD, TTL)?;
    assert!(matches!(
        VaultSession::open(&root, PASSWORD, TTL),
        Err(VaultError::Busy)
    ));
    assert_eq!(s.put(login("demo"), 99), Err(VaultError::Conflict));
    assert_eq!(s.metadata()?.revision, 0);
    s.put(login("demo"), 0)?;
    assert_eq!(s.delete("demo", 0), Err(VaultError::Conflict));
    s.lock();
    assert!(matches!(s.get("demo"), Err(VaultError::Locked)));
    drop(s);
    fs::write(
        root.join("pending-crashed-writer"),
        b"incomplete-ciphertext",
    )?;
    let mut s = VaultSession::open(&root, PASSWORD, Duration::from_millis(20))?;
    std::thread::sleep(Duration::from_millis(30));
    assert!(s.is_expired());
    assert_eq!(s.delete("demo", 1), Err(VaultError::Locked));
    drop(s);
    let s = VaultSession::open(&root, PASSWORD, TTL)?;
    assert_eq!(s.get("demo")?.id, "demo");
    Ok(())
}
#[test]
fn unsafe_files_symlinks_hardlinks_and_external_change_rejected()
-> std::result::Result<(), Box<dyn Error>> {
    let t = Temp::new()?;
    let root = t.child("vault")?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
    assert!(matches!(
        VaultSession::create(&root, PASSWORD, TTL),
        Err(VaultError::UnsafePath)
    ));
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let (mut s, _) = VaultSession::create(&root, PASSWORD, TTL)?;
    let file = root.join("vault.hbv");
    let bytes = fs::read(&file)?;
    fs::write(&file, b"attacker-mutated-content")?;
    assert_eq!(s.put(login("demo"), 0), Err(VaultError::Conflict));
    drop(s);
    fs::write(&file, &bytes)?;
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644))?;
    assert!(matches!(
        VaultSession::open(&root, PASSWORD, TTL),
        Err(VaultError::UnsafePath)
    ));
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
    fs::hard_link(&file, root.join("other-link"))?;
    assert!(matches!(
        VaultSession::open(&root, PASSWORD, TTL),
        Err(VaultError::UnsafePath)
    ));
    fs::remove_file(root.join("other-link"))?;
    let alias = t.0.join("alias");
    symlink(&root, &alias)?;
    assert!(matches!(
        VaultSession::open(&alias, PASSWORD, TTL),
        Err(VaultError::UnsafePath)
    ));
    fs::rename(&file, root.join("real"))?;
    symlink(root.join("real"), &file)?;
    assert!(matches!(
        VaultSession::open(&root, PASSWORD, TTL),
        Err(VaultError::UnsafePath)
    ));
    Ok(())
}
#[test]
fn import_export_and_local_health() -> std::result::Result<(), Box<dyn Error>> {
    let t = Temp::new()?;
    let root = t.child("vault")?;
    let (mut s, _) = VaultSession::create(&root, PASSWORD, TTL)?;
    s.put(login("one"), 0)?;
    s.put(login("two"), 1)?;
    assert_eq!(s.health()?.reused_entries, 2);
    let exported = s.export_plaintext()?;
    s.delete("one", 2)?;
    assert_eq!(s.metadata()?.item_count, 1);
    s.import_plaintext(&exported, 3)?;
    assert_eq!(s.metadata()?.item_count, 2);
    let mut foreign: serde_json::Value = serde_json::from_slice(&exported)?;
    foreign["vault_id"] = serde_json::json!("another-vault");
    assert_eq!(
        s.import_plaintext(&serde_json::to_vec(&foreign)?, 4),
        Err(VaultError::InvalidInput)
    );
    assert_eq!(s.metadata()?.revision, 4);
    Ok(())
}
#[test]
fn all_entry_kinds_survive_reopen_and_bounds_fail_closed() -> std::result::Result<(), Box<dyn Error>>
{
    let t = Temp::new()?;
    let root = t.child("vault")?;
    let (mut session, _) = VaultSession::create(&root, PASSWORD, TTL)?;
    let mut note = login("note");
    note.kind = ItemKind::Note;
    note.origin = None;
    note.username = None;
    note.secret = String::new();
    note.notes = "synthetic private note".into();
    session.put(note, 0)?;
    let mut api = login("api");
    api.kind = ItemKind::Api;
    api.origin = None;
    api.secret = "synthetic api key".into();
    session.put(api, 1)?;
    let mut too_large = login("oversized");
    too_large.secret = "x".repeat(heptabao_personal_vault::MAX_FIELD_BYTES + 1);
    assert_eq!(session.put(too_large, 2), Err(VaultError::InvalidInput));
    let mut bad_origin = login("suffix");
    bad_origin.origin = Some("https://*.example.test".into());
    assert_eq!(session.put(bad_origin, 2), Err(VaultError::InvalidInput));
    assert_eq!(session.metadata()?.revision, 2);
    drop(session);
    let reopened = VaultSession::open(&root, PASSWORD, TTL)?;
    assert_eq!(reopened.get("note")?.notes, "synthetic private note");
    assert_eq!(reopened.get("api")?.secret, "synthetic api key");
    assert!(
        reopened
            .login_for_origin("api", "https://example.test")
            .is_err()
    );
    Ok(())
}
#[test]
fn totp_rfc6238_vectors_and_password_generation() -> std::result::Result<(), Box<dyn Error>> {
    let times = [
        59,
        1_111_111_109,
        1_111_111_111,
        1_234_567_890,
        2_000_000_000,
        20_000_000_000,
    ];
    let expected = [
        [
            "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
        ],
        [
            "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
        ],
        [
            "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
        ],
    ];
    for (i, (algorithm, key)) in [
        (TotpAlgorithm::Sha1, b"12345678901234567890".as_slice()),
        (
            TotpAlgorithm::Sha256,
            b"12345678901234567890123456789012".as_slice(),
        ),
        (
            TotpAlgorithm::Sha512,
            b"1234567890123456789012345678901234567890123456789012345678901234".as_slice(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let c = TotpConfig {
            secret_base32: base32(key),
            algorithm,
            digits: 8,
            period: 30,
        };
        for (j, time) in times.iter().enumerate() {
            assert_eq!(&*totp(&c, *time)?, expected[i][j]);
        }
    }
    for seed in [
        "JBSWY3DPEHPK3PXP",
        "gez dgnbv",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ=",
    ] {
        let config = TotpConfig {
            secret_base32: seed.into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
        };
        assert!(totp(&config, 59).is_err());
    }
    let a = generate_password(32)?;
    let b = generate_password(32)?;
    assert_eq!(a.len(), 32);
    assert_ne!(*a, *b);
    assert!(generate_password(15).is_err());
    assert!(generate_password(129).is_err());
    Ok(())
}
fn base32(bytes: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut bits = 0u16;
    let mut n = 0;
    for b in bytes {
        bits = (bits << 8) | u16::from(*b);
        n += 8;
        while n >= 5 {
            n -= 5;
            out.push(char::from(A[usize::from((bits >> n) & 31)]));
        }
        bits &= (1 << n) - 1;
    }
    if n > 0 {
        out.push(char::from(A[usize::from((bits << (5 - n)) & 31)]));
    }
    out
}
#[test]
fn exact_origins_reject_ambiguous_forms() {
    for x in [
        "https://example.test",
        "https://example.test:8443",
        "https://xn--bcher-kva.test",
    ] {
        assert!(valid_https_origin(x), "{x}");
    }
    for x in [
        "http://example.test",
        "https://EXAMPLE.test",
        "https://example.test.",
        "https://example.test:443",
        "https://example.test:0443",
        "https://example.test/login",
        "https://example.test?x=1",
        "https://user@example.test",
        "https://*.example.test",
        "https://127.0.0.1",
        "https://127.1",
        "https://0177.0.0.1",
        "https://0x7f.0.0.1",
        "https://127.0.0.0x1",
        "https://[::1]",
        "https://example.test#foo",
        "https://example.test\\evil",
    ] {
        assert!(!valid_https_origin(x), "{x}");
    }
}
#[test]
fn recovery_publication_failure_never_creates_initial_ciphertext()
-> std::result::Result<(), Box<dyn Error>> {
    let t = Temp::new()?;
    let root = t.child("vault")?;
    let outputs = t.child("outputs")?;
    let occupied = outputs.join("occupied.json");
    heptabao_personal_vault::write_private_file(&occupied, b"preserve-existing-file")?;
    assert!(matches!(
        VaultSession::create_with_recovery_file(&root, PASSWORD, TTL, &occupied),
        Err(VaultError::Exists)
    ));
    assert!(!root.join("vault.hbv").exists());
    assert_eq!(fs::read(&occupied)?, b"preserve-existing-file");
    fs::set_permissions(&outputs, fs::Permissions::from_mode(0o755))?;
    let recovery = outputs.join("recovery.json");
    assert!(matches!(
        VaultSession::create_with_recovery_file(&root, PASSWORD, TTL, &recovery),
        Err(VaultError::UnsafePath)
    ));
    assert!(!root.join("vault.hbv").exists());
    fs::set_permissions(&outputs, fs::Permissions::from_mode(0o700))?;
    let session = VaultSession::create_with_recovery_file(&root, PASSWORD, TTL, &recovery)?;
    let metadata = session.metadata()?;
    let document: serde_json::Value = serde_json::from_slice(&fs::read(&recovery)?)?;
    assert_eq!(document["vault_id"], metadata.vault_id);
    assert!(root.join("vault.hbv").exists());
    drop(session);
    let unused = outputs.join("unused.json");
    assert!(matches!(
        VaultSession::create_with_recovery_file(&root, PASSWORD, TTL, &unused),
        Err(VaultError::Exists)
    ));
    assert!(!unused.exists());
    Ok(())
}
#[test]
fn independent_cli_processes_keep_secret_out_of_stdout() -> std::result::Result<(), Box<dyn Error>>
{
    let t = Temp::new()?;
    let root = t.child("vault")?;
    let outputs = t.child("outputs")?;
    let recovery = outputs.join("recovery.json");
    let initial = cli(
        &root,
        "init",
        serde_json::json!({"password":String::from_utf8_lossy(PASSWORD),"output":recovery}),
    )?;
    assert!(initial["ok"].as_bool() == Some(true));
    let put = cli(
        &root,
        "put",
        serde_json::json!({"password":String::from_utf8_lossy(PASSWORD),"expected_revision":0,"item":login("process")}),
    )?;
    assert_eq!(put["metadata"]["revision"], 1);
    let listing = cli(
        &root,
        "list",
        serde_json::json!({"password":String::from_utf8_lossy(PASSWORD)}),
    )?;
    assert_eq!(listing["metadata"]["item_count"], 1);
    let clear = outputs.join("readback.json");
    cli(
        &root,
        "get",
        serde_json::json!({"password":String::from_utf8_lossy(PASSWORD),"id":"process","output":clear}),
    )?;
    let item: VaultItem = serde_json::from_slice(&fs::read(&clear)?)?;
    assert_eq!(item.secret, "synthetic-secret-that-must-not-leak");
    assert_eq!(fs::metadata(&clear)?.permissions().mode() & 0o777, 0o600);
    let backup = outputs.join("backup.hbv");
    cli(
        &root,
        "backup",
        serde_json::json!({"password":String::from_utf8_lossy(PASSWORD),"output":backup}),
    )?;
    let new_root = t.child("replacement")?;
    let recovery: serde_json::Value = serde_json::from_slice(&fs::read(&recovery)?)?;
    cli(
        &new_root,
        "restore",
        serde_json::json!({"input":backup,"recovery_key":recovery["recovery_key"]}),
    )?;
    assert_eq!(
        VaultSession::open(&new_root, PASSWORD, TTL)?
            .metadata()?
            .item_count,
        1
    );
    Ok(())
}
#[test]
fn cli_denials_publish_no_plaintext_and_report_failure() -> std::result::Result<(), Box<dyn Error>>
{
    let t = Temp::new()?;
    let root = t.child("vault")?;
    let output = t.child("outputs")?.join("must-not-exist.json");
    let (mut session, _) = VaultSession::create(&root, PASSWORD, TTL)?;
    session.put(login("protected"), 0)?;
    drop(session);
    let cases = [
        (
            "get",
            serde_json::json!({"password":"synthetic-wrong-passphrase", "id":"protected", "output":output}),
        ),
        (
            "export",
            serde_json::json!({"password":String::from_utf8_lossy(PASSWORD), "output":output}),
        ),
        (
            "put",
            serde_json::json!({"password":String::from_utf8_lossy(PASSWORD), "expected_revision":0, "item":login("stale")}),
        ),
    ];
    for (command, request) in cases {
        let mut child = Command::new(env!("CARGO_BIN_EXE_heptabao-vault"))
            .arg(&root)
            .arg(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut input) = child.stdin.take() {
            input.write_all(&serde_json::to_vec(&request)?)?;
        }
        let result = child.wait_with_output()?;
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&result.stderr)?;
        assert_eq!(error["ok"], false);
        assert!(!String::from_utf8_lossy(&result.stderr).contains("synthetic"));
        assert!(!output.exists());
    }
    assert_eq!(
        VaultSession::open(&root, PASSWORD, TTL)?
            .metadata()?
            .revision,
        1
    );
    Ok(())
}
fn cli(
    root: &std::path::Path,
    command: &str,
    request: serde_json::Value,
) -> std::result::Result<serde_json::Value, Box<dyn Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_heptabao-vault"))
        .arg(root)
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut input) = child.stdin.take() {
        input.write_all(&serde_json::to_vec(&request)?)?;
    }
    let result = child.wait_with_output()?;
    let stdout = String::from_utf8(result.stdout)?;
    let stderr = String::from_utf8(result.stderr)?;
    assert!(!stdout.contains("synthetic-secret"));
    assert!(!stderr.contains("synthetic-secret"));
    assert!(!stdout.contains("synthetic-only-passphrase"));
    assert!(!stderr.contains("synthetic-only-passphrase"));
    assert!(result.status.success(), "redacted CLI error: {stderr}");
    Ok(serde_json::from_str(&stdout)?)
}
#[test]
fn kill_owner_child() -> std::result::Result<(), Box<dyn Error>> {
    let Some(path) = std::env::var_os("HB_PERSONAL_TEST_CRASH_ROOT") else {
        return Ok(());
    };
    let _session = VaultSession::open(&PathBuf::from(path), PASSWORD, TTL)?;
    println!("VAULT_OWNER_READY");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(())
}
#[test]
fn killed_owner_releases_fence_and_committed_data_survives()
-> std::result::Result<(), Box<dyn Error>> {
    let t = Temp::new()?;
    let root = t.child("vault")?;
    let (mut session, _) = VaultSession::create(&root, PASSWORD, TTL)?;
    session.put(login("survivor"), 0)?;
    drop(session);
    let mut child = Command::new(std::env::current_exe()?)
        .args(["--exact", "kill_owner_child", "--nocapture"])
        .env("HB_PERSONAL_TEST_CRASH_ROOT", &root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let out = child.stdout.take().ok_or("no child stdout")?;
    let mut reader = BufReader::new(out);
    let mut ready = false;
    for _ in 0..8 {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line.contains("VAULT_OWNER_READY") {
            ready = true;
            break;
        }
    }
    assert!(ready);
    assert!(matches!(
        VaultSession::open(&root, PASSWORD, TTL),
        Err(VaultError::Busy)
    ));
    child.kill()?;
    let status = child.wait()?;
    assert!(!status.success());
    let session = VaultSession::open(&root, PASSWORD, TTL)?;
    assert_eq!(session.get("survivor")?.id, "survivor");
    Ok(())
}
