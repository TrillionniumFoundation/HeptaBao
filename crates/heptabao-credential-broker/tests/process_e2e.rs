#![cfg(unix)]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use heptabao_credential_broker::{
    Bootstrap, Broker, Credential, Operation, Request, SignedGrant, authorize_revocation, call,
    initialize, issue, write_private,
};
use std::{
    error::Error,
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

type TestResult = Result<(), Box<dyn Error>>;
// Qualification can run these compiled test artifacts on an authorized Unix
// host whose process sandbox permits AF_UNIX; this is a test-only executable
// path override, never an authorization or credential override.
fn executable() -> std::ffi::OsString {
    std::env::var_os("HEPTABAO_BROKER_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heptabao-credential-broker").into())
}
struct Fixture {
    base: PathBuf,
    root: PathBuf,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let mut entropy = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut entropy)
            .map_err(|_| "random")?;
        let base =
            std::env::temp_dir().join(format!("hb-broker-{}", URL_SAFE_NO_PAD.encode(entropy)));
        fs::DirBuilder::new().mode(0o700).create(&base)?;
        let root = base.join("owner");
        Ok(Self { base, root })
    }
    fn initialize(&self, target: &str) -> TestResult {
        initialize(
            &self.root,
            Bootstrap {
                synthetic_only: true,
                credentials: vec![Credential {
                    id: "api".into(),
                    kind: "loopback_http".into(),
                    target: target.into(),
                    method: "POST".into(),
                    path: "/execute".into(),
                    secret: "SYNTHETIC-SECRET-DO-NOT-RETURN".into(),
                }],
            },
        )?;
        Ok(())
    }
    fn op(&self, target: &str, id: &str) -> Operation {
        Operation {
            operation_id: id.into(),
            task_id: "task-one".into(),
            run_id: "run-one".into(),
            credential_id: "api".into(),
            target: target.into(),
            method: "POST".into(),
            path: "/execute".into(),
            body_base64: URL_SAFE_NO_PAD.encode(b"synthetic-payload"),
        }
    }
    fn start(&self, max: usize) -> Result<Process, Box<dyn Error>> {
        let old_inode = fs::symlink_metadata(self.root.join("broker.sock"))
            .ok()
            .map(|m| m.ino());
        let child = Command::new(executable())
            .arg("serve")
            .arg(&self.root)
            .arg(max.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut p = Process { child: Some(child) };
        let started = Instant::now();
        loop {
            if let Ok(meta) = fs::symlink_metadata(self.root.join("broker.sock"))
                && Some(meta.ino()) != old_inode
                && meta.mode() & 0o077 == 0
            {
                break;
            }
            if started.elapsed() > Duration::from_secs(5) {
                return Err("socket timeout".into());
            }
            if p.child.as_mut().ok_or("child")?.try_wait()?.is_some() {
                let output = p.child.take().ok_or("child")?.wait_with_output()?;
                return Err(
                    format!("server exited: {}", String::from_utf8_lossy(&output.stderr)).into(),
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(p)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.base);
    }
}
struct Process {
    child: Option<Child>,
}
impl Process {
    fn finish(&mut self) -> TestResult {
        let output = self
            .child
            .take()
            .ok_or("missing child")?
            .wait_with_output()?;
        assert!(output.status.success(), "broker failed");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        Ok(())
    }
    fn kill(&mut self) -> TestResult {
        let mut c = self.child.take().ok_or("child")?;
        c.kill()?;
        let output = c.wait_with_output()?;
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        Ok(())
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _kill = c.kill();
            let _wait = c.wait();
        }
    }
}
fn response(listener: TcpListener, bytes: Vec<u8>) -> thread::JoinHandle<Result<Vec<u8>, String>> {
    thread::spawn(move || {
        let (mut s, _) = listener.accept().map_err(|_| "accept")?;
        s.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| "timeout")?;
        let mut input = Vec::new();
        let mut b = [0u8; 1];
        while !input.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).map_err(|_| "read")?;
            input.push(b[0]);
            if input.len() > 8192 {
                return Err("overflow".into());
            }
        }
        s.write_all(&bytes).map_err(|_| "write")?;
        Ok(input)
    })
}
fn target(listener: &TcpListener) -> Result<String, Box<dyn Error>> {
    Ok(format!("http://{}", listener.local_addr()?))
}
fn request(grant: &SignedGrant, op: &Operation) -> Request {
    Request::Execute {
        grant: grant.clone(),
        operation: op.clone(),
    }
}

#[test]
fn real_process_api_echo_is_not_released_and_result_survives_restart() -> TestResult {
    let fixture = Fixture::new()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let origin = target(&listener)?;
    fixture.initialize(&origin)?;
    let op = fixture.op(&origin, "normal-1");
    let grant = issue(&fixture.root, &op, 60)?;
    let server=response(listener,b"HTTP/1.1 200 OK\r\nX-Secret: SYNTHETIC-SECRET-DO-NOT-RETURN\r\nContent-Length: 35\r\n\r\nSYNTHETIC-SECRET-DO-NOT-RETURN".to_vec());
    let mut process = fixture.start(1)?;
    let result = call(&fixture.root, &request(&grant, &op))?;
    assert_eq!(result["receipt"]["http_status"], 200);
    assert_eq!(result["receipt"]["http_success"], true);
    assert!(!result.to_string().contains("SECRET"));
    process.finish()?;
    let upstream = server
        .join()
        .map_err(|_| "fixture panic")?
        .map_err(|e| -> Box<dyn Error> { e.into() })?;
    assert!(
        String::from_utf8(upstream)?
            .contains("Authorization: Bearer SYNTHETIC-SECRET-DO-NOT-RETURN")
    );
    let mut second = fixture.start(2)?;
    let replay = call(&fixture.root, &request(&grant, &op))?;
    assert_eq!(replay, result);
    let status = call(
        &fixture.root,
        &Request::Status {
            grant,
            operation: op,
        },
    )?;
    assert_eq!(status, result);
    second.finish()?;
    assert!(!fs::read_to_string(fixture.root.join("state.json"))?.contains("SECRET"));
    Ok(())
}

#[test]
fn wrong_target_body_task_signature_and_expired_grants_do_not_contact_target() -> TestResult {
    let fixture = Fixture::new()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let origin = target(&listener)?;
    fixture.initialize(&origin)?;
    let op = fixture.op(&origin, "deny-1");
    let grant = issue(&fixture.root, &op, 60)?;
    let expired = issue(&fixture.root, &fixture.op(&origin, "expired-1"), 1)?;
    let mut process = fixture.start(5)?;
    let mut wrong = op.clone();
    wrong.target = "http://127.0.0.1:1".into();
    assert_eq!(call(&fixture.root, &request(&grant, &wrong))?["ok"], false);
    wrong = op.clone();
    wrong.task_id = "other-task".into();
    assert_eq!(call(&fixture.root, &request(&grant, &wrong))?["ok"], false);
    wrong = op.clone();
    wrong.body_base64 = URL_SAFE_NO_PAD.encode(b"changed");
    assert_eq!(call(&fixture.root, &request(&grant, &wrong))?["ok"], false);
    let mut value = serde_json::to_value(&grant)?;
    value["signature"] = serde_json::Value::String("A".repeat(43));
    let forged: SignedGrant = serde_json::from_value(value)?;
    assert_eq!(call(&fixture.root, &request(&forged, &op))?["ok"], false);
    thread::sleep(Duration::from_millis(1100));
    assert_eq!(
        call(
            &fixture.root,
            &request(&expired, &fixture.op(&origin, "expired-1"))
        )?["ok"],
        false
    );
    process.finish()?;
    assert!(listener.accept().is_err());
    Ok(())
}

#[test]
fn revocation_survives_process_restart() -> TestResult {
    let fixture = Fixture::new()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let origin = target(&listener)?;
    fixture.initialize(&origin)?;
    let op = fixture.op(&origin, "revoked-1");
    let grant = issue(&fixture.root, &op, 60)?;
    let mut process = fixture.start(1)?;
    let revocation = authorize_revocation(&fixture.root, &grant)?;
    assert_eq!(
        call(&fixture.root, &Request::Revoke { revocation })?["receipt"]["outcome"],
        "revoked"
    );
    process.finish()?;
    let mut next = fixture.start(1)?;
    assert_eq!(call(&fixture.root, &request(&grant, &op))?["ok"], false);
    next.finish()?;
    assert!(listener.accept().is_err());
    Ok(())
}

#[test]
fn killed_after_target_contact_remains_unknown_without_second_dispatch() -> TestResult {
    let fixture = Fixture::new()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let origin = target(&listener)?;
    fixture.initialize(&origin)?;
    let op = fixture.op(&origin, "crash-1");
    let grant = issue(&fixture.root, &op, 60)?;
    let mut process = fixture.start(100)?;
    let root = fixture.root.clone();
    let req = request(&grant, &op);
    let client = thread::spawn(move || call(&root, &req));
    let (mut upstream, _) = listener.accept()?;
    upstream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut bytes = [0u8; 4096];
    assert!(upstream.read(&mut bytes)? > 0);
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.root.join("state.json"))?)?;
    assert_eq!(
        state["operations"]["crash-1"]["receipt"]["outcome"],
        "outcome_unknown"
    );
    process.kill()?;
    assert!(client.join().map_err(|_| "client panic")?.is_err());
    drop(upstream);
    // The crashed broker left its own socket. The exclusive owner removes it
    // on restart, but never removes an unrelated ordinary file at that name.
    let mut next = fixture.start(1)?;
    let result = call(&fixture.root, &request(&grant, &op))?;
    assert_eq!(result["receipt"]["outcome"], "outcome_unknown");
    next.finish()?;
    listener.set_nonblocking(true)?;
    assert!(listener.accept().is_err());
    Ok(())
}

#[test]
fn redirect_is_not_followed_and_conflicting_id_is_rejected() -> TestResult {
    let fixture = Fixture::new()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let trap = TcpListener::bind("127.0.0.1:0")?;
    trap.set_nonblocking(true)?;
    let origin = target(&listener)?;
    fixture.initialize(&origin)?;
    let op = fixture.op(&origin, "redirect-1");
    let grant = issue(&fixture.root, &op, 60)?;
    let server = response(
        listener,
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {}/collect\r\n\r\n",
            target(&trap)?
        )
        .into_bytes(),
    );
    let mut process = fixture.start(2)?;
    assert_eq!(
        call(&fixture.root, &request(&grant, &op))?["receipt"]["http_status"],
        302
    );
    let mut changed = op.clone();
    changed.body_base64 = URL_SAFE_NO_PAD.encode(b"different");
    let changed_grant = issue(&fixture.root, &changed, 60)?;
    let result = call(&fixture.root, &request(&changed_grant, &changed))?;
    assert_eq!(result["error"], "operation_identity_conflict");
    process.finish()?;
    server
        .join()
        .map_err(|_| "fixture panic")?
        .map_err(|e| -> Box<dyn Error> { e.into() })?;
    assert!(trap.accept().is_err());
    Ok(())
}

#[test]
fn private_permissions_symlinks_and_competing_writer_are_rejected() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.initialize("http://127.0.0.1:9")?;
    let broker = Broker::open(&fixture.root)?;
    assert!(Broker::open(&fixture.root).is_err());
    drop(broker);
    let linked = fixture.base.join("linked");
    std::os::unix::fs::symlink(&fixture.root, &linked)?;
    assert!(Broker::open(&linked).is_err());
    fs::set_permissions(
        fixture.root.join("owner.key"),
        fs::Permissions::from_mode(0o644),
    )?;
    assert!(Broker::open(&fixture.root).is_err());
    Ok(())
}

#[test]
fn actual_cli_and_ed25519_git_sshsig_verify() -> TestResult {
    let fixture = Fixture::new()?;
    let key_path = fixture.base.join("synthetic-key");
    let keygen = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(&key_path)
        .output()?;
    assert!(keygen.status.success());
    let secret = fs::read_to_string(&key_path)?;
    let bootstrap = Bootstrap {
        synthetic_only: true,
        credentials: vec![Credential {
            id: "git-sign".into(),
            kind: "git_sshsig".into(),
            target: "git:synthetic-repo".into(),
            method: "SIGN".into(),
            path: "git".into(),
            secret,
        }],
    };
    let mut init = Command::new(executable())
        .arg("init")
        .arg(&fixture.root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    init.stdin
        .take()
        .ok_or("stdin")?
        .write_all(&serde_json::to_vec(&bootstrap)?)?;
    let out = init.wait_with_output()?;
    assert!(out.status.success());
    assert!(!String::from_utf8(out.stdout)?.contains("PRIVATE"));
    assert!(out.stderr.is_empty());
    let payload=b"tree 0000000000000000000000000000000000000000\nauthor Synthetic <synthetic@example.invalid> 1 +0000\ncommitter Synthetic <synthetic@example.invalid> 1 +0000\n\nsynthetic commit\n";
    let op = Operation {
        operation_id: "git-op".into(),
        task_id: "git-task".into(),
        run_id: "git-run".into(),
        credential_id: "git-sign".into(),
        target: "git:synthetic-repo".into(),
        method: "SIGN".into(),
        path: "git".into(),
        body_base64: URL_SAFE_NO_PAD.encode(payload),
    };
    let opfile = fixture.base.join("operation.json");
    let grantfile = fixture.base.join("grant.json");
    write_private(&opfile, &serde_json::to_vec(&op)?)?;
    let issue_out = Command::new(executable())
        .arg("issue")
        .arg(&fixture.root)
        .arg(&opfile)
        .arg(&grantfile)
        .arg("60")
        .output()?;
    assert!(issue_out.status.success());
    assert!(issue_out.stderr.is_empty());
    let mut process = fixture.start(1)?;
    let execution = Command::new(executable())
        .arg("execute")
        .arg(&fixture.root)
        .arg(&opfile)
        .arg(&grantfile)
        .output()?;
    assert!(execution.status.success());
    assert!(execution.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&execution.stdout)?;
    assert_eq!(value["ok"], true);
    process.finish()?;
    let pem = value["receipt"]["signature_pem"]
        .as_str()
        .ok_or("signature")?;
    let public = value["receipt"]["public_key"]
        .as_str()
        .ok_or("public key")?;
    let signature = fixture.base.join("commit.sig");
    write_private(&signature, pem.as_bytes())?;
    let allowed = fixture.base.join("allowed_signers");
    write_private(&allowed, format!("synthetic {public}\n").as_bytes())?;
    let mut verifier = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-n", "git", "-I", "synthetic", "-f"])
        .arg(&allowed)
        .arg("-s")
        .arg(&signature)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    verifier.stdin.take().ok_or("stdin")?.write_all(payload)?;
    let verified = verifier.wait_with_output()?;
    assert!(verified.status.success());
    assert!(!fs::read_to_string(fixture.root.join("state.json"))?.contains("PRIVATE KEY"));
    Ok(())
}

#[test]
fn owner_rejects_unscoped_targets_and_request_variants() -> TestResult {
    for target in [
        "https://127.0.0.1:443",
        "http://localhost:80",
        "http://8.8.8.8:80",
        "http://127.0.0.1:0",
        "http://127.0.0.1:80/",
        "http://user@127.0.0.1:80",
        "http://2130706433:80",
    ] {
        let f = Fixture::new()?;
        assert!(f.initialize(target).is_err());
        assert!(!f.root.exists());
    }
    let f = Fixture::new()?;
    f.initialize("http://127.0.0.1:9")?;
    let op = f.op("http://127.0.0.1:9", "policy-1");
    let mut bad = op.clone();
    bad.method = "GET".into();
    assert!(issue(&f.root, &bad, 60).is_err());
    bad = op.clone();
    bad.path = "/other".into();
    assert!(issue(&f.root, &bad, 60).is_err());
    bad = op.clone();
    bad.run_id = "".into();
    assert!(issue(&f.root, &bad, 60).is_err());
    bad = op.clone();
    bad.body_base64 = "eA==".into();
    assert!(issue(&f.root, &bad, 60).is_err());
    assert!(issue(&f.root, &op, 0).is_err());
    assert!(issue(&f.root, &op, 3601).is_err());
    Ok(())
}

fn cli_request(
    f: &Fixture,
    command: &str,
    op: &Path,
    grant: &Path,
) -> std::io::Result<std::process::Output> {
    Command::new(executable())
        .arg(command)
        .arg(&f.root)
        .arg(op)
        .arg(grant)
        .output()
}

#[test]
fn actual_cli_denials_have_nonzero_exit_and_no_target_contact() -> TestResult {
    let f = Fixture::new()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let origin = target(&listener)?;
    f.initialize(&origin)?;
    let op = f.op(&origin, "cli-denied");
    let grant = issue(&f.root, &op, 60)?;
    let mut wrong = op.clone();
    wrong.target = "http://127.0.0.1:1".into();
    let wrong_file = f.base.join("wrong.json");
    let op_file = f.base.join("op.json");
    let grant_file = f.base.join("grant.json");
    write_private(&wrong_file, &serde_json::to_vec(&wrong)?)?;
    write_private(&op_file, &serde_json::to_vec(&op)?)?;
    write_private(&grant_file, &serde_json::to_vec(&grant)?)?;
    let expired = f.op(&origin, "cli-expired");
    let expired_grant = issue(&f.root, &expired, 1)?;
    let expired_file = f.base.join("expired-op.json");
    let expired_grant_file = f.base.join("expired-grant.json");
    write_private(&expired_file, &serde_json::to_vec(&expired)?)?;
    write_private(&expired_grant_file, &serde_json::to_vec(&expired_grant)?)?;
    let mut process = f.start(4)?;
    let denied = cli_request(&f, "execute", &wrong_file, &grant_file)?;
    assert!(!denied.status.success());
    assert!(denied.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&denied.stdout)?["error"],
        "authorization_denied"
    );
    thread::sleep(Duration::from_millis(1100));
    let denied = cli_request(&f, "execute", &expired_file, &expired_grant_file)?;
    assert!(!denied.status.success());
    assert!(denied.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&denied.stdout)?["error"],
        "authorization_denied"
    );
    let revoked = Command::new(executable())
        .arg("revoke")
        .arg(&f.root)
        .arg(&grant_file)
        .output()?;
    assert!(revoked.status.success());
    assert!(revoked.stderr.is_empty());
    let denied = cli_request(&f, "execute", &op_file, &grant_file)?;
    assert!(!denied.status.success());
    assert!(denied.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&denied.stdout)?["error"],
        "authorization_denied"
    );
    assert!(!String::from_utf8_lossy(&denied.stdout).contains("SECRET"));
    process.finish()?;
    assert!(listener.accept().is_err());
    Ok(())
}

#[test]
fn cli_non_success_http_is_recorded_without_retry_and_queryable() -> TestResult {
    let f = Fixture::new()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let origin = target(&listener)?;
    f.initialize(&origin)?;
    let op = f.op(&origin, "http-failed");
    let grant = issue(&f.root, &op, 60)?;
    let op_file = f.base.join("op.json");
    let grant_file = f.base.join("grant.json");
    write_private(&op_file, &serde_json::to_vec(&op)?)?;
    write_private(&grant_file, &serde_json::to_vec(&grant)?)?;
    let server = response(
        listener,
        b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n".to_vec(),
    );
    let mut process = f.start(3)?;
    let failed = cli_request(&f, "execute", &op_file, &grant_file)?;
    assert!(!failed.status.success());
    assert!(failed.stderr.is_empty());
    let receipt: serde_json::Value = serde_json::from_slice(&failed.stdout)?;
    assert_eq!(receipt["receipt"]["outcome"], "completed");
    assert_eq!(receipt["receipt"]["http_status"], 503);
    assert_eq!(receipt["receipt"]["http_success"], false);
    server
        .join()
        .map_err(|_| "fixture panic")?
        .map_err(|e| -> Box<dyn Error> { e.into() })?;
    let replay = cli_request(&f, "execute", &op_file, &grant_file)?;
    assert!(!replay.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&replay.stdout)?,
        receipt
    );
    let status = cli_request(&f, "status", &op_file, &grant_file)?;
    assert!(status.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&status.stdout)?,
        receipt
    );
    process.finish()?;
    Ok(())
}

fn git(repo: &Path, tmp: &Path, config: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo)
        .args(["-c", "core.hooksPath=/dev/null"])
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "Synthetic Broker")
        .env("GIT_COMMITTER_NAME", "Synthetic Broker")
        .env("GIT_AUTHOR_EMAIL", "synthetic@example.invalid")
        .env("GIT_COMMITTER_EMAIL", "synthetic@example.invalid")
        .env("GIT_AUTHOR_DATE", "1700000000 +0000")
        .env("GIT_COMMITTER_DATE", "1700000000 +0000")
        .env("TMPDIR", tmp)
        .env("HEPTABAO_GIT_SIGNER_CONFIG", config)
        .env_remove("SSH_AUTH_SOCK");
    command
}
fn git_output(command: &mut Command) -> Result<Vec<u8>, Box<dyn Error>> {
    let result = command.output()?;
    if !result.status.success() {
        return Err(format!(
            "synthetic git command failed: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(result.stdout)
}

#[test]
fn actual_git_commit_signing_and_verify_commit_bind_repository_and_payload() -> TestResult {
    let f = Fixture::new()?;
    let repo = f.base.join("repository");
    let other = f.base.join("other-repository");
    let tmp = f.base.join("git-tmp");
    for path in [&repo, &other, &tmp] {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let config = f.base.join("signing.json");
    let signer = std::env::var_os("HEPTABAO_GIT_SIGNER_TEST_SCRIPT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/heptabao_git_signer.py")
        });
    let signer = fs::canonicalize(signer)?;
    let key = f.base.join("synthetic-signing-key");
    let generated = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "synthetic-only",
            "-f",
        ])
        .arg(&key)
        .output()?;
    assert!(generated.status.success());
    let public = PathBuf::from(format!("{}.pub", key.display()));
    initialize(
        &f.root,
        Bootstrap {
            synthetic_only: true,
            credentials: vec![Credential {
                id: "git-sign".into(),
                kind: "git_sshsig".into(),
                target: "git:synthetic-repository".into(),
                method: "SIGN".into(),
                path: "git".into(),
                secret: fs::read_to_string(&key)?,
            }],
        },
    )?;
    // Only the broker's private store retains the synthetic private key.
    fs::remove_file(&key)?;
    for repository in [&repo, &other] {
        git_output(git(repository, &tmp, &config).args(["init", "--quiet"]))?;
        fs::write(repository.join("hello.txt"), b"synthetic content\n")?;
        git_output(git(repository, &tmp, &config).args(["add", "hello.txt"]))?;
        git_output(git(repository, &tmp, &config).args(["config", "gpg.format", "ssh"]))?;
        git_output(
            git(repository, &tmp, &config)
                .args(["config", "gpg.ssh.program"])
                .arg(&signer),
        )?;
        git_output(
            git(repository, &tmp, &config)
                .args(["config", "user.signingkey"])
                .arg(&public),
        )?;
    }
    let tree = String::from_utf8(git_output(git(&repo, &tmp, &config).arg("write-tree"))?)?
        .trim()
        .to_string();
    let unsigned = String::from_utf8(git_output(git(&repo, &tmp, &config).args([
        "commit-tree",
        &tree,
        "-m",
        "Synthetic signed commit",
    ]))?)?
    .trim()
    .to_string();
    let payload = git_output(git(&repo, &tmp, &config).args(["cat-file", "commit", &unsigned]))?;
    let op = Operation {
        operation_id: "actual-commit".into(),
        task_id: "git-task".into(),
        run_id: "git-run".into(),
        credential_id: "git-sign".into(),
        target: "git:synthetic-repository".into(),
        method: "SIGN".into(),
        path: "git".into(),
        body_base64: URL_SAFE_NO_PAD.encode(&payload),
    };
    let grant = issue(&f.root, &op, 300)?;
    let op_path = f.base.join("commit-operation.json");
    let grant_path = f.base.join("commit-grant.json");
    write_private(&op_path, &serde_json::to_vec(&op)?)?;
    write_private(&grant_path, &serde_json::to_vec(&grant)?)?;
    let repo_meta = fs::metadata(&repo)?;
    let git_meta = fs::metadata(repo.join(".git"))?;
    let config_doc = serde_json::json!({"schema":1,"root":f.root,"op":op_path,"grant":grant_path,"broker_executable":PathBuf::from(executable()),"expected_repository":repo,"expected_tree":tree,"expected_repository_identity":{"device":repo_meta.dev(),"inode":repo_meta.ino(),"git_device":git_meta.dev(),"git_inode":git_meta.ino()}});
    write_private(&config, &serde_json::to_vec(&config_doc)?)?;
    let mut process = f.start(1)?;
    // An identical Git object in another repository does not authorize this
    // invocation. The resulting SSHSIG itself remains a transferable artifact.
    let denied = git(&other, &tmp, &config)
        .args([
            "commit",
            "-S",
            "--no-verify",
            "-m",
            "Synthetic signed commit",
        ])
        .output()?;
    assert!(!denied.status.success());
    git_output(git(&repo, &tmp, &config).args([
        "commit",
        "-S",
        "--no-verify",
        "-m",
        "Synthetic signed commit",
    ]))?;
    process.finish()?;
    let allowed = f.base.join("allowed-signers");
    write_private(
        &allowed,
        format!("synthetic@example.invalid {}", fs::read_to_string(&public)?).as_bytes(),
    )?;
    git_output(
        git(&repo, &tmp, &config)
            .args(["config", "gpg.ssh.allowedSignersFile"])
            .arg(&allowed),
    )?;
    // The signing adapter deliberately accepts sign only. Standard OpenSSH is
    // used explicitly for independent Git verification.
    git_output(git(&repo, &tmp, &config).args([
        "-c",
        "gpg.ssh.program=ssh-keygen",
        "verify-commit",
        "HEAD",
    ]))?;
    let committed = git_output(git(&repo, &tmp, &config).args(["rev-parse", "HEAD"]))?;
    let denied = git(&repo, &tmp, &config)
        .args([
            "commit",
            "-S",
            "--allow-empty",
            "--no-verify",
            "-m",
            "Unauthorized changed payload",
        ])
        .output()?;
    assert!(!denied.status.success());
    assert_eq!(
        git_output(git(&repo, &tmp, &config).args(["rev-parse", "HEAD"]))?,
        committed
    );
    let state: serde_json::Value = serde_json::from_slice(&fs::read(f.root.join("state.json"))?)?;
    assert_eq!(
        state["operations"].as_object().ok_or("operations")?.len(),
        1
    );
    assert!(!state.to_string().contains("PRIVATE KEY"));
    Ok(())
}
