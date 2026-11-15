#![cfg(unix)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use heptabao_credential_broker::{Bootstrap, Credential, initialize};
use std::{
    error::Error,
    fs,
    io::Write,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Command, Stdio},
};

type TestResult = Result<(), Box<dyn Error>>;

struct SyntheticDirectory(PathBuf);
impl SyntheticDirectory {
    fn new() -> Result<Self, Box<dyn Error>> {
        let mut entropy = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut entropy)
            .map_err(|_| "random_failure")?;
        let path = std::env::temp_dir().join(format!(
            "hb-broker-algorithm-{}",
            URL_SAFE_NO_PAD.encode(entropy)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for SyntheticDirectory {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.0);
    }
}

fn rejects_algorithm(algorithm: &str, bits: &str, public_prefix: &[u8]) -> TestResult {
    let directory = SyntheticDirectory::new()?;
    let key_path = directory.0.join("synthetic-key");
    let generated = Command::new("ssh-keygen")
        .args(["-q", "-t", algorithm, "-b", bits, "-N", ""])
        .arg("-f")
        .arg(&key_path)
        .output()?;
    assert!(
        generated.status.success(),
        "synthetic_key_generation_failed"
    );
    // Independently parse the generated key with OpenSSH: this negative control
    // must contain a valid unsupported algorithm, not merely malformed input.
    let public = Command::new("ssh-keygen")
        .args(["-y", "-f"])
        .arg(&key_path)
        .output()?;
    assert!(public.status.success(), "synthetic_key_parse_failed");
    assert!(
        public.stdout.starts_with(public_prefix),
        "synthetic_key_algorithm_changed"
    );
    let bootstrap = Bootstrap {
        synthetic_only: true,
        credentials: vec![Credential {
            id: "git-sign".into(),
            kind: "git_sshsig".into(),
            target: "git:synthetic-algorithm-policy".into(),
            method: "SIGN".into(),
            path: "git".into(),
            secret: fs::read_to_string(&key_path)?,
        }],
    };
    let bootstrap_json = zeroize::Zeroizing::new(serde_json::to_vec(&bootstrap)?);
    let sdk_root = directory.0.join("sdk-owner");
    let result = initialize(&sdk_root, bootstrap);
    assert!(
        matches!(result, Err(error) if matches!(error.0, "invalid_signing_key" | "unsupported_signing_key")),
        "unsupported_algorithm_not_rejected_by_sdk"
    );
    assert!(!sdk_root.exists(), "rejected_sdk_key_was_persisted");

    let cli_root = directory.0.join("cli-owner");
    let executable = std::env::var_os("HEPTABAO_BROKER_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heptabao-credential-broker").into());
    let mut child = Command::new(executable)
        .arg("init")
        .arg(&cli_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("missing_stdin")?
        .write_all(&bootstrap_json)?;
    let output = child.wait_with_output()?;
    assert!(
        !output.status.success(),
        "unsupported_algorithm_cli_success"
    );
    assert!(output.stdout.is_empty(), "unexpected_public_output");
    let status: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert!(status["ok"] == false, "missing_cli_rejection");
    assert!(
        matches!(
            status["error"].as_str(),
            Some("invalid_signing_key" | "unsupported_signing_key")
        ),
        "unexpected_cli_error"
    );
    assert!(
        status.as_object().is_some_and(|object| object.len() == 2),
        "unexpected_cli_fields"
    );
    assert!(!cli_root.exists(), "rejected_cli_key_was_persisted");
    Ok(())
}

#[test]
fn valid_rsa_key_is_rejected_by_sdk_and_cli() -> TestResult {
    rejects_algorithm("rsa", "3072", b"ssh-rsa ")
}

#[test]
fn valid_ecdsa_key_is_rejected_by_sdk_and_cli() -> TestResult {
    rejects_algorithm("ecdsa", "256", b"ecdsa-sha2-nistp256 ")
}
