#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use heptabao_plugin_host::OwnedExecutableImage;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp(std::path::PathBuf);
impl Temp {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "hb-kms-exec-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        let owned = Self(path);
        fs::set_permissions(&owned.0, fs::Permissions::from_mode(0o700))?;
        Ok(owned)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("true-elf"));
        let _ = fs::remove_dir(&self.0);
    }
}

fn elf_image(owned: &Temp) -> Result<(std::path::PathBuf, OwnedExecutableImage), Box<dyn Error>> {
    // Some distributions expose /usr/bin/true as a symlink. Executable
    // admission still forbids symlink traversal; give it an owned regular ELF.
    let source = fs::canonicalize("/usr/bin/true")?;
    let bytes = fs::read(source)?;
    if !bytes.starts_with(b"\x7fELF") {
        return Err(std::io::Error::other("system fixture is not an ELF image").into());
    }
    let path = owned.0.join("true-elf");
    fs::write(&path, &bytes)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o500))?;
    let metadata = fs::symlink_metadata(&path)?;
    assert!(metadata.is_file());
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o500);
    let digest: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .try_into()?;
    let image = OwnedExecutableImage::open(&path, digest)
        .map_err(|_| std::io::Error::other("test image admission failed"))?;
    Ok((path, image))
}

fn wait(mut child: Child) -> Result<std::process::ExitStatus, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let failure: Box<dyn Error> = loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => break error.into(),
        }
        if Instant::now() >= deadline {
            break "owned adapter fixture exceeded its test bound".into();
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    // Keep the same original Child through every failure. Failed termination
    // must still attempt the original terminal wait; neither cleanup success
    // nor KILL changes an over-budget/observation failure into test success.
    let _termination = child.kill();
    let _original_wait = child.wait();
    Err(failure)
}

fn command(path: &Path, owned: &Temp) -> Result<Command, Box<dyn Error>> {
    let time = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Known(
        rustix::time::ClockId::Monotonic,
    ))?;
    let now = u64::try_from(i128::from(time.tv_sec) * 1_000_000_000 + i128::from(time.tv_nsec))?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_heptabao-kms-sealed-exec"));
    command
        .args([
            "--heptabao-profile",
            "kms_sealed_exec_v1",
            "--heptabao-plugin",
        ])
        .arg(path)
        .args(["--heptabao-protocol", "1", "--heptabao-operation", "read"])
        .env_clear()
        .env("HEPTABAO_SANDBOX_PROVIDER", "sealed_exec_adapter")
        .env(
            "HEPTABAO_KMS_DEPLOYMENT",
            "/data/adapter-test-deployment.json",
        )
        .env("HEPTABAO_KMS_DEPLOYMENT_SHA256", "a".repeat(64))
        .env("HEPTABAO_KMS_PROVIDER", "transit")
        .env("HEPTABAO_KMS_TEMP", &owned.0)
        .env("HEPTABAO_KMS_TIMEOUT_MS", "5000")
        .env(
            "HEPTABAO_KMS_DEADLINE_MONOTONIC_NS",
            (now + 5_000_000_000).to_string(),
        )
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command)
}

#[test]
fn actual_sealed_elf_handoff_executes_and_returns_original_owned_wait() -> Result<(), Box<dyn Error>>
{
    // This proves descriptor handoff only. The true ELF is no KMS provider and
    // no HBR1 response or cryptographic success is asserted by this test.
    let owned = Temp::new()?;
    let (_, image) = elf_image(&owned)?;
    let child = command(image.descriptor_path(), &owned)?.spawn()?;
    let original_pid = child.id();
    let status = wait(child)?;
    assert!(
        original_pid > 0 && status.success(),
        "actual owned ELF terminal wait"
    );
    Ok(())
}

#[test]
fn mutable_path_and_unenrolled_environment_fail_without_execution() -> Result<(), Box<dyn Error>> {
    let owned = Temp::new()?;
    let (path, image) = elf_image(&owned)?;
    let status = wait(command(&path, &owned)?.spawn()?)?;
    assert_eq!(
        status.code(),
        Some(2),
        "ordinary pathname never replaces admitted descriptor"
    );
    let mut command = command(image.descriptor_path(), &owned)?;
    command.env("PATH", "/usr/bin");
    assert_eq!(
        wait(command.spawn()?)?.code(),
        Some(2),
        "closed environment refuses added loader input"
    );
    Ok(())
}
