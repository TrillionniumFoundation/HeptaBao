//! Functional KMS executable handoff. This module provides no OS containment.
//!
//! CommandSandboxRunner already admitted the wrapper and bridge by SHA-256.
//! This receiver accepts only that parent's immutable proc-FD capability; it
//! never resolves a manifest pathname or reads the HBP1 request. The retained
//! descriptor is executed in this process, preserving the host's original
//! process group, pipes, deadline, and terminal wait. Same-UID parent trust and
//! genuine kernel procfs are deployment assumptions, not independent admission.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use rustix::fs::{Mode, OFlags, SealFlags};

const PROFILE: &str = "kms_sealed_exec_v1";
const PROVIDER: &str = "sealed_exec_adapter";
const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const ENVIRONMENT: [&str; 7] = [
    "HEPTABAO_SANDBOX_PROVIDER",
    "HEPTABAO_KMS_DEPLOYMENT",
    "HEPTABAO_KMS_DEPLOYMENT_SHA256",
    "HEPTABAO_KMS_PROVIDER",
    "HEPTABAO_KMS_TEMP",
    "HEPTABAO_KMS_TIMEOUT_MS",
    "HEPTABAO_KMS_DEADLINE_MONOTONIC_NS",
];

/// Closed failure classes; no paths, environment values or business data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterError {
    Arguments,
    Environment,
    Deadline,
    Parent,
    Image,
    Exec,
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Arguments => "sealed handoff arguments refused",
            Self::Environment => "sealed handoff environment refused",
            Self::Deadline => "sealed handoff deadline refused",
            Self::Parent => "sealed handoff parent refused",
            Self::Image => "sealed handoff image refused",
            Self::Exec => "sealed handoff execution refused",
        })
    }
}
impl std::error::Error for AdapterError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Descriptor {
    parent: u32,
    fd: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessIdentity {
    pid: u32,
    parent: u32,
    start_ticks: u64,
}

struct Parent {
    directory: File,
    identity: ProcessIdentity,
}

fn decimal(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return None;
    }
    value.parse().ok()
}

fn parse_descriptor(value: &str) -> Option<Descriptor> {
    let parts: Vec<_> = value.split('/').collect();
    if parts.len() != 5 || !parts[0].is_empty() || parts[1] != "proc" || parts[3] != "fd" {
        return None;
    }
    let parent = u32::try_from(decimal(parts[2])?).ok()?;
    let fd = u32::try_from(decimal(parts[4])?).ok()?;
    (parent > 0 && fd >= 3).then_some(Descriptor { parent, fd })
}

fn arguments(args: &[OsString]) -> Result<Descriptor, AdapterError> {
    if args.len() != 8
        || args[0] != "--heptabao-profile"
        || args[1] != PROFILE
        || args[2] != "--heptabao-plugin"
        || args[4] != "--heptabao-protocol"
        || args[5] != "1"
        || args[6] != "--heptabao-operation"
        || args[7] != "read"
    {
        return Err(AdapterError::Arguments);
    }
    args[3]
        .to_str()
        .and_then(parse_descriptor)
        .ok_or(AdapterError::Arguments)
}

fn canonical_absolute(value: &str) -> bool {
    value.len() <= 4096
        && value.starts_with('/')
        && value.split('/').skip(1).all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.bytes().any(|b| b.is_ascii_control())
        })
}

fn environment(
    entries: impl IntoIterator<Item = (OsString, OsString)>,
    now: u64,
) -> Result<BTreeMap<String, String>, AdapterError> {
    let mut values = BTreeMap::new();
    for (name, value) in entries {
        let name = name.into_string().map_err(|_| AdapterError::Environment)?;
        let value = value.into_string().map_err(|_| AdapterError::Environment)?;
        if !ENVIRONMENT.contains(&name.as_str())
            || value.is_empty()
            || value.len() > 4096
            || value.contains('\0')
            || values.insert(name, value).is_some()
        {
            return Err(AdapterError::Environment);
        }
    }
    if values.len() != ENVIRONMENT.len() {
        return Err(AdapterError::Environment);
    }
    let get = |name: &str| values.get(name).map(String::as_str);
    if get("HEPTABAO_SANDBOX_PROVIDER") != Some(PROVIDER)
        || get("HEPTABAO_KMS_PROVIDER") != Some("transit")
        || !get("HEPTABAO_KMS_DEPLOYMENT").is_some_and(canonical_absolute)
        || !get("HEPTABAO_KMS_TEMP")
            .is_some_and(|value| value.len() <= 60 && canonical_absolute(value))
        || !get("HEPTABAO_KMS_DEPLOYMENT_SHA256").is_some_and(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && value.bytes().any(|b| b != b'0')
        })
        || !get("HEPTABAO_KMS_TIMEOUT_MS")
            .and_then(decimal)
            .is_some_and(|value| (1..=60_000).contains(&value))
    {
        return Err(AdapterError::Environment);
    }
    if !get("HEPTABAO_KMS_DEADLINE_MONOTONIC_NS")
        .and_then(decimal)
        .is_some_and(|value| value > now && i64::try_from(value).is_ok())
    {
        return Err(AdapterError::Deadline);
    }
    Ok(values)
}

fn bounded_text(mut file: File) -> Result<String, AdapterError> {
    let mut bytes = Vec::new();
    file.by_ref()
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| AdapterError::Parent)?;
    if bytes.len() > 4096 {
        return Err(AdapterError::Parent);
    }
    String::from_utf8(bytes).map_err(|_| AdapterError::Parent)
}

fn process_identity(text: &str) -> Option<ProcessIdentity> {
    let opening = text.find(" (")?;
    let closing = text.rfind(") ")?;
    if opening >= closing {
        return None;
    }
    let pid = u32::try_from(decimal(&text[..opening])?).ok()?;
    let fields: Vec<_> = text[closing + 2..].split_ascii_whitespace().collect();
    let parent = u32::try_from(decimal(fields.get(1)?)?).ok()?;
    let start_ticks = decimal(fields.get(19)?)?;
    (pid > 0 && start_ticks > 0).then_some(ProcessIdentity {
        pid,
        parent,
        start_ticks,
    })
}

fn self_identity() -> Result<ProcessIdentity, AdapterError> {
    let file = File::open("/proc/self/stat").map_err(|_| AdapterError::Parent)?;
    process_identity(&bounded_text(file)?).ok_or(AdapterError::Parent)
}

impl Parent {
    fn capture(descriptor: Descriptor) -> Result<Self, AdapterError> {
        if self_identity()?.parent != descriptor.parent {
            return Err(AdapterError::Parent);
        }
        let directory = File::from(
            rustix::fs::open(
                format!("/proc/{}", descriptor.parent),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| AdapterError::Parent)?,
        );
        if directory
            .metadata()
            .map_err(|_| AdapterError::Parent)?
            .uid()
            != rustix::process::geteuid().as_raw()
        {
            return Err(AdapterError::Parent);
        }
        let identity = Self::observe(&directory)?;
        if identity.pid != descriptor.parent {
            return Err(AdapterError::Parent);
        }
        Ok(Self {
            directory,
            identity,
        })
    }

    fn observe(directory: &File) -> Result<ProcessIdentity, AdapterError> {
        let file = File::from(
            rustix::fs::openat(
                directory,
                "stat",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| AdapterError::Parent)?,
        );
        process_identity(&bounded_text(file)?).ok_or(AdapterError::Parent)
    }

    fn current(&self) -> Result<(), AdapterError> {
        if Self::observe(&self.directory)? != self.identity
            || self_identity()?.parent != self.identity.pid
            || self
                .directory
                .metadata()
                .map_err(|_| AdapterError::Parent)?
                .uid()
                != rustix::process::geteuid().as_raw()
        {
            return Err(AdapterError::Parent);
        }
        Ok(())
    }

    fn image(&self, descriptor: Descriptor) -> Result<File, AdapterError> {
        // fd/N is generated from the strict integer grammar. Following the
        // kernel's proc-FD symlink is intentional; arbitrary path resolution
        // and a manifest pathname fallback are never accepted.
        rustix::fs::openat(
            &self.directory,
            format!("fd/{}", descriptor.fd),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| AdapterError::Image)
    }
}

fn checked_image(file: &mut File) -> Result<(u64, u64), AdapterError> {
    let metadata = file.metadata().map_err(|_| AdapterError::Image)?;
    if !metadata.is_file()
        || !(64..=MAX_IMAGE_BYTES).contains(&metadata.len())
        || metadata.mode() & 0o7777 != 0o500
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 0
        || !rustix::fs::fcntl_get_seals(&*file).is_ok_and(|seals| {
            seals.contains(
                SealFlags::WRITE
                    | SealFlags::GROW
                    | SealFlags::SHRINK
                    | SealFlags::EXEC
                    | SealFlags::SEAL,
            )
        })
    {
        return Err(AdapterError::Image);
    }
    let mut header = [0_u8; 64];
    file.read_exact(&mut header)
        .map_err(|_| AdapterError::Image)?;
    let machine = u16::from_le_bytes([header[18], header[19]]);
    let kind = u16::from_le_bytes([header[16], header[17]]);
    let machine_supported = cfg!(target_arch = "x86_64") && machine == 62
        || cfg!(target_arch = "aarch64") && machine == 183;
    if &header[..7] != b"\x7fELF\x02\x01\x01" || !matches!(kind, 2..=3) || !machine_supported {
        return Err(AdapterError::Image);
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn monotonic_nanos() -> Result<u64, AdapterError> {
    let value = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Known(
        rustix::time::ClockId::Monotonic,
    ))
    .map_err(|_| AdapterError::Deadline)?;
    u64::try_from(i128::from(value.tv_sec) * 1_000_000_000 + i128::from(value.tv_nsec))
        .map_err(|_| AdapterError::Deadline)
}

fn temp_current(values: &BTreeMap<String, String>) -> Result<(), AdapterError> {
    let path = values
        .get("HEPTABAO_KMS_TEMP")
        .ok_or(AdapterError::Environment)?;
    let metadata =
        std::fs::symlink_metadata(Path::new(path)).map_err(|_| AdapterError::Environment)?;
    if !metadata.is_dir()
        || metadata.mode() & 0o7777 != 0o700
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(AdapterError::Environment);
    }
    Ok(())
}

/// Replace this adapter with the admitted KMS bridge without another child.
///
/// This is a functional, trusted-code handoff, not a sandbox implementation.
/// Failures emit no HBR1 success response; the already-entered host invocation
/// remains subject to its original unknown-outcome fence and cleanup policy.
pub fn run() -> Result<(), AdapterError> {
    let descriptor = arguments(&std::env::args_os().skip(1).collect::<Vec<_>>())?;
    let values = environment(std::env::vars_os(), monotonic_nanos()?)?;
    temp_current(&values)?;
    let parent = Parent::capture(descriptor)?;
    let mut image = parent.image(descriptor)?;
    let identity = checked_image(&mut image)?;
    let mut current = parent.image(descriptor)?;
    if checked_image(&mut current)? != identity {
        return Err(AdapterError::Image);
    }
    parent.current()?;
    let deadline = values
        .get("HEPTABAO_KMS_DEADLINE_MONOTONIC_NS")
        .and_then(|value| decimal(value))
        .ok_or(AdapterError::Deadline)?;
    if monotonic_nanos()? >= deadline {
        return Err(AdapterError::Deadline);
    }
    temp_current(&values)?;
    let mut command = Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()));
    command
        .arg0("heptabao-kms-bridge")
        .env_clear()
        .envs(&values);
    let _error: io::Error = command.exec();
    Err(AdapterError::Exec)
}

#[cfg(test)]
#[path = "sealed_exec_adapter_tests.rs"]
mod tests;
