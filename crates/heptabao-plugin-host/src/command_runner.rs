//! Linux executable binding and bounded process I/O, not an OS security sandbox.
//! The enrolled provider still owns namespaces, resource controls and containment
//! of descendants that change their process group or session.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use ring::digest::{Context, SHA256};
use rustix::fs::{MemfdFlags, Mode, OFlags, SealFlags};
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};
use zeroize::Zeroizing;

use super::{
    CommandSandboxRunner, PluginManifest, PluginOperation, SandboxFailure, SandboxRunner,
    SecretEnvironment, SecretValue, decode_response, encode_request,
};

const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(2);

impl SandboxRunner for CommandSandboxRunner {
    fn admit(&self, manifest: &PluginManifest) -> Result<(), SandboxFailure> {
        Executables::open(manifest).map(|_| ())
    }

    fn invoke(
        &self,
        manifest: &PluginManifest,
        operation: PluginOperation,
        request: &SecretValue,
        environment: &SecretEnvironment,
    ) -> Result<SecretValue, SandboxFailure> {
        if request.len() > manifest.limits().maximum_request_bytes
            || environment
                .iter()
                .any(|(name, _)| !manifest.environment_allowlist().contains(name))
        {
            return Err(SandboxFailure::BeforeEntry);
        }
        let frame = encode_request(
            manifest.descriptor().protocol_version(),
            operation,
            request.expose(),
        )
        .map_err(|_| SandboxFailure::BeforeEntry)?;
        let executables = Executables::open(manifest)?;
        executables.invoke(manifest, operation, &frame, environment)
    }
}

struct Executables {
    provider: SealedExecutable,
    plugin: SealedExecutable,
}

impl Executables {
    fn open(manifest: &PluginManifest) -> Result<Self, SandboxFailure> {
        Ok(Self {
            provider: SealedExecutable::open(
                Path::new(manifest.sandbox().command.as_str()),
                manifest.sandbox().command_sha256,
            )?,
            plugin: SealedExecutable::open(
                Path::new(manifest.descriptor().command().as_str()),
                *manifest.descriptor().checksum(),
            )?,
        })
    }

    fn invoke(
        &self,
        manifest: &PluginManifest,
        operation: PluginOperation,
        frame: &[u8],
        environment: &SecretEnvironment,
    ) -> Result<SecretValue, SandboxFailure> {
        // This deadline starts before process entry, not after a blocking stdin
        // write. Admission of owner-installed local files is a separate phase.
        let deadline = Instant::now() + Duration::from_millis(manifest.limits().timeout_ms);
        let mut command = Command::new(self.provider.descriptor_path());
        command
            .arg("--heptabao-profile")
            .arg(manifest.sandbox().profile_id.as_str())
            .arg("--heptabao-plugin")
            .arg(self.plugin.descriptor_path())
            .arg("--heptabao-protocol")
            .arg(manifest.descriptor().protocol_version().to_string())
            .arg("--heptabao-operation")
            .arg(operation.as_str())
            .env_clear()
            .env(
                "HEPTABAO_SANDBOX_PROVIDER",
                manifest.sandbox().provider_id.as_str(),
            )
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (name, value) in environment.iter() {
            command.env(name, value);
        }
        let child = command.spawn().map_err(|_| SandboxFailure::BeforeEntry)?;
        let mut process = ProcessGuard::new(child)?;
        let child = process
            .child
            .as_mut()
            .ok_or(SandboxFailure::OutcomeUnknownAfterEntry)?;
        let mut stdin = Some(
            child
                .stdin
                .take()
                .ok_or(SandboxFailure::OutcomeUnknownAfterEntry)?,
        );
        let mut stdout = child
            .stdout
            .take()
            .ok_or(SandboxFailure::OutcomeUnknownAfterEntry)?;
        nonblocking(
            stdin
                .as_ref()
                .ok_or(SandboxFailure::OutcomeUnknownAfterEntry)?,
        )?;
        nonblocking(&stdout)?;
        let maximum = manifest.limits().maximum_response_bytes + 8;
        let mut output = Zeroizing::new(Vec::new());
        let mut written = 0;
        let mut eof = false;
        let mut buffer = Zeroizing::new([0_u8; 16 * 1024]);
        loop {
            if Instant::now() >= deadline {
                return Err(SandboxFailure::OutcomeUnknownAfterEntry);
            }
            if let Some(writer) = stdin.as_mut() {
                match writer.write(&frame[written..]) {
                    Ok(0) => return Err(SandboxFailure::OutcomeUnknownAfterEntry),
                    Ok(count) => written += count,
                    Err(error) if retryable(&error) => {}
                    Err(_) => return Err(SandboxFailure::OutcomeUnknownAfterEntry),
                }
                if written == frame.len() {
                    stdin = None;
                }
            }
            if !eof {
                match stdout.read(&mut buffer[..]) {
                    Ok(0) => eof = true,
                    Ok(count) => {
                        if count > maximum - output.len() {
                            return Err(SandboxFailure::OutcomeUnknownAfterEntry);
                        }
                        output.extend_from_slice(&buffer[..count]);
                    }
                    Err(error) if retryable(&error) => {}
                    Err(_) => return Err(SandboxFailure::OutcomeUnknownAfterEntry),
                }
            }
            // NOWAIT keeps the leader unreaped, reserving its PID/PGID until
            // cleanup has signalled the process group (no PID-reuse kill race).
            let status = rustix::process::waitid(
                WaitId::Pid(process.pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )
            .map_err(|_| SandboxFailure::OutcomeUnknownAfterEntry)?;
            if let Some(status) = status {
                if status.exit_status() != Some(0) {
                    return Err(SandboxFailure::OutcomeUnknownAfterEntry);
                }
                if eof && stdin.is_none() {
                    return decode_response(&output, manifest.limits().maximum_response_bytes)
                        .map_err(|_| SandboxFailure::OutcomeUnknownAfterEntry);
                }
            }
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }
}

fn nonblocking(fd: &impl AsFd) -> Result<(), SandboxFailure> {
    let flags =
        rustix::fs::fcntl_getfl(fd).map_err(|_| SandboxFailure::OutcomeUnknownAfterEntry)?;
    rustix::fs::fcntl_setfl(fd, flags | OFlags::NONBLOCK)
        .map_err(|_| SandboxFailure::OutcomeUnknownAfterEntry)
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

struct ProcessGuard {
    child: Option<Child>,
    pid: Pid,
}

impl ProcessGuard {
    fn new(mut child: Child) -> Result<Self, SandboxFailure> {
        let Some(pid) = i32::try_from(child.id()).ok().and_then(Pid::from_raw) else {
            let _ = child.kill();
            return Err(SandboxFailure::OutcomeUnknownAfterEntry);
        };
        Ok(Self {
            child: Some(child),
            pid,
        })
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = rustix::process::kill_process_group(self.pid, Signal::KILL);
            let _ = child.kill();
            // Neither pipes held by descendants nor a kernel-delayed SIGKILL
            // may make the caller join or wait without a deadline. Reaping is
            // detached only if the kernel has not yet reported child exit.
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let _ = thread::Builder::new()
                    .name("heptabao-plugin-reaper".into())
                    .spawn(move || {
                        let _ = child.wait();
                    });
            }
        }
    }
}

struct SealedExecutable {
    _image: File,
    descriptor_path: PathBuf,
}

impl SealedExecutable {
    fn open(path: &Path, expected: [u8; 32]) -> Result<Self, SandboxFailure> {
        Self::snapshot(path, expected).map_err(|_| SandboxFailure::BeforeEntry)
    }

    fn snapshot(path: &Path, expected: [u8; 32]) -> io::Result<Self> {
        let mut source = open_without_symlinks(path)?;
        let metadata = source.metadata()?;
        if !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_EXECUTABLE_BYTES
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o100 == 0
        {
            return Err(io::Error::other("invalid executable"));
        }
        // Linux 6.3+ MFD_EXEC is explicit. Unsupported kernel/policy rejects
        // admission, with no fallback to mutable pathname execution.
        let mut image = File::from(rustix::fs::memfd_create(
            "heptabao-executable",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING | MemfdFlags::EXEC,
        )?);
        let mut digest = Context::new(&SHA256);
        let mut buffer = [0_u8; 16 * 1024];
        let mut observed = 0_u64;
        loop {
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            observed += count as u64;
            if observed > MAX_EXECUTABLE_BYTES {
                return Err(io::Error::other("executable exceeds bound"));
            }
            digest.update(&buffer[..count]);
            image.write_all(&buffer[..count])?;
        }
        if observed == 0 || digest.finish().as_ref() != expected {
            return Err(io::Error::other("executable digest mismatch"));
        }
        rustix::fs::fchmod(&image, Mode::RUSR | Mode::XUSR)?;
        rustix::fs::fcntl_add_seals(
            &image,
            SealFlags::WRITE
                | SealFlags::GROW
                | SealFlags::SHRINK
                | SealFlags::EXEC
                | SealFlags::SEAL,
        )?;
        // A procfs mount may expose an ancestor PID namespace. getpid() then
        // names a different /proc entry; resolve the kernel's self link instead.
        let proc_pid = std::fs::read_link("/proc/self")?;
        let Some(proc_pid) = proc_pid
            .to_str()
            .filter(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
        else {
            return Err(io::Error::other("unsupported procfs process identity"));
        };
        let descriptor_path = PathBuf::from(format!("/proc/{proc_pid}/fd/{}", image.as_raw_fd()));
        let exposed = std::fs::metadata(&descriptor_path)?;
        let sealed = image.metadata()?;
        if exposed.dev() != sealed.dev() || exposed.ino() != sealed.ino() {
            return Err(io::Error::other("procfs descriptor identity mismatch"));
        }
        Ok(Self {
            _image: image,
            descriptor_path,
        })
    }

    fn descriptor_path(&self) -> &Path {
        // Parent-owned CLOEXEC descriptors work for both ELF and shebang scripts
        // without leaking inheritable FDs to unrelated concurrently spawned jobs.
        // The parent retains both immutable images for the full invocation.
        &self.descriptor_path
    }
}

fn open_without_symlinks(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::other("absolute path required"));
    }
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(io::Error::other("invalid executable path"));
    }
    let mut directory = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut remaining = components.peekable();
    while let Some(component) = remaining.next() {
        let Component::Normal(name) = component else {
            return Err(io::Error::other("invalid executable component"));
        };
        let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        if remaining.peek().is_some() {
            flags |= OFlags::DIRECTORY;
        }
        let opened = rustix::fs::openat(&directory, name, flags, Mode::empty())?;
        if remaining.peek().is_none() {
            return Ok(File::from(opened));
        }
        directory = opened;
    }
    Err(io::Error::other("executable filename required"))
}

#[cfg(test)]
#[path = "command_runner_tests.rs"]
mod tests;
