//! Opt-in, local deployment-owned shutdown control. No HTTP capability.
//! Failed custody observations never authorize the server to exit early.
use super::*;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use rustix::fs::{Mode, OFlags};

const POLL: Duration = Duration::from_millis(2);
const SCHEMA: &str = "heptabao.pkcs11-production-closed-event.v1";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalControlConfig {
    pub directory: PathBuf,
    pub epoch: String,
    pub nonce_sha256: String,
    pub shutdown_timeout_ms: u64,
}
impl std::fmt::Debug for LocalControlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalControlConfig([REDACTED])")
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StopRequest { epoch: String, nonce: PrivateNonce, stop: bool }
struct PrivateNonce(String);
impl Drop for PrivateNonce {
    fn drop(&mut self) { self.0.zeroize(); }
}
impl<'de> Deserialize<'de> for PrivateNonce {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}
fn hex32(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    if text.len() != 64 || !text.bytes().all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)) {
        return None;
    }
    let mut bytes = Zeroizing::new([0; 32]);
    for (slot, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(bytes)
}
fn stamp(m: &std::fs::Metadata) -> (u64,u64,u32,u32,u64,u64,i64,i64,i64,i64) {
    (m.dev(),m.ino(),m.uid(),m.mode(),m.len(),m.nlink(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec())
}
pub(super) struct Control {
    config: LocalControlConfig,
    directory: File,
    directory_identity: (u64, u64),
    rejected: bool,
}
impl Control {
    pub(super) fn open(config: &LocalControlConfig) -> Result<Self, String> {
        if hex32(&config.epoch).is_none() || hex32(&config.nonce_sha256).is_none()
            || !(100..=10_000).contains(&config.shutdown_timeout_ms) {
            return Err("invalid private control policy".into());
        }
        let directory = heptabao_filesystem_guard::open_absolute_directory_no_symlinks(&config.directory)
            .map_err(|_| "cannot open private control directory")?;
        let metadata = directory.metadata().map_err(|_| "cannot inspect private control directory")?;
        if !metadata.is_dir() || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o700 {
            return Err("private control directory requires owner mode700".into());
        }
        let held_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
        if std::fs::read_dir(held_path).map_err(|_| "cannot inspect fresh control directory")?
            .next().is_some() {
            return Err("private control directory must be fresh and empty".into());
        }
        Ok(Self { config: config.clone(), directory_identity: (metadata.dev(), metadata.ino()), directory, rejected: false })
    }
    fn check_directory(&self) -> Result<(), String> {
        let metadata = self.directory.metadata().map_err(|_| "private control directory unavailable")?;
        if (metadata.dev(), metadata.ino()) != self.directory_identity
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o700 {
            return Err("private control directory identity changed".into());
        }
        Ok(())
    }
    fn event(&self, name: &str, phase: &str, observation: Value) -> Result<(), String> {
        self.check_directory()?;
        let bytes = serde_json::to_vec(&json!({"schema":SCHEMA,"epoch":self.config.epoch,
            "nonce_sha256":self.config.nonce_sha256,"phase":phase,"wrapper":observation}))
            .map_err(|_| "cannot encode private control observation")?;
        let pending = format!(".{name}.pending");
        let mut file = File::from(rustix::fs::openat(&self.directory, pending.as_str(),
            OFlags::WRONLY|OFlags::CREATE|OFlags::EXCL|OFlags::NOFOLLOW|OFlags::CLOEXEC,
            Mode::RUSR|Mode::WUSR).map_err(|_| "cannot create immutable private observation")?);
        rustix::fs::fchmod(&file, Mode::RUSR|Mode::WUSR).map_err(|_| "cannot bind private observation mode600")?;
        file.write_all(&bytes).map_err(|_| "cannot write private observation")?;
        file.sync_all().map_err(|_| "cannot sync private observation")?;
        rustix::fs::renameat_with(&self.directory, pending.as_str(), &self.directory, name,
            rustix::fs::RenameFlags::NOREPLACE).map_err(|_| "cannot publish immutable private observation")?;
        self.directory.sync_all().map_err(|_| "cannot sync private observation directory")
    }
    pub(super) fn ready(&self, service: &Arc<Mutex<Service>>) -> Result<(), String> {
        let observation = service.lock().map_err(|_| "service observation unavailable")?
            .openbao_wrapper_private_observation()?;
        if observation["cleanup"] != "Live" || observation["authenticated_h2"] != true
            || observation["health_authenticated"] != true {
            return Err("private control requires authenticated live Wrapper admission".into());
        }
        self.event("ready.json", "ready", observation)
    }
    fn read_stop(&self) -> Result<bool, String> {
        self.check_directory()?;
        let descriptor = match rustix::fs::openat(&self.directory, "stop.json",
            OFlags::RDONLY|OFlags::NOFOLLOW|OFlags::NONBLOCK|OFlags::CLOEXEC, Mode::empty()) {
            Ok(value) => value,
            Err(rustix::io::Errno::NOENT) => return Ok(false),
            Err(_) => return Err("private stop request unavailable".into()),
        };
        let mut file = File::from(descriptor);
        let before = file.metadata().map_err(|_| "private stop request metadata unavailable")?;
        if !before.is_file() || before.uid() != rustix::process::geteuid().as_raw()
            || before.mode() & 0o7777 != 0o600 || before.nlink() != 1 || before.len() > 1024 {
            return Err("private stop request binding denied".into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file).take(1025).read_to_end(&mut bytes).map_err(|_| "cannot read private stop request")?;
        if bytes.len() > 1024 || stamp(&before) != stamp(&file.metadata().map_err(|_| "cannot reobserve private stop request")?) {
            return Err("private stop request changed".into());
        }
        let request: StopRequest = serde_json::from_slice(&bytes).map_err(|_| "invalid private stop request")?;
        let nonce = hex32(&request.nonce.0).ok_or("invalid private stop nonce")?;
        let expected = hex32(&self.config.nonce_sha256).ok_or("invalid private stop nonce binding")?;
        if !request.stop || request.epoch != self.config.epoch || crypto::digest(nonce.as_slice()) != *expected {
            return Err("private stop authorization denied".into());
        }
        Ok(true)
    }
    pub(super) fn poll(&mut self, service: &Arc<Mutex<Service>>) -> bool {
        if self.rejected { return false; }
        match self.read_stop() {
            Ok(value) => value,
            Err(_) => {
                // An invalid nonce cannot seal a running service or authorize exit.
                self.rejected = true;
                let observation = service.lock().ok().and_then(|writer| writer.openbao_wrapper_private_observation().ok());
                let _ = self.event("terminal.json", "denied", observation.unwrap_or(Value::Null));
                eprintln!("heptabao-server: private control authorization or observation denied; service retained");
                false
            }
        }
    }
    pub(super) fn shutdown<F: FnOnce()>(&self, service: &Arc<Mutex<Service>>, connections: &AtomicUsize,
        initial_failure: Option<String>, stop_maintenance: F) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_millis(self.config.shutdown_timeout_ms);
        let seal = match lock_until(service, deadline) {
            Ok(mut writer) => writer.begin_private_shutdown().map_err(str::to_owned),
            Err(_) => Err("private shutdown writer unavailable".into()),
        };
        let mut failure = initial_failure.or_else(|| seal.err());
        let mut recorded = false;
        loop {
            let observation = service.try_lock().ok().and_then(|writer| writer.openbao_wrapper_private_observation().ok());
            let complete = observation.as_ref().is_some_and(|value| value["sealed"] == true &&
                (value["cleanup"] == "TerminalReaped" || (failure.is_some() && value["cleanup"] == "NotStarted"
                    && value["owned_pid"].is_null() && value["provider"].is_null())))
                && connections.load(Ordering::Acquire) == 0;
            if Instant::now() >= deadline && failure.is_none() { failure = Some("private shutdown deadline expired; custody retained".into()); }
            if failure.is_some() && !recorded {
                let result = self.event("terminal.json", "denied", observation.clone().unwrap_or(Value::Null));
                recorded = true;
                if result.is_err() { eprintln!("heptabao-server: private shutdown failure observation unavailable; custody retained"); }
            }
            if complete {
                // Join only after the actual child is reaped (or known never
                // spawned). A slow join retains this server's custody; a later
                // time observation cannot turn it into an in-budget success.
                stop_maintenance();
                if Instant::now() >= deadline && failure.is_none() {
                    failure = Some("private shutdown deadline expired while joining maintenance".into());
                    let _ = self.event("terminal.json", "denied", observation.clone().unwrap_or(Value::Null));
                }
                if let Some(error) = failure { return Err(error); }
                self.event("terminal.json", "terminal", observation.ok_or("private terminal observation unavailable")?)?;
                if Instant::now() >= deadline { return Err("private terminal evidence completed after shutdown deadline".into()); }
                return Ok(());
            }
            // No repeated seal, provider RPC, signal, deadline reset, or assumed reap.
            std::thread::sleep(POLL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::hex32;
    #[test]
    fn private_nonce_requires_exact_lowercase_32_bytes() {
        assert!(hex32(&"ab".repeat(32)).is_some());
        assert!(hex32(&"AB".repeat(32)).is_none());
        assert!(hex32(&"ab".repeat(31)).is_none());
        assert!(hex32(&"gg".repeat(32)).is_none());
    }
}
