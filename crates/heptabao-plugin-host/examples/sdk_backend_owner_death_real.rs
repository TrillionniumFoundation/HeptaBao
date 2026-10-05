//! A deliberately blocked genuine SDK plugin for an owned host-death test.
//! Its external test launcher owns and observes all three real processes.
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use heptabao_plugin_host::sdk_backend::{
    SdkBackendHost, SdkBridgeError, SdkLaunch, SdkStorage, SdkStorageEntry,
};
use ring::digest::{SHA256, digest};
use serde_json::json;

struct Storage {
    entries: BTreeMap<String, SdkStorageEntry>,
    receipt: PathBuf,
}
impl SdkStorage for Storage {
    fn get(&mut self, key: &str, _: Instant) -> Result<Option<SdkStorageEntry>, SdkBridgeError> {
        Ok(self.entries.get(key).cloned())
    }
    fn put(&mut self, entry: SdkStorageEntry, _: Instant) -> Result<(), SdkBridgeError> {
        if entry.key != "owner-death" || entry.value.as_slice() != b"entered" {
            return Err(SdkBridgeError::Storage);
        }
        self.entries.insert(entry.key.clone(), entry);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&self.receipt)
            .map_err(|_| SdkBridgeError::Storage)?;
        file.write_all(serde_json::to_string(&json!({"actual_Rust_pid":std::process::id(),"real_SDK_Storage_Put_received":true,"storage_fixture":true})).map_err(|_| SdkBridgeError::Storage)?.as_bytes()).map_err(|_| SdkBridgeError::Storage)?;
        file.sync_all().map_err(|_| SdkBridgeError::Storage)
    }
    fn delete(&mut self, key: &str, _: Instant) -> Result<(), SdkBridgeError> {
        self.entries.remove(key);
        Ok(())
    }
    fn list_page(
        &mut self,
        prefix: &str,
        after: &str,
        limit: i64,
        _: Instant,
    ) -> Result<Vec<String>, SdkBridgeError> {
        let n = if limit <= 0 {
            usize::MAX
        } else {
            usize::try_from(limit).map_err(|_| SdkBridgeError::Storage)?
        };
        Ok(self
            .entries
            .keys()
            .filter(|k| k.starts_with(prefix) && (after.is_empty() || k.as_str() > after))
            .take(n)
            .cloned()
            .collect())
    }
}
fn checksum(path: &Path) -> Result<[u8; 32], Box<dyn Error>> {
    Ok(digest(&SHA256, &std::fs::read(path)?).as_ref().try_into()?)
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 4 {
        return Err("companion plugin fresh-output arguments".into());
    }
    let companion = PathBuf::from(&args[1]);
    let plugin = PathBuf::from(&args[2]);
    let out = PathBuf::from(&args[3]);
    std::fs::create_dir(&out)?;
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700))?;
    let socket = out.join("socket");
    std::fs::create_dir(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o700))?;
    let config = SdkLaunch {
        companion: companion.clone(),
        companion_sha256: checksum(&companion)?,
        plugin: plugin.clone(),
        plugin_sha256: checksum(&plugin)?,
        plugin_args: vec!["--serve".into()],
        socket_directory: socket,
        private_log: out.join("companion.private.log"),
        timeout: Duration::from_secs(30),
        default_ttl_seconds: 3600,
        max_ttl_seconds: 86400,
    };
    let mut storage = Storage {
        entries: BTreeMap::new(),
        receipt: out.join("entered-original.json"),
    };
    let mut host = SdkBackendHost::launch(&config, &mut storage)?;
    let result = host.handle_request("update", "blocked", json!({}), &mut storage);
    Err(format!("expected launcher-owned death, SDK returned {result:?}").into())
}
