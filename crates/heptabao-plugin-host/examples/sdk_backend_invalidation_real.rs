//! Genuine official SDK process/AutoMTLS/control-IPC invalidation evidence.
//! This fixture does not qualify Service committed-state or the plugin manager.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix_fixture {
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
    use serde_json::{Value, json};
    use zeroize::Zeroizing;

    #[derive(Default)]
    struct OwnedFixtureStorage(BTreeMap<String, SdkStorageEntry>);
    impl SdkStorage for OwnedFixtureStorage {
        fn get(
            &mut self,
            key: &str,
            deadline: Instant,
        ) -> Result<Option<SdkStorageEntry>, SdkBridgeError> {
            if Instant::now() >= deadline {
                return Err(SdkBridgeError::Storage);
            }
            Ok(self.0.get(key).cloned())
        }
        fn put(&mut self, entry: SdkStorageEntry, deadline: Instant) -> Result<(), SdkBridgeError> {
            if Instant::now() >= deadline {
                return Err(SdkBridgeError::Storage);
            }
            self.0.insert(entry.key.clone(), entry);
            Ok(())
        }
        fn delete(&mut self, key: &str, deadline: Instant) -> Result<(), SdkBridgeError> {
            if Instant::now() >= deadline {
                return Err(SdkBridgeError::Storage);
            }
            self.0.remove(key);
            Ok(())
        }
        fn list_page(
            &mut self,
            prefix: &str,
            after: &str,
            limit: i64,
            deadline: Instant,
        ) -> Result<Vec<String>, SdkBridgeError> {
            if Instant::now() >= deadline {
                return Err(SdkBridgeError::Storage);
            }
            Ok(self
                .0
                .keys()
                .filter_map(|k| k.strip_prefix(prefix))
                .filter(|k| *k > after)
                .take(if limit <= 0 {
                    usize::MAX
                } else {
                    limit as usize
                })
                .map(str::to_owned)
                .collect())
        }
    }
    fn checksum(path: &Path) -> Result<[u8; 32], Box<dyn Error>> {
        digest(&SHA256, &std::fs::read(path)?)
            .as_ref()
            .try_into()
            .map_err(|_| "SHA256 length".into())
    }
    fn check(ok: bool, label: &str, checks: &mut Vec<String>) -> Result<(), Box<dyn Error>> {
        if !ok {
            return Err(label.to_owned().into());
        }
        checks.push(label.to_owned());
        Ok(())
    }
    fn read(
        host: &mut SdkBackendHost,
        storage: &mut OwnedFixtureStorage,
    ) -> Result<Value, Box<dyn Error>> {
        host.handle_request("read", "cached-item", json!({}), storage)?
            .ok_or_else(|| "missing cache response".into())
    }
    fn install(storage: &mut OwnedFixtureStorage, value: &str) {
        storage.0.insert(
            "item".into(),
            SdkStorageEntry {
                key: "item".into(),
                value: Zeroizing::new(value.as_bytes().to_vec()),
                seal_wrap: false,
            },
        );
    }
    fn run() -> Result<(), Box<dyn Error>> {
        let args: Vec<_> = std::env::args_os().collect();
        if args.len() != 5 {
            return Err("companion plugin old-companion fresh-output arguments".into());
        }
        let companion = PathBuf::from(&args[1]);
        let plugin = PathBuf::from(&args[2]);
        let old_companion = PathBuf::from(&args[3]);
        let out = PathBuf::from(&args[4]);
        std::fs::create_dir(&out)?;
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700))?;
        let config = |round: u8, companion: &Path| -> Result<SdkLaunch, Box<dyn Error>> {
            let sockets = out.join(format!("sockets-{round}"));
            std::fs::create_dir(&sockets)?;
            std::fs::set_permissions(&sockets, std::fs::Permissions::from_mode(0o700))?;
            Ok(SdkLaunch {
                companion: companion.into(),
                companion_sha256: checksum(companion)?,
                plugin: plugin.clone(),
                plugin_sha256: checksum(&plugin)?,
                plugin_args: vec!["--serve".into()],
                socket_directory: sockets,
                private_log: out.join(format!("companion-{round}.private.log")),
                timeout: Duration::from_secs(5),
                default_ttl_seconds: 60,
                max_ttl_seconds: 60,
            })
        };
        let mut checks = Vec::new();
        let mut storage = OwnedFixtureStorage::default();
        install(&mut storage, "old");
        let mut host = SdkBackendHost::launch(&config(1, &companion)?, &mut storage)?;
        check(true, "actual-owned-SDK-v5-AutoMTLS-Setup", &mut checks)?;
        check(
            read(&mut host, &mut storage)?["data"]["value"] == "old",
            "actual-cache-prime",
            &mut checks,
        )?;
        install(&mut storage, "committed-new");
        check(
            read(&mut host, &mut storage)?["data"]["value"] == "old",
            "out-of-band-storage-change-retains-old-cache",
            &mut checks,
        )?;
        host.invalidate(&["item".into()], Instant::now() + Duration::from_secs(2))?;
        let refreshed = read(&mut host, &mut storage)?;
        check(
            refreshed["data"]["value"] == "committed-new",
            "actual-typed-control-SDK-hook-clears-cache",
            &mut checks,
        )?;
        check(
            refreshed["data"]["invalidations"] == 1,
            "exact-single-SDK-hook-after-control-ack",
            &mut checks,
        )?;
        check(
            host.invalidate(&[], Instant::now() + Duration::from_secs(2))
                == Err(SdkBridgeError::BeforeEntry),
            "empty-key-control-rejected-before-entry",
            &mut checks,
        )?;
        check(
            host.invalidate(
                &["b".into(), "a".into()],
                Instant::now() + Duration::from_secs(2),
            ) == Err(SdkBridgeError::BeforeEntry),
            "unordered-key-control-rejected-before-entry",
            &mut checks,
        )?;
        check(
            host.invalidate(&["item".into()], Instant::now()) == Err(SdkBridgeError::BeforeEntry),
            "expired-original-deadline-rejected-before-entry",
            &mut checks,
        )?;
        host.invalidate(
            &["item".into(), "other".into()],
            Instant::now() + Duration::from_secs(2),
        )?;
        check(
            read(&mut host, &mut storage)?["data"]["invalidations"] == 3,
            "ordered-two-key-control-hooks-complete-on-original-instance",
            &mut checks,
        )?;
        host.invalidate(
            &["storage-attempt".into()],
            Instant::now() + Duration::from_secs(2),
        )?;
        check(
            read(&mut host, &mut storage)?["data"]["storage_mutation_denied"] == true
                && !storage.0.contains_key("invalidation-mutation"),
            "control-hook-has-no-Storage-mutation-authority",
            &mut checks,
        )?;
        host.close(&mut storage)?;
        check(
            true,
            "successful-owned-companion-terminal-cleanup",
            &mut checks,
        )?;
        drop(host);
        let mut blocked = SdkBackendHost::launch(&config(2, &companion)?, &mut storage)?;
        let started = Instant::now();
        check(
            blocked.invalidate(
                &["deadline-blocked".into()],
                started + Duration::from_millis(30),
            ) == Err(SdkBridgeError::OutcomeUnknown)
                && started.elapsed() < Duration::from_secs(1),
            "actual-hook-timeout-cannot-extend-original-deadline",
            &mut checks,
        )?;
        check(
            blocked.handle_request("read", "cached-item", json!({}), &mut storage)
                == Err(SdkBridgeError::Fenced),
            "uncertain-control-fences-next-logical-request",
            &mut checks,
        )?;
        drop(blocked);
        let mut old = SdkBackendHost::launch(&config(3, &old_companion)?, &mut storage)?;
        check(
            old.invalidate(&["item".into()], Instant::now() + Duration::from_secs(2))
                == Err(SdkBridgeError::Fenced)
                && old.handle_request("read", "cached-item", json!({}), &mut storage)
                    == Err(SdkBridgeError::Fenced),
            "actual-old-companion-unsupported-control-fails-closed",
            &mut checks,
        )?;
        drop(old);
        let report = json!({"checks":checks,"required":14,"passed":checks.len()==14,"SDK_module":"github.com/openbao/openbao/sdk/v2@v2.7.0","actual_SDK_AutoMTLS_and_Rust_control_scope_only":true,"Service_committed_state_qualified":false,"full_OpenBao_replacement":false});
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(out.join("report.json"))?;
        file.write_all(&serde_json::to_vec_pretty(&report)?)?;
        file.sync_all()?;
        if checks.len() != 14 {
            return Err("fixed denominator".into());
        }
        println!("SDK real invalidation control: 14/14");
        Ok(())
    }
    pub fn main() {
        if let Err(error) = run() {
            eprintln!("SDK invalidation fixture failed: {error}");
            std::process::exit(1);
        }
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() {
    unix_fixture::main();
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("Unix owned SDK fixture required");
    std::process::exit(1);
}
