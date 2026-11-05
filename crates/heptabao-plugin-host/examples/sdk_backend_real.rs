//! A real SDK plugin test of the HeptaBao Rust host and a test file storage view.
//! This does not qualify the server's catalog, HTTP mounting or barrier storage.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix_fixture {
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::fs::{File, OpenOptions};
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

    #[derive(Debug)]
    struct TestFileStorage {
        path: PathBuf,
        cells: BTreeMap<String, Value>,
        put_rejected: bool,
        callbacks: Vec<String>,
    }
    impl TestFileStorage {
        fn open(path: PathBuf) -> Result<Self, Box<dyn Error>> {
            let cells = if path.exists() {
                serde_json::from_slice(&std::fs::read(&path)?)?
            } else {
                BTreeMap::new()
            };
            Ok(Self {
                path,
                cells,
                put_rejected: false,
                callbacks: Vec::new(),
            })
        }
        fn save(&self, deadline: Instant) -> Result<(), SdkBridgeError> {
            if Instant::now() >= deadline {
                return Err(SdkBridgeError::Storage);
            }
            let tmp = self.path.with_extension("new");
            let raw = serde_json::to_vec(&self.cells).map_err(|_| SdkBridgeError::Storage)?;
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|_| SdkBridgeError::Storage)?;
            file.write_all(&raw)
                .and_then(|_| file.sync_all())
                .map_err(|_| SdkBridgeError::Storage)?;
            std::fs::rename(tmp, &self.path).map_err(|_| SdkBridgeError::Storage)?;
            File::open(self.path.parent().ok_or(SdkBridgeError::Storage)?)
                .and_then(|f| f.sync_all())
                .map_err(|_| SdkBridgeError::Storage)
        }
    }
    impl SdkStorage for TestFileStorage {
        fn get(
            &mut self,
            key: &str,
            deadline: Instant,
        ) -> Result<Option<SdkStorageEntry>, SdkBridgeError> {
            if Instant::now() >= deadline {
                return Err(SdkBridgeError::Storage);
            }
            self.callbacks.push(format!("get:{key}"));
            self.cells
                .get(key)
                .map(|v| {
                    Ok(SdkStorageEntry {
                        key: key.to_owned(),
                        value: Zeroizing::new(
                            serde_json::from_value(v["bytes"].clone())
                                .map_err(|_| SdkBridgeError::Storage)?,
                        ),
                        seal_wrap: v["seal_wrap"].as_bool().ok_or(SdkBridgeError::Storage)?,
                    })
                })
                .transpose()
        }
        fn put(&mut self, entry: SdkStorageEntry, deadline: Instant) -> Result<(), SdkBridgeError> {
            self.callbacks.push(format!("put:{}", entry.key));
            if self.put_rejected {
                return Err(SdkBridgeError::Storage);
            }
            self.cells.insert(
                entry.key,
                json!({"bytes":&*entry.value,"seal_wrap":entry.seal_wrap}),
            );
            self.save(deadline)
        }
        fn delete(&mut self, key: &str, deadline: Instant) -> Result<(), SdkBridgeError> {
            self.callbacks.push(format!("delete:{key}"));
            self.cells.remove(key);
            self.save(deadline)
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
            self.callbacks.push(format!("list:{prefix}"));
            let keys: BTreeSet<String> = self
                .cells
                .keys()
                .filter_map(|key| {
                    let suffix = key.strip_prefix(prefix)?;
                    Some(
                        suffix
                            .find('/')
                            .map_or_else(|| suffix.to_owned(), |i| suffix[..=i].to_owned()),
                    )
                })
                .filter(|k| after.is_empty() || k.as_str() > after)
                .collect();
            Ok(keys
                .into_iter()
                .take(if limit <= 0 {
                    usize::MAX
                } else {
                    usize::try_from(limit).map_err(|_| SdkBridgeError::Storage)?
                })
                .collect())
        }
    }
    fn checksum(path: &Path) -> Result<[u8; 32], Box<dyn Error>> {
        let raw = std::fs::read(path)?;
        digest(&SHA256, &raw)
            .as_ref()
            .try_into()
            .map_err(|_| "SHA256 length".into())
    }
    fn check(value: bool, label: &str, checks: &mut Vec<String>) -> Result<(), Box<dyn Error>> {
        if !value {
            return Err(label.to_owned().into());
        }
        checks.push(label.to_owned());
        Ok(())
    }
    fn read_value(value: Option<Value>) -> Option<String> {
        let value = value?;
        // The companion preserves the official logical.Response JSON field names.
        value.get("data")?.get("value")?.as_str().map(str::to_owned)
    }
    fn run() -> Result<(), Box<dyn Error>> {
        let args: Vec<_> = std::env::args_os().collect();
        if args.len() != 4 {
            return Err("companion plugin fresh-output arguments".into());
        }
        let companion = PathBuf::from(&args[1]);
        let plugin = PathBuf::from(&args[2]);
        let out = PathBuf::from(&args[3]);
        std::fs::create_dir(&out)?;
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700))?;
        let mut checks = Vec::new();
        let config = |round: u8| -> Result<SdkLaunch, Box<dyn Error>> {
            let sockets = out.join(format!("sockets-{round}"));
            std::fs::create_dir(&sockets)?;
            std::fs::set_permissions(&sockets, std::fs::Permissions::from_mode(0o700))?;
            Ok(SdkLaunch {
                companion: companion.clone(),
                companion_sha256: checksum(&companion)?,
                plugin: plugin.clone(),
                plugin_sha256: checksum(&plugin)?,
                plugin_args: vec!["--serve".to_owned()],
                socket_directory: sockets,
                private_log: out.join(format!("companion-{round}.private.log")),
                timeout: Duration::from_secs(10),
                default_ttl_seconds: 3600,
                max_ttl_seconds: 86400,
            })
        };
        let path = out.join("rust-host-storage.private.json");
        let mut storage = TestFileStorage::open(path.clone())?;
        let mut host = SdkBackendHost::launch(&config(1)?, &mut storage)?;
        check(
            true,
            "Hepta-Rust-owned-host-official-SDK-v5-AutoMTLS-Setup",
            &mut checks,
        )?;
        check(
            host.handle_request("read", "item", json!({}), &mut storage)?
                .is_none(),
            "real-plugin-missing-read",
            &mut checks,
        )?;
        check(
            matches!(
                host.handle_request("invalid", "item", json!({}), &mut storage),
                Err(SdkBridgeError::BeforeEntry)
            ),
            "unsupported-operation-before-entry",
            &mut checks,
        )?;
        host.handle_request(
            "update",
            "item",
            json!({"value":"Rust-host-durable-broker-value"}),
            &mut storage,
        )?;
        let independent: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        check(
            independent["item"]["bytes"] == json!(b"Rust-host-durable-broker-value".to_vec()),
            "plugin-Storage-Put-reaches-Rust-fsynced-file",
            &mut checks,
        )?;
        check(
            read_value(host.handle_request("read", "item", json!({}), &mut storage)?).as_deref()
                == Some("Rust-host-durable-broker-value"),
            "real-plugin-read-from-Rust-Storage-broker",
            &mut checks,
        )?;
        host.close(&mut storage)?;
        check(true, "same-owned-companion-natural-close", &mut checks)?;
        drop(host);
        drop(storage);
        let mut storage = TestFileStorage::open(path.clone())?;
        let mut host = SdkBackendHost::launch(&config(2)?, &mut storage)?;
        check(
            read_value(host.handle_request("read", "item", json!({}), &mut storage)?).as_deref()
                == Some("Rust-host-durable-broker-value"),
            "fresh-Rust-host-and-plugin-read-persisted-storage",
            &mut checks,
        )?;
        storage.put_rejected = true;
        check(
            matches!(
                host.handle_request(
                    "update",
                    "item",
                    json!({"value":"must-not-write"}),
                    &mut storage
                ),
                Err(SdkBridgeError::Backend)
            ),
            "Rust-storage-error-crosses-real-SDK-broker",
            &mut checks,
        )?;
        check(
            read_value(host.handle_request("read", "item", json!({}), &mut storage)?).as_deref()
                == Some("Rust-host-durable-broker-value"),
            "rejected-write-preserves-Rust-value",
            &mut checks,
        )?;
        storage.put_rejected = false;
        let parallel = host
            .handle_request("update", "parallel", json!({}), &mut storage)?
            .ok_or("parallel response")?;
        check(
            parallel["data"]["workers"] == 16 && storage.cells.len() == 17,
            "sixteen-real-SDK-workers-concurrent-Storage-Put-Get-to-Rust",
            &mut checks,
        )?;
        let independent: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        for index in 0..16 {
            let key = format!("parallel/{index:02}");
            if independent[&key]["bytes"] != json!(format!("worker-{index:02}").into_bytes()) {
                return Err("independent parallel storage value".into());
            }
        }
        check(
            true,
            "all-sixteen-concurrent-values-independently-read-from-fsynced-Rust-file",
            &mut checks,
        )?;
        let listed = host
            .handle_request("read", "parallel", json!({}), &mut storage)?
            .ok_or("parallel list response")?;
        check(
            listed["data"]["keys"]
                .as_array()
                .is_some_and(|v| v.len() == 16)
                && listed["data"]["page"] == json!(["00", "01", "02", "03", "04", "05", "06"])
                && listed["data"]["next"] == json!(["07", "08", "09", "10", "11", "12", "13"]),
            "real-SDK-Storage-List-and-ListPage-cross-Rust-broker",
            &mut checks,
        )?;
        host.handle_request("delete", "parallel", json!({}), &mut storage)?;
        check(
            storage.cells.len() == 1,
            "sixteen-real-SDK-workers-concurrent-Storage-Delete-to-Rust",
            &mut checks,
        )?;
        host.handle_request("delete", "item", json!({}), &mut storage)?;
        check(
            serde_json::from_slice::<Value>(&std::fs::read(&path)?)? == json!({}),
            "plugin-Storage-Delete-reaches-Rust-fsynced-file",
            &mut checks,
        )?;
        host.close(&mut storage)?;
        check(
            storage.callbacks.iter().any(|v| v == "get:item")
                && storage.callbacks.iter().any(|v| v == "put:item")
                && storage.callbacks.iter().any(|v| v == "delete:item"),
            "Rust-host-observed-real-Get-Put-Delete-callbacks",
            &mut checks,
        )?;
        let report = json!({"checks":checks,"passed":true,"Rust_host_real_SDK_storage_scope":true,"test_file_storage_fixture":true,"HeptaBao_server_plugin_catalog_mount_API_qualified":false,"HeptaBao_plugin_ABI_qualified":false,"full_OpenBao_replacement":false,"second_host_callbacks":storage.callbacks});
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(out.join("Rust-SDK-host-result.original.json"))?;
        file.write_all(&serde_json::to_vec_pretty(&report)?)?;
        file.sync_all()?;
        println!("Rust SDK host checks={} passed=true", checks.len());
        Ok(())
    }
    pub(super) fn main() -> Result<(), Box<dyn Error>> {
        run()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    unix_fixture::main()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("this native SDK fixture requires Linux or Darwin".into())
}
