//! Actual TypeCredential admission and unchanged SDK Auth bytes. This fixture
//! does not grant a Service token or qualify catalog, mount or durable storage.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix_fixture {
    use heptabao_plugin_host::sdk_backend::{
        SdkBackendHost, SdkBackendType, SdkBridgeError, SdkLaunch, SdkStorage, SdkStorageEntry,
    };
    use ring::digest::{SHA256, digest};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::{
        collections::BTreeMap,
        error::Error,
        fs,
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };
    use zeroize::Zeroizing;
    #[derive(Default)]
    struct Storage {
        cells: BTreeMap<String, Zeroizing<Vec<u8>>>,
        calls: Vec<String>,
    }
    impl SdkStorage for Storage {
        fn get(
            &mut self,
            key: &str,
            deadline: Instant,
        ) -> Result<Option<SdkStorageEntry>, SdkBridgeError> {
            if Instant::now() >= deadline {
                return Err(SdkBridgeError::Fenced);
            }
            self.calls.push(format!("get:{key}"));
            Ok(self.cells.get(key).map(|value| SdkStorageEntry {
                key: key.into(),
                value: value.clone(),
                seal_wrap: false,
            }))
        }
        fn put(&mut self, entry: SdkStorageEntry, deadline: Instant) -> Result<(), SdkBridgeError> {
            if Instant::now() >= deadline {
                return Err(SdkBridgeError::Fenced);
            }
            self.calls.push(format!("put:{}", entry.key));
            self.cells.insert(entry.key, entry.value);
            Ok(())
        }
        fn delete(&mut self, key: &str, deadline: Instant) -> Result<(), SdkBridgeError> {
            if Instant::now() >= deadline {
                return Err(SdkBridgeError::Fenced);
            }
            self.calls.push(format!("delete:{key}"));
            self.cells.remove(key);
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
                return Err(SdkBridgeError::Fenced);
            }
            self.calls.push(format!("list:{prefix}"));
            Ok(self
                .cells
                .keys()
                .filter(|key| key.starts_with(prefix) && key.as_str() > after)
                .take(if limit <= 0 {
                    usize::MAX
                } else {
                    usize::try_from(limit).map_err(|_| SdkBridgeError::Storage)?
                })
                .cloned()
                .collect())
        }
    }
    fn sha(path: &Path) -> Result<[u8; 32], Box<dyn Error>> {
        Ok(digest(&SHA256, &fs::read(path)?).as_ref().try_into()?)
    }
    fn check(value: bool, label: &str, checks: &mut Vec<String>) -> Result<(), Box<dyn Error>> {
        if !value {
            return Err(label.into());
        }
        checks.push(label.into());
        Ok(())
    }
    pub(super) fn main() -> Result<(), Box<dyn Error>> {
        let args: Vec<_> = std::env::args_os().collect();
        if args.len() != 4 {
            return Err("companion plugin fresh-output".into());
        }
        let companion = PathBuf::from(&args[1]);
        let plugin = PathBuf::from(&args[2]);
        let out = PathBuf::from(&args[3]);
        fs::create_dir(&out)?;
        fs::set_permissions(&out, fs::Permissions::from_mode(0o700))?;
        let config = |round: u8| -> Result<SdkLaunch, Box<dyn Error>> {
            let socket = out.join(format!("sockets-{round}"));
            fs::create_dir(&socket)?;
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o700))?;
            Ok(SdkLaunch {
                companion: companion.clone(),
                companion_sha256: sha(&companion)?,
                plugin: plugin.clone(),
                plugin_sha256: sha(&plugin)?,
                plugin_args: match round {
                    4 => vec!["--serve".into(), "--private-login".into()],
                    5 => vec!["--serve".into(), "--root-special".into()],
                    _ => vec!["--serve".into()],
                },
                socket_directory: socket,
                private_log: out.join(format!("companion-{round}.private.log")),
                timeout: Duration::from_secs(10),
                default_ttl_seconds: 30,
                max_ttl_seconds: 60,
            })
        };
        let mut storage = Storage::default();
        let mut checks = Vec::new();
        let mut host = SdkBackendHost::launch_typed_before(
            &config(1)?,
            &mut storage,
            SdkBackendType::Auth,
            Instant::now() + Duration::from_secs(10),
        )?;
        check(
            true,
            "actual-TypeCredential-AutoMTLS-and-Setup-admitted-as-Auth",
            &mut checks,
        )?;
        host.handle_request(
            "update",
            "config",
            json!({"username":"alice","password":"fixture-passphrase"}),
            &mut storage,
        )?;
        check(
            storage.calls == ["put:config"] && storage.cells.len() == 1,
            "actual-Auth-Storage-Put-returned-to-owned-Rust-view",
            &mut checks,
        )?;
        let response = host
            .handle_request(
                "update",
                "login",
                json!({"username":"alice","password":"fixture-passphrase"}),
                &mut storage,
            )?
            .ok_or("actual Auth response")?;
        check(
            response["auth"]["alias"]["name"] == "alice"
                && response["auth"]["policies"] == json!(["sdk-test"]),
            "actual-Auth-alias-and-policies-preserved",
            &mut checks,
        )?;
        check(
            response["auth"]["lease"] == 30_000_000_000u64
                && response["auth"]["max_ttl"] == 60_000_000_000u64
                && response["auth"]["num_uses"] == 2,
            "literal-Go-Auth-lease-duration-and-use-fields",
            &mut checks,
        )?;
        check(
            response["auth"]["client_token"] == "plugin-forged-token"
                && response["auth"]["accessor"] == "plugin-forged-accessor",
            "raw-plugin-strings-preserved-without-any-Service-token-grant",
            &mut checks,
        )?;
        let denied = host
            .handle_request(
                "update",
                "login",
                json!({"username":"alice","password":"wrong"}),
                &mut storage,
            )?
            .ok_or("actual wrong credentials response")?;
        check(
            denied["auth"].is_null() && denied["data"]["error"] == "invalid credentials",
            "genuine-backend-wrong-credentials-yields-no-Auth",
            &mut checks,
        )?;
        host.close(&mut storage)?;
        check(true, "same-owned-auth-companion-natural-close", &mut checks)?;
        let before = storage.cells.clone();
        let calls = storage.calls.clone();
        let mismatch = SdkBackendHost::launch_before(
            &config(2)?,
            &mut storage,
            Instant::now() + Duration::from_secs(10),
        );
        check(
            mismatch.is_err(),
            "Auth-plugin-rejected-by-legacy-Secret-admission",
            &mut checks,
        )?;
        check(
            storage.cells == before && storage.calls == calls,
            "wrong-family-backend-published-no-config-callbacks",
            &mut checks,
        )?;
        let mut host = SdkBackendHost::launch_typed_before(
            &config(3)?,
            &mut storage,
            SdkBackendType::Auth,
            Instant::now() + Duration::from_secs(10),
        )?;
        let again = host
            .handle_request(
                "update",
                "login",
                json!({"username":"alice","password":"fixture-passphrase"}),
                &mut storage,
            )?
            .ok_or("reopened Auth response")?;
        check(
            again["auth"]["alias"]["name"] == "alice",
            "fresh-owned-Auth-host-brokers-existing-view",
            &mut checks,
        )?;
        host.close(&mut storage)?;
        for (round, label) in [
            (
                4,
                "actual-SDK-private-login-metadata-cannot-mint-public-login",
            ),
            (
                5,
                "actual-SDK-Root-path-cannot-drop-sudo-through-first-admission",
            ),
        ] {
            let before_cells = storage.cells.clone();
            let before_calls = storage.calls.clone();
            let rejected = SdkBackendHost::launch_typed_before(
                &config(round)?,
                &mut storage,
                SdkBackendType::Auth,
                Instant::now() + Duration::from_secs(10),
            );
            check(rejected.is_err(), label, &mut checks)?;
            check(
                storage.cells == before_cells && storage.calls == before_calls,
                "rejected-special-paths-no-Storage-or-config-effect",
                &mut checks,
            )?;
        }
        fs::write(
            out.join("result.original.json"),
            serde_json::to_vec_pretty(
                &json!({"passed":true,"checks":checks,"scope":"actual-Rust-owned-SDK-TypeCredential-and-raw-Auth","memory_Storage_fixture":true,"Service_Auth_qualified":false,"full_ABI_qualified":false,"full_OpenBao_replacement":false}),
            )?,
        )?;
        println!("checks={} passed=true", checks.len());
        Ok(())
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    unix_fixture::main()
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    println!("SDK Auth fixture is only implemented on Linux and macOS")
}
