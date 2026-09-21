use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn invalid_postgres_config() -> PgStorageConfig {
    PgStorageConfig {
        endpoint: crate::outbound::EndpointConfig {
            origin: "https://not-postgresql.example".into(),
            address: std::net::SocketAddr::from(([127, 0, 0, 1], 5432)),
            server_name: "not-postgresql.example".into(),
            ca_pem: String::new(),
            path_prefix: "/".into(),
            shared_secret: String::new(),
        },
        connection_url: "postgresql://db.invalid/app".into(),
        username: "heptabao".into(),
        password: "secret".into(),
        scope: "service".into(),
    }
}

#[test]
fn postgres_profile_binding_rejects_target_changes_without_binding_passwords() {
    let config = invalid_postgres_config();
    let profile = DurableProfile::postgresql(&config);
    let mut changed = clone_pg_storage_config(&config);
    changed.password = "rotated-secret".into();
    assert_eq!(profile.binding, durable_profile_binding(&changed));
    changed.connection_url = "postgresql://db.invalid/other".into();
    assert_ne!(profile.binding, durable_profile_binding(&changed));
    changed = clone_pg_storage_config(&config);
    changed.endpoint.address = std::net::SocketAddr::from(([127, 0, 0, 2], 5432));
    assert_ne!(profile.binding, durable_profile_binding(&changed));
    changed = clone_pg_storage_config(&config);
    changed.username = "another-user".into();
    assert_ne!(profile.binding, durable_profile_binding(&changed));
    let mut old_profile = profile.clone();
    old_profile.schema = 1;
    assert!(old_profile.validate().is_err());
}

#[test]
fn postgres_backend_configuration_is_admitted_only_before_activation()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    assert!(
        service
            .install_postgres_durable_storage(invalid_postgres_config())
            .is_err()
    );
    assert!(service.postgres_durable.is_none());
    bootstrap(&mut service)?;
    assert_eq!(
        service.install_postgres_durable_storage(invalid_postgres_config()),
        Err("durable backend configuration is immutable while unsealed".into())
    );
    Ok(())
}

#[test]
fn postgres_profile_marks_initialized_store_without_allowing_filesystem_fallback()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let service = root.service()?;
    private_directory(&service.data_dir)?;
    let profile_config = PgStorageConfig {
        endpoint: crate::outbound::EndpointConfig {
            origin: "postgresql://db.example".into(),
            address: std::net::SocketAddr::from(([127, 0, 0, 1], 5432)),
            server_name: "db.example".into(),
            ca_pem: String::new(),
            path_prefix: "/".into(),
            shared_secret: String::new(),
        },
        connection_url: "postgresql://db.example/app".into(),
        username: "heptabao".into(),
        password: "secret".into(),
        scope: "service".into(),
    };
    persist_durable_profile(
        &service.data_dir,
        &DurableProfile::postgresql(&profile_config),
    )?;
    drop(service);
    let mut reopened = root.service()?;
    assert!(reopened.initialized());
    assert_eq!(
        reopened
            .durable_profile
            .as_ref()
            .and_then(|profile| profile.scope.as_deref()),
        Some("service")
    );
    assert!(
        reopened
            .install_postgres_durable_storage(invalid_postgres_config())
            .is_err()
    );
    assert!(reopened.postgres_durable.is_none());
    let error = reopened
        .activate_barrier(&[17; 32])
        .err()
        .ok_or("unseal must fail")?;
    assert_eq!(error.status, 503);
    assert_eq!(
        error.body["errors"][0],
        "PostgreSQL durable backend configuration is required before unseal"
    );
    let mut changed = clone_pg_storage_config(&profile_config);
    changed.connection_url = "postgresql://db.example/other".into();
    // Inject only at the test seam so this exercises reopen binding before
    // network construction; production installation validates enrollment.
    reopened.postgres_durable = Some(changed);
    let error = reopened
        .activate_barrier(&[17; 32])
        .err()
        .ok_or("unseal must fail")?;
    assert_eq!(error.status, 503);
    assert_eq!(
        error.body["errors"][0],
        "PostgreSQL durable backend target does not match the initialized profile"
    );
    assert!(reopened.state.is_none());
    assert!(reopened.durable.is_none());
    assert!(!reopened.data_dir.join("state.hbs").exists());
    Ok(())
}

static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn postgres_initialization_body() -> Value {
    json!({"secret_shares": 1, "secret_threshold": 1, "recovery_nonce": STANDARD.encode([93_u8; 32])})
}

fn mock_postgres_initialization_import(
    root: &Path,
    bundle: &BackendBundle,
) -> Result<Box<dyn DurableBackend>, BackendError> {
    let mut backend = if root.exists() {
        let mut backend = FileBackend::open(root)?;
        if backend.load()? != *bundle {
            return Err(BackendError::RootNotEmpty);
        }
        backend
    } else {
        let mut backend = FileBackend::create_new(root)?;
        backend.initialize_empty(bundle)?;
        backend
    };
    assert_eq!(backend.load()?, *bundle);
    Ok(Box::new(backend))
}

#[test]
fn postgres_initialization_requires_nonce_before_local_or_remote_work()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    service.postgres_durable = Some(invalid_postgres_config());
    let mut imports = 0;
    let (response, _) = service.initialize_with_postgres_import(
        &json!({"secret_shares": 1, "secret_threshold": 1}),
        100,
        "test",
        |_, _| {
            imports += 1;
            Err(BackendError::Unavailable)
        },
    );
    assert_eq!(response.status, 400);
    assert_eq!(imports, 0);
    assert!(!service.data_dir.exists());
    assert!(!postgres_pending_exists(&service.data_dir)?);
    Ok(())
}

#[test]
fn postgres_prepared_initialization_survives_restart_and_authenticates_every_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    service.postgres_durable = Some(invalid_postgres_config());
    let body = postgres_initialization_body();
    let mut expected = None;
    let (response, _) =
        service.initialize_with_postgres_import(&body, 100, "prepare", |_, bundle| {
            expected = Some(bundle.clone());
            Err(BackendError::Unavailable)
        });
    assert_eq!(response.status, 503);
    assert!(!service.initialized());
    assert!(service.recovery_required);
    assert!(!service.data_dir.exists());
    let pending_path = postgres_pending_path(&service.data_dir)?;
    assert!(pending_path.is_dir());
    let bundle = expected.ok_or("missing prepared bundle")?;
    let original_journal = fs::read(pending_path.join("journal.hbj"))?;
    let original_binding = fs::read(pending_path.join(PG_INIT_BINDING_FILE))?;
    drop(service);

    let mut service = root.service()?;
    service.postgres_durable = Some(invalid_postgres_config());
    let mut imports = 0;
    for (body, expected_status) in [
        (json!({"secret_shares": 1, "secret_threshold": 1}), 400),
        (
            json!({"secret_shares": 1, "secret_threshold": 1, "recovery_nonce": STANDARD.encode([94_u8;32])}),
            403,
        ),
        (
            json!({"secret_shares": 2, "secret_threshold": 2, "recovery_nonce": STANDARD.encode([93_u8;32])}),
            400,
        ),
    ] {
        let (response, _) =
            service.initialize_with_postgres_import(&body, 101, "rejected", |_, _| {
                imports += 1;
                Err(BackendError::Unavailable)
            });
        assert_eq!(response.status, expected_status);
    }
    assert_eq!(imports, 0);
    let mut changed_config = invalid_postgres_config();
    changed_config.connection_url = "postgresql://db.invalid/other".into();
    service.postgres_durable = Some(changed_config);
    let (response, _) = service.initialize_with_postgres_import(&body, 101, "target", |_, _| {
        imports += 1;
        Err(BackendError::Unavailable)
    });
    assert_eq!(response.status, 503);
    assert_eq!(imports, 0);
    service.postgres_durable = Some(invalid_postgres_config());
    let mut tampered = original_journal.clone();
    tampered[0] ^= 1;
    fs::write(pending_path.join("journal.hbj"), &tampered)?;
    let (response, _) = service.initialize_with_postgres_import(&body, 101, "tampered", |_, _| {
        imports += 1;
        Err(BackendError::Unavailable)
    });
    assert_eq!(response.status, 403);
    assert_eq!(imports, 0);
    fs::write(pending_path.join("journal.hbj"), &original_journal)?;
    assert_eq!(
        fs::read(pending_path.join(PG_INIT_BINDING_FILE))?,
        original_binding
    );

    let remote = root.path.join("remote");
    let (response, _) =
        service.initialize_with_postgres_import(&body, 102, "recovery", |_, candidate| {
            assert_eq!(candidate, &bundle);
            mock_postgres_initialization_import(&remote, candidate)
        });
    assert_eq!(response.status, 200);
    assert!(service.initialized());
    assert!(!postgres_pending_exists(&service.data_dir)?);
    for artifact in ["state.hbs", "journal.hbj", "ledger.hbl"] {
        assert!(!service.data_dir.join(artifact).exists());
    }
    let expected_response = response.body.clone();
    for path in [
        remote.join("state.hbs"),
        remote.join("journal.hbj"),
        service.data_dir.join(INIT_RECOVERY_FILE),
    ] {
        let ciphertext = fs::read(path)?;
        for secret in [
            expected_response["root_token"].as_str(),
            expected_response["keys_base64"][0].as_str(),
            body["recovery_nonce"].as_str(),
        ]
        .into_iter()
        .flatten()
        {
            assert!(
                !ciphertext
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes())
            );
        }
    }
    drop(service);
    let mut service = root.service()?;
    let (retried, _) =
        service.initialize_with_postgres_import(&body, 103, "response-loss", |_, _| {
            imports += 1;
            Err(BackendError::Unavailable)
        });
    assert_eq!(retried.status, 200);
    assert_eq!(retried.body, expected_response);
    assert_eq!(imports, 0);
    Ok(())
}

#[test]
fn postgres_unknown_import_reconciles_exact_candidate_and_conflicts_never_overwrite()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    service.postgres_durable = Some(invalid_postgres_config());
    let body = postgres_initialization_body();
    let remote = root.path.join("remote");
    let (response, _) =
        service.initialize_with_postgres_import(&body, 100, "lost-ack", |_, candidate| {
            drop(mock_postgres_initialization_import(&remote, candidate)?);
            Err(BackendError::OutcomeUnknown)
        });
    assert_eq!(response.status, 503);
    assert!(!service.initialized());
    assert!(postgres_pending_exists(&service.data_dir)?);
    let committed = FileBackend::open(&remote)?.load()?;
    let (conflict, _) = service.initialize_with_postgres_import(&body, 101, "conflict", |_, _| {
        Err(BackendError::RootNotEmpty)
    });
    assert_eq!(conflict.status, 409);
    assert_eq!(FileBackend::open(&remote)?.load()?, committed);
    assert!(postgres_pending_exists(&service.data_dir)?);
    drop(service);
    let mut service = root.service()?;
    service.postgres_durable = Some(invalid_postgres_config());
    let (response, _) =
        service.initialize_with_postgres_import(&body, 102, "retry", |_, candidate| {
            assert_eq!(candidate, &committed);
            mock_postgres_initialization_import(&remote, candidate)
        });
    assert_eq!(response.status, 200);
    assert_eq!(FileBackend::open(&remote)?.load()?, committed);
    Ok(())
}

#[test]
fn postgres_pending_candidate_survives_audit_and_publication_failure_without_releasing_fences()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    service.postgres_durable = Some(invalid_postgres_config());
    service.audit_capacity = 0;
    let body = postgres_initialization_body();
    let mut imports = 0;
    let (response, _) =
        service.initialize_with_postgres_import(&body, 100, "audit-full", |_, _| {
            imports += 1;
            Err(BackendError::Unavailable)
        });
    assert_eq!(response.status, 503);
    assert_eq!(imports, 0);
    assert!(postgres_pending_exists(&service.data_dir)?);
    let pending = postgres_pending_path(&service.data_dir)?;
    let prepared = FileBackend::open(&pending)?.load()?;
    drop(service);

    let mut service = root.service()?;
    service.postgres_durable = Some(invalid_postgres_config());
    let data_dir = service.data_dir.clone();
    let remote = root.path.join("remote");
    let (response, _) =
        service.initialize_with_postgres_import(&body, 101, "publish-fault", |_, candidate| {
            assert!(ExclusiveDirectory::open(&root.path).is_err());
            assert!(matches!(
                FileBackend::open(&pending),
                Err(BackendError::WriterLocked)
            ));
            let remote_fence = mock_postgres_initialization_import(&remote, candidate)?;
            // A non-cooperating filesystem fault prevents publication. It must
            // not delete the committed remote candidate or overwrite this path.
            private_directory(&data_dir).map_err(|_| BackendError::Io)?;
            fs::write(data_dir.join("foreign"), b"retain").map_err(|_| BackendError::Io)?;
            Ok(remote_fence)
        });
    assert_eq!(response.status, 503);
    assert_eq!(fs::read(data_dir.join("foreign"))?, b"retain");
    assert_eq!(FileBackend::open(&remote)?.load()?, prepared);
    assert_eq!(FileBackend::open(&pending)?.load()?, prepared);
    // Remove only the explicit fault fixture, then retry the same candidate.
    fs::remove_dir_all(&data_dir)?;
    drop(service);
    let mut service = root.service()?;
    service.postgres_durable = Some(invalid_postgres_config());
    let (response, _) =
        service.initialize_with_postgres_import(&body, 102, "retry", |_, candidate| {
            mock_postgres_initialization_import(&remote, candidate)
        });
    assert_eq!(response.status, 200);
    assert!(!postgres_pending_exists(&data_dir)?);
    Ok(())
}

#[test]
fn postgres_published_metadata_with_pending_residue_requires_matching_identity_on_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    service.postgres_durable = Some(invalid_postgres_config());
    let body = postgres_initialization_body();
    let data_dir = service.data_dir.clone();
    let pending = postgres_pending_path(&data_dir)?;
    let remote = root.path.join("remote");
    let (response, _) = service.initialize_with_postgres_import(
        &body,
        100,
        "published-before-crash",
        |_, candidate| {
            drop(mock_postgres_initialization_import(&remote, candidate)?);
            // Model a crash after the atomic metadata rename, before pending
            // cleanup. The metadata is copied byte-for-byte from the candidate.
            private_directory(&data_dir).map_err(|_| BackendError::Io)?;
            for name in [SEAL_METADATA_FILE, DURABLE_PROFILE_FILE, INIT_RECOVERY_FILE] {
                fs::copy(pending.join(name), data_dir.join(name)).map_err(|_| BackendError::Io)?;
            }
            File::open(&data_dir)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| BackendError::Io)?;
            Err(BackendError::OutcomeUnknown)
        },
    );
    assert_eq!(response.status, 503);
    drop(service);
    let original_profile = fs::read(data_dir.join(DURABLE_PROFILE_FILE))?;
    let mut profile = load_durable_profile(&data_dir)?.ok_or("missing profile")?;
    profile.binding = "0".repeat(64);
    persist_durable_profile(&data_dir, &profile)?;
    let mut service = root.service()?;
    let mut imports = 0;
    let (response, _) =
        service.initialize_with_postgres_import(&body, 101, "wrong-published-target", |_, _| {
            imports += 1;
            Err(BackendError::Unavailable)
        });
    assert_eq!(response.status, 503);
    assert_eq!(imports, 0);
    assert!(pending.exists());
    drop(service);
    fs::write(data_dir.join(DURABLE_PROFILE_FILE), &original_profile)?;
    let mut service = root.service()?;
    assert!(service.recovery_required);
    assert_eq!(service.unseal(&json!({"key": "unused"})).status, 503);
    let (response, _) = service.initialize_with_postgres_import(&body, 102, "cleanup", |_, _| {
        imports += 1;
        Err(BackendError::Unavailable)
    });
    assert_eq!(response.status, 200);
    assert_eq!(imports, 0);
    assert!(!service.recovery_required);
    assert!(!pending.exists());
    Ok(())
}

#[test]
fn postgres_pending_candidate_cannot_be_relocated_to_another_data_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    service.postgres_durable = Some(invalid_postgres_config());
    let body = postgres_initialization_body();
    let (response, _) = service.initialize_with_postgres_import(&body, 100, "prepare", |_, _| {
        Err(BackendError::Unavailable)
    });
    assert_eq!(response.status, 503);
    let source = postgres_pending_path(&service.data_dir)?;
    let other = Root::new();
    let mut relocated = other.service()?;
    relocated.postgres_durable = Some(invalid_postgres_config());
    let target = postgres_pending_path(&relocated.data_dir)?;
    private_directory(&target)?;
    for entry in fs::read_dir(&source)? {
        let entry = entry?;
        fs::copy(entry.path(), target.join(entry.file_name()))?;
    }
    let mut imports = 0;
    let (response, _) =
        relocated.initialize_with_postgres_import(&body, 101, "relocated", |_, _| {
            imports += 1;
            Err(BackendError::Unavailable)
        });
    assert_eq!(response.status, 403);
    assert_eq!(imports, 0);
    assert!(source.exists());
    assert!(target.exists());
    assert!(!relocated.initialized());
    Ok(())
}

#[test]
fn postgres_partial_retired_cleanup_cannot_recreate_an_active_pending_initialization()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    service.postgres_durable = Some(invalid_postgres_config());
    let body = postgres_initialization_body();
    let (response, _) = service.initialize_with_postgres_import(&body, 100, "prepare", |_, _| {
        Err(BackendError::Unavailable)
    });
    assert_eq!(response.status, 503);
    let data_dir = service.data_dir.clone();
    let pending = postgres_pending_path(&data_dir)?;
    // Model the final metadata already durably published after remote ack.
    private_directory(&data_dir)?;
    for name in [SEAL_METADATA_FILE, DURABLE_PROFILE_FILE, INIT_RECOVERY_FILE] {
        fs::copy(pending.join(name), data_dir.join(name))?;
    }
    File::open(&data_dir)?.sync_all()?;
    let parent = ExclusiveDirectory::open(&root.path)?;
    parent.sync_all()?;
    let mut retired_name = None;
    retire_postgres_pending(&pending, &parent, |retired| {
        retired_name = retired.file_name().map(|name| name.to_os_string());
        fs::remove_file(retired.join("state.hbs"))?;
        Err(io::Error::other("injected recursive cleanup failure"))
    })?;
    assert!(!pending.exists());
    let retired = root.path.join(retired_name.ok_or("missing retired path")?);
    assert!(retired.exists());
    assert!(!retired.join("state.hbs").exists());
    assert!(retired.join("journal.hbj").exists());
    drop(parent);
    drop(service);
    let mut service = root.service()?;
    assert!(!service.recovery_required);
    let mut imports = 0;
    let (response, _) = service.initialize_with_postgres_import(&body, 101, "retry", |_, _| {
        imports += 1;
        Err(BackendError::Unavailable)
    });
    assert_eq!(response.status, 200);
    assert_eq!(imports, 0);
    assert!(service.initialized());
    Ok(())
}

#[test]
fn postgres_service_constructed_before_peer_publication_recovers_same_response()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut first = root.service()?;
    let mut second = Service::new(
        root.path.join("data"),
        &root.path.join("second-audit.jsonl"),
    )?;
    first.postgres_durable = Some(invalid_postgres_config());
    second.postgres_durable = Some(invalid_postgres_config());
    let remote = root.path.join("remote");
    let body = postgres_initialization_body();
    let (response, _) =
        first.initialize_with_postgres_import(&body, 100, "first", |_, candidate| {
            mock_postgres_initialization_import(&remote, candidate)
        });
    assert_eq!(response.status, 200);
    assert!(second.seal.is_none());
    let mut imports = 0;
    let (recovered, _) = second.initialize_with_postgres_import(&body, 101, "second", |_, _| {
        imports += 1;
        Err(BackendError::Unavailable)
    });
    assert_eq!(recovered.status, 200);
    assert_eq!(recovered.body, response.body);
    assert_eq!(imports, 0);
    assert!(second.seal.is_some());
    assert!(second.durable_profile.is_some());
    Ok(())
}
pub(super) struct Root {
    pub(super) path: PathBuf,
}
impl Root {
    pub(super) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "heptabao-service-test-{}-{}",
            std::process::id(),
            ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        Self { path }
    }
    pub(super) fn service(&self) -> Result<Service, Box<dyn std::error::Error>> {
        if !self.path.exists() {
            private_directory(&self.path)?;
        }
        Service::new(self.path.join("data"), &self.path.join("audit.jsonl")).map_err(Into::into)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
pub(super) fn call(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> Response {
    service.handle_at(method, path, "", token, body, 100)
}
pub(super) fn bootstrap(
    service: &mut Service,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let response = call(
        service,
        "PUT",
        "sys/init",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(response.status, 200);
    let key = response.body["keys_base64"][0]
        .as_str()
        .ok_or("missing key")?
        .to_owned();
    let token = response.body["root_token"]
        .as_str()
        .ok_or("missing token")?
        .to_owned();
    assert!(service.state.is_none());
    assert_eq!(
        call(service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    Ok((key, token))
}
pub(super) fn limited_token(
    service: &mut Service,
    root: &str,
    policy: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let policy_response = call(
        service,
        "PUT",
        "sys/policies/acl/scoped",
        root,
        json!({"policy":policy}),
    );
    assert!(policy_response.status < 300);
    let response = call(
        service,
        "POST",
        "auth/token/create",
        root,
        json!({"policies":["scoped"],"no_default_policy":true,"num_uses":1}),
    );
    assert_eq!(response.status, 200);
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing limited token")?
        .to_owned())
}

#[test]
fn initialization_recovery_survives_response_loss_and_requires_root_ack()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let secret = STANDARD.encode([93_u8; 32]);
    let body = json!({"secret_shares":3,"secret_threshold":2,"recovery_nonce":secret});
    let initialized = call(&mut service, "POST", "sys/init", "", body.clone());
    assert_eq!(initialized.status, 200);
    assert_eq!(initialized.body["init_ack_required"], true);
    let expected = initialized.body.clone();
    let keys = expected["keys_base64"].as_array().ok_or("missing shares")?;
    let token = expected["root_token"]
        .as_str()
        .ok_or("missing root token")?;
    let recovery_path = root.path.join("data").join(INIT_RECOVERY_FILE);
    for directory in [&root.path, &root.path.join("data")] {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let bytes = fs::read(entry.path())?;
            for credential in [
                secret.as_str(),
                token,
                keys[0].as_str().ok_or("missing first share")?,
            ] {
                assert!(
                    !bytes
                        .windows(credential.len())
                        .any(|window| window == credential.as_bytes())
                );
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&recovery_path)?.permissions().mode() & 0o777,
            0o600
        );
    }
    // Simulate losing the entire response and the process after publication.
    drop(initialized);
    drop(service);
    let mut service = root.service()?;
    let recovered = call(&mut service, "POST", "sys/init", "", body.clone());
    assert_eq!(recovered.status, 200);
    assert_eq!(recovered.body, expected);
    assert_eq!(
        call(&mut service, "GET", "sys/init", "", json!({})).body,
        json!({"initialized":true})
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/init",
            "",
            json!({"secret_shares":3,"secret_threshold":2})
        )
        .status,
        400
    );
    let mut wrong = body.clone();
    wrong["recovery_nonce"] = json!(STANDARD.encode([94_u8; 32]));
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", wrong).status,
        403
    );
    let mut unknown = body.clone();
    unknown["unknown"] = json!(true);
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", unknown).status,
        400
    );
    assert_eq!(
        service
            .handle_at("POST", "sys/init", "team", "", body.clone(), 100)
            .status,
        400
    );
    assert_eq!(
        call(&mut service, "POST", "sys/init/ack", token, json!({})).status,
        503
    );
    for key in keys.iter().take(2) {
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
    }
    assert!(service.state.is_some());
    assert_eq!(
        call(&mut service, "POST", "sys/rekey/init", token, json!({})).status,
        409
    );
    assert_eq!(
        call(&mut service, "POST", "sys/init/ack", "", json!({})).status,
        403
    );
    assert_eq!(
        service
            .handle_at("POST", "sys/init/ack", "team", token, json!({}), 100)
            .status,
        403
    );
    let limited = limited_token(
        &mut service,
        token,
        r#"path "auth/token/lookup-self" { capabilities = ["read"] }"#,
    )?;
    assert_eq!(
        call(&mut service, "POST", "sys/init", &limited, body.clone()).body,
        expected
    );
    // Recovering with the client secret does not authenticate or consume this token.
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &limited,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "POST", "sys/init/ack", token, json!({})).status,
        204
    );
    assert!(!recovery_path.exists());
    assert_eq!(
        call(&mut service, "POST", "sys/init/ack", token, json!({})).status,
        204
    );
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", body.clone()).status,
        409
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(call(&mut service, "POST", "sys/init", "", body).status, 409);
    for key in keys.iter().take(2) {
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
    }
    assert_eq!(
        call(&mut service, "POST", "sys/rekey/init", token, json!({})).status,
        200
    );
    Ok(())
}

#[test]
fn unsupported_database_provider_names_fail_closed_without_mount_state()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_key, token) = bootstrap(&mut service)?;
    let mounted = call(
        &mut service,
        "POST",
        "sys/mounts/database",
        &token,
        json!({"type":"database"}),
    );
    assert!(mounted.status < 300, "{}", mounted.body);
    let before = service.state_digest;
    for plugin_name in [
        "mysql-database-plugin",
        "cassandra-database-plugin",
        "influxdb-database-plugin",
    ] {
        let response = call(
            &mut service,
            "POST",
            "database/config/main",
            &token,
            json!({
                "plugin_name": plugin_name,
                "connection_url": "https://127.0.0.1:8443/",
                "username": "manager",
                "password": "manager-password",
                "allowed_roles": ["reader"],
                "verify_connection": true
            }),
        );
        assert_eq!(response.status, 400, "{plugin_name}: {}", response.body);
        assert_eq!(
            service.state_digest, before,
            "{plugin_name} mutated durable state"
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "database/config/main",
                &token,
                json!({})
            )
            .status,
            404,
            "{plugin_name} left a configuration behind"
        );
    }
    Ok(())
}

#[test]
fn initialization_recovery_rejects_tampering_wrong_seal_and_invalid_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    for secret in [
        json!(null),
        json!(0),
        json!("short"),
        json!(STANDARD.encode([0_u8; 32])),
        json!("f".repeat(63)),
    ] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/init",
                "",
                json!({"recovery_nonce":secret})
            )
            .status,
            400
        );
        assert!(!service.initialized());
    }
    let body = json!({"secret_shares":1,"secret_threshold":1,"recovery_nonce":"a3".repeat(32)});
    let response = call(&mut service, "POST", "sys/init", "", body.clone());
    assert_eq!(response.status, 200);
    let path = root.path.join("data").join(INIT_RECOVERY_FILE);
    let original = fs::read(&path)?;
    let mut tampered = original.clone();
    *tampered.last_mut().ok_or("empty recovery ciphertext")? ^= 1;
    fs::write(&path, tampered)?;
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", body.clone()).status,
        403
    );
    fs::write(&path, &original)?;
    let seal_path = root.path.join("data").join(SEAL_METADATA_FILE);
    let original_seal = fs::read(&seal_path)?;
    let mut seal: SealMetadata = serde_json::from_slice(&original_seal)?;
    seal.generation += 1;
    fs::write(&seal_path, serde_json::to_vec(&seal)?)?;
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", body.clone()).status,
        503
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", body.clone()).status,
        403
    );
    fs::write(&seal_path, &original_seal)?;
    drop(service);
    let mut service = root.service()?;
    fs::write(&path, vec![0_u8; INIT_RECOVERY_LIMIT as usize + 1])?;
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", body.clone()).status,
        503
    );
    fs::write(&path, &original)?;
    #[cfg(unix)]
    {
        fs::remove_file(&path)?;
        std::os::unix::fs::symlink(&seal_path, &path)?;
        assert_eq!(
            call(&mut service, "POST", "sys/init", "", body.clone()).status,
            503
        );
        fs::remove_file(&path)?;
        fs::write(&path, &original)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", body).body,
        response.body
    );
    Ok(())
}

#[test]
fn initialization_ack_directory_sync_failure_fences_and_retry_resyncs()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let response = call(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({"secret_shares":1,"secret_threshold":1,"recovery_nonce":STANDARD.encode([92_u8;32])}),
    );
    assert_eq!(response.status, 200);
    let key = response.body["keys_base64"][0]
        .as_str()
        .ok_or("missing key")?;
    let token = response.body["root_token"]
        .as_str()
        .ok_or("missing root token")?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let failed = service.ack_initialization_with_sync("POST", &json!({}), |_| {
        Err(io::Error::other("injected directory sync failure"))
    });
    assert_eq!(failed.status, 503);
    assert!(service.recovery_required);
    assert!(!root.path.join("data").join(INIT_RECOVERY_FILE).exists());
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            token,
            json!({})
        )
        .status,
        503
    );
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let resynced = std::cell::Cell::new(false);
    let retry = service.ack_initialization_with_sync("POST", &json!({}), |path| {
        resynced.set(true);
        File::open(path)?.sync_all()
    });
    assert_eq!(retry.status, 204);
    assert!(resynced.get());
    Ok(())
}

#[test]
fn initialization_without_recovery_secret_never_creates_escrow_and_legacy_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let response = call(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(response.status, 200);
    assert!(response.body.get("init_ack_required").is_none());
    assert!(!initialization_recovery_pending(&service.data_dir)?);
    assert_eq!(call(&mut service, "POST", "sys/init", "", json!({"secret_shares":1,"secret_threshold":1,"recovery_nonce":STANDARD.encode([91_u8;32])})).status, 409);
    drop(service);
    fs::write(
        root.path.join("audit.jsonl.init-escrow"),
        b"legacy-audit-key-ciphertext",
    )?;
    assert!(root.service().is_err());
    Ok(())
}

#[test]
fn shamir_threshold_unseal_and_online_rekey_preserve_the_barrier_key()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let initialized = call(
        &mut service,
        "PUT",
        "sys/init",
        "",
        json!({"secret_shares":5,"secret_threshold":3}),
    );
    assert_eq!(initialized.status, 200);
    let old_keys = initialized.body["keys_base64"]
        .as_array()
        .ok_or("missing Shamir shares")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or("invalid Shamir share")
                .map(str::to_owned)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let root_token = initialized.body["root_token"]
        .as_str()
        .ok_or("missing root token")?
        .to_owned();
    assert_eq!(old_keys.len(), 5);

    let first = call(
        &mut service,
        "PUT",
        "sys/unseal",
        "",
        json!({"key":old_keys[0]}),
    );
    assert_eq!(first.status, 200);
    assert_eq!(first.body["sealed"], true);
    assert_eq!(first.body["progress"], 1);
    let nonce = first.body["nonce"].as_str().ok_or("missing unseal nonce")?;
    let duplicate = call(
        &mut service,
        "PUT",
        "sys/unseal",
        "",
        json!({"key":old_keys[0]}),
    );
    assert_eq!(duplicate.body["progress"], 1);
    assert_eq!(duplicate.body["nonce"], nonce);
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":old_keys[2]}),
        )
        .body["progress"],
        2
    );
    let unsealed = call(
        &mut service,
        "PUT",
        "sys/unseal",
        "",
        json!({"key":old_keys[4]}),
    );
    assert_eq!(unsealed.status, 200);
    assert_eq!(unsealed.body["sealed"], false);

    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/rekey",
            &root_token,
            json!({"data":{"value":"survives-rekey"}}),
        )
        .status,
        200
    );
    let start = call(
        &mut service,
        "POST",
        "sys/rekey/init",
        &root_token,
        json!({"secret_shares":4,"secret_threshold":2,"require_verification":false}),
    );
    assert_eq!(start.status, 200);
    let rekey_nonce = start.body["nonce"]
        .as_str()
        .ok_or("missing rekey nonce")?
        .to_owned();
    let first_update = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":rekey_nonce,"key":old_keys[1]}),
    );
    assert_eq!(first_update.status, 200);
    assert_eq!(first_update.body["complete"], false);
    let second_update = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":rekey_nonce,"key":old_keys[3]}),
    );
    assert_eq!(second_update.status, 200);
    assert_eq!(second_update.body["complete"], false);
    let completed = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":rekey_nonce,"key":old_keys[4]}),
    );
    assert_eq!(completed.status, 200);
    assert_eq!(completed.body["complete"], true);
    let new_keys = completed.body["keys_base64"]
        .as_array()
        .ok_or("missing rekey shares")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or("invalid rekey share")
                .map(str::to_owned)
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(new_keys.len(), 4);

    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &root_token, json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":old_keys[0]}),
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":new_keys[0]}),
        )
        .body["progress"],
        1
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":new_keys[2]}),
        )
        .body["sealed"],
        false
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/rekey",
            &root_token,
            json!({}),
        )
        .body["data"]["data"]["value"],
        "survives-rekey"
    );
    drop(service);

    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":new_keys[1]}),
        )
        .body["progress"],
        1
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":new_keys[3]}),
        )
        .body["sealed"],
        false
    );
    Ok(())
}

#[test]
fn verified_rekey_survives_response_loss_restart_and_cancel()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let initialized = call(
        &mut service,
        "PUT",
        "sys/init",
        "",
        json!({"secret_shares":5,"secret_threshold":3}),
    );
    assert_eq!(initialized.status, 200);
    let old_keys = initialized.body["keys_base64"]
        .as_array()
        .ok_or("missing original shares")?
        .iter()
        .map(|value| value.as_str().ok_or("invalid share").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let root_token = initialized.body["root_token"]
        .as_str()
        .ok_or("missing root token")?
        .to_owned();
    for index in [0, 2, 4] {
        let response = call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":old_keys[index]}),
        );
        assert_eq!(response.status, 200);
    }
    assert!(service.state.is_some());
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/verified-rekey",
            &root_token,
            json!({"data":{"value":"survives-verified-rekey"}}),
        )
        .status,
        200
    );

    let started = call(
        &mut service,
        "POST",
        "sys/rekey/init",
        &root_token,
        json!({"secret_shares":4,"secret_threshold":2}),
    );
    let authorization_nonce = started.body["nonce"]
        .as_str()
        .ok_or("missing rekey authorization nonce")?
        .to_owned();
    for index in [1, 3] {
        let response = call(
            &mut service,
            "POST",
            "sys/rekey/update",
            &root_token,
            json!({"nonce":authorization_nonce,"key":old_keys[index]}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["complete"], false);
    }
    let staged = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":authorization_nonce,"key":old_keys[4]}),
    );
    assert_eq!(staged.status, 200);
    assert_eq!(staged.body["complete"], true);
    assert_eq!(staged.body["verification_required"], true);
    let verification_nonce = staged.body["verification_nonce"]
        .as_str()
        .ok_or("missing rekey verification nonce")?
        .to_owned();
    let new_keys = staged.body["keys_base64"]
        .as_array()
        .ok_or("missing candidate shares")?
        .iter()
        .map(|value| value.as_str().ok_or("invalid share").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(new_keys.len(), 4);
    assert_eq!(
        service
            .seal
            .as_ref()
            .ok_or("missing active seal")?
            .generation,
        1
    );
    let pending_path = root.path.join("data").join(PENDING_REKEY_FILE);
    assert!(pending_path.is_file());
    let pending_text = fs::read_to_string(&pending_path)?;
    assert!(old_keys.iter().all(|share| !pending_text.contains(share)));
    assert!(new_keys.iter().all(|share| !pending_text.contains(share)));

    // Losing the response or process cannot activate keys that have not been
    // independently verified. The original shares remain authoritative.
    drop(staged);
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":new_keys[0]}),
        )
        .status,
        400
    );
    for index in [0, 1, 2] {
        assert_eq!(
            call(
                &mut service,
                "PUT",
                "sys/unseal",
                "",
                json!({"key":old_keys[index]}),
            )
            .status,
            200
        );
    }
    let status = call(
        &mut service,
        "GET",
        "sys/rekey/init",
        &root_token,
        json!({}),
    );
    assert_eq!(status.body["verification_required"], true);
    assert_eq!(status.body["verification_nonce"], verification_nonce);
    assert_eq!(status.body["verification_progress"], 0);
    let first_verify = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":verification_nonce,"key":new_keys[0]}),
    );
    assert_eq!(first_verify.status, 200);
    assert_eq!(first_verify.body["verification_progress"], 1);

    // Verification progress may be replayed after restart, but the pending
    // candidate and its nonce survive without changing the active seal.
    drop(service);
    let mut service = root.service()?;
    for index in [0, 2, 4] {
        assert_eq!(
            call(
                &mut service,
                "PUT",
                "sys/unseal",
                "",
                json!({"key":old_keys[index]}),
            )
            .status,
            200
        );
    }
    let resumed = call(
        &mut service,
        "GET",
        "sys/rekey/init",
        &root_token,
        json!({}),
    );
    assert_eq!(resumed.body["verification_nonce"], verification_nonce);
    assert_eq!(resumed.body["verification_progress"], 0);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/rekey/update",
            &root_token,
            json!({"nonce":verification_nonce,"key":new_keys[1]}),
        )
        .body["verification_progress"],
        1
    );
    let verified = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":verification_nonce,"key":new_keys[3]}),
    );
    assert_eq!(verified.status, 200);
    assert_eq!(verified.body["verification_required"], false);
    assert_eq!(
        service
            .seal
            .as_ref()
            .ok_or("missing promoted seal")?
            .generation,
        2
    );
    assert!(!pending_path.exists());

    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &root_token, json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":old_keys[0]}),
        )
        .status,
        400
    );
    for index in [0, 2] {
        assert_eq!(
            call(
                &mut service,
                "PUT",
                "sys/unseal",
                "",
                json!({"key":new_keys[index]}),
            )
            .status,
            200
        );
    }
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/verified-rekey",
            &root_token,
            json!({}),
        )
        .body["data"]["data"]["value"],
        "survives-verified-rekey"
    );

    // A second staged generation can be cancelled durably. Its unpublished
    // shares never displace the currently active generation.
    let started = call(
        &mut service,
        "POST",
        "sys/rekey/init",
        &root_token,
        json!({"secret_shares":3,"secret_threshold":2,"require_verification":true}),
    );
    let nonce = started.body["nonce"]
        .as_str()
        .ok_or("missing nonce")?
        .to_owned();
    let partial = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":nonce,"key":new_keys[0]}),
    );
    assert_eq!(partial.body["complete"], false);
    let staged = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":nonce,"key":new_keys[2]}),
    );
    let cancelled_keys = staged.body["keys_base64"]
        .as_array()
        .ok_or("missing cancelled candidate shares")?
        .iter()
        .map(|value| value.as_str().ok_or("invalid share").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(pending_path.exists());
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/rekey/init",
            &root_token,
            json!({}),
        )
        .status,
        204
    );
    assert!(!pending_path.exists());
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &root_token, json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":cancelled_keys[0]}),
        )
        .status,
        400
    );
    for index in [1, 3] {
        assert_eq!(
            call(
                &mut service,
                "PUT",
                "sys/unseal",
                "",
                json!({"key":new_keys[index]}),
            )
            .status,
            200
        );
    }
    Ok(())
}

#[test]
fn init_seal_wrong_key_root_policy_kv_restart_and_no_plaintext_disk()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/app",
            &token,
            json!({"data":{"password":"synthetic-private-secret"}})
        )
        .status,
        200
    );
    let reader = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/app" { capabilities = ["read"] }"#,
    )?;
    let read = call(&mut service, "GET", "secret/data/app", &reader, json!({}));
    assert_eq!(read.status, 200);
    assert_eq!(
        read.body["data"]["data"]["password"],
        "synthetic-private-secret"
    );
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &token, json!({})).status,
        204
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &token, json!({})).status,
        503
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":STANDARD.encode([5;32])})
        )
        .status,
        400
    );
    assert!(service.state.is_none());
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "GET", "sys/seal-status", "", json!({})).body["sealed"],
        true
    );
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &token, json!({})).body["data"]["data"]["password"],
        "synthetic-private-secret"
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &reader, json!({})).status,
        403
    );
    for file in [
        "data/state.hbs",
        "data/journal.hbj",
        "data/ledger.hbl",
        "data/seal.json",
        "audit.jsonl",
    ] {
        let bytes = fs::read(root.path.join(file))?;
        for secret in ["synthetic-private-secret", token.as_str(), key.as_str()] {
            assert!(!bytes.windows(secret.len()).any(|b| b == secret.as_bytes()));
        }
    }
    Ok(())
}

#[test]
fn finite_use_is_committed_for_acl_denial_and_state_capacity_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let denied = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/allowed" { capabilities = ["read"] }"#,
    )?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/forbidden",
            &denied,
            json!({})
        )
        .status,
        403
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/allowed",
            &denied,
            json!({})
        )
        .status,
        403
    );
    let writer = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/large" { capabilities = ["create", "update", "read"] }"#,
    )?;
    // Leave room for the separately committed finite-use admission while
    // rejecting the 4 KiB business mutation under the record payload bound.
    service.state_capacity = service
        .record_root
        .as_ref()
        .ok_or("missing root")?
        .owners
        .iter()
        .map(|owner| owner.total_bytes as usize)
        .sum::<usize>()
        + 1024;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/large",
            &writer,
            json!({"data":{"value":"x".repeat(4000)}})
        )
        .status,
        507
    );
    service.state_capacity = MAX_STATE_BYTES;
    assert_eq!(
        call(&mut service, "GET", "secret/data/large", &writer, json!({})).status,
        403
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/large", &token, json!({})).status,
        404
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/large", &writer, json!({})).status,
        403
    );
    Ok(())
}

#[test]
fn unknown_journal_write_releases_no_secret_and_preserves_last_committed_state()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let seeded = call(
        &mut service,
        "PUT",
        "secret/data/committed",
        &token,
        json!({"data":{"value":"acknowledged-secret"}}),
    );
    assert_eq!(seeded.status, 200);
    // The normal writer appends deltas; ledger.tmp is used only by checkpoints.
    fs::rename(
        root.path.join("data/journal.hbj"),
        root.path.join("data/journal.saved"),
    )?;
    fs::create_dir(root.path.join("data/journal.hbj"))?;
    let result = call(
        &mut service,
        "PUT",
        "secret/data/uncertain",
        &token,
        json!({"data":{"value":"uncertain-secret"}}),
    );
    assert_eq!(result.status, 503);
    assert!(
        result.body["recovery_reference"].is_string(),
        "{}",
        result.body
    );
    assert!(!result.body.to_string().contains("uncertain-secret"));
    assert!(service.recovery_required);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/uncertain",
            &token,
            json!({})
        )
        .status,
        503
    );
    drop(service);
    fs::remove_dir(root.path.join("data/journal.hbj"))?;
    fs::rename(
        root.path.join("data/journal.saved"),
        root.path.join("data/journal.hbj"),
    )?;
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/committed",
            &token,
            json!({})
        )
        .body["data"]["data"]["value"],
        "acknowledged-secret"
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/uncertain",
            &token,
            json!({})
        )
        .status,
        404
    );
    Ok(())
}

#[test]
fn failed_engine_and_auth_transactions_leave_only_the_durable_token_consumption()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/app",
            &token,
            json!({"data":{"value":"first"}})
        )
        .status,
        200
    );
    let finite = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/app" { capabilities = ["read", "update"] }"#,
    )?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/app",
            &finite,
            json!({"data":{"value":"bad-change"},"options":{"cas":99}})
        )
        .status,
        400
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &finite, json!({})).status,
        403
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &token, json!({})).body["data"]["data"]["value"],
        "first"
    );
    let state_before = serde_json::to_vec(service.state.as_ref().ok_or("missing state")?)?;
    let response = call(
        &mut service,
        "PUT",
        "auth/userpass/users/broken",
        &token,
        json!({"password":"synthetic-password","token_ttl":"not-a-duration"}),
    );
    assert_eq!(response.status, 400);
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("missing state")?)?,
        state_before
    );
    Ok(())
}

#[test]
fn all_failed_routes_are_audited_and_authenticated_audit_rejects_tampering()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    for (method, path, token, body, status) in [
        ("GET", "../invalid", "", json!({}), 400),
        ("GET", "secret/data/app", "invalid-token", json!({}), 403),
        ("PUT", "sys/init", "", json!({}), 400),
    ] {
        let sequence = service.audit_sequence;
        assert_eq!(call(&mut service, method, path, token, body).status, status);
        assert_eq!(service.audit_sequence, sequence + 2);
    }
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &token, json!({})).status,
        204
    );
    let sequence = service.audit_sequence;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":"wrong"})
        )
        .status,
        400
    );
    assert_eq!(service.audit_sequence, sequence + 2);
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert!(root.service().is_err()); // A second audit writer is fenced.
    drop(service);
    let path = root.path.join("audit.jsonl");
    let mut bytes = fs::read(&path)?;
    let index = bytes
        .windows(7)
        .position(|b| b == b"request")
        .ok_or("missing audit request")?;
    bytes[index] = b'X';
    fs::write(path, bytes)?;
    assert!(root.service().is_err());
    Ok(())
}

#[test]
fn result_audit_failure_withholds_plaintext_and_preserves_consumed_token_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/app",
            &token,
            json!({"data":{"value":"withhold-this-plaintext"}})
        )
        .status,
        200
    );
    let finite = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/app" { capabilities = ["read"] }"#,
    )?;
    // Reserve exactly the encoded next request audit record, leaving no room for
    // the result record. Admission and token consumption succeed before failure.
    let fingerprint = service.request_fingerprint("GET", "secret/data/app", "", &finite);
    let event = AuditUnsigned {
        schema: 2,
        sequence: service.audit_sequence + 1,
        previous: STANDARD.encode(service.audit_previous),
        time: 100,
        kind: "request".into(),
        path_digest: fingerprint,
        status: None,
    };
    let payload = serde_json::to_vec(&event)?;
    let mac = STANDARD.encode(hmac::sign(&service.audit_key, &payload).as_ref());
    let next = serde_json::to_vec(&AuditRecord { event, mac })?.len() + 1;
    service.audit_capacity = service.audit.metadata()?.len() + next as u64;
    let result = call(&mut service, "GET", "secret/data/app", &finite, json!({}));
    assert_eq!(result.status, 503);
    assert!(!result.body.to_string().contains("withhold-this-plaintext"));
    assert!(service.recovery_required);
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &finite, json!({})).status,
        403
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &token, json!({})).body["data"]["data"]["value"],
        "withhold-this-plaintext"
    );
    Ok(())
}

#[test]
fn wire_rejections_are_audited_without_request_material() -> Result<(), Box<dyn std::error::Error>>
{
    let root = Root::new();
    let mut service = root.service()?;
    let before = service.audit_sequence;
    let response = service.handle_wire_rejection(
        &[7; 16],
        WireRejection::ParseRejected,
        400,
        "invalid wire request",
    );
    assert_eq!(response.status, 400);
    assert_eq!(service.audit_sequence, before + 2);
    drop(service);
    let audit = fs::read(root.path.join("audit.jsonl"))?;
    for forbidden in [
        "secret/data/private",
        "bearer-secret",
        "request-body-secret",
    ] {
        assert!(
            !audit
                .windows(forbidden.len())
                .any(|bytes| bytes == forbidden.as_bytes())
        );
    }
    let _ = root.service()?;
    Ok(())
}

#[test]
fn initialization_response_audit_failure_publishes_no_state_and_is_retryable()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let body = json!({"secret_shares":3,"secret_threshold":2,"recovery_nonce":STANDARD.encode([73_u8;32])});
    let fingerprint = service.request_fingerprint("PUT", "sys/init", "", "");
    let event = AuditUnsigned {
        schema: 2,
        sequence: service.audit_sequence + 1,
        previous: STANDARD.encode(service.audit_previous),
        time: 100,
        kind: "request".into(),
        path_digest: fingerprint,
        status: None,
    };
    let payload = serde_json::to_vec(&event)?;
    let mac = STANDARD.encode(hmac::sign(&service.audit_key, &payload).as_ref());
    let next = serde_json::to_vec(&AuditRecord { event, mac })?.len() + 1;
    service.audit_capacity = service.audit.metadata()?.len() + next as u64;
    let response = call(&mut service, "PUT", "sys/init", "", body.clone());
    assert_eq!(response.status, 503);
    assert!(!service.initialized());
    assert!(service.seal.is_none());
    assert!(!root.path.join("data").exists());
    assert!(
        fs::read_dir(&root.path)?
            .filter_map(Result::ok)
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".heptabao-init-"))
    );
    drop(service);

    let mut service = root.service()?;
    let response = call(&mut service, "PUT", "sys/init", "", body);
    assert_eq!(response.status, 200);
    let key = response.body["keys_base64"][0]
        .as_str()
        .ok_or("missing retry key")?
        .to_owned();
    assert!(response.body["root_token"].as_str().is_some());
    assert!(service.initialized());
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    Ok(())
}

#[test]
fn root_maintenance_routes_compact_snapshot_restore_and_reconcile()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/maintenance",
            &token,
            json!({"data":{"value":"before-snapshot"}}),
        )
        .status,
        200
    );
    let snapshot_response = call(
        &mut service,
        "GET",
        "sys/storage/raft/snapshot",
        &token,
        json!({}),
    );
    assert_eq!(snapshot_response.status, 200);
    let snapshot = snapshot_response.body["data"]["snapshot"]
        .as_str()
        .ok_or("missing encrypted snapshot")?
        .to_owned();
    assert_eq!(
        snapshot_response.body["data"]["format"],
        "heptabao-encrypted-backup-v1"
    );

    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/maintenance",
            &token,
            json!({"data":{"value":"after-snapshot"}}),
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/storage/raft/snapshot",
            &token,
            json!({"snapshot":snapshot.clone()}),
        )
        .status,
        400
    );
    let restored = call(
        &mut service,
        "POST",
        "sys/storage/raft/snapshot-force",
        &token,
        json!({"snapshot":snapshot}),
    );
    assert_eq!(restored.status, 200);
    assert_eq!(restored.body["data"]["rollback"], true);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/maintenance",
            &token,
            json!({}),
        )
        .body["data"]["data"]["value"],
        "before-snapshot"
    );

    for number in 0..8 {
        assert_eq!(
            call(
                &mut service,
                "PUT",
                &format!("secret/data/compact-{number}"),
                &token,
                json!({"data":{"number":number}}),
            )
            .status,
            200
        );
    }
    let compacted = call(
        &mut service,
        "POST",
        "sys/storage/raft/compact",
        &token,
        json!({}),
    );
    assert_eq!(compacted.status, 200);
    assert!(
        compacted.body["data"]["journal_bytes_after"]
            .as_u64()
            .ok_or("missing compacted journal size")?
            < compacted.body["data"]["journal_bytes_before"]
                .as_u64()
                .ok_or("missing original journal size")?
    );

    let recovery_reference = match service
        .durable
        .as_mut()
        .ok_or("missing durable service")?
        .put(PutRequest::new(
            "maintenance-test",
            "system",
            "recovery-lookup",
            "maintenance-probe",
            crypto::digest(b"maintenance-probe"),
            Secret::new(b"probe".to_vec())?,
        )?)? {
        heptabao_durable_service::MutationOutcome::Committed {
            recovery_reference, ..
        } => recovery_reference,
        _ => return Err("unexpected duplicate maintenance probe".into()),
    };
    let lookup = call(
        &mut service,
        "GET",
        &format!("sys/internal/recovery/{recovery_reference}"),
        &token,
        json!({}),
    );
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["status"], "committed");
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/internal/recovery/00000000000000000000000000000000",
            &token,
            json!({}),
        )
        .status,
        404
    );

    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &token, json!({})).status,
        204
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/maintenance",
            &token,
            json!({}),
        )
        .body["data"]["data"]["value"],
        "before-snapshot"
    );
    Ok(())
}

#[test]
fn snapshot_restore_rejects_incoming_openldap_mount_after_local_unmount()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/ldap-old",
            &token,
            json!({"type":"ldap"}),
        )
        .status,
        204
    );
    let snapshot = call(
        &mut service,
        "GET",
        "sys/storage/raft/snapshot",
        &token,
        json!({}),
    )
    .body["data"]["snapshot"]
        .as_str()
        .ok_or("missing encrypted snapshot")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/ldap-old",
            &token,
            json!({}),
        )
        .status,
        204
    );
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("missing current state")?
            .engines
            .has_openldap_mount()
    );
    let restored = call(
        &mut service,
        "POST",
        "sys/storage/raft/snapshot-force",
        &token,
        json!({"snapshot":snapshot}),
    );
    assert_eq!(restored.status, 409);
    assert!(
        restored.body["errors"]
            .as_array()
            .is_some_and(|errors| errors.iter().any(|error| {
                error
                    .as_str()
                    .is_some_and(|message| message.contains("external provider identities"))
            }))
    );
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("missing current state after rejection")?
            .engines
            .has_openldap_mount()
    );
    Ok(())
}

#[test]
fn legacy_unkeyed_audit_and_partial_audit_tail_are_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    private_directory(&root.path)?;
    let audit = root.path.join("audit.jsonl");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&audit)?;
    file.write_all(b"{\"schema\":1}\n")?;
    drop(file);
    assert!(root.service().is_err());
    fs::remove_file(&audit)?;
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "GET", "sys/init", "", json!({})).status,
        200
    );
    drop(service);
    let length = fs::metadata(&audit)?.len();
    OpenOptions::new()
        .write(true)
        .open(&audit)?
        .set_len(length - 2)?;
    assert!(root.service().is_err());
    Ok(())
}

#[test]
fn sys_audit_exposes_and_binds_mandatory_file_device() -> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_key, token) = bootstrap(&mut service)?;

    let list = call(&mut service, "GET", "sys/audit", &token, json!({}));
    assert_eq!(list.status, 200);
    assert_eq!(list.body["data"]["file/"]["type"], "file");
    let configured_path = list.body["data"]["file/"]["options"]["file_path"]
        .as_str()
        .ok_or("missing configured audit path")?;

    // The standard declarative route does not expose HeptaBao's extension.
    assert_eq!(
        call(&mut service, "GET", "sys/audit/file", &token, json!({})).status,
        405
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/audit/file",
            &token,
            json!({"type":"file","options":{"file_path":configured_path}})
        )
        .status,
        400
    );
    assert_eq!(
        call(&mut service, "DELETE", "sys/audit/file", &token, json!({})).status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/internal/audit/file",
            "invalid",
            json!({})
        )
        .status,
        403
    );

    let read = call(
        &mut service,
        "GET",
        "sys/internal/audit/file",
        &token,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["options"]["file_path"], configured_path);

    let enable = call(
        &mut service,
        "PUT",
        "sys/internal/audit/file",
        &token,
        json!({"type":"file","options":{"file_path":configured_path}}),
    );
    assert_eq!(enable.status, 204);

    let wrong_path = call(
        &mut service,
        "PUT",
        "sys/internal/audit/file",
        &token,
        json!({"type":"file","options":{"file_path":"/tmp/other-audit.jsonl"}}),
    );
    assert_eq!(wrong_path.status, 409);
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/internal/audit/file",
            &token,
            json!({})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/internal/audit/file",
            &token,
            json!({"type":"http"}),
        )
        .status,
        501
    );
    Ok(())
}

#[test]
fn request_effect_classification_persists_side_effecting_reads_and_skips_pure_reads()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        classify_request_effect("GET", crypto::digest(b"same"), crypto::digest(b"same")),
        RequestEffectClass::PureRead
    );
    assert_eq!(
        classify_request_effect("GET", crypto::digest(b"before"), crypto::digest(b"after")),
        RequestEffectClass::SideEffectingRead
    );
    assert_eq!(
        classify_request_effect("PUT", crypto::digest(b"before"), crypto::digest(b"after")),
        RequestEffectClass::DurableMutation
    );

    let root = Root::new();
    let mut service = root.service()?;
    let (key, root_token) = bootstrap(&mut service)?;

    let generation = service
        .durable
        .as_ref()
        .ok_or("missing durable service")?
        .generation();
    let pure = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &root_token,
        json!({}),
    );
    assert_eq!(pure.status, 200);
    assert_eq!(
        service
            .durable
            .as_ref()
            .ok_or("missing durable service")?
            .generation(),
        generation,
        "pure authenticated read allocated durable state"
    );

    let finite = limited_token(
        &mut service,
        &root_token,
        r#"path "auth/token/lookup-self" { capabilities = ["read"] }"#,
    )?;
    let generation = service
        .durable
        .as_ref()
        .ok_or("missing durable service")?
        .generation();
    let side_effecting = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &finite,
        json!({}),
    );
    assert_eq!(side_effecting.status, 200);
    assert!(
        service
            .durable
            .as_ref()
            .ok_or("missing durable service")?
            .generation()
            > generation,
        "finite-use read did not durably publish consumption"
    );

    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &finite,
            json!({}),
        )
        .status,
        403,
        "side-effecting read resurrected consumed authority after reopen"
    );
    Ok(())
}

#[test]
fn system_backend_health_seal_and_error_precedence_are_executable()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;

    let health = call(&mut service, "GET", "sys/health", "", json!({}));
    assert_eq!(health.status, 501);
    assert_eq!(health.body["initialized"], false);
    assert_eq!(health.body["sealed"], true);
    assert_eq!(
        call(&mut service, "GET", "sys/init", "", json!({})).body,
        json!({"initialized":false})
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/init",
            "",
            json!({"secret_shares":1,"secret_threshold":1,"unknown":true}),
        )
        .status,
        400
    );
    assert!(!service.initialized());

    let initialized = call(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({"secret_shares":2,"secret_threshold":2}),
    );
    assert_eq!(initialized.status, 200);
    let shares = initialized.body["keys_base64"]
        .as_array()
        .ok_or("missing initialization shares")?
        .iter()
        .map(|value| value.as_str().ok_or("invalid share").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let root_token = initialized.body["root_token"]
        .as_str()
        .ok_or("missing root token")?
        .to_owned();
    assert_eq!(
        call(&mut service, "GET", "sys/health", "", json!({})).status,
        503
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/blocked",
            &root_token,
            json!({})
        )
        .status,
        503,
        "sealed state must win before active authenticated dispatch"
    );
    for share in &shares {
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":share}),).status,
            200
        );
    }
    assert_eq!(
        call(&mut service, "GET", "sys/health", "", json!({})).status,
        200
    );
    assert_eq!(
        call(&mut service, "POST", "sys/seal", "", json!({})).status,
        403,
        "root authorization must precede seal mutation"
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/rekey/update",
            &root_token,
            json!({"nonce":"missing","key":"bad"}),
        )
        .status,
        400
    );
    assert_eq!(service.seal.as_ref().ok_or("missing seal")?.generation, 1);
    assert_eq!(
        call(&mut service, "POST", "sys/seal", &root_token, json!({})).status,
        204
    );
    assert_eq!(
        call(&mut service, "HEAD", "sys/health", "", json!({})).status,
        503
    );
    Ok(())
}

#[test]
fn mount_registry_remount_cas_and_restart_fence_stale_incarnations()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/team",
            &token,
            json!({"type":"kv","options":{"version":"2"},"cas_revision":0})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "team/data/app",
            &token,
            json!({"data":{"value":"persisted"}})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/remount",
            &token,
            json!({"from":"team/","to":"archive/","cas_revision":1})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "team/data/app", &token, json!({})).status,
        404
    );
    assert_eq!(
        call(&mut service, "GET", "archive/data/app", &token, json!({})).body["data"]["data"]["value"],
        "persisted"
    );
    let audit = call(
        &mut service,
        "GET",
        "sys/internal/audit/file",
        &token,
        json!({}),
    );
    assert_eq!(audit.body["data"]["revision"], 1);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/internal/audit/file",
            &token,
            json!({"type":"file","cas_revision":2})
        )
        .status,
        409
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/internal/audit/file",
            &token,
            json!({"type":"file","cas_revision":1})
        )
        .status,
        204
    );
    drop(service);

    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let descriptor = call(&mut service, "GET", "sys/mounts/archive", &token, json!({}));
    assert_eq!(descriptor.body["data"]["revision"], 2);
    assert_eq!(descriptor.body["data"]["incarnation"], 1);
    assert_eq!(
        call(&mut service, "GET", "archive/data/app", &token, json!({})).body["data"]["data"]["value"],
        "persisted"
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/mounts/archive/tune",
            &token,
            json!({"description":"stale","cas_revision":1})
        )
        .status,
        409
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/archive",
            &token,
            json!({"cas_revision":2})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/archive",
            &token,
            json!({"type":"kv","options":{"version":"2"},"cas_revision":0})
        )
        .status,
        204
    );
    let recreated = call(&mut service, "GET", "sys/mounts/archive", &token, json!({}));
    assert_eq!(recreated.body["data"]["revision"], 1);
    assert_eq!(recreated.body["data"]["incarnation"], 2);
    assert_eq!(
        call(&mut service, "GET", "archive/data/app", &token, json!({})).status,
        404
    );

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/team",
            &token,
            json!({"type":"userpass","cas_revision":0})
        )
        .status,
        204
    );
    let auth_before = call(&mut service, "GET", "sys/auth/team", &token, json!({}));
    let auth_accessor = auth_before.body["data"]["accessor"]
        .as_str()
        .ok_or("missing auth accessor")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "auth/team/users/alice",
            &token,
            json!({"password":"correct horse battery staple"})
        )
        .status,
        204
    );
    let issued = call(
        &mut service,
        "POST",
        "auth/team/login/alice",
        "",
        json!({"password":"correct horse battery staple"}),
    );
    let issued_token = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing auth token")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/remount",
            &token,
            json!({"from":"auth/team/","to":"auth/moved/","cas_revision":1})
        )
        .status,
        200
    );
    let auth_after = call(&mut service, "GET", "sys/auth/moved", &token, json!({}));
    assert_eq!(auth_after.body["data"]["revision"], 2);
    assert_eq!(auth_after.body["data"]["accessor"], auth_accessor);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/team/login/alice",
            "",
            json!({"password":"correct horse battery staple"})
        )
        .status,
        404
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/moved/login/alice",
            "",
            json!({"password":"correct horse battery staple"})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &issued_token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/auth/moved",
            &token,
            json!({"cas_revision":2})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &issued_token,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/moved",
            &token,
            json!({"type":"userpass","cas_revision":0})
        )
        .status,
        204
    );
    let auth_recreated = call(&mut service, "GET", "sys/auth/moved", &token, json!({}));
    assert_eq!(auth_recreated.body["data"]["revision"], 1);
    assert_ne!(auth_recreated.body["data"]["accessor"], auth_accessor);
    Ok(())
}

#[test]
fn public_approle_login_ignores_unrelated_bearer_without_bypassing_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/team/role",
            &token,
            json!({"type":"approle"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/team/role/tune",
            &token,
            json!({"default_lease_ttl":120,"max_lease_ttl":300})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/team/role/role/reader",
            &token,
            json!({"token_policies":["default"],"secret_id_num_uses":0})
        )
        .status,
        204
    );
    let role = call(
        &mut service,
        "GET",
        "auth/team/role/role/reader/role-id",
        &token,
        json!({}),
    );
    let secret = call(
        &mut service,
        "POST",
        "auth/team/role/role/reader/secret-id",
        &token,
        json!({}),
    );
    let credentials = json!({"role_id":role.body["data"]["role_id"],
        "secret_id":secret.body["data"]["secret_id"]});
    let login = call(
        &mut service,
        "POST",
        "auth/team/role/login",
        "expired-source-token",
        credentials.clone(),
    );
    assert_eq!(login.status, 200);
    assert_eq!(login.body["auth"]["lease_duration"], 120);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/team/role/login",
            &token,
            json!({"role_id":role.body["data"]["role_id"],"secret_id":"incorrect"})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/team/role/role/reader/role-id",
            "expired-source-token",
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/login",
            "expired-source-token",
            credentials.clone()
        )
        .status,
        403
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "auth/team/role/login",
                "other",
                "expired-source-token",
                credentials.clone(),
                100
            )
            .status,
        403
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/team/role/login",
            "expired-source-token",
            credentials
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn public_userpass_login_does_not_spend_a_separate_finite_bearer()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/reader",
            &token,
            json!({"password":"synthetic-password","token_policies":["default"]})
        )
        .status,
        204
    );
    let separate = limited_token(
        &mut service,
        &token,
        "path \"secret/*\" { capabilities = [\"read\"] }",
    )?;
    let data = json!({"password":"synthetic-password"});
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/login/reader",
            "invalid-old-token",
            data.clone()
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/login/reader",
            &separate,
            data
        )
        .status,
        200
    );
    let observed = call(
        &mut service,
        "POST",
        "auth/token/lookup",
        &token,
        json!({"token":separate}),
    );
    assert_eq!(observed.status, 200);
    assert_eq!(observed.body["data"]["num_uses"], 1);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/login/reader",
            &token,
            json!({"password":"incorrect"})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/userpass/users/reader",
            "invalid-old-token",
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/login",
            "invalid-old-token",
            json!({})
        )
        .status,
        403
    );
    Ok(())
}

#[test]
fn http_request_deadline_scope_restores_and_expired_request_cannot_initialize()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let previous = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let previous_scope = crate::request_deadline::RequestDeadlineScope::enter(previous);
    for forwarded in [false, true] {
        let response = service.begin_request_before(
            ServiceRequest::new("GET", "sys/health", "", "", Value::Null),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            forwarded,
        );
        assert!(matches!(response, RequestExecution::Complete(_)));
        assert_eq!(crate::request_deadline::current(), Some(previous));
        let response = service.begin_request_before(
            ServiceRequest::new(
                "POST",
                "sys/init",
                "",
                "",
                json!({"secret_shares":1,"secret_threshold":1}),
            ),
            std::time::Instant::now(),
            forwarded,
        );
        assert!(matches!(
            response,
            RequestExecution::Complete(Response { status: 503, .. })
        ));
        assert_eq!(crate::request_deadline::current(), Some(previous));
        assert!(service.seal.is_none());
        assert!(service.state.is_none());
    }
    drop(previous_scope);
    let _ = service.begin_request_before(
        ServiceRequest::new("GET", "sys/health", "", "", Value::Null),
        std::time::Instant::now() + std::time::Duration::from_secs(1),
        false,
    );
    assert!(crate::request_deadline::current().is_none());
    Ok(())
}

#[test]
fn original_http_deadline_bounds_a_contended_ha_lock_without_poisoning_next_request()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let process = crate::ha::request_deadline_tests::process(&root.path.join("raft"))?;
    let ha = Arc::new(Mutex::new(process));
    service.ha = Some(Arc::clone(&ha));
    let digest_before = service.state_digest;
    let held = ha.lock().map_err(|_| "test HA poisoned")?;
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let execution = service.begin_request_before(
            ServiceRequest::new("GET", "secret/data/missing", "", &token, Value::Null),
            std::time::Instant::now() + Duration::from_millis(60),
            false,
        );
        let status = match execution {
            RequestExecution::Complete(response) => response.status,
            RequestExecution::External(_) => 0,
        };
        let cleared = crate::request_deadline::current().is_none();
        let _ = send.send(status);
        (service, cleared)
    });
    // The production Service dispatch must finish while the HA lock is still
    // held. Release it even on failure, so this regression cannot hang Cargo.
    let status = receive.recv_timeout(Duration::from_secs(2));
    drop(held);
    let (mut service, cleared) = worker.join().map_err(|_| "request thread panicked")?;
    assert_eq!(status?, 503);
    assert!(cleared);
    assert_eq!(service.state_digest, digest_before);
    ha.lock_for_request()
        .map_err(|_| "HA did not recover")?
        .ensure_linearizable()?;
    service.ha = None;
    assert!(matches!(
        service.begin_request_before(
            ServiceRequest::new("GET", "sys/health", "", "", Value::Null),
            std::time::Instant::now() + Duration::from_secs(1),
            false,
        ),
        RequestExecution::Complete(Response { status: 200, .. })
    ));
    assert!(crate::request_deadline::current().is_none());
    Ok(())
}
