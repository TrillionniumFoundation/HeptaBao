use super::*;
use crate::auth::{AuthorityTime, Timestamp};
use crate::engines::sdk::{Descriptor, StorageEntry};
use crate::engines::sdk_lease::{Binding as LeaseBinding, Grant, Lease, Phase};
use crate::engines::sdk_registration::Registration;
use crate::service::tests::{Root, bootstrap_unmounted, call};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NS: &str = "retire";
fn native(service: &mut Service, method: &str, path: &str, token: &str) -> Response {
    let execution = service.begin_request_before(
        ServiceRequest {
            method,
            path,
            namespace: "",
            token,
            body: json!({}),
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now() + Duration::from_secs(15),
        false,
    );
    service.finish_synchronous_request(execution)
}
fn clock() -> TestResult<RequestClock> {
    Ok(RequestClock::anchored(
        SystemTime::now().duration_since(UNIX_EPOCH)?,
        Instant::now(),
    )?)
}
fn publish(service: &mut Service, mut state: State) -> TestResult {
    state.schema = state.writer_schema();
    service
        .commit_state(&mut state)
        .map_err(|_| "actual record publication rejected")?;
    service.state = Some(state);
    Ok(())
}
struct Fixture {
    directory: Root,
    service: Service,
    key: String,
    token: String,
    logical: Lease,
    credential: crate::auth::sdk_credential::Record,
}
fn fixture() -> TestResult<Fixture> {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, token) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        native(&mut service, "POST", "sys/namespaces/retire", &token).status,
        200
    );
    let mut state = service.state.clone().ok_or("state")?;
    state
        .ensure_namespace_batch_registry()
        .map_err(|_| "actual namespace lifecycle")?;
    let descriptor = state.engines.register_sdk_descriptor(Descriptor {
        name: "logical_probe".into(),
        version: "v1.0.0".into(),
        command: "probe".into(),
        args: vec![],
        sha256: "a".repeat(64),
        generation: 1,
    })?;
    state.engines.handle(
        NS,
        "POST",
        "sys/mounts/logical",
        &json!({
            "type":"plugin","config":{"plugin_id":"logical_probe"}
        }),
        100,
    )?;
    let logical_backend = state.engines.bind_sdk_mount(NS, "logical/", &descriptor)?;
    // The fixture uses typed model admission rather than launching a plugin.
    // Follow the real Service SDK mount publication prerequisite before Storage.
    service
        .prepare_sdk_mount_record_root(&mut state)
        .map_err(|_| "actual SDK mount record-root preparation")?;
    publish(&mut service, state)?;
    assert!(service.record_root.is_some());
    let mut state = service.state.clone().ok_or("published SDK mount")?;
    assert!(state.engines.record_root().is_some());
    let at = clock()?.observed_at()?;
    let actor = state
        .auth
        .authenticate_from_observed(&token, AuthorityTime::Precise(at), None)?;
    let entry = state
        .auth
        .admitted_standard_sdk_lease_issuer_observed(&actor, NS, AuthorityTime::Precise(at))?
        .ok_or("actual accepted issuer")?;
    let grant = || Grant {
        issued: at,
        ttl_ns: 30_000_000_000,
        max_ttl_ns: 60_000_000_000,
        renewable: true,
        secret: json!({"LeaseID":"","lease":30_000_000_000u64,"max_ttl":60_000_000_000u64,
          "renewable":true,"internal_data":{"secret_type":"owned","storage_key":"record"}}),
        data: json!({"value":"finite-namespace-sdk-secret"}),
    };
    let registration = Registration::from_entry(
        &entry,
        at,
        at,
        false,
        &state.auth,
        NS,
        state.namespaces.incarnation(NS),
    )?;
    let mut logical = Lease::new(
        LeaseBinding {
            id: "logical/record/selected".into(),
            namespace: NS.into(),
            cluster: state.cluster_id.clone(),
            mount: "logical/".into(),
            path: "logical/record".into(),
            backend: logical_backend.clone(),
            issuer: entry.issuer.owner.clone(),
        },
        grant(),
    )?;
    logical.register(registration.clone())?;
    state.engines.observe_sdk_lease_clock(at);
    state.engines.store_sdk_lease(logical.clone())?;
    state.engines.sdk_storage_put(
        NS,
        "logical/",
        &logical_backend,
        StorageEntry {
            key: "record".into(),
            value: Zeroizing::new(b"finite-logical-owned".to_vec()),
            seal_wrap: true,
        },
    )?;
    assert_eq!(
        state
            .auth
            .handle(
                Some(&actor),
                NS,
                "POST",
                "sys/auth/credential",
                &json!({"type":"plugin"}),
                at.seconds()
            )?
            .ok_or("actual auth mount")?
            .status,
        204
    );
    let auth_descriptor = state.auth.register_sdk_auth_descriptor(Descriptor {
        name: "credential_probe".into(),
        version: "v1.0.0".into(),
        command: "probe".into(),
        args: vec![],
        sha256: "b".repeat(64),
        generation: 1,
    })?;
    let credential_backend = state
        .auth
        .bind_sdk_auth_mount(NS, "credential", &auth_descriptor)?;
    let mut credential = Lease::new(
        LeaseBinding {
            id: "auth/credential/record/selected".into(),
            namespace: NS.into(),
            cluster: state.cluster_id.clone(),
            mount: "auth/credential/".into(),
            path: "auth/credential/record".into(),
            backend: credential_backend.clone(),
            issuer: entry.issuer.owner.clone(),
        },
        grant(),
    )?;
    credential.register(registration)?;
    state.auth.observe_sdk_auth_clock(at);
    let namespace_owner = state
        .auth
        .namespace_batch_registry()
        .ok_or("namespace registry")?
        .binding(NS)?;
    let credential = crate::auth::sdk_credential::Record::new(credential, Some(namespace_owner));
    state.auth.store_sdk_credential(credential.clone())?;
    state.auth.sdk_auth_storage_put(
        &credential_backend,
        crate::auth::sdk::Entry {
            key: "record".into(),
            value: Zeroizing::new(b"finite-credential-owned".to_vec()),
            seal_wrap: true,
        },
    )?;
    publish(&mut service, state)?;
    Ok(Fixture {
        directory,
        service,
        key,
        token,
        logical,
        credential,
    })
}
fn begin(f: &mut Fixture) -> TestResult {
    let response = native(&mut f.service, "DELETE", "sys/namespaces/retire", &f.token);
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["status"], "in-progress");
    let state = f.service.state.as_ref().ok_or("pending")?;
    assert!(state.namespace_is_tainted(NS));
    assert_eq!(state.schema, NAMESPACE_SDK_CLEANUP_STATE_SCHEMA);
    state.validate_format().map_err(|_| "actual109 format")?;
    Ok(())
}
fn keys(state: &State) -> TestResult<Vec<String>> {
    Ok(state
        .namespaces
        .deletions
        .as_ref()
        .ok_or("ledger")?
        .sdk_cleanup()
        .ok_or("jobs")?
        .records()
        .keys()
        .cloned()
        .collect())
}
fn attempt_all(service: &mut Service) -> TestResult {
    let mut next = service.state.clone().ok_or("state")?;
    for key in keys(&next)? {
        next.attempt_namespace_sdk_cleanup(&key)
            .map_err(|_| "attempt")?;
    }
    publish(service, next)
}

#[test]
fn namespace109_actual_delete_queues_both_families_without_discarding_storage() -> TestResult {
    let mut f = fixture()?;
    begin(&mut f)?;
    let state = f.service.state.as_ref().ok_or("pending")?;
    let jobs = state
        .namespaces
        .deletions
        .as_ref()
        .ok_or("ledger")?
        .sdk_cleanup()
        .ok_or("jobs")?;
    assert_eq!(jobs.records().len(), 2);
    for job in jobs.records().values() {
        assert!(job.stage() == &Stage::Queued);
    }
    assert!(
        state
            .auth
            .namespace_sdk_cleanup_blocks(Kind::Logical, NS, &f.logical.id)
    );
    assert!(
        state
            .auth
            .namespace_sdk_cleanup_blocks(Kind::Credential, NS, &f.credential.id)
    );
    assert!(
        state
            .engines
            .sdk_lease(NS, &f.logical.id)
            .ok_or("logical")?
            .phase
            == Phase::PendingRevoke
    );
    assert!(
        state
            .auth
            .sdk_credential_record(NS, &f.credential.id)
            .ok_or("credential")?
            .phase
            == Phase::PendingRevoke
    );
    assert_eq!(
        state
            .engines
            .sdk_storage_get(NS, "logical/", &f.logical.backend, "record")?
            .ok_or("actual logical storage")?
            .value
            .as_slice(),
        b"finite-logical-owned"
    );
    assert_eq!(
        state
            .auth
            .sdk_auth_storage_get(&f.credential.backend, "record")?
            .ok_or("actual auth storage")?
            .value
            .as_slice(),
        b"finite-credential-owned"
    );
    assert!(
        !state
            .namespace_sdk_deletion_terminal(NS)
            .map_err(|_| "terminal")?
    );
    Ok(())
}

#[test]
fn namespace109_attempted_encrypted_reopen_is_unknown_and_cannot_return_to_queue() -> TestResult {
    let mut f = fixture()?;
    begin(&mut f)?;
    let queued_backup = Zeroizing::new(
        f.service
            .durable
            .as_ref()
            .ok_or("durable")?
            .export_backup()?,
    );
    attempt_all(&mut f.service)?;
    let state = f.service.state.as_ref().ok_or("attempted")?;
    assert!(state.queued_namespace_sdk_cleanup(None).is_none());
    let late = Timestamp::from_wall(
        SystemTime::now().duration_since(UNIX_EPOCH)? + Duration::from_secs(120),
    )?;
    assert!(
        state
            .engines
            .sdk_cleanup_candidate(&state.auth, late, None)?
            .is_none()
    );
    assert!(
        state
            .auth
            .next_sdk_credential_cleanup(late, None)?
            .is_none()
    );
    assert!(f.service.prepare_snapshot_restore(&queued_backup).is_err());
    let Fixture {
        directory,
        service,
        key,
        token: _,
        logical,
        credential,
    } = f;
    drop(service);
    let mut reopened = directory.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let state = reopened.state.as_ref().ok_or("reopened")?;
    assert!(state.queued_namespace_sdk_cleanup(None).is_none());
    for key in keys(state)? {
        assert!(
            state
                .namespace_sdk_cleanup_record(&key)
                .map_err(|_| "job")?
                .stage()
                == &Stage::Attempted
        );
    }
    assert!(
        state
            .auth
            .namespace_sdk_cleanup_blocks(Kind::Logical, NS, &logical.id)
    );
    assert!(
        state
            .auth
            .namespace_sdk_cleanup_blocks(Kind::Credential, NS, &credential.id)
    );
    assert!(
        !state
            .namespace_sdk_deletion_terminal(NS)
            .map_err(|_| "terminal")?
    );
    Ok(())
}

#[test]
fn namespace109_native_authority_keeps_original_nonce_and_deadline_without_actor() -> TestResult {
    let mut f = fixture()?;
    begin(&mut f)?;
    attempt_all(&mut f.service)?;
    let key = keys(f.service.state.as_ref().ok_or("state")?)?.remove(0);
    let original_clock = clock()?;
    let deadline = original_clock.started() + Duration::from_secs(15);
    let authority = Authority::capture(&f.service, key.clone(), original_clock, deadline)
        .map_err(|_| "actual native authority")?;
    authority
        .check(&f.service)
        .map_err(|_| "positive actual owner")?;
    let original = f.service.unseal_nonce.clone();
    f.service.unseal_nonce.push('x');
    assert!(authority.check(&f.service).is_err());
    f.service.unseal_nonce = original;
    authority
        .check(&f.service)
        .map_err(|_| "same owner restored")?;
    assert!(Authority::capture(&f.service, key, original_clock, original_clock.started()).is_err());
    let state = f.service.state.as_ref().ok_or("state")?;
    assert!(state.queued_namespace_sdk_cleanup(None).is_none());
    Ok(())
}

#[test]
fn namespace109_terminal_requires_exact_registered_record_and_same_storage_transaction()
-> TestResult {
    let mut f = fixture()?;
    begin(&mut f)?;
    attempt_all(&mut f.service)?;
    let before = f.service.state.clone().ok_or("state")?;
    let key = keys(&before)?
        .into_iter()
        .find(|key| {
            before
                .namespace_sdk_cleanup_record(key)
                .is_ok_and(|job| job.kind() == Kind::Logical)
        })
        .ok_or("logical key")?;
    let mut lease = before
        .engines
        .sdk_lease(NS, &f.logical.id)
        .ok_or("pending")?;
    lease.revoke();
    let mut wrong = lease.clone();
    wrong.path = "logical/other".into();
    let mut negative = before.clone();
    assert!(negative.finish_namespace_sdk_logical(&key, &wrong).is_err());
    let mut terminal = before.clone();
    terminal
        .engines
        .sdk_storage_delete(NS, "logical/", &lease.backend, "record")?;
    terminal.engines.store_sdk_lease(lease.clone())?;
    terminal
        .finish_namespace_sdk_logical(&key, &lease)
        .map_err(|_| "terminal same selected owner")?;
    publish(&mut f.service, terminal)?;
    let current = f.service.state.as_ref().ok_or("terminal")?;
    assert!(matches!(
        current
            .namespace_sdk_cleanup_record(&key)
            .map_err(|_| "job")?
            .stage(),
        Stage::Terminal { .. }
    ));
    assert!(
        current
            .engines
            .sdk_storage_get(NS, "logical/", &lease.backend, "record")?
            .is_none()
    );
    assert!(
        !current
            .namespace_sdk_deletion_terminal(NS)
            .map_err(|_| "other family still pending")?
    );
    assert!(Service::validate_snapshot_protected_floor(current, &before).is_err());
    Ok(())
}

#[test]
fn namespace109_credential_terminal_retains_global_registered_owner_and_rejects_mismatch()
-> TestResult {
    let mut f = fixture()?;
    begin(&mut f)?;
    attempt_all(&mut f.service)?;
    let mut next = f.service.state.clone().ok_or("state")?;
    let key = keys(&next)?
        .into_iter()
        .find(|key| {
            next.namespace_sdk_cleanup_record(key)
                .is_ok_and(|job| job.kind() == Kind::Credential)
        })
        .ok_or("credential key")?;
    let mut record = next
        .auth
        .sdk_credential_record(NS, &f.credential.id)
        .ok_or("pending")?;
    record.revoke();
    let mut changed = record.clone();
    changed.ttl_ns -= 1;
    assert!(
        next.clone()
            .finish_namespace_sdk_credential(&key, &changed)
            .is_err()
    );
    next.auth
        .sdk_auth_storage_delete(&record.backend, "record")?;
    next.auth.store_sdk_credential(record.clone())?;
    next.finish_namespace_sdk_credential(&key, &record)
        .map_err(|_| "actual credential terminal")?;
    publish(&mut f.service, next)?;
    let state = f.service.state.as_ref().ok_or("terminal")?;
    assert!(
        state
            .auth
            .sdk_credential_record(NS, &record.id)
            .ok_or("retained terminal")?
            .phase
            == Phase::Revoked
    );
    assert!(!state.auth.sdk_credential_namespace_pending(NS));
    assert!(state.auth.has_sdk_credential_state());
    let terminal = state
        .namespace_sdk_cleanup_record(&key)
        .map_err(|_| "job")?;
    terminal.check_credential(&record, true)?;
    let mut damaged = record.clone();
    damaged.ttl_ns -= 1;
    assert!(terminal.check_credential(&damaged, true).is_err());
    Ok(())
}

mod literal_root89 {
    use crate::namespace_custody::Binding;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    include!("service_namespace_sdk_cleanup_old106_fixture.rs");
}
#[test]
fn namespace109_literal_old_strict_ledger_decoder_rejects_new_field_and_empty_is_sticky()
-> TestResult {
    let mut f = fixture()?;
    begin(&mut f)?;
    let state = f.service.state.as_ref().ok_or("state")?;
    let ledger = state.namespaces.deletions.as_ref().ok_or("ledger")?;
    let encoded = Zeroizing::new(
        crate::secret_serde::to_vec(ledger, 512 * 1024).map_err(|_| "actual ledger encoding")?,
    );
    let old = serde_json::from_slice::<literal_root89::Ledger>(&encoded);
    let error = old
        .err()
        .ok_or("literal old strict ledger unexpectedly accepted sdk_cleanup")?;
    assert!(
        error.to_string().contains("unknown field") && error.to_string().contains("sdk_cleanup")
    );
    let mut lower = state.clone();
    lower.schema = 108;
    assert!(lower.validate_format().is_err());
    let mut empty = state.clone();
    let mut value = serde_json::to_value(ledger)?;
    value["sdk_cleanup"]["records"] = json!({});
    let empty_ledger: crate::auth::namespace_deletion::Ledger = serde_json::from_value(value)?;
    assert!(empty_ledger.sdk_cleanup().is_some());
    empty.namespaces.deletions = Some(empty_ledger);
    assert!(
        empty.sync_namespace_deletion_ledger().is_err(),
        "actual unresolved jobs cannot be removed from the Auth mirror"
    );
    assert!(
        Service::validate_snapshot_protected_floor(&empty, state).is_err(),
        "unresolved actual work cannot disappear into an empty registry"
    );
    Ok(())
}

#[test]
fn namespace109_rotation_skips_busy_queue_position_and_excludes_attempted_job() -> TestResult {
    let mut f = fixture()?;
    begin(&mut f)?;
    let mut state = f.service.state.clone().ok_or("state")?;
    let (first, _) = state
        .queued_namespace_sdk_cleanup(None)
        .ok_or("first queued")?;
    let (second, _) = state
        .queued_namespace_sdk_cleanup(Some(&first))
        .ok_or("later queued")?;
    assert_ne!(
        first, second,
        "a busy first selection must not starve the other SDK family"
    );
    assert_eq!(
        state
            .queued_namespace_sdk_cleanup(Some(&second))
            .ok_or("wrap")?
            .0,
        first
    );
    state
        .attempt_namespace_sdk_cleanup(&first)
        .map_err(|_| "real attempt transition")?;
    assert_eq!(
        state
            .queued_namespace_sdk_cleanup(Some(&second))
            .ok_or("only queued")?
            .0,
        second
    );
    state
        .attempt_namespace_sdk_cleanup(&second)
        .map_err(|_| "second attempt")?;
    assert!(state.queued_namespace_sdk_cleanup(None).is_none());
    Ok(())
}

#[test]
fn namespace109_true_terminal_namespace_retirement_preserves_empty_registry_and_old_owner_history()
-> TestResult {
    let mut f = fixture()?;
    let mut state = f.service.state.clone().ok_or("state")?;
    let mut logical = state
        .engines
        .sdk_lease(NS, &f.logical.id)
        .ok_or("logical")?;
    logical.revoke();
    state.engines.store_sdk_lease(logical)?;
    let mut credential = state
        .auth
        .sdk_credential_record(NS, &f.credential.id)
        .ok_or("credential")?;
    credential.revoke();
    state.auth.store_sdk_credential(credential)?;
    publish(&mut f.service, state)?;
    begin(&mut f)?;
    let pending = f.service.state.as_ref().ok_or("state")?;
    assert!(
        pending
            .namespaces
            .deletions
            .as_ref()
            .ok_or("ledger")?
            .sdk_cleanup()
            .ok_or("actual Some empty registry")?
            .records()
            .is_empty()
    );
    let native_clock = clock()?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        native_clock.started() + Duration::from_secs(15),
    );
    assert!(
        f.service
            .maintain_namespace_deletions(native_clock)
            .map_err(|_| "real native terminal")?
    );
    let state = f.service.state.as_ref().ok_or("terminal")?;
    assert!(!state.namespace_exists(NS));
    assert!(!state.namespace_is_tainted(NS));
    assert!(
        state
            .auth
            .sdk_credential_record(NS, &f.credential.id)
            .ok_or("retained original history")?
            .phase
            == Phase::Revoked
    );
    assert!(state.auth.has_namespace_sdk_cleanup_state());
    assert!(
        state
            .namespaces
            .deletions
            .as_ref()
            .ok_or("ledger")?
            .sdk_cleanup()
            .ok_or("sticky Some empty")?
            .records()
            .is_empty()
    );
    assert_eq!(state.schema, NAMESPACE_SDK_CLEANUP_STATE_SCHEMA);
    let mut lower = state.clone();
    lower.schema = 108;
    assert!(lower.validate_format().is_err());
    Ok(())
}

#[test]
fn namespace109_original_attempted_authority_rejects_real_handoff_before_setup() -> TestResult {
    let mut f = fixture()?;
    let cluster_id = f.service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = crate::ha::snapshot_test_support::Cluster::new(
        &f.directory.path.join("raft"),
        &cluster_id,
    )?;
    f.service.ha = Some(Arc::clone(&cluster.processes[0]));
    f.service
        .sync_from_ha()
        .map_err(|_| "real initial HA publication")?;
    begin(&mut f)?;
    attempt_all(&mut f.service)?;
    let state = f.service.state.as_ref().ok_or("state")?;
    let key = keys(state)?
        .into_iter()
        .find(|key| {
            state
                .namespace_sdk_cleanup_record(key)
                .is_ok_and(|record| record.kind() == Kind::Credential)
        })
        .ok_or("actual credential job")?;
    let original = clock()?;
    let deadline = original.started() + Duration::from_secs(15);
    let authority = Authority::capture(&f.service, key.clone(), original, deadline)
        .map_err(|_| "actual current leader authority")?;
    authority
        .sync_before_setup(&mut f.service)
        .map_err(|_| "actual current prefix before handoff")?;
    let identity = f.service.current_state_identity().map_err(|_| "identity")?;
    let generation = f.service.durable.as_ref().ok_or("durable")?.generation();
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let successor = cluster.processes[0]
        .lock()
        .map_err(|_| "HA mutex")?
        .step_down()?;
    assert_ne!(successor, 1);
    assert_eq!(
        cluster.processes[0]
            .lock()
            .map_err(|_| "HA mutex")?
            .leader()?,
        Some(successor)
    );
    assert!(authority.check(&f.service).is_err());
    assert!(authority.sync_before_setup(&mut f.service).is_err());
    assert!(f.service.pending_sdk_auth_request.is_none());
    assert_eq!(
        f.service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    assert_eq!(
        f.service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert!(!f.service.recovery_required);
    assert!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .namespace_sdk_cleanup_record(&key)
            .map_err(|_| "saved attempted job")?
            .stage()
            == &Stage::Attempted
    );
    Ok(())
}
