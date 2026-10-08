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
    fixture_with_owner(false).map(|(fixture, _)| fixture)
}
fn fixture_with_owner(independent: bool) -> TestResult<(Fixture, Option<Zeroizing<Vec<u8>>>)> {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, token) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        native(&mut service, "POST", "sys/namespaces/retire", &token).status,
        200
    );
    let namespace_share = if independent {
        Some(install_test_independent_owner(&mut service, NS)?)
    } else {
        None
    };
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
    Ok((
        Fixture {
            directory,
            service,
            key,
            token,
            logical,
            credential,
        },
        namespace_share,
    ))
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
    next.namespace_sdk_cleanup_record(&key)
        .map_err(|_| "actual attempted credential wire")?
        .check_unboxed_credential_wire()?;
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
    terminal.check_unboxed_credential_wire()?;
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

fn terminal_fixture() -> TestResult<Fixture> {
    let mut f = fixture()?;
    begin(&mut f)?;
    attempt_all(&mut f.service)?;
    let mut next = f.service.state.clone().ok_or("pending")?;
    for key in keys(&next)? {
        let job = next.namespace_sdk_cleanup_record(&key).map_err(|_| "job")?;
        match job.kind() {
            Kind::Logical => {
                let mut lease = next
                    .engines
                    .sdk_lease(NS, job.lease_id())
                    .ok_or("logical")?;
                next.engines
                    .sdk_storage_delete(NS, &lease.mount, &lease.backend, "record")?;
                lease.revoke();
                next.engines.store_sdk_lease(lease.clone())?;
                next.finish_namespace_sdk_logical(&key, &lease)
                    .map_err(|_| "logical terminal")?;
            }
            Kind::Credential => {
                let mut lease = next
                    .auth
                    .sdk_credential_record(NS, job.lease_id())
                    .ok_or("credential")?;
                next.auth
                    .sdk_auth_storage_delete(&lease.backend, "record")?;
                lease.revoke();
                next.auth.store_sdk_credential(lease.clone())?;
                next.finish_namespace_sdk_credential(&key, &lease)
                    .map_err(|_| "credential terminal")?;
            }
        }
    }
    publish(&mut f.service, next)?;
    let original = clock()?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        original.started() + Duration::from_secs(15),
    );
    assert!(
        f.service
            .maintain_namespace_deletions(original)
            .map_err(|error| {
                format!(
                    "actual namespace terminal status={} first_error={}",
                    error.status,
                    error
                        .body
                        .get("errors")
                        .and_then(Value::as_array)
                        .and_then(|errors| errors.first())
                        .and_then(Value::as_str)
                        .unwrap_or("non-string-error")
                )
            })?
    );
    Ok(f)
}
fn replace_both_ledgers(state: &mut State, value: Value) -> TestResult {
    let ledger = serde_json::from_value::<crate::auth::namespace_deletion::Ledger>(value)?;
    state
        .auth
        .namespace_deletion_fixture_replace(ledger.clone());
    state.namespaces.deletions = Some(ledger);
    Ok(())
}
#[test]
fn namespace109_both_mirror_orphan_jobs_and_forged_empty_selection_reject_materialized_resources()
-> TestResult {
    let mut f = fixture()?;
    begin(&mut f)?;
    let original = f.service.state.as_ref().ok_or("pending")?;
    assert!(original.validate_format().is_ok());
    let mut ledger = serde_json::to_value(original.namespaces.deletions.as_ref().ok_or("ledger")?)?;
    ledger["sdk_cleanup"]["records"] = json!({});
    let mut orphan = original.clone();
    replace_both_ledgers(&mut orphan, ledger.clone())?;
    assert!(orphan.validate_format().is_err());
    assert!(Service::validate_snapshot_protected_floor(original, &orphan).is_err());
    assert!(Service::validate_snapshot_protected_floor(&orphan, original).is_err());
    ledger["sdk_cleanup"]["source_selections"][NS]["members"] = json!({});
    let mut forged_source = original.clone();
    replace_both_ledgers(&mut forged_source, ledger)?;
    assert!(
        forged_source.validate_format().is_err(),
        "actual Pending resources need exact jobs even with forged mirror agreement"
    );
    assert!(Service::validate_snapshot_protected_floor(original, &forged_source).is_err());
    assert!(original.validate_format().is_ok());
    Ok(())
}
#[test]
fn namespace109_retired_logical_full_registration_is_not_a_live_lease_or_callback_owner()
-> TestResult {
    let mut f = terminal_fixture()?;
    let state = f.service.state.as_ref().ok_or("terminal")?;
    assert!(state.validate_format().is_ok());
    let history = state
        .engines
        .sdk_logical_history_records()
        .next()
        .ok_or("actual history")?;
    assert!(history.phase == Phase::Revoked);
    assert!(history.registration == f.logical.registration);
    assert!(history.issuer == f.logical.issuer);
    assert_eq!(history.issued, f.logical.issued);
    assert!(history.validate(NS).is_ok());
    assert!(state.engines.sdk_lease(NS, &f.logical.id).is_none());
    assert!(!state.engines.has_live_sdk_leases());
    let late = Timestamp::from_wall(
        SystemTime::now().duration_since(UNIX_EPOCH)? + Duration::from_secs(120),
    )?;
    assert!(
        state
            .engines
            .sdk_cleanup_candidate(&state.auth, late, None)?
            .is_none()
    );
    assert!(state.engines.sdk_mount_binding(NS, "logical/").is_none());
    assert_eq!(
        call(
            &mut f.service,
            "POST",
            "sys/leases/lookup",
            &f.token,
            json!({"lease_id":f.logical.id})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut f.service,
            "POST",
            "sys/leases/renew",
            &f.token,
            json!({"lease_id":f.logical.id})
        )
        .status,
        400
    );
    assert_eq!(
        native(&mut f.service, "POST", "sys/namespaces/retire", &f.token).status,
        200
    );
    let recreated = f.service.state.as_ref().ok_or("recreated")?;
    assert!(
        recreated
            .namespaces
            .incarnation(NS)
            .is_some_and(|inc| inc > 1)
    );
    assert!(recreated.engines.sdk_lease(NS, &f.logical.id).is_none());
    assert!(
        recreated
            .engines
            .sdk_logical_history_records()
            .next()
            .is_some()
    );
    assert!(recreated.validate_format().is_ok());
    Ok(())
}
#[test]
fn namespace109_complete_history_encrypted_reopen_keeps_original_provenance_and_retired_frontier()
-> TestResult {
    let f = terminal_fixture()?;
    let before = f.service.state.as_ref().ok_or("terminal")?;
    let history = Zeroizing::new(
        crate::secret_serde::to_vec(
            &before.engines.sdk_logical_history_projection()?,
            512 * 1024,
        )
        .map_err(|_| "history")?,
    );
    let Fixture {
        directory,
        service,
        key,
        logical,
        credential,
        token: _,
    } = f;
    drop(service);
    let mut reopened = directory.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let state = reopened.state.as_ref().ok_or("reopened")?;
    assert!(state.validate_format().is_ok());
    assert!(!state.namespace_exists(NS));
    assert!(state.engines.sdk_lease(NS, &logical.id).is_none());
    assert!(
        state
            .auth
            .sdk_credential_record(NS, &credential.id)
            .is_some_and(|record| record.phase == Phase::Revoked)
    );
    let actual = Zeroizing::new(
        crate::secret_serde::to_vec(&state.engines.sdk_logical_history_projection()?, 512 * 1024)
            .map_err(|_| "history")?,
    );
    assert_eq!(&*history, &*actual);
    assert!(state.engines.sdk_logical_history_records().next().is_some());
    Ok(())
}
#[test]
fn namespace109_complete_history_full_record_mirror_and_sticky_owner_changes_reject() -> TestResult
{
    let f = terminal_fixture()?;
    let state = f.service.state.as_ref().ok_or("terminal")?;
    assert!(state.validate_format().is_ok());
    assert!(
        state
            .engines
            .owner_metadata_shared_with(&state.engines.clone())
    );
    let mut record_changed = state.clone();
    record_changed.engines.sdk_history_fixture_damage();
    assert!(
        !record_changed
            .engines
            .owner_metadata_shared_with(&state.engines)
    );
    assert!(record_changed.validate_format().is_err());
    assert!(
        record_changed
            .engines
            .validate_sdk_lease_clock(Some(&state.engines))
            .is_err()
    );
    let mut mirror_changed =
        serde_json::to_value(state.namespaces.deletions.as_ref().ok_or("ledger")?)?;
    let entries = mirror_changed["sdk_cleanup"]["logical_history"]["entries"]
        .as_object_mut()
        .ok_or("history entries")?;
    let entry = entries.values_mut().next().ok_or("history entry")?;
    entry["lease_digest"] = json!(vec![0u8; 32]);
    let mut both_bad = state.clone();
    replace_both_ledgers(&mut both_bad, mirror_changed)?;
    assert!(both_bad.validate_format().is_err());
    assert!(Service::validate_snapshot_protected_floor(state, &both_bad).is_err());
    let mut stripped = serde_json::to_value(state.namespaces.deletions.as_ref().ok_or("ledger")?)?;
    stripped["sdk_cleanup"]
        .as_object_mut()
        .ok_or("sdk registry")?
        .remove("logical_history");
    let mut no_history = state.clone();
    replace_both_ledgers(&mut no_history, stripped)?;
    assert!(no_history.validate_format().is_err());
    assert!(Service::validate_snapshot_protected_floor(state, &no_history).is_err());
    assert!(state.validate_format().is_ok());
    Ok(())
}
#[test]
fn namespace109_literal_r04_registry_declaration_rejects_refined_history_marker() -> TestResult {
    // Supplemental strict declaration class only. Actual retained old R04 binary
    // receiver/backup/encrypted-store tests remain a separate required scope.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct R04Registry {
        #[serde(default)]
        records: std::collections::BTreeMap<String, Value>,
    }
    let old: R04Registry = serde_json::from_value(json!({"records":{}}))?;
    assert!(old.records.is_empty());
    let mut f = fixture()?;
    begin(&mut f)?;
    let state = f.service.state.as_ref().ok_or("pending")?;
    let registry = state
        .namespaces
        .deletions
        .as_ref()
        .ok_or("ledger")?
        .sdk_cleanup()
        .ok_or("registry")?;
    let value = serde_json::to_value(registry)?;
    let rejected = serde_json::from_value::<R04Registry>(value)
        .err()
        .ok_or("old declaration accepted new fields")?;
    let public_class = rejected.to_string();
    assert!(public_class.contains("unknown field"));
    assert!(public_class.contains("logical_history") || public_class.contains("source_selections"));
    Ok(())
}

fn close_selected_namespace(f: &Fixture) -> TestResult<State> {
    let source = f.service.state.as_ref().ok_or("selected source")?;
    let key = f.service.barrier_key.as_ref().ok_or("actual root key")?;
    let closed = f
        .service
        .namespace_runtime
        .inherited_closed_candidate(source, NS, key)
        .map_err(|_| "actual selected namespace closure")?;
    assert!(closed.namespaces.inherited_owner(NS).is_some());
    assert!(closed.engines.sdk_lease(NS, &f.logical.id).is_none());
    assert!(!closed.engines.sdk_namespace_records_materialized(NS));
    assert!(closed.validate_format().is_ok());
    Ok(closed)
}
#[test]
fn namespace109_actual_closed_hydration_keeps_jobs_records_and_terminal_lineage() -> TestResult {
    let mut f = fixture()?;
    begin(&mut f)?;
    let closed = close_selected_namespace(&f)?;
    let saved = closed
        .namespaces
        .deletions
        .clone()
        .ok_or("actual closed jobs")?;
    // A verified ciphertext owner is not a logical publication view: the
    // current accepted SDK registration must still be checked in full.
    let before_rejected = f
        .service
        .current_state_identity()
        .map_err(|_| "original logical identity")?;
    let mut fragment = closed.clone();
    let rejected = match f.service.commit_state(&mut fragment) {
        Ok(_) => return Err("closed fragment cannot erase current registered resources".into()),
        Err(rejected) => rejected,
    };
    assert!(
        rejected.status == 503
            && rejected.body["errors"][0].as_str()
                == Some("SDK registration provenance was removed")
    );
    assert!(
        f.service
            .current_state_identity()
            .map_err(|_| "unchanged logical identity")?
            == before_rejected
    );
    let logical_to_publish = {
        let key = f.service.barrier_key.as_ref().ok_or("actual root key")?;
        f.service
            .namespace_runtime
            .restore_root_inherited(&closed, key, |_| Ok(()))
            .map_err(|_| "real keyed logical publication view")?
    };
    assert!(f.service.namespace_runtime.is_loaded(NS));
    assert!(
        logical_to_publish
            .engines
            .sdk_namespace_records_materialized(NS)
    );
    assert!(
        logical_to_publish
            .engines
            .sdk_lease(NS, &f.logical.id)
            .is_some_and(|lease| lease.registration == f.logical.registration)
    );
    assert!(logical_to_publish.namespaces.deletions.as_ref() == Some(&saved));
    // The original commit path checks the complete logical successor and
    // publishes its actual keyed canonical encrypted owner and resource cells.
    publish(&mut f.service, logical_to_publish)?;
    let before = f
        .service
        .current_state_identity()
        .map_err(|_| "published physical identity")?;
    let closed = f
        .service
        .state
        .as_ref()
        .ok_or("published logical state")?
        .protected_state()
        .map_err(|_| "published canonical physical view")?
        .clone();
    assert!(closed.namespaces.inherited_owner(NS).is_some());
    assert!(closed.engines.sdk_lease(NS, &f.logical.id).is_none());
    assert!(!closed.engines.sdk_namespace_records_materialized(NS));
    assert!(closed.namespaces.deletions.as_ref() == Some(&saved));
    assert!(closed.validate_format().is_ok());
    // Drop the logical continuation, revoke the actual slot, and restore only
    // the canonical ciphertext graph produced by that real commit.
    f.service.state = Some(closed.clone());
    f.service.namespace_runtime.close(NS);
    assert!(!f.service.namespace_runtime.is_loaded(NS));
    assert!(
        f.service
            .current_state_identity()
            .map_err(|_| "canonical physical identity")?
            == before
    );
    let hydrated = {
        let key = f.service.barrier_key.as_ref().ok_or("actual root key")?;
        f.service
            .namespace_runtime
            .restore_root_inherited(&closed, key, |_| Ok(()))
            .map_err(|_| "authenticated full resource hydration")?
    };
    assert!(f.service.namespace_runtime.is_loaded(NS));
    assert!(hydrated.engines.sdk_namespace_records_materialized(NS));
    assert!(hydrated.engines.sdk_lease(NS, &f.logical.id).is_some());
    assert!(hydrated.namespaces.deletions.as_ref() == Some(&saved));
    assert!(hydrated.validate_format().is_ok());
    assert!(
        f.service
            .current_state_identity()
            .map_err(|_| "hydrated identity")?
            == before
    );
    let mut absent = hydrated.clone();
    absent
        .engines
        .sdk_history_fixture_clear_materialized_leases(NS);
    assert!(absent.engines.sdk_namespace_records_materialized(NS));
    assert!(
        absent.validate_format().is_err(),
        "a loaded graph cannot disguise selected record removal"
    );
    assert!(hydrated.engines.sdk_lease(NS, &f.logical.id).is_some());
    f.service.state = Some(hydrated);
    attempt_all(&mut f.service)?;
    let mut next = f.service.state.clone().ok_or("hydrated Attempted")?;
    for selected in keys(&next)? {
        let job = next
            .namespace_sdk_cleanup_record(&selected)
            .map_err(|_| "selected job")?;
        match job.kind() {
            Kind::Logical => {
                let mut lease = next
                    .engines
                    .sdk_lease(NS, job.lease_id())
                    .ok_or("hydrated logical")?;
                next.engines
                    .sdk_storage_delete(NS, &lease.mount, &lease.backend, "record")?;
                lease.revoke();
                next.engines.store_sdk_lease(lease.clone())?;
                next.finish_namespace_sdk_logical(&selected, &lease)
                    .map_err(|_| "hydrated logical terminal")?;
            }
            Kind::Credential => {
                let mut record = next
                    .auth
                    .sdk_credential_record(NS, job.lease_id())
                    .ok_or("saved credential")?;
                next.auth
                    .sdk_auth_storage_delete(&record.backend, "record")?;
                record.revoke();
                next.auth.store_sdk_credential(record.clone())?;
                next.finish_namespace_sdk_credential(&selected, &record)
                    .map_err(|_| "credential terminal")?;
            }
        }
    }
    publish(&mut f.service, next)?;
    let original = clock()?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        original.started() + Duration::from_secs(15),
    );
    assert!(
        f.service
            .maintain_namespace_deletions(original)
            .map_err(|_| "hydrated namespace terminal")?
    );
    let terminal = f.service.state.as_ref().ok_or("terminal")?;
    assert!(!terminal.namespace_exists(NS));
    assert!(!f.service.namespace_runtime.is_loaded(NS));
    assert!(terminal.validate_format().is_ok());
    let history = terminal
        .engines
        .sdk_logical_history_records()
        .next()
        .ok_or("real retained history")?;
    assert!(history.phase == Phase::Revoked && history.registration == f.logical.registration);
    assert!(history.issuer == f.logical.issuer && history.issued == f.logical.issued);
    assert!(
        terminal
            .namespaces
            .deletions
            .as_ref()
            .ok_or("sticky ledger")?
            .sdk_cleanup()
            .ok_or("sticky work")?
            .records()
            .is_empty()
    );
    Ok(())
}
#[test]
fn namespace109_closed_empty_dual_mirrors_cannot_bypass_authenticated_resource_hydration()
-> TestResult {
    let mut f = fixture()?;
    let mut source = f.service.state.clone().ok_or("source")?;
    let mut credential = source
        .auth
        .sdk_credential_record(NS, &f.credential.id)
        .ok_or("credential")?;
    source
        .auth
        .sdk_auth_storage_delete(&credential.backend, "record")?;
    credential.revoke();
    source.auth.store_sdk_credential(credential)?;
    publish(&mut f.service, source)?;
    begin(&mut f)?;
    assert_eq!(keys(f.service.state.as_ref().ok_or("selected")?)?.len(), 1);
    let closed = close_selected_namespace(&f)?;
    let key = f.service.barrier_key.as_ref().ok_or("actual root key")?;
    let mut ledger = serde_json::to_value(closed.namespaces.deletions.as_ref().ok_or("ledger")?)?;
    ledger["sdk_cleanup"]["records"] = json!({});
    let mut orphan = closed.clone();
    replace_both_ledgers(&mut orphan, ledger.clone())?;
    assert!(
        orphan.validate_format().is_err(),
        "closed source selection rejects erased jobs"
    );
    ledger["sdk_cleanup"]["source_selections"][NS]["members"] = json!({});
    let mut forged = closed.clone();
    replace_both_ledgers(&mut forged, ledger)?;
    assert!(Service::validate_snapshot_protected_floor(&closed, &forged).is_err());
    let mut failed_runtime = namespace_runtime::Runtime::default();
    assert!(
        failed_runtime
            .restore_root_inherited(&forged, key, |_| Ok(()))
            .is_err(),
        "actual authenticated graph reveals the unselected Pending logical resource"
    );
    assert!(!failed_runtime.is_loaded(NS));
    let mut no_floor = closed.clone();
    no_floor
        .namespaces
        .deletion_fixture_remove_custody_frontier(NS);
    assert!(
        no_floor.validate_format().is_err(),
        "opaque ownership requires its exact durable floor"
    );
    let binding = closed
        .namespaces
        .custody_binding(&closed.cluster_id, NS)
        .map_err(|_| "closed Binding")?;
    let mut missing_cells = closed.clone();
    missing_cells
        .engines
        .retire_namespace_record_cells(&binding)?;
    assert!(
        failed_runtime
            .restore_root_inherited(&missing_cells, key, |_| Ok(()))
            .is_err()
    );
    assert!(!failed_runtime.is_loaded(NS));
    let mut genuine_runtime = namespace_runtime::Runtime::default();
    let hydrated = genuine_runtime
        .restore_root_inherited(&closed, key, |_| Ok(()))
        .map_err(|_| "genuine complete hydration")?;
    assert!(genuine_runtime.is_loaded(NS));
    assert!(hydrated.engines.sdk_lease(NS, &f.logical.id).is_some());
    assert!(hydrated.validate_format().is_ok());
    assert!(closed.validate_format().is_ok());
    Ok(())
}

#[test]
fn namespace109_tainted_catalog_matches_official_without_allowing_token_or_data() -> TestResult {
    let mut f = fixture()?;
    begin(&mut f)?;
    let before = f.service.current_state_identity().map_err(|_| "identity")?;
    assert!(
        f.service
            .state
            .as_ref()
            .ok_or("pending")?
            .namespace_is_tainted(NS)
    );
    for (method, path, expected) in [
        ("GET", "sys/mounts", 404),
        ("GET", "sys/auth", 404),
        ("GET", "auth/token/lookup-self", 403),
        ("GET", "logical/record", 403),
        ("POST", "logical/record", 403),
    ] {
        let execution = f.service.begin_request_before(
            ServiceRequest {
                method,
                path,
                namespace: NS,
                token: &f.token,
                body: json!({}),
                wrap_ttl_seconds: None,
                origin_peer: None,
                client_certificates: None,
            },
            Instant::now() + Duration::from_secs(15),
            true,
        );
        let response = f.service.finish_synchronous_request(execution);
        assert_eq!(response.status, expected, "tainted request {method} {path}");
        assert_eq!(
            f.service.current_state_identity().map_err(|_| "identity")?,
            before
        );
    }
    let state = f.service.state.as_ref().ok_or("retained pending")?;
    assert!(state.namespace_is_tainted(NS));
    assert_eq!(keys(state)?.len(), 2);
    state
        .validate_format()
        .map_err(|_| "actual retained format")?;
    Ok(())
}

// These controls exercise actual job capture, canonical publication and storage
// merge on the typed model fixture. Actual plugin Revoke/ACK and fixed native
// observation budgets remain separate native controls; no plugin is forged here.
fn owned_body(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> Response {
    let execution = service.begin_request_before(
        ServiceRequest {
            method,
            path,
            namespace: "",
            token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now() + Duration::from_secs(15),
        false,
    );
    service.finish_synchronous_request(execution)
}
fn owned_job(service: &Service, kind: Kind) -> TestResult<String> {
    let state = service.state.as_ref().ok_or("state")?;
    keys(state)?
        .into_iter()
        .find(|key| {
            state
                .namespace_sdk_cleanup_record(key)
                .is_ok_and(|job| job.kind() == kind)
        })
        .ok_or_else(|| "selected actual job".into())
}
fn owned_authority(service: &Service, kind: Kind) -> TestResult<Authority> {
    let original = clock()?;
    Authority::capture(
        service,
        owned_job(service, kind)?,
        original,
        original.started() + Duration::from_secs(15),
    )
    .map_err(|_| "selected actual native authority".into())
}
#[test]
fn namespace109_owned_storage_rebase_keeps_current_unrelated_publications() -> TestResult {
    let mut f = fixture()?;
    assert_eq!(
        owned_body(
            &mut f.service,
            "POST",
            "auth/token/create",
            &f.token,
            json!({"ttl":"30s"})
        )
        .status,
        200
    );
    assert!(
        f.service
            .state
            .as_ref()
            .ok_or("precise state")?
            .has_token_api_precision_state()
    );
    begin(&mut f)?;
    attempt_all(&mut f.service)?;
    let logical = owned_authority(&f.service, Kind::Logical)?;
    let credential = owned_authority(&f.service, Kind::Credential)?;
    let logical_cut = logical
        .logical_storage_cut(&f.service, NS, &f.logical.mount, &f.logical.backend)
        .map_err(|_| "actual logical cut")?;
    let credential_cut = credential
        .credential_storage_cut(&f.service, &f.credential.backend)
        .map_err(|_| "actual credential cut")?;
    let original_identity = f.service.current_state_identity().map_err(|_| "identity")?;
    let source = f.service.state.as_ref().ok_or("source")?;
    let original_jobs = source.namespaces.deletions.clone();
    let mut working_engines = source.engines.clone();
    let mut working_auth = source.auth.clone();
    working_engines.sdk_storage_put(
        NS,
        &f.logical.mount,
        &f.logical.backend,
        StorageEntry {
            key: "record".into(),
            value: Zeroizing::new(b"new-owned-logical".to_vec()),
            seal_wrap: true,
        },
    )?;
    working_auth.sdk_auth_storage_put(
        &f.credential.backend,
        crate::auth::sdk::Entry {
            key: "record".into(),
            value: Zeroizing::new(b"new-owned-credential".to_vec()),
            seal_wrap: true,
        },
    )?;
    // Real normal requests publish other current owners after both SDK cuts.
    assert_eq!(
        owned_body(
            &mut f.service,
            "POST",
            "sys/mounts/unrelated",
            &f.token,
            json!({"type":"kv"})
        )
        .status,
        204
    );
    assert_eq!(
        owned_body(
            &mut f.service,
            "POST",
            "unrelated/kept",
            &f.token,
            json!({"value":"current-unrelated-kv"})
        )
        .status,
        204
    );
    let minted = owned_body(
        &mut f.service,
        "POST",
        "auth/token/create",
        &f.token,
        json!({"ttl":"30s"}),
    );
    assert_eq!(minted.status, 200);
    let current_token = Zeroizing::new(
        minted.body["auth"]["client_token"]
            .as_str()
            .ok_or("actual current token")?
            .to_owned(),
    );
    assert_eq!(
        native(&mut f.service, "GET", "sys/namespaces/retire", &f.token).status,
        200
    );
    assert!(f.service.current_state_identity().map_err(|_| "identity")? != original_identity);
    logical
        .logical_native_role(&f.service, NS, &f.logical.mount, &f.logical.backend)
        .map_err(|_| "original logical authority after unrelated publication")?;
    credential
        .credential_native_role(&f.service, &f.credential.backend)
        .map_err(|_| "original credential authority after unrelated publication")?;
    let mut candidate = f.service.state.clone().ok_or("current candidate")?;
    logical_cut
        .merge(
            &mut candidate.engines,
            &working_engines,
            NS,
            &f.logical.mount,
            &f.logical.backend,
        )
        .map_err(|_| "owned logical merge")?;
    credential_cut
        .merge(&mut candidate.auth, &working_auth, &f.credential.backend)
        .map_err(|_| "owned credential merge")?;
    assert!(candidate.namespaces.deletions == original_jobs);
    publish(&mut f.service, candidate)?;
    assert_eq!(
        native(
            &mut f.service,
            "GET",
            "auth/token/lookup-self",
            &current_token
        )
        .status,
        200
    );
    assert_eq!(
        native(&mut f.service, "GET", "unrelated/kept", &f.token).body["data"]["value"],
        "current-unrelated-kv"
    );
    let state = f.service.state.as_ref().ok_or("merged")?;
    assert!(
        &*state
            .engines
            .sdk_storage_get(NS, &f.logical.mount, &f.logical.backend, "record")?
            .ok_or("logical value")?
            .value
            == b"new-owned-logical"
    );
    assert!(
        &*state
            .auth
            .sdk_auth_storage_get(&f.credential.backend, "record")?
            .ok_or("credential value")?
            .value
            == b"new-owned-credential"
    );
    assert!(state.validate_format().is_ok());
    let Fixture {
        directory,
        service,
        key,
        token,
        logical,
        credential,
        ..
    } = f;
    drop(service);
    // The legacy fixture entry has no trusted incoming RequestClock. Retain
    // its actual completion veto before reopening with a real bounded request.
    let mut without_clock = directory.service()?;
    let rejected = call(
        &mut without_clock,
        "POST",
        "sys/unseal",
        "",
        json!({"key":key}),
    );
    let first_error = rejected.body["errors"][0].as_str().unwrap_or("");
    let error_sha: String = crypto::digest(first_error.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    eprintln!(
        "NS_OWNED_REOPEN missing_trusted_clock status={} first_error_sha={} loaded={} precise={}",
        rejected.status,
        error_sha,
        without_clock.state.is_some(),
        without_clock
            .state
            .as_ref()
            .is_some_and(State::has_token_api_precision_state)
    );
    assert_eq!(rejected.status, 503);
    assert_eq!(
        error_sha,
        "453d8eec647abc2cf768e59e9a1cf605ac543ab23ef765abe5356b1b6192419f"
    );
    assert!(
        without_clock
            .state
            .as_ref()
            .is_some_and(State::has_token_api_precision_state)
    );
    drop(without_clock);
    let mut reopened = directory.service()?;
    assert_eq!(
        owned_body(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        native(
            &mut reopened,
            "GET",
            "auth/token/lookup-self",
            &current_token
        )
        .status,
        200
    );
    assert_eq!(
        native(&mut reopened, "GET", "unrelated/kept", &token).body["data"]["value"],
        "current-unrelated-kv"
    );
    let state = reopened.state.as_ref().ok_or("reopened")?;
    assert!(state.validate_format().is_ok());
    assert!(state.namespace_is_tainted(NS));
    assert!(state.engines.sdk_lease(NS, &logical.id).is_some());
    assert!(
        state
            .auth
            .sdk_credential_record(NS, &credential.id)
            .is_some()
    );
    assert!(
        &*state
            .engines
            .sdk_storage_get(NS, &logical.mount, &logical.backend, "record")?
            .ok_or("reopened logical value")?
            .value
            == b"new-owned-logical"
    );
    assert!(
        &*state
            .auth
            .sdk_auth_storage_get(&credential.backend, "record")?
            .ok_or("reopened credential value")?
            .value
            == b"new-owned-credential"
    );
    for key in keys(state)? {
        assert!(
            state
                .namespace_sdk_cleanup_record(&key)
                .map_err(|_| "saved job")?
                .stage()
                == &Stage::Attempted
        );
    }
    Ok(())
}
#[test]
fn namespace109_owned_storage_rebase_rejects_actual_owned_cell_changes() -> TestResult {
    let mut f = fixture()?;
    begin(&mut f)?;
    attempt_all(&mut f.service)?;
    let logical = owned_authority(&f.service, Kind::Logical)?;
    let credential = owned_authority(&f.service, Kind::Credential)?;
    let logical_cut = logical
        .logical_storage_cut(&f.service, NS, &f.logical.mount, &f.logical.backend)
        .map_err(|_| "logical cut")?;
    let credential_cut = credential
        .credential_storage_cut(&f.service, &f.credential.backend)
        .map_err(|_| "credential cut")?;
    let original = f.service.state.clone().ok_or("original")?;
    let mut changed = original.clone();
    changed.engines.sdk_storage_put(
        NS,
        &f.logical.mount,
        &f.logical.backend,
        StorageEntry {
            key: "new-member".into(),
            value: Zeroizing::new(b"conflict".to_vec()),
            seal_wrap: false,
        },
    )?;
    changed.auth.sdk_auth_storage_put(
        &f.credential.backend,
        crate::auth::sdk::Entry {
            key: "record".into(),
            value: Zeroizing::new(b"conflict".to_vec()),
            seal_wrap: false,
        },
    )?;
    publish(&mut f.service, changed)?;
    // Job metadata remains valid; full key membership / bytes / sealWrap changed.
    assert!(logical.check(&f.service).is_ok());
    assert!(credential.check(&f.service).is_ok());
    let mut current = f.service.state.clone().ok_or("current")?;
    assert!(
        logical_cut
            .check(&current.engines, NS, &f.logical.mount, &f.logical.backend)
            .is_err()
    );
    assert!(
        credential_cut
            .check(&current.auth, &f.credential.backend)
            .is_err()
    );
    let engine_before = Zeroizing::new(
        crate::secret_serde::to_vec(&*current.engines, 4 * 1024 * 1024)
            .map_err(|_| "original Engine snapshot rejected")?,
    );
    let auth_before = Zeroizing::new(
        crate::secret_serde::to_vec(&*current.auth, 4 * 1024 * 1024)
            .map_err(|_| "original Auth snapshot rejected")?,
    );
    assert!(
        logical_cut
            .merge(
                &mut current.engines,
                &original.engines,
                NS,
                &f.logical.mount,
                &f.logical.backend
            )
            .is_err()
    );
    assert!(
        credential_cut
            .merge(&mut current.auth, &original.auth, &f.credential.backend)
            .is_err()
    );
    let engine_after = Zeroizing::new(
        crate::secret_serde::to_vec(&*current.engines, 4 * 1024 * 1024)
            .map_err(|_| "current Engine snapshot rejected")?,
    );
    let auth_after = Zeroizing::new(
        crate::secret_serde::to_vec(&*current.auth, 4 * 1024 * 1024)
            .map_err(|_| "current Auth snapshot rejected")?,
    );
    assert!(&*engine_before == &*engine_after && &*auth_before == &*auth_after);
    Ok(())
}
#[test]
fn namespace109_owned_storage_cut_rejects_wrong_family_scope_and_namespace_seal() -> TestResult {
    let mut f = fixture()?;
    begin(&mut f)?;
    attempt_all(&mut f.service)?;
    let logical = owned_authority(&f.service, Kind::Logical)?;
    let credential = owned_authority(&f.service, Kind::Credential)?;
    assert!(
        logical
            .credential_storage_cut(&f.service, &f.credential.backend)
            .is_err()
    );
    assert!(
        credential
            .logical_storage_cut(&f.service, NS, &f.logical.mount, &f.logical.backend)
            .is_err()
    );
    assert!(
        logical
            .logical_storage_cut(&f.service, "", &f.logical.mount, &f.logical.backend)
            .is_err()
    );
    let credential_cut = credential
        .credential_storage_cut(&f.service, &f.credential.backend)
        .map_err(|_| "credential cut")?;
    let mut wrong = f.credential.backend.clone();
    wrong.namespace.clear();
    assert!(
        credential_cut
            .check(&f.service.state.as_ref().ok_or("state")?.auth, &wrong)
            .is_err()
    );
    assert!(
        Authority::capture(
            &f.service,
            "absent".into(),
            clock()?,
            Instant::now() + Duration::from_secs(15)
        )
        .is_err()
    );
    // No ordinary caller/token obtains this private cleanup capability.
    let denied = f.service.begin_request_before(
        ServiceRequest {
            method: "GET",
            path: "logical/record",
            namespace: NS,
            token: &f.token,
            body: json!({}),
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now() + Duration::from_secs(15),
        false,
    );
    assert_eq!(f.service.finish_synchronous_request(denied).status, 403);
    assert_eq!(
        native(
            &mut f.service,
            "GET",
            "auth/token/lookup-self",
            "invalid-token"
        )
        .status,
        403
    );
    let sealed_response = owned_body(
        &mut f.service,
        "POST",
        "sys/namespaces/retire/seal",
        &f.token,
        json!({}),
    );
    let seal_error_sha: String = crypto::digest(
        sealed_response.body["errors"][0]
            .as_str()
            .unwrap_or("")
            .as_bytes(),
    )
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect();
    let actual = f.service.state.as_ref();
    eprintln!(
        "NS_OWNED_SEAL namespace_seal status={} first_error_sha={} schema={} target_sealed={} jobs={} precise={}",
        sealed_response.status,
        seal_error_sha,
        actual.map_or(0, |state| state.schema),
        actual.is_some_and(|state| state.namespace_is_sealed(NS)),
        actual
            .and_then(|state| state.namespaces.deletions.as_ref())
            .and_then(|ledger| ledger.sdk_cleanup())
            .map_or(0, |jobs| jobs.records().len()),
        actual.is_some_and(State::has_token_api_precision_state)
    );
    assert_eq!(sealed_response.status, 204);
    assert!(
        logical
            .logical_native_role(&f.service, NS, &f.logical.mount, &f.logical.backend)
            .is_err()
    );
    assert!(
        credential
            .credential_native_role(&f.service, &f.credential.backend)
            .is_err()
    );
    assert!(f.service.pending_sdk_request.is_none());
    assert!(f.service.pending_sdk_auth_request.is_none());
    Ok(())
}
#[test]
fn namespace109_original_owned_storage_authority_rejects_real_return_in_new_term() -> TestResult {
    let mut f = fixture()?;
    let cluster_id = f.service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = crate::ha::snapshot_test_support::Cluster::new(
        &f.directory.path.join("raft"),
        &cluster_id,
    )?;
    f.service.ha = Some(Arc::clone(&cluster.processes[0]));
    f.service
        .sync_from_ha()
        .map_err(|_| "initial actual HA publication")?;
    begin(&mut f)?;
    attempt_all(&mut f.service)?;
    let logical = owned_authority(&f.service, Kind::Logical)?;
    let credential = owned_authority(&f.service, Kind::Credential)?;
    let original_role = credential
        .credential_native_role(&f.service, &f.credential.backend)
        .map_err(|_| "actual original role")?
        .captured()
        .ok_or("actual HA role")?;
    let identity = f.service.current_state_identity().map_err(|_| "identity")?;
    let generation = f.service.durable.as_ref().ok_or("durable")?.generation();
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(credential.deadline);
    let next = cluster.processes[0]
        .lock()
        .map_err(|_| "HA mutex")?
        .step_down()?;
    assert_ne!(next, 1);
    let returned = cluster.processes[(next - 1) as usize]
        .lock()
        .map_err(|_| "successor mutex")?
        .step_down()?;
    assert_eq!(returned, 1);
    let actual = cluster.processes[0]
        .lock()
        .map_err(|_| "HA mutex")?
        .leader_status()?;
    assert!(actual.local_is_leader && actual.leader == Some(1) && actual.term > original_role.1);
    assert!(
        logical
            .logical_native_role(&f.service, NS, &f.logical.mount, &f.logical.backend)
            .is_err()
    );
    assert!(
        credential
            .credential_native_role(&f.service, &f.credential.backend)
            .is_err()
    );
    assert!(credential.sync_before_setup(&mut f.service).is_err());
    assert!(f.service.current_state_identity().map_err(|_| "identity")? == identity);
    assert_eq!(
        f.service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert!(
        f.service.pending_sdk_request.is_none() && f.service.pending_sdk_auth_request.is_none()
    );
    Ok(())
}

#[test]
fn namespace109_owned_storage_native_role_stable_publish_and_post_stage_return_veto() -> TestResult
{
    let mut f = fixture()?;
    let cluster_id = f.service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = crate::ha::snapshot_test_support::Cluster::new(
        &f.directory.path.join("raft"),
        &cluster_id,
    )?;
    f.service.ha = Some(Arc::clone(&cluster.processes[0]));
    f.service
        .sync_from_ha()
        .map_err(|_| "initial actual HA publication")?;
    begin(&mut f)?;
    attempt_all(&mut f.service)?;
    let authority = owned_authority(&f.service, Kind::Credential)?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(authority.deadline);
    let role = authority
        .credential_native_role(&f.service, &f.credential.backend)
        .map_err(|_| "actual original role")?
        .captured()
        .ok_or("actual HA role")?;
    let cut = authority
        .credential_storage_cut(&f.service, &f.credential.backend)
        .map_err(|_| "actual owned cut")?;
    let mut working = f.service.state.as_ref().ok_or("state")?.auth.clone();
    working.sdk_auth_storage_put(
        &f.credential.backend,
        crate::auth::sdk::Entry {
            key: "record".into(),
            value: Zeroizing::new(b"stable-owned-publish".to_vec()),
            seal_wrap: true,
        },
    )?;
    let mut current = f.service.state.clone().ok_or("candidate")?;
    cut.merge(&mut current.auth, &working, &f.credential.backend)
        .map_err(|_| "actual owned merge")?;
    current.schema = current.writer_schema();
    let publication = f
        .service
        .prepare_record_plan(&mut current)
        .map_err(|_| "actual canonical preparation")?;
    f.service
        .commit_record_plan_with_native_role(
            &current,
            publication,
            Some(role),
            |auth| authority.check_auth(auth),
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            None,
        )
        .map_err(|_| "stable original role publication")?;
    f.service.state = Some(current);
    assert!(authority.check(&f.service).is_ok());
    // Recapture Storage from the same affine job, clock and original HA term.
    let cut = authority
        .credential_storage_cut(&f.service, &f.credential.backend)
        .map_err(|_| "same original authority current owned cut")?;
    let mut working = f.service.state.as_ref().ok_or("state")?.auth.clone();
    working.sdk_auth_storage_put(
        &f.credential.backend,
        crate::auth::sdk::Entry {
            key: "record".into(),
            value: Zeroizing::new(b"must-not-publish".to_vec()),
            seal_wrap: false,
        },
    )?;
    let mut rejected = f.service.state.clone().ok_or("candidate")?;
    cut.merge(&mut rejected.auth, &working, &f.credential.backend)
        .map_err(|_| "actual candidate owned merge")?;
    rejected.schema = rejected.writer_schema();
    let publication = f
        .service
        .prepare_record_plan(&mut rejected)
        .map_err(|_| "actual candidate canonical preparation")?;
    let identity = f.service.current_state_identity().map_err(|_| "identity")?;
    let generation = f.service.durable.as_ref().ok_or("durable")?.generation();
    let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::clone(&entered);
    let processes = cluster.processes.clone();
    f.service.native_record_role_hook = Some(Box::new(move |process| {
        let next = process
            .step_down()
            .expect("actual post-Stage first handoff");
        assert_ne!(next, 1);
        let returned = processes[(next - 1) as usize]
            .lock()
            .expect("real successor mutex")
            .step_down()
            .expect("actual post-Stage return handoff");
        assert_eq!(returned, 1);
        observed.store(true, std::sync::atomic::Ordering::Release);
    }));
    let failure = f
        .service
        .commit_record_plan_with_native_role(
            &rejected,
            publication,
            Some(role),
            |auth| authority.check_auth(auth),
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            None,
        )
        .err()
        .ok_or("original role must veto actual post-Stage Publish")?;
    assert_eq!(failure.status, 503);
    assert!(entered.load(std::sync::atomic::Ordering::Acquire));
    let actual = cluster.processes[0]
        .lock()
        .map_err(|_| "actual leader mutex")?
        .leader_status()?;
    assert!(actual.local_is_leader && actual.leader == Some(1) && actual.term > role.1);
    assert!(f.service.current_state_identity().map_err(|_| "identity")? == identity);
    assert_eq!(
        f.service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let state = f.service.state.as_ref().ok_or("current")?;
    assert!(
        &*state
            .auth
            .sdk_auth_storage_get(&f.credential.backend, "record")?
            .ok_or("stable value retained")?
            .value
            == b"stable-owned-publish"
    );
    assert!(authority.check(&f.service).is_err());
    let Fixture {
        directory,
        service,
        key,
        credential,
        ..
    } = f;
    drop(service);
    let mut reopened = directory.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let state = reopened.state.as_ref().ok_or("reopened")?;
    assert!(state.validate_format().is_ok());
    assert!(
        &*state
            .auth
            .sdk_auth_storage_get(&credential.backend, "record")?
            .ok_or("durable stable value retained")?
            .value
            == b"stable-owned-publish"
    );
    for key in keys(state)? {
        assert!(
            state
                .namespace_sdk_cleanup_record(&key)
                .map_err(|_| "saved job")?
                .stage()
                == &Stage::Attempted
        );
    }
    Ok(())
}

#[test]
fn namespace109_same_original_authorities_recapture_terminal_storage_before_namespace_removal()
-> TestResult {
    let mut f = fixture()?;
    begin(&mut f)?;
    attempt_all(&mut f.service)?;
    let mut logical = owned_authority(&f.service, Kind::Logical)?;
    let mut credential = owned_authority(&f.service, Kind::Credential)?;
    let logical_start = logical.clock.started();
    let logical_deadline = logical.deadline;
    let credential_start = credential.clock.started();
    let credential_deadline = credential.deadline;
    let logical_role = logical.native_role;
    let credential_role = credential.native_role;
    let logical_cut = logical
        .logical_storage_cut(&f.service, NS, &f.logical.mount, &f.logical.backend)
        .map_err(|_| "actual original logical cut")?;
    let credential_cut = credential
        .credential_storage_cut(&f.service, &f.credential.backend)
        .map_err(|_| "actual original credential cut")?;
    let original = f.service.state.as_ref().ok_or("source")?;
    let mut working_engines = original.engines.clone();
    let mut working_auth = original.auth.clone();
    working_engines.sdk_storage_delete(NS, &f.logical.mount, &f.logical.backend, "record")?;
    working_auth.sdk_auth_storage_delete(&f.credential.backend, "record")?;
    let mut terminal = f.service.state.clone().ok_or("current")?;
    logical_cut
        .merge(
            &mut terminal.engines,
            &working_engines,
            NS,
            &f.logical.mount,
            &f.logical.backend,
        )
        .map_err(|_| "actual logical cut merge")?;
    credential_cut
        .merge(&mut terminal.auth, &working_auth, &f.credential.backend)
        .map_err(|_| "actual credential cut merge")?;
    let mut revoked_logical = terminal
        .engines
        .sdk_lease(NS, &f.logical.id)
        .ok_or("same actual logical lease")?;
    revoked_logical.revoke();
    terminal.engines.store_sdk_lease(revoked_logical.clone())?;
    logical
        .finish_logical(&mut terminal, &revoked_logical)
        .map_err(|_| "original work logical terminal publication")?;
    let mut revoked_credential = terminal
        .auth
        .sdk_credential_record(NS, &f.credential.id)
        .ok_or("same actual credential lease")?;
    revoked_credential.revoke();
    terminal
        .auth
        .store_sdk_credential(revoked_credential.clone())?;
    credential
        .finish_credential(&mut terminal, &revoked_credential)
        .map_err(|_| "original work credential terminal publication")?;
    publish(&mut f.service, terminal)?;
    let state = f.service.state.as_ref().ok_or("terminal")?;
    // These are the actual post-commit ordering and predicates: the selected
    // terminal records remain present until the later namespace-removal pass.
    logical
        .after_publication(&state.auth)
        .map_err(|_| "logical selected terminal")?;
    credential
        .after_publication(&state.auth)
        .map_err(|_| "credential selected terminal")?;
    assert!(matches!(logical.selected.stage(), Stage::Terminal { .. }));
    assert!(matches!(
        credential.selected.stage(),
        Stage::Terminal { .. }
    ));
    let logical_cut = logical
        .logical_storage_cut(&f.service, NS, &f.logical.mount, &f.logical.backend)
        .map_err(|_| "same original logical terminal recapture")?;
    let credential_cut = credential
        .credential_storage_cut(&f.service, &f.credential.backend)
        .map_err(|_| "same original credential terminal recapture")?;
    assert!(
        logical_cut
            .check(&state.engines, NS, &f.logical.mount, &f.logical.backend)
            .is_ok()
    );
    assert!(
        credential_cut
            .check(&state.auth, &f.credential.backend)
            .is_ok()
    );
    assert!(state.namespace_exists(NS) && state.namespace_is_tainted(NS));
    assert!(
        state
            .engines
            .sdk_lease(NS, &f.logical.id)
            .is_some_and(|r| r.phase == Phase::Revoked)
    );
    assert!(
        state
            .auth
            .sdk_credential_record(NS, &f.credential.id)
            .is_some_and(|r| r.phase == Phase::Revoked)
    );
    assert!(
        state
            .engines
            .sdk_storage_get(NS, &f.logical.mount, &f.logical.backend, "record")?
            .is_none()
    );
    assert!(
        state
            .auth
            .sdk_auth_storage_get(&f.credential.backend, "record")?
            .is_none()
    );
    assert!(
        logical.clock.started() == logical_start
            && logical.deadline == logical_deadline
            && logical.native_role == logical_role
    );
    assert!(
        credential.clock.started() == credential_start
            && credential.deadline == credential_deadline
            && credential.native_role == credential_role
    );
    assert!(state.validate_format().is_ok());
    let Fixture {
        directory,
        service,
        key,
        logical: lease,
        credential: record,
        ..
    } = f;
    drop(service);
    let mut reopened = directory.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let state = reopened.state.as_ref().ok_or("reopened terminal")?;
    assert!(state.validate_format().is_ok() && state.namespace_exists(NS));
    assert!(
        state
            .engines
            .sdk_lease(NS, &lease.id)
            .is_some_and(|r| r.phase == Phase::Revoked)
    );
    assert!(
        state
            .auth
            .sdk_credential_record(NS, &record.id)
            .is_some_and(|r| r.phase == Phase::Revoked)
    );
    for key in keys(state)? {
        assert!(matches!(
            state
                .namespace_sdk_cleanup_record(&key)
                .map_err(|_| "terminal job")?
                .stage(),
            Stage::Terminal { .. }
        ));
    }
    Ok(())
}

fn install_test_independent_owner(
    service: &mut Service,
    actual: &str,
) -> TestResult<Zeroizing<Vec<u8>>> {
    let original = service.state.as_ref().ok_or("actual predecessor")?;
    let fresh = namespace_runtime::Runtime::fresh_candidate(original, actual, 1, 1)
        .map_err(|_| "actual fresh independent owner")?;
    let share = fresh
        .shares
        .into_iter()
        .next()
        .ok_or("actual original share")?;
    publish(service, fresh.candidate)?;
    let closed = service.state.clone().ok_or("actual closed independent")?;
    let restored = service
        .namespace_runtime
        .submit(&closed, actual, &share, |_| Ok(()))
        .map_err(|_| "actual independent share restore")?
        .ok_or("actual complete independent share")?;
    service.state = Some(restored);
    assert!(service.namespace_runtime.is_loaded(actual));
    Ok(share)
}
fn owned_namespace_body(
    service: &mut Service,
    namespace: &str,
    path: &str,
    token: &str,
    body: Value,
) -> Response {
    let execution = service.begin_request_before(
        ServiceRequest {
            method: "POST",
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now() + Duration::from_secs(15),
        false,
    );
    service.finish_synchronous_request(execution)
}
fn assert_original_sdk_and_storage(
    state: &State,
    logical: &Lease,
    credential: &crate::auth::sdk_credential::Record,
) -> TestResult {
    assert!(
        state
            .engines
            .sdk_lease(NS, &logical.id)
            .is_some_and(|actual| actual.registration == logical.registration
                && actual.issued == logical.issued
                && actual.backend == logical.backend)
    );
    assert!(
        state
            .auth
            .sdk_credential_record(NS, &credential.id)
            .is_some_and(|actual| actual.registration == credential.registration
                && actual.issued == credential.issued
                && actual.backend == credential.backend)
    );
    assert!(
        state
            .engines
            .sdk_storage_get(NS, &logical.mount, &logical.backend, "record")?
            .is_some_and(|entry| entry.value.as_slice() == b"finite-logical-owned")
    );
    assert!(
        state
            .auth
            .sdk_auth_storage_get(&credential.backend, "record")?
            .is_some_and(|entry| entry.value.as_slice() == b"finite-credential-owned")
    );
    Ok(())
}

#[test]
fn namespace109_authenticated_inherited_seal_keeps_actual_auth_retirement_attempt_and_live_sdk_on_reopen()
-> TestResult {
    let mut f = fixture()?;
    let plugins = f.directory.path.join("actual-retirement-plugins");
    let runtime = f.directory.path.join("actual-retirement-runtime");
    private_directory(&plugins)?;
    private_directory(&runtime)?;
    f.service
        .install_sdk_backend(Some(crate::service::SdkBackendConfig {
            plugin_directory: plugins,
            runtime_directory: runtime,
            companion: f
                .directory
                .path
                .join("intentionally-absent-retirement-companion"),
            companion_sha256: "a".repeat(64),
            timeout_ms: 5_000,
        }))?;
    let execution = f.service.begin_request_before(
        ServiceRequest {
            method: "DELETE",
            path: "sys/auth/credential",
            namespace: NS,
            token: &f.token,
            body: json!({}),
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now() + Duration::from_secs(15),
        false,
    );
    let RequestExecution::External(pending) = execution else {
        return Err("actual live namespace Auth retirement did not produce owned work".into());
    };
    assert!(matches!(&pending.effect, ExternalEffectPlan::SdkAuth(_)));
    // The real DELETE commits accepted and Attempted before staging this Plan.
    // This typed-model test does not execute it or claim external Setup/Revoke.
    drop(pending);
    let before = f.service.state.as_ref().ok_or("actual original graph")?;
    assert!(!before.namespace_is_tainted(NS));
    let jobs = before.auth.sdk_auth_retirement_jobs_for_test();
    assert_eq!(jobs.len(), 1);
    let (job_id, job) = &jobs[0];
    assert!(job.binding() == &f.credential.backend && !job.completed());
    assert!(
        job.phase(&f.credential.id) == Some(crate::auth::sdk_retirement::ResourcePhase::Attempted)
    );
    assert!(
        before
            .auth
            .sdk_auth_retirement_recovery_selections()?
            .is_empty()
    );
    let namespace_jobs = before.namespaces.deletions.clone();
    let logical = before
        .engines
        .sdk_lease(NS, &f.logical.id)
        .ok_or("actual original logical")?
        .clone();
    let credential = before
        .auth
        .sdk_credential_record(NS, &f.credential.id)
        .ok_or("actual original credential")?
        .clone();
    assert!(logical.phase == Phase::Active && credential.phase == Phase::PendingRevoke);
    let credential_bytes = Zeroizing::new(
        crate::secret_serde::to_vec(&credential, 4 * 1024 * 1024)
            .map_err(|_| "original retained credential snapshot rejected")?,
    );
    let sealed = owned_body(
        &mut f.service,
        "POST",
        "sys/namespaces/retire/seal",
        &f.token,
        json!({}),
    );
    assert_eq!(sealed.status, 204);
    assert!(!f.service.namespace_runtime.is_loaded(NS));
    let closed = f.service.state.as_ref().ok_or("actual installed closed")?;
    assert!(closed.namespaces.custody_owner(NS).is_none());
    assert!(!closed.namespace_is_tainted(NS));
    match f.service.namespace_runtime.status(closed, NS) {
        Err(error) => assert_eq!(error.status, 400),
        Ok(_) => return Err("ordinary namespace acquired independent seal status".into()),
    }
    assert!(closed.engines.sdk_lease(NS, &f.logical.id).is_none());
    let retained = closed
        .auth
        .sdk_credential_record(NS, &f.credential.id)
        .ok_or("actual global credential retained while namespace assets are closed")?;
    assert!(
        retained.phase == credential.phase
            && retained.registration == credential.registration
            && retained.issued == credential.issued
            && retained.backend == credential.backend
    );
    let retained_bytes = Zeroizing::new(
        crate::secret_serde::to_vec(&retained, 4 * 1024 * 1024)
            .map_err(|_| "closed retained credential snapshot rejected")?,
    );
    assert!(&*retained_bytes == &*credential_bytes);
    assert!(closed.namespaces.deletions == namespace_jobs);
    assert!(closed.auth.sdk_auth_retirement_jobs_for_test() == jobs);
    assert!(
        closed
            .auth
            .sdk_auth_retirement_job(job_id)
            .is_some_and(|actual| actual == job)
    );
    let bytes = owner_store::serialize_owner(closed)?;
    for marker in [
        b"finite-logical-owned".as_slice(),
        b"finite-credential-owned".as_slice(),
    ] {
        assert!(!bytes.windows(marker.len()).any(|window| window == marker));
    }
    let Fixture {
        directory,
        service,
        key,
        token: _,
        logical: _,
        credential: _,
    } = f;
    drop(service);
    let mut reopened = directory.service()?;
    assert_eq!(
        owned_body(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let state = reopened.state.as_ref().ok_or("actual reopened graph")?;
    assert!(!state.namespace_is_tainted(NS));
    assert!(state.namespaces.deletions == namespace_jobs);
    assert!(state.auth.sdk_auth_retirement_jobs_for_test() == jobs);
    assert_original_sdk_and_storage(state, &logical, &credential)?;
    assert!(
        state
            .engines
            .sdk_lease(NS, &logical.id)
            .is_some_and(|record| record.phase == Phase::Active)
    );
    assert!(
        state
            .auth
            .sdk_credential_record(NS, &credential.id)
            .is_some_and(|record| record.phase == Phase::PendingRevoke)
    );
    let reopened_credential = state
        .auth
        .sdk_credential_record(NS, &credential.id)
        .ok_or("actual reopened original retained credential")?;
    let reopened_bytes = Zeroizing::new(
        crate::secret_serde::to_vec(&reopened_credential, 4 * 1024 * 1024)
            .map_err(|_| "reopened retained credential snapshot rejected")?,
    );
    assert!(&*reopened_bytes == &*credential_bytes);
    state
        .validate_format()
        .map_err(|_| "reopened full typed graph")?;
    Ok(())
}
#[test]
fn namespace109_authenticated_independent_seal_preserves_two_original_descendant_frontiers()
-> TestResult {
    let (mut f, parent_share) = fixture_with_owner(true)?;
    let parent_share = parent_share.ok_or("actual parent share")?;
    assert_eq!(
        owned_namespace_body(
            &mut f.service,
            NS,
            "sys/namespaces/child",
            &f.token,
            json!({})
        )
        .status,
        200
    );
    let child = "retire/child";
    let child_share = install_test_independent_owner(&mut f.service, child)?;
    assert_eq!(
        owned_namespace_body(
            &mut f.service,
            child,
            "sys/mounts/records",
            &f.token,
            json!({"type":"kv","options":{"version":"1"}})
        )
        .status,
        204
    );
    assert_eq!(
        owned_namespace_body(
            &mut f.service,
            child,
            "records/value",
            &f.token,
            json!({"marker":"actual-two-owner-child-record"})
        )
        .status,
        204
    );
    let original = f.service.state.as_ref().ok_or("actual two loaded owners")?;
    let credential = original
        .auth
        .sdk_credential_record(NS, &f.credential.id)
        .ok_or("actual original global credential before independent seal")?;
    let credential_bytes = Zeroizing::new(
        crate::secret_serde::to_vec(&credential, 4 * 1024 * 1024)
            .map_err(|_| "original retained credential snapshot rejected")?,
    );
    let parent = original
        .namespaces
        .custody_owner(NS)
        .ok_or("actual parent owner")?
        .clone();
    let descendant = original
        .namespaces
        .custody_owner(child)
        .ok_or("actual child owner")?
        .clone();
    assert!(
        f.service.namespace_runtime.is_loaded(NS) && f.service.namespace_runtime.is_loaded(child)
    );
    assert_eq!(
        owned_body(
            &mut f.service,
            "POST",
            "sys/namespaces/retire/seal",
            &f.token,
            json!({})
        )
        .status,
        204
    );
    assert!(
        !f.service.namespace_runtime.is_loaded(NS) && !f.service.namespace_runtime.is_loaded(child)
    );
    let closed = f.service.state.as_ref().ok_or("closed two owners")?;
    let parent_closed = closed
        .namespaces
        .custody_owner(NS)
        .ok_or("actual closed parent")?;
    assert!(
        parent_closed.key_epoch() == parent.key_epoch()
            && parent_closed.seal_frontier() == parent.seal_frontier() + 1
    );
    assert!(closed.engines.sdk_lease(NS, &f.logical.id).is_none());
    let retained = closed
        .auth
        .sdk_credential_record(NS, &f.credential.id)
        .ok_or("actual global credential retained while namespace assets are closed")?;
    assert!(
        retained.phase == credential.phase
            && retained.registration == credential.registration
            && retained.issued == credential.issued
            && retained.backend == credential.backend
    );
    let retained_bytes = Zeroizing::new(
        crate::secret_serde::to_vec(&retained, 4 * 1024 * 1024)
            .map_err(|_| "closed retained credential snapshot rejected")?,
    );
    assert!(&*retained_bytes == &*credential_bytes);
    let Fixture {
        directory,
        service,
        key,
        token,
        logical,
        credential,
    } = f;
    drop(service);
    let mut reopened = directory.service()?;
    assert_eq!(
        owned_body(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert!(
        !reopened.namespace_runtime.is_loaded(NS) && !reopened.namespace_runtime.is_loaded(child)
    );
    assert_eq!(
        owned_body(
            &mut reopened,
            "POST",
            "sys/namespaces/retire/unseal",
            &token,
            json!({"key":hex(&parent_share)})
        )
        .status,
        200
    );
    let parent_open = reopened.state.as_ref().ok_or("actual parent unseal")?;
    assert_original_sdk_and_storage(parent_open, &logical, &credential)?;
    let child_closed = parent_open
        .namespaces
        .custody_owner(child)
        .ok_or("actual contained child")?;
    assert!(
        child_closed.key_epoch() == descendant.key_epoch()
            && child_closed.seal_frontier() == descendant.seal_frontier() + 1
    );
    assert!(!reopened.namespace_runtime.is_loaded(child));
    assert_eq!(
        owned_namespace_body(
            &mut reopened,
            NS,
            "sys/namespaces/child/unseal",
            &token,
            json!({"key":hex(&child_share)})
        )
        .status,
        200
    );
    let actual = reopened.state.as_ref().ok_or("actual child unseal")?;
    assert_original_sdk_and_storage(actual, &logical, &credential)?;
    let reopened_credential = actual
        .auth
        .sdk_credential_record(NS, &credential.id)
        .ok_or("actual reopened original retained credential")?;
    assert!(
        reopened_credential.phase == credential.phase
            && reopened_credential.registration == credential.registration
            && reopened_credential.issued == credential.issued
            && reopened_credential.backend == credential.backend
    );
    let reopened_bytes = Zeroizing::new(
        crate::secret_serde::to_vec(&reopened_credential, 4 * 1024 * 1024)
            .map_err(|_| "reopened retained credential snapshot rejected")?,
    );
    assert!(&*reopened_bytes == &*credential_bytes);
    let read = reopened.begin_request_before(
        ServiceRequest {
            method: "GET",
            path: "records/value",
            namespace: child,
            token: &token,
            body: json!({}),
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now() + Duration::from_secs(15),
        false,
    );
    let response = reopened.finish_synchronous_request(read);
    assert_eq!(response.status, 200);
    assert!(response.body["data"]["marker"] == "actual-two-owner-child-record");
    Ok(())
}
#[test]
fn namespace109_authenticated_seal_rejects_erased_registration_and_changed_current_base()
-> TestResult {
    let mut f = fixture()?;
    let original = f.service.state.clone().ok_or("actual current graph")?;
    let mut absent = original.clone();
    absent
        .engines
        .sdk_history_fixture_clear_materialized_leases(NS);
    assert!(
        f.service
            .prepare_namespace_seal_publication(&absent, NS)
            .is_err()
    );
    let proof = f
        .service
        .prepare_namespace_seal_publication(&original, NS)
        .map_err(|_| "actual full seal evidence")?;
    assert_eq!(
        owned_body(
            &mut f.service,
            "POST",
            "sys/mounts/unrelated",
            &f.token,
            json!({"type":"kv","options":{"version":"1"}})
        )
        .status,
        204
    );
    let identity = f
        .service
        .current_state_identity()
        .map_err(|_| "changed actual base")?;
    let generation = f
        .service
        .durable
        .as_ref()
        .ok_or("actual durable")?
        .generation();
    assert!(
        f.service
            .commit_namespace_seal_publication(proof, |_, _| Ok(()))
            .is_err()
    );
    assert!(
        f.service
            .current_state_identity()
            .map_err(|_| "unchanged changed-base")?
            == identity
    );
    assert_eq!(
        f.service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let actual = f.service.state.as_ref().ok_or("preserved current graph")?;
    assert_original_sdk_and_storage(actual, &f.logical, &f.credential)?;
    assert!(!actual.namespace_is_sealed(NS));
    Ok(())
}
#[test]
fn namespace109_authenticated_seal_rejects_retired_original_slot_and_expired_request() -> TestResult
{
    let (mut f, _) = fixture_with_owner(true)?;
    let source = f.service.state.clone().ok_or("actual loaded independent")?;
    let proof = f
        .service
        .prepare_namespace_seal_publication(&source, NS)
        .map_err(|_| "actual original slot seal evidence")?;
    let identity = f
        .service
        .current_state_identity()
        .map_err(|_| "original base")?;
    let generation = f
        .service
        .durable
        .as_ref()
        .ok_or("actual durable")?
        .generation();
    f.service.namespace_runtime.close(NS);
    assert!(
        f.service
            .commit_namespace_seal_publication(proof, |_, _| Ok(()))
            .is_err()
    );
    assert!(
        f.service
            .current_state_identity()
            .map_err(|_| "still original base")?
            == identity
    );
    assert_eq!(
        f.service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert!(!f.service.namespace_runtime.is_loaded(NS));
    let other = fixture()?;
    let expired = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .ok_or("past deadline")?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(expired);
    assert!(
        other
            .service
            .prepare_namespace_seal_publication(
                other
                    .service
                    .state
                    .as_ref()
                    .ok_or("actual expired source")?,
                NS,
            )
            .is_err()
    );
    assert!(!other.service.namespace_runtime.is_loaded(NS));
    Ok(())
}
#[test]
fn namespace109_authenticated_seal_rejects_real_same_node_new_ha_term() -> TestResult {
    let mut f = fixture()?;
    let cluster_id = f.service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = crate::ha::snapshot_test_support::Cluster::new(
        &f.directory.path.join("seal-raft"),
        &cluster_id,
    )?;
    f.service.ha = Some(Arc::clone(&cluster.processes[0]));
    f.service
        .sync_from_ha()
        .map_err(|_| "actual initial HA publication")?;
    let source = f.service.state.clone().ok_or("actual HA source")?;
    let proof = f
        .service
        .prepare_namespace_seal_publication(&source, NS)
        .map_err(|_| "actual ReadIndex seal evidence")?;
    let original = cluster.processes[0]
        .lock()
        .map_err(|_| "original leader")?
        .leader_status()
        .map_err(|_| "original role")?;
    let successor = cluster.processes[0]
        .lock()
        .map_err(|_| "original process")?
        .step_down()
        .map_err(|_| "actual first handoff")?;
    {
        let process = cluster.processes[(successor - 1) as usize]
            .lock()
            .map_err(|_| "actual successor")?;
        assert_eq!(process.step_down().map_err(|_| "actual second handoff")?, 1);
    }
    let returned = cluster.processes[0]
        .lock()
        .map_err(|_| "actual returned process")?
        .leader_status()
        .map_err(|_| "actual returned role")?;
    assert!(
        returned.local_is_leader
            && returned.local_id == original.local_id
            && returned.term > original.term
    );
    let identity = f
        .service
        .current_state_identity()
        .map_err(|_| "actual base")?;
    let generation = f.service.durable.as_ref().ok_or("durable")?.generation();
    assert!(
        f.service
            .commit_namespace_seal_publication(proof, |_, _| Ok(()))
            .is_err()
    );
    assert!(
        f.service
            .current_state_identity()
            .map_err(|_| "unchanged base")?
            == identity
    );
    assert_eq!(
        f.service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_original_sdk_and_storage(
        f.service.state.as_ref().ok_or("preserved SDK")?,
        &f.logical,
        &f.credential,
    )?;
    assert!(!f.service.namespace_runtime.is_loaded(NS));
    Ok(())
}

#[test]
fn namespace109_authenticated_seal_rejects_changed_ciphertext_and_resource_cells() -> TestResult {
    for cells in [false, true] {
        let mut f = fixture()?;
        let original = f.service.state.clone().ok_or("actual original graph")?;
        let mut proof = f
            .service
            .prepare_namespace_seal_publication(&original, NS)
            .map_err(|_| "genuine authenticated seal proof")?;
        proof
            .check_original_custody()
            .map_err(|_| "genuine live proof")?;
        proof
            .corrupt_physical_owner_for_test(cells)
            .map_err(|_| "actual ciphertext or cell changed")?;
        let identity = f
            .service
            .current_state_identity()
            .map_err(|_| "original identity")?;
        let generation = f
            .service
            .durable
            .as_ref()
            .ok_or("actual durable")?
            .generation();
        assert!(
            f.service
                .commit_namespace_seal_publication(proof, |_, _| Ok(()))
                .is_err()
        );
        assert!(
            f.service
                .current_state_identity()
                .map_err(|_| "same original identity")?
                == identity
        );
        assert_eq!(
            f.service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert_original_sdk_and_storage(
            f.service.state.as_ref().ok_or("original SDK")?,
            &f.logical,
            &f.credential,
        )?;
        assert!(!f.service.namespace_runtime.is_loaded(NS));
    }
    Ok(())
}

#[test]
fn namespace109_authenticated_seal_rejects_original_captured_deadline_after_proof() -> TestResult {
    let (mut f, _) = fixture_with_owner(true)?;
    begin(&mut f)?;
    assert!(crate::request_deadline::current().is_none());
    let original = f
        .service
        .state
        .clone()
        .ok_or("actual loaded original graph")?;
    let identity = f
        .service
        .current_state_identity()
        .map_err(|_| "original identity")?;
    let generation = f
        .service
        .durable
        .as_ref()
        .ok_or("actual durable")?
        .generation();
    let owner_bytes = owner_store::serialize_owner(&original)?;
    let jobs = original.namespaces.deletions.clone();
    assert!(!original.namespace_is_sealed(NS));
    assert!(f.service.namespace_runtime.is_loaded(NS));
    assert_original_sdk_and_storage(&original, &f.logical, &f.credential)?;

    // Capture the real request deadline while it is still live. The same
    // affine proof must retain it after the original thread-local scope ends.
    let deadline = Instant::now() + Duration::from_secs(2);
    let proof = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        assert_eq!(crate::request_deadline::current(), Some(deadline));
        let proof = f
            .service
            .prepare_namespace_seal_publication(&original, NS)
            .map_err(|_| "actual full proof captured under original live deadline")?;
        proof
            .check_original_custody()
            .map_err(|_| "actual original proof is live")?;
        proof
    };
    assert!(crate::request_deadline::current().is_none());
    proof
        .check_original_custody()
        .map_err(|_| "same captured proof remains live after original scope ends")?;
    assert!(Instant::now() < deadline);
    // No new deadline scope is entered and neither clock nor proof is rearmed.
    std::thread::sleep(
        deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
    );
    assert!(Instant::now() >= deadline);
    assert!(crate::request_deadline::current().is_none());
    let expired = proof
        .check_original_custody()
        .err()
        .ok_or("same captured proof must reject after original deadline")?;
    assert_eq!(expired.status, 503);
    let before_publish = std::cell::Cell::new(false);
    let failure = f
        .service
        .commit_namespace_seal_publication(proof, |_, _| {
            before_publish.set(true);
            Ok(())
        })
        .err()
        .ok_or("same original expired proof must not publish")?;
    assert_eq!(failure.status, 503);
    assert!(!before_publish.get());
    assert!(
        f.service
            .current_state_identity()
            .map_err(|_| "unchanged identity")?
            == identity
    );
    assert_eq!(
        f.service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let actual = f.service.state.as_ref().ok_or("unchanged original graph")?;
    assert!(!actual.namespace_is_sealed(NS));
    assert!(f.service.namespace_runtime.is_loaded(NS));
    assert!(actual.namespaces.deletions == jobs);
    let actual_bytes = owner_store::serialize_owner(actual)?;
    assert!(&*actual_bytes == &*owner_bytes);
    assert_original_sdk_and_storage(actual, &f.logical, &f.credential)?;
    assert!(
        f.service.pending_sdk_request.is_none() && f.service.pending_sdk_auth_request.is_none()
    );
    Ok(())
}

// This direct route control excludes the general HTTP terminal-clock audit.
// It tests that the seal operation itself cannot protect/publish/unload taint.
fn namespace_route_with_original_clock(
    f: &mut Fixture,
    path: &str,
    body: &Value,
) -> TestResult<Response> {
    let original = clock()?;
    let state = f.service.state.clone().ok_or("actual route state")?;
    let mut entrance_auth = state.auth.clone();
    let principal = entrance_auth.authenticate_from_observed(
        &f.token,
        AuthorityTime::Precise(original.observed_at()?),
        None,
    )?;
    let started = original.started();
    let _deadline =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let _publication = external_pki::PublicationClockScope::enter(
        original.admitted_at().duration_since_epoch(),
        started,
    );
    let request = RequestView {
        method: "POST",
        path,
        namespace: "",
        token: &f.token,
        body,
        now: original.admitted_at().duration_since_epoch().as_secs(),
        admission_started: started,
        token_clock: Some(original),
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    Ok(f.service.namespace_route(state, Some(principal), &request))
}
#[test]
fn namespace109_public_tainted_seal400_preserves_full_sdk_jobs_owner_slots_and_durable_root()
-> TestResult {
    for independent in [false, true] {
        let (mut f, _) = fixture_with_owner(independent)?;
        begin(&mut f)?;
        let state = f.service.state.as_ref().ok_or("actual tainted original")?;
        assert!(state.namespace_is_tainted(NS));
        let full = owner_store::serialize_owner(state)?;
        let identity = f
            .service
            .current_state_identity()
            .map_err(|_| "actual original identity")?;
        let generation = f
            .service
            .durable
            .as_ref()
            .ok_or("actual durable")?
            .generation();
        let loaded = f.service.namespace_runtime.is_loaded(NS);
        let progress = f.service.namespace_runtime.status(state, NS);
        let response =
            namespace_route_with_original_clock(&mut f, "sys/namespaces/retire/seal", &json!({}))?;
        assert_eq!(response.status, 400);
        assert_eq!(
            response.body["errors"][0],
            "unable to seal tainted namespace"
        );
        let current = f.service.state.as_ref().ok_or("actual preserved state")?;
        let after = owner_store::serialize_owner(current)?;
        assert!(&*after == &*full);
        assert!(
            f.service
                .current_state_identity()
                .map_err(|_| "actual preserved identity")?
                == identity
        );
        assert_eq!(
            f.service
                .durable
                .as_ref()
                .ok_or("actual durable")?
                .generation(),
            generation
        );
        assert!(f.service.namespace_runtime.is_loaded(NS) == loaded);
        let after_progress = f.service.namespace_runtime.status(current, NS);
        match (progress, after_progress) {
            (Ok(before), Ok(after)) => {
                assert!(before.status == after.status && before.body == after.body)
            }
            (Err(before), Err(after)) => {
                assert!(before.status == after.status && before.body == after.body)
            }
            _ => return Err("actual namespace progress owner changed".into()),
        }
        assert_original_sdk_and_storage(current, &f.logical, &f.credential)?;
        current
            .validate_format()
            .map_err(|_| "actual preserved full graph")?;
    }
    Ok(())
}

#[test]
fn namespace109_ordinary_unseal_keeps_primary_nonempty400_and_emptykey500_without_publication()
-> TestResult {
    let mut f = fixture()?;
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("actual live namespace")?
            .namespace_is_tainted(NS)
    );
    let actual_root_key = f.key.clone();
    for (body, status, fixed_error) in [
        (
            json!({"key": actual_root_key}),
            400,
            "namespace is not sealable",
        ),
        (json!({}), 500, "provided key is empty"),
    ] {
        let before = f.service.state.as_ref().ok_or("actual inherited source")?;
        let full = owner_store::serialize_owner(before)?;
        let identity = f
            .service
            .current_state_identity()
            .map_err(|_| "actual original identity")?;
        let generation = f
            .service
            .durable
            .as_ref()
            .ok_or("actual durable")?
            .generation();
        let loaded = f.service.namespace_runtime.is_loaded(NS);
        let response =
            namespace_route_with_original_clock(&mut f, "sys/namespaces/retire/unseal", &body)?;
        assert_eq!(response.status, status);
        assert_eq!(response.body["errors"][0], fixed_error);
        let current = f
            .service
            .state
            .as_ref()
            .ok_or("actual unchanged inherited graph")?;
        let after = owner_store::serialize_owner(current)?;
        assert!(&*after == &*full);
        assert!(
            f.service
                .current_state_identity()
                .map_err(|_| "actual unchanged identity")?
                == identity
        );
        assert_eq!(
            f.service
                .durable
                .as_ref()
                .ok_or("actual durable")?
                .generation(),
            generation
        );
        assert!(f.service.namespace_runtime.is_loaded(NS) == loaded);
        assert_original_sdk_and_storage(current, &f.logical, &f.credential)?;
        current
            .validate_format()
            .map_err(|_| "actual unchanged graph")?;
    }
    Ok(())
}
