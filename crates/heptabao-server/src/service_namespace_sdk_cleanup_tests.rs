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
