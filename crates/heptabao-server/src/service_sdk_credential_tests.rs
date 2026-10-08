use super::super::durable_tests::{mount, publish};
use super::super::{Context, Transaction};
use super::*;
use crate::engines::sdk_lease::Grant;
use crate::service::tests::{Root, bootstrap, call};
use std::collections::VecDeque;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn registered(
    candidate: &mut State,
    root: &str,
    binding: &Binding,
) -> Result<Record, Box<dyn std::error::Error>> {
    let accepted = Timestamp::checked(100, 200_000_000)?;
    let at = Timestamp::checked(100, 300_000_000)?;
    let actor =
        candidate
            .auth
            .authenticate_from_observed(root, AuthorityTime::Precise(accepted), None)?;
    let entry = candidate
        .auth
        .admitted_standard_sdk_lease_issuer_observed(&actor, "", AuthorityTime::Precise(accepted))?
        .ok_or("actual accepted issuer")?;
    let mut lease = Lease::new(
        LeaseBinding {
            id: "auth/sdk/record/credential-owned".into(),
            namespace: String::new(),
            cluster: candidate.cluster_id.clone(),
            mount: "auth/sdk/".into(),
            path: "auth/sdk/record".into(),
            backend: binding.clone(),
            issuer: entry.issuer.owner.clone(),
        },
        Grant {
            issued: at,
            ttl_ns: 30_000_000_000,
            max_ttl_ns: 60_000_000_000,
            renewable: true,
            secret: json!({"internal_data":{"real":"credential"},"LeaseID":"","lease":30_000_000_000u64,"max_ttl":60_000_000_000u64,"renewable":true}),
            data: json!({"value":"actual encrypted auth-owned lease"}),
        },
    )?;
    lease.register(Registration::from_entry(
        &entry,
        accepted,
        at,
        false,
        &candidate.auth,
        "",
        Some(0),
    )?)?;
    candidate.auth.observe_sdk_auth_clock(at);
    Ok(Record::new(lease, None))
}
#[test]
fn sdk_credential102_encrypted_reopen_lookup_and_snapshot_downgrade() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, root) = bootstrap(&mut service)?;
    let previous = service.state.clone().ok_or("previous")?;
    let backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let mut candidate = previous.clone();
    let backend = mount(&mut candidate, &root)?;
    let record = registered(&mut candidate, &root, &backend)?;
    let id = record.id.clone();
    candidate.auth.store_sdk_credential(record)?;
    publish(&mut service, candidate)?;
    let actual = service.state.as_ref().ok_or("actual")?;
    assert_eq!(actual.schema, SDK_BATCH_CREDENTIAL_SECRET_STATE_SCHEMA);
    assert!(actual.auth.sdk_credential_owners().len() == 1);
    assert!(Service::validate_snapshot_protected_floor(actual, &previous).is_err());
    assert!(service.prepare_snapshot_restore(&backup).is_err());
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let state = reopened.state.as_ref().ok_or("reopened")?;
    let record = state
        .auth
        .sdk_credential_record("", &id)
        .ok_or("real decrypted credential record")?;
    assert_eq!(record.backend, backend);
    assert_eq!(record.lookup(Timestamp::checked(101, 0)?)?["ttl"], 29);
    assert!(record.lookup(Timestamp::checked(131, 0)?).is_err());
    assert!(state.engines.sdk_lease("", &id).is_none());
    Ok(())
}
#[test]
fn sdk_credential102_retained_provenance_rejects_removal_and_foreign_backend() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let backend = mount(&mut candidate, &root)?;
    let record = registered(&mut candidate, &root, &backend)?;
    candidate.auth.store_sdk_credential(record.clone())?;
    publish(&mut service, candidate)?;
    let current = service.state.clone().ok_or("current")?;
    let mut expanded = record.clone();
    expanded.max_ttl_ns += 1;
    let mut changed = current.clone();
    assert!(changed.auth.store_sdk_credential(expanded).is_err());
    let renewed_at = Timestamp::checked(110, 0)?;
    let mut renewed = record.clone();
    renewed.renew(Grant {
        issued: renewed_at,
        ttl_ns: 20_000_000_000,
        max_ttl_ns: 60_000_000_000,
        renewable: true,
        secret: record.callback(),
        data: record.response_data(),
    })?;
    let mut candidate = current.clone();
    candidate.auth.observe_sdk_auth_clock(renewed_at);
    candidate.auth.store_sdk_credential(renewed.clone())?;
    publish(&mut service, candidate)?;
    let current = service.state.clone().ok_or("actual renewed")?;
    for rollback in [None, Some(Timestamp::checked(109, 0)?)] {
        let mut bad = renewed.clone();
        bad.renewed = rollback;
        let mut changed = current.clone();
        assert!(changed.auth.store_sdk_credential(bad).is_err());
    }
    let record = renewed;
    let mut changed = current.clone();
    let mut bad = record.clone();
    bad.registration = None;
    assert!(changed.auth.store_sdk_credential(bad).is_err());
    let mut changed = current.clone();
    let mut value = serde_json::to_value(&changed.auth)?;
    value
        .as_object_mut()
        .ok_or("auth object")?
        .remove("sdk_credential_leases");
    changed.auth = serde_json::from_value::<AuthState>(value)?.into();
    assert!(changed.validate_publication_schema(Some(&current)).is_err());
    let mut bad = record.clone();
    bad.cluster = "foreign cluster".into();
    let mut changed = current.clone();
    assert!(changed.auth.store_sdk_credential(bad).is_err());
    let mut revoked = record.clone();
    revoked.revoke();
    let mut changed = current.clone();
    changed.auth.store_sdk_credential(revoked)?;
    publish(&mut service, changed)?;
    let retired = service.state.as_ref().ok_or("retired")?;
    assert_eq!(retired.schema, SDK_BATCH_CREDENTIAL_SECRET_STATE_SCHEMA);
    assert!(retired.auth.has_sdk_credential_state());
    assert!(
        retired
            .auth
            .sdk_credential_record("", &record.id)
            .ok_or("retained")?
            .lookup(Timestamp::checked(101, 0)?)
            .is_err()
    );
    let mut resurrection = retired.clone();
    assert!(resurrection.auth.store_sdk_credential(record).is_err());
    Ok(())
}

#[test]
fn sdk_credential102_requested_renewal_increment_persists_exact_ttl() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, root) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let backend = mount(&mut candidate, &root)?;
    let record = registered(&mut candidate, &root, &backend)?;
    let id = record.id.clone();
    candidate.auth.store_sdk_credential(record.clone())?;
    publish(&mut service, candidate)?;
    let at = Timestamp::checked(110, 0)?;
    let mut renewed = record.clone();
    let grant = super::super::super::secret_lease::renewal_grant(
        record.callback(),
        record.response_data(),
        at,
        10_000_000_000,
    )
    .map_err(|response| format!("renewal grant status {}", response.status))?;
    renewed.renew(grant)?;
    assert_eq!(renewed.public_duration(at)?, 10);
    assert_eq!(renewed.callback()["lease"], 10_000_000_000u64);
    let mut candidate = service.state.clone().ok_or("published issue")?;
    candidate.auth.observe_sdk_auth_clock(at);
    candidate.auth.store_sdk_credential(renewed)?;
    publish(&mut service, candidate)?;
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let restored = reopened
        .state
        .as_ref()
        .ok_or("reopened")?
        .auth
        .sdk_credential_record("", &id)
        .ok_or("renewed record")?;
    assert_eq!(restored.lookup(Timestamp::checked(111, 0)?)?["ttl"], 9);
    assert!(restored.lookup(Timestamp::checked(120, 0)?).is_err());
    assert_eq!(restored.callback()["lease"], 10_000_000_000u64);
    Ok(())
}

type RetirementFixture = (Root, Service, super::super::Plan, String, Record);
fn retirement_terminal_fixture() -> Result<RetirementFixture, Box<dyn std::error::Error>> {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let mut state = service.state.clone().ok_or("state")?;
    let binding = mount(&mut state, &root)?;
    let mut record = registered(&mut state, &root, &binding)?;
    record.phase = Phase::PendingRevoke;
    state.auth.store_sdk_credential(record.clone())?;
    let job = "11111111111111111111111111111111".to_owned();
    let at = Timestamp::checked(100, 300_000_000)?;
    state.auth.begin_sdk_auth_retirement(
        job.clone(),
        &state.cluster_id,
        binding.clone(),
        at,
        service.request_fingerprint("DELETE", "sys/auth/credential", "", &root),
    )?;
    publish(&mut service, state)?;
    let mut state = service.state.clone().ok_or("queued state")?;
    state
        .auth
        .attempt_sdk_auth_retirement_resource(&job, &record.id, at)?;
    publish(&mut service, state)?;
    let mut state = service.state.clone().ok_or("attempted state")?;
    record.revoke();
    state.auth.store_sdk_credential(record.clone())?;
    state
        .auth
        .complete_sdk_auth_retirement_resource(&job, &record.id, at)?;
    publish(&mut service, state)?;
    let clock = RequestClock::anchored(Duration::new(100, 400_000_000), Instant::now())?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        clock.started() + Duration::from_secs(4),
    );
    let mut state = service.state.clone().ok_or("actual state")?;
    let principal = state.auth.authenticate_from_observed(
        &root,
        AuthorityTime::Precise(clock.observed_at()?),
        None,
    )?;
    // Commit the actual fixture entrance observation before minting its caller.
    publish(&mut service, state.clone())?;
    let body = json!({});
    let request = RequestView {
        namespace: "",
        method: "DELETE",
        path: "sys/auth/sdk",
        token: &root,
        body: &body,
        now: 100,
        admission_started: clock.started(),
        token_clock: Some(clock),
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    let caller = plugin::PluginResponseAuthority::new(
        principal,
        &state,
        &request,
        "delete",
        true,
        &service.unseal_nonce,
    )
    .with_sdk_clock();
    let context = Context {
        namespace: String::new(),
        incarnation: state.namespaces.incarnation(""),
        delivery: namespace_runtime::DeliveryBinding::capture(&state, ""),
        cluster: state.cluster_id.clone(),
        activation: service.unseal_nonce.clone(),
        ha: service.ha.clone(),
        clock,
        namespace_required: true,
    };
    let mut removed = state.clone();
    let response = removed
        .auth
        .handle_with_connection_clock(
            Some(caller.principal()),
            "",
            "DELETE",
            "sys/auth/sdk",
            &body,
            AuthorityTime::Precise(clock.observed_at()?),
            Some(clock),
            None,
            None,
        )?
        .ok_or("native removal")?;
    assert_eq!(response.status, 204);
    let at = clock.observed_at()?;
    removed.auth.observe_sdk_auth_clock(at);
    removed.auth.complete_sdk_auth_retirement_mount(&job, at)?;
    publish(&mut service, removed)?;
    let actual = service.state.as_ref().ok_or("removed state")?;
    let (sender, _receiver) = mpsc::sync_channel(1);
    let control = Arc::new(Control {
        sender,
        busy: Arc::new(AtomicBool::new(false)),
        fenced: Arc::new(AtomicBool::new(true)),
        retiring: AtomicBool::new(true),
    });
    let bytes = Zeroizing::new(
        crate::secret_serde::to_vec(&record, 512 * 1024).map_err(|_| "fixture record encoding")?,
    );
    let plan = super::super::Plan {
        context,
        binding,
        paths: None,
        caller: Mutex::new(Some(caller)),
        admission: None,
        control,
        transaction: Mutex::new(Transaction {
            namespace_original: None,
            auth: actual.auth.clone(),
            identity: service.current_state_identity().map_err(|_| "identity")?,
        }),
        operation: "revoke".into(),
        path: "record".into(),
        data: json!({}),
        deadline: clock.started() + Duration::from_secs(4),
        renewal: Mutex::new(None),
        lease: Mutex::new(None),
        cleanup: Mutex::new(None),
        private_retirement: Mutex::new(None),
        private_cleanup: Mutex::new(None),
        retirement: Some(Mutex::new(super::super::retirement::Retirement {
            remaining: VecDeque::new(),
            job,
            sent: BTreeSet::new(),
            body: json!({}),
            completed: Some(vec![(record.id.clone(), crypto::digest(&bytes))]),
            native: None,
        })),
        namespace_cleanup: false,
    };
    Ok((files, service, plan, root, record))
}
#[test]
fn sdk_auth_retirement_native_completed_gate_rejects_remount_and_changed_retained_record()
-> TestResult {
    let (_files, mut service, plan, _root, record) = retirement_terminal_fixture()?;
    service
        .sdk_auth_gate(&plan)
        .map_err(|e| format!("initial gate {} {}", e.status, e.body))?;
    let removed = service.state.clone().ok_or("removed")?;
    let mut altered = removed.clone();
    let mut altered_record = record.clone();
    altered_record.max_ttl_ns -= 1;
    altered.auth.store_sdk_credential(altered_record)?;
    // The new durable receipt rejects altered terminal bytes at publication.
    assert!(publish(&mut service, altered).is_err());
    // New independent native mount instance also cannot borrow the old removal.
    let (_files, mut service, plan, root, _) = retirement_terminal_fixture()?;
    let mut changed = service.state.clone().ok_or("removed")?;
    mount(&mut changed, &root)?;
    publish(&mut service, changed)?;
    assert!(service.sdk_auth_gate(&plan).is_err());
    Ok(())
}
#[test]
fn sdk_auth_retirement_completed_original_deadline_and_seal_withhold_metadata() -> TestResult {
    let (_files, mut service, mut plan, _, _) = retirement_terminal_fixture()?;
    plan.deadline = Instant::now() + Duration::from_millis(20);
    std::thread::sleep(Duration::from_millis(25));
    let mut response = Response::ok(json!({"data":{"must":"withhold"}}));
    response.response_headers = ResponseHeaders::from_sdk(
        Some(&json!({"X-SDK-Secret":["withheld-header"]})),
        &["X-SDK-Secret".into()],
    )
    .map_err(|()| "headers")?;
    let response = service.complete_sdk_auth_delivery(&plan, response, "retirement-deadline");
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.response_headers.is_empty());
    assert!(response.consistency_index.is_none());
    let (_files, mut service, plan, _, _) = retirement_terminal_fixture()?;
    service.state = None;
    assert!(service.sdk_auth_gate(&plan).is_err());
    Ok(())
}

#[test]
fn sdk_combined_lease_list_retains_live_owner_and_rejects_revoke_or_removed_mount() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let mut state = service.state.clone().ok_or("state")?;
    let binding = mount(&mut state, &root)?;
    let record = registered(&mut state, &root, &binding)?;
    state.auth.store_sdk_credential(record.clone())?;
    let listing = CredentialList {
        binding: binding.clone(),
        prefix: "auth/sdk/record".into(),
        keys: state
            .auth
            .sdk_credential_lease_keys(&binding, "auth/sdk/record")?,
    };
    assert_eq!(listing.keys, BTreeSet::from(["credential-owned".into()]));
    listing
        .check(&state.auth)
        .map_err(|e| format!("live list {}", e.status))?;
    let mut renewed = record.clone();
    renewed.renew(Grant {
        issued: Timestamp::checked(101, 0)?,
        ttl_ns: 10_000_000_000,
        max_ttl_ns: 60_000_000_000,
        renewable: true,
        secret: record.callback(),
        data: record.response_data(),
    })?;
    state
        .auth
        .observe_sdk_auth_clock(Timestamp::checked(101, 0)?);
    state.auth.store_sdk_credential(renewed.clone())?;
    listing
        .check(&state.auth)
        .map_err(|e| format!("renewed list {}", e.status))?;
    renewed.revoke();
    state.auth.store_sdk_credential(renewed)?;
    assert!(listing.check(&state.auth).is_err());
    let empty = CredentialList {
        binding: binding.clone(),
        prefix: "auth/sdk/record".into(),
        keys: BTreeSet::new(),
    };
    empty
        .check(&state.auth)
        .map_err(|e| format!("empty live list {}", e.status))?;
    let clock = RequestClock::anchored(Duration::new(101, 100_000_000), Instant::now())?;
    let at = AuthorityTime::Precise(clock.observed_at()?);
    let actor = state.auth.authenticate_from_observed(&root, at, None)?;
    let response = state
        .auth
        .handle_with_connection_clock(
            Some(&actor),
            "",
            "DELETE",
            "sys/auth/sdk",
            &json!({}),
            at,
            Some(clock),
            None,
            None,
        )?
        .ok_or("native delete")?;
    assert_eq!(response.status, 204);
    assert!(empty.check(&state.auth).is_err());
    Ok(())
}

type QueuedFixture = (Root, Service, String, Binding, Record, String);
fn retirement_queued_fixture() -> Result<QueuedFixture, Box<dyn std::error::Error>> {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, root) = bootstrap(&mut service)?;
    let mut state = service.state.clone().ok_or("state")?;
    let binding = mount(&mut state, &root)?;
    let mut record = registered(&mut state, &root, &binding)?;
    record.phase = Phase::PendingRevoke;
    state.auth.store_sdk_credential(record.clone())?;
    let job = "77777777777777777777777777777777".to_owned();
    state.auth.begin_sdk_auth_retirement(
        job.clone(),
        &state.cluster_id,
        binding.clone(),
        Timestamp::checked(100, 300_000_000)?,
        service.request_fingerprint("DELETE", "sys/auth/credential", "", &root),
    )?;
    publish(&mut service, state)?;
    Ok((files, service, job, binding, record, key))
}
#[test]
fn sdk_auth_retirement107_none_preserves_legacy_bytes() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let mut state = service.state.clone().ok_or("state")?;
    mount(&mut state, &root)?;
    let before = Zeroizing::new(
        crate::secret_serde::to_vec(&state.auth, 4 * 1024 * 1024)
            .map_err(|_| "fixture encoding")?,
    );
    state
        .auth
        .validate_sdk_auth_retirement_state(None, &state.cluster_id, |ns| {
            state.namespaces.incarnation(ns)
        })?;
    let after = Zeroizing::new(
        crate::secret_serde::to_vec(&state.auth, 4 * 1024 * 1024)
            .map_err(|_| "fixture encoding")?,
    );
    assert!(before.as_slice() == after.as_slice());
    assert!(!state.auth.has_sdk_auth_retirement_state());
    Ok(())
}
#[test]
fn sdk_auth_retirement107_queued_encrypted_reopen_and_protected_restore() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, root) = bootstrap(&mut service)?;
    let previous = service.state.clone().ok_or("previous")?;
    let old_backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let mut state = previous.clone();
    let binding = mount(&mut state, &root)?;
    let mut record = registered(&mut state, &root, &binding)?;
    record.phase = Phase::PendingRevoke;
    state.auth.store_sdk_credential(record.clone())?;
    let job = "88888888888888888888888888888888".to_owned();
    state.auth.begin_sdk_auth_retirement(
        job.clone(),
        &state.cluster_id,
        binding.clone(),
        Timestamp::checked(100, 300_000_000)?,
        service.request_fingerprint("DELETE", "sys/auth/credential", "", &root),
    )?;
    publish(&mut service, state)?;
    let actual = service.state.as_ref().ok_or("actual")?;
    assert_eq!(actual.schema, SDK_AUTH_RETIREMENT_STATE_SCHEMA);
    assert!(actual.auth.sdk_auth_retirement_tainted(&binding));
    assert!(
        actual
            .auth
            .next_sdk_credential_cleanup(Timestamp::checked(200, 0)?, None)?
            .is_none()
    );
    assert!(Service::validate_snapshot_protected_floor(actual, &previous).is_err());
    assert!(service.prepare_snapshot_restore(&old_backup).is_err());
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let state = reopened.state.as_ref().ok_or("reopened")?;
    assert!(state.auth.sdk_auth_retirement_tainted(&binding));
    assert!(
        state
            .auth
            .sdk_auth_retirement_job(&job)
            .ok_or("retained queued job")?
            .phase(&record.id)
            == Some(crate::auth::sdk_retirement::ResourcePhase::Queued)
    );
    assert_eq!(state.auth.sdk_credential_owners().len(), 1);
    Ok(())
}
#[test]
fn sdk_auth_retirement107_attempted_reopen_cannot_rearm() -> TestResult {
    let (files, mut service, job, binding, record, key) = retirement_queued_fixture()?;
    let mut state = service.state.clone().ok_or("queued")?;
    let at = Timestamp::checked(100, 400_000_000)?;
    state.auth.observe_sdk_auth_clock(at);
    state
        .auth
        .attempt_sdk_auth_retirement_resource(&job, &record.id, at)?;
    publish(&mut service, state)?;
    let attempted = service.state.clone().ok_or("attempted")?;
    let mut bad = attempted.clone();
    assert!(
        bad.auth
            .attempt_sdk_auth_retirement_resource(&job, &record.id, at)
            .is_err()
    );
    bad.auth
        .sdk_auth_retirement_tamper_for_test(&job, "rollback")?;
    assert!(bad.validate_publication_schema(Some(&attempted)).is_err());
    // Drop/reopen retains the exact durable Attempted value; no caller is serialized.
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let state = reopened.state.as_ref().ok_or("reopened")?;
    assert!(
        state
            .auth
            .sdk_auth_retirement_job(&job)
            .ok_or("job")?
            .phase(&record.id)
            == Some(crate::auth::sdk_retirement::ResourcePhase::Attempted)
    );
    assert!(state.auth.sdk_auth_retirement_tainted(&binding));
    assert!(
        state
            .auth
            .next_sdk_credential_cleanup(Timestamp::checked(200, 0)?, None)?
            .is_none()
    );
    Ok(())
}
#[test]
fn sdk_auth_retirement107_successor_and_catalog_mirror_loss_rejected() -> TestResult {
    let (_files, service, job, _binding, _record, _key) = retirement_queued_fixture()?;
    let current = service.state.clone().ok_or("current")?;
    for mode in ["remove", "mirror", "accepted", "resource", "request"] {
        let mut bad = current.clone();
        bad.auth.sdk_auth_retirement_tamper_for_test(&job, mode)?;
        assert!(
            bad.validate_publication_schema(Some(&current)).is_err(),
            "closed mutation kind {mode}"
        );
    }
    let mut downgraded = current.clone();
    downgraded.schema = SDK_AUTH_RETIREMENT_STATE_SCHEMA - 1;
    assert!(
        downgraded
            .validate_publication_schema(Some(&current))
            .is_err()
    );
    Ok(())
}
#[test]
fn sdk_auth_retirement107_terminal_resources_do_not_clear_mount_taint() -> TestResult {
    let (_files, mut service, job, binding, mut record, _key) = retirement_queued_fixture()?;
    let mut state = service.state.clone().ok_or("queued")?;
    let at = Timestamp::checked(100, 400_000_000)?;
    state.auth.observe_sdk_auth_clock(at);
    state
        .auth
        .attempt_sdk_auth_retirement_resource(&job, &record.id, at)?;
    publish(&mut service, state)?;
    let mut state = service.state.clone().ok_or("attempted")?;
    record.revoke();
    state.auth.store_sdk_credential(record.clone())?;
    state
        .auth
        .complete_sdk_auth_retirement_resource(&job, &record.id, at)?;
    publish(&mut service, state)?;
    let state = service.state.as_ref().ok_or("terminal resources")?;
    assert!(state.auth.sdk_auth_retirement_tainted(&binding));
    assert!(
        !state
            .auth
            .sdk_auth_retirement_job(&job)
            .ok_or("job")?
            .completed()
    );
    let mut bad = state.clone();
    assert!(
        bad.auth
            .complete_sdk_auth_retirement_mount(&job, at)
            .is_err()
    );
    Ok(())
}
#[test]
fn sdk_auth_retirement107_empty_job_requires_real_mount_removal() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let mut state = service.state.clone().ok_or("state")?;
    let binding = mount(&mut state, &root)?;
    let at = Timestamp::checked(100, 300_000_000)?;
    state.auth.observe_sdk_auth_clock(at);
    let job = "99999999999999999999999999999999".to_owned();
    state.auth.begin_sdk_auth_retirement(
        job.clone(),
        &state.cluster_id,
        binding.clone(),
        at,
        service.request_fingerprint("DELETE", "sys/auth/credential", "", &root),
    )?;
    publish(&mut service, state)?;
    let state = service.state.as_ref().ok_or("published empty job")?;
    assert!(state.auth.sdk_auth_retirement_tainted(&binding));
    assert!(
        !state
            .auth
            .sdk_auth_retirement_job(&job)
            .ok_or("job")?
            .completed()
    );
    let mut bad = state.clone();
    assert!(
        bad.auth
            .complete_sdk_auth_retirement_mount(&job, at)
            .is_err()
    );
    assert!(state.auth.sdk_credential_owners().is_empty());
    Ok(())
}

#[test]
fn sdk_credential102_unrelated_native_kv_remount_preserves_registered_credential() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let mut state = service.state.clone().ok_or("state")?;
    let binding = mount(&mut state, &root)?;
    let record = registered(&mut state, &root, &binding)?;
    let id = record.id.clone();
    state.auth.store_sdk_credential(record.clone())?;
    publish(&mut service, state)?;
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .sdk_credential_namespace_pending("")
    );
    let precise = RequestClock::anchored(Duration::new(100, 400_000_000), Instant::now())?;
    let create = crate::service::native_remount::tests::call_and_complete(
        &mut service,
        precise,
        "POST",
        "sys/mounts/unrelated-native",
        &root,
        json!({"type":"kv"}),
    );
    assert_eq!(create.status, 204);
    let ack = crate::service::native_remount::tests::call_and_complete(
        &mut service,
        precise,
        "POST",
        "sys/remount",
        &root,
        json!({"from":"unrelated-native","to":"moved-native"}),
    );
    assert_eq!(ack.status, 200);
    let actual = service.state.as_ref().ok_or("state")?;
    let retained = actual
        .auth
        .sdk_credential_record("", &id)
        .ok_or("actual retained record")?;
    let before = Zeroizing::new(
        crate::secret_serde::to_vec(&record, 512 * 1024)
            .map_err(|_| "registered record encoding")?,
    );
    let after = Zeroizing::new(
        crate::secret_serde::to_vec(&retained, 512 * 1024)
            .map_err(|_| "retained record encoding")?,
    );
    assert!(before.as_slice() == after.as_slice());
    assert_eq!(retained.backend, binding);
    assert_eq!(retained.lookup(Timestamp::checked(101, 0)?)?["ttl"], 29);
    assert!(actual.auth.sdk_credential_namespace_pending(""));
    Ok(())
}

#[test]
fn sdk_auth_retirement107_native_selection_blocks_attempted_job_and_queued_sibling_after_reopen()
-> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, root) = bootstrap(&mut service)?;
    let mut state = service.state.clone().ok_or("state")?;
    let binding = mount(&mut state, &root)?;
    let mut first = registered(&mut state, &root, &binding)?;
    first.phase = Phase::PendingRevoke;
    let mut sibling = first.clone();
    sibling.id = "auth/sdk/record/queued-sibling".into();
    state.auth.store_sdk_credential(first.clone())?;
    state.auth.store_sdk_credential(sibling.clone())?;
    let job = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
    let at = Timestamp::checked(100, 300_000_000)?;
    state.auth.begin_sdk_auth_retirement(
        job.clone(),
        &state.cluster_id,
        binding,
        at,
        service.request_fingerprint("DELETE", "sys/auth/sdk", "", &root),
    )?;
    publish(&mut service, state)?;
    let mut selections = service
        .state
        .as_ref()
        .ok_or("queued")?
        .auth
        .sdk_auth_retirement_recovery_selections()?;
    assert_eq!(selections.len(), 1);
    let mut selected = selections.pop().ok_or("native selection")?;
    assert_eq!(
        selected
            .queued_records(&service.state.as_ref().ok_or("state")?.auth)?
            .len(),
        2
    );
    let mut next = service.state.clone().ok_or("queued")?;
    next.auth
        .attempt_sdk_auth_retirement_resource(&job, &first.id, at)?;
    assert!(
        selected
            .published_attempt(
                &service.state.as_ref().ok_or("old actual")?.auth,
                &first.id,
                at
            )
            .is_err()
    );
    publish(&mut service, next)?;
    selected.published_attempt(
        &service.state.as_ref().ok_or("actual attempted")?.auth,
        &first.id,
        at,
    )?;
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let state = reopened.state.as_ref().ok_or("reopened")?;
    assert!(
        state
            .auth
            .sdk_auth_retirement_recovery_selections()?
            .is_empty()
    );
    assert!(
        state
            .auth
            .sdk_auth_retirement_job(&job)
            .ok_or("job")?
            .phase(&sibling.id)
            == Some(crate::auth::sdk_retirement::ResourcePhase::Queued)
    );
    Ok(())
}

#[test]
fn sdk_auth_retirement107_native_terminal_selection_removes_actual_storage_and_reopens_completed()
-> TestResult {
    let (files, mut service, job, binding, mut record, key) = retirement_queued_fixture()?;
    let at = Timestamp::checked(100, 400_000_000)?;
    let mut state = service.state.clone().ok_or("queued")?;
    state.auth.observe_sdk_auth_clock(at);
    state
        .auth
        .attempt_sdk_auth_retirement_resource(&job, &record.id, at)?;
    publish(&mut service, state)?;
    let mut state = service.state.clone().ok_or("attempted")?;
    record.revoke();
    state.auth.store_sdk_credential(record.clone())?;
    state
        .auth
        .complete_sdk_auth_retirement_resource(&job, &record.id, at)?;
    publish(&mut service, state)?;
    drop(service);
    let mut service = files.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.clone()})
        )
        .status,
        200
    );
    let mut selections = service
        .state
        .as_ref()
        .ok_or("terminal reopened")?
        .auth
        .sdk_auth_retirement_recovery_selections()?;
    let mut selected = selections.pop().ok_or("terminal native selection")?;
    assert!(
        selected
            .queued_records(&service.state.as_ref().ok_or("terminal")?.auth)?
            .is_empty()
    );
    let mut next = service.state.clone().ok_or("terminal")?;
    next.auth.remove_sdk_auth_retirement_mount(&selected, at)?;
    assert!(
        selected
            .published_removal(&service.state.as_ref().ok_or("old actual")?.auth, at)
            .is_err()
    );
    publish(&mut service, next)?;
    selected.published_removal(&service.state.as_ref().ok_or("removed")?.auth, at)?;
    assert!(selected.completed());
    assert!(service.sdk_hosts.is_empty());
    assert!(
        service
            .state
            .as_ref()
            .ok_or("removed")?
            .auth
            .sdk_auth_storage_get(&binding, "probe")
            .is_err()
    );
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let state = reopened.state.as_ref().ok_or("completed reopened")?;
    assert!(
        state
            .auth
            .sdk_auth_retirement_job(&job)
            .ok_or("completed")?
            .completed()
    );
    assert!(!state.auth.sdk_auth_owned_mount("", "sdk"));
    assert!(
        state
            .auth
            .sdk_auth_retirement_recovery_selections()?
            .is_empty()
    );
    assert!(
        state
            .auth
            .sdk_credential_record("", &record.id)
            .ok_or("retained102")?
            .phase
            == Phase::Revoked
    );
    Ok(())
}

type NativeRecoveryFixture = (Root, Service, String, Binding, Vec<Record>, String, String);
fn native_recovery_fixture(
    two: bool,
    issuer: bool,
) -> Result<NativeRecoveryFixture, Box<dyn std::error::Error>> {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, root) = bootstrap(&mut service)?;
    let mut state = service.state.clone().ok_or("state")?;
    let binding = mount(&mut state, &root)?;
    state.auth.sdk_auth_storage_put(
        &binding,
        crate::auth::sdk::Entry {
            key: "native-final/probe".into(),
            value: Zeroizing::new(b"actual retained encrypted SDK cell".to_vec()),
            seal_wrap: true,
        },
    )?;
    if issuer {
        let login_clock = RequestClock::anchored(Duration::new(100, 100_000_000), Instant::now())?;
        let response = state.auth.finish_sdk_auth_login(
            &binding, "login",
            &json!({"alias":{"name":"native-recovery-issued-owner"},"lease":30_000_000_000u64,"max_ttl":60_000_000_000u64}),
            login_clock,
        )?;
        assert_eq!(response.status, 200);
        assert!(
            state.auth.sdk_auth_retirement_has_live_issuer(
                &binding,
                Timestamp::checked(100, 300_000_000)?
            )
        );
    }
    let mut first = registered(&mut state, &root, &binding)?;
    first.phase = Phase::PendingRevoke;
    let mut records = vec![first];
    if two {
        let mut sibling = records[0].clone();
        sibling.id = "auth/sdk/record/native-queued-sibling".into();
        records.push(sibling);
    }
    for record in &records {
        state.auth.store_sdk_credential(record.clone())?;
    }
    let job = "cccccccccccccccccccccccccccccccc".to_owned();
    let retirement_request = service.request_fingerprint("DELETE", "sys/auth/sdk", "", &root);
    if !issuer {
        state.auth.begin_sdk_auth_retirement(
            job.clone(),
            &state.cluster_id,
            binding.clone(),
            Timestamp::checked(100, 300_000_000)?,
            retirement_request.clone(),
        )?;
    }
    publish(&mut service, state)?;
    Ok((files, service, job, binding, records, key, retirement_request))
}
fn native_recovery_configured_reopen(
    files: &Root,
    key: &str,
) -> Result<Service, Box<dyn std::error::Error>> {
    let mut service = files.service()?;
    let plugin_directory = files.path.join("native-recovery-plugins");
    let runtime_directory = files.path.join("native-recovery-runtime");
    for directory in [&plugin_directory, &runtime_directory] {
        if !directory.exists() {
            private_directory(directory)?;
        }
    }
    // These service tests deliberately configure no transport executable.
    // Final-only work must still succeed; a queued staging failure must leave
    // real durable Attempted. Actual SDK callbacks have separate native tests.
    service.install_sdk_backend(Some(super::super::super::SdkBackendConfig {
        plugin_directory,
        runtime_directory,
        companion: files.path.join("intentionally-absent-native-companion"),
        companion_sha256: "a".repeat(64),
        timeout_ms: 5_000,
    }))?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    Ok(service)
}
fn native_recovery_clock() -> Result<RequestClock, Box<dyn std::error::Error>> {
    Ok(RequestClock::anchored(
        Duration::new(101, 0),
        Instant::now(),
    )?)
}
fn native_recovery_terminal(service: &mut Service, job: &str, records: &[Record]) -> TestResult {
    let at = Timestamp::checked(100, 400_000_000)?;
    for record in records {
        let mut state = service.state.clone().ok_or("queued")?;
        state.auth.observe_sdk_auth_clock(at);
        state
            .auth
            .attempt_sdk_auth_retirement_resource(job, &record.id, at)?;
        publish(service, state)?;
        let mut state = service.state.clone().ok_or("attempted")?;
        let mut revoked = record.clone();
        revoked.revoke();
        state.auth.store_sdk_credential(revoked)?;
        state
            .auth
            .complete_sdk_auth_retirement_resource(job, &record.id, at)?;
        publish(service, state)?;
    }
    Ok(())
}
#[test]
fn sdk_auth_retirement107_native_service_terminal_reopen_executes_final_without_transport()
-> TestResult {
    let (files, mut service, job, binding, records, key, _request) = native_recovery_fixture(true, false)?;
    native_recovery_terminal(&mut service, &job, &records)?;
    drop(service);
    let mut service = native_recovery_configured_reopen(&files, &key)?;
    assert_eq!(
        service
            .state
            .as_ref()
            .ok_or("reopened")?
            .auth
            .sdk_auth_storage_get(&binding, "native-final/probe")?
            .ok_or("actual encrypted cell")?
            .value
            .as_slice(),
        b"actual retained encrypted SDK cell"
    );
    let work = service
        .prepare_sdk_auth_retirement_recovery(native_recovery_clock()?)
        .map_err(|_| "actual terminal service preparation")?
        .ok_or("real final task")?;
    assert!(matches!(&work, super::super::RecoveryWork::Final(_)));
    assert!(service.sdk_hosts.is_empty());
    assert!(service.pending_sdk_auth_request.is_none());
    let shared = Arc::new(Mutex::new(service));
    work.execute(&shared)
        .map_err(|_| "actual final state publication")?;
    {
        let service = shared.lock().map_err(|_| "writer")?;
        let state = service.state.as_ref().ok_or("actual removed")?;
        assert!(
            state
                .auth
                .sdk_auth_retirement_job(&job)
                .ok_or("job")?
                .completed()
        );
        assert!(
            state
                .auth
                .sdk_auth_storage_get(&binding, "native-final/probe")
                .is_err()
        );
        assert!(!state.auth.sdk_auth_owned_mount("", "sdk"));
        assert!(service.sdk_hosts.is_empty());
        assert!(service.pending_sdk_auth_request.is_none());
        for record in &records {
            assert!(
                state
                    .auth
                    .sdk_credential_record("", &record.id)
                    .ok_or("retained102")?
                    .phase
                    == Phase::Revoked
            );
        }
    }
    drop(shared);
    let mut reopened = native_recovery_configured_reopen(&files, &key)?;
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("completed reopened")?
            .auth
            .sdk_auth_retirement_job(&job)
            .ok_or("job")?
            .completed()
    );
    assert!(
        reopened
            .prepare_sdk_auth_retirement_recovery(native_recovery_clock()?)
            .map_err(|_| "completed skip")?
            .is_none()
    );
    Ok(())
}
#[test]
fn sdk_auth_retirement107_native_service_missing_transport_retains_attempt_before_setup_and_skips_sibling()
-> TestResult {
    let (files, service, job, binding, records, key, _request) = native_recovery_fixture(true, false)?;
    drop(service);
    let mut service = native_recovery_configured_reopen(&files, &key)?;
    let work = service
        .prepare_sdk_auth_retirement_recovery(native_recovery_clock()?)
        .map_err(|_| "actual missing transport preparation")?
        .ok_or("actual missing transport callback")?;
    assert!(matches!(&work, super::super::RecoveryWork::Callback(_)));
    assert_eq!(service.sdk_hosts.len(), 1);
    let host_key = super::super::sdk_auth_key(
        &service.state.as_ref().ok_or("callback state")?.cluster_id, &binding,
    ).map_err(|_| "actual callback key")?;
    let owner = service.sdk_hosts.get(&host_key).cloned().ok_or("actual callback owner")?;
    assert!(service.state.as_ref().ok_or("retiring state")?
        .auth.sdk_auth_retirement_tainted(&binding));
    assert!(service.pending_sdk_auth_request.is_none());
    let attempted_identity = service.current_state_identity().map_err(|_| "attempt identity")?;
    let attempted_generation = service.durable.as_ref().ok_or("attempt durable")?.generation();
    let prepared = service.state.as_ref().ok_or("actual prepared attempt")?;
    let prepared_job = prepared.auth.sdk_auth_retirement_job(&job).ok_or("prepared job")?;
    assert!(prepared_job.phase(&records[0].id)
        == Some(crate::auth::sdk_retirement::ResourcePhase::Attempted));
    assert!(prepared_job.phase(&records[1].id)
        == Some(crate::auth::sdk_retirement::ResourcePhase::Queued));
    let shared = Arc::new(Mutex::new(service));
    let failure = work.execute(&shared).err().ok_or("missing companion must reject actual invoke")?;
    assert_eq!(failure.status, 503);
    assert!(failure.body.get("data").is_none());
    let service = Arc::try_unwrap(shared)
        .map_err(|_| "actual callback service still shared")?
        .into_inner().map_err(|_| "actual callback writer")?;
    assert_eq!(service.current_state_identity().map_err(|_| "failed callback identity")?,
        attempted_identity);
    assert_eq!(service.durable.as_ref().ok_or("failed callback durable")?.generation(),
        attempted_generation);
    let actual = service.state.as_ref().ok_or("actual attempted")?;
    let saved = actual.auth.sdk_auth_retirement_job(&job).ok_or("job")?;
    assert!(
        saved.phase(&records[0].id) == Some(crate::auth::sdk_retirement::ResourcePhase::Attempted)
    );
    assert!(
        saved.phase(&records[1].id) == Some(crate::auth::sdk_retirement::ResourcePhase::Queued)
    );
    assert!(!saved.completed());
    assert!(
        actual
            .auth
            .sdk_credential_record("", &records[0].id)
            .ok_or("retained")?
            .phase
            == Phase::PendingRevoke
    );
    assert!(
        actual
            .auth
            .sdk_auth_storage_get(&binding, "native-final/probe")?
            .is_some()
    );
    assert_eq!(service.sdk_hosts.len(), 1);
    assert!(service.sdk_hosts.get(&host_key).is_some_and(|current| Arc::ptr_eq(current, &owner)));
    assert!(service.state.as_ref().ok_or("retained retirement")?
        .auth.sdk_auth_retirement_tainted(&binding));
    assert!(service.pending_sdk_auth_request.is_none());
    drop(owner);
    drop(service);
    let mut service = native_recovery_configured_reopen(&files, &key)?;
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert!(
        service
            .prepare_sdk_auth_retirement_recovery(native_recovery_clock()?)
            .map_err(|_| "unknown entire job skip")?
            .is_none()
    );
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert!(service.sdk_hosts.is_empty());
    assert!(service.pending_sdk_auth_request.is_none());
    Ok(())
}
#[test]
fn sdk_auth_retirement107_native_service_busy_owner_dispatches_no_setup_or_phase() -> TestResult {
    let (files, service, job, binding, records, key, _request) = native_recovery_fixture(true, false)?;
    drop(service);
    let mut service = native_recovery_configured_reopen(&files, &key)?;
    let (sender, commands) = mpsc::sync_channel(1);
    let control = Arc::new(super::super::super::Control {
        sender,
        busy: Arc::new(AtomicBool::new(true)),
        fenced: Arc::new(AtomicBool::new(false)),
        retiring: AtomicBool::new(false),
    });
    let host_key =
        super::super::sdk_auth_key(&service.state.as_ref().ok_or("state")?.cluster_id, &binding)
            .map_err(|_| "actual host key")?;
    service.sdk_hosts.insert(host_key, Arc::clone(&control));
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert!(
        service
            .prepare_sdk_auth_retirement_recovery(native_recovery_clock()?)
            .map_err(|_| "busy skip")?
            .is_none()
    );
    assert!(matches!(
        commands.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert!(!control.retiring.load(Ordering::Acquire));
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let saved = service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .sdk_auth_retirement_job(&job)
        .ok_or("job")?;
    for record in &records {
        assert!(
            saved.phase(&record.id) == Some(crate::auth::sdk_retirement::ResourcePhase::Queued)
        );
    }
    assert!(service.pending_sdk_auth_request.is_none());
    Ok(())
}
#[test]
fn sdk_auth_retirement107_native_service_live_sdk_issued_owner_admission409_before_attempt_no_job_and_no_publication()
-> TestResult {
    let (files, service, job, binding, records, key, request) = native_recovery_fixture(false, true)?;
    drop(service);
    let mut service = native_recovery_configured_reopen(&files, &key)?;
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let mut candidate = service.state.clone().ok_or("admission candidate")?;
    let original_auth = serde_json::to_vec(&candidate.auth)?;
    let error = candidate.auth.begin_sdk_auth_retirement(
        job.clone(), &candidate.cluster_id, binding.clone(),
        Timestamp::checked(101, 0)?, request,
    ).err().ok_or("live issuer must veto actual admission")?;
    assert_eq!(error.status, 409);
    assert!(serde_json::to_vec(&candidate.auth)? == original_auth);
    assert!(candidate.auth.sdk_auth_retirement_job(&job).is_none());
    assert!(
        service
            .prepare_sdk_auth_retirement_recovery(native_recovery_clock()?)
            .map_err(|_| "no admitted job must have no recovery work")?
            .is_none()
    );
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let state = service.state.as_ref().ok_or("state")?;
    assert!(
        state
            .auth
            .sdk_auth_retirement_has_live_issuer(&binding, Timestamp::checked(101, 0)?)
    );
    assert!(state.auth.sdk_auth_retirement_job(&job).is_none());
    assert!(state.auth.sdk_auth_owned_mount("", "sdk"));
    assert!(state.auth.sdk_auth_storage_get(&binding, "native-final/probe")?.is_some());
    for record in &records {
        assert!(state.auth.sdk_credential_record("", &record.id).ok_or("live owner retained record")?
            .phase == Phase::PendingRevoke);
    }
    assert!(service.sdk_hosts.is_empty());
    assert!(service.pending_sdk_auth_request.is_none());
    Ok(())
}
#[test]
fn sdk_auth_retirement107_native_service_expired_original_clock_never_restarts_budget() -> TestResult
{
    let (files, service, job, _, records, key, _request) = native_recovery_fixture(false, false)?;
    drop(service);
    let mut service = native_recovery_configured_reopen(&files, &key)?;
    let expired = RequestClock::anchored(
        Duration::new(101, 0),
        Instant::now()
            .checked_sub(Duration::from_secs(6))
            .ok_or("original instant")?,
    )?;
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert!(
        service
            .prepare_sdk_auth_retirement_recovery(expired)
            .is_err()
    );
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .sdk_auth_retirement_job(&job)
            .ok_or("job")?
            .phase(&records[0].id)
            == Some(crate::auth::sdk_retirement::ResourcePhase::Queued)
    );
    assert!(service.sdk_hosts.is_empty());
    assert!(service.pending_sdk_auth_request.is_none());
    Ok(())
}
#[test]
fn sdk_auth_retirement107_native_service_captured_final_rejects_real_ha_handoff() -> TestResult {
    let (files, mut service, job, binding, records, key, _request) = native_recovery_fixture(false, false)?;
    native_recovery_terminal(&mut service, &job, &records)?;
    drop(service);
    let mut service = native_recovery_configured_reopen(&files, &key)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&files.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    service
        .sync_from_ha()
        .map_err(|_| "real current HA prefix")?;
    let work = service
        .prepare_sdk_auth_retirement_recovery(native_recovery_clock()?)
        .map_err(|_| "current original leader final")?
        .ok_or("captured final")?;
    assert!(matches!(&work, super::super::RecoveryWork::Final(_)));
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
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
    let shared = Arc::new(Mutex::new(service));
    assert!(work.execute(&shared).is_err());
    let service = shared.lock().map_err(|_| "writer")?;
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let state = service.state.as_ref().ok_or("state")?;
    assert!(
        !state
            .auth
            .sdk_auth_retirement_job(&job)
            .ok_or("job")?
            .completed()
    );
    assert!(
        state
            .auth
            .sdk_auth_storage_get(&binding, "native-final/probe")?
            .is_some()
    );
    assert!(service.sdk_hosts.is_empty());
    assert!(service.pending_sdk_auth_request.is_none());
    Ok(())
}
