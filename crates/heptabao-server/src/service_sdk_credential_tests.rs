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
    record.revoke();
    state.auth.store_sdk_credential(record.clone())?;
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
        retirement: Some(Mutex::new(super::super::retirement::Retirement {
            remaining: VecDeque::new(),
            body: json!({}),
            completed: Some(vec![(record.id.clone(), crypto::digest(&bytes))]),
        })),
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
    publish(&mut service, altered)?;
    assert!(service.sdk_auth_gate(&plan).is_err());
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
