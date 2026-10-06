use super::super::durable_tests::{mount, publish};
use super::*;
use crate::engines::sdk_lease::Grant;
use crate::service::tests::{Root, bootstrap, call};
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
