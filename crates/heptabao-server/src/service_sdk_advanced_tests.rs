//! Real native identity, encrypted State and Lease owners; no RPC fixture is
//! represented as a maintained provider process.
use super::durable_tests::{mount, publish};
use super::*;
use crate::engines::sdk_lease::{Binding as LeaseBinding, Grant, Lease};
use crate::engines::sdk_registration::Registration;
use crate::service::tests::{Root, bootstrap, call};
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn clock(seconds: u64, nanos: u32) -> Result<RequestClock, Box<dyn std::error::Error>> {
    Ok(RequestClock::anchored(
        Duration::new(seconds, nanos),
        Instant::now(),
    )?)
}
fn native_login(
    state: &mut State,
    binding: &Binding,
    payload: &Value,
    original: RequestClock,
) -> Result<AuthResponse, Box<dyn std::error::Error>> {
    let at = original.observed_at()?;
    let mut response = state
        .auth
        .finish_sdk_auth_login(binding, "login", payload, original)?;
    Service::finish_identity_response_observed(
        &mut state.auth,
        &mut state.engines,
        &mut response,
        &state.namespaces,
        "",
        at.seconds(),
        AuthorityTime::Precise(at),
    )
    .map_err(|_| "actual native identity finalizer")?;
    Ok(response)
}
fn bearer(response: &AuthResponse) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    Ok(Zeroizing::new(
        response.body["auth"]["client_token"]
            .as_str()
            .ok_or("actual bearer")?
            .into(),
    ))
}

#[test]
fn sdk126_actual_identity_and_encrypted_reopen_keep_reader_floor_and_retired_marker() -> TestResult
{
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let previous = service.state.clone().ok_or("state")?;
    let old_backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let mut candidate = previous.clone();
    let binding = mount(&mut candidate, &admin)?;
    let original = clock(100, 125_000_000)?;
    let response = native_login(
        &mut candidate,
        &binding,
        &json!({
            "alias":{"name":"alice"},"renewable":true,"period":600_000_000_000u64,
            "explicit_max_ttl":1_800_000_000_000u64,"bound_cidrs":["127.0.0.0/8"]
        }),
        original,
    )?;
    let raw = bearer(&response)?;
    let entity = response.body["auth"]["entity_id"]
        .as_str()
        .ok_or("native entity")?;
    assert!(!entity.is_empty());
    assert!(candidate.engines.identity_projection("", entity).is_ok());
    assert!(candidate.auth.sdk_auth_issued_live(&raw, original).is_ok());
    publish(&mut service, candidate)?;
    let current = service.state.clone().ok_or("published")?;
    assert_eq!(current.schema, SDK_ADVANCED_STATE_SCHEMA);
    assert!(current.auth.has_sdk_advanced_state());
    assert!(Service::validate_snapshot_protected_floor(&current, &previous).is_err());
    assert!(service.prepare_snapshot_restore(&old_backup).is_err());
    let mut lower = current.clone();
    lower.schema = 125;
    assert!(lower.validate_format().is_err());
    assert!(lower.validate_publication_schema(Some(&current)).is_err());
    let mut encoded = serde_json::to_value(&current.auth)?;
    encoded
        .as_object_mut()
        .ok_or("auth")?
        .remove("sdk_advanced_format");
    let mut torn = current.clone();
    torn.auth = serde_json::from_slice::<AuthState>(&serde_json::to_vec(&encoded)?)?.into();
    assert!(torn.validate_format().is_err());
    assert!(torn.validate_publication_schema(Some(&current)).is_err());
    let identity = service
        .current_state_identity()
        .map_err(|_| "encrypted identity")?;
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(
        call(&mut reopened, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let restored = reopened.state.as_ref().ok_or("reopened")?;
    assert_eq!(restored.schema, SDK_ADVANCED_STATE_SCHEMA);
    assert!(restored.auth.has_sdk_advanced_state());
    assert!(restored.auth.sdk_auth_issued_live(&raw, original).is_ok());
    assert!(restored.engines.identity_projection("", entity).is_ok());
    assert_eq!(
        reopened
            .current_state_identity()
            .map_err(|_| "reopened identity")?,
        identity
    );
    let mut retired = restored.clone();
    let at = original.observed_at()?;
    let root = retired
        .auth
        .authenticate_from_observed(&admin, AuthorityTime::Precise(at), None)?;
    let result = retired
        .auth
        .handle_with_connection_clock(
            Some(&root),
            "",
            "POST",
            "auth/token/revoke",
            &json!({"token":raw.as_str()}),
            AuthorityTime::Precise(at),
            Some(original),
            None,
            None,
        )?
        .ok_or("native revoke")?;
    assert_eq!(result.status, 204);
    assert!(retired.auth.sdk_auth_issued_live(&raw, original).is_err());
    publish(&mut reopened, retired)?;
    let retired = reopened.state.as_ref().ok_or("retired")?;
    assert_eq!(retired.schema, SDK_ADVANCED_STATE_SCHEMA);
    assert!(retired.auth.has_sdk_advanced_state());
    assert!(Service::validate_snapshot_protected_floor(retired, &previous).is_err());
    drop(reopened);
    let mut reopened = files.service()?;
    assert_eq!(
        call(&mut reopened, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let final_state = reopened.state.as_ref().ok_or("retirement reopened")?;
    assert!(final_state.auth.has_sdk_advanced_state());
    assert!(
        final_state
            .auth
            .sdk_auth_issued_live(&raw, original)
            .is_err()
    );
    Ok(())
}

#[test]
fn sdk126_actual_external_group_projection_renews_original_alias_and_removes_membership()
-> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let binding = mount(&mut candidate, &admin)?;
    let accessor = candidate.auth.mount_accessor("", "sdk")?;
    publish(&mut service, candidate)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/sdk-operators",
            &admin,
            json!({"policy":"path \"secret/operator\" { capabilities = [\"read\"] }"})
        )
        .status,
        204
    );
    let group = call(
        &mut service,
        "POST",
        "identity/group",
        &admin,
        json!({"name":"operators","type":"external","policies":["sdk-operators"]}),
    );
    assert_eq!(group.status, 200);
    let group_id = group.body["data"]["id"]
        .as_str()
        .ok_or("actual group")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "identity/group-alias",
            &admin,
            json!({"name":"operators","mount_accessor":accessor,"canonical_id":group_id})
        )
        .status,
        200
    );
    let mut candidate = service.state.clone().ok_or("configured identity")?;
    let original = clock(100, 200_000_000)?;
    let response = native_login(
        &mut candidate,
        &binding,
        &json!({
            "alias":{"name":"alice"},"renewable":true,"lease":10_000_000_000u64,
            "group_aliases":[{"name":"operators","mount_accessor":"foreign","namespace_id":"foreign"}]
        }),
        original,
    )?;
    let raw = bearer(&response)?;
    let entity = response.body["auth"]["entity_id"]
        .as_str()
        .ok_or("actual entity")?
        .to_owned();
    assert!(
        candidate
            .engines
            .identity_projection("", &entity)?
            .policies
            .contains("sdk-operators")
    );
    publish(&mut service, candidate)?;
    drop(service);
    let mut service = files.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let mut candidate = service.state.clone().ok_or("reopened")?;
    assert!(
        candidate
            .engines
            .identity_projection("", &entity)?
            .policies
            .contains("sdk-operators")
    );
    let renewal_clock = clock(101, 200_000_000)?;
    let at = renewal_clock.observed_at()?;
    let actor =
        candidate
            .auth
            .authenticate_from_observed(&admin, AuthorityTime::Precise(at), None)?;
    let target = candidate.auth.prepare_sdk_renewal(
        &actor,
        "",
        "auth/token/renew",
        &json!({"token":raw.as_str()}),
        &admin,
        renewal_clock,
    )?;
    let (input, _, _) = target.input(&candidate.auth, renewal_clock)?;
    assert_eq!(input["alias"]["name"], json!("alice"));
    // The actual original alias owns renewal. A foreign callback alias does not
    // select another entity, even when the provider returns an empty group set.
    let mut response = candidate.auth.finish_sdk_renewal(
        &target,
        &json!({
            "renewable":true,"lease":10_000_000_000u64,
            "alias":{"name":"foreign"},"group_aliases":[]
        }),
        renewal_clock,
    )?;
    Service::finish_identity_response_observed(
        &mut candidate.auth,
        &mut candidate.engines,
        &mut response,
        &candidate.namespaces,
        "",
        at.seconds(),
        AuthorityTime::Precise(at),
    )
    .map_err(|_| "actual renewed native identity")?;
    assert_eq!(response.body["auth"]["entity_id"], json!(entity));
    assert!(
        !candidate
            .engines
            .identity_projection("", &entity)?
            .policies
            .contains("sdk-operators")
    );
    assert_eq!(response.body["auth"]["client_token"], json!(raw.as_str()));
    publish(&mut service, candidate)?;
    drop(service);
    let mut service = files.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let current = service.state.as_ref().ok_or("final reopen")?;
    assert_eq!(current.schema, SDK_ADVANCED_STATE_SCHEMA);
    assert!(
        !current
            .engines
            .identity_projection("", &entity)?
            .policies
            .contains("sdk-operators")
    );
    Ok(())
}

#[test]
fn sdk126_sdk_batch_secret_registration_wrap_reopen_and_native_mount_retirement_stay_owned()
-> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let auth_binding = mount(&mut candidate, &admin)?;
    let original = clock(100, 200_000_000)?;
    let issued = native_login(
        &mut candidate,
        &auth_binding,
        &json!({
            "alias":{"name":"batch-user"},"lease":5_000_000_000u64,"token_type":2,
            "bound_cidrs":["127.0.0.0/8"]
        }),
        original,
    )?;
    let raw = bearer(&issued)?;
    let accepted = original.observed_at()?;
    let actor = candidate.auth.authenticate_from_observed(
        &raw,
        AuthorityTime::Precise(accepted),
        Some("127.0.0.1".parse()?),
    )?;
    let entry = candidate
        .auth
        .admitted_standard_sdk_lease_issuer_observed(&actor, "", AuthorityTime::Precise(accepted))?
        .ok_or("real authenticated batch entrance")?;
    assert!(entry.issuer.owner.batch_claims().is_some());
    let d = candidate
        .engines
        .register_sdk_descriptor(crate::engines::sdk::Descriptor {
            name: "batch_secret_probe".into(),
            version: "v0.0.1".into(),
            command: "probe".into(),
            args: vec![],
            sha256: "a".repeat(64),
            generation: 1,
        })?;
    candidate.engines.handle(
        "",
        "POST",
        "sys/mounts/sdk_secret",
        &json!({"type":"plugin","config":{"plugin_id":"batch_secret_probe"}}),
        100,
    )?;
    let backend = candidate.engines.bind_sdk_mount("", "sdk_secret/", &d)?;
    let registered = Timestamp::checked(100, 300_000_000)?;
    let mut lease = Lease::new(
        LeaseBinding {
            id: "sdk_secret/creds/registered-batch-owner".into(),
            namespace: String::new(),
            cluster: candidate.cluster_id.clone(),
            mount: "sdk_secret/".into(),
            path: "sdk_secret/creds".into(),
            backend: backend.clone(),
            issuer: entry.issuer.owner.clone(),
        },
        Grant {
            issued: registered,
            ttl_ns: 30_000_000_000,
            max_ttl_ns: 60_000_000_000,
            renewable: true,
            secret: json!({"internal_data":{"native":"batch-callback"},"lease":30_000_000_000u64,
            "max_ttl":60_000_000_000u64,"renewable":true}),
            data: json!({"value":"synthetic actual encrypted SDK record"}),
        },
    )?;
    lease.register(Registration::from_entry(
        &entry,
        accepted,
        registered,
        false,
        &candidate.auth,
        "",
        Some(0),
    )?)?;
    assert!(
        lease
            .registration
            .as_ref()
            .ok_or("registration")?
            .is_batch()
    );
    assert_eq!(
        lease.expires,
        entry.issuer.precise_expires_at.ok_or("batch expiry")?
    );
    let id = lease.id.clone();
    candidate.engines.observe_sdk_lease_clock(registered);
    candidate.engines.store_sdk_lease(lease.clone())?;
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xC7; 16]);
    let context = crate::auth::current_ingress().ok_or("real ingress scope")?;
    let body = json!({"lease_id":id,"lease_duration":lease.public_duration(registered)?,
        "renewable":lease.renewable,"data":lease.response_data()});
    let wrapped = candidate.auth.wrap_sdk_response(
        "",
        "sdk_secret/creds",
        2,
        &body,
        registered.seconds(),
        Some(&context),
    )?;
    candidate.auth.mark_sdk_advanced_state();
    let wrapper = Zeroizing::new(
        wrapped.body["wrap_info"]["token"]
            .as_str()
            .ok_or("native wrapper")?
            .to_owned(),
    );
    assert!(wrapped.body["data"].is_null());
    publish(&mut service, candidate)?;
    drop(service);
    let mut service = files.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let mut candidate = service.state.clone().ok_or("reopened")?;
    let record = candidate
        .engines
        .sdk_lease("", &id)
        .ok_or("encrypted SDK batch record")?;
    assert!(
        record
            .registration
            .as_ref()
            .ok_or("registration")?
            .is_batch()
    );
    assert!(record.callback()["internal_data"]["native"] == json!("batch-callback"));
    assert!(!record.parent_cleanup_required(&candidate.auth, Timestamp::checked(101, 0)?)?);
    assert!(record.lookup(Timestamp::checked(106, 0)?).is_err());
    assert!(
        candidate
            .auth
            .sdk_wrapped_auth_token(
                &wrapper,
                "",
                "sdk_secret/creds",
                AuthorityTime::Precise(Timestamp::checked(101, 0)?)
            )?
            .is_none()
    );
    let wrapper_actor = candidate.auth.authenticate_from_observed(
        &wrapper,
        AuthorityTime::Precise(Timestamp::checked(101, 0)?),
        None,
    )?;
    let unwrapped = candidate
        .auth
        .handle(
            Some(&wrapper_actor),
            "",
            "POST",
            "sys/wrapping/unwrap",
            &json!({}),
            101,
        )?
        .ok_or("actual unwrap")?;
    assert_eq!(unwrapped.body["lease_id"], json!(id));
    assert!(
        candidate
            .auth
            .authenticate_from_observed(
                &wrapper,
                AuthorityTime::Precise(Timestamp::checked(101, 0)?),
                None
            )
            .is_err()
    );
    let root = candidate.auth.authenticate_from_observed(
        &admin,
        AuthorityTime::Precise(Timestamp::checked(101, 0)?),
        None,
    )?;
    let removed = candidate
        .auth
        .handle(Some(&root), "", "DELETE", "sys/auth/sdk", &json!({}), 101)?
        .ok_or("native SDK auth mount removal")?;
    assert_eq!(removed.status, 204);
    assert!(record.parent_cleanup_required(&candidate.auth, Timestamp::checked(101, 0)?)?);
    assert!(
        candidate
            .auth
            .resolve_lease_owner_observed(
                &record.issuer,
                "",
                AuthorityTime::Precise(Timestamp::checked(101, 0)?)
            )
            .is_none()
    );
    let mut revoked = record.clone();
    revoked.revoke();
    candidate.engines.store_sdk_lease(revoked)?;
    publish(&mut service, candidate)?;
    let retired = service.state.as_ref().ok_or("retired")?;
    assert_eq!(retired.schema, SDK_ADVANCED_STATE_SCHEMA);
    assert!(retired.auth.has_sdk_advanced_state());
    assert!(
        retired
            .engines
            .sdk_lease("", &id)
            .ok_or("retained revoked record")?
            .lookup(Timestamp::checked(101, 0)?)
            .is_err()
    );
    Ok(())
}
