//! Actual configured File owners and public requests. Detached corruptions at
//! the end prove rejection only; they never provide publication authority.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn request(
    service: &mut Service,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: Value,
) -> Response {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    service.handle_request(
        ServiceRequest::new(method, path, namespace, token, body)
            .with_origin_peer(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 14))),
    )
}

fn initialized(
    activate: bool,
) -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let mut response = request(
        &mut service,
        "POST",
        "sys/init",
        "",
        "",
        json!({"secret_shares":1, "secret_threshold":1}),
    );
    assert_eq!(response.status, 200);
    let key = Zeroizing::new(
        response.body["keys_base64"][0]
            .as_str()
            .ok_or("actual share")?
            .to_owned(),
    );
    let token = Zeroizing::new(
        response.body["root_token"]
            .as_str()
            .ok_or("actual root bearer")?
            .to_owned(),
    );
    erase_json(&mut response.body);
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        request(&mut service, "POST", "sys/init/ack", "", &token, json!({})).status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/retained",
            "",
            &token,
            json!({"type":"kv", "options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "retained/data/item",
            "",
            &token,
            json!({"data":{"value":"root-data-must-survive"}})
        )
        .status,
        200
    );
    if activate {
        activate_file(&mut service, &token)?;
    }
    Ok((files, service, key, token))
}

// Test-only low-disclosure observation. These read-only checks precede the
// unchanged request helper, so they cannot create or extend its 15 s budget.
fn observe_activation_state(stage: &'static str, service: &Service) {
    let state = service.state.as_ref();
    let fields = state.map(|state| {
        let paths = state
            .namespaces
            .entries
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        (
            state.schema,
            state.has_token_api_precision_state(),
            state.namespace_protected.is_some(),
            state.namespace_leases.is_empty(),
            state.validate_format().is_ok(),
            super::super::native_plain::profile(state).is_ok(),
            super::super::native_empty::require_catalog_profile(state).is_ok(),
            state.auth.native_plain_namespace_auth_profile(&paths),
            state.engines.native_plain_namespace_engine_profile(&paths),
            state.validate_namespace_batch_state().is_ok(),
            service.require_native_root_candidate(state).is_ok(),
            state.namespaces.entries.len(),
        )
    });
    let stored = service
        .durable
        .as_ref()
        .and_then(|durable| durable.get("system", "state").ok())
        .flatten();
    let source_format = match stored.as_ref() {
        None => "absent_or_unavailable",
        Some(bytes)
            if crate::state_record_root_v6::RecordStateRootV6::decode(bytes.expose()).is_ok() =>
        {
            "native_v6"
        }
        Some(bytes) if records::decode_root(bytes.expose()).is_ok_and(|root| root.is_some()) => {
            "records_v5"
        }
        Some(bytes)
            if owner_store::decode_manifest(bytes.expose()).is_ok_and(|root| root.is_some()) =>
        {
            "owners_v4"
        }
        Some(_) => "other_or_invalid",
    };
    let generation = service.durable.as_ref().map(|durable| durable.generation());
    eprintln!(
        "HB140-ACTIVATION stage={stage} state_loaded={} native_root={} record_root={} recovery_required={} audit_failed={} source_format={source_format} durable_generation={generation:?} fields={fields:?}",
        state.is_some(),
        service.native_root.is_some(),
        service.record_root.is_some(),
        service.recovery_required,
        service.audit_failed,
    );
}

fn activate_file(service: &mut Service, token: &str) -> TestResult {
    observe_activation_state("before", service);
    let started = Instant::now();
    // Exactly the original real mutation, once. The original helper captures
    // its own unchanged absolute 15 s deadline; there is no retry or fallback.
    let response = request(
        service,
        "POST",
        "sys/storage/native-v6/activate",
        "",
        token,
        json!({}),
    );
    let elapsed_us = started.elapsed().as_micros();
    observe_activation_state("after", service);
    let errors = response.body.get("errors").and_then(Value::as_array);
    let error = errors
        .and_then(|errors| errors.first())
        .and_then(Value::as_str);
    let code = match error {
        Some("native plain namespace ownership unavailable") => "plain_namespace_owner",
        Some("native empty namespace ownership unavailable") => "empty_namespace_owner",
        Some("native flat namespace retirement custody is invalid") => "flat_retirement_custody",
        Some("native V6 Service candidate publication rejected") => "native_publication",
        Some("native migration source or custody rejected") => "native_migration_source",
        Some("native V6 Service candidate custody or publication rejected") => "native_reader",
        Some("Token API observation floor was not committed") => "terminal_clock_floor",
        Some("trusted token clock is required") => "missing_trusted_clock",
        Some("native durable outcome unknown; reopen and reconcile; do not blindly retry") => {
            "native_outcome_unknown"
        }
        None => "no_string_error",
        Some(_) => "other_fixed_error_hash_only",
    };
    let error_sha = error.map(|text| hex(&crypto::digest(text.as_bytes())));
    eprintln!(
        "HB140-ACTIVATION stage=response status={} elapsed_us={elapsed_us} error_code={code} error_count={:?} error_sha={error_sha:?}",
        response.status,
        errors.map(Vec::len),
    );
    assert_eq!(response.status, 204);
    assert_eq!(
        service
            .native_root
            .as_ref()
            .ok_or("actual native root")?
            .reader_floor
            .native_kv2_format,
        2
    );
    assert!(service.record_root.is_none() && !service.recovery_required);
    Ok(())
}

fn reopen(files: &Root, key: &str) -> TestResult<Service> {
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key})
        )
        .status,
        200
    );
    assert!(service.native_root.is_some() && service.record_root.is_none());
    assert!(!service.recovery_required);
    Ok(service)
}

fn create(service: &mut Service, token: &str, name: &str) -> TestResult<Value> {
    let response = request(
        service,
        "POST",
        &format!("sys/namespaces/{name}"),
        "",
        token,
        json!({}),
    );
    assert_eq!(response.status, 200, "{}", response.body["errors"]);
    Ok(response
        .body
        .get("data")
        .filter(|value| value.is_object())
        .ok_or("actual namespace metadata")?
        .clone())
}

fn quota(service: &mut Service, token: &str, name: &str, path: &str) {
    assert_eq!(
        request(
            service,
            "POST",
            &format!("sys/quotas/rate-limit/{name}"),
            "",
            token,
            json!({"path":path, "rate":10000, "interval":"1h"})
        )
        .status,
        204
    );
}

fn quota_read(service: &mut Service, token: &str, name: &str) -> Response {
    request(
        service,
        "GET",
        &format!("sys/quotas/rate-limit/{name}"),
        "",
        token,
        json!({}),
    )
}

fn snapshot(
    service: &mut Service,
    token: &str,
    input: Option<&[u8]>,
) -> TestResult<(Response, Option<Zeroizing<Vec<u8>>>)> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let method = if input.is_some() { "POST" } else { "GET" };
    let admission = service.begin_native_snapshot_before(
        ServiceRequest::new(method, "sys/storage/raft/snapshot", "", token, json!({})),
        deadline,
    );
    match admission {
        NativeSnapshotAdmission::Execute(RequestExecution::External(mut pending)) => {
            let mut reader = io::Cursor::new(input.unwrap_or_default());
            let (observation, file) = pending.execute_snapshot_transfer(&mut reader);
            let response = service.finish_external_request(*pending, observation);
            assert!(service.native_request_binding.is_none());
            let bytes = if let Some(mut file) = file {
                file.rewind_checked()?;
                let mut bytes = Zeroizing::new(Vec::new());
                file.read_to_end(&mut bytes)?;
                Some(bytes)
            } else {
                None
            };
            Ok((response, bytes))
        }
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            Ok((response, None))
        }
        NativeSnapshotAdmission::Redirect(_) => Err("configured File cannot redirect".into()),
        #[cfg(feature = "native-v6-ha")]
        NativeSnapshotAdmission::Forward(_) => Err("configured File cannot forward".into()),
    }
}

fn assert_retired(service: &Service, namespace: &str, next: u64) -> TestResult {
    let state = service.state.as_ref().ok_or("actual state")?;
    // The actual current child factory adds 144; retirement's independent
    // marker and paired incarnation history remain mandatory below.
    assert_eq!(state.schema, NAMESPACE_FACTORY_STATE_SCHEMA);
    assert_eq!(state.namespaces.native_flat_retirement_format, Some(1));
    assert_eq!(
        state.namespaces.next_incarnation.get(namespace),
        Some(&next)
    );
    assert!(state.validate_native_flat_retirement_state(None).is_ok());
    assert!(state.validate_namespace_batch_state().is_ok());
    assert!(super::super::native_plain::profile(state).is_ok());
    assert!(state.validate_format().is_ok());
    assert_eq!(
        service
            .native_root
            .as_ref()
            .ok_or("native root")?
            .reader_floor
            .minimum_state_schema,
        NAMESPACE_FACTORY_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn native_flat_retirement140_file_quota_delete_recreate_cold_preserves_foreign_graphs() -> TestResult
{
    let (files, mut service, key, token) = initialized(true)?;
    let original = create(&mut service, &token, "retired")?;
    create(&mut service, &token, "sibling")?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/data",
            "sibling",
            &token,
            json!({"type":"kv", "options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "data/data/item",
            "sibling",
            &token,
            json!({"data":{"value":"sibling-data-must-survive"}})
        )
        .status,
        200
    );
    quota(&mut service, &token, "retired-only", "retired/");
    quota(&mut service, &token, "root-only", "retained/");
    quota(&mut service, &token, "sibling-only", "sibling/data/");
    let root_quota = quota_read(&mut service, &token, "root-only").body["data"].clone();
    let sibling_quota = quota_read(&mut service, &token, "sibling-only").body["data"].clone();
    let bound = super::super::native_plain::PlainNamespaceScope::capture(
        service.state.as_ref().ok_or("actual state")?,
        "retired",
    )
    .map_err(|_| "actual namespace binding")?;
    let prior = service
        .native_root
        .as_ref()
        .ok_or("source native root")?
        .clone();
    let response = request(
        &mut service,
        "DELETE",
        "sys/namespaces/retired",
        "",
        &token,
        json!({}),
    );
    assert_eq!(response.status, 200, "{}", response.body["errors"]);
    assert_retired(&service, "retired", 2)?;
    assert!(
        bound
            .check(service.state.as_ref().ok_or("retired state")?)
            .is_err()
    );
    let next = service
        .native_root
        .as_ref()
        .ok_or("published native root")?;
    assert!(next.kv2 == prior.kv2);
    assert_eq!(next.kv1, prior.kv1);
    assert!(next.object_address_key.0 == prior.object_address_key.0);
    for (old, new) in prior.owners.iter().zip(&next.owners) {
        assert_eq!(old.domain, new.domain);
        if !matches!(
            old.domain,
            crate::state_record_root_v6::OwnerDomain::Auth
                | crate::state_record_root_v6::OwnerDomain::Engines
                | crate::state_record_root_v6::OwnerDomain::Namespaces
        ) {
            assert_eq!(old.owner, new.owner);
        }
    }
    assert_eq!(quota_read(&mut service, &token, "retired-only").status, 404);
    assert_eq!(
        quota_read(&mut service, &token, "root-only").body["data"],
        root_quota
    );
    assert_eq!(
        quota_read(&mut service, &token, "sibling-only").body["data"],
        sibling_quota
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/namespaces/retired",
            "",
            &token,
            json!({})
        )
        .status,
        404
    );
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_retired(&service, "retired", 2)?;
    assert_eq!(quota_read(&mut service, &token, "retired-only").status, 404);
    assert_eq!(
        quota_read(&mut service, &token, "root-only").body["data"],
        root_quota
    );
    let recreated = create(&mut service, &token, "retired")?;
    assert!(recreated["id"] != original["id"]);
    assert_eq!(
        service
            .state
            .as_ref()
            .ok_or("recreated state")?
            .namespaces
            .incarnation("retired"),
        Some(2)
    );
    assert_retired(&service, "retired", 3)?;
    assert!(
        bound
            .check(service.state.as_ref().ok_or("recreated state")?)
            .is_err()
    );
    assert_eq!(quota_read(&mut service, &token, "retired-only").status, 404);
    let root_read = request(
        &mut service,
        "GET",
        "retained/data/item",
        "",
        &token,
        json!({}),
    );
    assert_eq!(root_read.status, 200);
    assert_eq!(
        root_read.body["data"]["data"]["value"],
        "root-data-must-survive"
    );
    let sibling_read = request(
        &mut service,
        "GET",
        "data/data/item",
        "sibling",
        &token,
        json!({}),
    );
    assert_eq!(sibling_read.status, 200);
    assert_eq!(
        sibling_read.body["data"]["data"]["value"],
        "sibling-data-must-survive"
    );
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_retired(&service, "retired", 3)?;
    let read = request(
        &mut service,
        "GET",
        "sys/namespaces/retired",
        "",
        &token,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"], recreated);
    assert!(
        bound
            .check(service.state.as_ref().ok_or("cold recreated state")?)
            .is_err()
    );
    assert_eq!(
        quota_read(&mut service, &token, "sibling-only").body["data"],
        sibling_quota
    );
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn native_flat_retirement140_file_snapshot_rejects_old_floor_and_old_incarnation() -> TestResult {
    let (files, mut service, key, token) = initialized(true)?;
    create(&mut service, &token, "retired")?;
    quota(&mut service, &token, "child", "retired/");
    assert_eq!(
        service.state.as_ref().ok_or("pre-retirement state")?.schema,
        NAMESPACE_FACTORY_STATE_SCHEMA
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("pre-retirement state")?
            .namespaces
            .native_flat_retirement_format
            .is_none()
    );
    let (response, old) = snapshot(&mut service, &token, None)?;
    assert_eq!(response.status, 200);
    let old = old.ok_or("actual pre-retirement archive")?;
    assert_eq!(
        request(
            &mut service,
            "DELETE",
            "sys/namespaces/retired",
            "",
            &token,
            json!({})
        )
        .status,
        200
    );
    let (response, retired) = snapshot(&mut service, &token, None)?;
    assert_eq!(response.status, 200);
    let retired = retired.ok_or("actual retired archive")?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "retained/data/item",
            "",
            &token,
            json!({"options":{"cas":1}, "data":{"value":"post-archive"}})
        )
        .status,
        200
    );
    let (rejected, _) = snapshot(&mut service, &token, Some(&old))?;
    assert_eq!(rejected.status, 400);
    assert_eq!(quota_read(&mut service, &token, "child").status, 404);
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/namespaces/retired",
            "",
            &token,
            json!({})
        )
        .status,
        404
    );
    let (restored, _) = snapshot(&mut service, &token, Some(&retired))?;
    assert_eq!(restored.status, 200, "{}", restored.body["errors"]);
    assert_retired(&service, "retired", 2)?;
    let read = request(
        &mut service,
        "GET",
        "retained/data/item",
        "",
        &token,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["data"]["value"], "root-data-must-survive");
    let current = create(&mut service, &token, "retired")?;
    assert_retired(&service, "retired", 3)?;
    let (rejected, _) = snapshot(&mut service, &token, Some(&retired))?;
    assert_eq!(
        rejected.status, 400,
        "same schema must retain the real incarnation frontier"
    );
    let read = request(
        &mut service,
        "GET",
        "sys/namespaces/retired",
        "",
        &token,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"], current);
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_retired(&service, "retired", 3)?;
    assert_eq!(quota_read(&mut service, &token, "child").status, 404);
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/namespaces/retired",
            "",
            &token,
            json!({})
        )
        .body["data"],
        current
    );
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn native_flat_retirement140_file_nonempty_children_never_publish_partial_prune() -> TestResult {
    let (_files, mut service, _key, token) = initialized(true)?;
    create(&mut service, &token, "auth-owner")?;
    create(&mut service, &token, "engine-owner")?;
    create(&mut service, &token, "auth-history")?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/policies/acl/retained",
            "auth-owner",
            &token,
            json!({"policy":"path \"auth/token/lookup-self\" { capabilities = [\"read\"] }"})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/data",
            "engine-owner",
            &token,
            json!({"type":"kv", "options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "data/data/item",
            "engine-owner",
            &token,
            json!({"data":{"value":"must-not-be-deleted"}})
        )
        .status,
        200
    );
    // A real completed auth-mount lifecycle retains owner history even though
    // it never issued a credential. Visible emptiness is not pristine custody.
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/auth/temporary",
            "auth-history",
            &token,
            json!({"type":"approle"})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "DELETE",
            "sys/auth/temporary",
            "auth-history",
            &token,
            json!({})
        )
        .status,
        204
    );
    quota(&mut service, &token, "auth-quota", "auth-owner/");
    quota(&mut service, &token, "engine-quota", "engine-owner/");
    quota(&mut service, &token, "history-quota", "auth-history/");
    let catalog =
        owner_store::serialize_owner(&service.state.as_ref().ok_or("actual state")?.namespaces)?;
    let prior = service.native_root.as_ref().ok_or("actual root")?.clone();
    let auth_quota = quota_read(&mut service, &token, "auth-quota").body["data"].clone();
    let engine_quota = quota_read(&mut service, &token, "engine-quota").body["data"].clone();
    let history_quota = quota_read(&mut service, &token, "history-quota").body["data"].clone();
    for name in ["auth-owner", "engine-owner", "auth-history"] {
        let rejected = request(
            &mut service,
            "DELETE",
            &format!("sys/namespaces/{name}"),
            "",
            &token,
            json!({}),
        );
        assert_eq!(rejected.status, 409);
        assert_eq!(
            owner_store::serialize_owner(
                &service
                    .state
                    .as_ref()
                    .ok_or("unmodified catalog")?
                    .namespaces
            )?,
            catalog
        );
        assert!(service.native_root.as_ref().ok_or("unmodified graph")?.kv2 == prior.kv2);
        assert!(
            service
                .state
                .as_ref()
                .ok_or("no new floor")?
                .namespaces
                .native_flat_retirement_format
                .is_none()
        );
    }
    assert_eq!(
        quota_read(&mut service, &token, "auth-quota").body["data"],
        auth_quota
    );
    assert_eq!(
        quota_read(&mut service, &token, "engine-quota").body["data"],
        engine_quota
    );
    assert_eq!(
        quota_read(&mut service, &token, "history-quota").body["data"],
        history_quota
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/policies/acl/retained",
            "auth-owner",
            &token,
            json!({})
        )
        .status,
        200
    );
    let read = request(
        &mut service,
        "GET",
        "data/data/item",
        "engine-owner",
        &token,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["data"]["value"], "must-not-be-deleted");
    assert!(!service.recovery_required);
    Ok(())
}

fn batch(service: &mut Service, token: &str, namespace: &str) -> TestResult<Zeroizing<String>> {
    let mut response = request(
        service,
        "POST",
        "auth/token/create-orphan",
        namespace,
        token,
        json!({"type":"batch", "ttl":"1h", "policies":["default"]}),
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["auth"]["token_type"], "batch");
    let bearer = Zeroizing::new(
        response.body["auth"]["client_token"]
            .as_str()
            .ok_or("actual orphan batch")?
            .to_owned(),
    );
    erase_json(&mut response.body);
    Ok(bearer)
}

#[test]
fn native_flat_retirement140_file_migrated_batch_is_inert_after_same_name_recreation() -> TestResult
{
    // The original public V5 owner issues the actual stateless child batches,
    // then the real formal activation migrates their unchanged key and ledger.
    // This does not claim new native child batch issuance is implemented.
    let (files, mut service, key, token) = initialized(false)?;
    create(&mut service, &token, "retired")?;
    create(&mut service, &token, "sibling")?;
    let retired = batch(&mut service, &token, "retired")?;
    let sibling = batch(&mut service, &token, "sibling")?;
    activate_file(&mut service, &token)?;
    for (namespace, bearer) in [("retired", retired.as_str()), ("sibling", sibling.as_str())] {
        assert_eq!(
            request(
                &mut service,
                "GET",
                "auth/token/lookup-self",
                namespace,
                bearer,
                json!({})
            )
            .status,
            200
        );
    }
    let mut before = serde_json::to_value(&*service.state.as_ref().ok_or("actual Auth")?.auth)?;
    assert_eq!(
        request(
            &mut service,
            "DELETE",
            "sys/namespaces/retired",
            "",
            &token,
            json!({})
        )
        .status,
        200
    );
    create(&mut service, &token, "retired")?;
    assert_eq!(
        request(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            "retired",
            &retired,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            "sibling",
            &sibling,
            json!({})
        )
        .status,
        200
    );
    let mut after = serde_json::to_value(&*service.state.as_ref().ok_or("retained Auth")?.auth)?;
    for field in ["authority_id", "active_key"] {
        assert!(!before["batch_authority"][field].is_null());
        assert!(before["batch_authority"][field] == after["batch_authority"][field]);
    }
    erase_json(&mut before);
    erase_json(&mut after);
    assert_retired(&service, "retired", 3)?;
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_retired(&service, "retired", 3)?;
    assert_eq!(
        request(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            "retired",
            &retired,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            "sibling",
            &sibling,
            json!({})
        )
        .status,
        200
    );
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn native_flat_retirement140_readers_reject_stripped_decreased_and_unpaired_history() -> TestResult
{
    let (files, mut service, key, token) = initialized(true)?;
    create(&mut service, &token, "retired")?;
    let before = service.state.as_ref().ok_or("before state")?.clone();
    assert_eq!(
        request(
            &mut service,
            "DELETE",
            "sys/namespaces/retired",
            "",
            &token,
            json!({})
        )
        .status,
        200
    );
    create(&mut service, &token, "retired")?;
    let actual = service
        .state
        .as_ref()
        .ok_or("real recreated state")?
        .clone();
    let scope = super::super::native_plain::PlainNamespaceScope::capture(&actual, "retired")
        .map_err(|_| "actual scope")?;
    assert!(scope.check(&actual).is_ok());
    assert!(actual.validate_publication_schema(Some(&before)).is_ok());
    assert!(before.validate_publication_schema(Some(&actual)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&actual, &before).is_err());

    let mut lower = actual.clone();
    lower.schema = SCOPED_RATE_LIMIT_QUOTA_STATE_SCHEMA;
    assert!(lower.validate_format().is_err());
    assert!(lower.validate_publication_schema(Some(&actual)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&actual, &lower).is_err());

    let mut missing = actual.clone();
    missing.namespaces.native_flat_retirement_format = None;
    // A schema above 140 also admits ordinary namespace lifecycle history.
    // Its native interpretation needs the actual native reader/profile, not
    // an inference from a higher, unrelated global schema number.
    assert!(missing.validate_format().is_ok());
    assert!(super::super::native_plain::profile(&missing).is_err());
    assert!(service.require_native_root_candidate(&missing).is_err());
    assert!(missing.validate_publication_schema(Some(&actual)).is_err());
    assert!(scope.check(&missing).is_err());
    assert!(Service::validate_snapshot_protected_floor(&actual, &missing).is_err());

    let mut decreased = actual.clone();
    decreased
        .namespaces
        .next_incarnation
        .insert("retired".to_owned(), 2);
    assert!(decreased.validate_format().is_err());
    assert!(
        decreased
            .validate_publication_schema(Some(&actual))
            .is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(&actual, &decreased).is_err());

    let mut unpaired = actual.clone();
    unpaired.namespaces.batch_lifecycle = before.namespaces.batch_lifecycle.clone();
    assert!(unpaired.validate_format().is_err());
    assert!(Service::validate_snapshot_protected_floor(&actual, &unpaired).is_err());

    let mut foreign = actual.clone();
    foreign.cluster_id.push_str("-other");
    assert!(scope.check(&foreign).is_err());
    assert!(foreign.validate_publication_schema(Some(&actual)).is_err());

    let mut sealed = actual.clone();
    sealed
        .namespaces
        .entries
        .get_mut("retired")
        .ok_or("entry")?
        .sealed = true;
    assert!(sealed.validate_format().is_err());
    assert!(scope.check(&sealed).is_err());

    // None of these detached negative fixtures is committed or installed.
    assert_eq!(
        service
            .state
            .as_ref()
            .ok_or("still actual state")?
            .namespaces
            .incarnation("retired"),
        Some(2)
    );
    assert_retired(&service, "retired", 3)?;
    assert!(!service.recovery_required);

    // First prove an unchanged real File cold reader admits this same history.
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_retired(&service, "retired", 3)?;
    // This separate negative fixture has a valid MAC, object graph, root and
    // active cursor. Only native catalog provenance is removed. It is never
    // supplied to a production publisher as an authorized candidate.
    persist_stripped_native_catalog_for_cold_reader(&mut service)?;
    drop(service);
    let mut rejected = files.service()?;
    rejected.configure_native_v6_storage(NativeStorageProfile::File)?;
    let unseal = request(
        &mut rejected,
        "POST",
        "sys/unseal",
        "",
        "",
        json!({"key":key.as_str()}),
    );
    assert_eq!(unseal.status, 503);
    assert!(rejected.state.is_none() && rejected.native_root.is_none());
    let read = request(
        &mut rejected,
        "GET",
        "retained/data/item",
        "",
        &token,
        json!({}),
    );
    assert_eq!(read.status, 503);
    assert!(read.body.get("data").is_none());
    Ok(())
}

// Fault injection into this test's disposable File owner only. Re-authenticate
// the changed catalog, rather than relying on a bad MAC or an inconsistent
// cursor to reject the subsequent real cold native reader.
fn persist_stripped_native_catalog_for_cold_reader(service: &mut Service) -> TestResult {
    use crate::service::{native_blob_source, native_v6_reader, v6_records};
    use crate::state_record_root::{OpaqueOwnerRef, RecordStateRoot};
    use crate::state_record_root_v6::{ObjectDomain, OwnerDomain};
    use crate::state_records::StagedObject;
    use crate::v6_native_custody::OriginalDeadline;
    use crate::v6_read_validation::{ReadContext, ReadIdentity};

    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let deadline = OriginalDeadline::capture()?;
    let mut detached = service.state.clone().ok_or("actual native state")?;
    assert_eq!(detached.namespaces.native_flat_retirement_format, Some(1));
    detached.namespaces.native_flat_retirement_format = None;
    detached
        .validate_format()
        .map_err(|_| "ordinary-compatible catalog")?;
    assert!(super::super::native_plain::profile(&detached).is_err());
    let bytes = owner_store::serialize_owner(&detached.namespaces)?;
    let mut root = service.native_root.clone().ok_or("actual native root")?;
    let key = root
        .owner_key(OwnerDomain::Namespaces)
        .map_err(|_| "catalog address key")?;
    let domain = ObjectDomain::Owner(OwnerDomain::Namespaces);
    let mut objects = Vec::new();
    for chunk in bytes.chunks(crate::state_record_root::OWNER_CHUNK_BYTES) {
        objects.push(StagedObject::owner_chunk(&key, chunk)?);
    }
    root.owners[0].owner = OpaqueOwnerRef {
        name: OwnerDomain::Namespaces.name().into(),
        total_bytes: bytes.len() as u64,
        chunks: objects
            .iter()
            .map(|object| object.reference().clone())
            .collect(),
        digest: root
            .owner_digest(OwnerDomain::Namespaces, &bytes)
            .map_err(|_| "catalog digest")?,
    };
    let encoded = root.encode().map_err(|_| "negative root encoding")?;
    let durable = service.durable.as_mut().ok_or("actual durable owner")?;
    let current = durable
        .get("system", "state")?
        .ok_or("actual published root")?;
    let source_bytes = durable
        .get("system", native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE)?
        .ok_or("actual retained source")?;
    let source_root =
        RecordStateRoot::decode(source_bytes.expose()).map_err(|_| "retained root")?;
    let cursor_bytes = durable
        .get("system", native_v6_reader::ACTIVE_CURSOR_RESOURCE)?
        .ok_or("actual active cursor")?;
    let cursor = native_v6_reader::NativeActiveCursor::decode(cursor_bytes.expose())
        .map_err(|_| "active cursor")?;
    let session = native_blob_source::session(durable, current.expose())?;
    let mut mutations = Vec::new();
    for object in objects {
        let slot = native_blob_source::stage(durable, &session, &domain, &object, &mut || {
            deadline.check().map_err(|_| ServiceError::BarrierFailure)
        })?;
        mutations.push((
            v6_records::native_resource(&domain, object.reference()),
            Some(slot),
        ));
    }
    let generation = durable
        .generation()
        .checked_add(1)
        .ok_or("test generation overflow")?;
    let cursor = cursor
        .advance(&root, generation)
        .map_err(|_| "negative root cursor")?;
    let cursor_bytes = cursor.encode().map_err(|_| "negative cursor encoding")?;
    mutations.push(("state".into(), Some(Secret::new(encoded.to_vec())?)));
    mutations.push((
        native_v6_reader::ACTIVE_CURSOR_RESOURCE.into(),
        Some(Secret::new(cursor_bytes.to_vec())?),
    ));
    durable.apply_batch_in_replay_epoch(
        durable.replay_epoch(),
        "native-flat-negative-fixture",
        "system",
        "stripped-catalog-with-authenticated-cursor",
        root.identity()
            .map_err(|_| "negative root identity")?
            .digest(),
        mutations,
    )?;
    assert_eq!(durable.generation(), generation);
    cursor
        .validate(&source_root, &root, generation)
        .map_err(|_| "exact persisted cursor")?;
    let source = native_blob_source::NativeSource::new_checked(durable, deadline, || Ok(()))?;
    let context = ReadContext {
        expected_identity: ReadIdentity::RecordsV6(
            root.identity().map_err(|_| "reader identity")?.digest(),
        ),
        cluster_id: &root.cluster_id,
        replay_epoch: root.replay_epoch,
        minimum_state_schema: root.state_schema,
        maximum_state_schema: root.state_schema,
        reader_format: crate::state_record_root_v6::READER_FORMAT,
    };
    let (metadata, _) = v6_records::materialize_metadata_for_service(&root, context, &source)
        .map_err(|_| "negative catalog must retain authentic native objects")?;
    assert!(metadata.namespaces.native_flat_retirement_format.is_none());
    assert_eq!(
        metadata.namespaces.next_incarnation.get("retired"),
        Some(&3)
    );
    assert!(super::super::native_plain::profile(&metadata).is_err());
    Ok(())
}

#[test]
fn native_flat_retirement140_higher_floor_preserves_real_ordinary_history_and_fresh_root()
-> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, token) = crate::service::tests::bootstrap_unmounted(&mut service)?;
    let fresh = service.state.as_ref().ok_or("fresh ordinary root")?;
    assert_eq!(fresh.schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
    assert!(fresh.auth.has_security_contract_state());
    assert!(fresh.namespaces.native_flat_retirement_format.is_none());
    assert!(fresh.validate_format().is_ok());
    drop(service);
    let mut service = files.service()?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key})
        )
        .status,
        200
    );
    assert_eq!(
        service.state.as_ref().ok_or("fresh cold root")?.schema,
        AUTH_SECURITY_CONTRACT_STATE_SCHEMA
    );
    create(&mut service, &token, "retired")?;
    assert_eq!(
        request(
            &mut service,
            "DELETE",
            "sys/namespaces/retired",
            "",
            &token,
            json!({})
        )
        .status,
        200
    );
    let recreated = create(&mut service, &token, "retired")?;
    let ordinary = service
        .state
        .as_ref()
        .ok_or("actual ordinary recreated namespace")?;
    assert_eq!(ordinary.schema, NAMESPACE_FACTORY_STATE_SCHEMA);
    assert!(ordinary.auth.has_namespace_factory_state());
    assert!(ordinary.namespaces.native_flat_retirement_format.is_none());
    assert_eq!(ordinary.namespaces.incarnation("retired"), Some(2));
    assert_eq!(
        ordinary.namespaces.next_incarnation.get("retired"),
        Some(&3)
    );
    assert!(ordinary.validate_format().is_ok());
    assert!(ordinary.validate_namespace_batch_state().is_ok());
    assert!(super::super::native_plain::profile(ordinary).is_err());
    drop(service);
    let mut service = files.service()?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key})
        )
        .status,
        200
    );
    let read = request(
        &mut service,
        "GET",
        "sys/namespaces/retired",
        "",
        &token,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"], recreated);
    let state = service.state.as_ref().ok_or("cold ordinary history")?;
    assert!(state.namespaces.native_flat_retirement_format.is_none());
    assert_eq!(state.namespaces.next_incarnation.get("retired"), Some(&3));
    assert!(state.validate_format().is_ok());
    assert!(!service.recovery_required);
    Ok(())
}
