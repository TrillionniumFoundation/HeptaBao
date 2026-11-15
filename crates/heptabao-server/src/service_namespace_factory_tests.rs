//! Real catalog, writer, barrier and namespace custody paths for schema 144.
use super::*;
#[cfg(feature = "native-v6-storage")]
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn call(
    service: &mut Service,
    seconds: u64,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: Value,
) -> TestResult<Response> {
    let at = Timestamp::checked(seconds, 123_456_789).map_err(|_| "private factory timestamp")?;
    let clock = RequestClock::anchored(Duration::ZERO, Instant::now())
        .map_err(|_| "private factory clock")?
        .with_timestamp_floor(at);
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    let _explicit = external_pki::PublicationClockScope::explicit();
    Ok(service.handle_request_clock(
        ServiceRequest::new(method, path, namespace, token, body),
        seconds,
        true,
        Some(clock),
    ))
}

fn open(files: &Root, native: bool) -> TestResult<Service> {
    #[cfg(feature = "native-v6-storage")]
    let mut service = files.service()?;
    #[cfg(not(feature = "native-v6-storage"))]
    let service = files.service()?;
    #[cfg(feature = "native-v6-storage")]
    if native {
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
    }
    #[cfg(not(feature = "native-v6-storage"))]
    assert!(!native);
    Ok(service)
}

fn initialized(native: bool) -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    let files = Root::new();
    let mut service = open(&files, native)?;
    let nonce = Zeroizing::new(hex(&crypto::random::<32>()?));
    let mut response = call(
        &mut service,
        100,
        "POST",
        "sys/init",
        "",
        "",
        json!({
            "secret_shares":1, "secret_threshold":1, "recovery_nonce":nonce.as_str(),
        }),
    )?;
    assert_eq!(response.status, 200);
    let key = response.body["keys"][0]
        .as_str()
        .map(|value| Zeroizing::new(value.to_owned()));
    let token = response.body["root_token"]
        .as_str()
        .map(|value| Zeroizing::new(value.to_owned()));
    erase_json(&mut response.body);
    let key = key.ok_or("actual root share")?;
    let token = token.ok_or("actual root credential")?;
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )?
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "sys/init/ack",
            "",
            &token,
            json!({})
        )?
        .status,
        204
    );
    #[cfg(feature = "native-v6-storage")]
    if native {
        assert_eq!(
            call(
                &mut service,
                100,
                "POST",
                "sys/storage/native-v6/activate",
                "",
                &token,
                json!({})
            )?
            .status,
            204
        );
    }
    Ok((files, service, key, token))
}

fn default_data(
    service: &mut Service,
    seconds: u64,
    namespace: &str,
    token: &str,
) -> TestResult<Value> {
    let response = call(
        service,
        seconds,
        "GET",
        "sys/policies/acl/default",
        namespace,
        token,
        json!({}),
    )?;
    assert_eq!(response.status, 200);
    let data = response.body["data"].clone();
    let fields = data
        .as_object()
        .ok_or("actual default data")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        fields,
        BTreeSet::from([
            "allow_slashes_in_identity_templates",
            "allow_wildcards_in_identity_templates",
            "cas_required",
            "modified",
            "name",
            "policy",
            "version",
        ])
    );
    assert_eq!(data["name"], "default");
    for field in [
        "cas_required",
        "allow_slashes_in_identity_templates",
        "allow_wildcards_in_identity_templates",
    ] {
        assert_eq!(data[field], false);
    }
    Ok(data)
}

fn current_child_roundtrip(native: bool) -> TestResult {
    let (files, mut service, key, admin) = initialized(native)?;
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "sys/namespaces/factory",
            "",
            &admin,
            json!({})
        )?
        .status,
        200
    );
    let original = default_data(&mut service, 100, "factory", &admin)?;
    assert_eq!(original["version"], 1);
    assert_eq!(original["modified"], "1970-01-01T00:01:40.123456789Z");
    let state = service.state.as_ref().ok_or("created state")?;
    assert_eq!(state.schema, NAMESPACE_FACTORY_STATE_SCHEMA);
    assert!(state.auth.has_namespace_factory_state());
    assert!(!state.auth.namespace_is_empty("factory"));
    state
        .validate_namespace_factory_state()
        .map_err(|_| "actual catalog origin")?;
    if !native {
        assert_eq!(
            call(
                &mut service,
                100,
                "PATCH",
                "sys/namespaces/factory",
                "",
                &admin,
                json!({"custom_metadata":{"purpose":"factory-regression"}})
            )?
            .status,
            200
        );
        assert_eq!(
            default_data(&mut service, 100, "factory", &admin)?,
            original
        );
        assert!(
            service
                .state
                .as_ref()
                .ok_or("metadata-only state")?
                .auth
                .has_namespace_factory_state()
        );
    }
    drop(service);

    let mut service = open(&files, native)?;
    assert_eq!(
        call(
            &mut service,
            101,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )?
        .status,
        200
    );
    assert_eq!(
        default_data(&mut service, 101, "factory", &admin)?,
        original
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("cold state")?
            .auth
            .has_namespace_factory_state()
    );
    // A real write of the identical public source loses factory provenance.
    // Neither source equality nor a later version may grant empty retirement.
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/policies/acl/default",
            "factory",
            &admin,
            json!({"policy":original["policy"],"cas":1})
        )?
        .status,
        204
    );
    let rewritten = default_data(&mut service, 102, "factory", &admin)?;
    assert_eq!(rewritten["version"], 2);
    assert_eq!(rewritten["modified"], "1970-01-01T00:01:42.123456789Z");
    let state = service.state.as_ref().ok_or("rewritten state")?;
    assert!(!state.auth.has_namespace_factory_state());
    let binding = state
        .namespaces
        .custody_binding(&state.cluster_id, "factory")
        .map_err(|_| "actual rewritten binding")?;
    let mut detached = state.auth.clone();
    let before = owner_store::serialize_owner(&detached)?;
    assert!(
        !detached
            .retire_empty_namespace_factory_default(&binding)
            .map_err(|_| "rewritten normalization")?
    );
    assert!(owner_store::serialize_owner(&detached)?.as_slice() == before.as_slice());
    #[cfg(feature = "native-v6-storage")]
    if native {
        assert!(native_empty::empty_profile(state).is_err());
        assert_eq!(
            call(
                &mut service,
                102,
                "DELETE",
                "sys/namespaces/factory",
                "",
                &admin,
                json!({})
            )?
            .status,
            409
        );
        assert_eq!(
            default_data(&mut service, 102, "factory", &admin)?,
            rewritten
        );
    }
    drop(service);
    let mut service = open(&files, native)?;
    assert_eq!(
        call(
            &mut service,
            103,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )?
        .status,
        200
    );
    assert_eq!(
        default_data(&mut service, 103, "factory", &admin)?,
        rewritten
    );
    let state = service.state.as_ref().ok_or("rewritten cold state")?;
    assert_eq!(state.schema, NAMESPACE_FACTORY_STATE_SCHEMA);
    assert!(!state.auth.has_namespace_factory_state());
    Ok(())
}

#[test]
fn factory144_ordinary_child_has_version_one_and_replay_cannot_restore_origin() -> TestResult {
    current_child_roundtrip(false)
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn factory144_native_child_has_version_one_and_replay_cannot_restore_origin() -> TestResult {
    current_child_roundtrip(true)
}

#[test]
fn factory144_independent_creation_seals_origin_before_any_reader_can_see_it() -> TestResult {
    let (files, mut service, key, admin) = initialized(false)?;
    let mut created = call(
        &mut service,
        100,
        "POST",
        "sys/namespaces/independent",
        "",
        &admin,
        json!({"seal":"seal \"shamir\" { shares = 1\n threshold = 1 }"}),
    )?;
    assert_eq!(created.status, 200);
    assert_eq!(created.body["data"]["key_threshold"], 1);
    let share = created.body["data"]["key_shares"][0]
        .as_str()
        .map(|value| Zeroizing::new(value.to_owned()));
    erase_json(&mut created.body);
    let share = share.ok_or("actual independent share")?;
    let state = service.state.as_ref().ok_or("closed new child")?;
    assert_eq!(state.schema, NAMESPACE_FACTORY_STATE_SCHEMA);
    assert!(!state.auth.has_namespace_factory_state());
    assert!(state.namespaces.custody_owner("independent").is_some());
    assert!(state.namespace_is_sealed("independent"));
    assert!(!service.namespace_runtime.is_loaded("independent"));
    let mut mislabeled = state.clone();
    mislabeled.schema = NAMESPACE_FACTORY_STATE_SCHEMA - 1;
    assert!(mislabeled.validate_publication_schema(Some(state)).is_err());
    assert!(Service::validate_snapshot_protected_floor(state, &mislabeled).is_err());
    drop(service);

    let mut service = open(&files, false)?;
    assert_eq!(
        call(
            &mut service,
            101,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )?
        .status,
        200
    );
    let status = call(
        &mut service,
        101,
        "GET",
        "sys/namespaces/independent/seal-status",
        "",
        &admin,
        json!({}),
    )?;
    assert_eq!(status.status, 200);
    assert_eq!(status.body["data"]["sealed"], true);
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("closed cold state")?
            .auth
            .has_namespace_factory_state()
    );
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/namespaces/independent/unseal",
            "",
            &admin,
            json!({"key":share.as_str()})
        )?
        .status,
        200
    );
    let restored = default_data(&mut service, 102, "independent", &admin)?;
    assert_eq!(restored["version"], 1);
    assert_eq!(restored["modified"], "1970-01-01T00:01:40.123456789Z");
    let state = service.state.as_ref().ok_or("opened child")?;
    state
        .validate_namespace_factory_state()
        .map_err(|_| "authenticated child provenance")?;
    assert!(state.auth.has_namespace_factory_state());
    assert_eq!(state.schema, NAMESPACE_FACTORY_STATE_SCHEMA);
    Ok(())
}

#[test]
fn factory144_inherited_ciphertext_and_real_root_restart_keep_original_origin() -> TestResult {
    let (files, mut service, key, admin) = initialized(false)?;
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "sys/namespaces/inherited",
            "",
            &admin,
            json!({})
        )?
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "sys/namespaces/nested",
            "inherited",
            &admin,
            json!({})
        )?
        .status,
        200
    );
    let original = default_data(&mut service, 100, "inherited", &admin)?;
    let child = default_data(&mut service, 100, "inherited/nested", &admin)?;
    assert_eq!(
        call(
            &mut service,
            101,
            "POST",
            "sys/namespaces/inherited/seal",
            "",
            &admin,
            json!({})
        )?
        .status,
        204
    );
    let state = service.state.as_ref().ok_or("closed inherited state")?;
    assert_eq!(state.schema, NAMESPACE_FACTORY_STATE_SCHEMA);
    assert!(state.namespaces.inherited_owner("inherited").is_some());
    assert!(!state.namespace_exists("inherited/nested"));
    assert!(!state.auth.has_namespace_factory_state());
    let canonical = owner_store::serialize_owner(state)?;
    drop(service);

    let mut service = open(&files, false)?;
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )?
        .status,
        200
    );
    let state = service.state.as_ref().ok_or("restored inherited state")?;
    assert!(owner_store::serialize_owner(state)?.as_slice() == canonical.as_slice());
    assert!(state.namespace_exists("inherited/nested"));
    state
        .validate_namespace_factory_state()
        .map_err(|_| "real inherited provenance")?;
    assert!(state.auth.has_namespace_factory_state());
    assert_eq!(
        default_data(&mut service, 102, "inherited", &admin)?,
        original
    );
    assert_eq!(
        default_data(&mut service, 102, "inherited/nested", &admin)?,
        child
    );
    Ok(())
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn factory144_native_empty_retirement_uses_actual_incarnation_and_recreation_gets_new_seed()
-> TestResult {
    let (files, mut service, key, admin) = initialized(true)?;
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "sys/namespaces/recreated",
            "",
            &admin,
            json!({})
        )?
        .status,
        200
    );
    let state = service.state.as_ref().ok_or("first incarnation")?;
    let first = state
        .namespaces
        .custody_binding(&state.cluster_id, "recreated")
        .map_err(|_| "first binding")?;
    assert_eq!(first.incarnation(), 1);
    assert!(!state.auth.namespace_is_empty("recreated"));
    assert!(native_empty::empty_profile(state).is_ok());
    assert_eq!(
        call(
            &mut service,
            101,
            "DELETE",
            "sys/namespaces/recreated",
            "",
            &admin,
            json!({})
        )?
        .status,
        200
    );
    let state = service.state.as_ref().ok_or("retired incarnation")?;
    assert!(!state.namespace_exists("recreated"));
    assert!(!state.auth.has_namespace_factory_state());
    assert_eq!(state.schema, NAMESPACE_FACTORY_STATE_SCHEMA);
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/namespaces/recreated",
            "",
            &admin,
            json!({})
        )?
        .status,
        200
    );
    let recreated = default_data(&mut service, 102, "recreated", &admin)?;
    assert_eq!(recreated["version"], 1);
    assert_eq!(recreated["modified"], "1970-01-01T00:01:42.123456789Z");
    let state = service.state.as_ref().ok_or("second incarnation")?;
    let actual = state
        .namespaces
        .custody_binding(&state.cluster_id, "recreated")
        .map_err(|_| "second binding")?;
    assert_eq!(actual.incarnation(), 2);
    assert_ne!(actual, first);
    let mut detached = state.auth.clone();
    let before = owner_store::serialize_owner(&detached)?;
    assert!(
        detached
            .retire_empty_namespace_factory_default(&first)
            .is_err()
    );
    assert!(owner_store::serialize_owner(&detached)?.as_slice() == before.as_slice());
    drop(service);
    let mut service = open(&files, true)?;
    assert_eq!(
        call(
            &mut service,
            103,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )?
        .status,
        200
    );
    assert_eq!(
        default_data(&mut service, 103, "recreated", &admin)?,
        recreated
    );
    assert_eq!(
        service
            .state
            .as_ref()
            .ok_or("cold incarnation")?
            .namespaces
            .incarnation("recreated"),
        Some(2)
    );
    Ok(())
}

#[test]
fn factory144_actual_catalog_binding_and_reader_floor_reject_detached_downgrades() -> TestResult {
    let (_files, mut service, _key, admin) = initialized(false)?;
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "sys/namespaces/bound",
            "",
            &admin,
            json!({})
        )?
        .status,
        200
    );
    let state = service.state.as_ref().ok_or("actual bound state")?;
    let original = owner_store::serialize_owner(state)?;
    let mut lower = state.clone();
    lower.schema = NAMESPACE_FACTORY_STATE_SCHEMA - 1;
    assert!(lower.validate_format().is_err());
    assert!(lower.validate_publication_schema(Some(state)).is_err());
    assert!(Service::validate_snapshot_protected_floor(state, &lower).is_err());
    for poison in 0..3 {
        let mut candidate = state.clone();
        if poison == 0 {
            candidate.cluster_id.push_str("-different");
        } else {
            let entry = candidate
                .namespaces
                .entries
                .get_mut("bound")
                .ok_or("actual catalog entry")?;
            if poison == 1 {
                entry.id.push('x');
            } else {
                entry.incarnation += 1;
            }
        }
        assert!(candidate.validate_namespace_factory_state().is_err());
        assert!(candidate.validate_format().is_err());
    }
    let binding = state
        .namespaces
        .custody_binding(&state.cluster_id, "bound")
        .map_err(|_| "real binding")?;
    let mut retired = state.clone();
    assert!(
        retired
            .auth
            .retire_empty_namespace_factory_default(&binding)
            .map_err(|_| "detached normalization")?
    );
    assert!(!retired.auth.has_namespace_factory_state());
    assert_eq!(retired.writer_schema(), NAMESPACE_FACTORY_STATE_SCHEMA);
    retired.schema = NAMESPACE_FACTORY_STATE_SCHEMA - 1;
    assert!(retired.validate_publication_schema(Some(state)).is_err());
    assert!(Service::validate_snapshot_protected_floor(state, &retired).is_err());
    assert!(
        owner_store::serialize_owner(service.state.as_ref().ok_or("unchanged real state")?)?
            .as_slice()
            == original.as_slice()
    );
    Ok(())
}

#[test]
fn factory144_explicit_legacy_child_keeps_implicit_zero_across_activation_and_metadata_update()
-> TestResult {
    let files = Root::new();
    let mut service = open(&files, false)?;
    let (key, token) = crate::service::tests::bootstrap_pre141_unmounted(&mut service)?;
    let key = Zeroizing::new(key);
    let token = Zeroizing::new(token);
    assert_eq!(
        service
            .create_pre144_namespace_fixture("legacy", &token)?
            .status,
        200
    );
    let old = call(
        &mut service,
        100,
        "GET",
        "sys/policies/acl/default",
        "legacy",
        &token,
        json!({}),
    )?;
    assert_eq!(old.status, 200);
    assert_eq!(old.body["data"]["version"], 0);
    assert!(old.body["data"].get("modified").is_none());
    let state = service.state.as_ref().ok_or("legacy published child")?;
    assert!(!state.auth.has_namespace_factory_state());
    assert!(state.schema < NAMESPACE_FACTORY_STATE_SCHEMA);
    assert!(state.auth.namespace_is_empty("legacy"));
    let before = owner_store::serialize_owner(state)?;
    assert!(
        service
            .create_pre144_namespace_fixture("legacy", &token)
            .is_err()
    );
    assert!(
        owner_store::serialize_owner(service.state.as_ref().ok_or("unchanged legacy child")?)?
            .as_slice()
            == before.as_slice()
    );
    drop(service);

    let mut service = open(&files, false)?;
    assert_eq!(
        call(
            &mut service,
            101,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )?
        .status,
        200
    );
    let loaded = call(
        &mut service,
        101,
        "GET",
        "sys/policies/acl/default",
        "legacy",
        &token,
        json!({}),
    )?;
    assert_eq!(loaded.status, 200);
    assert_eq!(loaded.body["data"], old.body["data"]);
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/namespaces/legacy",
            "",
            &token,
            json!({"custom_metadata":{"purpose":"old-input"}})
        )?
        .status,
        200
    );
    let retained = call(
        &mut service,
        102,
        "GET",
        "sys/policies/acl/default",
        "legacy",
        &token,
        json!({}),
    )?;
    assert_eq!(retained.status, 200);
    assert_eq!(retained.body["data"], old.body["data"]);
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("metadata legacy state")?
            .auth
            .has_namespace_factory_state()
    );
    // The production wrapper selects Current even when the source contains
    // old implicit defaults. It never guesses creation mode from that source.
    assert_eq!(
        call(
            &mut service,
            103,
            "POST",
            "sys/namespaces/current",
            "",
            &token,
            json!({})
        )?
        .status,
        200
    );
    let new = default_data(&mut service, 103, "current", &token)?;
    assert_eq!(new["version"], 1);
    assert_eq!(new["modified"], "1970-01-01T00:01:43.123456789Z");
    let old_after = call(
        &mut service,
        103,
        "GET",
        "sys/policies/acl/default",
        "legacy",
        &token,
        json!({}),
    )?;
    assert_eq!(old_after.status, 200);
    assert_eq!(old_after.body["data"], old.body["data"]);
    assert_eq!(
        service.state.as_ref().ok_or("mixed current state")?.schema,
        NAMESPACE_FACTORY_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn factory144_historical_child_factory_rejects_current_or_unauthenticated_source_without_changes()
-> TestResult {
    let (_files, mut current, _key, admin) = initialized(false)?;
    let before = owner_store::serialize_owner(current.state.as_ref().ok_or("current source")?)?;
    assert!(
        current
            .create_pre144_namespace_fixture("refused", &admin)
            .is_err()
    );
    assert!(
        owner_store::serialize_owner(current.state.as_ref().ok_or("unchanged current source")?)?
            .as_slice()
            == before.as_slice()
    );
    let old_files = Root::new();
    let mut old = open(&old_files, false)?;
    let (_key, admin) = crate::service::tests::bootstrap_pre141_unmounted(&mut old)?;
    let admin = Zeroizing::new(admin);
    let before = owner_store::serialize_owner(old.state.as_ref().ok_or("old source")?)?;
    assert!(old.create_pre144_namespace_fixture("refused", "").is_err());
    assert!(
        old.create_pre144_namespace_fixture("parent/child", &admin)
            .is_err()
    );
    assert!(old.create_pre144_namespace_fixture("root", &admin).is_err());
    assert!(
        owner_store::serialize_owner(old.state.as_ref().ok_or("unchanged old source")?)?.as_slice()
            == before.as_slice()
    );
    assert_eq!(
        old.create_pre144_namespace_fixture("accepted", &admin)?
            .status,
        200
    );
    assert!(
        !old.state
            .as_ref()
            .ok_or("accepted historical state")?
            .auth
            .has_namespace_factory_state()
    );
    assert_eq!(
        call(
            &mut old,
            100,
            "DELETE",
            "sys/namespaces/accepted",
            "",
            &admin,
            json!({})
        )?
        .status,
        200
    );
    crate::service::tests::finish_namespace_deletion_fixture(
        &mut old,
        "accepted",
        Duration::from_secs(100),
    )?;
    let retired = old
        .state
        .as_ref()
        .ok_or("actual retired historical child")?;
    assert!(retired.namespaces.entries.is_empty());
    assert!(!retired.namespaces.is_empty());
    assert!(retired.namespace_protected.is_none());
    assert!(retired.namespace_leases.is_empty());
    let next_incarnation = owner_store::serialize_owner(&retired.namespaces.next_incarnation)?;
    let retired_custody = owner_store::serialize_owner(&retired.namespaces.retired_custody)?;
    let frontiers = owner_store::serialize_owner(&retired.namespaces.custody_frontiers)?;
    let before = owner_store::serialize_owner(retired)?;
    assert!(
        old.create_pre144_namespace_fixture("accepted", &admin)
            .is_err()
    );
    assert!(
        owner_store::serialize_owner(old.state.as_ref().ok_or("unchanged retirement history")?)?
            .as_slice()
            == before.as_slice()
    );
    assert_eq!(
        old.create_pre144_namespace_fixture("another", &admin)?
            .status,
        200
    );
    let after = old.state.as_ref().ok_or("new historical target")?;
    assert_eq!(after.namespaces.incarnation("another"), Some(1));
    assert!(
        owner_store::serialize_owner(&after.namespaces.next_incarnation)?.as_slice()
            == next_incarnation.as_slice()
    );
    assert!(
        owner_store::serialize_owner(&after.namespaces.retired_custody)?.as_slice()
            == retired_custody.as_slice()
    );
    assert!(
        owner_store::serialize_owner(&after.namespaces.custody_frontiers)?.as_slice()
            == frontiers.as_slice()
    );
    assert!(!after.auth.has_namespace_factory_state());
    Ok(())
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn factory144_native_prepared_seed_is_stable_and_original_deadline_cannot_be_replaced() -> TestResult
{
    let (_files, service, _key, admin) = initialized(true)?;
    let state = service.state.as_ref().ok_or("actual native source")?;
    let root = service.native_root.as_ref().ok_or("actual native root")?;
    let before = owner_store::serialize_owner(&state.auth)?;
    let clock = RequestClock::anchored(Duration::new(100, 123_456_789), Instant::now())
        .map_err(|_| "actual advancing request clock")?;
    let mut actor = state
        .auth
        .authenticate_read_only(&admin, 100)
        .map_err(|_| "actual root authentication")?
        .ok_or("actual root principal")?;
    actor
        .bind_request_clock(Some(clock))
        .map_err(|_| "actual original actor clock")?;
    let body = json!({});
    let request = RequestView {
        method: "POST",
        path: "sys/namespaces/fixed",
        namespace: "",
        token: &admin,
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
    let expires = Instant::now() + Duration::from_secs(1);
    let original_deadline = crate::request_deadline::RequestDeadlineScope::enter(expires);
    let draft = native_empty::NativeEmptyNamespaceDraft::prepare(state, root, actor, &request)
        .map_err(|_| "actual native creation draft")?;
    let first = draft
        .candidate(state, root)
        .map_err(|_| "first candidate")?;
    let earlier = clock
        .observed_at()
        .map_err(|_| "original clock observation")?;
    std::thread::sleep(Duration::from_millis(2));
    assert!(
        clock
            .observed_at()
            .map_err(|_| "later original clock observation")?
            > earlier
    );
    let later = draft
        .candidate(state, root)
        .map_err(|_| "repeated candidate")?;
    assert!(
        owner_store::serialize_owner(&first.auth)?.as_slice()
            == owner_store::serialize_owner(&later.auth)?.as_slice()
    );
    assert!(draft.check_candidate(state, root, &first).is_ok());
    assert!(draft.check_candidate(state, root, &later).is_ok());
    let binding = later
        .namespaces
        .custody_binding(&later.cluster_id, "fixed")
        .map_err(|_| "prepared actual binding")?;
    let mut missing_seed = later.clone();
    assert!(
        missing_seed
            .auth
            .retire_empty_namespace_factory_default(&binding)
            .map_err(|_| "detached missing seed")?
    );
    assert!(draft.check_candidate(state, root, &missing_seed).is_err());
    assert!(owner_store::serialize_owner(&state.auth)?.as_slice() == before.as_slice());
    std::thread::sleep(
        expires.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
    );
    drop(original_deadline);
    let _later_deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    assert!(draft.check_source(state, root).is_err());
    assert!(draft.candidate(state, root).is_err());
    assert!(owner_store::serialize_owner(&state.auth)?.as_slice() == before.as_slice());
    Ok(())
}
