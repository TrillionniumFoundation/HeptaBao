use super::*;
use crate::auth::{BatchClaims, BatchKeyAuthority, LeaseOwner};
use crate::service::tests::{Root, bootstrap_unmounted, call};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn create(service: &mut Service, root: &str, path: &str) {
    assert_eq!(
        call(
            service,
            "POST",
            &format!("sys/namespaces/{path}"),
            root,
            json!({})
        )
        .status,
        200
    );
}

fn batch(service: &mut Service, root: &str, namespace: &str) -> TestResult<String> {
    let response = service.handle_at(
        "POST",
        "auth/token/create-orphan",
        namespace,
        root,
        json!({"type":"batch", "ttl":3600, "policies":["default"]}),
        100,
    );
    assert_eq!(response.status, 200, "actual orphan batch creation");
    assert_eq!(response.body["auth"]["token_type"], "batch");
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("batch token absent")?
        .to_owned())
}

fn lookup(service: &mut Service, namespace: &str, bearer: &str) -> u16 {
    service
        .handle_at(
            "GET",
            "auth/token/lookup-self",
            namespace,
            bearer,
            json!({}),
            101,
        )
        .status
}

/// An actual old authenticated claim, without the field unknown to old readers.
/// The same genuine key is retained in the live root candidate; no new key is
/// invented, no provider response or caller body selects an incarnation.
fn legacy_batch(service: &mut Service, namespace: &str) -> TestResult<(String, LeaseOwner)> {
    let mut state = service.state.clone().ok_or("state")?;
    let mut stored = serde_json::to_value(&*state.auth)?;
    let mut authority: BatchKeyAuthority =
        serde_json::from_value(stored["batch_authority"].take())?;
    let raw = authority
        .seal(
            BatchClaims {
                namespace_binding: None,
                token_api_precision: None,
                token_role: None,
                token_api_policy_names: false,
                public_origin: None,
                namespace: namespace.to_owned(),
                policies: BTreeSet::from(["default".to_owned()]),
                metadata: BTreeMap::new(),
                display_name: "legacy-orphan".to_owned(),
                path: "auth/token/create-orphan".to_owned(),
                bound_cidrs: Vec::new(),
                issued_at: 100,
                expires_at: 3700,
                parent: None,
                entity_id: None,
            },
            100,
        )
        .map_err(|_| "genuine historical batch sealing failed")?;
    let verified = authority
        .open(raw.as_str(), namespace, 101)
        .map_err(|_| "historical claim verification failed")?;
    assert!(verified.namespace_binding().is_none());
    let owner = LeaseOwner::from_batch(&verified);
    let bearer = raw.as_str().to_owned();
    stored["batch_authority"] = serde_json::to_value(authority)?;
    state.auth = serde_json::from_value::<AuthState>(stored)?.into();
    state.schema = state.writer_schema();
    service
        .commit_state(&mut state)
        .map_err(|_| "historical genuine key commit failed")?;
    service.state = Some(state);
    Ok((bearer, owner))
}

#[test]
fn namespace_batch_actual_orphan_delete_recreate_and_real_reopen_retire_only_actual_path()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, root) = bootstrap_unmounted(&mut service)?;
    create(&mut service, &root, "child");
    create(&mut service, &root, "sibling");
    let child = batch(&mut service, &root, "child")?;
    let sibling = batch(&mut service, &root, "sibling")?;
    assert_eq!(lookup(&mut service, "child", &child), 200);
    assert_eq!(lookup(&mut service, "sibling", &sibling), 200);
    let before = service.state.clone().ok_or("state")?;
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/child",
            &root,
            json!({})
        )
        .status,
        200
    );
    create(&mut service, &root, "child");
    assert_eq!(lookup(&mut service, "child", &child), 403);
    let replacement = batch(&mut service, &root, "child")?;
    assert_eq!(lookup(&mut service, "child", &replacement), 200);
    assert_eq!(lookup(&mut service, "sibling", &sibling), 200);
    let current = service.state.as_ref().ok_or("current")?;
    assert!(
        Service::validate_snapshot_protected_floor(current, &before).is_err(),
        "same-key old snapshot cannot undo actual retirement"
    );
    let key_before = serde_json::to_value(&*before.auth)?;
    let key_after = serde_json::to_value(&*current.auth)?;
    for field in ["authority_id", "active_key"] {
        assert!(!key_before["batch_authority"][field].is_null());
        assert_eq!(
            key_before["batch_authority"][field],
            key_after["batch_authority"][field]
        );
    }
    drop(service);
    let mut reopened = directory.service()?;
    assert_eq!(
        call(&mut reopened, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(lookup(&mut reopened, "child", &child), 403);
    assert_eq!(lookup(&mut reopened, "child", &replacement), 200);
    assert_eq!(lookup(&mut reopened, "sibling", &sibling), 200);
    Ok(())
}

#[test]
fn namespace_batch_legacy_none_and_typed_provider_owner_are_permanently_retired_without_sibling_key_rotation()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap_unmounted(&mut service)?;
    create(&mut service, &root, "legacy");
    create(&mut service, &root, "sibling");
    let (old, old_owner) = legacy_batch(&mut service, "legacy")?;
    let (sibling, sibling_owner) = legacy_batch(&mut service, "sibling")?;
    let (root_old, _) = legacy_batch(&mut service, "")?;
    assert_eq!(lookup(&mut service, "legacy", &old), 200);
    assert_eq!(lookup(&mut service, "sibling", &sibling), 200);
    assert_eq!(lookup(&mut service, "", &root_old), 200);
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .resolve_lease_owner(&old_owner, "legacy", 101)
            .is_some()
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/legacy",
            &root,
            json!({})
        )
        .status,
        200
    );
    create(&mut service, &root, "legacy");
    assert_eq!(lookup(&mut service, "legacy", &old), 403);
    assert_eq!(lookup(&mut service, "sibling", &sibling), 200);
    assert_eq!(lookup(&mut service, "", &root_old), 200);
    let state = service.state.as_ref().ok_or("state")?;
    assert!(
        state
            .auth
            .resolve_lease_owner(&old_owner, "legacy", 101)
            .is_none()
    );
    assert!(
        state
            .auth
            .validate_batch_lease_owner(old_owner.batch_claims().ok_or("owner")?, "legacy")
            .is_ok(),
        "saved retired cleanup owner remains valid format but never live"
    );
    assert!(
        state
            .auth
            .resolve_lease_owner(&sibling_owner, "sibling", 101)
            .is_some()
    );
    assert!(
        state
            .auth
            .validate_batch_lease_owner(
                sibling_owner.batch_claims().ok_or("sibling owner")?,
                "sibling"
            )
            .is_ok()
    );
    let received: State = serde_json::from_slice(&serde_json::to_vec(state)?)?;
    assert!(received.validate_format().is_ok());
    assert!(
        received
            .auth
            .resolve_lease_owner(&old_owner, "legacy", 101)
            .is_none()
    );
    let new = batch(&mut service, &root, "legacy")?;
    assert_eq!(lookup(&mut service, "legacy", &new), 200);
    Ok(())
}

#[test]
fn namespace_batch_protected_floor_rejects_same_schema_and_empty_reader_downgrades() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap_unmounted(&mut service)?;
    create(&mut service, &root, "retired");
    let old = service.state.clone().ok_or("state")?;
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/retired",
            &root,
            json!({})
        )
        .status,
        200
    );
    let current = service.state.as_ref().ok_or("current")?;
    assert!(current.validate_publication_schema(Some(&old)).is_ok());
    assert!(old.validate_publication_schema(Some(current)).is_err());
    assert!(Service::validate_snapshot_protected_floor(current, &old).is_err());
    let mut downgraded = current.clone();
    downgraded.schema = 90;
    assert!(downgraded.validate_format().is_err());
    assert!(Service::validate_snapshot_protected_floor(current, &downgraded).is_err());
    let mut missing: Value = serde_json::to_value(current)?;
    missing["namespaces"]
        .as_object_mut()
        .ok_or("namespace shape")?
        .remove("batch_lifecycle");
    missing["auth"]
        .as_object_mut()
        .ok_or("auth shape")?
        .remove("namespace_batch_registry");
    let missing: State = serde_json::from_value(missing)?;
    assert!(
        missing.validate_publication_schema(Some(current)).is_err(),
        "even same-reader empty state cannot erase retirement"
    );
    assert!(Service::validate_snapshot_protected_floor(current, &missing).is_err());
    Ok(())
}

#[test]
fn namespace_batch_sticky_lifecycle_survives_actual_closed_catalog_and_real_key_reopen()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, root) = bootstrap_unmounted(&mut service)?;
    let created = call(
        &mut service,
        "POST",
        "sys/namespaces/outer",
        &root,
        json!({"seal":"seal \"shamir\" { shares = 1\n threshold = 1 }"}),
    );
    assert_eq!(created.status, 200);
    let share = created.body["data"]["key_shares"][0]
        .as_str()
        .ok_or("actual namespace share")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/outer/unseal",
            &root,
            json!({"key":share})
        )
        .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/namespaces/child",
                "outer",
                &root,
                json!({}),
                100
            )
            .status,
        200
    );
    let child = batch(&mut service, &root, "outer/child")?;
    assert_eq!(lookup(&mut service, "outer/child", &child), 200);
    let binding = service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .namespace_batch_registry()
        .ok_or("ledger")?
        .binding("outer/child")
        .map_err(|_| "actual child binding")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/outer/seal",
            &root,
            json!({})
        )
        .status,
        204
    );
    let state = service.state.as_ref().ok_or("state")?;
    assert!(
        !state.namespaces.contains("outer/child"),
        "real close detaches routing catalog"
    );
    assert!(state.validate_format().is_ok());
    assert!(
        state
            .auth
            .namespace_batch_registry()
            .ok_or("ledger")?
            .check(Some(&binding), "outer/child")
            .is_ok(),
        "closing does not retire the actual incarnation"
    );
    // A pre-ledger old encrypted catalog cannot be synthesized from this
    // visible subset. The conservative migration limitation remains explicit.
    let mut historical = serde_json::to_value(state)?;
    historical["namespaces"]
        .as_object_mut()
        .ok_or("namespace")?
        .remove("batch_lifecycle");
    historical["auth"]
        .as_object_mut()
        .ok_or("auth")?
        .remove("namespace_batch_registry");
    let mut historical: State = serde_json::from_value(historical)?;
    let refusal = historical
        .ensure_namespace_batch_registry()
        .err()
        .ok_or("cold migration must refuse")?;
    assert_eq!(refusal.status, 503);
    assert!(!historical.has_namespace_batch_state());
    drop(service);
    let mut reopened = directory.service()?;
    assert_eq!(
        call(&mut reopened, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "sys/namespaces/outer/unseal",
            &root,
            json!({"key":share})
        )
        .status,
        200
    );
    assert_eq!(lookup(&mut reopened, "outer/child", &child), 200);
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("reopened")?
            .auth
            .namespace_batch_registry()
            .ok_or("reopened ledger")?
            .check(Some(&binding), "outer/child")
            .is_ok()
    );
    Ok(())
}

fn native_batch_owner(service: &Service, namespace: &str, bearer: &str) -> TestResult<LeaseOwner> {
    let state = service.state.as_ref().ok_or("state")?;
    let stored = serde_json::to_value(&*state.auth)?;
    let authority: BatchKeyAuthority = serde_json::from_value(stored["batch_authority"].clone())?;
    let verified = authority
        .open(bearer, namespace, 101)
        .map_err(|_| "actual batch verification")?;
    assert!(
        verified.namespace_binding().is_some(),
        "actual new MAC-covered binding"
    );
    Ok(LeaseOwner::from_batch(&verified))
}

#[test]
fn namespace_batch_saved_retired_native_owner_stays_format_valid_without_regrant() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap_unmounted(&mut service)?;
    create(&mut service, &root, "child");
    let bearer = batch(&mut service, &root, "child")?;
    let old_owner = native_batch_owner(&service, "child", &bearer)?;
    assert_eq!(lookup(&mut service, "child", &bearer), 200);
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/child",
            &root,
            json!({})
        )
        .status,
        200
    );
    create(&mut service, &root, "child");
    assert_eq!(lookup(&mut service, "child", &bearer), 403);
    let state = service.state.as_ref().ok_or("state")?;
    let received_owner: LeaseOwner = serde_json::from_slice(&serde_json::to_vec(&old_owner)?)?;
    let claims = received_owner.batch_claims().ok_or("typed claims")?;
    assert!(
        state
            .auth
            .validate_batch_lease_owner(claims, "child")
            .is_ok()
    );
    assert!(
        state
            .auth
            .resolve_lease_owner(&received_owner, "child", 101)
            .is_none()
    );
    // The saved format admits only actual cluster/frontier evidence. Merely
    // well-shaped foreign or future binding fields confer no saved authority.
    let mut foreign = serde_json::to_value(&received_owner)?;
    foreign["namespace_binding"]["cluster_id"] = json!("foreign-actual-cluster");
    let foreign: LeaseOwner = serde_json::from_value(foreign)?;
    assert!(
        state
            .auth
            .validate_batch_lease_owner(foreign.batch_claims().ok_or("foreign")?, "child")
            .is_err()
    );
    let mut future = serde_json::to_value(&received_owner)?;
    future["namespace_binding"]["incarnation"] = json!(u64::MAX);
    let future: LeaseOwner = serde_json::from_value(future)?;
    assert!(
        state
            .auth
            .validate_batch_lease_owner(future.batch_claims().ok_or("future")?, "child")
            .is_err()
    );
    let new_bearer = batch(&mut service, &root, "child")?;
    assert_eq!(lookup(&mut service, "child", &new_bearer), 200);
    Ok(())
}

#[test]
fn namespace_batch_retained_revoked_pki_binding_requires_matching_91_registry() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap_unmounted(&mut service)?;
    let bearer = batch(&mut service, &root, "")?;
    let owner = native_batch_owner(&service, "", &bearer)?;
    let mut retained = service.state.clone().ok_or("state")?;
    let issuer = retained
        .auth
        .resolve_lease_owner(&owner, "", 101)
        .ok_or("live actual batch issuer")?;
    for (path, body) in [
        ("sys/mounts/pki", json!({"type":"pki"})),
        (
            "pki/root/generate/internal",
            json!({"common_name":"ca.example.test","ttl":"48h"}),
        ),
        (
            "pki/roles/retained",
            json!({"allowed_domains":["example.test"],"allow_subdomains":true,"max_ttl":"2h","generate_lease":true}),
        ),
    ] {
        retained
            .engines
            .handle("", "POST", path, &body, 101)?
            .ok_or("pki route")?;
    }
    retained.engines.handle_service_pki(
        "",
        "POST",
        "pki/issue/retained",
        &json!({"common_name":"api.example.test","ttl":"1h"}),
        &issuer,
        101,
    )?;
    assert!(
        retained
            .engines
            .reconcile_lease_state(102, &BTreeSet::new())
    );
    assert!(
        retained.engines.lease_owners().is_empty(),
        "revoked/nonleased cleanup record"
    );
    assert!(
        retained
            .engines
            .all_lease_owners()
            .contains(&(String::new(), owner))
    );
    retained.schema = retained.writer_schema();
    assert!(retained.validate_namespace_batch_state().is_ok());
    let mut missing = serde_json::to_value(&retained)?;
    missing["auth"]
        .as_object_mut()
        .ok_or("auth")?
        .remove("namespace_batch_registry");
    missing["namespaces"]
        .as_object_mut()
        .ok_or("namespace")?
        .remove("batch_lifecycle");
    let mut missing: State = serde_json::from_value(missing)?;
    assert!(
        missing.has_namespace_batch_state(),
        "all retained owners carry the floor"
    );
    for schema in [80, NAMESPACE_BATCH_STATE_SCHEMA] {
        missing.schema = schema;
        assert!(missing.writer_schema() >= NAMESPACE_BATCH_STATE_SCHEMA);
        assert!(missing.validate_namespace_batch_state().is_err());
        assert!(missing.validate_format().is_err());
    }
    Ok(())
}

#[test]
fn namespace_batch_lazy_init_and_plain_post_preserve_legacy_until_actual_seal() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap_unmounted(&mut service)?;
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("initial state")?
            .has_namespace_batch_state()
    );
    assert!(service.state.as_ref().ok_or("initial state")?.schema < NAMESPACE_BATCH_STATE_SCHEMA);
    create(&mut service, &root, "child");
    let plain = service.state.as_ref().ok_or("plain state")?;
    assert!(!plain.has_namespace_batch_state());
    assert!(plain.schema < NAMESPACE_BATCH_STATE_SCHEMA);
    let bearer = batch(&mut service, &root, "child")?;
    let issued = service.state.as_ref().ok_or("issued state")?;
    assert!(issued.has_namespace_batch_state());
    assert_eq!(issued.schema, NAMESPACE_BATCH_STATE_SCHEMA);
    assert_eq!(lookup(&mut service, "child", &bearer), 200);
    Ok(())
}

#[test]
fn namespace_batch_actual_nested_key_hydration_required_before_first_seal() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap_unmounted(&mut service)?;
    let outer = call(
        &mut service,
        "POST",
        "sys/namespaces/outer",
        &root,
        json!({"seal":"seal \"shamir\" { shares = 1\n threshold = 1 }"}),
    );
    assert_eq!(outer.status, 200);
    let outer_share = outer.body["data"]["key_shares"][0]
        .as_str()
        .ok_or("outer share")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/outer/unseal",
            &root,
            json!({"key":outer_share})
        )
        .status,
        200
    );
    let inner = service.handle_at(
        "POST",
        "sys/namespaces/inner",
        "outer",
        &root,
        json!({"seal":"seal \"shamir\" { shares = 1\n threshold = 1 }"}),
        100,
    );
    assert_eq!(inner.status, 200);
    let inner_share = inner.body["data"]["key_shares"][0]
        .as_str()
        .ok_or("inner share")?
        .to_owned();
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .has_namespace_batch_state()
    );
    let denied = service.handle_at(
        "POST",
        "auth/token/create-orphan",
        "outer",
        &root,
        json!({"type":"batch","ttl":3600,"policies":["default"]}),
        100,
    );
    assert_eq!(denied.status, 503, "nested actual key is not loaded");
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .has_namespace_batch_state()
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/namespaces/inner/unseal",
                "outer",
                &root,
                json!({"key":inner_share}),
                100
            )
            .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/namespaces/child",
                "outer/inner",
                &root,
                json!({}),
                100
            )
            .status,
        200
    );
    // Serialization deliberately carries no process-local slot. A fully visible
    // catalog with false seal flags must still fail without the captured keys.
    let mut no_keys: State =
        serde_json::from_slice(&serde_json::to_vec(service.state.as_ref().ok_or("state")?)?)?;
    assert_eq!(
        no_keys
            .ensure_namespace_batch_registry()
            .err()
            .ok_or("missing key refusal")?
            .status,
        503
    );
    let issued = batch(&mut service, &root, "outer/inner/child")?;
    assert_eq!(lookup(&mut service, "outer/inner/child", &issued), 200);
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .validate_namespace_batch_state()
            .is_ok()
    );
    Ok(())
}
