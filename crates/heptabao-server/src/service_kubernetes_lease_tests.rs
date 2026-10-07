//! Real Service/durable publication with authenticated synthetic batch ownership.
//! Provider replies are injected typed metadata; these are not kube-apiserver tests.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use crate::auth::{BatchClaims, BatchKeyAuthority, LeaseOwner};
use std::collections::{BTreeMap, BTreeSet};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Fixture = (Root, Service, String, String, KubernetesTokenEffectPlan);

fn fixture(parented: bool, identity: bool) -> TestResult<Fixture> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, root_token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/kubernetes",
            &root_token,
            json!({"type":"kubernetes"})
        )
        .status,
        204
    );
    let mut state = service.state.clone().ok_or("state")?;
    let entity_id = if identity {
        let entity = state
            .engines
            .handle(
                "",
                "POST",
                "identity/entity",
                &json!({"name":"kube-issuer"}),
                100,
            )
            .map_err(|_| "entity")?
            .ok_or("entity route")?;
        Some(
            entity.body["data"]["id"]
                .as_str()
                .ok_or("entity id")?
                .to_owned(),
        )
    } else {
        None
    };
    let mut keys = BatchKeyAuthority::new(100)?;
    let raw = keys.seal(
        BatchClaims {
            namespace_binding: None,
            token_role: None,
            token_api_precision: None,
            token_api_policy_names: false,
            public_origin: None,
            namespace: String::new(),
            policies: BTreeSet::from(["default".into()]),
            metadata: BTreeMap::new(),
            display_name: "test".into(),
            path: "auth/token/create".into(),
            bound_cidrs: Vec::new(),
            issued_at: 100,
            expires_at: 200,
            entity_id,
            parent: parented
                .then(|| URL_SAFE_NO_PAD.encode(crate::crypto::digest(root_token.as_bytes()))),
        },
        100,
    )?;
    let owner = LeaseOwner::from_batch(&keys.open(raw.as_str(), "", 100)?);
    let mut auth = serde_json::to_value(&state.auth)?;
    auth["batch_authority"] = serde_json::to_value(&keys)?;
    state.auth = serde_json::from_value(auth)?;
    let issuer = state
        .auth
        .resolve_lease_owner(&owner, "", 100)
        .ok_or("owner")?;
    // Configure without contacting a provider; actual network is covered separately.
    for (path, body) in [
        (
            "kubernetes/config",
            json!({"kubernetes_host":"https://localhost:8443","service_account_token":"synthetic-manager"}),
        ),
        (
            "kubernetes/roles/reader",
            json!({"allowed_kubernetes_namespaces":["default"],"service_account_name":"reader",
            "token_default_ttl":600,"token_max_ttl":3600}),
        ),
    ] {
        state
            .engines
            .kubernetes_dispatch("", path, "POST", &body, 100, None)
            .map_err(|_| "configure")?
            .ok_or("config route")?;
    }
    let dispatch = state
        .engines
        .kubernetes_dispatch(
            "",
            "kubernetes/creds/reader",
            "POST",
            &json!({"kubernetes_namespace":"default"}),
            100,
            Some(&issuer),
        )
        .map_err(|_| "issue")?
        .ok_or("issue route")?;
    let crate::engines::kubernetes::Dispatch::External(plan) = dispatch else {
        return Err("expected external".into());
    };
    state.schema = CURRENT_STATE_SCHEMA;
    state.validate_format().map_err(|_| "validate")?;
    service.commit_state(&mut state).map_err(|_| "commit")?;
    service.state = Some(state);
    let effect = KubernetesTokenEffectPlan::new(
        *plan,
        service.outbound.clone(),
        None,
        100,
        std::time::Instant::now(),
        service.unseal_nonce.clone(),
        false,
    );
    Ok((root, service, key, root_token, effect))
}
fn metadata() -> TokenMetadata {
    TokenMetadata {
        token: Zeroizing::new("synthetic-provider-token-no-network".into()),
        expires_at: 700,
        audiences: Vec::new(),
        artifact_lifetime_nanos: None,
    }
}

#[test]
fn kube_batch_lease_caps_response_only_and_admin_retirement_survives_reopen() -> TestResult {
    let (root, mut service, key, token, plan) = fixture(false, false)?;
    assert_eq!(plan.inner.ttl, 600);
    let response = service.finalize_kubernetes_token_with_clock(&plan, Ok(metadata()), || 101);
    assert_eq!(response.status, 200);
    assert_eq!(response.body["lease_duration"], 99);
    assert_eq!(response.body["renewable"], false);
    assert_eq!(
        response.body["data"]["service_account_token"],
        "synthetic-provider-token-no-network"
    );
    let lease_id = plan.inner.lease_id.clone();
    let mut state = service.state.clone().ok_or("state")?;
    let lookup = state
        .engines
        .handle_lease_admin(
            "",
            "POST",
            "sys/leases/lookup",
            &json!({"lease_id":lease_id}),
            101,
        )
        .map_err(|_| "lookup")?;
    assert_eq!(lookup.body["data"]["ttl"], 99);
    assert!(
        state
            .engines
            .handle_lease_admin(
                "",
                "POST",
                "sys/leases/renew",
                &json!({"lease_id":lease_id}),
                101
            )
            .is_err()
    );
    let listing = state
        .engines
        .handle_lease_admin(
            "",
            "LIST",
            "sys/leases/lookup/kubernetes/creds/reader",
            &json!({}),
            101,
        )
        .map_err(|_| "list")?;
    assert_eq!(
        listing.body["data"]["keys"].as_array().ok_or("keys")?.len(),
        1
    );
    let revoke = state
        .engines
        .handle_lease_admin(
            "",
            "POST",
            "sys/leases/revoke",
            &json!({"lease_id":lease_id}),
            101,
        )
        .map_err(|_| "revoke")?;
    assert!(revoke.mutated);
    service
        .commit_state(&mut state)
        .map_err(|_| "commit revoke")?;
    service.state = Some(state);
    drop(plan);
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "sys/leases/lookup",
            &token,
            json!({"lease_id":lease_id})
        )
        .status,
        400
    );
    // A retained observation documents remote expiry, not successful JWT revocation.
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .has_kubernetes_typed_lease_owners()
    );
    Ok(())
}

#[test]
fn kube_completion_rechecks_parent_and_same_scope_identity_and_keeps_terminal_observation()
-> TestResult {
    for identity in [false, true] {
        let (_root, mut service, _, token, plan) = fixture(!identity, identity)?;
        if identity {
            let mut state = service.state.clone().ok_or("state")?;
            let id = state
                .auth
                .resolve_lease_owner(&plan.inner.authority.owner, "", 100)
                .ok_or("owner")?
                .entity_id
                .ok_or("identity")?;
            state
                .engines
                .handle(
                    "",
                    "POST",
                    &format!("identity/entity/id/{id}"),
                    &json!({"disabled":true}),
                    100,
                )
                .map_err(|_| "disable")?
                .ok_or("disable route")?;
            service
                .commit_state(&mut state)
                .map_err(|_| "commit identity")?;
            service.state = Some(state);
        } else {
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "auth/token/revoke-self",
                    &token,
                    json!({})
                )
                .status,
                204
            );
        }
        let response = service.finalize_kubernetes_token_with_clock(&plan, Ok(metadata()), || 101);
        assert_eq!(response.status, 503);
        assert_eq!(response.body["retry_allowed"], false);
        assert_eq!(response.body["provider_token_revoked"], false);
        assert_eq!(response.body["local_lease_retired"], true);
        assert!(response.body.get("data").is_none());
        assert!(
            service
                .state
                .as_mut()
                .ok_or("state")?
                .engines
                .handle_lease_admin(
                    "",
                    "POST",
                    "sys/leases/lookup",
                    &json!({"lease_id":plan.inner.lease_id}),
                    101
                )
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn kube_completion_expiry_during_commit_withholds_token_and_activation_change_preserves_unknown_intent()
-> TestResult {
    let (_root, mut service, _, _, plan) = fixture(false, false)?;
    let mut reads = 0;
    let response = service.finalize_kubernetes_token_with_clock(&plan, Ok(metadata()), || {
        reads += 1;
        if reads == 1 { 199 } else { 200 }
    });
    assert_eq!(reads, 2);
    assert_eq!(response.status, 503);
    assert_eq!(response.body["local_lease_retired"], true);
    assert!(response.body.get("data").is_none());
    let (_root, mut service, _, _, plan) = fixture(false, false)?;
    let before = serde_json::to_vec(&service.state.as_ref().ok_or("state")?.engines)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    service.unseal_nonce.push('x');
    let response = service.finalize_kubernetes_token_with_clock(&plan, Ok(metadata()), || 101);
    assert_eq!(response.status, 503);
    assert_eq!(response.body["reconcile_required"], true);
    assert_eq!(response.body["retry_allowed"], false);
    assert_eq!(
        generation,
        service.durable.as_ref().ok_or("durable")?.generation()
    );
    assert_eq!(
        before,
        serde_json::to_vec(&service.state.as_ref().ok_or("state")?.engines)?
    );
    Ok(())
}

#[test]
fn kube_typed_pending_and_observed_state_require_schema42() -> TestResult {
    let (_root, mut service, _, _, plan) = fixture(false, false)?;
    let mut old = service.state.clone().ok_or("state")?;
    old.schema = 41;
    assert!(old.validate_format().is_err());
    old.schema = 42;
    assert!(old.validate_format().is_ok());
    assert_eq!(
        service
            .finalize_kubernetes_token_with_clock(&plan, Ok(metadata()), || 101)
            .status,
        200
    );
    let mut observed = service.state.clone().ok_or("state")?;
    observed.schema = 41;
    assert!(observed.validate_format().is_err());
    observed.schema = 42;
    assert!(observed.validate_format().is_ok());
    Ok(())
}

#[test]
fn kube_unknown_provider_result_preserves_intent_and_prefix_revoke_does_not_replay_it() -> TestResult
{
    let (_root, mut service, _, _, plan) = fixture(false, false)?;
    let before = serde_json::to_vec(&service.state.as_ref().ok_or("state")?.engines)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let response = service.finalize_kubernetes_token_with_clock(
        &plan,
        Err(outcome_unknown(&plan.inner.lease_id)),
        || 101,
    );
    assert_eq!(response.status, 503);
    assert_eq!(response.body["retry_allowed"], false);
    assert_eq!(
        before,
        serde_json::to_vec(&service.state.as_ref().ok_or("state")?.engines)?
    );
    assert_eq!(
        generation,
        service.durable.as_ref().ok_or("durable")?.generation()
    );
    let mut state = service.state.clone().ok_or("state")?;
    let revoked = state
        .engines
        .handle_lease_admin(
            "",
            "POST",
            "sys/leases/revoke-prefix/kubernetes",
            &json!({}),
            100,
        )
        .map_err(|_| "prefix")?;
    assert!(!revoked.mutated);
    assert_eq!(before, serde_json::to_vec(&state.engines)?);
    Ok(())
}

#[test]
fn kube_zero_elapsed_one_second_lease_is_not_artificially_expired() -> TestResult {
    let (_root, mut service, _, _, plan) = fixture(false, false)?;
    let response = service.finalize_kubernetes_token_with_clock(
        &plan,
        Ok(TokenMetadata {
            token: Zeroizing::new("one-second-synthetic-provider-token".into()),
            expires_at: 101,
            audiences: Vec::new(),
            artifact_lifetime_nanos: None,
        }),
        || 100,
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["lease_duration"], 1);
    Ok(())
}

#[test]
fn kube_public_creds_admission_consumes_finite_actor_once_only() -> TestResult {
    let (_root, mut service, _, admin, first) = fixture(false, false)?;
    assert_eq!(
        service
            .finalize_kubernetes_token_with_clock(&first, Ok(metadata()), || 100)
            .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/policies/acl/kube-read",
            &admin,
            json!({"policy":"path \"kubernetes/creds/*\" { capabilities=[\"update\"] }"})
        )
        .status,
        204
    );
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["kube-read"],"ttl":300,"num_uses":2}),
    );
    assert_eq!(issued.status, 200);
    let actor = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?
        .to_owned();
    let pending = match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path: "kubernetes/creds/reader",
        namespace: "",
        token: &actor,
        body: json!({"kubernetes_namespace":"default"}),
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    }) {
        RequestExecution::External(pending) => pending,
        RequestExecution::Complete(response) => {
            return Err(format!("expected external, got {}", response.status).into());
        }
    };
    assert!(matches!(
        &pending.effect,
        ExternalEffectPlan::KubernetesToken(_)
    ));
    let lookup = call(
        &mut service,
        "POST",
        "auth/token/lookup",
        &admin,
        json!({"token":actor}),
    );
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["num_uses"], 1);
    let response = service.finish_external_request(
        *pending,
        ExternalEffectResult::KubernetesToken(Ok(metadata())),
    );
    assert_eq!(response.status, 200);
    assert!(
        response.body["lease_duration"]
            .as_u64()
            .is_some_and(|ttl| ttl > 300 && ttl <= 600)
    );
    let lookup = call(
        &mut service,
        "POST",
        "auth/token/lookup",
        &admin,
        json!({"token":actor}),
    );
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["num_uses"], 1);
    // The live service owner expires at 400; it must not cap the independent
    // provider JWT/Bao lease to 300 merely because it remains an alive owner.
    assert_eq!(
        response.body["data"]["service_account_token"],
        "synthetic-provider-token-no-network"
    );
    Ok(())
}

#[test]
fn kube_final_actor_use_executes_once_but_durably_retires_without_returning_credentials()
-> TestResult {
    let (root, mut service, key, admin, first) = fixture(false, false)?;
    assert_eq!(
        service
            .finalize_kubernetes_token_with_clock(&first, Ok(metadata()), || 100)
            .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/policies/acl/kube-read",
            &admin,
            json!({"policy":"path \"kubernetes/creds/*\" { capabilities=[\"update\"] }"})
        )
        .status,
        204
    );
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["kube-read"],"ttl":300,"num_uses":1}),
    );
    assert_eq!(issued.status, 200);
    let actor = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?
        .to_owned();
    let pending = match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path: "kubernetes/creds/reader",
        namespace: "",
        token: &actor,
        body: json!({"kubernetes_namespace":"default"}),
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    }) {
        RequestExecution::External(pending) => pending,
        RequestExecution::Complete(response) => {
            return Err(format!("expected external, got {}", response.status).into());
        }
    };
    let ExternalEffectPlan::KubernetesToken(plan) = &pending.effect else {
        return Err("expected TokenRequest".into());
    };
    assert!(plan.last_use);
    let lease_id = plan.inner.lease_id.clone();
    // This admitted request may execute, but its owner cannot authorize any
    // persistent lease or another request. Do not relax the owner resolver.
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .resolve_lease_owner(&plan.inner.authority.owner, "", 100)
            .is_none()
    );
    let response = service.finish_external_request(
        *pending,
        ExternalEffectResult::KubernetesToken(Ok(metadata())),
    );
    assert_eq!(response.status, 400);
    assert_eq!(
        response.body,
        json!({"errors":["Secret cannot be returned; token had one use left, so leased credentials were immediately revoked."]})
    );
    let encoded = serde_json::to_vec(&service.state.as_ref().ok_or("state")?.engines)?;
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        serde_json::to_vec(&service.state.as_ref().ok_or("state")?.engines)?,
        encoded
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/leases/lookup",
            &admin,
            json!({"lease_id":lease_id})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "kubernetes/creds/reader",
            &actor,
            json!({"kubernetes_namespace":"default"})
        )
        .status,
        403
    );
    assert!(service.pending_kubernetes_token.is_none());
    Ok(())
}

#[test]
fn schema41_without_typed_kube_owner_reopens_without_migration() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let mut state = service.state.clone().ok_or("state")?;
    state.schema = 41;
    assert!(!state.engines.has_kubernetes_typed_lease_owners());
    state.validate_format().map_err(|_| "schema41 validation")?;
    crate::service::tests::commit_legacy_state_fixture(&mut service, &state)
        .map_err(|_| "persist schema41")?;
    service.state = Some(state);
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(reopened.state.as_ref().ok_or("reopen state")?.schema, 41);
    assert_eq!(
        call(&mut reopened, "GET", "sys/mounts", &admin, json!({})).status,
        200
    );
    assert_eq!(reopened.state.as_ref().ok_or("read state")?.schema, 41);
    Ok(())
}

#[test]
fn kube_completion_clock_includes_admission_before_provider_plan() -> TestResult {
    for admission_elapsed in [0, 2] {
        let (_root, mut service, _, admin, first) = fixture(false, false)?;
        assert_eq!(
            service
                .finalize_kubernetes_token_with_clock(&first, Ok(metadata()), || 100)
                .status,
            200
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/policies/acl/kube-clock",
                &admin,
                json!({"policy":"path \"kubernetes/creds/*\" { capabilities=[\"update\"] }"})
            )
            .status,
            204
        );
        let issued = call(
            &mut service,
            "POST",
            "auth/token/create",
            &admin,
            json!({"policies":["kube-clock"],"ttl":1,"num_uses":2}),
        );
        assert_eq!(issued.status, 200);
        let actor = issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("actor")?;
        let observed = std::time::Instant::now();
        let admission_started = observed
            .checked_sub(std::time::Duration::from_secs(admission_elapsed))
            .ok_or("admission clock")?;
        // Inject elapsed admission without sleeps, using the actual public
        // dispatch path (including finite-use publication), not a forged plan.
        let pending = match service.begin_at_mode_started(
            RequestDispatch {
                method: "POST",
                path: "kubernetes/creds/reader",
                namespace: "",
                token: actor,
                body: json!({"kubernetes_namespace":"default"}),
                now: 100,
                allow_forward: false,
                enforce_namespace: true,
                wrap_ttl_seconds: None,
                origin_peer: None,
                client_certificates: None,
            },
            admission_started,
        ) {
            RequestExecution::External(pending) => pending,
            RequestExecution::Complete(response) => {
                return Err(format!("admission status {}", response.status).into());
            }
        };
        let ExternalEffectPlan::KubernetesToken(plan) = &pending.effect else {
            return Err("wrong effect".into());
        };
        assert_eq!(plan.started, admission_started);
        assert_eq!(plan.completed_at(observed), 100 + admission_elapsed);
        let response = service.finalize_kubernetes_token_with_clock(plan, Ok(metadata()), || {
            plan.completed_at(observed)
        });
        if admission_elapsed == 0 {
            assert_eq!(response.status, 200);
            assert_eq!(
                response.body["data"]["service_account_token"],
                "synthetic-provider-token-no-network"
            );
        } else {
            assert_eq!(response.status, 503);
            assert_eq!(response.body["local_lease_retired"], true);
            assert_eq!(response.body["provider_token_revoked"], false);
            assert!(response.body.get("data").is_none());
        }
        let state = service.state.as_ref().ok_or("state")?;
        state.validate_format().map_err(|_| "format")?;
        let serialized = Zeroizing::new(serde_json::to_vec(&state.engines)?);
        assert!(
            !serialized
                .windows(b"synthetic-provider-token-no-network".len())
                .any(|window| window == b"synthetic-provider-token-no-network")
        );
    }
    Ok(())
}

#[test]
fn kube_precise_batch_owner_expires_inside_one_second_and_floor_cannot_replay_it() -> TestResult {
    let (_root, mut service, _, _, mut plan) = fixture(false, false)?;
    let mut keys = BatchKeyAuthority::new(100)?;
    let raw = keys.seal(
        BatchClaims {
            namespace_binding: None,
            public_origin: None,
            token_role: None,
            token_api_precision: Some(serde_json::from_value(json!({
                "granted_ttl":500000000,
                "expires_at":{"seconds":100,"nanoseconds":500000000}
            }))?),
            token_api_policy_names: true,
            namespace: String::new(),
            policies: BTreeSet::from(["default".into()]),
            metadata: BTreeMap::new(),
            display_name: "precise-provider-owner".into(),
            path: "auth/token/create-orphan".into(),
            bound_cidrs: Vec::new(),
            issued_at: 100,
            expires_at: 101,
            entity_id: None,
            parent: None,
        },
        100,
    )?;
    let before = AuthorityTime::Precise(crate::auth::Timestamp::checked(100, 400000000)?);
    let after = AuthorityTime::Precise(crate::auth::Timestamp::checked(100, 600000000)?);
    let claims = keys.open_authenticated_observed(raw.as_str(), before)?;
    plan.inner.authority.owner = LeaseOwner::from_batch(&claims);
    plan.inner.authority.expires_at = 101;
    let state = service.state.as_mut().ok_or("state")?;
    let mut auth = serde_json::to_value(&state.auth)?;
    auth["batch_authority"] = serde_json::to_value(&keys)?;
    auth["token_api_precision_state"] = json!(true);
    auth["token_api_observed_at"] = json!({"seconds":100,"nanoseconds":200000000});
    state.auth = serde_json::from_value(auth)?;
    state.auth.validate_system_lease_defaults()?;
    assert!(Service::kubernetes_completion_owner_live(
        state, &plan, before
    ));
    assert!(!Service::kubernetes_completion_owner_live(
        state, &plan, after
    ));
    assert!(!Service::kubernetes_completion_owner_live(
        state,
        &plan,
        AuthorityTime::Coarse(100)
    ));
    state.auth.observe_token_api_time(after)?;
    // A replayed wall fraction stays behind the already authenticated private floor.
    assert!(!Service::kubernetes_completion_owner_live(
        state, &plan, before
    ));
    let reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&state.auth)?)?;
    assert!(
        reopened
            .resolve_lease_owner_observed(&plan.inner.authority.owner, "", before)
            .is_none()
    );
    Ok(())
}

#[test]
fn kube_completed_time_keeps_original_anchor_and_never_adds_elapsed_to_floor() -> TestResult {
    let (_root, _service, _, _, mut plan) = fixture(false, false)?;
    let started = std::time::Instant::now() - std::time::Duration::from_millis(250);
    let floor = crate::auth::Timestamp::checked(1000, 800000000)?;
    let clock = RequestClock::anchored(std::time::Duration::new(100, 200000000), started)?
        .with_timestamp_floor(floor);
    plan.token_clock = Some(clock);
    plan.now = 999;
    assert_eq!(
        plan.completed_time()
            .map_err(|_| "completion clock")?
            .exact(),
        Some(floor)
    );
    assert_eq!(plan.token_clock.ok_or("clock")?.started(), started);
    // The legacy constructor is explicitly coarse and does not invent a fraction.
    plan.token_clock = None;
    assert!(
        plan.completed_time()
            .map_err(|_| "completion clock")?
            .exact()
            .is_none()
    );
    Ok(())
}

#[test]
fn kube_clock_failure_before_completion_does_not_publish_or_release_provider_token() -> TestResult {
    let (_root, mut service, _, _, plan) = fixture(false, false)?;
    let before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let mut committed_receipt = None;
    let response = service.finalize_kubernetes_token_checked(
        &plan,
        Ok(metadata()),
        || Err(failure("trusted token clock is unavailable")),
        |_| Ok(()),
        &mut committed_receipt,
    );
    assert!(committed_receipt.is_none());
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert_eq!(response.body["retry_allowed"], false);
    assert_eq!(
        before,
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?
    );
    assert_eq!(
        generation,
        service.durable.as_ref().ok_or("durable")?.generation()
    );
    Ok(())
}

// The gate remains off. This fixture binds the actual admitted intent using the
// same internal producer before a real durable publication; no HTTP body field
// can select it. These cases do not replace the R54/R62 real HTTPS oracles.
fn opaque_fixture() -> TestResult<Fixture> {
    let (root, mut service, key, token, mut plan) = fixture(false, false)?;
    let mut state = service.state.clone().ok_or("state")?;
    let defaults = state.auth.secret_lease_defaults().map_err(|_| "defaults")?;
    state
        .engines
        .bind_kubernetes_opaque_artifact_intent(&mut plan.inner, defaults)
        .map_err(|_| "actual admitted opaque contract")?;
    state
        .engines
        .observe_kubernetes_artifact_time(AuthorityTime::Precise(crate::auth::Timestamp::whole(
            100,
        )?))
        .map_err(|_| "actual admitted precise observation")?;
    state.schema = state.writer_schema();
    assert_eq!(state.schema, KUBERNETES_OPAQUE_ARTIFACT_STATE_SCHEMA);
    state.validate_format().map_err(|_| "opaque state")?;
    service
        .commit_state(&mut state)
        .map_err(|_| "actual opaque intent publication")?;
    service.state = Some(state);
    Ok((root, service, key, token, plan))
}

fn opaque_reply(claims: Value) -> TestResult<Value> {
    // Signature bytes are intentionally not a grant. R54 proves that opaque
    // public metadata does not verify them; the original private Box does.
    let token = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?),
        URL_SAFE_NO_PAD.encode(b"not-a-signature-authority")
    );
    Ok(json!({"status":{"token":token,"expirationTimestamp":"2000-01-01T00:00:00Z"}}))
}

#[test]
fn kube_opaque_artifact_public_claims_do_not_change_private_owner_and_bad_metadata_keeps_intent()
-> TestResult {
    let (_root, service, _, _, plan) = opaque_fixture()?;
    for (claims, lifetime) in [
        (
            json!({"iat":100,"exp":700,"sub":"wrong","aud":["wrong"]}),
            600_000_000_000,
        ),
        (json!({"iat":100.75,"exp":700.75}), 600_000_000_000),
        (json!({"iat":null,"exp":null}), 0),
        (json!({"iat":100}), -100_000_000_000),
    ] {
        let reply = opaque_reply(claims)?;
        let metadata = token_metadata(&reply, &plan.inner, 101).map_err(|_| "opaque metadata")?;
        assert_eq!(metadata.expires_at, 0);
        assert_eq!(metadata.artifact_lifetime_nanos, Some(lifetime));
        assert_eq!(metadata.audiences, plan.inner.audiences);
        assert_eq!(plan.inner.authority.expires_at, 200);
    }
    let state_before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    for (claims, word) in [
        (json!({"iat":100,"exp":"700"}), "string"),
        (json!({"iat":true,"exp":700}), "bool"),
    ] {
        let rejected = token_metadata(&opaque_reply(claims)?, &plan.inner, 101)
            .err()
            .ok_or("bad metadata accepted")?;
        assert_eq!(rejected.status, 500);
        assert!(
            rejected.body["errors"][0]
                .as_str()
                .ok_or("public error")?
                .contains(&format!("got unconvertible type '{word}'"))
        );
    }
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
        state_before
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .has_kubernetes_opaque_artifact_state()
    );
    Ok(())
}

#[test]
fn kube_opaque_artifact_durable_registration_and_retirement_preserve_schema_and_private_cap()
-> TestResult {
    let (root, mut service, key, token, plan) = opaque_fixture()?;
    let metadata = token_metadata(
        &opaque_reply(json!({"iat":null,"exp":null}))?,
        &plan.inner,
        101,
    )
    .map_err(|_| "metadata")?;
    let completed_time = AuthorityTime::Precise(crate::auth::Timestamp::whole(101)?);
    let response =
        service
            .finalize_kubernetes_token_with_observed_clock(&plan, Ok(metadata), || completed_time);
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body["lease_duration"], 99);
    assert_eq!(plan.inner.authority.expires_at, 200);
    let mut state = service.state.clone().ok_or("state")?;
    assert_eq!(state.schema, KUBERNETES_OPAQUE_ARTIFACT_STATE_SCHEMA);
    let lookup = state
        .engines
        .handle_lease_admin_observed(
            "",
            "POST",
            "sys/leases/lookup",
            &json!({"lease_id":plan.inner.lease_id}),
            AuthorityTime::Precise(crate::auth::Timestamp::whole(101)?),
        )
        .map_err(|_| "lookup")?;
    assert_eq!(lookup.body["data"]["ttl"], 99);
    let retired = state
        .engines
        .handle_lease_admin_observed(
            "",
            "POST",
            "sys/leases/revoke",
            &json!({"lease_id":plan.inner.lease_id}),
            AuthorityTime::Precise(crate::auth::Timestamp::whole(102)?),
        )
        .map_err(|_| "retire")?;
    assert_eq!(retired.status, 204);
    assert!(state.engines.has_kubernetes_opaque_artifact_state());
    service
        .commit_state(&mut state)
        .map_err(|_| "real retirement publication")?;
    service.state = Some(state);
    let digest = service.current_state_digest().map_err(|_| "digest")?;
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(reopened.unseal(&json!({"key":key})).status, 200);
    assert_eq!(
        reopened
            .current_state_digest()
            .map_err(|_| "reopened digest")?,
        digest
    );
    assert_eq!(
        reopened.state.as_ref().ok_or("state")?.schema,
        KUBERNETES_OPAQUE_ARTIFACT_STATE_SCHEMA
    );
    let observed_lookup = reopened
        .state
        .as_ref()
        .ok_or("restored state")?
        .engines
        .clone()
        .handle_lease_admin_observed(
            "",
            "POST",
            "sys/leases/lookup",
            &json!({"lease_id":plan.inner.lease_id}),
            AuthorityTime::Precise(crate::auth::Timestamp::whole(103)?),
        )
        .err()
        .ok_or("retired lease accepted")?;
    assert_eq!(observed_lookup.status, 400);
    let coarse = call(
        &mut reopened,
        "POST",
        "sys/leases/lookup",
        &token,
        json!({"lease_id":plan.inner.lease_id}),
    );
    assert_eq!(coarse.status, 503);
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .has_kubernetes_opaque_artifact_state()
    );
    Ok(())
}

#[test]
fn kube_opaque_artifact_precise_floor_rollback_and_coarse_maintenance_preserve_complete_owner()
-> TestResult {
    let (_root, service, _, _, _plan) = opaque_fixture()?;
    let mut before = service.state.clone().ok_or("state")?;
    let floor = crate::auth::Timestamp::checked(100, 800_000_000)?;
    assert!(
        before
            .engines
            .observe_kubernetes_artifact_time(AuthorityTime::Precise(floor))
            .map_err(|_| "floor")?
    );
    let original = serde_json::to_vec(&before)?;
    let lower = AuthorityTime::Precise(crate::auth::Timestamp::checked(100, 200_000_000)?);
    assert_eq!(
        before
            .engines
            .kubernetes_artifact_time(lower)
            .map_err(|_| "observed floor")?
            .exact(),
        Some(floor)
    );
    assert!(
        !before
            .engines
            .observe_kubernetes_artifact_time(lower)
            .map_err(|_| "unchanged floor")?
    );
    assert_eq!(serde_json::to_vec(&before)?, original);
    assert!(
        Service::reconcile_lease_owners_observed(&mut before, AuthorityTime::Coarse(201)).is_err()
    );
    assert_eq!(serde_json::to_vec(&before)?, original);
    let mut encoded = serde_json::to_value(&before)?;
    encoded["engines"]["kubernetes_artifact_clock"] =
        json!({"seconds":100,"nanoseconds":200_000_000});
    let rollback: State = serde_json::from_value(encoded)?;
    assert!(rollback.validate_publication_schema(Some(&before)).is_err());
    let mut encoded = serde_json::to_value(&before)?;
    encoded["engines"]
        .as_object_mut()
        .ok_or("engine owner")?
        .remove("kubernetes_artifact_clock");
    let stripped: State = serde_json::from_value(encoded)?;
    assert!(stripped.validate_publication_schema(Some(&before)).is_err());
    Ok(())
}

fn registered_opaque_fixture() -> TestResult<Fixture> {
    let (root, mut service, key, token, plan) = opaque_fixture()?;
    let metadata = token_metadata(
        &opaque_reply(json!({"iat":null,"exp":null}))?,
        &plan.inner,
        101,
    )
    .map_err(|_| "metadata")?;
    let at = AuthorityTime::Precise(crate::auth::Timestamp::whole(101)?);
    let response =
        service.finalize_kubernetes_token_with_observed_clock(&plan, Ok(metadata), || at);
    assert_eq!(response.status, 200, "{}", response.body);
    Ok((root, service, key, token, plan))
}

fn retire_opaque(service: &mut Service, plan: &KubernetesTokenEffectPlan) -> TestResult {
    let mut state = service.state.clone().ok_or("state")?;
    let response = state.engines.handle_lease_admin_observed(
        "",
        "POST",
        "sys/leases/revoke",
        &json!({"lease_id":plan.inner.lease_id}),
        AuthorityTime::Precise(crate::auth::Timestamp::whole(102)?),
    )?;
    assert_eq!(response.status, 204);
    service
        .commit_state(&mut state)
        .map_err(|_| "actual retirement publication")?;
    service.state = Some(state);
    Ok(())
}

fn precise_lifecycle_call(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
    seconds: u64,
) -> TestResult<Response> {
    let clock = RequestClock::anchored(
        std::time::Duration::from_secs(seconds),
        std::time::Instant::now(),
    )?;
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method,
            path,
            namespace: "",
            token,
            body,
            now: seconds,
            allow_forward: false,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        clock,
    );
    let RequestExecution::Complete(response) = execution else {
        return Err("unexpected provider effect".into());
    };
    Ok(response)
}

#[test]
fn kube_opaque_artifact_retired_config_role_changes_and_compaction_survive_real_durable_reopen()
-> TestResult {
    let (root, mut service, key, token, plan) = registered_opaque_fixture()?;
    let active = service.state.clone().ok_or("active")?;
    let receipt = active
        .engines
        .capture_kubernetes_delivery_receipt(&plan.inner)?
        .ok_or("receipt")?;
    let binding = active
        .engines
        .kubernetes_mount_binding("", "kubernetes/creds/reader")
        .ok_or("mount")?;
    retire_opaque(&mut service, &plan)?;
    let retired = service.state.clone().ok_or("retired")?;
    // The direct engine fixture does not enroll process-level outbound trust.
    // This call exercises Service's real configuration gate.
    service.outbound = crate::outbound::Outbound::new(vec![crate::outbound::EndpointConfig {
        origin: "https://localhost:9443".into(),
        address: std::net::SocketAddr::from(([127, 0, 0, 1], 9443)),
        server_name: "localhost".into(),
        ca_pem: include_str!("testdata/kubernetes-api-ca.pem").into(),
        path_prefix: "/api/".into(),
        shared_secret: String::new(),
    }])?;
    let changed = precise_lifecycle_call(
        &mut service,
        "POST",
        "kubernetes/config",
        &token,
        json!({"kubernetes_host":"https://localhost:9443", "service_account_token":"changed-synthetic-manager"}),
        103,
    )?;
    assert_eq!(changed.status, 204, "{}", changed.body);
    let state = service.state.as_ref().ok_or("state")?;
    let encoded = serde_json::to_value(&state.engines)?;
    let kube = &encoded["namespaces"][""]["mounts"]["kubernetes/"]["backend"]["Kubernetes"];
    assert!(kube.get("leases").is_none());
    assert_eq!(kube["compacted_opaque"]["count"], 1);
    assert!(
        state
            .engines
            .validate_kubernetes_delivery_receipt_observed(
                &plan.inner,
                "kubernetes/creds/reader",
                binding,
                &receipt,
                AuthorityTime::Precise(crate::auth::Timestamp::whole(103)?)
            )
            .is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(state, &retired).is_err());
    assert!(Service::validate_snapshot_protected_floor(state, &active).is_err());
    for path in ["kubernetes/roles/reader", "kubernetes/config"] {
        let response =
            precise_lifecycle_call(&mut service, "DELETE", path, &token, json!({}), 104)?;
        assert_eq!(response.status, 204, "{}", response.body);
    }
    let digest = service.current_state_digest().map_err(|_| "digest")?;
    let original = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let mut forged = serde_json::to_value(service.state.as_ref().ok_or("state")?)?;
    forged["engines"]["namespaces"][""]["mounts"]["kubernetes/"]["backend"]["Kubernetes"]["compacted_opaque"]
        ["count"] = json!(2);
    let mut forged: State = serde_json::from_value(forged)?;
    assert!(service.commit_state(&mut forged).is_err());
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
        original
    );
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(reopened.unseal(&json!({"key":key})).status, 200);
    assert_eq!(
        reopened.current_state_digest().map_err(|_| "digest")?,
        digest
    );
    let state = reopened.state.as_ref().ok_or("restored")?;
    assert_eq!(state.schema, KUBERNETES_OPAQUE_ARTIFACT_STATE_SCHEMA);
    assert!(state.engines.has_kubernetes_opaque_artifact_state());
    state.engines.validate_kubernetes_state()?;
    let lookup = precise_lifecycle_call(
        &mut reopened,
        "POST",
        "sys/leases/lookup",
        &token,
        json!({"lease_id":plan.inner.lease_id}),
        105,
    )?;
    assert_eq!(lookup.status, 400, "{}", lookup.body);
    assert!(lookup.body.get("data").is_none());
    Ok(())
}

#[test]
fn kube_opaque_artifact_actual_unmount_recreate_preserves_epoch_and_last_mount_kv_clock()
-> TestResult {
    let (root, mut service, key, token, plan) = registered_opaque_fixture()?;
    let mut seed = service.state.clone().ok_or("state")?;
    let seeded = seed
        .engines
        .handle(
            "",
            "PUT",
            "secret/data/lifecycle",
            &json!({"data":{"value":"durable-secret"}}),
            101,
        )?
        .ok_or("KV seed")?;
    assert_eq!(seeded.status, 200);
    service
        .commit_state(&mut seed)
        .map_err(|_| "seed publication")?;
    service.state = Some(seed);
    let active = service.state.clone().ok_or("active")?;
    let binding = active
        .engines
        .kubernetes_mount_binding("", "kubernetes/creds/reader")
        .ok_or("mount")?;
    let receipt = active
        .engines
        .capture_kubernetes_delivery_receipt(&plan.inner)?
        .ok_or("receipt")?;
    let rejected = precise_lifecycle_call(
        &mut service,
        "DELETE",
        "sys/mounts/kubernetes",
        &token,
        json!({"cas_revision":binding.1}),
        102,
    )?;
    assert_eq!(rejected.status, 409, "{}", rejected.body);
    retire_opaque(&mut service, &plan)?;
    let removed = precise_lifecycle_call(
        &mut service,
        "DELETE",
        "sys/mounts/kubernetes",
        &token,
        json!({"cas_revision":binding.1}),
        103,
    )?;
    assert_eq!(removed.status, 204, "{}", removed.body);
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .has_kubernetes_mount()
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .has_kubernetes_opaque_artifact_state()
    );
    let encoded = serde_json::to_value(&service.state.as_ref().ok_or("state")?.engines)?;
    assert_eq!(
        encoded["namespaces"][""]["mount_epochs"]["kubernetes/"],
        binding.0 + 1
    );
    let reads = service.kv_read_only_dispatches;
    let original = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let coarse = call(
        &mut service,
        "GET",
        "secret/data/lifecycle",
        &token,
        json!({}),
    );
    assert_eq!(coarse.status, 503);
    assert!(coarse.body.get("data").is_none());
    assert_eq!(service.kv_read_only_dispatches, reads);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
        original
    );
    let observed = precise_lifecycle_call(
        &mut service,
        "GET",
        "secret/data/lifecycle",
        &token,
        json!({}),
        104,
    )?;
    assert_eq!(observed.status, 200, "{}", observed.body);
    assert_eq!(observed.body["data"]["data"]["value"], "durable-secret");
    assert_eq!(service.kv_read_only_dispatches, reads);
    assert!(service.durable.as_ref().ok_or("durable")?.generation() > generation);
    let state = service.state.as_ref().ok_or("state")?;
    let encoded = serde_json::to_value(&state.engines)?;
    assert!(
        encoded["kubernetes_artifact_clock"]["seconds"]
            .as_u64()
            .ok_or("clock")?
            >= 104
    );
    let mut downgraded = serde_json::to_value(state)?;
    downgraded["engines"]["namespaces"][""]["mount_epochs"]
        .as_object_mut()
        .ok_or("epochs")?
        .remove("kubernetes/");
    let mut downgraded: State = serde_json::from_value(downgraded)?;
    assert!(Service::validate_snapshot_protected_floor(state, &downgraded).is_err());
    assert!(service.commit_state(&mut downgraded).is_err());
    let recreated = precise_lifecycle_call(
        &mut service,
        "POST",
        "sys/mounts/kubernetes",
        &token,
        json!({"type":"kubernetes", "cas_revision":0}),
        105,
    )?;
    assert_eq!(recreated.status, 204, "{}", recreated.body);
    let state = service.state.as_ref().ok_or("state")?;
    let next_binding = state
        .engines
        .kubernetes_mount_binding("", "kubernetes/creds/reader")
        .ok_or("recreated")?;
    assert!(next_binding.0 > binding.0);
    assert!(
        state
            .engines
            .validate_kubernetes_delivery_receipt_observed(
                &plan.inner,
                "kubernetes/creds/reader",
                binding,
                &receipt,
                AuthorityTime::Precise(crate::auth::Timestamp::whole(105)?)
            )
            .is_err()
    );
    let mut resurrected = serde_json::to_value(state)?;
    let old = serde_json::to_value(&active.engines)?;
    resurrected["engines"]["namespaces"][""]["mounts"]["kubernetes/"]["backend"] =
        old["namespaces"][""]["mounts"]["kubernetes/"]["backend"].clone();
    let mut resurrected: State = serde_json::from_value(resurrected)?;
    assert!(service.commit_state(&mut resurrected).is_err());
    let digest = service.current_state_digest().map_err(|_| "digest")?;
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(reopened.unseal(&json!({"key":key})).status, 200);
    assert_eq!(
        reopened.current_state_digest().map_err(|_| "digest")?,
        digest
    );
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("restored")?
            .engines
            .has_kubernetes_opaque_artifact_state()
    );
    let reads = reopened.kv_read_only_dispatches;
    let observed = precise_lifecycle_call(
        &mut reopened,
        "GET",
        "secret/data/lifecycle",
        &token,
        json!({}),
        106,
    )?;
    assert_eq!(observed.status, 200, "{}", observed.body);
    assert_eq!(observed.body["data"]["data"]["value"], "durable-secret");
    assert_eq!(reopened.kv_read_only_dispatches, reads);
    Ok(())
}
