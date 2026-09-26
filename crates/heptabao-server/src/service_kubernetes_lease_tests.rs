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
    service.commit_state(&state).map_err(|_| "commit")?;
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
    service.commit_state(&state).map_err(|_| "commit revoke")?;
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
                .commit_state(&state)
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
    service
        .commit_state(&state)
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
