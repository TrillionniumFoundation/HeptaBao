//! Actual affine actor issuance and TLS provider effects around expiry and audit.
use super::*;
use crate::auth::{LeaseOwner, RequestClock, Timestamp};
use std::time::{Duration, Instant};

fn precise_dispatch(
    service: &mut Service,
    actor: &str,
    path: &str,
    body: Value,
    clock: RequestClock,
) -> RequestExecution {
    if let (Some(state), Ok(at)) = (service.state.as_ref(), clock.observed_at()) {
        eprintln!(
            "PKI_NANO_OBSERVER_SAFE path={} original_elapsed_ns={} raw_time={}.{:09} engine_floor={} auth_floor={:?}",
            path,
            clock.started().elapsed().as_nanos(),
            at.seconds(),
            at.duration_since_epoch().subsec_nanos(),
            state.engines.lease_clock(),
            state
                .auth
                .terminal_token_clock_floor()
                .map(|t| (t.seconds(), t.duration_since_epoch().subsec_nanos()))
        );
    }
    service.begin_at_mode_precise(
        RequestDispatch {
            method: "POST",
            path,
            namespace: "",
            token: actor,
            body,
            now: 100,
            allow_forward: true,
            enforce_namespace: false,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        clock,
    )
}

fn actor_in_service(service: &mut Service, admin: &str) -> TestResult<(String, u64)> {
    let state = service.state.as_ref().ok_or("issuer fixture state")?;
    let auth_floor = state.auth.terminal_token_clock_floor();
    let base = state
        .engines
        .lease_clock()
        .max(100)
        .max(auth_floor.map_or(0, |at| {
            at.seconds() + u64::from(at.duration_since_epoch().subsec_nanos() >= 250_000_000)
        }));
    let clock = RequestClock::anchored(Duration::new(base, 250_000_000), Instant::now())?;
    let execution = precise_dispatch(
        service,
        admin,
        "auth/token/create",
        json!({"ttl":"2s","policies":["nano-pki"],"no_default_policy":true}),
        clock,
    );
    let response = service.finish_synchronous_request(execution);
    assert_eq!(response.status, 200, "actual precise actor issuance");
    let actor = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("actual actor")?
        .to_owned();
    let owner = LeaseOwner::service(&base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        crate::crypto::digest(actor.as_bytes()),
    ))?;
    let binding = service
        .state
        .as_ref()
        .ok_or("actor state")?
        .auth
        .resolve_lease_owner_observed(
            &owner,
            "",
            crate::auth::AuthorityTime::Precise(clock.observed_at()?),
        )
        .ok_or("actual actor lease owner")?;
    assert_eq!(
        binding.expires_at,
        Some(base + 3),
        "public ceil is not private expiry"
    );
    let expiry = binding
        .precise_expires_at
        .ok_or("actual private actor expiry")?;
    eprintln!(
        "PKI_NANO_OBSERVER_SAFE actual_actor_expiry={}.{:09} engine_floor={} actual_issuer_elapsed_ns={}",
        expiry.seconds(),
        expiry.duration_since_epoch().subsec_nanos(),
        service.state.as_ref().ok_or("state")?.engines.lease_clock(),
        clock.started().elapsed().as_nanos()
    );
    assert_eq!(expiry.seconds(), base + 2);
    assert!(expiry < Timestamp::checked(base + 2, 500_000_000)?);
    Ok((actor, base))
}

fn actor_fixture(remote: &RemoteTransit) -> TestResult<(Root, Service, String, String, u64)> {
    let (root, mut service, _unseal, admin) = leaf_fixture(remote)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/nano-pki",
            &admin,
            json!({"policy":r#"path "external-ca/issue/leaf" { capabilities=["update"] }"#}),
        )
        .status,
        204
    );
    let (actor, base) = actor_in_service(&mut service, &admin)?;
    Ok((root, service, admin, actor, base))
}

#[test]
fn pki_nano_tls_provider_before_entry_metadata_and_signature_expiry_never_retries() -> TestResult {
    for cut in 0..3 {
        let remote = RemoteTransit::new_kind("ed25519")?;
        let (_root, mut service, _admin, actor, base) = actor_fixture(&remote)?;
        let before = remote.calls()?;
        let clock = RequestClock::anchored(Duration::new(base, 500_000_000), Instant::now())?;
        let pending = match precise_dispatch(
            &mut service,
            &actor,
            "external-ca/issue/leaf",
            json!({"common_name":"leaf.example.test","ttl":"10m"}),
            clock,
        ) {
            RequestExecution::External(pending) => *pending,
            RequestExecution::Complete(response) => {
                return Err(format!("actual staging status {}", response.status).into());
            }
        };
        let until = clock.started() + Duration::from_millis(2100);
        if cut == 0 {
            std::thread::sleep(until.saturating_duration_since(Instant::now()));
        } else {
            remote.delay_response_at(before + cut, until)?;
        }
        let result = pending.execute();
        let response = service.finish_external_request(pending, result);
        assert_eq!(
            response.status, 403,
            "expired original private actor at cut {cut}"
        );
        assert!(response.body.get("data").is_none());
        assert!(response.body.get("auth").is_none());
        assert_eq!(
            remote.calls()?,
            before + cut,
            "no later sign or retry after cut {cut}"
        );
        // Terminal private clock persistence can publish observation state; the
        // certificate domain must remain empty despite a real remote signature.
        let mut state = serde_json::to_value(
            &service
                .state
                .as_ref()
                .ok_or("actual resulting state")?
                .engines,
        )?;
        let count = state["namespaces"][""]["mounts"]["external-ca/"]["backend"]["Pki"]["issued"]
            .as_object()
            .ok_or("actual certificate index")?
            .len();
        erase_json(&mut state);
        assert_eq!(
            count, 0,
            "no public certificate publication after cut {cut}"
        );
    }
    Ok(())
}

#[test]
fn pki_nano_tls_actual_signed_publication_then_post_audit_actor_expiry_withholds_private()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (root, mut service, _admin, actor, base) = actor_fixture(&remote)?;
    let before = remote.calls()?;
    let clock = RequestClock::anchored(Duration::new(base, 500_000_000), Instant::now())?;
    let pending = match precise_dispatch(
        &mut service,
        &actor,
        "external-ca/issue/leaf",
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
        clock,
    ) {
        RequestExecution::External(pending) => *pending,
        RequestExecution::Complete(response) => {
            return Err(format!("actual staging status {}", response.status).into());
        }
    };
    let result = pending.execute();
    let (mut plan, result) = match (pending.effect, result) {
        (ExternalEffectPlan::ExternalPki(plan), ExternalEffectResult::ExternalPki(result)) => {
            (plan, result)
        }
        _ => return Err("actual external signing observation".into()),
    };
    let response = service.finalize_external_pki(&mut plan, result);
    assert_eq!(
        response.status, 200,
        "actual verified signature durably published"
    );
    assert_eq!(response.body["data"]["expiration"], base + 2);
    let certificate = response.body["data"]["certificate"]
        .as_str()
        .ok_or("actual signed certificate")?;
    let issuer_pem = response.body["data"]["issuing_ca"]
        .as_str()
        .ok_or("actual issuer certificate")?;
    let cert = openssl::x509::X509::from_pem(certificate.as_bytes())?;
    let issuer = openssl::x509::X509::from_pem(issuer_pem.as_bytes())?;
    let issuer_public = issuer.public_key()?;
    assert!(cert.verify(&issuer_public)?);
    let committed = service
        .state
        .as_ref()
        .ok_or("actual published state")?
        .engines
        .clone();
    let response = service.audit_external_pki_response(
        &mut plan,
        &pending.fingerprint,
        (pending.now, pending.token_clock),
        response,
        || {
            std::thread::sleep(
                (clock.started() + Duration::from_millis(2100))
                    .saturating_duration_since(Instant::now()),
            )
        },
    );
    assert_eq!(
        response.status, 200,
        "real response audit completed before private veto"
    );
    let response =
        service.complete_external_pki_delivery(&mut plan, response, &pending.fingerprint);
    assert_eq!(
        response.status, 403,
        "private actor expired before its later public ceil"
    );
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("auth").is_none());
    assert_eq!(
        remote.calls()?,
        before + 2,
        "one actual metadata and one signature only"
    );
    assert_eq!(
        serde_json::to_vec(&service.state.as_ref().ok_or("resulting state")?.engines)?,
        serde_json::to_vec(&committed)?
    );
    let records = fs::read_to_string(root.path.join("audit.jsonl"))?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let success = records
        .iter()
        .rev()
        .nth(1)
        .ok_or("actual planned response audit")?;
    let veto = records.last().ok_or("actual final veto audit")?;
    assert_eq!(success["event"]["kind"], "response");
    assert_eq!(success["event"]["status"], 200);
    assert_eq!(veto["event"]["kind"], "external-pki-delivery-veto");
    assert_eq!(veto["event"]["status"], 403);
    assert_eq!(
        success["event"]["path_digest"],
        veto["event"]["path_digest"]
    );
    Ok(())
}

#[test]
fn pki_nano_tls_live_precise_actor_delivers_after_actual_terminal_clock_audit() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _admin, actor, base) = actor_fixture(&remote)?;
    let before = remote.calls()?;
    let clock = RequestClock::anchored(Duration::new(base, 500_000_000), Instant::now())?;
    let execution = precise_dispatch(
        &mut service,
        &actor,
        "external-ca/issue/leaf",
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
        clock,
    );
    let response = service.finish_synchronous_request(execution);
    assert_eq!(
        response.status, 200,
        "live precise actor must survive its owned clock-only audit write"
    );
    assert_eq!(response.body["data"]["expiration"], base + 2);
    assert!(response.body["data"]["private_key"].as_str().is_some());
    assert_eq!(remote.calls()?, before + 2);
    Ok(())
}

#[test]
fn pki_nano_tls_clock_receipt_cannot_carry_unrelated_state_before_or_after_audit() -> TestResult {
    for before_audit in [true, false] {
        let remote = RemoteTransit::new_kind("ed25519")?;
        let (_root, mut service, admin, actor, base) = actor_fixture(&remote)?;
        let before = remote.calls()?;
        let clock = RequestClock::anchored(Duration::new(base, 500_000_000), Instant::now())?;
        let pending = match precise_dispatch(
            &mut service,
            &actor,
            "external-ca/issue/leaf",
            json!({"common_name":"leaf.example.test","ttl":"10m"}),
            clock,
        ) {
            RequestExecution::External(pending) => *pending,
            RequestExecution::Complete(response) => {
                return Err(format!("actual staging status {}", response.status).into());
            }
        };
        let result = pending.execute();
        let (mut plan, result) = match (pending.effect, result) {
            (ExternalEffectPlan::ExternalPki(plan), ExternalEffectResult::ExternalPki(result)) => {
                (plan, result)
            }
            _ => return Err("actual external signing observation".into()),
        };
        let response = service.finalize_external_pki(&mut plan, result);
        assert_eq!(response.status, 200, "real signed certificate publication");
        let mutate = |service: &mut Service| -> TestResult {
            let execution = precise_dispatch(
                service,
                &admin,
                "external-ca/roles/unrelated",
                json!({"allow_any_name":true,"key_type":"ed25519","ttl":"10m"}),
                RequestClock::anchored(Duration::new(base, 600_000_000), Instant::now())?,
            );
            assert_eq!(
                service.finish_synchronous_request(execution).status,
                200,
                "unrelated role is really durably written"
            );
            Ok(())
        };
        if before_audit {
            mutate(&mut service)?;
        }
        let response = service.audit_external_pki_response(
            &mut plan,
            &pending.fingerprint,
            (pending.now, pending.token_clock),
            response,
            || {},
        );
        assert_eq!(response.status, 200, "actual response audit");
        if !before_audit {
            mutate(&mut service)?;
        }
        let response =
            service.complete_external_pki_delivery(&mut plan, response, &pending.fingerprint);
        assert_eq!(
            response.status, 503,
            "clock receipt cannot carry unrelated role write"
        );
        assert!(response.body.get("data").is_none());
        assert_eq!(remote.calls()?, before + 2, "veto never repeats signing");
    }
    Ok(())
}

#[test]
fn pki_nano_actual_durable_floor_rejects_prior_actor_and_new_fixture_owns_current_time()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, admin, actor, original_base) = actor_fixture(&remote)?;
    let precursor = precise_dispatch(
        &mut service,
        &admin,
        "external-ca/issue/leaf",
        json!({"common_name":"precursor.example.test","ttl":"10m"}),
        RequestClock::anchored(
            Duration::new(original_base + 5, 500_000_000),
            Instant::now(),
        )?,
    );
    assert_eq!(service.finish_synchronous_request(precursor).status, 200);
    let floor = service
        .state
        .as_ref()
        .ok_or("actual durable floor")?
        .engines
        .lease_clock();
    assert!(
        floor >= original_base + 5,
        "actual signed precursor advances the engine clock"
    );
    let before = remote.calls()?;
    let old = precise_dispatch(
        &mut service,
        &actor,
        "external-ca/issue/leaf",
        json!({"common_name":"old-actor.example.test","ttl":"10m"}),
        RequestClock::anchored(Duration::new(original_base, 500_000_000), Instant::now())?,
    );
    let RequestExecution::Complete(response) = old else {
        return Err("expired prior actor must be vetoed before provider staging".into());
    };
    eprintln!(
        "PKI_NANO_FLOOR_SAFE floor={} old_actor_status={} static_errors={:?}",
        floor,
        response.status,
        response.body.get("errors")
    );
    assert_eq!(response.status, 403);
    assert_eq!(
        remote.calls()?,
        before,
        "expired prior actor never reaches metadata or sign"
    );
    let (current_actor, base) = actor_in_service(&mut service, &admin)?;
    assert!(base >= floor);
    let current = precise_dispatch(
        &mut service,
        &current_actor,
        "external-ca/issue/leaf",
        json!({"common_name":"current-actor.example.test","ttl":"10m"}),
        RequestClock::anchored(Duration::new(base, 500_000_000), Instant::now())?,
    );
    let delivered = service.finish_synchronous_request(current);
    assert_eq!(delivered.status, 200);
    assert_eq!(delivered.body["data"]["expiration"], base + 2);
    let certificate = openssl::x509::X509::from_pem(
        delivered.body["data"]["certificate"]
            .as_str()
            .ok_or("actual certificate")?
            .as_bytes(),
    )?;
    let issuer = openssl::x509::X509::from_pem(
        delivered.body["data"]["issuing_ca"]
            .as_str()
            .ok_or("actual issuer")?
            .as_bytes(),
    )?;
    let public = issuer.public_key()?;
    assert!(certificate.verify(&public)?);
    assert_eq!(
        remote.calls()?,
        before + 2,
        "new actual2s actor has exactly one metadata and sign"
    );
    Ok(())
}
