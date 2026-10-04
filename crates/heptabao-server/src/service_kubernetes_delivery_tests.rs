//! Actual Kubernetes admission, durable lease publication and mandatory local
//! audit with injected typed provider metadata. These are not network oracles.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use std::time::{Duration, Instant};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    files: Root,
    service: Service,
    admin: String,
    actor: String,
    plan: KubernetesTokenEffectPlan,
    fingerprint: String,
    response: Response,
}

fn fixture(ttl: &str, deadline: Option<Instant>, audited: bool) -> TestResult<Fixture> {
    let files = Root::new();
    let mut service = files.service()?;
    // Exercise the real Service config enrollment gate, even though these
    // provider completions inject typed metadata and make no network call.
    service.outbound = crate::outbound::Outbound::new(vec![crate::outbound::EndpointConfig {
        origin: "https://localhost:8443".into(),
        address: std::net::SocketAddr::from(([127, 0, 0, 1], 8443)),
        server_name: "localhost".into(),
        ca_pem: include_str!("testdata/kubernetes-api-ca.pem").into(),
        path_prefix: "/api/".into(),
        shared_secret: String::new(),
    }])?;
    let (_, admin) = bootstrap(&mut service)?;
    for (path, body) in [
        ("sys/mounts/kubernetes", json!({"type":"kubernetes"})),
        (
            "kubernetes/config",
            json!({"kubernetes_host":"https://localhost:8443","service_account_token":"synthetic-manager"}),
        ),
        (
            "kubernetes/roles/reader",
            json!({"allowed_kubernetes_namespaces":["default"],"service_account_name":"reader","token_default_ttl":600,"token_max_ttl":3600}),
        ),
        (
            "sys/policies/acl/kube-delivery",
            json!({"policy":r#"path "kubernetes/creds/*" { capabilities=["update"] }"#}),
        ),
    ] {
        let response = call(&mut service, "POST", path, &admin, body);
        assert_eq!(
            response.status, 204,
            "fixture route {path}: {}",
            response.body
        );
    }
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["kube-delivery"],"no_default_policy":true,"ttl":ttl}),
    );
    assert_eq!(issued.status, 200, "actor issuance");
    let actor = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?
        .to_owned();
    let _deadline_scope = deadline.map(crate::request_deadline::RequestDeadlineScope::enter);
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
        RequestExecution::External(pending) => *pending,
        RequestExecution::Complete(_) => {
            return Err("actual Kubernetes admission did not stage".into());
        }
    };
    let ExternalEffectPlan::KubernetesToken(mut plan) = pending.effect else {
        return Err("actual Kubernetes effect type".into());
    };
    let original = std::ptr::from_ref(plan.response_authority.as_deref().ok_or("original Box")?);
    let mut response = service.finalize_kubernetes_token(
        &mut plan,
        Ok(TokenMetadata {
            token: Zeroizing::new("synthetic-private-delivery-credential".into()),
            expires_at: 700,
            audiences: Vec::new(),
            artifact_lifetime_nanos: None,
        }),
    );
    assert_eq!(response.status, 200, "actual lease publication");
    assert_eq!(
        Some(original),
        plan.response_authority.as_deref().map(std::ptr::from_ref),
        "same original Box survives finalization"
    );
    assert!(plan.committed_receipt.is_some());
    if audited {
        response = service.audit_completed_response_with_receipt(
            &pending.fingerprint,
            pending.now,
            pending.token_clock,
            response,
            || plan.mark_response_audited(&pending.fingerprint),
        );
        assert_eq!(response.status, 200, "actual mandatory audit");
        assert_eq!(
            Some(original),
            plan.response_authority.as_deref().map(std::ptr::from_ref),
            "same Box survives audit"
        );
    }
    Ok(Fixture {
        files,
        service,
        admin,
        actor,
        plan,
        fingerprint: pending.fingerprint,
        response,
    })
}

fn withheld(response: &Response) {
    assert!(!(200..300).contains(&response.status));
    assert!(response.body.get("data").is_none());
    assert!(response.consistency_index.is_none());
    assert!(
        !response
            .body
            .to_string()
            .contains("synthetic-private-delivery-credential")
    );
}

fn veto_audit(fixture: &Fixture, status: u16) -> TestResult {
    let records = std::fs::read_to_string(fixture.files.path.join("audit.jsonl"))?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let veto = records.last().ok_or("veto event")?;
    assert_eq!(veto["event"]["kind"], "kubernetes-delivery-veto");
    assert_eq!(veto["event"]["status"], status);
    assert!(
        records
            .iter()
            .any(|record| record["event"]["kind"] == "response"
                && record["event"]["status"] == 200
                && record["event"]["path_digest"] == veto["event"]["path_digest"])
    );
    Ok(())
}

#[test]
fn kube_delivery_original_box_and_actual_lease_ignore_public_duration_claim() -> TestResult {
    let mut f = fixture("10m", None, true)?;
    f.response.body["lease_duration"] = json!(u64::MAX);
    let response =
        f.service
            .complete_kubernetes_token_delivery(&mut f.plan, f.response, &f.fingerprint);
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["data"]["service_account_token"],
        "synthetic-private-delivery-credential"
    );
    assert!(
        response.body["lease_duration"]
            .as_u64()
            .is_some_and(|ttl| ttl > 0 && ttl <= 600)
    );
    Ok(())
}

#[test]
fn kube_delivery_post_audit_revoke_and_policy_change_withhold_real_published_credential()
-> TestResult {
    for change in ["revoke", "policy"] {
        let mut f = fixture("10m", None, true)?;
        let response = if change == "revoke" {
            call(
                &mut f.service,
                "POST",
                "auth/token/revoke",
                &f.admin,
                json!({"token":f.actor}),
            )
        } else {
            call(
                &mut f.service,
                "POST",
                "sys/policies/acl/kube-delivery",
                &f.admin,
                json!({"policy":r#"path "kubernetes/creds/*" { capabilities=["deny"] }"#}),
            )
        };
        assert_eq!(response.status, 204, "actual actor mutation");
        let response = std::mem::replace(&mut f.response, Response::error(500, "moved"));
        let denied =
            f.service
                .complete_kubernetes_token_delivery(&mut f.plan, response, &f.fingerprint);
        assert_eq!(denied.status, 403);
        withheld(&denied);
        veto_audit(&f, 403)?;
    }
    Ok(())
}

#[test]
fn kube_delivery_frozen_provider_config_preserves_owner_and_real_mount_revision_rejects()
-> TestResult {
    for change in ["provider", "mount-revision"] {
        let mut f = fixture("10m", None, true)?;
        if change == "provider" {
            // Existing leases make this configuration update unreachable:
            // observe the real 409 rather than inventing a changed config.
            // The first ordinary request after typed injected completion may
            // legitimately persist the existing Engine observation floor.
            // Establish it with an actual lookup, never omit/normalize it.
            let observed = call(
                &mut f.service,
                "POST",
                "sys/leases/lookup",
                &f.admin,
                json!({"lease_id":f.plan.inner.lease_id}),
            );
            assert_eq!(observed.status, 200, "{}", observed.body);
            assert_eq!(
                f.service
                    .state
                    .as_ref()
                    .ok_or("state")?
                    .engines
                    .lease_clock(),
                100
            );
            let before = serde_json::to_vec(f.service.state.as_ref().ok_or("state")?)?;
            let rejected = call(
                &mut f.service,
                "POST",
                "kubernetes/config",
                &f.admin,
                json!({"kubernetes_host":"https://localhost:8443","service_account_token":"synthetic-replacement-manager"}),
            );
            assert_eq!(rejected.status, 409, "{}", rejected.body);
            assert_eq!(
                rejected.body["errors"],
                json!(["Kubernetes configuration is frozen while token intents or leases exist"])
            );
            assert_eq!(
                serde_json::to_vec(f.service.state.as_ref().ok_or("state")?)?,
                before
            );
            let delivered = f.service.complete_kubernetes_token_delivery(
                &mut f.plan,
                f.response,
                &f.fingerprint,
            );
            assert_eq!(
                delivered.status, 200,
                "rejected config leaves the owner unchanged"
            );
            assert_eq!(
                delivered.body["data"]["service_account_token"],
                "synthetic-private-delivery-credential"
            );
            continue;
        }
        // DELETE/remount are correctly fenced while this actual lease exists.
        // Tune is reachable and changes the real committed mount revision;
        // the original Box and committed receipt must reject that new owner.
        let before_binding = f
            .service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .kubernetes_mount_binding("", "kubernetes/creds/reader")
            .ok_or("admitted mount binding")?;
        let tuned = call(
            &mut f.service,
            "POST",
            "sys/mounts/kubernetes/tune",
            &f.admin,
            json!({"description":"real post-audit revision change"}),
        );
        assert_eq!(tuned.status, 204, "{}", tuned.body);
        let after_binding = f
            .service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .kubernetes_mount_binding("", "kubernetes/creds/reader")
            .ok_or("changed mount binding")?;
        assert_eq!(
            after_binding,
            (
                before_binding.0,
                before_binding.1.checked_add(1).ok_or("revision overflow")?
            )
        );
        let response = std::mem::replace(&mut f.response, Response::error(500, "moved"));
        let denied =
            f.service
                .complete_kubernetes_token_delivery(&mut f.plan, response, &f.fingerprint);
        assert_eq!(denied.status, 503);
        withheld(&denied);
        veto_audit(&f, 503)?;
    }
    Ok(())
}

#[test]
fn kube_delivery_public_lease_json_cannot_replace_missing_private_receipt_or_audit() -> TestResult {
    for missing in ["receipt", "audit", "fingerprint"] {
        let mut f = fixture("10m", None, missing != "audit")?;
        f.response.body["lease_id"] = json!(f.plan.inner.lease_id);
        f.response.body["committed"] = json!(true);
        if missing == "receipt" {
            f.plan.committed_receipt = None;
        }
        let fingerprint = if missing == "fingerprint" {
            "different-original-request"
        } else {
            &f.fingerprint
        };
        let denied =
            f.service
                .complete_kubernetes_token_delivery(&mut f.plan, f.response, fingerprint);
        assert_eq!(denied.status, 503);
        withheld(&denied);
    }
    Ok(())
}

#[test]
fn kube_delivery_actual_committed_lease_retirement_rejects_receipt() -> TestResult {
    let mut f = fixture("10m", None, true)?;
    assert_eq!(
        call(
            &mut f.service,
            "POST",
            "sys/leases/revoke",
            &f.admin,
            json!({"lease_id":f.plan.inner.lease_id})
        )
        .status,
        204
    );
    let response = std::mem::replace(&mut f.response, Response::error(500, "moved"));
    let denied =
        f.service
            .complete_kubernetes_token_delivery(&mut f.plan, response, &f.fingerprint);
    assert_eq!(denied.status, 503);
    withheld(&denied);
    veto_audit(&f, 503)?;
    Ok(())
}

#[test]
fn kube_delivery_actual_actor_expiry_after_audit_erases_credential() -> TestResult {
    let mut f = fixture("1s", None, true)?;
    std::thread::sleep(Duration::from_millis(1100));
    let response = std::mem::replace(&mut f.response, Response::error(500, "moved"));
    let denied =
        f.service
            .complete_kubernetes_token_delivery(&mut f.plan, response, &f.fingerprint);
    assert_eq!(denied.status, 403);
    withheld(&denied);
    veto_audit(&f, 403)?;
    Ok(())
}

#[test]
fn kube_delivery_original_deadline_expiry_after_audit_has_no_new_budget() -> TestResult {
    let mut f = fixture("10m", Some(Instant::now() + Duration::from_secs(2)), true)?;
    std::thread::sleep(Duration::from_millis(2100));
    let response = std::mem::replace(&mut f.response, Response::error(500, "moved"));
    let denied =
        f.service
            .complete_kubernetes_token_delivery(&mut f.plan, response, &f.fingerprint);
    assert_eq!(denied.status, 503);
    withheld(&denied);
    // The expired original deadline can also reject the negative audit; either
    // outcome is closed and no provider request or response retry is introduced.
    Ok(())
}

#[test]
fn kube_delivery_negative_audit_capacity_failure_fences_without_private_body() -> TestResult {
    let mut f = fixture("10m", None, true)?;
    assert_eq!(
        call(
            &mut f.service,
            "POST",
            "auth/token/revoke",
            &f.admin,
            json!({"token":f.actor})
        )
        .status,
        204
    );
    let before = std::fs::read(f.files.path.join("audit.jsonl"))?;
    f.service.audit_capacity = f.service.audit.metadata()?.len();
    let denied =
        f.service
            .complete_kubernetes_token_delivery(&mut f.plan, f.response, &f.fingerprint);
    assert_eq!(denied.status, 503);
    withheld(&denied);
    assert!(f.service.recovery_required);
    assert!(f.service.ha_activation.is_none());
    assert_eq!(std::fs::read(f.files.path.join("audit.jsonl"))?, before);
    Ok(())
}
