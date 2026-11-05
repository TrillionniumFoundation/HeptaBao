//! Reuse the unchanged formal three-node Raft fixture and pinned TLS transport.
//! These are actual process-local File/Raft regressions, not physical-host or
//! public HTTPS acceptance. All calls retain the fixture's original 15 seconds.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

const SELF: &str = "sys/capabilities-self";
const TOKEN: &str = "sys/capabilities";
const ACCESSOR: &str = "sys/capabilities-accessor";
const RESOURCE: &str = "secret/data/pipeline/history";
const SUBJECT_POLICY: &str = r#"
path "sys/capabilities-self" { capabilities=["update"] }
path "secret/data/pipeline/history" { capabilities=["read"] }
"#;
const INSPECTOR_POLICY: &str = r#"
path "sys/capabilities" { capabilities=["update"] }
path "sys/capabilities-accessor" { capabilities=["update"] }
path "sys/capabilities-self" { capabilities=["update"] }
"#;

struct Credential {
    raw: Zeroizing<String>,
    accessor: Zeroizing<String>,
}

fn policy(p: &MissingRoutePipeline, node: usize, name: &str, text: &str) -> TestResult {
    expect(
        p.call(
            node,
            "PUT",
            &format!("sys/policies/acl/{name}"),
            p.admin(),
            json!({"policy":text}),
        )?,
        204,
        "formal-capabilities-policy",
    )?;
    Ok(())
}

fn issue(p: &MissingRoutePipeline, node: usize, name: &str, uses: u64) -> TestResult<Credential> {
    let mut response = expect(
        p.call(
            node,
            "POST",
            "auth/token/create",
            p.admin(),
            json!({"policies":[name],"no_default_policy":true,"num_uses":uses,"ttl":"1h"}),
        )?,
        200,
        "formal-capabilities-credential",
    )?;
    let raw = secret_field(&mut response, "/auth/client_token")?;
    let accessor = secret_field(&mut response, "/auth/accessor")?;
    erase_json(&mut response.body);
    Ok(Credential { raw, accessor })
}

fn inspect(
    p: &MissingRoutePipeline,
    node: usize,
    actor: &str,
    target: &Credential,
    path: &str,
) -> TestResult<Response> {
    let body = match path {
        SELF => json!({"paths":[RESOURCE]}),
        TOKEN => json!({"paths":[RESOURCE],"token":target.raw.as_str()}),
        ACCESSOR => json!({"paths":[RESOURCE],"accessor":target.accessor.as_str()}),
        _ => return Err("invalid capabilities test path".into()),
    };
    p.call(node, "POST", path, actor, body)
}

fn caps(response: Response, expected: &[&str]) -> TestResult {
    let response = expect(response, 200, "formal-capabilities-result")?;
    assert_eq!(response.body["data"][RESOURCE], json!(expected));
    assert_eq!(response.body[RESOURCE], json!(expected));
    assert_eq!(response.body["capabilities"], json!(expected));
    assert!(response.body.get("auth").is_none());
    assert!(response.unwrapped_json.is_none() && response.response_headers.is_empty());
    Ok(())
}

fn withheld(response: Response) -> TestResult {
    let response = expect(response, 503, "formal-capabilities-owned-result-withheld")?;
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("capabilities").is_none());
    assert!(response.body.get(RESOURCE).is_none());
    assert!(response.unwrapped_json.is_none() && response.response_headers.is_empty());
    assert!(response.consistency_index.is_none());
    Ok(())
}

fn remaining(p: &MissingRoutePipeline, node: usize, target: &Credential) -> TestResult<u64> {
    let response = expect(
        p.call(
            node,
            "POST",
            "auth/token/lookup-accessor",
            p.admin(),
            json!({"accessor":target.accessor.as_str()}),
        )?,
        200,
        "formal-target-use-count",
    )?;
    response.body["data"]["num_uses"]
        .as_u64()
        .ok_or_else(|| "formal target finite-use count".into())
}

#[test]
fn native_capabilities_formal_ha_forwarding_finite_uses_election_and_cold_rejoin() -> TestResult {
    let mut p = MissingRoutePipeline::start()?;
    let leader = p.ready_leader()?;
    let standby = (leader + 1) % 3;
    policy(&p, leader, "cap-subject", SUBJECT_POLICY)?;
    policy(&p, leader, "cap-inspector", INSPECTOR_POLICY)?;
    let target = issue(&p, leader, "cap-subject", 1)?;
    let inspector = issue(&p, leader, "cap-inspector", 0)?;
    let finite = issue(&p, leader, "cap-inspector", 1)?;
    // Actual HTTP parsing and standby forwarding retain the original numeric
    // carrier; the leader may not recreate weak strings from decoded Values.
    let payload = r#"{"paths":[1.00,1E+08,-0,9007199254740993]}"#;
    let wire = Zeroizing::new(format!(
        "POST /v1/sys/capabilities-self HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        inspector.raw.as_str(),
        payload.len(),
    ));
    let mut transport_error = None;
    let response = {
        // Preserve this fixture's original 15-second scope before the real
        // parser, whose standalone fallback budget would otherwise be 5 seconds.
        let _scope = scope();
        crate::http::logical_data_wire_dispatch_fixture(wire.as_bytes(), |request| {
            match p.call(
                standby,
                request.method,
                request.path,
                request.token,
                request.body,
            ) {
                Ok(response) => response,
                Err(error) => {
                    transport_error = Some(error);
                    Response::error(503, "actual HA capability transport failed")
                }
            }
        })?
    };
    if let Some(error) = transport_error {
        return Err(error);
    }
    let response = expect(response, 200, "formal-capabilities-HTTP-forwarded-carrier")?;
    for path in ["1.00", "1E+08", "-0", "9007199254740993"] {
        assert_eq!(response.body["data"][path], json!(["deny"]));
    }
    caps(
        inspect(&p, standby, &finite.raw, &target, TOKEN)?,
        &["read"],
    )?;
    for node in 0..3 {
        expect(
            inspect(&p, node, &finite.raw, &target, TOKEN)?,
            403,
            "finite inspector spent once across actual replicas",
        )?;
        caps(
            inspect(&p, node, &inspector.raw, &target, ACCESSOR)?,
            &["read"],
        )?;
        assert_eq!(remaining(&p, node, &target)?, 1);
        p.assert_history(node, &[(1, "seed-v5")])?;
    }
    p.stop_process(leader)?;
    let next = p.ready_leader()?;
    assert_ne!(leader, next);
    caps(
        inspect(&p, next, &inspector.raw, &target, TOKEN)?,
        &["read"],
    )?;
    p.start_formal_process(leader)?;
    p.wait_cold_native_readindex_ready(leader)?;
    p.unseal(leader)?;
    caps(
        inspect(&p, leader, &inspector.raw, &target, ACCESSOR)?,
        &["read"],
    )?;
    for node in 0..3 {
        p.stop_process(node)?;
    }
    for node in [1, 2, 0] {
        p.start_formal_process(node)?;
    }
    let leader = p.ready_leader()?;
    for node in std::iter::once(leader).chain((0..3).filter(|node| *node != leader)) {
        p.unseal(node)?;
    }
    for node in 0..3 {
        caps(
            inspect(&p, node, &inspector.raw, &target, TOKEN)?,
            &["read"],
        )?;
        assert_eq!(remaining(&p, node, &target)?, 1);
        expect(
            inspect(&p, node, &finite.raw, &target, TOKEN)?,
            403,
            "finite inspector is not restored by cold election",
        )?;
    }
    // All prior target/accessor reads were non-consuming. Official 2.7.1's
    // actual final self admission spends the use but returns invalid-token 400.
    let spent = expect(
        inspect(&p, (leader + 1) % 3, &target.raw, &target, SELF)?,
        400,
        "official final-use self is an invalid inspection target",
    )?;
    assert_eq!(
        spent.body["errors"],
        json!(["1 error occurred:\n\t* invalid token\n\n"])
    );
    assert!(spent.body.get("data").is_none());
    for node in 0..3 {
        expect(
            inspect(&p, node, &target.raw, &target, SELF)?,
            403,
            "original target final use consumed once",
        )?;
        p.assert_history(node, &[(1, "seed-v5")])?;
    }
    Ok(())
}

#[test]
fn native_capabilities_formal_ha_actual_post_audit_policy_actor_and_target_changes() -> TestResult {
    let mut p = MissingRoutePipeline::start()?;
    let leader = p.ready_leader()?;
    policy(&p, leader, "cap-inspector", INSPECTOR_POLICY)?;
    let mut retired = Vec::new();
    for case in 0..3 {
        policy(&p, leader, "cap-subject", SUBJECT_POLICY)?;
        let target = issue(&p, leader, "cap-subject", 1)?;
        let inspector = issue(&p, leader, "cap-inspector", 0)?;
        let writer = p.admin.clone();
        let revoked = if case == 2 {
            inspector.raw.clone()
        } else {
            target.raw.clone()
        };
        let observed = Arc::new(AtomicBool::new(false));
        let hook_observed = Arc::clone(&observed);
        let _hook = crate::service::native_auth::capabilities_tests::after_audit(
            move |service, response| {
                assert_eq!(response.status, 200);
                assert_eq!(response.body["data"][RESOURCE], json!(["read"]));
                hook_observed.store(true, Ordering::SeqCst);
                let changed =
                    if case == 0 {
                        service.handle("PUT", "sys/policies/acl/cap-subject", "", &writer,
                        json!({"policy":r#"path "sys/capabilities-self" { capabilities=["update"] }
path "secret/data/pipeline/history" { capabilities=["update"] }"#}))
                    } else {
                        service.handle(
                            "POST",
                            "auth/token/revoke",
                            "",
                            &writer,
                            json!({"token":revoked.as_str()}),
                        )
                    };
                assert_eq!(changed.status, 204);
            },
        )?;
        // The hook runs on the actual leader after its response audit. No test
        // thread-local hook is mistaken for one running on a forward worker.
        withheld(inspect(&p, leader, &inspector.raw, &target, ACCESSOR)?)?;
        assert!(observed.load(Ordering::SeqCst));
        if case == 0 {
            for node in 0..3 {
                caps(
                    inspect(&p, node, &inspector.raw, &target, TOKEN)?,
                    &["update"],
                )?;
                assert_eq!(remaining(&p, node, &target)?, 1);
            }
        } else if case == 1 {
            for node in 0..3 {
                expect(
                    inspect(&p, node, &target.raw, &target, SELF)?,
                    403,
                    "actual inspected target revoked on all replicas",
                )?;
            }
            retired.push(target.raw.clone());
        } else {
            for node in 0..3 {
                expect(
                    inspect(&p, node, &inspector.raw, &target, TOKEN)?,
                    403,
                    "actual requesting actor revoked on all replicas",
                )?;
                assert_eq!(remaining(&p, node, &target)?, 1);
            }
            retired.push(inspector.raw.clone());
        }
    }
    p.stop_process(leader)?;
    let next = p.ready_leader()?;
    p.start_formal_process(leader)?;
    p.wait_cold_native_readindex_ready(leader)?;
    p.unseal(leader)?;
    for raw in &retired {
        for node in [next, leader] {
            expect(
                p.call(node, "POST", SELF, raw, json!({"paths":[RESOURCE]}))?,
                403,
                "post-audit revocation survives election and actual cold owner",
            )?;
        }
    }
    for node in 0..3 {
        p.assert_history(node, &[(1, "seed-v5")])?;
    }
    Ok(())
}

#[test]
fn native_capabilities_formal_ha_real_quorum_loss_cannot_release_inspection() -> TestResult {
    let mut p = MissingRoutePipeline::start()?;
    let leader = p.ready_leader()?;
    policy(&p, leader, "cap-subject", SUBJECT_POLICY)?;
    policy(&p, leader, "cap-inspector", INSPECTOR_POLICY)?;
    let target = issue(&p, leader, "cap-subject", 1)?;
    let inspector = issue(&p, leader, "cap-inspector", 0)?;
    caps(
        inspect(&p, leader, &inspector.raw, &target, TOKEN)?,
        &["read"],
    )?;
    let stopped: Vec<_> = (0..3).filter(|node| *node != leader).collect();
    for node in &stopped {
        p.stop_process(*node)?;
    }
    withheld(inspect(&p, leader, &inspector.raw, &target, ACCESSOR)?)?;
    for node in &stopped {
        p.start_formal_process(*node)?;
    }
    let current = p.ready_leader()?;
    for node in &stopped {
        p.wait_cold_native_readindex_ready(*node)?;
        p.unseal(*node)?;
    }
    caps(
        inspect(&p, current, &inspector.raw, &target, TOKEN)?,
        &["read"],
    )?;
    assert_eq!(remaining(&p, current, &target)?, 1);
    p.assert_history(current, &[(1, "seed-v5")])?;
    Ok(())
}
