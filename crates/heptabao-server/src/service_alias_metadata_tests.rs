//! Actual static signed JWT dispatch proves alias metadata shares login publication.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{Ed25519KeyPair, KeyPair};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture(root: &Root) -> TestResult<(Service, String, String, String)> {
    let mut service = root.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let pair = Ed25519KeyPair::from_seed_unchecked(&[72; 32]).map_err(|_| "test key")?;
    for (path, body) in [
        ("sys/auth/jwt", json!({"type":"jwt"})),
        (
            "auth/jwt/config",
            json!({"issuer":"https://issuer.example","audiences":["service"],
            "keys":[{"kid":"key","algorithm":"EdDSA","key_base64":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())}]}),
        ),
        (
            "auth/jwt/role/first",
            json!({"role_type":"jwt","bound_audiences":["service"],"token_ttl":60,"token_max_ttl":600}),
        ),
        (
            "auth/jwt/role/second",
            json!({"role_type":"jwt","bound_audiences":["service"],"token_ttl":60,"token_max_ttl":600}),
        ),
    ] {
        assert_eq!(
            call(&mut service, "POST", path, &admin, body).status,
            204,
            "{path}"
        );
    }
    let signed = format!("{}.{}", URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"key"}"#),
        URL_SAFE_NO_PAD.encode(br#"{"iss":"https://issuer.example","aud":"service","sub":"subject","iat":100,"exp":1000}"#));
    let jwt = format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(pair.sign(signed.as_bytes()).as_ref())
    );
    Ok((service, key, admin, jwt))
}
fn login(service: &mut Service, jwt: &str, role: &str, wrap: Option<u64>) -> Response {
    service.handle_at_mode(RequestDispatch {
        method: "POST",
        path: "auth/jwt/login",
        namespace: "",
        token: "",
        body: json!({"role":role,"jwt":jwt}),
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: wrap,
        origin_peer: None,
        client_certificates: None,
    })
}
fn alias(service: &mut Service, admin: &str, entity: &str) -> TestResult<Value> {
    let response = call(
        service,
        "GET",
        &format!("identity/entity/id/{entity}"),
        admin,
        json!({}),
    );
    assert_eq!(response.status, 200);
    response.body["data"]["aliases"]
        .as_array()
        .and_then(|v| v.first())
        .cloned()
        .ok_or("alias".into())
}

#[test]
fn jwt_schema44_role_and_mount_types_independently_reject_schema43_before_any_login() -> TestResult
{
    for path in ["auth/jwt/role/first", "sys/auth/jwt/tune"] {
        let root = Root::new();
        let (mut service, _, admin, _) = fixture(&root)?;
        let mut old = service.state.clone().ok_or("state")?;
        old.schema = 43;
        assert!(old.validate_format().is_ok());
        assert!(!old.engines.has_login_alias_metadata_state());
        assert!(!old.auth.has_jwt_batch_state());
        let kind = if path.ends_with("tune") {
            "default-service"
        } else {
            "default"
        };
        assert_eq!(
            call(
                &mut service,
                "POST",
                path,
                &admin,
                json!({"token_type":kind})
            )
            .status,
            204
        );
        let mut changed = service.state.clone().ok_or("state")?;
        assert!(!changed.engines.has_login_alias_metadata_state());
        assert!(changed.auth.has_jwt_batch_state());
        assert!(changed.validate_format().is_ok());
        changed.schema = 43;
        assert_eq!(
            changed
                .validate_format()
                .err()
                .ok_or("old reader accepted token type")?
                .status,
            503
        );
    }
    Ok(())
}

#[test]
fn jwt_backend_alias_metadata_persists_and_is_gated_after_mount_removal() -> TestResult {
    let root = Root::new();
    let (mut service, key, admin, jwt) = fixture(&root)?;
    let issued = login(&mut service, &jwt, "first", None);
    assert_eq!(issued.status, 200);
    let entity = issued.body["auth"]["entity_id"]
        .as_str()
        .ok_or("entity")?
        .to_owned();
    let first = alias(&mut service, &admin, &entity)?;
    assert_eq!(first["metadata"], json!({"role":"first"}));
    assert_eq!(call(&mut service,"POST",&format!("identity/entity-alias/id/{}",first["id"].as_str().ok_or("alias id")?),&admin,
        json!({"name":first["name"],"mount_accessor":first["mount_accessor"],"canonical_id":entity,"custom_metadata":{"role":"custom"}})).status,200);
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let wrapped = login(&mut service, &jwt, "second", Some(60));
    assert_eq!(wrapped.status, 200);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation + 1
    );
    let second = alias(&mut service, &admin, &entity)?;
    assert_eq!(second["metadata"], json!({"role":"second"}));
    assert_eq!(second["custom_metadata"], json!({"role":"custom"}));
    assert_eq!(
        call(&mut service, "DELETE", "sys/auth/jwt", &admin, json!({})).status,
        204
    );
    let state = service.state.as_ref().ok_or("state")?;
    assert!(state.engines.has_login_alias_metadata_state());
    let mut old = state.clone();
    old.schema = 43;
    assert_eq!(
        old.validate_format()
            .err()
            .ok_or("old reader must reject")?
            .status,
        503
    );
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let after = alias(&mut reopened, &admin, &entity)?;
    assert_eq!(after["metadata"], json!({"role":"second"}));
    assert_eq!(after["custom_metadata"], json!({"role":"custom"}));
    Ok(())
}

#[test]
fn jwt_disabled_identity_wrapping_and_commit_failures_do_not_publish_backend_metadata() -> TestResult
{
    for kind in ["service", "batch"] {
        for failure in ["disabled", "wrapping", "commit"] {
            let root = Root::new();
            let (mut service, _, admin, jwt) = fixture(&root)?;
            for role in ["first", "second"] {
                assert_eq!(
                    call(
                        &mut service,
                        "POST",
                        &format!("auth/jwt/role/{role}"),
                        &admin,
                        json!({"token_type":kind})
                    )
                    .status,
                    204
                );
            }
            let issued = login(&mut service, &jwt, "first", None);
            assert_eq!(issued.status, 200);
            let entity = issued.body["auth"]["entity_id"]
                .as_str()
                .ok_or("entity")?
                .to_owned();
            assert_eq!(
                alias(&mut service, &admin, &entity)?["metadata"],
                json!({"role":"first"})
            );
            if failure == "disabled" {
                assert_eq!(
                    call(
                        &mut service,
                        "POST",
                        &format!("identity/entity/id/{entity}"),
                        &admin,
                        json!({"disabled":true})
                    )
                    .status,
                    204
                );
            } else if failure == "wrapping" {
                let mut state = service.state.clone().ok_or("state")?;
                for _ in 0..256 {
                    state.auth.wrap_response(
                        "",
                        "synthetic/wrapper",
                        3600,
                        &json!({"synthetic":true}),
                        100,
                    )?;
                }
                service
                    .commit_state(&state)
                    .map_err(|_| "fixture wrapper commit")?;
                service.state = Some(state);
            }
            let before = service.state_digest;
            let engine_before =
                owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.engines)
                    .map_err(|_| "engines")?;
            let generation = service.durable.as_ref().ok_or("durable")?.generation();
            if failure == "commit" {
                service.state_capacity = 1;
            }
            let response = login(&mut service, &jwt, "second", Some(60));
            assert_eq!(
                response.status,
                match failure {
                    "disabled" => 403,
                    "wrapping" => 503,
                    _ => 507,
                }
            );
            assert!(response.body.get("auth").is_none_or(Value::is_null));
            assert!(response.body.get("wrap_info").is_none_or(Value::is_null));
            assert_eq!(service.state_digest, before);
            assert_eq!(
                service.durable.as_ref().ok_or("durable")?.generation(),
                generation
            );
            let engine_after =
                owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.engines)
                    .map_err(|_| "engines")?;
            assert_eq!(engine_before.as_slice(), engine_after.as_slice());
        }
    }
    Ok(())
}
