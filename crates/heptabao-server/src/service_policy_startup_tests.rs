//! Active unseal recreates the root default through the real durable writer.
//! A later ordinary request in that same activation never recreates it.
use super::super::tests::{Root, bootstrap};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE: &str = r#"path "secret/data/startup143" { capabilities = ["read"] }"#;

fn call(
    service: &mut Service,
    seconds: u64,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> TestResult<Response> {
    let at = Timestamp::whole(seconds).map_err(|_| "private startup timestamp")?;
    let clock = RequestClock::anchored(Duration::ZERO, Instant::now())
        .map_err(|_| "private startup clock")?
        .with_timestamp_floor(at);
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    let _explicit = external_pki::PublicationClockScope::explicit();
    Ok(service.handle_request_clock(
        ServiceRequest::new(method, path, "", token, body),
        seconds,
        true,
        Some(clock),
    ))
}

fn open(root: &Root, native: bool) -> TestResult<Service> {
    let mut service = root.service()?;
    #[cfg(feature = "native-v6-storage")]
    if native {
        service.configure_native_v6_candidate()?;
    }
    #[cfg(not(feature = "native-v6-storage"))]
    assert!(!native);
    Ok(service)
}

fn bootstrap_with_original_deadline(
    service: &mut Service,
    native: bool,
) -> TestResult<(String, String)> {
    // Native cold loading needs the first HTTP request's deadline, including
    // the initial unseal before activation. Later requests keep call()'s own
    // original deadline; this scope ends before the startup assertions.
    let _deadline = native.then(|| {
        crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        )
    });
    bootstrap(service)
}

fn configured_default(service: &mut Service, admin: &str, expires: u64) -> TestResult {
    assert_eq!(
        call(
            service,
            100,
            "POST",
            "sys/policies/acl/default",
            admin,
            json!({"policy":SOURCE,"expiration":expires,"cas_required":true,"cas":1})
        )?
        .status,
        204
    );
    Ok(())
}

fn retired_default_reopens(native: bool) -> TestResult {
    let root = Root::new();
    let mut service = open(&root, native)?;
    let (key, admin) = bootstrap_with_original_deadline(&mut service, native)?;
    #[cfg(feature = "native-v6-storage")]
    if native {
        assert_eq!(
            call(
                &mut service,
                100,
                "POST",
                "sys/internal/native-v6/activate",
                &admin,
                json!({})
            )?
            .status,
            204
        );
    }
    configured_default(&mut service, &admin, 101)?;
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "sys/policies/acl/unobserved143",
            &admin,
            json!({"policy":SOURCE,"expiration":101,"cas_required":true,"cas":-1})
        )?
        .status,
        204
    );
    let issued = call(
        &mut service,
        100,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["default"],"ttl":600}),
    )?;
    assert_eq!(issued.status, 200);
    let token = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("default credential")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            102,
            "GET",
            "sys/policies/acl/default",
            &admin,
            json!({})
        )?
        .status,
        404
    );
    assert_eq!(
        call(
            &mut service,
            102,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({})
        )?
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            102,
            "GET",
            "sys/policies/acl/default",
            &admin,
            json!({})
        )?
        .status,
        404
    );
    drop(service);

    let mut service = open(&root, native)?;
    #[cfg(feature = "native-v6-storage")]
    let full_reads_before = super::super::native_v6_reader::full_cold_loads_for_test();
    assert_eq!(
        call(
            &mut service,
            103,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key})
        )?
        .status,
        200
    );
    #[cfg(feature = "native-v6-storage")]
    if native {
        // This real expired-default publication remains on the original
        // first load + adjacent capture + both audit-side fresh full reads.
        assert_eq!(
            super::super::native_v6_reader::full_cold_loads_for_test() - full_reads_before,
            4
        );
    }
    let restored = call(
        &mut service,
        103,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    )?;
    assert_eq!(restored.status, 200);
    assert_eq!(restored.body["data"]["version"], 1);
    assert_eq!(restored.body["data"]["modified"], "1970-01-01T00:01:43Z");
    assert_eq!(restored.body["data"]["cas_required"], false);
    assert!(restored.body["data"].get("expiration").is_none());
    assert_eq!(
        call(
            &mut service,
            103,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({})
        )?
        .status,
        200
    );
    // Startup must not scan and purge unrelated unread policies.
    assert_eq!(
        call(
            &mut service,
            103,
            "POST",
            "sys/policies/acl/unobserved143",
            &admin,
            json!({"policy":SOURCE})
        )?
        .status,
        400
    );
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        POLICY_EXPIRATION_STATE_SCHEMA
    );
    drop(service);

    let mut service = open(&root, native)?;
    assert_eq!(
        call(
            &mut service,
            104,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key})
        )?
        .status,
        200
    );
    let unchanged = call(
        &mut service,
        104,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    )?;
    assert_eq!(unchanged.status, 200);
    assert_eq!(unchanged.body["data"], restored.body["data"]);
    assert_eq!(
        call(
            &mut service,
            104,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({})
        )?
        .status,
        200
    );
    Ok(())
}

#[test]
fn startup143_ordinary_default_tombstone_recreates_once_on_actual_unseal() -> TestResult {
    retired_default_reopens(false)
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn startup143_native_default_tombstone_recreates_once_on_actual_unseal() -> TestResult {
    retired_default_reopens(true)
}

#[test]
fn startup143_unexpired_default_survives_activation_and_is_not_recreated_by_later_reads()
-> TestResult {
    let root = Root::new();
    let mut service = open(&root, false)?;
    let (key, admin) = bootstrap(&mut service)?;
    configured_default(&mut service, &admin, 103)?;
    let original = call(
        &mut service,
        100,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    )?;
    assert_eq!(original.status, 200);
    drop(service);
    let mut service = open(&root, false)?;
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key})
        )?
        .status,
        200
    );
    let retained = call(
        &mut service,
        102,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    )?;
    assert_eq!(retained.body["data"], original.body["data"]);
    assert_eq!(
        call(
            &mut service,
            103,
            "GET",
            "sys/policies/acl/default",
            &admin,
            json!({})
        )?
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            104,
            "GET",
            "sys/policies/acl/default",
            &admin,
            json!({})
        )?
        .status,
        404
    );
    assert_eq!(
        call(
            &mut service,
            105,
            "GET",
            "sys/policies/acl/default",
            &admin,
            json!({})
        )?
        .status,
        404
    );
    drop(service);
    let mut service = open(&root, false)?;
    assert_eq!(
        call(
            &mut service,
            106,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key})
        )?
        .status,
        200
    );
    let restored = call(
        &mut service,
        106,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    )?;
    assert_eq!(restored.status, 200);
    assert_eq!(restored.body["data"]["version"], 1);
    assert_eq!(restored.body["data"]["modified"], "1970-01-01T00:01:46Z");
    assert!(restored.body["data"].get("expiration").is_none());
    Ok(())
}

fn health_waits_for_closed_default_startup(native: bool) -> TestResult {
    for expires in [101, 105] {
        let root = Root::new();
        let mut service = open(&root, native)?;
        let (key, admin) = bootstrap_with_original_deadline(&mut service, native)?;
        #[cfg(feature = "native-v6-storage")]
        if native {
            assert_eq!(
                call(
                    &mut service,
                    100,
                    "POST",
                    "sys/internal/native-v6/activate",
                    &admin,
                    json!({})
                )?
                .status,
                204
            );
        }
        configured_default(&mut service, &admin, expires)?;
        drop(service);
        let mut service = open(&root, native)?;
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(30),
        );
        // Exercise the real authenticated barrier step and pause before its
        // outer public caller completes policy startup. No State, key, policy
        // projection or lifecycle stamp is fabricated for this window.
        assert_eq!(service.unseal(&json!({"key":key})).status, 200);
        assert!(service.default_policy_activation_pending());
        let auth_before = serde_json::to_vec(&service.state.as_ref().ok_or("pending state")?.auth)?;
        let generation = service
            .durable
            .as_ref()
            .ok_or("pending durable owner")?
            .generation();
        for _ in 0..2 {
            let health = call(&mut service, 102, "GET", "sys/health", "", json!({}))?;
            assert_eq!(health.status, 503);
            assert_eq!(health.body["initialized"], true);
            assert_eq!(health.body["sealed"], false);
            assert_eq!(health.body["ha_application_ready"], false);
            assert!(service.policy_default_activation.is_none());
            assert_eq!(
                service
                    .durable
                    .as_ref()
                    .ok_or("observed durable owner")?
                    .generation(),
                generation
            );
            assert!(
                serde_json::to_vec(&service.state.as_ref().ok_or("observed state")?.auth)?
                    == auth_before
            );
        }
        // The ordinary request reaches the existing closed active lifecycle.
        // Health itself did not choose a reset or turn a future default into
        // a later-time startup operation.
        let policy = call(
            &mut service,
            102,
            "GET",
            "sys/policies/acl/default",
            &admin,
            json!({}),
        )?;
        assert_eq!(policy.status, 200);
        assert!(!service.default_policy_activation_pending());
        assert_eq!(
            call(&mut service, 102, "GET", "sys/health", "", json!({}))?.status,
            200
        );
        if expires == 101 {
            assert!(policy.body["data"].get("expiration").is_none());
            assert_eq!(policy.body["data"]["modified"], "1970-01-01T00:01:42Z");
        } else {
            assert_eq!(policy.body["data"]["expiration"], "1970-01-01T00:01:45Z");
            assert_eq!(policy.body["data"]["modified"], "1970-01-01T00:01:40Z");
            assert_eq!(
                call(
                    &mut service,
                    106,
                    "GET",
                    "sys/policies/acl/default",
                    &admin,
                    json!({})
                )?
                .status,
                404
            );
            assert_eq!(
                call(&mut service, 106, "GET", "sys/health", "", json!({}))?.status,
                200
            );
            assert_eq!(
                call(
                    &mut service,
                    106,
                    "GET",
                    "sys/policies/acl/default",
                    &admin,
                    json!({})
                )?
                .status,
                404
            );
        }
        drop(service);
    }
    Ok(())
}

#[test]
fn startup143_ordinary_health_observes_pending_activation_without_writing_auth() -> TestResult {
    health_waits_for_closed_default_startup(false)
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn startup143_native_health_observes_pending_activation_without_writing_auth() -> TestResult {
    health_waits_for_closed_default_startup(true)
}

fn fresh_root_default(native: bool) -> TestResult {
    let root = Root::new();
    let mut service = open(&root, native)?;
    let (key, admin) = bootstrap_with_original_deadline(&mut service, native)?;
    let initial = call(
        &mut service,
        100,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    )?;
    assert_eq!(initial.status, 200);
    assert_eq!(initial.body["data"]["version"], 1);
    assert_eq!(initial.body["data"]["modified"], "1970-01-01T00:01:40Z");
    assert_eq!(initial.body["data"]["cas_required"], false);
    assert_eq!(
        initial.body["data"]["allow_slashes_in_identity_templates"],
        false
    );
    assert_eq!(
        initial.body["data"]["allow_wildcards_in_identity_templates"],
        false
    );
    assert!(initial.body["data"].get("expiration").is_none());
    assert_eq!(
        service.state.as_ref().ok_or("fresh state")?.schema,
        AUTH_SECURITY_CONTRACT_STATE_SCHEMA
    );
    let builtin = initial.body["data"]["policy"]
        .as_str()
        .ok_or("builtin policy source")?
        .to_owned();
    #[cfg(feature = "native-v6-storage")]
    if native {
        assert_eq!(
            call(
                &mut service,
                100,
                "POST",
                "sys/internal/native-v6/activate",
                &admin,
                json!({})
            )?
            .status,
            204
        );
    }
    for cas in [-1, 0] {
        assert_eq!(
            call(
                &mut service,
                100,
                "POST",
                "sys/policies/acl/default",
                &admin,
                json!({"policy": builtin, "cas": cas})
            )?
            .status,
            400
        );
        let unchanged = call(
            &mut service,
            100,
            "GET",
            "sys/policies/acl/default",
            &admin,
            json!({}),
        )?;
        assert_eq!(unchanged.status, 200);
        assert_eq!(unchanged.body["data"], initial.body["data"]);
    }
    let issued = call(
        &mut service,
        100,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["default"], "no_default_policy":false, "ttl":600}),
    )?;
    assert_eq!(issued.status, 200);
    assert_eq!(issued.body["auth"]["policies"], json!(["default"]));
    let token = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("default token")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            100,
            "GET",
            "auth/token/lookup-self",
            &token,
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
            "sys/policies/acl/default",
            &admin,
            json!({"policy":builtin, "cas":1, "cas_required":true})
        )?
        .status,
        204
    );
    let edited = call(
        &mut service,
        100,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    )?;
    assert_eq!(edited.status, 200);
    assert_eq!(edited.body["data"]["version"], 2);
    assert_eq!(edited.body["data"]["cas_required"], true);
    drop(service);
    let mut service = open(&root, native)?;
    assert_eq!(
        call(
            &mut service,
            101,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":key})
        )?
        .status,
        200
    );
    let loaded = call(
        &mut service,
        101,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    )?;
    assert_eq!(loaded.status, 200);
    assert_eq!(loaded.body["data"], edited.body["data"]);
    assert_eq!(
        call(
            &mut service,
            101,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({})
        )?
        .status,
        200
    );
    // A historical constructor may never be selected for an installed owner.
    let auth_before = serde_json::to_vec(&service.state.as_ref().ok_or("loaded state")?.auth)?;
    assert!(super::super::tests::bootstrap_pre141_unmounted(&mut service).is_err());
    assert_eq!(
        serde_json::to_vec(&service.state.as_ref().ok_or("unchanged state")?.auth)?,
        auth_before
    );
    Ok(())
}

#[test]
fn startup143_fresh_ordinary_root_default_has_version_one_and_real_cas_after_restart() -> TestResult
{
    fresh_root_default(false)
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn startup143_fresh_native_root_default_has_version_one_and_real_cas_after_restart() -> TestResult {
    fresh_root_default(true)
}

#[test]
fn startup143_explicit_old_factory_keeps_implicit_zero_until_a_real_update() -> TestResult {
    let root = Root::new();
    let mut service = open(&root, false)?;
    let (key, admin) = super::super::tests::bootstrap_pre141_unmounted(&mut service)?;
    let old = call(
        &mut service,
        100,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    )?;
    assert_eq!(old.status, 200);
    assert_eq!(old.body["data"]["version"], 0);
    assert!(old.body["data"].get("modified").is_none());
    let builtin = old.body["data"]["policy"]
        .as_str()
        .ok_or("legacy builtin source")?
        .to_owned();
    super::super::tests::create_pre141_acl_policy_fixture(
        &mut service,
        &admin,
        "old-factory-fixture143",
        SOURCE,
    )?;
    super::super::tests::provision_fixture_mounts(&mut service, "", &admin);
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "secret/data/old-factory143",
            &admin,
            json!({"data":{"value":"historical factory"}})
        )?
        .status,
        200
    );
    let before = call(
        &mut service,
        100,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    )?;
    assert_eq!(before.body["data"], old.body["data"]);
    drop(service);
    let mut service = open(&root, false)?;
    assert_eq!(
        call(
            &mut service,
            101,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":key})
        )?
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            101,
            "GET",
            "secret/data/old-factory143",
            &admin,
            json!({})
        )?
        .status,
        200
    );
    let loaded = call(
        &mut service,
        101,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    )?;
    assert_eq!(loaded.body["data"], old.body["data"]);
    assert_eq!(
        call(
            &mut service,
            101,
            "POST",
            "sys/policies/acl/unrelated-current143",
            &admin,
            json!({"policy":SOURCE})
        )?
        .status,
        204
    );
    let still_old = call(
        &mut service,
        101,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    )?;
    assert_eq!(still_old.body["data"], old.body["data"]);
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/policies/acl/default",
            &admin,
            json!({"policy":builtin, "cas":0})
        )?
        .status,
        204
    );
    let updated = call(
        &mut service,
        102,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    )?;
    assert_eq!(updated.status, 200);
    assert_eq!(updated.body["data"]["version"], 1);
    assert_eq!(updated.body["data"]["modified"], "1970-01-01T00:01:42Z");
    Ok(())
}
