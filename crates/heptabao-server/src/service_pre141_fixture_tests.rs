//! Historical fixture selection happens before the real first publication.
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type FixtureBootstrap = fn(&mut Service) -> TestResult<(String, String)>;

fn historical_factories() -> [FixtureBootstrap; 3] {
    [
        bootstrap_pre141,
        bootstrap_pre141_approle,
        bootstrap_legacy_auth_fixture,
    ]
}

#[test]
fn pre141_fixture_entrypoints_reject_installed_current_default_without_mutation() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let current = call(
        &mut service,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    );
    assert_eq!(current.status, 200);
    assert_eq!(current.body["data"]["version"], 1);
    assert_eq!(current.body["data"]["modified"], "1970-01-01T00:01:40Z");
    let source = serde_json::to_vec(&service.state.as_ref().ok_or("current state")?.auth)?;
    let digest = service
        .current_state_digest()
        .map_err(|_| "current state digest")?;
    for initialize in historical_factories() {
        assert!(initialize(&mut service).is_err());
        assert_eq!(
            serde_json::to_vec(&service.state.as_ref().ok_or("retained state")?.auth)?,
            source
        );
        assert_eq!(
            service
                .current_state_digest()
                .map_err(|_| "retained state digest")?,
            digest
        );
        assert_eq!(
            service.state.as_ref().ok_or("retained schema")?.schema,
            AUTH_SECURITY_CONTRACT_STATE_SCHEMA
        );
        let retained = call(
            &mut service,
            "GET",
            "sys/policies/acl/default",
            &admin,
            json!({}),
        );
        assert_eq!(retained.status, 200);
        assert_eq!(retained.body["data"], current.body["data"]);
    }
    Ok(())
}

#[test]
fn pre141_fixture_entrypoints_keep_old_default_and_publish_real_upgrade_after_reopen() -> TestResult
{
    for initialize in historical_factories() {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, admin) = initialize(&mut service)?;
        let old = call(
            &mut service,
            "GET",
            "sys/policies/acl/default",
            &admin,
            json!({}),
        );
        assert_eq!(old.status, 200);
        assert_eq!(old.body["data"]["version"], 0);
        assert!(old.body["data"].get("modified").is_none());
        assert_eq!(
            service.state.as_ref().ok_or("historical state")?.schema,
            CURRENT_STATE_SCHEMA
        );
        assert!(
            !service
                .state
                .as_ref()
                .ok_or("historical auth")?
                .auth
                .has_security_contract_state()
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/data/pre141-seeded",
                &admin,
                json!({"data":{"value":"original historical value"}})
            )
            .status,
            200
        );
        drop(service);

        let mut service = root.service()?;
        assert_eq!(
            call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        let loaded = call(
            &mut service,
            "GET",
            "sys/policies/acl/default",
            &admin,
            json!({}),
        );
        assert_eq!(loaded.status, 200);
        assert_eq!(loaded.body["data"], old.body["data"]);
        let secret = call(
            &mut service,
            "GET",
            "secret/data/pre141-seeded",
            &admin,
            json!({}),
        );
        assert_eq!(secret.status, 200);
        assert_eq!(
            secret.body["data"]["data"]["value"],
            "original historical value"
        );
        assert_eq!(call(&mut service, "POST", "sys/policies/acl/pre141-real-upgrade", &admin,
            json!({"policy":r#"path "secret/data/pre141-seeded" { capabilities = ["read"] }"#,"cas":-1})).status, 204);
        assert_eq!(
            service.state.as_ref().ok_or("upgraded state")?.schema,
            AUTH_SECURITY_CONTRACT_STATE_SCHEMA
        );
        assert!(
            service
                .state
                .as_ref()
                .ok_or("upgraded auth")?
                .auth
                .has_security_contract_state()
        );
        let written = call(
            &mut service,
            "GET",
            "sys/policies/acl/pre141-real-upgrade",
            &admin,
            json!({}),
        );
        assert_eq!(written.status, 200);
        assert_eq!(written.body["data"]["version"], 1);
        assert_eq!(written.body["data"]["modified"], "1970-01-01T00:01:40Z");
        let unchanged_default = call(
            &mut service,
            "GET",
            "sys/policies/acl/default",
            &admin,
            json!({}),
        );
        assert_eq!(unchanged_default.status, 200);
        assert_eq!(unchanged_default.body["data"], old.body["data"]);
        let fixed = serde_json::to_vec(&service.state.as_ref().ok_or("fixed upgraded auth")?.auth)?;
        assert!(initialize(&mut service).is_err());
        assert_eq!(
            serde_json::to_vec(&service.state.as_ref().ok_or("retained upgraded auth")?.auth)?,
            fixed
        );
    }
    Ok(())
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn pre141_fixture_entrypoint_rejects_selected_native_profile_before_first_publication() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_candidate()?;
    assert!(!service.initialized());
    assert!(service.state.is_none());
    assert!(bootstrap_pre141_unmounted(&mut service).is_err());
    assert!(!service.initialized());
    assert!(service.state.is_none());
    // The original current factory remains available after the rejected old path.
    let (_, admin) = {
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
            std::time::Instant::now() + std::time::Duration::from_secs(15),
        );
        bootstrap_unmounted(&mut service)?
    };
    let current = call(
        &mut service,
        "GET",
        "sys/policies/acl/default",
        &admin,
        json!({}),
    );
    assert_eq!(current.status, 200);
    assert_eq!(current.body["data"]["version"], 1);
    assert_eq!(current.body["data"]["modified"], "1970-01-01T00:01:40Z");
    Ok(())
}
