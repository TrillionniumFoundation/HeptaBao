use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn checked<T, E>(value: Result<T, E>) -> TestResult<T> {
    value.map_err(|_| "namespace factory fixture operation failed".into())
}

fn binding(namespace: &str, incarnation: u64) -> TestResult<Binding> {
    checked(Binding::new(
        "factory-cluster".into(),
        namespace.into(),
        format!("factory-id-{namespace}-{incarnation}"),
        incarnation,
    ))
}

fn precise() -> TestResult<AuthorityTime> {
    Ok(AuthorityTime::Precise(checked(Timestamp::checked(
        100,
        123_456_789,
    ))?))
}

fn bytes(auth: &AuthState) -> TestResult<Vec<u8>> {
    checked(serde_json::to_vec(auth))
}

#[test]
fn factory144_original_precise_seed_is_identical_on_repeated_install_and_roundtrip() -> TestResult {
    let (source, _) =
        AuthState::bootstrap(100).map_err(|_| "namespace factory fixture operation failed")?;
    let actual = binding("fresh", 1)?;
    let seed = PreparedChild::new(actual.clone(), precise()?)
        .map_err(|_| "namespace factory fixture operation failed")?;
    let mut first = source.clone();
    let mut second = source.clone();
    seed.install(&mut first, &actual)
        .map_err(|_| "namespace factory fixture operation failed")?;
    seed.install(&mut second, &actual)
        .map_err(|_| "namespace factory fixture operation failed")?;
    assert!(bytes(&first)? == bytes(&second)?);
    let data = first.policies["fresh"]["default"]
        .read_security_data("default", false)
        .map_err(|_| "namespace factory fixture operation failed")?;
    assert_eq!(data["version"], 1);
    assert_eq!(data["modified"], "1970-01-01T00:01:40.123456789Z");
    for field in [
        "cas_required",
        "allow_slashes_in_identity_templates",
        "allow_wildcards_in_identity_templates",
    ] {
        assert_eq!(data[field], false);
    }
    assert!(data.get("expiration").is_none());
    assert!(!first.namespace_is_empty("fresh"));
    let normalized = first
        .without_namespace_factory_defaults(&BTreeMap::from([("fresh".to_owned(), actual.clone())]))
        .map_err(|_| "verified detached namespace normalization")?;
    assert!(normalized.namespace_is_empty("fresh"));
    assert!(!first.namespace_is_empty("fresh"));
    first
        .validate_namespace_factory_state(|name| binding(name, 1).map_err(|_| ()))
        .map_err(|_| "namespace factory fixture operation failed")?;
    let serialized = bytes(&first)?;
    let loaded: AuthState = serde_json::from_slice(&serialized)
        .map_err(|_| "namespace factory fixture operation failed")?;
    loaded
        .validate_namespace_factory_state(|name| binding(name, 1).map_err(|_| ()))
        .map_err(|_| "namespace factory fixture operation failed")?;
    assert!(bytes(&loaded)? == serialized);
    let before = bytes(&first)?;
    assert!(seed.install(&mut first, &actual).is_err());
    assert!(bytes(&first)? == before);
    Ok(())
}

#[test]
fn factory144_coarse_seed_keeps_original_time_and_invalid_clock_never_installs() -> TestResult {
    let (mut auth, _) =
        AuthState::bootstrap(100).map_err(|_| "namespace factory fixture operation failed")?;
    let actual = binding("coarse", 1)?;
    let seed = PreparedChild::new(actual.clone(), AuthorityTime::Coarse(100))
        .map_err(|_| "namespace factory fixture operation failed")?;
    seed.install(&mut auth, &actual)
        .map_err(|_| "namespace factory fixture operation failed")?;
    let policy = &auth.policies["coarse"]["default"];
    assert_eq!(
        policy
            .read_security_data("default", false)
            .map_err(|_| "namespace factory fixture operation failed")?["modified"],
        "1970-01-01T00:01:40Z"
    );
    assert!(matches!(
        policy
            .namespace_factory
            .as_ref()
            .ok_or("factory origin")?
            .created,
        CreationTime::Coarse { seconds: 100 }
    ));
    let before = bytes(&auth)?;
    assert!(PreparedChild::new(binding("invalid", 1)?, AuthorityTime::Coarse(u64::MAX)).is_err());
    assert!(bytes(&auth)? == before);
    Ok(())
}

#[test]
fn factory144_same_body_replace_patch_recreation_and_tombstone_have_no_origin() -> TestResult {
    let (mut auth, _) =
        AuthState::bootstrap(100).map_err(|_| "namespace factory fixture operation failed")?;
    let actual = binding("rewritten", 1)?;
    PreparedChild::new(actual.clone(), precise()?)
        .map_err(|_| "namespace factory fixture operation failed")?
        .install(&mut auth, &actual)
        .map_err(|_| "namespace factory fixture operation failed")?;
    let factory = auth.policies["rewritten"]["default"].clone();
    assert!(
        security_contract::prepare_policy(
            Some(&factory),
            &json!({
                "policy":default_policy_source(), "cas":1,
                "namespace_factory":{"format":1},
            }),
            false,
            false,
            AuthorityTime::Coarse(200)
        )
        .is_err()
    );
    for (patch, body) in [
        (false, json!({"policy":default_policy_source(),"cas":1})),
        (true, json!({"cas":1})),
    ] {
        let replacement = security_contract::prepare_policy(
            Some(&factory),
            &body,
            patch,
            false,
            AuthorityTime::Coarse(200),
        )
        .map_err(|_| "namespace factory fixture operation failed")?;
        assert!(replacement.namespace_factory.is_none());
        assert_eq!(
            replacement
                .read_security_data("default", false)
                .map_err(|_| "namespace factory fixture operation failed")?["version"],
            2
        );
        let mut changed = auth.clone();
        changed
            .policies
            .get_mut("rewritten")
            .ok_or("rewritten namespace")?
            .insert("default".into(), replacement);
        let before = bytes(&changed)?;
        assert!(
            !changed
                .retire_empty_namespace_factory_default(&actual)
                .map_err(|_| "namespace factory fixture operation failed")?
        );
        assert!(bytes(&changed)? == before);
    }
    let recreated = default_at(AuthorityTime::Coarse(200))
        .map_err(|_| "namespace factory fixture operation failed")?;
    assert_eq!(
        recreated
            .read_security_data("default", false)
            .map_err(|_| "namespace factory fixture operation failed")?["version"],
        1
    );
    assert!(recreated.namespace_factory.is_none());
    assert!(Policy::expired_default().namespace_factory.is_none());
    assert!(
        parse_policy(&json!(default_policy_source()))
            .map_err(|_| "namespace factory fixture operation failed")?
            .namespace_factory
            .is_none()
    );
    Ok(())
}

#[test]
fn factory144_binding_or_policy_changes_cannot_gain_provenance() -> TestResult {
    let (source, _) =
        AuthState::bootstrap(100).map_err(|_| "namespace factory fixture operation failed")?;
    let actual = binding("bound", 1)?;
    let seed = PreparedChild::new(actual.clone(), precise()?)
        .map_err(|_| "namespace factory fixture operation failed")?;
    for wrong in [
        binding("other", 1)?,
        binding("bound", 2)?,
        Binding::new(
            "other-cluster".into(),
            "bound".into(),
            "factory-id-bound-1".into(),
            1,
        )
        .map_err(|_| "namespace factory fixture operation failed")?,
        Binding::new(
            "factory-cluster".into(),
            "bound".into(),
            "other-id".into(),
            1,
        )
        .map_err(|_| "namespace factory fixture operation failed")?,
    ] {
        let mut changed = source.clone();
        let before = bytes(&changed)?;
        assert!(seed.install(&mut changed, &wrong).is_err());
        assert!(bytes(&changed)? == before);
        let mut installed = source.clone();
        seed.install(&mut installed, &actual)
            .map_err(|_| "namespace factory fixture operation failed")?;
        assert!(
            installed
                .validate_namespace_factory_state(|_| Ok(wrong.clone()))
                .is_err()
        );
        let before = bytes(&installed)?;
        let result = installed.retire_empty_namespace_factory_default(&wrong);
        if wrong.namespace() == actual.namespace() {
            assert!(result.is_err());
        } else {
            assert!(!result.map_err(|_| "foreign absent namespace")?);
        }
        assert!(bytes(&installed)? == before);
    }
    let mut installed = source;
    seed.install(&mut installed, &actual)
        .map_err(|_| "namespace factory fixture operation failed")?;
    for change in 0..4 {
        let mut poisoned = installed.clone();
        let policy = poisoned
            .policies
            .get_mut("bound")
            .ok_or("bound namespace")?
            .get_mut("default")
            .ok_or("bound default")?;
        match change {
            0 => {
                let mut wire = serde_json::to_value(&*policy)
                    .map_err(|_| "namespace factory fixture operation failed")?;
                wire["security"]["version"] = json!(2);
                *policy = serde_json::from_value(wire)
                    .map_err(|_| "namespace factory fixture operation failed")?;
            }
            1 => policy.source.push(' '),
            2 => policy.rules.clear(),
            _ => {
                policy
                    .namespace_factory
                    .as_mut()
                    .ok_or("mutable factory origin")?
                    .format = 2
            }
        }
        assert!(
            poisoned
                .validate_namespace_factory_state(|_| Ok(actual.clone()))
                .is_err()
        );
        let before = bytes(&poisoned)?;
        assert!(
            poisoned
                .retire_empty_namespace_factory_default(&actual)
                .is_err()
        );
        assert!(bytes(&poisoned)? == before);
    }
    Ok(())
}

#[test]
fn factory144_nonempty_candidate_is_unchanged_and_lookalike_is_not_normalized() -> TestResult {
    let (mut auth, _) =
        AuthState::bootstrap(100).map_err(|_| "namespace factory fixture operation failed")?;
    let actual = binding("resources", 1)?;
    PreparedChild::new(actual.clone(), precise()?)
        .map_err(|_| "namespace factory fixture operation failed")?
        .install(&mut auth, &actual)
        .map_err(|_| "namespace factory fixture operation failed")?;
    auth.policies
        .get_mut("resources")
        .ok_or("resource namespace")?
        .insert(
            "other".into(),
            parse_policy(&json!(
                r#"path "secret/data/item" { capabilities = ["read"] }"#
            ))
            .map_err(|_| "namespace factory fixture operation failed")?,
        );
    let before = bytes(&auth)?;
    assert!(
        !auth
            .retire_empty_namespace_factory_default(&actual)
            .map_err(|_| "namespace factory fixture operation failed")?
    );
    assert!(bytes(&auth)? == before);
    let mut lookalike = auth.clone();
    lookalike
        .policies
        .get_mut("resources")
        .ok_or("lookalike namespace")?
        .remove("other");
    lookalike
        .policies
        .get_mut("resources")
        .ok_or("lookalike namespace")?
        .get_mut("default")
        .ok_or("lookalike default")?
        .namespace_factory = None;
    let before = bytes(&lookalike)?;
    assert!(
        !lookalike
            .retire_empty_namespace_factory_default(&actual)
            .map_err(|_| "namespace factory fixture operation failed")?
    );
    assert!(bytes(&lookalike)? == before);
    auth.policies
        .get_mut("resources")
        .ok_or("resource namespace")?
        .remove("other");
    assert!(
        auth.retire_empty_namespace_factory_default(&actual)
            .map_err(|_| "namespace factory fixture operation failed")?
    );
    assert!(auth.namespace_is_empty("resources"));
    assert!(!auth.has_namespace_factory_state());
    Ok(())
}

#[test]
fn factory144_typed_namespace_parcel_preserves_origin_and_old_absence_stays_old() -> TestResult {
    let (mut auth, _) =
        AuthState::bootstrap(100).map_err(|_| "namespace factory fixture operation failed")?;
    auth.initialize_fresh_namespace_auth("legacy")
        .map_err(|_| "namespace factory fixture operation failed")?;
    let old = bytes(&auth)?;
    let loaded: AuthState =
        serde_json::from_slice(&old).map_err(|_| "namespace factory fixture operation failed")?;
    assert!(!loaded.has_namespace_factory_state());
    assert!(bytes(&loaded)? == old);
    let actual = binding("parcel", 1)?;
    PreparedChild::new(actual.clone(), precise()?)
        .map_err(|_| "namespace factory fixture operation failed")?
        .install(&mut auth, &actual)
        .map_err(|_| "namespace factory fixture operation failed")?;
    let original = bytes(&auth)?;
    let parcel = auth
        .detach_namespace("parcel")
        .map_err(|_| "namespace factory fixture operation failed")?;
    assert!(!auth.has_namespace_factory_state());
    let wire =
        serde_json::to_vec(&parcel).map_err(|_| "namespace factory fixture operation failed")?;
    let parcel: namespace_assets::NamespaceAssets =
        serde_json::from_slice(&wire).map_err(|_| "namespace factory fixture operation failed")?;
    parcel
        .validate("parcel")
        .map_err(|_| "namespace factory fixture operation failed")?;
    assert!(parcel.validate("other").is_err());
    auth.attach_namespace("parcel", parcel)
        .map_err(|_| "namespace factory fixture operation failed")?;
    auth.validate_namespace_factory_state(|_| Ok(actual.clone()))
        .map_err(|_| "namespace factory fixture operation failed")?;
    assert!(bytes(&auth)? == original);
    Ok(())
}

#[test]
fn factory144_authorization_observation_keeps_original_coarse_or_bound_clock() -> TestResult {
    let (mut auth, raw) =
        AuthState::bootstrap(100).map_err(|_| "namespace factory fixture operation failed")?;
    let mut actor = auth
        .authenticate(&raw, 100)
        .map_err(|_| "namespace factory fixture operation failed")?;
    let observed = auth
        .authorize_request_observation(
            &actor,
            "",
            "sys/namespaces/new",
            "update",
            AuthorityTime::Coarse(100),
        )
        .map_err(|_| "namespace factory fixture operation failed")?;
    assert!(matches!(observed, AuthorityTime::Coarse(100)));
    let clock = RequestClock::anchored(std::time::Duration::ZERO, std::time::Instant::now())
        .map_err(|_| "namespace factory fixture operation failed")?
        .with_timestamp_floor(
            Timestamp::checked(100, 123_456_789)
                .map_err(|_| "namespace factory fixture operation failed")?,
        );
    actor
        .bind_request_clock(Some(clock))
        .map_err(|_| "namespace factory fixture operation failed")?;
    let observed = auth
        .authorize_request_observation(
            &actor,
            "",
            "sys/namespaces/new",
            "update",
            AuthorityTime::Coarse(100),
        )
        .map_err(|_| "namespace factory fixture operation failed")?;
    assert!(matches!(observed, AuthorityTime::Precise(_)));
    assert_eq!(
        observed.exact().ok_or("original precise observation")?,
        Timestamp::checked(100, 123_456_789)
            .map_err(|_| "namespace factory fixture operation failed")?
    );
    Ok(())
}
