//! Pinned 2.7.1 self-authorization meaning and strict 44-derived state recovery.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn source(global: Option<bool>, nested: Option<Value>) -> Value {
    let mut identity = json!({"group_names":["cg-team"],"approvals":1});
    if let Some(value) = nested {
        identity["self_authorization"] = value;
    }
    let mut control = json!({"ttl":"60s","factor":{"review":{
        "controlled_capabilities":["create","update"],"identity":identity}}});
    if let Some(value) = global {
        control["self_auth_allowed"] = json!(value);
    }
    json!({"path":{"secret/data/+":{"capabilities":["create","update","read"],
        "control_group":control}}})
}

#[test]
fn cg271_json_self_authorization_uses_only_the_global_flag() -> TestResult {
    for global in [None, Some(false), Some(true)] {
        for nested in [None, Some(false), Some(true)] {
            let parsed = parse_policy(&source(global, nested.map(Value::Bool)))?;
            assert_eq!(
                parsed.control_groups["secret/data/+"][0].control.factors[0].self_authorization,
                global.unwrap_or(false),
                "nested field must never introduce self-approval authority",
            );
        }
    }
    Ok(())
}

#[test]
fn cg271_hcl_self_authorization_uses_only_the_global_flag() -> TestResult {
    for global in [None, Some(false), Some(true)] {
        for nested in [None, Some(false), Some(true)] {
            let global = global.map_or_else(String::new, |v| format!("self_auth_allowed={v}"));
            let nested = nested.map_or_else(String::new, |v| format!("self_authorization={v}"));
            let raw = format!(
                r#"path "secret/data/+" {{ capabilities=["create","update","read"]
                control_group={{ttl="60s" {global} factor "review" {{
                    controlled_capabilities=["create","update"]
                    identity {{group_names=["cg-team"] approvals=1 {nested} }}
                }}
            }}
            }}"#
            );
            let parsed = parse_policy(&Value::String(raw))?;
            assert_eq!(
                parsed.control_groups["secret/data/+"][0].control.factors[0].self_authorization,
                global == "self_auth_allowed=true",
            );
        }
    }
    Ok(())
}

#[test]
fn cg271_ignored_nested_values_cannot_grant_or_override_authority() -> TestResult {
    for nested in [
        json!("true"),
        json!(3),
        json!(null),
        json!({"unexpected":true}),
    ] {
        for global in [None, Some(false), Some(true)] {
            let parsed = parse_policy(&source(global, Some(nested.clone())))?;
            assert_eq!(
                parsed.control_groups["secret/data/+"][0].control.factors[0].self_authorization,
                global.unwrap_or(false),
            );
        }
    }
    let mut invalid = source(None, Some(json!(true)));
    invalid["path"]["secret/data/+"]["control_group"]["self_auth_allowed"] = json!("true");
    assert!(
        parse_policy(&invalid).is_err(),
        "the actual authority flag stays typed"
    );
    Ok(())
}

#[test]
fn cg271_legacy44_projection_roundtrips_without_becoming_runtime_authority() -> TestResult {
    let now = 100;
    let mut policy = parse_policy(&source(None, Some(json!(true))))?;
    policy.control_groups = collect_projection(
        &policy.source,
        &policy.rules,
        SelfAuthorizationProjection::Legacy44,
    )?;
    assert!(policy.control_groups["secret/data/+"][0].control.factors[0].self_authorization);
    let (mut state, raw) = AuthState::bootstrap(now)?;
    let token = state
        .tokens
        .get_mut(&hash(&raw))
        .ok_or("bootstrap token missing")?;
    token.root = false;
    token.policies = BTreeSet::from(["cg-legacy".into()]);
    state
        .policies
        .entry(String::new())
        .or_default()
        .insert("cg-legacy".into(), policy);
    state.control_groups.floor = true;
    state.control_groups.clock = now;
    state.validate_control_group_state()?;
    let encoded = serde_json::to_vec(&state)?;
    let restored: AuthState = serde_json::from_slice(&encoded)?;
    restored.validate_control_group_state()?;
    assert_eq!(
        serde_json::to_vec(&restored)?,
        encoded,
        "loading must not rewrite saved custody"
    );
    let actor = restored
        .authenticate_read_only(&raw, now)?
        .ok_or("actor missing")?;
    let effective = restored
        .control_group_policy(
            &actor,
            "",
            "secret/data/key",
            "create",
            AuthorityTime::Coarse(now),
        )?
        .ok_or("effective control missing")?;
    assert!(
        !effective.factors[0].self_authorization,
        "saved legacy true is never a runtime grant"
    );
    assert!(
        restored.policies[""]["cg-legacy"].control_groups["secret/data/+"][0]
            .control
            .factors[0]
            .self_authorization,
        "the old projection remains unmodified"
    );
    Ok(())
}

#[test]
fn cg271_legacy44_validation_does_not_accept_unrelated_projection_tampering() -> TestResult {
    let policy = parse_policy(&source(None, Some(json!(true))))?;
    let saved = collect_projection(
        &policy.source,
        &policy.rules,
        SelfAuthorizationProjection::Legacy44,
    )?;
    for change in 0..5 {
        let mut altered = saved.clone();
        let stanza = &mut altered.get_mut("secret/data/+").ok_or("stanza missing")?[0];
        match change {
            0 => stanza.control.factors[0].approvals = 2,
            1 => {
                stanza.control.factors[0]
                    .group_names
                    .insert("injected-group".into());
            }
            2 => stanza.control.ttl = 59,
            3 => stanza.rule_index = 1,
            _ => stanza.control.factors[0].name = "renamed".into(),
        }
        assert!(canonical_policy_projection(&policy.source, &policy.rules, &altered).is_err());
    }
    let changed = parse_policy(&source(Some(false), Some(json!(true))))?;
    assert!(
        canonical_policy_projection(&changed.source, &changed.rules, &saved).is_err(),
        "a forged global false source must not authenticate a saved true projection"
    );
    Ok(())
}

#[test]
fn cg271_legacy44_global_true_projection_retains_its_canonical_permission() -> TestResult {
    let policy = parse_policy(&source(Some(true), Some(json!(false))))?;
    let saved = collect_projection(
        &policy.source,
        &policy.rules,
        SelfAuthorizationProjection::Legacy44,
    )?;
    let canonical = canonical_policy_projection(&policy.source, &policy.rules, &saved)?;
    assert!(canonical == saved);
    assert!(canonical["secret/data/+"][0].control.factors[0].self_authorization);
    Ok(())
}
