//! Template producer controls only; actual actor admission is covered separately by Service tests.
use super::super::ssh_ca_policy::{CaRole, SigningContext};
use super::*;
use serde_json::json;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn identity(values: &[(&str, &str)]) -> RequestIdentity {
    let mut projected = IdentityTemplateValues::default();
    for (name, value) in values {
        projected.insert(name, value);
    }
    RequestIdentity {
        values: Some(projected),
    }
}
fn policy(
    role: serde_json::Value,
    body: serde_json::Value,
    id: &RequestIdentity,
) -> Result<(super::super::ssh_ca_policy::SigningPolicy, bool)> {
    let role = CaRole::parse(&role)?;
    let key = super::super::ssh_ca_crypto::generate("ed25519", 0)?.public()?;
    role.signing_policy_authenticated(
        &body,
        &key,
        &SigningContext {
            role_name: "operators",
            display_name: "real-display",
            now: 100,
            default_ttl: 3600,
            max_ttl: 86400,
        },
        id,
    )
}
fn role() -> serde_json::Value {
    json!({"key_type":"ca","allow_user_certificates":true,"allowed_users":"*",
        "default_user":"alice","ttl":"60s"})
}

#[test]
fn ssh_identity_literal_no_entity_and_go_fast_match_rules() -> TestResult {
    let absent = RequestIdentity::absent();
    let current = identity(&[("identity.entity.name", "alice")]);
    for literal in [
        "{{}}",
        "{{\n}}",
        "{{",
        "}}",
        "plain+*",
        "{{identity.entity.name\n}}",
    ] {
        assert!(!matched_template(literal));
        assert_eq!(current.render(literal, false)?, literal);
    }
    assert!(matched_template("{{{identity.entity.name}}"));
    assert!(matched_template("{{é}}"));
    assert!(!matched_template(&"{".repeat(MAX_TEMPLATE_BYTES)));
    assert!(matched_template(&format!(
        "{}x}}}}",
        "{".repeat(MAX_TEMPLATE_BYTES - 3)
    )));
    for source in [
        "{{unknown}}",
        "{{identity.entity.name}}",
        "}}x{{unknown}}",
        "{{unknown}}}}",
    ] {
        assert_eq!(absent.render(source, false)?, source);
    }
    assert_eq!(
        current.render("pre{{ identity.entity.name }}post", false)?,
        "prealicepost"
    );
    for invalid in [
        "{{unknown}}",
        "{{{identity.entity.name}}",
        "}}x{{identity.entity.name}}",
        "{{identity.entity.name}}}}",
        "{{identity.entity.name}}{{unfinished",
    ] {
        assert_eq!(
            current
                .render(invalid, true)
                .err()
                .ok_or("expected template denial")?
                .status,
            400
        );
    }
    Ok(())
}
#[test]
fn ssh_identity_metadata_nonrecursive_comma_only_blocking_and_missing_values() -> TestResult {
    let id = identity(&[
        ("identity.entity.metadata.empty", ""),
        (
            "identity.entity.metadata.literal",
            "{{identity.entity.name}}",
        ),
        ("identity.entity.metadata.users", "alice,bob"),
        ("identity.entity.metadata.symbols", "*+/colon:at@"),
        ("identity.entity.name", ""),
    ]);
    assert_eq!(
        id.render("a{{identity.entity.metadata.empty}}b", false)?,
        "ab"
    );
    assert_eq!(
        id.render("{{identity.entity.metadata.literal}}", false)?,
        "{{identity.entity.name}}"
    );
    assert_eq!(
        id.render("{{identity.entity.metadata.symbols}}", false)?,
        "*+/colon:at@"
    );
    assert_eq!(id.render("alice,bob", false)?, "alice,bob");
    assert_eq!(
        id.render("{{identity.entity.metadata.users}}", false)
            .err()
            .ok_or("comma denial")?
            .status,
        400
    );
    assert_eq!(
        id.render("{{identity.entity.metadata.users}}", true)?,
        "alice,bob"
    );
    for source in [
        "{{identity.entity.name}}",
        "{{identity.entity.metadata.absent}}",
        "{{identity.entity.metadata}}",
        "{{identity.entity.groups.ids}}",
        "{{identity.groups.names.nonmember.name}}",
    ] {
        assert!(id.render(source, true).is_err());
    }
    assert!(parse_selector("identity.groups.names.team@ops.metadata.realm").is_some());
    Ok(())
}
#[test]
fn ssh_identity_default_rendered_even_with_explicit_principals_and_wildcard_not_inferred()
-> TestResult {
    let id = identity(&[("identity.entity.metadata.users", "*")]);
    let mut current = role();
    current["default_user"] = json!("{{identity.entity.metadata.absent}}");
    current["default_user_template"] = json!(true);
    assert_eq!(
        policy(current, json!({"valid_principals":"alice"}), &id)
            .err()
            .ok_or("default template denial")?
            .status,
        500
    );
    let mut current = role();
    current["allowed_users"] = json!("{{identity.entity.metadata.users}}");
    current["allowed_users_template"] = json!(true);
    assert_eq!(
        policy(current.clone(), json!({"valid_principals":"alice"}), &id)
            .err()
            .ok_or("rendered wildcard is literal")?
            .status,
        400
    );
    assert_eq!(
        policy(current, json!({"valid_principals":"*"}), &id)?
            .0
            .principals,
        vec!["*"]
    );
    let absent = RequestIdentity::absent();
    assert_eq!(
        policy(role(), json!({"valid_principals":"alice,bob"}), &absent)?
            .0
            .principals,
        vec!["alice", "bob"]
    );
    Ok(())
}
#[test]
fn ssh_identity_extensions_no_entity_warning_and_explicit_override_are_lazy() -> TestResult {
    let mut current = role();
    current["default_extensions_template"] = json!(true);
    current["allowed_extensions"] = json!("explicit");
    current["default_extensions"] = json!({
        "static":"unchanged", "empty":"{{}}", "missing":"{{identity.entity.name}}"
    });
    let (result, warning) = policy(current.clone(), json!({}), &RequestIdentity::absent())?;
    assert!(warning);
    assert_eq!(
        result.extensions,
        BTreeMap::from([
            ("empty".to_owned(), "{{}}".to_owned()),
            ("static".to_owned(), "unchanged".to_owned())
        ])
    );
    let (result, warning) = policy(
        current.clone(),
        json!({"extensions":{"explicit":"actual"}}),
        &RequestIdentity::absent(),
    )?;
    assert!(!warning);
    assert_eq!(
        result.extensions,
        BTreeMap::from([("explicit".to_owned(), "actual".to_owned())])
    );
    let id = identity(&[("identity.entity.name", "alice")]);
    let (result, warning) = policy(current, json!({"extensions":{}}), &id)?;
    assert!(!warning);
    assert_eq!(result.extensions["missing"], "alice");
    Ok(())
}
#[test]
fn ssh_identity_host_domain_context_ignores_user_template_but_checks_actual_domains() -> TestResult
{
    let mut current = role();
    current["allow_host_certificates"] = json!(true);
    current["default_user_template"] = json!(true);
    current["default_user"] = json!("{{missing}}");
    current["allowed_users_template"] = json!(true);
    current["allowed_users"] = json!("{{missing}}");
    current["allowed_domains_template"] = json!(true);
    current["allowed_domains"] = json!("{{identity.entity.metadata.domain}}");
    current["allow_subdomains"] = json!(true);
    let id = identity(&[("identity.entity.metadata.domain", "example.test")]);
    let (result, _) = policy(
        current.clone(),
        json!({"cert_type":"host","valid_principals":"a.example.test"}),
        &id,
    )?;
    assert!(result.kind.is_host());
    assert_eq!(result.principals, vec!["a.example.test"]);
    assert!(
        policy(
            current.clone(),
            json!({"cert_type":"host","valid_principals":"example.test"}),
            &id
        )
        .is_err()
    );
    assert!(
        policy(
            current,
            json!({"cert_type":"host","valid_principals":"a.attacker.test"}),
            &id
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn ssh_identity_time_uses_actual_wall_data_without_grant_or_clock_rearm() -> TestResult {
    let id = identity(&[]);
    let before = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let rendered = id.render("{{time.now.plus.1.5s}}", true)?.parse::<i64>()?;
    let after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    assert!(rendered > before && rendered <= after + 2);
    for input in [
        "{{time.never}}",
        "{{time.now.plus}}",
        "{{time.now.times.1s}}",
        "{{time.now.plus.no}}",
    ] {
        assert!(id.render(input, true).is_err());
    }
    let original = std::time::Instant::now() - std::time::Duration::from_millis(1);
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(original);
    assert!(id.render("{{time.now}}", true)?.parse::<i64>()? >= before);
    assert_eq!(crate::request_deadline::current(), Some(original));
    assert_eq!(
        super::super::ssh_ca_crypto::deadline()
            .err()
            .ok_or("original deadline")?
            .status,
        503
    );
    Ok(())
}
