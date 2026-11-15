#![allow(clippy::unwrap_used)]
use super::*;
use std::time::{Duration, Instant};

const POLICY: &str =
    r#"path "secret/data/timed143" { capabilities = ["create", "update", "read"] }"#;

fn at(seconds: u64, nanoseconds: u32) -> AuthorityTime {
    AuthorityTime::Precise(Timestamp::checked(seconds, nanoseconds).unwrap())
}

fn call(
    state: &mut AuthState,
    raw: &str,
    time: AuthorityTime,
    method: &str,
    path: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    let mut actor = state.authenticate_from_observed(raw, time, None)?;
    // A deterministic private Service-style clock; the request's immutable
    // floor, never a public field, owns all observations in this unit fixture.
    let clock = RequestClock::anchored(Duration::ZERO, Instant::now())
        .unwrap()
        .with_timestamp_floor(time.exact().unwrap());
    actor.bind_request_clock(Some(clock))?;
    state
        .handle_with_connection_clock(
            Some(&actor),
            "",
            method,
            path,
            &body,
            time,
            Some(clock),
            None,
            None,
        )?
        .ok_or_else(denied)
}

fn write(
    state: &mut AuthState,
    root: &str,
    time: AuthorityTime,
    name: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    call(
        state,
        root,
        time,
        "POST",
        &format!("sys/policies/acl/{name}"),
        body,
    )
}

fn user(state: &mut AuthState, root: &str, names: &[&str]) -> String {
    let response = call(
        state,
        root,
        at(100, 0),
        "POST",
        "auth/token/create",
        json!({"policies":names,"ttl":1000,"no_default_policy":!names.contains(&"default")}),
    )
    .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body["auth"]["policies"], json!(names));
    response.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn expiration143_absolute_epoch_rfc3339_fraction_and_utc_api_conversion() {
    let deadline = absolute(&json!("1970-01-01T01:01:41.123456789+01:00")).unwrap();
    assert_eq!(deadline.instant(), (101, 123_456_789));
    assert_eq!(
        deadline.render().unwrap(),
        "1970-01-01T01:01:41.123456789+01:00"
    );
    for value in [json!(-1), json!("-1"), json!("+00101"), json!(101)] {
        assert!(absolute(&value).is_ok());
    }
    for value in [
        json!(true),
        json!(101.5),
        json!("1e3"),
        json!(""),
        json!([]),
        json!("1970-01-01t00:01:41Z"),
        json!("1970-01-01T00:01:60Z"),
    ] {
        assert!(absolute(&value).is_err(), "{value}");
    }
    let prepared = prepare(
        None,
        &json!({"expiration":"1970-01-01T01:01:41.1+01:00"}),
        false,
        at(100, 0),
    )
    .unwrap()
    .unwrap();
    assert_eq!(prepared.render().unwrap(), "1970-01-01T00:01:41.1Z");
    let mut policy = security_contract::prepare_policy(
        None,
        &json!({"policy":POLICY,"expiration":"1970-01-01T01:01:41.1+01:00"}),
        false,
        false,
        at(100, 0),
    )
    .unwrap();
    policy.validate_expiration().unwrap();
    policy.expiration.as_mut().unwrap().offset_seconds = 3_600;
    assert!(policy.validate_expiration().is_err());
}

#[test]
fn expiration143_path_hcl_json_signed_epoch_null_and_live_equality() {
    for source in [
        r#"path "secret/data/timed143" { capabilities = ["read"] expiration = -1 }"#.to_owned(),
        r#"path "secret/data/timed143" { capabilities = ["read"] expiration = "-1" }"#.to_owned(),
        json!({"path":{"secret/data/timed143":{"capabilities":["read"],"expiration":-1}}})
            .to_string(),
    ] {
        let parsed = security_contract::prepare_policy(
            None,
            &json!({"policy":source}),
            false,
            false,
            at(100, 0),
        )
        .unwrap();
        assert_eq!(parsed.source, source);
        assert!(parsed.rules.is_empty());
        assert_eq!(parsed.path_compiled_at, at(100, 0).exact());
        parsed.validate_expiration().unwrap();
    }
    assert!(
        !path(Some(&json!(-1)))
            .unwrap()
            .unwrap()
            .live(at(100, 0))
            .unwrap()
    );
    for value in [Value::Null, json!("")] {
        assert!(path(Some(&value)).unwrap().is_none());
    }
    assert!(path(Some(&json!(true))).is_err());
    assert!(path(Some(&json!(101.5))).is_err());
    let deadline = path(Some(&json!("1970-01-01T00:01:41.5Z")))
        .unwrap()
        .unwrap();
    assert!(deadline.live(at(101, 500_000_000)).unwrap());
    assert!(!deadline.live(at(101, 500_000_001)).unwrap());
    assert!(deadline.live(AuthorityTime::Coarse(101)).is_err());
}

#[test]
fn expiration143_whole_ttl_truncation_conflict_null_zero_and_strict_future() {
    let now = at(100, 125_000_000);
    for (ttl, seconds) in [(json!("1.9s"), 1), (json!(2), 2), (json!("1d"), 86_400)] {
        let deadline = prepare(None, &json!({"ttl":ttl}), false, now)
            .unwrap()
            .unwrap();
        assert_eq!(deadline.instant(), (100 + seconds, 125_000_000));
    }
    for body in [
        json!({"ttl":0}),
        json!({"ttl":"999ms"}),
        json!({"ttl":"-1s"}),
        json!({"ttl":true}),
        json!({"expiration":100}),
        json!({"expiration":"1970-01-01T00:01:40.125Z"}),
        json!({"expiration":200,"ttl":1}),
    ] {
        assert!(prepare(None, &body, false, now).is_err(), "{body}");
    }
    assert!(
        prepare(None, &json!({"expiration":null,"ttl":null}), false, now)
            .unwrap()
            .is_none()
    );
    assert!(
        prepare(
            None,
            &json!({"expiration":"0001-01-01T00:00:00Z"}),
            false,
            now
        )
        .unwrap()
        .is_none()
    );
    assert!(prepare(None, &json!({"ttl":1}), false, AuthorityTime::Coarse(100)).is_err());
}

#[test]
fn expiration143_patch_preserves_and_post_clears_omitted_expiration() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    write(
        &mut state,
        &root,
        at(100, 0),
        "lifecycle",
        json!({"policy":POLICY,"ttl":50}),
    )
    .unwrap();
    call(
        &mut state,
        &root,
        at(110, 0),
        "PATCH",
        "sys/policies/acl/lifecycle",
        json!({"ttl":null}),
    )
    .unwrap();
    let read = call(
        &mut state,
        &root,
        at(110, 0),
        "GET",
        "sys/policies/acl/lifecycle",
        json!({}),
    )
    .unwrap();
    assert_eq!(read.body["data"]["expiration"], "1970-01-01T00:02:30Z");
    assert_eq!(read.body["data"]["version"], 2);
    call(
        &mut state,
        &root,
        at(115, 0),
        "PATCH",
        "sys/policies/acl/lifecycle",
        json!({"expiration":"0001-01-01T00:00:00Z"}),
    )
    .unwrap();
    assert!(state.policies[""]["lifecycle"].expiration.is_none());
    write(
        &mut state,
        &root,
        at(120, 0),
        "lifecycle",
        json!({"policy":POLICY,"ttl":30}),
    )
    .unwrap();
    write(
        &mut state,
        &root,
        at(130, 0),
        "lifecycle",
        json!({"policy":POLICY,"expiration":null}),
    )
    .unwrap();
    assert!(state.policies[""]["lifecycle"].expiration.is_none());
    assert!(
        call(
            &mut state,
            &root,
            at(151, 0),
            "GET",
            "sys/policies/acl/lifecycle",
            json!({})
        )
        .unwrap()
        .body["data"]
            .get("expiration")
            .is_none()
    );
}

#[test]
fn expiration143_unread_expired_post_keeps_cas_but_get_and_patch_delete() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    for name in ["unread", "read", "patch"] {
        write(
            &mut state,
            &root,
            at(100, 0),
            name,
            json!({"policy":POLICY,"expiration":101,"cas":-1,"cas_required":true}),
        )
        .unwrap();
    }
    let before = serde_json::to_vec(&state).unwrap();
    let list = call(
        &mut state,
        &root,
        at(102, 0),
        "LIST",
        "sys/policies/acl",
        json!({}),
    )
    .unwrap();
    assert!(
        list.body["data"]["keys"]
            .as_array()
            .unwrap()
            .contains(&json!("unread"))
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    assert!(
        write(
            &mut state,
            &root,
            at(102, 0),
            "unread",
            json!({"policy":POLICY})
        )
        .is_err()
    );
    write(
        &mut state,
        &root,
        at(102, 0),
        "unread",
        json!({"policy":POLICY,"cas":1}),
    )
    .unwrap();
    assert_eq!(
        state.policies[""]["unread"]
            .read_security_data("unread", false)
            .unwrap()["version"],
        2
    );
    let get = call(
        &mut state,
        &root,
        at(101, 0),
        "GET",
        "sys/policies/acl/read",
        json!({}),
    )
    .unwrap();
    assert_eq!(get.status, 200);
    let get = call(
        &mut state,
        &root,
        at(101, 1),
        "GET",
        "sys/policies/acl/read",
        json!({}),
    )
    .unwrap();
    assert_eq!(get.status, 404);
    assert!(get.mutated);
    assert!(!state.policies[""].contains_key("read"));
    let patch = call(
        &mut state,
        &root,
        at(102, 0),
        "PATCH",
        "sys/policies/acl/patch",
        json!({"ttl":100}),
    )
    .unwrap();
    assert_eq!(patch.status, 404);
    assert!(patch.mutated);
    assert!(!state.policies[""].contains_key("patch"));
    write(
        &mut state,
        &root,
        at(103, 0),
        "read",
        json!({"policy":POLICY,"cas":-1}),
    )
    .unwrap();
    assert_eq!(
        state.policies[""]["read"]
            .read_security_data("read", false)
            .unwrap()["version"],
        1
    );
}

#[test]
fn expiration143_invalid_policy_mutations_leave_owner_bytes_unchanged() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    write(
        &mut state,
        &root,
        at(100, 0),
        "atomic",
        json!({"policy":POLICY,"ttl":30}),
    )
    .unwrap();
    for body in [
        json!({"policy":POLICY,"ttl":0}),
        json!({"policy":POLICY,"expiration":99}),
        json!({"policy":POLICY,"expiration":140,"ttl":20}),
        json!({"policy":POLICY,"ttl":20,"cas":100}),
    ] {
        let before = serde_json::to_vec(&state).unwrap();
        assert!(write(&mut state, &root, at(101, 0), "atomic", body).is_err());
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    }
}

#[test]
fn expiration143_cached_rule_cannot_drop_or_splice_expiration() {
    let source = r#"path "secret/data/timed143" { capabilities = ["read"] expiration = "101" }
        path "secret/data/timed143" { capabilities = ["deny"] expiration = "102" }"#;
    let parsed = security_contract::prepare_policy(
        None,
        &json!({"policy":source}),
        false,
        false,
        at(100, 0),
    )
    .unwrap();
    let wire = serde_json::to_vec(&parsed).unwrap();
    let restored: Policy = serde_json::from_slice(&wire).unwrap();
    restored.validate_expiration().unwrap();
    assert_eq!(serde_json::to_vec(&restored).unwrap(), wire);
    let mut missing = restored.clone();
    missing.rules[0].expiration = None;
    assert!(missing.validate_expiration().is_err());
    let mut missing_clock = restored.clone();
    missing_clock.path_compiled_at = None;
    assert!(missing_clock.validate_expiration().is_err());
    let mut spliced = restored;
    spliced.rules[0].expiration = spliced.rules[1].expiration;
    assert!(spliced.validate_expiration().is_err());
    let old = parse_policy(&json!(POLICY)).unwrap();
    let old_wire = serde_json::to_value(old).unwrap();
    assert!(old_wire.get("expiration").is_none());
    assert!(old_wire.get("expired_default").is_none());
    assert!(old_wire["rules"][0].get("expiration").is_none());
}

#[test]
fn expiration143_expired_at_write_skips_semantics_but_keeps_raw_and_compile_clock() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    let source = r#"path "secret/retired" { capabilities = ["unsupported"]
        min_wrapping_ttl = "not-a-duration" expiration = "99" }
        path "secret/missing" { expiration = "99" }
        path "secret/data/timed143" { capabilities = ["read"] }"#;
    write(
        &mut state,
        &root,
        at(100, 0),
        "compiled",
        json!({"policy":source}),
    )
    .unwrap();
    let stored = &state.policies[""]["compiled"];
    assert_eq!(stored.source, source);
    assert_eq!(stored.rules.len(), 1);
    assert!(stored.path_compiled_at.is_some());
    stored.validate_expiration().unwrap();
    let wire = serde_json::to_vec(stored).unwrap();
    let reopened: Policy = serde_json::from_slice(&wire).unwrap();
    reopened.validate_expiration().unwrap();
    assert_eq!(serde_json::to_vec(&reopened).unwrap(), wire);
    let mut lost_clock = reopened.clone();
    lost_clock.path_compiled_at = None;
    assert!(lost_clock.validate_expiration().is_err());
    let mut moved_clock = reopened;
    moved_clock.path_compiled_at = Some(Timestamp::whole(101).unwrap());
    assert!(moved_clock.validate_expiration().is_err());
    let still_live = source.replace("expiration = \"99\"", "expiration = \"100\"");
    let before = serde_json::to_vec(&state).unwrap();
    assert!(
        write(
            &mut state,
            &root,
            at(100, 0),
            "compiled",
            json!({"policy":still_live})
        )
        .is_err()
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
}

#[test]
fn expiration143_past_paths_keep_pre_expiration_template_control_and_typed_field_checks() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    for source in [
        r#"path "secret/{{bad" { capabilities = ["read"] expiration = "99" }"#,
        r#"path "secret/past" { capabilities = ["read"] allowed_parameters = false expiration = "99" }"#,
        r#"path "secret/past" { capabilities = ["read"] control_group = { ttl = "10s" } expiration = "99" }"#,
        r#"{"path":{"secret/past":{"capabilities":["read"],"required_parameters":false,"expiration":"99"}}}"#,
        r#"{"path":{"secret/past":{"capabilities":[1.0],"expiration":"99"}}}"#,
        r#"{"path":{"secret/past":{"capabilities":[1e3],"expiration":"99"}}}"#,
        r#"{"path":{"secret/past":{"capabilities":["read"],"control_group":{"ttl":"10s"},"expiration":"99"}}}"#,
    ] {
        let before = serde_json::to_vec(&state).unwrap();
        assert!(
            write(
                &mut state,
                &root,
                at(100, 0),
                "prechecks",
                json!({"policy":source})
            )
            .is_err()
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    }
    let past_bad_wildcard = r#"path "secret/+*" { capabilities = ["read"] expiration = "99" }"#;
    write(
        &mut state,
        &root,
        at(100, 0),
        "past-wildcard",
        json!({"policy":past_bad_wildcard}),
    )
    .unwrap();
    assert!(state.policies[""]["past-wildcard"].rules.is_empty());
    let at_boundary = past_bad_wildcard.replace("\"99\"", "\"100\"");
    assert!(
        write(
            &mut state,
            &root,
            at(100, 0),
            "past-wildcard",
            json!({"policy":at_boundary})
        )
        .is_err()
    );
}

#[test]
fn expiration143_expired_grants_and_denies_leave_the_existing_acl_priority() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    let source = r#"path "secret/*" { capabilities = ["read"] }
        path "secret/data/timed143" { capabilities = ["deny"] expiration = "101" }
        path "other/data/timed143" { capabilities = ["read"] expiration = "102" }"#;
    write(
        &mut state,
        &root,
        at(100, 0),
        "paths",
        json!({"policy":source}),
    )
    .unwrap();
    let raw = user(&mut state, &root, &["paths"]);
    let actor = state
        .authenticate_from_observed(&raw, at(100, 0), None)
        .unwrap();
    assert_eq!(
        state
            .authorize_request_observed(&actor, "", "secret/data/timed143", "read", at(101, 0))
            .err()
            .unwrap()
            .status,
        403
    );
    assert!(
        state
            .authorize_request_observed(&actor, "", "secret/data/timed143", "read", at(101, 1))
            .is_ok()
    );
    assert!(
        state
            .authorize_request_observed(&actor, "", "other/data/timed143", "read", at(102, 0))
            .is_ok()
    );
    assert_eq!(
        state
            .authorize_request_observed(&actor, "", "other/data/timed143", "read", at(102, 1))
            .err()
            .unwrap()
            .status,
        403
    );
    assert_eq!(state.policies[""]["paths"].source, source);
}

#[test]
fn expiration143_whole_policy_filters_tokens_identity_and_templates_without_fallback() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    write(
        &mut state,
        &root,
        at(100, 0),
        "whole",
        json!({"policy":POLICY,"ttl":1}),
    )
    .unwrap();
    let raw = user(&mut state, &root, &["whole"]);
    let mut actor = state
        .authenticate_from_observed(&raw, at(100, 0), None)
        .unwrap();
    assert!(
        state
            .authorize_request_observed(&actor, "", "secret/data/timed143", "read", at(101, 0))
            .is_ok()
    );
    assert_eq!(
        state
            .authorize_request_observed(&actor, "", "secret/data/timed143", "read", at(101, 1))
            .err()
            .unwrap()
            .status,
        403
    );
    write(
        &mut state,
        &root,
        at(100, 0),
        "identity",
        json!({"policy":POLICY,"ttl":1}),
    )
    .unwrap();
    actor.bind_identity_policies(BTreeSet::from(["identity".into()]));
    assert_eq!(
        state
            .authorize_request_observed(&actor, "", "secret/data/timed143", "read", at(101, 1))
            .err()
            .unwrap()
            .status,
        403
    );
    let source = r#"path "secret/data/{{identity.entity.metadata.scope}}" { capabilities = ["read"] expiration = "101" }"#;
    write(
        &mut state,
        &root,
        at(100, 0),
        "templates",
        json!({"policy":source}),
    )
    .unwrap();
    let names = BTreeSet::from(["templates".into()]);
    assert!(
        !state
            .policy_template_selectors_observed("", &names, &BTreeSet::new(), at(101, 0))
            .unwrap()
            .is_empty()
    );
    assert!(
        state
            .policy_template_selectors_observed("", &names, &BTreeSet::new(), at(101, 1))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn expiration143_expired_parameters_and_wrapping_bounds_do_not_survive_the_stanza() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    let source = r#"path "secret/*" { capabilities = ["update"] }
        path "secret/data/timed143" { capabilities = ["update"]
            denied_parameters = { "blocked" = [] } min_wrapping_ttl = 1 expiration = "101" }"#;
    write(
        &mut state,
        &root,
        at(100, 0),
        "constraints",
        json!({"policy":source}),
    )
    .unwrap();
    let raw = user(&mut state, &root, &["constraints"]);
    let mut actor = state
        .authenticate_from_observed(&raw, at(100, 0), None)
        .unwrap();
    assert!(
        state
            .authorize_request_observed(&actor, "", "secret/data/timed143", "update", at(101, 0))
            .is_err()
    );
    actor.bind_request_wrapping_ttl(Some(5));
    assert!(
        state
            .authorize_request_parameters_observed(
                &actor,
                "",
                "POST",
                "secret/data/timed143",
                &json!({"blocked":true}),
                at(101, 0)
            )
            .is_err()
    );
    actor.bind_request_wrapping_ttl(None);
    assert!(
        state
            .authorize_request_observed(&actor, "", "secret/data/timed143", "update", at(101, 1))
            .is_ok()
    );
    assert!(
        state
            .authorize_request_parameters_observed(
                &actor,
                "",
                "POST",
                "secret/data/timed143",
                &json!({"blocked":true}),
                at(101, 1)
            )
            .is_ok()
    );
}

#[test]
fn expiration143_control_group_expiry_uses_the_same_original_policy_time() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    let source = r#"path "secret/data/timed143" { capabilities = ["read"] expiration = "101"
        control_group = { ttl = "60s" factor "review" {
            identity { group_names = ["reviewers"] approvals = 1 }
        } } }"#;
    write(
        &mut state,
        &root,
        at(100, 0),
        "controlled",
        json!({"policy":source}),
    )
    .unwrap();
    let raw = user(&mut state, &root, &["controlled"]);
    let actor = state
        .authenticate_from_observed(&raw, at(100, 0), None)
        .unwrap();
    assert!(
        state
            .control_group_policy(&actor, "", "secret/data/timed143", "read", at(101, 0))
            .unwrap()
            .is_some()
    );
    assert!(
        state
            .control_group_policy(&actor, "", "secret/data/timed143", "read", at(101, 1))
            .unwrap()
            .is_none()
    );
}

#[test]
fn expiration143_capability_target_identity_does_not_refresh_an_old_observation() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    write(
        &mut state,
        &root,
        at(100, 0),
        "inspected",
        json!({"policy":POLICY,"ttl":1}),
    )
    .unwrap();
    let raw = user(&mut state, &root, &["inspected"]);
    let actor = state
        .authenticate_from_observed(&root, at(100, 0), None)
        .unwrap();
    let target = state
        .inspection_target_observed(
            &actor,
            "",
            "sys/capabilities",
            &json!({"token":raw}),
            at(100, 0),
        )
        .unwrap();
    let caps = state
        .inspect_capabilities_observed(
            "",
            "secret/data/timed143",
            &target,
            &BTreeSet::new(),
            false,
            &IdentityTemplateValues::default(),
            at(101, 0),
        )
        .unwrap();
    assert!(caps.contains(&"read"));
    let observation = state
        .retain_inspection_observation("", target, &BTreeSet::new(), at(100, 0))
        .unwrap();
    assert!(observation.check_at(at(101, 0)).is_ok());
    assert!(observation.check_at(at(101, 1)).is_err());
    assert!(observation.check_at(AuthorityTime::Coarse(100)).is_err());
    let later = state
        .inspection_target_observed(
            &actor,
            "",
            "sys/capabilities",
            &json!({"token":raw}),
            at(102, 0),
        )
        .unwrap();
    #[cfg(feature = "native-v6-storage")]
    assert!(observation.target() == &later);
    assert_eq!(
        state
            .inspect_capabilities_observed(
                "",
                "secret/data/timed143",
                &later,
                &BTreeSet::new(),
                false,
                &IdentityTemplateValues::default(),
                at(102, 0)
            )
            .unwrap(),
        vec!["deny"]
    );
}

#[test]
fn expiration143_default_expiry_does_not_restore_builtin_permissions_on_get() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    write(
        &mut state,
        &root,
        at(100, 0),
        "default",
        json!({"policy":POLICY,"ttl":1}),
    )
    .unwrap();
    let raw = user(&mut state, &root, &["default"]);
    let before = state
        .authenticate_from_observed(&raw, at(100, 0), None)
        .unwrap();
    state
        .authorize_request_observed(&before, "", "secret/data/timed143", "read", at(100, 0))
        .unwrap();
    assert_eq!(
        call(
            &mut state,
            &root,
            at(102, 0),
            "GET",
            "sys/policies/acl/default",
            json!({})
        )
        .unwrap()
        .status,
        404
    );
    assert!(state.policies[""]["default"].expired_default);
    let list = call(
        &mut state,
        &root,
        at(102, 0),
        "LIST",
        "sys/policies/acl",
        json!({}),
    )
    .unwrap();
    assert!(
        !list.body["data"]["keys"]
            .as_array()
            .unwrap()
            .contains(&json!("default"))
    );
    let actor = state
        .authenticate_from_observed(&raw, at(102, 0), None)
        .unwrap();
    assert!(
        state
            .authorize_request_observed(&actor, "", "secret/data/timed143", "read", at(102, 0))
            .is_err()
    );
    assert!(
        state
            .authorize_request_observed(&actor, "", "auth/token/lookup-self", "read", at(102, 0))
            .is_err()
    );
    assert_eq!(
        call(
            &mut state,
            &root,
            at(102, 0),
            "GET",
            "sys/policies/acl/default",
            json!({})
        )
        .unwrap()
        .status,
        404
    );
    state.validate_policy_expiration_state().unwrap();
    write(
        &mut state,
        &root,
        at(103, 0),
        "default",
        json!({"policy":default_policy_source(),"cas":-1}),
    )
    .unwrap();
    assert!(!state.policies[""]["default"].expired_default);
    let restored = state
        .authenticate_from_observed(&raw, at(103, 0), None)
        .unwrap();
    state
        .authorize_request_observed(&restored, "", "auth/token/lookup-self", "read", at(103, 0))
        .unwrap();
}

fn expired_control_policy143() -> Value {
    json!({"path":{"secret/past-control143":{
        "expiration":"99",
        "control_group":{"ttl":"10s","factor":{"review":{
            "controlled_capabilities":["read"],
            "identity":{"group_names":["reviewers"],"approvals":1}
        }}}
    }}})
}

#[test]
fn expiration143_past_control_operations_do_not_require_retained_path_capabilities() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    for (index, capabilities) in [None, Some(json!(["unsupported"]))].into_iter().enumerate() {
        let mut policy = expired_control_policy143();
        if let Some(capabilities) = capabilities {
            policy["path"]["secret/past-control143"]["capabilities"] = capabilities;
        }
        let source = policy.to_string();
        let name = format!("past-control-{index}");
        write(
            &mut state,
            &root,
            at(100, 0),
            &name,
            json!({"policy":source.clone()}),
        )
        .unwrap();
        let saved = &state.policies[""][&name];
        assert_eq!(saved.source, source);
        assert!(saved.rules.is_empty());
        assert!(saved.control_groups.is_empty());
        saved.validate_expiration().unwrap();
        let bytes = serde_json::to_vec(saved).unwrap();
        let reopened: Policy = serde_json::from_slice(&bytes).unwrap();
        reopened.validate_expiration().unwrap();
        assert_eq!(serde_json::to_vec(&reopened).unwrap(), bytes);
    }
    let hcl = r#"path "secret/past-control143" {
        expiration = "99"
        control_group = { ttl = "10s" factor "review" {
            controlled_capabilities = ["read"]
            identity = { group_names = ["reviewers"] approvals = 1 }
        } }
    }"#;
    write(
        &mut state,
        &root,
        at(100, 0),
        "past-hcl-control",
        json!({"policy":hcl}),
    )
    .unwrap();
    let saved = &state.policies[""]["past-hcl-control"];
    assert_eq!(saved.source, hcl);
    assert!(saved.rules.is_empty());
    saved.validate_expiration().unwrap();
    let still_live = hcl.replace("expiration = \"99\"", "expiration = \"100\"");
    let before = serde_json::to_vec(&state).unwrap();
    assert!(
        write(
            &mut state,
            &root,
            at(100, 0),
            "boundary-control",
            json!({"policy":still_live})
        )
        .is_err()
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
}

#[test]
fn expiration143_past_control_uses_official_operations_and_revalidates_saved_source() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    let mut policy = expired_control_policy143();
    let stanza = &mut policy["path"]["secret/past-control143"];
    stanza["capabilities"] = json!(["unsupported"]);
    stanza["control_group"]["factor"]["review"]["controlled_capabilities"] = json!([
        "create",
        "read",
        "update",
        "patch",
        "delete",
        "list",
        "scan",
        "help",
        "alias-lookahead",
        "resolve-role",
        "resolve-path",
        "header",
        "revoke",
        "renew",
        "rollback"
    ]);
    write(
        &mut state,
        &root,
        at(100, 0),
        "operation-vocabulary",
        json!({"policy":policy.to_string()}),
    )
    .unwrap();
    let saved = &state.policies[""]["operation-vocabulary"];
    assert!(saved.rules.is_empty());
    saved.validate_expiration().unwrap();
    let bytes = serde_json::to_vec(saved).unwrap();
    let mut reopened: Policy = serde_json::from_slice(&bytes).unwrap();
    reopened.source = reopened.source.replace("\"help\"", "\"not-an-operation\"");
    assert!(reopened.validate_expiration().is_err());

    for invalid in ["deny", "sudo", "not-an-operation", "READ"] {
        let mut policy = expired_control_policy143();
        let stanza = &mut policy["path"]["secret/past-control143"];
        // A matching path spelling must not launder an invalid operation
        // through the live path's old subset check before the stanza is skipped.
        stanza["capabilities"] = json!([invalid]);
        stanza["control_group"]["factor"]["review"]["controlled_capabilities"] = json!([invalid]);
        let before = serde_json::to_vec(&state).unwrap();
        assert!(
            write(
                &mut state,
                &root,
                at(100, 0),
                "invalid-operation",
                json!({"policy":policy.to_string()})
            )
            .is_err()
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    }
}

#[test]
fn expiration143_past_control_required_fields_cannot_be_hidden_by_expiration() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    let mut missing_operations = expired_control_policy143();
    missing_operations["path"]["secret/past-control143"]["control_group"]["factor"]["review"]
        .as_object_mut()
        .unwrap()
        .remove("controlled_capabilities");
    let mut empty_operations = expired_control_policy143();
    empty_operations["path"]["secret/past-control143"]["control_group"]["factor"]["review"]["controlled_capabilities"] =
        json!([]);
    let mut ids_only = expired_control_policy143();
    ids_only["path"]["secret/past-control143"]["control_group"]["factor"]["review"]["identity"] =
        json!({"group_ids":["group-id"],"approvals":1});
    let mut empty_names = expired_control_policy143();
    empty_names["path"]["secret/past-control143"]["control_group"]["factor"]["review"]["identity"] =
        json!({"group_ids":["group-id"],"group_names":[],"approvals":1});
    let mut no_approvals = expired_control_policy143();
    no_approvals["path"]["secret/past-control143"]["control_group"]["factor"]["review"]["identity"]
        ["approvals"] = json!(0);
    let mut invalid_ttl = expired_control_policy143();
    invalid_ttl["path"]["secret/past-control143"]["control_group"]["ttl"] = json!("not-a-duration");
    for policy in [
        missing_operations,
        empty_operations,
        ids_only,
        empty_names,
        no_approvals,
        invalid_ttl,
    ] {
        let before = serde_json::to_vec(&state).unwrap();
        assert!(
            write(
                &mut state,
                &root,
                at(100, 0),
                "invalid-control",
                json!({"policy":policy.to_string()})
            )
            .is_err()
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    }
}

#[test]
fn expiration143_live_control_keeps_existing_subset_and_group_id_contract() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    let mut policy = expired_control_policy143();
    let stanza = &mut policy["path"]["secret/past-control143"];
    stanza["expiration"] = json!("101");
    stanza["capabilities"] = json!(["read"]);
    stanza["control_group"]["factor"]["review"]["identity"] =
        json!({"group_ids":["group-id"],"approvals":1});
    stanza["control_group"]["factor"]["review"]
        .as_object_mut()
        .unwrap()
        .remove("controlled_capabilities");
    write(
        &mut state,
        &root,
        at(100, 0),
        "legacy-live-control",
        json!({"policy":policy.to_string()}),
    )
    .unwrap();
    assert_eq!(state.policies[""]["legacy-live-control"].rules.len(), 1);
    policy["path"]["secret/past-control143"]["expiration"] = json!("99");
    let before = serde_json::to_vec(&state).unwrap();
    assert!(
        write(
            &mut state,
            &root,
            at(100, 0),
            "past-id-control",
            json!({"policy":policy.to_string()})
        )
        .is_err()
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);

    let mut policy = expired_control_policy143();
    let stanza = &mut policy["path"]["secret/past-control143"];
    stanza["expiration"] = json!("101");
    stanza["capabilities"] = json!(["read"]);
    stanza["control_group"]["factor"]["review"]["controlled_capabilities"] = json!(["help"]);
    assert!(
        write(
            &mut state,
            &root,
            at(100, 0),
            "live-subset-control",
            json!({"policy":policy.to_string()})
        )
        .is_err()
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    policy["path"]["secret/past-control143"]["expiration"] = json!("99");
    write(
        &mut state,
        &root,
        at(100, 0),
        "past-help-control",
        json!({"policy":policy.to_string()}),
    )
    .unwrap();
    assert!(state.policies[""]["past-help-control"].rules.is_empty());
}

#[test]
fn expiration143_past_control_preserves_lists_and_ignores_unused_identity_fields() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    let mut policy = expired_control_policy143();
    let control = &mut policy["path"]["secret/past-control143"]["control_group"];
    control["factor"]["review"]["controlled_capabilities"] = json!(["read", "read"]);
    control["factor"]["review"]["identity"] = json!({
        "group_names":["reviewers", "reviewers", "", 1], "approvals":"0x1",
        "group_ids":false, "ttl":"not-a-duration", "self_authorization":{"unused":true},
        "unrecognized_identity_field":{"ignored":true}
    });
    let source = policy.to_string();
    write(
        &mut state,
        &root,
        at(100, 0),
        "past-duplicate-control",
        json!({"policy":source.clone()}),
    )
    .unwrap();
    let saved = &state.policies[""]["past-duplicate-control"];
    assert_eq!(saved.source, source);
    assert!(saved.rules.is_empty());
    assert!(saved.control_groups.is_empty());
    let bytes = serde_json::to_vec(saved).unwrap();
    let reopened: Policy = serde_json::from_slice(&bytes).unwrap();
    reopened.validate_expiration().unwrap();
    assert_eq!(serde_json::to_vec(&reopened).unwrap(), bytes);

    let hcl = r#"path "secret/past-control143" {
        expiration = "99"
        control_group = { ttl = "0s" factor "review" {
            controlled_capabilities = ["read", "read"]
            identity = { group_names = ["", "reviewers", "reviewers", 1]
                approvals = "0x1" group_ids = false ttl = "not-a-duration" }
        } }
    }"#;
    write(
        &mut state,
        &root,
        at(100, 0),
        "past-hcl-duplicate-control",
        json!({"policy":hcl}),
    )
    .unwrap();
    state.policies[""]["past-hcl-duplicate-control"]
        .validate_expiration()
        .unwrap();
    assert!(
        state.policies[""]["past-hcl-duplicate-control"]
            .rules
            .is_empty()
    );
    let before = serde_json::to_vec(&state).unwrap();
    policy["path"]["secret/past-control143"]["expiration"] = json!("101");
    policy["path"]["secret/past-control143"]["capabilities"] = json!(["read"]);
    assert!(
        write(
            &mut state,
            &root,
            at(100, 0),
            "live-duplicate-control",
            json!({"policy":policy.to_string()})
        )
        .is_err()
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
}

#[test]
fn expiration143_past_control_ttl_decodes_zero_negative_and_numeric_values() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    for (index, ttl) in [
        None,
        Some(Value::Null),
        Some(json!("")),
        Some(json!(0)),
        Some(json!(-1)),
        Some(json!(0.2)),
        Some(json!(-0.2)),
        Some(json!(1.9)),
        Some(json!("-1s")),
        Some(json!("31536001s")),
        Some(json!("1d")),
    ]
    .into_iter()
    .enumerate()
    {
        let mut policy = expired_control_policy143();
        let control = &mut policy["path"]["secret/past-control143"]["control_group"];
        match ttl {
            Some(ttl) => control["ttl"] = ttl,
            None => {
                control.as_object_mut().unwrap().remove("ttl");
            }
        }
        let name = format!("past-control-ttl-{index}");
        write(
            &mut state,
            &root,
            at(100, 0),
            &name,
            json!({"policy":policy.to_string()}),
        )
        .unwrap();
        let saved = &state.policies[""][&name];
        assert!(saved.rules.is_empty());
        assert!(saved.control_groups.is_empty());
        saved.validate_expiration().unwrap();
    }
    for ttl in [
        json!(true),
        json!([]),
        json!({}),
        json!("0.2"),
        json!("0.5d"),
        json!(i64::MAX),
        json!(1e30),
        json!("9223372036854775808ns"),
    ] {
        let mut policy = expired_control_policy143();
        policy["path"]["secret/past-control143"]["control_group"]["ttl"] = ttl;
        let before = serde_json::to_vec(&state).unwrap();
        assert!(
            write(
                &mut state,
                &root,
                at(100, 0),
                "invalid-past-ttl",
                json!({"policy":policy.to_string()})
            )
            .is_err()
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    }
}

#[test]
fn expiration143_past_control_approvals_use_hcl_int_without_live_owner_limits() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    for (index, approvals) in [
        json!(1),
        json!(257),
        json!(1000000),
        json!("1"),
        json!("0x1"),
        json!("01"),
        json!("0b1"),
        json!("0o1"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut policy = expired_control_policy143();
        policy["path"]["secret/past-control143"]["control_group"]["factor"]["review"]["identity"]
            ["approvals"] = approvals;
        let name = format!("past-control-approvals-{index}");
        write(
            &mut state,
            &root,
            at(100, 0),
            &name,
            json!({"policy":policy.to_string()}),
        )
        .unwrap();
        assert!(state.policies[""][&name].rules.is_empty());
        state.policies[""][&name].validate_expiration().unwrap();
    }
    for approvals in [
        Value::Null,
        json!(0),
        json!(-1),
        json!(true),
        json!(1.0),
        json!("1.0"),
        json!("1e3"),
        json!(""),
    ] {
        let mut policy = expired_control_policy143();
        policy["path"]["secret/past-control143"]["control_group"]["factor"]["review"]["identity"]
            ["approvals"] = approvals;
        let before = serde_json::to_vec(&state).unwrap();
        assert!(
            write(
                &mut state,
                &root,
                at(100, 0),
                "invalid-past-approvals",
                json!({"policy":policy.to_string()})
            )
            .is_err()
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    }
}

#[test]
fn expiration143_past_control_json_list_stage_distinguishes_bool_null_and_hcl() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    let mut policy = expired_control_policy143();
    let factor = &mut policy["path"]["secret/past-control143"]["control_group"]["factor"]["review"];
    factor["controlled_capabilities"] = json!([true, "read", false]);
    factor["identity"]["group_names"] = json!([false, "reviewers", true]);
    write(
        &mut state,
        &root,
        at(100, 0),
        "past-json-bools",
        json!({"policy":policy.to_string()}),
    )
    .unwrap();
    state.policies[""]["past-json-bools"]
        .validate_expiration()
        .unwrap();
    assert!(state.policies[""]["past-json-bools"].rules.is_empty());

    for (operations, groups) in [
        (json!([true]), json!(["reviewers"])),
        (json!(["read", null]), json!(["reviewers"])),
        (json!(["read"]), json!([true])),
        (json!(["read"]), json!(["reviewers", null])),
        (json!(["read"]), json!([1.0])),
        (json!(["read", true, "sudo"]), json!(["reviewers"])),
    ] {
        let mut policy = expired_control_policy143();
        let factor =
            &mut policy["path"]["secret/past-control143"]["control_group"]["factor"]["review"];
        factor["controlled_capabilities"] = operations;
        factor["identity"]["group_names"] = groups;
        let before = serde_json::to_vec(&state).unwrap();
        assert!(
            write(
                &mut state,
                &root,
                at(100, 0),
                "invalid-past-list",
                json!({"policy":policy.to_string()})
            )
            .is_err()
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    }
    let hcl = r#"path "secret/past-control143" {
        expiration = "99"
        control_group = { ttl = "10s" factor "review" {
            controlled_capabilities = [true, "read"]
            identity = { group_names = ["reviewers"] approvals = 1 }
        } }
    }"#;
    let before = serde_json::to_vec(&state).unwrap();
    assert!(
        write(
            &mut state,
            &root,
            at(100, 0),
            "invalid-past-hcl-list",
            json!({"policy":hcl})
        )
        .is_err()
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
}

#[test]
fn expiration143_ttl_seconds_match_go_split_float_boundary() {
    // Both inputs are valid signed Go durations. The first distinguishes
    // Duration.Seconds from integer division; the second distinguishes its
    // split whole/remainder calculation from a whole-nanosecond float cast.
    for (ttl, seconds) in [
        ("9223372035.999999999s", 9_223_372_036_i64),
        ("9007199.999999999s", 9_007_199_i64),
        ("1.999999999s", 1_i64),
    ] {
        let deadline = prepare(None, &json!({"ttl":ttl}), false, at(100, 125_000_000))
            .unwrap()
            .unwrap();
        assert_eq!(deadline.instant(), (100 + seconds, 125_000_000), "{ttl}");
    }
}
