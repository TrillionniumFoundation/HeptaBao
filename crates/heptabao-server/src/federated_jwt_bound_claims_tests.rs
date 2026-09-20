#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use serde_json::json;

fn bound(kind: NativeJwtBoundClaimsType, expected: Value, actual: Value) -> bool {
    NativeJwtBoundClaims {
        kind,
        claims: BTreeMap::from([("value".into(), expected)]),
    }
    .matches(&BTreeMap::from([("value".into(), actual)]))
}

#[test]
fn exact_claim_alternatives_preserve_types_and_scalar_number_coercion() {
    // These expectations are observed with both static ES256 and remote JWKS
    // against the pinned OpenBao 2.6.2 binary, not inferred from this matcher.
    for (expected, actual, accepted) in [
        (json!("alpha"), json!("alpha"), true),
        (json!("alpha"), json!("Alpha"), false),
        (json!(true), json!(true), true),
        (json!(true), json!("true"), false),
        (json!(42), json!(42), true),
        (json!(42), json!(42.9), true),
        (json!(-42), json!(-42.9), true),
        (json!(42.9), json!(42.9), false),
        (json!(42.0), json!(42), false),
        (serde_json::from_str("42e0").unwrap(), json!(42), false),
        (serde_json::from_str("-0").unwrap(), json!(0), false),
        (json!(0), json!(-0.0), true),
        (json!(42), json!("42"), false),
        (json!(42), json!([42]), false),
        (json!([42]), json!(42), true),
        (json!([42]), json!([42]), false),
        (
            json!(9_007_199_254_740_992u64),
            json!(9_007_199_254_740_993u64),
            true,
        ),
        (
            json!(9_007_199_254_740_993u64),
            json!(9_007_199_254_740_993u64),
            false,
        ),
        (Value::Null, Value::Null, false),
        (json!([null]), json!([null]), true),
        (json!([null, "alpha"]), json!([false, "alpha"]), true),
        (json!("alpha"), json!(["other", "alpha"]), true),
        (json!(["other", "alpha"]), json!("alpha"), true),
        (json!([]), json!([]), false),
        (json!({"key":"alpha"}), json!({"key":"alpha"}), false),
    ] {
        assert_eq!(
            bound(
                NativeJwtBoundClaimsType::String,
                expected.clone(),
                actual.clone()
            ),
            accepted,
            "expected={expected}; actual={actual}"
        );
    }
    // Do not emulate architecture-dependent float-to-int overflow or panic on
    // equality between nested objects inside arrays.
    assert!(!bound(
        NativeJwtBoundClaimsType::String,
        json!(i64::MIN),
        json!(1e100)
    ));
    assert!(!bound(
        NativeJwtBoundClaimsType::String,
        json!([{}]),
        json!([{}])
    ));
}

#[test]
fn glob_has_only_star_and_checks_typed_alternatives_in_order() {
    for (expected, actual, accepted) in [
        (json!("*"), json!(""), true),
        (json!(""), json!(""), true),
        (json!("repo/*/main"), json!("repo/team/sub/main"), true),
        (json!("a?c"), json!("abc"), false),
        (json!("a[bc]"), json!("ab"), false),
        (json!("a?c"), json!("a?c"), true),
        (json!("a*b*c"), json!("a---b---c"), true),
        (json!("a*"), json!([42, "alpha"]), true),
        (json!("a*a"), json!("a"), false),
        (json!("*组*"), json!("主组成员"), true),
        (json!("a\\*"), json!("abc"), false),
        (json!([42, "a*"]), json!("alpha"), false),
        (json!(["a*", 42]), json!("alpha"), true),
    ] {
        assert_eq!(
            bound(
                NativeJwtBoundClaimsType::Glob,
                expected.clone(),
                actual.clone()
            ),
            accepted,
            "expected={expected}; actual={actual}"
        );
    }
}

#[test]
fn pointers_follow_pinned_pointerstructure_escaping_and_base_zero_indices() {
    let claims: BTreeMap<String, Value> = serde_json::from_value(json!({
        "a/b":{"~name":["zero","one","two","three","four","five","six","seven","eight"]},
        "invalid~2":"literal", "":"empty-key", "literal/name":"direct"
    }))
    .unwrap();
    for (selector, expected, accepted) in [
        ("/a~1b/~0name/1", "one", true),
        ("/a~1b/~0name/+1", "one", true),
        ("/a~1b/~0name/010", "eight", true),
        ("/a~1b/~0name/08", "eight", false),
        ("/a~1b/~0name/0x1", "one", true),
        ("/a~1b/~0name/", "zero", true),
        ("/invalid~2", "literal", true),
        ("/", "empty-key", true),
        ("", "empty-key", true),
        ("literal/name", "direct", true),
        ("/absent", "alpha", false),
    ] {
        let bounds = NativeJwtBoundClaims {
            kind: NativeJwtBoundClaimsType::String,
            claims: BTreeMap::from([(selector.into(), json!(expected))]),
        };
        assert_eq!(bounds.matches(&claims), accepted, "{selector}");
    }
    for (index, expected) in [
        ("0b1", Some(1)),
        ("0o10", Some(8)),
        ("0x_1", Some(1)),
        ("0_1", Some(1)),
        ("1_0", Some(10)),
        ("-0", Some(0)),
        ("-1", None),
        ("0x__1", None),
        ("1_", None),
        ("+", None),
        (" 1", None),
        ("18446744073709551616", None),
    ] {
        assert_eq!(pointer_index(index), expected, "{index}");
    }
}

#[test]
fn every_bound_claim_is_required_and_empty_configuration_has_no_extra_predicate() {
    let mut bounds = NativeJwtBoundClaims {
        kind: NativeJwtBoundClaimsType::String,
        claims: BTreeMap::new(),
    };
    let claims = BTreeMap::from([("a".into(), json!(true)), ("b".into(), json!("yes"))]);
    assert!(bounds.matches(&claims));
    bounds.claims.insert("a".into(), json!(true));
    bounds.claims.insert("b".into(), json!("yes"));
    assert!(bounds.matches(&claims));
    bounds.claims.insert("c".into(), json!(true));
    assert!(!bounds.matches(&claims));
}
