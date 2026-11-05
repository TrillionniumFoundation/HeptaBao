use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn seeded() -> Result<Kv2> {
    let mut engine = Kv2::default();
    engine.handle(
        "POST",
        "data/item",
        &json!({"data":{"value":"synthetic"}}),
        1_700_000_000,
    )?;
    engine.handle(
        "POST",
        "data/item",
        &json!({"data":{"value":"synthetic-next"}}),
        1_700_000_001,
    )?;
    Ok(engine)
}

#[test]
fn string_versions_delete_undelete_destroy_survive_reopen() -> TestResult {
    let mut engine = seeded()?;
    let response = engine.handle(
        "PUT",
        "delete/item",
        &json!({"versions":["2"]}),
        1_700_000_002,
    )?;
    assert_eq!(response.status, 204);
    assert!(response.mutated);
    let deleted = engine.handle("GET", "data/item", &json!({}), 1_700_000_003)?;
    assert_eq!(deleted.status, 404);
    assert_eq!(deleted.body["data"]["metadata"]["destroyed"], false);
    let bytes = serde_json::to_vec(&engine)?;
    let mut reopened: Kv2 = serde_json::from_slice(&bytes)?;
    reopened.handle(
        "PUT",
        "undelete/item",
        &json!({"versions":["2"]}),
        1_700_000_004,
    )?;
    assert_eq!(
        reopened
            .handle("GET", "data/item", &json!({}), 1_700_000_005)?
            .status,
        200
    );
    reopened.handle(
        "PUT",
        "destroy/item",
        &json!({"versions":["2"]}),
        1_700_000_006,
    )?;
    let destroyed = reopened.handle("GET", "data/item", &json!({}), 1_700_000_007)?;
    assert_eq!(destroyed.status, 404);
    assert_eq!(destroyed.body["data"]["metadata"]["destroyed"], true);
    reopened.handle(
        "PUT",
        "undelete/item",
        &json!({"versions":["2"]}),
        1_700_000_008,
    )?;
    assert_eq!(
        reopened
            .handle("GET", "data/item", &json!({}), 1_700_000_009)?
            .status,
        404
    );
    Ok(())
}

#[test]
fn public_version_types_select_the_same_version() -> TestResult {
    for version in [
        json!(1),
        json!("1"),
        json!("01"),
        json!("+1"),
        json!(true),
        json!("0x1"),
        json!("0b1"),
        json!("0o1"),
        json!("+0x1"),
        json!("0X1"),
        json!("0x_1"),
        json!("0_1"),
        json!("0b_1"),
    ] {
        let mut engine = seeded()?;
        let response = engine.handle(
            "POST",
            "delete/item",
            &json!({"versions":[version]}),
            1_700_000_002,
        )?;
        assert_eq!(response.status, 204);
        assert!(response.mutated);
        assert_eq!(
            engine
                .handle("GET", "data/item", &json!({"version":1}), 1_700_000_003)?
                .status,
            404
        );
        assert_eq!(
            engine
                .handle("GET", "data/item", &json!({"version":2}), 1_700_000_003)?
                .status,
            200
        );
    }
    Ok(())
}

#[test]
fn public_nonpositive_and_null_versions_are_noops() -> TestResult {
    for version in [
        json!(0),
        json!("0"),
        json!(-1),
        json!("-1"),
        Value::Null,
        json!(false),
        json!(""),
        json!("-0"),
        json!("-9223372036854775808"),
        json!("-0x1"),
        json!("-0b1"),
        json!("-0o1"),
    ] {
        for operation in ["delete", "undelete", "destroy"] {
            let mut engine = seeded()?;
            let before = serde_json::to_vec(&engine)?;
            let response = engine.handle(
                "PUT",
                &format!("{operation}/item"),
                &json!({"versions":[version]}),
                1_700_000_002,
            )?;
            assert_eq!(response.status, 204);
            assert!(!response.mutated);
            assert!(serde_json::to_vec(&engine)? == before);
        }
    }
    Ok(())
}

#[test]
fn invalid_version_arrays_reject_before_any_mutation() -> TestResult {
    let cases = [
        json!([]),
        json!([1, "invalid"]),
        json!([" 1 "]),
        json!(["1.0"]),
        json!(["1e0"]),
        json!([1.0]),
        json!([1.5]),
        json!(["9223372036854775808"]),
        json!(["18446744073709551615"]),
        json!([18446744073709551615_u64]),
        json!(["08"]),
        json!(["0__1"]),
        json!(["0x1_"]),
        json!(["_1"]),
        json!(["0x"]),
        json!(["+"]),
        json!(["١"]),
    ];
    for versions in cases {
        for operation in ["delete", "undelete", "destroy"] {
            let mut engine = seeded()?;
            let before = serde_json::to_vec(&engine)?;
            let result = engine.handle(
                "PUT",
                &format!("{operation}/item"),
                &json!({"versions":versions}),
                1_700_000_002,
            );
            assert_eq!(result.err().map(|error| error.status), Some(400));
            assert!(serde_json::to_vec(&engine)? == before);
        }
    }
    Ok(())
}

#[test]
fn mixed_integer_and_string_versions_are_atomic_and_idempotent() -> TestResult {
    let mut engine = seeded()?;
    let body = json!({"versions":["1",2,"2"]});
    let response = engine.handle("PUT", "delete/item", &body, 1_700_000_002)?;
    assert_eq!(response.status, 204);
    assert!(response.mutated);
    let after = serde_json::to_vec(&engine)?;
    let second = engine.handle("PUT", "delete/item", &body, 1_700_000_003)?;
    assert!(!second.mutated);
    assert!(serde_json::to_vec(&engine)? == after);
    for version in [1, 2] {
        assert_eq!(
            engine
                .handle(
                    "GET",
                    "data/item",
                    &json!({"version":version}),
                    1_700_000_004
                )?
                .status,
            404
        );
    }
    Ok(())
}

#[test]
fn absent_versions_do_not_create_an_entry() -> TestResult {
    let mut engine = Kv2::default();
    let before = serde_json::to_vec(&engine)?;
    for operation in ["delete", "undelete", "destroy"] {
        let response = engine.handle(
            "PUT",
            &format!("{operation}/missing"),
            &json!({"versions":["1"]}),
            1_700_000_002,
        )?;
        assert_eq!(response.status, 204);
        assert!(!response.mutated);
        assert!(serde_json::to_vec(&engine)? == before);
    }
    Ok(())
}

#[test]
fn observed_octal_and_decimal_underscore_select_distinct_versions() -> TestResult {
    for (text, expected) in [("010", 8), ("1_0", 10)] {
        let mut engine = seeded()?;
        for ordinal in 3..=10 {
            engine.handle(
                "POST",
                "data/item",
                &json!({"data":{"value":"synthetic"}}),
                1_700_000_000 + ordinal,
            )?;
        }
        engine.handle(
            "PUT",
            "delete/item",
            &json!({"versions":[text]}),
            1_700_000_020,
        )?;
        for version in [8, 10] {
            let response = engine.handle(
                "GET",
                "data/item",
                &json!({"version":version}),
                1_700_000_021,
            )?;
            assert_eq!(response.status, if version == expected { 404 } else { 200 });
        }
    }
    Ok(())
}
