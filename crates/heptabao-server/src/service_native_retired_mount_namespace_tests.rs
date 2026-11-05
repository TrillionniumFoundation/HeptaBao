//! Disabled engine metadata retires only with the enclosing namespace owner.
//! The original 2.7.1 observer and original failed Rust assertion stay unchanged.
use super::*;

#[test]
fn formal_retired_kv1_namespace_recreation_fences_old_scope_and_preserves_siblings() -> TestResult {
    let mut f = Fixture::start(true, false)?;
    create(&mut f, "", "team")?;
    create(&mut f, "", "sibling")?;
    create(&mut f, "team", "child")?;
    for namespace in ["team/child", "sibling"] {
        expect(
            admin(
                &mut f,
                namespace,
                "POST",
                "sys/mounts/reused",
                json!({
                    "type": "kv", "options": {"version": "1"},
                    "config": {"default_lease_ttl": "-1s", "max_lease_ttl": "60s"}
                }),
            ),
            204,
            "mount exact child KV1",
        )?;
        expect(
            admin(
                &mut f,
                namespace,
                "POST",
                "reused/value",
                json!({"scope": namespace}),
            ),
            204,
            "write exact child KV1",
        )?;
    }
    let old_namespace = expect(
        admin(&mut f, "team", "GET", "sys/namespaces/child", json!({})),
        200,
        "original namespace public identity",
    )?;
    let old_id = old_namespace.body["data"]["id"]
        .as_str()
        .ok_or("original namespace id")?
        .to_owned();
    let state = f.service.state.as_ref().ok_or("source state")?;
    let old_scope =
        crate::service::namespaces::native_plain::PlainNamespaceScope::capture(state, "team/child")
            .map_err(|_| "capture old native namespace scope")?;
    let old_incarnation = state
        .namespaces
        .incarnation("team/child")
        .ok_or("child incarnation")?;
    let schema_floor = state.schema;
    let reader_floor = f.root()?.reader_floor.minimum_state_schema;

    expect(
        admin(&mut f, "team", "DELETE", "sys/namespaces/child", json!({})),
        409,
        "live child mount still prevents empty retirement",
    )?;
    old_scope
        .check(f.service.state.as_ref().ok_or("unmodified state")?)
        .map_err(|_| "live namespace scope after denied retirement")?;
    let old_read = expect(
        admin(&mut f, "team/child", "GET", "reused/value", json!({})),
        200,
        "denied retirement leaves old value",
    )?;
    assert_eq!(old_read.body["data"], json!({"scope": "team/child"}));

    expect(
        admin(
            &mut f,
            "team/child",
            "DELETE",
            "sys/mounts/reused",
            json!({}),
        ),
        204,
        "disable exact child mount",
    )?;
    let state = f.service.state.as_ref().ok_or("disabled state")?;
    assert!(
        !state.engines.namespace_is_empty("team/child"),
        "a retained mount epoch must never become pristine metadata"
    );
    let record_root = state.engines.record_root();
    expect(
        admin(&mut f, "team", "DELETE", "sys/namespaces/child", json!({})),
        200,
        "retire disabled namespace under the actual catalog transaction",
    )?;
    let state = f.service.state.as_ref().ok_or("retired state")?;
    assert!(!state.namespaces.contains("team/child"));
    assert_eq!(
        state
            .auth
            .namespace_batch_registry()
            .ok_or("retired paired ledger")?
            .current_incarnation("team/child"),
        None
    );
    assert!(
        state
            .auth
            .namespace_batch_registry()
            .ok_or("paired ledger")?
            .knows_retired_incarnation("team/child", old_incarnation)
    );
    assert!(old_scope.check(state).is_err());
    assert!(!state.engines.known_namespaces().contains("team/child"));
    assert_eq!(
        state.engines.record_root(),
        record_root,
        "retirement must not rewrite root or sibling record payloads"
    );
    assert!(state.schema >= schema_floor);
    assert!(f.root()?.reader_floor.minimum_state_schema >= reader_floor);
    state
        .validate_format()
        .map_err(|_| "retired state format")?;
    state
        .validate_native_flat_retirement_state(None)
        .map_err(|_| "retired native namespace ledger")?;

    let mut f = f.restart()?;
    let state = f.service.state.as_ref().ok_or("cold retired state")?;
    assert!(old_scope.check(state).is_err());
    let cold_ledger = state
        .auth
        .namespace_batch_registry()
        .ok_or("cold paired ledger")?;
    assert_eq!(cold_ledger.current_incarnation("team/child"), None);
    assert!(cold_ledger.knows_retired_incarnation("team/child", old_incarnation));
    let sibling = expect(
        admin(&mut f, "sibling", "GET", "reused/value", json!({})),
        200,
        "cold sibling value preserved",
    )?;
    assert_eq!(sibling.body["data"], json!({"scope": "sibling"}));
    assert_eq!(sibling.body["lease_duration"], -1);

    create(&mut f, "team", "child")?;
    let state = f.service.state.as_ref().ok_or("new child state")?;
    assert_eq!(
        state.namespaces.incarnation("team/child"),
        Some(old_incarnation + 1)
    );
    assert!(
        old_scope.check(state).is_err(),
        "same path creation must not revive the captured owner"
    );
    let new_namespace = expect(
        admin(&mut f, "team", "GET", "sys/namespaces/child", json!({})),
        200,
        "recreated namespace public identity",
    )?;
    assert_ne!(
        new_namespace.body["data"]["id"]
            .as_str()
            .ok_or("recreated namespace id")?,
        old_id
    );
    expect(
        admin(
            &mut f,
            "team/child",
            "POST",
            "sys/mounts/reused",
            json!({"type": "kv", "options": {"version": "1"}}),
        ),
        204,
        "recreate same mount under a new namespace owner",
    )?;
    let absent = expect(
        admin(&mut f, "team/child", "GET", "reused/value", json!({})),
        404,
        "old value cannot reappear in new namespace",
    )?;
    assert!(absent.body.get("data").is_none_or(Value::is_null));
    expect(
        admin(
            &mut f,
            "team/child",
            "POST",
            "reused/value",
            json!({"scope": "new-owner"}),
        ),
        204,
        "write new namespace value",
    )?;
    let mut f = f.restart()?;
    assert!(
        old_scope
            .check(f.service.state.as_ref().ok_or("cold new child")?)
            .is_err()
    );
    for (namespace, expected) in [("team/child", "new-owner"), ("sibling", "sibling")] {
        let response = expect(
            admin(&mut f, namespace, "GET", "reused/value", json!({})),
            200,
            "cold exact namespace readback",
        )?;
        assert_eq!(response.body["data"], json!({"scope": expected}));
    }
    f.sentinel()
}
