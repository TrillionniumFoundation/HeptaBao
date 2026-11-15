//! Genuine namespace/key/token producers exercise the closed private writer.
use super::*;
use crate::service::tests::{Root, bootstrap_unmounted};
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NS: &str = "closed143";
const SOURCE: &str = r#"path "records/value" { capabilities = ["read"] }"#;
const REQUIRED: &str =
    r#"path "records/value" { capabilities = ["read"] required_parameters = ["needed"] }"#;

fn clock(seconds: u64) -> TestResult<RequestClock> {
    Ok(RequestClock::anchored(Duration::ZERO, Instant::now())
        .map_err(|_| "original closed-policy clock")?
        .with_timestamp_floor(Timestamp::whole(seconds).map_err(|_| "fixture timestamp")?))
}

fn call(
    service: &mut Service,
    seconds: u64,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: Value,
) -> TestResult<Response> {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    let _explicit = external_pki::PublicationClockScope::explicit();
    Ok(service.handle_request_clock(
        ServiceRequest::new(method, path, namespace, token, body),
        seconds,
        true,
        Some(clock(seconds)?),
    ))
}

struct Fixture {
    root: Root,
    service: Service,
    share: String,
    admin: String,
    bearer: String,
}

fn fixture(uses: u64, required: bool) -> TestResult<Fixture> {
    let root = Root::new();
    let mut service = root.service()?;
    let (share, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "sys/namespaces/closed143",
            "",
            &admin,
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
            "sys/mounts/records",
            NS,
            &admin,
            json!({"type":"kv","options":{"version":"1"}})
        )?
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "records/value",
            NS,
            &admin,
            json!({"marker":"private-namespace-policy143-only"})
        )?
        .status,
        204
    );
    for name in ["observed143", "unobserved143"] {
        assert_eq!(
            call(
                &mut service,
                100,
                "POST",
                &format!("sys/policies/acl/{name}"),
                NS,
                &admin,
                json!({"policy":SOURCE,"expiration":101,"cas_required":true,"cas":-1})
            )?
            .status,
            204
        );
    }
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "sys/policies/acl/required143",
            NS,
            &admin,
            json!({"policy":if required { REQUIRED } else { SOURCE }})
        )?
        .status,
        204
    );
    let policies = if required {
        json!(["observed143", "required143"])
    } else {
        json!(["observed143"])
    };
    let issued = call(
        &mut service,
        100,
        "POST",
        "auth/token/create",
        NS,
        &admin,
        json!({"policies":policies,"no_default_policy":true,"num_uses":uses,"ttl":600}),
    )?;
    assert_eq!(issued.status, 200);
    let bearer = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("real namespace token")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "sys/namespaces/closed143/seal",
            "",
            &admin,
            json!({})
        )?
        .status,
        204
    );
    let state = service.state.as_ref().ok_or("closed source")?;
    assert!(state.namespaces.inherited_owner(NS).is_some());
    assert!(!state.namespace_is_sealed(NS));
    assert!(state.auth.namespace_is_empty(NS));
    assert!(state.engines.namespace_is_empty(NS));
    assert!(!service.namespace_runtime.is_loaded(NS));
    Ok(Fixture {
        root,
        service,
        share,
        admin,
        bearer,
    })
}

fn keys(response: &Response) -> TestResult<Vec<String>> {
    assert_eq!(response.status, 200);
    response.body["data"]["keys"]
        .as_array()
        .ok_or("policy list")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "policy name".into())
        })
        .collect()
}

#[test]
fn expiration143_closed_private_denial_retires_only_observed_policy_after_use_and_restart()
-> TestResult {
    let Fixture {
        root,
        mut service,
        share,
        admin,
        bearer,
    } = fixture(3, true)?;
    let before = service
        .state
        .as_ref()
        .ok_or("source")?
        .namespaces
        .inherited_owner(NS)
        .cloned()
        .ok_or("source owner")?;
    // The live Q policy supplies a real parameter denial. The closed slice's
    // existing authorize method evaluates parameters/wrapping; it does not
    // dispatch an ordinary capability-protected resource.
    assert_eq!(
        call(
            &mut service,
            102,
            "GET",
            "records/value",
            NS,
            &bearer,
            json!({})
        )?
        .status,
        403
    );
    let closed = service.state.as_ref().ok_or("closed candidate")?;
    let after = closed
        .namespaces
        .inherited_owner(NS)
        .ok_or("candidate owner")?;
    assert!(after != &before);
    assert_eq!(after.seal_frontier(), before.seal_frontier());
    assert!(after.parent() == before.parent());
    assert!(!service.namespace_runtime.is_loaded(NS));
    assert!(closed.auth.namespace_is_empty(NS));
    assert!(closed.engines.namespace_is_empty(NS));
    let encoded = owner_store::serialize_owner(closed)?;
    assert!(
        !encoded
            .windows(SOURCE.len())
            .any(|bytes| bytes == SOURCE.as_bytes())
    );
    assert!(
        !encoded
            .windows(b"private-namespace-policy143-only".len())
            .any(|bytes| bytes == b"private-namespace-policy143-only")
    );
    drop(service);

    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            103,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":share})
        )?
        .status,
        200
    );
    let names = keys(&call(
        &mut service,
        103,
        "LIST",
        "sys/policies/acl",
        NS,
        &admin,
        json!({}),
    )?)?;
    assert!(!names.contains(&"observed143".to_owned()));
    assert!(names.contains(&"unobserved143".to_owned()));
    assert!(names.contains(&"required143".to_owned()));
    let token = call(
        &mut service,
        103,
        "POST",
        "auth/token/lookup",
        NS,
        &admin,
        json!({"token":bearer}),
    )?;
    assert_eq!(token.status, 200);
    assert_eq!(token.body["data"]["num_uses"], 2);
    assert_eq!(
        call(
            &mut service,
            103,
            "POST",
            "sys/policies/acl/observed143",
            NS,
            &admin,
            json!({"policy":SOURCE,"cas":-1})
        )?
        .status,
        204
    );
    let replacement = call(
        &mut service,
        103,
        "GET",
        "sys/policies/acl/observed143",
        NS,
        &admin,
        json!({}),
    )?;
    assert_eq!(replacement.status, 200);
    assert_eq!(replacement.body["data"]["version"], 1);
    let value = call(
        &mut service,
        103,
        "GET",
        "records/value",
        NS,
        &admin,
        json!({}),
    )?;
    assert_eq!(value.status, 200);
    assert_eq!(
        value.body["data"]["marker"],
        "private-namespace-policy143-only"
    );
    Ok(())
}

#[test]
fn expiration143_closed_private_unloaded_read_retires_without_loading_resources() -> TestResult {
    let Fixture {
        root,
        mut service,
        share,
        admin,
        bearer,
    } = fixture(0, false)?;
    let before = service
        .state
        .as_ref()
        .ok_or("source")?
        .namespaces
        .inherited_owner(NS)
        .cloned()
        .ok_or("source owner")?;
    assert_eq!(
        call(
            &mut service,
            100,
            "GET",
            "records/value",
            NS,
            &bearer,
            json!({})
        )?
        .status,
        404
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("live source")?
            .namespaces
            .inherited_owner(NS)
            == Some(&before)
    );
    assert_eq!(
        call(
            &mut service,
            102,
            "GET",
            "records/value",
            NS,
            &bearer,
            json!({})
        )?
        .status,
        404
    );
    let state = service.state.as_ref().ok_or("retired source")?;
    assert!(state.namespaces.inherited_owner(NS) != Some(&before));
    assert!(state.auth.namespace_is_empty(NS) && state.engines.namespace_is_empty(NS));
    assert!(!service.namespace_runtime.is_loaded(NS));
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            103,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":share})
        )?
        .status,
        200
    );
    let names = keys(&call(
        &mut service,
        103,
        "LIST",
        "sys/policies/acl",
        NS,
        &admin,
        json!({}),
    )?)?;
    assert!(!names.contains(&"observed143".to_owned()));
    assert!(names.contains(&"unobserved143".to_owned()));
    Ok(())
}

#[test]
fn expiration143_closed_policy_retirement_requires_separate_consumption_and_exact_source()
-> TestResult {
    let Fixture {
        root: _root,
        mut service,
        share,
        admin,
        bearer,
    } = fixture(1, false)?;
    // Keep a genuine sibling loaded so State::clone/Serialize's protected
    // publication view participates in both exact-source negative controls.
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/namespaces/live143",
            "",
            &admin,
            json!({})
        )?
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/namespaces/live143/seal",
            "",
            &admin,
            json!({})
        )?
        .status,
        204
    );
    assert_eq!(
        call(&mut service, 102, "POST", "sys/seal", "", &admin, json!({}))?.status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":share})
        )?
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/namespaces/closed143/seal",
            "",
            &admin,
            json!({})
        )?
        .status,
        204
    );
    assert!(service.namespace_runtime.is_loaded("live143"));
    assert!(
        service
            .state
            .as_ref()
            .ok_or("loaded sibling")?
            .namespace_protected
            .is_some()
    );
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    let original_clock = RequestClock::anchored(Duration::from_secs(102), Instant::now())?;
    let time = AuthorityTime::Precise(original_clock.observed_at()?);
    let current = service.state.as_ref().ok_or("source")?;
    let mut admission = service
        .namespace_runtime
        .closed_auth_attempt_observed(
            current,
            NS,
            service.barrier_key.as_ref().ok_or("original root key")?,
            &bearer,
            time,
            None,
        )
        .map_err(|_| "real private admission")?;
    admission
        .bind_request_clock(Some(original_clock))
        .map_err(|_| "original clock")?;
    assert!(admission.needs_commit());
    assert!(
        admission
            .policy_retirement(&service.namespace_runtime, current, NS, time)
            .is_err()
    );
    let mut consumed = admission
        .candidate(&service.namespace_runtime)
        .map_err(|_| "original use candidate")?;
    consumed.schema = consumed.writer_schema();
    service
        .commit_state(&mut consumed)
        .map_err(|_| "separate original use commit")?;
    service.state = Some(consumed);

    let current = service.state.as_ref().ok_or("post-use source")?;
    let plan = admission
        .policy_retirement(&service.namespace_runtime, current, NS, time)
        .map_err(|_| "policy plan from actual post-use descriptor")?
        .ok_or("nonempty policy plan")?;
    let mut candidate = plan.candidate();
    plan.check_candidate(current, &candidate, time)
        .map_err(|_| "fixed candidate")?;
    let mut unrelated = plan.candidate();
    assert!(unrelated.namespace_protected.is_some());
    unrelated.replay_epoch = unrelated
        .replay_epoch
        .checked_add(1)
        .ok_or("epoch overflow")?;
    assert!(plan.check_candidate(current, &unrelated, time).is_err());
    let mut changed = current.clone();
    changed.namespace_protected = current.namespace_protected.clone();
    changed.replay_epoch = changed
        .replay_epoch
        .checked_add(1)
        .ok_or("epoch overflow")?;
    assert!(plan.check_candidate(&changed, &candidate, time).is_err());
    service
        .commit_state(&mut candidate)
        .map_err(|_| "separate policy commit")?;
    service.state = Some(candidate);
    let committed = service.state.as_ref().ok_or("committed")?;
    plan.check_committed(committed, time)
        .map_err(|_| "actual committed policy owner")?;
    assert!(plan.check_source(committed, time).is_err());
    assert!(!service.namespace_runtime.is_loaded(NS));
    let exhausted = service
        .namespace_runtime
        .closed_auth_attempt_observed(
            committed,
            NS,
            service.barrier_key.as_ref().ok_or("original root key")?,
            &bearer,
            time,
            None,
        )
        .map_err(|_| "reopen the same final-use owner")?;
    match exhausted.actor() {
        Ok(_) => return Err("final-use actor was admitted twice".into()),
        Err(response) => assert_eq!(response.status, 403),
    }
    Ok(())
}

#[test]
fn expiration143_closed_policy_retirement_keeps_original_deadline() -> TestResult {
    let Fixture {
        root: _root,
        service,
        share: _,
        admin: _,
        bearer,
    } = fixture(0, false)?;
    let original_deadline = Instant::now() + Duration::from_secs(30);
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(original_deadline);
    let original_clock = RequestClock::anchored(Duration::from_secs(102), Instant::now())?;
    let time = AuthorityTime::Precise(original_clock.observed_at()?);
    let current = service.state.as_ref().ok_or("source")?;
    let before = state_digest(current).map_err(|_| "original state")?;
    let mut admission = service
        .namespace_runtime
        .closed_auth_attempt_observed(
            current,
            NS,
            service.barrier_key.as_ref().ok_or("original root key")?,
            &bearer,
            time,
            None,
        )
        .map_err(|_| "real private admission")?;
    admission
        .bind_request_clock(Some(original_clock))
        .map_err(|_| "original clock")?;
    assert!(!admission.needs_commit());
    let plan = admission
        .policy_retirement(&service.namespace_runtime, current, NS, time)
        .map_err(|_| "original policy plan")?
        .ok_or("nonempty policy plan")?;
    assert_eq!(plan.deadline, Some(original_deadline));
    let candidate = plan.candidate();
    plan.check_candidate(current, &candidate, time)
        .map_err(|_| "initially valid owner")?;
    // The narrower caller scope is already expired. The plan cannot refresh
    // the request budget or install a replacement actor to publish its delta.
    {
        let _expired = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() - Duration::from_secs(1),
        );
        assert!(plan.check_candidate(current, &candidate, time).is_err());
        assert!(plan.check_committed(current, time).is_err());
        assert_eq!(plan.deadline, Some(original_deadline));
    }
    assert_eq!(
        state_digest(current).map_err(|_| "unchanged source")?,
        before
    );
    assert!(
        plan.check_candidate(
            current,
            &candidate,
            AuthorityTime::Precise(Timestamp::whole(100000)?)
        )
        .is_err()
    );
    Ok(())
}

fn record_graph_edits_are_bound(loaded_sibling: bool) -> TestResult {
    let Fixture {
        root,
        mut service,
        share,
        admin,
        bearer,
    } = fixture(3, false)?;
    const SIBLING: &str = "recordview143";
    const PATH: &str = "bindingrecords143/value";
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/namespaces/recordview143",
            "",
            &admin,
            json!({})
        )?
        .status,
        200
    );
    for namespace in ["", SIBLING] {
        assert_eq!(
            call(
                &mut service,
                102,
                "POST",
                "sys/mounts/bindingrecords143",
                namespace,
                &admin,
                json!({"type":"kv","options":{"version":"1"}})
            )?
            .status,
            204
        );
        assert_eq!(
            call(
                &mut service,
                102,
                "POST",
                PATH,
                namespace,
                &admin,
                json!({"marker":"original graph"})
            )?
            .status,
            204
        );
    }
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/namespaces/recordview143/seal",
            "",
            &admin,
            json!({})
        )?
        .status,
        204
    );
    assert_eq!(
        call(&mut service, 102, "POST", "sys/seal", "", &admin, json!({}))?.status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":share})
        )?
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            102,
            "POST",
            "sys/namespaces/closed143/seal",
            "",
            &admin,
            json!({})
        )?
        .status,
        204
    );
    assert!(service.namespace_runtime.is_loaded(SIBLING));
    assert!(service.record_root.is_some());

    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    let original_clock = RequestClock::anchored(Duration::from_secs(102), Instant::now())?;
    let time = AuthorityTime::Precise(original_clock.observed_at()?);
    let current = service.state.as_ref().ok_or("record source")?;
    let mut admission = service
        .namespace_runtime
        .closed_auth_attempt_observed(
            current,
            NS,
            service.barrier_key.as_ref().ok_or("original root key")?,
            &bearer,
            time,
            None,
        )
        .map_err(|_| "actual closed admission")?;
    admission
        .bind_request_clock(Some(original_clock))
        .map_err(|_| "original clock")?;
    assert!(admission.needs_commit());
    let mut consumed = admission
        .candidate(&service.namespace_runtime)
        .map_err(|_| "separate use candidate")?;
    consumed.schema = consumed.writer_schema();
    service
        .commit_state(&mut consumed)
        .map_err(|_| "actual separate use commit")?;
    service.state = Some(consumed);

    let current = service.state.as_ref().ok_or("record post-use source")?;
    let plan = admission
        .policy_retirement(&service.namespace_runtime, current, NS, time)
        .map_err(|_| "actual fixed policy plan")?
        .ok_or("nonempty policy plan")?;
    let mut candidate = plan.candidate();
    let namespace = if loaded_sibling { SIBLING } else { "" };
    let mutate = |state: &mut State| -> TestResult {
        let response = state
            .engines
            .handle(
                namespace,
                "PUT",
                PATH,
                &json!({"marker":"unrelated graph"}),
                102,
            )?
            .ok_or("real record mutation")?;
        assert_eq!(response.status, 204);
        assert!(response.mutated);
        let read = state
            .engines
            .handle(namespace, "GET", PATH, &json!({}), 102)?
            .ok_or("mutated record read")?;
        assert_eq!(read.body["data"]["marker"], "unrelated graph");
        Ok(())
    };

    let mut changed_candidate = plan.candidate();
    let old_views = changed_candidate
        .engines
        .record_view_binding(|| true)?
        .ok_or("original record views")?;
    let old_protected_root = changed_candidate
        .engines
        .record_root()
        .ok_or("original protected root")?;
    mutate(&mut changed_candidate)?;
    let new_views = changed_candidate
        .engines
        .record_view_binding(|| true)?
        .ok_or("changed record views")?;
    let new_protected_root = changed_candidate
        .engines
        .record_root()
        .ok_or("changed protected root")?;
    assert_ne!(old_views, new_views);
    if loaded_sibling {
        assert!(
            old_protected_root == new_protected_root,
            "loaded edit leaves the protected root unchanged"
        );
    } else {
        assert!(
            old_protected_root != new_protected_root,
            "root edit changes the publication root"
        );
    }
    // This is an actual logical data change which the previous two Serialize
    // digests could not distinguish, because EngineState skips its record runtime.
    assert_eq!(
        state_digest(&changed_candidate).map_err(|_| "changed metadata")?,
        state_digest(&candidate).map_err(|_| "fixed metadata")?
    );
    assert!(
        plan.check_candidate(current, &changed_candidate, time)
            .is_err()
    );

    let mut changed_source = current.clone();
    changed_source.namespace_protected = current.namespace_protected.clone();
    mutate(&mut changed_source)?;
    assert_eq!(
        state_digest(&changed_source).map_err(|_| "changed source metadata")?,
        state_digest(current).map_err(|_| "original source metadata")?
    );
    assert!(
        plan.check_candidate(&changed_source, &candidate, time)
            .is_err()
    );

    // A retained canonical view is bound independently of the logical one.
    let mut changed_protected = plan.candidate();
    let logical_before = changed_protected.engines.record_view_binding(|| true)?;
    let protected = Arc::make_mut(
        changed_protected
            .namespace_protected
            .as_mut()
            .ok_or("prepared protected view")?,
    );
    let response = protected
        .engines
        .handle(
            "",
            "PUT",
            PATH,
            &json!({"marker":"different canonical graph"}),
            102,
        )?
        .ok_or("actual canonical record mutation")?;
    assert_eq!(response.status, 204);
    assert!(response.mutated);
    assert!(changed_protected.engines.record_view_binding(|| true)? == logical_before);
    assert_eq!(
        state_digest(&changed_protected).map_err(|_| "changed canonical metadata")?,
        state_digest(&candidate).map_err(|_| "candidate metadata")?
    );
    assert!(
        plan.check_candidate(current, &changed_protected, time)
            .is_err()
    );

    plan.check_candidate(current, &candidate, time)
        .map_err(|_| "unchanged fixed candidate")?;
    service
        .commit_state(&mut candidate)
        .map_err(|_| "actual fixed policy commit")?;
    service.state = Some(candidate);
    let committed = service.state.as_ref().ok_or("published fixed owner")?;
    assert!(committed.engines.record_objects()?.is_empty());
    plan.check_committed(committed, time)
        .map_err(|_| "postcommit cache cleanup preserves binding")?;
    drop(plan);
    drop(admission);
    drop(_deadline);
    drop(service);

    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            103,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":share})
        )?
        .status,
        200
    );
    for namespace in ["", SIBLING] {
        let read = call(&mut service, 103, "GET", PATH, namespace, &admin, json!({}))?;
        assert_eq!(read.status, 200);
        assert_eq!(read.body["data"]["marker"], "original graph");
    }
    assert_eq!(
        call(
            &mut service,
            103,
            "GET",
            "sys/policies/acl/observed143",
            NS,
            &admin,
            json!({})
        )?
        .status,
        404
    );
    Ok(())
}

#[test]
fn expiration143_closed_policy_retirement_binds_root_record_graph_before_and_after_commit()
-> TestResult {
    record_graph_edits_are_bound(false)
}

#[test]
fn expiration143_closed_policy_retirement_binds_loaded_sibling_record_graph_before_and_after_commit()
-> TestResult {
    record_graph_edits_are_bound(true)
}
