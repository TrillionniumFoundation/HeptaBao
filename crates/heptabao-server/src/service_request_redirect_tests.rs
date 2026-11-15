//! Local routing provenance uses real Raft role/configuration and mandatory audit.
use super::*;
use crate::ha::snapshot_test_support::Cluster;
use crate::http::no_forward_tests::project_response;
use crate::request_metadata::{CheckedLocalRedirectTarget, DataFrame, Scope};
use crate::service::tests::{Root, bootstrap};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn no_forward271_capsule_keeps_origin_codec_audit_and_original_deadline() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let unknown = Cluster::uninitialized(&root.path.join("unknown-raft"), &cluster_id)?;
    assert!(
        unknown
            .configure_api_address(1, "http://untrusted.example")
            .is_err()
    );
    unknown.configure_api_address(1, "https://configured.example:8200")?;
    service.ha = Some(Arc::clone(&unknown.processes[0]));
    assert_eq!(
        service
            .configured_standby_destination()
            .err()
            .ok_or("unknown leader must fail")?
            .status,
        503
    );
    service.ha = None;
    drop(unknown);
    let cluster = Cluster::new(&root.path.join("active-raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    assert_eq!(
        service
            .configured_standby_destination()
            .err()
            .ok_or("missing origin must fail")?
            .status,
        503
    );
    cluster.configure_api_address(1, "https://configured.example:8200/")?;
    let origin = service
        .configured_standby_destination()
        .map_err(|_| "actual origin")?
        .ok_or("actual standby")?;
    assert_eq!(origin.as_str(), "https://configured.example:8200");

    let original = [0x61; 16];
    let _ingress = crate::auth::IngressReplyScope::listener(&original);
    let body = json!({});
    let target = "/v1/secret/data/probe?encoded=a%2Fb+z&next=x%26y";
    let mut frame = DataFrame::default();
    frame.headers.insert(
        crate::request_metadata::NO_FORWARD_HEADER.to_owned(),
        vec!["1".to_owned()],
    );
    frame.bind_local_redirect(
        CheckedLocalRedirectTarget::checked(target)?,
        ("GET", "secret/data/probe", "", &body),
        &original,
    )?;
    let profile = frame
        .local_redirect
        .as_ref()
        .ok_or("bound profile")?
        .clone();
    let _metadata = Scope::enter(Some(frame), "GET", "secret/data/probe", "", &body)?;
    let make = |deadline| {
        let mut response = Response::error(307, "local routing fixture");
        response.response_headers =
            ResponseHeaders::local_redirect(origin.clone(), profile.clone(), deadline);
        response
    };

    {
        let deadline = Instant::now() + Duration::from_secs(5);
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        let response = make(deadline);
        assert!(
            response
                .response_headers
                .local_redirect_matches_current(307)
        );
        assert!(serde_json::to_vec(&response.response_headers).is_err());
        assert!(serde_json::to_vec(&response.response_headers.copy_for_forward()).is_err());
        let wire = project_response(response)?;
        assert_eq!(wire.status, 307);
        assert_eq!(
            wire.header("Location"),
            &[format!("https://configured.example:8200{target}")]
        );
        assert!(wire.body.is_empty());

        let mut quota = make(deadline);
        quota
            .response_headers
            .merge_quota(ResponseHeaders::retry_after_seconds(7))
            .map_err(|()| "original numeric quota merge")?;
        assert!(quota.response_headers.local_redirect_matches_current(307));
        assert!(serde_json::to_vec(&quota.response_headers).is_err());
        let wire = project_response(quota)?;
        assert_eq!(wire.status, 307);
        assert_eq!(
            wire.header("Location"),
            &[format!("https://configured.example:8200{target}")]
        );
        assert_eq!(wire.header("Retry-After"), &["7".to_owned()]);
        assert!(wire.body.is_empty());

        let mut ordinary = Response::error(307, "ordinary SDK data remains ordinary");
        ordinary.response_headers = ResponseHeaders::from_sdk(
            Some(&json!({"Location":["https://sdk.example/untrusted"]})),
            &["Location".to_owned()],
        )
        .map_err(|()| "SDK header")?;
        assert!(!ordinary.response_headers.has_local_redirect());
        let serialized = serde_json::to_vec(&ordinary.response_headers)?;
        let decoded: ResponseHeaders = serde_json::from_slice(&serialized)?;
        assert!(!decoded.has_local_redirect());
        let wire = project_response(ordinary)?;
        assert_eq!(wire.status, 307);
        assert!(
            !wire.body.is_empty(),
            "plain SDK Location/status never selects the empty native redirect writer"
        );
        assert_eq!(
            wire.json()?["errors"][0],
            "ordinary SDK data remains ordinary"
        );

        let mut veto = make(deadline);
        veto.status = 503;
        let wire = project_response(veto)?;
        assert_eq!(wire.status, 503);
        assert!(wire.header("Location").is_empty());
        let preexpired = make(Instant::now() - Duration::from_millis(1));
        assert!(
            !preexpired
                .response_headers
                .local_redirect_matches_current(307)
        );
        let wire = project_response(preexpired)?;
        assert_eq!(wire.status, 503);
        assert!(wire.header("Location").is_empty());
        {
            let _other = crate::auth::IngressReplyScope::listener(&[0x62; 16]);
            let wire = project_response(make(deadline))?;
            assert_eq!(wire.status, 503);
            assert!(wire.header("Location").is_empty());
        }
    }

    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let identity = service
        .current_state_identity()
        .map_err(|_| "state identity")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let fingerprint = service.request_fingerprint("GET", "secret/data/probe", "", &admin);
    {
        let deadline = Instant::now() + Duration::from_secs(5);
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        let before = service.audit_sequence;
        service.audit_event("request", &fingerprint, now, None)?;
        let delivered = service.audit_completed_response_with_receipt(
            &fingerprint,
            now,
            None,
            make(deadline),
            || {
                // Expire only after the real response audit, retaining the one
                // captured deadline rather than granting a replacement budget.
                while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                    std::thread::sleep(remaining.min(Duration::from_millis(10)));
                }
            },
        );
        assert_eq!(service.audit_sequence, before + 2);
        assert_eq!(
            delivered.status, 307,
            "actual response audit preceded the injected expiry"
        );
        let wire = project_response(delivered)?;
        assert_eq!(wire.status, 503);
        assert!(wire.header("Location").is_empty());
    }
    {
        let deadline = Instant::now() + Duration::from_secs(5);
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        service.audit_event("request", &fingerprint, now, None)?;
        service.audit_capacity = service.audit.metadata()?.len();
        let before = service.audit_sequence;
        let delivered = service.audit_completed_response(&fingerprint, now, None, make(deadline));
        assert_eq!(
            service.audit_sequence, before,
            "the actual failing response append never becomes an audit event"
        );
        assert_eq!(delivered.status, 503);
        assert!(!delivered.response_headers.has_local_redirect());
        let wire = project_response(delivered)?;
        assert_eq!(wire.status, 503);
        assert!(wire.header("Location").is_empty());
        assert!(service.recovery_required);
    }
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "state identity")?
            == identity
    );
    Ok(())
}
