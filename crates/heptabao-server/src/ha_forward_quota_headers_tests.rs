use super::*;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn quota() -> Result<crate::service::ResponseHeaders, &'static str> {
    crate::service::ResponseHeaders::from_sdk(
        Some(&json!({
            "X-RateLimit-Limit":["10"], "X-RateLimit-Remaining":["9"], "X-RateLimit-Reset":["59"],
        })),
        &[
            "X-RateLimit-Limit".into(),
            "X-RateLimit-Remaining".into(),
            "X-RateLimit-Reset".into(),
        ],
    )
    .map_err(|()| "quota metadata")
}

fn begin() -> CompletionScope {
    let scope = CompletionScope::enter(
        Some([1; 32]),
        b"request",
        Instant::now() + std::time::Duration::from_secs(60),
        "cluster",
        1,
        true,
    );
    // This unit fixture isolates the metadata edge. Real publication still
    // requires the existing authenticated scope, clock, audit and owner gates.
    CAPTURE.with(|slot| {
        if let Some(capture) = slot.borrow_mut().as_mut() {
            capture.audited = true;
        }
    });
    scope
}

fn bound(response: &crate::Response) -> bool {
    CAPTURE.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|capture| logical_headers_remain_empty(capture, response))
    })
}

#[test]
fn quota_transform_retains_the_exact_original_and_final_response_digests() -> TestResult {
    let _scope = begin();
    let mut response = crate::Response::error(204, "fixture");
    response.body = serde_json::Value::Null;
    let original = response_digest(&response)?;
    merge_quota_headers(&mut response, quota()?).map_err(|()| "merge")?;
    let completed = response_digest(&response)?;
    assert_ne!(original, completed);
    assert!(bound(&response));
    assert!(CAPTURE.with(|slot| {
        slot.borrow()
            .as_ref()
            .and_then(|capture| capture.quota_response_headers.as_ref())
            .is_some_and(|headers| headers.original == original && headers.completed == completed)
    }));
    response.body = json!({"unexpected":"body"});
    assert!(!bound(&response));
    response.body = serde_json::Value::Null;
    assert!(bound(&response));
    response.response_headers = crate::service::ResponseHeaders::from_sdk(
        Some(&json!({"X-RateLimit-Limit":["100"]})),
        &["X-RateLimit-Limit".into()],
    )
    .map_err(|()| "tamper fixture")?;
    assert!(!bound(&response));
    Ok(())
}

#[test]
fn status_or_header_shape_alone_never_establishes_a_transform_and_audit_veto_revokes_it()
-> TestResult {
    let _scope = begin();
    let mut response = crate::Response::error(204, "fixture");
    response.body = serde_json::Value::Null;
    response.response_headers = quota()?;
    assert!(!bound(&response));
    merge_quota_headers(&mut response, quota()?).map_err(|()| "preexisting merge")?;
    assert!(!bound(&response));
    response.response_headers.clear();
    merge_quota_headers(&mut response, quota()?).map_err(|()| "original merge")?;
    assert!(bound(&response));
    audited(None);
    assert!(!bound(&response));
    Ok(())
}
