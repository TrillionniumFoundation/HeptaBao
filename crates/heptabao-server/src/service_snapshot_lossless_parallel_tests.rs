//! Actual File/floor-2 export refusal after worker-side AEAD observation.
//! These tests retain the original transport, Actor and ambient deadline.
use super::*;

fn exact_fresh_export(service: &mut Service, root: &str) -> TestResult {
    let bytes = downloaded(service, root, "secret")?;
    let mut value = crate::engines::decode_lossless_json(&bytes)?;
    assert_eq!(value, bundle()?);
    erase_json(&mut value);
    Ok(())
}

#[test]
fn lossless_export_parallel_worker_rechecks_original_actor_after_actual_aead() -> TestResult {
    let (_files, mut service, _key, root) = initialized()?;
    let mut issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root,
        json!({"policies":["root"],"no_default_policy":true,"ttl":"6s"}),
    );
    assert_eq!(issued.status, 200);
    let actor = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("expiring original root Actor")?
            .to_owned(),
    );
    erase_json(&mut issued.body);
    let pause =
        crate::service::native_blob_source::pause_after_payload_open_once(Duration::from_secs(7))?;
    let (response, bytes) = transfer(&mut service, &actor, "", json!({"mount":"secret"}))?;
    assert!(pause.fired(), "must reach the actual worker payload AEAD");
    // The worker refuses the expired original Actor. The owning request's
    // recheck retains its precise authorization denial instead of relabeling
    // it as a transport deadline or malformed export. Deadline-only failure
    // remains the separate strict 503 case below.
    assert_eq!(response.status, 403);
    assert_eq!(response.body["errors"], json!(["permission denied"]));
    assert!(response.body.get("data").is_none() && response.body.get("auth").is_none());
    assert!(response.unwrapped_json.is_none() && response.consistency_index.is_none());
    assert!(bytes.is_none());
    assert!(service.pending_snapshot_transfer.is_none());
    assert!(service.native_request_binding.is_none());
    drop(pause);
    // A new request uses the separately live original administrative Actor.
    // No expired plan, reader or prefetched bytes can authorize this request.
    exact_fresh_export(&mut service, &root)?;
    Ok(())
}

#[test]
fn lossless_export_parallel_worker_keeps_shorter_original_scope_after_actual_aead() -> TestResult {
    let (_files, mut service, _key, root) = initialized()?;
    let pause =
        crate::service::native_blob_source::pause_after_payload_open_once(Duration::from_secs(3))?;
    let (response, bytes) = {
        let _original = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(2),
        );
        // transfer retains its original 15s transport deadline; the same 2s
        // enclosing scope must remain effective on every scoped worker.
        transfer(&mut service, &root, "", json!({"mount":"secret"}))?
    };
    assert!(pause.fired(), "must reach the actual worker payload AEAD");
    assert_eq!(response.status, 503);
    assert!(bytes.is_none());
    assert!(service.pending_snapshot_transfer.is_none());
    assert!(service.native_request_binding.is_none());
    drop(pause);
    // The expired enclosing scope is already gone. This is a fresh request.
    exact_fresh_export(&mut service, &root)?;
    Ok(())
}
