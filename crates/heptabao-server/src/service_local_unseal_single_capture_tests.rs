use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::{Root, bootstrap_unmounted};
use std::cell::Cell;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    service: Service,
    share: Zeroizing<String>,
    token: Zeroizing<String>,
    root: Root,
}

fn request(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    service.handle_request(ServiceRequest::new(method, path, "", token, body))
}

fn fixture() -> TestResult<Fixture> {
    let root = Root::new();
    let mut service = root.service()?;
    let (share, token) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        request(&mut service, "POST", "sys/init/ack", &token, json!({})).status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/secret",
            &token,
            json!({"type":"kv", "options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "secret/data/cold-single-proof",
            &token,
            json!({"data":{"value":"cold-single-synthetic-sentinel"}})
        )
        .status,
        200
    );
    drop(service);
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(&mut service, "POST", "sys/unseal", "", json!({"key":share})).status,
        200
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/storage/native-v6/activate",
            &token,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        service
            .native_root
            .as_ref()
            .ok_or("actual native root")?
            .reader_floor
            .native_kv2_format,
        2
    );
    drop(service);
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    Ok(Fixture {
        root,
        service,
        share: Zeroizing::new(share),
        token: Zeroizing::new(token),
    })
}

fn original_clock() -> TestResult<RequestClock> {
    RequestClock::anchored(
        SystemTime::now().duration_since(UNIX_EPOCH)?,
        Instant::now(),
    )
    .map_err(|_| "original clock".into())
}

fn capture(f: &mut Fixture) -> TestResult<(Response, LocalUnsealOwner)> {
    let clock = original_clock()?;
    let deadline = crate::request_deadline::current();
    let response = f.service.unseal(&json!({"key":f.share.as_str()}));
    assert_eq!(response.status, 200);
    assert!(f.service.ha.is_none());
    let owner = LocalUnsealOwner::capture(&mut f.service, Some(clock), deadline)
        .map_err(|_| "actual native single owner")?;
    assert!(matches!(
        owner.native.as_ref(),
        Some(super::super::native_v6_reader::NativeProof::Single(_))
    ));
    assert!(owner.logical.is_empty());
    Ok((response, owner))
}

fn capture_syntax(f: &mut Fixture) -> TestResult<(Response, LocalUnsealOwner)> {
    assert!(f.service.state.is_none());
    let clock = original_clock()?;
    let deadline = crate::request_deadline::current();
    let response = f.service.unseal(&json!({"key":f.share.as_str()}));
    assert_eq!(response.status, 200);
    let owner = LocalUnsealOwner::capture_with_syntax(&mut f.service, Some(clock), deadline, true)
        .map_err(|_| "actual request syntax capture")?;
    let Some(super::super::native_v6_reader::NativeProof::Single(proof)) = &owner.native else {
        return Err("actual single native proof".into());
    };
    assert!(proof.syntax_hint_scopes() > 0);
    Ok((response, owner))
}

#[test]
fn native_file_syntax_hint_keeps_actual_metadata_reopens_on_both_audit_sides() -> TestResult {
    for (after_audit, corrupt) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut f = fixture()?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let (response, owner) = capture_syntax(&mut f)?;
        let leaf = selected_kv2_index_file(&f)?;
        let moved = leaf.with_extension("syntax-missing-source");
        let original = Zeroizing::new(fs::read(&leaf)?);
        assert!(!original.is_empty());
        let mut damaged = Zeroizing::new(original.to_vec());
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        let apply = || -> std::io::Result<()> {
            if corrupt {
                fs::write(&leaf, damaged.as_slice())
            } else {
                fs::rename(&leaf, &moved)
            }
        };
        if !after_audit {
            apply()?;
        }
        let changed = Cell::new(!after_audit);
        let denied = f.service.complete_local_unseal_response_with(
            LocalUnsealCompletion::Ready(Box::new(owner)),
            response,
            "syntax-index-negative",
            100,
            |_| {
                if after_audit {
                    changed.set(apply().is_ok());
                }
            },
        );
        assert!(changed.get());
        assert_eq!(denied.status, 503);
        assert!(denied.response_headers.is_empty());
        assert!(denied.consistency_index.is_none());
        if corrupt {
            fs::write(&leaf, original.as_slice())?;
        } else {
            fs::rename(&moved, &leaf)?;
        }
        drop(f.service);
        f.service = f.root.service()?;
        f.service
            .configure_native_v6_storage(NativeStorageProfile::File)?;
        assert_eq!(
            request(
                &mut f.service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":f.share.as_str()})
            )
            .status,
            200
        );
        assert_eq!(
            request(
                &mut f.service,
                "GET",
                "secret/data/cold-single-proof",
                f.token.as_str(),
                json!({})
            )
            .body["data"]["data"]["value"],
            "cold-single-synthetic-sentinel"
        );
    }
    Ok(())
}

#[test]
fn native_file_syntax_hint_keeps_current_bindings_and_original_deadline_refusal() -> TestResult {
    for changed in [
        "barrier",
        "publication",
        "cursor",
        "retained-source",
        "audit",
    ] {
        let mut f = fixture()?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let (response, owner) = capture_syntax(&mut f)?;
        match changed {
            "barrier" => f.service.barrier_key.as_mut().ok_or("key")?[0] ^= 1,
            "audit" => f.service.audit_capacity = f.service.audit.metadata()?.len(),
            _ => {
                let resource = match changed {
                    "publication" => "state",
                    "cursor" => super::super::native_v6_reader::ACTIVE_CURSOR_RESOURCE,
                    "retained-source" => {
                        super::super::native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE
                    }
                    _ => return Err("unexpected syntax fault".into()),
                };
                f.service
                    .durable
                    .as_mut()
                    .ok_or("durable")?
                    .put(PutRequest::new(
                        "syntax-negative",
                        "system",
                        "independent-syntax-binding",
                        resource,
                        crypto::digest(b"syntax-negative"),
                        Secret::new(b"syntax-negative".to_vec())?,
                    )?)?;
            }
        }
        let denied = f.service.complete_local_unseal_response(
            LocalUnsealCompletion::Ready(Box::new(owner)),
            response,
            "syntax-binding-negative",
            100,
        );
        assert_eq!(denied.status, 503, "{changed}");
    }
    let mut f = fixture()?;
    let end = Instant::now() + Duration::from_secs(1);
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(end);
    let (response, owner) = capture_syntax(&mut f)?;
    let denied = f.service.complete_local_unseal_response_with(
        LocalUnsealCompletion::Ready(Box::new(owner)),
        response,
        "syntax-expired-after-audit",
        100,
        |_| {
            std::thread::sleep(
                end.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            )
        },
    );
    assert_eq!(denied.status, 503);
    assert_eq!(
        denied.body["errors"][0],
        "local unseal original deadline elapsed"
    );
    Ok(())
}

#[test]
fn native_file_spent_syntax_owner_cannot_follow_nonce_and_fresh_cold_scope_recovers() -> TestResult
{
    let mut f = fixture()?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let (response, owner) = capture_syntax(&mut f)?;
    f.service.unseal_nonce.push('x');
    let denied = f.service.complete_local_unseal_response(
        LocalUnsealCompletion::Ready(Box::new(owner)),
        response,
        "syntax-nonce-negative",
        100,
    );
    assert_eq!(denied.status, 503);
    drop(f.service);
    f.service = f.root.service()?;
    f.service
        .configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(
            &mut f.service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":f.share.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        request(
            &mut f.service,
            "GET",
            "secret/data/cold-single-proof",
            f.token.as_str(),
            json!({})
        )
        .body["data"]["data"]["value"],
        "cold-single-synthetic-sentinel"
    );
    Ok(())
}

#[test]
fn native_file_normal_syntax_route_double_cold_keeps_exact_value_and_repeated_unseal() -> TestResult
{
    let mut f = fixture()?;
    for cold in 0..2 {
        assert_eq!(
            request(
                &mut f.service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":f.share.as_str()})
            )
            .status,
            200
        );
        assert_eq!(
            request(
                &mut f.service,
                "GET",
                "secret/data/cold-single-proof",
                f.token.as_str(),
                json!({})
            )
            .body["data"]["data"]["value"],
            "cold-single-synthetic-sentinel"
        );
        assert_eq!(
            request(
                &mut f.service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":f.share.as_str()})
            )
            .status,
            200
        );
        if cold == 0 {
            drop(f.service);
            f.service = f.root.service()?;
            f.service
                .configure_native_v6_storage(NativeStorageProfile::File)?;
        }
    }
    Ok(())
}

// Select a real referenced owner-metadata leaf from this fresh synthetic
// fixture's authenticated locator. A missing leaf cannot be hidden by an
// unchanged warm state, root digest or durable generation.
fn selected_metadata_file(f: &Fixture) -> TestResult<PathBuf> {
    let root = f.service.native_root.as_ref().ok_or("actual native root")?;
    let owner = root.owners.first().ok_or("actual owner metadata")?;
    let reference = owner.owner.chunks.first().ok_or("actual owner chunk")?;
    let resource = v6_records::native_resource(
        &crate::state_record_root_v6::ObjectDomain::Owner(owner.domain),
        reference,
    );
    let slot = f
        .service
        .durable
        .as_ref()
        .ok_or("actual durable")?
        .get("system", &resource)?
        .ok_or("actual metadata locator")?;
    if slot.expose().len() != 72 || !slot.expose().starts_with(b"HBV6BLOBREF0001\0") {
        return Err("actual metadata must use an immutable locator".into());
    }
    let address = hex(&slot.expose()[32..64]);
    assert_eq!(address, hex(reference.id.bytes()));
    let ciphertext_bytes = u32::from_be_bytes(slot.expose()[64..68].try_into()?) as u64;
    assert!(ciphertext_bytes > 0);
    let mut pending = vec![f.root.path.join("data")];
    let mut selected = Vec::new();
    let mut observed = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            observed += 1;
            if observed > 4096 || entry.file_type()?.is_symlink() {
                return Err("fresh synthetic metadata fixture shape".into());
            }
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else if entry.file_type()?.is_file()
                && entry.file_name().to_string_lossy().contains(&address)
                && entry.metadata()?.len() == ciphertext_bytes
            {
                selected.push(entry.path());
            }
        }
    }
    if selected.len() != 1 {
        return Err("exactly one actual selected metadata leaf is required".into());
    }
    Ok(selected.remove(0))
}

#[test]
fn native_file_captured_single_unseal_keeps_cold_read_and_mandatory_audit() -> TestResult {
    let mut f = fixture()?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let (response, owner) = capture(&mut f)?;
    let generation = f.service.durable.as_ref().ok_or("durable")?.generation();
    let audit_before = f.service.audit.metadata()?.len();
    let after_audit = Cell::new(false);
    let response = f.service.complete_local_unseal_response_with(
        LocalUnsealCompletion::Ready(Box::new(owner)),
        response,
        "native-single-capture-positive",
        100,
        |_| after_audit.set(true),
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["sealed"], false);
    assert!(response.response_headers.is_empty());
    assert!(response.consistency_index.is_none());
    assert!(after_audit.get());
    assert!(f.service.audit.metadata()?.len() > audit_before);
    assert_eq!(
        f.service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(
        request(
            &mut f.service,
            "GET",
            "secret/data/cold-single-proof",
            &f.token,
            json!({})
        )
        .body["data"]["data"]["value"],
        "cold-single-synthetic-sentinel"
    );
    Ok(())
}

#[test]
fn native_file_captured_single_unseal_reopens_metadata_before_and_after_audit() -> TestResult {
    for after_audit in [false, true] {
        let mut f = fixture()?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let (response, owner) = capture(&mut f)?;
        let leaf = selected_metadata_file(&f)?;
        let moved = leaf.with_extension("single-capture-negative");
        assert!(!moved.exists());
        let generation = f.service.durable.as_ref().ok_or("durable")?.generation();
        let identity = f.service.current_state_identity().map_err(|_| "identity")?;
        if !after_audit {
            fs::rename(&leaf, &moved)?;
            owner
                .check_instance(&f.service)
                .map_err(|_| "warm instance remains exact")?;
        }
        let fault_applied = Cell::new(!after_audit);
        let denied = f.service.complete_local_unseal_response_with(
            LocalUnsealCompletion::Ready(Box::new(owner)),
            response,
            "native-single-metadata-negative",
            100,
            |_| {
                if after_audit {
                    fault_applied.set(fs::rename(&leaf, &moved).is_ok());
                }
            },
        );
        assert!(fault_applied.get());
        assert_eq!(denied.status, 503);
        assert!(denied.response_headers.is_empty());
        assert!(denied.consistency_index.is_none());
        assert_eq!(
            f.service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert_eq!(
            f.service.current_state_identity().map_err(|_| "identity")?,
            identity
        );
        assert!(f.service.barrier_key.is_some());
    }
    Ok(())
}

#[test]
fn native_file_captured_single_unseal_rejects_changed_bindings_audit_and_clock() -> TestResult {
    for changed in [
        "nonce",
        "barrier",
        "publication",
        "cursor",
        "retained-source",
        "audit",
    ] {
        let mut f = fixture()?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let (response, owner) = capture(&mut f)?;
        match changed {
            "nonce" => f.service.unseal_nonce.push('x'),
            "barrier" => f.service.barrier_key.as_mut().ok_or("key")?[0] ^= 1,
            "audit" => f.service.audit_capacity = f.service.audit.metadata()?.len(),
            _ => {
                let resource = match changed {
                    "publication" => "state",
                    "cursor" => super::super::native_v6_reader::ACTIVE_CURSOR_RESOURCE,
                    "retained-source" => {
                        super::super::native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE
                    }
                    _ => return Err("unexpected local test case".into()),
                };
                f.service
                    .durable
                    .as_mut()
                    .ok_or("durable")?
                    .put(PutRequest::new(
                        "single-capture-negative",
                        "system",
                        "independent-changed-binding",
                        resource,
                        crypto::digest(b"single-capture-negative"),
                        Secret::new(b"single-capture-negative".to_vec())?,
                    )?)?;
            }
        }
        let denied = f.service.complete_local_unseal_response(
            LocalUnsealCompletion::Ready(Box::new(owner)),
            response,
            "native-single-binding-negative",
            100,
        );
        assert_eq!(denied.status, 503, "{changed}");
        assert!(f.service.barrier_key.is_some());
    }
    let mut f = fixture()?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    assert_eq!(
        f.service.unseal(&json!({"key":f.share.as_str()})).status,
        200
    );
    assert!(
        LocalUnsealOwner::capture(&mut f.service, None, crate::request_deadline::current())
            .is_err()
    );
    let end = Instant::now() + Duration::from_secs(1);
    let _original = crate::request_deadline::RequestDeadlineScope::enter(end);
    let (response, owner) = capture(&mut f)?;
    let denied = f.service.complete_local_unseal_response_with(
        LocalUnsealCompletion::Ready(Box::new(owner)),
        response,
        "native-single-expired-after-audit",
        100,
        |_| {
            std::thread::sleep(
                end.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            )
        },
    );
    assert_eq!(denied.status, 503);
    assert_eq!(
        denied.body["errors"][0],
        "local unseal original deadline elapsed"
    );
    assert!(f.service.barrier_key.is_some());
    Ok(())
}

// Select the exact immutable KV2 index object whose parsed cells seed syntax.
fn selected_kv2_index_file(f: &Fixture) -> TestResult<PathBuf> {
    let root = f.service.native_root.as_ref().ok_or("actual native root")?;
    let graph = root.kv2.first().ok_or("actual KV2 graph")?;
    let reference = graph
        .root
        .reference
        .as_ref()
        .ok_or("actual KV2 index root")?;
    let resource = v6_records::native_resource(
        &crate::state_record_root_v6::ObjectDomain::Kv2(graph.scope.clone()),
        reference,
    );
    let slot = f
        .service
        .durable
        .as_ref()
        .ok_or("actual durable")?
        .get("system", &resource)?
        .ok_or("actual metadata locator")?;
    if slot.expose().len() != 72 || !slot.expose().starts_with(b"HBV6BLOBREF0001\0") {
        return Err("actual metadata must use an immutable locator".into());
    }
    let address = hex(&slot.expose()[32..64]);
    assert_eq!(address, hex(reference.id.bytes()));
    let ciphertext_bytes = u32::from_be_bytes(slot.expose()[64..68].try_into()?) as u64;
    assert!(ciphertext_bytes > 0);
    let mut pending = vec![f.root.path.join("data")];
    let mut selected = Vec::new();
    let mut observed = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            observed += 1;
            if observed > 4096 || entry.file_type()?.is_symlink() {
                return Err("fresh synthetic metadata fixture shape".into());
            }
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else if entry.file_type()?.is_file()
                && entry.file_name().to_string_lossy().contains(&address)
                && entry.metadata()?.len() == ciphertext_bytes
            {
                selected.push(entry.path());
            }
        }
    }
    if selected.len() != 1 {
        return Err("exactly one actual selected metadata leaf is required".into());
    }
    Ok(selected.remove(0))
}

fn pending_cold_handoff(
    f: &mut Fixture,
) -> TestResult<(Response, super::super::native_v6_reader::ColdUnsealHandoff)> {
    let mut handoff = None;
    let response = f
        .service
        .unseal_with_cold_handoff(&json!({"key":f.share.as_str()}), Some(&mut handoff));
    assert_eq!(response.status, 200);
    Ok((response, handoff.ok_or("eligible actual cold handoff")?))
}

fn capture_cold_handoff(f: &mut Fixture) -> TestResult<(Response, LocalUnsealOwner)> {
    let clock = original_clock()?;
    let (response, mut handoff) = pending_cold_handoff(f)?;
    handoff
        .check_before_policy(&mut f.service)
        .map_err(|_| "policy guard")?;
    f.service
        .complete_default_policy_activation(Some(clock))
        .map_err(|_| "stable policy")?;
    let owner = LocalUnsealOwner::capture_with_handoff(
        &mut f.service,
        Some(clock),
        crate::request_deadline::current(),
        true,
        Some(handoff),
    )
    .map_err(|_| "affine capture")?;
    assert!(
        owner
            .native
            .as_ref()
            .is_some_and(|proof| proof.is_cold_handoff())
    );
    Ok((response, owner))
}

fn assert_cold_handoff_fenced(f: &mut Fixture) {
    assert!(f.service.recovery_required);
    assert!(f.service.state.is_none());
    assert!(f.service.state_digest.is_none());
    assert!(f.service.durable.is_none());
    assert!(f.service.barrier_key.is_none());
    assert!(f.service.record_root.is_none());
    assert!(f.service.native_root.is_none());
    assert_eq!(
        request(
            &mut f.service,
            "GET",
            "secret/data/cold-single-proof",
            f.token.as_str(),
            json!({})
        )
        .status,
        503
    );
}

#[test]
fn cold_handoff_reuses_only_adjacent_capture_and_keeps_two_actual_audit_full_reads() -> TestResult {
    let mut f = fixture()?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let before = super::super::native_v6_reader::full_cold_loads_for_test();
    let (response, owner) = capture_cold_handoff(&mut f)?;
    assert_eq!(
        super::super::native_v6_reader::full_cold_loads_for_test() - before,
        1
    );
    let response = f.service.complete_local_unseal_response_with(
        LocalUnsealCompletion::Ready(Box::new(owner)),
        response,
        "cold-affine-success",
        100,
        |_| {},
    );
    assert_eq!(response.status, 200);
    assert_eq!(
        super::super::native_v6_reader::full_cold_loads_for_test() - before,
        3
    );
    assert_eq!(
        request(
            &mut f.service,
            "GET",
            "secret/data/cold-single-proof",
            f.token.as_str(),
            json!({})
        )
        .body["data"]["data"]["value"],
        "cold-single-synthetic-sentinel"
    );
    Ok(())
}

#[test]
fn cold_handoff_fresh_audit_sides_reject_actual_leaf_rename_and_bitflip_then_fresh_scope_recovers()
-> TestResult {
    for (after_audit, corrupt) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut f = fixture()?;
        {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                Instant::now() + Duration::from_secs(15),
            );
            let (response, owner) = capture_cold_handoff(&mut f)?;
            let leaf = selected_kv2_index_file(&f)?;
            let moved = leaf.with_extension("affine-missing-source");
            let original = Zeroizing::new(fs::read(&leaf)?);
            let mut damaged = Zeroizing::new(original.to_vec());
            let last = damaged.len() - 1;
            damaged[last] ^= 1;
            let apply = || -> std::io::Result<()> {
                if corrupt {
                    fs::write(&leaf, damaged.as_slice())
                } else {
                    fs::rename(&leaf, &moved)
                }
            };
            if !after_audit {
                apply()?;
            }
            let changed = Cell::new(!after_audit);
            let denied = f.service.complete_local_unseal_response_with(
                LocalUnsealCompletion::Ready(Box::new(owner)),
                response,
                "cold-affine-audit-damage",
                100,
                |_| {
                    if after_audit {
                        changed.set(apply().is_ok());
                    }
                },
            );
            assert!(changed.get());
            assert_eq!(denied.status, 503);
            assert_cold_handoff_fenced(&mut f);
            if corrupt {
                fs::write(&leaf, original.as_slice())?;
            } else {
                fs::rename(&moved, &leaf)?;
            }
        }
        drop(f.service);
        f.service = f.root.service()?;
        f.service
            .configure_native_v6_storage(NativeStorageProfile::File)?;
        assert_eq!(
            request(
                &mut f.service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":f.share.as_str()})
            )
            .status,
            200
        );
        assert_eq!(
            request(
                &mut f.service,
                "GET",
                "secret/data/cold-single-proof",
                f.token.as_str(),
                json!({})
            )
            .body["data"]["data"]["value"],
            "cold-single-synthetic-sentinel"
        );
    }
    Ok(())
}

#[test]
fn cold_handoff_nonce_attempts_deadline_key_and_epoch_nochange_cannot_revive_authority()
-> TestResult {
    for changed in [
        "nonce-aba",
        "failed-entropy",
        "repeated-rotation",
        "exhaustion",
        "key",
        "deadline",
        "epoch-nochange",
        "epoch-install-aba",
    ] {
        let mut f = fixture()?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let (_, mut handoff) = pending_cold_handoff(&mut f)?;
        let old = Zeroizing::new(f.service.unseal_nonce.clone());
        let mut expired = None;
        match changed {
            "nonce-aba" => {
                f.service.rotate_unseal_nonce().map_err(|_| "rotate")?;
                f.service.unseal_nonce = old.to_string();
            }
            "failed-entropy" => {
                assert!(
                    f.service
                        .rotate_unseal_nonce_with(|| Err("injected entropy failure"))
                        .is_err()
                );
                assert_eq!(f.service.unseal_nonce, *old);
            }
            "repeated-rotation" => {
                assert!(handoff.rotate_once(&mut f.service).is_err());
            }
            "exhaustion" => {
                f.service.unseal_nonce_attempt = u64::MAX;
                f.service
                    .rotate_unseal_nonce()
                    .map_err(|_| "old rotation entropy result")?;
                assert_eq!(f.service.unseal_nonce_attempt, u64::MAX);
                let unchanged = Zeroizing::new(f.service.unseal_nonce.clone());
                assert_eq!(
                    f.service
                        .rotate_unseal_nonce_with(|| Err("original entropy failure")),
                    Err("original entropy failure")
                );
                assert_eq!(f.service.unseal_nonce, *unchanged);
                assert_eq!(f.service.unseal_nonce_attempt, u64::MAX);
            }
            "key" => {
                f.service.barrier_key.as_mut().ok_or("barrier")?[0] ^= 1;
            }
            "deadline" => {
                expired = Some(crate::request_deadline::RequestDeadlineScope::enter(
                    Instant::now() - Duration::from_nanos(1),
                ));
            }
            "epoch-nochange" => {
                let epoch = f.service.durable.as_ref().ok_or("durable")?.replay_epoch();
                assert!(
                    f.service
                        .prepare_epoch_activation(epoch, false)
                        .map_err(|_| "epoch prepare")?
                        .is_none()
                );
                assert_eq!(f.service.unseal_nonce, *old);
            }
            "epoch-install-aba" => {
                f.service.install_epoch_activation(Some(old.to_string()));
                assert_eq!(f.service.unseal_nonce, *old);
            }
            _ => unreachable!(),
        }
        assert!(
            handoff.into_native_proof(&mut f.service).is_err(),
            "{changed}"
        );
        drop(expired);
        assert_cold_handoff_fenced(&mut f);
    }
    Ok(())
}

#[test]
fn cold_handoff_prepare_before_policy_and_capture_failures_clear_installed_barrier() -> TestResult {
    for changed in ["prepare", "before-policy", "capture"] {
        let mut f = fixture()?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        if changed == "prepare" {
            assert_eq!(
                f.service.unseal(&json!({"key":f.share.as_str()})).status,
                200
            );
            let proof = f
                .service
                .capture_native_unseal_proof(false)
                .map_err(|_| "actual capture")?
                .ok_or("single proof")?;
            let super::super::native_v6_reader::NativeProof::Single(proof) = proof else {
                return Err("single proof required".into());
            };
            let key = Zeroizing::new(**f.service.barrier_key.as_ref().ok_or("key")?);
            f.service.barrier_key.as_mut().ok_or("key")?[0] ^= 1;
            assert!(
                super::super::native_v6_reader::ColdUnsealHandoff::prepare(
                    &mut f.service,
                    &key,
                    *proof
                )
                .is_err()
            );
        } else {
            let (_, mut handoff) = pending_cold_handoff(&mut f)?;
            f.service.barrier_key.as_mut().ok_or("barrier")?[0] ^= 1;
            if changed == "before-policy" {
                assert!(handoff.check_before_policy(&mut f.service).is_err());
            } else {
                assert!(handoff.into_native_proof(&mut f.service).is_err());
            }
        }
        assert_cold_handoff_fenced(&mut f);
    }
    Ok(())
}

#[test]
fn cold_handoff_real_durable_owner_replacement_rejects_same_service_nonce_and_views() -> TestResult
{
    let mut f = fixture()?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let (_, handoff) = pending_cold_handoff(&mut f)?;
    let key = Zeroizing::new(**f.service.barrier_key.as_ref().ok_or("key")?);
    let nonce = Zeroizing::new(f.service.unseal_nonce.clone());
    let attempt = f.service.unseal_nonce_attempt;
    let old = f.service.durable.take().ok_or("original durable")?;
    let generation = old.generation();
    let epoch = old.replay_epoch();
    let resources = [
        "state",
        super::super::native_v6_reader::ACTIVE_CURSOR_RESOURCE,
        super::super::native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE,
    ];
    let before = resources
        .iter()
        .map(|name| {
            old.get("system", name)
                .map(|value| value.map(|secret| Zeroizing::new(secret.expose().to_vec())))
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Preserve the actual Service/Spool/nonce/attempt/key/typed views. Only drop
    // and independently reopen the actual durable owner on the same backend.
    drop(old);
    let reopened =
        DurableService::reopen(&f.service.data_dir, AeadBarrier::new(*key)?, MAX_OPERATIONS)?;
    assert_eq!(reopened.generation(), generation);
    assert_eq!(reopened.replay_epoch(), epoch);
    for (name, expected) in resources.iter().zip(&before) {
        let value = reopened.get("system", name)?;
        assert_eq!(
            value.as_ref().map(|secret| secret.expose()),
            expected.as_ref().map(|bytes| bytes.as_slice())
        );
    }
    f.service.durable = Some(reopened);
    assert_eq!(f.service.unseal_nonce, *nonce);
    assert_eq!(f.service.unseal_nonce_attempt, attempt);
    assert_eq!(
        f.service.barrier_key.as_ref().ok_or("key")?.as_slice(),
        key.as_slice()
    );
    assert!(handoff.into_native_proof(&mut f.service).is_err());
    assert_cold_handoff_fenced(&mut f);
    Ok(())
}

fn handoff_snapshot_plan(
    service: &mut Service,
    method: &str,
    token: &str,
) -> TestResult<Box<PendingExternalRequest>> {
    match service.begin_native_snapshot_before(
        ServiceRequest::new(method, "sys/storage/raft/snapshot", "", token, json!({})),
        Instant::now() + Duration::from_secs(15),
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(plan)) => Ok(plan),
        _ => Err("actual native snapshot plan required".into()),
    }
}

#[test]
fn cold_handoff_real_snapshot_restore_cannot_revive_old_nonce_or_source_session() -> TestResult {
    let mut f = fixture()?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    assert_eq!(
        f.service.unseal(&json!({"key":f.share.as_str()})).status,
        200
    );
    f.service
        .complete_default_policy_activation(Some(original_clock()?))
        .map_err(|_| "stable policy")?;
    let mut download = handoff_snapshot_plan(&mut f.service, "GET", f.token.as_str())?;
    let (result, file) = download.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(
        f.service.finish_external_request(*download, result).status,
        200
    );
    let mut file = file.ok_or("actual native archive")?;
    let mut archive = Zeroizing::new(Vec::new());
    file.read_to_end(&mut archive)?;
    drop(file);
    drop(f.service);
    f.service = f.root.service()?;
    f.service
        .configure_native_v6_storage(NativeStorageProfile::File)?;
    let (_, handoff) = pending_cold_handoff(&mut f)?;
    let old_nonce = Zeroizing::new(f.service.unseal_nonce.clone());
    let old_epoch = f.service.durable.as_ref().ok_or("durable")?.replay_epoch();
    f.service
        .complete_default_policy_activation(Some(original_clock()?))
        .map_err(|_| "stable policy")?;
    let mut restore = handoff_snapshot_plan(&mut f.service, "POST", f.token.as_str())?;
    let (result, returned) = restore.execute_snapshot_transfer(&mut archive.as_slice());
    assert!(returned.is_none());
    let response = f.service.finish_external_request(*restore, result);
    assert_eq!(response.status, 200);
    assert!(
        f.service
            .durable
            .as_ref()
            .ok_or("restored durable")?
            .replay_epoch()
            > old_epoch
    );
    assert_eq!(
        request(
            &mut f.service,
            "GET",
            "secret/data/cold-single-proof",
            f.token.as_str(),
            json!({})
        )
        .body["data"]["data"]["value"],
        "cold-single-synthetic-sentinel"
    );
    // Deliberately restore the public nonce bytes in this test only. Neither
    // that ABA nor an archive with the same logical value recreates the actual
    // pre-restore weak durable session / replay frontier / attempt event.
    f.service.unseal_nonce = old_nonce.to_string();
    assert!(handoff.into_native_proof(&mut f.service).is_err());
    assert_cold_handoff_fenced(&mut f);
    Ok(())
}
