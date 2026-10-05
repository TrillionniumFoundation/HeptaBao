//! Genuine Token API producers and the complete private durable owner are tested
//! together. These tests never use an origin field as a credential or key grant.
use super::tests::{Root, bootstrap_unmounted, call};
use super::*;
use crate::state_records::{ObjectRef, RecordError, RecordReader, StagedObject};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn realtime(
    service: &mut Service,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: Value,
) -> Response {
    service.handle_request(ServiceRequest::new(method, path, namespace, token, body))
}
fn bearer(response: &Response) -> TestResult<Zeroizing<String>> {
    assert_eq!(response.status, 200);
    Ok(Zeroizing::new(
        response.body["auth"]["client_token"]
            .as_str()
            .ok_or("mint bearer shape")?
            .into(),
    ))
}
fn wall() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}
fn epoch_nanos(value: &Value) -> TestResult<u128> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value.as_str().ok_or("timestamp shape")?)?;
    let seconds = u128::try_from(parsed.timestamp())?;
    Ok(seconds * 1_000_000_000 + u128::from(parsed.timestamp_subsec_nanos()))
}
fn artifact_digests(service: &Service) -> TestResult<Vec<[u8; 32]>> {
    ["state.hbs", "journal.hbj", "ledger.hbl"]
        .into_iter()
        .map(|name| {
            fs::read(service.data_dir.join(name))
                .map(|bytes| crypto::digest(&bytes))
                .map_err(Into::into)
        })
        .collect()
}

#[test]
fn public_origin_real_meta_and_service_issue_stamp_survive_process_reopen() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        realtime(
            &mut service,
            "POST",
            "sys/namespaces/plain",
            "",
            &admin,
            json!({})
        )
        .status,
        200
    );
    let mut samples = Vec::new();
    for namespace in ["", "plain"] {
        for kind in ["service", "batch"] {
            for meta in [
                None,
                Some(Value::Null),
                Some(json!({})),
                Some(json!({"public_marker":"native-origin"})),
            ] {
                let mut input = json!({"policies":["default"], "no_default_policy":true, "type":kind, "ttl":"1h"});
                if let Some(meta) = &meta {
                    input["meta"] = meta.clone();
                }
                let before = wall();
                let response = realtime(
                    &mut service,
                    "POST",
                    "auth/token/create",
                    namespace,
                    &admin,
                    input,
                );
                let after = wall();
                let actor = bearer(&response)?;
                let mint_meta = meta.clone().unwrap_or(Value::Null);
                assert_eq!(response.body["auth"]["metadata"], mint_meta);
                let lookup = realtime(
                    &mut service,
                    "GET",
                    "auth/token/lookup-self",
                    namespace,
                    &actor,
                    json!({}),
                );
                assert_eq!(lookup.status, 200);
                let lookup_meta = if kind == "batch"
                    && mint_meta.as_object().is_some_and(serde_json::Map::is_empty)
                {
                    Value::Null
                } else {
                    mint_meta
                };
                assert_eq!(lookup.body["data"]["meta"], lookup_meta);
                assert_eq!(lookup.body["data"]["path"], "auth/token/create");
                let issue = lookup.body["data"]["issue_time"].clone();
                let nanos = epoch_nanos(&issue)?;
                if kind == "service" {
                    assert!(
                        before.as_nanos() <= nanos && nanos <= after.as_nanos(),
                        "genuine service producer time lies within its actual mint operation"
                    );
                } else {
                    assert_eq!(
                        nanos % 1_000_000_000,
                        0,
                        "native batch retains the actual integer claims time"
                    );
                    assert!(
                        before.as_secs() <= (nanos / 1_000_000_000) as u64
                            && (nanos / 1_000_000_000) as u64 <= after.as_secs()
                    );
                }
                samples.push((namespace.to_owned(), actor, lookup_meta, issue));
            }
        }
    }
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        AUTH_PUBLIC_ORIGIN_STATE_SCHEMA
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    for (namespace, actor, metadata, stamp) in samples {
        let lookup = realtime(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &namespace,
            &actor,
            json!({}),
        );
        assert_eq!(lookup.status, 200);
        assert_eq!(lookup.body["data"]["meta"], metadata);
        assert_eq!(lookup.body["data"]["issue_time"], stamp);
    }
    Ok(())
}

#[test]
fn public_origin_real_wrapper_stamp_and_relative_creation_path_survive_reopen() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        realtime(
            &mut service,
            "POST",
            "sys/namespaces/plain",
            "",
            &admin,
            json!({})
        )
        .status,
        200
    );
    let mut samples = Vec::new();
    for namespace in ["", "plain"] {
        for path in ["sys/wrapping/wrap", "auth/token/create"] {
            let body = if path == "sys/wrapping/wrap" {
                json!({"public_marker":"never_release"})
            } else {
                json!({"policies":["default"],"no_default_policy":true,"ttl":"1h","meta":{}})
            };
            let mut request = ServiceRequest::new("POST", path, namespace, &admin, body);
            request.wrap_ttl_seconds = Some(60);
            let before = wall();
            let response = service.handle_request(request);
            let after = wall();
            assert_eq!(response.status, 200);
            assert!(response.body.get("data").is_some_and(Value::is_null));
            let stamp = response.body["wrap_info"]["creation_time"].clone();
            let nanos = epoch_nanos(&stamp)?;
            assert!(before.as_nanos() <= nanos && nanos <= after.as_nanos());
            assert_eq!(response.body["wrap_info"]["creation_path"], path);
            let wrapper = Zeroizing::new(
                response.body["wrap_info"]["token"]
                    .as_str()
                    .ok_or("wrapper shape")?
                    .to_owned(),
            );
            let lookup = realtime(
                &mut service,
                "POST",
                "sys/wrapping/lookup",
                namespace,
                "",
                json!({"token":wrapper.as_str()}),
            );
            assert_eq!(lookup.status, 200);
            assert_eq!(lookup.body["data"]["creation_time"], stamp);
            assert_eq!(lookup.body["data"]["creation_path"], path);
            samples.push((namespace.to_owned(), path, wrapper, stamp));
        }
    }
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    for (namespace, path, wrapper, stamp) in samples {
        let lookup = realtime(
            &mut service,
            "POST",
            "sys/wrapping/lookup",
            &namespace,
            "",
            json!({"token":wrapper.as_str()}),
        );
        assert_eq!(lookup.status, 200);
        assert_eq!(lookup.body["data"]["creation_time"], stamp);
        assert_eq!(lookup.body["data"]["creation_path"], path);
    }
    Ok(())
}

#[test]
fn public_origin_explicit_clock_never_fabricates_a_fractional_observation() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap_unmounted(&mut service)?;
    let _outer_listener =
        external_pki::PublicationClockScope::enter(wall(), std::time::Instant::now());
    let issued = service.handle_request_at(
        ServiceRequest::new(
            "POST",
            "auth/token/create",
            "",
            &admin,
            json!({"policies":["default"], "no_default_policy":true, "meta":{}}),
        ),
        100,
    );
    let actor = bearer(&issued)?;
    let lookup = service.handle_request_at(
        ServiceRequest::new("GET", "auth/token/lookup-self", "", &actor, json!({})),
        100,
    );
    assert_eq!(lookup.status, 200);
    assert!(
        lookup.body["data"].get("issue_time").is_none(),
        "explicit clock does not fabricate a new real observation"
    );
    let private = Zeroizing::new(serde_json::to_vec(
        &service.state.as_ref().ok_or("state")?.auth,
    )?);
    let shape: Value = serde_json::from_slice(&private)?;
    assert!(
        shape["tokens"]
            .as_object()
            .ok_or("token owner")?
            .values()
            .all(|token| token.get("issue_stamp").is_none())
    );
    Ok(())
}

#[test]
fn public_origin_floor_is_sticky_after_retirement_and_rejects_old_snapshot_without_writes()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap_unmounted(&mut service)?;
    let old_backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let issued = realtime(
        &mut service,
        "POST",
        "auth/token/create",
        "",
        &admin,
        json!({"policies":["default"],"no_default_policy":true,"meta":{}}),
    );
    let actor = bearer(&issued)?;
    assert_eq!(
        realtime(
            &mut service,
            "POST",
            "auth/token/revoke",
            "",
            &admin,
            json!({"token":actor.as_str()})
        )
        .status,
        204
    );
    let retired = service.state.clone().ok_or("state")?;
    assert_eq!(retired.schema, AUTH_PUBLIC_ORIGIN_STATE_SCHEMA);
    assert!(retired.auth.has_public_origin_state());
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let files = artifact_digests(&service)?;
    assert!(service.prepare_snapshot_restore(&old_backup).is_err());
    let mut lower = retired.clone();
    lower.schema = NAMESPACE_CUSTODY_STATE_SCHEMA;
    assert!(lower.validate_format().is_err());
    assert!(service.commit_state(&mut lower).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired, &lower).is_err());
    let mut auth: Value = serde_json::to_value(&retired.auth)?;
    auth.as_object_mut()
        .ok_or("auth owner")?
        .remove("public_origin_floor");
    let mut stripped = retired.clone();
    stripped.auth = serde_json::from_value(auth)?;
    assert!(
        stripped.validate_format().is_err(),
        "retired floor is mandatory even without previous live state"
    );
    assert!(
        stripped
            .validate_publication_schema(Some(&retired))
            .is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(&retired, &stripped).is_err());
    for gap in 82..=85 {
        let mut state = retired.clone();
        state.schema = gap;
        assert!(state.validate_format().is_err());
        assert!(state.validate_publication_schema(Some(&retired)).is_err());
    }
    assert_eq!(artifact_digests(&service)?, files);
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        AUTH_PUBLIC_ORIGIN_STATE_SCHEMA
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_public_origin_state()
    );
    Ok(())
}

// This test-only authenticated overlay changes an owner under the genuine
// committed address key. It proves semantic gates after MAC validation; no
// unauthenticated JSON or fake key stands in for a received record graph.
struct Overlay<'a> {
    durable: records::DurableReader<'a>,
    objects: BTreeMap<crate::state_records::ObjectId, Arc<StagedObject>>,
}
impl RecordReader for Overlay<'_> {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        if let Some(object) = self.objects.get(&reference.id) {
            if object.reference() != reference {
                return Err(RecordError::Corrupt);
            }
            return Ok(Zeroizing::new(object.bytes().to_vec()));
        }
        self.durable.read_object(reference)
    }
}
#[test]
fn public_origin_complete_auth_digest_and_received_graph_reject_malformed_stamp_and_hidden_floor()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/records",
            &admin,
            json!({"type":"kv", "options":{"version":"1"}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "records/marker",
            &admin,
            json!({"public_marker":"record-origin"})
        )
        .status,
        204
    );
    let issued = realtime(
        &mut service,
        "POST",
        "auth/token/create",
        "",
        &admin,
        json!({"policies":["default"],"no_default_policy":true,"meta":{"public_marker":"auth-origin"}}),
    );
    let _actor = bearer(&issued)?;
    let current = service.state.as_ref().ok_or("state")?;
    let canonical = current.protected_state().map_err(|_| "protected view")?;
    let committed = service.record_root.as_ref().ok_or("root")?;
    let key = committed.address_key();
    let encoded = owner_store::serialize_owner(&canonical.auth).map_err(|_| "serialize owner")?;
    assert_eq!(
        committed.owners[1].digest,
        crate::state_record_root::digest_owner(&key, "auth", &encoded)
            .map_err(|_| "auth digest")?
    );
    let restored = Service::materialize_record_state(
        committed,
        &records::DurableReader(service.durable.as_ref().ok_or("durable")?),
    )
    .map_err(|_| "received authentic graph")?;
    assert_eq!(
        owner_store::serialize_owner(&restored.auth)
            .map_err(|_| "restored owner")?
            .as_slice(),
        encoded.as_slice()
    );
    let original_identity = service.current_state_identity().map_err(|_| "identity")?;
    let files = artifact_digests(&service)?;
    for malformed in [false, true] {
        let mut auth: Value = serde_json::from_slice(&encoded)?;
        if malformed {
            let token = auth["tokens"]
                .as_object_mut()
                .ok_or("token owner")?
                .values_mut()
                .find(|token| token.get("issue_stamp").is_some())
                .ok_or("actual issue producer")?;
            token["issue_stamp"]["nanoseconds"] = json!(1_000_000_000_u32);
        } else {
            auth.as_object_mut()
                .ok_or("auth owner")?
                .remove("public_origin_floor");
        }
        let typed: AuthState = serde_json::from_value(auth)?;
        let bytes = owner_store::serialize_owner(&typed).map_err(|_| "corrupt typed owner")?;
        let mut changed_root = committed.clone();
        let mut objects = BTreeMap::new();
        let mut chunks = Vec::new();
        for chunk in bytes.chunks(crate::state_record_root::OWNER_CHUNK_BYTES) {
            let object =
                StagedObject::owner_chunk(&key, chunk).map_err(|_| "authenticated owner chunk")?;
            chunks.push(object.reference().clone());
            objects.insert(object.reference().id, object);
        }
        changed_root.owners[1] = crate::state_record_root::OpaqueOwnerRef {
            name: "auth".into(),
            total_bytes: bytes.len() as u64,
            chunks,
            digest: crate::state_record_root::digest_owner(&key, "auth", &bytes)
                .map_err(|_| "changed digest")?,
        };
        assert_ne!(changed_root.owners[1].digest, committed.owners[1].digest);
        let overlay = Overlay {
            durable: records::DurableReader(service.durable.as_ref().ok_or("durable")?),
            objects,
        };
        assert!(Service::materialize_record_state(&changed_root, &overlay).is_err());
        let mut candidate = current.clone();
        candidate.auth = typed.into();
        assert!(candidate.validate_format().is_err());
        assert!(Service::validate_snapshot_protected_floor(current, &candidate).is_err());
    }
    for schema in [NAMESPACE_CUSTODY_STATE_SCHEMA, 82, 83, 84, 85] {
        let mut bad_root = committed.clone();
        bad_root.state_schema = schema;
        assert!(
            Service::materialize_record_state(
                &bad_root,
                &records::DurableReader(service.durable.as_ref().ok_or("durable")?)
            )
            .is_err()
        );
    }
    assert_eq!(artifact_digests(&service)?, files);
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        original_identity
    );
    Ok(())
}

#[test]
fn public_origin_retired_floor_received_without_previous_state_is_rejected_after_actual_mac()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/records",
            &admin,
            json!({"type":"kv","options":{"version":"1"}})
        )
        .status,
        204
    );
    let issued = realtime(
        &mut service,
        "POST",
        "auth/token/create",
        "",
        &admin,
        json!({"policies":["default"],"no_default_policy":true,"meta":{}}),
    );
    let actor = bearer(&issued)?;
    assert_eq!(
        realtime(
            &mut service,
            "POST",
            "auth/token/revoke",
            "",
            &admin,
            json!({"token":actor.as_str()})
        )
        .status,
        204
    );
    let current = service.state.as_ref().ok_or("retired live state")?;
    assert_eq!(current.schema, AUTH_PUBLIC_ORIGIN_STATE_SCHEMA);
    let committed = service.record_root.as_ref().ok_or("committed root")?;
    let key = committed.address_key();
    let mut auth: Value = serde_json::to_value(
        &current
            .protected_state()
            .map_err(|_| "protected retired owner")?
            .auth,
    )?;
    assert!(auth["tokens"].as_object().ok_or("retired tokens")?.values().all(|token| token.get("public_origin").is_none() && token.get("issue_stamp").is_none()));
    assert!(
        auth.as_object_mut()
            .ok_or("retired auth")?
            .remove("public_origin_floor")
            .is_some()
    );
    let typed: AuthState = serde_json::from_value(auth)?;
    // Facts are genuinely retired. The high schema tag alone cannot hide a
    // removed typed floor from a fresh received/restore reader without history.
    assert!(!typed.has_public_origin_state());
    let bytes = owner_store::serialize_owner(&typed).map_err(|_| "retired malformed owner")?;
    let mut bad_root = committed.clone();
    let mut objects = BTreeMap::new();
    let mut chunks = Vec::new();
    for chunk in bytes.chunks(crate::state_record_root::OWNER_CHUNK_BYTES) {
        let object =
            StagedObject::owner_chunk(&key, chunk).map_err(|_| "real authenticated owner")?;
        chunks.push(object.reference().clone());
        objects.insert(object.reference().id, object);
    }
    bad_root.owners[1] = crate::state_record_root::OpaqueOwnerRef {
        name: "auth".into(),
        total_bytes: bytes.len() as u64,
        chunks,
        digest: crate::state_record_root::digest_owner(&key, "auth", &bytes)
            .map_err(|_| "retired owner digest")?,
    };
    let files = artifact_digests(&service)?;
    let identity = service
        .current_state_identity()
        .map_err(|_| "retired identity")?;
    let reader = Overlay {
        durable: records::DurableReader(service.durable.as_ref().ok_or("durable")?),
        objects,
    };
    assert!(Service::materialize_record_state(&bad_root, &reader).is_err());
    assert_eq!(artifact_digests(&service)?, files);
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "unchanged retired identity")?,
        identity
    );
    Ok(())
}
