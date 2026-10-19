//! Uses the real HTTP parser/Service admission, FileBackend, encrypted immutable
//! objects, fsynced journal fault helper, and normal cold recovery. No network
//! oracle result is claimed here; the two-process controller supplies that gate.
use super::*;
use crate::engines::kv2_native_large::{PATH, MEDIA_TYPE, MAX_BUNDLE_BYTES};

struct Wire<'a> {
    header: Zeroizing<Vec<u8>>,
    head_offset: usize,
    body: &'a [u8],
    body_offset: usize,
    body_reads: usize,
}
impl Read for Wire<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.head_offset < self.header.len() {
            let count = out.len().min(self.header.len() - self.head_offset);
            out[..count].copy_from_slice(&self.header[self.head_offset..self.head_offset + count]);
            self.head_offset += count;
            return Ok(count);
        }
        self.body_reads += 1;
        let count = out.len().min(self.body.len() - self.body_offset);
        out[..count].copy_from_slice(&self.body[self.body_offset..self.body_offset + count]);
        self.body_offset += count;
        Ok(count)
    }
}
fn upload_http(native: Service, token: &str, mount: &str, bytes: &[u8])
    -> TestResult<(Service, Response, usize)> {
    let shared = Arc::new(Mutex::new(native));
    let mut input = Wire {
        header: Zeroizing::new(format!(
            "POST /v1/{PATH}?mount={mount} HTTP/1.1\r\nHost: fixture\r\nX-Vault-Token: {token}\r\nContent-Type: {MEDIA_TYPE}\r\nContent-Length: {}\r\n\r\n",
            bytes.len(),
        ).into_bytes()), head_offset: 0, body: bytes, body_offset: 0, body_reads: 0,
    };
    let response = crate::http::native_large_upload_wire_fixture(
        &shared, &mut input, Instant::now() + Duration::from_secs(30),
    )?;
    let reads = input.body_reads;
    let native = Arc::try_unwrap(shared).map_err(|_| "fixture Service still borrowed")?
        .into_inner().map_err(|_| "fixture Service lock")?;
    Ok((native, response, reads))
}
fn encode(value: &Value) -> TestResult<Zeroizing<Vec<u8>>> {
    crate::secret_serde::to_vec(value, MAX_BUNDLE_BYTES).map_err(|_| "fixture encoding".into())
}
fn begin(native: &mut Service, token: &str, deadline: Instant) -> TestResult<Box<PendingExternalRequest>> {
    match native.begin_native_kv2_large_before(
        ServiceRequest::new("POST", PATH, "", token, json!({"mount":"secret"})), deadline,
    ) {
        RequestExecution::External(pending) => Ok(pending),
        RequestExecution::Complete(response) => Err(format!("native-large admission status={}", response.status).into()),
    }
}
fn full34_bundle() -> TestResult<Value> {
    let mut bundle = fixture_bundle(false)?;
    let exact = crate::engines::decode_lossless_json(
        r#"{"wide_integer":9007199254740993,"decimal":0.123456789012345678901234567890,"private":{"$serde_json::private::Number":"7"},"unicode":"保留"}"#.as_bytes(),
    )?;
    let mut versions = serde_json::Map::new();
    for number in 1..=19_u64 {
        let mut data = exact.clone();
        data["ordinal"] = json!(number);
        data["payload"] = json!(char::from(b'a' + number as u8).to_string().repeat(
            if number <= 2 { 1024 } else { 2 * 1024 * 1024 },
        ));
        versions.insert(number.to_string(), json!({
            "created_time":format!("1970-01-01T00:01:{:02}.000000113Z", 30 + number),
            "deletion_time":if number == 1 { "1970-01-01T00:03:20.000000113Z" } else { "" },
            "source_deletion_time":if number == 1 { "1970-01-01T00:05:00.000000113Z" } else { "" },
            "destroyed":number == 2,
            "data":if number == 2 { Value::Null } else { data },
        }));
    }
    bundle["config"]["max_versions"] = json!(19);
    bundle["entries"]["history"] = json!({
        "created_time":"1970-01-01T00:01:30.000000113Z", "updated_time":"1970-01-01T00:01:50.000000113Z",
        "current_version":19,"oldest_version":0,"current_metadata_version":2,
        "max_versions":19,"cas_required":true,"metadata_cas_required":true,
        "delete_version_after":"0s","custom_metadata":{"revision":"2","purpose":"full34"},
        "versions":versions,
    });
    Ok(bundle)
}
fn full34_api_data(exact: &Value) -> TestResult<Value> {
    assert_eq!(exact["wide_integer"].as_number().ok_or("exact integer")?.to_string(),
        "9007199254740993");
    assert_eq!(exact["decimal"].as_number().ok_or("exact decimal")?.to_string(),
        "0.123456789012345678901234567890");
    let mut api=exact.clone();
    // Independent observed 2.7.1 API constants, not a call to the product
    // projection under test. The original input continues to bind storage.
    api["wide_integer"]=json!(9007199254740992_u64);
    api["decimal"]=crate::engines::decode_lossless_json(b"0.12345678901234568")?;
    Ok(api)
}
fn assert_full34(native: &mut Service, token: &str, source: &Value) -> TestResult {
    sentinel(native, token);
    let metadata = call(native, "GET", "secret/metadata/history", token, json!({}));
    assert_eq!(metadata.status, 200);
    for field in ["created_time", "updated_time", "current_version", "oldest_version",
        "current_metadata_version", "max_versions", "cas_required", "metadata_cas_required",
        "delete_version_after", "custom_metadata"] {
        assert_eq!(metadata.body["data"][field], source["entries"]["history"][field]);
    }
    for version in 1..=19 {
        let key = version.to_string();
        let original = &source["entries"]["history"]["versions"][&key];
        for field in ["created_time", "deletion_time", "destroyed"] {
            assert_eq!(metadata.body["data"]["versions"][&key][field], original[field]);
        }
        let response = call(native, "GET", "secret/data/history", token, json!({"version":version}));
        assert_eq!(response.status, if version <= 2 { 404 } else { 200 });
        if version > 2 {
            assert_eq!(response.body["data"]["data"], full34_api_data(&original["data"])?);
        }
        assert_storage_version(native,token,"history",version,original)?;
    }
    let graph = selected_graph(native)?;
    // The deleted payload must also be stored, even though normal reads hide it.
    assert!(graph.logical_payload_bytes > (34 * 1024 * 1024 + 1024) as u64);
    assert!(crate::secret_serde::to_vec(&*native.state.as_ref().ok_or("state")?.engines,
        crate::MAX_APPLICATION_STATE_BYTES).is_err());
    Ok(())
}

#[test]
fn native_large_kv2_service_full34_history_snapshot_and_cold_recovery() -> TestResult {
    let (files, mut native, key, token) = initialized()?;
    activate(&mut native, &token);
    let source = full34_bundle()?;
    let bytes = encode(&source)?;
    assert!(bytes.len() > 34 * 1024 * 1024 && bytes.len() < MAX_BUNDLE_BYTES);
    {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(30));
        let mut candidate = native.state.as_ref().ok_or("state")?.clone();
        let parent = native.native_root.as_ref().ok_or("root")?.kv2_parent_key().map_err(|_| "key")?;
        assert!(candidate.engines.stage_openbao_kv2_native_import("", "secret", &bytes, &parent, &|| Ok(())).is_err());
    }
    let (mut native, response, reads) = upload_http(native, &token, "secret", &bytes)?;
    assert_eq!(response.status, 204); assert!(reads > 0);
    assert_full34(&mut native, &token, &source)?;
    let mut request = snapshot_request(&mut native, &token, "GET")?;
    let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(native.finish_external_request(*request, result).status, 200);
    let mut archive = Zeroizing::new(Vec::new());
    file.ok_or("snapshot file")?.read_to_end(&mut archive)?;
    assert_eq!(call(&mut native, "POST", "secret/data/history", &token,
        json!({"options":{"cas":19},"data":{"discard":"after snapshot"}})).status, 200);
    let mut request = snapshot_request(&mut native, &token, "POST")?;
    let (result, file) = request.execute_snapshot_transfer(&mut &archive[..]);
    assert!(file.is_none());
    assert_eq!(native.finish_external_request(*request, result).status, 200);
    drop(native);
    let mut native = reopen(&files, &key)?;
    assert_full34(&mut native, &token, &source)?;
    assert_eq!(call(&mut native, "POST", "secret/undelete/history", &token, json!({"versions":[1,2]})).status, 204);
    let recovered = call(&mut native, "GET", "secret/data/history", &token, json!({"version":1}));
    assert_eq!(recovered.status, 200);
    assert_eq!(recovered.body["data"]["data"],
        full34_api_data(&source["entries"]["history"]["versions"]["1"]["data"])?);
    let mut undeleted=source["entries"]["history"]["versions"]["1"].clone();
    undeleted["deletion_time"]=json!("");
    assert_storage_version(&mut native,&token,"history",1,&undeleted)?;
    assert_storage_version(&mut native,&token,"history",2,
        &source["entries"]["history"]["versions"]["2"])?;
    assert_eq!(call(&mut native, "GET", "secret/data/history", &token, json!({"version":2})).status, 404);
    Ok(())
}

#[test]
fn native_large_kv2_service_rejects_unadmitted_replayed_and_nonpristine_before_body() -> TestResult {
    let (_files, mut native, _key, token) = initialized()?;
    assert_eq!(call(&mut native, "PUT", "sys/policies/acl/large-no-sudo", &token,
        json!({"policy":format!("path \"{PATH}\" {{ capabilities=[\"update\"] }}")})).status, 204);
    let issued = call(&mut native, "POST", "auth/token/create", &token,
        json!({"policies":["large-no-sudo"],"no_default_policy":true,"ttl":"1h"}));
    assert_eq!(issued.status, 200);
    let denied = Zeroizing::new(issued.body["auth"]["client_token"].as_str().ok_or("actor")?.to_owned());
    activate(&mut native, &token);
    let bytes = encode(&fixture_bundle(false)?)?;
    let old = selected_graph(&native)?;
    for actor in ["", denied.as_str()] {
        for mount in ["secret", "keep"] {
            let (next, response, reads) = upload_http(native, actor, mount, &bytes)?;
            native = next;
            assert_eq!(response.status, 403); assert_eq!(reads, 0);
            assert!(same_graph(&selected_graph(&native)?, &old));
        }
    }
    assert_eq!(call(&mut native, "POST", PATH, &token, json!({"mount":"secret"})).status, 501);
    let (next, response, reads) = upload_http(native, &token, "keep", &bytes)?;
    native = next; assert_eq!(response.status, 409); assert_eq!(reads, 0);
    let (next, response, _) = upload_http(native, &token, "secret", &bytes)?;
    native = next; assert_eq!(response.status, 204);
    let (mut native, response, reads) = upload_http(native, &token, "secret", &bytes)?;
    assert_eq!(response.status, 409); assert_eq!(reads, 0);
    assert_imported(&mut native, &token, false)?;
    Ok(())
}

#[test]
fn native_large_kv2_service_original_deadline_survives_body_and_finalization() -> TestResult {
    let (files, mut native, key, token) = initialized()?;
    activate(&mut native, &token);
    let old = selected_graph(&native)?;
    let mut request = begin(&mut native, &token, Instant::now() + Duration::from_secs(1))?;
    struct Delayed { calls: usize }
    impl Read for Delayed {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            std::thread::sleep(Duration::from_millis(1100));
            out[0] = b'{'; Ok(1)
        }
    }
    let mut delayed = Delayed { calls: 0 };
    let result = request.execute_native_kv2_large_transfer(&mut delayed);
    assert_eq!(delayed.calls, 1);
    // A fresh outer scope cannot replace the plan's original deadline.
    let _outer = crate::request_deadline::RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(30));
    assert_eq!(native.finish_external_request(*request, result).status, 503);
    drop(native);
    let mut native = reopen(&files, &key)?;
    assert!(same_graph(&selected_graph(&native)?, &old));
    sentinel(&mut native, &token);
    Ok(())
}

#[test]
fn native_large_kv2_service_one_admitted_upload_and_cancel_releases_own_slot() -> TestResult {
    let (_files, mut native, _key, token) = initialized()?;
    activate(&mut native, &token);
    let old = selected_graph(&native)?;
    let first = begin(&mut native, &token, Instant::now() + Duration::from_secs(30))?;
    let bytes = encode(&fixture_bundle(false)?)?;
    let (native, response, reads) = upload_http(native, &token, "secret", &bytes)?;
    assert_eq!(response.status, 429); assert_eq!(reads, 0);
    assert!(same_graph(&selected_graph(&native)?, &old));
    drop(first);
    let (mut native, response, _) = upload_http(native, &token, "secret", &bytes)?;
    assert_eq!(response.status, 204);
    assert_imported(&mut native, &token, false)?;
    Ok(())
}

#[test]
fn native_large_kv2_service_rechecks_actual_actor_and_source_after_transfer() -> TestResult {
    let (_files, mut native, _key, token) = initialized()?;
    assert_eq!(call(&mut native, "PUT", "sys/policies/acl/large-sudo", &token,
        json!({"policy":format!("path \"{PATH}\" {{ capabilities=[\"update\",\"sudo\"] }}")})).status, 204);
    let issued = call(&mut native, "POST", "auth/token/create", &token,
        json!({"policies":["large-sudo"],"no_default_policy":true,"ttl":"1h"}));
    assert_eq!(issued.status, 200);
    let actor = Zeroizing::new(issued.body["auth"]["client_token"].as_str().ok_or("actor")?.to_owned());
    activate(&mut native, &token);
    let old = selected_graph(&native)?;
    let bytes = encode(&fixture_bundle(false)?)?;
    let mut request = begin(&mut native, &actor, Instant::now() + Duration::from_secs(30))?;
    let result = request.execute_native_kv2_large_transfer(&mut &bytes[..]);
    assert_eq!(call(&mut native, "POST", "auth/token/revoke", &token, json!({"token":actor.as_str()})).status, 204);
    let response = native.finish_external_request(*request, result);
    assert!(matches!(response.status, 403 | 409));
    assert!(same_graph(&selected_graph(&native)?, &old));
    assert_eq!(call(&mut native, "GET", "secret/metadata/item", &token, json!({})).status, 404);
    Ok(())
}

#[test]
fn native_large_kv2_service_locator_lost_ack_reopens_pristine_then_retries() -> TestResult {
    let (files, mut native, key, token) = initialized()?;
    activate(&mut native, &token);
    let old = selected_graph(&native)?;
    let fired = lose_ack(&mut native, "-locators-0")?;
    let bytes = encode(&fixture_bundle(true)?)?;
    let (native, response, reads) = upload_http(native, &token, "secret", &bytes)?;
    assert_eq!(response.status, 503); assert!(reads > 0);
    assert!(fired.load(Ordering::SeqCst)); assert!(native.recovery_required);
    drop(native);
    let native = reopen(&files, &key)?;
    assert!(same_graph(&selected_graph(&native)?, &old));
    let (mut native, response, _) = upload_http(native, &token, "secret", &bytes)?;
    assert_eq!(response.status, 204); assert_imported(&mut native, &token, true)?;
    Ok(())
}

#[test]
fn native_large_kv2_service_root_lost_ack_reopens_complete_once() -> TestResult {
    let (files, mut native, key, token) = initialized()?;
    activate(&mut native, &token);
    let old = selected_graph(&native)?;
    let fired = lose_ack(&mut native, "-root")?;
    let bytes = encode(&fixture_bundle(true)?)?;
    let (native, response, _) = upload_http(native, &token, "secret", &bytes)?;
    assert_eq!(response.status, 503); assert!(fired.load(Ordering::SeqCst));
    assert!(native.recovery_required); drop(native);
    let native = reopen(&files, &key)?;
    assert!(!same_graph(&selected_graph(&native)?, &old));
    let (mut native, response, reads) = upload_http(native, &token, "secret", &bytes)?;
    assert_eq!(response.status, 409); assert_eq!(reads, 0);
    assert_imported(&mut native, &token, true)?;
    Ok(())
}

fn large_actor_policy(native: &mut Service, admin: &str) {
    assert_eq!(call(native, "PUT", "sys/policies/acl/large-terminal-sudo", admin,
        json!({"policy":format!("path \"{PATH}\" {{ capabilities=[\"update\",\"sudo\"] }}")})).status, 204);
}

fn finish_after_audit(
    native: &mut Service,
    pending: PendingExternalRequest,
    result: ExternalEffectResult,
    after_audit: impl FnOnce(),
) -> TestResult<Response> {
    let _raw_reply_ingress = crate::auth::IngressReplyScope::restore(pending.raw_reply_ingress.clone());
    match (pending.effect, result) {
        (ExternalEffectPlan::NativeKv2Large(plan), ExternalEffectResult::NativeKv2Large(result)) =>
            Ok(native.complete_native_kv2_large_with_receipt(
                *plan, result, &pending.fingerprint, (pending.now, pending.token_clock), after_audit,
            )),
        _ => Err("actual native-large transfer was not prepared".into()),
    }
}

#[test]
fn native_large_kv2_service_terminal_clock_self_write_keeps_actual_finite_actor() -> TestResult {
    let (files, mut native, key, admin) = initialized()?;
    large_actor_policy(&mut native, &admin);
    activate(&mut native, &admin);
    let bytes = encode(&fixture_bundle(false)?)?;
    let mut issued = call(&mut native, "POST", "auth/token/create", &admin,
        json!({"policies":["large-terminal-sudo"],"no_default_policy":true,"ttl":"1h","num_uses":2}));
    assert_eq!(issued.status, 200);
    let actor = Zeroizing::new(issued.body["auth"]["client_token"].as_str().ok_or("actual actor")?.to_owned());
    erase_json(&mut issued.body);
    let mut pending = begin(&mut native, &actor, Instant::now() + Duration::from_secs(30))?;
    // Finite-use admission has already published its one use. The import does
    // not change Auth; a subsequent Auth change here is the real terminal floor.
    let admitted_auth = owner_store::serialize_owner(&native.state.as_ref().ok_or("state")?.auth)?;
    let result = pending.execute_native_kv2_large_transfer(&mut &bytes[..]);
    let audit_seen = std::cell::Cell::new(false);
    let response = finish_after_audit(&mut native, *pending, result, || audit_seen.set(true))?;
    assert!(audit_seen.get()); assert_eq!(response.status, 204);
    assert!(!native.recovery_required); assert!(!native.audit_failed);
    let completed_auth = owner_store::serialize_owner(&native.state.as_ref().ok_or("state")?.auth)?;
    assert!(admitted_auth.as_slice() != completed_auth.as_slice());
    let mut lookup = call(&mut native, "POST", "auth/token/lookup", &admin, json!({"token":actor.as_str()}));
    assert_eq!(lookup.status, 200); assert_eq!(lookup.body["data"]["num_uses"], 1);
    erase_json(&mut lookup.body);
    assert_imported(&mut native, &admin, false)?;
    drop(native);
    let mut native = reopen(&files, &key)?;
    assert_imported(&mut native, &admin, false)?;
    let mut lookup = call(&mut native, "POST", "auth/token/lookup", &admin, json!({"token":actor.as_str()}));
    assert_eq!(lookup.status, 200); assert_eq!(lookup.body["data"]["num_uses"], 1);
    erase_json(&mut lookup.body);
    Ok(())
}

#[test]
fn native_large_kv2_service_original_actor_expires_after_real_audit() -> TestResult {
    let (files, mut native, key, admin) = initialized()?;
    large_actor_policy(&mut native, &admin);
    activate(&mut native, &admin);
    let bytes = encode(&fixture_bundle(false)?)?;
    let mut issued = call(&mut native, "POST", "auth/token/create", &admin,
        json!({"policies":["large-terminal-sudo"],"no_default_policy":true,"ttl":"2s","explicit_max_ttl":"2s"}));
    assert_eq!(issued.status, 200);
    let actor = Zeroizing::new(issued.body["auth"]["client_token"].as_str().ok_or("actual actor")?.to_owned());
    erase_json(&mut issued.body);
    let original_deadline = Instant::now() + Duration::from_secs(30);
    let mut pending = begin(&mut native, &actor, original_deadline)?;
    let result = pending.execute_native_kv2_large_transfer(&mut &bytes[..]);
    let audit_seen = std::cell::Cell::new(false);
    let response = finish_after_audit(&mut native, *pending, result, || {
        audit_seen.set(true);
        std::thread::sleep(Duration::from_millis(2100));
    })?;
    assert!(audit_seen.get()); assert!(Instant::now() < original_deadline);
    assert_eq!(response.status, 503);
    assert_eq!(response.body["retry_allowed"], false);
    assert_eq!(response.body["recovery_required"], true);
    assert!(response.body.get("auth").is_none()); assert!(response.body.get("data").is_none());
    assert!(response.unwrapped_json.is_none()); assert!(response.consistency_index.is_none());
    assert!(native.recovery_required); assert!(!native.audit_failed);
    let audit = std::fs::read_to_string(files.path.join("audit.jsonl"))?;
    let records = audit.lines().map(serde_json::from_str::<Value>).collect::<Result<Vec<_>, _>>()?;
    let veto = records.last().ok_or("actual delivery veto audit")?;
    let approved = records.iter().rev().nth(1).ok_or("actual response audit")?;
    assert_eq!(approved["event"]["kind"], "response"); assert_eq!(approved["event"]["status"], 204);
    assert_eq!(veto["event"]["kind"], "native-large-kv2-delivery-veto");
    assert_eq!(veto["event"]["status"], 503);
    assert_eq!(approved["event"]["path_digest"], veto["event"]["path_digest"]);
    drop(native);
    let mut native = reopen(&files, &key)?;
    assert_imported(&mut native, &admin, false)?;
    // A late negative response does not undo a committed root or permit a
    // second import. The expired actor also remains unusable after cold reopen.
    let (next, rejected, reads) = upload_http(native, &actor, "secret", &bytes)?;
    native = next; assert_eq!(rejected.status, 403); assert_eq!(reads, 0);
    let (_native, rejected, reads) = upload_http(native, &admin, "secret", &bytes)?;
    assert_eq!(rejected.status, 409); assert_eq!(reads, 0);
    Ok(())
}
