//! Dedicated upload admission and real three-voter native publication.
//! The HTTP parser, immutable stores, pinned TLS peers, snapshot transaction,
//! and cold reopen are real. This does not claim an official OpenBao source,
//! separate physical hosts or SIGKILL: the external controller owns those gates.
#[path = "service_native_v6_ha_published_plan_tests.rs"]
mod published_plan_tests;

use super::*;
use crate::engines::kv2_native_large::{MAX_BUNDLE_BYTES, MEDIA_TYPE, PATH};
use std::io::Read;

const MOUNT: &str = "imported";

struct UploadWire<'a> {
    header: Zeroizing<Vec<u8>>,
    header_offset: usize,
    bytes: &'a [u8],
    offset: usize,
    body_reads: usize,
}

impl Read for UploadWire<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.header_offset < self.header.len() {
            let count = output.len().min(self.header.len() - self.header_offset);
            output[..count]
                .copy_from_slice(&self.header[self.header_offset..self.header_offset + count]);
            self.header_offset += count;
            return Ok(count);
        }
        self.body_reads += 1;
        let count = output.len().min(self.bytes.len() - self.offset);
        output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

fn upload(
    pipeline: &Pipeline,
    index: usize,
    actor: &str,
    bytes: &[u8],
) -> TestResult<(Response, usize)> {
    let service = pipeline.services[index]
        .as_ref()
        .ok_or("upload Service absent")?;
    let mut wire = UploadWire {
        header: Zeroizing::new(format!(
            "POST /v1/{PATH}?mount={MOUNT} HTTP/1.1\r\nHost: fixture\r\nX-Vault-Token: {actor}\r\nContent-Type: {MEDIA_TYPE}\r\nContent-Length: {}\r\n\r\n",
            bytes.len(),
        ).into_bytes()),
        header_offset: 0,
        bytes,
        offset: 0,
        body_reads: 0,
    };
    let until = Instant::now() + REQUEST_BUDGET;
    let response = crate::http::native_large_upload_wire_fixture(service, &mut wire, until)?;
    assert!(
        Instant::now() < until,
        "HA upload retains the original 15-second budget"
    );
    Ok((response, wire.body_reads))
}

fn fixture(payload_bytes: usize) -> TestResult<(Value, Zeroizing<Vec<u8>>)> {
    let mut versions = serde_json::Map::new();
    for number in 1..=19_u64 {
        let payload = char::from(b'a' + number as u8)
            .to_string()
            .repeat(if number <= 2 { 1024 } else { payload_bytes });
        versions.insert(number.to_string(), json!({
            "created_time":format!("1970-01-01T00:01:{:02}.000000113Z",30+number),
            "deletion_time":if number==1 {"1970-01-01T00:03:20.000000113Z"} else {""},
            "source_deletion_time":if number==1 {"1970-01-01T00:05:00.000000113Z"} else {""},
            "destroyed":number==2,
            "data":if number==2 {Value::Null} else {json!({"ordinal":number,"payload":payload,"unicode":"保留"})},
        }));
    }
    let source = json!({
        "schema":"openbao270-kv2-lossless-v1",
        "config":{"max_versions":19,"cas_required":false,"metadata_cas_required":true,"delete_version_after":"0s"},
        "entries":{"history":{
            "created_time":"1970-01-01T00:01:31.000000113Z",
            "updated_time":"1970-01-01T00:01:49.000000113Z",
            "current_version":19,"oldest_version":0,"current_metadata_version":7,
            "max_versions":19,"cas_required":true,"metadata_cas_required":true,
            "delete_version_after":"0s","custom_metadata":{"purpose":"ha-lossless-import"},
            "versions":versions,
        }},
    });
    let bytes = crate::secret_serde::to_vec(&source, MAX_BUNDLE_BYTES)
        .map_err(|_| "HA import fixture encoding")?;
    Ok((source, bytes))
}

fn setup() -> TestResult<(Pipeline, usize)> {
    let mut pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let cloned_v5_seed = pipeline.seed_identity;
    expect(
        pipeline.call(
            leader,
            "POST",
            &format!("sys/mounts/{MOUNT}"),
            pipeline.admin(),
            json!({"type":"kv","options":{"version":"2"}}),
        )?,
        204,
        "HA import pristine mount",
    )?;
    let predecessor = pipeline.with_service(leader, |service| {
        let identity = service
            .current_state_identity()
            .map_err(|_| "actual V5 predecessor")?;
        assert!(matches!(
            identity,
            crate::state_record_root::StateIdentity::RecordsV5(_)
        ));
        assert!(service.record_root.is_some() && service.native_root.is_none());
        Ok(identity)
    })?;
    assert_ne!(
        predecessor, cloned_v5_seed,
        "the extra V5 mount must change the source root"
    );
    // Read-only inspection deliberately leaves both followers at their genuine
    // older V5 roots. No request, prewarming or copied cursor catches them up.
    assert_lagging_v5_followers(&pipeline, leader, cloned_v5_seed)?;
    // native_selection still enforces the exact source digest. Its expectation
    // now describes the observed authoritative V5 root immediately before the
    // real activation, rather than the earlier clone made by Pipeline::start.
    pipeline.seed_identity = predecessor;
    expect(
        pipeline.call(
            leader,
            "POST",
            "sys/internal/native-v6/activate",
            pipeline.admin(),
            json!({}),
        )?,
        204,
        "HA import native activation",
    )?;
    Ok((pipeline, leader))
}

fn assert_lagging_v5_followers(
    pipeline: &Pipeline,
    leader: usize,
    seed: crate::state_record_root::StateIdentity,
) -> TestResult {
    assert!(matches!(
        seed,
        crate::state_record_root::StateIdentity::RecordsV5(_)
    ));
    for peer in 0..3 {
        if peer == leader {
            continue;
        }
        pipeline.with_service(peer, |service| {
            assert_eq!(
                service
                    .current_state_identity()
                    .map_err(|_| "lagging V5 identity")?,
                seed
            );
            assert!(service.record_root.is_some() && service.native_root.is_none());
            Ok(())
        })?;
    }
    Ok(())
}

fn assert_history(pipeline: &Pipeline, index: usize, source: &Value) -> TestResult {
    let metadata = expect(
        pipeline.call(
            index,
            "GET",
            &format!("{MOUNT}/metadata/history"),
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "HA imported metadata",
    )?;
    for key in [
        "created_time",
        "updated_time",
        "current_version",
        "oldest_version",
        "current_metadata_version",
        "max_versions",
        "cas_required",
        "metadata_cas_required",
        "delete_version_after",
        "custom_metadata",
    ] {
        assert_eq!(
            metadata.body["data"][key],
            source["entries"]["history"][key]
        );
    }
    for version in 1..=19 {
        let key = version.to_string();
        let original = &source["entries"]["history"]["versions"][&key];
        for field in ["created_time", "deletion_time", "destroyed"] {
            assert_eq!(
                metadata.body["data"]["versions"][&key][field],
                original[field]
            );
        }
        let response = pipeline.call(
            index,
            "GET",
            &format!("{MOUNT}/data/history"),
            pipeline.admin(),
            json!({"version":version}),
        )?;
        assert_eq!(response.status, if version <= 2 { 404 } else { 200 });
        if version > 2 {
            assert_eq!(response.body["data"]["data"], original["data"]);
        }
    }
    let unchanged = expect(
        pipeline.call(
            index,
            "GET",
            "secret/data/pipeline/history",
            pipeline.admin(),
            json!({"version":1}),
        )?,
        200,
        "unrelated original history",
    )?;
    assert_eq!(unchanged.body["data"]["data"], json!({"value":"seed-v5"}));
    Ok(())
}

fn begin(
    pipeline: &Pipeline,
    index: usize,
    actor: &str,
    until: Instant,
) -> TestResult<Box<PendingExternalRequest>> {
    let service = pipeline.services[index]
        .as_ref()
        .ok_or("begin Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "begin Service lock")?;
    match writer.begin_native_kv2_large_before(
        ServiceRequest::new("POST", PATH, "", actor, json!({"mount":MOUNT})),
        until,
    ) {
        RequestExecution::External(pending) => Ok(pending),
        RequestExecution::Complete(response) => {
            errors_only("HA native-large admission", &response);
            Err(format!("HA native-large admission HTTP {}", response.status).into())
        }
    }
}

fn finish(
    pipeline: &Pipeline,
    index: usize,
    pending: PendingExternalRequest,
    result: ExternalEffectResult,
    until: Instant,
) -> TestResult<Response> {
    let service = pipeline.services[index]
        .as_ref()
        .ok_or("finish Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "finish Service lock")?;
    let response = writer.finish_external_request(pending, result);
    errors_only("HA native-large finalization", &response);
    assert!(writer.native_request_binding.is_none());
    Ok(response)
}

fn snapshot(
    pipeline: &Pipeline,
    index: usize,
    bytes: Option<&[u8]>,
) -> TestResult<(Response, Option<Zeroizing<Vec<u8>>>)> {
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let timing = crate::ha::NativeV6RequestObservation::start(until, "snapshot_test", false);
    let service = pipeline.services[index]
        .as_ref()
        .ok_or("snapshot Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "snapshot Service lock")?;
    let request = ServiceRequest::new(
        if bytes.is_some() { "POST" } else { "GET" },
        "sys/storage/raft/snapshot",
        "",
        pipeline.admin(),
        json!({}),
    );
    let mut pending = match writer.begin_native_snapshot_before(request, until) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(pending)) => pending,
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            errors_only("HA import snapshot admission", &response);
            return Err(format!("HA import snapshot admission HTTP {}", response.status).into());
        }
        NativeSnapshotAdmission::Redirect(_) => {
            return Err("HA import snapshot unexpected redirect".into());
        }
    };
    drop(writer);
    let (result, file) = pending.execute_snapshot_transfer(&mut bytes.unwrap_or(&[]));
    let mut writer = lock_until(service, until).map_err(|_| "snapshot completion lock")?;
    let response = writer.finish_external_request(*pending, result);
    errors_only("HA import snapshot completion", &response);
    timing.finish(Some(response.status));
    drop(writer);
    let output = if let Some(mut file) = file {
        let mut output = Zeroizing::new(Vec::new());
        file.read_to_end(&mut output)?;
        Some(output)
    } else {
        None
    };
    assert!(
        Instant::now() < until,
        "snapshot retains the original 15-second budget"
    );
    Ok((response, output))
}

fn cold_rejoin(pipeline: &mut Pipeline, index: usize) -> TestResult {
    pipeline.start_process(index)?;
    pipeline.wait_cold_native_readindex_ready(index)?;
    pipeline.unseal(index)
}

#[test]
fn native_ha_large_kv2_full34_pre_activation_mount_lagging_v5_follower_kill_restore_cold()
-> TestResult {
    let (mut pipeline, leader) = setup()?;
    let lagging_seed = pipeline.with_service((leader + 1) % 3, |service| {
        Ok(service
            .current_state_identity()
            .map_err(|_| "pre-activation lag fixture")?)
    })?;
    assert_ne!(lagging_seed, pipeline.seed_identity);
    let (source, bytes) = fixture(2 * 1024 * 1024)?;
    assert!(bytes.len() > 34 * 1024 * 1024 && bytes.len() < MAX_BUNDLE_BYTES);
    let (response, reads) = upload(&pipeline, leader, pipeline.admin(), &bytes)?;
    expect(response, 204, "actual full34 native HA import")?;
    assert!(reads > 0);
    assert_history(&pipeline, leader, &source)?;
    let (response, archive) = snapshot(&pipeline, leader, None)?;
    expect(response, 200, "same imported HA snapshot")?;
    let archive = archive.ok_or("HA archive absent")?;
    expect(
        pipeline.call(
            leader,
            "POST",
            &format!("{MOUNT}/data/history"),
            pipeline.admin(),
            json!({"options":{"cas":19},"data":{"later":"must roll back"}}),
        )?,
        200,
        "later import mutation",
    )?;
    let (response, output) = snapshot(&pipeline, leader, Some(&archive))?;
    expect(response, 200, "same imported historical restore")?;
    assert!(output.is_none());
    assert_history(&pipeline, leader, &source)?;
    assert_lagging_v5_followers(&pipeline, leader, lagging_seed)?;
    pipeline.stop_process(leader)?;
    let successor = pipeline.ready_leader()?;
    assert_ne!(successor, leader);
    assert_history(&pipeline, successor, &source)?;
    cold_rejoin(&mut pipeline, leader)?;
    assert_history(&pipeline, leader, &source)?;
    expect(
        pipeline.call(
            successor,
            "POST",
            &format!("{MOUNT}/undelete/history"),
            pipeline.admin(),
            json!({"versions":[1,2]}),
        )?,
        204,
        "undelete imported retained history",
    )?;
    let restored = expect(
        pipeline.call(
            successor,
            "GET",
            &format!("{MOUNT}/data/history"),
            pipeline.admin(),
            json!({"version":1}),
        )?,
        200,
        "imported soft-deleted payload preserved",
    )?;
    assert_eq!(
        restored.body["data"]["data"],
        source["entries"]["history"]["versions"]["1"]["data"]
    );
    expect(
        pipeline.call(
            successor,
            "GET",
            &format!("{MOUNT}/data/history"),
            pipeline.admin(),
            json!({"version":2}),
        )?,
        404,
        "imported destroyed payload stays absent",
    )?;
    let (response, reads) = upload(&pipeline, successor, pipeline.admin(), &bytes)?;
    expect(response, 409, "nonpristine HA import is not replayed")?;
    assert_eq!(reads, 0);
    Ok(())
}

#[test]
fn native_ha_large_kv2_admission_rejects_standby_and_anonymous_without_body() -> TestResult {
    let (pipeline, leader) = setup()?;
    let (_, bytes) = fixture(128)?;
    let before = pipeline.native_selection(leader)?;
    let standby = (leader + 1) % 3;
    let (response, reads) = upload(&pipeline, standby, pipeline.admin(), &bytes)?;
    expect(response, 503, "standby cannot forward an upload query")?;
    assert_eq!(reads, 0);
    let (response, reads) = upload(&pipeline, leader, "", &bytes)?;
    expect(response, 403, "anonymous HA import refusal")?;
    assert_eq!(reads, 0);
    assert_eq!(pipeline.native_selection(leader)?, before);
    pipeline.with_service(leader, |service| {
        assert!(
            !service
                .native_kv2_large_flight
                .load(std::sync::atomic::Ordering::Acquire)
        );
        assert!(!service.recovery_required);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn native_ha_large_kv2_transfer_rejects_changed_source_owner_and_expired_clock() -> TestResult {
    let (pipeline, leader) = setup()?;
    let (_, bytes) = fixture(128)?;
    let until = Instant::now() + REQUEST_BUDGET;
    let mut pending = begin(&pipeline, leader, pipeline.admin(), until)?;
    let result = pending.execute_native_kv2_large_transfer(&mut &bytes[..]);
    expect(
        pipeline.call(
            leader,
            "POST",
            "secret/data/pipeline/history",
            pipeline.admin(),
            json!({"options":{"cas":1},"data":{"value":"unrelated later root"}}),
        )?,
        200,
        "actual source advancement",
    )?;
    let changed = pipeline.native_selection(leader)?;
    expect(
        finish(&pipeline, leader, *pending, result, until)?,
        409,
        "stale upload cannot select later root",
    )?;
    assert_eq!(pipeline.native_selection(leader)?, changed);

    let until = Instant::now() + REQUEST_BUDGET;
    let mut pending = begin(&pipeline, leader, pipeline.admin(), until)?;
    let result = pending.execute_native_kv2_large_transfer(&mut &bytes[..]);
    {
        let service = pipeline.services[leader].as_ref().ok_or("owner Service")?;
        let mut writer = lock_until(service, until).map_err(|_| "owner swap lock")?;
        let original = writer.ha.take();
        writer.ha = pipeline.processes[(leader + 1) % 3].clone();
        let response = writer.finish_external_request(*pending, result);
        writer.ha = original;
        assert_eq!(response.status, 409);
        assert!(writer.native_request_binding.is_none());
    }
    assert_eq!(pipeline.native_selection(leader)?, changed);

    let until = Instant::now() + Duration::from_secs(2);
    let mut pending = begin(&pipeline, leader, pipeline.admin(), until)?;
    let result = pending.execute_native_kv2_large_transfer(&mut &bytes[..]);
    thread::sleep(until.saturating_duration_since(Instant::now()) + Duration::from_millis(10));
    let service = pipeline.services[leader]
        .as_ref()
        .ok_or("expired Service")?;
    let mut writer = service.lock().map_err(|_| "expired completion lock")?;
    let response = writer.finish_external_request(*pending, result);
    assert_eq!(response.status, 503);
    assert!(writer.native_request_binding.is_none());
    drop(writer);
    assert_eq!(pipeline.native_selection(leader)?, changed);
    Ok(())
}

#[test]
fn native_ha_large_kv2_quorum_loss_before_finalization_cannot_publish() -> TestResult {
    let (mut pipeline, leader) = setup()?;
    let (_, bytes) = fixture(128)?;
    let until = Instant::now() + REQUEST_BUDGET;
    let mut pending = begin(&pipeline, leader, pipeline.admin(), until)?;
    let result = pending.execute_native_kv2_large_transfer(&mut &bytes[..]);
    let before = pipeline.with_service(leader, |service| {
        Ok(service
            .current_state_identity()
            .map_err(|_| "before quorum loss root")?)
    })?;
    for peer in 0..3 {
        if peer != leader {
            pipeline.stop_process(peer)?;
        }
    }
    let response = finish(&pipeline, leader, *pending, result, until)?;
    assert!(response.status >= 400);
    pipeline.with_service(leader, |service| {
        assert_eq!(
            service
                .current_state_identity()
                .map_err(|_| "after quorum loss root")?,
            before
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn native_ha_large_kv2_finite_actor_terminal_clock_keeps_affine_successor() -> TestResult {
    let (pipeline, leader) = setup()?;
    let mut issued=expect(pipeline.call(leader,"POST","auth/token/create",pipeline.admin(),
        json!({"policies":["root"],"ttl":"60s","num_uses":2,"no_default_policy":true,"no_parent":true}))?,
        200,"finite-use actual import actor")?;
    let actor = secret_field(&mut issued, "/auth/client_token")?;
    let (source, bytes) = fixture(128)?;
    let (response, reads) = upload(&pipeline, leader, &actor, &bytes)?;
    expect(
        response,
        204,
        "finite actor import and precise terminal successor",
    )?;
    assert!(reads > 0);
    let mut lookup = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/token/lookup",
            pipeline.admin(),
            json!({"token":actor.as_str()}),
        )?,
        200,
        "same original finite actor after import",
    )?;
    assert_eq!(lookup.body["data"]["num_uses"], 1);
    erase_json(&mut lookup.body);
    assert_history(&pipeline, leader, &source)?;
    pipeline.with_service(leader, |service| {
        assert!(!service.recovery_required && !service.audit_failed);
        assert!(service.native_request_binding.is_none());
        Ok(())
    })?;
    Ok(())
}

fn audit_records(path: &std::path::Path) -> TestResult<Vec<Value>> {
    Ok(fs::read_to_string(path)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?)
}

fn assert_uncertain_import(response: &Response) {
    assert_eq!(response.status, 503);
    assert_eq!(response.body["retry_allowed"], false);
    assert_eq!(response.body["recovery_required"], true);
    assert!(response.body.get("data").is_none() && response.body.get("auth").is_none());
    assert!(response.unwrapped_json.is_none());
    assert!(response.consistency_index.is_none());
}

fn committed_identity_before(
    pipeline: &Pipeline,
    index: usize,
    until: Instant,
) -> TestResult<crate::state_record_root::StateIdentity> {
    let _scope = RequestDeadlineScope::enter(until);
    let process = pipeline.processes[index]
        .as_ref()
        .ok_or("committed observation process")?
        .lock_for_request()
        .map_err(|_| "committed observation lock")?;
    let read = process
        .native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("actual committed import absent")?;
    process.verify_native_v6_committed_read(&read)?;
    assert_eq!(
        read.published().migration_source().0,
        pipeline.seed_identity.digest()
    );
    assert!(
        Instant::now() < until,
        "observation retains the original request budget"
    );
    Ok(crate::state_record_root::StateIdentity::RecordsV6(
        read.published().root_digest(),
    ))
}

fn reconcile_committed_refusal(
    pipeline: &mut Pipeline,
    leader: usize,
    source: &Value,
    actor: &str,
    bytes: &[u8],
) -> TestResult {
    pipeline.stop_process(leader)?;
    let successor = pipeline.ready_leader()?;
    assert_ne!(successor, leader);
    assert_history(pipeline, successor, source)?;
    cold_rejoin(pipeline, leader)?;
    assert_history(pipeline, leader, source)?;
    let (response, reads) = upload(pipeline, successor, actor, bytes)?;
    expect(
        response,
        403,
        "expired original actor remains expired after cold reopen",
    )?;
    assert_eq!(reads, 0);
    let (response, reads) = upload(pipeline, successor, pipeline.admin(), bytes)?;
    expect(
        response,
        409,
        "committed import cannot replay after a negative response",
    )?;
    assert_eq!(reads, 0);
    Ok(())
}

#[test]
fn native_ha_large_kv2_two_second_actor_expires_at_local_install_after_actual_commit() -> TestResult
{
    let (mut pipeline, leader) = setup()?;
    let (source, bytes) = fixture(128)?;
    let mut issued = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/token/create",
            pipeline.admin(),
            json!({"policies":["root"],"ttl":"2s","no_default_policy":true,"no_parent":true}),
        )?,
        200,
        "original two-second actual import actor",
    )?;
    let issued_finished = Instant::now();
    let actor = secret_field(&mut issued, "/auth/client_token")?;
    let until = Instant::now() + REQUEST_BUDGET;
    let mut pending = begin(&pipeline, leader, &actor, until)?;
    let result = pending.execute_native_kv2_large_transfer(&mut &bytes[..]);
    let before = pipeline.with_service(leader, |service| {
        Ok(service
            .current_state_identity()
            .map_err(|_| "admitted local import source")?)
    })?;
    let observed = std::rc::Rc::new(std::cell::Cell::new(None));
    let seen = std::rc::Rc::clone(&observed);
    // This observer is bound to the exact prepared import root, and is entered
    // only after its actual quorum/root commit/readback and a successful check
    // of the same original Actor at the first local-install gate. An Auth clock
    // publication after an earlier refusal cannot satisfy that observation.
    // It returns no synthetic denial: the original two-second Actor expires
    // against its unchanged request clock, then the real gate refuses it.
    let observer =
        native_kv2_large::local_install_observer::arm(move |candidate, original_until| {
            assert_eq!(original_until, until);
            assert!(matches!(
                candidate,
                crate::state_record_root::StateIdentity::RecordsV6(_)
            ));
            assert_ne!(candidate, before);
            assert!(
                seen.replace(Some(candidate)).is_none(),
                "one exact local-install observation"
            );
            // The writer just verified actual liveness with the original Actor and
            // clock. Request-start + TTL is not the issuance anchor: the precise
            // grant begins inside real Token API creation, after request admission.
            let expired_after = issued_finished + Duration::from_millis(2100);
            thread::sleep(expired_after.saturating_duration_since(Instant::now()));
            assert!(
                Instant::now() < until,
                "actor expiry never extends the original 15-second request"
            );
        });
    let response = finish(&pipeline, leader, *pending, result, until)?;
    drop(observer);
    let committed = observed.get().ok_or(
        "the real imported-root local-install entry with a live original Actor was never reached",
    )?;
    assert_uncertain_import(&response);
    assert!(
        response.body["recovery_reference"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    pipeline.with_service(leader, |service| {
        assert_eq!(
            service
                .current_state_identity()
                .map_err(|_| "refused local install root")?,
            before
        );
        assert!(service.recovery_required && !service.audit_failed);
        assert!(service.native_request_binding.is_none());
        Ok(())
    })?;
    assert_eq!(
        committed_identity_before(&pipeline, leader, until)?,
        committed
    );
    let audit = audit_records(&pipeline.directory(leader).join("audit.jsonl"))?;
    let last = audit
        .last()
        .ok_or("actual in-install refusal response audit")?;
    assert_eq!(last["event"]["kind"], "response");
    assert_ne!(
        last["event"]["status"], 204,
        "in-install refusal must not masquerade as a post-success-audit veto"
    );
    assert!(
        Instant::now() < until,
        "original two-second expiry regression retains 15 seconds"
    );
    reconcile_committed_refusal(&mut pipeline, leader, &source, &actor, &bytes)
}

#[test]
fn native_ha_large_kv2_terminal_actor_expiry_after_successful_local_install_and_audit() -> TestResult
{
    let (mut pipeline, leader) = setup()?;
    let (source, bytes) = fixture(128)?;
    // This separate Actor is long enough to reach the terminal boundary. The
    // preceding test retains the original two-second regression unchanged;
    // both tests retain the same 15-second request and eight-second ReadIndex.
    let issued_started = Instant::now();
    let mut issued = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/token/create",
            pipeline.admin(),
            json!({"policies":["root"],"ttl":"8s","explicit_max_ttl":"8s",
            "no_default_policy":true,"no_parent":true}),
        )?,
        200,
        "terminal-boundary actual import actor",
    )?;
    let issued_finished = Instant::now();
    let actor = secret_field(&mut issued, "/auth/client_token")?;
    let until = Instant::now() + REQUEST_BUDGET;
    let mut pending = begin(&pipeline, leader, &actor, until)?;
    let result = pending.execute_native_kv2_large_transfer(&mut &bytes[..]);
    let _raw_reply_ingress =
        crate::auth::IngressReplyScope::restore(pending.raw_reply_ingress.clone());
    let PendingExternalRequest {
        fingerprint,
        now,
        token_clock,
        effect,
        ..
    } = *pending;
    let ExternalEffectPlan::NativeKv2Large(plan) = effect else {
        return Err("wrong import effect".into());
    };
    let ExternalEffectResult::NativeKv2Large(result) = result else {
        return Err("wrong import result".into());
    };
    let audit_path = pipeline.directory(leader).join("audit.jsonl");
    let audited = std::cell::Cell::new(false);
    let committed_before_expiry = std::cell::Cell::new(None);
    let mut observation_result: TestResult = Ok(());
    {
        let service = pipeline.services[leader]
            .as_ref()
            .ok_or("terminal Service")?;
        let mut writer = lock_until(service, until).map_err(|_| "terminal audit lock")?;
        let response = writer.complete_native_kv2_large_with_receipt(
            *plan,
            result,
            &fingerprint,
            (now, token_clock),
            || {
                observation_result = (|| -> TestResult {
                    let records = audit_records(&audit_path)?;
                    let approved = records.last().ok_or("actual response audit present")?;
                    assert_eq!(approved["event"]["kind"], "response");
                    assert_eq!(
                        approved["event"]["status"], 204,
                        "terminal veto requires actual commit, local install and success audit first"
                    );
                    assert!(
                        approved["event"]["path_digest"]
                            .as_str()
                            .is_some_and(|value| !value.is_empty())
                    );
                    let actual = committed_identity_before(&pipeline, leader, until)?;
                    committed_before_expiry.set(Some(actual));
                    assert!(
                        Instant::now() < issued_started + Duration::from_secs(8),
                        "the original terminal Actor must still be live before waiting"
                    );
                    audited.set(true);
                    let expired_after = issued_finished + Duration::from_millis(8100);
                    thread::sleep(expired_after.saturating_duration_since(Instant::now()));
                    assert!(
                        Instant::now() < until,
                        "terminal expiry retains the original 15-second request"
                    );
                    Ok(())
                })();
            },
        );
        observation_result?;
        assert!(audited.get());
        assert_uncertain_import(&response);
        assert!(writer.recovery_required && !writer.audit_failed);
        assert!(writer.native_request_binding.is_none());
        assert_eq!(
            writer
                .current_state_identity()
                .map_err(|_| "terminal selected import")?,
            committed_before_expiry
                .get()
                .ok_or("terminal commit observation absent")?
        );
    }
    assert_eq!(
        committed_identity_before(&pipeline, leader, until)?,
        committed_before_expiry
            .get()
            .ok_or("terminal commit observation absent")?
    );
    let audit = audit_records(&audit_path)?;
    let veto = audit.last().ok_or("actual terminal delivery-veto audit")?;
    let approved = audit
        .iter()
        .rev()
        .nth(1)
        .ok_or("actual preceding successful audit")?;
    assert_eq!(approved["event"]["kind"], "response");
    assert_eq!(approved["event"]["status"], 204);
    assert_eq!(veto["event"]["kind"], "native-large-kv2-delivery-veto");
    assert_eq!(veto["event"]["status"], 503);
    assert_eq!(
        approved["event"]["path_digest"],
        veto["event"]["path_digest"]
    );
    assert!(
        Instant::now() < until,
        "the terminal veto does not renew request custody"
    );
    reconcile_committed_refusal(&mut pipeline, leader, &source, &actor, &bytes)
}

#[test]
fn native_ha_large_kv2_cold_v5_lagger_unseals_through_exact_predecessor_after_import() -> TestResult
{
    let mut pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let cold = (leader + 1) % 3;
    let cloned_v5_seed = pipeline.seed_identity;
    expect(
        pipeline.call(
            leader,
            "POST",
            &format!("sys/mounts/{MOUNT}"),
            pipeline.admin(),
            json!({"type":"kv","options":{"version":"2"}}),
        )?,
        204,
        "cold-lagger later V5 mount",
    )?;
    let predecessor = pipeline.with_service(leader, |service| {
        let identity = service
            .current_state_identity()
            .map_err(|_| "cold-lagger actual V5 predecessor")?;
        assert!(matches!(
            identity,
            crate::state_record_root::StateIdentity::RecordsV5(_)
        ));
        assert!(service.record_root.is_some() && service.native_root.is_none());
        Ok(identity)
    })?;
    assert_ne!(predecessor, cloned_v5_seed);
    assert_lagging_v5_followers(&pipeline, leader, cloned_v5_seed)?;
    pipeline.seed_identity = predecessor;
    // Stop the real process and Service while this node's local root is still
    // the older V5 clone. It never activates native storage before this stop.
    pipeline.stop_process(cold)?;
    assert!(pipeline.services[cold].is_none() && pipeline.processes[cold].is_none());
    expect(
        pipeline.call(
            leader,
            "POST",
            "sys/internal/native-v6/activate",
            pipeline.admin(),
            json!({}),
        )?,
        204,
        "two-live-voter activation with a cold V5 lagger",
    )?;
    let (source, bytes) = fixture(128)?;
    let (response, reads) = upload(&pipeline, leader, pipeline.admin(), &bytes)?;
    expect(response, 204, "two-live-voter import with a cold V5 lagger")?;
    assert!(reads > 0);
    assert_history(&pipeline, leader, &source)?;

    // Reuse the unchanged physical directory and actual Shamir unseal path.
    // The initial local root has no native cursors; load_cold_native_ha returns
    // None for V5, so ordinary unseal's subsequent sync must perform the bridge.
    cold_rejoin(&mut pipeline, cold)?;
    assert_history(&pipeline, cold, &source)?;
    let selected = pipeline.native_selection(cold)?;
    assert_eq!(selected, pipeline.native_selection(leader)?);
    pipeline.with_service(cold, |service| {
        assert_eq!(
            service
                .current_state_identity()
                .map_err(|_| "cold-lagger selected native root")?,
            crate::state_record_root::StateIdentity::RecordsV6(selected.1)
        );
        assert!(service.record_root.is_none() && service.native_root.is_some());
        assert!(!service.recovery_required && !service.audit_failed);
        assert!(service.native_candidate_profile.is_none());
        Ok(())
    })?;
    Ok(())
}

#[path = "service_native_v6_ha_migration_negative_tests.rs"]
mod predecessor_negative_tests;

// Independent deterministic scheduling regression. This selector deliberately
// does not match any of the original fixed108 selectors or replace its failure.
#[test]
fn extra_terminal_floor_generated_checkpoint_reselection_commits_one_affine_successor() -> TestResult
{
    let (pipeline, leader) = setup()?;
    let mut issued = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/token/create",
            pipeline.admin(),
            json!({"policies":["root"],"ttl":"60s","num_uses":2,
                "no_default_policy":true,"no_parent":true}),
        )?,
        200,
        "checkpoint diagnostic finite actor",
    )?;
    let actor = secret_field(&mut issued, "/auth/client_token")?;
    let (source, bytes) = fixture(128)?;
    let (response, reads) = upload(&pipeline, leader, &actor, &bytes)?;
    expect(
        response,
        204,
        "checkpoint diagnostic original finite import",
    )?;
    assert!(reads > 0);
    let mut lookup = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/token/lookup",
            pipeline.admin(),
            json!({"token":actor.as_str()}),
        )?,
        200,
        "checkpoint diagnostic unchanged finite actor",
    )?;
    assert_eq!(lookup.body["data"]["num_uses"], 1);
    erase_json(&mut lookup.body);

    // Enter the actual terminal writer with a fresh trusted ingress clock and
    // the SAME production fifteen-second bound. The checkpoint only advances
    // durable Raft storage generation; no request time is frozen or replaced.
    let started = Instant::now();
    let until = started + REQUEST_BUDGET;
    let wall = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let clock = RequestClock::anchored(wall, started)?;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[leader]
        .as_ref()
        .ok_or("checkpoint diagnostic Service absent")?;
    let process = pipeline.processes[leader]
        .as_ref()
        .ok_or("checkpoint diagnostic process absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "checkpoint Service lock")?;
    let before = writer
        .current_state_identity()
        .map_err(|_| "checkpoint source identity")?;
    let before_generation = writer
        .external_effect_generation()
        .map_err(|_| "checkpoint source publication generation")?;
    let old_floor = writer
        .state
        .as_ref()
        .ok_or("checkpoint source state")?
        .auth
        .terminal_token_clock_floor();
    assert!(old_floor.is_some());
    let probe = process
        .lock_for_request()
        .map_err(|_| "checkpoint arm lock")?
        .arm_native_checkpoint_reselection_probe()?;
    let receipt = writer
        .persist_terminal_token_clock_with_receipt(Some(clock), wall.as_secs(), true)
        .map_err(|response| {
            format!(
                "checkpoint reselection floor refused with status {}",
                response.status
            )
        })?
        .ok_or("checkpoint reselection did not issue an affine terminal receipt")?;
    let after = writer
        .current_state_identity()
        .map_err(|_| "checkpoint successor source")?;
    let after_generation = writer
        .external_effect_generation()
        .map_err(|_| "checkpoint successor publication generation")?;
    assert_ne!(after, before);
    let new_floor = writer
        .state
        .as_ref()
        .ok_or("checkpoint successor state")?
        .auth
        .terminal_token_clock_floor();
    assert!(new_floor > old_floor);
    let mut checkpoint = Some((before, before_generation));
    receipt
        .advance_native_auth(&mut checkpoint)
        .map_err(|_| "checkpoint actual affine successor was refused")?;
    assert_eq!(checkpoint, Some((after, after_generation)));
    assert!(!writer.recovery_required && !writer.audit_failed);
    assert_eq!(clock.started(), started);
    assert!(Instant::now() < until);

    // The controlled checkpoint still rejected the old witness. Only the new
    // production read branch continued, without a second Stage or root CAS.
    let evidence = process
        .lock_for_request()
        .map_err(|_| "checkpoint finish lock")?
        .finish_native_checkpoint_reselection_probe(probe)?;
    assert_eq!(evidence.stage_calls, 1);
    assert_eq!(evidence.root_calls, 1);
    assert_eq!(evidence.reselection_calls, 1);
    assert!(evidence.after_generation > evidence.before_generation);
    assert_eq!(evidence.snapshot_index, evidence.staged_index);
    assert_eq!(evidence.published_index, evidence.staged_index + 1);
    assert!(evidence.old_witness_refused);
    assert!(evidence.fresh_exact_intent_admitted);
    assert!(evidence.source_and_membership_unchanged && evidence.original_deadline_live);
    assert!(evidence.original_read_bound_preserved);
    assert_eq!(
        writer
            .current_state_identity()
            .map_err(|_| "checkpoint final source")?,
        after
    );
    assert_eq!(
        writer
            .state
            .as_ref()
            .ok_or("checkpoint final state")?
            .auth
            .terminal_token_clock_floor(),
        new_floor
    );
    assert!(Instant::now() < until);
    drop(writer);
    drop(_scope);
    assert_history(&pipeline, leader, &source)?;
    let mut lookup = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/token/lookup",
            pipeline.admin(),
            json!({"token":actor.as_str()}),
        )?,
        200,
        "checkpoint keeps original finite actor",
    )?;
    assert_eq!(lookup.body["data"]["num_uses"], 1);
    erase_json(&mut lookup.body);
    eprintln!(
        "HBHA-TEST-CHECKPOINT-RESELECTION evidence={evidence:?} floor_committed=true mutation_replayed=false original_request_budget_seconds=15"
    );
    Ok(())
}
