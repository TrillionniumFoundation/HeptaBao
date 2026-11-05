//! Formal storage profile, real three-voter mTLS/Raft and owned loopback API
//! TLS listeners use the actual parser, Service and response writer. Production
//! serve startup and physical-host qualification remain separate.
use super::*;
#[path = "service_native_v6_ha_formal_api_pipeline_tests.rs"]
mod formal_api_pipeline;
use crate::crypto::AeadBarrier;
use crate::ha::native_v6_backup::{NativeV6ArchiveSelection, validate_native_v6_archive};
use crate::snapshot_file::SnapshotSpool;
use formal_api_pipeline::{FormalApiPipeline, formal_api_source};
use heptabao_durable_service::Barrier;

struct WireReply {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Zeroizing<Vec<u8>>,
}

#[derive(Default)]
struct WireRouting<'a> {
    no_forward: Option<&'a str>,
    inconsistent: Option<&'a str>,
    missing_forward: bool,
}

fn wire(
    pipeline: &FormalApiPipeline,
    index: usize,
    method: &str,
    path: &str,
    token: &str,
    body: &[u8],
    no_forward: Option<&str>,
) -> TestResult<WireReply> {
    wire_with_routing(
        pipeline,
        index,
        method,
        path,
        token,
        body,
        WireRouting {
            no_forward,
            ..WireRouting::default()
        },
    )
}

fn wire_with_routing(
    pipeline: &FormalApiPipeline,
    index: usize,
    method: &str,
    path: &str,
    token: &str,
    body: &[u8],
    routing: WireRouting<'_>,
) -> TestResult<WireReply> {
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let mut input = Zeroizing::new(Vec::new());
    write!(
        &mut *input,
        "{method} /v1/{path} HTTP/1.1\r\nHost: local\r\nConnection: close\r\n"
    )?;
    if !token.is_empty() {
        write!(&mut *input, "X-Vault-Token: {token}\r\n")?;
    }
    if let Some(value) = routing.no_forward {
        write!(&mut *input, "X-Vault-No-Request-Forwarding: {value}\r\n")?;
    }
    if let Some(value) = routing.inconsistent {
        write!(&mut *input, "X-Vault-Inconsistent: {value}\r\n")?;
    }
    if matches!(method, "POST" | "PUT") {
        write!(
            &mut *input,
            "Content-Type: {}\r\nContent-Length: {}\r\n",
            if path.starts_with("sys/storage/raft/snapshot") {
                "application/octet-stream"
            } else {
                "application/json"
            },
            body.len()
        )?;
    }
    input.extend_from_slice(b"\r\n");
    input.extend_from_slice(body);
    let output = pipeline.exchange(index, &input, until, routing.missing_forward)?;
    let split = output
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .ok_or("formal wire response header truncated")?;
    let text = std::str::from_utf8(&output[..split])?;
    let mut lines = text.split("\r\n");
    let line = lines.next().ok_or("formal wire status absent")?;
    assert!(line.starts_with("HTTP/1.1 "));
    let status = line
        .split(' ')
        .nth(1)
        .ok_or("formal wire status malformed")?
        .parse()?;
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("formal wire header malformed")?;
        assert!(
            headers
                .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                .is_none()
        );
    }
    let body = Zeroizing::new(output[split + 4..].to_vec());
    if let Some(length) = headers.get("content-length") {
        assert_eq!(
            if method == "HEAD" {
                0
            } else {
                length.parse::<usize>()?
            },
            body.len()
        );
    } else {
        assert_eq!(
            status, 204,
            "these bounded fixture responses require complete framing"
        );
        assert!(body.is_empty());
    }
    assert!(
        Instant::now() < until,
        "formal wire retains the original request budget"
    );
    Ok(WireReply {
        status,
        headers,
        body,
    })
}

fn redirected(reply: &WireReply) {
    assert_eq!(reply.status, 307);
    assert_eq!(
        reply.headers.get("content-length").map(String::as_str),
        Some("0")
    );
    assert!(
        reply
            .headers
            .get("location")
            .is_some_and(|value| value.starts_with("https://"))
    );
    assert!(reply.body.is_empty());
}

#[test]
fn formal_native_standby_snapshot_read_restore_validation_and_no_forward_use_real_owners()
-> TestResult {
    let pipeline = formal_api_source()?;
    let leader = pipeline.ready_leader()?;
    activate_formal_cold(&pipeline, leader)?;
    let standby = (leader + 1) % 3;
    let original = pipeline.native_selection(leader)?;
    let reply = wire(
        &pipeline,
        standby,
        "GET",
        SNAPSHOT,
        pipeline.admin(),
        b"",
        None,
    )?;
    assert_eq!(reply.status, 200);
    assert!(reply.body.starts_with(&[0x1f, 0x8b]));
    assert_eq!(pipeline.native_selection(leader)?, original);
    pipeline.with_service(standby, |service| {
        assert!(matches!(
            service.native_storage_profile,
            Some(crate::configuration::NativeStorageProfile::Raft)
        ));
        assert!(service.native_candidate_profile.is_none());
        assert!(service.native_root.is_some());
        assert!(
            !service
                .state
                .as_ref()
                .ok_or("formal standby state")?
                .has_token_api_precision_state()
        );
        assert!(service.native_request_binding.is_none());
        Ok(())
    })?;

    // Authenticate the returned real archive against a separately obtained
    // current Raft selection and the actual local barrier/seal owner.
    {
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let directory = pipeline.files.path.join("standby-archive-verification");
        private_directory(&directory)?;
        let spool = SnapshotSpool::open(&directory)?;
        let lease = spool.lease()?;
        let mut archive = lease.file(crate::snapshot_file::MAX_NATIVE_ARCHIVE, until)?;
        archive.write_all(&reply.body)?;
        let imported = crate::snapshot_archive::import(archive, &lease, until)?;
        assert!(imported.metadata.is_v6_ha());
        let (barrier, expected_seal) = pipeline.with_service(standby, |service| {
            let barrier =
                AeadBarrier::new(**service.barrier_key.as_ref().ok_or("actual barrier")?)?;
            let seal = crate::service::snapshot_transfer::canonical_seal_identity(
                service.seal.as_ref().ok_or("actual seal")?,
            )?;
            Ok((barrier, seal))
        })?;
        assert_eq!(
            barrier.open(
                crate::snapshot_archive::CHECKSUM_CONTEXT,
                &imported.sealed_sums
            )?,
            imported.sums
        );
        let process = pipeline.processes[standby]
            .as_ref()
            .ok_or("actual standby process")?
            .lock_for_request()
            .map_err(|_| "standby archive ReadIndex")?;
        let selected = process
            .native_v6_committed_read(OriginalDeadline::capture()?)?
            .ok_or("standby archive selected root")?;
        let selection =
            NativeV6ArchiveSelection::from_committed(selected.enrollment(), selected.published())?;
        let verified = validate_native_v6_archive(
            imported.state,
            &selection,
            expected_seal,
            &barrier,
            OriginalDeadline::capture()?,
            &mut || Ok(()),
        )?;
        assert!(verified.report().shared_object_count > 0);
        process.verify_native_v6_committed_read(&selected)?;
    }

    for header in ["1", "false"] {
        let read = wire(
            &pipeline,
            standby,
            "GET",
            "secret/data/pipeline/history",
            pipeline.admin(),
            b"",
            Some(header),
        )?;
        assert_eq!(read.status, 200);
        let value: Value = serde_json::from_slice(&read.body)?;
        assert_eq!(value["data"]["data"]["value"], "seed-v5");
        let refused = wire(
            &pipeline,
            standby,
            "POST",
            "secret/data/no-forward-owned",
            pipeline.admin(),
            br#"{"options":{"cas":0},"data":{"value":"must-not-write"}}"#,
            Some(header),
        )?;
        redirected(&refused);
        expect(
            pipeline.call(
                leader,
                "GET",
                "secret/data/no-forward-owned",
                pipeline.admin(),
                json!({}),
            )?,
            404,
            "no-forward-has-no-write",
        )?;
    }
    for token in ["", "invalid-standby-token"] {
        redirected(&wire(
            &pipeline, standby, "GET", SNAPSHOT, token, b"", None,
        )?);
    }
    for path in [SNAPSHOT, "sys/storage/raft/snapshot-force"] {
        let before = pipeline.native_selection(leader)?;
        let invalid = wire(
            &pipeline,
            standby,
            "POST",
            path,
            pipeline.admin(),
            b"not-gzip",
            None,
        )?;
        assert_eq!(
            invalid.status, 500,
            "actual archive parser has precedence over redirect"
        );
        let valid = wire(
            &pipeline,
            standby,
            "POST",
            path,
            pipeline.admin(),
            &reply.body,
            None,
        )?;
        redirected(&valid);
        assert_eq!(
            pipeline.native_selection(leader)?,
            before,
            "standby validation cannot publish an archive, clock-free state, or restore epoch"
        );
    }
    assert_eq!(pipeline.native_selection(leader)?, original);
    Ok(())
}

#[test]
fn formal_native_standby_snapshot_finite_tokens_redirect_without_consumption() -> TestResult {
    let pipeline = formal_api_source()?;
    let leader = pipeline.ready_leader()?;
    activate_formal_cold(&pipeline, leader)?;
    let standby = (leader + 1) % 3;
    for uses in [1, 2] {
        let mut issued = expect(
            pipeline.call(
                leader,
                "POST",
                "auth/token/create",
                pipeline.admin(),
                json!({"policies":["root"],"ttl":"60s","num_uses":uses,
                "no_default_policy":true,"no_parent":true}),
            )?,
            200,
            "standby-finite-root",
        )?;
        let token = secret_field(&mut issued, "/auth/client_token")?;
        for (method, body, header) in [
            ("GET", &b""[..], None),
            ("GET", &b""[..], Some("false")),
            ("POST", &b"not-gzip"[..], None),
        ] {
            let before = pipeline.native_selection(leader)?;
            redirected(&wire(
                &pipeline, standby, method, SNAPSHOT, &token, body, header,
            )?);
            assert_eq!(
                pipeline.native_selection(leader)?,
                before,
                "routing a finite token must not consume or publish a floor"
            );
            let lookup = expect(
                pipeline.call(
                    leader,
                    "POST",
                    "auth/token/lookup",
                    pipeline.admin(),
                    json!({"token":token.as_str()}),
                )?,
                200,
                "standby-finite-remaining",
            )?;
            assert_eq!(lookup.body["data"]["num_uses"], uses);
        }
    }
    Ok(())
}

#[test]
fn formal_native_standby_snapshot_late_root_change_and_lost_quorum_refuse_delivery() -> TestResult {
    let mut pipeline = formal_api_source()?;
    let leader = pipeline.ready_leader()?;
    activate_formal_cold(&pipeline, leader)?;
    let standby = (leader + 1) % 3;
    {
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let service = pipeline.services[standby]
            .as_ref()
            .ok_or("late-root standby")?;
        let mut writer = lock_until(service, until).map_err(|_| "late-root admission")?;
        let mut pending = admit(&mut writer, "GET", pipeline.admin(), until)?;
        drop(writer);
        let (observation, archive) = pending.execute_snapshot_transfer(&mut io::empty());
        assert!(
            archive.is_some(),
            "archive exists only privately before completion"
        );
        expect(
            pipeline.call(
                leader,
                "POST",
                "secret/data/pipeline/history",
                pipeline.admin(),
                json!({"options":{"cas":1},"data":{"value":"changed-before-finalization"}}),
            )?,
            200,
            "standby-snapshot-racing-write",
        )?;
        let mut writer = lock_until(service, until).map_err(|_| "late-root completion")?;
        let refusal = writer.finish_external_request(*pending, observation);
        assert!(matches!(refusal.status, 409 | 503));
        assert!(refusal.body.get("data").is_none());
        drop((writer, archive));
    }
    for index in (0..3).filter(|index| *index != standby) {
        pipeline.stop_process(index)?;
    }
    let refused = wire(
        &pipeline,
        standby,
        "GET",
        SNAPSHOT,
        pipeline.admin(),
        b"",
        None,
    )?;
    assert_eq!(refused.status, 503);
    assert!(!refused.body.starts_with(&[0x1f, 0x8b]));
    Ok(())
}

#[test]
fn formal_native_standby_ttl_snapshot_commits_real_leader_floor_and_survives_cold_restart()
-> TestResult {
    let mut pipeline = formal_api_source()?;
    let leader = pipeline.ready_leader()?;
    activate_formal_cold(&pipeline, leader)?;
    let standby = (leader + 1) % 3;
    let token = root_token(&pipeline, leader, "60s")?;
    let before = pipeline.native_selection(leader)?;
    let before_floor = pipeline
        .with_service(leader, |service| {
            Ok(service
                .state
                .as_ref()
                .ok_or("leader precision state")?
                .auth
                .terminal_token_clock_floor())
        })?
        .ok_or("leader actual precision floor")?;
    let downloaded = wire(&pipeline, standby, "GET", SNAPSHOT, &token, b"", None)?;
    assert_eq!(downloaded.status, 200);
    assert!(downloaded.body.starts_with(&[0x1f, 0x8b]));
    let after = pipeline.native_selection(leader)?;
    assert_eq!(after.0, before.0 + 1, "one actual clock-only publication");
    assert_ne!(after.1, before.1);
    let floor = pipeline
        .with_service(leader, |service| {
            Ok(service
                .state
                .as_ref()
                .ok_or("leader terminal state")?
                .auth
                .terminal_token_clock_floor())
        })?
        .ok_or("leader committed clock floor")?;
    assert!(floor > before_floor);
    assert_eq!(
        pipeline.with_service(standby, |service| Ok(service
            .state
            .as_ref()
            .ok_or("standby applied state")?
            .auth
            .terminal_token_clock_floor()))?,
        Some(floor)
    );
    assert_eq!(pipeline.native_selection(standby)?, after);
    pipeline.stop_process(standby)?;
    pipeline.start_formal_process(standby)?;
    pipeline.wait_cold_native_readindex_ready(standby)?;
    pipeline.unseal(standby)?;
    assert!(
        pipeline
            .with_service(standby, |service| Ok(service
                .state
                .as_ref()
                .ok_or("cold standby state")?
                .auth
                .terminal_token_clock_floor()))?
            .is_some_and(|cold| cold >= floor)
    );
    let second = wire(
        &pipeline,
        standby,
        "GET",
        SNAPSHOT,
        &token,
        b"",
        Some("false"),
    )?;
    assert_eq!(second.status, 200);
    expect(
        pipeline.call(
            leader,
            "POST",
            "auth/token/revoke",
            pipeline.admin(),
            json!({"token":token.as_str()}),
        )?,
        204,
        "standby-ttl-revoke",
    )?;
    redirected(&wire(
        &pipeline, standby, "GET", SNAPSHOT, &token, b"", None,
    )?);
    Ok(())
}

#[test]
fn formal_native_standby_snapshot_missing_api_origin_remains_503() -> TestResult {
    // Retain the exact old configuration as an independent refusal. No origin
    // is synthesized and no permission, archive or transfer lease is created.
    let pipeline = formal_cold_source()?;
    assert!(
        pipeline
            .configs
            .iter()
            .all(|config| config.peers.values().all(|peer| peer.api_address.is_none()))
    );
    let leader = pipeline.ready_leader()?;
    activate_formal_cold(&pipeline, leader)?;
    let standby = (leader + 1) % 3;
    let before = pipeline.native_selection(leader)?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let mut input = Zeroizing::new(Vec::new());
    write!(
        &mut *input,
        "GET /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: local\r\nX-Vault-Token: {}\r\nConnection: close\r\n\r\n",
        pipeline.admin()
    )?;
    let service = pipeline.services[standby]
        .as_ref()
        .ok_or("missing API Service")?;
    let output = crate::http::formal_standby_http_wire_fixture(service, &input, until)?;
    let split = output
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .ok_or("missing API response framing")?;
    let header = std::str::from_utf8(&output[..split])?;
    assert!(header.starts_with("HTTP/1.1 503 "));
    let body: Value = serde_json::from_slice(&output[split + 4..])?;
    assert_eq!(
        body["errors"],
        json!(["HA leader API address is unavailable"])
    );
    assert!(body.get("data").is_none());
    pipeline.with_service(standby, |service| {
        assert!(service.pending_snapshot_transfer.is_none());
        assert!(service.pending_native_auth_delivery.is_none());
        assert!(service.native_request_binding.is_none());
        Ok(())
    })?;
    assert_eq!(pipeline.native_selection(leader)?, before);
    assert!(Instant::now() < until);
    Ok(())
}

#[path = "service_native_v6_ha_snapshot_acl_tests.rs"]
mod acl_denial_tests;
