//! Normal NativeV6Raft remount with actual process-local OpenRaft, mTLS,
//! forwarded ACK, original accepted worker, ReadIndex and cold owners.
//! This does not claim physical-host SIGKILL or public HTTPS socket coverage.
use super::*;

fn accepted_loopback_peer(
    until: Instant,
) -> TestResult<(std::net::TcpStream, std::net::TcpStream, std::net::IpAddr)> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let remaining = until
        .checked_duration_since(Instant::now())
        .ok_or("remount actual peer original deadline expired")?;
    let client = std::net::TcpStream::connect_timeout(&listener.local_addr()?, remaining)?;
    let (accepted, peer) = listener.accept()?;
    assert_eq!(peer, client.local_addr()?);
    assert_eq!(accepted.peer_addr()?, peer);
    if Instant::now() >= until {
        return Err("remount actual peer original deadline expired".into());
    }
    Ok((client, accepted, peer.ip()))
}

impl WrappingPipeline {
    fn remount_peer_call(
        &self,
        node: usize,
        method: &str,
        path: &str,
        token: &str,
        body: Value,
    ) -> TestResult<Response> {
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        // Only this test's Service boundary is in-process. Its peer address
        // comes from a real loopback accept, never a header or a claimed
        // public HTTPS connection. Production mTLS forwarding stays unchanged.
        let (_client, _accepted, peer) = accepted_loopback_peer(until)?;
        let service = self.services[node]
            .as_ref()
            .ok_or("actual remount Service absent")?;
        let mut writer =
            lock_until(service, until).map_err(|_| "original remount Service lock deadline")?;
        let ingress = crypto::random::<16>().map_err(std::io::Error::other)?;
        let _ingress = crate::auth::IngressReplyScope::listener(&ingress);
        let execution = writer.begin_request_before(
            ServiceRequest {
                method,
                path,
                namespace: "",
                token,
                body,
                wrap_ttl_seconds: None,
                origin_peer: Some(peer),
                client_certificates: None,
            },
            until,
            false,
        );
        let response = writer.finish_synchronous_request(execution);
        if Instant::now() >= until {
            return Err("formal remount original 15-second request exceeded".into());
        }
        assert!(writer.pending_native_auth_delivery.is_none());
        assert!(writer.pending_ordinary_kv_authority.is_none());
        Ok(response)
    }
}

fn remount_history(
    pipeline: &WrappingPipeline,
    node: usize,
    mount: &str,
    expected: &[(u64, &str)],
) -> TestResult<Value> {
    for (version, value) in expected {
        let response = expect(
            pipeline.remount_peer_call(
                node,
                "GET",
                &format!("{mount}/data/pipeline/history"),
                pipeline.admin(),
                json!({"version":version}),
            )?,
            200,
            "formal-remount-retained-history",
        )?;
        assert_eq!(response.body["data"]["metadata"]["version"], *version);
        assert_eq!(
            response.body["data"]["data"]["value"].as_str(),
            Some(*value)
        );
    }
    let metadata = expect(
        pipeline.remount_peer_call(
            node,
            "GET",
            &format!("{mount}/metadata/pipeline/history"),
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "formal-remount-history-metadata",
    )?;
    let retained = expect(
        pipeline.remount_peer_call(
            node,
            "GET",
            "keep/data/sentinel",
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "formal-remount-unrelated-graph",
    )?;
    assert_eq!(
        retained.body["data"]["data"],
        json!({"kept":"actual-raft-unrelated-owner"})
    );
    pipeline.with_service(node, |service| {
        assert!(matches!(
            service.native_storage_profile,
            Some(NativeStorageProfile::Raft)
        ));
        assert!(service.native_candidate_profile.is_none());
        assert!(service.native_root.is_some() && service.record_root.is_none());
        assert!(!service.recovery_required && !service.audit_failed);
        assert!(service.native_request_binding.is_none());
        Ok(())
    })?;
    Ok(metadata.body["data"].clone())
}

fn remount_setup(pipeline: &WrappingPipeline, follower: usize) -> TestResult {
    for (version, value) in [
        (2_u64, "native-before-move-v2"),
        (3, "native-before-move-v3"),
    ] {
        let response = expect(
            pipeline.remount_peer_call(
                follower,
                "POST",
                "secret/data/pipeline/history",
                pipeline.admin(),
                json!({"data":{"value":value},"options":{"cas":version-1}}),
            )?,
            200,
            "formal-remount-source-native-CAS",
        )?;
        assert_eq!(response.body["data"]["version"], version);
    }
    expect(
        pipeline.remount_peer_call(
            follower,
            "POST",
            "sys/mounts/keep",
            pipeline.admin(),
            json!({"type":"kv","options":{"version":"2"}}),
        )?,
        204,
        "formal-remount-unrelated-mount",
    )?;
    expect(
        pipeline.remount_peer_call(
            follower,
            "POST",
            "keep/data/sentinel",
            pipeline.admin(),
            json!({"data":{"kept":"actual-raft-unrelated-owner"},"options":{"cas":0}}),
        )?,
        200,
        "formal-remount-unrelated-value",
    )?;
    expect(
        pipeline.remount_peer_call(
            follower,
            "POST",
            "sys/quotas/rate-limit/ha-remount",
            pipeline.admin(),
            json!({"path":"secret/data/pipeline/history","rate":1000,"interval":"60s"}),
        )?,
        204,
        "formal-remount-source-quota",
    )?;
    Ok(())
}

fn quota_path(pipeline: &WrappingPipeline, node: usize, expected: &str) -> TestResult {
    let response = expect(
        pipeline.remount_peer_call(
            node,
            "GET",
            "sys/quotas/rate-limit/ha-remount",
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "formal-remount-persisted-quota",
    )?;
    assert_eq!(response.body["data"]["path"], expected);
    Ok(())
}

fn accept_and_execute_once(
    pipeline: &WrappingPipeline,
    follower: usize,
    original_leader: usize,
) -> TestResult<String> {
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let (_client, _accepted, peer) = accepted_loopback_peer(until)?;
    let response = {
        let service = pipeline.services[follower]
            .as_ref()
            .ok_or("actual follower Service absent")?;
        let mut writer =
            lock_until(service, until).map_err(|_| "original remount ingress lock deadline")?;
        let ingress = crypto::random::<16>().map_err(std::io::Error::other)?;
        let _ingress = crate::auth::IngressReplyScope::listener(&ingress);
        let execution = writer.begin_request_before(
            ServiceRequest {
                method: "POST",
                path: "sys/remount",
                namespace: "",
                token: pipeline.admin(),
                body: json!({"from":"secret/","to":"moved/"}),
                wrap_ttl_seconds: None,
                origin_peer: Some(peer),
                client_certificates: None,
            },
            until,
            false,
        );
        let response = writer.finish_synchronous_request(execution);
        assert!(
            writer.native_remount_jobs.is_empty(),
            "follower must not own the forwarded task"
        );
        assert!(writer.native_request_binding.is_none());
        response
    };
    let response = expect(response, 200, "formal-remount-actual-forwarded-ACK")?;
    let id = response.body["data"]["migration_id"]
        .as_str()
        .ok_or("actual migration id absent")?
        .to_owned();
    {
        let service = pipeline.services[original_leader]
            .as_ref()
            .ok_or("original leader Service absent")?;
        let mut writer =
            lock_until(service, until).map_err(|_| "original remount worker lock deadline")?;
        assert_eq!(writer.native_remount_jobs.len(), 1);
        // The production task re-enters its own original forwarded deadline.
        // This test neither replaces that private deadline nor moves the task
        // to another leader/owner, and never retries a failed execution.
        assert!(writer.maintain_native_remounts());
        assert!(!writer.maintain_native_remounts());
        assert!(writer.native_remount_jobs.is_empty());
        assert!(!writer.recovery_required && !writer.audit_failed);
        assert!(writer.native_request_binding.is_none());
    }
    if Instant::now() >= until {
        return Err("formal remount original 15-second ingress/worker budget exceeded".into());
    }
    drop(_scope);
    let status = expect(
        pipeline.remount_peer_call(
            original_leader,
            "GET",
            &format!("sys/remount/status/{id}"),
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "formal-remount-actual-worker-status",
    )?;
    assert_eq!(status.body["data"]["migration_info"]["status"], "success");
    Ok(id)
}

#[test]
fn native_remount_formal_ha_forwarded_history_quota_election_and_cold_rejoin() -> TestResult {
    let mut pipeline = WrappingPipeline::start()?;
    let first = pipeline.ready_leader()?;
    let follower = (first + 1) % 3;
    remount_setup(&pipeline, follower)?;
    let versions = [
        (1, "seed-v5"),
        (2, "native-before-move-v2"),
        (3, "native-before-move-v3"),
    ];
    let metadata = remount_history(&pipeline, first, "secret", &versions)?;
    let old_graph = pipeline.with_service(first, |service| {
        service
            .native_root
            .as_ref()
            .ok_or("actual source root absent")?
            .kv2
            .iter()
            .find(|graph| graph.scope.namespace.is_empty() && graph.scope.mount == "secret/")
            .cloned()
            .ok_or_else(|| "actual source graph absent".into())
    })?;
    let keep_graph = pipeline.with_service(first, |service| {
        service
            .native_root
            .as_ref()
            .ok_or("actual unrelated root absent")?
            .kv2
            .iter()
            .find(|graph| graph.scope.namespace.is_empty() && graph.scope.mount == "keep/")
            .cloned()
            .ok_or_else(|| "actual unrelated graph absent".into())
    })?;
    let id = accept_and_execute_once(&pipeline, follower, first)?;
    for node in 0..3 {
        assert_eq!(
            remount_history(&pipeline, node, "moved", &versions)?,
            metadata
        );
        expect(
            pipeline.remount_peer_call(
                node,
                "GET",
                "secret/data/pipeline/history",
                pipeline.admin(),
                json!({}),
            )?,
            404,
            "formal-remount-old-path-absent",
        )?;
        quota_path(&pipeline, node, "moved/data/pipeline/history")?;
        pipeline.with_service(node, |service| {
            let current = service
                .native_root
                .as_ref()
                .ok_or("actual installed root absent")?;
            let moved = current
                .kv2
                .iter()
                .find(|graph| graph.scope.namespace.is_empty() && graph.scope.mount == "moved/")
                .ok_or("actual moved graph absent")?;
            assert!(moved.scope != old_graph.scope);
            assert_ne!(moved.root, old_graph.root);
            assert_eq!(moved.logical_payload_bytes, old_graph.logical_payload_bytes);
            assert!(
                current
                    .kv2
                    .iter()
                    .find(|graph| graph.scope.namespace.is_empty() && graph.scope.mount == "keep/")
                    == Some(&keep_graph)
            );
            Ok(())
        })?;
    }
    let selected = pipeline.native_selection(first)?;
    for node in 0..3 {
        assert_eq!(pipeline.native_selection(node)?, selected);
    }
    pipeline.stop_process(first)?;
    let successor = pipeline.ready_leader()?;
    assert_ne!(successor, first);
    for node in (0..3).filter(|node| *node != first) {
        assert_eq!(
            remount_history(&pipeline, node, "moved", &versions)?,
            metadata
        );
        quota_path(&pipeline, node, "moved/data/pipeline/history")?;
    }
    let surviving_follower = (0..3)
        .find(|node| *node != first && *node != successor)
        .ok_or("actual surviving follower absent")?;
    let written = expect(
        pipeline.remount_peer_call(
            surviving_follower,
            "POST",
            "moved/data/pipeline/history",
            pipeline.admin(),
            json!({"data":{"value":"after-election-v4"},"options":{"cas":3}}),
        )?,
        200,
        "formal-remount-new-leader-CAS",
    )?;
    assert_eq!(written.body["data"]["version"], 4);
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    let extended = [
        (1, "seed-v5"),
        (2, "native-before-move-v2"),
        (3, "native-before-move-v3"),
        (4, "after-election-v4"),
    ];
    for node in 0..3 {
        remount_history(&pipeline, node, "moved", &extended)?;
        expect(
            pipeline.remount_peer_call(
                node,
                "GET",
                "secret/data/pipeline/history",
                pipeline.admin(),
                json!({}),
            )?,
            404,
            "formal-remount-cold-old-path-absent",
        )?;
        quota_path(&pipeline, node, "moved/data/pipeline/history")?;
    }
    let current = pipeline.ready_leader()?;
    expect(
        pipeline.remount_peer_call(
            current,
            "GET",
            &format!("sys/remount/status/{id}"),
            pipeline.admin(),
            json!({}),
        )?,
        404,
        "formal-remount-RAM-status-does-not-recreate-a-task",
    )?;
    let selected = pipeline.native_selection(current)?;
    for node in 0..3 {
        assert_eq!(pipeline.native_selection(node)?, selected);
    }
    eprintln!(
        "HBREMOUNTHA completed=true formal_raft_nodes=3 forwarded_ack_once=true original_http_seconds=15 original_forward_seconds=8 original_cold_readindex_seconds=8 leader_replaced=true cold_rejoins=1 versions=4 quota_cold_path=true physical_hosts=false"
    );
    Ok(())
}

#[test]
fn native_remount_formal_ha_no_quorum_refuses_ack_and_never_arms_a_task() -> TestResult {
    let mut pipeline = WrappingPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let before = pipeline.with_service(leader, |service| {
        assert!(service.native_remount_jobs.is_empty());
        service
            .current_state_identity()
            .map_err(|_| "actual before identity".into())
    })?;
    for node in (0..3).filter(|node| *node != leader) {
        pipeline.stop_process(node)?;
    }
    let denied = expect(
        pipeline.remount_peer_call(
            leader,
            "POST",
            "sys/remount",
            pipeline.admin(),
            json!({"from":"secret/","to":"not-admitted/"}),
        )?,
        503,
        "formal-remount-no-quorum-ACK-refused",
    )?;
    assert!(denied.body["data"]["migration_id"].is_null());
    pipeline.with_service(leader, |service| {
        assert!(service.native_remount_jobs.is_empty());
        assert!(
            service
                .current_state_identity()
                .map_err(|_| "actual after identity")?
                == before
        );
        assert!(!service.recovery_required && !service.audit_failed);
        Ok(())
    })?;
    for node in (0..3).filter(|node| *node != leader) {
        pipeline.start_formal_process(node)?;
        pipeline.wait_cold_native_readindex_ready(node)?;
        pipeline.unseal(node)?;
    }
    pipeline.ready_leader()?;
    for node in 0..3 {
        pipeline.assert_history(node, &[(1, "seed-v5")])?;
        expect(
            pipeline.remount_peer_call(
                node,
                "GET",
                "not-admitted/data/pipeline/history",
                pipeline.admin(),
                json!({}),
            )?,
            404,
            "formal-remount-refused-destination-absent",
        )?;
        pipeline.with_service(node, |service| {
            assert!(service.native_remount_jobs.is_empty());
            assert!(service.native_root.is_some() && service.record_root.is_none());
            Ok(())
        })?;
    }
    // Recovery above performs no second remount POST or worker invocation.
    eprintln!(
        "HBREMOUNTHA no_quorum_ack_refused=true original_http_seconds=15 task_count=0 mutation_retries=0 physical_hosts=false"
    );
    Ok(())
}
