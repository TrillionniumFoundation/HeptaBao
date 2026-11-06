//! Actual formal NativeV6Raft: child AppRole and CG through pinned TLS forwarding,
//! three-node commits, leader stop/election, ReadIndex and two cold rejoins.
//! This is a process-local Service test; physical-host/public-HTTPS evidence is
//! independently required and is never inferred from this fixture.
use super::*;

fn scoped_call(
    pipeline: &WrappingPipeline,
    index: usize,
    namespace: &str,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> TestResult<Response> {
    let started = Instant::now();
    let until = started + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[index]
        .as_ref()
        .ok_or("child HA Service")?;
    let mut writer = lock_until(service, until).map_err(|_| "child HA original lock deadline")?;
    let ingress = crypto::random::<16>().map_err(std::io::Error::other)?;
    let _ingress = crate::auth::IngressReplyScope::listener(&ingress);
    let execution = writer.begin_request_before(
        ServiceRequest {
            method,
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        until,
        false,
    );
    let response = writer.finish_synchronous_request(execution);
    if started.elapsed() >= REQUEST_BUDGET {
        return Err("child HA original 15-second deadline exceeded".into());
    }
    assert!(writer.pending_native_auth_delivery.is_none());
    assert!(writer.pending_ordinary_kv_authority.is_none());
    Ok(response)
}

fn admin_call(
    p: &WrappingPipeline,
    node: usize,
    ns: &str,
    method: &str,
    path: &str,
    body: Value,
) -> TestResult<Response> {
    scoped_call(p, node, ns, method, path, p.admin(), body)
}

struct Login {
    token: Zeroizing<String>,
    entity: String,
}

fn login(p: &WrappingPipeline, node: usize, ns: &str, name: &str) -> TestResult<Login> {
    let role = format!("auth/cg-child/role/{name}");
    expect(
        admin_call(
            p,
            node,
            ns,
            "POST",
            &role,
            json!({"token_policies":[name],"token_no_default_policy":true,
            "secret_id_num_uses":1,"token_ttl":"1h"}),
        )?,
        204,
        "child-HA-role",
    )?;
    let mut id = expect(
        admin_call(p, node, ns, "GET", &format!("{role}/role-id"), json!({}))?,
        200,
        "child-HA-role-id",
    )?;
    let id = secret_field(&mut id, "/data/role_id")?;
    let mut secret = expect(
        admin_call(p, node, ns, "POST", &format!("{role}/secret-id"), json!({}))?,
        200,
        "child-HA-secret-id",
    )?;
    let secret = secret_field(&mut secret, "/data/secret_id")?;
    let mut reply = expect(
        scoped_call(
            p,
            node,
            ns,
            "POST",
            "auth/cg-child/login",
            "",
            json!({"role_id":id.as_str(),"secret_id":secret.as_str()}),
        )?,
        200,
        "child-HA-login",
    )?;
    let token = secret_field(&mut reply, "/auth/client_token")?;
    let entity = reply.body["auth"]["entity_id"]
        .as_str()
        .ok_or("child login entity")?
        .to_owned();
    assert!(!entity.is_empty());
    erase_json(&mut reply.body);
    // Known-success negative one-use check, never a mutation retry.
    expect(
        scoped_call(
            p,
            node,
            ns,
            "POST",
            "auth/cg-child/login",
            "",
            json!({"role_id":id.as_str(),"secret_id":secret.as_str()}),
        )?,
        400,
        "child-HA-secret-spent",
    )?;
    Ok(Login { token, entity })
}

fn value(p: &WrappingPipeline, node: usize, ns: &str) -> TestResult {
    let read = expect(
        admin_call(
            p,
            node,
            ns,
            "GET",
            "secret/data/child-controlled",
            json!({}),
        )?,
        200,
        "child-HA-ReadIndex-value",
    )?;
    assert_eq!(read.body["data"]["metadata"]["version"], 1);
    assert_eq!(read.body["data"]["data"]["value"], "quorum-child");
    p.with_service(node, |service| {
        assert!(matches!(
            service.native_storage_profile,
            Some(NativeStorageProfile::Raft)
        ));
        assert!(service.native_candidate_profile.is_none());
        let root = service.native_root.as_ref().ok_or("child native root")?;
        assert!(root.reader_floor.minimum_state_schema >= NATIVE_PLAIN_NAMESPACE_STATE_SCHEMA);
        assert!(
            root.kv2
                .iter()
                .any(|graph| graph.scope.namespace == ns && graph.scope.mount == "secret/")
        );
        assert!(
            namespaces::native_plain::profile(service.state.as_ref().ok_or("child actual state")?)
                .is_ok()
        );
        Ok(())
    })
}

// One actual export/upload through the production snapshot admission, streamed
// execution and completion owner. Each call keeps its original 15-second scope.
fn snapshot(
    p: &WrappingPipeline,
    node: usize,
    method: &str,
    input: &[u8],
) -> TestResult<(Response, Zeroizing<Vec<u8>>)> {
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = p.services[node]
        .as_ref()
        .ok_or("child HA snapshot Service")?;
    let mut writer =
        lock_until(service, until).map_err(|_| "child snapshot original lock deadline")?;
    let admission = writer.begin_native_snapshot_before(
        ServiceRequest::new(
            method,
            "sys/storage/raft/snapshot",
            "",
            p.admin(),
            json!({}),
        ),
        until,
    );
    let mut plan = match admission {
        NativeSnapshotAdmission::Execute(RequestExecution::External(plan)) => plan,
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            return Err(format!("child snapshot admission status={}", response.status).into());
        }
        NativeSnapshotAdmission::Redirect(_) => {
            return Err("selected child snapshot leader redirected".into());
        }
        #[cfg(feature = "native-v6-ha")]
        NativeSnapshotAdmission::Forward(_) => {
            return Err("selected child snapshot leader forwarded".into());
        }
    };
    // Match the production HTTP external phase: no transfer/body I/O while
    // holding the Service writer. Completion reacquires the same real owner
    // within the original deadline; no new budget or request is admitted.
    drop(writer);
    let (result, output) = plan.execute_snapshot_transfer(&mut &input[..]);
    let mut writer = lock_until(service, until)
        .map_err(|_| "child snapshot completion original lock deadline")?;
    let response = writer.finish_external_request(*plan, result);
    assert!(writer.native_request_binding.is_none());
    drop(writer);
    let mut bytes = Zeroizing::new(Vec::new());
    if method == "GET" {
        output
            .ok_or("actual HA child archive")?
            .read_to_end(&mut bytes)?;
        assert!(bytes.starts_with(&[0x1f, 0x8b]));
    } else {
        assert!(output.is_none());
    }
    if Instant::now() >= until {
        return Err("child snapshot original deadline exceeded".into());
    }
    Ok((response, bytes))
}

fn pending_snapshot_epoch_roundtrip(p: &WrappingPipeline, leader: usize, ns: &str) -> TestResult {
    let epoch = p.with_service(leader, |service| {
        Ok(service
            .state
            .as_ref()
            .ok_or("actual current epoch")?
            .replay_epoch)
    })?;
    let (exported, bytes) = snapshot(p, leader, "GET", &[])?;
    expect(exported, 200, "child-HA-authenticated-pending-export")?;
    expect(
        admin_call(
            p,
            leader,
            "",
            "POST",
            "secret/data/child-ha-after-archive",
            json!({"options":{"cas":0},"data":{"must_disappear":true}}),
        )?,
        200,
        "child-HA-post-archive-divergence",
    )?;
    // The one upload is never retried, including any completion failure.
    let (restored, output) = snapshot(p, leader, "POST", &bytes)?;
    assert!(output.is_empty());
    let restored = expect(restored, 200, "child-HA-actual-pending-historical-restore")?;
    assert_eq!(restored.body["data"]["cluster_coordinated"], true);
    assert_eq!(
        restored.body["data"]["replay_epoch"],
        epoch.checked_add(1).ok_or("epoch overflow")?
    );
    for node in 0..3 {
        expect(
            admin_call(
                p,
                node,
                "",
                "GET",
                "secret/metadata/child-ha-after-archive",
                json!({}),
            )?,
            404,
            "child-HA-authentic-history-restored",
        )?;
        expect(
            admin_call(
                p,
                node,
                ns,
                "GET",
                "secret/metadata/child-controlled",
                json!({}),
            )?,
            404,
            "child-HA-restored-pending-never-executed",
        )?;
        p.with_service(node, |service| {
            assert_eq!(
                service
                    .state
                    .as_ref()
                    .ok_or("actual installed epoch")?
                    .replay_epoch,
                epoch + 1
            );
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn native_cg271_child_formal_ha_forward_election_readindex_and_spent_cold_rejoin() -> TestResult {
    let mut p = WrappingPipeline::start()?;
    let first = p.ready_leader()?;
    let ingress = (first + 1) % 3;
    let ns = "cg-ha-child";
    let sibling = "cg-ha-sibling";
    for namespace in [ns, sibling] {
        expect(
            admin_call(
                &p,
                ingress,
                "",
                "POST",
                &format!("sys/namespaces/{namespace}"),
                json!({}),
            )?,
            200,
            "child-HA-namespace",
        )?;
        expect(
            admin_call(
                &p,
                ingress,
                namespace,
                "POST",
                "sys/mounts/secret",
                json!({"type":"kv","options":{"version":"2"}}),
            )?,
            204,
            "child-HA-mount",
        )?;
    }
    expect(
        admin_call(
            &p,
            ingress,
            ns,
            "POST",
            "sys/auth/cg-child",
            json!({"type":"approle"}),
        )?,
        204,
        "child-HA-auth-mount",
    )?;
    let policy = r#"path "secret/data/child-controlled" {
        capabilities=["create","update","read"]
        control_group={ttl="600s" self_auth_allowed=false
            factor "review" {controlled_capabilities=["create","update","read"]
                identity {group_names=["child-reviewers"] approvals=1}
            }
        }
    }"#;
    let reviewer_policy = r#"path "sys/control-group/request" {capabilities=["update"]}
        path "sys/control-group/authorize" {capabilities=["update"]}
        path "sys/wrapping/unwrap" {capabilities=["update"]}"#;
    for (name, policy) in [("requester", policy), ("reviewer", reviewer_policy)] {
        expect(
            admin_call(
                &p,
                ingress,
                ns,
                "PUT",
                &format!("sys/policies/acl/{name}"),
                json!({"policy":policy}),
            )?,
            204,
            "child-HA-policy",
        )?;
    }
    let requester = login(&p, ingress, ns, "requester")?;
    let reviewer = login(&p, ingress, ns, "reviewer")?;
    expect(
        admin_call(
            &p,
            ingress,
            ns,
            "POST",
            "identity/group",
            json!({"name":"child-reviewers","type":"internal","member_entity_ids":[reviewer.entity]}),
        )?,
        200,
        "child-HA-live-group",
    )?;
    let mut deferred = expect(
        scoped_call(
            &p,
            ingress,
            ns,
            "POST",
            "secret/data/child-controlled",
            &requester.token,
            json!({"data":{"value":"quorum-child"}}),
        )?,
        200,
        "child-HA-defer",
    )?;
    let raw = secret_field(&mut deferred, "/wrap_info/token")?;
    let accessor = deferred.body["wrap_info"]["accessor"]
        .as_str()
        .ok_or("CG accessor")?
        .to_owned();
    erase_json(&mut deferred.body);
    for wrong in ["", sibling] {
        for path in ["sys/control-group/request", "sys/control-group/authorize"] {
            let denied = admin_call(
                &p,
                ingress,
                wrong,
                "POST",
                path,
                json!({"accessor":accessor}),
            )?;
            assert!(denied.status >= 400 && denied.body["data"].is_null());
        }
        let denied = scoped_call(
            &p,
            ingress,
            wrong,
            "POST",
            "sys/wrapping/unwrap",
            &raw,
            json!({}),
        )?;
        assert!(matches!(denied.status, 400 | 403));
    }
    let approved = expect(
        scoped_call(
            &p,
            ingress,
            ns,
            "POST",
            "sys/control-group/authorize",
            &reviewer.token,
            json!({"accessor":accessor}),
        )?,
        200,
        "child-HA-approve",
    )?;
    assert_eq!(approved.body["data"]["approved"], true);
    expect(
        admin_call(
            &p,
            ingress,
            ns,
            "GET",
            "secret/metadata/child-controlled",
            json!({}),
        )?,
        404,
        "child-HA-pending-never-writes",
    )?;
    pending_snapshot_epoch_roundtrip(&p, first, ns)?;
    // Real owner stop causes another real voter election. No root or receipt
    // is installed by the test and no failed mutation is replayed.
    p.stop_process(first)?;
    let next = p.ready_leader()?;
    assert_ne!(first, next);
    let review = expect(
        scoped_call(
            &p,
            next,
            ns,
            "POST",
            "sys/control-group/request",
            &reviewer.token,
            json!({"accessor":accessor}),
        )?,
        200,
        "child-HA-approved-after-election",
    )?;
    assert_eq!(review.body["data"]["approved"], true);
    assert_eq!(
        review.body["data"]["authorizations"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    p.start_formal_process(first)?;
    p.wait_cold_native_readindex_ready(first)?;
    p.unseal(first)?;
    let executed = expect(
        scoped_call(
            &p,
            first,
            ns,
            "POST",
            "sys/wrapping/unwrap",
            &raw,
            json!({}),
        )?,
        200,
        "child-HA-execute-after-cold-rejoin",
    )?;
    assert_eq!(executed.body["data"]["version"], 1);
    for node in 0..3 {
        value(&p, node, ns)?;
        for wrong in ["", sibling] {
            expect(
                admin_call(
                    &p,
                    node,
                    wrong,
                    "GET",
                    "secret/metadata/child-controlled",
                    json!({}),
                )?,
                404,
                "child-HA-foreign-path-unchanged",
            )?;
        }
    }
    p.stop_process(first)?;
    p.start_formal_process(first)?;
    p.wait_cold_native_readindex_ready(first)?;
    p.unseal(first)?;
    expect(
        scoped_call(
            &p,
            first,
            ns,
            "POST",
            "sys/wrapping/unwrap",
            &raw,
            json!({}),
        )?,
        400,
        "child-HA-spent-after-second-cold",
    )?;
    value(&p, first, ns)?;
    p.assert_history(first, &[(1, "seed-v5")])?;
    Ok(())
}
