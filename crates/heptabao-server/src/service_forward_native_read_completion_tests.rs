//! A genuine completed native read must survive an overlapping data append.
//! This is a real three-node production mTLS/Service/Raft fixture, not a
//! counterfeit completion or a replay of the failed physical-host history.
use super::*;
use crate::ha_forward::ForwardContext;
use crate::service::native_v6_ha_pipeline_tests::Pipeline;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn native_completed_read_retained_version_survives_data_append_across_actual_local_audit()
-> TestResult {
    let pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let activated = pipeline.call(
        leader,
        "POST",
        "sys/internal/native-v6/activate",
        pipeline.admin(),
        json!({}),
    )?;
    assert_eq!(activated.status, 204);
    let path = "secret/data/pipeline/completed-read-audit";
    let written = pipeline.call(
        leader,
        "POST",
        path,
        pipeline.admin(),
        json!({"options":{"cas":0},"data":{"value":"original-completed-read"}}),
    )?;
    assert_eq!(written.status, 200);
    let standby = (0..3)
        .find(|index| *index != leader)
        .ok_or("standby absent")?;
    let original = Instant::now() + Duration::from_secs(15);
    let clock = RequestClock::anchored(
        SystemTime::now().duration_since(UNIX_EPOCH)?,
        Instant::now(),
    )?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (response, receipt_deadline) =
        pipeline.with_service_mut_for_delivery_test(standby, |service| {
            let _original = crate::request_deadline::RequestDeadlineScope::enter(original);
            let ha = Arc::clone(service.ha.as_ref().ok_or("actual standby HA absent")?);
            let body = json!({});
            // The actual authenticated peer executes the read and mints its own
            // non-clone completion. No test creates, edits, or resigns the wire.
            let (response, receipt) = ha
                .lock_for_request()
                .map_err(|_| "actual standby HA lock")?
                .forward_request_completed(ForwardContext {
                    method: "GET",
                    path,
                    namespace: "",
                    token: pipeline.admin(),
                    body: &body,
                    wrap_ttl_seconds: None,
                    origin_peer: None,
                    client_certificates: None,
                    caller_deadline: Some(original),
                })?;
            assert_eq!(response.status, 200);
            assert_eq!(
                response.body["data"]["data"]["value"],
                "original-completed-read"
            );
            let deadline = receipt.deadline;
            assert!(deadline <= original);
            let authority = service
                .stage_forward_delivery(receipt, Arc::clone(&ha), "", Some(clock), now)
                .map_err(|_| "actual stage before overlapping publication refused")?;
            service.pending_forward_delivery =
                Some(PendingForwardDelivery::Completed(Box::new(authority)));
            let audited = service.audit_completed_response(
                "native-completed-read-audit",
                now,
                Some(clock),
                response,
            );
            assert_eq!(audited.status, 200);
            Ok((audited, deadline))
        })?;
    // The original read has already executed and passed its local audit. A
    // genuinely committed append retains that exact old version and payload.
    let appended = pipeline.call(
        leader,
        "POST",
        path,
        pipeline.admin(),
        json!({"options":{"cas":1},"data":{"value":"later-version"}}),
    )?;
    assert_eq!(appended.status, 200);
    assert_eq!(appended.body["data"]["version"], 2);
    let delivered = pipeline.with_service_mut_for_delivery_test(standby, |service| {
        let _original = crate::request_deadline::RequestDeadlineScope::enter(receipt_deadline);
        assert!(Instant::now() < receipt_deadline);
        let response = service.complete_forward_delivery(response, "native-completed-read-audit");
        assert!(service.pending_forward_delivery.is_none());
        Ok(response)
    })?;
    assert_eq!(
        delivered.status, 200,
        "retained-version completed read was vetoed after unrelated data publication"
    );
    assert_eq!(
        delivered.body["data"]["data"]["value"],
        "original-completed-read"
    );
    assert_eq!(delivered.body["data"]["metadata"]["version"], 1);
    Ok(())
}

struct PendingNativeRead {
    pipeline: Pipeline,
    leader: usize,
    standby: usize,
    response: Option<Response>,
    deadline: Instant,
    accessor: String,
    actor: Zeroizing<String>,
}
const RETAINED_PATH: &str = "secret/data/pipeline/finite-retained-read";
impl PendingNativeRead {
    fn start(retention_one: bool, budget: Duration) -> TestResult<Self> {
        Self::start_with_uses(retention_one, budget, 2)
    }
    fn start_with_uses(
        retention_one: bool,
        budget: Duration,
        finite_uses: u64,
    ) -> TestResult<Self> {
        let pipeline = Pipeline::start()?;
        let leader = pipeline.ready_leader()?;
        let root = pipeline.admin();
        assert_eq!(
            pipeline
                .call(
                    leader,
                    "POST",
                    "sys/internal/native-v6/activate",
                    root,
                    json!({})
                )?
                .status,
            204
        );
        if retention_one {
            assert_eq!(
                pipeline
                    .call(
                        leader,
                        "POST",
                        "secret/config",
                        root,
                        json!({"max_versions":1})
                    )?
                    .status,
                204
            );
        }
        assert_eq!(
            pipeline
                .call(
                    leader,
                    "POST",
                    RETAINED_PATH,
                    root,
                    json!({"options":{"cas":0},"data":{"value":"one-real-read"}})
                )?
                .status,
            200
        );
        assert_eq!(
            pipeline
                .call(
                    leader,
                    "POST",
                    "secret/data/pipeline/unrelated-retained-read",
                    root,
                    json!({"options":{"cas":0},"data":{"value":"other-before"}})
                )?
                .status,
            200
        );
        assert_eq!(pipeline.call(leader,"PUT","sys/policies/acl/native-retained-read",root,json!({"policy":"path \"secret/data/pipeline/finite-retained-read\" { capabilities = [\"read\"] }"}))?.status,204);
        let mut issued = pipeline.call(leader,"POST","auth/token/create",root,json!({"policies":["native-retained-read"],"no_default_policy":true,"num_uses":finite_uses,"ttl":"10m"}))?;
        assert_eq!(issued.status, 200);
        let actor = Zeroizing::new(
            issued.body["auth"]["client_token"]
                .as_str()
                .ok_or("finite actor absent")?
                .to_owned(),
        );
        let accessor = issued.body["auth"]["accessor"]
            .as_str()
            .ok_or("finite accessor absent")?
            .to_owned();
        erase_json(&mut issued.body);
        let standby = (0..3).find(|i| *i != leader).ok_or("standby absent")?;
        let original = Instant::now() + budget;
        let clock = RequestClock::anchored(
            SystemTime::now().duration_since(UNIX_EPOCH)?,
            Instant::now(),
        )?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let (response, deadline) =
            pipeline.with_service_mut_for_delivery_test(standby, |service| {
                let _original = crate::request_deadline::RequestDeadlineScope::enter(original);
                let ha = Arc::clone(service.ha.as_ref().ok_or("standby HA absent")?);
                let body = json!({});
                let (response, receipt) = ha
                    .lock_for_request()
                    .map_err(|_| "standby HA lock")?
                    .forward_request_completed(ForwardContext {
                        method: "GET",
                        path: RETAINED_PATH,
                        namespace: "",
                        token: &actor,
                        body: &body,
                        wrap_ttl_seconds: None,
                        origin_peer: None,
                        client_certificates: None,
                        caller_deadline: Some(original),
                    })?;
                assert_eq!(response.status, 200);
                assert!(
                    receipt.actor().is_some(),
                    "actual original finite Actor must be retained"
                );
                let deadline = receipt.deadline;
                assert!(deadline <= original);
                let authority = service
                    .stage_forward_delivery(receipt, Arc::clone(&ha), "", Some(clock), now)
                    .map_err(|_| "finite read stage")?;
                service.pending_forward_delivery =
                    Some(PendingForwardDelivery::Completed(Box::new(authority)));
                let audited = service.audit_completed_response(
                    "finite-native-retained-read",
                    now,
                    Some(clock),
                    response,
                );
                assert_eq!(audited.status, 200);
                Ok((audited, deadline))
            })?;
        let result = Self {
            pipeline,
            leader,
            standby,
            response: Some(response),
            deadline,
            accessor,
            actor,
        };
        assert_eq!(
            result.remaining()?,
            Some(finite_uses - 1),
            "original read consumes exactly one use"
        );
        Ok(result)
    }
    fn remaining(&self) -> TestResult<Option<u64>> {
        self.pipeline.with_service(self.leader, |service| {
            let mut auth =
                serde_json::to_value(&service.state.as_ref().ok_or("actual state absent")?.auth)?;
            let count = auth["tokens"]
                .as_object()
                .ok_or("actual tokens absent")?
                .values()
                .find(|v| v["accessor"] == self.accessor)
                .and_then(|v| v["uses_remaining"].as_u64());
            erase_json(&mut auth);
            Ok(count)
        })
    }
    fn mutate(&self, method: &str, path: &str, body: Value, status: u16) -> TestResult {
        let mut response =
            self.pipeline
                .call(self.leader, method, path, self.pipeline.admin(), body)?;
        assert_eq!(
            response.status, status,
            "actual controlled publication failed"
        );
        erase_json(&mut response.body);
        Ok(())
    }
    fn finish(&mut self) -> TestResult<Response> {
        let response = self
            .response
            .take()
            .ok_or("same completed response already consumed")?;
        let deadline = self.deadline;
        self.pipeline
            .with_service_mut_for_delivery_test(self.standby, |service| {
                let _original = crate::request_deadline::RequestDeadlineScope::enter(deadline);
                let result =
                    service.complete_forward_delivery(response, "finite-native-retained-read");
                assert!(service.pending_forward_delivery.is_none());
                Ok(result)
            })
    }
    fn assert_no_refund_or_second_use(&self, token_revoked: bool) -> TestResult {
        assert!(
            self.remaining()? == Some(1) || token_revoked && self.remaining()?.is_none(),
            "re-admission, refund or second use occurred"
        );
        Ok(())
    }
}
impl Drop for PendingNativeRead {
    fn drop(&mut self) {
        if let Some(response) = self.response.as_mut() {
            erase_json(&mut response.body);
        }
        use zeroize::Zeroize as _;
        self.accessor.zeroize();
    }
}

#[test]
fn native_completed_read_unrelated_publication_preserves_exact_original_use() -> TestResult {
    let mut read = PendingNativeRead::start(false, Duration::from_secs(15))?;
    read.mutate(
        "POST",
        "secret/data/pipeline/unrelated-retained-read",
        json!({"options":{"cas":1},"data":{"value":"other-after"}}),
        200,
    )?;
    let mut result = read.finish()?;
    assert_eq!(result.status, 200);
    assert_eq!(result.body["data"]["data"]["value"], "one-real-read");
    assert_eq!(read.remaining()?, Some(1));
    assert!(
        read.finish().is_err(),
        "affine test carrier cannot deliver twice"
    );
    erase_json(&mut result.body);
    Ok(())
}

#[test]
fn native_completed_read_deleted_destroyed_retained_out_or_config_changed_stays_refused()
-> TestResult {
    for kind in [
        "deleted",
        "destroyed",
        "retained_out",
        "configuration",
        "custom_metadata",
    ] {
        let mut read = PendingNativeRead::start(kind == "retained_out", Duration::from_secs(15))?;
        match kind {
            "deleted" => read.mutate("DELETE", RETAINED_PATH, json!({}), 204)?,
            "destroyed" => read.mutate(
                "POST",
                "secret/destroy/pipeline/finite-retained-read",
                json!({"versions":[1]}),
                204,
            )?,
            "retained_out" => read.mutate(
                "POST",
                RETAINED_PATH,
                json!({"options":{"cas":1},"data":{"value":"new-retained-only"}}),
                200,
            )?,
            "configuration" => {
                read.mutate("POST", "secret/config", json!({"cas_required":true}), 204)?
            }
            "custom_metadata" => read.mutate(
                "POST",
                "secret/metadata/pipeline/finite-retained-read",
                json!({"custom_metadata":{"purpose":"changed"}}),
                204,
            )?,
            _ => return Err("unknown frozen fixture kind".into()),
        }
        let mut result = read.finish()?;
        assert_eq!(
            result.status, 503,
            "original visibility/metadata contract must remain closed: {kind}"
        );
        assert!(result.body.get("data").is_none());
        read.assert_no_refund_or_second_use(false)?;
        erase_json(&mut result.body);
    }
    Ok(())
}

#[test]
fn native_completed_read_policy_token_mount_or_namespace_changes_stay_refused() -> TestResult {
    for kind in ["policy", "token", "mount_recreated", "namespace"] {
        let mut read = PendingNativeRead::start(false, Duration::from_secs(15))?;
        match kind {
            "policy"=>read.mutate("PUT","sys/policies/acl/native-retained-read",json!({"policy":"path \"secret/data/pipeline/finite-retained-read\" { capabilities = [\"deny\"] }"}),204)?,
            "token"=>read.mutate("POST","auth/token/revoke-accessor",json!({"accessor":read.accessor}),204)?,
            "mount_recreated"=>{
                read.mutate("DELETE","sys/mounts/secret",json!({}),204)?;
                read.mutate("POST","sys/mounts/secret",json!({"type":"kv","options":{"version":"2"}}),204)?;
                read.mutate("POST",RETAINED_PATH,json!({"options":{"cas":0},"data":{"value":"different-incarnation"}}),200)?;
            }
            "namespace"=>read.mutate("POST","sys/namespaces/retained-read-other",json!({}),200)?,
            _=>unreachable!(),
        }
        let mut result = read.finish()?;
        assert_eq!(result.status, 503, "actual authority owner changed: {kind}");
        assert!(result.body.get("data").is_none());
        read.assert_no_refund_or_second_use(kind == "token")?;
        erase_json(&mut result.body);
    }
    Ok(())
}

#[test]
fn native_completed_read_original_deadline_and_original_unseal_owner_stay_refused() -> TestResult {
    for kind in ["deadline", "nonce", "key"] {
        let mut read = PendingNativeRead::start(
            false,
            if kind == "deadline" {
                Duration::from_secs(2)
            } else {
                Duration::from_secs(15)
            },
        )?;
        if kind == "deadline" {
            std::thread::sleep(
                read.deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
            );
        } else {
            read.pipeline
                .with_service_mut_for_delivery_test(read.standby, |service| {
                    if kind == "nonce" {
                        service.rotate_unseal_nonce()?;
                    } else {
                        *service
                            .barrier_key
                            .as_mut()
                            .ok_or("actual barrier key absent")?
                            .first_mut()
                            .ok_or("empty barrier key")? ^= 1;
                    }
                    Ok(())
                })?;
        }
        let mut result = read.finish()?;
        assert_eq!(
            result.status, 503,
            "original temporal/unseal owner changed: {kind}"
        );
        assert!(result.body.get("data").is_none());
        read.assert_no_refund_or_second_use(false)?;
        erase_json(&mut result.body);
    }
    Ok(())
}

#[test]
fn native_completed_read_real_missing_seal_is_not_revived_by_restoring_inode() -> TestResult {
    struct RestoreSeal {
        original: std::path::PathBuf,
        held: std::path::PathBuf,
    }
    impl Drop for RestoreSeal {
        fn drop(&mut self) {
            if self.held.is_file() && !self.original.exists() {
                let _ = std::fs::rename(&self.held, &self.original);
            }
        }
    }
    let mut read = PendingNativeRead::start(false, Duration::from_secs(15))?;
    let original = read.pipeline.with_service(read.standby, |service| {
        Ok(service.data_dir.join(SEAL_METADATA_FILE))
    })?;
    let held = original.with_file_name("retained-read-fixture-held-seal");
    assert!(original.is_file() && !held.exists());
    std::fs::rename(&original, &held)?;
    let restore = RestoreSeal { original, held };
    let mut result = read.finish()?;
    assert_eq!(
        result.status, 503,
        "actual physical Seal disappearance must veto typed read"
    );
    assert!(result.body.get("data").is_none());
    read.assert_no_refund_or_second_use(false)?;
    drop(restore);
    assert!(
        read.finish().is_err(),
        "restoring the same inode cannot mint a consumed read carrier"
    );
    erase_json(&mut result.body);
    Ok(())
}

#[test]
fn native_completed_read_forged_marker_prefix_write_scope_and_replay_are_refused() -> TestResult {
    use crate::ha_forward_completion::{
        CompletedExchange, CompletedForwardReceipt, CompletionWire,
    };
    for kind in [
        "marker",
        "descriptor",
        "prefix",
        "write_scope",
        "replay_nonce",
    ] {
        let read = PendingNativeRead::start(false, Duration::from_secs(15))?;
        let receipt =
            read.pipeline
                .with_service_mut_for_delivery_test(read.standby, |service| {
                    let Some(PendingForwardDelivery::Completed(authority)) =
                        service.pending_forward_delivery.take()
                    else {
                        return Err("actual affine read capsule absent".into());
                    };
                    Ok(authority.receipt)
                })?;
        let cluster = receipt.cluster.clone();
        let source = receipt.source;
        let target = receipt.target;
        let deadline = receipt.deadline;
        let wire = receipt.into_wire_for_test();
        assert!(
            wire.native_data_read.is_some(),
            "only the real completed native GET supplies this marker"
        );
        let mut nonce = wire.nonce;
        let body = json!({});
        let context = ForwardContext {
            method: "GET",
            path: RETAINED_PATH,
            namespace: "",
            token: &read.actor,
            body: &body,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
            caller_deadline: Some(deadline),
        };
        // Pure reconstruction of the exact already encoded request. It is
        // never dispatched, authenticated, or consumed for a second time.
        let candidates = [
            crate::ha_forward::encode_completed_index_request_for_cluster(
                &cluster,
                (target, source),
                &context,
                Some(nonce),
            )?,
            crate::ha_forward::encode_completed_request_with_native_index_capacity(
                &cluster,
                (target, source),
                &context,
                Some(nonce),
            )?,
        ];
        let mut request = Zeroizing::new(
            candidates
                .into_iter()
                .find(|v| crate::ha_forward_completion::digest(v) == wire.request_digest)
                .ok_or("original request byte reconstruction")?,
        );
        let response_digest = crate::ha_forward_completion::response_digest(
            read.response.as_ref().ok_or("actual response absent")?,
        )?;
        let mut encoded = serde_json::to_value(&wire)?;
        match kind {
            "marker" | "descriptor" => {
                let slot = if kind == "marker" {
                    &mut encoded["native_data_read"]["stable_owner_projection"][0]
                } else {
                    &mut encoded["native_data_read"]["data"]["descriptor"][0]
                };
                *slot = json!(slot.as_u64().ok_or("actual marker digest absent")? ^ 1);
            }
            "prefix" => encoded["prefix"]["term"] = json!(u64::MAX),
            "write_scope" => {
                let context = ForwardContext {
                    method: "POST",
                    path: RETAINED_PATH,
                    namespace: "",
                    token: &read.actor,
                    body: &body,
                    wrap_ttl_seconds: None,
                    origin_peer: None,
                    client_certificates: None,
                    caller_deadline: Some(deadline),
                };
                *request = crate::ha_forward::encode_completed_index_request_for_cluster(
                    &cluster,
                    (target, source),
                    &context,
                    Some(nonce),
                )?;
                encoded["request_digest"] = json!(crate::ha_forward_completion::digest(&request));
            }
            "replay_nonce" => nonce[0] ^= 1,
            _ => return Err("unknown frozen forgery kind".into()),
        }
        let altered: CompletionWire = serde_json::from_value(encoded.clone())?;
        erase_json(&mut encoded);
        let verified = CompletedForwardReceipt::verified(
            altered,
            CompletedExchange {
                cluster,
                source,
                target,
                deadline,
                nonce,
                request: &request,
                response_digest,
            },
        );
        match verified {
            Err(_) => {}
            Ok(receipt) => {
                read.pipeline
                    .with_service_mut_for_delivery_test(read.standby, |service| {
                        let ha = Arc::clone(service.ha.as_ref().ok_or("actual HA absent")?);
                        let clock = RequestClock::anchored(
                            SystemTime::now().duration_since(UNIX_EPOCH)?,
                            Instant::now(),
                        )?;
                        let result = service.stage_forward_delivery(
                            receipt,
                            ha,
                            "",
                            Some(clock),
                            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                        );
                        assert!(
                            matches!(result,Err(ref response) if response.status==503),
                            "altered native read proof must remain refused: {kind}"
                        );
                        Ok(())
                    })?
            }
        }
        assert_eq!(
            read.remaining()?,
            Some(1),
            "forgery/replay never re-admits or refunds original Actor"
        );
    }
    Ok(())
}

#[test]
fn native_completed_write_never_gains_retained_read_marker_or_owner_exception() -> TestResult {
    let read = PendingNativeRead::start(false, Duration::from_secs(15))?;
    let original = Instant::now() + Duration::from_secs(15);
    let (response,receipt)=read.pipeline.with_service_mut_for_delivery_test(read.standby,|service| {
        let _scope=crate::request_deadline::RequestDeadlineScope::enter(original);
        let ha=Arc::clone(service.ha.as_ref().ok_or("actual HA absent")?);
        let body=json!({"options":{"cas":1},"data":{"value":"actual-forwarded-write","native_data_read":true}});
        let result=ha.lock_for_request().map_err(|_|"actual HA lock")?.forward_request_completed(ForwardContext{
            method:"POST",path:RETAINED_PATH,namespace:"",token:read.pipeline.admin(),body:&body,wrap_ttl_seconds:None,origin_peer:None,client_certificates:None,caller_deadline:Some(original)})?;
        assert_eq!(result.0.status,200);
        assert!(result.1.native_data_read().is_none(),"request data cannot construct a read marker");
        Ok(result)
    })?;
    read.mutate(
        "POST",
        "secret/data/pipeline/unrelated-retained-read",
        json!({"options":{"cas":1},"data":{"value":"intervening-publication"}}),
        200,
    )?;
    read.pipeline
        .with_service_mut_for_delivery_test(read.standby, |service| {
            let ha = Arc::clone(service.ha.as_ref().ok_or("actual HA absent")?);
            let clock = RequestClock::anchored(
                SystemTime::now().duration_since(UNIX_EPOCH)?,
                Instant::now(),
            )?;
            let result = service.stage_forward_delivery(
                receipt,
                ha,
                "",
                Some(clock),
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            );
            assert!(
                matches!(result,Err(ref response) if response.status==503),
                "completed write retains original full-owner gate"
            );
            Ok(())
        })?;
    assert_eq!(read.remaining()?, Some(1));
    let mut response = response;
    erase_json(&mut response.body);
    Ok(())
}

#[test]
fn native_retained_read_stable_projection_preserves_authority_domains_and_root_interpretation()
-> TestResult {
    use crate::state_record_root_v6::OwnerDomain;
    let read = PendingNativeRead::start(false, Duration::from_secs(15))?;
    let (root, auth) = read.pipeline.with_service(read.leader, |service| {
        let state = service
            .state
            .as_ref()
            .ok_or("actual state absent")?
            .protected_state()
            .map_err(|_| "actual protected state")?;
        Ok((
            service
                .native_root
                .as_ref()
                .ok_or("actual selected native root")?
                .clone(),
            state.auth.forward_owner_projection_digest()?,
        ))
    })?;
    let initial = Service::forward_native_data_read_projection_root(&root, auth)
        .map_err(|_| "actual stable root projection")?;
    for kind in [
        "storage",
        "schema",
        "record_reader",
        "state_reader",
        "kv2_reader",
        "number_format",
        "cluster",
        "epoch",
        "namespace",
        "engine",
        "database",
        "raft_admin",
        "address_key",
        "mount_incarnation",
        "graph_format",
    ] {
        let mut counterfeit = root.clone();
        match kind {
            "storage" => counterfeit.storage_format.push('x'),
            "schema" => counterfeit.state_schema += 1,
            "record_reader" => counterfeit.reader_floor.record_format += 1,
            "state_reader" => counterfeit.reader_floor.minimum_state_schema += 1,
            "kv2_reader" => counterfeit.reader_floor.native_kv2_format += 1,
            "number_format" => {
                counterfeit.global_lossless_json_format =
                    if counterfeit.global_lossless_json_format.is_some() {
                        None
                    } else {
                        Some(1)
                    }
            }
            "cluster" => counterfeit.cluster_id.push('x'),
            "epoch" => counterfeit.replay_epoch += 1,
            "namespace" | "engine" | "database" | "raft_admin" => {
                let domain = match kind {
                    "namespace" => OwnerDomain::Namespaces,
                    "engine" => OwnerDomain::Engines,
                    "database" => OwnerDomain::Database,
                    _ => OwnerDomain::RaftAdmin,
                };
                counterfeit
                    .owners
                    .iter_mut()
                    .find(|o| o.domain == domain)
                    .ok_or("actual role owner absent")?
                    .owner
                    .digest[0] ^= 1;
            }
            "address_key" => counterfeit.object_address_key.0[0] ^= 1,
            "mount_incarnation" => {
                counterfeit
                    .kv2
                    .first_mut()
                    .ok_or("actual native mount absent")?
                    .scope
                    .incarnation += 1
            }
            "graph_format" => counterfeit
                .kv2
                .first_mut()
                .ok_or("actual native mount absent")?
                .graph_format
                .push('x'),
            _ => return Err("unknown frozen projection fault".into()),
        }
        // Hash-boundary fault only: never installed, selected or authorized.
        let result = Service::forward_native_data_read_projection_root(&counterfeit, auth);
        assert!(
            result.is_err() || result.ok() != Some(initial),
            "stable read projection omitted authority domain {kind}"
        );
    }
    let mut changed_auth = auth;
    changed_auth[0] ^= 1;
    assert_ne!(
        Service::forward_native_data_read_projection_root(&root, changed_auth)
            .map_err(|_| "auth projection")?,
        initial
    );
    Ok(())
}

#[test]
fn native_completed_read_final_spent_use_is_neither_reauthenticated_consumed_nor_refunded()
-> TestResult {
    let mut read = PendingNativeRead::start_with_uses(false, Duration::from_secs(15), 1)?;
    assert_eq!(read.remaining()?, Some(0));
    read.mutate(
        "POST",
        RETAINED_PATH,
        json!({"options":{"cas":1},"data":{"value":"after-final-read-use"}}),
        200,
    )?;
    let mut delivered = read.finish()?;
    assert_eq!(delivered.status, 200);
    assert_eq!(delivered.body["data"]["data"]["value"], "one-real-read");
    assert_eq!(read.remaining()?, Some(0));
    assert!(read.finish().is_err());
    erase_json(&mut delivered.body);
    Ok(())
}
