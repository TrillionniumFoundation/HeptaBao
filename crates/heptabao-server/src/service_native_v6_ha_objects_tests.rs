//! Real Service/barrier objects, three durable Raft stores and cold shared-key
//! recovery. The RPC router and enrolled TLS pins are synthetic: this suite
//! does not claim physical mTLS quorum delivery or a native Service HA ACK.
use super::*;

#[cfg(unix)]
#[path = "service_native_v6_ha_mtls_tests.rs"]
mod mtls_tests;
use crate::request_deadline::RequestDeadlineScope;
use crate::service::tests::{Root, bootstrap};
use crate::state_record_root::StateIdentity;
use crate::state_records::RecordReader;
use futures::future::BoxFuture;
use heptabao_raft_runtime::{
    ProcessRaftNode, PublishedRecordRoot, RaftPeerRpc, RaftRpcKind, RaftRpcService, RecordRootBase,
    RemoteNetworkFactory, RemoteRaftError, ReplicatedEnvelope, SealedRecordObject,
};
use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::Instant;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Default)]
struct Router(Mutex<BTreeMap<u64, RaftRpcService>>);
#[derive(Clone, Debug)]
struct SharedRouter(Arc<Router>);
impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeV6CodecTestRouter")
    }
}
impl RaftPeerRpc for SharedRouter {
    fn exchange(
        &self,
        source: u64,
        target: u64,
        kind: RaftRpcKind,
        bytes: Vec<u8>,
        _timeout: Duration,
    ) -> BoxFuture<'static, Result<Vec<u8>, RemoteRaftError>> {
        let router = Arc::clone(&self.0);
        Box::pin(async move {
            let peer = router
                .0
                .lock()
                .map_err(|_| RemoteRaftError::InvalidTopology)?
                .get(&target)
                .cloned()
                .ok_or(RemoteRaftError::InvalidTopology)?;
            peer.handle(source, kind, bytes).await
        })
    }
}

struct Cluster {
    runtime: tokio::runtime::Runtime,
    nodes: Vec<ProcessRaftNode>,
    router: Arc<Router>,
    path: PathBuf,
}
impl Cluster {
    fn new(path: PathBuf) -> TestResult<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()?;
        let router = Arc::new(Router::default());
        let mut nodes = Vec::new();
        for id in 1..=3 {
            let network = RemoteNetworkFactory::new(
                id,
                BTreeSet::from([1, 2, 3]),
                Arc::new(SharedRouter(Arc::clone(&router))),
            )?;
            let node = runtime.block_on(ProcessRaftNode::create(
                path.join(id.to_string()),
                id,
                network,
            ))?;
            router
                .0
                .lock()
                .map_err(|_| "router")?
                .insert(id, node.rpc_service());
            nodes.push(node);
        }
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(12), async {
                nodes[0].initialize_single().await?;
                while nodes[0].current_leader().await != Some(1) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                nodes[0].add_learner(2).await?;
                nodes[0].add_learner(3).await?;
                nodes[0]
                    .change_membership(BTreeSet::from([1, 2, 3]))
                    .await?;
                nodes[0].ensure_linearizable().await
            })
            .await
        })??;
        Ok(Self {
            runtime,
            nodes,
            router,
            path,
        })
    }
    fn cold_reopen(&mut self) -> TestResult {
        for node in self.nodes.drain(..) {
            self.runtime.block_on(node.shutdown())?;
        }
        self.router.0.lock().map_err(|_| "router")?.clear();
        for id in 1..=3 {
            let network = RemoteNetworkFactory::new(
                id,
                BTreeSet::from([1, 2, 3]),
                Arc::new(SharedRouter(Arc::clone(&self.router))),
            )?;
            let node = self.runtime.block_on(ProcessRaftNode::reopen(
                self.path.join(id.to_string()),
                id,
                network,
            ))?;
            self.router
                .0
                .lock()
                .map_err(|_| "router")?
                .insert(id, node.rpc_service());
            self.nodes.push(node);
        }
        self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    for node in &self.nodes {
                        if node.current_leader().await == Some(node.id()) {
                            node.ensure_linearizable().await?;
                            return Ok::<_, RemoteRaftError>(());
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
        })??;
        Ok(())
    }
    fn shutdown(&mut self) -> TestResult {
        for node in self.nodes.drain(..) {
            self.runtime.block_on(node.shutdown())?;
        }
        self.router.0.lock().map_err(|_| "router")?.clear();
        Ok(())
    }
}
impl Drop for Cluster {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn scope() -> RequestDeadlineScope {
    RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(60))
}

fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _scope = scope();
    let response = service.handle(method, path, "", token, body);
    if response.status >= 400 {
        // Fixed error fields only. Never print a token, private owner or body.
        let errors: Vec<_> = response
            .body
            .get("errors")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        eprintln!(
            "native HA codec {path}: HTTP {} errors={errors:?}",
            response.status
        );
    }
    response
}

fn initialized() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_candidate()?;
    let (key, token) = {
        let _scope = scope();
        bootstrap(&mut service)?
    };
    Ok((files, service, Zeroizing::new(key), Zeroizing::new(token)))
}

fn stage(path: &Path) -> TestResult<LocalV6BlobStage> {
    private_directory(path)?;
    Ok(LocalV6BlobStage::open_existing(path)?)
}

fn enroll_and_anchor(
    cluster: &Cluster,
    codec: &ClusterStateCodec,
    service: &Service,
) -> TestResult<(NativeV6PeerEnrollment, [u8; 32], u64)> {
    let state = service.state.as_ref().ok_or("actual source state")?;
    let plan = service
        .full_existing_record_plan(state)
        .map_err(|_| "actual V5 source closure")?;
    let source = plan.identity.digest();
    let key = plan.root.address_key();
    cluster.runtime.block_on(async {
        let node = &cluster.nodes[0];
        for object in &plan.objects {
            let sealed = codec.seal_record_object(&key, object)?;
            node.stage_application_object(node.next_production_client_serial().await?, &sealed)
                .await?;
        }
        let sealed =
            codec.seal_record_root("native-codec-v5-source", &RecordRootBase::Empty, &plan.root)?;
        let root = PublishedRecordRoot::new(
            RecordRootBase::Empty,
            ReplicatedEnvelope::new(
                sealed.operation_id(),
                sealed.digest(),
                sealed.sealed().to_vec(),
            )?,
            plan.root
                .references()
                .map(crate::ha_state::runtime_reference)
                .collect(),
        )?;
        let receipt = node
            .publish_application_root(node.next_production_client_serial().await?, &root)
            .await?;
        let enrollment = node
            .enroll_native_v6_peers(
                node.next_production_client_serial().await?,
                codec.native_v6_cluster_digest(),
                plan.root.replay_epoch,
                BTreeMap::from([(1, [21; 32]), (2, [22; 32]), (3, [23; 32])]),
                Instant::now() + Duration::from_secs(5),
            )
            .await?;
        Ok((enrollment, source, receipt.log_index))
    })
}

fn intent(
    prepared: &PreparedNativeV6HaObjects,
    enrollment: &NativeV6PeerEnrollment,
    prior: [u8; 32],
    index: u64,
) -> NativeV6CommitIntent {
    let local = prepared.local_closure();
    NativeV6CommitIntent {
        cluster_digest: enrollment.cluster_digest(),
        epoch: enrollment.epoch(),
        operation_digest: [87; 32],
        closure_manifest_sha256: local.manifest_sha256(),
        object_count: local.object_count() as u64,
        ciphertext_bytes: local.ciphertext_bytes(),
        prior_root_digest: prior,
        proposed_root_digest: prepared.root_digest(),
        prior_generation: 0,
        proposed_generation: 1,
        expected_previous_commit_index: index,
    }
}

fn unique_payload(version: usize) -> String {
    let mut value = String::with_capacity(2 * 1024 * 1024);
    for index in 0..512 {
        let marker = format!("native-shared-codec/{version:04}/{index:04}/");
        value.push_str(&marker);
        value.extend(std::iter::repeat_n('x', 4096 - marker.len()));
    }
    value
}

struct DomainReader<'a, S> {
    source: &'a S,
    domain: ObjectDomain,
}
impl<S: ObjectSource> RecordReader for DomainReader<'_, S> {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        self.source.read(&self.domain, reference)
    }
}

#[test]
fn native_ha_shared_codec_real_34mib_history_three_raft_cold_recovery_and_missing_blob()
-> TestResult {
    let (files, mut service, key, token) = initialized()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/config",
            &token,
            json!({"max_versions": 30})
        )
        .status,
        204
    );
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let codec = ClusterStateCodec::new(&cluster_id, [59; 32])?;
    let mut cluster = Cluster::new(files.path.join("cipher-raft"))?;
    let (enrollment, prior_digest, prior_index) = enroll_and_anchor(&cluster, &codec, &service)?;
    let local_target = native_blob_source::ha_local_stage::tests::RewrapTarget::prepare(
        &service,
        files.path.join("local-cold-target"),
    )?;
    assert_eq!(
        enrollment.epoch(),
        0,
        "actual initialized Service replay epoch is not fabricated"
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/internal/native-v6/activate",
            &token,
            json!({})
        )
        .status,
        204
    );
    for version in 1..=17 {
        assert_eq!(call(&mut service, "POST", "secret/data/cipher-history", &token,
            json!({"options":{"cas":version-1},"data":{"version":version,"blob":unique_payload(version)}})).status, 200);
    }
    let actual_local = service
        .current_state_identity()
        .map_err(|_| "source identity")?;
    let original = scope();
    let current = service.state.as_ref().ok_or("state")?.clone();
    let plan = service
        .prepare_native_live_root_checked(&current, &mut |_| Ok(()))
        .map_err(|_| "actual native source plan")?;
    assert_eq!(plan.root.identity().map_err(|_| "identity")?, actual_local);
    let schema = plan.root.state_schema;
    let sender_path = files.path.join("replication-sender");
    let sender = stage(&sender_path)?;
    let mut checks = 0usize;
    let prepared = {
        let durable = service.durable.as_mut().ok_or("actual durable source")?;
        let source =
            native_blob_source::NativeSource::new_checked(durable, plan.deadline, || Ok(()))?;
        prepare_native_v6_ha_objects(
            &plan,
            &codec,
            &enrollment,
            &sender,
            Some(&source),
            None,
            &mut || {
                checks += 1;
                Ok(())
            },
        )?
    };
    assert!(checks > 500, "original gate surrounds actual object work");
    assert!(prepared.local_closure().ciphertext_bytes() >= 34 * 1024 * 1024);
    assert!(
        prepared
            .references()
            .iter()
            .all(|reference| reference.encoded_bytes <= 256 * 1024)
    );
    let intent = intent(&prepared, &enrollment, prior_digest, prior_index);
    let expected = intent.proposed_root_digest;
    let proposal = prepared.into_proposal(&codec, &enrollment, intent, &mut || Ok(()))?;
    assert!(proposal.sealed_root().len() <= crate::state_record_root::MAX_ROOT_BYTES + 69);
    // Every target gets only explicit bounded ciphertext leaves, never a copy
    // of the source's local-barrier .hbo files or its unseal key.
    let mut replicas = Vec::new();
    for id in 1..=3 {
        let target = stage(&files.path.join(format!("replication-{id}")))?;
        for reference in proposal.references() {
            let bytes = sender.read_local(reference)?;
            target.stage_received_replica_checked(reference, &bytes, &mut || Ok(()))?;
        }
        let local = target.persist_local_closure(proposal.references(), &mut || Ok(()))?;
        assert_eq!(local.manifest_sha256(), intent.closure_manifest_sha256);
        replicas.push(target);
    }
    let published = cluster.runtime.block_on(async {
        let node = &cluster.nodes[0];
        let object = SealedRecordObject::new_native_v6_commit_intent(proposal.intent())?;
        let receipt = node
            .stage_application_object(node.next_production_client_serial().await?, &object)
            .await?;
        node.publish_native_v6_root(
            node.next_production_client_serial().await?,
            &proposal.intent(),
            &receipt,
            &enrollment,
            proposal.sealed_root().to_vec(),
            Instant::now() + Duration::from_secs(5),
        )
        .await
    })?;
    let committed_index = published.publication_log_id().index;
    for node in &cluster.nodes {
        cluster.runtime.block_on(node.ensure_linearizable())?;
        let observed = cluster.runtime.block_on(node.snapshot_observed())?;
        assert!(observed.persisted_index >= committed_index);
        assert!(
            observed.byte_count < 1024 * 1024,
            "34 MiB history must remain outside Raft snapshot"
        );
    }
    assert!(
        service.ha.is_none(),
        "this suite does not enable Service HA admission"
    );
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "local identity")?,
        actual_local
    );
    // Erase every warm typed owner, barrier key and codec handle, then remove
    // only this test's source Service files. Reopening must use copied ciphertext.
    drop((
        published, proposal, plan, current, service, codec, enrollment, key, token, sender,
        original,
    ));
    fs::remove_dir_all(files.path.join("data"))?;
    cluster.cold_reopen()?;
    drop(replicas);
    for (position, node) in cluster.nodes.iter().enumerate() {
        let _scope = scope();
        let deadline = OriginalDeadline::capture()?;
        let (witness, enrollment, published) = cluster
            .runtime
            .block_on(node.native_v6_application_read_witness(deadline.instant()))?;
        let enrollment = enrollment.ok_or("cold enrollment")?;
        let published = published.ok_or("cold root")?;
        assert_eq!(published.root_digest(), expected);
        let codec = ClusterStateCodec::new(&cluster_id, [59; 32])?;
        let replica = LocalV6BlobStage::open_existing(
            &files.path.join(format!("replication-{}", position + 1)),
        )?;
        let context = ReadContext {
            expected_identity: ReadIdentity::RecordsV6(expected),
            cluster_id: &cluster_id,
            replay_epoch: 0,
            minimum_state_schema: schema,
            maximum_state_schema: schema,
            reader_format: 6,
        };
        let received = open_native_v6_ha_objects(
            &codec,
            &enrollment,
            &published,
            &replica,
            context,
            deadline,
            &mut || Ok(()),
        )?;
        assert_eq!(
            received.root().identity().map_err(|_| "typed identity")?,
            StateIdentity::RecordsV6(expected)
        );
        let mut original_actor = || Ok(());
        let gate = RefCell::new(OriginalGate {
            deadline,
            actor: &mut original_actor,
        });
        let source = CipherSource {
            codec: &codec,
            store: &replica,
            closure: received.cipher_closure(),
            gate: &gate,
        };
        let (mount, view) = received
            .native
            .iter()
            .find(|(mount, _)| mount.mount == "secret/")
            .ok_or("native KV2 view")?;
        assert_eq!(view.counts(), (1, 17, 17));
        let reader = DomainReader {
            source: &source,
            domain: ObjectDomain::Kv2(mount.clone()),
        };
        for version in [1, 9, 17] {
            let response = view.read_with_source(
                "GET",
                "data/cipher-history",
                &json!({"version":version}),
                crate::auth::Timestamp::whole(200)?,
                &reader,
            )?;
            assert_eq!(response.status, 200);
            assert_eq!(response.body["data"]["data"]["version"], version);
            assert!(
                response.body["data"]["data"]["blob"].as_str()
                    == Some(unique_payload(version).as_str())
            );
        }
        if position == 0 {
            local_target.exercise(&received, &codec, &replica)?;
        }
        cluster
            .runtime
            .block_on(node.verify_application_read_witness(&witness))?;
        let wrong_key = ClusterStateCodec::new(&cluster_id, [60; 32])?;
        assert!(
            open_native_v6_ha_objects(
                &wrong_key,
                &enrollment,
                &published,
                &replica,
                context,
                deadline,
                &mut || Ok(())
            )
            .is_err()
        );
        let foreign = ClusterStateCodec::new("foreign-native-codec-cluster", [59; 32])?;
        assert!(
            open_native_v6_ha_objects(
                &foreign,
                &enrollment,
                &published,
                &replica,
                context,
                deadline,
                &mut || Ok(())
            )
            .is_err()
        );
        if position == 0 {
            let selected = received
                .cipher_closure()
                .references()
                .first()
                .ok_or("cipher leaf")?;
            let mut name = String::from("v6-");
            for byte in selected.id {
                use std::fmt::Write;
                write!(&mut name, "{byte:02x}")?;
            }
            name.push_str(".blob");
            let path = files.path.join("replication-1").join(name);
            let bytes = fs::read(&path)?;
            fs::remove_file(&path)?;
            assert!(
                open_native_v6_ha_objects(
                    &codec,
                    &enrollment,
                    &published,
                    &replica,
                    context,
                    deadline,
                    &mut || Ok(())
                )
                .is_err()
            );
            let (_, _, still) = cluster
                .runtime
                .block_on(node.native_v6_application_read_witness(deadline.instant()))?;
            assert_eq!(
                still.ok_or("root retained on missing blob")?.root_digest(),
                expected
            );
            replica.stage_received_replica_checked(selected, &bytes, &mut || Ok(()))?;
        }
    }
    cluster.shutdown()?;
    Ok(())
}

#[path = "ha_native_v6_backup_tests.rs"]
mod backup_tests;

#[test]
fn native_ha_preparation_real_v5_missing_typed_object_actor_revocation_and_expired_original_budget()
-> TestResult {
    let (files, mut service, _key, token) = initialized()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/migrate",
            &token,
            json!({"data":{"value":"synthetic migration"}})
        )
        .status,
        200
    );
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let codec = ClusterStateCodec::new(&cluster_id, [62; 32])?;
    let mut cluster = Cluster::new(files.path.join("preparation-raft"))?;
    let (enrollment, old_root, index) = enroll_and_anchor(&cluster, &codec, &service)?;
    let _scope = scope();
    let mut plan = service
        .prepare_native_root_migration_paged(&|| Ok(()))
        .map_err(|_| "native source plan")?;
    let store = stage(&files.path.join("preparation-cipher"))?;
    let removed = plan.objects.pop_first().ok_or("owner object")?;
    assert!(
        prepare_native_v6_ha_objects(&plan, &codec, &enrollment, &store, None, None, &mut || Ok(
            ()
        ))
        .is_err()
    );
    plan.objects.insert(removed.0, removed.1);
    let mut checked = 0usize;
    assert!(
        prepare_native_v6_ha_objects(&plan, &codec, &enrollment, &store, None, None, &mut || {
            checked += 1;
            if checked >= 25 {
                Err(NativeV6CodecError::Gate)
            } else {
                Ok(())
            }
        })
        .is_err()
    );
    assert!(checked >= 25);
    let prepared =
        prepare_native_v6_ha_objects(&plan, &codec, &enrollment, &store, None, None, &mut || {
            Ok(())
        })?;
    let declaration = intent(&prepared, &enrollment, old_root, index);
    // A different manifest/length cannot reuse a prepared directory seal.
    let mut wrong = declaration;
    wrong.closure_manifest_sha256[0] ^= 1;
    assert!(
        prepared
            .closure
            .seal_root(&codec, &enrollment, &wrong, &mut || Ok(()))
            .is_err()
    );
    let short = {
        let _short = RequestDeadlineScope::enter(Instant::now() + Duration::from_millis(2));
        OriginalDeadline::capture()?
    };
    std::thread::sleep(Duration::from_millis(5));
    plan.deadline = short;
    let count = fs::read_dir(files.path.join("preparation-cipher"))?.count();
    assert!(
        prepare_native_v6_ha_objects(&plan, &codec, &enrollment, &store, None, None, &mut || Ok(
            ()
        ))
        .is_err()
    );
    assert_eq!(
        fs::read_dir(files.path.join("preparation-cipher"))?.count(),
        count
    );
    let expired = PreparedNativeV6HaObjects {
        closure: prepared.closure,
        deadline: short,
    };
    assert!(
        expired
            .into_proposal(&codec, &enrollment, declaration, &mut || Ok(()))
            .is_err()
    );
    let (_, _, native) = cluster.runtime.block_on(
        cluster.nodes[0]
            .native_v6_application_read_witness(Instant::now() + Duration::from_secs(5)),
    )?;
    assert!(
        native.is_none(),
        "no failed preparation can publish a consensus root"
    );
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "local V5 root")?,
        StateIdentity::RecordsV5(old_root)
    );
    cluster.shutdown()?;
    Ok(())
}
