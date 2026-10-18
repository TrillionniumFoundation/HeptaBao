//! Complete actual Service history through real pinned mTLS fsync quorum.
//! Three durable Raft nodes use the explicitly in-process RPC router. Only
//! voter 3's ciphertext listener is offline. No physical-host HA or Service
//! response/publication guard is claimed by this component integration test.
use super::*;
use heptabao_ha_service::replicate_native_v6_closure_to_quorum;
use heptabao_raft_runtime::with_read_index_deadline;

#[path = "service_native_v6_ha_mtls_fixture.rs"]
mod fixture;
use fixture::{LiveReceivers, tls_fixture};

const REQUEST_BUDGET: Duration = Duration::from_secs(15);

fn failed(phase: &'static str, began: Instant) -> String {
    format!(
        "native TLS 34MiB phase={phase} failed at elapsed_ms={} with original_budget_ms={}",
        began.elapsed().as_millis(),
        REQUEST_BUDGET.as_millis()
    )
}

fn completed(phase: &'static str, began: Instant) {
    eprintln!(
        "native TLS 34MiB phase={phase} elapsed_ms={} original_budget_ms={}",
        began.elapsed().as_millis(),
        REQUEST_BUDGET.as_millis()
    );
}

// This fixture seeds a real typed V5 source root, not an empty placeholder or
// numeric acknowledgement. Actual generated TLS leaf pins enter consensus.
fn enroll_tls_and_anchor(
    cluster: &Cluster,
    codec: &ClusterStateCodec,
    service: &Service,
    pins: BTreeMap<u64, [u8; 32]>,
) -> TestResult<(NativeV6PeerEnrollment, [u8; 32], u64)> {
    let state = service.state.as_ref().ok_or("actual V5 source state")?;
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
        let sealed = codec.seal_record_root(
            "native-mtls-real-v5-source",
            &RecordRootBase::Empty,
            &plan.root,
        )?;
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
                pins,
                Instant::now() + Duration::from_secs(8),
            )
            .await?;
        Ok((enrollment, source, receipt.log_index))
    })
}

#[test]
fn native_ha_actual_34mib_history_pinned_mtls_two_voters_original_15s_and_cold_rewrap() -> TestResult
{
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
    let pki = files.path.join("mtls-pki");
    private_directory(&pki)?;
    let tls = tls_fixture(&pki)?;
    let mut cluster = Cluster::new(files.path.join("mtls-raft"))?;
    let (enrollment, prior_digest, prior_index) =
        enroll_tls_and_anchor(&cluster, &codec, &service, tls.pins.clone())?;
    assert_eq!(enrollment.epoch(), 0);
    assert!(enrollment.pins() == &tls.pins);
    let local_target = native_blob_source::ha_local_stage::tests::RewrapTarget::prepare(
        &service,
        files.path.join("mtls-local-cold-target"),
    )?;
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
    let actual_local = service.current_state_identity().map_err(|_| "local root")?;
    let sender = stage(&files.path.join("mtls-sender"))?;
    let mut stores = Vec::new();
    for id in 1..=3 {
        stores.push(Arc::new(stage(
            &files.path.join(format!("mtls-cipher-{id}")),
        )?));
    }
    let nodes: Vec<_> = std::mem::take(&mut cluster.nodes)
        .into_iter()
        .map(Arc::new)
        .collect();
    let live = LiveReceivers::start(&nodes, cluster.runtime.handle(), &stores, &enrollment, &tls)?;
    let transport = live.transport(tls.clients[&1].clone())?;

    // Passive role/membership checks avoid treating a remembered leader hint
    // as write readiness. The subsequent real ReadIndex remains mandatory.
    cluster.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let role = nodes[0].local_leader_observation()?;
                let membership = nodes[0].membership_observation().await?;
                if role.local_is_leader
                    && role.leader == Some(1)
                    && role.term == membership.term
                    && membership.committed
                    && !membership.joint
                    && membership.voters == BTreeSet::from([1, 2, 3])
                    && role.committed_index.is_some_and(|index| {
                        role.applied_index.is_some_and(|applied| applied >= index)
                    })
                    && [2, 3].into_iter().all(|id| {
                        membership
                            .peer_contact_ms
                            .get(&id)
                            .is_some_and(|age| age.is_some_and(|age| age <= 400))
                            && membership.peer_matched.get(&id).is_some_and(|matched| {
                                matched.is_some_and(|matched| {
                                    role.committed_index
                                        .is_some_and(|committed| matched >= committed)
                                })
                            })
                    })
                {
                    let (witness, _, _) = nodes[0].application_read_witness().await?;
                    nodes[0].verify_application_read_witness(&witness).await?;
                    return Ok::<_, RemoteRaftError>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
    })??;

    // One original request: preparation, all real network/file work, final
    // admission and the only root CAS share this exact 15-second deadline.
    // The runtime's final admission retains its normal max 8-second ReadIndex
    // witness bound; neither component is given an extended retry deadline.
    let began = Instant::now();
    let original_scope = RequestDeadlineScope::enter(began + REQUEST_BUDGET);
    let original = OriginalDeadline::capture()?;
    let current = service
        .state
        .as_ref()
        .ok_or("current source state")?
        .clone();
    let plan = service
        .prepare_native_live_root_checked(&current, &mut |_| Ok(()))
        .map_err(|_| failed("typed-plan", began))?;
    assert_eq!(plan.deadline.instant(), original.instant());
    let schema = plan.root.state_schema;
    let prepared = {
        let durable = service.durable.as_mut().ok_or("actual durable source")?;
        let source = native_blob_source::NativeSource::new_checked(durable, original, || Ok(()))?;
        prepare_native_v6_ha_objects(
            &plan,
            &codec,
            &enrollment,
            &sender,
            Some(&source),
            None,
            &mut || Ok(()),
        )
        .map_err(|_| failed("typed-closure-prepare", began))?
    };
    completed("typed-closure-prepared", began);
    assert!(prepared.local_closure().ciphertext_bytes() >= 34 * 1024 * 1024);
    eprintln!(
        "native TLS 34MiB leaf_count={} ciphertext_bytes={}",
        prepared.references().len(),
        prepared.local_closure().ciphertext_bytes()
    );
    let intent = intent(&prepared, &enrollment, prior_digest, prior_index);
    let expected = intent.proposed_root_digest;
    let proposal = prepared
        .into_proposal(&codec, &enrollment, intent, &mut || Ok(()))
        .map_err(|_| failed("proposal-seal", began))?;
    let stage_intent = SealedRecordObject::new_native_v6_commit_intent(proposal.intent())?;
    let origin = cluster
        .runtime
        .block_on(async {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(original.instant()),
                with_read_index_deadline(original.instant(), async {
                    nodes[0]
                        .stage_application_object(
                            nodes[0].next_production_client_serial().await?,
                            &stage_intent,
                        )
                        .await
                }),
            )
            .await
        })
        .map_err(|_| failed("intent-timeout", began))?
        .map_err(|_| failed("intent-stage", began))?;
    completed("intent-committed", began);
    let quorum = replicate_native_v6_closure_to_quorum(
        &nodes[0],
        cluster.runtime.handle(),
        &transport,
        &live.routes,
        &sender,
        proposal.references(),
        &proposal.intent(),
        original.instant(),
    );
    if quorum.is_err() {
        completed("quorum-failed", began);
        for id in 1..=3 {
            let observed = fs::read_dir(files.path.join(format!("mtls-cipher-{id}")))?
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with("v6-") && name.ends_with(".blob"))
                })
                .count();
            // Physical names are diagnostic counts, never accepted fsync votes.
            eprintln!(
                "native TLS 34MiB voter={id} observed_blob_files={observed} expected_leaf_count={}",
                proposal.references().len()
            );
        }
        assert!(
            cluster
                .runtime
                .block_on(nodes[0].native_v6_root_at_generation())
                .1
                .is_none()
        );
        assert_eq!(
            service
                .current_state_identity()
                .map_err(|_| "local identity")?,
            actual_local
        );
    }
    let quorum = quorum.map_err(|_| failed("pinned-tls-full-closure-quorum", began))?;
    completed("pinned-tls-full-closure-quorum", began);
    assert_eq!(quorum.voter_ids(), &[1, 2]);
    assert_eq!(quorum.intent(), &proposal.intent());
    assert_eq!(quorum.enrollment().digest(), enrollment.digest());
    original.check()?;
    cluster
        .runtime
        .block_on(quorum.verify_for_publication(&nodes[0]))
        .map_err(|_| failed("final-original-admission", began))?;
    original.check()?;
    let published = cluster
        .runtime
        .block_on(async {
            nodes[0]
                .publish_native_v6_root(
                    nodes[0].next_production_client_serial().await?,
                    &proposal.intent(),
                    &origin,
                    &enrollment,
                    proposal.sealed_root().to_vec(),
                    original.instant(),
                )
                .await
        })
        .map_err(|_| failed("single-root-cas", began))?;
    original.check()?;
    completed("root-cas-reconciled", began);
    assert!(began.elapsed() < REQUEST_BUDGET);
    assert_eq!(published.root_digest(), expected);
    assert!(service.ha.is_none());
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "local identity")?,
        actual_local
    );
    assert!(
        fs::read_dir(files.path.join("mtls-cipher-3"))?
            .next()
            .is_none(),
        "offline ciphertext voter must never receive an implicit local copy"
    );
    let committed_index = published.publication_log_id().index;

    // Stop and join real TLS owners before releasing ProcessRaftNode Arcs.
    // Recovery is a separate operation, not an extension of the write request.
    drop((live, transport, quorum, original_scope));
    for node in nodes {
        cluster.nodes.push(
            Arc::try_unwrap(node).map_err(|_| "TLS receiver retained a Raft owner after stop")?,
        );
    }
    for node in &cluster.nodes {
        cluster.runtime.block_on(node.ensure_linearizable())?;
        let observed = cluster.runtime.block_on(node.snapshot_observed())?;
        assert!(observed.persisted_index >= committed_index);
        assert!(observed.byte_count < 1024 * 1024);
    }
    drop((
        published, proposal, plan, current, service, codec, enrollment, key, token, sender, stores,
        tls,
    ));
    fs::remove_dir_all(files.path.join("data"))?;
    cluster.cold_reopen()?;
    for (position, node) in cluster.nodes.iter().enumerate() {
        let _scope = scope();
        let deadline = OriginalDeadline::capture()?;
        let (witness, enrollment, published) = cluster
            .runtime
            .block_on(node.native_v6_application_read_witness(deadline.instant()))?;
        let enrollment = enrollment.ok_or("cold real TLS enrollment")?;
        let published = published.ok_or("cold selected root")?;
        assert_eq!(published.root_digest(), expected);
        let codec = ClusterStateCodec::new(&cluster_id, [59; 32])?;
        let replica = LocalV6BlobStage::open_existing(
            &files.path.join(format!("mtls-cipher-{}", position + 1)),
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
        );
        if position == 2 {
            assert!(
                received.is_err(),
                "committed root does not invent the offline voter's missing closure"
            );
            cluster
                .runtime
                .block_on(node.verify_application_read_witness(&witness))?;
            continue;
        }
        let received = received?;
        let mut actor = || Ok(());
        let gate = RefCell::new(OriginalGate {
            deadline,
            actor: &mut actor,
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
            .ok_or("cold native KV2")?;
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
    }
    cluster.shutdown()?;
    Ok(())
}
