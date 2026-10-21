//! The actual local Service owner consumes real three-node Raft selections.
//! Ciphertext transport is an explicit fixture copy here; this does not replace
//! the independently executed full pinned-mTLS quorum regression or exercise an
//! HTTP HA write route. Source credentials and all payloads are synthetic.
use super::*;
use crate::ha::snapshot_test_support::Cluster;
use crate::request_deadline::RequestDeadlineScope;
use crate::service::native_v6_ha_objects::{NativeV6HaProposal, prepare_native_v6_ha_objects};
use crate::service::tests::{Root, bootstrap};
use crate::state_record_root_v6::{ObjectDomain, OwnerDomain};
use crate::state_records::{ObjectRef, RecordError, RecordReader};
use crate::v6_read_validation::ObjectSource;
use heptabao_durable_service::PutRequest;
use heptabao_raft_runtime::{NativeV6CommitIntent, NativeV6PeerEnrollment};
use std::time::Instant;

#[path = "service_native_v6_ha_archive_repair_tests.rs"]
mod archive_repair_tests;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const REQUEST_BUDGET: Duration = Duration::from_secs(15);

fn scope() -> RequestDeadlineScope {
    RequestDeadlineScope::enter(Instant::now() + REQUEST_BUDGET)
}
fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _scope = scope();
    let response = service.handle(method, path, "", token, body);
    if response.status >= 400 {
        let errors: Vec<_> = response
            .body
            .get("errors")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        eprintln!(
            "native HA installer {path}: HTTP {} errors={errors:?}",
            response.status
        );
    }
    response
}
fn initialized() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, token) = {
        let _scope = scope();
        bootstrap(&mut service)?
    };
    Ok((files, service, Zeroizing::new(key), Zeroizing::new(token)))
}
fn populate(service: &mut Service, token: &str, count: usize) {
    for index in 0..count {
        assert_eq!(
            call(
                service,
                "POST",
                &format!("secret/data/install/{index:03}"),
                token,
                json!({"options":{"cas":0},"data":{"index":index,"value":"r".repeat(512)}})
            )
            .status,
            200
        );
    }
    for version in 1..=4 {
        assert_eq!(call(service, "POST", "secret/data/install-history", token,
            json!({"options":{"cas":version-1},"data":{"version":version,"value":format!("synthetic-history-{version}")}})).status, 200);
    }
    assert_eq!(
        call(
            service,
            "POST",
            "secret/delete/install-history",
            token,
            json!({"versions":[2]})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            service,
            "POST",
            "secret/destroy/install-history",
            token,
            json!({"versions":[1]})
        )
        .status,
        204
    );
}
fn seed_different_local_barrier(source: &Service, target: &mut Service) -> TestResult {
    let state = source.state.as_ref().ok_or("source state")?.clone();
    let plan = source
        .full_existing_record_plan(&state)
        .map_err(|_| "source V5 closure")?;
    assert!(
        source.barrier_key.as_ref().ok_or("source key")?.as_slice()
            != target.barrier_key.as_ref().ok_or("target key")?.as_slice()
    );
    let durable = target.durable.as_mut().ok_or("target durable")?;
    let selected = durable.get("system", "state")?.ok_or("target seed root")?;
    // Explicit test seeding under the target's independent actual barrier. The
    // subsequent installer must authenticate this complete selected V5 graph.
    for (batch, objects) in plan
        .objects
        .chunks(heptabao_durable_service::MAX_ATOMIC_MUTATIONS)
        .enumerate()
    {
        durable.apply_batch_conditionally_before_publish(
            BatchPublication {
                replay_epoch: 0,
                principal: "native-install-fixture".into(),
                namespace: "system".into(),
                request_id: format!("seed-v5-objects-{batch}"),
                authorization_digest: plan.identity.digest(),
                mutations: objects
                    .iter()
                    .map(|object| {
                        Ok((
                            object.reference().resource(),
                            Some(Secret::new(object.bytes().to_vec())?),
                        ))
                    })
                    .collect::<Result<_, ServiceError>>()?,
            },
            vec![PublicationCondition {
                resource: "state".into(),
                expected: Some(selected.clone()),
            }],
            &mut || Ok(()),
        )?;
    }
    put(durable, "seed-v5-root", "state", plan.bytes.as_slice())?;
    target.state = Some(state);
    target.state_digest = Some(plan.identity.digest());
    target.record_root = Some(plan.root);
    target.native_root = None;
    Ok(())
}
fn put(
    durable: &mut DurableService<AeadBarrier>,
    id: &str,
    resource: &str,
    bytes: &[u8],
) -> TestResult {
    durable.put(PutRequest::new(
        "native-install-fixture",
        "system",
        id,
        resource,
        [117; 32],
        Secret::new(bytes.to_vec())?,
    )?)?;
    Ok(())
}
fn cluster(source: &Service, path: &Path) -> TestResult<(Cluster, NativeV6PeerEnrollment, u64)> {
    let state = source.state.as_ref().ok_or("source state")?;
    let cluster = Cluster::new(path, &state.cluster_id)?;
    for process in &cluster.processes {
        process
            .lock()
            .map_err(|_| "fixture process lock")?
            .native_install_test_enable()?;
    }
    let plan = source
        .full_existing_record_plan(state)
        .map_err(|_| "source V5 records")?;
    let (enrollment, previous_index) = cluster.processes[0]
        .lock()
        .map_err(|_| "fixture leader lock")?
        .native_install_test_anchor_v5(&plan.root, &plan.objects)?;
    Ok((cluster, enrollment, previous_index))
}
fn publish(
    source: &mut Service,
    cluster: &Cluster,
    enrollment: &NativeV6PeerEnrollment,
    prior_digest: [u8; 32],
    prior_generation: u64,
    previous_index: u64,
) -> TestResult<(NativeV6PublishedRoot, usize)> {
    let _scope = scope();
    let plan = source
        .prepare_native_root_migration_paged(&|| Ok(()))
        .map_err(|_| "actual source native projection")?;
    let count = plan.objects.len();
    let proposal: NativeV6HaProposal = cluster.processes[0]
        .lock()
        .map_err(|_| "fixture leader lock")?
        .native_install_test_with_source(|codec, store| {
            let prepared = prepare_native_v6_ha_objects(
                &plan,
                codec,
                enrollment,
                store,
                None,
                None,
                &mut || Ok(()),
            )?;
            let local = prepared.local_closure();
            let generation = prior_generation + 1;
            let intent = NativeV6CommitIntent {
                cluster_digest: enrollment.cluster_digest(),
                epoch: enrollment.epoch(),
                operation_digest: crypto::digest(
                    format!("native-install-fixture-{generation}").as_bytes(),
                ),
                closure_manifest_sha256: local.manifest_sha256(),
                object_count: local.object_count() as u64,
                ciphertext_bytes: local.ciphertext_bytes(),
                prior_root_digest: prior_digest,
                proposed_root_digest: prepared.root_digest(),
                prior_generation,
                proposed_generation: generation,
                expected_previous_commit_index: previous_index,
            };
            prepared.into_proposal(codec, enrollment, intent, &mut || Ok(()))
        })??;
    let sender = cluster.processes[0]
        .lock()
        .map_err(|_| "fixture leader lock")?
        .native_install_test_store()?;
    for process in &cluster.processes {
        process
            .lock()
            .map_err(|_| "fixture process lock")?
            .native_install_test_copy_ciphertext(&sender, &proposal)?;
    }
    let published = cluster.processes[0]
        .lock()
        .map_err(|_| "fixture leader lock")?
        .native_install_test_publish(&proposal, enrollment)?;
    Ok((published, count))
}
fn fresh(ha: &Arc<Mutex<HaProcess>>) -> TestResult<CommittedNativeV6Read> {
    let deadline = OriginalDeadline::capture()?;
    ha.lock_for_request()
        .map_err(|_| "actual request lock")?
        .native_v6_committed_read(deadline)?
        .ok_or_else(|| "actual committed V6 root absent".into())
}
fn selected_bytes(service: &Service) -> TestResult<Vec<u8>> {
    Ok(service
        .durable
        .as_ref()
        .ok_or("durable")?
        .get("system", "state")?
        .ok_or("selected root")?
        .expose()
        .to_vec())
}
fn authorize(auth: &AuthState, principal: &Principal, path: &str) -> Result<(), Response> {
    auth.authorize_request(principal, "", path, "read", 100)
        .map_err(|_| Response::error(403, "fixture original principal denied"))
}
fn assert_history_with_real_proof(
    service: &mut Service,
    token: &str,
    last_version: u64,
) -> TestResult {
    let _scope = scope();
    let auth = service
        .state
        .as_ref()
        .ok_or("installed state")?
        .auth
        .clone();
    let principal = auth
        .authenticate_read_only(token, 100)?
        .ok_or("original actual principal")?;
    let mut actor = || authorize(&auth, &principal, "secret/data/install-history");
    let proof = service
        .capture_native_ha_request_proof(&mut actor)
        .map_err(|_| "fresh native HA read proof")?
        .ok_or("proof absent")?;
    proof
        .check_checked(service, &mut actor)
        .map_err(|_| "actual full local read proof")?;
    let root = service.native_root.as_ref().ok_or("native root")?.clone();
    let deadline = OriginalDeadline::capture()?;
    let mut durable = service.durable.take().ok_or("local durable")?;
    let result = (|| -> TestResult {
        let source = native_blob_source::NativeSource::new_checked(&mut durable, deadline, || {
            actor().map_err(|_| ServiceError::BarrierFailure)
        })?;
        let (_, native) = v6_records::materialize_for_service(
            &root,
            context(&root).map_err(|_| "typed local context")?,
            &source,
        )?;
        let (mount, view) = native
            .iter()
            .find(|(mount, _)| mount.mount == "secret/")
            .ok_or("native KV2 mount")?;
        struct Domain<'a, S> {
            source: &'a S,
            domain: ObjectDomain,
        }
        impl<S: ObjectSource> RecordReader for Domain<'_, S> {
            fn read_object(
                &self,
                reference: &ObjectRef,
            ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
                self.source.read(&self.domain, reference)
            }
        }
        let reader = Domain {
            source: &source,
            domain: ObjectDomain::Kv2(mount.clone()),
        };
        for version in 1..=last_version {
            let result = view.read_with_source(
                "GET",
                "data/install-history",
                &json!({"version":version}),
                crate::auth::Timestamp::whole(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs(),
                )?,
                &reader,
            );
            if version <= 2 {
                let status = match result {
                    Ok(response) => response.status,
                    Err(error) => error.status,
                };
                assert_eq!(status, 404, "deleted/destroyed version remains unavailable");
            } else {
                let response = result?;
                assert_eq!(response.status, 200);
                assert_eq!(response.body["data"]["data"]["version"], version);
                assert_eq!(
                    response.body["data"]["data"]["value"],
                    format!("synthetic-history-{version}")
                );
            }
        }
        Ok(())
    })();
    service.durable = Some(durable);
    result?;
    proof
        .check_checked(service, &mut actor)
        .map_err(|_| "post-payload actual same read proof")?;
    Ok(())
}
fn install_warm(service: &mut Service, ha: &Arc<Mutex<HaProcess>>, token: &str) -> TestResult {
    let _scope = scope();
    let principal = service
        .state
        .as_ref()
        .ok_or("V5 source state")?
        .auth
        .authenticate_read_only(token, 100)?
        .ok_or("actual source principal")?;
    let read = fresh(ha)?;
    service
        .sync_native_v6_from_ha_checked(ha, read, &mut |auth| {
            authorize(auth, &principal, "secret/data/install-history")
        })
        .map_err(|_| "actual committed root installation")?;
    Ok(())
}
fn cold_load(
    files: &Root,
    ha: &Arc<Mutex<HaProcess>>,
    barrier: &[u8; 32],
) -> TestResult<(Service, DurableService<AeadBarrier>, ColdNativeHaRead)> {
    let _scope = scope();
    let mut cold = files.service()?;
    cold.ha = Some(ha.clone());
    assert!(cold.state.is_none() && cold.barrier_key.is_none());
    let mut durable =
        DurableService::reopen(&cold.data_dir, AeadBarrier::new(*barrier)?, MAX_OPERATIONS)?;
    let loaded = load_cold_native_ha(&cold, &mut durable, barrier, OriginalDeadline::capture()?)
        .map_err(|_| "actual cold native HA load")?
        .ok_or("cold V6 root absent")?;
    Ok((cold, durable, loaded))
}
fn install_cold_owner(
    mut cold: Service,
    durable: DurableService<AeadBarrier>,
    mut loaded: ColdNativeHaRead,
    barrier: &[u8; 32],
) -> TestResult<Service> {
    // Only fixture ownership setup after the production cold loader succeeded.
    // There is intentionally no HTTP unseal ACK or audit assertion here.
    loaded
        .metadata
        .engines
        .install_native_views(loaded.native)?;
    cold.state_digest = Some(
        loaded
            .root
            .identity()
            .map_err(|error| {
                std::io::Error::other(format!("cold native root identity: {error:?}"))
            })?
            .digest(),
    );
    cold.state = Some(loaded.metadata);
    cold.native_root = Some(loaded.root);
    cold.record_root = None;
    cold.barrier_key = Some(Zeroizing::new(*barrier));
    cold.durable = Some(durable);
    Ok(cold)
}
fn first_owner_file(service: &Service) -> TestResult<(String, PathBuf)> {
    let root = service.native_root.as_ref().ok_or("native root")?;
    let reference = root.owners[0]
        .owner
        .chunks
        .first()
        .ok_or("actual owner chunk")?;
    let resource =
        v6_records::native_resource(&ObjectDomain::Owner(OwnerDomain::ALL[0]), reference);
    let marker = service
        .durable
        .as_ref()
        .ok_or("durable")?
        .get("system", &resource)?
        .ok_or("registered locator")?;
    let bytes = marker.expose();
    if bytes.len() != 72 {
        return Err("fixture locator width".into());
    }
    let path = service.data_dir.join(format!(
        "nv6.{}.{}.hbo",
        hex(&bytes[16..32]),
        hex(&bytes[32..64])
    ));
    assert!(path.is_file());
    Ok((resource, path))
}

#[test]
fn native_ha_install_batches_actual_readindex_cold_missing_and_corrupt_file() -> TestResult {
    let (source_files, mut source, _source_key, token) = initialized()?;
    populate(&mut source, &token, 112);
    let (files, mut target, _target_key, _target_token) = initialized()?;
    seed_different_local_barrier(&source, &mut target)?;
    let prior = source
        .current_state_identity()
        .map_err(|_| "V5 identity")?
        .digest();
    let (cluster, enrollment, index) = cluster(&source, &source_files.path.join("install-raft"))?;
    let (published, object_count) = publish(&mut source, &cluster, &enrollment, prior, 0, index)?;
    assert!(object_count > heptabao_durable_service::MAX_ATOMIC_MUTATIONS);
    let ha = cluster.processes[1].clone();
    target.ha = Some(ha.clone());
    assert!(
        target.native_candidate_profile.is_none(),
        "HA must not borrow the single-node profile"
    );
    let before_generation = target.durable.as_ref().ok_or("durable")?.generation();
    let before_root = selected_bytes(&target)?;
    install_warm(&mut target, &ha, &token)?;
    assert!(selected_bytes(&target)? != before_root);
    assert_eq!(
        target
            .current_state_identity()
            .map_err(|_| "installed identity")?
            .digest(),
        published.root_digest()
    );
    let generation = target.durable.as_ref().ok_or("durable")?.generation();
    assert_eq!(
        generation - before_generation,
        object_count.div_ceil(heptabao_durable_service::MAX_ATOMIC_MUTATIONS) as u64 + 1
    );
    let cursor_bytes = target
        .durable
        .as_ref()
        .ok_or("durable")?
        .get("system", HA_CURSOR_RESOURCE)?
        .ok_or("HA cursor")?;
    let cursor =
        NativeHaCursor::decode(cursor_bytes.expose()).map_err(|_| "canonical HA cursor")?;
    assert_eq!(cursor.raft_generation, 1);
    assert_eq!(cursor.local_publication_generation, generation);
    assert_ne!(cursor.raft_generation, generation);
    assert_eq!(
        cursor.publication_log.index,
        published.publication_log_id().index
    );
    assert_eq!(cursor.intent_log.index, published.intent_log_id().index);
    assert_history_with_real_proof(&mut target, &token, 4)?;
    let barrier = Zeroizing::new(**target.barrier_key.as_ref().ok_or("target barrier")?);
    let (resource, physical) = first_owner_file(&target)?;
    let root_bytes = selected_bytes(&target)?;
    let original_marker = target
        .durable
        .as_ref()
        .ok_or("durable")?
        .get("system", &resource)?
        .ok_or("marker")?;
    drop(target);
    fs::remove_file(&physical)?;
    let (cold, durable, loaded) = cold_load(&files, &ha, &barrier)?;
    assert!(
        physical.is_file(),
        "actual missing object repaired under local barrier"
    );
    assert_eq!(
        durable.generation(),
        generation,
        "physical repair does not advance root or journal"
    );
    assert_eq!(
        durable.get("system", "state")?.ok_or("root")?.expose(),
        root_bytes.as_slice()
    );
    assert_eq!(
        durable.get("system", &resource)?.ok_or("marker")?.expose(),
        original_marker.expose()
    );
    let mut target = install_cold_owner(cold, durable, loaded, &barrier)?;
    assert_history_with_real_proof(&mut target, &token, 4)?;

    // A changed registered marker is not legitimized by a missing-file repair.
    let mut changed = original_marker.expose().to_vec();
    changed[67] ^= 1;
    put(
        target.durable.as_mut().ok_or("durable")?,
        "inject-locator-change",
        &resource,
        &changed,
    )?;
    drop(target);
    fs::remove_file(&physical)?;
    assert!(cold_load(&files, &ha, &barrier).is_err());
    assert!(!physical.exists());
    // Restore only the explicit synthetic fault in the authenticated fixture
    // journal, then perform another genuine missing-file recovery.
    let mut durable = DurableService::reopen(
        &files.path.join("data"),
        AeadBarrier::new(*barrier)?,
        MAX_OPERATIONS,
    )?;
    put(
        &mut durable,
        "restore-locator-fixture",
        &resource,
        original_marker.expose(),
    )?;
    durable.close()?;
    let (cold, durable, loaded) = cold_load(&files, &ha, &barrier)?;
    let target = install_cold_owner(cold, durable, loaded, &barrier)?;
    let mut damaged = fs::read(&physical)?;
    let last = damaged.last_mut().ok_or("ciphertext")?;
    *last ^= 1;
    drop(target);
    fs::write(&physical, &damaged)?;
    assert!(cold_load(&files, &ha, &barrier).is_err());
    assert_eq!(
        fs::read(&physical)?,
        damaged,
        "existing bad object was never overwritten"
    );
    let durable = DurableService::reopen(
        &files.path.join("data"),
        AeadBarrier::new(*barrier)?,
        MAX_OPERATIONS,
    )?;
    assert_eq!(
        durable.get("system", "state")?.ok_or("root")?.expose(),
        root_bytes.as_slice()
    );
    durable.close()?;
    Ok(())
}

#[test]
fn native_ha_install_original_actor_stale_read_and_cold_catchup_to_later_root() -> TestResult {
    let (source_files, mut source, _key, token) = initialized()?;
    populate(&mut source, &token, 3);
    let (files, mut target, _target_key, _target_token) = initialized()?;
    seed_different_local_barrier(&source, &mut target)?;
    let source_digest = source
        .current_state_identity()
        .map_err(|_| "source identity")?
        .digest();
    let (cluster, enrollment, index) = cluster(&source, &source_files.path.join("catchup-raft"))?;
    let (first, _) = publish(&mut source, &cluster, &enrollment, source_digest, 0, index)?;
    let ha = cluster.processes[1].clone();
    target.ha = Some(ha.clone());
    // Actual original principal denial prevents even the first local effect.
    let original_root = selected_bytes(&target)?;
    let original_generation = target.durable.as_ref().ok_or("durable")?.generation();
    {
        let _scope = scope();
        let read = fresh(&ha)?;
        let denied = target.sync_native_v6_from_ha_checked(&ha, read, &mut |_| {
            Err(Response::error(403, "original fixture actor revoked"))
        });
        match denied {
            Err(response) => assert_eq!(response.status, 403),
            Ok(_) => panic!("original Actor must survive receive"),
        }
    }
    assert_eq!(selected_bytes(&target)?, original_root);
    assert_eq!(
        target.durable.as_ref().ok_or("durable")?.generation(),
        original_generation
    );
    install_warm(&mut target, &ha, &token)?;
    #[cfg(unix)]
    let ciphertext_directory = ha
        .lock()
        .map_err(|_| "proof ciphertext directory lock")?
        .storage_binding()?
        .directory
        .join("native-v6-ciphertext");
    #[cfg(unix)]
    let before_capture = publication_readback_directory(&ciphertext_directory)?;
    let before_capture_root = selected_bytes(&target)?;
    let before_capture_generation = target.durable.as_ref().ok_or("durable")?.generation();
    let original_scope = scope();
    let proof = target
        .capture_native_ha_request_proof(&mut || Ok(()))
        .map_err(|_| "actual first-root proof")?
        .ok_or("first-root proof")?;
    #[cfg(unix)]
    assert_eq!(
        publication_readback_directory(&ciphertext_directory)?,
        before_capture,
        "a proof for the actual installed root must read, not republish its complete closure",
    );
    let denied = target.capture_native_ha_request_proof(&mut || {
        Err(Response::error(403, "original fixture actor revoked"))
    });
    assert!(matches!(denied, Err(response) if response.status == 403));
    assert_eq!(selected_bytes(&target)?, before_capture_root);
    assert_eq!(
        target.durable.as_ref().ok_or("durable")?.generation(),
        before_capture_generation,
    );
    {
        let read = fresh(&ha)?;
        assert!(
            cluster.processes[2]
                .lock()
                .map_err(|_| "other process")?
                .verify_native_v6_committed_read(&read)
                .is_err(),
            "foreign actual process cannot borrow a witness"
        );
    }
    assert_eq!(
        call(
            &mut source,
            "POST",
            "secret/data/install-history",
            &token,
            json!({"options":{"cas":4},"data":{"version":5,"value":"synthetic-history-5"}})
        )
        .status,
        200
    );
    let (second, _) = publish(
        &mut source,
        &cluster,
        &enrollment,
        first.root_digest(),
        1,
        first.publication_log_id().index,
    )?;
    assert_eq!(second.generation(), 2);
    assert_eq!(second.migration_source(), first.migration_source());
    // A new actual ReadIndex also waits for follower apply. It never renews the
    // retained old proof, which must now fail before old payload delivery.
    let current = fresh(&ha)?;
    assert_eq!(current.published().root_digest(), second.root_digest());
    assert!(proof.check_warm(&target).is_err());
    assert!(
        target
            .capture_native_ha_request_proof(&mut || Ok(()))
            .is_err(),
        "a stale actual local identity cannot admit the new committed graph",
    );
    assert_eq!(
        target
            .current_state_identity()
            .map_err(|_| "old local identity")?
            .digest(),
        first.root_digest()
    );
    drop((current, proof, original_scope));
    let barrier = Zeroizing::new(**target.barrier_key.as_ref().ok_or("target barrier")?);
    let (_, obsolete_file) = first_owner_file(&target)?;
    let generation = target.durable.as_ref().ok_or("durable")?.generation();
    drop(target);
    fs::remove_file(&obsolete_file)?;
    let (cold, durable, loaded) = cold_load(&files, &ha, &barrier)?;
    assert_eq!(
        loaded
            .root
            .identity()
            .map_err(|error| std::io::Error::other(format!(
                "cold native root identity: {error:?}"
            )))?
            .digest(),
        second.root_digest()
    );
    assert!(durable.generation() > generation);
    assert!(
        !obsolete_file.exists(),
        "catch-up did not fabricate obsolete root payload"
    );
    let mut target = install_cold_owner(cold, durable, loaded, &barrier)?;
    assert_history_with_real_proof(&mut target, &token, 5)?;
    let _scope = scope();
    let read = fresh(&ha)?;
    let expired = RequestDeadlineScope::enter(Instant::now());
    let before = selected_bytes(&target)?;
    assert!(
        target
            .capture_native_ha_request_proof(&mut || Ok(()))
            .is_err()
    );
    assert!(target.sync_native_v6_from_ha(&ha, read).is_err());
    assert_eq!(selected_bytes(&target)?, before);
    drop(expired);
    Ok(())
}

#[test]
fn native_ha_install_actual_public_cold_unseal_and_credential_read() -> TestResult {
    let (source_files, mut source, _source_key, token) = initialized()?;
    populate(&mut source, &token, 1);
    let (files, mut target, unseal_key, _target_token) = initialized()?;
    seed_different_local_barrier(&source, &mut target)?;
    let prior = source
        .current_state_identity()
        .map_err(|_| "source identity")?
        .digest();
    let (cluster, enrollment, index) = cluster(&source, &source_files.path.join("http-read-raft"))?;
    let (published, _) = publish(&mut source, &cluster, &enrollment, prior, 0, index)?;
    // Public dispatch uses the real leader. This Raft fixture has no HTTP peer
    // listener and cannot claim standby forwarding coverage.
    let ha = cluster.processes[0].clone();
    target.ha = Some(ha.clone());
    install_warm(&mut target, &ha, &token)?;
    let generation = target
        .durable
        .as_ref()
        .ok_or("target durable")?
        .generation();
    // Remove every warm local Service owner. Consensus/cipher stores stay alive
    // as real independent processes; there is no source Service fallback.
    drop((source, target));
    fs::remove_dir_all(source_files.path.join("data"))?;
    let mut cold = files.service()?;
    cold.ha = Some(ha);
    assert!(cold.state.is_none() && cold.barrier_key.is_none());
    assert_eq!(
        call(
            &mut cold,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal_key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        cold.current_state_identity()
            .map_err(|_| "public unsealed identity")?
            .digest(),
        published.root_digest()
    );
    assert!(!cold.recovery_required && cold.native_candidate_profile.is_none());
    let lookup = call(
        &mut cold,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
    );
    assert_eq!(lookup.status, 200);
    assert!(lookup.body["data"]["id"].as_str() == Some(token.as_str()));
    assert!(cold.pending_native_auth_delivery.is_none());
    assert_eq!(
        call(
            &mut cold,
            "GET",
            "auth/token/lookup-self",
            "synthetic-invalid-token",
            json!({})
        )
        .status,
        403
    );
    let metadata = call(
        &mut cold,
        "GET",
        "secret/metadata/install-history",
        &token,
        json!({}),
    );
    assert_eq!(metadata.status, 200);
    assert_eq!(metadata.body["data"]["current_version"], 4);
    for version in 1..=4 {
        let response = call(
            &mut cold,
            "GET",
            "secret/data/install-history",
            &token,
            json!({"version":version}),
        );
        assert_eq!(response.status, if version <= 2 { 404 } else { 200 });
        if version > 2 {
            assert_eq!(response.body["data"]["data"]["version"], version);
            assert_eq!(
                response.body["data"]["data"]["value"],
                format!("synthetic-history-{version}")
            );
        }
    }
    assert_eq!(
        call(
            &mut cold,
            "GET",
            "secret/data/install-history",
            "synthetic-invalid-token",
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        cold.durable.as_ref().ok_or("cold durable")?.generation(),
        generation
    );
    Ok(())
}

#[test]
fn native_ha_install_auth_lookup_retains_preaudit_proof_after_real_root_advance() -> TestResult {
    let (source_files, mut source, _source_key, token) = initialized()?;
    populate(&mut source, &token, 1);
    let (_files, mut target, _target_key, _target_token) = initialized()?;
    seed_different_local_barrier(&source, &mut target)?;
    let source_digest = source
        .current_state_identity()
        .map_err(|_| "source identity")?
        .digest();
    let (cluster, enrollment, index) =
        cluster(&source, &source_files.path.join("auth-delivery-raft"))?;
    let (first, _) = publish(&mut source, &cluster, &enrollment, source_digest, 0, index)?;
    let ha = cluster.processes[0].clone();
    target.ha = Some(ha.clone());
    install_warm(&mut target, &ha, &token)?;
    let source_auth = crypto::digest(&owner_store::serialize_owner(
        &target.state.as_ref().ok_or("installed state")?.auth,
    )?);
    let original_generation = target.durable.as_ref().ok_or("durable")?.generation();
    let started = Instant::now();
    let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, started)?;
    let original_scope = RequestDeadlineScope::enter(started + REQUEST_BUDGET);
    let body = json!({});
    let response = target.handle_inner(RequestView {
        method: "GET",
        path: "auth/token/lookup-self",
        namespace: "",
        token: &token,
        body: &body,
        now: clock.admitted_at().seconds(),
        admission_started: started,
        token_clock: Some(clock),
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    });
    assert_eq!(response.status, 200);
    assert!(response.body["data"]["id"].as_str() == Some(token.as_str()));
    assert!(target.pending_native_auth_delivery.is_some());
    assert_eq!(
        target.durable.as_ref().ok_or("durable")?.generation(),
        original_generation,
        "lookup did not publish an Auth mutation"
    );

    // Real response audit completes. An independent source KV update then
    // reaches actual three-node Raft while the original capsule is retained.
    // The explicit ciphertext fixture is setup, never a TLS quorum receipt.
    let mut advanced = None;
    let response = target.audit_completed_response_with_receipt(
        "native-ha-auth-retained-proof",
        clock.admitted_at().seconds(),
        Some(clock),
        response,
        || {
            advanced = Some((|| -> TestResult<_> {
                assert_eq!(
                    call(
                        &mut source,
                        "POST",
                        "secret/data/install-history",
                        &token,
                        json!({"options":{"cas":4},"data":{"version":5,"value":"synthetic-history-5"}})
                    )
                    .status,
                    200
                );
                publish(
                    &mut source,
                    &cluster,
                    &enrollment,
                    first.root_digest(),
                    first.generation(),
                    first.publication_log_id().index,
                )
            })());
        },
    );
    let (second, _) = advanced.ok_or("audit callback did not execute")??;
    assert_eq!(response.status, 200);
    // Catch up the actual local barrier too: a broken delivery path that
    // recaptures after audit would now find a healthy new root and accept it.
    // The original affine proof must still bind the old exact root/full LogIds.
    install_warm(&mut target, &ha, &token)?;
    assert_eq!(
        target
            .current_state_identity()
            .map_err(|_| "new installed identity")?
            .digest(),
        second.root_digest()
    );
    assert_eq!(
        crypto::digest(&owner_store::serialize_owner(
            &target.state.as_ref().ok_or("new state")?.auth
        )?),
        source_auth,
        "the independently committed change left Auth unchanged"
    );
    let response =
        target.complete_native_auth_delivery(true, response, "native-ha-auth-retained-proof");
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("auth").is_none());
    assert!(response.unwrapped_json.is_none());
    assert!(response.consistency_index.is_none());
    assert!(target.pending_native_auth_delivery.is_none());
    assert!(!target.recovery_required && !target.audit_failed);
    drop(original_scope);

    // A separately admitted request may use that actual new root. Rejecting
    // the stale response did not undo the publication or consume a token use.
    let response = call(
        &mut target,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
    );
    assert_eq!(response.status, 200);
    assert!(response.body["data"]["id"].as_str() == Some(token.as_str()));
    assert!(target.pending_native_auth_delivery.is_none());
    Ok(())
}

#[cfg(unix)]
#[derive(Debug, Eq, PartialEq)]
struct PublicationReadbackDirectory {
    identity: (u64, u64, i64, i64, i64, i64),
    files: BTreeMap<std::ffi::OsString, (u64, [u8; 32])>,
}

#[cfg(unix)]
fn publication_readback_directory(path: &Path) -> TestResult<PublicationReadbackDirectory> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::metadata(path)?;
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        assert!(
            entry.file_type()?.is_file(),
            "fixture ciphertext entry must be a file"
        );
        let bytes = fs::read(entry.path())?;
        files.insert(
            entry.file_name(),
            (bytes.len() as u64, crypto::digest(&bytes)),
        );
    }
    Ok(PublicationReadbackDirectory {
        identity: (
            metadata.dev(),
            metadata.ino(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ),
        files,
    })
}

#[cfg(unix)]
fn publication_readback_fixture_publish(
    source: &mut Service,
    cluster: &Cluster,
    enrollment: &NativeV6PeerEnrollment,
    prior_digest: [u8; 32],
    prior_generation: u64,
    previous_index: u64,
) -> TestResult<(NativeV6HaProposal, NativeV6PublishedRoot)> {
    // This primitive fixture retains the actual typed proposal so its API
    // binding can be tested. Explicit ciphertext copies here are not TLS votes;
    // the separate Pipeline case exercises the complete production coordinator.
    let plan = source
        .prepare_native_root_migration_paged(&|| Ok(()))
        .map_err(|_| "publication fixture native projection")?;
    let proposal = cluster.processes[0]
        .lock()
        .map_err(|_| "publication fixture leader lock")?
        .native_install_test_with_source(|codec, store| {
            let prepared = prepare_native_v6_ha_objects(
                &plan,
                codec,
                enrollment,
                store,
                None,
                None,
                &mut || Ok(()),
            )?;
            let local = prepared.local_closure();
            let generation = prior_generation + 1;
            let intent = NativeV6CommitIntent {
                cluster_digest: enrollment.cluster_digest(),
                epoch: enrollment.epoch(),
                operation_digest: crypto::digest(
                    format!("publication-readback-fixture-{generation}").as_bytes(),
                ),
                closure_manifest_sha256: local.manifest_sha256(),
                object_count: local.object_count() as u64,
                ciphertext_bytes: local.ciphertext_bytes(),
                prior_root_digest: prior_digest,
                proposed_root_digest: prepared.root_digest(),
                prior_generation,
                proposed_generation: generation,
                expected_previous_commit_index: previous_index,
            };
            prepared.into_proposal(codec, enrollment, intent, &mut || Ok(()))
        })??;
    let sender = cluster.processes[0]
        .lock()
        .map_err(|_| "publication fixture sender lock")?
        .native_install_test_store()?;
    for process in &cluster.processes {
        process
            .lock()
            .map_err(|_| "publication fixture process lock")?
            .native_install_test_copy_ciphertext(&sender, &proposal)?;
    }
    let published = cluster.processes[0]
        .lock()
        .map_err(|_| "publication fixture publication lock")?
        .native_install_test_publish(&proposal, enrollment)?;
    Ok((proposal, published))
}

#[cfg(unix)]
#[test]
fn native_ha_published_proposal_readback_keeps_binding_clock_quorum_and_read_only_store()
-> TestResult {
    let (files, mut source, _key, token) = initialized()?;
    populate(&mut source, &token, 3);
    let prior = source
        .current_state_identity()
        .map_err(|_| "publication fixture V5 identity")?
        .digest();
    let raft_path = files.path.join("publication-readback-raft");
    let (cluster, enrollment, previous_index) = cluster(&source, &raft_path)?;
    let _original_scope = scope();
    let deadline = OriginalDeadline::capture()?;
    let (proposal, published) = publication_readback_fixture_publish(
        &mut source,
        &cluster,
        &enrollment,
        prior,
        0,
        previous_index,
    )?;
    assert_eq!(proposal.original_deadline().instant(), deadline.instant());
    let path = raft_path.join("1").join("native-v6-ciphertext");
    let before = publication_readback_directory(&path)?;
    let before_generation = cluster.processes[0]
        .lock()
        .map_err(|_| "publication fixture process lock")?
        .snapshot_test_record_usage()?
        .0;
    {
        let process = cluster.processes[0]
            .lock()
            .map_err(|_| "publication fixture readback lock")?;
        let read = process
            .native_v6_committed_read_for_published_proposal(deadline, &proposal, &published)?;
        assert!(read.published() == &published);
        assert_eq!(read.deadline().instant(), deadline.instant());
        process.verify_native_v6_committed_read(&read)?;
        assert_eq!(process.snapshot_test_record_usage()?.0, before_generation);
    }
    assert_eq!(
        publication_readback_directory(&path)?,
        before,
        "complete proposal readback must not republish a manifest or change ciphertext entries",
    );

    // An intact closure and the right published bytes do not permit substituting
    // another request clock for the one owned by the original typed proposal.
    {
        let _shorter = RequestDeadlineScope::enter(deadline.instant() - Duration::from_millis(1));
        let different = OriginalDeadline::capture()?;
        assert_ne!(different.instant(), deadline.instant());
        assert!(
            cluster.processes[0]
                .lock()
                .map_err(|_| "publication clock lock")?
                .native_v6_committed_read_for_published_proposal(different, &proposal, &published,)
                .is_err(),
        );
    }
    assert_eq!(publication_readback_directory(&path)?, before);

    assert_eq!(
        call(
            &mut source,
            "POST",
            "secret/data/install-history",
            &token,
            json!({"options":{"cas":4},"data":{"version":5,"value":"readback-next-root"}}),
        )
        .status,
        200,
    );
    let (next_proposal, next_published) = publication_readback_fixture_publish(
        &mut source,
        &cluster,
        &enrollment,
        published.root_digest(),
        published.generation(),
        published.publication_log_id().index,
    )?;
    assert!(next_published != published);
    {
        let process = cluster.processes[0]
            .lock()
            .map_err(|_| "publication replacement lock")?;
        assert!(
            process
                .native_v6_committed_read_for_published_proposal(
                    deadline,
                    &proposal,
                    &next_published,
                )
                .is_err(),
            "a different operation's committed root cannot bind the retained proposal",
        );
        assert!(
            process
                .native_v6_committed_read_for_published_proposal(deadline, &proposal, &published,)
                .is_err(),
            "a fresh actual selection must reject a superseded published root",
        );
        deadline.check()?;
        let current = process.native_v6_committed_read_for_published_proposal(
            deadline,
            &next_proposal,
            &next_published,
        )?;
        assert!(current.published() == &next_published);
    }

    let before_expired = publication_readback_directory(&path)?;
    {
        let _expired = RequestDeadlineScope::enter(Instant::now());
        let expected = deadline
            .check()
            .err()
            .ok_or("fixture deadline did not expire")?;
        let failed = cluster.processes[0]
            .lock()
            .map_err(|_| "publication expired lock")?
            .native_v6_committed_read_for_published_proposal(
                deadline,
                &next_proposal,
                &next_published,
            );
        assert_eq!(
            failed.err().ok_or("expired readback returned a handle")?,
            expected.to_string()
        );
    }
    assert_eq!(publication_readback_directory(&path)?, before_expired);
    deadline.check()?;

    let blocked_before = cluster.blocked_probes();
    cluster.isolate_all_peers(true);
    let unavailable = cluster.processes[0]
        .lock()
        .map_err(|_| "publication no-quorum lock")?
        .native_v6_committed_read_for_published_proposal(deadline, &next_proposal, &next_published);
    cluster.isolate_all_peers(false);
    assert!(
        cluster.blocked_probes() > blocked_before,
        "this refusal must include actual blocked Raft peer exchanges",
    );
    assert!(
        unavailable.is_err(),
        "prepared ciphertext cannot replace a real ReadIndex quorum"
    );
    assert_eq!(publication_readback_directory(&path)?, before_expired);
    Ok(())
}
