//! Internal child of service_native_v6_ha_install_tests; no Service/HTTP repair entry.
//!
//! These tests use its real three-node Raft fixture and independently encrypted
//! local Service. Fixture archive construction is explicit and is NOT a tested
//! Service/HTTP export owner, physical TLS quorum or full backup qualification.
//! Only the new exact-current repair primitive is exercised by these tests.
use super::*;
use crate::ha::native_v6_backup::{
    ArchiveResult, NativeV6ArchiveError, NativeV6ArchiveReport, NativeV6ArchiveSelection,
    prepare_native_v6_local_pack, write_native_v6_archive,
};
use heptabao_raft_runtime::RecordObjectRef;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::fs::OpenOptions;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

struct RepairFixture {
    // Owners drop before the Root directories and their retained lock files.
    target: Option<Service>,
    source: Service,
    cluster: Cluster,
    token: Zeroizing<String>,
    archive: Vec<u8>,
    seal_identity: [u8; 32],
    barrier: Zeroizing<[u8; 32]>,
    published: NativeV6PublishedRoot,
    enrollment: NativeV6PeerEnrollment,
    references: Vec<RecordObjectRef>,
    ciphertext: Vec<Vec<u8>>,
    raft_path: PathBuf,
    _source_files: Root,
    target_files: Root,
}

fn repair_fixture() -> TestResult<RepairFixture> {
    let (source_files, mut source, _source_key, token) = initialized()?;
    populate(&mut source, &token, 9);
    let (target_files, mut target, _target_key, _target_token) = initialized()?;
    seed_different_local_barrier(&source, &mut target)?;
    let prior = source
        .current_state_identity()
        .map_err(|_| "actual V5 source identity")?
        .digest();
    let raft_path = source_files.path.join("archive-repair-raft");
    let (cluster, enrollment, prior_index) = cluster(&source, &raft_path)?;
    let (published, _) = publish(&mut source, &cluster, &enrollment, prior, 0, prior_index)?;
    let ha = cluster.processes[1].clone();
    target.ha = Some(ha.clone());
    install_warm(&mut target, &ha, &token)?;
    assert_history_with_real_proof(&mut target, &token, 4)?;
    let barrier = Zeroizing::new(**target.barrier_key.as_ref().ok_or("target barrier")?);
    assert_ne!(
        barrier.as_slice(),
        source
            .barrier_key
            .as_ref()
            .ok_or("source barrier")?
            .as_slice(),
        "target really has independent local encryption custody"
    );
    // Explicit fixture binding only. The future Service owner must instead
    // supply the existing physically checked canonical snapshot seal identity.
    let seal_identity = Sha256::digest(serde_json::to_vec(
        target.seal.as_ref().ok_or("target seal")?,
    )?)
    .into();
    let (archive, references, ciphertext) = {
        let _scope = scope();
        let deadline = OriginalDeadline::capture()?;
        let process = ha.lock_for_request().map_err(|_| "actual HA owner")?;
        let read = process
            .native_v6_committed_read(deadline)?
            .ok_or("actual current root")?;
        assert_eq!(read.published(), &published);
        let selection =
            NativeV6ArchiveSelection::from_committed(read.enrollment(), read.published())?;
        let mut gate = || {
            process
                .verify_native_v6_committed_read(&read)
                .map_err(|_| NativeV6ArchiveError::Gate)
        };
        let local = prepare_native_v6_local_pack(
            target.durable.as_mut().ok_or("actual target durable")?,
            &selection,
            Cursor::new(Vec::new()),
            deadline,
            &mut gate,
            &mut |_, _| Ok(()),
        )?;
        let mut archive = Vec::new();
        let (report, references, ciphertext) =
            process.with_native_v6_source(&read, |_, store| {
                let report = write_native_v6_archive(
                    &selection,
                    local,
                    store,
                    seal_identity,
                    &AeadBarrier::new(*barrier).map_err(|_| NativeV6ArchiveError::Gate)?,
                    &mut archive,
                    &mut gate,
                )?;
                let (_, references) = store
                    .reopen_root_closure_archive(&published, &mut || {
                        gate()
                            .map_err(|_| heptabao_raft_runtime::LocalV6BlobError::CorruptOrChanged)
                    })
                    .map_err(|_| NativeV6ArchiveError::Storage)?;
                let ciphertext = references
                    .iter()
                    .map(|reference| {
                        store
                            .read_local_checked(reference, &mut || {
                                gate().map_err(|_| {
                                    heptabao_raft_runtime::LocalV6BlobError::CorruptOrChanged
                                })
                            })
                            .map_err(|_| NativeV6ArchiveError::Storage)
                    })
                    .collect::<ArchiveResult<Vec<_>>>()?;
                Ok::<_, NativeV6ArchiveError>((report, references, ciphertext))
            })??;
        assert_eq!(report.archive_bytes, archive.len() as u64);
        assert_eq!(report.shared_object_count, references.len() as u64);
        assert_eq!(
            report.archive_sha256,
            <[u8; 32]>::from(Sha256::digest(&archive))
        );
        (archive, references, ciphertext)
    };
    Ok(RepairFixture {
        target: Some(target),
        source,
        cluster,
        token,
        archive,
        seal_identity,
        barrier,
        published,
        enrollment,
        references,
        ciphertext,
        raft_path,
        _source_files: source_files,
        target_files,
    })
}

fn local_anchor(service: &Service) -> TestResult<(u64, u64, Vec<Option<Vec<u8>>>)> {
    let durable = service.durable.as_ref().ok_or("actual durable")?;
    let mut resources = Vec::new();
    for resource in [
        "state",
        ACTIVE_CURSOR_RESOURCE,
        ACTIVE_SOURCE_ROOT_RESOURCE,
        HA_CURSOR_RESOURCE,
    ] {
        resources.push(
            durable
                .get("system", resource)?
                .map(|secret| secret.expose().to_vec()),
        );
    }
    Ok((durable.generation(), durable.replay_epoch(), resources))
}

fn cipher_file(fixture: &RepairFixture, voter: u64, reference: &RecordObjectRef) -> PathBuf {
    fixture
        .raft_path
        .join(voter.to_string())
        .join("native-v6-ciphertext")
        .join(format!("v6-{}.blob", hex(&reference.id)))
}

fn remove_fixture_closure(fixture: &RepairFixture) -> TestResult {
    // Explicit synthetic fault only: these are exact references in this fresh
    // Root fixture. No directory enumeration or production cleanup is used.
    for voter in 1..=3 {
        for reference in &fixture.references {
            let path = cipher_file(fixture, voter, reference);
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn assert_no_fixture_closure(fixture: &RepairFixture) {
    for voter in 1..=3 {
        for reference in &fixture.references {
            assert!(!cipher_file(fixture, voter, reference).exists());
        }
    }
}

fn attempt<R: Read + Seek>(
    fixture: &RepairFixture,
    reader: R,
    seal_identity: [u8; 32],
    original_owner: &mut impl FnMut(
        &NativeV6PeerEnrollment,
        &NativeV6PublishedRoot,
    ) -> ArchiveResult<()>,
) -> ArchiveResult<(CommittedNativeV6Read, NativeV6ArchiveReport)> {
    let deadline = OriginalDeadline::capture().map_err(|_| NativeV6ArchiveError::Gate)?;
    let process = fixture.cluster.processes[1]
        .lock_for_request()
        .map_err(|_| NativeV6ArchiveError::Gate)?;
    process
        .repair_native_v6_current_closure_from_archive(
            reader,
            seal_identity,
            &AeadBarrier::new(*fixture.barrier).map_err(|_| NativeV6ArchiveError::Gate)?,
            deadline,
            original_owner,
        )
        .map(|repaired| repaired.into_parts())
}

struct OnFirstRead<R, F> {
    reader: R,
    effect: Option<F>,
}
impl<R: Read, F: FnOnce()> Read for OnFirstRead<R, F> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if let Some(effect) = self.effect.take() {
            effect();
        }
        self.reader.read(output)
    }
}
impl<R: Seek, F> Seek for OnFirstRead<R, F> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.reader.seek(position)
    }
}

#[test]
fn native_ha_archive_repair_all_donors_missing_exact_bytes_and_independent_cold_owner() -> TestResult
{
    let mut fixture = repair_fixture()?;
    let baseline = local_anchor(fixture.target.as_ref().ok_or("target")?)?;
    let raft_before = fixture.cluster.processes[1]
        .lock()
        .map_err(|_| "actual process")?
        .snapshot_test_record_usage()?
        .0;
    remove_fixture_closure(&fixture)?;
    assert_no_fixture_closure(&fixture);

    // Every malformed/unauthorized attempt fails BEFORE any leaf publication.
    {
        let _scope = scope();
        let mut wrong_seal = fixture.seal_identity;
        wrong_seal[0] ^= 1;
        assert!(matches!(
            attempt(
                &fixture,
                Cursor::new(&fixture.archive),
                wrong_seal,
                &mut |_, _| Ok(())
            ),
            Err(NativeV6ArchiveError::WrongSelection)
        ));
        assert_no_fixture_closure(&fixture);
    }
    {
        let _scope = scope();
        let mut damaged = fixture.archive.clone();
        *damaged.last_mut().ok_or("archive footer")? ^= 1;
        assert!(
            attempt(
                &fixture,
                Cursor::new(damaged),
                fixture.seal_identity,
                &mut |_, _| Ok(())
            )
            .is_err()
        );
        assert_no_fixture_closure(&fixture);
    }
    {
        let _scope = scope();
        let cancelled = Cell::new(false);
        let reader = OnFirstRead {
            reader: Cursor::new(&fixture.archive),
            effect: Some(|| cancelled.set(true)),
        };
        assert!(matches!(
            attempt(&fixture, reader, fixture.seal_identity, &mut |_, _| {
                if cancelled.get() {
                    Err(NativeV6ArchiveError::Gate)
                } else {
                    Ok(())
                }
            }),
            Err(NativeV6ArchiveError::Gate)
        ));
        assert!(
            cancelled.get(),
            "cancellation was observed during actual archive I/O"
        );
        assert_no_fixture_closure(&fixture);
    }

    // An already registered corrupt leaf is preserved. Missing-file repair is
    // not permission to replace an existing wrong file, even with valid input.
    let first = fixture.references.first().ok_or("archive reference")?;
    let bad_path = cipher_file(&fixture, 2, first);
    let mut bad_bytes = fixture.ciphertext.first().ok_or("archive leaf")?.clone();
    *bad_bytes.last_mut().ok_or("ciphertext")? ^= 1;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&bad_path)?;
    file.write_all(&bad_bytes)?;
    file.sync_all()?;
    drop(file);
    {
        let _scope = scope();
        assert!(matches!(
            attempt(
                &fixture,
                Cursor::new(&fixture.archive),
                fixture.seal_identity,
                &mut |_, _| Ok(())
            ),
            Err(NativeV6ArchiveError::Storage)
        ));
    }
    assert_eq!(fs::read(&bad_path)?, bad_bytes);
    assert_eq!(
        local_anchor(fixture.target.as_ref().ok_or("target")?)?,
        baseline
    );
    fs::remove_file(&bad_path)?; // Remove only the deliberate synthetic fault.

    {
        let _scope = scope();
        let deadline = OriginalDeadline::capture()?;
        let ha = fixture.cluster.processes[1].clone();
        let mut target = fixture.target.take().ok_or("target")?;
        let environment = LocalHaEnvironment::capture(&target, &ha, &fixture.barrier, deadline)
            .map_err(|_| "actual original Service barrier owner")?;
        let source_auth = target.state.as_ref().ok_or("source State")?.auth.clone();
        let principal = source_auth
            .authenticate_read_only(&fixture.token, 100)?
            .ok_or("actual original root principal")?;
        let source_auth_digest = crypto::digest(&owner_store::serialize_owner(&source_auth)?);
        let mut durable = target.durable.take().ok_or("actual durable")?;
        let repaired = attempt(
            &fixture,
            Cursor::new(&fixture.archive),
            fixture.seal_identity,
            &mut |enrollment, published| {
                environment
                    .check(&target)
                    .map_err(|_| NativeV6ArchiveError::Gate)?;
                if enrollment != &fixture.enrollment
                    || published != &fixture.published
                    || target
                        .current_state_identity()
                        .map_err(|_| NativeV6ArchiveError::Gate)?
                        != StateIdentity::RecordsV6(published.root_digest())
                {
                    return Err(NativeV6ArchiveError::WrongSelection);
                }
                source_auth
                    .authorize_request(&principal, "", "sys/storage/raft/snapshot", "update", 100)
                    .map_err(|_| NativeV6ArchiveError::Gate)?;
                let current_auth = &target
                    .state
                    .as_ref()
                    .ok_or(NativeV6ArchiveError::Gate)?
                    .auth;
                if crypto::digest(
                    &owner_store::serialize_owner(current_auth)
                        .map_err(|_| NativeV6ArchiveError::Gate)?,
                ) != source_auth_digest
                {
                    return Err(NativeV6ArchiveError::Gate);
                }
                durable
                    .verify_live_ownership()
                    .map_err(|_| NativeV6ArchiveError::Storage)?;
                if durable.generation() != baseline.0 || durable.replay_epoch() != baseline.1 {
                    return Err(NativeV6ArchiveError::WrongSelection);
                }
                for (resource, expected) in [
                    "state",
                    ACTIVE_CURSOR_RESOURCE,
                    ACTIVE_SOURCE_ROOT_RESOURCE,
                    HA_CURSOR_RESOURCE,
                ]
                .into_iter()
                .zip(&baseline.2)
                {
                    let observed = durable
                        .get("system", resource)
                        .map_err(|_| NativeV6ArchiveError::Storage)?;
                    if observed.as_ref().map(Secret::expose) != expected.as_deref() {
                        return Err(NativeV6ArchiveError::WrongSelection);
                    }
                }
                deadline.check().map_err(|_| NativeV6ArchiveError::Gate)
            },
        );
        target.durable = Some(durable);
        fixture.target = Some(target);
        let (read, report) = repaired?;
        assert_eq!(read.published(), &fixture.published);
        assert_eq!(read.enrollment(), &fixture.enrollment);
        assert_eq!(report.shared_object_count, fixture.references.len() as u64);
        let process = fixture.cluster.processes[1]
            .lock_for_request()
            .map_err(|_| "actual repaired process")?;
        process.verify_native_v6_committed_read(&read)?;
        process.with_native_v6_source(&read, |_, store| -> TestResult {
            let (_, references) =
                store.reopen_root_closure_archive(read.published(), &mut || Ok(()))?;
            assert_eq!(references, fixture.references);
            for (reference, expected) in references.iter().zip(&fixture.ciphertext) {
                assert_eq!(store.read_local(reference)?, *expected);
            }
            Ok(())
        })??;
        assert_eq!(process.snapshot_test_record_usage()?.0, raft_before);
    }
    assert_eq!(
        local_anchor(fixture.target.as_ref().ok_or("target")?)?,
        baseline
    );
    // Both other actual voter stores remain empty: the successful repair had
    // no healthy peer donor and produced no remote quorum fsync receipt.
    for voter in [1, 3] {
        for reference in &fixture.references {
            assert!(!cipher_file(&fixture, voter, reference).exists());
        }
    }

    // Then lose an actual target-barrier object and reopen its whole local
    // owner. The existing cold materializer consumes the repaired shared bytes
    // and rewraps only that missing object under the target's independent key.
    let (_, missing_local) = first_owner_file(fixture.target.as_ref().ok_or("target")?)?;
    drop(fixture.target.take().ok_or("target")?);
    fs::remove_file(&missing_local)?;
    let ha = fixture.cluster.processes[1].clone();
    let (cold, durable, loaded) = cold_load(&fixture.target_files, &ha, &fixture.barrier)?;
    assert_eq!(durable.generation(), baseline.0);
    assert_eq!(durable.replay_epoch(), baseline.1);
    fixture.target = Some(install_cold_owner(cold, durable, loaded, &fixture.barrier)?);
    assert!(missing_local.is_file());
    assert_eq!(
        local_anchor(fixture.target.as_ref().ok_or("target")?)?,
        baseline
    );
    assert_history_with_real_proof(
        fixture.target.as_mut().ok_or("cold target")?,
        &fixture.token,
        4,
    )?;
    Ok(())
}

#[test]
fn native_ha_archive_repair_real_readindex_after_eight_seconds_keeps_original_deadline()
-> TestResult {
    let fixture = repair_fixture()?;
    let ha = fixture.cluster.processes[1].clone();
    let original_scope = scope();
    let original_deadline = OriginalDeadline::capture()?.instant();
    let old = fresh(&ha)?;
    remove_fixture_closure(&fixture)?;
    let began = Instant::now();
    let (read, _) = attempt(
        &fixture,
        OnFirstRead {
            reader: Cursor::new(&fixture.archive),
            effect: Some(|| std::thread::sleep(Duration::from_millis(8_100))),
        },
        fixture.seal_identity,
        &mut |_, _| Ok(()),
    )?;
    assert!(began.elapsed() >= Duration::from_millis(8_100));
    assert!(Instant::now() < original_deadline);
    assert_eq!(read.deadline().instant(), original_deadline);
    assert_eq!(read.published(), old.published());
    assert_eq!(read.enrollment(), old.enrollment());
    {
        let process = ha.lock_for_request().map_err(|_| "actual HA owner")?;
        assert!(process.verify_native_v6_committed_read(&old).is_err());
        process.verify_native_v6_committed_read(&read)?;
    }
    drop((read, old, original_scope));

    // A later separate operation uses its own explicit shorter deadline. A
    // blocking reader can finish after that bound but no subsequent leaf I/O,
    // successful repair or read authority is allowed to escape.
    remove_fixture_closure(&fixture)?;
    let deadline = Instant::now() + Duration::from_millis(500);
    let _short_scope = RequestDeadlineScope::enter(deadline);
    let entered = Cell::new(false);
    let result = attempt(
        &fixture,
        OnFirstRead {
            reader: Cursor::new(&fixture.archive),
            effect: Some(|| {
                entered.set(true);
                std::thread::sleep(
                    deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
                );
            }),
        },
        fixture.seal_identity,
        &mut |_, _| Ok(()),
    );
    assert!(
        entered.get(),
        "actual archive read must have begun before the fault"
    );
    assert!(matches!(result, Err(NativeV6ArchiveError::Gate)));
    assert_no_fixture_closure(&fixture);
    Ok(())
}

#[test]
fn native_ha_archive_repair_rejects_real_checkpoint_drift_and_historical_root() -> TestResult {
    let mut fixture = repair_fixture()?;
    let ha = fixture.cluster.processes[1].clone();
    {
        let _scope = scope();
        let deadline = OriginalDeadline::capture()?;
        let process = ha.lock_for_request().map_err(|_| "actual HA owner")?;
        let initial = process
            .native_v6_committed_read(deadline)?
            .ok_or("actual root")?;
        let generation = process.snapshot_test_record_usage()?.0;
        let checkpointed = Cell::new(false);
        let result = process.repair_native_v6_current_closure_from_archive(
            OnFirstRead {
                reader: Cursor::new(&fixture.archive),
                effect: Some(|| {
                    process.trigger_snapshot().expect("actual Raft checkpoint");
                    checkpointed.set(true);
                }),
            },
            fixture.seal_identity,
            &AeadBarrier::new(*fixture.barrier)?,
            deadline,
            &mut |_, _| Ok(()),
        );
        assert!(checkpointed.get());
        assert!(process.snapshot_test_record_usage()?.0 > generation);
        assert!(
            result.is_err(),
            "same root digest cannot excuse a changed real store generation"
        );
        assert!(process.verify_native_v6_committed_read(&initial).is_err());
        let fresh = process
            .native_v6_committed_read(deadline)?
            .ok_or("fresh actual root")?;
        assert_eq!(fresh.published(), initial.published());
    }
    assert_eq!(
        call(
            &mut fixture.source,
            "POST",
            "secret/data/install-history",
            &fixture.token,
            json!({"options":{"cas":4},"data":{"version":5,"value":"synthetic-history-5"}}),
        )
        .status,
        200
    );
    let (next, _) = publish(
        &mut fixture.source,
        &fixture.cluster,
        &fixture.enrollment,
        fixture.published.root_digest(),
        fixture.published.generation(),
        fixture.published.publication_log_id().index,
    )?;
    assert!(next.generation() > fixture.published.generation());
    let _scope = scope();
    let selected = fresh(&ha)?;
    assert_eq!(selected.published(), &next);
    let local_before = local_anchor(fixture.target.as_ref().ok_or("target")?)?;
    assert!(matches!(
        attempt(
            &fixture,
            Cursor::new(&fixture.archive),
            fixture.seal_identity,
            &mut |_, _| Ok(())
        ),
        Err(NativeV6ArchiveError::WrongSelection)
    ));
    assert_eq!(
        local_anchor(fixture.target.as_ref().ok_or("target")?)?,
        local_before
    );
    assert_eq!(fresh(&ha)?.published(), &next);
    Ok(())
}
