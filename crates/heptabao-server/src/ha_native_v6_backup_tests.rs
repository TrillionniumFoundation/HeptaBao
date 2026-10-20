//! Child of the actual Service/three-Raft codec tests. This proves archive
//! format/byte preservation, not physical TLS durability, live export owner
//! admission, Service recovery, an epoch transition or backup qualification.
use super::*;
use crate::crypto::AeadBarrier;
use crate::ha::native_v6_backup::{
    NativeV6ArchiveError, NativeV6ArchiveSelection, prepare_native_v6_local_pack,
    validate_native_v6_archive, write_native_v6_archive,
};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::rc::Rc;

fn archive_scope() -> RequestDeadlineScope {
    RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(15))
}

// Diagnostic-only test observations. This file is cfg(test); the original
// operations, deadlines, assertions, gates and cleanup are unchanged. Observe
// the existing thread-local deadline without creating or renewing a scope.
struct ArchiveDiagnosticPhase {
    phase: &'static str,
    started: Instant,
    original_deadline: Option<Instant>,
    completed: bool,
}
impl ArchiveDiagnosticPhase {
    fn start(phase: &'static str) -> Self {
        Self {
            phase,
            started: Instant::now(),
            original_deadline: crate::request_deadline::current(),
            completed: false,
        }
    }
    fn finish(mut self) {
        self.completed = true;
    }
    fn error<E>(&self, operation: &'static str, _error: &E) {
        // inspect_err observes the original typed Result before `?` starts
        // unwinding locals. Neither the error nor the deadline is replaced.
        let observed = Instant::now();
        let _ = writeln!(
            io::stderr().lock(),
            "HBARCHIVE-TEST-ERROR phase={} operation={} error_type={} elapsed_us={} original_deadline_present={} original_deadline_expired_at_return={}",
            self.phase,
            operation,
            std::any::type_name::<E>(),
            observed.duration_since(self.started).as_micros(),
            self.original_deadline.is_some(),
            self.original_deadline.is_some_and(|deadline| observed >= deadline),
        );
    }
}
impl Drop for ArchiveDiagnosticPhase {
    fn drop(&mut self) {
        let observed = Instant::now();
        let _ = writeln!(
            io::stderr().lock(),
            "HBARCHIVE-TEST-PHASE phase={} elapsed_us={} completed={} original_deadline_present={} original_remaining_at_start_us={} original_deadline_expired={}",
            self.phase,
            observed.duration_since(self.started).as_micros(),
            self.completed,
            self.original_deadline.is_some(),
            self.original_deadline
                .map(|deadline| deadline.saturating_duration_since(self.started).as_micros())
                .unwrap_or(0),
            self.original_deadline.is_some_and(|deadline| observed >= deadline),
        );
    }
}

fn private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
fn hash_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut input = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 256 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().into())
}

// An actual file with an adversarial bounded read view. It can replace bytes,
// truncate, append zeros, or change one leaf AFTER validation, without copying
// the 70+ MiB archive into memory. Read and Seek expose the same virtual length.
struct ArchiveView {
    file: File,
    actual_len: u64,
    length: u64,
    at: u64,
    patches: Vec<(u64, u8)>,
    active: Rc<Cell<bool>>,
    largest: Rc<Cell<usize>>,
    finish_first_read_after: Option<Instant>,
}
impl ArchiveView {
    fn new(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let actual_len = file.metadata()?.len();
        Ok(Self {
            file,
            actual_len,
            length: actual_len,
            at: 0,
            patches: Vec::new(),
            active: Rc::new(Cell::new(true)),
            largest: Rc::new(Cell::new(0)),
            finish_first_read_after: None,
        })
    }
    fn flip(&mut self, offset: u64) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        let mut byte = [0];
        self.file.read_exact(&mut byte)?;
        self.patches.push((offset, byte[0] ^ 0x80));
        Ok(())
    }
}
impl Read for ArchiveView {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.largest.set(self.largest.get().max(output.len()));
        if let Some(deadline) = self.finish_first_read_after.take() {
            std::thread::sleep(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            );
        }
        if self.at >= self.length {
            return Ok(0);
        }
        let count = (self.length - self.at).min(output.len() as u64) as usize;
        let from_file = self.actual_len.saturating_sub(self.at).min(count as u64) as usize;
        if from_file != 0 {
            self.file.seek(SeekFrom::Start(self.at))?;
            self.file.read_exact(&mut output[..from_file])?;
        }
        output[from_file..count].fill(0);
        if self.active.get() {
            for (offset, byte) in &self.patches {
                if *offset >= self.at && *offset < self.at + count as u64 {
                    output[(*offset - self.at) as usize] = *byte;
                }
            }
        }
        self.at += count as u64;
        Ok(count)
    }
}
impl Seek for ArchiveView {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let at = match position {
            SeekFrom::Start(value) => value as i128,
            SeekFrom::Current(offset) => self.at as i128 + offset as i128,
            SeekFrom::End(offset) => self.length as i128 + offset as i128,
        };
        self.at = u64::try_from(at).map_err(|_| io::Error::other("invalid test seek"))?;
        Ok(self.at)
    }
}

#[test]
fn native_ha_archive_real_34mib_dual_pack_roundtrip_and_hostile_inputs() -> TestResult {
    let phase = ArchiveDiagnosticPhase::start("initialized");
    let (files, mut service, _key, token) = initialized()?;
    phase.finish();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/config",
            &token,
            json!({"max_versions":30})
        )
        .status,
        204
    );
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let codec = ClusterStateCodec::new(&cluster_id, [59; 32])?;
    let phase = ArchiveDiagnosticPhase::start("cluster_anchor");
    let cluster = Cluster::new(files.path.join("archive-raft"))?;
    let (enrollment, prior_digest, prior_index) = enroll_and_anchor(&cluster, &codec, &service)?;
    phase.finish();
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
    let phase = ArchiveDiagnosticPhase::start("seed_17_history_versions");
    for version in 1..=17 {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/data/cipher-history",
                &token,
                json!({"options":{"cas":version-1},"data":{"version":version,
                "blob":unique_payload(version)}})
            )
            .status,
            200
        );
    }
    phase.finish();
    let sender_path = files.path.join("archive-original-ciphertext");
    let sender = stage(&sender_path)?;
    let export_scope = archive_scope();
    let deadline = OriginalDeadline::capture()?;
    let phase = ArchiveDiagnosticPhase::start("prepare_full_shared_ciphertext");
    let state = service.state.as_ref().ok_or("state")?.clone();
    let plan = service
        .prepare_native_live_root_checked(&state, &mut |_| Ok(()))
        .map_err(|_| "actual source plan")?;
    let prepared = {
        let durable = service.durable.as_mut().ok_or("actual durable")?;
        let source =
            native_blob_source::NativeSource::new_checked(durable, plan.deadline, || Ok(()))?;
        // This real materializer validates the full typed graph before the
        // Durable pack later reauthenticates its complete committed slot index.
        prepare_native_v6_ha_objects(
            &plan,
            &codec,
            &enrollment,
            &sender,
            Some(&source),
            None,
            &mut || Ok(()),
        )
        .inspect_err(|error| phase.error("prepare_native_v6_ha_objects", error))?
    };
    phase.finish();
    let intent = intent(&prepared, &enrollment, prior_digest, prior_index);
    assert!(intent.ciphertext_bytes >= 34 * 1024 * 1024);
    let phase = ArchiveDiagnosticPhase::start("proposal");
    let proposal = prepared
        .into_proposal(&codec, &enrollment, intent, &mut || Ok(()))
        .inspect_err(|error| phase.error("into_proposal", error))?;
    phase.finish();
    let phase = ArchiveDiagnosticPhase::start("publish_root");
    let published = cluster.runtime.block_on(async {
        let node = &cluster.nodes[0];
        let staged = node
            .stage_application_object(
                node.next_production_client_serial().await?,
                &SealedRecordObject::new_native_v6_commit_intent(intent)?,
            )
            .await?;
        node.publish_native_v6_root(
            node.next_production_client_serial().await?,
            &intent,
            &staged,
            &enrollment,
            proposal.sealed_root().to_vec(),
            Instant::now() + Duration::from_secs(5),
        )
        .await
    })?;
    phase.finish();
    let phase = ArchiveDiagnosticPhase::start("selection_and_local_pack");
    let selection = NativeV6ArchiveSelection::from_committed(&enrollment, &published)?;
    let (manifest, expected_refs) =
        sender.reopen_root_closure_archive(&published, &mut || Ok(()))?;
    let barrier = AeadBarrier::new(**service.barrier_key.as_ref().ok_or("barrier")?)?;
    // Raw seal metadata bytes are a test binding here. The future HTTP owner
    // must supply its existing canonical seal identity and custody proof.
    let seal_identity: [u8; 32] = Sha256::digest(serde_json::to_vec(
        service.seal.as_ref().ok_or("seal metadata")?,
    )?)
    .into();
    let local_path = files.path.join("archive-original-local.pack");
    let local = prepare_native_v6_local_pack(
        service.durable.as_mut().ok_or("durable")?,
        &selection,
        private_file(&local_path)?,
        deadline,
        &mut || Ok(()),
        &mut |_, _| Ok(()),
    )
    .inspect_err(|error| phase.error("prepare_native_v6_local_pack", error))?;
    phase.finish();
    let archive_path = files.path.join("native-v6-ha-format.archive");
    let mut archive_file = private_file(&archive_path)?;
    let phase = ArchiveDiagnosticPhase::start("write_dual_archive");
    let report = write_native_v6_archive(
        &selection,
        local,
        &sender,
        seal_identity,
        &barrier,
        &mut archive_file,
        &mut || Ok(()),
    )
    .inspect_err(|error| phase.error("write_native_v6_archive", error))?;
    phase.finish();
    archive_file.flush()?;
    assert_eq!(
        report.local.generation,
        service.durable.as_ref().ok_or("durable")?.generation()
    );
    assert_ne!(
        report.local.generation,
        published.generation(),
        "local and Raft generations stay distinct"
    );
    assert_eq!(report.shared_object_count, expected_refs.len() as u64);
    assert_eq!(report.shared_ciphertext_bytes, intent.ciphertext_bytes);
    assert_eq!(report.archive_bytes, archive_file.metadata()?.len());
    assert_eq!(report.archive_sha256, hash_file(&archive_path)?);
    drop((archive_file, sender, proposal, plan, state, export_scope));
    fs::remove_dir_all(&sender_path)?;
    assert!(
        !sender_path.exists(),
        "roundtrip cannot borrow the original shared ciphertext store"
    );

    let read_scope = archive_scope();
    let phase = ArchiveDiagnosticPhase::start("validate_dual_archive");
    let reader = ArchiveView::new(&archive_path)?;
    let largest = Rc::clone(&reader.largest);
    let mut verified = validate_native_v6_archive(
        reader,
        &selection,
        seal_identity,
        &barrier,
        OriginalDeadline::capture()?,
        &mut || Ok(()),
    )?;
    phase.finish();
    assert_eq!(verified.report(), report);
    assert_eq!(verified.manifest(), manifest);
    assert_eq!(verified.references(), expected_refs);
    let phase = ArchiveDiagnosticPhase::start("copy_and_prepare_local_restore");
    let local_copy_path = files.path.join("archive-roundtrip-local.pack");
    let mut local_copy = private_file(&local_copy_path)?;
    verified.copy_local_pack_to(&mut local_copy, &mut || Ok(()))?;
    local_copy.flush()?;
    assert_eq!(hash_file(&local_copy_path)?, hash_file(&local_path)?);
    let local_generation = service.durable.as_ref().ok_or("durable")?.generation();
    let local_prepared = service
        .durable
        .as_ref()
        .ok_or("durable")?
        .prepare_v6_restore_from_reader(
            File::open(&local_copy_path)?,
            report.local.archive_bytes,
            &mut || Ok(()),
            &mut |_, _, _| Ok(()),
        )?;
    assert_eq!(local_prepared.size(), report.local);
    let local_root = RecordStateRootV6::decode(
        local_prepared
            .state()
            .get("system", "state")?
            .ok_or("prepared original local root")?,
    )
    .map_err(|_| "local root")?;
    assert_eq!(
        local_root.identity().map_err(|_| "identity")?,
        StateIdentity::RecordsV6(published.root_digest())
    );
    drop(local_prepared); // Deliberately never install or change a local cursor.
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        local_generation
    );
    phase.finish();
    let phase = ArchiveDiagnosticPhase::start("restore_shared_ciphertext");
    let target = stage(&files.path.join("archive-roundtrip-ciphertext"))?;
    let mut received_bytes = 0u64;
    verified.visit_shared_ciphertext(&mut || Ok(()), &mut |reference, bytes| {
        target
            .stage_received_replica_checked(reference, bytes, &mut || Ok(()))
            .inspect_err(|error| phase.error("stage_received_replica_checked", error))
            .map_err(|_| NativeV6ArchiveError::Storage)?;
        received_bytes += bytes.len() as u64;
        Ok(())
    })
    .inspect_err(|error| phase.error("visit_shared_ciphertext", error))?;
    assert_eq!(received_bytes, report.shared_ciphertext_bytes);
    assert!(
        largest.get() <= 256 * 1024,
        "every untrusted Read remains bounded"
    );
    let local_closure = target.persist_local_closure(&expected_refs, &mut || Ok(()))?;
    assert_eq!(
        local_closure.manifest_sha256(),
        intent.closure_manifest_sha256
    );
    assert_eq!(
        target
            .reopen_root_closure_archive(&published, &mut || Ok(()))?
            .0,
        manifest
    );
    phase.finish();
    drop((verified, read_scope));

    // The exact original shared cipher references still decrypt and materialize
    // all retained Service history; no re-encryption reconstructed fake IDs.
    let graph_scope = archive_scope();
    let graph_deadline = OriginalDeadline::capture()?;
    let phase = ArchiveDiagnosticPhase::start("open_typed_graph_and_exact_history");
    let context = ReadContext {
        expected_identity: ReadIdentity::RecordsV6(published.root_digest()),
        cluster_id: &cluster_id,
        replay_epoch: enrollment.epoch(),
        minimum_state_schema: local_root.state_schema,
        maximum_state_schema: local_root.state_schema,
        reader_format: 6,
    };
    let received = open_native_v6_ha_objects(
        &codec,
        &enrollment,
        &published,
        &target,
        context,
        graph_deadline,
        &mut || Ok(()),
    )
    .inspect_err(|error| phase.error("open_native_v6_ha_objects", error))?;
    let mut original_actor = || Ok(());
    let original_gate = RefCell::new(OriginalGate {
        deadline: graph_deadline,
        actor: &mut original_actor,
    });
    let source = CipherSource {
        codec: &codec,
        store: &target,
        closure: received.cipher_closure(),
        gate: &original_gate,
    };
    let (mount, view) = received
        .native
        .iter()
        .find(|(mount, _)| mount.mount == "secret/")
        .ok_or("KV2 history")?;
    assert_eq!(view.counts(), (1, 17, 17));
    let graph_reader = DomainReader {
        source: &source,
        domain: ObjectDomain::Kv2(mount.clone()),
    };
    for version in [1, 9, 17] {
        let response = view.read_with_source(
            "GET",
            "data/cipher-history",
            &json!({"version":version}),
            crate::auth::Timestamp::whole(200)?,
            &graph_reader,
        )?;
        assert_eq!(response.status, 200);
        assert_eq!(
            response.body["data"]["data"]["blob"].as_str(),
            Some(unique_payload(version).as_str())
        );
    }
    drop(graph_reader);
    drop(source);
    drop(received);
    phase.finish();
    drop(graph_scope);

    // Wire offsets below intentionally test the documented fixed HBV6HA01
    // framing independently of its private Rust Header implementation.
    let mut header = [0; 232];
    File::open(&archive_path)?.read_exact(&mut header)?;
    let provenance_bytes = u32::from_be_bytes(header[8..12].try_into()?) as u64;
    let local_offset = 232 + provenance_bytes;
    let manifest_offset = local_offset + report.local.archive_bytes;
    let leaves_offset = manifest_offset + manifest.len() as u64;
    let first_leaf = expected_refs.first().ok_or("first leaf")?.payload_bytes;
    let mut provenance = vec![0; provenance_bytes as usize];
    let mut raw = File::open(&archive_path)?;
    raw.seek(SeekFrom::Start(232))?;
    raw.read_exact(&mut provenance)?;
    let root_offset = 232
        + provenance
            .windows(32)
            .position(|bytes| bytes == published.root_digest())
            .ok_or("encoded actual root digest")? as u64;
    for (label, offset) in [
        ("wrong actual root digest", root_offset),
        ("changed enrollment digest", 232 + 48),
        ("changed full membership LogId", 232 + 80),
        ("oversized provenance", 8),
        ("reserved framing", 12),
        ("oversized manifest", 16),
        ("oversized local pack", 48),
        ("oversized leaf count", 56),
        ("corrupt local pack", local_offset + 64),
        ("corrupt manifest", manifest_offset + 8),
        ("corrupt shared leaf", leaves_offset + 7),
        ("corrupt sealed footer", report.archive_bytes - 1),
    ] {
        let _operation = archive_scope();
        let mut hostile = ArchiveView::new(&archive_path)?;
        hostile.flip(offset)?;
        assert!(
            validate_native_v6_archive(
                hostile,
                &selection,
                seal_identity,
                &barrier,
                OriginalDeadline::capture()?,
                &mut || Ok(())
            )
            .is_err(),
            "{label}"
        );
    }
    for (label, length) in [
        ("missing full leaf", report.archive_bytes - first_leaf),
        ("extra full leaf", report.archive_bytes + first_leaf),
        ("truncated footer", report.archive_bytes - 1),
        ("oversized archive", u64::MAX),
    ] {
        let _operation = archive_scope();
        let mut hostile = ArchiveView::new(&archive_path)?;
        hostile.length = length;
        assert!(
            validate_native_v6_archive(
                hostile,
                &selection,
                seal_identity,
                &barrier,
                OriginalDeadline::capture()?,
                &mut || Ok(())
            )
            .is_err(),
            "{label}"
        );
    }
    {
        let _operation = archive_scope();
        assert!(
            validate_native_v6_archive(
                ArchiveView::new(&archive_path)?,
                &selection,
                [99; 32],
                &barrier,
                OriginalDeadline::capture()?,
                &mut || Ok(())
            )
            .is_err()
        );
        let other_barrier = AeadBarrier::new([91; 32])?;
        assert!(
            validate_native_v6_archive(
                ArchiveView::new(&archive_path)?,
                &selection,
                seal_identity,
                &other_barrier,
                OriginalDeadline::capture()?,
                &mut || Ok(())
            )
            .is_err()
        );
    }
    {
        let _operation = archive_scope();
        let mut checks = 0;
        let denied = validate_native_v6_archive(
            ArchiveView::new(&archive_path)?,
            &selection,
            seal_identity,
            &barrier,
            OriginalDeadline::capture()?,
            &mut || {
                checks += 1;
                if checks >= 8 {
                    Err(NativeV6ArchiveError::Gate)
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(denied, Err(NativeV6ArchiveError::Gate)));
    }
    {
        let _operation = archive_scope();
        let mut late = ArchiveView::new(&archive_path)?;
        late.flip(leaves_offset + 7)?;
        late.active.set(false);
        let change = Rc::clone(&late.active);
        let mut verified = validate_native_v6_archive(
            late,
            &selection,
            seal_identity,
            &barrier,
            OriginalDeadline::capture()?,
            &mut || Ok(()),
        )?;
        change.set(true);
        let mut delivered = 0;
        let outcome = verified.visit_shared_ciphertext(&mut || Ok(()), &mut |_, _| {
            delivered += 1;
            Ok(())
        });
        assert!(outcome.is_err());
        assert_eq!(
            delivered, 0,
            "changed first leaf never reaches the data callback"
        );
    }
    {
        let end = Instant::now() + Duration::from_millis(250);
        let _operation = RequestDeadlineScope::enter(end);
        let mut late = ArchiveView::new(&archive_path)?;
        late.finish_first_read_after = Some(end);
        let reads = Rc::clone(&late.largest);
        let outcome = validate_native_v6_archive(
            late,
            &selection,
            seal_identity,
            &barrier,
            OriginalDeadline::capture()?,
            &mut || Ok(()),
        );
        assert!(matches!(outcome, Err(NativeV6ArchiveError::Gate)));
        assert_eq!(
            reads.get(),
            232,
            "a real first Read returned after the original deadline"
        );
    }
    assert!(
        service.ha.is_none(),
        "format test never admits native Service HA backup"
    );
    Ok(())
}
