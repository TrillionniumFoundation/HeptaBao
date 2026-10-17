//! Candidate-only, data-only dual-pack archive primitives.
//!
//! HBV6HA01 preserves the original shared ciphertext manifest and leaves beside
//! the real local-barrier HBV6PK01 pack. Neither a decoded archive nor its
//! hashes can become a published root, enrollment, fsync receipt, live read
//! witness, Actor or restore plan. In particular, this module does not make a
//! captured Raft root current. A future Service export coordinator must retain
//! and verify its actual owner/read/typed-graph proof around this primitive.
//! No snapshot HTTP guard, current-root repair or epoch transition is enabled.
use crate::crypto::AeadBarrier;
use crate::state_record_root::StateIdentity;
use crate::state_record_root_v6::RecordStateRootV6;
use crate::v6_native_custody::OriginalDeadline;
use heptabao_durable_service::{Barrier, DurableService, ServiceError, V6BackupSize};
use heptabao_raft_runtime::{
    LocalV6BlobError, LocalV6BlobStage, NativeV6CommitIntent, NativeV6PeerEnrollment,
    NativeV6PublishedRoot, RecordObjectRef, SealedRecordObject,
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};
use zeroize::Zeroizing;

#[path = "ha_native_v6_backup_format.rs"]
mod format;
use format::*;

#[derive(Debug)]
pub(crate) enum NativeV6ArchiveError {
    Invalid,
    TooLarge,
    WrongSelection,
    Corrupt,
    Gate,
    Storage,
    Io(io::Error),
}
impl fmt::Display for NativeV6ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "native HA archive has invalid framing or counts",
            Self::TooLarge => "native HA archive exceeds its explicit component bound",
            Self::WrongSelection => "native HA archive differs from the expected root or seal",
            Self::Corrupt => "native HA archive bytes or authentication changed",
            Self::Gate => "original native HA archive gate is unavailable",
            Self::Storage => "native HA archive source storage is unavailable or changed",
            Self::Io(_) => "native HA archive bounded I/O failed",
        })
    }
}
impl std::error::Error for NativeV6ArchiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for NativeV6ArchiveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
pub(crate) type ArchiveResult<T> = Result<T, NativeV6ArchiveError>;

/// Static provenance copied ONLY from actual opaque Raft values. There is no
/// wire constructor and no accessor returning the retained published root.
/// Even the originating values may be stale; this is expressly not authority.
pub(crate) struct NativeV6ArchiveSelection {
    provenance: Vec<u8>,
    published: NativeV6PublishedRoot,
}
impl NativeV6ArchiveSelection {
    pub(crate) fn from_committed(
        enrollment: &NativeV6PeerEnrollment,
        published: &NativeV6PublishedRoot,
    ) -> ArchiveResult<Self> {
        let intent = published.intent();
        let encoded_intent = intent.encode().map_err(|_| NativeV6ArchiveError::Invalid)?;
        if published.enrollment_digest() != enrollment.digest()
            || intent.cluster_digest != enrollment.cluster_digest()
            || intent.epoch != enrollment.epoch()
            || enrollment.enrollment_log_id().index >= published.intent_log_id().index
            || published.intent_log_id().index >= published.publication_log_id().index
            || !(3..=256).contains(&enrollment.pins().len())
            || !(25..=crate::state_record_root::MAX_ROOT_BYTES + 256)
                .contains(&published.sealed_root().len())
        {
            return Err(NativeV6ArchiveError::WrongSelection);
        }
        // These are encodings of existing getters, not mirrored deserializable
        // enrollment/root structs. Validation compares the entire exact byte
        // sequence with another actual selection; it never rebuilds authority.
        let mut provenance = b"HBV6HAP1".to_vec();
        provenance.extend_from_slice(&enrollment.cluster_digest());
        provenance.extend_from_slice(&enrollment.epoch().to_be_bytes());
        provenance.extend_from_slice(&enrollment.digest());
        for log in [
            enrollment.membership_log_id(),
            enrollment.enrollment_log_id(),
            published.intent_log_id(),
            published.publication_log_id(),
            published.migration_source().1,
        ] {
            provenance.extend_from_slice(&log.committed_leader_id().term.to_be_bytes());
            provenance.extend_from_slice(&log.committed_leader_id().node_id.to_be_bytes());
            provenance.extend_from_slice(&log.index.to_be_bytes());
        }
        provenance.extend_from_slice(&published.migration_source().0);
        provenance.extend_from_slice(&(enrollment.pins().len() as u64).to_be_bytes());
        for (voter, pin) in enrollment.pins() {
            provenance.extend_from_slice(&voter.to_be_bytes());
            provenance.extend_from_slice(pin);
        }
        provenance.extend_from_slice(&(encoded_intent.len() as u32).to_be_bytes());
        provenance.extend_from_slice(&encoded_intent);
        provenance.extend_from_slice(&(published.sealed_root().len() as u32).to_be_bytes());
        provenance.extend_from_slice(published.sealed_root());
        if provenance.len() > MAX_PROVENANCE_BYTES {
            return Err(NativeV6ArchiveError::TooLarge);
        }
        Ok(Self {
            provenance,
            published: published.clone(),
        })
    }

    fn intent(&self) -> NativeV6CommitIntent {
        self.published.intent()
    }

    fn check_local(&self, durable: &mut DurableService<AeadBarrier>) -> ArchiveResult<()> {
        durable
            .verify_live_ownership()
            .map_err(|_| NativeV6ArchiveError::Storage)?;
        let bytes = durable
            .get("system", "state")
            .map_err(|_| NativeV6ArchiveError::Storage)?
            .ok_or(NativeV6ArchiveError::WrongSelection)?;
        let root = RecordStateRootV6::decode(bytes.expose())
            .map_err(|_| NativeV6ArchiveError::WrongSelection)?;
        if root
            .identity()
            .map_err(|_| NativeV6ArchiveError::WrongSelection)?
            != StateIdentity::RecordsV6(self.published.root_digest())
            || root.replay_epoch != self.intent().epoch
        {
            return Err(NativeV6ArchiveError::WrongSelection);
        }
        Ok(())
    }
}

/// Owns the output of one real Durable export, not caller-asserted pack counts.
/// The reader is not detached or exposed before archive emission consumes it.
pub(crate) struct NativeV6LocalArchivePack<R> {
    reader: R,
    size: V6BackupSize,
    digest: [u8; 32],
    selection_digest: [u8; 32],
    deadline: OriginalDeadline,
}

/// Export the actual complete local slot index. `verify` is the existing typed
/// object validator; it supplements the source session and AEAD checks. A
/// caller must have materialized the complete original typed graph as well.
/// The supplied spool must be an empty, owned seekable object (the production
/// composition should use SnapshotFile, not an ambient pathname).
pub(crate) fn prepare_native_v6_local_pack<R: Read + Write + Seek>(
    durable: &mut DurableService<AeadBarrier>,
    selection: &NativeV6ArchiveSelection,
    mut spool: R,
    deadline: OriginalDeadline,
    gate: &mut impl FnMut() -> ArchiveResult<()>,
    verify: &mut impl FnMut(&str, &[u8]) -> Result<(), ServiceError>,
) -> ArchiveResult<NativeV6LocalArchivePack<R>> {
    check(deadline, gate)?;
    selection.check_local(durable)?;
    if seek(&mut spool, SeekFrom::End(0), deadline, gate)? != 0 {
        return Err(NativeV6ArchiveError::Invalid);
    }
    seek(&mut spool, SeekFrom::Start(0), deadline, gate)?;
    let (size, digest, count) = {
        let mut output = HashWriter::new(&mut spool, MAX_LOCAL_PACK_BYTES);
        let mut source_gate = || check(deadline, gate).map_err(|_| ServiceError::BarrierFailure);
        let source = durable
            .prepare_v6_backup(&mut source_gate)
            .map_err(|_| NativeV6ArchiveError::Storage)?;
        let size = durable
            .export_v6_backup_to(source, &mut output, &mut source_gate, verify)
            .map_err(|_| NativeV6ArchiveError::Storage)?;
        (size, output.digest(), output.count)
    };
    check(deadline, gate)?;
    selection.check_local(durable)?;
    validate_local_size(size)?;
    if size.archive_bytes != count
        || size.generation != durable.generation()
        || seek(&mut spool, SeekFrom::End(0), deadline, gate)? != count
    {
        return Err(NativeV6ArchiveError::Corrupt);
    }
    seek(&mut spool, SeekFrom::Start(0), deadline, gate)?;
    Ok(NativeV6LocalArchivePack {
        reader: spool,
        size,
        digest,
        selection_digest: Sha256::digest(&selection.provenance).into(),
        deadline,
    })
}

/// Format facts only, including separate local and Raft generations. There is
/// no publication/restore method and no live witness hidden in this report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeV6ArchiveReport {
    pub(crate) local: V6BackupSize,
    pub(crate) shared_object_count: u64,
    pub(crate) shared_ciphertext_bytes: u64,
    pub(crate) archive_bytes: u64,
    pub(crate) archive_sha256: [u8; 32],
}

/// Write a complete authenticated dual pack. On error the caller must discard
/// the output; this primitive neither publishes a file nor changes live state.
/// The original operation deadline comes from the consumed local pack.
pub(crate) fn write_native_v6_archive<R: Read + Seek>(
    selection: &NativeV6ArchiveSelection,
    mut local: NativeV6LocalArchivePack<R>,
    store: &LocalV6BlobStage,
    seal_identity: [u8; 32],
    barrier: &AeadBarrier,
    writer: &mut impl Write,
    gate: &mut impl FnMut() -> ArchiveResult<()>,
) -> ArchiveResult<NativeV6ArchiveReport> {
    let deadline = local.deadline;
    check(deadline, gate)?;
    if seal_identity == [0; 32]
        || local.selection_digest != <[u8; 32]>::from(Sha256::digest(&selection.provenance))
    {
        return Err(NativeV6ArchiveError::WrongSelection);
    }
    let (manifest, references) = store
        .reopen_root_closure_archive(&selection.published, &mut || {
            check(deadline, gate).map_err(|_| LocalV6BlobError::CorruptOrChanged)
        })
        .map_err(|_| NativeV6ArchiveError::Storage)?;
    let mut shared_hash = shared_hasher();
    shared_hash.update(&manifest);
    for reference in &references {
        let bytes = read_leaf(store, reference, deadline, gate)?;
        shared_hash.update(&bytes);
    }
    let intent = selection.intent();
    let header = Header {
        provenance_bytes: selection.provenance.len(),
        manifest_bytes: manifest.len(),
        local: local.size,
        shared_object_count: intent.object_count,
        shared_ciphertext_bytes: intent.ciphertext_bytes,
        seal_identity,
        provenance_sha256: local.selection_digest,
        manifest_sha256: Sha256::digest(&manifest).into(),
        local_sha256: local.digest,
        shared_sha256: shared_hash.finalize().into(),
    };
    header.validate()?;
    let mut output = HashWriter::new(writer, MAX_ARCHIVE_BYTES);
    let mut transcript = transcript_hasher();
    let header_bytes = header.encode();
    for bytes in [header_bytes.as_slice(), selection.provenance.as_slice()] {
        emit(&mut output, &mut transcript, bytes, deadline, gate)?;
    }
    seek(&mut local.reader, SeekFrom::Start(0), deadline, gate)?;
    let mut local_hash = Sha256::new();
    copy_exact(
        &mut local.reader,
        local.size.archive_bytes,
        deadline,
        gate,
        &mut |bytes, gate| {
            local_hash.update(bytes);
            emit(&mut output, &mut transcript, bytes, deadline, gate)
        },
    )?;
    require_eof(&mut local.reader, deadline, gate)?;
    if <[u8; 32]>::from(local_hash.finalize()) != local.digest {
        return Err(NativeV6ArchiveError::Corrupt);
    }
    emit(&mut output, &mut transcript, &manifest, deadline, gate)?;
    let mut observed_shared = shared_hasher();
    observed_shared.update(&manifest);
    for reference in &references {
        let bytes = read_leaf(store, reference, deadline, gate)?;
        observed_shared.update(&bytes);
        emit(&mut output, &mut transcript, &bytes, deadline, gate)?;
    }
    if <[u8; 32]>::from(observed_shared.finalize()) != header.shared_sha256 {
        return Err(NativeV6ArchiveError::Corrupt);
    }
    check(deadline, gate)?;
    let transcript: [u8; 32] = transcript.finalize().into();
    let footer = barrier
        .seal(ARCHIVE_AAD, &transcript)
        .map_err(|_| NativeV6ArchiveError::Corrupt)?;
    if !(1..=MAX_FOOTER_BYTES).contains(&footer.len()) {
        return Err(NativeV6ArchiveError::TooLarge);
    }
    write(
        &mut output,
        &(footer.len() as u32).to_be_bytes(),
        deadline,
        gate,
    )?;
    write(&mut output, &footer, deadline, gate)?;
    check(deadline, gate)?;
    Ok(header.report(output.count, output.digest()))
}

fn read_leaf(
    store: &LocalV6BlobStage,
    reference: &RecordObjectRef,
    deadline: OriginalDeadline,
    gate: &mut impl FnMut() -> ArchiveResult<()>,
) -> ArchiveResult<Vec<u8>> {
    check(deadline, gate)?;
    let bytes = store
        .read_local(reference)
        .map_err(|_| NativeV6ArchiveError::Storage)?;
    check(deadline, gate)?;
    Ok(bytes)
}

/// A fully checked archive retained under its original bounded read operation.
/// Only raw encrypted pack/manifest/leaf bytes can be revisited. They are
/// rehashed at use, so a mutable reader cannot swap bytes after validation.
pub(crate) struct VerifiedNativeV6Archive<R> {
    reader: R,
    header: Header,
    manifest: Vec<u8>,
    references: Vec<RecordObjectRef>,
    local_offset: u64,
    leaves_offset: u64,
    report: NativeV6ArchiveReport,
    deadline: OriginalDeadline,
}
impl<R: Read + Seek> VerifiedNativeV6Archive<R> {
    pub(crate) fn report(&self) -> NativeV6ArchiveReport {
        self.report
    }
    pub(crate) fn manifest(&self) -> &[u8] {
        &self.manifest
    }
    pub(crate) fn references(&self) -> &[RecordObjectRef] {
        &self.references
    }

    pub(crate) fn copy_local_pack_to(
        &mut self,
        writer: &mut impl Write,
        gate: &mut impl FnMut() -> ArchiveResult<()>,
    ) -> ArchiveResult<()> {
        seek(
            &mut self.reader,
            SeekFrom::Start(self.local_offset),
            self.deadline,
            gate,
        )?;
        let mut digest = Sha256::new();
        copy_exact(
            &mut self.reader,
            self.header.local.archive_bytes,
            self.deadline,
            gate,
            &mut |bytes, gate| {
                digest.update(bytes);
                write(writer, bytes, self.deadline, gate)
            },
        )?;
        if <[u8; 32]>::from(digest.finalize()) != self.header.local_sha256 {
            return Err(NativeV6ArchiveError::Corrupt);
        }
        check(self.deadline, gate)
    }

    /// Callback output is data only. A late callback/I/O failure may leave
    /// unreferenced local bytes, never a completed closure or Raft ACK.
    pub(crate) fn visit_shared_ciphertext(
        &mut self,
        gate: &mut impl FnMut() -> ArchiveResult<()>,
        visit: &mut impl FnMut(&RecordObjectRef, &[u8]) -> ArchiveResult<()>,
    ) -> ArchiveResult<()> {
        seek(
            &mut self.reader,
            SeekFrom::Start(self.leaves_offset),
            self.deadline,
            gate,
        )?;
        for reference in &self.references {
            let mut bytes = vec![0; reference.encoded_bytes as usize];
            read_exact(&mut self.reader, &mut bytes, self.deadline, gate)?;
            verify_leaf(reference, &bytes)?;
            check(self.deadline, gate)?;
            visit(reference, &bytes)?;
            check(self.deadline, gate)?;
        }
        check(self.deadline, gate)
    }
}

/// Authenticate the whole archive against an actual, independently selected
/// root and expected seal metadata digest. The expected root need not be live;
/// that check and any recovery decision belong to the future Service owner.
/// No untrusted bytes are decoded into opaque Raft types or a restore plan.
pub(crate) fn validate_native_v6_archive<R: Read + Seek>(
    mut reader: R,
    expected: &NativeV6ArchiveSelection,
    expected_seal_identity: [u8; 32],
    barrier: &AeadBarrier,
    deadline: OriginalDeadline,
    gate: &mut impl FnMut() -> ArchiveResult<()>,
) -> ArchiveResult<VerifiedNativeV6Archive<R>> {
    check(deadline, gate)?;
    let length = seek(&mut reader, SeekFrom::End(0), deadline, gate)?;
    if length > MAX_ARCHIVE_BYTES {
        return Err(NativeV6ArchiveError::TooLarge);
    }
    if length < HEADER_BYTES as u64 + 5 {
        return Err(NativeV6ArchiveError::Invalid);
    }
    seek(&mut reader, SeekFrom::Start(0), deadline, gate)?;
    let mut whole = Sha256::new();
    let mut transcript = transcript_hasher();
    let mut bytes = [0; HEADER_BYTES];
    absorb(
        &mut reader,
        &mut bytes,
        &mut whole,
        &mut transcript,
        deadline,
        gate,
    )?;
    let header = Header::decode(&bytes)?;
    let intent = expected.intent();
    if header.seal_identity != expected_seal_identity
        || expected_seal_identity == [0; 32]
        || header.shared_object_count != intent.object_count
        || header.shared_ciphertext_bytes != intent.ciphertext_bytes
        || header.provenance_bytes != expected.provenance.len()
        || header.provenance_sha256 != <[u8; 32]>::from(Sha256::digest(&expected.provenance))
    {
        return Err(NativeV6ArchiveError::WrongSelection);
    }
    let body_end = header.body_bytes()?;
    if length < body_end + 5 || length > body_end + 4 + MAX_FOOTER_BYTES as u64 {
        return Err(NativeV6ArchiveError::Invalid);
    }
    let mut provenance = vec![0; header.provenance_bytes];
    absorb(
        &mut reader,
        &mut provenance,
        &mut whole,
        &mut transcript,
        deadline,
        gate,
    )?;
    if provenance != expected.provenance {
        return Err(NativeV6ArchiveError::WrongSelection);
    }
    let local_offset = HEADER_BYTES as u64 + header.provenance_bytes as u64;
    let mut local_hash = Sha256::new();
    copy_exact(
        &mut reader,
        header.local.archive_bytes,
        deadline,
        gate,
        &mut |part, _gate| {
            local_hash.update(part);
            whole.update(part);
            transcript.update(part);
            Ok(())
        },
    )?;
    if <[u8; 32]>::from(local_hash.finalize()) != header.local_sha256 {
        return Err(NativeV6ArchiveError::Corrupt);
    }
    let mut manifest = vec![0; header.manifest_bytes];
    absorb(
        &mut reader,
        &mut manifest,
        &mut whole,
        &mut transcript,
        deadline,
        gate,
    )?;
    if <[u8; 32]>::from(Sha256::digest(&manifest)) != header.manifest_sha256 {
        return Err(NativeV6ArchiveError::Corrupt);
    }
    let references = LocalV6BlobStage::validate_archived_closure_manifest(&manifest, &intent)
        .map_err(|_| NativeV6ArchiveError::Corrupt)?;
    let leaves_offset = local_offset + header.local.archive_bytes + header.manifest_bytes as u64;
    let mut shared_hash = shared_hasher();
    shared_hash.update(&manifest);
    for reference in &references {
        let mut leaf = vec![0; reference.encoded_bytes as usize];
        absorb(
            &mut reader,
            &mut leaf,
            &mut whole,
            &mut transcript,
            deadline,
            gate,
        )?;
        verify_leaf(reference, &leaf)?;
        shared_hash.update(&leaf);
    }
    if <[u8; 32]>::from(shared_hash.finalize()) != header.shared_sha256 {
        return Err(NativeV6ArchiveError::Corrupt);
    }
    let mut footer_length = [0; 4];
    read_exact(&mut reader, &mut footer_length, deadline, gate)?;
    whole.update(footer_length);
    let footer_length = u32::from_be_bytes(footer_length) as usize;
    if !(1..=MAX_FOOTER_BYTES).contains(&footer_length)
        || body_end + 4 + footer_length as u64 != length
    {
        return Err(NativeV6ArchiveError::Invalid);
    }
    let mut footer = vec![0; footer_length];
    read_exact(&mut reader, &mut footer, deadline, gate)?;
    whole.update(&footer);
    require_eof(&mut reader, deadline, gate)?;
    check(deadline, gate)?;
    let verified = Zeroizing::new(
        barrier
            .open(ARCHIVE_AAD, &footer)
            .map_err(|_| NativeV6ArchiveError::Corrupt)?,
    );
    let transcript: [u8; 32] = transcript.finalize().into();
    if verified.as_slice() != transcript {
        return Err(NativeV6ArchiveError::Corrupt);
    }
    check(deadline, gate)?;
    let report = header.report(length, whole.finalize().into());
    Ok(VerifiedNativeV6Archive {
        reader,
        header,
        manifest,
        references,
        local_offset,
        leaves_offset,
        report,
        deadline,
    })
}

fn verify_leaf(reference: &RecordObjectRef, bytes: &[u8]) -> ArchiveResult<()> {
    let actual = SealedRecordObject::new_native_v6_ciphertext_chunk(bytes.to_vec())
        .map_err(|_| NativeV6ArchiveError::Corrupt)?;
    if actual.reference() != reference {
        return Err(NativeV6ArchiveError::Corrupt);
    }
    Ok(())
}
