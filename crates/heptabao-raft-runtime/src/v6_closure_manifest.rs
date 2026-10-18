//! Durable, canonical external closure manifests. Only references enter this
//! file; neither manifest nor ciphertext is inserted into the Raft JSON state.
use super::*;
use heptabao_filesystem_guard::ImmutablePublicationCheckedError;

const MAGIC: &[u8; 8] = b"HBVCM001";
const MAX_OBJECTS: usize = 131_072;
const HEADER_BYTES: usize = 16;
const ENTRY_BYTES: usize = 40;
const MAX_MANIFEST_BYTES: usize = HEADER_BYTES + MAX_OBJECTS * ENTRY_BYTES;

fn canonical(
    references: &[RecordObjectRef],
) -> Result<(Vec<u8>, LocalV6ClosureReceipt), LocalV6BlobError> {
    if references.is_empty() || references.len() > MAX_OBJECTS {
        return Err(LocalV6BlobError::InvalidClosure);
    }
    let mut ordered: Vec<_> = references.iter().collect();
    ordered.sort_unstable_by_key(|reference| reference.id);
    if ordered.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(LocalV6BlobError::InvalidClosure);
    }
    let count = references.len() as u64;
    let mut bytes = Vec::with_capacity(HEADER_BYTES + references.len() * ENTRY_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&count.to_be_bytes());
    let mut hash = Sha256::new();
    hash.update(b"heptabao.v6.local-ciphertext-closure.v1\0");
    hash.update(count.to_be_bytes());
    let mut total = 0u64;
    for reference in ordered {
        LocalV6BlobStage::leaf(reference)?;
        if reference.id == [0; 32] {
            return Err(LocalV6BlobError::InvalidClosure);
        }
        total = total
            .checked_add(reference.payload_bytes)
            .ok_or(LocalV6BlobError::InvalidClosure)?;
        bytes.extend_from_slice(&reference.id);
        bytes.extend_from_slice(&reference.payload_bytes.to_be_bytes());
        hash.update(reference.id);
        hash.update(reference.payload_bytes.to_be_bytes());
    }
    Ok((
        bytes,
        LocalV6ClosureReceipt {
            object_count: references.len(),
            ciphertext_bytes: total,
            manifest_sha256: hash.finalize().into(),
        },
    ))
}

fn decode(bytes: &[u8]) -> Result<Vec<RecordObjectRef>, LocalV6BlobError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_MANIFEST_BYTES || &bytes[..8] != MAGIC {
        return Err(LocalV6BlobError::CorruptOrChanged);
    }
    let count = u64::from_be_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| LocalV6BlobError::InvalidClosure)?,
    );
    let count = usize::try_from(count).map_err(|_| LocalV6BlobError::InvalidClosure)?;
    if count == 0 || count > MAX_OBJECTS || bytes.len() != HEADER_BYTES + count * ENTRY_BYTES {
        return Err(LocalV6BlobError::InvalidClosure);
    }
    let mut refs = Vec::with_capacity(count);
    for entry in bytes[HEADER_BYTES..].chunks_exact(ENTRY_BYTES) {
        let id = entry[..32]
            .try_into()
            .map_err(|_| LocalV6BlobError::InvalidClosure)?;
        let payload_bytes = u64::from_be_bytes(
            entry[32..]
                .try_into()
                .map_err(|_| LocalV6BlobError::InvalidClosure)?,
        );
        refs.push(RecordObjectRef {
            id,
            kind: RecordObjectKind::NativeV6CiphertextChunk,
            encoded_bytes: u32::try_from(payload_bytes)
                .map_err(|_| LocalV6BlobError::InvalidClosure)?,
            record_count: 0,
            payload_bytes,
        });
    }
    // Reject duplicate, unsorted or noncanonical input, not merely a matching
    // set after silently repairing the file's order.
    if canonical(&refs)?.0 != bytes {
        return Err(LocalV6BlobError::CorruptOrChanged);
    }
    Ok(refs)
}

fn name(digest: &[u8; 32]) -> Result<String, LocalV6BlobError> {
    if *digest == [0; 32] {
        return Err(LocalV6BlobError::InvalidClosure);
    }
    let mut name = String::from("v6-closure-");
    crate::append_hex(&mut name, digest);
    name.push_str(".manifest");
    Ok(name)
}

fn read_manifest(
    file: &mut File,
    gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
) -> Result<Vec<u8>, LocalV6BlobError> {
    gate()?;
    let len = file.metadata()?.len();
    gate()?;
    if len < HEADER_BYTES as u64 || len > MAX_MANIFEST_BYTES as u64 {
        return Err(LocalV6BlobError::InvalidClosure);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut result = Vec::with_capacity(len as usize);
    let mut scratch = [0u8; 64 * 1024];
    loop {
        gate()?;
        let count = file.read(&mut scratch)?;
        gate()?;
        if count == 0 {
            break;
        }
        if result
            .len()
            .checked_add(count)
            .is_none_or(|size| size > len as usize)
        {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        result.extend_from_slice(&scratch[..count]);
    }
    if result.len() != len as usize {
        return Err(LocalV6BlobError::CorruptOrChanged);
    }
    Ok(result)
}

impl LocalV6BlobStage {
    /// Reauthenticate all local files and fsync a canonical no-replace manifest,
    /// including its directory entry. This is local durability only. The same
    /// caller gate surrounds every object, manifest I/O and publication barrier.
    /// A failed/late result must not be treated as a successful root publication.
    pub fn persist_local_closure(
        &self,
        references: &[RecordObjectRef],
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<LocalV6ClosureReceipt, LocalV6BlobError> {
        gate()?;
        let (bytes, receipt) = canonical(references)?;
        for reference in references {
            gate()?;
            drop(self.read_local(reference)?);
            gate()?;
        }
        let target = name(&receipt.manifest_sha256)?;
        let temporary = format!(
            ".v6-manifest-tmp-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        );
        let mut file = self
            .directory
            .open_file(&temporary, FileAccess::CreateNewReadWrite)?;
        for part in bytes.chunks(64 * 1024) {
            gate()?;
            file.write_all(part)?;
            gate()?;
        }
        let publication = self
            .directory
            .publish_file_noreplace_checked(&temporary, &file, &target, bytes.len() as u64, gate)
            .map_err(|error| match error {
                ImmutablePublicationCheckedError::Publication(error) => {
                    LocalV6BlobError::Publication(error)
                }
                ImmutablePublicationCheckedError::GateBeforeLink(error)
                | ImmutablePublicationCheckedError::GateAfterLink(error) => error,
            })?;
        let mut published = match publication {
            ImmutablePublication::Published(file) | ImmutablePublication::AlreadyExists(file) => {
                file
            }
        };
        if read_manifest(&mut published, gate)? != bytes {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        gate()?;
        Ok(receipt)
    }

    /// Recover the exact external closure selected by a root obtained from the
    /// actual state machine. No directory scanning, unreferenced-file adoption,
    /// target writes or Raft state repair occurs. Missing or changed bytes fail.
    /// The returned references prove local availability only: the server still
    /// needs fresh quorum, barrier/graph validation and its original Actor gate.
    pub fn reopen_root_closure(
        &self,
        root: &crate::NativeV6PublishedRoot,
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<Vec<RecordObjectRef>, LocalV6BlobError> {
        self.reopen_root_closure_archive(root, gate)
            .map(|(_, references)| references)
    }

    /// Preserve the original canonical manifest bytes and verify every selected
    /// local leaf through the existing held directory descriptor. This is a
    /// data-only archive primitive: it creates no fsync receipt, live witness,
    /// intent permit, publication or restore authority. The caller still owns
    /// the actual root selection, original deadline and application gate.
    pub fn reopen_root_closure_archive(
        &self,
        root: &crate::NativeV6PublishedRoot,
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<(Vec<u8>, Vec<RecordObjectRef>), LocalV6BlobError> {
        gate()?;
        root.0
            .validate()
            .map_err(|_| LocalV6BlobError::InvalidClosure)?;
        let intent = root.intent();
        let manifest_name = name(&intent.closure_manifest_sha256)?;
        gate()?;
        let mut manifest = self.directory.open_file(&manifest_name, FileAccess::Read)?;
        let bytes = read_manifest(&mut manifest, gate)?;
        let refs = Self::validate_archived_closure_manifest(&bytes, &intent)?;
        for reference in &refs {
            gate()?;
            drop(self.read_local_checked(reference, gate)?);
            gate()?;
        }
        gate()?;
        Ok((bytes, refs))
    }

    /// Validate archived bytes using the one existing canonical manifest
    /// grammar and exact intent digest/count/length. Input intent metadata is
    /// data only; success does not claim local availability, fsync, an applied
    /// intent, membership, an Actor, a quorum or a selected published root.
    pub fn validate_archived_closure_manifest(
        bytes: &[u8],
        intent: &crate::NativeV6CommitIntent,
    ) -> Result<Vec<RecordObjectRef>, LocalV6BlobError> {
        intent
            .encode()
            .map_err(|_| LocalV6BlobError::InvalidClosure)?;
        let refs = decode(bytes)?;
        let (_, observed) = canonical(&refs)?;
        if observed.manifest_sha256 != intent.closure_manifest_sha256
            || observed.object_count as u64 != intent.object_count
            || observed.ciphertext_bytes != intent.ciphertext_bytes
        {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        Ok(refs)
    }
}
