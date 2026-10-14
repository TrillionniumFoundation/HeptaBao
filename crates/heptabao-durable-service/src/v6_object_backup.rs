//! Source-bound transport of the HBB2 state AND every committed V6 blob slot.
//!
//! HBV6PK01 is not the existing HTTP snapshot format and grants no Actor,
//! typed graph, namespace or HA authority. The server must validate the full
//! incoming root/graph with `state()` plus the authenticated object callbacks
//! before consuming a prepared restore. No public endpoint is enabled here.
//! Only registered slots enter the pack; unreferenced filesystem orphans do not.
//! The existing component bounds are unchanged; external ciphertext is streamed.
use super::*;
use std::collections::BTreeSet;
use std::io::{self, Read, Seek, SeekFrom, Write};

const MAGIC: &[u8; 8] = b"HBV6PK01";
const SLOT_MAGIC: &[u8; 16] = b"HBV6BLOBREF0001\0";
const OBJECT_PREFIX: &str = "state-records/v6/";
const OBJECT_AAD: &[u8] = b"HeptaBao/native-v6/typed-object-file/v1\0";
const PACK_AAD: &[u8] = b"HeptaBao/native-v6/object-backup/transcript/v1\0";
const MAX_OBJECTS: usize = 65_536;
const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_FOOTER: usize = 4096;
const HEADER_BYTES: usize = 32;
const IO_CHUNK: usize = 64 * 1024;

#[derive(Clone)]
struct Slot {
    resource: String,
    locator: BlobLocator,
    ciphertext_bytes: usize,
    plaintext_bytes: usize,
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.resource.zeroize();
    }
}
impl Slot {
    fn decode(resource: &str, bytes: &[u8]) -> Result<Self, ServiceError> {
        if bytes.len() != 72 || &bytes[..16] != SLOT_MAGIC {
            return Err(ServiceError::CorruptState);
        }
        let suffix = resource
            .strip_prefix(OBJECT_PREFIX)
            .ok_or(ServiceError::CorruptState)?;
        let fields: Vec<_> = suffix.split('/').collect();
        if !(matches!(fields.as_slice(), ["kv1" | "kv2", _])
            || matches!(fields.as_slice(), ["owner", role, _] if !role.is_empty() && role.len() <= 64
                && role.bytes().all(|x| x.is_ascii_alphanumeric() || x == b'-' || x == b'_')))
        {
            return Err(ServiceError::CorruptState);
        }
        let name = fields.last().ok_or(ServiceError::CorruptState)?;
        if name.len() != 64 {
            return Err(ServiceError::CorruptState);
        }
        let mut address = [0; 32];
        for (index, pair) in name.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            fn digit(x: u8) -> Result<u8, ServiceError> {
                match x {
                    b'0'..=b'9' => Ok(x - b'0'),
                    b'a'..=b'f' => Ok(x - b'a' + 10),
                    _ => Err(ServiceError::CorruptState),
                }
            }
            address[index] = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        if bytes[32..64] != address {
            return Err(ServiceError::CorruptState);
        }
        let store_id = bytes[16..32]
            .try_into()
            .map_err(|_| ServiceError::CorruptState)?;
        let ciphertext_bytes = u32::from_be_bytes(
            bytes[64..68]
                .try_into()
                .map_err(|_| ServiceError::CorruptState)?,
        ) as usize;
        let plaintext_bytes = u32::from_be_bytes(
            bytes[68..72]
                .try_into()
                .map_err(|_| ServiceError::CorruptState)?,
        ) as usize;
        if ciphertext_bytes == 0
            || ciphertext_bytes > MAX_IMMUTABLE_CIPHERTEXT_BYTES
            || plaintext_bytes == 0
            || plaintext_bytes > MAX_IMMUTABLE_CIPHERTEXT_BYTES
        {
            return Err(ServiceError::CorruptState);
        }
        Ok(Self {
            resource: resource.into(),
            locator: BlobLocator::new(store_id, address).map_err(map_backend_error)?,
            ciphertext_bytes,
            plaintext_bytes,
        })
    }
    fn aad(&self) -> Vec<u8> {
        let mut aad = OBJECT_AAD.to_vec();
        aad.extend_from_slice(self.resource.as_bytes());
        aad
    }
}

// Deliberately reserved system resources only. User KV bytes that happen to
// contain this marker do not acquire native-object or transport semantics.
pub(super) fn registered_slot(namespace: &str, resource: &str, value: &[u8]) -> bool {
    namespace == "system" && resource.starts_with(OBJECT_PREFIX) && value.starts_with(b"HBV6BLOB")
}
fn collect_slots<'a>(
    entries: impl Iterator<Item = (&'a str, &'a str, &'a [u8])>,
) -> Result<Vec<Slot>, ServiceError> {
    let mut slots = Vec::new();
    let mut addresses = BTreeSet::new();
    let mut total = 0_u64;
    let mut store = None;
    for (namespace, resource, bytes) in entries {
        if !registered_slot(namespace, resource, bytes) {
            continue;
        }
        if slots.len() == MAX_OBJECTS {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        let slot = Slot::decode(resource, bytes)?;
        let id = slot.locator.store_id();
        if store.is_some_and(|old| old != id) || !addresses.insert((id, slot.locator.address())) {
            return Err(ServiceError::CorruptState);
        }
        store = Some(id);
        total = total
            .checked_add(slot.ciphertext_bytes as u64)
            .ok_or(ServiceError::RequestCapacityExhausted)?;
        if total > MAX_OBJECT_BYTES {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        slots.push(slot);
    }
    if slots.is_empty() {
        return Err(ServiceError::UnsupportedProfile);
    }
    slots.sort_by(|a, b| a.resource.cmp(&b.resource));
    Ok(slots)
}
fn read_exact_checked(
    reader: &mut impl Read,
    bytes: &mut [u8],
    gate: &mut impl FnMut() -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    let mut done = 0;
    let mut interrupts = 0;
    while done < bytes.len() {
        gate()?;
        let end = bytes.len().min(done + IO_CHUNK);
        let result = reader.read(&mut bytes[done..end]);
        gate()?;
        match result {
            Ok(0) => return Err(ServiceError::CorruptState),
            Ok(n) if n <= end - done => {
                done += n;
                interrupts = 0;
            }
            Ok(_) => return Err(ServiceError::CorruptState),
            Err(e) if e.kind() == io::ErrorKind::Interrupted && interrupts < 64 => {
                interrupts += 1;
            }
            Err(e) => return Err(e.into()),
        }
    }
    gate()
}
fn write_checked(
    writer: &mut impl Write,
    bytes: &[u8],
    gate: &mut impl FnMut() -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    let mut done = 0;
    let mut interrupts = 0;
    while done < bytes.len() {
        gate()?;
        let end = bytes.len().min(done + IO_CHUNK);
        let result = writer.write(&bytes[done..end]);
        gate()?;
        match result {
            Ok(0) => {
                return Err(
                    io::Error::new(io::ErrorKind::WriteZero, "backup output stopped").into(),
                );
            }
            Ok(n) if n <= end - done => {
                done += n;
                interrupts = 0;
            }
            Ok(_) => return Err(ServiceError::CorruptState),
            Err(e) if e.kind() == io::ErrorKind::Interrupted && interrupts < 64 => {
                interrupts += 1;
            }
            Err(e) => return Err(e.into()),
        }
    }
    gate()
}
fn seek_checked(
    reader: &mut impl Seek,
    to: SeekFrom,
    gate: &mut impl FnMut() -> Result<(), ServiceError>,
) -> Result<u64, ServiceError> {
    gate()?;
    let at = reader.seek(to)?;
    gate()?;
    Ok(at)
}

/// One live source, captured once. Not Clone, serializable, or an application
/// read capability. Export consumes it and retains the original caller gate.
pub struct V6BackupSource {
    session: ImmutableSourceSession,
    core: Vec<u8>,
    slots: Vec<Slot>,
}
impl fmt::Debug for V6BackupSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6BackupSource")
            .field("object_count", &self.slots.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct V6BackupSize {
    pub generation: u64,
    pub object_count: usize,
    pub ciphertext_bytes: u64,
    pub archive_bytes: u64,
}
struct Member {
    slot: Slot,
    offset: u64,
    digest: [u8; 32],
}

/// Entire archive authenticated, but not yet staged or published. Owns the
/// input reader; selected ciphertext is hash-rechecked during installation.
/// The borrow-only state accessor does not let a caller detach an incomplete
/// HBB2 restore from the corresponding external objects.
pub struct PreparedV6Restore<R> {
    state: PreparedRestore,
    reader: R,
    members: Vec<Member>,
    size: V6BackupSize,
}
impl<R> fmt::Debug for PreparedV6Restore<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedV6Restore")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}
impl<R> PreparedV6Restore<R> {
    pub fn state(&self) -> &PreparedRestore {
        &self.state
    }
    pub fn size(&self) -> V6BackupSize {
        self.size
    }
}
impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    /// Capture a complete committed slot index, not a caller-supplied subset.
    /// The application must still validate root/graph closure and authority.
    pub fn prepare_v6_backup(
        &mut self,
        gate: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<V6BackupSource, ServiceError> {
        gate()?;
        self.verify_live_ownership()?;
        let slots = collect_slots(
            self.snapshot
                .entries
                .iter()
                .map(|((n, r), v)| (n.as_str(), r.as_str(), v.expose())),
        )?;
        let root = self
            .get("system", "state")?
            .ok_or(ServiceError::CorruptState)?;
        gate()?;
        let session = self.immutable_source_session(
            "system",
            "state",
            root.expose(),
            slots[0].locator.store_id(),
        )?;
        let mut core = Vec::new();
        self.export_core_backup_to(&mut core)?;
        gate()?;
        self.check_immutable_source_session(&session)?;
        Ok(V6BackupSource {
            session,
            core,
            slots,
        })
    }

    /// Emit only ciphertext. Every object is freshly source-bound and AEAD
    /// authenticated before output; `verify` must enforce typed object grammar
    /// against the caller's already authenticated root. A failed/expired export
    /// has no valid sealed footer and must not be published as a completed file.
    pub fn export_v6_backup_to(
        &mut self,
        source: V6BackupSource,
        writer: &mut impl Write,
        gate: &mut impl FnMut() -> Result<(), ServiceError>,
        verify: &mut impl FnMut(&str, &[u8]) -> Result<(), ServiceError>,
    ) -> Result<V6BackupSize, ServiceError> {
        gate()?;
        self.check_immutable_source_session(&source.session)?;
        let total = source
            .slots
            .iter()
            .map(|s| s.ciphertext_bytes as u64)
            .sum::<u64>();
        let mut header = Vec::with_capacity(HEADER_BYTES);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&(source.core.len() as u64).to_le_bytes());
        header.extend_from_slice(&(source.slots.len() as u32).to_le_bytes());
        header.extend_from_slice(&0_u32.to_le_bytes());
        header.extend_from_slice(&total.to_le_bytes());
        let mut hash = Sha256::new();
        hash.update(PACK_AAD);
        for bytes in [header.as_slice(), source.core.as_slice()] {
            write_checked(writer, bytes, &mut || {
                gate()?;
                self.check_immutable_source_session(&source.session)
            })?;
            hash.update(bytes);
        }
        for slot in &source.slots {
            gate()?;
            self.check_immutable_source_session(&source.session)?;
            let pin = self.pin_immutable_object_before_read(
                &source.session,
                slot.locator,
                slot.ciphertext_bytes,
                gate,
            )?;
            let ciphertext = pin
                .read_ciphertext_checked(&mut || {
                    gate()?;
                    self.check_immutable_source_session(&source.session)
                })
                .map_err(|e| match e {
                    PinReadError::Backend(e) => map_backend_error(e),
                    PinReadError::Gate(e) => e,
                })?;
            gate()?;
            let plaintext = Zeroizing::new(
                self.barrier
                    .open(&slot.aad(), ciphertext.as_slice())
                    .map_err(|_| ServiceError::BarrierFailure)?,
            );
            gate()?;
            self.check_immutable_source_session(&source.session)?;
            if plaintext.len() != slot.plaintext_bytes {
                return Err(ServiceError::CorruptState);
            }
            verify(&slot.resource, &plaintext)?;
            gate()?;
            self.check_immutable_source_session(&source.session)?;
            let length = (ciphertext.len() as u32).to_le_bytes();
            for bytes in [length.as_slice(), ciphertext.as_slice()] {
                write_checked(writer, bytes, &mut || {
                    gate()?;
                    self.check_immutable_source_session(&source.session)
                })?;
                hash.update(bytes);
            }
        }
        gate()?;
        self.check_immutable_source_session(&source.session)?;
        let digest = hash.finalize();
        let footer = self
            .barrier
            .seal(PACK_AAD, &digest)
            .map_err(|_| ServiceError::BarrierFailure)?;
        if footer.is_empty() || footer.len() > MAX_FOOTER {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        gate()?;
        self.check_immutable_source_session(&source.session)?;
        write_checked(writer, &(footer.len() as u32).to_le_bytes(), &mut || {
            gate()?;
            self.check_immutable_source_session(&source.session)
        })?;
        write_checked(writer, &footer, &mut || {
            gate()?;
            self.check_immutable_source_session(&source.session)
        })?;
        gate()?;
        self.check_immutable_source_session(&source.session)?;
        Ok(V6BackupSize {
            generation: source.session.generation(),
            object_count: source.slots.len(),
            ciphertext_bytes: total,
            archive_bytes: HEADER_BYTES as u64
                + source.core.len() as u64
                + total
                + source.slots.len() as u64 * 4
                + 4
                + footer.len() as u64,
        })
    }

    /// Authenticate a whole bounded pack BEFORE any target object is staged.
    /// `verify` sees borrowed authenticated bytes plus the incoming state and
    /// must enforce the application's original graph/address-key contract.
    /// Missing, duplicate, reordered, foreign, damaged and trailing records fail.
    pub fn prepare_v6_restore_from_reader<R: Read + Seek>(
        &self,
        mut reader: R,
        length: u64,
        gate: &mut impl FnMut() -> Result<(), ServiceError>,
        verify: &mut impl FnMut(&PreparedRestore, &str, &[u8]) -> Result<(), ServiceError>,
    ) -> Result<PreparedV6Restore<R>, ServiceError> {
        gate()?;
        if length < HEADER_BYTES as u64 + 60
            || length
                > MAX_BACKUP_BYTES as u64
                    + MAX_OBJECT_BYTES
                    + (MAX_OBJECTS as u64) * 4
                    + MAX_FOOTER as u64
                    + 36
        {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        self.backend.verify().map_err(map_backend_error)?;
        if self.unresolved {
            return Err(ServiceError::RecoveryRequired);
        }
        if seek_checked(&mut reader, SeekFrom::End(0), gate)? != length {
            return Err(ServiceError::CorruptState);
        }
        seek_checked(&mut reader, SeekFrom::Start(0), gate)?;
        let mut header = [0; HEADER_BYTES];
        read_exact_checked(&mut reader, &mut header, gate)?;
        if &header[..8] != MAGIC || header[20..24] != [0; 4] {
            return Err(ServiceError::CorruptState);
        }
        let core_len = u64::from_le_bytes(
            header[8..16]
                .try_into()
                .map_err(|_| ServiceError::CorruptState)?,
        );
        let count = u32::from_le_bytes(
            header[16..20]
                .try_into()
                .map_err(|_| ServiceError::CorruptState)?,
        ) as usize;
        let total = u64::from_le_bytes(
            header[24..32]
                .try_into()
                .map_err(|_| ServiceError::CorruptState)?,
        );
        if !(60..=MAX_BACKUP_BYTES as u64).contains(&core_len)
            || count == 0
            || count > MAX_OBJECTS
            || total > MAX_OBJECT_BYTES
            || (HEADER_BYTES as u64 + core_len + count as u64 * 4 + total + 5) > length
        {
            return Err(ServiceError::CorruptState);
        }
        let mut core = Zeroizing::new(vec![0; core_len as usize]);
        read_exact_checked(&mut reader, &mut core, gate)?;
        let state = self.prepare_core_restore(&core)?;
        gate()?;
        self.verify_prepared_restore(&state)?;
        if state.get("system", "state")?.is_none() {
            return Err(ServiceError::CorruptState);
        }
        let mut entries = Vec::new();
        state.inspect(|n, r, v| {
            if registered_slot(n, r, v) {
                entries.push((n.to_owned(), r.to_owned(), Secret(v.to_vec())));
            }
        });
        let slots = collect_slots(
            entries
                .iter()
                .map(|(n, r, v)| (n.as_str(), r.as_str(), v.expose())),
        )?;
        if slots.len() != count
            || slots.iter().map(|x| x.ciphertext_bytes as u64).sum::<u64>() != total
        {
            return Err(ServiceError::CorruptState);
        }
        let mut hash = Sha256::new();
        hash.update(PACK_AAD);
        hash.update(header);
        hash.update(&*core);
        let mut members = Vec::with_capacity(count);
        for slot in slots {
            gate()?;
            self.verify_prepared_restore(&state)?;
            let mut encoded = [0; 4];
            read_exact_checked(&mut reader, &mut encoded, gate)?;
            hash.update(encoded);
            if u32::from_le_bytes(encoded) as usize != slot.ciphertext_bytes {
                return Err(ServiceError::CorruptState);
            }
            let offset = seek_checked(&mut reader, SeekFrom::Current(0), gate)?;
            if offset
                .checked_add(slot.ciphertext_bytes as u64)
                .is_none_or(|end| end > length)
            {
                return Err(ServiceError::CorruptState);
            }
            let mut ciphertext = Zeroizing::new(vec![0; slot.ciphertext_bytes]);
            read_exact_checked(&mut reader, &mut ciphertext, gate)?;
            hash.update(&*ciphertext);
            let plaintext = Zeroizing::new(
                self.barrier
                    .open(&slot.aad(), &ciphertext)
                    .map_err(|_| ServiceError::BarrierFailure)?,
            );
            gate()?;
            self.verify_prepared_restore(&state)?;
            if plaintext.len() != slot.plaintext_bytes {
                return Err(ServiceError::CorruptState);
            }
            verify(&state, &slot.resource, &plaintext)?;
            gate()?;
            self.verify_prepared_restore(&state)?;
            members.push(Member {
                slot,
                offset,
                digest: Sha256::digest(&*ciphertext).into(),
            });
        }
        let mut encoded = [0; 4];
        read_exact_checked(&mut reader, &mut encoded, gate)?;
        let footer_len = u32::from_le_bytes(encoded) as usize;
        if footer_len == 0
            || footer_len > MAX_FOOTER
            || seek_checked(&mut reader, SeekFrom::Current(0), gate)?.checked_add(footer_len as u64)
                != Some(length)
        {
            return Err(ServiceError::CorruptState);
        }
        let mut footer = vec![0; footer_len];
        read_exact_checked(&mut reader, &mut footer, gate)?;
        let digest = Zeroizing::new(
            self.barrier
                .open(PACK_AAD, &footer)
                .map_err(|_| ServiceError::BarrierFailure)?,
        );
        gate()?;
        if !constant_time_eq(&hash.finalize(), &digest) {
            return Err(ServiceError::CorruptState);
        }
        let mut extra = [0; 1];
        gate()?;
        let eof = reader.read(&mut extra)?;
        gate()?;
        if eof != 0 {
            return Err(ServiceError::CorruptState);
        }
        self.verify_prepared_restore(&state)?;
        let size = V6BackupSize {
            generation: state.metadata().generation,
            object_count: count,
            ciphertext_bytes: total,
            archive_bytes: length,
        };
        Ok(PreparedV6Restore {
            state,
            reader,
            members,
            size,
        })
    }

    /// Reopen one registered object from the already authenticated archive for
    /// application graph validation. Never consult the target filesystem or a
    /// caller-supplied fallback; retain the same prepared target and input hash.
    pub fn read_v6_restore_object<R: Read + Seek>(
        &self,
        prepared: &mut PreparedV6Restore<R>,
        resource: &str,
        gate: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
        gate()?;
        self.verify_prepared_restore(&prepared.state)?;
        let index = prepared
            .members
            .binary_search_by(|member| member.slot.resource.as_str().cmp(resource))
            .map_err(|_| ServiceError::InvalidResource)?;
        let member = &prepared.members[index];
        seek_checked(&mut prepared.reader, SeekFrom::Start(member.offset), gate)?;
        let mut ciphertext = Zeroizing::new(vec![0; member.slot.ciphertext_bytes]);
        read_exact_checked(&mut prepared.reader, &mut ciphertext, gate)?;
        if !constant_time_eq(&Sha256::digest(&*ciphertext), &member.digest) {
            return Err(ServiceError::CorruptState);
        }
        let plaintext = Zeroizing::new(
            self.barrier
                .open(&member.slot.aad(), &ciphertext)
                .map_err(|_| ServiceError::BarrierFailure)?,
        );
        gate()?;
        self.verify_prepared_restore(&prepared.state)?;
        if plaintext.len() != member.slot.plaintext_bytes {
            return Err(ServiceError::CorruptState);
        }
        Ok(plaintext)
    }

    /// After application validation, stage already authenticated objects, then
    /// consume the existing exact-frontier restore transaction. A late failure
    /// may leave only unreferenced immutable files; it never claims root commit.
    /// This storage method is NOT HTTP completion, an audit receipt, or HA approval.
    pub fn restore_v6_prepared<R: Read + Seek>(
        &mut self,
        mut prepared: PreparedV6Restore<R>,
        allow_rollback: bool,
        gate: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<RestoreOutcome, ServiceError> {
        gate()?;
        self.verify_prepared_restore(&prepared.state)?;
        // A backend unable to publish a recoverable restore must reject before
        // staging external files, not after all object I/O has already happened.
        self.backend.restore_profile().map_err(map_backend_error)?;
        if !allow_rollback && prepared.state.metadata().generation < self.generation() {
            return Err(ServiceError::BackupRollbackRejected);
        }
        for member in &prepared.members {
            gate()?;
            self.verify_prepared_restore(&prepared.state)?;
            seek_checked(&mut prepared.reader, SeekFrom::Start(member.offset), gate)?;
            let mut ciphertext = Zeroizing::new(vec![0; member.slot.ciphertext_bytes]);
            read_exact_checked(&mut prepared.reader, &mut ciphertext, gate)?;
            if !constant_time_eq(&Sha256::digest(&*ciphertext), &member.digest) {
                return Err(ServiceError::CorruptState);
            }
            let plaintext = Zeroizing::new(
                self.barrier
                    .open(&member.slot.aad(), &ciphertext)
                    .map_err(|_| ServiceError::BarrierFailure)?,
            );
            gate()?;
            self.verify_prepared_restore(&prepared.state)?;
            if plaintext.len() != member.slot.plaintext_bytes {
                return Err(ServiceError::CorruptState);
            }
            let incoming_slot = prepared
                .state
                .get("system", &member.slot.resource)?
                .ok_or(ServiceError::CorruptState)?;
            let current_slot = self.get("system", &member.slot.resource)?;
            let already_registered = current_slot
                .as_ref()
                .is_some_and(|current| current.expose() == incoming_slot);
            let pin = if already_registered {
                // A matching committed slot avoids rewriting/fsyncing identical
                // ciphertext. It grants no read authority: the exact live pin,
                // profile, AEAD and plaintext equality checks below still run.
                // Missing or corrupt registered files are refused, not repaired.
                self.backend
                    .pin_immutable_ciphertext(member.slot.locator, member.slot.ciphertext_bytes)
                    .map_err(map_backend_error)?
            } else {
                let mut gate_error = None;
                let mut physical_gate = || match gate() {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        gate_error = Some(e);
                        Err(BackendError::Unavailable)
                    }
                };
                let staged = self.backend.stage_immutable_ciphertext_checked(
                    member.slot.locator,
                    &ciphertext,
                    &mut physical_gate,
                );
                if matches!(
                    staged,
                    Err(BackendError::OutcomeUnknown | BackendError::StaleWriter)
                ) {
                    self.unresolved = true;
                }
                if let Some(error) = gate_error {
                    return Err(error);
                }
                match staged.map_err(map_backend_error)? {
                    ImmutableBlobStage::Published(pin) | ImmutableBlobStage::AlreadyExists(pin) => {
                        pin
                    }
                }
            };
            gate()?;
            self.verify_prepared_restore(&prepared.state)?;
            let profile = self
                .backend
                .immutable_blob_profile()
                .map_err(map_backend_error)?;
            if pin.locator() != member.slot.locator
                || pin.ciphertext_len() != member.slot.ciphertext_bytes
                || !pin.matches_profile(&profile)
            {
                return Err(ServiceError::CorruptState);
            }
            let actual = pin
                .read_ciphertext_checked(&mut || {
                    gate()?;
                    self.verify_prepared_restore(&prepared.state)
                })
                .map_err(|e| match e {
                    PinReadError::Backend(e) => map_backend_error(e),
                    PinReadError::Gate(e) => e,
                })?;
            let opened = Zeroizing::new(
                self.barrier
                    .open(&member.slot.aad(), actual.as_slice())
                    .map_err(|_| ServiceError::BarrierFailure)?,
            );
            gate()?;
            self.verify_prepared_restore(&prepared.state)?;
            if opened.as_slice() != plaintext.as_slice() {
                return Err(ServiceError::RequestBindingConflict);
            }
        }
        gate()?;
        self.verify_prepared_restore(&prepared.state)?;
        self.restore_prepared(prepared.state, allow_rollback)
    }
}

#[cfg(all(test, unix))]
#[path = "v6_object_backup_tests.rs"]
mod tests;
