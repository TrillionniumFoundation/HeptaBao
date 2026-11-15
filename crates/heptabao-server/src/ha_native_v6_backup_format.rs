//! Private HBV6HA01 framing. The only structured Raft input is an existing
//! NativeV6ArchiveSelection; this parser never deserializes Raft authority.
use super::*;

const MAGIC: &[u8; 8] = b"HBV6HA01";
pub(super) const HEADER_BYTES: usize = 232;
pub(super) const MAX_PROVENANCE_BYTES: usize = 96 * 1024;
const MAX_SHARED_OBJECTS: u64 = 131_072;
const MAX_SHARED_LEAF: u64 = 256 * 1024;
const MAX_MANIFEST_BYTES: u64 = 16 + 40 * MAX_SHARED_OBJECTS;
pub(super) const MAX_LOCAL_PACK_BYTES: u64 = crate::snapshot_file::MAX_V6_SNAPSHOT_STATE;
pub(super) const MAX_FOOTER_BYTES: usize = 4096;
// This archive's explicit bound composes the EXISTING per-component maxima.
// It does not enlarge HTTP/spool limits or grant permission to create a file of
// this size. A future endpoint must retain its own capacity/owner/deadline gate.
pub(super) const MAX_ARCHIVE_BYTES: u64 = HEADER_BYTES as u64
    + MAX_PROVENANCE_BYTES as u64
    + MAX_LOCAL_PACK_BYTES
    + MAX_MANIFEST_BYTES
    + MAX_SHARED_OBJECTS * MAX_SHARED_LEAF
    + 4
    + MAX_FOOTER_BYTES as u64;
const IO_CHUNK: usize = 256 * 1024;
pub(super) const ARCHIVE_AAD: &[u8] = b"HeptaBao/native-v6/ha-dual-pack-archive/v1\0";

pub(super) struct Header {
    pub(super) provenance_bytes: usize,
    pub(super) manifest_bytes: usize,
    pub(super) local: V6BackupSize,
    pub(super) shared_object_count: u64,
    pub(super) shared_ciphertext_bytes: u64,
    pub(super) seal_identity: [u8; 32],
    pub(super) provenance_sha256: [u8; 32],
    pub(super) manifest_sha256: [u8; 32],
    pub(super) local_sha256: [u8; 32],
    pub(super) shared_sha256: [u8; 32],
}
impl Header {
    pub(super) fn validate(&self) -> ArchiveResult<()> {
        validate_local_size(self.local)?;
        if self.provenance_bytes == 0
            || self.provenance_bytes > MAX_PROVENANCE_BYTES
            || !(1..=MAX_SHARED_OBJECTS).contains(&self.shared_object_count)
            || self.manifest_bytes as u64 != 16 + 40 * self.shared_object_count
            || self.shared_ciphertext_bytes < 25 * self.shared_object_count
            || self.shared_ciphertext_bytes > MAX_SHARED_LEAF * self.shared_object_count
            || self.seal_identity == [0; 32]
        {
            return Err(NativeV6ArchiveError::Invalid);
        }
        if self.body_bytes()? + 4 + MAX_FOOTER_BYTES as u64 > MAX_ARCHIVE_BYTES {
            return Err(NativeV6ArchiveError::TooLarge);
        }
        Ok(())
    }
    pub(super) fn body_bytes(&self) -> ArchiveResult<u64> {
        [
            HEADER_BYTES as u64,
            self.provenance_bytes as u64,
            self.local.archive_bytes,
            self.manifest_bytes as u64,
            self.shared_ciphertext_bytes,
        ]
        .into_iter()
        .try_fold(0u64, |sum, part| {
            sum.checked_add(part).ok_or(NativeV6ArchiveError::TooLarge)
        })
    }
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(self.provenance_bytes as u32).to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        for value in [
            self.manifest_bytes as u64,
            self.local.generation,
            self.local.object_count as u64,
            self.local.ciphertext_bytes,
            self.local.archive_bytes,
            self.shared_object_count,
            self.shared_ciphertext_bytes,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        for digest in [
            self.seal_identity,
            self.provenance_sha256,
            self.manifest_sha256,
            self.local_sha256,
            self.shared_sha256,
        ] {
            bytes.extend_from_slice(&digest);
        }
        bytes
    }
    pub(super) fn decode(bytes: &[u8; HEADER_BYTES]) -> ArchiveResult<Self> {
        if &bytes[..8] != MAGIC || bytes[12..16] != [0; 4] {
            return Err(NativeV6ArchiveError::Invalid);
        }
        fn number(bytes: &[u8]) -> ArchiveResult<u64> {
            Ok(u64::from_be_bytes(
                bytes
                    .try_into()
                    .map_err(|_| NativeV6ArchiveError::Invalid)?,
            ))
        }
        fn digest(bytes: &[u8]) -> ArchiveResult<[u8; 32]> {
            bytes.try_into().map_err(|_| NativeV6ArchiveError::Invalid)
        }
        let result = Self {
            provenance_bytes: u32::from_be_bytes(
                bytes[8..12]
                    .try_into()
                    .map_err(|_| NativeV6ArchiveError::Invalid)?,
            ) as usize,
            manifest_bytes: usize::try_from(number(&bytes[16..24])?)
                .map_err(|_| NativeV6ArchiveError::TooLarge)?,
            local: V6BackupSize {
                generation: number(&bytes[24..32])?,
                object_count: usize::try_from(number(&bytes[32..40])?)
                    .map_err(|_| NativeV6ArchiveError::TooLarge)?,
                ciphertext_bytes: number(&bytes[40..48])?,
                archive_bytes: number(&bytes[48..56])?,
            },
            shared_object_count: number(&bytes[56..64])?,
            shared_ciphertext_bytes: number(&bytes[64..72])?,
            seal_identity: digest(&bytes[72..104])?,
            provenance_sha256: digest(&bytes[104..136])?,
            manifest_sha256: digest(&bytes[136..168])?,
            local_sha256: digest(&bytes[168..200])?,
            shared_sha256: digest(&bytes[200..232])?,
        };
        result.validate()?;
        Ok(result)
    }
    pub(super) fn report(
        &self,
        archive_bytes: u64,
        archive_sha256: [u8; 32],
    ) -> NativeV6ArchiveReport {
        NativeV6ArchiveReport {
            local: self.local,
            shared_object_count: self.shared_object_count,
            shared_ciphertext_bytes: self.shared_ciphertext_bytes,
            archive_bytes,
            archive_sha256,
        }
    }
}

pub(super) fn validate_local_size(size: V6BackupSize) -> ArchiveResult<()> {
    if size.generation == 0
        || !(1..=65_536).contains(&size.object_count)
        || size.ciphertext_bytes < size.object_count as u64
        || size.ciphertext_bytes > 1024 * 1024 * 1024
        || size.archive_bytes > MAX_LOCAL_PACK_BYTES
        || size.archive_bytes < 32 + size.ciphertext_bytes + size.object_count as u64 * 4 + 5
    {
        return Err(NativeV6ArchiveError::Invalid);
    }
    Ok(())
}

pub(super) fn transcript_hasher() -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(ARCHIVE_AAD);
    hash
}
pub(super) fn shared_hasher() -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(b"HeptaBao/native-v6/ha-archive-shared-part/v1\0");
    hash
}
pub(super) fn check(
    deadline: OriginalDeadline,
    gate: &mut impl FnMut() -> ArchiveResult<()>,
) -> ArchiveResult<()> {
    deadline.check().map_err(|_| NativeV6ArchiveError::Gate)?;
    gate()?;
    deadline.check().map_err(|_| NativeV6ArchiveError::Gate)
}
pub(super) fn seek(
    reader: &mut impl Seek,
    position: SeekFrom,
    deadline: OriginalDeadline,
    gate: &mut impl FnMut() -> ArchiveResult<()>,
) -> ArchiveResult<u64> {
    check(deadline, gate)?;
    let result = reader.seek(position);
    check(deadline, gate)?;
    let observed = result?;
    if let SeekFrom::Start(expected) = position
        && observed != expected
    {
        return Err(NativeV6ArchiveError::Corrupt);
    }
    Ok(observed)
}
pub(super) fn read_exact(
    reader: &mut impl Read,
    bytes: &mut [u8],
    deadline: OriginalDeadline,
    gate: &mut impl FnMut() -> ArchiveResult<()>,
) -> ArchiveResult<()> {
    let mut done = 0;
    let mut interrupts = 0;
    while done < bytes.len() {
        check(deadline, gate)?;
        let end = bytes.len().min(done + IO_CHUNK);
        let result = reader.read(&mut bytes[done..end]);
        check(deadline, gate)?;
        match result {
            Ok(0) => return Err(NativeV6ArchiveError::Corrupt),
            Ok(n) if n <= end - done => {
                done += n;
                interrupts = 0;
            }
            Ok(_) => return Err(NativeV6ArchiveError::Corrupt),
            Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupts < 64 => {
                interrupts += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }
    check(deadline, gate)
}
pub(super) fn write(
    writer: &mut impl Write,
    bytes: &[u8],
    deadline: OriginalDeadline,
    gate: &mut impl FnMut() -> ArchiveResult<()>,
) -> ArchiveResult<()> {
    let mut done = 0;
    let mut interrupts = 0;
    while done < bytes.len() {
        check(deadline, gate)?;
        let end = bytes.len().min(done + IO_CHUNK);
        let result = writer.write(&bytes[done..end]);
        check(deadline, gate)?;
        match result {
            Ok(0) => {
                return Err(NativeV6ArchiveError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "native HA archive output stopped",
                )));
            }
            Ok(n) if n <= end - done => {
                done += n;
                interrupts = 0;
            }
            Ok(_) => return Err(NativeV6ArchiveError::Corrupt),
            Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupts < 64 => {
                interrupts += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }
    check(deadline, gate)
}
pub(super) fn require_eof(
    reader: &mut impl Read,
    deadline: OriginalDeadline,
    gate: &mut impl FnMut() -> ArchiveResult<()>,
) -> ArchiveResult<()> {
    for _ in 0..=64 {
        check(deadline, gate)?;
        let mut byte = [0];
        let result = reader.read(&mut byte);
        check(deadline, gate)?;
        match result {
            Ok(0) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(NativeV6ArchiveError::Corrupt),
        }
    }
    Err(NativeV6ArchiveError::Corrupt)
}
pub(super) fn copy_exact<R, G, V>(
    reader: &mut R,
    mut bytes: u64,
    deadline: OriginalDeadline,
    gate: &mut G,
    visit: &mut V,
) -> ArchiveResult<()>
where
    R: Read,
    G: FnMut() -> ArchiveResult<()>,
    V: FnMut(&[u8], &mut G) -> ArchiveResult<()>,
{
    let mut buffer = vec![0; IO_CHUNK];
    while bytes != 0 {
        let count = bytes.min(IO_CHUNK as u64) as usize;
        read_exact(reader, &mut buffer[..count], deadline, gate)?;
        visit(&buffer[..count], gate)?;
        check(deadline, gate)?;
        bytes -= count as u64;
    }
    check(deadline, gate)
}
pub(super) fn emit(
    writer: &mut impl Write,
    transcript: &mut Sha256,
    bytes: &[u8],
    deadline: OriginalDeadline,
    gate: &mut impl FnMut() -> ArchiveResult<()>,
) -> ArchiveResult<()> {
    write(writer, bytes, deadline, gate)?;
    transcript.update(bytes);
    Ok(())
}
pub(super) fn absorb(
    reader: &mut impl Read,
    bytes: &mut [u8],
    whole: &mut Sha256,
    transcript: &mut Sha256,
    deadline: OriginalDeadline,
    gate: &mut impl FnMut() -> ArchiveResult<()>,
) -> ArchiveResult<()> {
    read_exact(reader, bytes, deadline, gate)?;
    whole.update(&*bytes);
    transcript.update(&*bytes);
    Ok(())
}
pub(super) struct HashWriter<'a, W> {
    writer: &'a mut W,
    hash: Sha256,
    pub(super) count: u64,
    max: u64,
}
impl<'a, W> HashWriter<'a, W> {
    pub(super) fn new(writer: &'a mut W, max: u64) -> Self {
        Self {
            writer,
            hash: Sha256::new(),
            count: 0,
            max,
        }
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        self.hash.clone().finalize().into()
    }
}
impl<W: Write> Write for HashWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .count
            .checked_add(bytes.len() as u64)
            .is_none_or(|total| total > self.max)
        {
            return Err(io::Error::other(
                "native HA archive component capacity exhausted",
            ));
        }
        let written = self.writer.write(bytes)?;
        if written > bytes.len() {
            return Err(io::Error::other("invalid archive write length"));
        }
        self.hash.update(&bytes[..written]);
        self.count += written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
