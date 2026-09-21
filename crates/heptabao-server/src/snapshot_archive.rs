//! Native HBB2 state in a CLI-transport-compatible gzip/tar envelope.
//! This is not an OpenBao state.bin or seal-wrapper format.
use crate::snapshot_file::{MAX_NATIVE_ARCHIVE, MAX_NATIVE_STATE, SnapshotFile, SnapshotLease};
use flate2::{Compression, bufread::GzDecoder, write::GzEncoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, BufReader, Read, Write},
    sync::Arc,
    time::Instant,
};
use zeroize::Zeroizing;

pub(crate) const CHECKSUM_CONTEXT: &[u8] = b"heptabao.native-snapshot.checksums.v2";
const NAMES: [&str; 4] = ["meta.json", "state.bin", "SHA256SUMS", "SHA256SUMS.sealed"];
const MAX_SMALL: u64 = 8192;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SealIdentity {
    format: String,
    sha256: String,
}
impl SealIdentity {
    fn new(digest: &[u8; 32]) -> Self {
        Self {
            format: "heptabao-seal-metadata-digest-v1".into(),
            sha256: hex(digest),
        }
    }
    fn valid(&self) -> bool {
        self.format == "heptabao-seal-metadata-digest-v1"
            && self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
    pub(crate) fn matches(&self, digest: &[u8; 32]) -> bool {
        self.valid() && self.sha256 == hex(digest)
    }
}

// V1 is recognized to return a precise missing-binding error. It cannot
// manufacture V2 authority through a missing/default/null seal field.
#[derive(Serialize, Deserialize)]
#[serde(tag = "format", deny_unknown_fields)]
pub(crate) enum Metadata {
    #[serde(rename = "heptabao-native-snapshot-v1")]
    V1 {
        state_format: String,
        generation: u64,
        state_bytes: u64,
    },
    #[serde(rename = "heptabao-native-snapshot-v2")]
    V2 {
        state_format: String,
        generation: u64,
        state_bytes: u64,
        seal_identity: SealIdentity,
    },
}
impl Metadata {
    pub(crate) fn new(generation: u64, state_bytes: u64, seal_digest: &[u8; 32]) -> Self {
        Self::V2 {
            state_format: "heptabao-encrypted-backup-v1/HBB2".into(),
            generation,
            state_bytes,
            seal_identity: SealIdentity::new(seal_digest),
        }
    }
    pub(crate) fn generation(&self) -> u64 {
        match self {
            Self::V1 { generation, .. } | Self::V2 { generation, .. } => *generation,
        }
    }
    pub(crate) fn state_bytes(&self) -> u64 {
        match self {
            Self::V1 { state_bytes, .. } | Self::V2 { state_bytes, .. } => *state_bytes,
        }
    }
    pub(crate) fn seal_identity(&self) -> Option<&SealIdentity> {
        match self {
            Self::V1 { .. } => None,
            Self::V2 { seal_identity, .. } => Some(seal_identity),
        }
    }
    pub(crate) fn valid(&self) -> bool {
        let state_format = match self {
            Self::V1 { state_format, .. } | Self::V2 { state_format, .. } => state_format,
        };
        state_format == "heptabao-encrypted-backup-v1/HBB2"
            && (60..=MAX_NATIVE_STATE).contains(&self.state_bytes())
            && self.seal_identity().is_none_or(SealIdentity::valid)
    }
}

pub(crate) struct DownloadSource {
    pub state: SnapshotFile,
    pub metadata: Vec<u8>,
    pub sums: Vec<u8>,
    pub sealed_sums: Vec<u8>,
}
pub(crate) struct Import {
    pub state: SnapshotFile,
    pub metadata: Metadata,
    pub sums: Vec<u8>,
    pub sealed_sums: Vec<u8>,
}
fn bad() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid native snapshot archive",
    )
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn sums(metadata: &[u8], state_digest: &[u8; 32]) -> Vec<u8> {
    format!(
        "{}  meta.json\n{}  state.bin\n",
        hex(&Sha256::digest(metadata)),
        hex(state_digest)
    )
    .into_bytes()
}

pub(crate) struct HashWriter<W> {
    pub writer: W,
    pub hash: Sha256,
}
impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.writer.write(bytes)?;
        self.hash.update(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

fn header(name: &str, length: u64) -> io::Result<[u8; 512]> {
    if name.len() > 99 || length > MAX_NATIVE_STATE {
        return Err(bad());
    }
    let mut block = [0; 512];
    block[..name.len()].copy_from_slice(name.as_bytes());
    block[100..108].copy_from_slice(b"0000600\0");
    block[108..116].copy_from_slice(b"0000000\0");
    block[116..124].copy_from_slice(b"0000000\0");
    block[124..136].copy_from_slice(format!("{length:011o}\0").as_bytes());
    block[136..148].copy_from_slice(b"00000000000\0");
    block[148..156].fill(b' ');
    block[156] = b'0';
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    let checksum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
    block[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    Ok(block)
}
fn padding(length: u64) -> usize {
    ((512 - length % 512) % 512) as usize
}
fn small_entry(writer: &mut impl Write, name: &str, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() as u64 >= MAX_SMALL {
        return Err(bad());
    }
    writer.write_all(&header(name, bytes.len() as u64)?)?;
    writer.write_all(bytes)?;
    writer.write_all(&[0; 512][..padding(bytes.len() as u64)])
}

pub(crate) fn export(
    mut source: DownloadSource,
    lease: &Arc<SnapshotLease>,
    deadline: Instant,
) -> io::Result<SnapshotFile> {
    if source.sealed_sums.is_empty() {
        return Err(bad());
    }
    let archive = lease.file(MAX_NATIVE_ARCHIVE, deadline)?;
    let mut gzip = GzEncoder::new(archive, Compression::fast());
    small_entry(&mut gzip, NAMES[0], &source.metadata)?;
    source.state.rewind_checked()?;
    let length = source.state.len();
    gzip.write_all(&header(NAMES[1], length)?)?;
    copy_exact(&mut source.state, &mut gzip, length)?;
    gzip.write_all(&[0; 512][..padding(length)])?;
    small_entry(&mut gzip, NAMES[2], &source.sums)?;
    small_entry(&mut gzip, NAMES[3], &source.sealed_sums)?;
    gzip.write_all(&[0; 1024])?;
    let mut file = gzip.finish()?;
    file.rewind_checked()?;
    Ok(file)
}

fn copy_exact(reader: &mut impl Read, writer: &mut impl Write, mut length: u64) -> io::Result<()> {
    let mut buffer = Zeroizing::new([0; 64 * 1024]);
    while length > 0 {
        let count = length.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..count])?;
        writer.write_all(&buffer[..count])?;
        length -= count as u64;
    }
    Ok(())
}
fn read_header(reader: &mut impl Read, expected: &str, maximum: u64) -> io::Result<u64> {
    let mut block = [0; 512];
    reader.read_exact(&mut block)?;
    if block[135] != 0 || !block[124..135].iter().all(|b| (b'0'..=b'7').contains(b)) {
        return Err(bad());
    }
    let length = u64::from_str_radix(std::str::from_utf8(&block[124..135]).map_err(|_| bad())?, 8)
        .map_err(|_| bad())?;
    // Canonical native regular files only: no links, PAX/GNU extension headers,
    // duplicate paths, prefix traversal, device records or alternative names.
    if length > maximum || block != header(expected, length)? {
        return Err(bad());
    }
    Ok(length)
}
fn discard_padding(reader: &mut impl Read, length: u64) -> io::Result<()> {
    let mut block = [0; 512];
    let count = padding(length);
    reader.read_exact(&mut block[..count])?;
    if block[..count].iter().any(|b| *b != 0) {
        return Err(bad());
    }
    Ok(())
}
fn small(reader: &mut impl Read, name: &str) -> io::Result<Vec<u8>> {
    let length = read_header(reader, name, MAX_SMALL - 1)?;
    let mut bytes = vec![0; length as usize];
    reader.read_exact(&mut bytes)?;
    discard_padding(reader, length)?;
    Ok(bytes)
}

pub(crate) fn import(
    mut archive: SnapshotFile,
    lease: &Arc<SnapshotLease>,
    deadline: Instant,
) -> io::Result<Import> {
    archive.rewind_checked()?;
    // Native exports have no filename/comment/extra fields. Refuse optional
    // unbounded gzip header strings before handing the stream to the decoder.
    let mut gzip_header = [0; 10];
    archive.read_exact(&mut gzip_header)?;
    if gzip_header[..4] != [0x1f, 0x8b, 8, 0] {
        return Err(bad());
    }
    archive.rewind_checked()?;
    let mut gzip = GzDecoder::new(BufReader::new(archive));
    let metadata_bytes = small(&mut gzip, NAMES[0])?;
    let metadata: Metadata = serde_json::from_slice(&metadata_bytes).map_err(|_| bad())?;
    if !metadata.valid() {
        return Err(bad());
    }
    let length = read_header(&mut gzip, NAMES[1], MAX_NATIVE_STATE)?;
    if length != metadata.state_bytes() {
        return Err(bad());
    }
    let state = lease.file(MAX_NATIVE_STATE, deadline)?;
    let mut output = HashWriter {
        writer: state,
        hash: Sha256::new(),
    };
    copy_exact(&mut gzip, &mut output, length)?;
    discard_padding(&mut gzip, length)?;
    let expected_sums = sums(&metadata_bytes, &output.hash.finalize().into());
    let sums = small(&mut gzip, NAMES[2])?;
    if sums != expected_sums {
        return Err(bad());
    }
    let sealed_sums = small(&mut gzip, NAMES[3])?;
    if sealed_sums.is_empty() {
        return Err(bad());
    }
    let mut terminator = [0; 1024];
    gzip.read_exact(&mut terminator)?;
    let mut trailing = [0; 1];
    if terminator != [0; 1024] || gzip.read(&mut trailing)? != 0 {
        return Err(bad());
    }
    // GzDecoder reads exactly one gzip member; reject appended members/data.
    if gzip.into_inner().read(&mut trailing)? != 0 {
        return Err(bad());
    }
    let mut state = output.writer;
    state.rewind_checked()?;
    let mut magic = [0; 4];
    state.read_exact(&mut magic)?;
    if &magic != b"HBB2" {
        return Err(bad());
    }
    state.rewind_checked()?;
    Ok(Import {
        state,
        metadata,
        sums,
        sealed_sums,
    })
}

#[cfg(test)]
#[path = "snapshot_archive_tests.rs"]
mod tests;
