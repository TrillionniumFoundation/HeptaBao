//! Inspection-only validation for OpenBao's `raft.snap` export.
//!
//! OpenBao 2.6.2 writes a gzip-compressed tar archive containing exactly
//! `meta.json`, `state.bin`, and `SHA256SUMS`, with an optional
//! `SHA256SUMS.sealed`.  This module deliberately stops at bounded format and
//! integrity inspection.  It never opens a Raft store, decrypts sealed bytes,
//! writes extracted state, or converts the archive into a HeptaBao backup.

use std::fmt;
use std::io::{self, Read, Write};

use flate2::read::MultiGzDecoder;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tar::{Archive, EntryType};

const DEFAULT_MAX_COMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const DEFAULT_MAX_UNCOMPRESSED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const DEFAULT_MAX_STATE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const DEFAULT_MAX_META_BYTES: u64 = 1024 * 1024;
const DEFAULT_MAX_SUMS_BYTES: u64 = 1024 * 1024;
const DEFAULT_MAX_SEALED_BYTES: u64 = 4 * 1024 * 1024;

/// Resource ceilings applied before any snapshot bytes are accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotInspectionLimits {
    pub max_compressed_bytes: u64,
    pub max_uncompressed_bytes: u64,
    pub max_state_bytes: u64,
    pub max_meta_bytes: u64,
    pub max_sums_bytes: u64,
    pub max_sealed_bytes: u64,
}

impl Default for SnapshotInspectionLimits {
    fn default() -> Self {
        Self {
            max_compressed_bytes: DEFAULT_MAX_COMPRESSED_BYTES,
            max_uncompressed_bytes: DEFAULT_MAX_UNCOMPRESSED_BYTES,
            max_state_bytes: DEFAULT_MAX_STATE_BYTES,
            max_meta_bytes: DEFAULT_MAX_META_BYTES,
            max_sums_bytes: DEFAULT_MAX_SUMS_BYTES,
            max_sealed_bytes: DEFAULT_MAX_SEALED_BYTES,
        }
    }
}

/// Result of validating an OpenBao Raft snapshot archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenBaoSnapshotInspection {
    /// Raft snapshot metadata version. OpenBao 2.6.2 uses version 1.
    pub metadata_version: u64,
    pub index: u64,
    pub term: u64,
    pub configuration_index: u64,
    pub configuration_servers: usize,
    pub state_size: u64,
    pub meta_sha256: String,
    pub state_sha256: String,
    /// True when the archive has a sealed checksum marker. The marker is not
    /// cryptographically verified by this inspection-only API.
    pub sealed_sums_present: bool,
    pub compressed_bytes: u64,
    pub uncompressed_bytes: u64,
}

/// A malformed, hostile, or unsupported snapshot archive.
#[derive(Debug)]
pub enum SnapshotInspectionError {
    Io(io::Error),
    InvalidArchive(String),
    InvalidMetadata(String),
    InvalidChecksums(String),
    LimitExceeded { resource: &'static str, limit: u64 },
}

impl fmt::Display for SnapshotInspectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "snapshot I/O error: {error}"),
            Self::InvalidArchive(reason) => write!(f, "invalid snapshot archive: {reason}"),
            Self::InvalidMetadata(reason) => write!(f, "invalid snapshot metadata: {reason}"),
            Self::InvalidChecksums(reason) => write!(f, "invalid snapshot checksums: {reason}"),
            Self::LimitExceeded { resource, limit } => {
                write!(f, "snapshot {resource} exceeds limit {limit} bytes")
            }
        }
    }
}

impl std::error::Error for SnapshotInspectionError {}

impl From<io::Error> for SnapshotInspectionError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Inspect a gzip-compressed OpenBao snapshot with default resource limits.
pub fn inspect_openbao_raft_snapshot<R: Read>(
    reader: R,
) -> Result<OpenBaoSnapshotInspection, SnapshotInspectionError> {
    inspect_openbao_raft_snapshot_with_limits(reader, SnapshotInspectionLimits::default())
}

/// Inspect a gzip-compressed OpenBao snapshot without restoring or converting it.
pub fn inspect_openbao_raft_snapshot_with_limits<R: Read>(
    reader: R,
    limits: SnapshotInspectionLimits,
) -> Result<OpenBaoSnapshotInspection, SnapshotInspectionError> {
    let mut compressed = CountingReader::new(reader, limits.max_compressed_bytes, "compressed");
    let mut decoder = MultiGzDecoder::new(&mut compressed);
    let (meta, state, sums, sealed, uncompressed_bytes) = {
        let mut uncompressed =
            CountingReader::new(&mut decoder, limits.max_uncompressed_bytes, "uncompressed");
        let mut archive = Archive::new(&mut uncompressed);

        let mut meta = None;
        let mut state = None;
        let mut sums = None;
        let mut sealed = None;
        let mut entries = 0usize;

        let archive_entries = archive
            .entries()
            .map_err(|error| SnapshotInspectionError::InvalidArchive(error.to_string()))?;
        for entry_result in archive_entries {
            let mut entry = entry_result
                .map_err(|error| SnapshotInspectionError::InvalidArchive(error.to_string()))?;
            entries = entries.checked_add(1).ok_or_else(|| {
                SnapshotInspectionError::InvalidArchive("entry count overflow".into())
            })?;
            if entries > 4 {
                return Err(SnapshotInspectionError::InvalidArchive(
                    "archive contains more than four entries".into(),
                ));
            }
            if entry.header().entry_type() != EntryType::Regular {
                return Err(SnapshotInspectionError::InvalidArchive(
                    "archive entries must be regular files".into(),
                ));
            }
            let path = entry.path_bytes();
            if path.as_ref() == b"meta.json" {
                if meta.is_some() {
                    return Err(SnapshotInspectionError::InvalidArchive(
                        "duplicate meta.json entry".into(),
                    ));
                }
                let size = entry.header().size()?;
                if size > limits.max_meta_bytes {
                    return Err(SnapshotInspectionError::LimitExceeded {
                        resource: "metadata",
                        limit: limits.max_meta_bytes,
                    });
                }
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                meta = Some(bytes);
            } else if path.as_ref() == b"state.bin" {
                if state.is_some() {
                    return Err(SnapshotInspectionError::InvalidArchive(
                        "duplicate state.bin entry".into(),
                    ));
                }
                let mut sink = DigestSink::new(limits.max_state_bytes, "state");
                io::copy(&mut entry, &mut sink)?;
                state = Some(sink.finish());
            } else if path.as_ref() == b"SHA256SUMS" {
                if sums.is_some() {
                    return Err(SnapshotInspectionError::InvalidArchive(
                        "duplicate SHA256SUMS entry".into(),
                    ));
                }
                let size = entry.header().size()?;
                if size > limits.max_sums_bytes {
                    return Err(SnapshotInspectionError::LimitExceeded {
                        resource: "checksum list",
                        limit: limits.max_sums_bytes,
                    });
                }
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                sums = Some(bytes);
            } else if path.as_ref() == b"SHA256SUMS.sealed" {
                if sealed.is_some() {
                    return Err(SnapshotInspectionError::InvalidArchive(
                        "duplicate SHA256SUMS.sealed entry".into(),
                    ));
                }
                let size = entry.header().size()?;
                if size > limits.max_sealed_bytes {
                    return Err(SnapshotInspectionError::LimitExceeded {
                        resource: "sealed checksum marker",
                        limit: limits.max_sealed_bytes,
                    });
                }
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                if bytes.is_empty() {
                    return Err(SnapshotInspectionError::InvalidArchive(
                        "sealed checksum marker is empty".into(),
                    ));
                }
                sealed = Some(bytes);
            } else {
                return Err(SnapshotInspectionError::InvalidArchive(format!(
                    "unexpected archive path {:?}",
                    String::from_utf8_lossy(path.as_ref())
                )));
            }
        }
        (meta, state, sums, sealed, uncompressed.consumed)
    };

    // Force the gzip reader to observe the end of the compressed stream. A
    // tar reader may stop after its two zero blocks without reading a corrupt
    // gzip trailer, so this explicit read is part of the integrity boundary.
    // `tar::Archive` stops after the first zero block, while a valid tar
    // writer emits the required second zero block. Drain that remainder and
    // accept only zero padding; arbitrary trailing bytes remain forbidden.
    let mut trailing = [0u8; 8192];
    loop {
        match decoder.read(&mut trailing) {
            Ok(0) => break,
            Ok(read) if trailing[..read].iter().all(|byte| *byte == 0) => {}
            Ok(_) => {
                return Err(SnapshotInspectionError::InvalidArchive(
                    "gzip stream has trailing non-padding bytes".into(),
                ));
            }
            Err(_) => {
                return Err(SnapshotInspectionError::InvalidArchive(
                    "gzip stream is truncated or corrupt".into(),
                ));
            }
        }
    }
    drop(decoder);
    let compressed_bytes = compressed.consumed;
    if meta.is_none() || state.is_none() || sums.is_none() {
        return Err(SnapshotInspectionError::InvalidArchive(
            "archive must contain meta.json, state.bin and SHA256SUMS".into(),
        ));
    }

    let metadata = parse_metadata(
        &meta.ok_or_else(|| SnapshotInspectionError::InvalidArchive("missing meta.json".into()))?,
    )?;
    let state_digest =
        state.ok_or_else(|| SnapshotInspectionError::InvalidArchive("missing state.bin".into()))?;
    if metadata.state_size != state_digest.bytes {
        return Err(SnapshotInspectionError::InvalidMetadata(format!(
            "meta.json Size {} does not match state.bin {}",
            metadata.state_size, state_digest.bytes
        )));
    }
    verify_checksums(
        &sums
            .ok_or_else(|| SnapshotInspectionError::InvalidArchive("missing SHA256SUMS".into()))?,
        &metadata,
        &state_digest,
    )?;

    Ok(OpenBaoSnapshotInspection {
        metadata_version: metadata.version,
        index: metadata.index,
        term: metadata.term,
        configuration_index: metadata.configuration_index,
        configuration_servers: metadata.configuration_servers,
        state_size: state_digest.bytes,
        meta_sha256: metadata.digest,
        state_sha256: state_digest.digest,
        sealed_sums_present: sealed.is_some(),
        compressed_bytes,
        uncompressed_bytes,
    })
}

#[derive(Debug)]
struct MetadataSummary {
    version: u64,
    index: u64,
    term: u64,
    configuration_index: u64,
    configuration_servers: usize,
    state_size: u64,
    digest: String,
}

fn parse_metadata(bytes: &[u8]) -> Result<MetadataSummary, SnapshotInspectionError> {
    let digest = hex_digest(bytes);
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| SnapshotInspectionError::InvalidMetadata(error.to_string()))?;
    let object = value.as_object().ok_or_else(|| {
        SnapshotInspectionError::InvalidMetadata("metadata must be an object".into())
    })?;
    const ALLOWED: &[&str] = &[
        "Version",
        "ID",
        "Index",
        "Term",
        "Peers",
        "Configuration",
        "ConfigurationIndex",
        "Size",
    ];
    if let Some(key) = object.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(SnapshotInspectionError::InvalidMetadata(format!(
            "unknown metadata field {key:?}"
        )));
    }
    let version = required_u64(object, "Version")?;
    if version != 1 {
        return Err(SnapshotInspectionError::InvalidMetadata(format!(
            "unsupported Raft metadata version {version}"
        )));
    }
    let index = required_u64(object, "Index")?;
    let term = required_u64(object, "Term")?;
    let configuration_index = required_u64(object, "ConfigurationIndex")?;
    let state_size = required_nonnegative_i64(object, "Size")?;
    if let Some(peers) = object.get("Peers")
        && !peers.is_null()
        && peers.as_str().is_none()
    {
        return Err(SnapshotInspectionError::InvalidMetadata(
            "Peers must be null or a base64 string".into(),
        ));
    }
    let configuration = object
        .get("Configuration")
        .ok_or_else(|| SnapshotInspectionError::InvalidMetadata("missing Configuration".into()))?;
    let configuration_object = configuration.as_object().ok_or_else(|| {
        SnapshotInspectionError::InvalidMetadata("Configuration must be an object".into())
    })?;
    if configuration_object.keys().any(|key| key != "Servers") {
        return Err(SnapshotInspectionError::InvalidMetadata(
            "Configuration has unknown fields".into(),
        ));
    }
    let servers = configuration_object
        .get("Servers")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SnapshotInspectionError::InvalidMetadata(
                "Configuration.Servers must be an array".into(),
            )
        })?;
    for server in servers {
        let server_object = server.as_object().ok_or_else(|| {
            SnapshotInspectionError::InvalidMetadata(
                "Configuration.Servers entries must be objects".into(),
            )
        })?;
        if server_object
            .keys()
            .any(|key| !["Suffrage", "ID", "Address"].contains(&key.as_str()))
        {
            return Err(SnapshotInspectionError::InvalidMetadata(
                "Configuration.Server has unknown fields".into(),
            ));
        }
        let suffrage = server_object
            .get("Suffrage")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                SnapshotInspectionError::InvalidMetadata(
                    "Configuration.Server.Suffrage must be an integer".into(),
                )
            })?;
        if suffrage > 2 {
            return Err(SnapshotInspectionError::InvalidMetadata(
                "Configuration.Server.Suffrage is outside the Raft enum".into(),
            ));
        }
        for field in ["ID", "Address"] {
            if server_object.get(field).and_then(Value::as_str).is_none() {
                return Err(SnapshotInspectionError::InvalidMetadata(format!(
                    "Configuration.Server.{field} must be a string"
                )));
            }
        }
    }
    Ok(MetadataSummary {
        version,
        index,
        term,
        configuration_index,
        configuration_servers: servers.len(),
        state_size,
        digest,
    })
}

fn required_u64(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<u64, SnapshotInspectionError> {
    object.get(field).and_then(Value::as_u64).ok_or_else(|| {
        SnapshotInspectionError::InvalidMetadata(format!("{field} must be an unsigned integer"))
    })
}

fn required_nonnegative_i64(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<u64, SnapshotInspectionError> {
    object
        .get(field)
        .and_then(Value::as_i64)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| {
            SnapshotInspectionError::InvalidMetadata(format!(
                "{field} must be a non-negative integer"
            ))
        })
}

fn verify_checksums(
    bytes: &[u8],
    metadata: &MetadataSummary,
    state: &DigestResult,
) -> Result<(), SnapshotInspectionError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| SnapshotInspectionError::InvalidChecksums("SHA256SUMS is not UTF-8".into()))?;
    if !text.ends_with('\n') {
        return Err(SnapshotInspectionError::InvalidChecksums(
            "SHA256SUMS must end with a newline".into(),
        ));
    }
    let mut seen = [false; 2];
    for line in text
        .split('\n')
        .take(text.split('\n').count().saturating_sub(1))
    {
        let (hex, path) = line.split_once("  ").ok_or_else(|| {
            SnapshotInspectionError::InvalidChecksums("checksum line must use two spaces".into())
        })?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(SnapshotInspectionError::InvalidChecksums(
                "checksum must be 64 lowercase hexadecimal characters".into(),
            ));
        }
        let (slot, expected) = match path {
            "meta.json" => (0, &metadata.digest),
            "state.bin" => (1, &state.digest),
            _ => {
                return Err(SnapshotInspectionError::InvalidChecksums(format!(
                    "unexpected checksum path {path:?}"
                )));
            }
        };
        if seen[slot] {
            return Err(SnapshotInspectionError::InvalidChecksums(format!(
                "duplicate checksum for {path:?}"
            )));
        }
        if hex != expected {
            return Err(SnapshotInspectionError::InvalidChecksums(format!(
                "checksum mismatch for {path:?}"
            )));
        }
        seen[slot] = true;
    }
    if !seen.into_iter().all(|value| value) {
        return Err(SnapshotInspectionError::InvalidChecksums(
            "SHA256SUMS must contain exactly meta.json and state.bin".into(),
        ));
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[derive(Debug)]
struct DigestResult {
    bytes: u64,
    digest: String,
}

struct DigestSink {
    hash: Sha256,
    bytes: u64,
    max: u64,
    resource: &'static str,
}

impl DigestSink {
    fn new(max: u64, resource: &'static str) -> Self {
        Self {
            hash: Sha256::new(),
            bytes: 0,
            max,
            resource,
        }
    }

    fn finish(self) -> DigestResult {
        let digest = self.hash.finalize();
        let mut output = String::with_capacity(64);
        for byte in digest {
            output.push_str(&format!("{byte:02x}"));
        }
        DigestResult {
            bytes: self.bytes,
            digest: output,
        }
    }
}

impl Write for DigestSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length =
            u64::try_from(bytes.len()).map_err(|_| io::Error::other("write length overflow"))?;
        let next = self
            .bytes
            .checked_add(length)
            .ok_or_else(|| io::Error::other("byte count overflow"))?;
        if next > self.max {
            return Err(io::Error::other(format!(
                "{} exceeds configured limit",
                self.resource
            )));
        }
        self.hash.update(bytes);
        self.bytes = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CountingReader<R> {
    reader: R,
    consumed: u64,
    max: u64,
    resource: &'static str,
}

impl<R> CountingReader<R> {
    fn new(reader: R, max: u64, resource: &'static str) -> Self {
        Self {
            reader,
            consumed: 0,
            max,
            resource,
        }
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.consumed >= self.max {
            return Err(io::Error::other(format!(
                "{} input limit exceeded",
                self.resource
            )));
        }
        let remaining = self.max - self.consumed;
        let length = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = self.reader.read(&mut buffer[..length])?;
        self.consumed = self
            .consumed
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("byte count overflow"))?;
        Ok(read)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Cursor;

    fn archive(state: &[u8], sums_override: Option<&str>, extra_path: Option<&str>) -> Vec<u8> {
        let metadata = format!(
            "{{\"Version\":1,\"ID\":\"snapshot-id\",\"Index\":7,\"Term\":3,\"Peers\":null,\"Configuration\":{{\"Servers\":[{{\"Suffrage\":0,\"ID\":\"node-1\",\"Address\":\"127.0.0.1:8201\"}}]}},\"ConfigurationIndex\":6,\"Size\":{}}}\n",
            state.len()
        );
        let meta_hash = hex_digest(metadata.as_bytes());
        let state_hash = hex_digest(state);
        let sums = sums_override
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{meta_hash}  meta.json\n{state_hash}  state.bin\n"));

        let mut compressed = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = tar::Builder::new(&mut compressed);
            append(&mut builder, "meta.json", metadata.as_bytes());
            append(&mut builder, "state.bin", state);
            append(&mut builder, "SHA256SUMS", sums.as_bytes());
            if let Some(path) = extra_path {
                append(&mut builder, path, b"unexpected");
            }
            builder.finish().expect("tar fixture must finish");
        }
        compressed.finish().expect("gzip fixture must finish")
    }

    fn append(builder: &mut tar::Builder<&mut GzEncoder<Vec<u8>>>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o600);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, path, Cursor::new(bytes))
            .expect("tar fixture entry must append");
    }

    #[test]
    fn inspection_accepts_real_v1_shape_and_checksums() {
        let snapshot = archive(b"state-bytes", None, None);
        let inspected =
            inspect_openbao_raft_snapshot(Cursor::new(snapshot)).expect("valid snapshot");
        assert_eq!(inspected.metadata_version, 1);
        assert_eq!(inspected.index, 7);
        assert_eq!(inspected.term, 3);
        assert_eq!(inspected.configuration_index, 6);
        assert_eq!(inspected.configuration_servers, 1);
        assert_eq!(inspected.state_size, 11);
        assert!(!inspected.sealed_sums_present);
    }

    #[test]
    fn inspection_rejects_checksum_tampering_and_unknown_paths() {
        let bad_sums = archive(
            b"state-bytes",
            Some(&format!(
                "{}  meta.json\n{}  state.bin\n",
                "0".repeat(64),
                "0".repeat(64)
            )),
            None,
        );
        assert!(matches!(
            inspect_openbao_raft_snapshot(Cursor::new(bad_sums)),
            Err(SnapshotInspectionError::InvalidChecksums(_))
        ));
        let extra = archive(b"state-bytes", None, Some("extra"));
        assert!(matches!(
            inspect_openbao_raft_snapshot(Cursor::new(extra)),
            Err(SnapshotInspectionError::InvalidArchive(_))
        ));
        let mut trailing = archive(b"state-bytes", None, None);
        trailing.push(0x42);
        assert!(matches!(
            inspect_openbao_raft_snapshot(Cursor::new(trailing)),
            Err(SnapshotInspectionError::InvalidArchive(_))
        ));
    }

    #[test]
    fn inspection_rejects_size_mismatch_and_state_limit() {
        let snapshot = archive(b"state-bytes", None, None);
        let limits = SnapshotInspectionLimits {
            max_state_bytes: 3,
            ..SnapshotInspectionLimits::default()
        };
        assert!(inspect_openbao_raft_snapshot_with_limits(Cursor::new(snapshot), limits).is_err());
    }
}
