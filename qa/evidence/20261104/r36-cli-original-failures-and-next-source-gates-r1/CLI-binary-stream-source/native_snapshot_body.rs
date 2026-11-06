//! Bounded binary snapshot body framing, independent of application authority.
//!
//! This module verifies bytes and explicit stream termination only. Its output
//! cannot authenticate a peer, admit an Actor, authorize storage or prove that a
//! restore committed. The authenticated transport and native Service owner must
//! retain their own capabilities and original absolute deadlines.
//!
//! A caller wrapping a TLS stream must provide actual deadline-bound I/O and
//! require authenticated TLS closure. A raw socket EOF is not a substitute for
//! a successful TLS close-notify. Encoding does not certify remote receipt.

use ring::digest::{Context, SHA256};
use std::fmt;
use std::io::{self, Read, Write};
use std::time::Instant;
use zeroize::Zeroizing;

/// Maximum payload in one DATA frame; memory never scales with the archive.
pub const SNAPSHOT_BODY_CHUNK_BYTES: usize = 65_536;

/// Existing native-HA MAX_NATIVE_ARCHIVE, not an increased transport allowance.
///
/// The server must still supply its feature-specific MAX_NATIVE_ARCHIVE.
/// The value equals 2 * (130 MiB + 1 GiB + 4 * 65536 + 4132) + 64 MiB + 1 MiB.
pub const MAX_SNAPSHOT_BODY_BYTES: u64 = 2_488_803_400;

const MAGIC: &[u8; 8] = b"HBSB0001";
const DATA: u8 = 1;
const END: u8 = 2;

/// An explicit per-operation bound, clamped to the existing largest archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotBodyLimits {
    maximum_bytes: u64,
}

impl SnapshotBodyLimits {
    pub fn new(maximum_bytes: u64) -> io::Result<Self> {
        if maximum_bytes > MAX_SNAPSHOT_BODY_BYTES {
            return Err(invalid("snapshot body limit exceeds the native archive bound"));
        }
        Ok(Self { maximum_bytes })
    }

    pub fn maximum_bytes(self) -> u64 {
        self.maximum_bytes
    }

    fn maximum_frames(self) -> u64 {
        self.maximum_bytes.div_ceil(SNAPSHOT_BODY_CHUNK_BYTES as u64)
    }
}

/// The byte binding emitted by one encoder; this is not delivery authority.
#[derive(Debug, Eq, PartialEq)]
pub struct EncodedSnapshotBody {
    bytes: u64,
    frames: u32,
    sha256: [u8; 32],
}

impl EncodedSnapshotBody {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn frames(&self) -> u32 {
        self.frames
    }

    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

/// A data-only, non-cloneable result of exact END/hash/count/EOF verification.
///
/// Only this decoder constructs the value. It grants no peer, Actor, current
/// read, replay or publication capability.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedSnapshotBody {
    bytes: u64,
    frames: u32,
    sha256: [u8; 32],
}

impl VerifiedSnapshotBody {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn frames(&self) -> u32 {
        self.frames
    }

    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn within(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "snapshot body original deadline elapsed",
        ));
    }
    Ok(())
}

fn read_some(reader: &mut impl Read, output: &mut [u8], deadline: Instant) -> io::Result<usize> {
    loop {
        within(deadline)?;
        let result = reader.read(output);
        within(deadline)?;
        match result {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Ok(bytes) if bytes > output.len() => {
                return Err(invalid("snapshot body reader returned an invalid length"));
            }
            other => return other,
        }
    }
}

fn read_exact(reader: &mut impl Read, mut output: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !output.is_empty() {
        let bytes = read_some(reader, output, deadline)?;
        if bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "snapshot body ended before its explicit terminal record",
            ));
        }
        output = &mut output[bytes..];
    }
    Ok(())
}

fn write_exact(writer: &mut impl Write, mut input: &[u8], deadline: Instant) -> io::Result<()> {
    while !input.is_empty() {
        within(deadline)?;
        let result = writer.write(input);
        within(deadline)?;
        let bytes = match result {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        if bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "snapshot body writer made no progress",
            ));
        }
        if bytes > input.len() {
            return Err(invalid("snapshot body writer returned an invalid length"));
        }
        input = &input[bytes..];
    }
    Ok(())
}

fn flush(writer: &mut impl Write, deadline: Instant) -> io::Result<()> {
    loop {
        within(deadline)?;
        let result = writer.flush();
        within(deadline)?;
        match result {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

fn hash_value(context: &Context) -> [u8; 32] {
    let mut value = [0_u8; 32];
    value.copy_from_slice(context.clone().finish().as_ref());
    value
}

/// Encode exactly one body using fixed DATA frames and one END record.
///
/// The source is read once. One additional byte is allowed only as a rejecting
/// EOF probe at the exact byte limit; it is never emitted. The caller must send
/// authenticated write-side termination after this succeeds. This function
/// does not close, retry, reconnect or infer a remote application outcome.
pub fn encode_snapshot_body(
    source: &mut impl Read,
    output: &mut impl Write,
    limits: SnapshotBodyLimits,
    deadline: Instant,
) -> io::Result<EncodedSnapshotBody> {
    within(deadline)?;
    write_exact(output, MAGIC, deadline)?;
    let mut buffer = Zeroizing::new(vec![0_u8; SNAPSHOT_BODY_CHUNK_BYTES]);
    let mut hash = Context::new(&SHA256);
    let mut total = 0_u64;
    let mut frames = 0_u32;
    loop {
        let mut filled = 0_usize;
        let mut eof = false;
        while filled < buffer.len() {
            let consumed = total
                .checked_add(filled as u64)
                .ok_or_else(|| invalid("snapshot body byte count overflow"))?;
            let remaining = limits
                .maximum_bytes
                .checked_sub(consumed)
                .ok_or_else(|| invalid("snapshot body exceeds its byte limit"))?;
            if remaining == 0 {
                let mut tail = [0_u8; 1];
                if read_some(source, &mut tail, deadline)? != 0 {
                    return Err(invalid("snapshot body exceeds its byte limit"));
                }
                eof = true;
                break;
            }
            let available = remaining.min((buffer.len() - filled) as u64) as usize;
            let bytes = read_some(source, &mut buffer[filled..filled + available], deadline)?;
            if bytes == 0 {
                eof = true;
                break;
            }
            filled += bytes;
        }
        if filled != 0 {
            if u64::from(frames) >= limits.maximum_frames() {
                return Err(invalid("snapshot body has too many frames"));
            }
            let mut header = [0_u8; 9];
            header[0] = DATA;
            header[1..5].copy_from_slice(&frames.to_be_bytes());
            header[5..9].copy_from_slice(&(filled as u32).to_be_bytes());
            write_exact(output, &header, deadline)?;
            write_exact(output, &buffer[..filled], deadline)?;
            hash.update(&buffer[..filled]);
            total = total
                .checked_add(filled as u64)
                .ok_or_else(|| invalid("snapshot body byte count overflow"))?;
            frames = frames
                .checked_add(1)
                .ok_or_else(|| invalid("snapshot body frame count overflow"))?;
        }
        if eof {
            break;
        }
    }
    let sha256 = hash_value(&hash);
    let mut terminal = [0_u8; 45];
    terminal[0] = END;
    terminal[1..5].copy_from_slice(&frames.to_be_bytes());
    terminal[5..13].copy_from_slice(&total.to_be_bytes());
    terminal[13..45].copy_from_slice(&sha256);
    write_exact(output, &terminal, deadline)?;
    flush(output, deadline)?;
    within(deadline)?;
    Ok(EncodedSnapshotBody {
        bytes: total,
        frames,
        sha256,
    })
}

/// A one-body reader that returns EOF only after END and underlying EOF agree.
///
/// The wrapper must be built only after the separate peer/prelude checks. The
/// underlying reader must enforce the same absolute I/O deadline and, for TLS,
/// distinguish authenticated close-notify from unexpected transport EOF.
pub struct SnapshotBodyReader<R: Read> {
    input: R,
    limits: SnapshotBodyLimits,
    deadline: Instant,
    buffer: Zeroizing<Vec<u8>>,
    cursor: usize,
    available: usize,
    total: u64,
    frames: u32,
    short_frame: bool,
    failed: bool,
    hash: Context,
    verified: Option<VerifiedSnapshotBody>,
}

impl<R: Read> fmt::Debug for SnapshotBodyReader<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotBodyReader")
            .field("maximum_bytes", &self.limits.maximum_bytes)
            .field("bytes", &self.total)
            .field("frames", &self.frames)
            .field("failed", &self.failed)
            .field("verified_end", &self.verified.is_some())
            .finish_non_exhaustive()
    }
}

impl<R: Read> SnapshotBodyReader<R> {
    pub fn new(
        mut input: R,
        limits: SnapshotBodyLimits,
        deadline: Instant,
    ) -> io::Result<Self> {
        within(deadline)?;
        let mut magic = [0_u8; 8];
        read_exact(&mut input, &mut magic, deadline)?;
        if &magic != MAGIC {
            return Err(invalid("snapshot body profile differs"));
        }
        Ok(Self {
            input,
            limits,
            deadline,
            buffer: Zeroizing::new(vec![0_u8; SNAPSHOT_BODY_CHUNK_BYTES]),
            cursor: 0,
            available: 0,
            total: 0,
            frames: 0,
            short_frame: false,
            failed: false,
            hash: Context::new(&SHA256),
            verified: None,
        })
    }

    fn next_frame(&mut self) -> io::Result<()> {
        let mut tag = [0_u8; 1];
        read_exact(&mut self.input, &mut tag, self.deadline)?;
        match tag[0] {
            DATA => {
                if self.short_frame || u64::from(self.frames) >= self.limits.maximum_frames() {
                    return Err(invalid("snapshot body DATA follows its final chunk"));
                }
                let mut fields = [0_u8; 8];
                read_exact(&mut self.input, &mut fields, self.deadline)?;
                let sequence = u32::from_be_bytes([fields[0], fields[1], fields[2], fields[3]]);
                let length = u32::from_be_bytes([fields[4], fields[5], fields[6], fields[7]]);
                if sequence != self.frames
                    || length == 0
                    || u64::from(length) > SNAPSHOT_BODY_CHUNK_BYTES as u64
                {
                    return Err(invalid("snapshot body DATA header differs"));
                }
                let next_total = self
                    .total
                    .checked_add(u64::from(length))
                    .ok_or_else(|| invalid("snapshot body byte count overflow"))?;
                if next_total > self.limits.maximum_bytes {
                    return Err(invalid("snapshot body exceeds its byte limit"));
                }
                let length = length as usize;
                read_exact(&mut self.input, &mut self.buffer[..length], self.deadline)?;
                self.hash.update(&self.buffer[..length]);
                self.total = next_total;
                self.frames = self
                    .frames
                    .checked_add(1)
                    .ok_or_else(|| invalid("snapshot body frame count overflow"))?;
                self.short_frame = length < SNAPSHOT_BODY_CHUNK_BYTES;
                self.cursor = 0;
                self.available = length;
                Ok(())
            }
            END => {
                let mut fields = [0_u8; 44];
                read_exact(&mut self.input, &mut fields, self.deadline)?;
                let frames = u32::from_be_bytes([fields[0], fields[1], fields[2], fields[3]]);
                let bytes = u64::from_be_bytes([
                    fields[4], fields[5], fields[6], fields[7],
                    fields[8], fields[9], fields[10], fields[11],
                ]);
                let sha256 = hash_value(&self.hash);
                if frames != self.frames
                    || bytes != self.total
                    || fields[12..44] != sha256
                {
                    return Err(invalid("snapshot body terminal binding differs"));
                }
                let mut tail = [0_u8; 1];
                if read_some(&mut self.input, &mut tail, self.deadline)? != 0 {
                    return Err(invalid("snapshot body has trailing wire bytes"));
                }
                within(self.deadline)?;
                self.verified = Some(VerifiedSnapshotBody {
                    bytes,
                    frames,
                    sha256,
                });
                Ok(())
            }
            _ => Err(invalid("snapshot body frame tag differs")),
        }
    }

    /// Consume the decoder only after the archive consumer has consumed all data.
    ///
    /// The one-byte read may validate the terminal record; any remaining archive
    /// byte is an error, not a request to drain or silently accept more data.
    pub fn finish(mut self) -> io::Result<VerifiedSnapshotBody> {
        within(self.deadline)?;
        let mut tail = [0_u8; 1];
        if self.read(&mut tail)? != 0 {
            return Err(invalid("snapshot archive consumer left unread body bytes"));
        }
        within(self.deadline)?;
        self.verified
            .take()
            .ok_or_else(|| invalid("snapshot body has no verified terminal record"))
    }
}

impl<R: Read> Read for SnapshotBodyReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(invalid("snapshot body reader is failed"));
        }
        let result = (|| {
            within(self.deadline)?;
            if self.cursor == self.available {
                if self.verified.is_some() {
                    return Ok(0);
                }
                self.next_frame()?;
                if self.verified.is_some() {
                    return Ok(0);
                }
            }
            let bytes = output.len().min(self.available - self.cursor);
            output[..bytes].copy_from_slice(&self.buffer[self.cursor..self.cursor + bytes]);
            self.cursor += bytes;
            within(self.deadline)?;
            Ok(bytes)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

#[cfg(test)]
#[path = "native_snapshot_body_tests.rs"]
mod tests;
