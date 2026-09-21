//! Binary snapshot transport only. Other routes retain bounded JSON framing.
use super::*;
use crate::service::{NativeSnapshotAdmission, TrustedSnapshotOrigin};
use crate::snapshot_file::{MAX_NATIVE_ARCHIVE, SnapshotFile};

// Constructed only after the ordinary HTTP target/query checks. It retains
// raw escaping and ordering without allowing request bytes into an authority.
pub(super) struct NativeTarget(Zeroizing<String>);
impl NativeTarget {
    pub(super) fn checked(target: &str) -> Result<Self, ParseError> {
        if target.len() > 8192
            || !target.bytes().all(|byte| (33..=126).contains(&byte))
            || target.contains('#')
            || !matches!(
                target.split('?').next(),
                Some("/v1/sys/storage/raft/snapshot" | "/v1/sys/storage/raft/snapshot-force")
            )
        {
            return Err(bad("invalid native snapshot target"));
        }
        Ok(Self(Zeroizing::new(target.to_owned())))
    }
}

pub(super) struct NativeRequest {
    pub body: NativeBody,
    pub target: NativeTarget,
}

pub(super) enum NativeReply {
    Json(Response),
    File(SnapshotFile),
    Redirect {
        origin: TrustedSnapshotOrigin,
        target: NativeTarget,
    },
}
impl NativeReply {
    pub(super) fn write(self, writer: &mut impl Write, head: bool) -> io::Result<()> {
        match self {
            Self::Json(response) => write_response(writer, response, head),
            Self::File(file) => write_file_response(writer, file, head),
            Self::Redirect { origin, target } => {
                write!(
                    writer,
                    "HTTP/1.1 307 Temporary Redirect\r\nLocation: {}{}\r\nContent-Length: 0\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n",
                    origin.as_str(),
                    target.0.as_str(),
                )?;
                writer.flush()
            }
        }
    }
}

pub(super) enum Framing {
    Download,
    Length(u64),
    Chunked,
}
pub(super) struct NativeBody {
    pub framing: Framing,
    pub prefix: Zeroizing<Vec<u8>>,
}

struct BodyReader<'a, R> {
    source: &'a mut R,
    prefix: Zeroizing<Vec<u8>>,
    offset: usize,
    remaining: u64,
    chunked: bool,
    chunks: usize,
    total: u64,
    delimiter: bool,
    finished: bool,
    deadline: Instant,
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid snapshot body framing")
}
impl<'a, R: Read> BodyReader<'a, R> {
    fn new(source: &'a mut R, body: NativeBody, deadline: Instant) -> io::Result<Self> {
        let (remaining, chunked, finished) = match body.framing {
            Framing::Download => (0, false, true),
            Framing::Length(length)
                if length <= MAX_NATIVE_ARCHIVE && body.prefix.len() as u64 <= length =>
            {
                (length, false, length == 0)
            }
            Framing::Length(_) => return Err(invalid()),
            Framing::Chunked => (0, true, false),
        };
        Ok(Self {
            source,
            prefix: body.prefix,
            offset: 0,
            remaining,
            chunked,
            chunks: 0,
            total: 0,
            delimiter: false,
            finished,
            deadline,
        })
    }
    fn raw(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "snapshot body deadline exceeded",
            ));
        }
        if self.offset < self.prefix.len() {
            let count = bytes.len().min(self.prefix.len() - self.offset);
            bytes[..count].copy_from_slice(&self.prefix[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        } else {
            self.source.read(bytes)
        }
    }
    fn exact(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            let count = self.raw(&mut bytes[offset..])?;
            if count == 0 {
                return Err(invalid());
            }
            offset += count;
        }
        Ok(())
    }
    fn next_chunk(&mut self) -> io::Result<()> {
        if self.delimiter {
            let mut crlf = [0; 2];
            self.exact(&mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(invalid());
            }
        }
        let mut line = Vec::with_capacity(18);
        loop {
            let mut byte = [0];
            self.exact(&mut byte)?;
            if byte[0] == b'\r' {
                self.exact(&mut byte)?;
                if byte[0] != b'\n' {
                    return Err(invalid());
                }
                break;
            }
            if line.len() == 16 || !byte[0].is_ascii_hexdigit() {
                return Err(invalid());
            }
            line.push(byte[0]);
        }
        if line.is_empty() {
            return Err(invalid());
        }
        let length = u64::from_str_radix(std::str::from_utf8(&line).map_err(|_| invalid())?, 16)
            .map_err(|_| invalid())?;
        self.chunks += 1;
        if self.chunks > 16_384
            || self
                .total
                .checked_add(length)
                .is_none_or(|value| value > MAX_NATIVE_ARCHIVE)
        {
            return Err(invalid());
        }
        self.total += length;
        self.remaining = length;
        self.delimiter = true;
        if length == 0 {
            let mut trailers = [0; 2];
            self.exact(&mut trailers)?;
            // No trailers/extensions/second messages. The sole allowlisted
            // streamed route cannot smuggle headers into general JSON routing.
            if trailers != *b"\r\n" || self.offset != self.prefix.len() {
                return Err(invalid());
            }
            self.finished = true;
        }
        Ok(())
    }
}
impl<R: Read> Read for BodyReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.finished {
            return Ok(0);
        }
        if self.chunked && self.remaining == 0 {
            self.next_chunk()?;
        }
        if self.finished {
            return Ok(0);
        }
        if self.remaining == 0 {
            self.finished = true;
            return Ok(0);
        }
        let wanted = bytes.len().min(self.remaining as usize);
        let count = self.raw(&mut bytes[..wanted])?;
        if count == 0 {
            return Err(invalid());
        }
        self.remaining -= count as u64;
        Ok(count)
    }
}

pub(super) fn execute(
    service: &Arc<Mutex<Service>>,
    request: ServiceRequest<'_>,
    native: NativeRequest,
    reader: &mut impl Read,
    deadline: Instant,
) -> NativeReply {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let execution = match lock_until(service, deadline) {
        Ok(mut writer) => writer.begin_native_snapshot_before(request, deadline),
        Err(_) => return NativeReply::Json(Response::error(503, "snapshot admission unavailable")),
    };
    let execution = match execution {
        NativeSnapshotAdmission::Execute(execution) => execution,
        NativeSnapshotAdmission::Redirect(origin) => {
            // Do not read/replay the upload, allocate a spool or transport any
            // archive in the ordinary bounded HA forwarding frame.
            return NativeReply::Redirect {
                origin,
                target: native.target,
            };
        }
    };
    let mut pending = match execution {
        RequestExecution::Complete(response) => {
            return rejected_upload_response(reader, native.body, deadline, response);
        }
        RequestExecution::External(pending) => pending,
    };
    let (observation, file) = match BodyReader::new(reader, native.body, deadline) {
        Ok(mut reader) => pending.execute_snapshot_transfer(&mut reader),
        Err(_) => (
            crate::service::ExternalEffectResult::SnapshotTransfer(Err(Response::error(
                400,
                "invalid snapshot body framing",
            ))),
            None,
        ),
    };
    // No network/body I/O occurs under the service writer. The final request
    // audit must succeed before this file capability can reach the socket.
    let response = match lock_until(service, deadline) {
        Ok(mut writer) => writer.finish_external_request(*pending, observation),
        Err(_) => return NativeReply::Json(Response::error(503, "snapshot finalize unavailable")),
    };
    if response.status == 200
        && let Some(file) = file
    {
        NativeReply::File(file)
    } else {
        NativeReply::Json(response)
    }
}

fn rejected_upload_response(
    reader: &mut impl Read,
    body: NativeBody,
    deadline: Instant,
    response: Response,
) -> NativeReply {
    // Admission has already refused the request and released the writer. Drain
    // only its bounded framing, without a spool, archive parsing or another
    // Service call. Closing a TCP connection with unread upload bytes can reset
    // the response while clients are still sending, hiding the actual refusal.
    // Both the decoder and DeadlineStream retain the original request deadline;
    // malformed, incomplete or slow uploads never acquire a new I/O budget.
    if !matches!(body.framing, Framing::Download)
        && let Ok(mut body) = BodyReader::new(reader, body, deadline)
    {
        let mut buffer = Zeroizing::new([0; 8192]);
        while let Ok(count) = body.read(&mut *buffer) {
            if count == 0 {
                break;
            }
        }
    }
    NativeReply::Json(response)
}

pub(super) fn write_file_response(
    writer: &mut impl Write,
    mut file: SnapshotFile,
    head: bool,
) -> io::Result<()> {
    write!(
        writer,
        "HTTP/1.1 200 OK\r\nContent-Type: application/gzip\r\nContent-Disposition: attachment; filename=\"heptabao-native.snap\"\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        file.len()
    )?;
    if !head {
        let mut buffer = Zeroizing::new([0; 64 * 1024]);
        loop {
            let count = file.read(&mut *buffer)?;
            if count == 0 {
                break;
            }
            writer.write_all(&buffer[..count])?;
        }
    }
    writer.flush()
}

#[cfg(test)]
#[path = "http_snapshot_redirect_tests.rs"]
mod redirect_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejected_uploads_drain_framing_without_changing_the_refusal_or_deadline() -> io::Result<()> {
        for (framing, prefix, remaining) in [
            (Framing::Length(3), b"a".as_slice(), b"bc".as_slice()),
            (
                Framing::Chunked,
                b"3\r\na".as_slice(),
                b"bc\r\n0\r\n\r\n".as_slice(),
            ),
        ] {
            let mut source = remaining;
            let reply = rejected_upload_response(
                &mut source,
                NativeBody {
                    framing,
                    prefix: Zeroizing::new(prefix.to_vec()),
                },
                Instant::now() + Duration::from_secs(1),
                Response::error(403, "permission denied"),
            );
            assert!(source.is_empty());
            let mut wire = Vec::new();
            reply.write(&mut wire, false)?;
            assert!(wire.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
            assert!(wire.ends_with(br#"{"errors":["permission denied"]}"#));
        }
        struct Unread(usize);
        impl Read for Unread {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                self.0 += 1;
                Err(io::Error::other("unexpected socket read"))
            }
        }
        for (framing, deadline) in [
            (Framing::Download, Instant::now() + Duration::from_secs(1)),
            (
                Framing::Length(1),
                Instant::now() - Duration::from_millis(1),
            ),
        ] {
            let mut source = Unread(0);
            let reply = rejected_upload_response(
                &mut source,
                NativeBody {
                    framing,
                    prefix: Zeroizing::new(Vec::new()),
                },
                deadline,
                Response::error(403, "permission denied"),
            );
            assert_eq!(source.0, 0);
            assert!(matches!(reply, NativeReply::Json(ref response) if response.status == 403));
        }
        Ok(())
    }

    #[test]
    fn native_chunked_decoder_accepts_split_chunks_and_rejects_ambiguous_or_unbounded_framing()
    -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut source = b"bc\r\n2\r\nde\r\n0\r\n\r\n".as_slice();
        let mut reader = BodyReader::new(
            &mut source,
            NativeBody {
                framing: Framing::Chunked,
                prefix: Zeroizing::new(b"3\r\na".to_vec()),
            },
            deadline,
        )?;
        let mut output = Vec::new();
        reader.read_to_end(&mut output)?;
        assert_eq!(output, b"abcde");
        for bad_body in [
            b"1;foo=bar\r\na\r\n0\r\n\r\n".as_slice(),
            b"1\na\n0\n\n",
            b"+1\r\na\r\n0\r\n\r\n",
            b"1\r\naX\n0\r\n\r\n",
            b"0\r\nX-Test: x\r\n\r\n",
            b"0\r\n\r\nGET /v1/sys/health HTTP/1.1\r\n\r\n",
            b"ffffffffffffffff\r\n",
            b"1\r\n",
        ] {
            let mut empty = io::empty();
            let mut reader = BodyReader::new(
                &mut empty,
                NativeBody {
                    framing: Framing::Chunked,
                    prefix: Zeroizing::new(bad_body.to_vec()),
                },
                deadline,
            )?;
            assert!(reader.read_to_end(&mut Vec::new()).is_err());
        }
        Ok(())
    }
    #[test]
    fn binary_route_only_supports_chunking_and_explicit_json_accept_preserves_old_download() {
        for text in [
            "POST /v1/secret/data/key HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "POST /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "POST /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ] {
            assert!(read_request_mode(&mut text.as_bytes(), Duration::from_secs(1), true).is_err());
        }
        let raw = "GET /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: local\r\n\r\n";
        assert!(
            read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true)
                .is_ok_and(|r| r.native_snapshot.is_some())
        );
        let json = "GET /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: local\r\nAccept: application/json\r\n\r\n";
        assert!(
            read_request_mode(&mut json.as_bytes(), Duration::from_secs(1), true)
                .is_ok_and(|r| r.native_snapshot.is_none())
        );
    }
    #[test]
    fn native_header_admission_does_not_read_entire_body_before_authorization() {
        let raw = "POST /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: local\r\nContent-Length: 25000000\r\n\r\n";
        assert!(
            read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true)
                .is_ok_and(|r| r.native_snapshot.is_some())
        );
        let json = "POST /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: 25000000\r\n\r\n";
        assert!(read_request_mode(&mut json.as_bytes(), Duration::from_secs(1), true).is_err());
    }
}
