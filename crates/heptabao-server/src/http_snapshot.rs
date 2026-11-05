//! Binary snapshot transport. The deferred native-body carrier is also used by
//! the separately admitted native-large KV2 lane; ordinary JSON is unchanged.
use super::*;
use crate::service::{NativeSnapshotAdmission, TrustedSnapshotOrigin};
use crate::snapshot_file::{MAX_NATIVE_ARCHIVE, SnapshotFile};

// Constructed only after the ordinary HTTP target/query checks. It retains
// raw escaping and ordering without allowing request bytes into an authority.
pub(super) struct NativeTarget(Zeroizing<String>);
impl NativeTarget {
    pub(super) fn checked(target: &str) -> Result<Self, ParseError> {
        let path = target.split('?').next();
        let accepted = matches!(
            path,
            Some(
                "/v1/sys/storage/raft/snapshot"
                    | "/v1/sys/storage/raft/snapshot-force"
                    | "/v1/sys/storage/raft/snapshot-repair"
            )
        );
        #[cfg(feature = "native-v6-storage")]
        let accepted = accepted
            || matches!(
                path,
                Some(
                    "/v1/sys/migration/openbao/kv2/native-large"
                        | "/v1/sys/migration/openbao/kv2/export"
                )
            );
        if target.len() > 8192
            || !target.bytes().all(|byte| (33..=126).contains(&byte))
            || target.contains('#')
            || !accepted
        {
            return Err(bad("invalid native snapshot target"));
        }
        Ok(Self(Zeroizing::new(target.to_owned())))
    }
}

// Keep native route admission closed. Ordinary origin-relative targets have
// their own HTTP parser/binding and can select only the same redirect writer.
pub(super) enum RedirectTarget {
    Native(NativeTarget),
    Ordinary(crate::request_metadata::CheckedLocalRedirectTarget),
}
impl RedirectTarget {
    fn as_str(&self) -> &str {
        match self {
            Self::Native(target) => target.0.as_str(),
            Self::Ordinary(target) => target.as_str(),
        }
    }
}

pub(super) struct NativeRequest {
    pub body: NativeBody,
    pub target: NativeTarget,
}

pub(super) enum NativeReply {
    Json(Response),
    Ui(super::ui::Reply),
    HttpBadRequest,
    File(SnapshotFile),
    #[cfg(feature = "native-v6-storage")]
    LosslessFile(SnapshotFile),
    Redirect {
        origin: TrustedSnapshotOrigin,
        target: RedirectTarget,
        headers: crate::service::ResponseHeaders,
    },
}
impl NativeReply {
    #[cfg(test)]
    pub(super) fn write(self, writer: &mut impl Write, head: bool) -> io::Result<()> {
        self.write_with_namespace(writer, head, "")
    }

    pub(super) fn write_with_namespace(
        self,
        writer: &mut impl Write,
        head: bool,
        namespace: &str,
    ) -> io::Result<()> {
        match self {
            // This transport failure has a body even for HEAD, as in Go's HTTP reader.
            Self::HttpBadRequest => {
                writer.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request")?;
                writer.flush()
            }
            Self::Json(response) => {
                write_response_with_namespace(writer, response, head, namespace)
            }
            Self::Ui(reply) => reply.write(writer, head),
            Self::File(file) => write_file_response(writer, file, head, namespace),
            #[cfg(feature = "native-v6-storage")]
            Self::LosslessFile(file) => write_lossless_file_response(writer, file, head, namespace),
            Self::Redirect {
                origin,
                target,
                headers,
            } => {
                // An unread upload can still be in another TLS record. Build
                // the complete head before the first transport write, instead
                // of emitting the status/Location prefix as its own record.
                // The fixed allowance covers the standard/date/timing headers;
                // existing variable fields keep their original input bounds.
                let capacity = origin
                    .as_str()
                    .len()
                    .checked_add(target.as_str().len())
                    .and_then(|size| size.checked_add(namespace.len()))
                    .and_then(|size| size.checked_add(512))
                    // Local routing may retain at most four original numeric
                    // quota fields, each with a value of at most twenty digits.
                    .and_then(|size| size.checked_add(if headers.is_empty() { 0 } else { 512 }))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "redirect header length overflow",
                        )
                    })?;
                let mut buffer = Zeroizing::new(vec![0; capacity]);
                let used = {
                    // Cursor over a fixed slice cannot grow the allocation.
                    let mut header = io::Cursor::new(buffer.as_mut_slice());
                    write!(
                        header,
                        "HTTP/1.1 307 Temporary Redirect\r\nLocation: {}{}\r\nContent-Length: 0\r\n",
                        origin.as_str(),
                        target.as_str(),
                    )?;
                    headers.write(&mut header)?;
                    write_standard_headers(&mut header, namespace)?;
                    header.write_all(b"\r\n")?;
                    header.position() as usize
                };
                writer.write_all(&buffer[..used])?;
                writer.flush()
            }
        }
    }
}

pub(super) fn project_local_redirect(reply: NativeReply) -> NativeReply {
    let NativeReply::Json(mut response) = reply else {
        return reply;
    };
    let Some(capsule) = response.response_headers.take_local_redirect() else {
        return NativeReply::Json(response);
    };
    // A terminal audit/projection failure remains its original error; neither
    // a status code nor ordinary SDK Location fields can create this capsule.
    if response.status != 307 {
        return NativeReply::Json(response);
    }
    if !capsule.matches_current() {
        return NativeReply::Json(Response::error(
            503,
            "local redirect completion binding or deadline changed",
        ));
    }
    let headers =
        match std::mem::take(&mut response.response_headers).into_local_redirect_metadata() {
            Ok(headers) => headers,
            Err(()) => {
                return NativeReply::Json(Response::error(503, "local redirect metadata changed"));
            }
        };
    let (origin, target) = capsule.into_parts();
    NativeReply::Redirect {
        origin,
        target: RedirectTarget::Ordinary(target),
        headers,
    }
}

pub(super) fn finish_redirect_connection(
    stream: &mut StreamOwned<rustls::ServerConnection, DeadlineStream>,
) {
    // The actual redirect is already written. This close helper never parses
    // or forwards an upload. An immediate close with unread TCP bytes can
    // reset the peer and erase even a fully written TLS response.
    // Perform the staged close from HTTP/1.1 connection teardown: finish TLS,
    // half-close the write side, then discard transport bytes until peer EOF
    // or the unchanged accepted connection deadline. No request body decoder,
    // Service call, spool, retry or additional I/O budget is involved.
    stream.conn.send_close_notify();
    if stream.flush().is_err()
        || stream
            .sock
            .stream
            .shutdown(std::net::Shutdown::Write)
            .is_err()
    {
        return;
    }
    let mut discarded = Zeroizing::new([0u8; 8192]);
    loop {
        match stream.sock.read(&mut *discarded) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
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
    let public_snapshot_upload = matches!(request.method, "POST" | "PUT")
        && matches!(
            request.path,
            "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
        );
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
                target: RedirectTarget::Native(native.target),
                headers: Default::default(),
            };
        }
    };
    let mut pending = match execution {
        RequestExecution::Complete(response) => {
            return rejected_upload_response(reader, native.body, deadline, response);
        }
        RequestExecution::External(pending) => pending,
    };
    #[cfg(feature = "native-v6-storage")]
    let lossless_download = pending.has_lossless_download();
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
    let uploaded_archive = public_snapshot_upload
        && file.is_none()
        && observation.is_native_snapshot_upload_observation();
    // No network/body I/O occurs under the service writer. The final request
    // audit must succeed before this file capability can reach the socket.
    let mut response = match lock_until(service, deadline) {
        Ok(mut writer) => writer.finish_external_request(*pending, observation),
        Err(_) => return NativeReply::Json(Response::error(503, "snapshot finalize unavailable")),
    };
    if let Some(origin) = response.response_headers.take_validated_snapshot_redirect() {
        return if response.status == 307 && file.is_none() {
            let headers = match std::mem::take(&mut response.response_headers)
                .into_local_redirect_metadata()
            {
                Ok(headers) => headers,
                Err(()) => {
                    return NativeReply::Json(Response::error(
                        503,
                        "snapshot redirect metadata changed",
                    ));
                }
            };
            NativeReply::Redirect {
                origin,
                target: RedirectTarget::Native(native.target),
                headers,
            }
        } else {
            NativeReply::Json(Response::error(
                503,
                "snapshot redirect lost its original route",
            ))
        };
    }
    if uploaded_archive && response.status == 200 {
        // OpenBao's public restore wire contract is 204 with no body. Apply
        // this only after the actual finalizer, mandatory audit and delivery
        // checks succeed. The typed Upload observation excludes inspect/cancel
        // reconciliation; the exact public routes exclude repair. Preserve the
        // final response's quota/consistency headers and internal Service reply.
        response.status = 204;
        crate::service::erase_json(&mut response.body);
    }
    if response.status == 200
        && let Some(file) = file
    {
        #[cfg(feature = "native-v6-storage")]
        if lossless_download {
            return NativeReply::LosslessFile(file);
        }
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
    namespace: &str,
) -> io::Result<()> {
    write!(
        writer,
        "HTTP/1.1 200 OK\r\nContent-Type: application/gzip\r\nContent-Disposition: attachment; filename=\"heptabao-native.snap\"\r\nContent-Length: {}\r\n",
        file.len()
    )?;
    write_standard_headers(writer, namespace)?;
    writer.write_all(b"\r\n")?;
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

#[cfg(feature = "native-v6-storage")]
fn write_lossless_file_response(
    writer: &mut impl Write,
    mut file: SnapshotFile,
    head: bool,
    namespace: &str,
) -> io::Result<()> {
    write!(
        writer,
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Disposition: attachment; filename=\"heptabao-kv2-lossless.json\"\r\nContent-Length: {}\r\n",
        crate::engines::kv2_lossless_export::MEDIA_TYPE,
        file.len()
    )?;
    write_standard_headers(writer, namespace)?;
    writer.write_all(b"\r\n")?;
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
    #[cfg(feature = "native-v6-storage")]
    #[test]
    fn lossless_export_http_keeps_read_only_typed_download_and_body_bounds() -> io::Result<()> {
        for method in ["GET", "HEAD"] {
            for accept in ["", "Accept: application/json\r\n"] {
                let raw = format!(
                    "{method} /v1/sys/migration/openbao/kv2/export?mount=secret HTTP/1.1\r\nHost: local\r\n{accept}\r\n"
                );
                let request = read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true)
                    .map_err(|_| io::Error::other("lossless download admission"))?;
                assert_eq!(request.body.0, json!({"mount":"secret"}));
                assert!(request.native_snapshot.is_some());
                assert!(
                    read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), false)
                        .is_ok_and(|request| request.native_snapshot.is_none())
                );
            }
        }
        for framing in [
            "Content-Length: 2\r\n\r\n{}",
            "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "Content-Length: 0\r\n\r\nGET /v1/sys/health HTTP/1.1\r\n\r\n",
        ] {
            let raw = format!(
                "GET /v1/sys/migration/openbao/kv2/export?mount=secret HTTP/1.1\r\nHost: local\r\n{framing}"
            );
            assert!(read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true).is_err());
        }
        for method in ["POST", "PUT"] {
            let raw = format!(
                "{method} /v1/sys/migration/openbao/kv2/export?mount=secret HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\n\r\n"
            );
            assert!(
                read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true)
                    .is_ok_and(|request| request.native_snapshot.is_none())
            );
        }
        Ok(())
    }

    #[cfg(feature = "native-v6-storage")]
    #[test]
    fn lossless_export_mount_query_is_bounded_route_specific_and_keeps_strings() -> io::Result<()> {
        for method in ["GET", "HEAD"] {
            for (query, expected) in [
                ("mount=true", "true"),
                ("mount=001", "001"),
                ("mount=secret%2Fnested", "secret/nested"),
            ] {
                let raw = format!(
                    "{method} /v1/sys/migration/openbao/kv2/export?{query} HTTP/1.1\r\nHost: local\r\n\r\n"
                );
                let request = read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true)
                    .map_err(|_| io::Error::other("route-specific lossless mount admission"))?;
                assert_eq!(request.body.0, json!({"mount": expected}));
                assert!(request.native_snapshot.is_some());
            }
            let maximum = "m".repeat(1024);
            let raw = format!(
                "{method} /v1/sys/migration/openbao/kv2/export?mount={maximum} HTTP/1.1\r\nHost: local\r\n\r\n"
            );
            let request = read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true)
                .map_err(|_| io::Error::other("bounded lossless mount admission"))?;
            assert_eq!(request.body.0, json!({"mount": maximum}));
            for query in [
                "mount".to_owned(),
                "mount=".to_owned(),
                "mount=%00".to_owned(),
                "mount=secret&mount=secret".to_owned(),
                "mount=secret&depth=1".to_owned(),
                "depth=1&mount=secret".to_owned(),
                "mount=secret&force=true".to_owned(),
                format!("mount={}", "m".repeat(1025)),
            ] {
                let raw = format!(
                    "{method} /v1/sys/migration/openbao/kv2/export?{query} HTTP/1.1\r\nHost: local\r\n\r\n"
                );
                assert!(
                    read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true).is_err()
                );
            }
            for path in [
                "sys/storage/raft/snapshot",
                "sys/migration/openbao/kv2/export-other",
            ] {
                let raw =
                    format!("{method} /v1/{path}?mount=secret HTTP/1.1\r\nHost: local\r\n\r\n");
                assert!(
                    read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true).is_err()
                );
            }
            // Ordinary KV reads retain their existing request-local query
            // carrier. Parsing that carrier does not select a typed download
            // or grant the lossless export route's mount selector.
            let ordinary_path = "secret/data/example";
            let raw = format!(
                "{method} /v1/{ordinary_path}?mount=secret HTTP/1.1\r\nHost: local\r\n\r\n"
            );
            let request = read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true)
                .map_err(|_| io::Error::other("existing ordinary KV query carrier"))?;
            assert_eq!(request.method, method);
            assert_eq!(request.path, ordinary_path);
            assert!(request.namespace.is_empty() && request.token.is_empty());
            assert!(request.native_snapshot.is_none());
            assert!(NativeTarget::checked("/v1/secret/data/example?mount=secret").is_err());
            let carrier = ocsp::query_request(&request.method, &request.path, &request.body.0)
                .ok_or_else(|| io::Error::other("query carrier remains bound to ordinary route"))?;
            assert!(
                ocsp::query_request(
                    method,
                    crate::engines::kv2_lossless_export::PATH,
                    &request.body.0,
                )
                .is_none()
            );
            assert!(ocsp::query_request("POST", &request.path, &request.body.0).is_none());
            if method == "GET" {
                // Without the synchronized actual KV owner, the original
                // strict query resolution still rejects this unknown field.
                assert!(carrier.resolve(false).is_err());
            }
            // Actual KV query resolution and ordinary HEAD preserve original
            // URL strings. Neither changes the method, target or authority.
            let (resolved_method, ordinary_body) = carrier
                .resolve(method == "GET")
                .map_err(|_| io::Error::other("existing KV and HEAD string query contract"))?;
            assert_eq!(resolved_method, method);
            assert_eq!(ordinary_body.0, json!({"mount": "secret"}));
        }
        for method in ["POST", "PUT"] {
            let body = r#"{"mount":"body"}"#;
            let raw = format!(
                "{method} /v1/sys/migration/openbao/kv2/export?mount=secret HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            assert!(read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true).is_err());
        }
        Ok(())
    }

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
            assert!(wire.ends_with(b"{\"errors\":[\"permission denied\"]}\n"));
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
    fn binary_route_only_supports_chunking_and_snapshot_accept_remains_binary() {
        for text in [
            "POST /v1/secret/data/key HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "POST /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "POST /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ] {
            assert!(read_request_mode(&mut text.as_bytes(), Duration::from_secs(1), true).is_err());
        }
        for method in ["GET", "HEAD"] {
            for accept in [
                "",
                "Accept: application/json\r\n",
                "Accept: application/octet-stream\r\n",
            ] {
                let raw = format!(
                    "{method} /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: local\r\n{accept}\r\n"
                );
                assert!(
                    read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true)
                        .is_ok_and(|r| r.native_snapshot.is_some())
                );
                // The explicitly non-wire parser used by internal JSON
                // fixtures retains its separate, bounded representation.
                assert!(
                    read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), false)
                        .is_ok_and(|r| r.native_snapshot.is_none())
                );
            }
        }
        let help = "GET /v1/sys/storage/raft/snapshot?help=1 HTTP/1.1\r\nHost: local\r\nAccept: application/json\r\n\r\n";
        assert!(
            read_request_mode(&mut help.as_bytes(), Duration::from_secs(1), true)
                .is_ok_and(|r| r.native_snapshot.is_none())
        );
        let upload = "POST /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: local\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        assert!(
            read_request_mode(&mut upload.as_bytes(), Duration::from_secs(1), true)
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

    #[test]
    fn current_root_repair_retains_binary_header_admission_and_bounded_json_lane() {
        let raw = "POST /v1/sys/storage/raft/snapshot-repair HTTP/1.1\r\nHost: local\r\nContent-Length: 25000000\r\n\r\n";
        assert!(
            read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true)
                .is_ok_and(|request| request.native_snapshot.is_some())
        );
        let json = "POST /v1/sys/storage/raft/snapshot-repair HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: 25000000\r\n\r\n";
        assert!(read_request_mode(&mut json.as_bytes(), Duration::from_secs(1), true).is_err());
        let get = "GET /v1/sys/storage/raft/snapshot-repair HTTP/1.1\r\nHost: local\r\n\r\n";
        assert!(
            read_request_mode(&mut get.as_bytes(), Duration::from_secs(1), true)
                .is_ok_and(|request| request.native_snapshot.is_none())
        );
    }

    #[cfg(feature = "native-v6-ha")]
    #[test]
    fn native_ha_pending_restore_query_reaches_empty_binary_lane_and_rejects_other_routes()
    -> io::Result<()> {
        let reference = format!("native-v6-restore-{}", "1".repeat(64));
        let cancel = format!("cancel_pending_restore={reference}");
        for (query, field, expected) in [
            (
                cancel.as_str(),
                "cancel_pending_restore",
                Value::String(reference),
            ),
            (
                "inspect_pending_restore=true",
                "inspect_pending_restore",
                Value::Bool(true),
            ),
        ] {
            for method in ["POST", "PUT"] {
                for framing in [
                    "Content-Length: 0\r\n\r\n",
                    "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                ] {
                    let raw = format!(
                        "{method} /v1/sys/storage/raft/snapshot?{query} HTTP/1.1\r\nHost: local\r\n{framing}"
                    );
                    let mut request =
                        read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true)
                            .map_err(|_| {
                                io::Error::other(
                                    "explicit pending selector must reach native admission",
                                )
                            })?;
                    assert_eq!(request.body.0[field], expected);
                    let native = request
                        .native_snapshot
                        .take()
                        .ok_or_else(|| io::Error::other("empty native binary request"))?;
                    let mut source = io::empty();
                    let mut body = BodyReader::new(
                        &mut source,
                        native.body,
                        Instant::now() + Duration::from_secs(1),
                    )?;
                    assert_eq!(body.read(&mut [0; 1])?, 0);
                }
            }
            for (method, path, query) in [
                ("GET", "sys/storage/raft/snapshot", query.to_owned()),
                ("HEAD", "sys/storage/raft/snapshot", query.to_owned()),
                ("POST", "sys/storage/raft/snapshot-force", query.to_owned()),
                ("POST", "sys/storage/raft/snapshot-repair", query.to_owned()),
                ("POST", "secret/data/example", query.to_owned()),
                (
                    "POST",
                    "sys/storage/raft/snapshot",
                    format!("{query}&{query}"),
                ),
                (
                    "POST",
                    "sys/storage/raft/snapshot",
                    format!("{query}&force=true"),
                ),
            ] {
                let raw = format!(
                    "{method} /v1/{path}?{query} HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\n\r\n"
                );
                assert!(
                    read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true).is_err()
                );
            }
        }
        for query in [
            "inspect_pending_restore",
            "inspect_pending_restore=",
            "inspect_pending_restore=false",
            "inspect_pending_restore=1",
            "inspect_pending_restore=TRUE",
            "inspect_pending_restore=null",
        ] {
            let raw = format!(
                "POST /v1/sys/storage/raft/snapshot?{query} HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\n\r\n"
            );
            assert!(read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true).is_err());
        }
        let mut duplicate = serde_json::json!({"inspect_pending_restore":true});
        assert!(
            merge_query_fields(
                "POST",
                "sys/storage/raft/snapshot",
                "inspect_pending_restore=true",
                &mut duplicate
            )
            .is_err()
        );
        Ok(())
    }
}
