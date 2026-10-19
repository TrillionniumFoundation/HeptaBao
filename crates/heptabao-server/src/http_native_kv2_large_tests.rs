use super::*;
use crate::engines::kv2_native_large::{PATH, MEDIA_TYPE};
type TestResult = Result<(), Box<dyn std::error::Error>>;

struct HeaderOnly {
    header: io::Cursor<Vec<u8>>,
    body_reads: usize,
}
impl Read for HeaderOnly {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.header.position() < self.header.get_ref().len() as u64 {
            return self.header.read(bytes);
        }
        self.body_reads += 1;
        Err(io::Error::other("body must remain deferred"))
    }
}
fn header(route: &str, media: &str, framing: &str) -> HeaderOnly {
    HeaderOnly { header: io::Cursor::new(format!(
        "POST /v1/{route}?mount=secret HTTP/1.1\r\nHost: local\r\nContent-Type: {media}\r\n{framing}\r\n",
    ).into_bytes()), body_reads: 0 }
}

#[test]
fn native_large_kv2_http_defers_body_and_preserves_ordinary_json_limits() -> TestResult {
    let mut input = header(PATH, MEDIA_TYPE, "Content-Length: 35660000\r\n");
    let request = read_request_mode(&mut input, Duration::from_secs(5), true)
        .map_err(|_| "deferred header rejected")?;
    assert_eq!(request.path, PATH);
    assert_eq!(request.body.0, json!({"mount":"secret"}));
    assert!(request.native_snapshot.is_some());
    assert_eq!(input.body_reads, 0);
    assert_eq!(MAX_BODY, 2 * 1024 * 1024);
    assert_eq!(json_ingress_body_limit("POST", PATH, Some("application/json")), MAX_BODY);
    let mut legacy = header("sys/migration/openbao/kv2", "application/json", "Content-Length: 35660000\r\n");
    let rejected = read_request_mode(&mut legacy, Duration::from_secs(5), true).err()
        .ok_or("legacy limit must reject")?;
    assert_eq!(rejected.status, 413);
    assert_eq!(legacy.body_reads, 0);
    Ok(())
}

#[test]
fn native_large_kv2_http_rejects_ambiguous_or_excessive_framing_without_body() -> TestResult {
    for framing in [
        "",
        "Transfer-Encoding: chunked\r\n",
        "Content-Length: 3\r\nTransfer-Encoding: chunked\r\n",
        "Content-Length: 3\r\nExpect: 100-continue\r\n",
        "Content-Length: 3\r\nContent-Length: 4\r\n",
        "Content-Length: 67108865\r\n",
    ] {
        let mut input = header(PATH, MEDIA_TYPE, framing);
        assert!(read_request_mode(&mut input, Duration::from_secs(5), true).is_err());
        assert_eq!(input.body_reads, 0);
    }
    for route in ["sys/migration/openbao/kv2/native-large/", "sys/migration/openbao/kv2/native-large-extra"] {
        let mut input = header(route, MEDIA_TYPE, "Content-Length: 35660000\r\n");
        assert!(read_request_mode(&mut input, Duration::from_secs(5), true).is_err());
        assert_eq!(input.body_reads, 0);
    }
    Ok(())
}

#[test]
fn native_large_kv2_http_length_reader_retains_original_deadline_and_detects_truncation() -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut source = b"bc".as_slice();
    let mut reader = BodyReader::new(&mut source, snapshot::NativeBody {
        framing: snapshot::Framing::Length(3), prefix: Zeroizing::new(b"a".to_vec()),
    }, deadline)?;
    let mut bytes = Vec::new(); reader.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"abc");
    let mut source = b"b".as_slice();
    let mut reader = BodyReader::new(&mut source, snapshot::NativeBody {
        framing: snapshot::Framing::Length(3), prefix: Zeroizing::new(b"a".to_vec()),
    }, deadline)?;
    assert!(reader.read_to_end(&mut Vec::new()).is_err());
    let mut source = HeaderOnly { header: io::Cursor::new(Vec::new()), body_reads: 0 };
    let mut reader = BodyReader::new(&mut source, snapshot::NativeBody {
        framing: snapshot::Framing::Length(1), prefix: Zeroizing::new(Vec::new()),
    }, Instant::now() - Duration::from_millis(1))?;
    assert_eq!(reader.read(&mut [0; 1]).err().ok_or("expired read")?.kind(), io::ErrorKind::TimedOut);
    drop(reader); assert_eq!(source.body_reads, 0);
    for framing in [snapshot::Framing::Chunked, snapshot::Framing::Length(0),
        snapshot::Framing::Length(MAX_BUNDLE_BYTES as u64 + 1)] {
        assert!(BodyReader::new(&mut io::empty(), snapshot::NativeBody {
            framing, prefix: Zeroizing::new(Vec::new()),
        }, deadline).is_err());
    }
    Ok(())
}
