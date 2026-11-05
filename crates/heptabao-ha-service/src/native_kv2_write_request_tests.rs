use super::*;
use std::io::Cursor;

fn inner(magic: &[u8; 5], size: usize) -> Vec<u8> {
    assert!(size > HEADER_BYTES);
    let mut frame = vec![b' '; size];
    frame[..5].copy_from_slice(magic);
    frame[5..9].copy_from_slice(&((size - HEADER_BYTES) as u32).to_be_bytes());
    frame[9] = b'0';
    frame
}

#[derive(Default)]
struct CountWriter(usize);
impl Write for CountWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.0 += input.len();
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn native_kv2_write_transport_new_profile_keeps_all_original_frame_bounds() {
    assert_eq!(MAX_PAYLOAD_BYTES, 1024 * 1024);
    let frame = inner(NATIVE_KV2_WRITE_REQUEST_MAGIC, 2 * 1024 * 1024 + 97);
    assert_eq!(validate_authenticated_request(&frame), Ok(()));
    assert_eq!(
        ResponseFrameProfile::for_request(&frame),
        Ok(ResponseFrameProfile::NativeIndexV1)
    );
    let mut writer = CountWriter::default();
    assert_eq!(write_authenticated_request(&mut writer, &frame), Ok(()));
    assert_eq!(writer.0, frame.len() + 4);
    let mut old_writer = CountWriter::default();
    assert_eq!(
        write_bounded_frame(&mut old_writer, &frame),
        Err(HaError::InvalidFrame)
    );
    assert_eq!(old_writer.0, 0);
    for magic in [
        b"HBFQ1", b"HBFQ2", b"HBFQ3", b"HBFQ4", b"HBFQ5", b"HBFQ7", b"HBFQ8", b"HBFQ9", b"HBFA1",
        b"HBFA2", b"HBFN2", b"HBFS7",
    ] {
        let mut old = frame.clone();
        old[..5].copy_from_slice(magic);
        assert_eq!(
            validate_authenticated_request(&old),
            Err(HaError::InvalidFrame)
        );
        assert_eq!(
            write_authenticated_request(&mut old_writer, &old),
            Err(HaError::InvalidFrame)
        );
    }
    assert_eq!(old_writer.0, 0);
    let mut q9 = inner(NATIVE_INDEX_REQUEST_MAGIC, MAX_PAYLOAD_BYTES + 1);
    assert_eq!(
        ResponseFrameProfile::for_request(&q9),
        Err(HaError::InvalidFrame)
    );
    q9.truncate(MAX_PAYLOAD_BYTES);
    q9[5..9].copy_from_slice(&((MAX_PAYLOAD_BYTES - 9) as u32).to_be_bytes());
    assert_eq!(
        ResponseFrameProfile::for_request(&q9),
        Ok(ResponseFrameProfile::NativeIndexV1)
    );
}

#[test]
fn native_kv2_write_transport_checks_header_and_strict_alpn_before_large_allocation() {
    for length in [
        0_u32,
        (MAX_NATIVE_KV2_WRITE_FRAME_BYTES + 1) as u32,
        u32::MAX,
    ] {
        let mut reader = Cursor::new(length.to_be_bytes());
        assert_eq!(
            read_authenticated_request(&mut reader, Some(RAFT_ALPN_PROTOCOL)),
            Err(HaError::InvalidFrame)
        );
        assert_eq!(reader.position(), 4);
    }
    let length = (2 * 1024 * 1024 + 97) as u32;
    for (magic, declared, alpn, expected) in [
        (
            b"HBFN2",
            length - 9,
            Some(RAFT_ALPN_PROTOCOL),
            HaError::InvalidFrame,
        ),
        (
            b"HBFQ9",
            length - 9,
            Some(RAFT_ALPN_PROTOCOL),
            HaError::InvalidFrame,
        ),
        (
            NATIVE_KV2_WRITE_REQUEST_MAGIC,
            length - 10,
            Some(RAFT_ALPN_PROTOCOL),
            HaError::InvalidFrame,
        ),
        (
            NATIVE_KV2_WRITE_REQUEST_MAGIC,
            length - 9,
            None,
            HaError::PeerAuthenticationFailed,
        ),
        (
            NATIVE_KV2_WRITE_REQUEST_MAGIC,
            length - 9,
            Some(&b"http/1.1"[..]),
            HaError::PeerAuthenticationFailed,
        ),
    ] {
        let mut header = length.to_be_bytes().to_vec();
        header.extend_from_slice(magic);
        header.extend_from_slice(&declared.to_be_bytes());
        let mut reader = Cursor::new(header);
        assert_eq!(read_authenticated_request(&mut reader, alpn), Err(expected));
        assert_eq!(reader.position(), 13, "refusal occurs before body I/O");
    }
    // The authenticated transport still accepts the old bounded byte frames;
    // application codecs retain the responsibility for their inner grammars.
    for size in 1..=9 {
        let frame = vec![b'x'; size];
        let mut wire = (size as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&frame);
        assert_eq!(
            read_authenticated_request(&mut Cursor::new(wire), None),
            Ok(frame)
        );
    }
}

#[test]
fn native_kv2_write_transport_exact_total_bound_and_legacy_reader_refusal() {
    let frame = inner(
        NATIVE_KV2_WRITE_REQUEST_MAGIC,
        MAX_NATIVE_KV2_WRITE_FRAME_BYTES,
    );
    let mut wire = Vec::new();
    assert_eq!(write_authenticated_request(&mut wire, &frame), Ok(()));
    assert_eq!(
        read_authenticated_request(&mut Cursor::new(&wire), Some(RAFT_ALPN_PROTOCOL)),
        Ok(frame.clone())
    );
    let mut old = Cursor::new(&wire);
    assert_eq!(read_bounded_frame(&mut old), Err(HaError::InvalidFrame));
    assert_eq!(
        old.position(),
        4,
        "old receiver cannot allocate or dispatch N1"
    );
    let oversized = inner(
        NATIVE_KV2_WRITE_REQUEST_MAGIC,
        MAX_NATIVE_KV2_WRITE_FRAME_BYTES + 1,
    );
    let mut writer = CountWriter::default();
    assert_eq!(
        write_authenticated_request(&mut writer, &oversized),
        Err(HaError::InvalidFrame)
    );
    assert_eq!(writer.0, 0);
    let mut malformed = frame;
    malformed[8] ^= 1;
    assert_eq!(
        validate_authenticated_request(&malformed),
        Err(HaError::InvalidFrame)
    );
}

#[test]
fn native_kv2_write_transport_original_expired_budget_refuses_before_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let peer = NodeId::parse("native-write-peer").unwrap();
    let transport = MutualTlsPeerTransport::new(
        BTreeMap::from([(
            peer.clone(),
            TlsPeerEndpoint::new(listener.local_addr().unwrap(), "localhost").unwrap(),
        )]),
        Arc::new(tls),
        Duration::from_secs(8),
    )
    .unwrap();
    let frame = inner(NATIVE_KV2_WRITE_REQUEST_MAGIC, 2 * 1024 * 1024 + 97);
    assert_eq!(
        transport.exchange_before(&peer, &frame, Instant::now()),
        Err(HaError::Transport)
    );
    assert!(
        listener
            .accept()
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
    );
}
