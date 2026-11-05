//! Actual public server TCP/mTLS response framing. These synthetic handler
//! replies grant no native root authority; the unchanged real root-repair tests
//! separately exercise actual ReadIndex, durable storage and hostile peers.
use super::*;
use std::io::{self, Cursor, Read};

type ReplyObservation = (Result<(), HaError>, Vec<usize>, Vec<u8>, u64);

fn receive_server_records(
    client: &mut rustls::ClientConnection,
    socket: &mut TcpStream,
) -> TestResult<(Vec<usize>, Vec<u8>)> {
    let mut sizes = Vec::new();
    let mut plaintext = Vec::new();
    for _ in 0..128 {
        let mut header = [0_u8; 5];
        match socket.read(&mut header[..1]) {
            Ok(0) => return Ok((sizes, plaintext)),
            Ok(1) => {}
            Ok(_) => unreachable!(),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
        socket.read_exact(&mut header[1..])?;
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        assert!(length > 0 && length <= 18 * 1024);
        let mut encoded = header.to_vec();
        encoded.resize(5 + length, 0);
        socket.read_exact(&mut encoded[5..])?;
        let mut incoming = Cursor::new(encoded);
        let before = plaintext.len();
        while incoming.position() < incoming.get_ref().len() as u64 {
            assert!(
                client.read_tls(&mut incoming)? > 0,
                "finite TLS flight advances"
            );
            let state = client.process_new_packets()?;
            let count = state.plaintext_bytes_to_read();
            if count != 0 {
                let start = plaintext.len();
                assert!(start + count <= crate::MAX_PAYLOAD_BYTES + 4100);
                plaintext.resize(start + count, 0);
                client.reader().read_exact(&mut plaintext[start..])?;
            }
        }
        if plaintext.len() > before {
            assert_eq!(header[0], 23, "actual TLS application record");
            sizes.push(plaintext.len() - before);
        }
    }
    Err("server response exceeded the bounded record count".into())
}

fn server_reply(
    fixture: &TlsFixture,
    request: &[u8],
    response: Vec<u8>,
    timeout: Duration,
    expire_in_handler: bool,
) -> TestResult<ReplyObservation> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let client_id = NodeId::parse("actual-response-voter-1")?;
    let client_pin = fixture.pins[&1];
    let identities =
        PinnedClientCertificateMap::new(BTreeMap::from([(client_pin, client_id.clone())]))?;
    let server_config = fixture.servers[&2].clone();
    let expected_request = request.to_vec();
    let invoked = Arc::new(AtomicU64::new(0));
    let calls = invoked.clone();
    thread::scope(|scope| {
        let worker = scope.spawn(move || {
            serve_one_mtls_authenticated_peer_frame(
                &listener,
                server_config,
                &identities,
                timeout,
                false,
                move |frame| {
                    assert_eq!(frame.peer(), &client_id);
                    assert_eq!(frame.actual_leaf_sha256(), client_pin);
                    assert!(frame.has_strict_raft_alpn());
                    assert_eq!(frame.payload(), expected_request);
                    assert_eq!(frame.deadline(), frame.accepted_at() + timeout);
                    calls.fetch_add(1, Ordering::AcqRel);
                    if expire_in_handler {
                        thread::sleep(
                            frame.deadline().saturating_duration_since(Instant::now())
                                + Duration::from_millis(5),
                        );
                        assert!(Instant::now() >= frame.deadline());
                    }
                    Ok(response)
                },
            )
        });
        let mut socket = TcpStream::connect(address)?;
        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut client = rustls::ClientConnection::new(
            fixture.clients[&1].clone(),
            rustls::pki_types::ServerName::try_from("localhost")?,
        )?;
        client.complete_io(&mut socket)?;
        assert!(!client.is_handshaking());
        assert_eq!(client.alpn_protocol(), Some(RAFT_ALPN_PROTOCOL));
        let chain = client
            .peer_certificates()
            .ok_or("actual server certificate absent")?;
        assert_eq!(
            digest(&SHA256, chain[0].as_ref()).as_ref(),
            fixture.pins[&2].as_slice(),
        );
        crate::write_bounded_frame(&mut rustls::Stream::new(&mut client, &mut socket), request)?;
        let (record_sizes, plaintext) = receive_server_records(&mut client, &mut socket)?;
        let result = worker
            .join()
            .map_err(|_| "authenticated server worker panicked")?;
        Ok((
            result,
            record_sizes,
            plaintext,
            invoked.load(Ordering::Acquire),
        ))
    })
}

fn expected_wire(payload: &[u8]) -> Vec<u8> {
    let mut wire = (payload.len() as u32).to_be_bytes().to_vec();
    wire.extend_from_slice(payload);
    wire
}

fn negotiated_frame(magic: &[u8; 5], body: &[u8]) -> Vec<u8> {
    let mut frame = magic.to_vec();
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

#[test]
fn root_pull_authenticated_tls_response_coalesces_only_original_root_profile() -> TestResult {
    let root = Root::new()?;
    let fixture = tls_fixture(&root.directory("pki")?)?;
    let response = vec![0x61; 256 * 1024 - 4];
    let expected = expected_wire(&response);
    let mut counts = Vec::new();
    for (request, first_record) in [
        (b"HBVP2-response-framing-fixture".as_slice(), 16 * 1024),
        (b"ordinary-legacy-response-fixture".as_slice(), 4),
    ] {
        let (result, sizes, plaintext, calls) = server_reply(
            &fixture,
            request,
            response.clone(),
            Duration::from_secs(2),
            false,
        )?;
        assert_eq!(result, Ok(()));
        assert_eq!(calls, 1, "the authenticated handler executes once");
        assert_eq!(plaintext, expected);
        assert_eq!(sizes.first(), Some(&first_record));
        counts.push(sizes.len());
    }
    assert_eq!(
        counts,
        [16, 17],
        "HBVP2 omits only the header-only TLS record"
    );
    for magic in [b"HBFQ9", b"HBFN1"] {
        let request = negotiated_frame(magic, b"{}");
        let reply = negotiated_frame(b"HBFS7", br#"{"data":{}}"#);
        let (result, sizes, plaintext, calls) = server_reply(
            &fixture,
            &request,
            reply.clone(),
            Duration::from_secs(2),
            false,
        )?;
        assert_eq!(result, Ok(()));
        assert_eq!(calls, 1);
        assert_eq!(plaintext, expected_wire(&reply));
        assert_eq!(
            sizes.first(),
            Some(&4),
            "Q9/N1 negotiated S7 path is unchanged"
        );
    }
    Ok(())
}

#[test]
fn root_pull_authenticated_tls_response_original_deadline_does_not_deliver_bytes() -> TestResult {
    let root = Root::new()?;
    let fixture = tls_fixture(&root.directory("pki")?)?;
    let (result, sizes, plaintext, calls) = server_reply(
        &fixture,
        b"HBVP2-response-deadline-fixture",
        vec![0x62; 256 * 1024],
        Duration::from_millis(500),
        true,
    )?;
    assert_eq!(result, Err(HaError::Transport));
    assert_eq!(calls, 1, "an expired response is never replayed");
    assert!(sizes.is_empty());
    assert!(
        plaintext.is_empty(),
        "no response header or body crossed the expired socket"
    );
    Ok(())
}

#[test]
fn root_pull_authenticated_tls_response_keeps_original_frame_limits() -> TestResult {
    let root = Root::new()?;
    let fixture = tls_fixture(&root.directory("pki")?)?;
    for response in [Vec::new(), vec![0x63; crate::MAX_PAYLOAD_BYTES + 4097]] {
        let (result, sizes, plaintext, calls) = server_reply(
            &fixture,
            b"HBVP2-response-limit-fixture",
            response,
            Duration::from_secs(2),
            false,
        )?;
        assert_eq!(result, Err(HaError::InvalidFrame));
        assert_eq!(calls, 1);
        assert!(sizes.is_empty());
        assert!(plaintext.is_empty());
    }
    Ok(())
}
