//! Actual TCP/mTLS tests of the small transport only. Synthetic handler bytes
//! do not claim a Service clock receipt; formal Service tests cover that owner.
use super::*;
use crate::{
    MAX_SNAPSHOT_CLOCK_FRAME_BYTES, SNAPSHOT_CLOCK_REQUEST_MAGIC, SNAPSHOT_CLOCK_RESPONSE_MAGIC,
    serve_one_mtls_authenticated_peer_frame,
};
use std::io::Cursor;
use std::sync::mpsc;

fn clock_request(remaining: Duration) -> Vec<u8> {
    let mut frame = SNAPSHOT_CLOCK_REQUEST_MAGIC.to_vec();
    frame.extend_from_slice(&u64::try_from(remaining.as_nanos()).unwrap().to_be_bytes());
    frame.extend_from_slice(b"{}");
    frame
}

#[test]
fn snapshot_clock_authenticated_tls_slow_tail_stops_at_original_shortened_deadline() -> TestResult {
    let root = Root::new()?;
    let fixture = tls_fixture(&root.directory("pki")?)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let client_id = NodeId::parse("clock-budget-client")?;
    let identities =
        PinnedClientCertificateMap::new(BTreeMap::from([(fixture.pins[&1], client_id)]))?;
    let config = fixture.servers[&2].clone();
    let invoked = Arc::new(AtomicU64::new(0));
    let calls = invoked.clone();
    let (sent, received) = mpsc::sync_channel(1);
    thread::scope(|scope| -> TestResult {
        let worker = scope.spawn(move || {
            let result = serve_one_mtls_authenticated_peer_frame(
                &listener,
                config,
                &identities,
                Duration::from_secs(2),
                false,
                move |_| {
                    calls.fetch_add(1, Ordering::AcqRel);
                    Ok(b"HBSC2{}".to_vec())
                },
            );
            let _ = sent.send(result);
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
        assert_eq!(client.alpn_protocol(), Some(RAFT_ALPN_PROTOCOL));
        let frame = clock_request(Duration::from_millis(200));
        let began = Instant::now();
        {
            let mut tls = rustls::Stream::new(&mut client, &mut socket);
            tls.write_all(&(frame.len() as u32).to_be_bytes())?;
            tls.write_all(&frame[..13])?;
            tls.flush()?;
        }
        // Keep the actual client socket open without sending the JSON tail.
        // A receiver using its old two-second outer bound cannot finish here.
        let result = received.recv_timeout(Duration::from_millis(900))?;
        assert_eq!(result, Err(HaError::Transport));
        assert!(began.elapsed() < Duration::from_secs(1));
        assert_eq!(invoked.load(Ordering::Acquire), 0);
        drop(client);
        drop(socket);
        worker
            .join()
            .map_err(|_| "clock slow-tail worker panicked")?;
        Ok(())
    })
}

#[test]
fn snapshot_clock_private_reader_rejects_oversized_length_before_tail_and_preserves_legacy()
-> TestResult {
    let began = Instant::now();
    let mut hostile = ((MAX_SNAPSHOT_CLOCK_FRAME_BYTES + 1) as u32)
        .to_be_bytes()
        .to_vec();
    hostile.extend_from_slice(SNAPSHOT_CLOCK_REQUEST_MAGIC);
    let mut input = Cursor::new(hostile);
    let result = crate::snapshot_clock_transport::read_authenticated_request(
        &mut input,
        Some(RAFT_ALPN_PROTOCOL),
        began,
        began + Duration::from_secs(1),
        |_, _| panic!("oversized request must not reach deadline/body admission"),
    );
    assert_eq!(result, Err(HaError::InvalidFrame));
    assert_eq!(input.position(), 9);
    for payload in [b"HBFQ1-legacy-fixture".as_slice(), b"tiny".as_slice()] {
        let mut framed = (payload.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(payload);
        let mut input = Cursor::new(framed);
        let actual = crate::snapshot_clock_transport::read_authenticated_request(
            &mut input,
            None,
            began,
            began + Duration::from_secs(1),
            |_, _| panic!("ordinary framing must retain its original path"),
        )?;
        assert_eq!(actual, payload);
    }
    Ok(())
}

#[test]
fn snapshot_clock_authenticated_transport_encodes_only_after_exact_server_pin() -> TestResult {
    let root = Root::new()?;
    let fixture = tls_fixture(&root.directory("pki")?)?;
    for correct_pin in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let identities = PinnedClientCertificateMap::new(BTreeMap::from([(
            fixture.pins[&1],
            NodeId::parse("clock-pinned-client")?,
        )]))?;
        let server_config = fixture.servers[&2].clone();
        let peer = NodeId::parse("clock-pinned-server")?;
        let transport = MutualTlsPeerTransport::new(
            BTreeMap::from([(peer.clone(), TlsPeerEndpoint::new(address, "localhost")?)]),
            fixture.clients[&1].clone(),
            Duration::from_secs(2),
        )?;
        let encoded = Arc::new(AtomicU64::new(0));
        let calls = encoded.clone();
        thread::scope(|scope| -> TestResult {
            let worker = scope.spawn(move || {
                serve_one_mtls_authenticated_peer_frame(
                    &listener,
                    server_config,
                    &identities,
                    Duration::from_secs(2),
                    false,
                    |frame| {
                        assert!(frame.has_strict_raft_alpn());
                        assert!(frame.payload().starts_with(SNAPSHOT_CLOCK_REQUEST_MAGIC));
                        let nanos = u64::from_be_bytes(frame.payload()[5..13].try_into().unwrap());
                        assert_eq!(
                            frame.deadline(),
                            frame.accepted_at() + Duration::from_nanos(nanos)
                        );
                        Ok([SNAPSHOT_CLOCK_RESPONSE_MAGIC.as_slice(), b"{}"].concat())
                    },
                )
            });
            let mut pin = fixture.pins[&2];
            if !correct_pin {
                pin[0] ^= 1;
            }
            let result = transport.exchange_snapshot_clock_before_pinned_server(
                &peer,
                Instant::now() + Duration::from_secs(2),
                pin,
                move |remaining| {
                    calls.fetch_add(1, Ordering::AcqRel);
                    Ok(clock_request(remaining))
                },
            );
            let served = worker.join().map_err(|_| "clock pinned worker panicked")?;
            if correct_pin {
                assert_eq!(result?, b"HBSC2{}");
                assert_eq!(served, Ok(()));
                assert_eq!(encoded.load(Ordering::Acquire), 1);
            } else {
                assert_eq!(result, Err(HaError::PeerAuthenticationFailed));
                assert!(served.is_err());
                assert_eq!(encoded.load(Ordering::Acquire), 0);
            }
            Ok(())
        })?;
    }
    Ok(())
}
