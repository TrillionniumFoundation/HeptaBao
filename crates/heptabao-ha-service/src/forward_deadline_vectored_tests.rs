//! Actual TCP checks for the deadline-preserving vectored transport adapter.
use super::*;
use std::io::IoSlice;

fn sockets() -> io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let client = TcpStream::connect(listener.local_addr()?)?;
    let (peer, _) = listener.accept()?;
    client.set_nodelay(true)?;
    peer.set_read_timeout(Some(Duration::from_millis(250)))?;
    Ok((client, peer))
}

#[test]
fn vectored_deadline_stream_preserves_order_and_empty_slices() -> io::Result<()> {
    let (stream, mut peer) = sockets()?;
    let mut writer = ForwardDeadlineStream {
        stream,
        deadline: Instant::now() + Duration::from_secs(1),
    };
    let mut buffers = [
        IoSlice::new(b""),
        IoSlice::new(b"strict"),
        IoSlice::new(b""),
        IoSlice::new(b"-peer-frame"),
        IoSlice::new(b""),
    ];
    let mut pending = buffers.as_mut_slice();
    let mut written = 0;
    while !pending.is_empty() {
        let count = writer.write_vectored(pending)?;
        if count == 0 {
            assert!(pending.iter().all(|part| part.is_empty()));
            break;
        }
        written += count;
        IoSlice::advance_slices(&mut pending, count);
    }
    let mut observed = vec![0; written];
    peer.read_exact(&mut observed)?;
    assert_eq!(observed, b"strict-peer-frame");
    Ok(())
}

#[test]
fn vectored_deadline_stream_expired_bound_sends_no_bytes() -> io::Result<()> {
    let (stream, mut peer) = sockets()?;
    let mut writer = ForwardDeadlineStream {
        stream,
        deadline: Instant::now(),
    };
    let error = writer
        .write_vectored(&[IoSlice::new(b"first"), IoSlice::new(b"second")])
        .expect_err("an expired original bound must refuse before socket I/O");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    let mut observed = [0];
    let error = peer.read(&mut observed).expect_err("no bytes may escape");
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
    Ok(())
}

#[test]
fn vectored_deadline_stream_backpressure_keeps_one_absolute_budget() -> io::Result<()> {
    let (stream, _peer) = sockets()?;
    let first = vec![0x61; 8 * 1024 * 1024];
    let second = vec![0x62; 8 * 1024 * 1024];
    let began = Instant::now();
    let deadline = began + Duration::from_millis(50);
    let mut writer = ForwardDeadlineStream { stream, deadline };
    let mut buffers = [IoSlice::new(&first), IoSlice::new(&second)];
    let mut pending = buffers.as_mut_slice();
    let mut sent = 0;
    let error = loop {
        match writer.write_vectored(pending) {
            Ok(0) => panic!("a nonempty pressured write must not report EOF"),
            Ok(count) => {
                sent += count;
                IoSlice::advance_slices(&mut pending, count);
                assert!(!pending.is_empty(), "the peer intentionally never reads");
            }
            Err(error) => break error,
        }
    };
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
    assert!(sent < first.len() + second.len());
    assert_eq!(writer.deadline, deadline);
    assert!(began.elapsed() < Duration::from_secs(2));
    Ok(())
}
