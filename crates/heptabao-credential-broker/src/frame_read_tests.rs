use super::{Error, MAX_MESSAGE, read_frame, write_frame};
use std::{
    io::Write,
    os::unix::net::UnixStream,
    thread,
    time::{Duration, Instant},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn complete_frame_remains_readable_after_peer_close() -> TestResult {
    let (mut reader, mut writer) = UnixStream::pair()?;
    let expected = b"synthetic-public-frame";
    write_frame(&mut writer, expected)?;
    drop(writer);
    let actual = read_frame(&mut reader, Duration::from_secs(1))?;
    assert_eq!(actual.as_slice(), expected);
    Ok(())
}

#[test]
fn closed_partial_header_and_body_are_incomplete() -> TestResult {
    for wire in [vec![0, 0], vec![0, 0, 0, 8, b'a', b'b']] {
        let (mut reader, mut writer) = UnixStream::pair()?;
        writer.write_all(&wire)?;
        drop(writer);
        assert_eq!(
            read_frame(&mut reader, Duration::from_secs(1)),
            Err(Error("incomplete_frame"))
        );
    }
    Ok(())
}

#[test]
fn invalid_frame_sizes_are_refused_before_reading_a_body() -> TestResult {
    for size in [0, MAX_MESSAGE as u32 + 1] {
        let (mut reader, mut writer) = UnixStream::pair()?;
        writer.write_all(&size.to_be_bytes())?;
        assert_eq!(
            read_frame(&mut reader, Duration::from_secs(1)),
            Err(Error("invalid_frame"))
        );
    }
    Ok(())
}

#[test]
fn fragmented_live_frame_is_read_within_one_deadline() -> TestResult {
    let (mut reader, mut writer) = UnixStream::pair()?;
    let sender = thread::spawn(move || -> std::io::Result<()> {
        for part in [&[0, 0][..], &[0, 3][..], b"a", b"bc"] {
            writer.write_all(part)?;
            thread::sleep(Duration::from_millis(15));
        }
        Ok(())
    });
    let result = read_frame(&mut reader, Duration::from_secs(2));
    sender.join().map_err(|_| "sender panicked")??;
    assert_eq!(result?.as_slice(), b"abc");
    Ok(())
}

#[test]
fn an_open_silent_peer_cannot_hold_the_reader_past_the_deadline() -> TestResult {
    let (mut reader, _writer) = UnixStream::pair()?;
    let started = Instant::now();
    assert_eq!(
        read_frame(&mut reader, Duration::from_millis(150)),
        Err(Error("request_timeout"))
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    Ok(())
}

#[test]
fn header_progress_does_not_reset_the_body_deadline() -> TestResult {
    let (mut reader, mut writer) = UnixStream::pair()?;
    let started = Instant::now();
    let sender = thread::spawn(move || -> std::io::Result<Duration> {
        thread::sleep(Duration::from_millis(200));
        writer.write_all(&3u32.to_be_bytes())?;
        let header_sent_at = started.elapsed();
        thread::sleep(Duration::from_millis(250));
        writer.write_all(b"abc")?;
        Ok(header_sent_at)
    });
    let result = read_frame(&mut reader, Duration::from_millis(400));
    let returned_at = started.elapsed();
    let header_sent_at = sender.join().map_err(|_| "sender panicked")??;
    assert!(header_sent_at < Duration::from_millis(400));
    assert_eq!(result, Err(Error("request_timeout")));
    assert!(returned_at < Duration::from_secs(2));
    Ok(())
}
