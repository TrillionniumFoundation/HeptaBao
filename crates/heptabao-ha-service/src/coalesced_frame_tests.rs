//! Framing error paths that must never duplicate bytes or renew an I/O budget.
use super::*;
use std::collections::VecDeque;

struct ShortWriter {
    steps: VecDeque<Result<usize, io::ErrorKind>>,
    bytes: Vec<u8>,
    calls: usize,
    flushes: usize,
    flush_error: bool,
}

impl ShortWriter {
    fn new(steps: Vec<Result<usize, io::ErrorKind>>) -> Self {
        Self {
            steps: steps.into(),
            bytes: Vec::new(),
            calls: 0,
            flushes: 0,
            flush_error: false,
        }
    }
}

impl Write for ShortWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.write_vectored(&[io::IoSlice::new(buffer)])
    }

    fn write_vectored(&mut self, buffers: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.calls += 1;
        let limit = self
            .steps
            .pop_front()
            .unwrap_or(Ok(usize::MAX))
            .map_err(io::Error::from)?;
        let mut remaining = limit;
        let mut count = 0;
        for part in buffers {
            let take = part.len().min(remaining);
            self.bytes.extend_from_slice(&part[..take]);
            count += take;
            remaining -= take;
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.flush_error {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        } else {
            Ok(())
        }
    }
}

#[test]
fn coalesced_frame_partial_header_body_and_interrupt_preserve_exact_wire_bytes() {
    let mut writer = ShortWriter::new(vec![
        Err(io::ErrorKind::Interrupted),
        Ok(2),
        Ok(3),
        Err(io::ErrorKind::Interrupted),
        Ok(4),
    ]);
    let payload = b"synthetic-closure-frame";
    assert_eq!(write_coalesced_bounded_frame(&mut writer, payload), Ok(()));
    let mut expected = (payload.len() as u32).to_be_bytes().to_vec();
    expected.extend_from_slice(payload);
    assert_eq!(writer.bytes, expected);
    assert_eq!(writer.calls, 6);
    assert_eq!(writer.flushes, 1);
}

#[test]
fn coalesced_frame_zero_or_failed_write_stops_without_flush_or_replay() {
    for final_step in [
        Ok(0),
        Err(io::ErrorKind::TimedOut),
        Err(io::ErrorKind::BrokenPipe),
    ] {
        let mut writer = ShortWriter::new(vec![Ok(5), final_step, Ok(usize::MAX)]);
        assert_eq!(
            write_coalesced_bounded_frame(&mut writer, b"fixture"),
            Err(HaError::Transport)
        );
        assert_eq!(writer.bytes, [0, 0, 0, 7, b'f']);
        assert_eq!(writer.calls, 2);
        assert_eq!(writer.flushes, 0);
        assert_eq!(writer.steps.len(), 1);
    }
}

#[test]
fn coalesced_frame_empty_and_oversized_refuse_before_any_write() {
    for payload in [Vec::new(), vec![0x61; MAX_PAYLOAD_BYTES + 4097]] {
        let mut writer = ShortWriter::new(Vec::new());
        assert_eq!(
            write_coalesced_bounded_frame(&mut writer, &payload),
            Err(HaError::InvalidFrame)
        );
        assert_eq!(writer.calls, 0);
        assert_eq!(writer.flushes, 0);
        assert!(writer.bytes.is_empty());
    }
}

#[test]
fn coalesced_frame_exact_maximum_and_flush_failure_keep_wire_bound() {
    let payload = vec![0x62; MAX_PAYLOAD_BYTES + 4096];
    let mut writer = ShortWriter::new(Vec::new());
    writer.flush_error = true;
    assert_eq!(
        write_coalesced_bounded_frame(&mut writer, &payload),
        Err(HaError::Transport)
    );
    assert_eq!(writer.bytes.len(), payload.len() + 4);
    assert_eq!(&writer.bytes[..4], &(payload.len() as u32).to_be_bytes());
    assert_eq!(&writer.bytes[4..], payload);
    assert_eq!(writer.calls, 1);
    assert_eq!(writer.flushes, 1);
}
