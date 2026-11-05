use super::*;
use crate::state_records::{AddressKey, ObjectId, StagedObject};
use std::collections::HashSet;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;

fn request() -> ReadResult<(RequestDeadlineScope, OriginalDeadline)> {
    let scope = RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(15));
    let deadline = OriginalDeadline::capture().map_err(|_| RecordError::Invalid)?;
    Ok((scope, deadline))
}
struct Active<'a>(&'a AtomicUsize);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
fn engine_error(_: RecordError) -> crate::engines::EngineError {
    super::super::rejected()
}

#[test]
fn lossless_prefetch_bounds_workers_refs_bytes_and_repeated_fresh_reads() -> ReadResult<()> {
    let key = AddressKey::from_bytes([181; 32]);
    let large = StagedObject::payload_block(&key, &vec![11; crate::state_records::BLOCK_BYTES])?;
    let small = StagedObject::payload_block(&key, b"small")?;
    let references = std::iter::repeat_n(large.reference().clone(), 40)
        .chain(std::iter::repeat_n(small.reference().clone(), 80))
        .collect::<Vec<_>>();
    let (_scope, deadline) = request()?;
    let stop = AtomicBool::new(false);
    let release = AtomicBool::new(false);
    let calls = AtomicUsize::new(0);
    let active = AtomicUsize::new(0);
    let peak_active = AtomicUsize::new(0);
    let delivered = AtomicUsize::new(0);
    let threads = Mutex::new(HashSet::new());
    let (entered_tx, entered_rx) = mpsc::sync_channel(4);
    let source = |reference: &ObjectRef| {
        if request_deadline::current() != Some(deadline.instant()) {
            return Err(RecordError::Invalid);
        }
        threads
            .lock()
            .map_err(|_| RecordError::Invalid)?
            .insert(std::thread::current().id());
        let count = active.fetch_add(1, Ordering::AcqRel) + 1;
        let _active = Active(&active);
        peak_active.fetch_max(count, Ordering::AcqRel);
        let call = calls.fetch_add(1, Ordering::AcqRel);
        if call < 4 {
            entered_tx.try_send(()).map_err(|_| RecordError::Invalid)?;
            while !release.load(Ordering::Acquire) {
                deadline.check().map_err(|_| RecordError::Invalid)?;
                std::thread::yield_now();
            }
        }
        let object = if reference == large.reference() {
            &large
        } else if reference == small.reference() {
            &small
        } else {
            return Err(RecordError::Corrupt);
        };
        Ok(Zeroizing::new(object.bytes().to_vec()))
    };
    let before_delivery = || {
        delivered.fetch_add(1, Ordering::AcqRel);
        Ok(())
    };
    let result = with_reader(
        references.iter().cloned().map(Ok),
        &source,
        &before_delivery,
        &|| Ok(()),
        deadline,
        &stop,
        |reader| {
            for _ in 0..4 {
                entered_rx
                    .recv_timeout(deadline.instant().saturating_duration_since(Instant::now()))
                    .map_err(|_| super::super::rejected())?;
            }
            release.store(true, Ordering::Release);
            let mut observed_count_bound = false;
            let mut observed_byte_bound = false;
            for reference in &references {
                let bytes = reader.read_object(reference).map_err(engine_error)?;
                reference.verify(&key, &bytes).map_err(engine_error)?;
                let window = reader.window.borrow();
                assert!(window.pending.len() + 1 <= MAX_OUTSTANDING);
                assert!(window.encoded_bytes + bytes.len() <= MAX_ENCODED_BYTES);
                observed_count_bound |= window.pending.len() + 1 == MAX_OUTSTANDING;
                observed_byte_bound |= window.encoded_bytes + bytes.len()
                    > MAX_ENCODED_BYTES - large.reference().encoded_bytes as usize;
            }
            assert!(observed_count_bound && observed_byte_bound);
            Ok(())
        },
    );
    assert!(result.is_ok());
    assert_eq!(calls.load(Ordering::Acquire), references.len());
    assert_eq!(delivered.load(Ordering::Acquire), references.len());
    assert_eq!(active.load(Ordering::Acquire), 0);
    assert_eq!(peak_active.load(Ordering::Acquire), 4);
    assert_eq!(threads.lock().map_err(|_| RecordError::Invalid)?.len(), 4);
    assert!(!stop.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn lossless_prefetch_reorders_completion_only_and_keeps_full_reference_identity() -> ReadResult<()>
{
    let key = AddressKey::from_bytes([182; 32]);
    let first = StagedObject::payload_block(&key, b"first")?;
    let second = StagedObject::payload_block(&key, b"second")?;
    let references = [first.reference().clone(), second.reference().clone()];
    let (_scope, deadline) = request()?;
    let stop = AtomicBool::new(false);
    let second_returning = AtomicBool::new(false);
    let source = |reference: &ObjectRef| {
        if reference == first.reference() {
            while !second_returning.load(Ordering::Acquire) {
                deadline.check().map_err(|_| RecordError::Invalid)?;
                std::thread::yield_now();
            }
            Ok(Zeroizing::new(first.bytes().to_vec()))
        } else if reference == second.reference() {
            second_returning.store(true, Ordering::Release);
            Ok(Zeroizing::new(second.bytes().to_vec()))
        } else {
            Err(RecordError::Corrupt)
        }
    };
    let result = with_reader(
        references.iter().cloned().map(Ok),
        &source,
        &|| Ok(()),
        &|| Ok(()),
        deadline,
        &stop,
        |reader| {
            for reference in &references {
                let bytes = reader.read_object(reference).map_err(engine_error)?;
                reference.verify(&key, &bytes).map_err(engine_error)?;
            }
            Ok(())
        },
    );
    assert!(result.is_ok());
    assert!(second_returning.load(Ordering::Acquire));

    for changed_field in 0..5 {
        let stop = AtomicBool::new(false);
        let delivered = AtomicUsize::new(0);
        let mut wrong = first.reference().clone();
        match changed_field {
            0 => wrong.id = ObjectId::from_bytes([8; 32]),
            1 => wrong.kind = ObjectKind::Value,
            2 => wrong.encoded_bytes += 1,
            3 => wrong.record_count += 1,
            _ => wrong.payload_bytes += 1,
        }
        let result = with_reader(
            std::iter::once(Ok(first.reference().clone())),
            &|_: &ObjectRef| Ok(Zeroizing::new(first.bytes().to_vec())),
            &|| {
                delivered.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
            &|| Ok(()),
            deadline,
            &stop,
            |reader| reader.read_object(&wrong).map(|_| ()).map_err(engine_error),
        );
        assert!(result.is_err());
        assert!(stop.load(Ordering::Acquire));
        assert_eq!(delivered.load(Ordering::Acquire), 0);
    }
    Ok(())
}

#[test]
fn lossless_prefetch_delivery_rechecks_revocation_after_source_read() -> ReadResult<()> {
    let key = AddressKey::from_bytes([183; 32]);
    let object = StagedObject::payload_block(&key, b"private")?;
    let (_scope, deadline) = request()?;
    let stop = AtomicBool::new(false);
    let revoked = AtomicBool::new(false);
    let source_calls = AtomicUsize::new(0);
    let delivery_calls = AtomicUsize::new(0);
    let result = with_reader(
        std::iter::once(Ok(object.reference().clone())),
        &|_: &ObjectRef| {
            let bytes = Zeroizing::new(object.bytes().to_vec());
            source_calls.fetch_add(1, Ordering::AcqRel);
            revoked.store(true, Ordering::Release);
            Ok(bytes)
        },
        &|| {
            delivery_calls.fetch_add(1, Ordering::AcqRel);
            if revoked.load(Ordering::Acquire) {
                Err(RecordError::Invalid)
            } else {
                Ok(())
            }
        },
        &|| Ok(()),
        deadline,
        &stop,
        |reader| {
            reader
                .read_object(object.reference())
                .map(|_| ())
                .map_err(engine_error)
        },
    );
    assert!(result.is_err());
    assert_eq!(source_calls.load(Ordering::Acquire), 1);
    assert_eq!(delivery_calls.load(Ordering::Acquire), 1);
    assert!(stop.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn lossless_prefetch_source_error_wrong_length_and_panic_join_workers() -> ReadResult<()> {
    let key = AddressKey::from_bytes([184; 32]);
    let object = StagedObject::payload_block(&key, b"private")?;
    let (_scope, deadline) = request()?;
    for failure in 0..3 {
        let stop = AtomicBool::new(false);
        let active = AtomicUsize::new(0);
        let calls = AtomicUsize::new(0);
        let result = with_reader(
            std::iter::once(Ok(object.reference().clone())),
            &|_: &ObjectRef| {
                active.fetch_add(1, Ordering::AcqRel);
                let _active = Active(&active);
                calls.fetch_add(1, Ordering::AcqRel);
                match failure {
                    0 => Err(RecordError::Missing),
                    1 => {
                        let mut bytes = object.bytes().to_vec();
                        bytes.push(0);
                        Ok(Zeroizing::new(bytes))
                    }
                    _ => panic!("synthetic bounded prefetch worker failure"),
                }
            },
            &|| Ok(()),
            &|| Ok(()),
            deadline,
            &stop,
            |reader| {
                reader
                    .read_object(object.reference())
                    .map(|_| ())
                    .map_err(engine_error)
            },
        );
        assert!(result.is_err());
        assert!(stop.load(Ordering::Acquire));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(active.load(Ordering::Acquire), 0);
    }
    Ok(())
}

#[test]
fn lossless_prefetch_writer_error_and_unconsumed_refs_close_full_queues() -> ReadResult<()> {
    let key = AddressKey::from_bytes([185; 32]);
    let object = StagedObject::payload_block(&key, b"small")?;
    let (_scope, deadline) = request()?;
    for writer_error in [true, false] {
        let stop = AtomicBool::new(false);
        let active = AtomicUsize::new(0);
        let calls = AtomicUsize::new(0);
        let result = with_reader(
            std::iter::repeat_n(Ok(object.reference().clone()), 80),
            &|_: &ObjectRef| {
                active.fetch_add(1, Ordering::AcqRel);
                let _active = Active(&active);
                calls.fetch_add(1, Ordering::AcqRel);
                Ok(Zeroizing::new(object.bytes().to_vec()))
            },
            &|| Ok(()),
            &|| Ok(()),
            deadline,
            &stop,
            |_reader| {
                if writer_error {
                    Err(super::super::output_failed())
                } else {
                    Ok(())
                }
            },
        );
        assert!(result.is_err());
        assert!(stop.load(Ordering::Acquire));
        assert_eq!(active.load(Ordering::Acquire), 0);
        assert!(calls.load(Ordering::Acquire) <= MAX_OUTSTANDING);
    }
    Ok(())
}

#[test]
fn lossless_prefetch_original_shorter_scope_and_expired_request_cannot_extend() -> ReadResult<()> {
    let key = AddressKey::from_bytes([186; 32]);
    let object = StagedObject::payload_block(&key, b"deadline")?;
    let (_scope, deadline) = request()?;
    let shorter = Instant::now() + Duration::from_secs(2);
    let nested = RequestDeadlineScope::enter(shorter);
    let stop = AtomicBool::new(false);
    let result = with_reader(
        std::iter::once(Ok(object.reference().clone())),
        &|_: &ObjectRef| {
            if request_deadline::current() != Some(shorter) {
                return Err(RecordError::Invalid);
            }
            deadline.check().map_err(|_| RecordError::Invalid)?;
            Ok(Zeroizing::new(object.bytes().to_vec()))
        },
        &|| Ok(()),
        &|| Ok(()),
        deadline,
        &stop,
        |reader| {
            reader
                .read_object(object.reference())
                .map(|_| ())
                .map_err(engine_error)
        },
    );
    assert!(result.is_ok());
    drop(nested);
    let _expired = RequestDeadlineScope::enter(Instant::now() - Duration::from_millis(1));
    let stop = AtomicBool::new(false);
    let calls = AtomicUsize::new(0);
    let result = with_reader(
        std::iter::once(Ok(object.reference().clone())),
        &|_: &ObjectRef| {
            calls.fetch_add(1, Ordering::AcqRel);
            Ok(Zeroizing::new(object.bytes().to_vec()))
        },
        &|| Ok(()),
        &|| Ok(()),
        deadline,
        &stop,
        |reader| {
            reader
                .read_object(object.reference())
                .map(|_| ())
                .map_err(engine_error)
        },
    );
    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::Acquire), 0);
    assert!(stop.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn lossless_prefetch_rejects_unadmitted_bounds_before_reading() -> ReadResult<()> {
    let key = AddressKey::from_bytes([187; 32]);
    let object = StagedObject::payload_block(&key, b"bounds")?;
    let (_scope, deadline) = request()?;
    for failure in 0..3 {
        let stop = AtomicBool::new(false);
        let calls = AtomicUsize::new(0);
        let mut reference = object.reference().clone();
        match failure {
            0 => reference.encoded_bytes = (MAX_ENCODED_BYTES + 1) as u32,
            1 => reference.encoded_bytes = 0,
            _ => reference.kind = ObjectKind::OwnerChunk,
        }
        let result = with_reader(
            std::iter::once(Ok(reference)),
            &|_: &ObjectRef| {
                calls.fetch_add(1, Ordering::AcqRel);
                Ok(Zeroizing::new(object.bytes().to_vec()))
            },
            &|| Ok(()),
            &|| Ok(()),
            deadline,
            &stop,
            |_reader| Ok(()),
        );
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert!(stop.load(Ordering::Acquire));
    }
    Ok(())
}

#[test]
fn lossless_prefetch_consumer_unwind_stops_sources_before_scoped_join() -> ReadResult<()> {
    let key = AddressKey::from_bytes([188; 32]);
    let object = StagedObject::payload_block(&key, b"unwind")?;
    let (_scope, deadline) = request()?;
    let stop = AtomicBool::new(false);
    let active = AtomicUsize::new(0);
    let observed_stop = AtomicBool::new(false);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: ExportResult<()> = with_reader(
            std::iter::once(Ok(object.reference().clone())),
            &|_: &ObjectRef| {
                active.fetch_add(1, Ordering::AcqRel);
                let _active = Active(&active);
                entered_tx.try_send(()).map_err(|_| RecordError::Invalid)?;
                loop {
                    if stop.load(Ordering::Acquire) {
                        observed_stop.store(true, Ordering::Release);
                        return Err(RecordError::Invalid);
                    }
                    deadline.check().map_err(|_| RecordError::Invalid)?;
                    std::thread::yield_now();
                }
            },
            &|| Ok(()),
            &|| Ok(()),
            deadline,
            &stop,
            |_reader| {
                entered_rx
                    .recv_timeout(deadline.instant().saturating_duration_since(Instant::now()))
                    .map_err(|_| super::super::rejected())?;
                panic!("synthetic private writer unwind");
            },
        );
    }));
    assert!(panic.is_err());
    assert!(stop.load(Ordering::Acquire));
    assert!(observed_stop.load(Ordering::Acquire));
    assert_eq!(active.load(Ordering::Acquire), 0);
    Ok(())
}
