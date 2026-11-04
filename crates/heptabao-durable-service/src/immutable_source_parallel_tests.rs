//! Owned real-file tests for the borrowed reader. TestBarrier is deliberately
//! nonproduction: these are source/gate/failure tests, not crypto qualification.
use super::*;
use crate::tests::{TestBarrier, TestRoot, put_request, serial_test};
use std::sync::Barrier as ThreadBarrier;
type TestResult = Result<(), Box<dyn std::error::Error>>;
const ROOT: &[u8] = b"parallel-reader-owned-source";
const CONTEXT: &[u8] = b"parallel-reader-owned-context";
const STORE: [u8; 16] = [0x48; 16];

fn source(owner: &mut DurableService<TestBarrier>) -> Result<ImmutableSourceSession, ServiceError> {
    owner.immutable_source_session("root/team-a", "secret/application", ROOT, STORE)
}
fn locator() -> Result<BlobLocator, BackendError> {
    BlobLocator::new(STORE, [0x91; 32])
}

#[test]
fn borrowed_file_reader_keeps_same_session_and_full_gates_across_four_scoped_workers() -> TestResult
{
    let _serial = serial_test();
    let root = TestRoot::new("parallel-file-four")?;
    let mut owner = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
    owner.put(put_request("source", ROOT)?)?;
    let session = source(&mut owner)?;
    // The actual physical bound is 512 KiB including barrier overhead.
    // 256 KiB of plaintext still crosses the positioned-read chunk boundary.
    let payload = vec![0x23; 256 * 1024];
    let pin = owner.stage_immutable_object_before_publish(
        &session,
        locator()?,
        CONTEXT,
        &payload,
        &mut || Ok(()),
    )?;
    let length = pin.ciphertext_len();
    drop(pin);
    let generation = owner.generation();
    let mut serial_gates = 0usize;
    let mut gate = || {
        serial_gates += 1;
        Ok(())
    };
    let original =
        owner.pin_immutable_object_before_read(&session, locator()?, length, &mut gate)?;
    assert_eq!(
        owner
            .read_immutable_object_before_delivery(&session, &original, CONTEXT, &mut gate)?
            .as_slice(),
        payload
    );
    drop(original);
    assert!(serial_gates > 8);
    {
        let view = owner.borrow_file_immutable_reader()?;
        fn assert_sync<T: Sync>(_: &T) {}
        assert_sync(&view);
        let rendezvous = ThreadBarrier::new(4);
        std::thread::scope(|scope| -> Result<(), ServiceError> {
            let mut handles = Vec::new();
            for _ in 0..4 {
                let view = &view;
                let session = &session;
                let payload = &payload;
                let rendezvous = &rendezvous;
                handles.push(scope.spawn(move || -> Result<usize, ServiceError> {
                    rendezvous.wait();
                    let mut gates = 0;
                    let mut before = || {
                        gates += 1;
                        Ok(())
                    };
                    for _ in 0..3 {
                        let pin = view.pin_immutable_object_before_read(
                            session,
                            locator().map_err(map_backend_error)?,
                            length,
                            &mut before,
                        )?;
                        let bytes = view.read_immutable_object_before_delivery(
                            session,
                            &pin,
                            CONTEXT,
                            &mut before,
                        )?;
                        assert_eq!(bytes.as_slice(), payload);
                    }
                    Ok(gates)
                }));
            }
            for handle in handles {
                assert_eq!(
                    handle
                        .join()
                        .map_err(|_| ServiceError::RecoveryRequired)??,
                    serial_gates * 3
                );
            }
            Ok(())
        })?;
    }
    assert!(!owner.recovery_required());
    assert_eq!(owner.generation(), generation);
    assert_eq!(
        owner
            .get("root/team-a", "secret/application")?
            .ok_or("missing source")?
            .expose(),
        ROOT
    );
    Ok(())
}

#[test]
fn borrowed_file_reader_preserves_every_original_failure_boundary() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("parallel-file-gates")?;
    let mut owner = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
    owner.put(put_request("source", ROOT)?)?;
    let session = source(&mut owner)?;
    let pin = owner.stage_immutable_object_before_publish(
        &session,
        locator()?,
        CONTEXT,
        b"private-fixture",
        &mut || Ok(()),
    )?;
    let length = pin.ciphertext_len();
    drop(pin);
    let mut count = 0;
    let mut before = || {
        count += 1;
        Ok(())
    };
    let pin = owner.pin_immutable_object_before_read(&session, locator()?, length, &mut before)?;
    owner.read_immutable_object_before_delivery(&session, &pin, CONTEXT, &mut before)?;
    drop(pin);
    {
        let view = owner.borrow_file_immutable_reader()?;
        for fail_at in 1..=count {
            let mut seen = 0usize;
            let mut before = || {
                seen += 1;
                if seen == fail_at {
                    Err(ServiceError::ReplayEpochMismatch)
                } else {
                    Ok(())
                }
            };
            let result = view
                .pin_immutable_object_before_read(&session, locator()?, length, &mut before)
                .and_then(|pin| {
                    view.read_immutable_object_before_delivery(&session, &pin, CONTEXT, &mut before)
                });
            assert!(matches!(result, Err(ServiceError::ReplayEpochMismatch)));
            assert_eq!(seen, fail_at);
        }
        assert!(
            view.pin_immutable_object_before_read(&session, locator()?, length + 1, &mut || Ok(()))
                .is_err()
        );
    }
    assert!(!owner.recovery_required());
    Ok(())
}

#[test]
fn borrowed_file_reader_rejects_foreign_source_and_wrong_context_without_write() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("parallel-file-owner")?;
    let foreign_root = TestRoot::new("parallel-file-foreign")?;
    let barrier = TestBarrier::new();
    let mut owner = DurableService::create_new(&root.0, barrier.clone(), 16)?;
    let mut foreign = DurableService::create_new(&foreign_root.0, barrier, 16)?;
    owner.put(put_request("source", ROOT)?)?;
    foreign.put(put_request("source", ROOT)?)?;
    let session = source(&mut owner)?;
    let foreign_session = source(&mut foreign)?;
    let pin = owner.stage_immutable_object_before_publish(
        &session,
        locator()?,
        CONTEXT,
        b"private-fixture",
        &mut || Ok(()),
    )?;
    let length = pin.ciphertext_len();
    drop(pin);
    let generation = owner.generation();
    {
        let view = owner.borrow_file_immutable_reader()?;
        assert!(matches!(
            view.verify_immutable_source_session(&foreign_session),
            Err(ServiceError::PublicationConditionConflict)
        ));
        let pin =
            view.pin_immutable_object_before_read(&session, locator()?, length, &mut || Ok(()))?;
        assert!(matches!(
            view.read_immutable_object_before_delivery(
                &session,
                &pin,
                b"other-context",
                &mut || Ok(())
            ),
            Err(ServiceError::BarrierFailure)
        ));
    }
    assert_eq!(owner.generation(), generation);
    assert!(!owner.recovery_required());
    Ok(())
}

#[test]
fn borrowed_file_reader_latches_injected_owner_failure_back_into_original_service() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("parallel-file-latched-owner")?;
    let mut owner = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
    owner.put(put_request("source", ROOT)?)?;
    let session = source(&mut owner)?;
    {
        let view = owner.borrow_file_immutable_reader()?;
        // Inject a backend ownership-loss notification into the same private
        // failure path used after backend.verify() fails. The real directory
        // descriptor deliberately survives pathname/mode changes; those changes
        // are not an ownership fault. This is a latch unit test, not a claim
        // that a physical disk failure was induced.
        view.latch_ownership_failure();
        assert!(matches!(
            view.verify_immutable_source_session(&session),
            Err(ServiceError::RecoveryRequired)
        ));
        assert!(matches!(
            view.get("root/team-a", "secret/application"),
            Err(ServiceError::RecoveryRequired)
        ));
    }
    assert!(owner.recovery_required());
    assert!(matches!(
        owner.verify_live_ownership(),
        Err(ServiceError::RecoveryRequired)
    ));
    Ok(())
}

struct SerialOnly(FileBackend);
impl DurableBackend for SerialOnly {
    fn close(self) -> Result<(), BackendError> {
        self.0.close()
    }
    fn verify(&self) -> Result<(), BackendError> {
        self.0.verify()
    }
    fn load(&mut self) -> Result<BackendBundle, BackendError> {
        self.0.load()
    }
    fn initialize_empty(&mut self, bundle: &BackendBundle) -> Result<(), BackendError> {
        self.0.initialize_empty(bundle)
    }
    fn append_journal(&mut self, len: usize, bytes: &[u8]) -> Result<usize, BackendError> {
        self.0.append_journal(len, bytes)
    }
    fn truncate_journal(&mut self, len: usize, new_len: usize) -> Result<(), BackendError> {
        self.0.truncate_journal(len, new_len)
    }
    fn publish_checkpoint(
        &mut self,
        old: &BackendBundle,
        new: &BackendBundle,
    ) -> Result<(), BackendError> {
        self.0.publish_checkpoint(old, new)
    }
}
#[test]
fn borrowed_file_reader_is_not_inferred_for_other_backends() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("parallel-file-serial-fallback")?;
    let backend = SerialOnly(FileBackend::create_new(&root.0)?);
    let mut owner = DurableService::create_new_with_backend(backend, TestBarrier::new(), 16)?;
    assert!(!owner.has_file_immutable_reader());
    assert!(matches!(
        owner.borrow_file_immutable_reader(),
        Err(ServiceError::UnsupportedProfile)
    ));
    assert!(!owner.recovery_required());
    Ok(())
}

#[test]
fn borrowed_file_reader_injected_failure_is_latched_even_when_view_is_abandoned() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("parallel-file-abandoned-failure")?;
    let mut owner = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
    owner.put(put_request("source", ROOT)?)?;
    let session = source(&mut owner)?;
    let view = owner.borrow_file_immutable_reader()?;
    // Same explicit unit-level ownership-loss injection as the test above.
    // Forgetting the borrowed view must not discard an already observed failure.
    view.latch_ownership_failure();
    assert!(matches!(
        view.verify_immutable_source_session(&session),
        Err(ServiceError::RecoveryRequired)
    ));
    // Keep the same borrowed view without running its destructor, including
    // if the view later acquires Drop. The owner must already retain the fault.
    let _abandoned = std::mem::ManuallyDrop::new(view);
    assert!(owner.recovery_required());
    assert!(matches!(
        owner.verify_live_ownership(),
        Err(ServiceError::RecoveryRequired)
    ));
    Ok(())
}
