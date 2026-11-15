//! Read-only floor2 payload source borrowed by scoped lossless-export workers.
//! It owns no new Actor, source root, deadline, publication or TLS admission.
use super::*;
use heptabao_durable_service::FileImmutableSourceReader;
use std::sync::atomic::AtomicBool;

pub(in crate::service) struct NativeFileSource<'a, F> {
    durable: FileImmutableSourceReader<'a, AeadBarrier>,
    session: ImmutableSourceSession,
    deadline: OriginalDeadline,
    original_gate: F,
    stopped: &'a AtomicBool,
    #[cfg(test)]
    payload_open_pause: std::sync::Mutex<Option<PayloadOpenPause>>,
}
impl<'a, F: Fn() -> Result<(), ServiceError> + Sync> NativeFileSource<'a, F> {
    pub(in crate::service) fn new_checked(
        durable: &'a mut DurableService<AeadBarrier>,
        deadline: OriginalDeadline,
        original_gate: F,
        stopped: &'a AtomicBool,
    ) -> Result<Self, RecordError> {
        if stopped.load(Ordering::Acquire) {
            return Err(RecordError::Invalid);
        }
        original_gate().map_err(|_| RecordError::Invalid)?;
        deadline.check().map_err(|_| RecordError::Invalid)?;
        durable
            .verify_live_ownership()
            .map_err(|_| RecordError::Corrupt)?;
        let root = durable
            .get("system", "state")
            .map_err(|_| RecordError::Corrupt)?
            .ok_or(RecordError::Missing)?;
        #[derive(Deserialize)]
        struct Frontier {
            #[serde(default)]
            reader_floor: Option<crate::state_record_root_v6::ReaderFloor>,
        }
        let frontier: Frontier =
            serde_json::from_slice(root.expose()).map_err(|_| RecordError::Corrupt)?;
        if frontier
            .reader_floor
            .is_none_or(|floor| floor.native_kv2_format != 2)
        {
            return Err(RecordError::Invalid);
        }
        let session = session(durable, root.expose()).map_err(|_| RecordError::Corrupt)?;
        deadline.check().map_err(|_| RecordError::Invalid)?;
        original_gate().map_err(|_| RecordError::Invalid)?;
        let durable = durable
            .borrow_file_immutable_reader()
            .map_err(|_| RecordError::Corrupt)?;
        Ok(Self {
            durable,
            session,
            deadline,
            original_gate,
            stopped,
            #[cfg(test)]
            payload_open_pause: std::sync::Mutex::new(
                AFTER_PAYLOAD_OPEN_PAUSE.with(|slot| slot.borrow_mut().take()),
            ),
        })
    }

    fn before(&self) -> Result<(), ServiceError> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(ServiceError::BarrierFailure);
        }
        self.deadline
            .check()
            .map_err(|_| ServiceError::BarrierFailure)?;
        (self.original_gate)()?;
        self.deadline
            .check()
            .map_err(|_| ServiceError::BarrierFailure)?;
        if self.stopped.load(Ordering::Acquire) {
            return Err(ServiceError::BarrierFailure);
        }
        Ok(())
    }

    /// The consuming writer repeats the actual original owner/source checks
    /// after waiting for an ordered result, before any bytes reach its decoder.
    pub(in crate::service) fn before_delivery(&self) -> Result<(), RecordError> {
        let result = (|| {
            self.before().map_err(|_| RecordError::Invalid)?;
            self.durable
                .verify_immutable_source_session(&self.session)
                .map_err(|_| RecordError::Corrupt)?;
            self.before().map_err(|_| RecordError::Invalid)
        })();
        if result.is_err() {
            self.stopped.store(true, Ordering::Release);
        }
        result
    }

    pub(in crate::service) fn read_paged_payload(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        let result = self.read_checked(domain, reference);
        if result.is_err() {
            self.stopped.store(true, Ordering::Release);
        }
        result
    }

    fn read_checked(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        if !matches!(domain, ObjectDomain::Kv2(_))
            || reference.kind != crate::state_records::ObjectKind::Block
        {
            return Err(RecordError::Invalid);
        }
        self.before().map_err(|_| RecordError::Invalid)?;
        let resource = v6_records::native_resource(domain, reference);
        let stored = self
            .durable
            .get("system", &resource)
            .map_err(|_| RecordError::Corrupt)?
            .ok_or(RecordError::Missing)?;
        self.deadline.check().map_err(|_| RecordError::Invalid)?;
        // Floor2 never admits inline logical bytes as a physical payload.
        let slot = Slot::decode(stored.expose(), reference)?;
        if slot.locator.store_id() != self.session.store_id() {
            return Err(RecordError::Corrupt);
        }
        let mut before = || self.before();
        let pin = self
            .durable
            .pin_immutable_object_before_read(
                &self.session,
                slot.locator,
                slot.ciphertext_bytes,
                &mut before,
            )
            .map_err(|_| RecordError::Corrupt)?;
        let plaintext = self
            .durable
            .read_immutable_object_before_delivery_observed(
                &self.session,
                &pin,
                &context_for_resource(&resource),
                &mut before,
                &mut |event| {
                    #[cfg(test)]
                    if matches!(
                        event,
                        ImmutableObjectReadObservation::PlaintextOpened { .. }
                    ) {
                        // Move this already-armed test observation once from the
                        // original request thread. It creates no production hook.
                        let pause = self
                            .payload_open_pause
                            .lock()
                            .ok()
                            .and_then(|mut slot| slot.take());
                        if let Some(pause) = pause {
                            pause.fired.store(true, Ordering::SeqCst);
                            std::thread::sleep(pause.delay);
                        }
                    }
                    #[cfg(not(test))]
                    let _ = event;
                },
            )
            .map_err(|_| RecordError::Corrupt)?;
        if plaintext.len() != slot.plaintext_bytes {
            return Err(RecordError::Corrupt);
        }
        self.deadline.check().map_err(|_| RecordError::Invalid)?;
        if self.stopped.load(Ordering::Acquire) {
            return Err(RecordError::Invalid);
        }
        Ok(plaintext)
    }
}
