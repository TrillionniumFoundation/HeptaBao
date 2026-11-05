//! One affine permission from an actual fresh, pre-business ingress binding.
//! It authorizes only read selection; full native install/Actor gates stay put.
use super::*;
use crate::ha::NativeV6IngressSuperseded;
use crate::service::native_v6_writer::NativeFreshIngressBinding;

pub(crate) struct NativeIngressSelectionPermit {
    binding: NativeFreshIngressBinding,
    environment: LocalHaEnvironment,
    initial_read_started: Cell<bool>,
    continuation_started: Cell<bool>,
    non_readonly_entered: Cell<bool>,
    attempt_identity: Arc<()>,
}

impl NativeIngressSelectionPermit {
    pub(in crate::service) fn capture(
        service: &mut Service,
        binding: NativeFreshIngressBinding,
        ha: &Arc<Mutex<HaProcess>>,
    ) -> Result<Self, Response> {
        binding.check(service)?;
        let deadline = binding.deadline();
        let key = Zeroizing::new(**service.barrier_key.as_ref().ok_or_else(unavailable)?);
        let environment = LocalHaEnvironment::capture(service, ha, &key, deadline)?;
        let permit = Self {
            binding,
            environment,
            initial_read_started: Cell::new(false),
            continuation_started: Cell::new(false),
            non_readonly_entered: Cell::new(false),
            attempt_identity: Arc::new(()),
        };
        permit.check(service)?;
        Ok(permit)
    }

    pub(in crate::service) fn check(&self, service: &mut Service) -> Result<(), Response> {
        let result = (|| {
            self.binding.check(service)?;
            self.environment.check(service)?;
            service
                .durable
                .as_mut()
                .ok_or_else(unavailable)?
                .verify_live_ownership()
                .map_err(storage_rejected)?;
            self.binding.check(service)
        })();
        if result.is_err() {
            self.refuse_reselection();
        }
        result
    }

    pub(crate) fn check_initial_read(
        &self,
        deadline: OriginalDeadline,
        local_root: [u8; 32],
    ) -> Result<(), String> {
        if self.initial_read_started.replace(true)
            || self.non_readonly_entered.get()
            || deadline.instant() != self.binding.deadline().instant()
            || local_root != self.binding.identity().digest()
            || crate::request_deadline::current() != Some(deadline.instant())
        {
            self.refuse_reselection();
            return Err("native ingress selection permission is not fresh or bound".into());
        }
        let result = deadline.check().map_err(|e| e.to_string());
        if result.is_err() {
            self.refuse_reselection();
        }
        result
    }

    pub(crate) fn check_superseded_read(
        &self,
        source: &NativeV6IngressSuperseded,
    ) -> Result<(), String> {
        if !self.initial_read_started.get()
            || self.non_readonly_entered.get()
            || self.continuation_started.replace(true)
            || !source.same_request_attempt(&self.attempt_identity)
            || source.previous_root_digest() != self.binding.identity().digest()
            || source.operation_deadline() != self.binding.deadline().instant()
            || crate::request_deadline::current() != Some(source.operation_deadline())
            || Instant::now() >= source.read_deadline().min(source.operation_deadline())
        {
            self.refuse_reselection();
            return Err("native ingress continuation changed original selection or bound".into());
        }
        let result = self.binding.deadline().check().map_err(|e| e.to_string());
        if result.is_err() {
            self.refuse_reselection();
        }
        result
    }

    pub(crate) fn refuse_reselection(&self) {
        self.non_readonly_entered.set(true);
    }
    pub(crate) fn attempt_identity(&self) -> Arc<()> {
        Arc::clone(&self.attempt_identity)
    }

    #[cfg(test)]
    pub(in crate::service) fn reselection_is_refused(&self) -> bool {
        self.non_readonly_entered.get()
    }

    pub(in crate::service) fn finish(
        self,
        service: &mut Service,
        ha: &Arc<Mutex<HaProcess>>,
        source: NativeV6IngressSuperseded,
    ) -> Result<CommittedNativeV6Read, Response> {
        self.check(service)?;
        if !Arc::ptr_eq(ha, &self.environment.ha) {
            return Err(unavailable());
        }
        let read = {
            let process = ha.lock_for_request().map_err(|_| unavailable())?;
            process
                .complete_native_v6_ingress_reselection(source, &self)
                .map_err(|_| unavailable())?
        };
        // Keep the SAME seal memo and original request across the new read.
        self.check(service)?;
        Ok(read)
    }
}
