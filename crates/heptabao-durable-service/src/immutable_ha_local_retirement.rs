//! The existing File retirement transaction under a live application HA owner.
//! This adapter is the same trusted server/durable boundary as the shared GC
//! physical-owner trait. Names and hashes are DATA, never standalone authority.
//! The production implementation is privately constructed only while the real
//! Raft writers, shared-store quiescence, typed history and original Actor live.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHaLocalRetirementBoundary {
    KnownPending,
    PhysicalCompleted,
}

/// Implementations must retain the original application authorities through
/// the entire call. The only production implementation borrows its live HA
/// guard; no HTTP body, serialized record or caller Boolean can construct it.
/// This public embedding interface does not sandbox arbitrary Rust callers.
pub trait NativeHaLocalRetentionOwner {
    fn catalog_sha256(&self) -> [u8; 32];
    fn typed_retained_resources(&self) -> &BTreeSet<String>;
    fn verify(&self) -> Result<(), ServiceError>;
    /// A veto-only observation emitted by the actual lower transaction.
    /// Receiving this value does not mint a pending or physical authority.
    fn verify_boundary(
        &self,
        _boundary: NativeHaLocalRetirementBoundary,
    ) -> Result<(), ServiceError> {
        self.verify()
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Retire,
    Reconcile([u8; 32]),
}

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    /// The ordinary File entry retains its exact three-selector allowlist.
    /// Only the separate HA entry may admit the four exact current selectors
    /// and completed HA ledgers, after binding the real registered catalog.
    pub(super) fn check_immutable_retirement_catalog(
        &mut self,
        catalog: RetirementCatalog,
        conditions: &[PublicationCondition],
        before: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        match catalog {
            RetirementCatalog::Standalone => {
                for leaf in self.list("system", "state-native-v6")? {
                    if !matches!(
                        leaf.as_str(),
                        "active-publication-cursor" | "active-source-root" | "file-retirement"
                    ) {
                        return Err(ServiceError::UnsupportedProfile);
                    }
                }
            }
            RetirementCatalog::NativeHa => {
                const REQUIRED: [&str; 4] = [
                    "state",
                    "state-native-v6/active-publication-cursor",
                    "state-native-v6/active-source-root",
                    "state-native-v6/ha-publication-cursor",
                ];
                before()?;
                if conditions.len() != REQUIRED.len()
                    || REQUIRED.iter().any(|name| {
                        conditions
                            .iter()
                            .filter(|condition| {
                                condition.resource == *name && condition.expected.is_some()
                            })
                            .count()
                            != 1
                    })
                {
                    return Err(ServiceError::InvalidResource);
                }
                self.ensure_no_pending_ha_shared_retirement()?;
                self.ensure_no_pending_ha_intent_retirement()?;
                if self.get("system", "state-native-v6")?.is_some()
                    || self.get("system", "state-records/v6")?.is_some()
                {
                    return Err(ServiceError::UnsupportedProfile);
                }
                for leaf in self.list("system", "state-native-v6")? {
                    before()?;
                    if !matches!(
                        leaf.as_str(),
                        "active-publication-cursor"
                            | "active-source-root"
                            | "ha-publication-cursor"
                            | "file-retirement"
                            | "ha-shared-retirement"
                            | "ha-intent-retirement"
                    ) {
                        return Err(ServiceError::UnsupportedProfile);
                    }
                }
                before()?;
            }
        }
        Ok(())
    }

    fn bind_native_ha_local_retirement(
        &mut self,
        request: &mut ImmutableRetirementRequest,
        owner: &impl NativeHaLocalRetentionOwner,
        operation: Operation,
    ) -> Result<[u8; 32], ServiceError> {
        owner.verify()?;
        self.check_immutable_source_session(&request.session)?;
        let fingerprint = owner.catalog_sha256();
        let historical = owner.typed_retained_resources();
        if fingerprint == [0; 32]
            || historical.is_empty()
            || historical.len() > MAX_OBJECTS
            || request.session.namespace != "system"
            || request.session.resource != "state"
            || request.retained_resources.is_empty()
            || request.retained_resources.len() > MAX_OBJECTS
            || request
                .conditions
                .iter()
                .find(|condition| condition.resource == "state")
                .and_then(|condition| condition.expected.as_ref())
                .map(Secret::expose)
                != Some(request.session.root.expose())
        {
            return Err(ServiceError::InvalidResource);
        }
        self.check_immutable_retirement_catalog(
            RetirementCatalog::NativeHa,
            &request.conditions,
            &mut || owner.verify(),
        )?;
        self.check_retirement_conditions(&request.conditions)?;
        match operation {
            Operation::Retire => self.ensure_no_pending_immutable_retirement()?,
            Operation::Reconcile(expected) => {
                let (bytes, record) = self
                    .retirement_record()?
                    .ok_or(ServiceError::PublicationConditionConflict)?;
                if record.phase.is_terminal() || raw_digest(bytes.expose()) != expected {
                    return Err(ServiceError::PublicationConditionConflict);
                }
                // Pending removed these markers from the registered catalog.
                // The fresh complete history may now retain one of those old
                // resources: check it BEFORE taking registered ∩ historical.
                // An absent old leaf is equally a hold; it cannot justify
                // publishing a false AbsenceConfirmed retirement result.
                for entry in &record.entries {
                    owner.verify()?;
                    if historical.contains(&entry.slot.resource) {
                        return Err(ServiceError::PublicationConditionConflict);
                    }
                }
            }
        }
        let mut registered = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        for ((namespace, resource), value) in &self.snapshot.entries {
            owner.verify()?;
            if namespace != "system" || !resource.starts_with(OBJECT_PREFIX) {
                continue;
            }
            let slot = Slot::decode(resource, value.expose())?;
            if slot.locator.store_id() != request.session.store_id
                || !addresses.insert((slot.locator.store_id(), slot.locator.address()))
            {
                return Err(ServiceError::CorruptState);
            }
            if registered.len() >= MAX_OBJECTS {
                return Err(ServiceError::RequestCapacityExhausted);
            }
            registered.insert(resource.clone());
        }
        // The request initially carries only the actual full current local
        // materializer's result. It must belong to BOTH independently observed
        // catalogs. The registered historical intersection is computed here,
        // never accepted as an HTTP/cached deletion list.
        if !request.retained_resources.is_subset(&registered)
            || !request.retained_resources.is_subset(historical)
        {
            return Err(ServiceError::CorruptState);
        }
        owner.verify()?;
        self.check_immutable_source_session(&request.session)?;
        self.check_retirement_conditions(&request.conditions)?;
        if owner.catalog_sha256() != fingerprint {
            return Err(ServiceError::PublicationConditionConflict);
        }
        request.retained_resources = registered.intersection(historical).cloned().collect();
        owner.verify()?;
        Ok(fingerprint)
    }

    /// Keeps one actual HA custody alive through the original bounded local
    /// Pending/descriptor-authentication/unlink/fsync/Complete transaction.
    pub fn retire_native_ha_local_immutable_objects(
        &mut self,
        mut request: ImmutableRetirementRequest,
        owner: &impl NativeHaLocalRetentionOwner,
    ) -> Result<ImmutableRetirementOutcome, ServiceError> {
        let fingerprint =
            self.bind_native_ha_local_retirement(&mut request, owner, Operation::Retire)?;
        self.retire_immutable_objects_owned(
            request,
            &mut || {
                owner.verify()?;
                if owner.catalog_sha256() != fingerprint {
                    return Err(ServiceError::PublicationConditionConflict);
                }
                Ok(())
            },
            RetirementCatalog::NativeHa,
            &mut |boundary| owner.verify_boundary(boundary),
        )
    }

    /// An old Pending record supplies only exact ciphertext/locator data. A
    /// fresh complete current mark and the newly held real historical owner
    /// are mandatory, including when every old leaf is already absent.
    pub fn reconcile_native_ha_local_immutable_retirement(
        &mut self,
        mut request: ImmutableRetirementRequest,
        expected_pending: [u8; 32],
        owner: &impl NativeHaLocalRetentionOwner,
    ) -> Result<ImmutableRetirementOutcome, ServiceError> {
        let fingerprint = self.bind_native_ha_local_retirement(
            &mut request,
            owner,
            Operation::Reconcile(expected_pending),
        )?;
        self.reconcile_pending_immutable_retirement_owned(
            request,
            expected_pending,
            &mut || {
                owner.verify()?;
                if owner.catalog_sha256() != fingerprint {
                    return Err(ServiceError::PublicationConditionConflict);
                }
                Ok(())
            },
            RetirementCatalog::NativeHa,
            &mut |boundary| owner.verify_boundary(boundary),
        )
    }
}
