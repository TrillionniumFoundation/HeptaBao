//! A data-only owner/root derivation within the original authenticated pack.
//! No storage publication occurs until the existing restore transaction.
use super::*;

pub(super) fn read_member_ciphertext<R: Read + Seek>(
    reader: &mut R,
    member: &Member,
    output: &mut [u8],
    gate: &mut impl FnMut() -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    if let Some(bytes) = &member.projected_ciphertext {
        gate()?;
        if output.len() != bytes.len() {
            return Err(ServiceError::CorruptState);
        }
        output.copy_from_slice(bytes);
        gate()
    } else {
        seek_checked(reader, SeekFrom::Start(member.offset), gate)?;
        read_exact_checked(reader, output, gate)
    }
}

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    /// Facts for a new derived checkpoint. These numbers grant no caller or
    /// application authority and are checked again against the same handle.
    pub fn v6_restore_projection_target<R>(
        &self,
        prepared: &PreparedV6Restore<R>,
    ) -> Result<(u64, u64), ServiceError> {
        if prepared.projected {
            return Err(ServiceError::RequestBindingConflict);
        }
        self.v6_projection_target(&prepared.state)
    }

    /// The application must have authenticated the whole incoming typed graph,
    /// inherited only permitted live clocks, and validated every protected
    /// floor. This consumes that data projection into the SAME affine pack.
    /// Root/cursor replacements and newly sealed owner objects remain memory
    /// only until restore_v6_prepared's real pin/transaction checks run.
    pub fn project_v6_restore_before_install<R: Read + Seek>(
        &self,
        prepared: &mut PreparedV6Restore<R>,
        target: (u64, u64),
        source_root: &[u8],
        root: Secret,
        cursor: Secret,
        objects: Vec<(String, Secret)>,
        gate: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        gate()?;
        if self.v6_restore_projection_target(prepared)? != target
            || prepared.state.get("system", "state")? != Some(source_root)
            || objects.len() > MAX_OBJECTS
        {
            return Err(ServiceError::RequestBindingConflict);
        }
        let store_id = prepared
            .members
            .first()
            .ok_or(ServiceError::CorruptState)?
            .slot
            .locator
            .store_id();
        let mut changes = vec![
            ("state".into(), root),
            ("state-native-v6/active-publication-cursor".into(), cursor),
        ];
        let mut added = Vec::new();
        let mut seen = BTreeSet::new();
        let mut addresses = prepared
            .members
            .iter()
            .map(|member| member.slot.locator.address())
            .collect::<BTreeSet<_>>();
        let mut ciphertext_bytes = prepared.size.ciphertext_bytes;
        for (resource, plaintext) in objects {
            gate()?;
            self.verify_prepared_restore(&prepared.state)?;
            if !seen.insert(resource.clone())
                || plaintext.expose().is_empty()
                || plaintext.expose().len() > MAX_IMMUTABLE_CIPHERTEXT_BYTES
            {
                return Err(ServiceError::InvalidResource);
            }
            if prepared.state.get("system", &resource)?.is_some() {
                // An existing locator is not repaired or overwritten. Read the
                // actual authenticated original archive member and compare it.
                let original = self.read_v6_restore_object(prepared, &resource, gate)?;
                if original.as_slice() != plaintext.expose() {
                    return Err(ServiceError::RequestBindingConflict);
                }
                continue;
            }
            // The typed projection cannot introduce a changed KV payload.
            if !resource.starts_with("state-records/v6/owner/") {
                return Err(ServiceError::InvalidResource);
            }
            if prepared.members.len() + added.len() >= MAX_OBJECTS {
                return Err(ServiceError::RequestCapacityExhausted);
            }
            let name = resource
                .rsplit('/')
                .next()
                .ok_or(ServiceError::InvalidResource)?;
            if name.len() != 64
                || !name
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(ServiceError::InvalidResource);
            }
            let mut address = [0; 32];
            for (index, byte) in address.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&name[2 * index..2 * index + 2], 16)
                    .map_err(|_| ServiceError::InvalidResource)?;
            }
            if !addresses.insert(address) {
                return Err(ServiceError::RequestBindingConflict);
            }
            let (encoded, slot, ciphertext) = if let Some(live) = self.get("system", &resource)? {
                // The inherited clock can reproduce the ACTUAL live Auth
                // owner. Reuse its registered ciphertext exactly; sealing the
                // same plaintext again would create a different physical file
                // at this immutable address. Corruption is never repaired.
                let slot = Slot::decode(&resource, live.expose())?;
                if slot.locator.store_id() != store_id
                    || slot.plaintext_bytes != plaintext.expose().len()
                {
                    return Err(ServiceError::RequestBindingConflict);
                }
                gate()?;
                self.verify_prepared_restore(&prepared.state)?;
                let profile = self
                    .backend
                    .immutable_blob_profile()
                    .map_err(map_backend_error)?;
                let pin = self
                    .backend
                    .pin_immutable_ciphertext(slot.locator, slot.ciphertext_bytes)
                    .map_err(map_backend_error)?;
                if pin.locator() != slot.locator
                    || pin.ciphertext_len() != slot.ciphertext_bytes
                    || !pin.matches_profile(&profile)
                {
                    return Err(ServiceError::CorruptState);
                }
                let ciphertext = pin
                    .read_ciphertext_checked(&mut || {
                        gate()?;
                        self.verify_prepared_restore(&prepared.state)
                    })
                    .map_err(|error| match error {
                        PinReadError::Backend(error) => map_backend_error(error),
                        PinReadError::Gate(error) => error,
                    })?;
                gate()?;
                self.verify_prepared_restore(&prepared.state)?;
                let actual = Zeroizing::new(
                    self.barrier
                        .open(&slot.aad(), &ciphertext)
                        .map_err(|_| ServiceError::BarrierFailure)?,
                );
                if actual.as_slice() != plaintext.expose() {
                    return Err(ServiceError::RequestBindingConflict);
                }
                gate()?;
                self.verify_prepared_restore(&prepared.state)?;
                (live.expose().to_vec(), slot, ciphertext)
            } else {
                let mut aad = OBJECT_AAD.to_vec();
                aad.extend_from_slice(resource.as_bytes());
                let ciphertext = Arc::new(Zeroizing::new(
                    self.barrier
                        .seal(&aad, plaintext.expose())
                        .map_err(|_| ServiceError::BarrierFailure)?,
                ));
                if ciphertext.len() > MAX_IMMUTABLE_CIPHERTEXT_BYTES {
                    return Err(ServiceError::RequestCapacityExhausted);
                }
                let mut encoded = Vec::with_capacity(72);
                encoded.extend_from_slice(SLOT_MAGIC);
                encoded.extend_from_slice(&store_id);
                encoded.extend_from_slice(&address);
                encoded.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
                encoded.extend_from_slice(&(plaintext.expose().len() as u32).to_be_bytes());
                let slot = Slot::decode(&resource, &encoded)?;
                (encoded, slot, ciphertext)
            };
            ciphertext_bytes = ciphertext_bytes
                .checked_add(ciphertext.len() as u64)
                .filter(|bytes| *bytes <= MAX_OBJECT_BYTES)
                .ok_or(ServiceError::RequestCapacityExhausted)?;
            let digest = accelerated_sha256(&ciphertext)?;
            changes.push((resource, Secret::new(encoded)?));
            added.push(Member {
                slot,
                offset: 0,
                digest,
                projected_ciphertext: Some(ciphertext),
            });
            gate()?;
        }
        let state = self.project_prepared_v6_state(&prepared.state, target, changes, gate)?;
        gate()?;
        self.verify_prepared_restore(&prepared.state)?;
        // All fallible work precedes these moves; an error never exposes a
        // half-derived handle. The original source size/identity is retained.
        prepared.state = state;
        prepared.members.extend(added);
        prepared
            .members
            .sort_by(|a, b| a.slot.resource.cmp(&b.slot.resource));
        prepared.projected = true;
        Ok(())
    }
}
