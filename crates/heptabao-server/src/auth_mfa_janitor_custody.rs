//! Root-owned terminal receipts cannot recreate a native first-factor grant.
//! Reopening must authenticate the original private capsule before cleanup.
use super::*;
use crate::auth::sdk_namespace_custody::CiphertextOwner;
use ring::hmac;
pub(super) const FORMAT: u32 = 2;
const MAX_RECEIPTS: usize = 16384;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub(super) sequence: u64,
    pub(super) binding: NativeMfaBinding,
    pub(super) created: Timestamp,
    pub(super) eligible_at: Timestamp,
    pub(super) commitment: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Capture {
    pub(super) namespace: String,
    pub(super) namespace_id: String,
    pub(super) incarnation: u64,
    pub(super) owner_digest: [u8; 32],
    issued: u64,
    terminal_digest: [u8; 32],
    epoch: u64,
    entries: BTreeMap<String, Entry>,
    pub(super) ciphertext: Option<CiphertextOwner>,
    mac: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Locator {
    pub(super) capture: Capture,
    pub(super) enclosures: Vec<CiphertextOwner>,
    mac: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    capture: Capture,
    source_capture: [u8; 32],
    id: String,
    at: Timestamp,
    epoch: u64,
    previous: [u8; 32],
    mac: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Applied {
    receipt: [u8; 32],
    owner_digest: [u8; 32],
    at: Timestamp,
    epoch: u64,
    mac: Vec<u8>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Custody {
    pub(super) current: BTreeMap<String, Locator>,
    pub(super) terminal: Vec<Receipt>,
    pub(super) applied: Vec<Applied>,
}
fn bytes<T: Serialize + ?Sized>(value: &T) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    crate::secret_serde::to_vec(&value, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| err(503, "MFA terminal custody encoding unavailable"))
}
fn digest<T: Serialize + ?Sized>(value: &T) -> Result<[u8; 32], AuthError> {
    Ok(crate::crypto::digest(&bytes(value)?))
}
fn sign<T: Serialize>(key: &[u8], value: &T) -> Result<Vec<u8>, AuthError> {
    Ok(
        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), &bytes(value)?)
            .as_ref()
            .to_vec(),
    )
}
fn verify<T: Serialize>(key: &[u8], value: &T, mac: &[u8]) -> Result<(), AuthError> {
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), &bytes(value)?, mac)
        .map_err(|_| err(503, "MFA terminal custody MAC rejected"))
}
fn within(path: &str, boundary: &str) -> bool {
    path == boundary
        || path
            .strip_prefix(boundary)
            .is_some_and(|rest| rest.starts_with('/'))
}
impl Capture {
    pub(super) fn from_owner(
        owner: &NamespaceOwner,
        owner_digest: [u8; 32],
        epoch: u64,
        key: &[u8],
    ) -> Result<Option<Self>, AuthError> {
        let entries = owner
            .challenges
            .iter()
            .map(|(id, challenge)| challenge.queue_entry(key).map(|entry| (id.clone(), entry)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(Some(Self {
            namespace: owner.namespace.clone(),
            namespace_id: owner.namespace_id.clone(),
            incarnation: owner.incarnation,
            owner_digest,
            issued: owner.issued,
            terminal_digest: digest(&owner.terminal)?,
            epoch,
            entries,
            ciphertext: None,
            mac: Vec::new(),
        }))
    }
    pub(super) fn core_digest(&self) -> Result<[u8; 32], AuthError> {
        digest(&(
            &self.namespace,
            &self.namespace_id,
            self.incarnation,
            self.owner_digest,
            self.issued,
            self.terminal_digest,
            &self.entries,
        ))
    }
    fn payload(&self) -> impl Serialize + '_ {
        (
            b"heptabao-mfa-capsule-queue-129".as_slice(),
            &self.namespace,
            &self.namespace_id,
            self.incarnation,
            self.owner_digest,
            self.issued,
            self.terminal_digest,
            self.epoch,
            &self.entries,
            &self.ciphertext,
        )
    }
    pub(super) fn verify(&self, key: &[u8]) -> Result<(), AuthError> {
        verify(key, &self.payload(), &self.mac)
    }
}
impl Locator {
    fn payload(&self) -> impl Serialize + '_ {
        (
            b"heptabao-mfa-capsule-enclosure-chain-129".as_slice(),
            &self.capture,
            &self.enclosures,
        )
    }
    fn verify(&self, key: &[u8]) -> Result<(), AuthError> {
        self.capture.verify(key)?;
        verify(key, &self.payload(), &self.mac)
    }
    fn sign(&mut self, key: &[u8]) -> Result<(), AuthError> {
        let mac = sign(key, &self.payload())?;
        self.mac = mac;
        Ok(())
    }
}
impl Receipt {
    fn payload(&self) -> impl Serialize + '_ {
        (
            b"heptabao-mfa-capsule-terminal-129".as_slice(),
            &self.capture,
            &self.id,
            self.source_capture,
            self.at,
            self.epoch,
            self.previous,
        )
    }
}
impl Applied {
    fn payload(&self) -> impl Serialize + '_ {
        (
            b"heptabao-mfa-capsule-terminal-applied-129".as_slice(),
            self.receipt,
            self.owner_digest,
            self.at,
            self.epoch,
        )
    }
}
impl Registry {
    pub(super) fn validate_janitor_custody(&self) -> Result<(), AuthError> {
        let Some(book) = &self.janitor_custody else {
            return Ok(());
        };
        if book.current.len() > 1024
            || book.terminal.len() > MAX_RECEIPTS
            || book.applied.len() > book.terminal.len()
        {
            return Err(err(
                503,
                "MFA terminal capacity or unpublished draft rejected",
            ));
        }
        for (namespace, index) in &self.closed_references {
            if let Some(commitment) = index.queue_digest {
                let locator = book
                    .current
                    .get(namespace)
                    .ok_or_else(|| err(503, "MFA closed queue reader marker erased"))?;
                if locator.capture.core_digest()? != commitment {
                    return Err(err(503, "MFA closed queue reader marker changed"));
                }
            }
        }
        for (namespace, locator) in &book.current {
            let capture = &locator.capture;
            locator.verify(&self.key.0)?;
            if !self.closed_references.contains_key(namespace)
                && !self.namespaces.contains_key(namespace)
            {
                return Err(err(503, "MFA queue locator has no native namespace owner"));
            }
            if capture.namespace != *namespace
                || capture.epoch > self.mutation_epoch
                || capture.entries.len() > issuance::MAX_CHALLENGES
                || capture.namespace_id.is_empty()
                || capture.incarnation == 0
                || capture.owner_digest == [0; 32]
                || capture.terminal_digest == [0; 32]
            {
                return Err(err(503, "MFA capsule queue owner rejected"));
            }
            let direct = capture
                .ciphertext
                .as_ref()
                .ok_or_else(|| err(503, "MFA original capsule absent"))?;
            let mut previous = capture.namespace.as_str();
            for (position, stamp) in std::iter::once(direct)
                .chain(&locator.enclosures)
                .enumerate()
            {
                if stamp.descriptor == [0; 32]
                    || stamp.key_epoch == 0
                    || stamp.seal_frontier == 0
                    || !within(previous, stamp.binding.namespace())
                    || position > 0 && previous == stamp.binding.namespace()
                {
                    return Err(err(503, "MFA original capsule enclosure rejected"));
                }
                previous = stamp.binding.namespace();
            }
            if locator.enclosures.len() > 256 {
                return Err(err(503, "MFA capsule nesting bound exceeded"));
            }
            let mut sequences = BTreeSet::new();
            for (id, entry) in &capture.entries {
                if !uuid_valid(id)
                    || entry.sequence == 0
                    || entry.sequence > capture.issued
                    || !sequences.insert(entry.sequence)
                    || entry.binding.namespace != *namespace
                    || entry.binding.namespace_id != capture.namespace_id
                    || entry.binding.incarnation != capture.incarnation
                    || entry.commitment == [0; 32]
                    || entry.eligible_at <= entry.created
                {
                    return Err(err(503, "MFA incapable queue commitment rejected"));
                }
                direct
                    .binding
                    .validate_cluster_namespace(
                        &entry.binding.cluster_id,
                        direct.binding.namespace(),
                    )
                    .map_err(|_| err(503, "MFA queue capsule cluster changed"))?;
                NativeMfaBinding::from_native(
                    &entry.binding.cluster_id,
                    &entry.binding.namespace,
                    &entry.binding.namespace_id,
                    entry.binding.incarnation,
                    entry.binding.custody.clone(),
                )?;
            }
            if let Some(index) = self.closed_references.get(namespace)
                && (index.namespace_id != capture.namespace_id
                    || index.incarnation != capture.incarnation
                    || index.owner_digest != capture.owner_digest
                    || index.queue_digest != Some(capture.core_digest()?))
            {
                return Err(err(503, "MFA queue differs from original closed owner"));
            }
        }
        let mut previous = [0; 32];
        let mut epoch = 0;
        let mut terminal_ids = BTreeSet::new();
        let mut terminal_records = BTreeMap::new();
        for receipt in &book.terminal {
            receipt.capture.verify(&self.key.0)?;
            let namespace = &receipt.capture.namespace;
            let owned = self.namespaces.get(namespace).is_some_and(|owner| {
                owner.namespace_id == receipt.capture.namespace_id
                    && owner.incarnation == receipt.capture.incarnation
            }) || self.closed_references.get(namespace).is_some_and(|index| {
                index.namespace_id == receipt.capture.namespace_id
                    && index.incarnation == receipt.capture.incarnation
            }) || self
                .retired
                .get(namespace)
                .is_some_and(|floor| *floor >= receipt.capture.incarnation);
            if !owned {
                return Err(err(
                    503,
                    "MFA terminal receipt has no actual owner or retirement floor",
                ));
            }
            verify(&self.key.0, &receipt.payload(), &receipt.mac)?;
            let entry = receipt
                .capture
                .entries
                .get(&receipt.id)
                .ok_or_else(|| err(503, "MFA receipt original entry absent"))?;
            if receipt.source_capture == [0; 32] || receipt.capture.entries.len() != 1 {
                return Err(err(
                    503,
                    "MFA receipt must bind exactly one original committed entry",
                ));
            }
            if let Some(locator) = book.current.get(namespace)
                && locator.capture.owner_digest == receipt.capture.owner_digest
                && digest(&locator.capture)? != receipt.source_capture
            {
                return Err(err(503, "MFA terminal source queue commitment differs"));
            }
            if receipt.previous != previous
                || receipt.epoch <= epoch
                || receipt.epoch > self.mutation_epoch
                || receipt.at < entry.eligible_at
                || receipt.at > self.clock
                || !terminal_ids.insert((
                    receipt.capture.namespace.clone(),
                    receipt.capture.namespace_id.clone(),
                    receipt.capture.incarnation,
                    entry.sequence,
                ))
            {
                return Err(err(503, "MFA terminal append-only chain rejected"));
            }
            epoch = receipt.epoch;
            previous = digest(receipt)?;
            terminal_records.insert(previous, receipt);
        }
        let mut applied = BTreeSet::new();
        for record in &book.applied {
            verify(&self.key.0, &record.payload(), &record.mac)?;
            let receipt = terminal_records
                .get(&record.receipt)
                .ok_or_else(|| err(503, "MFA applied receipt lacks original terminal"))?;
            if !applied.insert(record.receipt)
                || record.epoch <= receipt.epoch
                || record.epoch > self.mutation_epoch
                || record.at < receipt.at
                || record.at > self.clock
                || record.owner_digest == [0; 32]
            {
                return Err(err(503, "MFA applied receipt history rejected"));
            }
            if let Some(owner) = self.namespaces.get(&receipt.capture.namespace)
                && owner.namespace_id == receipt.capture.namespace_id
                && owner.incarnation == receipt.capture.incarnation
            {
                let entry = receipt
                    .capture
                    .entries
                    .get(&receipt.id)
                    .ok_or_else(|| err(503, "MFA applied entry absent"))?;
                if owner.challenges.values().any(|c| {
                    c.queue_entry(&self.key.0)
                        .is_ok_and(|e| e.sequence == entry.sequence)
                }) || !owner.terminal.contains(&entry.sequence)
                {
                    return Err(err(503, "MFA terminal private challenge resurrected"));
                }
            }
        }
        Ok(())
    }
    pub(super) fn validate_janitor_successor(&self, old: &Self) -> Result<(), AuthError> {
        if self.format < old.format {
            return Err(err(503, "MFA terminal reader floor regressed"));
        }
        let Some(previous) = &old.janitor_custody else {
            return Ok(());
        };
        let next = self
            .janitor_custody
            .as_ref()
            .ok_or_else(|| err(503, "MFA terminal owner cannot be removed"))?;
        if next.terminal.len() < previous.terminal.len()
            || next.applied.len() < previous.applied.len()
            || bytes(&next.terminal[..previous.terminal.len()])? != bytes(&previous.terminal)?
            || bytes(&next.applied[..previous.applied.len()])? != bytes(&previous.applied)?
        {
            return Err(err(503, "MFA terminal ledger prefix changed"));
        }
        for (namespace, index) in &old.closed_references {
            if self.closed_references.contains_key(namespace)
                && let Some(before) = previous.current.get(namespace)
            {
                let after = next
                    .current
                    .get(namespace)
                    .ok_or_else(|| err(503, "MFA closed queue erased"))?;
                if digest(&before.capture)? != digest(&after.capture)?
                    || before.capture.owner_digest != index.owner_digest
                {
                    return Err(err(503, "MFA original closed queue commitment changed"));
                }
            }
        }
        Ok(())
    }
}
impl AuthState {
    pub(crate) fn mfa_has_unbound_projection(&self) -> bool {
        self.identity_mfa
            .as_ref()
            .is_some_and(|registry| !registry.janitor_drafts.is_empty())
    }
    pub(crate) fn bind_mfa_namespace_ciphertext(
        &mut self,
        boundary: &crate::namespace_custody::Binding,
        owner: CiphertextOwner,
    ) -> Result<(), AuthError> {
        let Some(registry) = self.identity_mfa.as_mut() else {
            return Ok(());
        };
        if registry
            .janitor_drafts
            .keys()
            .any(|ns| within(ns, boundary.namespace()))
        {
            registry.format = FORMAT;
            registry
                .janitor_custody
                .get_or_insert_with(Custody::default);
        }
        let Some(book) = registry.janitor_custody.as_mut() else {
            return Ok(());
        };
        // Never re-sign a tampered retained chain while installing another
        // actual keyed capsule. New drafts do not exist in this retained map.
        for locator in book.current.values() {
            locator.verify(&registry.key.0)?;
        }
        if &owner.binding != boundary {
            return Err(err(503, "MFA actual capsule binding differs"));
        }
        let names = registry
            .janitor_drafts
            .keys()
            .filter(|ns| within(ns, boundary.namespace()))
            .cloned()
            .collect::<Vec<_>>();
        for namespace in names {
            let mut draft = registry
                .janitor_drafts
                .remove(&namespace)
                .ok_or_else(|| err(503, "MFA queue draft absent"))?;
            draft.ciphertext = Some(owner.clone());
            let index = registry
                .closed_references
                .get_mut(&namespace)
                .ok_or_else(|| err(503, "MFA original closed owner index absent"))?;
            if index.namespace_id != draft.namespace_id
                || index.incarnation != draft.incarnation
                || index.owner_digest != draft.owner_digest
            {
                return Err(err(503, "MFA actual partition draft owner differs"));
            }
            index.queue_digest = Some(draft.core_digest()?);
            let unchanged = book.current.get(&namespace).is_some_and(|before| {
                before.capture.owner_digest == draft.owner_digest
                    && before.capture.ciphertext == draft.ciphertext
                    && before.capture.entries == draft.entries
                    && before.capture.issued == draft.issued
                    && before.capture.terminal_digest == draft.terminal_digest
            });
            if unchanged {
                book.current
                    .get_mut(&namespace)
                    .ok_or_else(|| err(503, "MFA original locator absent"))?
                    .enclosures
                    .clear();
            } else {
                let mac = sign(&registry.key.0, &draft.payload())?;
                draft.mac = mac;
                book.current.insert(
                    namespace,
                    Locator {
                        capture: draft,
                        enclosures: Vec::new(),
                        mac: Vec::new(),
                    },
                );
            }
        }
        for locator in book.current.values_mut() {
            let visible = locator
                .enclosures
                .last()
                .or(locator.capture.ciphertext.as_ref())
                .ok_or_else(|| err(503, "MFA prior capsule absent"))?;
            if visible.binding.namespace() != boundary.namespace()
                && within(visible.binding.namespace(), boundary.namespace())
            {
                if locator.enclosures.len() >= 256 {
                    return Err(err(503, "MFA nesting capacity exhausted"));
                }
                locator.enclosures.push(owner.clone());
            }
        }
        for locator in book.current.values_mut() {
            locator.sign(&registry.key.0)?;
        }
        book.current.retain(|namespace, locator| {
            registry
                .closed_references
                .get(namespace)
                .is_some_and(|index| index.owner_digest == locator.capture.owner_digest)
                || registry.namespaces.contains_key(namespace)
        });
        Ok(())
    }
    pub(crate) fn mfa_namespace_visible_owners(&self) -> Vec<&CiphertextOwner> {
        self.identity_mfa
            .as_ref()
            .and_then(|r| r.janitor_custody.as_ref())
            .into_iter()
            .flat_map(|book| book.current.iter())
            .filter(|(namespace, _)| {
                self.identity_mfa
                    .as_ref()
                    .is_some_and(|r| r.closed_references.contains_key(*namespace))
            })
            .filter_map(|(_, locator)| {
                locator
                    .enclosures
                    .last()
                    .or(locator.capture.ciphertext.as_ref())
            })
            .collect()
    }
    pub(crate) fn mfa_namespace_opening_owners(
        &self,
        actual: &str,
        owner: &CiphertextOwner,
    ) -> Result<Vec<CiphertextOwner>, AuthError> {
        let mut inner = Vec::new();
        if let Some(registry) = self.identity_mfa.as_ref()
            && let Some(book) = registry.janitor_custody.as_ref()
        {
            for locator in book.current.values() {
                locator.verify(&registry.key.0)?;
                if let Some(last) = locator.enclosures.last()
                    && last.binding.namespace() == actual
                {
                    if last != owner {
                        return Err(err(503, "MFA enclosing capsule differs"));
                    }
                    inner.push(
                        locator
                            .enclosures
                            .iter()
                            .rev()
                            .nth(1)
                            .or(locator.capture.ciphertext.as_ref())
                            .ok_or_else(|| err(503, "MFA hidden original capsule absent"))?
                            .clone(),
                    );
                }
            }
        }
        Ok(inner)
    }
    pub(crate) fn remove_mfa_namespace_enclosure(
        &mut self,
        actual: &str,
        owner: &CiphertextOwner,
    ) -> Result<(), AuthError> {
        self.mfa_namespace_opening_owners(actual, owner)?;
        if let Some(registry) = self.identity_mfa.as_mut()
            && let Some(book) = registry.janitor_custody.as_mut()
        {
            for locator in book.current.values_mut() {
                locator.verify(&registry.key.0)?;
                if locator
                    .enclosures
                    .last()
                    .is_some_and(|stamp| stamp.binding.namespace() == actual)
                {
                    locator.enclosures.pop();
                    locator.sign(&registry.key.0)?;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn prepare_mfa_janitor_observed(
        &self,
        time: AuthorityTime,
    ) -> Result<Option<MfaJanitorHead>, AuthError> {
        let mut selected = self.prepare_mfa_open_janitor_observed(time)?;
        let now = time
            .exact()
            .ok_or_else(|| err(503, "MFA original janitor clock unavailable"))?;
        if let Some(registry) = &self.identity_mfa
            && let Some(book) = &registry.janitor_custody
        {
            for (namespace, locator) in &book.current {
                if !registry.closed_references.contains_key(namespace) {
                    continue;
                }
                locator.verify(&registry.key.0)?;
                for (id, entry) in &locator.capture.entries {
                    if book.terminal.iter().any(|receipt| {
                        receipt.capture.namespace == *namespace
                            && receipt.capture.namespace_id == locator.capture.namespace_id
                            && receipt.capture.incarnation == locator.capture.incarnation
                            && receipt.id == *id
                    }) {
                        continue;
                    }
                    if selected.as_ref().is_none_or(|head| {
                        (entry.created.seconds(), id) < (head.created.seconds(), &head.id)
                    }) {
                        selected = Some(MfaJanitorHead {
                            namespace: namespace.clone(),
                            id: id.clone(),
                            sequence: entry.sequence,
                            binding: entry.binding.clone(),
                            created: entry.created,
                            eligible_at: entry.eligible_at,
                            mac: Zeroizing::new(entry.commitment.to_vec()),
                            mutation_epoch: registry.mutation_epoch,
                            closed: Some(locator.clone()),
                        });
                    }
                }
            }
        }
        Ok(selected.filter(|head| now >= head.eligible_at))
    }
    pub(crate) fn finish_mfa_janitor_observed(
        &mut self,
        head: MfaJanitorHead,
        binding: NativeMfaBinding,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        let Some(original) = head.closed.as_ref() else {
            return self.finish_mfa_open_janitor_observed(head, binding, time);
        };
        let now = time
            .exact()
            .ok_or_else(|| err(503, "MFA original janitor clock unavailable"))?;
        let registry = self
            .identity_mfa
            .as_mut()
            .ok_or_else(|| err(503, "MFA closed queue owner absent"))?;
        let book = registry
            .janitor_custody
            .as_mut()
            .ok_or_else(|| err(503, "MFA closed queue floor absent"))?;
        let actual = book
            .current
            .get(&head.namespace)
            .ok_or_else(|| err(503, "MFA original closed queue absent"))?;
        original.verify(&registry.key.0)?;
        actual.verify(&registry.key.0)?;
        let entry = original
            .capture
            .entries
            .get(&head.id)
            .ok_or_else(|| err(503, "MFA original closed head absent"))?;
        if registry.mutation_epoch != head.mutation_epoch
            || digest(actual)? != digest(original)?
            || !registry.closed_references.contains_key(&head.namespace)
            || entry.binding != binding
            || head.binding != binding
            || entry.sequence != head.sequence
            || entry.created != head.created
            || entry.eligible_at != head.eligible_at
            || entry.commitment.as_slice() != head.mac.as_slice()
            || now < registry.clock
            || now < entry.eligible_at
            || book.terminal.len() >= MAX_RECEIPTS
            || book.terminal.iter().any(|receipt| {
                receipt.capture.namespace == head.namespace
                    && receipt.capture.namespace_id == original.capture.namespace_id
                    && receipt.capture.incarnation == original.capture.incarnation
                    && receipt.id == head.id
            })
        {
            return Err(err(503, "MFA original sealed janitor observation changed"));
        }
        let epoch = registry
            .mutation_epoch
            .checked_add(1)
            .ok_or_else(|| err(503, "MFA epoch exhausted"))?;
        let previous = book
            .terminal
            .last()
            .map(digest)
            .transpose()?
            .unwrap_or([0; 32]);
        let source_capture = digest(&original.capture)?;
        let mut capture = original.capture.clone();
        capture.entries.retain(|id, _| id == &head.id);
        let mac = sign(&registry.key.0, &capture.payload())?;
        capture.mac = mac;
        let mut receipt = Receipt {
            capture,
            source_capture,
            id: head.id,
            at: now,
            epoch,
            previous,
            mac: Vec::new(),
        };
        let mac = sign(&registry.key.0, &receipt.payload())?;
        receipt.mac = mac;
        book.terminal.push(receipt);
        registry.clock = now;
        registry.mutation_epoch = epoch;
        Ok(())
    }
    pub(crate) fn mfa_challenge_has_terminal_receipt(&self, namespace: &str, id: &str) -> bool {
        self.identity_mfa
            .as_ref()
            .and_then(|r| r.janitor_custody.as_ref())
            .is_some_and(|book| {
                book.terminal.iter().any(|receipt| {
                    receipt.capture.namespace == namespace
                        && receipt.id == id
                        && self
                            .identity_mfa
                            .as_ref()
                            .and_then(|r| r.namespaces.get(namespace))
                            .is_some_and(|owner| {
                                owner.namespace_id == receipt.capture.namespace_id
                                    && owner.incarnation == receipt.capture.incarnation
                            })
                })
            })
    }
    pub(crate) fn consume_authenticated_mfa_terminal_receipts(
        &mut self,
    ) -> Result<usize, AuthError> {
        let Some(registry) = self.identity_mfa.as_mut() else {
            return Ok(0);
        };
        let Some(book) = &registry.janitor_custody else {
            return Ok(0);
        };
        let consumed = book
            .applied
            .iter()
            .map(|record| record.receipt)
            .collect::<BTreeSet<_>>();
        let mut selected = Vec::new();
        for receipt in &book.terminal {
            let id = digest(receipt)?;
            if !consumed.contains(&id)
                && registry
                    .namespaces
                    .get(&receipt.capture.namespace)
                    .is_some_and(|owner| {
                        owner.namespace_id == receipt.capture.namespace_id
                            && owner.incarnation == receipt.capture.incarnation
                    })
            {
                selected.push(receipt.clone());
            }
        }
        if selected.is_empty() {
            return Ok(0);
        }
        let epoch = registry
            .mutation_epoch
            .checked_add(1)
            .ok_or_else(|| err(503, "MFA epoch exhausted"))?;
        let mut owners = registry.namespaces.clone();
        for receipt in &selected {
            receipt.capture.verify(&registry.key.0)?;
            verify(&registry.key.0, &receipt.payload(), &receipt.mac)?;
            let original = registry
                .namespaces
                .get(&receipt.capture.namespace)
                .ok_or_else(|| err(503, "MFA restored original owner absent"))?;
            let entry = receipt
                .capture
                .entries
                .get(&receipt.id)
                .ok_or_else(|| err(503, "MFA original receipt entry absent"))?;
            let challenge = original
                .challenges
                .get(&receipt.id)
                .ok_or_else(|| err(503, "MFA original private challenge absent"))?;
            if owner_digest(original)? != receipt.capture.owner_digest
                || original.issued != receipt.capture.issued
                || digest(&original.terminal)? != receipt.capture.terminal_digest
                || challenge.queue_entry(&registry.key.0)? != *entry
                || registry.clock < receipt.at
            {
                return Err(err(
                    503,
                    "MFA terminal receipt differs from original authenticated parcel",
                ));
            }
            let owner = owners
                .get_mut(&receipt.capture.namespace)
                .ok_or_else(|| err(503, "MFA staged owner absent"))?;
            owner
                .challenges
                .remove(&receipt.id)
                .ok_or_else(|| err(503, "MFA receipt replay rejected"))?;
            owner.terminal.insert(entry.sequence);
        }
        let mut records = Vec::new();
        for receipt in &selected {
            let mut record = Applied {
                receipt: digest(receipt)?,
                owner_digest: owner_digest(
                    owners
                        .get(&receipt.capture.namespace)
                        .ok_or_else(|| err(503, "MFA staged terminal owner absent"))?,
                )?,
                at: registry.clock,
                epoch,
                mac: Vec::new(),
            };
            let mac = sign(&registry.key.0, &record.payload())?;
            record.mac = mac;
            records.push(record);
        }
        registry.namespaces = owners;
        registry
            .janitor_custody
            .as_mut()
            .ok_or_else(|| err(503, "MFA ledger disappeared"))?
            .applied
            .extend(records);
        registry.mutation_epoch = epoch;
        Ok(selected.len())
    }
    pub(crate) fn mfa_terminal_receipt_clock(&self) -> Option<Timestamp> {
        self.identity_mfa.as_ref().map(|r| r.clock)
    }
}

impl Custody {
    pub(super) fn remove_namespace_locator(&mut self, namespace: &str) {
        self.current.remove(namespace);
    }
}
