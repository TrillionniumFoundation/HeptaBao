//! Retained Auth retirement control, never a second lease owner or Actor.
use super::*;
use crate::auth::sdk_credential::Record;
use crate::engines::sdk_lease::Phase as LeasePhase;

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum ResourcePhase {
    Queued,
    Attempted,
    Terminal,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resource {
    original: [u8; 32],
    accepted_record: [u8; 32],
    record: [u8; 32],
    phase: ResourcePhase,
    attempted_at: Option<Timestamp>,
    terminal_at: Option<Timestamp>,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    at: Timestamp,
    records: [u8; 32],
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Job {
    id: String,
    cluster: String,
    binding: sdk::Binding,
    namespace_owner: Option<batch_namespace::Binding>,
    accepted_at: Timestamp,
    request: String,
    resources: BTreeMap<String, Resource>,
    completion: Option<Completion>,
}
impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SDKAuthRetirement([REDACTED])")
    }
}
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    jobs: BTreeMap<String, Job>,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Mirror {
    digest: [u8; 32],
}
impl Job {
    pub(crate) fn binding(&self) -> &sdk::Binding {
        &self.binding
    }
    pub(crate) fn completed(&self) -> bool {
        self.completion.is_some()
    }
    pub(crate) fn phase(&self, id: &str) -> Option<ResourcePhase> {
        self.resources.get(id).map(|resource| resource.phase)
    }
    fn terminal_projection(&self) -> Result<[u8; 32], AuthError> {
        hash(&self.resources)
    }
}
fn hash<T: Serialize>(value: &T) -> Result<[u8; 32], AuthError> {
    let bytes = Zeroizing::new(
        crate::secret_serde::to_vec(value, 4 * 1024 * 1024)
            .map_err(|_| err(503, "SDK retirement control encoding unavailable"))?,
    );
    Ok(crate::crypto::digest(&bytes))
}
fn anchor(record: &Record) -> Result<[u8; 32], AuthError> {
    // No Secret/data copy, Principal or reconstructed issuer is stored in Jobs.
    hash(&(
        &record.id,
        &record.namespace,
        &record.cluster,
        &record.mount,
        &record.path,
        &record.backend,
        &record.issuer,
        &record.registration,
        record.issued,
        record.expires,
        record.renewed,
        record.max_ttl_ns,
        record.ttl_ns,
    ))
}
fn record_digest(record: &Record) -> Result<[u8; 32], AuthError> {
    hash(record)
}
impl AuthState {
    /// Subtractive joint107/109 gate; never creates either job's dispatch proof.
    pub(crate) fn sdk_auth_retirement_namespace_gate(
        &self,
        binding: &sdk::Binding,
        id: Option<&str>,
    ) -> Result<(), AuthError> {
        if self.namespace_is_tainted(&binding.namespace)
            || id.is_some_and(|id| {
                self.namespace_sdk_cleanup_blocks(
                    namespace_sdk_cleanup::Kind::Credential,
                    &binding.namespace,
                    id,
                )
            })
        {
            return Err(err(503, "namespace cleanup owns SDK retirement resource"));
        }
        Ok(())
    }
    pub(crate) fn has_sdk_auth_retirement_state(&self) -> bool {
        self.sdk_auth_retirements.is_some()
    }
    pub(crate) fn sdk_auth_retirement_job(&self, id: &str) -> Option<&Job> {
        self.sdk_auth_retirements.as_ref()?.jobs.get(id)
    }
    pub(crate) fn sdk_auth_retirement_tainted(&self, binding: &sdk::Binding) -> bool {
        self.custody_retirement_jobs()
            .iter()
            .any(|job| !job.completed() && job.binding == *binding)
            || self.sdk_auth_retirements.as_ref().is_some_and(|registry| {
                registry
                    .jobs
                    .values()
                    .any(|job| job.completion.is_none() && job.binding == *binding)
            })
    }
    pub(crate) fn sdk_auth_retirement_namespace_pending(&self, namespace: &str) -> bool {
        self.sdk_namespace_custody_pending(namespace)
            || self.sdk_auth_retirements.as_ref().is_some_and(|registry| {
                registry
                    .jobs
                    .values()
                    .any(|job| job.completion.is_none() && job.binding.namespace == namespace)
            })
    }
    pub(crate) fn sdk_auth_retirement_claims_record(&self, namespace: &str, id: &str) -> bool {
        self.custody_retirement_jobs()
            .iter()
            .any(|job| job.binding.namespace == namespace && job.resources.contains_key(id))
            || self.sdk_auth_retirements.as_ref().is_some_and(|registry| {
                registry
                    .jobs
                    .values()
                    .any(|job| job.binding.namespace == namespace && job.resources.contains_key(id))
            })
    }
    fn expected_sdk_auth_retirement_mirror(&self) -> Result<Option<Mirror>, AuthError> {
        match &self.sdk_namespace_custody {
            None => self
                .sdk_auth_retirements
                .as_ref()
                .map(|registry| hash(registry).map(|digest| Mirror { digest }))
                .transpose(),
            Some(custody) => Ok(Some(Mirror {
                digest: hash(&(
                    b"heptabao-sdk-auth-custody-mirror-114",
                    &self.sdk_auth_retirements,
                    custody,
                ))?,
            })),
        }
    }
    pub(super) fn update_sdk_auth_retirement_mirror(&mut self) -> Result<(), AuthError> {
        let mirror = self.expected_sdk_auth_retirement_mirror()?;
        let catalog = self
            .sdk_auth_catalog
            .as_mut()
            .ok_or_else(|| err(503, "SDK retirement catalog absent"))?;
        catalog.set_auth_retirement_mirror(mirror);
        Ok(())
    }
    pub(crate) fn begin_sdk_auth_retirement(
        &mut self,
        id: String,
        cluster: &str,
        binding: sdk::Binding,
        accepted_at: Timestamp,
        request: String,
    ) -> Result<(), AuthError> {
        self.sdk_auth_retirement_namespace_gate(&binding, None)?;
        self.sdk_auth_owner_gate(&binding)?;
        if self.sdk_auth_retirement_has_live_issuer(&binding, accepted_at) {
            return Err(err(
                409,
                "SDK Auth issued-token retirement is not implemented",
            ));
        }
        if self.namespace_is_tainted(&binding.namespace)
            || self.sdk_auth_retirement_tainted(&binding)
        {
            return Err(err(
                409,
                "SDK retirement controller already owns this mount",
            ));
        }
        let namespace_owner = if binding.namespace.is_empty() {
            None
        } else {
            Some(
                self.namespace_batch_registry
                    .as_ref()
                    .ok_or_else(|| err(503, "SDK retirement namespace lifecycle absent"))?
                    .binding(&binding.namespace)?,
            )
        };
        let mut resources = BTreeMap::new();
        for record in self.sdk_credential_mount_records(&binding)? {
            self.sdk_auth_retirement_namespace_gate(&binding, Some(&record.id))?;
            if record.phase != LeasePhase::PendingRevoke {
                return Err(err(503, "SDK retirement record was not durably selected"));
            }
            let digest = record_digest(&record)?;
            resources.insert(
                record.id.clone(),
                Resource {
                    original: anchor(&record)?,
                    accepted_record: digest,
                    record: digest,
                    phase: ResourcePhase::Queued,
                    attempted_at: None,
                    terminal_at: None,
                },
            );
        }
        let registry = self
            .sdk_auth_retirements
            .get_or_insert_with(Registry::default);
        if registry.jobs.contains_key(&id) || registry.jobs.len() >= 256 {
            return Err(err(507, "SDK retirement job capacity or id rejected"));
        }
        registry.jobs.insert(
            id.clone(),
            Job {
                id,
                cluster: cluster.into(),
                binding,
                namespace_owner,
                accepted_at,
                request,
                resources,
                completion: None,
            },
        );
        self.update_sdk_auth_retirement_mirror()
    }
    pub(crate) fn attempt_sdk_auth_retirement_resource(
        &mut self,
        job: &str,
        id: &str,
        at: Timestamp,
    ) -> Result<(), AuthError> {
        let selected = self
            .sdk_auth_retirement_job(job)
            .ok_or_else(|| err(503, "SDK retirement job absent"))?;
        self.sdk_auth_retirement_namespace_gate(&selected.binding, Some(id))?;
        let registry = self
            .sdk_auth_retirements
            .as_mut()
            .ok_or_else(|| err(503, "SDK retirement job absent"))?;
        let job = registry
            .jobs
            .get_mut(job)
            .ok_or_else(|| err(503, "SDK retirement job absent"))?;
        let resource = job
            .resources
            .get_mut(id)
            .ok_or_else(|| err(503, "SDK retirement resource absent"))?;
        if job.completion.is_some()
            || at < job.accepted_at
            || resource.phase != ResourcePhase::Queued
        {
            return Err(err(
                503,
                "SDK retirement resource cannot be attempted again",
            ));
        }
        resource.phase = ResourcePhase::Attempted;
        resource.attempted_at = Some(at);
        self.update_sdk_auth_retirement_mirror()
    }
    pub(crate) fn complete_sdk_auth_retirement_resource(
        &mut self,
        job: &str,
        id: &str,
        at: Timestamp,
    ) -> Result<(), AuthError> {
        let record = self
            .sdk_credential_record(
                self.sdk_auth_retirement_job(job)
                    .ok_or_else(|| err(503, "SDK retirement job absent"))?
                    .binding
                    .namespace
                    .as_str(),
                id,
            )
            .ok_or_else(|| err(503, "SDK retirement record absent"))?;
        let digest = record_digest(&record)?;
        let original = anchor(&record)?;
        let registry = self
            .sdk_auth_retirements
            .as_mut()
            .ok_or_else(|| err(503, "SDK retirement job absent"))?;
        let job = registry
            .jobs
            .get_mut(job)
            .ok_or_else(|| err(503, "SDK retirement job absent"))?;
        let resource = job
            .resources
            .get_mut(id)
            .ok_or_else(|| err(503, "SDK retirement resource absent"))?;
        if job.completion.is_some()
            || record.phase != LeasePhase::Revoked
            || resource.phase != ResourcePhase::Attempted
            || resource.original != original
            || resource.attempted_at.is_none_or(|before| at < before)
        {
            return Err(err(503, "SDK retirement terminal receipt rejected"));
        }
        resource.phase = ResourcePhase::Terminal;
        resource.terminal_at = Some(at);
        resource.record = digest;
        self.update_sdk_auth_retirement_mirror()
    }
    pub(crate) fn complete_sdk_auth_retirement_mount(
        &mut self,
        id: &str,
        at: Timestamp,
    ) -> Result<(), AuthError> {
        let job = self
            .sdk_auth_retirement_job(id)
            .ok_or_else(|| err(503, "SDK retirement job absent"))?;
        if job.completion.is_some()
            || self.sdk_auth_owned_mount(&job.binding.namespace, &job.binding.mount)
            || job.resources.values().any(|resource| {
                resource.phase != ResourcePhase::Terminal
                    || resource.terminal_at.is_none_or(|before| at < before)
            })
            || at < job.accepted_at
        {
            return Err(err(503, "SDK retirement mount removal was not completed"));
        }
        let projection = job.terminal_projection()?;
        let job = self
            .sdk_auth_retirements
            .as_mut()
            .and_then(|registry| registry.jobs.get_mut(id))
            .ok_or_else(|| err(503, "SDK retirement job absent"))?;
        job.completion = Some(Completion {
            at,
            records: projection,
        });
        self.update_sdk_auth_retirement_mirror()
    }
    pub(crate) fn validate_sdk_auth_retirement_state(
        &self,
        previous: Option<&Self>,
        cluster: &str,
        incarnation: impl Fn(&str) -> Option<u64>,
    ) -> Result<(), AuthError> {
        let expected = self.expected_sdk_auth_retirement_mirror()?;
        if self
            .sdk_auth_catalog
            .as_ref()
            .and_then(|catalog| catalog.auth_retirement_mirror())
            != expected.as_ref()
        {
            return Err(err(503, "SDK retirement strict catalog mirror differs"));
        }
        if let Some(registry) = &self.sdk_auth_retirements {
            if registry.jobs.len() > 256
                || registry
                    .jobs
                    .values()
                    .try_fold(0usize, |count, job| count.checked_add(job.resources.len()))
                    .is_none_or(|count| count > 4096)
            {
                return Err(err(503, "SDK retirement registry bound rejected"));
            }
            for (id, job) in &registry.jobs {
                if id != &job.id
                    || id.len() != 32
                    || !id.bytes().all(|c| c.is_ascii_hexdigit())
                    || job.cluster != cluster
                    || job.request.len() != 44
                    || base64::engine::general_purpose::STANDARD
                        .decode(&job.request)
                        .map_or(true, |bytes| bytes.len() != 32)
                    || job.resources.len() > 4096
                    || self
                        .sdk_auth_clock
                        .is_none_or(|floor| job.accepted_at > floor)
                    || job.binding.namespace.is_empty() != job.namespace_owner.is_none()
                {
                    return Err(err(503, "SDK retirement original admission rejected"));
                }
                if previous.is_some()
                    && previous
                        .and_then(|auth| auth.sdk_auth_retirement_job_for_validation(id))
                        .is_none()
                    && (job.completion.is_some()
                        || job
                            .resources
                            .values()
                            .any(|r| r.phase != ResourcePhase::Queued))
                {
                    return Err(err(
                        503,
                        "new SDK retirement must start with unattempted resources",
                    ));
                }
                self.validate_batch_namespace_owner_structure(
                    job.namespace_owner.as_ref(),
                    &job.binding.namespace,
                )?;
                if job.completion.is_none() {
                    self.sdk_auth_retirement_namespace_gate(&job.binding, None)?;
                    for id in job.resources.keys() {
                        self.sdk_auth_retirement_namespace_gate(&job.binding, Some(id))?;
                    }
                    self.sdk_auth_owner_gate(&job.binding)?;
                    if let Some(current) = incarnation(&job.binding.namespace)
                        && job
                            .namespace_owner
                            .as_ref()
                            .map_or(0, |owner| owner.incarnation())
                            != current
                    {
                        return Err(err(503, "SDK retirement namespace incarnation differs"));
                    }
                }
                if job.completion.is_none()
                    && self
                        .sdk_credential_mount_records(&job.binding)?
                        .iter()
                        .any(|record| !job.resources.contains_key(&record.id))
                {
                    return Err(err(503, "SDK retirement fixed resource set differs"));
                }
                for (id, resource) in &job.resources {
                    let record = self
                        .sdk_credential_record(&job.binding.namespace, id)
                        .ok_or_else(|| err(503, "SDK retirement retained credential absent"))?;
                    if record.backend != job.binding
                        || anchor(&record)? != resource.original
                        || record_digest(&record)? != resource.record
                    {
                        return Err(err(503, "SDK retirement retained credential differs"));
                    }
                    match resource.phase {
                        ResourcePhase::Queued
                            if record.phase == LeasePhase::PendingRevoke
                                && resource.attempted_at.is_none()
                                && resource.terminal_at.is_none()
                                && resource.record == resource.accepted_record => {}
                        ResourcePhase::Attempted
                            if record.phase == LeasePhase::PendingRevoke
                                && resource.record == resource.accepted_record
                                && resource.terminal_at.is_none()
                                && resource.attempted_at.is_some_and(|at| {
                                    at >= job.accepted_at
                                        && self.sdk_auth_clock.is_some_and(|floor| at <= floor)
                                }) => {}
                        ResourcePhase::Terminal
                            if record.phase == LeasePhase::Revoked
                                && resource.attempted_at.is_some_and(|before| {
                                    before >= job.accepted_at
                                        && resource.terminal_at.is_some_and(|at| {
                                            at >= before
                                                && self
                                                    .sdk_auth_clock
                                                    .is_some_and(|floor| at <= floor)
                                        })
                                }) => {}
                        _ => return Err(err(503, "SDK retirement attempt phase rejected")),
                    }
                }
                if let Some(completion) = &job.completion
                    && (completion.at < job.accepted_at
                        || self
                            .sdk_auth_clock
                            .is_none_or(|floor| completion.at > floor)
                        || completion.records != job.terminal_projection()?
                        || job.resources.values().any(|resource| {
                            resource.phase != ResourcePhase::Terminal
                                || resource.terminal_at.is_none_or(|at| completion.at < at)
                        })
                        || self
                            .sdk_auth_binding(
                                &job.binding.namespace,
                                &format!("auth/{}/config", job.binding.mount),
                            )?
                            .as_ref()
                            == Some(&job.binding))
                {
                    return Err(err(
                        503,
                        "SDK retirement completion lacks actual mount removal",
                    ));
                }
            }
        }
        if let Some(old) = previous.and_then(|auth| auth.sdk_auth_retirements.as_ref()) {
            for (id, before) in &old.jobs {
                let after = self
                    .sdk_auth_retirement_job_for_validation(id)
                    .ok_or_else(|| err(503, "SDK retirement history removed"))?;
                if before.id != after.id
                    || before.cluster != after.cluster
                    || before.binding != after.binding
                    || before.namespace_owner != after.namespace_owner
                    || before.accepted_at != after.accepted_at
                    || before.request != after.request
                    || before.resources.len() != after.resources.len()
                    || before
                        .completion
                        .as_ref()
                        .is_some_and(|completed| after.completion.as_ref() != Some(completed))
                {
                    return Err(err(503, "SDK retirement original intent changed"));
                }
                for (id, prior) in &before.resources {
                    let next = after
                        .resources
                        .get(id)
                        .ok_or_else(|| err(503, "SDK retirement resource removed"))?;
                    if prior.original != next.original
                        || prior.accepted_record != next.accepted_record
                        || !match (prior.phase, next.phase) {
                            (ResourcePhase::Queued, ResourcePhase::Attempted) => {
                                prior.record == next.record
                            }
                            (ResourcePhase::Attempted, ResourcePhase::Terminal) => {
                                prior.attempted_at == next.attempted_at
                            }
                            _ => prior == next,
                        }
                    {
                        return Err(err(
                            503,
                            "SDK retirement attempt cannot be reversed or skipped",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

/// An affine native cleanup selection from an actual retained Job. No
/// serialization, caller Principal, bearer or issuer grant can construct it.
pub(crate) struct RecoverySelection {
    selected: Job,
}
impl RecoverySelection {
    pub(crate) fn id(&self) -> &str {
        &self.selected.id
    }
    pub(crate) fn binding(&self) -> &sdk::Binding {
        &self.selected.binding
    }
    pub(crate) fn correlation(&self) -> &str {
        &self.selected.request
    }
    pub(crate) fn completed(&self) -> bool {
        self.selected.completed()
    }
    pub(crate) fn check(&self, auth: &AuthState) -> Result<(), AuthError> {
        if auth.sdk_auth_retirement_job(self.id()) != Some(&self.selected) {
            return Err(err(503, "SDK retirement selected durable intent changed"));
        }
        auth.sdk_auth_retirements
            .as_ref()
            .ok_or_else(|| err(503, "SDK retirement selected registry absent"))?;
        let expected = auth
            .expected_sdk_auth_retirement_mirror()?
            .ok_or_else(|| err(503, "SDK retirement selected strict mirror absent"))?;
        if auth
            .sdk_auth_catalog
            .as_ref()
            .and_then(|catalog| catalog.auth_retirement_mirror())
            != Some(&expected)
        {
            return Err(err(503, "SDK retirement selected strict mirror differs"));
        }
        let binding = self.binding();
        if !self.completed() {
            auth.sdk_auth_retirement_namespace_gate(binding, None)?;
            auth.sdk_auth_owner_gate(binding)?;
            auth.check_batch_namespace_binding(
                self.selected.namespace_owner.as_ref(),
                &binding.namespace,
            )?;
        }
        for (id, resource) in &self.selected.resources {
            if !self.completed() {
                auth.sdk_auth_retirement_namespace_gate(binding, Some(id))?;
            }
            let record = auth
                .sdk_credential_record(&binding.namespace, id)
                .ok_or_else(|| err(503, "SDK retirement selected record absent"))?;
            if record.backend != *binding
                || anchor(&record)? != resource.original
                || record_digest(&record)? != resource.record
            {
                return Err(err(503, "SDK retirement selected original record differs"));
            }
        }
        Ok(())
    }
    pub(crate) fn queued_records(&self, auth: &AuthState) -> Result<Vec<Record>, AuthError> {
        self.check(auth)?;
        if self.completed()
            || self
                .selected
                .resources
                .values()
                .any(|resource| resource.phase == ResourcePhase::Attempted)
        {
            return Err(err(
                503,
                "SDK retirement unknown attempt cannot be recovered automatically",
            ));
        }
        self.selected
            .resources
            .iter()
            .filter(|(_, resource)| resource.phase == ResourcePhase::Queued)
            .map(|(id, _)| {
                auth.sdk_credential_record(&self.binding().namespace, id)
                    .ok_or_else(|| err(503, "SDK retirement queued original record absent"))
            })
            .collect()
    }
    /// Called only after the exact candidate has physically committed and been
    /// installed into Service.state. A failed writer cannot adopt another Job.
    pub(crate) fn published_attempt(
        &mut self,
        auth: &AuthState,
        id: &str,
        at: Timestamp,
    ) -> Result<(), AuthError> {
        let mut expected = self.selected.clone();
        let resource = expected
            .resources
            .get_mut(id)
            .ok_or_else(|| err(503, "SDK retirement selected queued resource absent"))?;
        if expected.completion.is_some()
            || resource.phase != ResourcePhase::Queued
            || at < expected.accepted_at
        {
            return Err(err(
                503,
                "SDK retirement selected attempt successor rejected",
            ));
        }
        resource.phase = ResourcePhase::Attempted;
        resource.attempted_at = Some(at);
        if auth.sdk_auth_retirement_job(self.id()) != Some(&expected) {
            return Err(err(503, "SDK retirement committed attempt differs"));
        }
        self.selected = expected;
        self.check(auth)
    }
    pub(crate) fn published_terminal(
        &mut self,
        auth: &AuthState,
        id: &str,
        at: Timestamp,
    ) -> Result<(), AuthError> {
        let record = auth
            .sdk_credential_record(&self.binding().namespace, id)
            .ok_or_else(|| err(503, "SDK retirement committed terminal record absent"))?;
        let mut expected = self.selected.clone();
        let resource = expected
            .resources
            .get_mut(id)
            .ok_or_else(|| err(503, "SDK retirement selected attempted resource absent"))?;
        if expected.completion.is_some()
            || resource.phase != ResourcePhase::Attempted
            || resource.attempted_at.is_none_or(|before| at < before)
            || record.phase != LeasePhase::Revoked
            || anchor(&record)? != resource.original
        {
            return Err(err(
                503,
                "SDK retirement selected terminal successor rejected",
            ));
        }
        resource.phase = ResourcePhase::Terminal;
        resource.terminal_at = Some(at);
        resource.record = record_digest(&record)?;
        if auth.sdk_auth_retirement_job(self.id()) != Some(&expected) {
            return Err(err(503, "SDK retirement committed terminal differs"));
        }
        self.selected = expected;
        self.check(auth)
    }
    pub(crate) fn published_removal(
        &mut self,
        auth: &AuthState,
        at: Timestamp,
    ) -> Result<(), AuthError> {
        let mut expected = self.selected.clone();
        if expected.completion.is_some()
            || at < expected.accepted_at
            || expected.resources.values().any(|resource| {
                resource.phase != ResourcePhase::Terminal
                    || resource.terminal_at.is_none_or(|before| at < before)
            })
            || auth.sdk_auth_owned_mount(&expected.binding.namespace, &expected.binding.mount)
        {
            return Err(err(
                503,
                "SDK retirement selected removal successor rejected",
            ));
        }
        expected.completion = Some(Completion {
            at,
            records: expected.terminal_projection()?,
        });
        if auth.sdk_auth_retirement_job(self.id()) != Some(&expected) {
            return Err(err(503, "SDK retirement committed mount removal differs"));
        }
        self.selected = expected;
        self.check(auth)
    }
}
impl AuthState {
    /// Discovery alone never publishes, stages Setup or changes a resource.
    /// Skip the entire unknown Job, including all of its Queued siblings.
    pub(crate) fn sdk_auth_retirement_recovery_selections(
        &self,
    ) -> Result<Vec<RecoverySelection>, AuthError> {
        let Some(registry) = &self.sdk_auth_retirements else {
            return Ok(Vec::new());
        };
        let mut selected = Vec::new();
        for job in registry.jobs.values() {
            if !job.completed()
                && !job
                    .resources
                    .values()
                    .any(|resource| resource.phase == ResourcePhase::Attempted)
            {
                let value = RecoverySelection {
                    selected: job.clone(),
                };
                value.check(self)?;
                selected.push(value);
            }
        }
        Ok(selected)
    }
    /// The accepted native task can remove only this terminal SDK owner.
    /// Storage/catalog removal and Completion belong to the same real candidate.
    pub(crate) fn remove_sdk_auth_retirement_mount(
        &mut self,
        selected: &RecoverySelection,
        at: Timestamp,
    ) -> Result<(), AuthError> {
        selected.check(self)?;
        let job = &selected.selected;
        if job.completed()
            || at < job.accepted_at
            || job
                .resources
                .values()
                .any(|resource| resource.phase != ResourcePhase::Terminal)
            || !self.sdk_credential_mount_records(&job.binding)?.is_empty()
            || self.sdk_auth_retirement_has_live_issuer(&job.binding, at)
        {
            return Err(err(503, "SDK retirement selected mount is not terminal"));
        }
        self.sdk_auth_owner_gate(&job.binding)?;
        self.remove_auth_mount_current(&job.binding.namespace, &job.binding.mount)?;
        self.complete_sdk_auth_retirement_mount(&job.id, at)
    }
}

#[cfg(test)]
impl AuthState {
    pub(crate) fn sdk_auth_retirement_jobs_for_test(&self) -> Vec<(String, Job)> {
        self.sdk_auth_retirements
            .as_ref()
            .map(|registry| {
                registry
                    .jobs
                    .iter()
                    .map(|(id, job)| (id.clone(), job.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn sdk_auth_retirement_tamper_for_test(
        &mut self,
        id: &str,
        mode: &str,
    ) -> Result<(), AuthError> {
        if mode == "remove" {
            self.sdk_auth_retirements = None;
        } else if mode == "mirror" {
            self.sdk_auth_catalog
                .as_mut()
                .ok_or_else(|| err(503, "fixture catalog absent"))?
                .set_auth_retirement_mirror(None);
            return Ok(());
        } else {
            let job = self
                .sdk_auth_retirements
                .as_mut()
                .and_then(|registry| registry.jobs.get_mut(id))
                .ok_or_else(|| err(503, "fixture retirement absent"))?;
            match mode {
                "accepted" => {
                    job.accepted_at = Timestamp::checked(100, 299_000_000)
                        .map_err(|_| err(503, "fixture clock rejected"))?
                }
                "resource" => job.resources.clear(),
                "rollback" => {
                    let resource = job
                        .resources
                        .values_mut()
                        .next()
                        .ok_or_else(|| err(503, "fixture resource absent"))?;
                    resource.phase = ResourcePhase::Queued;
                    resource.attempted_at = None;
                    resource.terminal_at = None;
                }
                "request" => {
                    job.request = base64::engine::general_purpose::STANDARD.encode([2u8; 32])
                }
                _ => return Err(err(503, "fixture mutation rejected")),
            }
        }
        self.update_sdk_auth_retirement_mirror()
    }
}

impl Registry {
    pub(super) fn namespace_slice(
        &mut self,
        namespace: &str,
        owner: &batch_namespace::Binding,
    ) -> Self {
        let keys = self
            .jobs
            .iter()
            .filter(|(_, job)| {
                job.binding.namespace == namespace && job.namespace_owner.as_ref() == Some(owner)
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        Self {
            jobs: keys
                .into_iter()
                .filter_map(|id| self.jobs.remove_entry(&id))
                .collect(),
        }
    }
    /// Jobs contain original digests/control metadata, never Secret/data or a
    /// Principal. This copy is validation/indexing only; ordinary job lookup
    /// never consults it and it cannot produce a RecoverySelection.
    pub(super) fn namespace_index(
        &self,
        namespace: &str,
    ) -> Result<BTreeMap<String, Job>, AuthError> {
        if self
            .jobs
            .iter()
            .any(|(id, job)| id != &job.id || job.binding.namespace != namespace)
        {
            return Err(err(503, "SDK namespace retirement parcel binding rejected"));
        }
        Ok(self.jobs.clone())
    }
    pub(super) fn contains_any(&self, incoming: &Self) -> bool {
        incoming.jobs.keys().any(|id| self.jobs.contains_key(id))
    }
    pub(super) fn append_exact(&mut self, incoming: Self) -> Result<(), AuthError> {
        if self.contains_any(&incoming) || self.jobs.len() + incoming.jobs.len() > 256 {
            return Err(err(
                503,
                "SDK namespace retirement parcel collision or capacity rejected",
            ));
        }
        self.jobs.extend(incoming.jobs);
        Ok(())
    }
    pub(super) fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }
    pub(super) fn custody_global_job_count(&self) -> usize {
        self.jobs.len()
    }
}

impl AuthState {
    /// Structural/history lookup only. This method never prepares work.
    fn sdk_auth_retirement_job_for_validation(&self, id: &str) -> Option<&Job> {
        self.sdk_auth_retirement_job(id)
            .or_else(|| self.custody_retirement_job_for_validation(id))
    }
}
impl Job {
    pub(super) fn saved_namespace_owner(&self) -> Option<&batch_namespace::Binding> {
        self.namespace_owner.as_ref()
    }
}

impl Job {
    /// A locator proves only the retained control projection. Full per-Job
    /// validation still runs after authenticated restoration and checks actual
    /// Records, Secret/data digests, owner/mount and completion removal.
    pub(super) fn validate_custody_index(
        &self,
        id: &str,
        cluster: &str,
        auth: &AuthState,
    ) -> Result<(), AuthError> {
        if id != self.id
            || id.len() != 32
            || !id.bytes().all(|c| c.is_ascii_hexdigit())
            || self.cluster != cluster
            || self.request.len() != 44
            || base64::engine::general_purpose::STANDARD
                .decode(&self.request)
                .map_or(true, |bytes| bytes.len() != 32)
            || self.resources.len() > 4096
            || auth
                .sdk_auth_clock
                .is_none_or(|floor| self.accepted_at > floor)
            || self.binding.namespace.is_empty() != self.namespace_owner.is_none()
        {
            return Err(err(
                503,
                "SDK retirement custody original admission rejected",
            ));
        }
        auth.validate_batch_namespace_owner_structure(
            self.namespace_owner.as_ref(),
            &self.binding.namespace,
        )?;
        for (id, resource) in &self.resources {
            let record = auth
                .custody_record_for_validation(&self.binding.namespace, id)?
                .ok_or_else(|| err(503, "SDK retirement custody credential index absent"))?;
            let lease = &record.lease;
            let original = hash(&(
                &lease.id,
                &lease.namespace,
                &lease.cluster,
                &lease.mount,
                &lease.path,
                &lease.backend,
                &lease.issuer,
                &lease.registration,
                lease.issued,
                lease.expires,
                lease.renewed,
                lease.max_ttl_ns,
                lease.ttl_ns,
            ))?;
            if lease.backend != self.binding
                || record.namespace_owner != self.namespace_owner
                || original != resource.original
                || record.digest != resource.record
            {
                return Err(err(
                    503,
                    "SDK retirement custody resource projection differs",
                ));
            }
            match resource.phase {
                ResourcePhase::Queued
                    if lease.phase == LeasePhase::PendingRevoke
                        && resource.attempted_at.is_none()
                        && resource.terminal_at.is_none()
                        && resource.record == resource.accepted_record => {}
                ResourcePhase::Attempted
                    if lease.phase == LeasePhase::PendingRevoke
                        && resource.record == resource.accepted_record
                        && resource.terminal_at.is_none()
                        && resource.attempted_at.is_some_and(|at| {
                            at >= self.accepted_at
                                && auth.sdk_auth_clock.is_some_and(|floor| at <= floor)
                        }) => {}
                ResourcePhase::Terminal
                    if lease.phase == LeasePhase::Revoked
                        && resource.attempted_at.is_some_and(|before| {
                            before >= self.accepted_at
                                && resource.terminal_at.is_some_and(|at| {
                                    at >= before
                                        && auth.sdk_auth_clock.is_some_and(|floor| at <= floor)
                                })
                        }) => {}
                _ => return Err(err(503, "SDK retirement custody attempt phase rejected")),
            }
        }
        if let Some(completion) = &self.completion
            && (completion.at < self.accepted_at
                || auth
                    .sdk_auth_clock
                    .is_none_or(|floor| completion.at > floor)
                || completion.records != self.terminal_projection()?
                || self.resources.values().any(|resource| {
                    resource.phase != ResourcePhase::Terminal
                        || resource.terminal_at.is_none_or(|at| completion.at < at)
                }))
        {
            return Err(err(
                503,
                "SDK retirement custody completion projection rejected",
            ));
        }
        Ok(())
    }
}

impl Registry {
    pub(super) fn namespace_present(&self, actual: &str) -> bool {
        self.jobs
            .values()
            .any(|job| job.binding.namespace == actual)
    }
}

impl Registry {
    pub(super) fn custody_global_resource_count(&self) -> Option<usize> {
        self.jobs
            .values()
            .try_fold(0usize, |count, job| count.checked_add(job.resources.len()))
    }
}
impl Job {
    pub(super) fn custody_resource_count(&self) -> usize {
        self.resources.len()
    }
}

impl Job {
    pub(super) fn custody_id(&self) -> &str {
        &self.id
    }
}
