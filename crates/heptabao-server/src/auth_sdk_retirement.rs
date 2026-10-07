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
    pub(crate) fn has_sdk_auth_retirement_state(&self) -> bool {
        self.sdk_auth_retirements.is_some()
    }
    pub(crate) fn sdk_auth_retirement_job(&self, id: &str) -> Option<&Job> {
        self.sdk_auth_retirements.as_ref()?.jobs.get(id)
    }
    pub(crate) fn sdk_auth_retirement_tainted(&self, binding: &sdk::Binding) -> bool {
        self.sdk_auth_retirements.as_ref().is_some_and(|registry| {
            registry
                .jobs
                .values()
                .any(|job| job.completion.is_none() && job.binding == *binding)
        })
    }
    pub(crate) fn sdk_auth_retirement_namespace_pending(&self, namespace: &str) -> bool {
        self.sdk_auth_retirements.as_ref().is_some_and(|registry| {
            registry
                .jobs
                .values()
                .any(|job| job.completion.is_none() && job.binding.namespace == namespace)
        })
    }
    pub(crate) fn sdk_auth_retirement_claims_record(&self, namespace: &str, id: &str) -> bool {
        self.sdk_auth_retirements.as_ref().is_some_and(|registry| {
            registry
                .jobs
                .values()
                .any(|job| job.binding.namespace == namespace && job.resources.contains_key(id))
        })
    }
    fn update_sdk_auth_retirement_mirror(&mut self) -> Result<(), AuthError> {
        let mirror = self
            .sdk_auth_retirements
            .as_ref()
            .map(|registry| hash(registry).map(|digest| Mirror { digest }))
            .transpose()?;
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
        let expected = self
            .sdk_auth_retirements
            .as_ref()
            .map(|registry| hash(registry).map(|digest| Mirror { digest }))
            .transpose()?;
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
                        .and_then(|auth| auth.sdk_auth_retirement_job(id))
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
                    .sdk_auth_retirement_job(id)
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

#[cfg(test)]
impl AuthState {
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
