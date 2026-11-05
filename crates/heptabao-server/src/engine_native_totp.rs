//! One actual local TOTP operation owns its candidate and reply through the
//! native publisher. Typed metadata is storage, not actor or ReadIndex authority;
//! the Service retains those independent owners around this private capsule.
use super::*;
use crate::state_record_root_v6::{OwnerDomain, RecordStateRootV6};
use sha2::{Digest, Sha256};

fn rejected() -> EngineError {
    error(503, "native TOTP operation custody changed")
}

fn live(check: &impl Fn() -> bool) -> Result<()> {
    check().then_some(()).ok_or_else(rejected)
}

// Native payloads are separate authenticated graphs. Their exact roots are
// compared below; this streamed digest covers every other Engine owner field.
// No full secret-bearing JSON image is allocated to compare those fields.
fn metadata_digest(state: &EngineState, check: &impl Fn() -> bool) -> Result<[u8; 32]> {
    live(check)?;
    let mut metadata = state.clone();
    for namespace in metadata.namespaces.values_mut() {
        for mount in namespace.mounts.values_mut() {
            live(check)?;
            if matches!(mount.backend, Backend::Kv2Native(_)) {
                mount.backend = Backend::Kv2(kv::Kv2::default());
            }
        }
    }
    struct Sink<'a, F> {
        check: &'a F,
        digest: Sha256,
        bytes: usize,
    }
    impl<F: Fn() -> bool> std::io::Write for Sink<'_, F> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !(self.check)() {
                return Err(std::io::Error::other(
                    "native TOTP original deadline expired",
                ));
            }
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|bytes| *bytes <= crate::MAX_APPLICATION_STATE_BYTES)
                .ok_or_else(|| std::io::Error::other("native TOTP owner capacity exceeded"))?;
            self.digest.update(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Sink {
        check,
        digest: Sha256::new(),
        bytes: 0,
    };
    serde_json::to_writer(&mut sink, &metadata).map_err(|_| rejected())?;
    live(check)?;
    Ok(sink.digest.finalize().into())
}

fn same_root(left: &RecordStateRootV6, right: &RecordStateRootV6) -> Result<bool> {
    Ok(left.encode().map_err(|_| rejected())?.as_slice()
        == right.encode().map_err(|_| rejected())?.as_slice())
}

fn only_role_changed(
    prior: &RecordStateRootV6,
    next: &RecordStateRootV6,
    roles: &[OwnerDomain],
) -> Result<()> {
    prior.validate().map_err(|_| rejected())?;
    next.validate().map_err(|_| rejected())?;
    if next.state_schema < prior.state_schema
        || next.reader_floor.minimum_state_schema < prior.reader_floor.minimum_state_schema
    {
        return Err(rejected());
    }
    let mut normalized = next.clone();
    normalized.state_schema = prior.state_schema;
    normalized.reader_floor.minimum_state_schema = prior.reader_floor.minimum_state_schema;
    for (old, new) in prior.owners.iter().zip(&mut normalized.owners) {
        if old.domain == new.domain && roles.contains(&old.domain) {
            *new = old.clone();
        }
    }
    same_root(prior, &normalized)?
        .then_some(())
        .ok_or_else(rejected)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RegistryChange {
    Read,
    Enable,
    Tune,
    Disable,
}

fn registry_target(path: &str) -> Result<(String, bool)> {
    let requested = path
        .strip_prefix("sys/mounts/")
        .ok_or_else(rejected)?
        .trim_end_matches('/');
    let (requested, tune) = requested
        .strip_suffix("/tune")
        .map_or((requested, false), |mount| (mount, true));
    Ok((format!("{}/", canonical_secret_mount(requested)?), tune))
}

// No Clone, serde, public fields, caller-provided mutation witness or restored
// receipt. The actual engine handler alone binds this operation's post-state.
pub(crate) struct NativeTotpOwner {
    source: EngineState,
    source_digest: [u8; 32],
    source_root: RecordStateRootV6,
    mount: String,
    incarnation: u64,
    revision: u64,
    registry: Option<RegistryChange>,
    method: String,
    path: String,
    body: SecretJson,
    authorization_method: String,
    capability: &'static str,
    executed: bool,
    executed_at: Option<crate::auth::Timestamp>,
    candidate_digest: Option<[u8; 32]>,
    installed_root: Option<RecordStateRootV6>,
    terminal_finished: bool,
}

impl EngineState {
    #[cfg(test)]
    pub(crate) fn native_totp_replay_observation(
        &self,
        mount: &str,
        name: &str,
    ) -> Option<(Option<u64>, u64, u32)> {
        let backend = &self.namespaces.get("")?.mounts.get(mount)?.backend;
        let Backend::Totp(totp) = backend else {
            return None;
        };
        totp.native_replay_observation(name)
    }

    pub(crate) fn native_local_totp_route(&self, namespace: &str, path: &str) -> bool {
        namespace.is_empty() && self.native_totp_mount(path).is_some()
    }

    pub(crate) fn native_totp_registry_route(
        &self,
        method: &str,
        path: &str,
        body: &Value,
    ) -> bool {
        let Ok((mount, tune)) = registry_target(path) else {
            return false;
        };
        if !tune
            && matches!(method, "POST" | "PUT")
            && body.get("type").and_then(Value::as_str) == Some("totp")
        {
            return true;
        }
        self.namespaces
            .get("")
            .and_then(|owner| owner.mounts.get(&mount))
            .is_some_and(|owner| matches!(&owner.backend, Backend::Totp(_)))
    }

    fn native_totp_mount(&self, path: &str) -> Option<(&str, &Mount)> {
        if path.starts_with('/') {
            return None;
        }
        let path = path.split_once('?').map_or(path, |(path, _)| path);
        self.namespaces
            .get("")?
            .mounts
            .iter()
            .filter(|(mount, _)| path.starts_with(mount.as_str()))
            .max_by_key(|(mount, _)| mount.len())
            .and_then(|(name, mount)| {
                matches!(&mount.backend, Backend::Totp(_)).then_some((name.as_str(), mount))
            })
    }

    pub(crate) fn capture_native_totp_owner(
        &self,
        method: &str,
        path: &str,
        body: &Value,
        root: &RecordStateRootV6,
        check: &impl Fn() -> bool,
    ) -> Result<NativeTotpOwner> {
        live(check)?;
        let authorization_method = kv_request_method(method, body);
        let (mount, incarnation, revision, registry, capability) =
            if path.starts_with("sys/mounts/") {
                let (mount, tune) = registry_target(path)?;
                let before = self
                    .namespaces
                    .get("")
                    .ok_or_else(rejected)?
                    .mounts
                    .get(&mount);
                let change = match (method, tune) {
                    ("GET", _) => RegistryChange::Read,
                    ("POST" | "PUT", true) => RegistryChange::Tune,
                    ("DELETE", false) => RegistryChange::Disable,
                    ("POST" | "PUT", false)
                        if body.get("type").and_then(Value::as_str) == Some("totp") =>
                    {
                        RegistryChange::Enable
                    }
                    _ => return Err(unsupported()),
                };
                // An existing different mount may only enter the ordinary enable
                // conflict response, never a tune or disable operation.
                if change != RegistryChange::Enable
                    && before.is_none_or(|mount| !matches!(&mount.backend, Backend::Totp(_)))
                {
                    return Err(rejected());
                }
                let incarnation = before.map_or(0, |mount| mount.incarnation);
                let revision = before.map_or(0, |mount| mount.revision);
                let capability = match method {
                    "GET" => "read",
                    "DELETE" => "delete",
                    _ => "update",
                };
                (mount, incarnation, revision, Some(change), capability)
            } else {
                let (mount, target) = self.native_totp_mount(path).ok_or_else(rejected)?;
                if target.incarnation == 0 || target.revision == 0 {
                    return Err(rejected());
                }
                let capability = self
                    .required_capability("", authorization_method, path)
                    .ok_or_else(rejected)?;
                (
                    mount.to_owned(),
                    target.incarnation,
                    target.revision,
                    None,
                    capability,
                )
            };
        root.validate().map_err(|_| rejected())?;
        Ok(NativeTotpOwner {
            source: self.clone(),
            source_digest: metadata_digest(self, check)?,
            source_root: root.clone(),
            mount,
            incarnation,
            revision,
            registry,
            method: method.to_owned(),
            path: path.to_owned(),
            body: SecretJson(body.clone()),
            authorization_method: authorization_method.to_owned(),
            capability,
            executed: false,
            executed_at: None,
            candidate_digest: None,
            installed_root: None,
            terminal_finished: false,
        })
    }
}

impl NativeTotpOwner {
    pub(crate) fn read_only(&self) -> bool {
        self.registry == Some(RegistryChange::Read)
            || (self.registry.is_none()
                && matches!(self.authorization_method.as_str(), "GET" | "LIST"))
    }

    // The Service supplies only the retained request's actual observed clock.
    // This field is not serializable and cannot be reconstructed after restart.
    pub(crate) fn check_observed_time(&self, at: crate::auth::Timestamp) -> Result<()> {
        if self.executed && self.executed_at.is_none()
            || self.executed_at.is_some_and(|executed| at < executed)
        {
            return Err(rejected());
        }
        Ok(())
    }

    pub(crate) fn authorization_method(&self) -> &str {
        &self.authorization_method
    }

    pub(crate) fn capability(&self) -> &'static str {
        // A create-capable actor must not be silently reclassified as update
        // after this very operation created the previously absent key.
        self.capability
    }

    pub(crate) fn requires_sudo(&self) -> bool {
        self.registry.is_some() && self.method != "GET"
    }

    pub(crate) fn check_source(
        &self,
        engines: &EngineState,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        live(check)?;
        if metadata_digest(engines, check)? != self.source_digest
            || engines.record_root() != self.source.record_root()
        {
            return Err(rejected());
        }
        if self.registry.is_none() {
            let (path, mount) = engines.native_totp_mount(&self.path).ok_or_else(rejected)?;
            if path != self.mount
                || mount.incarnation != self.incarnation
                || mount.revision != self.revision
            {
                return Err(rejected());
            }
        }
        live(check)
    }

    /// Invoke the existing local domain implementation exactly once. Its
    /// mutated flag, including rejected-code replay/guess counters, determines installation;
    /// the HTTP status is never used as a substitute for this result.
    pub(crate) fn execute(
        &mut self,
        engines: &mut EngineState,
        at: crate::auth::Timestamp,
        check: &impl Fn() -> bool,
    ) -> Result<Option<EngineResponse>> {
        if self.executed || self.candidate_digest.is_some() || self.installed_root.is_some() {
            return Err(rejected());
        }
        self.check_source(engines, check)?;
        self.executed = true;
        self.executed_at = Some(at);
        let mut candidate = engines.clone();
        let result = candidate.handle_in_identity_namespace_with_ssh_principal_precise(
            IdentityNamespace { path: "", id: None },
            &self.method,
            &self.path,
            &self.body,
            at.seconds(),
            "",
            None,
            at,
        );
        if result
            .as_ref()
            .is_ok_and(|response| response.as_ref().is_some_and(|r| r.mutated))
        {
            self.check_candidate_scope(&candidate, check)?;
            *engines = candidate;
        }
        self.check_candidate_scope(engines, check)?;
        self.candidate_digest = Some(metadata_digest(engines, check)?);
        live(check)?;
        result
    }

    fn check_candidate_scope(
        &self,
        engines: &EngineState,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        live(check)?;
        if self.read_only() && metadata_digest(engines, check)? != self.source_digest {
            return Err(rejected());
        }
        if engines.record_root() != self.source.record_root() {
            return Err(rejected());
        }
        if let Some(change) = self.registry {
            return self.check_registry_candidate(engines, change, check);
        }
        let prior = self
            .source
            .namespaces
            .get("")
            .and_then(|n| n.mounts.get(&self.mount))
            .ok_or_else(rejected)?;
        let mut normalized = engines.clone();
        let target = normalized
            .namespaces
            .get_mut("")
            .and_then(|n| n.mounts.get_mut(&self.mount))
            .ok_or_else(rejected)?;
        if !matches!(&target.backend, Backend::Totp(_)) {
            return Err(rejected());
        }
        // Descriptor, incarnation and revision remain part of the comparison.
        // Only this exact mount's local TOTP backend may have changed.
        target.backend = prior.backend.clone();
        if metadata_digest(&normalized, check)? != self.source_digest {
            return Err(rejected());
        }
        live(check)
    }

    fn check_registry_candidate(
        &self,
        engines: &EngineState,
        change: RegistryChange,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        // The real handler may have rejected a conflict, CAS or malformed
        // request. Such a result leaves the complete engine owner unchanged.
        if metadata_digest(engines, check)? == self.source_digest {
            return Ok(());
        }
        let prior = self.source.namespaces.get("").ok_or_else(rejected)?;
        let next = engines.namespaces.get("").ok_or_else(rejected)?;
        let before = prior.mounts.get(&self.mount);
        let after = next.mounts.get(&self.mount);
        match change {
            RegistryChange::Read => return Err(rejected()),
            RegistryChange::Enable => {
                let after = after.ok_or_else(rejected)?;
                let empty = Backend::Totp(totp::Totp::default());
                if before.is_some()
                    || after.incarnation
                        != prior
                            .mount_epochs
                            .get(&self.mount)
                            .copied()
                            .unwrap_or(1)
                            .max(1)
                    || after.revision != 1
                    || next.mount_epochs.get(&self.mount) != prior.mount_epochs.get(&self.mount)
                    || crate::secret_serde::to_vec(
                        &after.backend,
                        crate::MAX_APPLICATION_STATE_BYTES,
                    )
                    .map_err(|_| rejected())?
                    .as_slice()
                        != crate::secret_serde::to_vec(&empty, crate::MAX_APPLICATION_STATE_BYTES)
                            .map_err(|_| rejected())?
                            .as_slice()
                {
                    return Err(rejected());
                }
            }
            RegistryChange::Tune => {
                let before = before.ok_or_else(rejected)?;
                let after = after.ok_or_else(rejected)?;
                if after.incarnation != before.incarnation
                    || next.mount_epochs.get(&self.mount) != prior.mount_epochs.get(&self.mount)
                    || crate::secret_serde::to_vec(
                        &after.backend,
                        crate::MAX_APPLICATION_STATE_BYTES,
                    )
                    .map_err(|_| rejected())?
                    .as_slice()
                        != crate::secret_serde::to_vec(
                            &before.backend,
                            crate::MAX_APPLICATION_STATE_BYTES,
                        )
                        .map_err(|_| rejected())?
                        .as_slice()
                {
                    return Err(rejected());
                }
                let mut normalized = after.clone();
                normalized.revision = before.revision;
                let revision = if normalized.encode_tune_state()?.as_slice()
                    == before.encode_tune_state()?.as_slice()
                {
                    before.revision
                } else {
                    next_mount_revision(before.revision)?
                };
                if after.revision != revision {
                    return Err(rejected());
                }
            }
            RegistryChange::Disable => {
                let before = before.ok_or_else(rejected)?;
                let epoch = before
                    .incarnation
                    .max(1)
                    .checked_add(1)
                    .ok_or_else(rejected)?;
                if after.is_some() || next.mount_epochs.get(&self.mount) != Some(&epoch) {
                    return Err(rejected());
                }
            }
        }
        let mut normalized = engines.clone();
        let owner = normalized.namespaces.get_mut("").ok_or_else(rejected)?;
        match before {
            Some(before) => {
                owner.mounts.insert(self.mount.clone(), before.clone());
            }
            None => {
                owner.mounts.remove(&self.mount);
            }
        }
        match prior.mount_epochs.get(&self.mount) {
            Some(epoch) => {
                owner.mount_epochs.insert(self.mount.clone(), *epoch);
            }
            None => {
                owner.mount_epochs.remove(&self.mount);
            }
        }
        if metadata_digest(&normalized, check)? != self.source_digest {
            return Err(rejected());
        }
        live(check)
    }

    pub(crate) fn admit_candidate(
        &self,
        engines: &EngineState,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        if !self.executed || self.candidate_digest != Some(metadata_digest(engines, check)?) {
            return Err(rejected());
        }
        self.check_candidate_scope(engines, check)
    }

    pub(crate) fn disabled_mount(&self) -> Option<(&str, &str)> {
        (self.executed
            && self.registry == Some(RegistryChange::Disable)
            && self
                .candidate_digest
                .is_some_and(|digest| digest != self.source_digest))
        .then_some(("", self.mount.as_str()))
    }

    pub(crate) fn admit_root(
        &mut self,
        prior: &RecordStateRootV6,
        next: &RecordStateRootV6,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        self.admit_root_inner(prior, next, None, check)
    }

    pub(crate) fn admit_root_with_quota_retirement(
        &mut self,
        prior: &RecordStateRootV6,
        next: &RecordStateRootV6,
        retirement: crate::auth::rate_limit_quotas::MountRetirement,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        self.admit_root_inner(prior, next, Some(retirement), check)
    }

    fn admit_root_inner(
        &mut self,
        prior: &RecordStateRootV6,
        next: &RecordStateRootV6,
        retirement: Option<crate::auth::rate_limit_quotas::MountRetirement>,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        live(check)?;
        if !self.executed
            || self.candidate_digest.is_none()
            || self.installed_root.is_some()
            || !same_root(prior, &self.source_root)?
        {
            return Err(rejected());
        }
        if let Some(retirement) = retirement {
            let (namespace, mount) = self.disabled_mount().ok_or_else(rejected)?;
            let mut comparison = next.clone();
            retirement
                .normalize_owned_disable(namespace, mount, prior, &mut comparison, check)
                .map_err(|_| rejected())?;
            only_role_changed(prior, &comparison, &[OwnerDomain::Engines])?;
        } else {
            // The original rule is unchanged without an exact quota-removal
            // proof consumed for this actual, successful mount disable.
            only_role_changed(prior, next, &[OwnerDomain::Engines])?;
        }
        // Delivery retains the complete actual target, never the comparison.
        self.installed_root = Some(next.clone());
        live(check)
    }

    pub(crate) fn check_installed(
        &self,
        engines: &EngineState,
        root: &RecordStateRootV6,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        if !self.executed || self.candidate_digest != Some(metadata_digest(engines, check)?) {
            return Err(rejected());
        }
        if !same_root(self.installed_root.as_ref().ok_or_else(rejected)?, root)? {
            return Err(rejected());
        }
        live(check)
    }

    // Called only after Service has consumed this request's actual affine
    // TerminalClockReceipt and matched its full resulting checkpoint.
    pub(crate) fn admit_terminal_clock_successor(
        &mut self,
        engines: &EngineState,
        root: &RecordStateRootV6,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        live(check)?;
        let mut normalized = engines.clone();
        if normalized.kubernetes_artifact_clock != self.source.kubernetes_artifact_clock {
            if !self.source.has_kubernetes_opaque_artifact_state()
                || normalized.kubernetes_artifact_clock.is_none()
                || normalized.kubernetes_artifact_clock < self.source.kubernetes_artifact_clock
            {
                return Err(rejected());
            }
            normalized.kubernetes_artifact_clock = self.source.kubernetes_artifact_clock;
        }
        if self.candidate_digest != Some(metadata_digest(&normalized, check)?) {
            return Err(rejected());
        }
        let prior = self.installed_root.as_ref().ok_or_else(rejected)?;
        if self.terminal_finished || same_root(prior, root)? {
            return Err(rejected());
        }
        only_role_changed(prior, root, &[OwnerDomain::Auth, OwnerDomain::Engines])?;
        self.candidate_digest = Some(metadata_digest(engines, check)?);
        self.installed_root = Some(root.clone());
        self.terminal_finished = true;
        self.check_installed(engines, root, check)
    }

    pub(crate) fn finish_terminal_unchanged(
        &mut self,
        engines: &EngineState,
        root: &RecordStateRootV6,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        if self.terminal_finished {
            return Err(rejected());
        }
        self.check_installed(engines, root, check)?;
        self.terminal_finished = true;
        live(check)
    }
}
