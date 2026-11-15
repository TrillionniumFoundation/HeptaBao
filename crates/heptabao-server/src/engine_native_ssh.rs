//! Exact Engine custody for one original root-local SSH operation. The Service
//! capsule invokes the existing OTP/CA domain once and binds its actual result.
//! Native KV data is compared by authenticated graph roots, never flattened.
use super::*;
use crate::state_record_root_v6::{OwnerDomain, RecordStateRootV6};
use sha2::{Digest, Sha256};

fn rejected() -> EngineError {
    error(503, "native local SSH ownership changed")
}
fn live(check: &impl Fn() -> bool) -> Result<()> {
    check().then_some(()).ok_or_else(rejected)
}
fn digest(state: &EngineState, check: &impl Fn() -> bool) -> Result<[u8; 32]> {
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
    struct Sink<'a, F>(&'a F, Sha256, usize);
    impl<F: Fn() -> bool> std::io::Write for Sink<'_, F> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !(self.0)() {
                return Err(std::io::Error::other(
                    "native SSH original deadline expired",
                ));
            }
            self.2 = self
                .2
                .checked_add(bytes.len())
                .filter(|n| *n <= crate::MAX_APPLICATION_STATE_BYTES)
                .ok_or_else(|| std::io::Error::other("native SSH owner capacity exceeded"))?;
            self.1.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Sink(check, Sha256::new(), 0);
    serde_json::to_writer(&mut sink, &metadata).map_err(|_| rejected())?;
    live(check)?;
    Ok(sink.1.finalize().into())
}
fn same_root(a: &RecordStateRootV6, b: &RecordStateRootV6) -> Result<bool> {
    Ok(a.encode().map_err(|_| rejected())?.as_slice()
        == b.encode().map_err(|_| rejected())?.as_slice())
}
fn only_roles(
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
enum Registry {
    Read,
    Enable,
    Tune,
    Disable,
}
enum Scope {
    Mount(String),
    Registry(String, Registry),
}
fn registry_target(path: &str) -> Result<(String, bool)> {
    let path = path
        .strip_prefix("sys/mounts/")
        .ok_or_else(rejected)?
        .trim_end_matches('/');
    let (path, tune) = path
        .strip_suffix("/tune")
        .map_or((path, false), |p| (p, true));
    Ok((format!("{}/", canonical_secret_mount(path)?), tune))
}

pub(crate) struct NativeSshEngineOwner {
    source: EngineState,
    source_digest: [u8; 32],
    source_root: RecordStateRootV6,
    scope: Scope,
    read_only: bool,
    candidate_digest: Option<[u8; 32]>,
    installed_root: Option<RecordStateRootV6>,
    terminal_finished: bool,
}
impl EngineState {
    #[cfg(test)]
    pub(crate) fn native_ssh_signature_count(&self, path: &str) -> Option<u64> {
        let (_, mount) = self.native_ssh_mount(path)?;
        match &mount.backend {
            Backend::Ssh(engine) => engine.native_signature_count(),
            _ => None,
        }
    }

    /// Data-only lookup of the actual OTP result. It neither validates a
    /// credential nor consumes it; the original SSH handler remains sole owner.
    pub(crate) fn native_ssh_otp_lease(
        &self,
        path: &str,
        raw: &str,
        consumed: bool,
    ) -> Option<(crate::auth::LeaseOwner, String, u64)> {
        let (_, mount) = self.native_ssh_mount(path)?;
        let Backend::Ssh(engine) = &mount.backend else {
            return None;
        };
        let lease = engine.native_otp_lease(raw, consumed)?;
        Some((lease.owner.clone(), lease.id.clone(), lease.expires))
    }
    fn native_ssh_mount(&self, path: &str) -> Option<(&str, &Mount)> {
        if path.starts_with('/') {
            return None;
        }
        self.namespaces
            .get("")?
            .mounts
            .iter()
            .filter(|(mount, _)| path.starts_with(mount.as_str()))
            .max_by_key(|(mount, _)| mount.len())
            .and_then(|(name, mount)| {
                matches!(&mount.backend, Backend::Ssh(_)).then_some((name.as_str(), mount))
            })
    }
    pub(crate) fn native_local_ssh_mounted(&self, namespace: &str, path: &str) -> bool {
        namespace.is_empty() && self.native_ssh_mount(path).is_some()
    }
    pub(crate) fn native_local_ssh_route(&self, namespace: &str, path: &str) -> bool {
        namespace.is_empty() && self.native_ssh_mount(path).is_some()
    }
    pub(crate) fn native_ssh_registry_route(&self, method: &str, path: &str, body: &Value) -> bool {
        let Ok((mount, tune)) = registry_target(path) else {
            return false;
        };
        (!tune
            && matches!(method, "POST" | "PUT")
            && body.get("type").and_then(Value::as_str) == Some("ssh"))
            || self
                .namespaces
                .get("")
                .and_then(|owner| owner.mounts.get(&mount))
                .is_some_and(|mount| matches!(&mount.backend, Backend::Ssh(_)))
    }
    pub(crate) fn capture_native_ssh_engine_owner(
        &self,
        method: &str,
        path: &str,
        body: &Value,
        _public: bool,
        root: &RecordStateRootV6,
        check: &impl Fn() -> bool,
    ) -> Result<NativeSshEngineOwner> {
        live(check)?;
        let (scope, read_only) = if path.starts_with("sys/mounts/") {
            let (mount, tune) = registry_target(path)?;
            let before = self
                .namespaces
                .get("")
                .and_then(|owner| owner.mounts.get(&mount));
            let change = match (method, tune) {
                ("GET", _) => Registry::Read,
                ("POST" | "PUT", true) => Registry::Tune,
                ("DELETE", false) => Registry::Disable,
                ("POST" | "PUT", false)
                    if body.get("type").and_then(Value::as_str) == Some("ssh") =>
                {
                    Registry::Enable
                }
                _ => return Err(unsupported()),
            };
            if change != Registry::Enable
                && before.is_none_or(|mount| !matches!(&mount.backend, Backend::Ssh(_)))
            {
                return Err(rejected());
            }
            (Scope::Registry(mount, change), change == Registry::Read)
        } else {
            let (mount, owner) = self.native_ssh_mount(path).ok_or_else(rejected)?;
            if owner.incarnation == 0 || owner.revision == 0 {
                return Err(rejected());
            }
            // Anonymous OTP verification is a write. Public visibility alone
            // must never turn that operation into an immutable read.
            let read_only = matches!(method, "GET" | "HEAD" | "LIST" | "SCAN" | "HELP");
            (Scope::Mount(mount.to_owned()), read_only)
        };
        Self::ssh_owner(self, scope, read_only, root, check)
    }
    fn ssh_owner(
        &self,
        scope: Scope,
        read_only: bool,
        root: &RecordStateRootV6,
        check: &impl Fn() -> bool,
    ) -> Result<NativeSshEngineOwner> {
        root.validate().map_err(|_| rejected())?;
        let owner = NativeSshEngineOwner {
            source: self.clone(),
            source_digest: digest(self, check)?,
            source_root: root.clone(),
            scope,
            read_only,
            candidate_digest: None,
            installed_root: None,
            terminal_finished: false,
        };
        owner.check_source(self, check)?;
        Ok(owner)
    }
}
impl NativeSshEngineOwner {
    pub(crate) fn read_only(&self) -> bool {
        self.read_only
    }
    pub(crate) fn check_source(
        &self,
        engines: &EngineState,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        if digest(engines, check)? != self.source_digest
            || engines.record_root() != self.source.record_root()
        {
            return Err(rejected());
        }
        live(check)
    }
    fn check_scope(&self, engines: &EngineState, check: &impl Fn() -> bool) -> Result<()> {
        live(check)?;
        if engines.record_root() != self.source.record_root()
            || engines.lease_clock < self.source.lease_clock
        {
            return Err(rejected());
        }
        if digest(engines, check)? == self.source_digest {
            return Ok(());
        }
        if self.read_only {
            return Err(rejected());
        }
        let mut normalized = engines.clone();
        normalized.lease_clock = self.source.lease_clock;
        if normalized.ssh_ca_format != self.source.ssh_ca_format {
            // Only the original SSH domain may introduce its existing CA
            // serialization marker. The reader floor can never move back.
            if self.source.ssh_ca_format.is_some()
                || normalized.ssh_ca_format != Some(115)
                || !engines.has_ssh_ca_state()
            {
                return Err(rejected());
            }
            normalized.ssh_ca_format = self.source.ssh_ca_format;
        }
        let prior = self.source.namespaces.get("").ok_or_else(rejected)?;
        let next = normalized.namespaces.get_mut("").ok_or_else(rejected)?;
        match &self.scope {
            Scope::Registry(name, change) => {
                let before = prior.mounts.get(name);
                let after = next.mounts.get(name);
                match change {
                    Registry::Read => return Err(rejected()),
                    Registry::Enable => {
                        let after = after.ok_or_else(rejected)?;
                        if before.is_some()
                            || !matches!(&after.backend, Backend::Ssh(_))
                            || after.incarnation
                                != prior.mount_epochs.get(name).copied().unwrap_or(1).max(1)
                            || after.revision != 1
                            || next.mount_epochs.get(name) != prior.mount_epochs.get(name)
                        {
                            return Err(rejected());
                        }
                    }
                    Registry::Tune => {
                        let before = before.ok_or_else(rejected)?;
                        let after = after.ok_or_else(rejected)?;
                        if after.incarnation != before.incarnation
                            || !matches!(&after.backend, Backend::Ssh(_))
                            || next.mount_epochs.get(name) != prior.mount_epochs.get(name)
                        {
                            return Err(rejected());
                        }
                        let mut comparison = after.clone();
                        comparison.revision = before.revision;
                        let expected_revision = if comparison.encode_tune_state()?.as_slice()
                            == before.encode_tune_state()?.as_slice()
                        {
                            before.revision
                        } else {
                            next_mount_revision(before.revision)?
                        };
                        if after.revision != expected_revision {
                            return Err(rejected());
                        }
                    }
                    Registry::Disable => {
                        let before = before.ok_or_else(rejected)?;
                        let next_epoch = before
                            .incarnation
                            .max(1)
                            .checked_add(1)
                            .ok_or_else(rejected)?;
                        if after.is_some() || next.mount_epochs.get(name) != Some(&next_epoch) {
                            return Err(rejected());
                        }
                    }
                }
                match before {
                    Some(mount) => {
                        next.mounts.insert(name.clone(), mount.clone());
                    }
                    None => {
                        next.mounts.remove(name);
                    }
                }
                match prior.mount_epochs.get(name) {
                    Some(epoch) => {
                        next.mount_epochs.insert(name.clone(), *epoch);
                    }
                    None => {
                        next.mount_epochs.remove(name);
                    }
                }
            }
            Scope::Mount(name) => {
                let before = prior.mounts.get(name).ok_or_else(rejected)?;
                let target = next.mounts.get_mut(name).ok_or_else(rejected)?;
                if !matches!(&target.backend, Backend::Ssh(_)) {
                    return Err(rejected());
                }
                target.backend = before.backend.clone();
            }
        }
        if digest(&normalized, check)? != self.source_digest {
            return Err(rejected());
        }
        live(check)
    }
    /// Bind once, immediately after the actual retained Service invocation.
    /// Callers cannot supply expected bytes, a restored witness or a receipt.
    pub(crate) fn bind_executed(
        &mut self,
        engines: &EngineState,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        if self.candidate_digest.is_some() || self.installed_root.is_some() {
            return Err(rejected());
        }
        self.check_scope(engines, check)?;
        self.candidate_digest = Some(digest(engines, check)?);
        Ok(())
    }
    pub(crate) fn admit_candidate(
        &self,
        engines: &EngineState,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        if self.candidate_digest != Some(digest(engines, check)?) {
            return Err(rejected());
        }
        self.check_scope(engines, check)
    }
    pub(crate) fn disabled_mount(&self) -> Option<(&str, &str)> {
        match &self.scope {
            Scope::Registry(mount, Registry::Disable)
                if self
                    .candidate_digest
                    .is_some_and(|digest| digest != self.source_digest) =>
            {
                Some(("", mount.as_str()))
            }
            _ => None,
        }
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
        if self.candidate_digest.is_none()
            || self.installed_root.is_some()
            || !same_root(prior, &self.source_root)?
        {
            return Err(rejected());
        }
        let domains = &[OwnerDomain::Engines][..];
        if let Some(retirement) = retirement {
            let (namespace, mount) = self.disabled_mount().ok_or_else(rejected)?;
            let mut comparison = next.clone();
            retirement
                .normalize_owned_disable(namespace, mount, prior, &mut comparison, check)
                .map_err(|_| rejected())?;
            only_roles(prior, &comparison, &[OwnerDomain::Engines])?;
        } else {
            only_roles(prior, next, domains)?;
        }
        if self.read_only && !same_root(prior, next)? {
            return Err(rejected());
        }
        self.installed_root = Some(next.clone());
        live(check)
    }
    pub(crate) fn check_installed(
        &self,
        engines: &EngineState,
        root: &RecordStateRootV6,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        if self.candidate_digest != Some(digest(engines, check)?)
            || !same_root(self.installed_root.as_ref().ok_or_else(rejected)?, root)?
        {
            return Err(rejected());
        }
        live(check)
    }
    pub(crate) fn bind_terminal(
        &mut self,
        engines: &EngineState,
        root: &RecordStateRootV6,
        written: bool,
        check: &impl Fn() -> bool,
    ) -> Result<()> {
        if self.terminal_finished {
            return Err(rejected());
        }
        let prior = self.installed_root.as_ref().ok_or_else(rejected)?;
        if written {
            if same_root(prior, root)? {
                return Err(rejected());
            }
            // The caller has consumed the actual TerminalClockReceipt and
            // matched its complete resulting checkpoint before this method.
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
            if self.candidate_digest != Some(digest(&normalized, check)?) {
                return Err(rejected());
            }
            only_roles(prior, root, &[OwnerDomain::Auth, OwnerDomain::Engines])?;
            self.candidate_digest = Some(digest(engines, check)?);
            self.installed_root = Some(root.clone());
        }
        self.check_installed(engines, root, check)?;
        self.terminal_finished = true;
        live(check)
    }
}
