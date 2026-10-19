//! One root KV2 registry operation, independently bound to its real engine owner.
//! This is a change constraint, never authentication or publication authority.
use super::*;
use crate::state_record_root_v6::{MountScope, OwnerDomain, RecordStateRootV6};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Change {
    Read,
    Enable,
    Tune,
    Disable,
}

pub(crate) struct NativeKv2MountOwner {
    mount: String,
    change: Change,
    source: EngineState,
    succeeded: bool,
    new_scope: Option<MountScope>,
    expected_metadata: Option<[u8; 32]>,
    expected_root: Option<RecordStateRootV6>,
    terminal_observation_bound: bool,
}

impl Drop for NativeKv2MountOwner {
    fn drop(&mut self) {
        self.mount.zeroize();
    }
}

fn denied() -> EngineError {
    error(503, "native KV2 mount owner changed")
}

// Native payloads never enter this metadata projection. The separately checked
// typed root binds every KV1/KV2 graph, including the omitted payload owners.
fn metadata_digest(state: &EngineState, live: &impl Fn() -> bool) -> Result<[u8; 32]> {
    let mut metadata = state.clone();
    for owner in metadata.namespaces.values_mut() {
        for mount in owner.mounts.values_mut() {
            if !live() {
                return Err(denied());
            }
            if matches!(mount.backend, Backend::Kv2Native(_)) {
                mount.backend = Backend::Kv2(kv::Kv2::default());
            }
        }
    }
    struct Sink<'a, F> {
        live: &'a F,
        digest: Sha256,
        bytes: usize,
    }
    impl<F: Fn() -> bool> std::io::Write for Sink<'_, F> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("native mount metadata bound exceeded"))?;
            if !(self.live)() || self.bytes > crate::MAX_APPLICATION_STATE_BYTES {
                return Err(std::io::Error::other("native mount metadata unavailable"));
            }
            self.digest.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Sink {
        live,
        digest: Sha256::new(),
        bytes: 0,
    };
    serde_json::to_writer(&mut sink, &metadata).map_err(|_| denied())?;
    if !live() {
        return Err(denied());
    }
    Ok(sink.digest.finalize().into())
}

impl EngineState {
    // Called only after the real actor's operation ACL and sudo check. Looking
    // up a mount here does not disclose its presence to an unauthorized caller.
    pub(crate) fn capture_native_kv2_mount_owner(
        &self,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<NativeKv2MountOwner> {
        let relative = path.strip_prefix("sys/mounts/").ok_or_else(denied)?;
        let requested = relative.trim_end_matches('/');
        let (requested, tune) = requested
            .strip_suffix("/tune")
            .map_or((requested, false), |mount| (mount, true));
        let requested = canonical_secret_mount(requested)?;
        let mount = format!("{requested}/");
        let owner = self.namespaces.get("").ok_or_else(denied)?;
        let prior = owner.mounts.get(&mount);
        if prior.is_some_and(
            |prior| !matches!(&prior.backend, Backend::Kv2Native(view) if view.is_paged()),
        ) {
            return Err(error(
                501,
                "native mount management requires an actual paged KV2 mount",
            ));
        }
        let change = match (method, tune) {
            ("GET", _) => Change::Read,
            ("POST" | "PUT", true) => Change::Tune,
            ("DELETE", false) => Change::Disable,
            ("POST" | "PUT", false) => {
                // The normal mount handler still checks all fields, conflicts,
                // CAS, TTL/cache defaults and unsupported mount options.
                let kind = body.get("type").and_then(Value::as_str);
                let version = body
                    .get("options")
                    .and_then(|v| v.get("version"))
                    .and_then(Value::as_str)
                    .unwrap_or(if kind == Some("kv-v2") { "2" } else { "1" });
                if !matches!(kind, Some("kv" | "kv-v2")) || version != "2" {
                    return Err(error(501, "native mount creation supports KV2 only"));
                }
                Change::Enable
            }
            _ => return Err(unsupported()),
        };
        Ok(NativeKv2MountOwner {
            mount,
            change,
            source: self.clone(),
            succeeded: false,
            new_scope: None,
            expected_metadata: None,
            expected_root: None,
            terminal_observation_bound: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn seed_retired_clock_for_native_mount_fixture(
        &mut self,
        at: crate::auth::Timestamp,
    ) -> Result<()> {
        // A valid retained floor after the last opaque artifact was retired.
        // The caller must publish this fixture through the actual legacy State
        // writer before activation. This does not supply an operation clock.
        if self.has_kubernetes_opaque_artifact_state() {
            return Err(denied());
        }
        self.kubernetes_artifact_clock = Some(at);
        Ok(())
    }
}

impl NativeKv2MountOwner {
    pub(crate) fn check_source(
        &self,
        source: &EngineState,
        live: &impl Fn() -> bool,
    ) -> Result<()> {
        if metadata_digest(source, live)? != metadata_digest(&self.source, live)?
            || source.record_root() != self.source.record_root()
        {
            return Err(denied());
        }
        Ok(())
    }

    pub(crate) fn admit_candidate(
        &mut self,
        candidate: &EngineState,
        status: u16,
        live: &impl Fn() -> bool,
    ) -> Result<()> {
        if self.expected_metadata.is_some() || self.expected_root.is_some() || !live() {
            return Err(denied());
        }
        if !self
            .source
            .namespaces
            .keys()
            .eq(candidate.namespaces.keys())
            || self.source.record_root() != candidate.record_root()
        {
            return Err(denied());
        }
        let prior = self.source.namespaces.get("").ok_or_else(denied)?;
        let next = candidate.namespaces.get("").ok_or_else(denied)?;
        let before = prior.mounts.get(&self.mount);
        let after = next.mounts.get(&self.mount);
        self.succeeded = status < 300;
        if !self.succeeded || self.change == Change::Read {
            if metadata_digest(candidate, live)? != metadata_digest(&self.source, live)? {
                return Err(denied());
            }
        } else {
            match self.change {
                Change::Enable => {
                    let after = after.ok_or_else(denied)?;
                    let incarnation = prior
                        .mount_epochs
                        .get(&self.mount)
                        .copied()
                        .unwrap_or(1)
                        .max(1);
                    if before.is_some()
                        || !matches!(&after.backend, Backend::Kv2(engine) if engine.is_pristine_for_import())
                        || after.incarnation != incarnation
                        || after.revision != 1
                        || next.mount_epochs.get(&self.mount) != prior.mount_epochs.get(&self.mount)
                    {
                        return Err(denied());
                    }
                    self.new_scope = Some(MountScope {
                        namespace: String::new(),
                        mount: self.mount.clone(),
                        incarnation,
                    });
                }
                Change::Tune => {
                    let before = before.ok_or_else(denied)?;
                    let after = after.ok_or_else(denied)?;
                    if !matches!(&after.backend, Backend::Kv2Native(view) if view.is_paged())
                        || after.incarnation != before.incarnation
                        || next.mount_epochs.get(&self.mount) != prior.mount_epochs.get(&self.mount)
                    {
                        return Err(denied());
                    }
                    let mut unchanged_revision = after.clone();
                    unchanged_revision.revision = before.revision;
                    let same = unchanged_revision.encode_tune_state()?.as_slice()
                        == before.encode_tune_state()?.as_slice();
                    let revision = if same {
                        before.revision
                    } else {
                        next_mount_revision(before.revision)?
                    };
                    if after.revision != revision {
                        return Err(denied());
                    }
                }
                Change::Disable => match before {
                    Some(before) => {
                        let epoch = before
                            .incarnation
                            .max(1)
                            .checked_add(1)
                            .ok_or_else(denied)?;
                        if after.is_some() || next.mount_epochs.get(&self.mount) != Some(&epoch) {
                            return Err(denied());
                        }
                    }
                    None => {
                        if after.is_some()
                            || next.mount_epochs.get(&self.mount)
                                != prior.mount_epochs.get(&self.mount)
                        {
                            return Err(denied());
                        }
                    }
                },
                Change::Read => return Err(denied()),
            }
            // Every other engine/namespace/identity/lease/clock field remains
            // exact. Only this mount and its checked tombstone may differ.
            let mut normalized = candidate.clone();
            let owner = normalized.namespaces.get_mut("").ok_or_else(denied)?;
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
            if metadata_digest(&normalized, live)? != metadata_digest(&self.source, live)? {
                return Err(denied());
            }
        }
        self.expected_metadata = Some(metadata_digest(candidate, live)?);
        Ok(())
    }

    pub(crate) fn admit_root(
        &mut self,
        prior: &RecordStateRootV6,
        next: &RecordStateRootV6,
        live: &impl Fn() -> bool,
    ) -> Result<()> {
        if self.expected_metadata.is_none()
            || self.expected_root.is_some()
            || !live()
            || prior.reader_floor.native_kv2_format != 2
            || next.reader_floor.native_kv2_format != 2
            || next.state_schema < prior.state_schema
            || next.reader_floor.minimum_state_schema < prior.reader_floor.minimum_state_schema
        {
            return Err(denied());
        }
        let mut normalized = next.clone();
        if self.succeeded && self.change == Change::Enable {
            let scope = self.new_scope.as_ref().ok_or_else(denied)?;
            let added = normalized
                .kv2
                .iter()
                .filter(|graph| &graph.scope == scope)
                .collect::<Vec<_>>();
            if added.len() != 1
                || added[0].logical_payload_bytes != 0
                || added[0].graph_format != kv::native_records::PAGED_NATIVE_FORMAT
                || prior.kv2.iter().any(|graph| &graph.scope == scope)
            {
                return Err(denied());
            }
            normalized.kv2.retain(|graph| &graph.scope != scope);
        } else if self.succeeded && self.change == Change::Disable {
            let mut retained = prior.kv2.clone();
            retained.retain(|graph| graph.scope.namespace != "" || graph.scope.mount != self.mount);
            if normalized.kv2 != retained {
                return Err(denied());
            }
            normalized.kv2 = prior.kv2.clone();
        }
        if normalized.kv2 != prior.kv2 {
            return Err(denied());
        }
        normalized.state_schema = prior.state_schema;
        normalized.reader_floor.minimum_state_schema = prior.reader_floor.minimum_state_schema;
        for (old, new) in prior.owners.iter().zip(normalized.owners.iter_mut()) {
            if old.domain == OwnerDomain::Engines && new.domain == OwnerDomain::Engines {
                *new = old.clone();
            }
        }
        // Auth, namespace, database, Raft, KV1, epoch and all reader floors are
        // untouched by a mount operation. The original Auth route guard is not
        // reused or weakened to admit this different owner transition.
        if normalized.encode().map_err(|_| denied())?.as_slice()
            != prior.encode().map_err(|_| denied())?.as_slice()
            || !live()
        {
            return Err(denied());
        }
        self.expected_root = Some(next.clone());
        Ok(())
    }

    pub(crate) fn check_installed(
        &self,
        engines: &EngineState,
        root: &RecordStateRootV6,
        live: &impl Fn() -> bool,
    ) -> Result<()> {
        if self.expected_metadata != Some(metadata_digest(engines, live)?) {
            return Err(denied());
        }
        let expected = self.expected_root.as_ref().ok_or_else(denied)?;
        if root.encode().map_err(|_| denied())?.as_slice()
            != expected.encode().map_err(|_| denied())?.as_slice()
            || !live()
        {
            return Err(denied());
        }
        Ok(())
    }

    pub(crate) fn finish_terminal_unchanged(
        &mut self,
        engines: &EngineState,
        root: &RecordStateRootV6,
        live: &impl Fn() -> bool,
    ) -> Result<()> {
        if self.terminal_observation_bound {
            return Err(denied());
        }
        self.check_installed(engines, root, live)?;
        self.terminal_observation_bound = true;
        Ok(())
    }

    // The Service capsule calls this only before audit, after consuming the
    // actual affine terminal-write receipt against its original checkpoint and
    // matching the receipt's successor to the installed identity/generation.
    // This remains an independent delta constraint, never publication authority.
    pub(crate) fn admit_terminal_clock_successor(
        &mut self,
        engines: &EngineState,
        root: &RecordStateRootV6,
        live: &impl Fn() -> bool,
    ) -> Result<()> {
        if self.terminal_observation_bound || !live() {
            return Err(denied());
        }
        let expected = self.expected_root.as_ref().ok_or_else(denied)?;
        let mut metadata = engines.clone();
        if metadata.kubernetes_artifact_clock != self.source.kubernetes_artifact_clock {
            if !self.source.has_kubernetes_opaque_artifact_state()
                || metadata.kubernetes_artifact_clock.is_none()
                || metadata.kubernetes_artifact_clock < self.source.kubernetes_artifact_clock
            {
                return Err(denied());
            }
            metadata.kubernetes_artifact_clock = self.source.kubernetes_artifact_clock;
        }
        if self.expected_metadata != Some(metadata_digest(&metadata, live)?) {
            return Err(denied());
        }
        let mut normalized = root.clone();
        if normalized.state_schema < expected.state_schema
            || normalized.reader_floor.minimum_state_schema
                < expected.reader_floor.minimum_state_schema
        {
            return Err(denied());
        }
        normalized.state_schema = expected.state_schema;
        normalized.reader_floor.minimum_state_schema = expected.reader_floor.minimum_state_schema;
        for (old, new) in expected.owners.iter().zip(normalized.owners.iter_mut()) {
            if old.domain == new.domain
                && matches!(old.domain, OwnerDomain::Auth | OwnerDomain::Engines)
            {
                *new = old.clone();
            }
        }
        // Exact metadata equality above admits only the one existing engine
        // clock field, never a different mount, lease, identity or engine owner.
        // The receipt's terminal writer separately fixes the Auth clock delta.
        // All graphs, epoch and remaining typed owner/floor fields stay exact.
        if normalized.encode().map_err(|_| denied())?.as_slice()
            != expected.encode().map_err(|_| denied())?.as_slice()
            || !live()
        {
            return Err(denied());
        }
        let metadata = metadata_digest(engines, live)?;
        self.expected_metadata = Some(metadata);
        self.expected_root = Some(root.clone());
        self.terminal_observation_bound = true;
        self.check_installed(engines, root, live)
    }
}
