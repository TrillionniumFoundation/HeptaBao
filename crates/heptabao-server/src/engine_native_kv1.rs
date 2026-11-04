//! One actual KV1 registry operation in the existing V6 KV1 record graph.
//! The owner constrains a candidate; it never authenticates an actor, selects a
//! durable source, publishes a root, or renews a request deadline.
use super::*;
use crate::state_record_root_v6::{OwnerDomain, RecordStateRootV6};
use crate::state_records::{Kv1Key, Kv1Scope};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Change {
    Read,
    Enable,
    Tune,
    Disable,
}

pub(crate) struct NativeKv1Owner {
    namespace: String,
    mount: String,
    incarnation: u64,
    method: String,
    capability: String,
    change: Change,
    source: EngineState,
    succeeded: bool,
    expected_metadata: Option<[u8; 32]>,
    expected_records: Option<kv1_records::Runtime>,
    expected_root: Option<RecordStateRootV6>,
    terminal_observation_bound: bool,
}

impl Drop for NativeKv1Owner {
    fn drop(&mut self) {
        self.namespace.zeroize();
        self.mount.zeroize();
    }
}

fn denied() -> EngineError {
    error(503, "native KV1 operation owner changed")
}

// Native KV2 payloads are bound separately by the unchanged typed root. KV1
// payloads already live in the authenticated record graph, outside this owner.
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
                .ok_or_else(|| std::io::Error::other("native KV1 metadata bound exceeded"))?;
            if !(self.live)() || self.bytes > crate::MAX_APPLICATION_STATE_BYTES {
                return Err(std::io::Error::other("native KV1 metadata unavailable"));
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

fn same_records(
    expected: &kv1_records::Runtime,
    actual: &kv1_records::Runtime,
    compare_observation: bool,
) -> Result<bool> {
    // Materialization reconstructs the AddressKey and clears RAM observations.
    // Compare key material through its existing keyed digest, not Arc identity.
    // Neither these root comparisons nor this key binding replace NativeProof.
    let domain = b"native-kv1-operation-key-binding";
    let input = b"existing-v6-record-owner";
    Ok(expected
        .key
        .digest(domain, input)
        .map_err(kv1_records::record_error)?
        == actual
            .key
            .digest(domain, input)
            .map_err(kv1_records::record_error)?
        && expected.index.root() == actual.index.root()
        && expected.protected.root() == actual.protected.root()
        && expected.loaded_namespaces == actual.loaded_namespaces
        && (!compare_observation
            || expected.observed_lossless_json == actual.observed_lossless_json))
}

fn registry_mount(path: &str) -> Result<(String, bool)> {
    let relative = path.strip_prefix("sys/mounts/").ok_or_else(denied)?;
    let relative = relative.trim_end_matches('/');
    let (relative, tune) = relative
        .strip_suffix("/tune")
        .map_or((relative, false), |mount| (mount, true));
    Ok((format!("{}/", canonical_secret_mount(relative)?), tune))
}

fn remove_scope(
    records: &mut kv1_records::Runtime,
    namespace: &str,
    mount: &str,
    incarnation: u64,
    live: &impl Fn() -> bool,
) -> Result<()> {
    let scope = Kv1Scope::new(namespace, mount, incarnation).map_err(kv1_records::record_error)?;
    let mut after = None;
    loop {
        if !live() {
            return Err(denied());
        }
        let page = records
            .index
            .scan(&scope, "", after.as_deref(), 256, true)
            .map_err(kv1_records::record_error)?;
        if page.next_after.is_some() && (page.keys.is_empty() || page.next_after == after) {
            return Err(denied());
        }
        for path in page.keys {
            if !live() {
                return Err(denied());
            }
            let key = Kv1Key::new(namespace, mount, incarnation, &path)
                .map_err(kv1_records::record_error)?;
            records.apply(key, None)?;
        }
        after = page.next_after;
        if after.is_none() {
            return Ok(());
        }
    }
}

impl EngineState {
    // Classification alone grants no authority. Ordinary KV1 key operations
    // retain their existing KV request/delivery owner and never enter here.
    pub(crate) fn is_native_kv1_registry_route(
        &self,
        namespace: &str,
        path: &str,
        body: &Value,
    ) -> bool {
        if !path.starts_with("sys/mounts/") {
            return false;
        }
        let Ok((mount, _)) = registry_mount(path) else {
            return false;
        };
        if self
            .namespaces
            .get(namespace)
            .and_then(|owner| owner.mounts.get(&mount))
            .is_some_and(|entry| matches!(entry.backend, Backend::Kv1Records))
        {
            return true;
        }
        body.get("type").and_then(Value::as_str) == Some("kv")
            && body
                .get("options")
                .and_then(|options| options.get("version"))
                .and_then(Value::as_str)
                .unwrap_or("1")
                == "1"
    }

    pub(crate) fn capture_native_kv1_owner(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        capability: &str,
    ) -> Result<NativeKv1Owner> {
        let records = self.records.as_ref().ok_or_else(denied)?;
        // Independent loaded namespace cells retain their separate owner.
        if !records.loaded_namespaces.is_empty() || records.index.root() != records.protected.root()
        {
            return Err(error(
                501,
                "native KV1 requires its complete protected record view",
            ));
        }
        let expected_capability = match method {
            "GET" => "read",
            "DELETE" => "delete",
            "POST" | "PUT" => "update",
            _ => return Err(unsupported()),
        };
        if capability != expected_capability {
            return Err(denied());
        }
        let (mount, tune) = registry_mount(path)?;
        let owner = self.namespaces.get(namespace).ok_or_else(denied)?;
        let prior = owner.mounts.get(&mount);
        if prior.is_some_and(|entry| !matches!(entry.backend, Backend::Kv1Records)) {
            return Err(error(
                501,
                "native KV1 registry requires an actual KV1 record mount",
            ));
        }
        let change = match (method, tune) {
            ("GET", _) => Change::Read,
            ("POST" | "PUT", true) => {
                if body
                    .get("options")
                    .and_then(|options| options.get("version"))
                    .and_then(Value::as_str)
                    .is_some_and(|version| version != "1")
                {
                    return Err(error(
                        501,
                        "native KV1 version conversion requires its own graph owner",
                    ));
                }
                Change::Tune
            }
            ("DELETE", false) => Change::Disable,
            ("POST" | "PUT", false) => {
                if body.get("type").and_then(Value::as_str) != Some("kv")
                    || body
                        .get("options")
                        .and_then(|options| options.get("version"))
                        .and_then(Value::as_str)
                        .unwrap_or("1")
                        != "1"
                {
                    return Err(error(501, "native KV1 creation requires version 1"));
                }
                Change::Enable
            }
            _ => return Err(unsupported()),
        };
        let incarnation = prior
            .map(|entry| entry.incarnation)
            .unwrap_or_else(|| owner.mount_epochs.get(&mount).copied().unwrap_or(1).max(1));
        Ok(NativeKv1Owner {
            namespace: namespace.to_owned(),
            mount,
            incarnation,
            method: method.to_owned(),
            capability: capability.to_owned(),
            change,
            source: self.clone(),
            succeeded: false,
            expected_metadata: None,
            expected_records: None,
            expected_root: None,
            terminal_observation_bound: false,
        })
    }
}

impl NativeKv1Owner {
    pub(crate) fn authorization_method(&self) -> &str {
        &self.method
    }
    pub(crate) fn capability(&self) -> &str {
        &self.capability
    }
    pub(crate) fn requires_sudo(&self) -> bool {
        self.method != "GET"
    }
    pub(crate) fn read_only(&self) -> bool {
        self.change == Change::Read
    }

    pub(crate) fn check_source(
        &self,
        source: &EngineState,
        live: &impl Fn() -> bool,
    ) -> Result<()> {
        if !live()
            || metadata_digest(source, live)? != metadata_digest(&self.source, live)?
            || !same_records(
                self.source.records.as_ref().ok_or_else(denied)?,
                source.records.as_ref().ok_or_else(denied)?,
                true,
            )?
            || !live()
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
        if self.expected_metadata.is_some()
            || self.expected_records.is_some()
            || self.expected_root.is_some()
            || !live()
            || !self
                .source
                .namespaces
                .keys()
                .eq(candidate.namespaces.keys())
        {
            return Err(denied());
        }
        let prior = self
            .source
            .namespaces
            .get(&self.namespace)
            .ok_or_else(denied)?;
        let next = candidate
            .namespaces
            .get(&self.namespace)
            .ok_or_else(denied)?;
        let before = prior.mounts.get(&self.mount);
        let after = next.mounts.get(&self.mount);
        let mut records = self.source.records.as_ref().ok_or_else(denied)?.clone();
        let mut normalized = candidate.clone();
        self.succeeded = status < 300;
        if self.succeeded && self.change != Change::Read {
            match self.change {
                Change::Enable => {
                    let after = after.ok_or_else(denied)?;
                    if before.is_some()
                        || !matches!(after.backend, Backend::Kv1Records)
                        || after.incarnation != self.incarnation
                        || after.revision != 1
                        || next.mount_epochs.get(&self.mount) != prior.mount_epochs.get(&self.mount)
                    {
                        return Err(denied());
                    }
                }
                Change::Tune => {
                    let before = before.ok_or_else(denied)?;
                    let after = after.ok_or_else(denied)?;
                    if !matches!(after.backend, Backend::Kv1Records)
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
                Change::Disable => {
                    if let Some(before) = before {
                        let epoch = before
                            .incarnation
                            .max(1)
                            .checked_add(1)
                            .ok_or_else(denied)?;
                        if after.is_some() || next.mount_epochs.get(&self.mount) != Some(&epoch) {
                            return Err(denied());
                        }
                        remove_scope(
                            &mut records,
                            &self.namespace,
                            &self.mount,
                            before.incarnation,
                            live,
                        )?;
                    } else if after.is_some()
                        || next.mount_epochs.get(&self.mount) != prior.mount_epochs.get(&self.mount)
                    {
                        return Err(denied());
                    }
                }
                Change::Read => return Err(denied()),
            }
            {
                let owner = normalized
                    .namespaces
                    .get_mut(&self.namespace)
                    .ok_or_else(denied)?;
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
            }
        }
        // The independently derived retired mount scope is the entire permitted
        // KV1 graph delta; every unrelated key remains part of the comparison.
        if metadata_digest(&normalized, live)? != metadata_digest(&self.source, live)?
            || !same_records(
                &records,
                candidate.records.as_ref().ok_or_else(denied)?,
                true,
            )?
            || !live()
        {
            return Err(denied());
        }
        self.expected_metadata = Some(metadata_digest(candidate, live)?);
        self.expected_records = Some(records);
        Ok(())
    }

    pub(crate) fn disabled_mount(&self) -> Option<(&str, &str)> {
        (self.succeeded && self.change == Change::Disable && self.expected_metadata.is_some())
            .then_some((self.namespace.as_str(), self.mount.as_str()))
    }

    pub(crate) fn admit_root(
        &mut self,
        prior: &RecordStateRootV6,
        next: &RecordStateRootV6,
        live: &impl Fn() -> bool,
    ) -> Result<()> {
        self.admit_root_inner(prior, next, None, live)
    }

    pub(crate) fn admit_root_with_quota_retirement(
        &mut self,
        prior: &RecordStateRootV6,
        next: &RecordStateRootV6,
        retirement: crate::auth::rate_limit_quotas::MountRetirement,
        live: &impl Fn() -> bool,
    ) -> Result<()> {
        self.admit_root_inner(prior, next, Some(retirement), live)
    }

    fn admit_root_inner(
        &mut self,
        prior: &RecordStateRootV6,
        next: &RecordStateRootV6,
        retirement: Option<crate::auth::rate_limit_quotas::MountRetirement>,
        live: &impl Fn() -> bool,
    ) -> Result<()> {
        let records = self.expected_records.as_ref().ok_or_else(denied)?;
        if self.expected_metadata.is_none()
            || self.expected_root.is_some()
            || !live()
            || prior.reader_floor.native_kv2_format != 2
            || next.reader_floor.native_kv2_format != 2
            || self.source.record_root().as_ref() != Some(&prior.kv1)
            || next.kv1 != records.protected.root()
            || next.state_schema < prior.state_schema
            || next.reader_floor.minimum_state_schema < prior.reader_floor.minimum_state_schema
        {
            return Err(denied());
        }
        let mut normalized = next.clone();
        if let Some(retirement) = retirement {
            let (namespace, mount) = self.disabled_mount().ok_or_else(denied)?;
            retirement
                .normalize_owned_disable(namespace, mount, prior, &mut normalized, live)
                .map_err(|_| denied())?;
        }
        normalized.kv1 = prior.kv1.clone();
        normalized.state_schema = prior.state_schema;
        normalized.reader_floor.minimum_state_schema = prior.reader_floor.minimum_state_schema;
        for (old, new) in prior.owners.iter().zip(normalized.owners.iter_mut()) {
            if old.domain == OwnerDomain::Engines && new.domain == OwnerDomain::Engines {
                *new = old.clone();
            }
        }
        // Auth can differ only by the consumed quota retirement above. KV2,
        // namespaces, database, Raft, epoch, key and remaining floors stay exact.
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
        if self.expected_metadata != Some(metadata_digest(engines, live)?)
            || !same_records(
                self.expected_records.as_ref().ok_or_else(denied)?,
                engines.records.as_ref().ok_or_else(denied)?,
                false,
            )?
        {
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

    // Called only after the actual affine terminal receipt has advanced this
    // request's checkpoint. This method admits no independently chosen clock.
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
        if self.expected_metadata != Some(metadata_digest(&metadata, live)?)
            || !same_records(
                self.expected_records.as_ref().ok_or_else(denied)?,
                engines.records.as_ref().ok_or_else(denied)?,
                false,
            )?
        {
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
        if normalized.encode().map_err(|_| denied())?.as_slice()
            != expected.encode().map_err(|_| denied())?.as_slice()
            || !live()
        {
            return Err(denied());
        }
        self.expected_metadata = Some(metadata_digest(engines, live)?);
        self.expected_root = Some(root.clone());
        self.terminal_observation_bound = true;
        self.check_installed(engines, root, live)
    }
}
