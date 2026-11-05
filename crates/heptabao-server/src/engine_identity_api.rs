//! Service-only compatibility entrypoint; ordinary internal Identity contracts
//! remain strict. The same namespace graph is staged and published exactly once.
use super::*;

fn api_request<'a>(path: &'a str, body: &Value) -> Result<(&'a str, SecretJson)> {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let path = path.trim_start_matches('/');
    let mut params = SecretJson(body.clone());
    if params.is_null() {
        *params = json!({});
    }
    let map = params
        .as_object_mut()
        .ok_or_else(|| bad("request body must be an object"))?;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| bad("invalid query parameter"))?;
        if map.contains_key(key) {
            return Err(bad("duplicate request parameter"));
        }
        map.insert(key.into(), Value::String(value.into()));
    }
    Ok((path, params))
}

impl EngineState {
    pub(crate) fn identity_api_alias_accessor(
        &self,
        namespace: &str,
        path: &str,
        body: &Value,
    ) -> Result<Option<String>> {
        let (base, _) = path.split_once('?').unwrap_or((path, ""));
        if !identity::api::owns(base) {
            return Ok(None);
        }
        let (path, params) = api_request(path, body)?;
        let fallback = identity::IdentityState::default();
        let identity = self
            .namespaces
            .get(namespace)
            .map(|state| &state.identity)
            .unwrap_or(&fallback);
        identity::api::alias_write_accessor(identity, path, &params)
    }

    pub(crate) fn handle_identity_api(
        &mut self,
        scope: &IdentityNamespace<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<EngineResponse>> {
        let (base, _) = path.split_once('?').unwrap_or((path, ""));
        if !identity::api::owns(base) {
            return Ok(None);
        }
        let (path, params) = api_request(path, body)?;
        let method = kv_request_method(method, &params);
        let mut candidate = self
            .namespaces
            .get(scope.path)
            .map(|state| state.identity.clone())
            .unwrap_or_default();
        candidate.set_uuid_namespace(scope.id)?;
        let response = identity::api::handle(
            &mut candidate,
            method,
            path,
            &params,
            now,
            scope.id.unwrap_or("root"),
        )?;
        candidate.set_uuid_namespace(None)?;
        if response.mutated {
            self.namespaces
                .entry(scope.path.into())
                .or_default()
                .identity = candidate;
        }
        Ok(Some(response))
    }
}

#[cfg(feature = "native-v6-storage")]
impl EngineState {
    /// Bind metadata without serializing the native KV payload a second time.
    /// The caller must independently retain the authenticated KV1/KV2 roots.
    pub(crate) fn native_identity_metadata_digest(
        &self,
        live: &impl Fn() -> bool,
    ) -> Option<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let mut metadata = self.clone();
        for owner in metadata.namespaces.values_mut() {
            for mount in owner.mounts.values_mut() {
                if !live() {
                    return None;
                }
                if matches!(mount.backend, Backend::Kv2Native(_)) {
                    mount.backend = Backend::Kv2(kv::Kv2::default());
                }
            }
        }
        struct Sink<'a, F>(&'a F, Sha256);
        impl<F: Fn() -> bool> std::io::Write for Sink<'_, F> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if !(self.0)() {
                    return Err(std::io::Error::other("native Identity deadline expired"));
                }
                self.1.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut sink = Sink(live, Sha256::new());
        serde_json::to_writer(&mut sink, &metadata).ok()?;
        live().then(|| sink.1.finalize().into())
    }

    /// Administrative Identity may change only the actual root Identity graph.
    /// Foreign namespace identities, mounts, clocks and format markers remain
    /// byte-identical. This is deliberately narrower than login alias binding.
    #[cfg(test)]
    pub(crate) fn native_root_identity_only_change(
        &self,
        next: &Self,
        live: &impl Fn() -> bool,
    ) -> bool {
        self.native_namespace_identity_only_change("", next, live)
    }

    pub(crate) fn native_namespace_identity_only_change(
        &self,
        namespace: &str,
        next: &Self,
        live: &impl Fn() -> bool,
    ) -> bool {
        if !self.namespaces.keys().eq(next.namespaces.keys()) {
            return false;
        }
        let Some(source) = self.namespaces.get(namespace) else {
            return false;
        };
        let mut normalized = next.clone();
        let Some(root) = normalized.namespaces.get_mut(namespace) else {
            return false;
        };
        root.identity = source.identity.clone();
        match (
            self.native_identity_metadata_digest(live),
            normalized.native_identity_metadata_digest(live),
        ) {
            (Some(before), Some(after)) => before == after,
            _ => false,
        }
    }

    /// Only the already consumed terminal observation receipt may select this
    /// check. It permits the one existing monotonic artifact clock, without
    /// changing Identity, any other metadata, or introducing a new clock owner.
    pub(crate) fn native_identity_terminal_clock_successor(
        &self,
        next: &Self,
        live: &impl Fn() -> bool,
    ) -> bool {
        if match (
            self.kubernetes_artifact_clock,
            next.kubernetes_artifact_clock,
        ) {
            (None, None) => false,
            (Some(before), Some(after)) => after < before,
            _ => true,
        } {
            return false;
        }
        let mut normalized = next.clone();
        normalized.kubernetes_artifact_clock = self.kubernetes_artifact_clock;
        match (
            self.native_identity_metadata_digest(live),
            normalized.native_identity_metadata_digest(live),
        ) {
            (Some(before), Some(after)) => before == after,
            _ => false,
        }
    }
}

#[cfg(all(test, feature = "native-v6-storage"))]
mod native_identity_guard_tests {
    use super::*;

    fn source() -> EngineState {
        let mut source = EngineState::default();
        source.namespaces.insert(
            String::new(),
            CowNamespace(Arc::new(NamespaceState::initialized_empty())),
        );
        source.namespaces.insert(
            "pristine-child".to_owned(),
            CowNamespace(Arc::new(NamespaceState::initialized_empty())),
        );
        source
    }

    #[test]
    fn native_identity_scoped_owner_rejects_root_and_sibling_graph_changes() -> Result<()> {
        let source = source();
        let mut child = source.clone();
        identity::handle(
            &mut child
                .namespaces
                .get_mut("pristine-child")
                .ok_or_else(not_found)?
                .identity,
            "POST",
            "identity/entity",
            &json!({"name":"child-owned"}),
            100,
        )?;
        assert!(source.native_namespace_identity_only_change("pristine-child", &child, &|| true));
        assert!(!source.native_namespace_identity_only_change("", &child, &|| true));
        let mut crossed = child.clone();
        identity::handle(
            &mut crossed
                .namespaces
                .get_mut("")
                .ok_or_else(not_found)?
                .identity,
            "POST",
            "identity/entity",
            &json!({"name":"root-crossed"}),
            100,
        )?;
        assert!(
            !source.native_namespace_identity_only_change("pristine-child", &crossed, &|| true)
        );
        assert!(!source.native_namespace_identity_only_change("missing", &child, &|| true));
        assert!(!source.native_namespace_identity_only_change("pristine-child", &child, &|| false));
        Ok(())
    }

    #[test]
    fn native_identity_guard_rejects_other_metadata_foreign_identity_and_format_drift() -> Result<()>
    {
        let source = source();
        let mut candidate = source.clone();
        identity::handle(
            &mut candidate
                .namespaces
                .get_mut("")
                .ok_or_else(not_found)?
                .identity,
            "POST",
            "identity/entity",
            &json!({"name":"native-identity-only"}),
            100,
        )?;
        assert!(source.native_root_identity_only_change(&candidate, &|| true));

        let mut unrelated = candidate.clone();
        unrelated.lease_clock += 1;
        assert!(!source.native_root_identity_only_change(&unrelated, &|| true));
        unrelated = candidate.clone();
        unrelated.kv2_lossless_format = Some(1);
        assert!(!source.native_root_identity_only_change(&unrelated, &|| true));
        let mut formatted = candidate.clone();
        formatted.kv2_lossless_format = Some(1);
        assert!(!formatted.native_root_identity_only_change(&candidate, &|| true));

        identity::handle(
            &mut candidate
                .namespaces
                .get_mut("pristine-child")
                .ok_or_else(not_found)?
                .identity,
            "POST",
            "identity/entity",
            &json!({"name":"foreign"}),
            100,
        )?;
        assert!(!source.native_root_identity_only_change(&candidate, &|| true));
        assert!(!source.native_root_identity_only_change(&source, &|| false));
        Ok(())
    }

    #[test]
    fn native_identity_guard_terminal_receipt_does_not_allow_identity_or_other_metadata()
    -> Result<()> {
        let source = source();
        assert!(source.native_identity_terminal_clock_successor(&source, &|| true));
        let mut next = source.clone();
        next.transit_cache_format = Some(1);
        assert!(!source.native_identity_terminal_clock_successor(&next, &|| true));
        next = source.clone();
        identity::handle(
            &mut next.namespaces.get_mut("").ok_or_else(not_found)?.identity,
            "POST",
            "identity/group",
            &json!({"name":"cannot-be-a-clock-delta"}),
            100,
        )?;
        assert!(!source.native_identity_terminal_clock_successor(&next, &|| true));
        Ok(())
    }
}
