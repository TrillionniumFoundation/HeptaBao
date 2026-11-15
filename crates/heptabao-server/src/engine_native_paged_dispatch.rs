//! Native-only logical dispatch with an explicit, custody-checked point source.
//! The caller must own the original real Service request admission.
use super::*;
use crate::engines::kv2_native_records::NativeReadView;
use crate::state_record_root_v6::MountScope;
use crate::state_records::{ObjectRef, RecordError, RecordReader};
use zeroize::Zeroizing;

struct ScopedReader<'a, F> {
    scope: &'a MountScope,
    source: &'a F,
}
impl<F: Fn(&MountScope, &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError>>
    RecordReader for ScopedReader<'_, F>
{
    fn read_object(
        &self,
        reference: &ObjectRef,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError> {
        (self.source)(self.scope, reference)
    }
}

impl EngineState {
    pub(crate) fn retained_native_read_visible(
        &self,
        original: &crate::engines::kv2_native_records::NativeRetainedReadVersion,
        at: crate::auth::Timestamp,
    ) -> bool {
        self.native_paged_view(original.scope())
            .is_some_and(|view| view.retained_completed_read_visible(original, at))
    }

    // Only exact actual mount ownership may supply a prior live descriptor
    // witness; a detached or newly opened metadata view cannot be substituted.
    pub(crate) fn native_paged_view(&self, scope: &MountScope) -> Option<&NativeReadView> {
        let mount = self
            .namespaces
            .get(&scope.namespace)?
            .mounts
            .get(&scope.mount)?;
        if mount.incarnation != scope.incarnation {
            return None;
        }
        match &mount.backend {
            Backend::Kv2Native(view) if view.is_paged() => Some(view),
            _ => None,
        }
    }
    pub(crate) fn has_paged_native_request(&self, namespace: &str, path: &str) -> bool {
        self.namespaces
            .get(namespace)
            .and_then(|owner| {
                owner
                    .mounts
                    .iter()
                    .find(|(mount, _)| path.starts_with(mount.as_str()))
            })
            .is_some_and(
                |(_, mount)| matches!(&mount.backend, Backend::Kv2Native(view) if view.is_paged()),
            )
    }

    /// Prove the precise metadata projection of this actual controlled write.
    /// Its first precise version may set the permanent KV2 format bit; no
    /// identity, mount, registry, clock or other opaque field may change.
    /// The caller separately binds every native KV graph to its original root.
    #[cfg(test)]
    pub(crate) fn native_cg_metadata_transition(
        &self,
        next: &Self,
        path: &str,
        live: &impl Fn() -> bool,
    ) -> Option<bool> {
        self.native_cg_scoped_metadata_transition(next, "", path, live)
    }

    pub(crate) fn native_cg_scoped_metadata_transition(
        &self,
        next: &Self,
        namespace: &str,
        path: &str,
        live: &impl Fn() -> bool,
    ) -> Option<bool> {
        if !live() {
            return None;
        }
        let binding = self.native_cg_kv2_scoped_data_binding(namespace, path)?;
        if next.native_cg_kv2_scoped_data_binding(namespace, path) != Some(binding) {
            return None;
        }
        let format_changed = self.kv2_lossless_format != next.kv2_lossless_format;
        if format_changed {
            if self.kv2_lossless_format.is_some() || next.kv2_lossless_format != Some(1) {
                return None;
            }
            let scope = MountScope {
                namespace: namespace.to_owned(),
                mount: binding.0.to_owned(),
                incarnation: binding.1,
            };
            if self.native_paged_view(&scope)?.has_lossless_state()
                || !next.native_paged_view(&scope)?.has_lossless_state()
            {
                return None;
            }
        }
        let mut normalized = next.clone();
        normalized.kv2_lossless_format = self.kv2_lossless_format;
        fn metadata_digest(state: &EngineState, live: &impl Fn() -> bool) -> Option<[u8; 32]> {
            use sha2::{Digest, Sha256};
            let mut metadata = state.clone();
            for owner in metadata.namespaces.values_mut() {
                for mount in owner.mounts.values_mut() {
                    if !live() {
                        return None;
                    }
                    // Match project_v6_native_paged's exact opaque projection.
                    // Native graph equality is proved by Service independently.
                    if matches!(mount.backend, Backend::Kv2(_) | Backend::Kv2Native(_)) {
                        mount.backend = Backend::Kv2(kv::Kv2::default());
                    }
                }
            }
            struct Sink<'a, F>(&'a F, Sha256);
            impl<F: Fn() -> bool> std::io::Write for Sink<'_, F> {
                fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                    if !(self.0)() {
                        return Err(std::io::Error::other("native CG deadline expired"));
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
        (metadata_digest(self, live)? == metadata_digest(&normalized, live)?)
            .then_some(format_changed)
    }

    pub(crate) fn read_native_paged(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        at: crate::auth::Timestamp,
        source: impl Fn(&MountScope, &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError>,
    ) -> Result<EngineResponse> {
        self.read_native_paged_completion(namespace, method, path, body, at, source)
            .map(|(response, _)| response)
    }

    pub(crate) fn read_native_paged_completion(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        at: crate::auth::Timestamp,
        source: impl Fn(&MountScope, &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError>,
    ) -> Result<(
        EngineResponse,
        Option<crate::engines::kv2_native_records::NativeDataReadWitness>,
    )> {
        let owner = self.namespaces.get(namespace).ok_or_else(not_found)?;
        let (mount_path, mount) = owner
            .mounts
            .iter()
            .find(|(mount, _)| path.starts_with(mount.as_str()))
            .ok_or_else(not_found)?;
        let Backend::Kv2Native(view) = &mount.backend else {
            return Err(error(503, "native paged dispatcher ownership mismatch"));
        };
        if !view.is_paged() {
            return Err(error(503, "native paged dispatcher format mismatch"));
        }
        let params = SecretJson(if body.is_null() {
            json!({})
        } else {
            body.clone()
        });
        if !params.is_object() {
            return Err(bad("request body must be an object"));
        }
        let scope = MountScope {
            namespace: namespace.into(),
            mount: mount_path.clone(),
            incarnation: mount.incarnation,
        };
        let reader = ScopedReader {
            scope: &scope,
            source: &source,
        };
        view.read_with_source_completion(
            kv_request_method(method, &params),
            &path[mount_path.len()..],
            &params,
            at,
            &reader,
        )
    }

    #[cfg(test)]
    pub(crate) fn dispatch_native_paged(
        &mut self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        at: crate::auth::Timestamp,
        source: impl Fn(&MountScope, &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError>,
    ) -> Result<EngineResponse> {
        self.dispatch_native_paged_completion(namespace, method, path, body, at, source)
            .map(|(response, _)| response)
    }

    pub(crate) fn dispatch_native_paged_completion(
        &mut self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        at: crate::auth::Timestamp,
        source: impl Fn(&MountScope, &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError>,
    ) -> Result<(
        EngineResponse,
        Option<crate::engines::kv2_native_records::NativeDataReadWitness>,
    )> {
        let owner = self.namespaces.get_mut(namespace).ok_or_else(not_found)?;
        let (mount_path, mount) = owner
            .mounts
            .iter_mut()
            .find(|(mount, _)| path.starts_with(mount.as_str()))
            .ok_or_else(not_found)?;
        let incarnation = mount.incarnation;
        let Backend::Kv2Native(view) = &mut mount.backend else {
            return Err(error(503, "native paged dispatcher ownership mismatch"));
        };
        if !view.is_paged() {
            return Err(error(503, "native paged dispatcher format mismatch"));
        }
        let params = SecretJson(if body.is_null() {
            json!({})
        } else {
            body.clone()
        });
        if !params.is_object() {
            return Err(bad("request body must be an object"));
        }
        let method = kv_request_method(method, &params);
        let relative = &path[mount_path.len()..];
        let scope = MountScope {
            namespace: namespace.into(),
            mount: mount_path.clone(),
            incarnation,
        };
        let reader = ScopedReader {
            scope: &scope,
            source: &source,
        };
        if matches!(method, "GET" | "LIST" | "SCAN") {
            return view.read_with_source_completion(method, relative, &params, at, &reader);
        }
        if method == "PATCH" {
            view.hydrate_current_for_patch(relative, &reader)?;
        }
        let result = view.mutate(method, relative, &params, at);
        view.clear_hydrated_payloads()?;
        // Match the ordinary dispatcher: a first precise mutation can add
        // lossless metadata to a previously empty native mount.
        if result.as_ref().is_ok_and(|response| response.mutated) && view.has_lossless_state() {
            self.kv2_lossless_format = Some(1);
        }
        result.map(|response| (response, None))
    }
}

#[cfg(test)]
#[path = "engine_native_controlgroups_metadata_tests.rs"]
mod control_group_metadata_tests;
