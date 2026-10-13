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

    pub(crate) fn read_native_paged(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        at: crate::auth::Timestamp,
        source: impl Fn(&MountScope, &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError>,
    ) -> Result<EngineResponse> {
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
        view.read_with_source(
            kv_request_method(method, &params),
            &path[mount_path.len()..],
            &params,
            at,
            &reader,
        )
    }

    pub(crate) fn dispatch_native_paged(
        &mut self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        at: crate::auth::Timestamp,
        source: impl Fn(&MountScope, &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError>,
    ) -> Result<EngineResponse> {
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
            return view.read_with_source(method, relative, &params, at, &reader);
        }
        if method == "PATCH" {
            view.hydrate_current_for_patch(relative, &reader)?;
        }
        let result = view.mutate(method, relative, &params, at);
        view.clear_hydrated_payloads()?;
        result
    }
}
