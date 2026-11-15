//! A detached native mount move is inseparable from typed graph readdressing.
use super::*;
use crate::engines::kv2_native_records::NativeKv2GraphImport;
use crate::state_record_root_v6::{Kv2GraphRef, MountScope};
use crate::state_records::{AddressKey, ObjectRef, RecordError, RecordReader};
use zeroize::Zeroizing;

struct Source<'a, F> {
    scope: &'a MountScope,
    read: &'a F,
}
impl<F: Fn(&MountScope, &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError>>
    RecordReader for Source<'_, F>
{
    fn read_object(
        &self,
        reference: &ObjectRef,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError> {
        (self.read)(self.scope, reference)
    }
}

struct Binding {
    from: MountScope,
    to: MountScope,
    revision: u64,
    retired_incarnation: u64,
}

impl EngineState {
    pub(crate) fn is_native_kv2_remount(&self, namespace: &str, from: &str) -> bool {
        self.namespaces
            .get(namespace)
            .and_then(|owner| {
                owner
                    .mounts
                    .get(&format!("{}/", from.trim_end_matches('/')))
            })
            .is_some_and(|mount| matches!(mount.backend, Backend::Kv2Native(_)))
    }

    fn native_kv2_remount_binding(
        &self,
        namespace: &str,
        from: &str,
        to: &str,
        cas: Option<u64>,
        accepted: &NativeRemountOwner,
    ) -> Result<Binding> {
        if self.native_remount_owner(namespace, from, to)?.as_ref() != Some(accepted) {
            return Err(error(503, "native KV2 remount original mount changed"));
        }
        let from = format!("{}/", canonical_secret_mount(from)?);
        let to = format!("{}/", canonical_secret_mount(to)?);
        if from == to {
            return Err(bad("remount source and destination must differ"));
        }
        let owner = self.namespaces.get(namespace).ok_or_else(not_found)?;
        let current = owner.mounts.get(&from).ok_or_else(not_found)?;
        if !matches!(current.backend, Backend::Kv2Native(_)) || owner.sdk_owners.contains_key(&from)
        {
            return Err(error(503, "native KV2 remount graph owner changed"));
        }
        require_mount_revision(cas, current.revision)?;
        if owner.mounts.keys().any(|existing| {
            existing != &from && (existing.starts_with(&to) || to.starts_with(existing))
        }) {
            return Err(bad("remount destination conflicts with an existing mount"));
        }
        let incarnation = current
            .incarnation
            .max(
                owner
                    .mount_epochs
                    .get(&to)
                    .copied()
                    .unwrap_or(current.incarnation),
            )
            .max(1);
        Ok(Binding {
            from: MountScope {
                namespace: namespace.into(),
                mount: from,
                incarnation: current.incarnation,
            },
            to: MountScope {
                namespace: namespace.into(),
                mount: to,
                incarnation,
            },
            revision: next_mount_revision(current.revision)?,
            retired_incarnation: incarnation
                .checked_add(1)
                .ok_or_else(|| error(507, "mount incarnation exhausted"))?,
        })
    }

    /// ACK preparation checks only immutable catalog/CAS constraints. The
    /// accepted task later reads the then-current graph once under its original
    /// deadline; it never copies a large history merely to prepare the ACK.
    pub(crate) fn check_native_kv2_remount(
        &self,
        namespace: &str,
        from: &str,
        to: &str,
        cas: Option<u64>,
        accepted: &NativeRemountOwner,
    ) -> Result<()> {
        self.native_kv2_remount_binding(namespace, from, to, cas, accepted)
            .map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stage_native_kv2_remount(
        &mut self,
        namespace: &str,
        from: &str,
        to: &str,
        cas: Option<u64>,
        accepted: &NativeRemountOwner,
        parent: &AddressKey,
        actual_graphs: &[Kv2GraphRef],
        read: impl Fn(&MountScope, &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError>,
        check: &impl Fn() -> std::result::Result<(), RecordError>,
    ) -> Result<Option<NativeKv2GraphImport>> {
        let rejected = || error(503, "native KV2 remount authenticated graph rejected");
        check().map_err(|_| rejected())?;
        let binding = self.native_kv2_remount_binding(namespace, from, to, cas, accepted)?;
        self.validate_kv2_lossless_state(None)?;
        let mut matches = actual_graphs
            .iter()
            .filter(|graph| graph.scope == binding.from);
        let actual = matches.next().ok_or_else(rejected)?;
        if matches.next().is_some() || actual_graphs.iter().any(|graph| graph.scope == binding.to) {
            return Err(rejected());
        }
        let current = self
            .namespaces
            .get(namespace)
            .and_then(|owner| owner.mounts.get(&binding.from.mount))
            .ok_or_else(rejected)?;
        let Backend::Kv2Native(view) = &current.backend else {
            return Err(rejected());
        };
        if (view.is_paged()
            && actual.graph_format != crate::engines::kv2_native_records::PAGED_NATIVE_FORMAT)
            || (!view.is_paged()
                && actual.graph_format != crate::engines::kv2_native_records::NATIVE_FORMAT)
            || view.logical_payload_bytes().map_err(|_| rejected())? != actual.logical_payload_bytes
        {
            return Err(rejected());
        }
        let source = Source {
            scope: &binding.from,
            read: &read,
        };
        let (view, objects) = view
            .prepare_graph_readdress(
                parent,
                binding.from.borrowed(),
                &actual.root,
                binding.to.borrowed(),
                &source,
                check,
            )
            .map_err(|cause| match cause {
                RecordError::TooLarge => error(507, "native KV2 remount exceeds graph capacity"),
                _ => rejected(),
            })?;
        let mut candidate = self.clone();
        let owner = candidate
            .namespaces
            .get_mut(namespace)
            .ok_or_else(rejected)?;
        let mut moved = owner
            .mounts
            .remove(&binding.from.mount)
            .ok_or_else(rejected)?;
        moved.backend = Backend::Kv2Native(view);
        moved.revision = binding.revision;
        moved.incarnation = binding.to.incarnation;
        owner
            .mount_epochs
            .insert(binding.from.mount.clone(), binding.retired_incarnation);
        if owner
            .mounts
            .insert(binding.to.mount.clone(), moved)
            .is_some()
        {
            return Err(rejected());
        }
        candidate.validate_kv2_lossless_state(Some(self))?;
        check().map_err(|_| rejected())?;
        *self = candidate;
        Ok(objects)
    }
}
