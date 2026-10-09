//! Complete typed logical namespace owner. Partition/restoration are candidate
//! transactions; the caller must publish the resulting ciphertext, opaque record
//! cells and owner removals together before changing runtime custody.
use super::*;
use crate::namespace_custody::Key;
use crate::namespace_record_graph::Cells;
use std::collections::BTreeSet;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedNamespace {
    namespace: String,
    incarnation: u64,
    auth: crate::auth::namespace_assets::NamespaceAssets,
    engines: crate::engines::namespace_assets::NamespaceAssets,
    database: database::NamespaceAssets,
    workflows: workflows::NamespaceAssets,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NamespaceAssets {
    version: u32,
    namespace: String,
    incarnation: u64,
    catalog: namespaces::CatalogAssets,
    owners: Vec<OwnedNamespace>,
}

/// An exclusive partial transaction. No State leaves this capsule before
/// the actual keyed ciphertext owner and complete typed cells are installed.
pub(super) struct NamespacePartition<'key> {
    closed: State,
    assets: NamespaceAssets,
    cells: Cells,
    binding: crate::namespace_custody::Binding,
    key: &'key Key,
}

impl NamespacePartition<'_> {
    pub(super) fn finish_with_owner(
        mut self,
        install: impl FnOnce(&mut State, &NamespaceAssets, &Cells) -> Result<(), Response>,
    ) -> Result<State, Response> {
        install(&mut self.closed, &self.assets, &self.cells)?;
        let stamp = self
            .closed
            .sdk_namespace_ciphertext_owner(self.binding.namespace())?;
        self.closed
            .auth
            .bind_sdk_namespace_ciphertext(&self.binding, stamp)
            .map_err(|_error| {
                #[cfg(test)]
                namespace_diagnostics::record_status("assets.finish.bind_ciphertext", _error.status);
                failed()
            })?;
        self.closed.schema = self.closed.writer_schema();
        let actual = self.binding.namespace();
        if !self.key.matches_binding(&self.binding)
            || self
                .closed
                .namespaces
                .custody_binding(&self.closed.cluster_id, actual)?
                != self.binding
        {
            return Err(failed());
        }
        self.closed.namespaces.validate(&self.closed.cluster_id)?;
        let opened = match (
            self.closed.namespaces.custody_owner(actual),
            self.closed.namespaces.inherited_owner(actual),
        ) {
            (Some(owner), None) => owner.open_assets(&self.binding, self.key),
            (None, Some(owner)) => owner.open_assets(&self.binding, self.key),
            _ => return Err(failed()),
        }
        .map_err(|_| failed())?;
        let expected = zeroize::Zeroizing::new(
            owner_store::serialize_owner(&self.assets).map_err(state_serialization_error)?,
        );
        let actual_cells = self
            .closed
            .engines
            .namespace_record_cells(&self.binding)
            .map_err(|_| failed())?;
        if opened.as_slice() != expected.as_slice() || actual_cells != self.cells {
            return Err(failed());
        }
        let authenticated: NamespaceAssets =
            serde_json::from_slice(&opened).map_err(|_| failed())?;
        // Restore the actual MAC-opened graph into an exclusive verification view.
        // No key slot, callback, route grant or durable publication is installed.
        namespace_diagnostic!(
            "assets.finish.restore",
            self.closed.restore_namespace_assets(actual, self.key, authenticated, &actual_cells)
        )?;
        self.closed.schema = self.closed.writer_schema();
        namespace_diagnostic!("assets.finish.format", self.closed.validate_format())?;
        Ok(self.closed)
    }
}

fn failed() -> Response {
    Response::error(503, "namespace typed owner validation rejected")
}

impl NamespaceAssets {
    pub(super) fn batch_hydrated_paths(
        &self,
        current: &namespaces::NamespaceRegistry,
        actual: &str,
    ) -> Result<BTreeSet<String>, Response> {
        if self.version != 1
            || self.namespace != actual
            || current.incarnation(actual) != Some(self.incarnation)
            || self.owners.is_empty()
            || self.owners.len() > 1024
        {
            return Err(failed());
        }
        let mut expected = self.catalog.batch_hydrated_paths(current, actual)?;
        expected.insert(actual.to_owned());
        let mut seen = BTreeSet::new();
        for owned in &self.owners {
            if !seen.insert(owned.namespace.clone())
                || !expected.contains(&owned.namespace)
                || current.incarnation(&owned.namespace) != Some(owned.incarnation)
                || owned.auth.namespace() != owned.namespace
                || owned.engines.namespace() != owned.namespace
            {
                return Err(failed());
            }
        }
        if seen != expected {
            return Err(failed());
        }
        Ok(expected)
    }
}

impl State {
    pub(super) fn partition_namespace_assets<'key>(
        &self,
        actual: &str,
        key: &'key Key,
    ) -> Result<NamespacePartition<'key>, Response> {
        namespace_diagnostic!("assets.partition.source_format", self.validate_format())?;
        let binding = self.namespaces.custody_binding(&self.cluster_id, actual)?;
        if actual.is_empty() || !key.matches_binding(&binding) {
            return Err(failed());
        }
        let incarnation = self.namespaces.incarnation(actual).ok_or_else(failed)?;
        let paths = self.namespaces.partition_paths(actual)?;
        let mut candidate = self.clone();
        let mut owners = Vec::with_capacity(paths.len());
        let mut cells = Cells::new();
        for namespace in paths {
            let incarnation = candidate
                .namespaces
                .incarnation(&namespace)
                .ok_or_else(failed)?;
            let auth = candidate
                .auth
                .detach_namespace(&namespace)
                .map_err(|_error| {
                    #[cfg(test)]
                    namespace_diagnostics::record_status("assets.partition.detach_auth", _error.status);
                    failed()
                })?;
            candidate
                .auth
                .install_sdk_namespace_custody(&namespace, &binding, &auth)
                .map_err(|_error| {
                    #[cfg(test)]
                    namespace_diagnostics::record_status("assets.partition.install_custody", _error.status);
                    failed()
                })?;
            let (engines, private_cells) = candidate
                .engines
                .detach_namespace(&namespace, key)
                .map_err(|_| failed())?;
            for (name, ciphertext) in private_cells {
                if cells.insert(name, ciphertext).is_some() {
                    return Err(failed());
                }
            }
            let database = candidate.database.detach_namespace(&namespace)?;
            let workflows = candidate
                .namespaces
                .workflows
                .detach_namespace(&namespace)?;
            owners.push(OwnedNamespace {
                namespace,
                incarnation,
                auth,
                engines,
                database,
                workflows,
            });
        }
        let catalog = candidate.namespaces.detach_catalog(actual)?;
        // Detachment is deliberately incomplete until the real opaque owner is
        // installed. Only finish_with_owner can expose a fully validated State.
        Ok(NamespacePartition {
            closed: candidate,
            assets: NamespaceAssets {
                version: 1,
                namespace: actual.to_owned(),
                incarnation,
                catalog,
                owners,
            },
            cells,
            binding,
            key,
        })
    }

    pub(super) fn restore_namespace_assets(
        &self,
        actual: &str,
        key: &Key,
        assets: NamespaceAssets,
        cells: &Cells,
    ) -> Result<Self, Response> {
        let binding = self.namespaces.custody_binding(&self.cluster_id, actual)?;
        if actual.is_empty()
            || !key.matches_binding(&binding)
            || assets.version != 1
            || assets.namespace != actual
            || self.namespaces.incarnation(actual) != Some(assets.incarnation)
            || assets.owners.is_empty()
            || assets.owners.len() > 1024
        {
            return Err(failed());
        }
        let stamp = self.sdk_namespace_ciphertext_owner(actual)?;
        let inner = self
            .auth
            .sdk_namespace_custody_opening_owners(actual, &stamp)
            .map_err(|_error| {
                #[cfg(test)]
                namespace_diagnostics::record_status("assets.restore.opening_owners", _error.status);
                failed()
            })?;
        let mut candidate = self.clone();
        candidate
            .namespaces
            .attach_catalog(actual, assets.catalog)?;
        for expected in inner {
            if candidate.sdk_namespace_ciphertext_owner(expected.binding.namespace())? != expected {
                return Err(failed());
            }
        }
        candidate
            .auth
            .remove_sdk_namespace_enclosure(actual, &stamp)
            .map_err(|_error| {
                #[cfg(test)]
                namespace_diagnostics::record_status("assets.restore.remove_enclosure", _error.status);
                failed()
            })?;
        let expected = candidate
            .namespaces
            .partition_paths(actual)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut seen = BTreeSet::new();
        for owned in assets.owners {
            if !seen.insert(owned.namespace.clone())
                || !expected.contains(&owned.namespace)
                || candidate.namespaces.incarnation(&owned.namespace) != Some(owned.incarnation)
                || owned.auth.namespace() != owned.namespace
                || owned.engines.namespace() != owned.namespace
            {
                return Err(failed());
            }
            candidate
                .auth
                .attach_namespace(&owned.namespace, owned.auth)
                .map_err(|_error| {
                    #[cfg(test)]
                    namespace_diagnostics::record_status("assets.restore.attach_auth", _error.status);
                    failed()
                })?;
            candidate
                .engines
                .attach_namespace(&owned.namespace, key, owned.engines, |name| {
                    cells
                        .get(name)
                        .cloned()
                        .ok_or(crate::state_records::RecordError::Missing)
                })
                .map_err(|_| failed())?;
            candidate
                .database
                .attach_namespace(&owned.namespace, owned.database)?;
            candidate
                .namespaces
                .workflows
                .attach_namespace(&owned.namespace, owned.workflows)?;
        }
        if seen != expected {
            return Err(failed());
        }
        namespace_diagnostic!("assets.restore.format", candidate.validate_format())?;
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace_custody::{Descriptor, InheritedDescriptor, Progress, Submission};
    use crate::service::tests::{Root, bootstrap_unmounted, call};
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    enum TypedOwner {
        Independent(Descriptor),
        Inherited(InheritedDescriptor),
    }

    impl TypedOwner {
        fn replace(
            &self,
            binding: &crate::namespace_custody::Binding,
            key: &Key,
            bytes: &[u8],
        ) -> TestResult<Self> {
            Ok(match self {
                Self::Independent(owner) => {
                    Self::Independent(owner.replace_assets(binding, key, bytes)?)
                }
                Self::Inherited(owner) => {
                    Self::Inherited(owner.replace_assets(binding, key, bytes)?)
                }
            })
        }
        fn install(&self, state: &mut State) -> Result<(), Response> {
            match self {
                Self::Independent(owner) => state.namespaces.install_custody_owner(
                    &state.cluster_id,
                    "custody",
                    owner.clone(),
                ),
                Self::Inherited(owner) => state.namespaces.install_inherited_owner(
                    &state.cluster_id,
                    "custody",
                    owner.clone(),
                ),
            }
        }
        fn open(
            &self,
            binding: &crate::namespace_custody::Binding,
            key: &Key,
        ) -> TestResult<Zeroizing<Vec<u8>>> {
            Ok(match self {
                Self::Independent(owner) => owner.open_assets(binding, key)?,
                Self::Inherited(owner) => owner.open_assets(binding, key)?,
            })
        }
    }

    #[test]
    fn typed_namespace_assets_remove_auth_engine_records_and_child_catalog_atomically() -> TestResult
    {
        typed_partition_roundtrip(false)
    }

    #[test]
    fn inherited_namespace_assets_commit_real_root_key_ciphertext_and_restore_all_owners()
    -> TestResult {
        typed_partition_roundtrip(true)
    }

    fn typed_partition_roundtrip(inherited: bool) -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, token) = bootstrap_unmounted(&mut service)?;
        assert!(
            call(
                &mut service,
                "POST",
                "sys/namespaces/custody",
                &token,
                json!({})
            )
            .status
                == 200,
            "namespace created"
        );
        assert!(
            service
                .handle_at(
                    "POST",
                    "sys/namespaces/child",
                    "custody",
                    &token,
                    json!({}),
                    100
                )
                .status
                == 200,
            "actual child created"
        );
        for namespace in ["", "custody", "custody/child"] {
            assert!(
                service
                    .handle_at(
                        "POST",
                        "sys/mounts/records",
                        namespace,
                        &token,
                        json!({"type":"kv","options":{"version":"1"}}),
                        100
                    )
                    .status
                    == 204,
                "real record mount"
            );
            assert!(service.handle_at("POST", "records/owned", namespace, &token, json!({"marker":"namespace-asset-secret-marker", "payload":"x".repeat(4096)}), 100).status == 204, "actual private record");
        }
        assert!(
            service
                .handle_at(
                    "PUT",
                    "sys/policies/acl/scoped",
                    "custody",
                    &token,
                    json!({"policy":"path \"records/*\" { capabilities = [\"read\"] }"}),
                    100
                )
                .status
                == 204,
            "actual scoped policy"
        );
        let issued = service.handle_at(
            "POST",
            "auth/token/create",
            "custody",
            &token,
            json!({"policies":["scoped"], "no_default_policy":true}),
            100,
        );
        assert!(issued.status == 200, "actual scoped token issued");
        let scoped_token = Zeroizing::new(
            issued.body["auth"]["client_token"]
                .as_str()
                .ok_or("scoped token")?
                .to_owned(),
        );
        let original = service.state.clone().ok_or("state")?;
        let binding = original
            .namespaces
            .custody_binding(&original.cluster_id, "custody")
            .map_err(|_| "binding")?;
        let (owner, key) = if inherited {
            let root_key = service
                .barrier_key
                .as_ref()
                .ok_or("actual root barrier key")?;
            let (owner, key) = InheritedDescriptor::create_root(binding.clone(), root_key, b"{}")?;
            (TypedOwner::Inherited(owner), key)
        } else {
            let created = Descriptor::create(binding.clone(), 2, 2, b"{}")?;
            let mut progress = Progress::new(binding.clone(), &created.descriptor)?;
            assert!(
                matches!(
                    progress.submit(&created.descriptor, &created.shares[0])?,
                    Submission::Pending
                ),
                "first share partial"
            );
            let key = match progress.submit(&created.descriptor, &created.shares[1])? {
                Submission::Unlocked { key, .. } => key,
                Submission::Pending => return Err("threshold".into()),
            };
            (TypedOwner::Independent(created.descriptor), key)
        };
        let partition = original
            .partition_namespace_assets("custody", &key)
            .map_err(|_| "partition")?;
        let assets = partition.assets.clone();
        let cells = partition.cells.clone();
        let bytes = crate::secret_serde::to_vec(&assets, MAX_STATE_BYTES)
            .map_err(|_| "typed assets serialization")?;
        let protected = owner.replace(&binding, &key, &bytes)?;
        let mut closed = partition
            .finish_with_owner(|closed, _, cells| {
                closed
                    .engines
                    .publish_namespace_record_cells(&binding, cells)
                    .map_err(|_| failed())?;
                protected.install(closed)
            })
            .map_err(|_| "actual encrypted owner closure")?;
        assert!(
            closed.namespace_exists("custody") && !closed.namespace_exists("custody/child"),
            "closed parent keeps its public owner and unloads actual child routing catalog"
        );
        assert!(
            closed.auth.namespace_is_empty("custody")
                && closed.engines.namespace_is_empty("custody")
                && closed.engines.namespace_is_empty("custody/child"),
            "real typed auth and engine assets unload"
        );
        assert!(
            original
                .auth
                .authenticate_read_only(&scoped_token, 100)
                .is_ok()
                && closed
                    .auth
                    .authenticate_read_only(&scoped_token, 100)
                    .is_err()
                && closed.auth.authenticate_read_only(&token, 100).is_ok(),
            "scoped token authority unloads while root credential stays root owned"
        );
        assert!(
            closed.schema == AUTH_PUBLIC_ORIGIN_STATE_SCHEMA,
            "typed ciphertext and actual native Token API facts require reader floor 86"
        );
        let mut lower = closed.clone();
        lower.schema = NAMESPACE_CUSTODY_STATE_SCHEMA - 1;
        assert!(
            lower.validate_format().is_err() && service.commit_state(&mut lower).is_err(),
            "old reader labels cannot publish custody assets"
        );
        let mut before_origin = closed.clone();
        before_origin.schema = NAMESPACE_CUSTODY_STATE_SCHEMA;
        assert!(
            before_origin.validate_format().is_err()
                && service.commit_state(&mut before_origin).is_err(),
            "supported custody reader 81 cannot relabel authentic native producer facts"
        );
        closed
            .validate_format()
            .map_err(|_| "protected V5 format admission")?;
        let plan = service
            .prepare_record_plan(&mut closed)
            .map_err(|_| "protected V5 plan preparation")?;
        service
            .commit_record_plan(&closed, plan)
            .map_err(|response| {
                // Only these fixed source literals may reach the test report.
                // Never format a response, owner, token, key or recovery reference.
                match response.body["errors"][0].as_str() {
                    Some("record state failed authenticated validation") => {
                        "protected V5 commit authenticated validation"
                    }
                    Some("record durable validation failed; reopen and reconcile") => {
                        "protected V5 commit durable validation"
                    }
                    Some("record storage capacity exhausted; no response released") => {
                        "protected V5 commit storage capacity"
                    }
                    Some("opaque owner capacity exhausted") => "protected V5 commit owner capacity",
                    _ => "protected V5 commit other public rejection",
                }
            })?;
        service.state = Some(closed.clone());
        let manifest = service
            .record_root
            .as_ref()
            .ok_or("protected record root")?;
        let persisted = Service::materialize_record_state(
            manifest,
            &records::DurableReader(service.durable.as_ref().ok_or("durable")?),
        )
        .map_err(|_| "actual protected V5 reopen")?;
        assert!(
            persisted.schema == AUTH_PUBLIC_ORIGIN_STATE_SCHEMA
                && persisted.engines.record_root() == closed.engines.record_root()
                && persisted
                    .auth
                    .authenticate_read_only(&scoped_token, 100)
                    .is_err()
                && !persisted.namespace_exists("custody/child"),
            "genuine durable reopening contains ciphertext and unloaded assets"
        );
        for (name, ciphertext) in &cells {
            let stored = persisted
                .engines
                .read_namespace_record_cell(&binding, name)?;
            assert!(
                stored.as_slice() == ciphertext.as_slice(),
                "actual durable graph retains exact namespace ciphertext cells"
            );
        }
        let opened = if let TypedOwner::Inherited(owner) = &protected {
            let root_key = service.barrier_key.as_ref().ok_or("same actual root key")?;
            let (reopened_key, bytes) = owner.open_root(&binding, root_key)?;
            assert!(
                reopened_key.matches_binding(&binding),
                "actual root key derives the exact namespace owner"
            );
            let wrong = Zeroizing::new([0u8; 32]);
            assert!(
                owner.open_root(&binding, &wrong).is_err(),
                "no alternate root key opens the real durable owner"
            );
            bytes
        } else {
            protected.open(&binding, &key)?
        };
        let decoded: NamespaceAssets = serde_json::from_slice(&opened)?;
        let restored = closed
            .restore_namespace_assets("custody", &key, decoded, &cells)
            .map_err(|_| "restore")?;
        assert!(
            restored.engines.record_root() == closed.engines.record_root(),
            "runtime restoration does not change the protected publication root"
        );
        assert!(
            restored.namespace_exists("custody/child"),
            "actual descendants restore"
        );
        let restored_auth =
            owner_store::serialize_owner(&restored.auth).map_err(|_| "restored auth")?;
        let original_auth =
            owner_store::serialize_owner(&original.auth).map_err(|_| "original auth")?;
        assert!(
            restored_auth.as_slice() == original_auth.as_slice(),
            "all namespace auth assets and root fields restore exactly"
        );
        for namespace in ["", "custody", "custody/child"] {
            let mut engines = (*restored.engines).clone();
            let read = engines
                .handle(namespace, "GET", "records/owned", &json!({}), 100)?
                .ok_or("engine response")?;
            assert!(
                read.body["data"]["marker"] == "namespace-asset-secret-marker",
                "real namespace records survive typed ciphertext restoration"
            );
        }
        let before = owner_store::serialize_owner(&closed).map_err(|_| "closed state")?;
        let decoded: NamespaceAssets = serde_json::from_slice(&opened)?;
        assert!(
            closed
                .restore_namespace_assets("custody", &key, decoded, &Cells::new())
                .is_err(),
            "missing private records cannot partially restore assets"
        );
        let after =
            owner_store::serialize_owner(&closed).map_err(|_| "closed state after failure")?;
        assert!(
            before.as_slice() == after.as_slice(),
            "failed restore leaves retained candidate unchanged"
        );
        assert!(
            original
                .restore_namespace_assets("custody", &key, assets, &cells)
                .is_err(),
            "already loaded catalog rejects collision without replacement"
        );
        Ok(())
    }
}
