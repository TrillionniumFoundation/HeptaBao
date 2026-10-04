//! Complete typed logical namespace owner. Partition/restoration are candidate
//! transactions; the caller must publish the resulting ciphertext, opaque record
//! cells and owner removals together before changing runtime custody.
use super::*;
use crate::namespace_custody::Key;
use crate::namespace_record_graph::Cells;

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

fn failed() -> Response {
    Response::error(503, "namespace typed owner validation rejected")
}

impl State {
    pub(super) fn partition_namespace_assets(
        &self,
        actual: &str,
        key: &Key,
    ) -> Result<(Self, NamespaceAssets, Cells), Response> {
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
                .map_err(|_| failed())?;
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
        candidate.validate_format()?;
        Ok((
            candidate,
            NamespaceAssets {
                version: 1,
                namespace: actual.to_owned(),
                incarnation,
                catalog,
                owners,
            },
            cells,
        ))
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
        let mut candidate = self.clone();
        candidate
            .namespaces
            .attach_catalog(actual, assets.catalog)?;
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
                .map_err(|_| failed())?;
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
        candidate.validate_format()?;
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace_custody::{Descriptor, Progress, Submission};
    use crate::service::tests::{Root, bootstrap_unmounted, call};
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn typed_namespace_assets_remove_auth_engine_records_and_child_catalog_atomically() -> TestResult
    {
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
        let (closed, assets, cells) = original
            .partition_namespace_assets("custody", &key)
            .map_err(|_| "partition")?;
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
        let bytes = crate::secret_serde::to_vec(&assets, MAX_STATE_BYTES)?;
        let protected = created.descriptor.replace_assets(&binding, &key, &bytes)?;
        let opened = protected.open_assets(&binding, &key)?;
        let decoded: NamespaceAssets = serde_json::from_slice(&opened)?;
        let restored = closed
            .restore_namespace_assets("custody", &key, decoded, &cells)
            .map_err(|_| "restore")?;
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
