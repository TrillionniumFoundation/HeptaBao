//! Engine metadata and record data share the same exact namespace owner.
//! Partition removes plaintext records from the retained immutable runtime;
//! bounded independent ciphertext cells are returned for durable publication.
use super::*;
use crate::namespace_custody::Key;
use crate::namespace_record_graph::{Cells, Graph};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamespaceAssets {
    namespace: String,
    metadata: Option<CowNamespace>,
    records: Option<Graph>,
}

impl NamespaceAssets {
    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }
}

impl EngineState {
    pub(crate) fn detach_namespace(
        &mut self,
        namespace: &str,
        key: &Key,
    ) -> Result<(NamespaceAssets, Cells)> {
        if namespace.is_empty() || !key.owns_namespace(namespace) {
            return Err(error(503, "namespace engine owner binding rejected"));
        }
        let (records, cells, retained) = if let Some(runtime) = &self.records {
            let private_key = key
                .record_address_key(namespace)
                .map_err(|_| error(503, "namespace record key is unavailable"))?;
            let (retained, owned) = runtime
                .index
                .partition_namespace(namespace, Arc::clone(&private_key))
                .map_err(kv1_records::record_error)?;
            let (protected, _) = runtime
                .protected
                .partition_namespace(namespace, private_key)
                .map_err(kv1_records::record_error)?;
            let (graph, cells) =
                Graph::protect(namespace, key, &owned).map_err(kv1_records::record_error)?;
            let mut objects = Vec::new();
            protected
                .visit_objects(|object| {
                    objects.push(Arc::clone(object));
                    Ok(())
                })
                .map_err(kv1_records::record_error)?;
            (
                Some(graph),
                cells,
                Some(kv1_records::Runtime::with_views(
                    Arc::clone(&runtime.key),
                    retained,
                    protected,
                    runtime
                        .loaded_namespaces
                        .iter()
                        .filter(|loaded| loaded.as_str() != namespace)
                        .cloned()
                        .collect(),
                    objects,
                )),
            )
        } else {
            (None, Cells::new(), None)
        };
        let metadata = self.namespaces.remove(namespace);
        if self.records.is_some() {
            self.records = retained;
        }
        Ok((
            NamespaceAssets {
                namespace: namespace.to_owned(),
                metadata,
                records,
            },
            cells,
        ))
    }

    pub(crate) fn attach_namespace(
        &mut self,
        actual: &str,
        key: &Key,
        assets: NamespaceAssets,
        read_cell: impl Fn(
            &str,
        ) -> std::result::Result<
            zeroize::Zeroizing<Vec<u8>>,
            crate::state_records::RecordError,
        >,
    ) -> Result<()> {
        if actual.is_empty()
            || assets.namespace != actual
            || !key.owns_namespace(actual)
            || self.namespaces.contains_key(actual)
        {
            return Err(error(
                503,
                "namespace engine owner is already loaded or mismatched",
            ));
        }
        let restored = match (&self.records, &assets.records) {
            (Some(runtime), Some(graph)) => {
                let owned = graph
                    .open(actual, key, read_cell)
                    .map_err(kv1_records::record_error)?;
                let index = runtime
                    .index
                    .merge_namespace(actual, &owned)
                    .map_err(kv1_records::record_error)?;
                let mut restored = runtime.clone();
                restored.index = index;
                restored.loaded_namespaces.insert(actual.to_owned());
                Some(restored)
            }
            (None, None) => None,
            (Some(_), None) => None,
            (None, Some(_)) => {
                return Err(error(
                    503,
                    "namespace records have no root publication owner",
                ));
            }
        };
        if let Some(metadata) = assets.metadata {
            self.namespaces.insert(actual.to_owned(), metadata);
        }
        if let Some(restored) = restored {
            self.records = Some(restored);
        }
        self.validate_record_registry()
    }
}
