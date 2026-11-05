//! Pure metadata for a genuinely completed paged data GET. It is neither an
//! Actor nor a physical source owner. Only read_with_source_completion can
//! construct the affine marker, after the actual payload read has succeeded.
use super::*;
use crate::state_record_root_v6::MountScope;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeRetainedReadVersion {
    scope: MountScope,
    graph_format: String,
    resource: String,
    version: u64,
    configuration: [u8; 32],
    metadata: [u8; 32],
    descriptor: [u8; 32],
}
impl Drop for NativeRetainedReadVersion {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.graph_format);
        zeroize::Zeroize::zeroize(&mut self.resource);
        zeroize::Zeroize::zeroize(&mut self.configuration);
        zeroize::Zeroize::zeroize(&mut self.metadata);
        zeroize::Zeroize::zeroize(&mut self.descriptor);
    }
}
impl NativeRetainedReadVersion {
    pub(crate) fn scope(&self) -> &MountScope {
        &self.scope
    }
    pub(crate) fn matches_ingress(&self, namespace: &str, path: &str) -> bool {
        namespace == self.scope.namespace
            && path
                .strip_prefix(&self.scope.mount)
                .and_then(|p| p.strip_prefix("data/"))
                == Some(self.resource.as_str())
    }
    pub(crate) fn structurally_valid(&self) -> bool {
        self.scope.validate().is_ok()
            && self.graph_format == PAGED_NATIVE_FORMAT
            && valid_path(&self.resource).is_ok()
            && self.version > 0
            && self.configuration != [0; 32]
            && self.metadata != [0; 32]
            && self.descriptor != [0; 32]
    }
}
// No Clone or Deserialize: request flags and untrusted wire metadata cannot
// construct this actual completed-payload observation.
pub(crate) struct NativeDataReadWitness(NativeRetainedReadVersion);
impl NativeDataReadWitness {
    pub(crate) fn into_version(self) -> NativeRetainedReadVersion {
        self.0
    }
}
fn fingerprint(value: &impl Serialize) -> Option<[u8; 32]> {
    // Retain the owning root/metadata's existing admission bounds. The secure
    // writer erases every old allocation on growth, including error paths.
    let bytes = crate::secret_serde::to_vec(value, usize::MAX).ok()?;
    Some(crate::crypto::digest(&bytes))
}
impl NativeReadView {
    // Data comparison only, not a renewed source/Actor/request permission.
    fn retained_version(
        &self,
        resource: &str,
        number: u64,
        now: Timestamp,
    ) -> Option<NativeRetainedReadVersion> {
        let graph = self.graph.as_ref()?;
        if !self.is_paged() || number == 0 || valid_path(resource).is_err() {
            return None;
        }
        let entry = self.owner.entries.get(resource)?;
        let version = entry.versions.get(&number)?;
        let precision = entry.version_precision(number);
        if version.destroyed
            || !version
                .deletion_at
                .is_none_or(|at| lossless::time_before(now, at, precision.deletion_at))
        {
            return None;
        }
        let descriptor = graph
            .paged
            .as_ref()?
            .descriptors
            .get(resource)?
            .get(&number)?;
        Some(NativeRetainedReadVersion {
            scope: MountScope {
                namespace: graph.scope.namespace.clone(),
                mount: graph.scope.mount.clone(),
                incarnation: graph.scope.incarnation,
            },
            graph_format: graph.format.clone(),
            resource: resource.to_owned(),
            version: number,
            configuration: fingerprint(&(
                &self.owner.config,
                self.owner.lossless_format,
                &entry.config,
                entry.current_metadata_version,
            ))?,
            metadata: fingerprint(&*SecretJson(version.metadata(
                number,
                &entry.custom_metadata,
                precision,
            )))?,
            descriptor: fingerprint(descriptor)?,
        })
    }
    pub(super) fn completed_data_read(
        &self,
        method: &str,
        path: &str,
        now: Timestamp,
        response: &EngineResponse,
    ) -> Option<NativeDataReadWitness> {
        if method != "GET" || response.status != 200 || response.mutated {
            return None;
        }
        let resource = path.strip_prefix("data/")?;
        let metadata = response.body.get("data")?.get("metadata")?;
        let selected = metadata.get("version")?.as_u64()?;
        let version = self.retained_version(resource, selected, now)?;
        if fingerprint(metadata)? != version.metadata {
            return None;
        }
        Some(NativeDataReadWitness(version))
    }
    pub(crate) fn retained_completed_read_visible(
        &self,
        original: &NativeRetainedReadVersion,
        now: Timestamp,
    ) -> bool {
        if !original.structurally_valid() {
            return false;
        }
        let Some(current) = self.retained_version(&original.resource, original.version, now) else {
            return false;
        };
        current.scope == original.scope
            && current.graph_format == original.graph_format
            && current.resource == original.resource
            && current.version == original.version
            && current.configuration == original.configuration
            && current.metadata == original.metadata
            && current.descriptor == original.descriptor
    }
    pub(crate) fn read_with_source_completion(
        &self,
        method: &str,
        path: &str,
        body: &Value,
        now: Timestamp,
        reader: &impl RecordReader,
    ) -> Result<(EngineResponse, Option<NativeDataReadWitness>)> {
        // Exactly the existing one read and its existing physical checks.
        let response = self.read_with_source(method, path, body, now, reader)?;
        let completed = self.completed_data_read(method, path, now, &response);
        Ok((response, completed))
    }
}
