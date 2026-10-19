//! Exact single-version evidence from the authenticated paged payload reader.
//! This codec does not grant an Actor, request clock, physical source or delivery.
use super::*;
use serde::ser::{SerializeMap, SerializeSeq};

fn rejected() -> EngineError {
    error(503, "native KV2 storage witness custody or payload rejected")
}

struct CanonicalJson<'a>(&'a Value);
impl Serialize for CanonicalJson<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self.0 {
            Value::Null => serializer.serialize_none(),
            Value::Bool(value) => serializer.serialize_bool(*value),
            Value::Number(value) => value.serialize(serializer),
            Value::String(value) => serializer.serialize_str(value),
            Value::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values { sequence.serialize_element(&CanonicalJson(value))?; }
                sequence.end()
            }
            Value::Object(values) => {
                // Explicit order makes the profile independent of serde's map
                // implementation. Valid UTF-8 lexicographic order agrees with
                // Unicode scalar-value order used by the controller.
                let ordered: BTreeMap<&str, &Value> = values.iter()
                    .map(|(key, value)| (key.as_str(), value)).collect();
                let mut map = serializer.serialize_map(Some(ordered.len()))?;
                for (key, value) in ordered { map.serialize_entry(key, &CanonicalJson(value))?; }
                map.end()
            }
        }
    }
}

fn fingerprint(value: &Value) -> Result<(String, usize)> {
    let bytes = serialize(&CanonicalJson(value), MAX_VALUE_BYTES).map_err(|_| rejected())?;
    let digest = crate::crypto::digest(&bytes);
    let hash = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    Ok((hash, bytes.len()))
}

impl NativeReadView {
    pub(crate) fn storage_version_witness(
        &self,
        path: &str,
        selected: u64,
        reader: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
    ) -> Result<Value> {
        check().map_err(|_| rejected())?;
        if selected == 0 { return Err(bad("a positive explicit version is required")); }
        valid_path(path)?;
        if !self.is_paged() {
            return Err(error(501, "storage witness requires native paged KV2"));
        }
        self.validate_paged_metadata().map_err(|_| rejected())?;
        let entry = self.owner.entries.get(path).ok_or_else(not_found)?;
        let version = entry.versions.get(&selected).ok_or_else(not_found)?;
        let precise = entry.version_precision(selected);
        let graph = self.graph.as_ref().ok_or_else(rejected)?;
        let descriptor = graph.paged.as_ref().ok_or_else(rejected)?
            .descriptors.get(path).and_then(|versions| versions.get(&selected));
        let (hash, bytes) = if version.destroyed {
            if descriptor.is_some() || version.data.is_some() { return Err(rejected()); }
            (None, 0)
        } else {
            // Soft deletion controls public readability only. Retained bytes
            // are authenticated using the original path/version descriptor,
            // without changing time, undeleting, or using the API projection.
            let data = descriptor.ok_or_else(rejected)?
                .read(&graph.key, path, selected, reader, check).map_err(|_| rejected())?;
            check().map_err(|_| rejected())?;
            let (hash, bytes) = fingerprint(data.expose())?;
            drop(data);
            check().map_err(|_| rejected())?;
            (Some(hash), bytes)
        };
        check().map_err(|_| rejected())?;
        Ok(json!({
            "schema":"heptabao-native-kv2-storage-witness-v1",
            "canonical_profile":"heptabao-lossless-json-v1",
            "path":path, "version":selected,
            "created_time":lossless::display_time(version.created_at, precise.created_at),
            "deletion_time":version.deletion_at
                .map(|seconds| lossless::display_time(seconds, precise.deletion_at)).unwrap_or_default(),
            "destroyed":version.destroyed,
            "payload_present":!version.destroyed,
            "payload_canonical_sha256":hash,
            "payload_canonical_bytes":bytes,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn vector() -> Result<Value> {
        lossless::decode_lossless_json(
            r#"{"z":9007199254740993,"unicode":"凭证迁移试验🧪","nested":[null,true,{"zero":"\\u0000"}],"a":0.123456789012345678901234567890}"#.as_bytes(),
        )
    }

    #[test]
    fn native_kv2_storage_witness_canonical_profile_matches_independent_python_vector() -> TestResult {
        let data = vector()?;
        let (hash, bytes) = fingerprint(&data)?;
        assert_eq!(bytes, 134);
        assert_eq!(hash, "8f55c32f8c1f2f2a8d0e5cc14f08b7007ae6ca496782cdc2ae84143879b40395");
        assert_eq!(data["a"].as_number().ok_or("decimal")?.to_string(),
            "0.123456789012345678901234567890");
        assert_eq!(data["z"].as_number().ok_or("integer")?.to_string(), "9007199254740993");
        assert_eq!(data["nested"][2]["zero"].as_str().ok_or("escaped string")?.len(), 6);
        Ok(())
    }

    #[test]
    fn native_kv2_storage_witness_reads_retained_soft_delete_and_rejects_torn_payload() -> TestResult {
        let mut owner = Kv2::default();
        for _ in 0..3 { owner.handle("POST", "data/history", &json!({"data":vector()?}), 100)?; }
        owner.handle("POST", "delete/history", &json!({"versions":[1]}), 101)?;
        owner.handle("POST", "destroy/history", &json!({"versions":[2]}), 102)?;
        let parent = AddressKey::from_bytes([67; 32]);
        let scope = NativeScope { namespace:"", mount:"secret/", incarnation:1 };
        let graph = NativeCellGraph::encode_paged(&owner, &parent, scope, &|| Ok(()))?;
        let mut objects = GraphObjects(BTreeMap::new());
        graph.visit_objects(|object| {
            objects.0.insert(object.reference().id, Arc::clone(object)); Ok(())
        }, &|| Ok(()))?;
        let view = NativeReadView::open_paged_checked(&parent, scope, graph.root(), &objects, &|| Ok(()))?;
        let original_root = graph.root();
        for number in [1, 3] {
            let witness = view.storage_version_witness("history", number, &objects, &|| Ok(()))?;
            assert_eq!(witness["payload_canonical_bytes"], 134);
            assert_eq!(witness["payload_canonical_sha256"], "8f55c32f8c1f2f2a8d0e5cc14f08b7007ae6ca496782cdc2ae84143879b40395");
            assert_eq!(witness["payload_present"], true);
            assert_eq!(witness["destroyed"], false);
            assert_eq!(witness["deletion_time"].as_str().ok_or("time")?.is_empty(), number == 3);
        }
        let absent = view.storage_version_witness("history", 2, &objects, &|| Ok(()))?;
        assert_eq!(absent["destroyed"], true);
        assert_eq!(absent["payload_present"], false);
        assert_eq!(absent["payload_canonical_bytes"], 0);
        assert!(absent["payload_canonical_sha256"].is_null());
        assert_eq!(view.read_with_source("GET", "data/history", &json!({"version":1}),
            Timestamp::checked(103,0)?, &objects)?.status, 404);
        let public = view.read_with_source("GET", "data/history", &json!({"version":3}),
            Timestamp::checked(103,0)?, &objects)?;
        assert_eq!(public.body["data"]["data"]["z"].as_number().ok_or("public integer")?.to_string(), "9007199254740992");
        assert_eq!(view.graph.as_ref().ok_or("graph")?.index.root(), original_root);
        assert!(view.storage_version_witness("history", 0, &objects, &|| Ok(())).is_err());
        assert!(view.storage_version_witness("history", 4, &objects, &|| Ok(())).is_err());
        assert!(view.storage_version_witness("history", 3, &objects, &|| Err(RecordError::Invalid)).is_err());
        let reference = view.graph.as_ref().ok_or("graph")?.paged.as_ref().ok_or("paged")?
            .descriptors.get("history").ok_or("path")?.get(&3).ok_or("version")?.blocks[0].id;
        objects.0.remove(&reference).ok_or("stored block")?;
        assert!(view.storage_version_witness("history", 3, &objects, &|| Ok(())).is_err());
        Ok(())
    }
}
