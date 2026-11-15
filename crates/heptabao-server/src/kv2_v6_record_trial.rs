//! Pre-admission KV2 record graph experiment on the existing authenticated KV1 pages.
//!
//! This deliberately does NOT enable a V6 production writer/reader. It proves
//! reusable record-index mechanics, scope binding, retained versions, and >16MiB
//! aggregate data while leaving V5 owner limits and old-reader fences unchanged.
use crate::state_records::{
    AddressKey, Kv1Index, Kv1Key, ObjectId, ObjectRef, RecordError, RecordReader, StagedObject,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use zeroize::Zeroizing;

// Keep the private V6 trial using the same compiled type/codec.
use crate::kv2_v6_record_codec::{Cell, FORMAT, MAX_CELL, Scope, decode, encode, key};

#[test]
fn kv2_v6_trial_refuses_malformed_version_field_types_and_destroyed_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let scope = Scope {
        namespace: "isolated".into(),
        mount: "secret/".into(),
        incarnation: 3,
        path: "sealed-history".into(),
    };
    let record_key = key(&scope)?;
    let cases = [
        json!({"current_version": 1, "versions": {"1": {
            "data": ["not", "a", "kv2", "object"], "destroyed": false
        }}}),
        json!({"current_version": 1, "versions": {"1": {
            "data": {"payload": "value"}, "destroyed": "false"
        }}}),
        json!({"current_version": 1, "versions": {"1": {
            "data": {"payload": "must_not_survive_destroy"}, "destroyed": true
        }}}),
    ];
    for (index, entry) in cases.into_iter().enumerate() {
        let bytes = encode(scope.clone(), 1, entry)?;
        assert!(
            decode(&record_key, &bytes).is_err(),
            "malformed KV2 version field accepted at case {index}"
        );
    }
    Ok(())
}

#[test]
fn kv2_v6_trial_accepts_rfc3339_and_sparse_legacy_temporal_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let scope = Scope {
        namespace: "r680-temporal".into(),
        mount: "secret/".into(),
        incarnation: 8,
        path: "good".into(),
    };
    let address = key(&scope)?;
    let entries = [
        json!({"current_version":1,"versions":{"1":{
            "data":{"payload":"good"},"destroyed":false
        }}}),
        json!({"current_version":1,"versions":{"1":{
            "data":{"payload":"good"},"created_time":null,"deletion_time":null
        }}}),
        json!({"current_version":1,"versions":{"1":{
            "data":{"payload":"good"},"destroyed":false,
            "created_time":"2026-10-12T00:00:00.123456789Z","deletion_time":""
        }}}),
        json!({"current_version":1,"versions":{"1":{
            "data":{"payload":"good"},"destroyed":false,
            "created_time":"2026-10-12T00:00:00+09:00",
            "deletion_time":"2026-10-13T10:00:00+09:00"
        }}}),
        // Two representations of the same instant are a valid boundary.
        json!({"current_version":1,"versions":{"1":{
            "data":{"payload":"good"},"destroyed":false,
            "created_time":"2026-10-12T00:00:00+09:00",
            "deletion_time":"2026-10-11T15:00:00Z"
        }}}),
        json!({"current_version":1,"versions":{"1":{
            "data":{"payload":"good"},"destroyed":false,
            "created_time":"2026-10-12T00:00:00+09:00",
            "deletion_time":"2026-10-11T15:00:00.000000001Z"
        }}}),
    ];
    for (case, entry) in entries.into_iter().enumerate() {
        let raw = encode(scope.clone(), 1, entry)?;
        assert_eq!(decode(&address, &raw)?.version, 1, "valid time case {case}");
    }
    Ok(())
}

struct LocalObjects(BTreeMap<ObjectId, Arc<StagedObject>>);
impl RecordReader for LocalObjects {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        let object = self.0.get(&reference.id).ok_or(RecordError::Missing)?;
        if object.reference() != reference {
            return Err(RecordError::Corrupt);
        }
        Ok(Zeroizing::new(object.bytes().to_vec()))
    }
}

fn stage(
    index: &mut Kv1Index,
    objects: &mut LocalObjects,
    record_key: Kv1Key,
    payload: Option<&[u8]>,
) -> Result<(), RecordError> {
    let result = index.edit(record_key, payload)?;
    // Validate the complete edit before publishing *any* of its objects.
    // A late address conflict must never leave earlier objects in the
    // staging cache while the original index still points at the old root.
    let mut pending = BTreeMap::new();
    for object in result.objects {
        let identity = object.reference().id;
        if let Some(previous) = pending.get(&identity).or_else(|| objects.0.get(&identity))
            && (previous.reference() != object.reference() || previous.bytes() != object.bytes())
        {
            return Err(RecordError::Corrupt);
        }
        pending.insert(identity, object);
    }
    objects.0.extend(pending);
    *index = result.next;
    Ok(())
}

#[test]
fn kv2_v6_trial_conflicting_late_object_preserves_all_pre_stage_state()
-> Result<(), Box<dyn std::error::Error>> {
    let address_key = AddressKey::from_bytes([0x64; 32]);
    let mut index = Kv1Index::empty(Arc::clone(&address_key));
    let scope = Scope {
        namespace: "synthetic".into(),
        mount: "secret/".into(),
        incarnation: 1,
        path: "ledger".into(),
    };
    let record_key = key(&scope)?;
    let cell = encode(scope, 1, json!({"data":{"payload":"x".repeat(64 * 1024)}}))?;
    let expected = index.edit(record_key.clone(), Some(&cell))?;
    assert!(
        expected.objects.len() >= 2,
        "fixture must include multiple staged objects"
    );
    let first = Arc::clone(&expected.objects[0]);
    let last = expected.objects.last().ok_or("missing last object")?;
    assert_ne!(first.reference().id, last.reference().id);

    // Poison the last address with an unrelated valid object. Failed staging
    // must not insert earlier objects or change the original index root.
    let mut objects = LocalObjects(BTreeMap::new());
    objects.0.insert(last.reference().id, Arc::clone(&first));
    let root_before = index.root();
    assert!(matches!(
        stage(&mut index, &mut objects, record_key, Some(&cell)),
        Err(RecordError::Corrupt)
    ));
    assert_eq!(index.root(), root_before);
    assert_eq!(objects.0.len(), 1, "failed stage left partial objects");
    assert!(Arc::ptr_eq(
        objects
            .0
            .get(&last.reference().id)
            .ok_or("poison disappeared")?,
        &first
    ));
    assert!(!objects.0.contains_key(&first.reference().id));
    Ok(())
}

#[test]
fn kv2_v6_trial_real_authenticated_index_above_16m_and_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let address_key = AddressKey::from_bytes([0x53; 32]);
    let mut index = Kv1Index::empty(Arc::clone(&address_key));
    let mut objects = LocalObjects(BTreeMap::new());
    let mut first = None;
    let mut last = None;
    let mut aggregate = 0usize;

    // Unlike the current V5 engines owner, the index is built from independent
    // immutable entries. Every payload remains below the per-record envelope.
    for sequence in 0..100_u64 {
        let scope = Scope {
            namespace: "isolated-team".into(),
            mount: "secret/".into(),
            incarnation: 7,
            path: format!("tenant-{sequence:03}"),
        };
        let record_key = key(&scope)?;
        let payload = format!("{sequence:03}").repeat(60 * 1024);
        let cell = encode(
            scope,
            1,
            json!({"current_version":1,"versions":{"1":{"data":{"payload":payload},
                  "destroyed":false,"deletion_time":""}}}),
        )?;
        aggregate += cell.len();
        stage(&mut index, &mut objects, record_key.clone(), Some(&cell))?;
        if sequence == 0 {
            first = Some((record_key.clone(), cell.to_vec()));
        }
        if sequence == 99 {
            last = Some((record_key, cell.to_vec()));
        }
    }
    assert!(
        aggregate > 16 * 1024 * 1024,
        "trial must actually cross V5 boundary"
    );
    assert!(aggregate < 32 * 1024 * 1024, "trial scope remains bounded");

    let retained = index.clone();
    let original = first.ok_or("missing first")?;
    let ending = last.ok_or("missing last")?;
    let reopened = Kv1Index::open(Arc::clone(&address_key), index.root(), &objects)?;
    for (record_key, original_bytes) in [&original, &ending] {
        let bytes = reopened.get(record_key).ok_or("missing reopened record")?;
        assert_eq!(bytes, original_bytes.as_slice());
        assert_eq!(decode(record_key, bytes)?.version, 1);
    }

    // A new version changes one record, never the original pinned snapshot.
    let next_scope = Scope {
        namespace: "isolated-team".into(),
        mount: "secret/".into(),
        incarnation: 7,
        path: "tenant-000".into(),
    };
    let next = encode(
        next_scope,
        2,
        json!({
           "current_version":2, "versions":{
              "1":{"data":{"payload":"prior-preserved"},"destroyed":false},
              "2":{"data":{"payload":"next-owned"},"destroyed":false}
           }
        }),
    )?;
    stage(&mut index, &mut objects, original.0.clone(), Some(&next))?;
    assert_eq!(retained.get(&original.0), Some(original.1.as_slice()));
    assert_eq!(
        decode(&original.0, index.get(&original.0).ok_or("new cell")?)?.version,
        2
    );
    let reopened_again = Kv1Index::open(address_key, index.root(), &objects)?;
    assert_eq!(reopened_again.get(&original.0), Some(next.as_slice()));
    assert_eq!(reopened_again.get(&ending.0), Some(ending.1.as_slice()));
    Ok(())
}

#[test]
fn kv2_v6_trial_incorrect_mount_incarnation_path_and_format_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let scope = Scope {
        namespace: "isolated-team".into(),
        mount: "secret/".into(),
        incarnation: 4,
        path: "invoice".into(),
    };
    let record_key = key(&scope)?;
    let bytes = encode(
        scope.clone(),
        2,
        json!({
            "current_version":2, "versions":{"1":{"destroyed":false},"2":{"destroyed":true}}
        }),
    )?;
    let parsed = decode(&record_key, &bytes)?;
    assert_eq!(parsed.scope, scope);
    assert_eq!(parsed.version, 2);
    for other in [
        Scope {
            incarnation: 5,
            ..scope.clone()
        },
        Scope {
            mount: "new-secret/".into(),
            ..scope.clone()
        },
        Scope {
            namespace: "other-tenant".into(),
            ..scope.clone()
        },
        Scope {
            path: "different".into(),
            ..scope.clone()
        },
    ] {
        assert!(decode(&key(&other)?, &bytes).is_err());
    }
    let mut unknown = serde_json::from_slice::<Value>(&bytes)?;
    unknown["format"] = json!("heptabao-kv2-typed-record-trial-v5");
    assert!(decode(&record_key, &serde_json::to_vec(&unknown)?).is_err());
    unknown["format"] = json!(FORMAT);
    unknown["version"] = json!(0);
    assert!(decode(&record_key, &serde_json::to_vec(&unknown)?).is_err());
    unknown["version"] = json!(2);
    unknown["unexpected"] = json!("must be rejected");
    assert!(decode(&record_key, &serde_json::to_vec(&unknown)?).is_err());
    assert!(matches!(
        encode(scope.clone(), 1, json!({"value":"x".repeat(MAX_CELL)})),
        Err(RecordError::TooLarge)
    ));
    assert!(matches!(
        encode(
            Scope {
                mount: "@reserved/".into(),
                ..scope
            },
            1,
            json!({})
        ),
        Err(RecordError::Invalid)
    ));
    Ok(())
}

#[cfg(test)]
#[path = "kv2_v6_record_disk_trial.rs"]
mod disk_trial;
