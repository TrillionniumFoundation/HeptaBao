//! Called by the actual 34 MiB/three-Raft cold receiver regression. The target
//! starts with the complete actual V5 source closure under a different local
//! AES barrier. This exercises staging only: its selected root remains V5.
use super::*;
use crate::ha_state::ClusterStateCodec;
use crate::ha_state::native_v6::NativeV6CodecError;
use crate::request_deadline::RequestDeadlineScope;
use crate::service::native_blob_source::stage_verified_received;
use crate::service::native_v6_ha_objects::ReceivedNativeV6HaObjects;
use heptabao_durable_service::{Barrier, PutRequest};
use heptabao_raft_runtime::LocalV6BlobStage;
use std::cell::Cell;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(in crate::service) struct RewrapTarget {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

fn put(
    durable: &mut DurableService<AeadBarrier>,
    request: &str,
    resource: &str,
    bytes: &[u8],
) -> TestResult {
    durable.put(PutRequest::new(
        "native-ha-local-target-fixture",
        "system",
        request,
        resource,
        [103; 32],
        Secret::new(bytes.to_vec())?,
    )?)?;
    Ok(())
}

fn ciphertext_digests(path: &Path) -> TestResult<BTreeMap<PathBuf, [u8; 32]>> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("nv6.") && name.ends_with(".hbo"))
        {
            result.insert(entry.path(), crypto::digest(&fs::read(entry.path())?));
        }
    }
    Ok(result)
}

impl RewrapTarget {
    pub(in crate::service) fn prepare(service: &Service, path: PathBuf) -> TestResult<Self> {
        let state = service.state.as_ref().ok_or("actual V5 source state")?;
        let plan = service
            .full_existing_record_plan(state)
            .map_err(|_| "actual V5 target seed closure")?;
        assert_eq!(plan.root.replay_epoch, 0);
        private_directory(&path)?;
        let key = Zeroizing::new([107; 32]);
        let mut durable =
            DurableService::create_new(&path, AeadBarrier::new(*key)?, MAX_OPERATIONS)?;
        for (index, object) in plan.objects.iter().enumerate() {
            put(
                &mut durable,
                &format!("target-v5-object-{index}"),
                &object.reference().resource(),
                object.bytes(),
            )?;
        }
        put(&mut durable, "target-v5-root", "state", &plan.bytes)?;
        durable.close()?;
        // No warm root/address key, source Service/barrier or object owner is
        // retained. The independent target opens its own actual V5 journal.
        drop(plan);
        Ok(Self { path, key })
    }

    pub(in crate::service) fn exercise(
        &self,
        received: &ReceivedNativeV6HaObjects,
        codec: &ClusterStateCodec,
        replica: &LocalV6BlobStage,
    ) -> TestResult {
        let mut durable =
            DurableService::reopen(&self.path, AeadBarrier::new(*self.key)?, MAX_OPERATIONS)?;
        let selected = durable.get("system", "state")?.ok_or("target V5 root")?;
        assert_eq!(
            serde_json::from_slice::<Value>(selected.expose())?["storage_format"],
            crate::state_record_root::STORAGE_FORMAT
        );
        let generation = durable.generation();
        let original_session = session(&mut durable, selected.expose())?;
        let permitted = Cell::new(true);
        let source_checks = Cell::new(0usize);
        let target_checks = Cell::new(0usize);
        let mut actor = || {
            source_checks.set(source_checks.get() + 1);
            if permitted.get() {
                Ok(())
            } else {
                Err(NativeV6CodecError::Gate)
            }
        };
        let mut slots = BTreeMap::new();
        received.visit_verified_objects(codec, replica, &mut actor, &mut |object| {
            let metadata =
                stage_verified_received(&mut durable, &original_session, object, &mut || {
                    target_checks.set(target_checks.get() + 1);
                    Ok(())
                })
                .map_err(|_| NativeV6CodecError::Storage)?;
            let slot = Slot::decode(metadata.expose(), object.reference())
                .map_err(|_| NativeV6CodecError::Directory)?;
            assert_eq!(slot.ciphertext_bytes, object.plaintext().len() + 32);
            let mut original = || {
                object
                    .check_original()
                    .map_err(|_| ServiceError::BarrierFailure)
            };
            let pin = durable
                .pin_immutable_object_before_read(
                    &original_session,
                    slot.locator,
                    slot.ciphertext_bytes,
                    &mut original,
                )
                .map_err(|_| NativeV6CodecError::Storage)?;
            let aad = context(object.domain(), object.reference());
            let opened = durable
                .read_immutable_object_before_delivery(&original_session, &pin, &aad, &mut original)
                .map_err(|_| NativeV6CodecError::Storage)?;
            assert!(opened.as_slice() == object.plaintext());
            if slots.is_empty() {
                let actual_ciphertext = pin
                    .read_ciphertext()
                    .map_err(|_| NativeV6CodecError::Storage)?;
                assert!(actual_ciphertext.starts_with(b"HBA1"));
                assert!(
                    AeadBarrier::new([59; 32])
                        .map_err(|_| NativeV6CodecError::Storage)?
                        .open(&aad, &actual_ciphertext)
                        .is_err(),
                    "replication key cannot open the target's local barrier"
                );
            }
            let resource = v6_records::native_resource(object.domain(), object.reference());
            assert!(
                durable
                    .get("system", &resource)
                    .map_err(|_| NativeV6CodecError::Storage)?
                    .is_none()
            );
            assert!(slots.insert(resource, metadata).is_none());
            Ok(())
        })?;
        assert_eq!(slots.len(), received.cipher_closure().object_count());
        assert!(source_checks.get() > target_checks.get());
        assert!(target_checks.get() > slots.len() * 4);
        assert_eq!(durable.generation(), generation);
        assert!(
            durable
                .get("system", "state")?
                .ok_or("unchanged V5 root")?
                .expose()
                == selected.expose()
        );
        assert!(
            durable
                .get("system", "state-native-v6/publication-cursor")?
                .is_none()
        );
        assert!(durable.get("system", "state-native-v6/active")?.is_none());
        let before = ciphertext_digests(&self.path)?;
        assert_eq!(before.len(), slots.len());
        durable.close()?;

        // No locator was registered. A genuine cold retry must authenticate the
        // already linked files and preserve their ciphertext, not overwrite a
        // same-address file with the fresh randomized seal from this attempt.
        let mut durable =
            DurableService::reopen(&self.path, AeadBarrier::new(*self.key)?, MAX_OPERATIONS)?;
        let fresh = session(&mut durable, selected.expose())?;
        let mut checked_stale = false;
        received.visit_verified_objects(codec, replica, &mut actor, &mut |object| {
            if !checked_stale {
                assert!(
                    stage_verified_received(
                        &mut durable,
                        &original_session,
                        object,
                        &mut || Ok(()),
                    )
                    .is_err()
                );
                checked_stale = true;
            }
            let metadata = stage_verified_received(&mut durable, &fresh, object, &mut || Ok(()))
                .map_err(|_| NativeV6CodecError::Storage)?;
            let resource = v6_records::native_resource(object.domain(), object.reference());
            assert!(
                metadata.expose()
                    == slots
                        .get(&resource)
                        .ok_or(NativeV6CodecError::Directory)?
                        .expose()
            );
            Ok(())
        })?;
        assert!(checked_stale);
        assert_eq!(ciphertext_digests(&self.path)?, before);

        // A physical source session with a caller-selected foreign store ID is
        // not a typed grant, even when its instance and generation are current.
        let foreign =
            durable.immutable_source_session("system", "state", selected.expose(), [109; 16])?;
        let mut checked_foreign = false;
        let rejected = received.visit_verified_objects(codec, replica, &mut actor, &mut |object| {
            assert!(
                stage_verified_received(&mut durable, &foreign, object, &mut || Ok(())).is_err()
            );
            checked_foreign = true;
            Err(NativeV6CodecError::Gate)
        });
        assert!(rejected.is_err() && checked_foreign);

        // The caller's target check cannot replace the original source Actor.
        // Revoke it *inside* a target callback: the immediately following
        // original check must reject before any crypto/write work proceeds.
        let mut checked_revocation = false;
        let rejected = received.visit_verified_objects(codec, replica, &mut actor, &mut |object| {
            let result = stage_verified_received(&mut durable, &fresh, object, &mut || {
                permitted.set(false);
                Ok(())
            });
            assert!(matches!(result, Err(ServiceError::BarrierFailure)));
            checked_revocation = true;
            Ok(())
        });
        assert!(rejected.is_err() && checked_revocation);
        permitted.set(true);

        let mut checked_expired = false;
        let rejected = received.visit_verified_objects(codec, replica, &mut actor, &mut |object| {
            if !checked_expired {
                let expired = RequestDeadlineScope::enter(std::time::Instant::now());
                let result = stage_verified_received(&mut durable, &fresh, object, &mut || Ok(()));
                assert!(matches!(result, Err(ServiceError::BarrierFailure)));
                checked_expired = true;
                drop(expired);
            }
            Err(NativeV6CodecError::Gate)
        });
        assert!(rejected.is_err() && checked_expired);
        assert_eq!(durable.generation(), generation);
        assert!(
            durable
                .get("system", "state")?
                .ok_or("retained V5 root")?
                .expose()
                == selected.expose()
        );
        assert_eq!(ciphertext_digests(&self.path)?, before);
        durable.close()?;
        Ok(())
    }
}
