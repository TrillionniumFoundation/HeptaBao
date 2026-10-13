//! Actual detached KV2 mutations across authenticated namespace ciphertext.
//! No test publishes or installs a Service root.
use super::*;
use crate::auth::Timestamp;
use crate::namespace_custody::{Descriptor, Progress, Submission};
use crate::request_deadline::RequestDeadlineScope;
use serde_json::{Value, json};
use std::cell::Cell;
use std::time::Duration;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const CLUSTER: &str = "native-mutation-fixture";
const EPOCH: u64 = 7;

fn scope() -> NativeScope<'static> {
    NativeScope {
        namespace: "team-a",
        mount: "secret/",
        incarnation: 7,
    }
}
fn at(seconds: u64) -> TestResult<Timestamp> {
    Ok(Timestamp::checked(seconds, 123_456_789)?)
}
fn owner() -> TestResult<NativeReadView> {
    Ok(NativeReadView::fixture_owner(br#"{"config":{"max_versions":0,"cas_required":false,"delete_version_after":0},"entries":{}}"#)?)
}
fn custody() -> TestResult<(Key, NamespaceFrontier)> {
    let binding = Binding::new(CLUSTER.into(), "team-a".into(), "fixture-id".into(), 3)?;
    let created = Descriptor::create(binding.clone(), 3, 2, b"{\"fixture\":true}")?;
    let frontier = NamespaceFrontier {
        binding: binding.clone(),
        key_epoch: created.descriptor.key_epoch(),
        seal_frontier: created.descriptor.seal_frontier(),
        inherited_parent: None,
    };
    let mut progress = Progress::new(binding, &created.descriptor)?;
    progress.submit(&created.descriptor, &created.shares[0])?;
    match progress.submit(&created.descriptor, &created.shares[1])? {
        Submission::Unlocked { key, .. } => Ok((key, frontier)),
        Submission::Pending => Err("fixture custody did not unlock".into()),
    }
}
fn digest(pin: &NativeCipherPin) -> TestResult<[u8; 32]> {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    digest.update(&serde_json::to_vec(&pin.header)?);
    for (resource, object) in pin.objects.iter() {
        digest.update(resource.as_bytes());
        digest.update(&serde_json::to_vec(&object.reference)?);
        digest.update(object.ciphertext());
    }
    Ok(digest.finish().as_ref().try_into()?)
}
// Only ciphertext and hashed/domain-bound references reach the filesystem.
// Destroy both in-memory object ownership and all readers before reloading.
fn disk_reopen(pin: NativeCipherPin) -> TestResult<NativeCipherPin> {
    let directory = std::env::temp_dir().join(format!(
        "heptabao-v6-mutation-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let references: Vec<_> = pin.references().cloned().collect();
    std::fs::write(
        directory.join("manifest.json"),
        serde_json::to_vec(&(pin.header.clone(), &references))?,
    )?;
    for (index, object) in pin.objects.values().enumerate() {
        std::fs::write(
            directory.join(format!("object-{index}.bin")),
            object.ciphertext(),
        )?;
    }
    drop(pin);
    let (header, references): (CipherReference, Vec<CipherReference>) =
        serde_json::from_slice(&std::fs::read(directory.join("manifest.json"))?)?;
    let mut objects = BTreeMap::new();
    for (index, reference) in references.into_iter().enumerate() {
        let object = CipherObject {
            reference,
            bytes: Zeroizing::new(std::fs::read(
                directory.join(format!("object-{index}.bin")),
            )?),
        };
        object.validate()?;
        assert!(
            objects
                .insert(object.reference.resource(), Arc::new(object))
                .is_none()
        );
    }
    std::fs::remove_dir_all(directory)?;
    Ok(NativeCipherPin {
        header,
        objects: Arc::new(objects),
    })
}
fn compare_read(
    view: &NativeReadView,
    pin: &NativeCipherPin,
    key: &Key,
    frontier: &NamespaceFrontier,
    deadline: OriginalDeadline,
    method: &str,
    path: &str,
    body: &Value,
) -> TestResult {
    let original = view.read(method, path, body, at(2000)?);
    pin.inspect_namespace(key, frontier, CLUSTER, EPOCH, scope(), deadline, |opened| {
        let restored = opened.read(
            method,
            path,
            body,
            at(2000).map_err(|_| CustodyError::Invalid)?,
        );
        match (&original, &restored) {
            (Ok(a), Ok(b)) => {
                assert_eq!((a.status, a.mutated), (b.status, b.mutated));
                assert_eq!(a.body, b.body);
                assert_eq!(
                    crate::secret_serde::to_vec(&a.body, 16 * 1024 * 1024)
                        .map_err(|_| CustodyError::Invalid)?,
                    crate::secret_serde::to_vec(&b.body, 16 * 1024 * 1024)
                        .map_err(|_| CustodyError::Invalid)?
                );
            }
            (Err(a), Err(b)) => assert_eq!((a.status, &a.message), (b.status, &b.message)),
            _ => return Err(CustodyError::Invalid),
        }
        Ok(())
    })?;
    Ok(())
}
fn apply(
    view: &mut NativeReadView,
    pin: &mut NativeCipherPin,
    key: &Key,
    frontier: &NamespaceFrontier,
    deadline: OriginalDeadline,
    method: &str,
    path: &str,
    body: &Value,
    seconds: u64,
) -> TestResult {
    let before = digest(pin)?;
    let original = view.mutate(method, path, body, at(seconds)?);
    let result = pin.mutate_namespace(
        key,
        frontier,
        CLUSTER,
        EPOCH,
        scope(),
        deadline,
        method,
        path,
        body,
        at(seconds)?,
        &|| Ok(()),
    );
    assert_eq!(digest(pin)?, before, "old encrypted source changed");
    match (original, result) {
        (Ok(a), Ok(mut b)) => {
            assert_eq!(b.expected_source, pin.header);
            assert_eq!(
                (a.status, a.mutated),
                (b.response.status, b.response.mutated)
            );
            assert_eq!(a.body, b.response.body);
            assert_eq!(a.mutated, b.candidate.is_some());
            if let Some(candidate) = b.candidate.take() {
                *pin = disk_reopen(candidate)?;
            }
        }
        (Err(a), Err(MutationError::Engine(b))) => {
            assert_eq!((a.status, a.message), (b.status, b.message))
        }
        _ => return Err("native mutation changed original KV2 business outcome".into()),
    }
    Ok(())
}

#[test]
fn encrypted_native_mutation_reopens_real_large_history_and_preserves_business_semantics()
-> TestResult {
    let _request = RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(180));
    let deadline = OriginalDeadline::capture()?;
    let (key, frontier) = custody()?;
    let mut view = owner()?;
    view.mutate("POST", "config", &json!({"max_versions":100}), at(1000)?)?;
    let lossless = crate::engines::decode_lossless_json(br#"{"huge":1234567890123456789012345678901234567890,"exponent":1.234567890123456789e-999,"$serde_json::private::Number":"user object","nested":[true,null,{"n":-0.00}]}"#)?;
    for version in 1..=40 {
        let mut blob = String::with_capacity(448 * 1024);
        for chunk in 0..112 {
            let marker = format!("version-{version:05}/chunk-{chunk:05}/");
            blob.push_str(&marker);
            blob.extend(std::iter::repeat_n(
                char::from(b'a' + (version % 26) as u8),
                4096 - marker.len(),
            ));
        }
        view.mutate(
            "POST",
            "data/folder/item",
            &json!({"data":{"blob":blob,"ordinal":version,"structured":lossless}}),
            at(1000 + version)?,
        )?;
    }
    view.mutate(
        "POST",
        "metadata/metadata-only",
        &json!({"custom_metadata":{}}),
        at(1100)?,
    )?;
    let mut pin = NativeCipherPin::project_namespace(
        &view,
        &key,
        frontier.clone(),
        CLUSTER,
        EPOCH,
        scope(),
        deadline,
    )?;
    assert!(pin.ciphertext_bytes() > 16 * 1024 * 1024);
    pin = disk_reopen(pin)?;
    let immutable_old = NativeCipherPin {
        header: pin.header.clone(),
        objects: Arc::clone(&pin.objects),
    };
    let immutable_digest = digest(&immutable_old)?;
    for (method, path, body, seconds) in [
        (
            "POST",
            "data/folder/item",
            json!({"data":{"next":true},"options":{"cas":39}}),
            1200,
        ),
        (
            "POST",
            "data/folder/item",
            json!({"data":{"next":lossless},"options":{"cas":40}}),
            1201,
        ),
        (
            "PATCH",
            "data/folder/item",
            json!({"data":{"patched":null},"options":{"cas":41}}),
            1202,
        ),
        (
            "POST",
            "metadata/folder/item",
            json!({"cas_required":true,"metadata_cas_required":true,"custom_metadata":{"owner":"fixture"}}),
            1203,
        ),
        ("POST", "delete/folder/item", json!({"versions":[2]}), 1204),
        ("POST", "destroy/folder/item", json!({"versions":[3]}), 1205),
        (
            "POST",
            "undelete/folder/item",
            json!({"versions":[2]}),
            1206,
        ),
        (
            "POST",
            "config",
            json!({"max_versions":90,"cas_required":true}),
            1207,
        ),
        ("DELETE", "data/missing", json!({}), 1208),
    ] {
        apply(
            &mut view, &mut pin, &key, &frontier, deadline, method, path, &body, seconds,
        )?;
    }
    for version in 1..=42 {
        compare_read(
            &view,
            &pin,
            &key,
            &frontier,
            deadline,
            "GET",
            "data/folder/item",
            &json!({"version":version}),
        )?;
    }
    for (method, path) in [
        ("GET", "config"),
        ("GET", "metadata/folder/item"),
        ("GET", "metadata/metadata-only"),
        ("GET", "subkeys/folder/item"),
        ("LIST", "metadata"),
        ("SCAN", "metadata"),
    ] {
        compare_read(
            &view,
            &pin,
            &key,
            &frontier,
            deadline,
            method,
            path,
            &json!({}),
        )?;
    }
    assert_eq!(digest(&immutable_old)?, immutable_digest);
    immutable_old.inspect_namespace(&key, &frontier, CLUSTER, EPOCH, scope(), deadline, |old| {
        assert_eq!(old.counts(), (2, 40, 40));
        Ok(())
    })?;
    let receipt =
        pin.inspect_namespace(&key, &frontier, CLUSTER, EPOCH, scope(), deadline, |_| {
            Ok(())
        })?;
    assert_eq!(
        (
            receipt.paths,
            receipt.retained_versions,
            receipt.payload_records
        ),
        (2, 42, 41)
    );
    assert!(
        !receipt.service_reader_admitted
            && !receipt.namespace_custody_admitted
            && !receipt.membership_fence_admitted
            && !receipt.production_writer_admitted
            && !receipt.migration_admitted
            && !receipt.replacement_authority
    );
    eprintln!(
        "encrypted-native-mutation objects={} ciphertext_bytes={} retained_versions={} service_writer_admitted=false replacement_authority=false",
        receipt.objects, receipt.ciphertext_bytes, receipt.retained_versions
    );
    Ok(())
}

#[test]
fn encrypted_native_mutation_authenticates_full_source_before_engine_and_rechecks_owner()
-> TestResult {
    let _request = RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(60));
    let deadline = OriginalDeadline::capture()?;
    let (key, frontier) = custody()?;
    let pin = NativeCipherPin::project_namespace(
        &owner()?,
        &key,
        frontier.clone(),
        CLUSTER,
        EPOCH,
        scope(),
        deadline,
    )?;
    let before = digest(&pin)?;
    for phase in 1..=5 {
        let calls = Cell::new(0);
        let result = pin.mutate_namespace(
            &key,
            &frontier,
            CLUSTER,
            EPOCH,
            scope(),
            deadline,
            "POST",
            "data/item",
            &json!({"data":{"value":"detached"}}),
            at(1000)?,
            &|| {
                calls.set(calls.get() + 1);
                if calls.get() == phase {
                    Err(CustodyError::Unavailable)
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(
            result,
            Err(MutationError::Custody(CustodyError::Unavailable))
        ));
        assert_eq!(calls.get(), phase);
        assert_eq!(digest(&pin)?, before);
    }
    // The original deadline can expire after authenticated decode, after the
    // real handler, or after projection. Neither response nor candidate escapes.
    for phase in 2..=4 {
        let _short_request =
            RequestDeadlineScope::enter(Instant::now() + Duration::from_millis(20));
        let short = OriginalDeadline::capture()?;
        let calls = Cell::new(0);
        let result = pin.mutate_namespace(
            &key,
            &frontier,
            CLUSTER,
            EPOCH,
            scope(),
            short,
            "POST",
            "data/item",
            &json!({"data":{"value":"late"}}),
            at(1000)?,
            &|| {
                calls.set(calls.get() + 1);
                if calls.get() == phase {
                    std::thread::sleep(
                        short.instant().saturating_duration_since(Instant::now())
                            + Duration::from_millis(1),
                    );
                }
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(MutationError::Custody(CustodyError::Deadline))
        ));
        assert_eq!(calls.get(), phase);
        assert_eq!(digest(&pin)?, before);
    }
    let mut wrong_epoch = frontier.clone();
    wrong_epoch.key_epoch += 1;
    assert!(
        NativeCipherPin::project_namespace(
            &owner()?,
            &key,
            wrong_epoch.clone(),
            CLUSTER,
            EPOCH,
            scope(),
            deadline
        )
        .is_err()
    );
    assert!(
        pin.open_namespace(&key, &wrong_epoch, CLUSTER, EPOCH, scope(), deadline)
            .is_err()
    );
    let mut wrong_seal = frontier.clone();
    wrong_seal.seal_frontier += 1;
    assert!(
        pin.open_namespace(&key, &wrong_seal, CLUSTER, EPOCH, scope(), deadline)
            .is_err()
    );
    assert!(
        pin.open_namespace(&key, &frontier, "wrong-cluster", EPOCH, scope(), deadline)
            .is_err()
    );
    for wrong_scope in [
        NativeScope {
            namespace: "team-ab",
            ..scope()
        },
        NativeScope {
            mount: "other/",
            ..scope()
        },
    ] {
        assert!(
            pin.open_namespace(&key, &frontier, CLUSTER, EPOCH, wrong_scope, deadline)
                .is_err()
        );
    }
    let mut wrong_parent = frontier.clone();
    wrong_parent.inherited_parent = Some(InheritedParent::Root {
        cluster_id: CLUSTER.into(),
    });
    assert!(
        pin.open_namespace(&key, &wrong_parent, CLUSTER, EPOCH, scope(), deadline)
            .is_err()
    );
    let wrong_scope = NativeScope {
        incarnation: 8,
        ..scope()
    };
    assert!(
        pin.open_namespace(&key, &frontier, CLUSTER, EPOCH, wrong_scope, deadline)
            .is_err()
    );
    assert!(
        pin.open_namespace(&key, &frontier, CLUSTER, EPOCH + 1, scope(), deadline)
            .is_err()
    );
    for corrupt in [0, 1, 2] {
        let mut objects = (*pin.objects).clone();
        let original = objects.remove(&pin.header.resource()).ok_or("header")?;
        let mut reference = original.reference.clone();
        let mut bytes = Zeroizing::new(original.ciphertext().to_vec());
        if corrupt == 0 {
            reference.record_count += 1;
        } else if corrupt == 1 {
            reference.kind = 1;
        } else {
            *bytes.last_mut().ok_or("empty ciphertext")? ^= 1;
        }
        objects.insert(
            pin.header.resource(),
            Arc::new(CipherObject { reference, bytes }),
        );
        let corrupt_pin = NativeCipherPin {
            header: pin.header.clone(),
            objects: Arc::new(objects),
        };
        assert!(
            corrupt_pin
                .open_namespace(&key, &frontier, CLUSTER, EPOCH, scope(), deadline)
                .is_err()
        );
    }
    let mut missing = (*pin.objects).clone();
    let resource = missing
        .keys()
        .find(|resource| **resource != pin.header.resource())
        .ok_or("graph object")?
        .clone();
    missing.remove(&resource);
    let missing_pin = NativeCipherPin {
        header: pin.header.clone(),
        objects: Arc::new(missing),
    };
    assert!(
        missing_pin
            .mutate_namespace(
                &key,
                &frontier,
                CLUSTER,
                EPOCH,
                scope(),
                deadline,
                "POST",
                "data/item",
                &json!({"data":{}}),
                at(1000)?,
                &|| Ok(())
            )
            .is_err()
    );
    assert_eq!(digest(&pin)?, before);
    Ok(())
}

#[test]
fn encrypted_native_mutation_cannot_replace_or_extend_original_request_deadline() -> TestResult {
    assert!(matches!(
        OriginalDeadline::capture(),
        Err(CustodyError::Deadline)
    ));
    let (key, frontier) = custody()?;
    let (pin, captured) = {
        let _request = RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(60));
        let captured = OriginalDeadline::capture()?;
        (
            NativeCipherPin::project_namespace(
                &owner()?,
                &key,
                frontier.clone(),
                CLUSTER,
                EPOCH,
                scope(),
                captured,
            )?,
            captured,
        )
    };
    assert!(
        pin.open_namespace(&key, &frontier, CLUSTER, EPOCH, scope(), captured)
            .is_err()
    );
    let _longer = RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(120));
    let expired_original = OriginalDeadline(Instant::now() - Duration::from_millis(1));
    assert!(matches!(
        pin.mutate_namespace(
            &key,
            &frontier,
            CLUSTER,
            EPOCH,
            scope(),
            expired_original,
            "POST",
            "data/item",
            &json!({"data":{}}),
            at(1000)?,
            &|| Ok(())
        ),
        Err(MutationError::Custody(CustodyError::Deadline))
    ));
    let _shorter = RequestDeadlineScope::enter(Instant::now() - Duration::from_millis(1));
    assert!(matches!(
        pin.mutate_namespace(
            &key,
            &frontier,
            CLUSTER,
            EPOCH,
            scope(),
            captured,
            "POST",
            "data/item",
            &json!({"data":{}}),
            at(1000)?,
            &|| Ok(())
        ),
        Err(MutationError::Custody(CustodyError::Deadline))
    ));
    Ok(())
}

#[test]
fn encrypted_native_candidate_preserves_real_lossless_import_before_and_after_mutation()
-> TestResult {
    let _request = RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(60));
    let deadline = OriginalDeadline::capture()?;
    let (key, frontier) = custody()?;
    let source = json!({"schema":"openbao270-kv2-lossless-v1",
        "config":{"max_versions":3,"cas_required":false,"metadata_cas_required":false,"delete_version_after":"0s"},
        "entries":{"item":{"created_time":at(100)?.rfc3339(),"updated_time":at(105)?.rfc3339(),
            "current_version":5,"current_metadata_version":2,"oldest_version":3,"max_versions":3,
            "cas_required":true,"metadata_cas_required":true,"delete_version_after":"0s","custom_metadata":{},
            "versions":{"3":{"created_time":at(103)?.rfc3339(),"deletion_time":"","destroyed":true,"data":null},
                "4":{"created_time":at(104)?.rfc3339(),"deletion_time":at(106)?.rfc3339(),"destroyed":false,"data":{"value":"four"}},
                "5":{"created_time":at(105)?.rfc3339(),"deletion_time":"","destroyed":false,"data":{"value":"five"}}}},
            "metadata-only":{"created_time":at(109)?.rfc3339(),"updated_time":at(109)?.rfc3339(),"current_version":0,
                "current_metadata_version":1,"oldest_version":0,"max_versions":2,"cas_required":true,"metadata_cas_required":false,
                "delete_version_after":"0s","custom_metadata":{},"versions":{}}}});
    let mut view = NativeReadView::fixture_lossless_import(&serde_json::to_vec(&source)?)?;
    let mut pin = disk_reopen(NativeCipherPin::project_namespace(
        &view,
        &key,
        frontier.clone(),
        CLUSTER,
        EPOCH,
        scope(),
        deadline,
    )?)?;
    for path in [
        "metadata/item",
        "metadata/metadata-only",
        "data/item?version=3",
        "data/item?version=4",
        "data/item?version=5",
    ] {
        let (path, version) = path
            .split_once("?version=")
            .map_or((path, None), |(p, v)| (p, v.parse::<u64>().ok()));
        compare_read(
            &view,
            &pin,
            &key,
            &frontier,
            deadline,
            "GET",
            path,
            &version.map_or(json!({}), |v| json!({"version":v})),
        )?;
    }
    apply(
        &mut view,
        &mut pin,
        &key,
        &frontier,
        deadline,
        "POST",
        "data/item",
        &json!({"data":{"value":"six"},"options":{"cas":5}}),
        111,
    )?;
    apply(
        &mut view,
        &mut pin,
        &key,
        &frontier,
        deadline,
        "POST",
        "destroy/item",
        &json!({"versions":[4]}),
        112,
    )?;
    compare_read(
        &view,
        &pin,
        &key,
        &frontier,
        deadline,
        "GET",
        "metadata/item",
        &json!({}),
    )?;
    compare_read(
        &view,
        &pin,
        &key,
        &frontier,
        deadline,
        "GET",
        "data/item",
        &json!({"version":6}),
    )?;
    Ok(())
}

// The same deterministic root can occur after A->B->A. A replayed A->C
// mutation must not gain write authority merely because both header bytes
// match. The trusted committed generation must independently advance.
#[test]
fn encrypted_native_publication_preflight_rejects_aba_stale_generation() -> TestResult {
    let _request = RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(90));
    let deadline = OriginalDeadline::capture()?;
    let (key, frontier) = custody()?;
    let pin_a = NativeCipherPin::project_namespace(
        &owner()?,
        &key,
        frontier.clone(),
        CLUSTER,
        EPOCH,
        scope(),
        deadline,
    )?;
    let fence_a1 = NativePublicationFence::observed(1, &pin_a)?;
    let mutation_ab = pin_a.mutate_namespace(
        &key,
        &frontier,
        CLUSTER,
        EPOCH,
        scope(),
        deadline,
        "POST",
        "data/item",
        &json!({"data":{"value":"B"}}),
        at(2000)?,
        &|| Ok(()),
    )?;
    assert!(mutation_ab.response.mutated && mutation_ab.candidate.is_some());
    let fence_b2 = fence_a1
        .preflight(&fence_a1, &mutation_ab, deadline, &|| Ok(()))?
        .ok_or("missing candidate B generation")?;
    assert_eq!(fence_b2.generation.get(), 2);
    assert_ne!(fence_b2.header, fence_a1.header);

    // Restore the *same logical A* in a distinct authenticated publication.
    // A content-addressed header cannot distinguish the returned A from A1.
    let pin_a3 = NativeCipherPin::project_namespace(
        &owner()?,
        &key,
        frontier.clone(),
        CLUSTER,
        EPOCH,
        scope(),
        deadline,
    )?;
    assert_eq!(pin_a.header, pin_a3.header);
    let fence_a3 = NativePublicationFence::observed(3, &pin_a3)?;
    assert_ne!(fence_a1, fence_a3);
    let checks = Cell::new(0);
    let stale = fence_a1.preflight(&fence_a3, &mutation_ab, deadline, &|| {
        checks.set(checks.get() + 1);
        Ok(())
    });
    assert!(matches!(stale, Err(CustodyError::Unavailable)));
    assert_eq!(checks.get(), 1);
    assert_eq!(digest(&pin_a)?, digest(&pin_a)?);
    Ok(())
}

#[test]
fn encrypted_native_publication_preflight_rejects_zero_rollover_and_malformed_candidate()
-> TestResult {
    let _request = RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(90));
    let deadline = OriginalDeadline::capture()?;
    let (key, frontier) = custody()?;
    let pin = NativeCipherPin::project_namespace(
        &owner()?,
        &key,
        frontier.clone(),
        CLUSTER,
        EPOCH,
        scope(),
        deadline,
    )?;
    assert!(matches!(
        NativePublicationFence::observed(0, &pin),
        Err(CustodyError::Invalid)
    ));
    let at_max = NativePublicationFence::observed(u64::MAX, &pin)?;
    let mut prepared = pin.mutate_namespace(
        &key,
        &frontier,
        CLUSTER,
        EPOCH,
        scope(),
        deadline,
        "POST",
        "data/item",
        &json!({"data":{"value":"next"}}),
        at(2000)?,
        &|| Ok(()),
    )?;
    assert!(matches!(
        at_max.preflight(&at_max, &prepared, deadline, &|| Ok(())),
        Err(CustodyError::Invalid)
    ));
    let one = NativePublicationFence::observed(1, &pin)?;
    let saved = prepared.candidate.take().ok_or("missing real candidate")?;
    assert!(matches!(
        one.preflight(&one, &prepared, deadline, &|| Ok(())),
        Err(CustodyError::Invalid)
    ));
    prepared.candidate = Some(saved);
    let candidate = prepared.candidate.as_mut().ok_or("candidate vanished")?;
    candidate.header.domain = crate::v6_record_resources::CipherDomain::Kv1;
    assert!(matches!(
        one.preflight(&one, &prepared, deadline, &|| Ok(())),
        Err(CustodyError::Authentication)
    ));
    Ok(())
}

#[test]
fn encrypted_native_publication_preflight_preserves_noop_owner_and_original_deadline() -> TestResult
{
    let _request = RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(90));
    let deadline = OriginalDeadline::capture()?;
    let (key, frontier) = custody()?;
    let pin = NativeCipherPin::project_namespace(
        &owner()?,
        &key,
        frontier.clone(),
        CLUSTER,
        EPOCH,
        scope(),
        deadline,
    )?;
    let fence = NativePublicationFence::observed(7, &pin)?;
    let noop = pin.mutate_namespace(
        &key,
        &frontier,
        CLUSTER,
        EPOCH,
        scope(),
        deadline,
        "DELETE",
        "data/missing",
        &json!({}),
        at(2000)?,
        &|| Ok(()),
    )?;
    assert!(!noop.response.mutated);
    assert!(noop.candidate.is_none());
    assert!(
        fence
            .preflight(&fence, &noop, deadline, &|| Ok(()))?
            .is_none()
    );
    let calls = Cell::new(0);
    assert!(matches!(
        fence.preflight(&fence, &noop, deadline, &|| {
            calls.set(calls.get() + 1);
            Err(CustodyError::Unavailable)
        }),
        Err(CustodyError::Unavailable)
    ));
    assert_eq!(calls.get(), 1);
    let expired = OriginalDeadline(Instant::now() - Duration::from_millis(1));
    assert!(matches!(
        fence.preflight(&fence, &noop, expired, &|| Ok(())),
        Err(CustodyError::Deadline)
    ));
    Ok(())
}

// The header/generation-only witness must not be mistaken for a verified
// ciphertext closure. A candidate's retained non-root objects can be missing
// or bit-flipped while the header reference remains byte-identical.
#[test]
fn encrypted_native_authenticated_precommit_rejects_corrupt_nonroot_ciphertext() -> TestResult {
    let _request = RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(90));
    let deadline = OriginalDeadline::capture()?;
    let (key, frontier) = custody()?;
    let old = NativeCipherPin::project_namespace(
        &owner()?,
        &key,
        frontier.clone(),
        CLUSTER,
        EPOCH,
        scope(),
        deadline,
    )?;
    let before = digest(&old)?;
    let base = NativePublicationFence::observed(1, &old)?;
    let mut pending = old.mutate_namespace(
        &key,
        &frontier,
        CLUSTER,
        EPOCH,
        scope(),
        deadline,
        "POST",
        "data/blob",
        &json!({"data":{"value":"R".repeat(768 * 1024)}}),
        at(1200)?,
        &|| Ok(()),
    )?;
    let candidate = pending
        .candidate
        .as_ref()
        .ok_or("mutated candidate absent")?;
    assert!(
        candidate.objects.len() >= 3,
        "large value must use non-root pages"
    );
    assert!(
        base.authenticated_preflight(
            &base,
            &pending,
            &key,
            &frontier,
            CLUSTER,
            EPOCH,
            scope(),
            deadline,
            &|| Ok(()),
        )?
        .is_some()
    );
    let original_objects = Arc::clone(&candidate.objects);
    let header_resource = candidate.header.resource();
    let victim = original_objects
        .keys()
        .find(|name| *name != &header_resource)
        .ok_or("missing independent payload object")?
        .clone();

    // A raw identity/generation match alone admits this incomplete candidate.
    let mut missing = (*original_objects).clone();
    missing.remove(&victim);
    pending.candidate.as_mut().ok_or("candidate")?.objects = Arc::new(missing);
    assert!(
        base.preflight(&base, &pending, deadline, &|| Ok(()))
            .is_ok()
    );
    assert!(
        base.authenticated_preflight(
            &base,
            &pending,
            &key,
            &frontier,
            CLUSTER,
            EPOCH,
            scope(),
            deadline,
            &|| Ok(()),
        )
        .is_err()
    );

    // An otherwise well-formed ciphertext with one changed AEAD byte also
    // passes the *structural* witness but must fail authenticated reopen.
    let source = original_objects.get(&victim).ok_or("victim")?;
    let mut corrupt = Zeroizing::new(source.ciphertext().to_vec());
    let last = corrupt.last_mut().ok_or("empty ciphertext")?;
    *last ^= 0x01;
    let mut tampered = (*original_objects).clone();
    tampered.insert(
        victim,
        Arc::new(CipherObject {
            reference: source.reference.clone(),
            bytes: corrupt,
        }),
    );
    pending.candidate.as_mut().ok_or("candidate")?.objects = Arc::new(tampered);
    assert!(
        base.preflight(&base, &pending, deadline, &|| Ok(()))
            .is_ok()
    );
    assert!(
        base.authenticated_preflight(
            &base,
            &pending,
            &key,
            &frontier,
            CLUSTER,
            EPOCH,
            scope(),
            deadline,
            &|| Ok(()),
        )
        .is_err()
    );

    // Neither rejected proposal mutated the immutable, committed source.
    assert_eq!(digest(&old)?, before);
    Ok(())
}
