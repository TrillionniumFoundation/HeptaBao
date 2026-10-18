//! The strict projection must retain live-owner admission while eliminating
//! only a duplicate encode. Fixtures open actual typed graphs for both floors;
//! these tests grant no disk, Service, HA or publication authority.
use super::*;
use std::cell::Cell;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn key() -> Arc<AddressKey> {
    AddressKey::from_bytes([83; 32])
}

fn project_fixture(state: &EngineState, format: u32) -> TestResult<ReaderFixture> {
    let mut objects = Vec::new();
    let mut collect = |scope: &MountScope, object: &Arc<StagedObject>| {
        objects.push((scope.clone(), Arc::clone(object)));
        Ok(())
    };
    let (opaque, roots) = if format == 2 {
        state.project_v6_native_paged(&key(), &|| Ok(()), &mut collect)?
    } else {
        state.project_v6_native(&key(), &|| Ok(()), &mut collect)?
    };
    Ok(ReaderFixture { opaque, roots, objects })
}

fn install(fixture: ReaderFixture, format: u32) -> TestResult<EngineState> {
    let mut views = BTreeMap::new();
    for reference in &fixture.roots {
        let objects = GraphObjects(
            fixture.objects.iter()
                .filter(|(scope, _)| scope == &reference.scope)
                .map(|(_, object)| (object.reference().id, Arc::clone(object)))
                .collect(),
        );
        let view = if format == 2 {
            let view = NativeReadView::open_paged(
                &key(), reference.scope.borrowed(), reference.root.clone(), &objects,
            )?;
            view.verify_paged_payloads(&objects, &|| Ok(()))?;
            view
        } else {
            NativeReadView::open(
                &key(), reference.scope.borrowed(), reference.root.clone(), &objects,
            )?
        };
        views.insert(reference.scope.clone(), view);
    }
    let mut live = fixture.opaque;
    live.install_native_views(views)?;
    Ok(live)
}

fn fixture(format: u32) -> TestResult<(EngineState, ReaderFixture)> {
    let mut source = EngineState::default();
    source.handle("", "POST", "secret/config", &json!({"max_versions":4}), 100)?
        .ok_or("config")?;
    for version in 1..=2 {
        source.handle(
            "", "POST", "secret/data/history",
            &json!({"data":{"version":version,"nested":[true,null,{"text":"synthetic"}]},
                    "options":{"cas":version-1}}),
            100 + version,
        )?.ok_or("history write")?;
    }
    source.handle(
        "", "POST", "sys/mounts/other",
        &json!({"type":"kv","options":{"version":"2"},"description":"second owner"}),
        103,
    )?.ok_or("second mount")?;
    source.handle("", "POST", "other/data/kept", &json!({"data":{"keep":7}}), 104)?
        .ok_or("second value")?;
    let projected = project_fixture(&source, format)?;
    let live = install(ReaderFixture {
        opaque: projected.opaque.clone(),
        roots: projected.roots.clone(),
        objects: projected.objects.clone(),
    }, format)?;
    Ok((live, projected))
}

fn encoded_roots(roots: &[Kv2GraphRef]) -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(roots)?)
}

#[test]
fn native_checked_projection_floor1_floor2_preserve_complete_roots_and_metadata() -> TestResult {
    for format in [1, 2] {
        let (live, expected) = fixture(format)?;
        assert_eq!(expected.roots.len(), 2);
        live.validate_native_roots(&key(), &expected.roots, &|| Ok(()))?;
        let (opaque, roots) = live.project_checked_native_roots(
            &key(), &expected.roots, format, &|| Ok(()),
        )?;
        assert_eq!(encoded_roots(&roots)?, encoded_roots(&expected.roots)?);
        assert_eq!(serde_json::to_vec(&opaque)?, serde_json::to_vec(&expected.opaque)?);
        assert!(serde_json::to_vec(&live).is_err(), "a live native owner remains non-serializable");
    }
    Ok(())
}

#[test]
fn native_checked_projection_rejects_placeholder_and_inexact_scope_coverage() -> TestResult {
    for format in [1, 2] {
        let (live, expected) = fixture(format)?;
        // The migration projection can encode these pristine placeholders;
        // the strict live-owner projection must never accept them as owners.
        assert!(expected.opaque.project_checked_native_roots(
            &key(), &expected.roots, format, &|| Ok(()),
        ).is_err());
        let pristine = project_fixture(&expected.opaque, format)?;
        assert!(expected.opaque.project_checked_native_roots(
            &key(), &pristine.roots, format, &|| Ok(()),
        ).is_err(), "even roots freshly encoded from placeholders confer no live ownership");
        let mut cases = Vec::new();
        cases.push(Vec::new());
        cases.push(expected.roots[1..].to_vec());
        let mut duplicate = expected.roots.clone();
        duplicate.push(duplicate[0].clone());
        cases.push(duplicate);
        let mut extra = expected.roots.clone();
        let mut foreign = extra[0].clone();
        foreign.scope.mount = "absent/".into();
        extra.push(foreign);
        cases.push(extra);
        for field in 0..3 {
            let mut changed = expected.roots.clone();
            match field {
                0 => changed[0].scope.namespace = "foreign".into(),
                1 => changed[0].scope.mount = "foreign/".into(),
                _ => changed[0].scope.incarnation += 1,
            }
            cases.push(changed);
        }
        let mut reordered = expected.roots.clone();
        reordered.reverse();
        cases.push(reordered);
        for roots in cases {
            assert!(live.project_checked_native_roots(&key(), &roots, format, &|| Ok(())).is_err());
        }
        let mut missing_owner = live.clone();
        let missing = &expected.roots[0].scope;
        missing_owner.namespaces.get_mut(&missing.namespace).ok_or("namespace")?
            .mounts.remove(&missing.mount).ok_or("mount")?;
        assert!(missing_owner.project_checked_native_roots(
            &key(), &expected.roots, format, &|| Ok(()),
        ).is_err());
        for field in 0..3 {
            // Make both the claimed scope and actual mount registry agree on
            // a new owner. The retained typed graph must still reject that
            // rebinding through its real scoped encoder, not just map lookup.
            let mut rebound = live.clone();
            let previous = &expected.roots[0].scope;
            let mut scope = previous.clone();
            match field {
                0 => scope.namespace = "foreign".into(),
                1 => scope.mount = "foreign/".into(),
                _ => scope.incarnation += 1,
            }
            let mut mount = rebound.namespaces.get_mut(&previous.namespace).ok_or("namespace")?
                .mounts.remove(&previous.mount).ok_or("mount")?;
            mount.incarnation = scope.incarnation;
            if scope.namespace != previous.namespace {
                let mut owner = rebound.namespaces.get(&previous.namespace).ok_or("namespace")?.clone();
                owner.mounts.clear();
                rebound.namespaces.insert(scope.namespace.clone(), owner);
            }
            rebound.namespaces.get_mut(&scope.namespace).ok_or("rebound namespace")?
                .mounts.insert(scope.mount.clone(), mount);
            let mut roots = expected.roots.clone();
            roots[0].scope = scope;
            roots.sort_by(|left, right| left.scope.cmp(&right.scope));
            assert!(rebound.project_checked_native_roots(&key(), &roots, format, &|| Ok(())).is_err());
        }
        live.project_checked_native_roots(&key(), &expected.roots, format, &|| Ok(()))?;
    }
    Ok(())
}

#[test]
fn native_checked_projection_rejects_wrong_format_lengths_root_and_address_key() -> TestResult {
    for format in [1, 2] {
        let (live, expected) = fixture(format)?;
        for fault in 0..4 {
            let mut roots = expected.roots.clone();
            match fault {
                0 => roots[0].graph_format = "unknown-native-format".into(),
                1 => roots[0].logical_payload_bytes += 1,
                2 => roots[0].root = Kv1Root::default(),
                _ => {
                    // A reference with the original address but a changed
                    // encoded length must not pass an address-only comparison.
                    roots[0].root.reference.as_mut().ok_or("root reference")?.encoded_bytes += 1;
                }
            }
            assert!(live.project_checked_native_roots(&key(), &roots, format, &|| Ok(())).is_err());
        }
        assert!(live.project_checked_native_roots(
            &key(), &expected.roots, if format == 1 { 2 } else { 1 }, &|| Ok(()),
        ).is_err());
        assert!(live.project_checked_native_roots(
            &key(), &expected.roots, 0, &|| Ok(()),
        ).is_err());
        assert!(live.project_checked_native_roots(
            &AddressKey::from_bytes([84; 32]), &expected.roots, format, &|| Ok(()),
        ).is_err());
    }
    Ok(())
}

#[test]
fn native_checked_projection_pending_cas_write_and_opaque_tune_are_not_hidden() -> TestResult {
    for format in [1, 2] {
        let (mut live, before) = fixture(format)?;
        let response = live.handle(
            "", "POST", "secret/data/history",
            &json!({"data":{"version":3,"changed":true},"options":{"cas":2}}),
            105,
        )?.ok_or("pending CAS write")?;
        assert!(response.mutated);
        assert_eq!(response.body["data"]["version"], 3);
        assert!(live.project_checked_native_roots(
            &key(), &before.roots, format, &|| Ok(()),
        ).is_err(), "the cached graph cannot hide an uncommitted selected-cell edit");
        let next = project_fixture(&live, format)?;
        if format == 2 {
            // Paged live admission also binds the cached descriptor's logical
            // byte total. A pending payload growth is not an installed view;
            // retain that existing rejection until the actual new graph opens.
            assert!(live.validate_native_roots(&key(), &next.roots, &|| Ok(())).is_err());
            assert!(live.project_checked_native_roots(
                &key(), &next.roots, format, &|| Ok(()),
            ).is_err());
            let mut objects = before.objects.clone();
            objects.extend(next.objects.iter().cloned());
            live = install(ReaderFixture {
                opaque: next.opaque.clone(),
                roots: next.roots.clone(),
                objects,
            }, format)?;
        }
        let (_, actual) = live.project_checked_native_roots(&key(), &next.roots, format, &|| Ok(()))?;
        assert_eq!(encoded_roots(&actual)?, encoded_roots(&next.roots)?);
        assert_ne!(encoded_roots(&actual)?, encoded_roots(&before.roots)?);
        let response = live.handle(
            "", "POST", "sys/mounts/secret/tune",
            &json!({"description":"changed opaque mount metadata","cas_revision":1}),
            106,
        )?.ok_or("mount tune")?;
        assert!(response.mutated);
        let (opaque, roots) = live.project_checked_native_roots(&key(), &next.roots, format, &|| Ok(()))?;
        assert_eq!(encoded_roots(&roots)?, encoded_roots(&next.roots)?);
        assert_ne!(serde_json::to_vec(&opaque)?, serde_json::to_vec(&next.opaque)?,
            "Service must still compare the returned opaque owner with authenticated metadata");
    }
    Ok(())
}

#[test]
fn native_checked_projection_original_gate_can_reject_before_during_and_after_encoding() -> TestResult {
    for format in [1, 2] {
        let (live, expected) = fixture(format)?;
        let calls = Cell::new(0_usize);
        live.project_checked_native_roots(&key(), &expected.roots, format, &|| {
            calls.set(calls.get() + 1);
            Ok(())
        })?;
        let total = calls.get();
        assert!(total > 4);
        for stop in [1, total / 2, total] {
            calls.set(0);
            let rejected = live.project_checked_native_roots(&key(), &expected.roots, format, &|| {
                calls.set(calls.get() + 1);
                if calls.get() >= stop { Err(RecordError::Invalid) } else { Ok(()) }
            });
            assert!(matches!(rejected, Err(RecordError::Invalid)));
        }
        let (opaque, roots) = live.project_checked_native_roots(&key(), &expected.roots, format, &|| Ok(()))?;
        assert_eq!(encoded_roots(&roots)?, encoded_roots(&expected.roots)?);
        assert_eq!(serde_json::to_vec(&opaque)?, serde_json::to_vec(&expected.opaque)?);
    }
    Ok(())
}

#[test]
fn native_checked_projection_preserves_aggregate_mount_limit() -> TestResult {
    for format in [1, 2] {
        let (mut live, fixture) = fixture(format)?;
        let template_scope = &fixture.roots[0].scope;
        let template = live.namespaces.get(&template_scope.namespace).ok_or("namespace")?
            .mounts.get(&template_scope.mount).ok_or("mount")?.clone();
        let mut roots = fixture.roots;
        let owner = NativeReadView::fixture_owner(&serde_json::to_vec(&Kv2::default())?)?;
        while roots.len() <= crate::state_record_root_v6::MAX_KV2_MOUNTS {
            let scope = MountScope {
                namespace: "".into(),
                mount: format!("extra-{}/", roots.len()),
                incarnation: template.incarnation,
            };
            let graph = if format == 2 {
                owner.encode_paged(&key(), scope.borrowed(), &|| Ok(()))?
            } else {
                owner.encode(&key(), scope.borrowed(), &|| Ok(()))?
            };
            let mut objects = GraphObjects::default();
            graph.visit_objects(|object| {
                objects.0.insert(object.reference().id, Arc::clone(object));
                Ok(())
            }, &|| Ok(()))?;
            let view = if format == 2 {
                NativeReadView::open_paged(&key(), scope.borrowed(), graph.root(), &objects)?
            } else {
                NativeReadView::open(&key(), scope.borrowed(), graph.root(), &objects)?
            };
            let mut mount = template.clone();
            mount.backend = Backend::Kv2Native(view);
            live.namespaces.get_mut("").ok_or("root namespace")?.mounts.insert(scope.mount.clone(), mount);
            roots.push(Kv2GraphRef {
                scope,
                graph_format: if format == 2 { PAGED_NATIVE_FORMAT } else { NATIVE_FORMAT }.into(),
                logical_payload_bytes: if format == 2 { graph.logical_payload_bytes()? } else { 0 },
                root: graph.root(),
            });
        }
        roots.sort_by(|left, right| left.scope.cmp(&right.scope));
        // Every scoped graph is real and individually valid; their aggregate
        // is one mount over the existing shared projection limit.
        live.validate_native_roots(&key(), &roots, &|| Ok(()))?;
        assert!(matches!(
            live.project_checked_native_roots(&key(), &roots, format, &|| Ok(())),
            Err(RecordError::TooLarge)
        ));
    }
    Ok(())
}
