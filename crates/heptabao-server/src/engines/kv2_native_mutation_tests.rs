//! Real business semantics and bounded selected-cell changes, detached only.
use super::*;
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn scope() -> NativeScope<'static> {
    NativeScope {
        namespace: "team-a",
        mount: "secret/",
        incarnation: 7,
    }
}
fn base() -> Arc<AddressKey> {
    AddressKey::from_bytes([61; 32])
}
fn at(seconds: u64) -> TestResult<Timestamp> {
    Ok(Timestamp::checked(seconds, 7)?)
}
fn open(owner: &Kv2) -> TestResult<NativeReadView> {
    let graph = NativeCellGraph::encode(owner, &base(), scope(), &|| Ok(()))?;
    let objects = GraphObjects::from_index(&graph.0.index)?;
    Ok(NativeCellGraph::open_view(
        &base(),
        scope(),
        graph.root(),
        &objects,
        &|| Ok(()),
    )?)
}
fn graph(view: &NativeReadView) -> TestResult<NativeCellGraph> {
    Ok(view.encode(&base(), scope(), &|| Ok(()))?)
}
fn check_owner(view: &NativeReadView, expected: &Kv2) -> TestResult {
    let graph = graph(view)?;
    let objects = GraphObjects::from_index(&graph.0.index)?;
    let reopened = NativeGraph::open(&base(), scope(), graph.root(), &objects)?;
    let restored = reopened.decode()?;
    assert_eq!(
        serialize(&restored, MAX_GRAPH_BYTES)?,
        serialize(expected, MAX_GRAPH_BYTES)?
    );
    Ok(())
}
fn mutation(
    view: &mut NativeReadView,
    expected: &mut Kv2,
    method: &str,
    path: &str,
    body: Value,
    seconds: u64,
) -> TestResult {
    let actual = view.mutate(method, path, &body, at(seconds)?);
    let wanted = expected.handle_precise(method, path, &body, at(seconds)?);
    match (actual, wanted) {
        (Ok(actual), Ok(wanted)) => {
            assert_eq!(actual.status, wanted.status);
            assert_eq!(actual.body, wanted.body);
            assert_eq!(actual.mutated, wanted.mutated);
        }
        (Err(actual), Err(wanted)) => {
            assert_eq!(actual.status, wanted.status);
            assert_eq!(actual.message, wanted.message);
        }
        _ => return Err("selected native mutation changed logical outcome".into()),
    }
    check_owner(view, expected)
}

#[test]
fn selected_cell_mutations_preserve_cas_metadata_history_and_retention() -> TestResult {
    let mut owner = Kv2::default();
    owner.handle_precise(
        "POST",
        "config",
        &json!({
            "max_versions":3, "cas_required":true, "metadata_cas_required":true,
        }),
        at(100)?,
    )?;
    owner.handle_precise(
        "POST",
        "data/cold",
        &json!({
            "data":{"untouched":[1,true,null]}, "options":{"cas":0}
        }),
        at(101)?,
    )?;
    let mut view = open(&owner)?;
    mutation(
        &mut view,
        &mut owner,
        "POST",
        "data/hot",
        json!({
            "data":{"a":1,"nested":{"x":2}}, "options":{"cas":0}
        }),
        102,
    )?;
    mutation(
        &mut view,
        &mut owner,
        "POST",
        "data/hot",
        json!({
            "data":{"rejected":true}, "options":{"cas":0}
        }),
        103,
    )?;
    mutation(
        &mut view,
        &mut owner,
        "POST",
        "metadata/hot",
        json!({
            "metadata_cas":0, "custom_metadata":{"purpose":"selected records"}
        }),
        104,
    )?;
    mutation(
        &mut view,
        &mut owner,
        "PATCH",
        "data/hot",
        json!({
            "data":{"nested":{"x":null,"y":3}}, "options":{"cas":1}
        }),
        105,
    )?;
    mutation(
        &mut view,
        &mut owner,
        "POST",
        "delete/hot",
        json!({"versions":[1,2]}),
        106,
    )?;
    mutation(
        &mut view,
        &mut owner,
        "POST",
        "undelete/hot",
        json!({"versions":[1]}),
        107,
    )?;
    mutation(
        &mut view,
        &mut owner,
        "POST",
        "destroy/hot",
        json!({"versions":[2]}),
        108,
    )?;
    mutation(
        &mut view,
        &mut owner,
        "POST",
        "data/hot",
        json!({
            "data":{"v":3}, "options":{"cas":2}
        }),
        109,
    )?;
    mutation(
        &mut view,
        &mut owner,
        "PATCH",
        "metadata/hot",
        json!({
            "metadata_cas":1, "max_versions":2
        }),
        110,
    )?;
    mutation(
        &mut view,
        &mut owner,
        "POST",
        "data/hot",
        json!({
            "data":{"v":4}, "options":{"cas":3}
        }),
        111,
    )?;
    assert_eq!(view.0.entries["hot"].versions.len(), 2);
    assert!(!view.0.entries["hot"].versions.contains_key(&1));
    mutation(&mut view, &mut owner, "DELETE", "data/hot", json!({}), 112)?;
    mutation(
        &mut view,
        &mut owner,
        "POST",
        "metadata/new",
        json!({
            "metadata_cas":0, "custom_metadata":{"metadata":"only"}
        }),
        113,
    )?;
    mutation(
        &mut view,
        &mut owner,
        "DELETE",
        "metadata/new",
        json!({}),
        114,
    )?;
    mutation(
        &mut view,
        &mut owner,
        "DELETE",
        "metadata/hot",
        json!({}),
        115,
    )?;
    assert_eq!(view.counts(), (1, 1, 1));
    Ok(())
}

#[test]
fn cached_graph_rejects_rekey_scope_and_expired_checks_without_changing_source() -> TestResult {
    let mut owner = Kv2::default();
    owner.handle_precise("POST", "data/hot", &json!({"data":{"v":1}}), at(100)?)?;
    let mut view = open(&owner)?;
    let source = graph(&view)?.root();
    let wrong_key = AddressKey::from_bytes([62; 32]);
    assert!(matches!(
        view.encode(&wrong_key, scope(), &|| Ok(())),
        Err(RecordError::Invalid)
    ));
    let wrong_scope = NativeScope {
        incarnation: 8,
        ..scope()
    };
    assert!(matches!(
        view.encode(&base(), wrong_scope, &|| Ok(())),
        Err(RecordError::Invalid)
    ));
    let denied = view.mutate(
        "POST",
        "data/hot",
        &json!({
            "data":{"denied":true}, "options":{"cas":0}
        }),
        at(101)?,
    );
    assert!(denied.is_err());
    assert_eq!(graph(&view)?.root(), source);
    assert!(
        !view
            .mutate("DELETE", "metadata/absent", &json!({}), at(102)?)?
            .mutated
    );
    assert_eq!(graph(&view)?.root(), source);
    view.mutate(
        "POST",
        "data/hot",
        &json!({
            "data":{"v":2}, "options":{"cas":1}
        }),
        at(103)?,
    )?;
    let checks = std::cell::Cell::new(0_usize);
    let fail_during_edit = || {
        checks.set(checks.get() + 1);
        if checks.get() >= 7 {
            Err(RecordError::Invalid)
        } else {
            Ok(())
        }
    };
    assert!(matches!(
        view.encode(&base(), scope(), &fail_during_edit),
        Err(RecordError::Invalid)
    ));
    assert_eq!(view.1.as_ref().ok_or("cached graph")?.index.root(), source);
    assert!(checks.get() >= 7);
    let candidate = graph(&view)?;
    assert_ne!(candidate.root(), source);
    check_owner(&view, &view.0)?;
    Ok(())
}

#[test]
fn forty_mib_old_graph_point_write_reuses_all_unchanged_payload_objects() -> TestResult {
    let mut owner = Kv2::default();
    owner.handle_precise("POST", "config", &json!({"max_versions":60}), at(100)?)?;
    for version in 1..=40_u64 {
        let mut blob = String::with_capacity(1024 * 1024);
        for chunk in 0..256_u64 {
            let marker = format!("version-{version:05}/chunk-{chunk:05}/");
            blob.push_str(&marker);
            blob.extend(std::iter::repeat_n(
                char::from(b'a' + (version % 26) as u8),
                4096 - marker.len(),
            ));
        }
        owner.handle_precise(
            "POST",
            "data/hot",
            &json!({
                "data":{"blob":blob,"ordinal":version}
            }),
            at(100 + version)?,
        )?;
    }
    let mut view = open(&owner)?;
    let before = graph(&view)?;
    let old = GraphObjects::from_index(&before.0.index)?;
    let old_bytes: usize = old.0.values().map(|object| object.bytes().len()).sum();
    assert!(old_bytes > 40 * 1024 * 1024);
    assert!(
        view.mutate(
            "POST",
            "data/hot",
            &json!({
                "data":{"small":"new point value"}, "options":{"cas":40}
            }),
            at(200)?
        )?
        .mutated
    );
    let after = graph(&view)?;
    let new = GraphObjects::from_index(&after.0.index)?;
    let mut changed_objects = 0_usize;
    let mut changed_bytes = 0_usize;
    let mut reused_bytes = 0_usize;
    for (id, object) in &new.0 {
        if let Some(old) = old.0.get(id) {
            assert!(
                Arc::ptr_eq(old, object),
                "unchanged staged object was rebuilt"
            );
            reused_bytes += object.bytes().len();
        } else {
            changed_objects += 1;
            changed_bytes += object.bytes().len();
        }
    }
    for version in 1..=40_u64 {
        let record = payload_key(&before.0.scope, &before.0.key, "hot", version)?;
        let previous = before.0.index.get(&record).ok_or("old payload")?;
        let next = after.0.index.get(&record).ok_or("preserved payload")?;
        assert_eq!(previous, next);
        assert_eq!(
            previous.as_ptr(),
            next.as_ptr(),
            "old payload was reencoded"
        );
    }
    assert!(reused_bytes > 40 * 1024 * 1024);
    assert!(
        changed_bytes < 256 * 1024,
        "point-write emitted a whole owner"
    );
    assert_eq!(view.counts(), (1, 41, 41));
    let current = view.read("GET", "data/hot", &json!({}), at(201)?)?;
    assert_eq!(current.status, 200);
    assert_eq!(current.body["data"]["data"]["small"], "new point value");
    let objects = GraphObjects::from_index(&after.0.index)?;
    let restored = NativeGraph::open(&base(), scope(), after.root(), &objects)?.decode()?;
    assert_eq!(restored.entries["hot"].current_version, 41);
    assert_eq!(restored.entries["hot"].versions.len(), 41);
    // Rebase the detached cache exactly as a retained Service candidate must,
    // then prove the next write also reuses the preceding new payload.
    view.advance_authenticated_cache(&base(), scope(), &after.root(), &|| Ok(()))?;
    let rebased = graph(&view)?;
    assert_eq!(rebased.root(), after.root());
    view.mutate(
        "POST",
        "data/hot",
        &json!({
            "data":{"small":"second point value"}, "options":{"cas":41}
        }),
        at(202)?,
    )?;
    let second = graph(&view)?;
    let second_objects = GraphObjects::from_index(&second.0.index)?;
    let second_delta: usize = second_objects
        .0
        .iter()
        .filter(|(id, _)| !new.0.contains_key(id))
        .map(|(_, object)| object.bytes().len())
        .sum();
    assert!(second_delta < 256 * 1024);
    let record = payload_key(&rebased.0.scope, &rebased.0.key, "hot", 41)?;
    let first_point = rebased.0.index.get(&record).ok_or("first point payload")?;
    let reused_point = second.0.index.get(&record).ok_or("reused point payload")?;
    assert_eq!(first_point.as_ptr(), reused_point.as_ptr());
    assert_eq!(view.counts(), (1, 42, 42));
    eprintln!(
        "detached-point-write-only old_unique_bytes={old_bytes} reused_bytes={reused_bytes} changed_objects={changed_objects} changed_bytes={changed_bytes} second_delta_bytes={second_delta} retained_versions=42 replacement_authority=false"
    );
    Ok(())
}

fn install_fixture(
    fixture: ReaderFixture,
) -> TestResult<(EngineState, Vec<crate::state_record_root_v6::Kv2GraphRef>)> {
    let mut views = BTreeMap::new();
    for reference in &fixture.roots {
        let objects = GraphObjects(
            fixture
                .objects
                .iter()
                .filter(|(scope, _)| scope == &reference.scope)
                .map(|(_, object)| (object.reference().id, Arc::clone(object)))
                .collect(),
        );
        let view = NativeCellGraph::open_view(
            &base(),
            reference.scope.borrowed(),
            reference.root.clone(),
            &objects,
            &|| Ok(()),
        )?;
        assert!(serde_json::to_vec(&view).is_err());
        assert!(serde_json::from_slice::<NativeReadView>(b"{}").is_err());
        views.insert(reference.scope.clone(), view);
    }
    let mut state = fixture.opaque;
    state.install_native_views(views)?;
    Ok((state, fixture.roots))
}

#[test]
fn installed_native_backend_dispatches_and_proves_exact_roots_without_inline_json() -> TestResult {
    let mut source = EngineState::default();
    source
        .handle(
            "",
            "POST",
            "secret/config",
            &json!({
                "max_versions":16, "cas_required":true, "metadata_cas_required":true,
            }),
            100,
        )?
        .ok_or("config response")?;
    source
        .handle(
            "",
            "POST",
            "secret/data/hot",
            &json!({
                "data":{"v":1}, "options":{"cas":0}
            }),
            101,
        )?
        .ok_or("write response")?;
    let fixture = reader_fixture(&source, &base())?;
    let (mut live, roots) = install_fixture(fixture)?;
    live.validate_native_roots(&base(), &roots, &|| Ok(()))?;
    assert!(serde_json::to_vec(&live).is_err());
    assert!(live.has_metadata_cas_state());
    live.validate_kv2_lossless_state(None)?;
    assert!(live.is_immutable_kv_read("", "GET", "secret/data/hot"));
    assert!(
        live.ordinary_kv_mount_binding("", "secret/data/hot")
            .is_some()
    );
    let expected = source
        .handle("", "GET", "secret/data/hot", &json!({}), 102)?
        .ok_or("legacy read")?;
    let actual = live
        .handle("", "GET", "secret/data/hot", &json!({}), 102)?
        .ok_or("native read")?;
    assert_eq!(actual.body, expected.body);
    assert!(live.help_projection("", "secret/data/hot")?.is_some());
    let before = live.clone();
    let response = live
        .handle(
            "",
            "POST",
            "secret/data/hot",
            &json!({
                "data":{"v":2}, "options":{"cas":1}
            }),
            103,
        )?
        .ok_or("native point write")?;
    assert!(response.mutated);
    before.validate_native_roots(&base(), &roots, &|| Ok(()))?;
    assert!(
        live.validate_native_roots(&base(), &roots, &|| Ok(()))
            .is_err()
    );
    let mut staged = Vec::new();
    let (metadata, next_roots) = live.project_v6_native(&base(), &|| Ok(()), |scope, object| {
        staged.push((scope.clone(), Arc::clone(object)));
        Ok(())
    })?;
    assert!(serde_json::to_vec(&metadata).is_ok());
    live.validate_native_roots(&base(), &next_roots, &|| Ok(()))?;
    live.advance_native_caches(&base(), &next_roots, &|| Ok(()))?;
    live.validate_native_roots(&base(), &next_roots, &|| Ok(()))?;
    let (fresh, _) = install_fixture(ReaderFixture {
        opaque: metadata,
        roots: next_roots.clone(),
        objects: staged,
    })?;
    fresh.validate_native_roots(&base(), &next_roots, &|| Ok(()))?;
    let cold = fresh.handle_immutable_kv_read_precise(
        "",
        "GET",
        "secret/data/hot",
        &json!({}),
        at(104)?,
    )?;
    assert_eq!(cold.body["data"]["data"]["v"], 2);
    let tune = live
        .handle(
            "",
            "POST",
            "sys/mounts/secret/tune",
            &json!({
                "description":"native metadata tune", "options":{"version":"2"}, "cas_revision":1,
            }),
            105,
        )?
        .ok_or("native tune")?;
    assert!(tune.mutated);
    assert!(
        live.stage_openbao_kv2_import("", "secret", b"{}")
            .is_err_and(|error| error.status == 501)
    );
    assert!(
        live.native_remount_owner("", "secret", "other")
            .is_err_and(|error| error.status == 501)
    );
    Ok(())
}

#[test]
fn native_install_rejects_missing_or_mismatched_scope_without_partial_owner_change() -> TestResult {
    let mut source = EngineState::default();
    source
        .handle("", "POST", "secret/data/hot", &json!({"data":{"v":1}}), 100)?
        .ok_or("write response")?;
    let fixture = reader_fixture(&source, &base())?;
    let mut metadata = fixture.opaque;
    let before = serialize(&metadata, MAX_GRAPH_BYTES)?;
    assert!(metadata.install_native_views(BTreeMap::new()).is_err());
    assert_eq!(serialize(&metadata, MAX_GRAPH_BYTES)?, before);
    let reference = fixture.roots.first().ok_or("native root")?;
    let objects = GraphObjects(
        fixture
            .objects
            .iter()
            .map(|(_, object)| (object.reference().id, Arc::clone(object)))
            .collect(),
    );
    let view = NativeCellGraph::open_view(
        &base(),
        reference.scope.borrowed(),
        reference.root.clone(),
        &objects,
        &|| Ok(()),
    )?;
    let mut wrong = reference.scope.clone();
    wrong.incarnation += 1;
    assert!(
        metadata
            .install_native_views(BTreeMap::from([(wrong, view)]))
            .is_err()
    );
    assert_eq!(serialize(&metadata, MAX_GRAPH_BYTES)?, before);
    Ok(())
}
