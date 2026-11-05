use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn encoded(registry: &Registry) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    crate::secret_serde::to_vec(registry, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| "bounded quota owner serialization failed".into())
}

fn add(
    registry: &mut Registry,
    name: &str,
    namespace: &str,
    mount: &str,
    suffix: &str,
    role: &str,
) -> Result<(), AuthError> {
    let selector = Target::from_catalog(
        namespace,
        mount,
        suffix,
        mount.starts_with("auth/"),
        mount.starts_with("auth/"),
    )?
    .into_selector();
    let revision = registry.next_revision;
    registry.next_revision += 1;
    registry.scoped_reader = true;
    registry.definitions.insert(
        name.into(),
        Definition {
            name: name.into(),
            path: selector.path(),
            role: role.into(),
            rate: 5.0,
            interval: 60,
            block_interval: 0,
            revision,
            inheritable: false,
        },
    );
    registry.selectors.insert(name.into(), selector);
    registry.validate()
}

#[test]
fn quota_remount_exact_glob_mount_role_and_unrelated_runtime_are_bound() -> TestResult {
    let mut original = Registry::default();
    for (name, namespace, mount, suffix, role) in [
        ("mount", "", "before/", "", ""),
        ("exact", "", "before/", "data/item", ""),
        ("glob", "", "before/", "data/app*", ""),
        ("sibling", "team", "before/", "", ""),
        ("other", "", "keep/", "", ""),
        ("role", "", "auth/app/", "", "deployment"),
    ] {
        add(&mut original, name, namespace, mount, suffix, role)?;
    }
    let before = encoded(&original)?;
    let next = original.relocated_mount("", "before/", "after/")?;
    assert!(std::sync::Arc::ptr_eq(
        &next.runtime_owner,
        &original.runtime_owner
    ));
    for (name, suffix) in [("mount", ""), ("exact", "data/item"), ("glob", "data/app*")] {
        assert_eq!(next.definitions[name].path, format!("after/{suffix}"));
        assert!(next.definitions[name].revision >= original.next_revision);
    }
    for name in ["sibling", "other", "role"] {
        assert_eq!(next.definitions[name], original.definitions[name]);
        assert_eq!(next.selectors[name], original.selectors[name]);
    }
    let role = next.relocated_mount("", "auth/app/", "auth/new/")?;
    assert_eq!(role.definitions["role"].path, "auth/new/");
    assert_eq!(role.definitions["role"].role, "deployment");
    let cold: Registry = serde_json::from_slice(&encoded(&role)?)?;
    cold.validate()?;
    assert_eq!(cold.definitions, role.definitions);
    assert_eq!(cold.selectors, role.selectors);
    assert_eq!(encoded(&original)?.as_slice(), before.as_slice());
    Ok(())
}

#[test]
fn quota_remount_preserves_legacy_reader_and_selected_revision_reset() -> TestResult {
    let mut original = Registry {
        next_revision: 3,
        ..Registry::default()
    };
    for (name, path, revision) in [("mount", "auth/app/", 1), ("login", "auth/app/login", 2)] {
        original.definitions.insert(
            name.into(),
            Definition {
                name: name.into(),
                path: path.into(),
                role: String::new(),
                rate: 1.0,
                interval: 60,
                block_interval: 0,
                revision,
                inheritable: false,
            },
        );
    }
    original.validate()?;
    let next = original.relocated_mount("", "auth/app/", "auth/moved/")?;
    assert!(!next.scoped_reader && !next.extended_reader);
    assert!(next.selectors.is_empty());
    assert_eq!(next.next_revision, 5);
    assert_eq!(next.definitions["login"].path, "auth/moved/login");
    assert_eq!(next.definitions["mount"].path, "auth/moved/");
    assert!(
        next.definitions
            .values()
            .all(|definition| definition.revision >= 3)
    );
    let cold: Registry = serde_json::from_slice(&encoded(&next)?)?;
    cold.validate()?;
    assert_eq!(cold.definitions, next.definitions);
    Ok(())
}

#[test]
fn quota_remount_collision_and_revision_exhaustion_do_not_mutate_source() -> TestResult {
    let mut original = Registry::default();
    add(&mut original, "source", "", "before/", "data/item", "")?;
    add(&mut original, "target", "", "after/", "data/item", "")?;
    let before = encoded(&original)?;
    assert!(original.relocated_mount("", "before/", "after/").is_err());
    assert_eq!(encoded(&original)?.as_slice(), before.as_slice());
    original.next_revision = u64::MAX;
    let before = encoded(&original)?;
    assert_eq!(
        original
            .relocated_mount("", "before/", "free/")
            .err()
            .ok_or("expected failure")?
            .status,
        507
    );
    assert_eq!(encoded(&original)?.as_slice(), before.as_slice());
    Ok(())
}

#[test]
fn quota_remount_plain_child_factors_move_without_changing_root_or_sibling() -> TestResult {
    let mut original = Registry::default();
    add(&mut original, "root", "", "before/", "data/*", "")?;
    add(&mut original, "child", "team", "before/", "data/*", "")?;
    add(&mut original, "sibling", "other", "before/", "data/*", "")?;
    let next = original.relocated_mount("team", "before/", "after/")?;
    assert_eq!(next.definitions["child"].path, "team/after/data/*");
    assert_eq!(next.definitions["root"], original.definitions["root"]);
    assert_eq!(next.definitions["sibling"], original.definitions["sibling"]);
    assert_eq!(next.selectors["child"].namespace(), "team");
    Ok(())
}
