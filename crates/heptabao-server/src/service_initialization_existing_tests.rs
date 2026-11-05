use super::tests::{Root, bootstrap_unmounted, call};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn initialization_existing_empty_native_api_publishes_unseals_and_reopens() -> TestResult {
    let root = Root::new();
    private_directory(&root.path)?;
    private_directory(&root.path.join("data"))?;
    let mut service = root.service()?;
    assert!(!service.initialized());
    let sealed = call(&mut service, "GET", "sys/seal-status", "", json!({}));
    assert_eq!(sealed.status, 200);
    assert!(sealed.body.get("cluster_id").is_none());
    assert!(sealed.body.get("cluster_name").is_none());
    let (key, token) = bootstrap_unmounted(&mut service)?;
    assert!(service.initialized());
    let status = call(&mut service, "GET", "sys/seal-status", "", json!({}));
    assert_eq!(status.status, 200);
    let cluster_id = status.body["cluster_id"]
        .as_str()
        .ok_or("cluster ID")?
        .to_owned();
    assert_eq!(cluster_id.len(), 36);
    assert_eq!(cluster_id.as_bytes()[8], b'-');
    assert_eq!(cluster_id.as_bytes()[13], b'-');
    assert_eq!(cluster_id.as_bytes()[18], b'-');
    assert_eq!(cluster_id.as_bytes()[23], b'-');
    assert_eq!(status.body["cluster_name"], "heptabao-single-node");
    assert_eq!(
        service.state.as_ref().ok_or("state")?.cluster_id,
        cluster_id
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/probe",
            &token,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "probe/data/kept",
            &token,
            json!({"data":{"value":"kept-after-reopen"}})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/init",
            "",
            json!({"secret_shares":1,"secret_threshold":1})
        )
        .status,
        400
    );
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let status = call(&mut reopened, "GET", "sys/seal-status", "", json!({}));
    assert_eq!(status.body["cluster_id"], cluster_id);
    assert_eq!(status.body["cluster_name"], "heptabao-single-node");
    let fetched = call(&mut reopened, "GET", "probe/data/kept", &token, json!({}));
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.body["data"]["data"]["value"], "kept-after-reopen");
    Ok(())
}

#[test]
fn initialization_existing_empty_replaces_atomically_and_releases_pending_target() -> TestResult {
    use std::os::unix::fs::MetadataExt;
    let root = Root::new();
    private_directory(&root.path)?;
    let target = root.path.join("data");
    private_directory(&target)?;
    let before = fs::metadata(&target)?.ino();
    let parent = ExclusiveDirectory::open(&root.path)?;
    let mut stage = InitializationStage::create(&target)?;
    fs::write(stage.path.join("prepared"), b"owned-candidate")?;
    assert!(stage.publish(&target, &parent)?);
    assert!(stage.retain_on_drop);
    assert_ne!(fs::metadata(&target)?.ino(), before);
    assert_eq!(fs::read(target.join("prepared"))?, b"owned-candidate");
    drop(stage);
    drop(parent);

    let second = Root::new();
    private_directory(&second.path)?;
    let target = second.path.join("data");
    private_directory(&target)?;
    let parent = ExclusiveDirectory::open(&second.path)?;
    let mut pending = InitializationStage::create(&target)?;
    fs::write(pending.path.join("prepared"), b"pending-owned-candidate")?;
    pending.retain_postgres_pending(&target, &parent)?;
    assert!(pending.retain_on_drop);
    let metadata = InitializationStage::create(&target)?;
    assert!(metadata.existing_empty.is_some());
    assert_eq!(
        fs::read(pending.path.join("prepared"))?,
        b"pending-owned-candidate"
    );
    Ok(())
}

#[test]
fn initialization_existing_empty_rejects_added_data_replacement_and_symlink() -> TestResult {
    use std::os::unix::fs::symlink;
    for damage in ["added-data", "replacement", "symlink"] {
        let root = Root::new();
        private_directory(&root.path)?;
        let target = root.path.join("data");
        private_directory(&target)?;
        let parent = ExclusiveDirectory::open(&root.path)?;
        let mut stage = InitializationStage::create(&target)?;
        fs::write(stage.path.join("prepared"), b"owned-candidate")?;
        match damage {
            "added-data" => fs::write(target.join("foreign"), b"preserve-foreign-data")?,
            "replacement" => {
                fs::rename(&target, root.path.join("original-empty"))?;
                private_directory(&target)?;
                fs::write(target.join("foreign"), b"preserve-foreign-data")?;
            }
            _ => {
                fs::remove_dir(&target)?;
                symlink("missing-synthetic-target", &target)?;
            }
        }
        assert!(stage.publish(&target, &parent).is_err());
        assert!(!stage.retain_on_drop);
        assert_eq!(fs::read(stage.path.join("prepared"))?, b"owned-candidate");
        if damage != "symlink" {
            assert_eq!(fs::read(target.join("foreign"))?, b"preserve-foreign-data");
        } else {
            assert!(fs::symlink_metadata(&target)?.file_type().is_symlink());
        }
    }
    let root = Root::new();
    private_directory(&root.path)?;
    let target = root.path.join("data");
    private_directory(&target)?;
    fs::write(target.join("existing"), b"preserve-existing-data")?;
    assert!(InitializationStage::create(&target).is_err());
    assert_eq!(
        fs::read(target.join("existing"))?,
        b"preserve-existing-data"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn initialization_existing_empty_ha_pending_retains_and_recovers_same_candidate() -> TestResult {
    for reopen in [false, true] {
        let root = Root::new();
        private_directory(&root.path)?;
        let target = root.path.join("data");
        private_directory(&target)?;
        let parent = ExclusiveDirectory::open(&root.path)?;
        let mut stage = InitializationStage::create(&target)?;
        fs::write(stage.path.join("prepared"), b"ha-pending-owned-candidate")?;
        stage.retain_ha_pending(&target, &parent)?;
        assert!(stage.existing_empty.is_some());
        if reopen {
            let pending_path = stage.path.clone();
            drop(stage);
            stage = InitializationStage {
                path: pending_path,
                retain_on_drop: true,
                existing_empty: InitializationStage::hold_existing_empty(&target)?,
            };
        }
        assert!(stage.publish(&target, &parent)?);
        assert_eq!(
            fs::read(target.join("prepared"))?,
            b"ha-pending-owned-candidate"
        );
        assert!(!wrapper_ha::pending_exists(&target)?);
    }
    Ok(())
}
