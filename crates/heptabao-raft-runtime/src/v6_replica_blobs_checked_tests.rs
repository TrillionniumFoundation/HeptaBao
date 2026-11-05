use super::*;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "hb-v6-checked-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(Self(root))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn checked_replica_authenticates_bytes_and_never_creates_after_initial_gate_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let ciphertext = vec![0x49; 196_608];
    let before = fs::read_dir(&root.0)?.count();
    assert!(
        store
            .stage_local_checked(&ciphertext, &mut || Err(LocalV6BlobError::CorruptOrChanged))
            .is_err()
    );
    assert_eq!(fs::read_dir(&root.0)?.count(), before);
    let first = store.stage_local_checked(&ciphertext, &mut || Ok(()))?;
    assert_eq!(store.read_local(first.reference())?, ciphertext);
    let duplicate =
        store.stage_received_replica_checked(first.reference(), &ciphertext, &mut || Ok(()))?;
    assert_eq!(duplicate.reference(), first.reference());
    let before = fs::read_dir(&root.0)?.count();
    let mut changed = ciphertext;
    changed[0] ^= 1;
    assert!(
        store
            .stage_received_replica_checked(first.reference(), &changed, &mut || Ok(()))
            .is_err()
    );
    assert_eq!(fs::read_dir(&root.0)?.count(), before);
    Ok(())
}

#[test]
fn checked_replica_rechecks_gate_after_actual_link_and_returns_no_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let store = LocalV6BlobStage::open_existing(&root.0)?;
    let ciphertext = vec![0x51; 131_072];
    let object = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.clone())?;
    let destination = root.0.join(LocalV6BlobStage::leaf(object.reference())?);
    let mut actual_link_seen = false;
    let result = store.stage_received_replica_checked(object.reference(), &ciphertext, &mut || {
        // Observe an actual filesystem effect, not the implementation's gate
        // invocation count. This rejection may leave durable orphan bytes but
        // must never manufacture a successful local or remote fsync receipt.
        if destination.exists() {
            actual_link_seen = true;
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        Ok(())
    });
    assert!(actual_link_seen);
    assert!(destination.exists());
    assert!(result.is_err());
    Ok(())
}
