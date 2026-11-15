use super::*;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::atomic::AtomicU64;
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(1);

struct Root(PathBuf);
impl Root {
    fn new() -> TestResult<Self> {
        let path = std::env::temp_dir().join(format!(
            "heptabao-seal-read-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(fs::canonicalize(path)?))
    }

    fn seal(&self, bytes: &[u8]) -> TestResult<File> {
        let path = self.0.join("seal.json");
        fs::write(&path, bytes)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(File::open(path)?)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn seal_read_small_real_file_is_fresh_and_keeps_physical_guards() -> TestResult {
    let root = Root::new()?;
    let original = b"synthetic-original-seal";
    drop(root.seal(original)?);
    let lease = SnapshotSpool::open(&root.0)?.lease()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let bytes = lease.read_seal_metadata(deadline)?;
    assert_eq!(bytes.as_slice(), original);
    assert!(bytes.capacity() <= original.len() + 1);
    drop(root.seal(b"changed-physical-seal")?);
    assert_eq!(
        lease.read_seal_metadata(deadline)?.as_slice(),
        b"changed-physical-seal"
    );
    fs::set_permissions(root.0.join("seal.json"), fs::Permissions::from_mode(0o644))?;
    assert!(lease.read_seal_metadata(deadline).is_err());
    fs::set_permissions(root.0.join("seal.json"), fs::Permissions::from_mode(0o600))?;
    assert!(lease.read_seal_metadata(Instant::now()).is_err());
    Ok(())
}

#[test]
fn seal_read_length_hint_does_not_limit_grown_or_shrunk_real_file() -> TestResult {
    let root = Root::new()?;
    let expected = vec![b's'; 8193];
    for hint in [0, 1, 17, SEAL_METADATA_LIMIT as u64] {
        let bytes = read_seal_bytes(root.seal(&expected)?, hint)?;
        assert_eq!(bytes.as_slice(), expected);
    }
    assert!(read_seal_bytes(root.seal(b"")?, 8193)?.is_empty());
    Ok(())
}

#[test]
fn seal_read_original_limit_and_extra_byte_overflow_are_preserved() -> TestResult {
    let root = Root::new()?;
    let expected = vec![b'l'; SEAL_METADATA_LIMIT];
    drop(root.seal(&expected)?);
    let lease = SnapshotSpool::open(&root.0)?.lease()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    assert_eq!(lease.read_seal_metadata(deadline)?.as_slice(), expected);
    let oversized = vec![b'o'; SEAL_METADATA_LIMIT + 100];
    let read = read_seal_bytes(root.seal(&oversized)?, 1)?;
    assert_eq!(read.len(), SEAL_METADATA_LIMIT + 1);
    assert_eq!(read.as_slice(), &oversized[..SEAL_METADATA_LIMIT + 1]);
    assert!(lease.read_seal_metadata(deadline).is_err());
    Ok(())
}

struct InterruptedFile {
    file: File,
    interrupted: bool,
    fail_after: Option<usize>,
    returned: usize,
}
impl Read for InterruptedFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.fail_after.is_some_and(|limit| self.returned >= limit) {
            return Err(io::Error::from_raw_os_error(5));
        }
        let length = bytes.len().min(7);
        let count = self.file.read(&mut bytes[..length])?;
        self.returned += count;
        Ok(count)
    }
}

#[test]
fn seal_read_retries_interruption_but_never_delivers_partial_io_failure() -> TestResult {
    let root = Root::new()?;
    let expected = vec![b'i'; 143];
    let reader = |file, fail_after| InterruptedFile {
        file,
        interrupted: false,
        fail_after,
        returned: 0,
    };
    assert_eq!(
        read_seal_bytes(reader(root.seal(&expected)?, None), 1)?.as_slice(),
        expected
    );
    let error = read_seal_bytes(reader(root.seal(&expected)?, Some(15)), 1)
        .err()
        .ok_or("partial I/O failure unexpectedly delivered bytes")?;
    assert_eq!(error.raw_os_error(), Some(5));
    Ok(())
}

#[test]
fn seal_parent_directory_replacement_is_rejected_with_an_open_lease() -> TestResult {
    let root = Root::new()?;
    drop(root.seal(b"original physical seal")?);
    let lease = SnapshotSpool::open(&root.0)?.lease()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    assert_eq!(
        lease.read_seal_metadata(deadline)?.as_slice(),
        b"original physical seal"
    );
    let moved = Root(root.0.with_extension("moved"));
    fs::rename(&root.0, &moved.0)?;
    fs::DirBuilder::new().mode(0o700).create(&root.0)?;
    drop(root.seal(b"replacement directory seal")?);
    assert!(lease.read_seal_metadata(deadline).is_err());
    assert!(lease.file(128, deadline).is_err());
    Ok(())
}

#[test]
fn seal_parent_symlink_to_the_same_held_inode_is_rejected() -> TestResult {
    let root = Root::new()?;
    drop(root.seal(b"original physical seal")?);
    let lease = SnapshotSpool::open(&root.0)?.lease()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let _first = lease.read_seal_metadata(deadline)?;
    let moved = Root(root.0.with_extension("moved"));
    fs::rename(&root.0, &moved.0)?;
    std::os::unix::fs::symlink(&moved.0, &root.0)?;
    assert!(lease.read_seal_metadata(deadline).is_err());
    assert!(lease.file(128, deadline).is_err());
    Ok(())
}

#[test]
fn seal_atomic_leaf_replacement_keeps_the_parent_and_reads_current_bytes() -> TestResult {
    let root = Root::new()?;
    drop(root.seal(br#"{"one":1,"two":2}"#)?);
    let lease = SnapshotSpool::open(&root.0)?.lease()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let _first = lease.read_seal_metadata(deadline)?;
    let old = fs::metadata(root.0.join("seal.json"))?;
    let replacement = root.0.join("replacement.json");
    let expected = b"{ \"two\": 2, \"one\": 1 }\n";
    fs::write(&replacement, expected)?;
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))?;
    fs::rename(&replacement, root.0.join("seal.json"))?;
    let current = fs::metadata(root.0.join("seal.json"))?;
    assert_ne!((old.dev(), old.ino()), (current.dev(), current.ino()));
    assert_eq!(lease.read_seal_metadata(deadline)?.as_slice(), expected);
    fs::set_permissions(root.0.join("seal.json"), fs::Permissions::from_mode(0o644))?;
    assert!(lease.read_seal_metadata(deadline).is_err());
    Ok(())
}
