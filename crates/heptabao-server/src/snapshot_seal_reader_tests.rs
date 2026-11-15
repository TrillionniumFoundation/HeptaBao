use super::*;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::sync::atomic::AtomicU64;
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(1);

struct Root(PathBuf);
impl Root {
    fn new() -> TestResult<Self> {
        let path = std::env::temp_dir().join(format!(
            "heptabao-seal-reader-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(fs::canonicalize(path)?))
    }
    fn write(&self, name: &str, bytes: &[u8]) -> TestResult {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(self.0.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

#[test]
fn seal_reader_parallel_positioned_reads_are_complete_and_fresh() -> TestResult {
    let root = Root::new()?;
    let bytes: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
    root.write("seal.json", &bytes)?;
    let spool = SnapshotSpool::open(&root.0)?;
    let lease = spool.lease()?;
    let reader = lease.seal_reader(deadline())?;
    let result = std::thread::scope(|scope| -> io::Result<()> {
        let mut workers = Vec::new();
        for _ in 0..4 {
            let reader = &reader;
            let bytes = &bytes;
            workers.push(scope.spawn(move || -> io::Result<()> {
                for _ in 0..32 {
                    assert_eq!(reader.read_metadata(deadline())?.as_slice(), bytes);
                }
                Ok(())
            }));
        }
        for worker in workers {
            worker
                .join()
                .map_err(|_| io::Error::other("reader worker panicked"))??;
        }
        Ok(())
    });
    result?;
    Ok(())
}

#[test]
fn seal_reader_does_not_cache_same_inode_bytes() -> TestResult {
    let root = Root::new()?;
    root.write("seal.json", b"initial-state")?;
    let spool = SnapshotSpool::open(&root.0)?;
    let lease = spool.lease()?;
    let reader = lease.seal_reader(deadline())?;
    assert_eq!(
        reader.read_metadata(deadline())?.as_slice(),
        b"initial-state"
    );
    root.write("seal.json", b"changed-state")?;
    assert_eq!(
        reader.read_metadata(deadline())?.as_slice(),
        b"changed-state"
    );
    Ok(())
}

#[test]
fn seal_reader_reads_current_bytes_after_atomic_replacement() -> TestResult {
    let root = Root::new()?;
    root.write("seal.json", b"synthetic-seal")?;
    let spool = SnapshotSpool::open(&root.0)?;
    let lease = spool.lease()?;
    let reader = lease.seal_reader(deadline())?;
    root.write("replacement", b"synthetic-seal")?;
    fs::rename(root.0.join("replacement"), root.0.join("seal.json"))?;
    assert_eq!(
        reader.read_metadata(deadline())?.as_slice(),
        b"synthetic-seal"
    );
    root.write("replacement", b"replacement-seal")?;
    fs::rename(root.0.join("replacement"), root.0.join("seal.json"))?;
    assert_eq!(
        reader.read_metadata(deadline())?.as_slice(),
        b"replacement-seal"
    );
    assert_eq!(
        lease
            .seal_reader(deadline())?
            .read_metadata(deadline())?
            .as_slice(),
        b"replacement-seal"
    );
    Ok(())
}

#[test]
fn seal_reader_revalidates_permissions_links_and_length() -> TestResult {
    let root = Root::new()?;
    root.write("seal.json", b"synthetic-seal")?;
    let spool = SnapshotSpool::open(&root.0)?;
    let lease = spool.lease()?;
    let reader = lease.seal_reader(deadline())?;
    let seal = root.0.join("seal.json");
    fs::set_permissions(&seal, fs::Permissions::from_mode(0o644))?;
    assert!(reader.read_metadata(deadline()).is_err());
    fs::set_permissions(&seal, fs::Permissions::from_mode(0o600))?;
    assert!(reader.read_metadata(deadline()).is_ok());
    fs::hard_link(&seal, root.0.join("second-link"))?;
    assert!(reader.read_metadata(deadline()).is_err());
    fs::remove_file(root.0.join("second-link"))?;
    assert!(reader.read_metadata(deadline()).is_ok());
    root.write("seal.json", &vec![b'x'; SEAL_METADATA_LIMIT + 1])?;
    assert!(reader.read_metadata(deadline()).is_err());
    Ok(())
}

#[test]
fn seal_reader_keeps_original_deadline() -> TestResult {
    let root = Root::new()?;
    root.write("seal.json", b"synthetic-seal")?;
    let spool = SnapshotSpool::open(&root.0)?;
    let lease = spool.lease()?;
    assert!(lease.seal_reader(Instant::now()).is_err());
    let reader = lease.seal_reader(deadline())?;
    assert!(
        reader
            .read_metadata(Instant::now())
            .is_err_and(|error| error.kind() == io::ErrorKind::TimedOut)
    );
    Ok(())
}

#[test]
fn seal_reader_rejects_detached_parent() -> TestResult {
    let root = Root::new()?;
    root.write("seal.json", b"synthetic-seal")?;
    let spool = SnapshotSpool::open(&root.0)?;
    let lease = spool.lease()?;
    let reader = lease.seal_reader(deadline())?;
    let moved = root.0.with_extension("moved");
    fs::rename(&root.0, &moved)?;
    let rejected = reader.read_metadata(deadline()).is_err();
    fs::rename(&moved, &root.0)?;
    assert!(rejected);
    Ok(())
}
