use super::*;
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(1);

struct Root(PathBuf);
impl Root {
    fn new() -> TestResult<Self> {
        let path = std::env::temp_dir().join(format!(
            "heptabao-export-buffer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(fs::canonicalize(path)?))
    }
    fn file(&self, maximum: u64) -> TestResult<SnapshotFile> {
        Ok(SnapshotSpool::open(&self.0)?
            .lease()?
            .file(maximum, Instant::now() + Duration::from_secs(30))?)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn export_buffer_coalesces_small_fragments_and_finishes_exact_bytes() -> TestResult {
    let root = Root::new()?;
    let size = EXPORT_WRITE_BUFFER + 7;
    let mut file = root.file(size as u64)?;
    let mut writer = file.buffered_writer()?;
    for _ in 0..EXPORT_WRITE_BUFFER {
        writer.write_all(b"x")?;
    }
    assert_eq!(writer.inner.file.metadata()?.len(), 0);
    writer.write_all(b"suffix!")?;
    assert_eq!(
        writer.inner.file.metadata()?.len(),
        EXPORT_WRITE_BUFFER as u64
    );
    assert_eq!(writer.pending.as_slice(), b"suffix!");
    writer.finish()?;
    assert_eq!(file.len(), size as u64);
    file.rewind_checked()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let mut expected = vec![b'x'; EXPORT_WRITE_BUFFER];
    expected.extend_from_slice(b"suffix!");
    assert_eq!(bytes, expected);
    Ok(())
}

#[test]
fn export_buffer_drop_discards_pending_plaintext_without_flushing() -> TestResult {
    let root = Root::new()?;
    let mut file = root.file(128)?;
    {
        let mut writer = file.buffered_writer()?;
        writer.write_all(b"synthetic-private-output")?;
        assert_eq!(writer.inner.file.metadata()?.len(), 0);
    }
    assert_eq!(file.len(), 0);
    assert_eq!(file.file.metadata()?.len(), 0);
    Ok(())
}

#[test]
fn export_buffer_original_deadline_and_bound_refusals_are_sticky() -> TestResult {
    let root = Root::new()?;
    let mut file = root.file(4)?;
    {
        let mut writer = file.buffered_writer()?;
        writer.write_all(b"1234")?;
        assert!(writer.write_all(b"5").is_err());
        assert!(writer.write(b"").is_err());
        assert!(writer.finish().is_err());
    }
    assert_eq!(file.len(), 0);
    assert_eq!(file.file.metadata()?.len(), 0);
    {
        let mut writer = file.buffered_writer()?;
        writer.write_all(b"12")?;
        writer.inner.deadline = Instant::now();
        let failure = writer.write(b"3");
        assert!(failure.is_err_and(|error| error.kind() == io::ErrorKind::TimedOut));
        assert!(writer.finish().is_err());
    }
    assert_eq!(file.file.metadata()?.len(), 0);
    Ok(())
}

#[test]
fn export_buffer_finish_rechecks_deadline_before_any_pending_flush() -> TestResult {
    let root = Root::new()?;
    let mut file = root.file(128)?;
    let mut writer = file.buffered_writer()?;
    writer.write_all(b"synthetic-pending-output")?;
    writer.inner.deadline = Instant::now();
    assert!(writer.finish().is_err());
    assert_eq!(file.len(), 0);
    assert_eq!(file.file.metadata()?.len(), 0);
    Ok(())
}

#[test]
fn export_buffer_large_direct_write_and_nonzero_cursor_keep_same_bound() -> TestResult {
    let root = Root::new()?;
    let mut file = root.file(EXPORT_WRITE_BUFFER as u64 + 5)?;
    file.write_all(b"head")?;
    {
        let mut writer = file.buffered_writer()?;
        writer.write_all(&vec![b'x'; EXPORT_WRITE_BUFFER])?;
        assert_eq!(
            writer.inner.file.metadata()?.len(),
            EXPORT_WRITE_BUFFER as u64 + 4
        );
        assert!(writer.pending.is_empty());
        writer.write_all(b"!")?;
        writer.finish()?;
    }
    assert_eq!(file.len(), EXPORT_WRITE_BUFFER as u64 + 5);
    file.rewind_checked()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    assert_eq!(&bytes[..4], b"head");
    assert!(bytes[4..bytes.len() - 1].iter().all(|byte| *byte == b'x'));
    assert_eq!(bytes.last(), Some(&b'!'));
    Ok(())
}

#[test]
fn export_buffer_real_descriptor_write_failure_never_drop_flushes() -> TestResult {
    let root = Root::new()?;
    let path = root.0.join("owned-readonly-output");
    fs::write(&path, b"")?;
    let readonly = File::open(&path)?;
    let mut file = root.file(128)?;
    file.file = readonly;
    {
        let mut writer = file.buffered_writer()?;
        writer.write_all(b"synthetic-failed-output")?;
        assert!(writer.flush().is_err());
        assert!(writer.finish().is_err());
    }
    assert_eq!(fs::metadata(&path)?.len(), 0);
    Ok(())
}
