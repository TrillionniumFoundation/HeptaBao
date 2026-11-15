//! One install-attempt memo of pure seal JSON decoding. Every check still
//! opens and reads the actual bounded private file using the ordinary loader.
//! The memo supplies no file, unseal, Actor, Raft or deadline authority. It
//! holds only the already expected SealMetadata and one zeroizing encoding;
//! changed bytes take the original full decode/validate/equality path.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) struct SealSyntaxMemo {
    expected: SealMetadata,
    encoded: Zeroizing<Vec<u8>>,
    refused: AtomicBool,
}

impl SealSyntaxMemo {
    pub(super) fn capture(data_dir: &Path, expected: SealMetadata) -> Result<Self, &'static str> {
        let encoded = read_seal_metadata_bytes(data_dir)?.ok_or("seal metadata is absent")?;
        if decode_seal_metadata(&encoded)? != expected {
            return Err("seal metadata changed");
        }
        Ok(Self {
            expected,
            encoded,
            refused: AtomicBool::new(false),
        })
    }

    pub(super) fn expected(&self) -> &SealMetadata {
        &self.expected
    }

    pub(super) fn refuse(&self) {
        self.refused.store(true, Ordering::Release);
    }

    pub(super) fn check(&self, data_dir: &Path) -> Result<(), &'static str> {
        if self.refused.load(Ordering::Acquire) {
            return Err("seal syntax observation already refused");
        }
        let result = (|| {
            // Always repeat O_NOFOLLOW, regular/private/link-count checks,
            // original size limits and the real descriptor byte read. Never
            // substitute inode, timestamp, a hash or a previous successful gate.
            let actual = read_seal_metadata_bytes(data_dir)?.ok_or("seal metadata is absent")?;
            if actual.as_slice() != self.encoded.as_slice()
                && decode_seal_metadata(&actual)? != self.expected
            {
                return Err("seal metadata changed");
            }
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        directory: PathBuf,
        metadata: SealMetadata,
        encoded: Vec<u8>,
    }

    impl Fixture {
        fn new() -> TestResult<Self> {
            let directory = std::env::temp_dir().join(format!(
                "heptabao-ha-seal-syntax-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&directory)?;
            let metadata = SealMetadata {
                schema: 1,
                generation: 1,
                share_format: "raw-v1".into(),
                secret_shares: 1,
                secret_threshold: 1,
                wrapped_barrier_key: STANDARD.encode([0x5a_u8; 64]),
            };
            metadata.validate()?;
            let encoded = serde_json::to_vec(&metadata)?;
            let fixture = Self {
                directory,
                metadata,
                encoded,
            };
            fixture.write(&fixture.encoded)?;
            Ok(fixture)
        }

        fn path(&self) -> PathBuf {
            self.directory.join(SEAL_METADATA_FILE)
        }

        fn write(&self, bytes: &[u8]) -> TestResult {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(self.path())?;
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        }

        fn memo(&self) -> TestResult<SealSyntaxMemo> {
            Ok(SealSyntaxMemo::capture(
                &self.directory,
                self.metadata.clone(),
            )?)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn different_equivalent_encoding_uses_full_decode_without_growing_or_replacing_memo()
    -> TestResult {
        let fixture = Fixture::new()?;
        let memo = fixture.memo()?;
        memo.check(&fixture.directory)?;
        let pretty = serde_json::to_vec_pretty(&fixture.metadata)?;
        assert_ne!(pretty, fixture.encoded);
        fixture.write(&pretty)?;
        memo.check(&fixture.directory)?;
        assert_eq!(memo.encoded.as_slice(), fixture.encoded.as_slice());
        assert!(memo.expected() == &fixture.metadata);
        // Current bytes, not a remembered inode/mtime success, remain decisive.
        fixture.write(b"{invalid")?;
        assert!(memo.check(&fixture.directory).is_err());
        fixture.write(&fixture.encoded)?;
        assert!(memo.check(&fixture.directory).is_err());
        Ok(())
    }

    #[test]
    fn valid_different_seal_and_later_restore_cannot_reenable_a_refused_attempt() -> TestResult {
        let fixture = Fixture::new()?;
        let memo = fixture.memo()?;
        let mut changed = fixture.metadata.clone();
        changed.generation += 1;
        changed.validate()?;
        fixture.write(&serde_json::to_vec(&changed)?)?;
        assert!(memo.check(&fixture.directory).is_err());
        fixture.write(&fixture.encoded)?;
        assert!(memo.check(&fixture.directory).is_err());
        // A separate later operation must establish its own actual capture.
        fixture.memo()?.check(&fixture.directory)?;
        Ok(())
    }

    #[test]
    fn identical_file_replacement_is_read_and_keeps_original_loader_semantics() -> TestResult {
        let fixture = Fixture::new()?;
        let memo = fixture.memo()?;
        let replacement = fixture.directory.join("owned-replacement");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&replacement)?;
        file.write_all(&fixture.encoded)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&replacement, fixture.path())?;
        memo.check(&fixture.directory)?;
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o644))?;
        assert!(memo.check(&fixture.directory).is_err());
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o600))?;
        assert!(memo.check(&fixture.directory).is_err());
        Ok(())
    }

    #[test]
    fn every_check_keeps_absence_symlink_hardlink_type_size_and_private_mode_guards() -> TestResult
    {
        for mutation in 0..6 {
            let fixture = Fixture::new()?;
            let memo = fixture.memo()?;
            match mutation {
                0 => fs::remove_file(fixture.path())?,
                1 => {
                    let target = fixture.directory.join("owned-link-target");
                    fs::rename(fixture.path(), &target)?;
                    std::os::unix::fs::symlink(&target, fixture.path())?;
                }
                2 => fs::hard_link(fixture.path(), fixture.directory.join("owned-second-link"))?,
                3 => {
                    fs::remove_file(fixture.path())?;
                    fs::create_dir(fixture.path())?;
                }
                4 => fixture.write(&vec![b' '; (SEAL_METADATA_LIMIT + 1) as usize])?,
                5 => fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o640))?,
                _ => unreachable!(),
            }
            assert!(
                memo.check(&fixture.directory).is_err(),
                "mutation {mutation}"
            );
            assert!(memo.refused.load(Ordering::Acquire), "mutation {mutation}");
        }
        Ok(())
    }

    #[test]
    fn capture_rejects_different_metadata_and_outer_deadline_refusal_is_sticky() -> TestResult {
        let fixture = Fixture::new()?;
        let mut wrong = fixture.metadata.clone();
        wrong.generation += 1;
        assert!(SealSyntaxMemo::capture(&fixture.directory, wrong).is_err());
        let memo = fixture.memo()?;
        memo.refuse();
        assert!(memo.check(&fixture.directory).is_err());
        Ok(())
    }
}
