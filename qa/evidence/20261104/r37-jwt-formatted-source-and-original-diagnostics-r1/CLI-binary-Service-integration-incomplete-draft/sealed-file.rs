//! A sealed descriptor and its actual private unlinked file have one owner.
use super::*;
use wire::{BodyDescriptor, BodyRole};

pub(super) struct SealedSnapshotFile {
    file: SnapshotFile,
    descriptor: BodyDescriptor,
}
impl SealedSnapshotFile {
    pub(super) fn seal(mut file: SnapshotFile) -> Result<Self, Response> {
        if file.len() == 0 || file.len() > MAX_NATIVE_ARCHIVE { return Err(unavailable()); }
        file.rewind_checked().map_err(|_| unavailable())?;
        let expected = file.len();
        let mut seen = 0_u64;
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        let mut buffer = Zeroizing::new(vec![0_u8; 65_536]);
        loop {
            let count = file.read(&mut buffer).map_err(|_| unavailable())?;
            seen = seen.checked_add(count as u64).filter(|seen| *seen <= expected)
                .ok_or_else(unavailable)?;
            hash.update(&buffer[..count]);
            if count == 0 { break; }
        }
        if seen != expected { return Err(unavailable()); }
        let mut sha256 = [0_u8; 32];
        sha256.copy_from_slice(hash.finish().as_ref());
        let descriptor = BodyDescriptor {
            role: BodyRole::NativeArchive,
            bytes: seen,
            frames: u32::try_from(seen.div_ceil(65_536)).map_err(|_| unavailable())?,
            sha256,
        };
        if !descriptor.valid() { return Err(unavailable()); }
        file.rewind_checked().map_err(|_| unavailable())?;
        Ok(Self { file, descriptor })
    }
    pub(super) fn descriptor(&self) -> BodyDescriptor { self.descriptor }
    pub(super) fn into_file(self) -> SnapshotFile { self.file }
}

impl Read for SealedSnapshotFile {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.file.read(output)
    }
}
