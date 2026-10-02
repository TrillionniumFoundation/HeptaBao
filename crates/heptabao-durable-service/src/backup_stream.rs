//! The HBB2 container wire contract, emitted/read without a whole-container copy.
use super::*;
use std::io::{Read, Write};

const DOMAIN: &[u8] = b"heptabao.durable-service.backup.v1";
fn hasher(payload_length: u64) -> Sha256 {
    let mut hash = Sha256::new();
    hash.update((DOMAIN.len() as u64).to_le_bytes());
    hash.update(DOMAIN);
    hash.update(payload_length.to_le_bytes());
    hash
}

pub(super) fn encode_to(
    writer: &mut impl Write,
    generation: u64,
    snapshot: &[u8],
    journal: &[u8],
    ledger: &[u8],
) -> Result<u64, ServiceError> {
    let mut length = 60_usize;
    for bytes in [snapshot, journal, ledger] {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(ServiceError::CorruptState);
        }
        length = length
            .checked_add(bytes.len())
            .ok_or(ServiceError::CorruptState)?;
    }
    if length > MAX_BACKUP_BYTES {
        return Err(ServiceError::CorruptState);
    }
    let mut hash = hasher((length - 32) as u64);
    let mut emit = |bytes: &[u8]| -> Result<(), ServiceError> {
        writer.write_all(bytes)?;
        hash.update(bytes);
        Ok(())
    };
    emit(BACKUP_MAGIC)?;
    emit(&BACKUP_VERSION.to_le_bytes())?;
    emit(&0_u16.to_le_bytes())?;
    emit(&generation.to_le_bytes())?;
    for bytes in [snapshot, journal, ledger] {
        emit(&(bytes.len() as u32).to_le_bytes())?;
        emit(bytes)?;
    }
    writer.write_all(&hash.finalize())?;
    Ok(length as u64)
}

pub(super) fn decode_from<B: Barrier>(
    barrier: &B,
    reader: &mut impl Read,
    length: u64,
    maximum_requests: usize,
) -> Result<BackupComponents, ServiceError> {
    if !(60..=MAX_BACKUP_BYTES as u64).contains(&length) {
        return Err(ServiceError::CorruptState);
    }
    let mut hash = hasher(length - 32);
    let mut consumed = 0_u64;
    let mut read = |bytes: &mut [u8]| -> Result<(), ServiceError> {
        consumed = consumed
            .checked_add(bytes.len() as u64)
            .ok_or(ServiceError::CorruptState)?;
        if consumed > length - 32 {
            return Err(ServiceError::CorruptState);
        }
        reader.read_exact(bytes)?;
        hash.update(bytes);
        Ok(())
    };
    let mut header = [0; 16];
    read(&mut header)?;
    let mut cursor = Cursor::new(&header);
    if cursor.read_exact(4)? != BACKUP_MAGIC
        || cursor.read_u16()? != BACKUP_VERSION
        || cursor.read_u16()? != 0
    {
        return Err(ServiceError::CorruptState);
    }
    let generation = cursor.read_u64()?;
    let mut component = || -> Result<Vec<u8>, ServiceError> {
        let mut encoded_length = [0; 4];
        read(&mut encoded_length)?;
        let size = u32::from_le_bytes(encoded_length) as usize;
        if size > MAX_FILE_BYTES {
            return Err(ServiceError::CorruptState);
        }
        let mut bytes = vec![0; size];
        read(&mut bytes)?;
        Ok(bytes)
    };
    let snapshot = component()?;
    let journal = component()?;
    let ledger = component()?;
    if consumed != length - 32 {
        return Err(ServiceError::CorruptState);
    }
    let mut expected = [0; 32];
    reader.read_exact(&mut expected)?;
    let mut trailing = [0; 1];
    if reader.read(&mut trailing)? != 0 || !constant_time_eq(&hash.finalize(), &expected) {
        return Err(ServiceError::CorruptState);
    }
    decode_backup_components(
        barrier,
        generation,
        snapshot,
        journal,
        ledger,
        maximum_requests,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{TestBarrier, TestRoot, put_request, serial_test};

    #[test]
    fn streaming_container_is_byte_identical_and_prepared_once() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("backup-stream")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
        service.put(put_request("stream", b"stream secret")?)?;
        let encoded = service.export_backup()?;
        let components = decode_backup(&TestBarrier::new(), &encoded, 16)?;
        let legacy = encode_backup(
            components.snapshot.generation,
            &components.snapshot_bytes,
            &components.journal_bytes,
            &components.ledger_bytes,
        )?;
        assert_eq!(encoded, legacy);
        let mut reader = encoded.as_slice();
        let prepared = service.prepare_restore_from_reader(&mut reader, encoded.len() as u64)?;
        assert_eq!(
            prepared.get("root/team-a", "secret/application")?,
            Some(b"stream secret".as_slice())
        );
        service.restore_prepared(prepared, false)?;
        Ok(())
    }

    #[test]
    fn streaming_lengths_truncation_checksum_and_trailing_bytes_fail_without_publication()
    -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("backup-stream-invalid")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
        service.put(put_request("original", b"original")?)?;
        let good = service.export_backup()?;
        let before = service.backend.load().map_err(map_backend_error)?;
        for cut in [0, 15, 19, good.len() - 1] {
            assert!(
                service
                    .prepare_restore_from_reader(&mut &good[..cut], good.len() as u64)
                    .is_err()
            );
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(
            service
                .prepare_restore_from_reader(&mut trailing.as_slice(), good.len() as u64)
                .is_err()
        );
        let mut corrupt = good.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(
            service
                .prepare_restore_from_reader(&mut corrupt.as_slice(), corrupt.len() as u64)
                .is_err()
        );
        assert!(
            service
                .prepare_restore_from_reader(&mut good.as_slice(), MAX_BACKUP_BYTES as u64 + 1)
                .is_err()
        );
        assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
        assert!(!service.recovery_required());
        Ok(())
    }
}
