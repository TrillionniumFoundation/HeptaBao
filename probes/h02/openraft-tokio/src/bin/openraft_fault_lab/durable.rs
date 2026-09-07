use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::time::{sleep, timeout};

const MAGIC: &[u8; 8] = b"HBWAL001";
const HEADER_LEN: usize = 24;

#[derive(Debug)]
struct Recovered {
    sequence: u64,
    value: Option<String>,
    torn_tail_detected: bool,
    valid_len: u64,
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn encode_record(sequence: u64, value: &str) -> io::Result<Vec<u8>> {
    let payload = value.as_bytes();
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| invalid_data("payload exceeds u32 length"))?;
    let mut record = Vec::with_capacity(HEADER_LEN + payload.len());
    record.extend_from_slice(MAGIC);
    record.extend_from_slice(&sequence.to_le_bytes());
    record.extend_from_slice(&payload_len.to_le_bytes());
    record.extend_from_slice(&crc32(payload).to_le_bytes());
    record.extend_from_slice(payload);
    Ok(record)
}

fn append_record(path: &Path, sequence: u64, value: &str, sync: bool) -> io::Result<u64> {
    let record = encode_record(sequence, value)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)?;
    let offset = file.metadata()?.len();
    file.write_all(&record)?;
    file.flush()?;
    if sync {
        file.sync_all()?;
    }
    Ok(offset)
}

fn append_torn_record(path: &Path, sequence: u64, value: &str) -> io::Result<()> {
    let record = encode_record(sequence, value)?;
    let partial_len = HEADER_LEN
        .saturating_sub(3)
        .max(record.len() / 2)
        .min(record.len() - 1);
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&record[..partial_len])?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn recover(path: &Path, repair_torn_tail: bool) -> io::Result<Recovered> {
    if !path.exists() {
        return Ok(Recovered {
            sequence: 0,
            value: None,
            torn_tail_detected: false,
            valid_len: 0,
        });
    }

    let mut options = OpenOptions::new();
    options.read(true).write(repair_torn_tail);
    let mut file = options.open(path)?;
    let mut valid_len = 0_u64;
    let mut latest_sequence = 0_u64;
    let mut latest_value = None;
    let mut torn_tail_detected = false;

    loop {
        let mut header = [0_u8; HEADER_LEN];
        let mut header_read = 0_usize;
        while header_read < HEADER_LEN {
            let count = file.read(&mut header[header_read..])?;
            if count == 0 {
                break;
            }
            header_read += count;
        }
        if header_read == 0 {
            break;
        }
        if header_read != HEADER_LEN {
            torn_tail_detected = true;
            break;
        }
        if &header[..8] != MAGIC {
            return Err(invalid_data(format!(
                "invalid WAL magic at byte {valid_len}"
            )));
        }

        let sequence = u64::from_le_bytes(header[8..16].try_into().expect("fixed sequence slice"));
        let payload_len =
            u32::from_le_bytes(header[16..20].try_into().expect("fixed length slice")) as usize;
        let expected_crc = u32::from_le_bytes(header[20..24].try_into().expect("fixed crc slice"));
        if payload_len > 16 * 1024 * 1024 {
            return Err(invalid_data(format!(
                "WAL payload length {payload_len} exceeds bound"
            )));
        }

        let mut payload = vec![0_u8; payload_len];
        let mut payload_read = 0_usize;
        while payload_read < payload_len {
            let count = file.read(&mut payload[payload_read..])?;
            if count == 0 {
                break;
            }
            payload_read += count;
        }
        if payload_read != payload_len {
            torn_tail_detected = true;
            break;
        }
        if crc32(&payload) != expected_crc {
            return Err(invalid_data(format!(
                "WAL checksum mismatch at sequence {sequence}"
            )));
        }
        if sequence <= latest_sequence {
            return Err(invalid_data(format!(
                "non-monotonic WAL sequence {sequence} after {latest_sequence}"
            )));
        }
        let value = String::from_utf8(payload).map_err(|error| invalid_data(error.to_string()))?;
        latest_sequence = sequence;
        latest_value = Some(value);
        valid_len += u64::try_from(HEADER_LEN + payload_len).expect("bounded WAL record length");
    }

    if torn_tail_detected && repair_torn_tail {
        file.set_len(valid_len)?;
        file.sync_all()?;
    }

    Ok(Recovered {
        sequence: latest_sequence,
        value: latest_value,
        torn_tail_detected,
        valid_len,
    })
}

fn truncate_to(path: &Path, len: u64) -> io::Result<()> {
    let file = OpenOptions::new().write(true).open(path)?;
    file.set_len(len)?;
    file.sync_all()?;
    Ok(())
}

fn corrupt_payload(path: &Path, record_offset: u64) -> io::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let payload_offset = record_offset + u64::try_from(HEADER_LEN).expect("header length fits u64");
    file.seek(SeekFrom::Start(payload_offset))?;
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte)?;
    byte[0] ^= 0x5a;
    file.seek(SeekFrom::Start(payload_offset))?;
    file.write_all(&byte)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn write_snapshot_atomic(root: &Path, sequence: u64, value: &str) -> io::Result<PathBuf> {
    let temporary = root.join("snapshot.json.tmp");
    let final_path = root.join("snapshot.json");
    let bytes = serde_json::to_vec(&json!({"sequence": sequence, "value": value}))
        .map_err(|error| invalid_data(error.to_string()))?;
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
    }
    fs::rename(&temporary, &final_path)?;
    File::open(root)?.sync_all()?;
    Ok(final_path)
}

fn case(pass: bool, detail: Value) -> Value {
    json!({
        "status": if pass { "PASS" } else { "FAIL" },
        "detail": detail,
    })
}

pub async fn execute_durable_faults(seed: u64) -> Value {
    let root = std::env::temp_dir().join(format!(
        "heptabao-h02-durable-{}-{seed:016x}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    if let Err(error) = fs::create_dir_all(&root) {
        return json!({
            "schema": "heptabao.h02-durable-fault-result.v1",
            "status": "BLOCKED",
            "reason": format!("create durable fault directory failed: {error}"),
            "qualification": false,
            "selection_effect": "NONE",
            "authority_effect": "NONE",
        });
    }

    let outcome = async {
        let restart_path = root.join("restart.wal");
        let restart_value = format!("restart-{seed:016x}");
        append_record(&restart_path, 1, &restart_value, true)?;
        let restarted = recover(&restart_path, true)?;
        let restart_pass = restarted.sequence == 1 && restarted.value.as_deref() == Some(&restart_value);

        let stall_path = root.join("stall.wal");
        let stall_base = format!("stall-base-{seed:016x}");
        append_record(&stall_path, 1, &stall_base, true)?;
        let stalled = timeout(Duration::from_millis(60), async {
            sleep(Duration::from_millis(240)).await;
            append_record(&stall_path, 2, "must-not-commit-after-timeout", true)
        })
        .await
        .is_err();
        let after_stall = recover(&stall_path, true)?;
        let stall_pass = stalled && after_stall.sequence == 1 && after_stall.value.as_deref() == Some(&stall_base);

        let torn_path = root.join("torn.wal");
        append_record(&torn_path, 1, "torn-base", true)?;
        append_torn_record(&torn_path, 2, "partially-written-record")?;
        let torn_recovered = recover(&torn_path, true)?;
        append_record(&torn_path, 3, "after-repair", true)?;
        let repaired = recover(&torn_path, false)?;
        let torn_pass = torn_recovered.sequence == 1
            && torn_recovered.torn_tail_detected
            && repaired.sequence == 3
            && repaired.value.as_deref() == Some("after-repair");

        let fsync_path = root.join("fsync-loss.wal");
        append_record(&fsync_path, 1, "fsync-base", true)?;
        let durable_len = fs::metadata(&fsync_path)?.len();
        append_record(&fsync_path, 2, "unsynced-tail", false)?;
        truncate_to(&fsync_path, durable_len)?;
        let fsync_recovered = recover(&fsync_path, false)?;
        let fsync_pass = fsync_recovered.sequence == 1 && fsync_recovered.value.as_deref() == Some("fsync-base");

        let corruption_path = root.join("corruption.wal");
        append_record(&corruption_path, 1, "corruption-base", true)?;
        let corrupt_offset = append_record(&corruption_path, 2, "corrupt-me", true)?;
        corrupt_payload(&corruption_path, corrupt_offset)?;
        let corruption_error = recover(&corruption_path, false).err().map(|error| error.to_string());
        let corruption_pass = corruption_error
            .as_deref()
            .is_some_and(|message| message.contains("checksum mismatch"));

        let snapshot_value = format!("snapshot-{seed:016x}");
        let snapshot_path = write_snapshot_atomic(&root, 9, &snapshot_value)?;
        let snapshot: Value = serde_json::from_slice(&fs::read(snapshot_path)?)
            .map_err(|error| invalid_data(error.to_string()))?;
        let snapshot_pass = snapshot["sequence"].as_u64() == Some(9)
            && snapshot["value"].as_str() == Some(snapshot_value.as_str());

        let all_pass = restart_pass && stall_pass && torn_pass && fsync_pass && corruption_pass && snapshot_pass;
        Ok::<Value, io::Error>(json!({
            "schema": "heptabao.h02-durable-fault-result.v1",
            "candidate_id": "HB-STORE-FILE-WAL-PROTOTYPE",
            "seed": format!("0x{seed:016x}"),
            "status": if all_pass { "EXECUTED_PASS" } else { "EXECUTED_FAIL" },
            "scope": {
                "storage_kind": "HEPTABAO_OWNED_FILE_WAL_PROTOTYPE",
                "openraft_storage_integrated": false,
                "production_selected": false,
                "record_integrity": "CRC32",
                "commit_boundary": "flush-plus-sync_all",
                "snapshot_commit": "temp-sync-rename-directory-sync",
            },
            "cases": {
                "restart_recovery": case(restart_pass, json!({"sequence": restarted.sequence, "valid_len": restarted.valid_len})),
                "bounded_disk_stall": case(stall_pass, json!({"deadline_ms": 60, "injected_stall_ms": 240, "recovered_sequence": after_stall.sequence})),
                "torn_tail_repair": case(torn_pass, json!({"torn_tail_detected": torn_recovered.torn_tail_detected, "repaired_sequence": repaired.sequence})),
                "fsync_loss_simulation": case(fsync_pass, json!({"durable_len": durable_len, "recovered_sequence": fsync_recovered.sequence})),
                "committed_corruption_fail_closed": case(corruption_pass, json!({"error": corruption_error})),
                "atomic_snapshot": case(snapshot_pass, snapshot),
            },
            "promotion_effect": "BLOCK_PENDING_OPENRAFT_STORE_INTEGRATION_AND_INDEPENDENT_STORAGE_REVIEW",
            "qualification": false,
            "selection_effect": "NONE",
            "authority_effect": "NONE",
        }))
    }
    .await;

    let value = match outcome {
        Ok(value) => value,
        Err(error) => json!({
            "schema": "heptabao.h02-durable-fault-result.v1",
            "candidate_id": "HB-STORE-FILE-WAL-PROTOTYPE",
            "seed": format!("0x{seed:016x}"),
            "status": "BLOCKED",
            "reason": error.to_string(),
            "promotion_effect": "BLOCK_PENDING_OPENRAFT_STORE_INTEGRATION_AND_INDEPENDENT_STORAGE_REVIEW",
            "qualification": false,
            "selection_effect": "NONE",
            "authority_effect": "NONE",
        }),
    };
    let _ = fs::remove_dir_all(&root);
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_detects_mutation() {
        assert_ne!(crc32(b"alpha"), crc32(b"alpHa"));
    }

    #[test]
    fn torn_tail_repairs_to_last_complete_record() {
        let root = std::env::temp_dir().join(format!("heptabao-wal-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("test.wal");
        append_record(&path, 1, "one", true).unwrap();
        append_torn_record(&path, 2, "two").unwrap();
        let recovered = recover(&path, true).unwrap();
        assert_eq!(recovered.sequence, 1);
        assert!(recovered.torn_tail_detected);
        append_record(&path, 3, "three", true).unwrap();
        assert_eq!(recover(&path, false).unwrap().sequence, 3);
        let _ = fs::remove_dir_all(&root);
    }
}
