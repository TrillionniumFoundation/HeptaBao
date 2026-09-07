from __future__ import annotations

from pathlib import Path


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{label} anchor count={count}")
    return source.replace(old, new, 1)


def main() -> None:
    for name in (
        "docs/architecture/HEPTABAO_V2_1_AUTHORIZED_DURABLE_PIPELINE.md",
        "docs/architecture/HEPTABAO_V2_1_DURABLE_RUNTIME_PIPELINE.md",
    ):
        path = Path(name)
        path.write_text(path.read_text(encoding="utf-8").rstrip() + "\n", encoding="utf-8")

    path = Path("crates/heptabao-durable-service/src/lib.rs")
    source = path.read_text(encoding="utf-8")

    source = replace_once(
        source,
        """            Ok(Self {
                root,
                lock_path,
                barrier,
""",
        """            Ok(Self {
                root,
                lock_path: lock_path.clone(),
                barrier,
""",
        "writer-lock ownership repair",
    )

    source = replace_once(
        source,
        """        let recovery_reference = recovery_reference(&binding_digest, generation);
""",
        """        let intent_sequence = self
            .journal_sequence
            .checked_add(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        let recovery_reference =
            recovery_reference(&binding_digest, generation, intent_sequence);
""",
        "attempt sequence",
    )

    source = replace_once(
        source,
        """fn recovery_reference(binding_digest: &[u8; 32], generation: u64) -> String {
    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(binding_digest);
    bytes.extend_from_slice(&generation.to_le_bytes());
    let digest = digest32(b"heptabao.durable-service.recovery.v1", &bytes);
""",
        """fn recovery_reference(
    binding_digest: &[u8; 32],
    generation: u64,
    intent_sequence: u64,
) -> String {
    let mut bytes = Vec::with_capacity(48);
    bytes.extend_from_slice(binding_digest);
    bytes.extend_from_slice(&generation.to_le_bytes());
    bytes.extend_from_slice(&intent_sequence.to_le_bytes());
    let digest = digest32(b"heptabao.durable-service.recovery.v2", &bytes);
""",
        "recovery reference",
    )

    source = replace_once(
        source,
        """        assert!(matches!(
            reopened.put(request)?,
            MutationOutcome::Committed { generation: 1, .. }
        ));
        Ok(())
""",
        """        let retry_recovery_reference = match reopened.put(request)? {
            MutationOutcome::Committed {
                generation: 1,
                recovery_reference,
            } => recovery_reference,
            _ => return Err(ServiceError::CorruptState),
        };
        assert_ne!(recovery_reference, retry_recovery_reference);
        assert_eq!(
            reopened.reconcile(&recovery_reference),
            ReconciliationStatus::Aborted
        );
        Ok(())
""",
        "aborted retry regression",
    )

    source = replace_once(
        source,
        """        if frame_len < 8 + 4 + 32 || frame_len > MAX_FILE_BYTES {
""",
        """        if !(8 + 4 + 32..=MAX_FILE_BYTES).contains(&frame_len) {
""",
        "frame range lint repair",
    )

    path.write_text(source, encoding="utf-8")


if __name__ == "__main__":
    main()
