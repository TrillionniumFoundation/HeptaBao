use super::*;
use crate::tests::{TestBarrier, TestRoot, put_request, serial_test};

#[test]
fn cold_dr_empty_owner_preserves_authenticated_epoch_without_retirement_loop()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    for epoch in [0, 7, u64::MAX] {
        let root = TestRoot::new("cold-epoch")?;
        let barrier = TestBarrier::new();
        let mut owner =
            DurableService::create_new_at_replay_epoch(&root.0, barrier.clone(), 16, epoch)?;
        assert_eq!(owner.generation(), 0);
        assert_eq!(owner.replay_epoch(), epoch);
        assert_eq!(owner.retained_request_count(), 0);
        if epoch != 0 {
            assert!(matches!(
                owner.put(put_request("wrong-domain", b"not-written")?),
                Err(ServiceError::ReplayEpochMismatch)
            ));
            assert_eq!(owner.generation(), 0);
        }
        owner.put_in_replay_epoch(epoch, put_request("bootstrap-data", b"authenticated")?)?;
        assert_eq!(owner.generation(), 1);
        assert!(matches!(
            DurableService::create_new_at_replay_epoch(&root.0, barrier.clone(), 16, epoch),
            Err(ServiceError::WriterLocked)
        ));
        owner.close()?;
        assert!(matches!(
            DurableService::create_new_at_replay_epoch(&root.0, barrier.clone(), 16, epoch),
            Err(ServiceError::RootNotEmpty)
        ));
        let reopened = DurableService::reopen(&root.0, barrier, 16)?;
        assert_eq!(reopened.replay_epoch(), epoch);
        assert_eq!(reopened.generation(), 1);
        assert_eq!(
            reopened
                .get("root/team-a", "secret/application")?
                .as_ref()
                .map(Secret::expose),
            Some(b"authenticated".as_slice())
        );
        reopened.close()?;
    }
    Ok(())
}
