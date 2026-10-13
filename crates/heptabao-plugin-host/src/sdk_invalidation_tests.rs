use super::*;

#[test]
fn committed_keys_are_bounded_unique_and_sorted_before_entry() {
    assert!(validate_invalidation_keys(&["a".into(), "dir/b".into()]).is_ok());
    for keys in [
        vec![],
        vec![String::new()],
        vec!["a\0b".into()],
        vec!["b".into(), "a".into()],
        vec!["a".into(), "a".into()],
        vec!["x".repeat(4097)],
        (0..257).map(|i| format!("{i:04}")).collect(),
        (0..17)
            .map(|i| format!("{i:04}{}", "x".repeat(4092)))
            .collect(),
    ] {
        assert_eq!(
            validate_invalidation_keys(&keys),
            Err(SdkBridgeError::BeforeEntry)
        );
    }
}

#[test]
fn control_ack_cannot_reuse_logical_auth_storage_or_last_wins_frames() {
    let accepted =
        br#"{"version":1,"kind":"invalidation_ack","call":2,"control":"storage_key_v1","count":2}"#;
    let ack = decode_invalidation_ack(accepted).unwrap();
    assert!(validate_invalidation_ack(&ack, 2, 2).is_ok());
    assert_eq!(
        validate_invalidation_ack(&ack, 3, 2),
        Err(SdkBridgeError::OutcomeUnknown)
    );
    assert_eq!(
        validate_invalidation_ack(&ack, 2, 1),
        Err(SdkBridgeError::OutcomeUnknown)
    );
    for raw in [
        br#"{"version":1,"kind":"result","call":2,"control":"storage_key_v1","count":2}"#.as_slice(),
        br#"{"version":1,"kind":"invalidation_ack","call":2,"call":3,"control":"storage_key_v1","count":2}"#,
        br#"{"version":1,"kind":"invalidation_ack","call":2,"control":"storage_key_v1","count":2,"response":{"auth":{}}}"#,
        br#"{"version":1,"kind":"storage","call":2,"rpc":1,"method":"put","entry":{}}"#,
        br#"{"version":1,"kind":"invalidation_ack","call":2,"control":"storage_key_v1"}"#,
        br#"{"version":1,"kind":"invalidation_ack","call":2,"control":"future","count":2}"#,
    ] {
        let rejected = decode_invalidation_ack(raw)
            .and_then(|ack| validate_invalidation_ack(&ack, 2, 2));
        assert_eq!(rejected, Err(SdkBridgeError::OutcomeUnknown));
    }
}
