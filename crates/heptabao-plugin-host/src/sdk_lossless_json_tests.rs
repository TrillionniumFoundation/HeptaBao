//! The exact production receive decoder, with existing frame limits.
use super::*;
#[test]
fn sdk_received_frame_keeps_lossless_numbers_maps_and_explicit_last_key_semantics()
-> Result<(), &'static str> {
    let decoded = decode_sdk_frame(br#"{"data":{"big":184467440737095516160001,"decimal":0.12345678901234567890123456789,"fake":{"$serde_json::private::Number":"7"}},"id":1,"id":2}"#).map_err(|_| "frame")?;
    assert_eq!(decoded["id"], 2);
    assert_eq!(
        decoded["data"]["big"].to_string(),
        "184467440737095516160001"
    );
    assert_eq!(
        decoded["data"]["decimal"].to_string(),
        "0.12345678901234567890123456789"
    );
    assert!(decoded["data"]["fake"].is_object());
    let encoded = serde_json::to_vec(&decoded).map_err(|_| "encode")?;
    assert_eq!(decode_sdk_frame(&encoded).map_err(|_| "reopen")?, decoded);
    for bytes in [
        br#"{"data":"\uD800"}"#.as_slice(),
        b"{\"data\":NaN}",
        &[0xff],
        b"",
    ] {
        assert!(matches!(
            decode_sdk_frame(bytes),
            Err(SdkBridgeError::OutcomeUnknown)
        ));
    }
    assert!(matches!(
        decode_sdk_frame(&vec![b' '; MAX_FRAME + 1]),
        Err(SdkBridgeError::OutcomeUnknown)
    ));
    Ok(())
}
