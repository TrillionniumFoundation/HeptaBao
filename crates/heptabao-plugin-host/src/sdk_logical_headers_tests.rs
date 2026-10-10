//! Actual host request-frame insertion, with bounded data and unchanged authority.
use super::*;
#[test]
fn logical131_sdk_private_request_frame_preserves_header_arrays_without_minting_authority()
-> Result<(), &'static str> {
    let mut request = SensitiveJson(json!({"version":1,"kind":"request","call":7,
        "operation":"update","path":"store","data":{"value":"synthetic"}}));
    let original = Zeroizing::new(serde_json::to_vec(&*request).map_err(|_| "original frame")?);
    append_logical_headers(&mut request, None).map_err(|_| "legacy empty")?;
    assert_eq!(
        serde_json::to_vec(&*request)
            .map_err(|_| "legacy frame")?
            .as_slice(),
        original.as_slice()
    );
    let mut headers = std::collections::BTreeMap::new();
    headers.insert(
        "X-Review".to_owned(),
        vec!["one".to_owned(), "two".to_owned()],
    );
    headers.insert("X-Vault-Token".to_owned(), vec!["data-only".to_owned()]);
    append_logical_headers(&mut request, Some(&headers)).map_err(|_| "actual frame")?;
    assert_eq!(
        request["headers"],
        json!({"X-Review":["one","two"],"X-Vault-Token":["data-only"]})
    );
    assert_eq!(request["path"], "store");
    assert_eq!(request["operation"], "update");
    assert_eq!(request["call"], 7);
    assert_eq!(request["data"], json!({"value":"synthetic"}));
    assert!(request.get("token").is_none());
    assert!(request.get("principal").is_none());
    assert!(request.get("auth").is_none());
    assert!(request.get("namespace").is_none());
    // Logical SDK data is not an HTTP line; both values are legal public SDK Header data.
    headers.insert("Bad Header".to_owned(), vec!["line\r\nlogical\0value".to_owned()]);
    append_logical_headers(&mut request, Some(&headers)).map_err(|_| "logical data frame")?;
    assert_eq!(request["headers"]["Bad Header"], json!(["line\r\nlogical\0value"]));
    assert_eq!(request["headers"]["X-Vault-Token"], json!(["data-only"]));
    assert!(request.get("token").is_none());
    assert!(request.get("principal").is_none());
    assert!(request.get("auth").is_none());
    assert!(request.get("namespace").is_none());
    headers.insert(String::new(), vec!["empty-map-name".to_owned()]);
    append_logical_headers(&mut request, Some(&headers)).map_err(|_| "empty map header name")?;
    assert_eq!(request["headers"][""], json!(["empty-map-name"]));
    assert!(request.get("token").is_none());
    assert!(request.get("principal").is_none());
    assert!(request.get("auth").is_none());
    assert!(request.get("namespace").is_none());
    let before = Zeroizing::new(serde_json::to_vec(&*request).map_err(|_| "bounded frame")?);
    let invalid_frames = [
        std::collections::BTreeMap::from([("X-Review".to_owned(), vec!["x".repeat(16 * 1024 + 1)])]),
        std::collections::BTreeMap::from([("X-Review".to_owned(), vec!["x".to_owned(); 65])]),
        (0..65).map(|i| (format!("X-{i}"), vec![String::new()])).collect(),
        (0..5).map(|i| (format!("X-{i}"), vec!["x".repeat(16 * 1024)])).collect(),
        std::collections::BTreeMap::from([("x".repeat(257), vec!["x".to_owned()])]),
    ];
    for invalid in invalid_frames {
        assert!(append_logical_headers(&mut request, Some(&invalid)).is_err());
        assert_eq!(
            serde_json::to_vec(&*request)
                .map_err(|_| "unchanged frame")?
                .as_slice(),
            before.as_slice()
        );
    }
    Ok(())
}
