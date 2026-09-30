use super::*;

#[test]
fn mount_preflight_patch_media_boundary_preserves_framing_and_body_errors() {
    for (content_type, body, expected) in [
        ("application/json", "", 400),
        ("application/json", "{}", 415),
        ("application/merge-patch+json", "", 400),
        ("application/merge-patch+json", "{", 400),
        ("application/merge-patch+json", "{}", 0),
    ] {
        let raw = format!(
            "PATCH /v1/sys/internal/ui/mounts/fixture HTTP/1.1\r\nHost: local\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        match read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true) {
            Ok(request) => {
                assert_eq!(expected, 0);
                assert_eq!(request.method, "PATCH");
                assert_eq!(request.path, "sys/internal/ui/mounts/fixture");
            }
            Err(error) => assert_eq!(error.status, expected),
        }
    }
    for raw in [
        "PATCH /v1/sys/internal/ui/mounts/fixture HTTP/1.1\r\nHost: local\r\nContent-Length: 2\r\nContent-Length: 0\r\n\r\n{}",
        "PATCH /v1/sys/internal/ui/mounts/fixture HTTP/1.1\r\nHost: local\r\nContent-Type: application/merge-patch+json\r\nContent-Length: 2\r\n\r\n{}extra",
    ] {
        assert!(read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true).is_err());
    }
}
