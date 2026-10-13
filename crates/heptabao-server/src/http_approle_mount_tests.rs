use super::*;

struct SplitBody<'a> {
    head: &'a [u8],
    body: &'a [u8],
    reads: usize,
}
impl Read for SplitBody<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        let source = if self.head.is_empty() {
            &mut self.body
        } else {
            &mut self.head
        };
        let count = source.len().min(out.len());
        out[..count].copy_from_slice(&source[..count]);
        *source = &source[count..];
        Ok(count)
    }
}

#[test]
fn unsupported_media_and_query_form_drain_only_bounded_body_before_rejection() {
    for (path, media) in [
        ("secret/data/a", "text/plain"),
        (
            "auth/forms/login?role_id=other",
            "application/x-www-form-urlencoded",
        ),
    ] {
        let body = b"role_id=one&secret_id=two";
        let header = format!(
            "POST /v1/{path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {media}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut reader = SplitBody {
            head: header.as_bytes(),
            body,
            reads: 0,
        };
        let error = match read_request_mode(&mut reader, Duration::from_secs(2), false) {
            Err(error) => error,
            Ok(_) => panic!("unsupported carrier was accepted"),
        };
        assert_eq!(error.status, 400);
        assert!(
            reader.body.is_empty(),
            "bounded rejected body must be consumed"
        );
        assert!(reader.reads > 1, "split body must actually be read");
    }
}

#[test]
fn client_codec_header_is_filtered_but_actual_form_gets_body_bound_marker() {
    let marker = crate::request_metadata::AUTH_FORM_CODEC_HEADER;
    for (media, payload, actual_form) in [
        (
            "application/json",
            r#"{"role_id":"one","secret_id":"two"}"#,
            false,
        ),
        (
            "application/x-www-form-urlencoded",
            "role_id=one&secret_id=two",
            true,
        ),
    ] {
        let wire = format!(
            "POST /v1/auth/forms/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: {media}\r\n{marker}: approle-form-v1\r\nContent-Length: {}\r\n\r\n{payload}",
            payload.len()
        );
        let parsed = read_request_mode(&mut wire.as_bytes(), Duration::from_secs(2), false)
            .unwrap_or_else(|_| panic!("well-framed carrier was rejected"));
        assert_eq!(
            parsed
                .logical_data
                .as_ref()
                .is_some_and(|data| data.is_approle_form()),
            actual_form
        );
    }
}
