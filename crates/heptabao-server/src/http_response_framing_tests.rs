use super::*;

fn json_response(body: Value) -> Response {
    Response {
        status: 200,
        response_headers: Default::default(),
        consistency_index: None,
        body,
    }
}

fn split_wire(wire: &[u8]) -> io::Result<(&str, &[u8])> {
    let boundary = wire
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("missing HTTP header boundary"))?;
    Ok((
        std::str::from_utf8(&wire[..boundary]).map_err(io::Error::other)?,
        &wire[boundary + 4..],
    ))
}

#[test]
fn json_framing_preserves_values_at_the_go_buffer_boundary() -> io::Result<()> {
    for entity_length in [2048, 2049] {
        let value = json!("x".repeat(entity_length - 3));
        let mut wire = Vec::new();
        write_response(&mut wire, json_response(value.clone()), false)?;
        let (headers, body) = split_wire(&wire)?;
        let entity = if entity_length == 2048 {
            assert!(headers.contains("\r\nContent-Length: 2048\r\n"));
            assert!(!headers.contains("Transfer-Encoding:"));
            body
        } else {
            assert!(headers.contains("\r\nTransfer-Encoding: chunked\r\n"));
            assert!(!headers.contains("Content-Length:"));
            let delimiter = body
                .windows(2)
                .position(|bytes| bytes == b"\r\n")
                .ok_or_else(|| io::Error::other("missing chunk delimiter"))?;
            let count = usize::from_str_radix(
                std::str::from_utf8(&body[..delimiter]).map_err(io::Error::other)?,
                16,
            )
            .map_err(io::Error::other)?;
            assert_eq!(count, entity_length);
            assert_eq!(&body[delimiter + 2 + count..], b"\r\n0\r\n\r\n");
            &body[delimiter + 2..delimiter + 2 + count]
        };
        assert_eq!(entity.len(), entity_length);
        assert_eq!(entity.last(), Some(&b'\n'));
        assert_eq!(serde_json::from_slice::<Value>(entity)?, value);
    }
    Ok(())
}

#[test]
fn head_keeps_small_representation_length_without_sending_an_entity() -> io::Result<()> {
    for entity_length in [2048, 2049] {
        let mut wire = Vec::new();
        write_response(
            &mut wire,
            json_response(json!("x".repeat(entity_length - 3))),
            true,
        )?;
        let (headers, body) = split_wire(&wire)?;
        assert!(body.is_empty());
        assert!(!headers.contains("Transfer-Encoding:"));
        assert_eq!(headers.contains("Content-Length:"), entity_length == 2048);
    }
    Ok(())
}

#[test]
fn no_content_has_neither_length_nor_entity_and_retains_standard_headers() -> io::Result<()> {
    for head in [false, true] {
        let mut wire = Vec::new();
        write_response_with_namespace(
            &mut wire,
            Response {
                status: 204,
                response_headers: Default::default(),
                consistency_index: None,
                body: json!({"not_a_wire_entity": true}),
            },
            head,
            "plain",
        )?;
        let (headers, body) = split_wire(&wire)?;
        assert!(headers.starts_with("HTTP/1.1 204 No Content\r\n"));
        assert!(!headers.contains("Content-Length:"));
        assert!(!headers.contains("Transfer-Encoding:"));
        assert!(body.is_empty());
        assert!(headers.contains("\r\nX-Vault-Namespace: plain"));
        assert!(
            headers
                .contains("\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\n")
        );
        assert!(!headers.contains("X-Content-Type-Options:"));
        let date = headers
            .lines()
            .find_map(|line| line.strip_prefix("Date: "))
            .ok_or_else(|| io::Error::other("missing Date header"))?;
        assert!(date.ends_with(" GMT"));
        assert!(chrono::DateTime::parse_from_rfc2822(date).is_ok());
    }
    Ok(())
}

#[test]
fn rejected_unknown_namespace_is_reflected_without_becoming_an_authority() -> io::Result<()> {
    let request = read_request(
        &mut "GET /v1/secret/value HTTP/1.1\r\nHost: local\r\nX-Vault-Namespace: unknown/\r\n\r\n"
            .as_bytes(),
        Duration::from_secs(1),
    )
    .map_err(|_| io::Error::other("valid namespace request rejected"))?;
    assert_eq!(request.namespace, "unknown");
    let mut wire = Vec::new();
    write_response_with_namespace(
        &mut wire,
        Response::error(404, "namespace not found"),
        false,
        &request.namespace,
    )?;
    let (headers, body) = split_wire(&wire)?;
    assert!(headers.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(headers.contains("\r\nX-Vault-Namespace: unknown"));
    assert_eq!(
        serde_json::from_slice::<Value>(body)?,
        json!({"errors": ["namespace not found"]})
    );
    let mut root = Vec::new();
    write_response(&mut root, Response::error(403, "permission denied"), false)?;
    assert!(!split_wire(&root)?.0.contains("X-Vault-Namespace:"));
    assert!(write_standard_headers(&mut Vec::new(), "plain\r\nInjected: yes").is_err());
    Ok(())
}

#[test]
fn custom_health_statuses_keep_go_status_lines_and_json_entities() -> io::Result<()> {
    for (status, reason) in [
        (201, "Created"),
        (299, "status code 299"),
        (499, "status code 499"),
        (500, "Internal Server Error"),
    ] {
        let mut wire = Vec::new();
        let body = json!({"initialized": false, "sealed": true});
        write_response(
            &mut wire,
            Response {
                status,
                response_headers: Default::default(),
                consistency_index: None,
                body: body.clone(),
            },
            false,
        )?;
        let (headers, entity) = split_wire(&wire)?;
        assert!(headers.starts_with(&format!("HTTP/1.1 {status} {reason}\r\n")));
        assert_eq!(serde_json::from_slice::<Value>(entity)?, body);
    }
    Ok(())
}

#[test]
fn sdk_headers95_exact_allowlist_multivalue_and_transport_framing() -> io::Result<()> {
    let offered = json!({
        "x-sdk-one":["one"], "X-SDK-Multi":["first","second"],
        "X-SDK-Blocked":["secret"], "X-SDK-Prefix-Item":["no-glob"],
        "X-SDK-Whitespace":["  line\r\nvalue\t  "]
    });
    for head in [false, true] {
        let mut response = json_response(json!({"data":{"marker":"preserved"}}));
        response.response_headers = crate::service::ResponseHeaders::from_sdk(
            Some(&offered),
            &[
                "X-SDK-One".into(),
                "x-sdk-multi".into(),
                "X-SDK-Prefix-*".into(),
                "X-SDK-Whitespace".into(),
            ],
        )
        .map_err(|()| io::Error::other("header filter"))?;
        let mut wire = Vec::new();
        write_response(&mut wire, response, head)?;
        let (headers, body) = split_wire(&wire)?;
        assert!(headers.contains("\r\nX-Sdk-One: one\r\n"));
        assert!(headers.contains("\r\nX-Sdk-Multi: first\r\nX-Sdk-Multi: second\r\n"));
        assert!(headers.contains("\r\nX-Sdk-Whitespace: line  value"));
        assert!(!headers.contains("Blocked"));
        assert!(!headers.contains("Prefix-Item"));
        assert_eq!(headers.matches("Content-Length:").count(), 1);
        if head {
            assert!(body.is_empty());
        } else {
            assert_eq!(
                serde_json::from_slice::<Value>(body)?,
                json!({"data":{"marker":"preserved"}})
            );
        }
    }
    let mut default = json_response(json!({"data":{}}));
    default.response_headers = crate::service::ResponseHeaders::from_sdk(Some(&offered), &[])
        .map_err(|()| io::Error::other("empty allowlist"))?;
    let mut wire = Vec::new();
    write_response(&mut wire, default, false)?;
    assert!(!split_wire(&wire)?.0.contains("X-Sdk-"));
    Ok(())
}

#[test]
fn sdk_headers95_transport_owned_primary_json_precedence() -> io::Result<()> {
    let offered = json!({
        "Date":["Mon, 01 Jan 2001 00:00:00 GMT","Tue, 02 Jan 2001 00:00:00 GMT"],
        "Content-Type":["application/x-sdk-first","application/x-sdk-second"],
        "Cache-Control":["sdk-cache-first","sdk-cache-second"],
        "Strict-Transport-Security":["max-age=17","max-age=19"]
    });
    let allowed = [
        "Date",
        "Content-Type",
        "Cache-Control",
        "Strict-Transport-Security",
    ]
    .map(str::to_owned);
    for head in [false, true] {
        let mut response = json_response(json!({"data":{"marker":"preserved"}}));
        response.response_headers =
            crate::service::ResponseHeaders::from_sdk(Some(&offered), &allowed)
                .map_err(|()| io::Error::other("primary transport header selection"))?;
        let mut wire = Vec::new();
        write_response(&mut wire, response, head)?;
        let (headers, body) = split_wire(&wire)?;
        let values = |name: &str| {
            headers
                .lines()
                .filter_map(|line| line.strip_prefix(name))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            values("Date: "),
            [
                "Mon, 01 Jan 2001 00:00:00 GMT",
                "Tue, 02 Jan 2001 00:00:00 GMT"
            ]
        );
        assert_eq!(values("Content-Type: "), ["application/json"]);
        assert_eq!(
            values("Cache-Control: "),
            ["no-store", "sdk-cache-first", "sdk-cache-second"]
        );
        assert_eq!(
            values("Strict-Transport-Security: "),
            ["max-age=31536000; includeSubDomains"]
        );
        assert!(!headers.contains("application/x-sdk") && !headers.contains("max-age=17"));
        if head {
            assert!(body.is_empty());
        } else {
            assert_eq!(
                serde_json::from_slice::<Value>(body)?,
                json!({"data":{"marker":"preserved"}})
            );
        }
    }
    let mut response = json_response(json!({}));
    response.response_headers =
        crate::service::ResponseHeaders::from_sdk(Some(&json!({"Date":[]})), &["Date".into()])
            .map_err(|()| io::Error::other("empty Date values"))?;
    let mut wire = Vec::new();
    write_response(&mut wire, response, false)?;
    let (headers, _) = split_wire(&wire)?;
    let dates = headers
        .lines()
        .filter_map(|line| line.strip_prefix("Date: "))
        .collect::<Vec<_>>();
    assert_eq!(dates.len(), 1);
    assert!(chrono::DateTime::parse_from_rfc2822(dates[0]).is_ok());
    Ok(())
}

#[test]
fn response_write_observation_retains_short_write_and_partial_error_semantics() -> io::Result<()> {
    struct PartialFailure {
        accepted: Vec<u8>,
        limit: usize,
        flush_calls: usize,
    }
    impl Write for PartialFailure {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.accepted.len() == self.limit {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "sensitive peer bytes",
                ));
            }
            let count = bytes.len().min(3).min(self.limit - self.accepted.len());
            self.accepted.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flush_calls += 1;
            Ok(())
        }
    }
    let mut direct = PartialFailure {
        accepted: Vec::new(),
        limit: 11,
        flush_calls: 0,
    };
    let direct_error = write_response(&mut direct, Response::error(400, "negative"), false)
        .err()
        .ok_or_else(|| io::Error::other("partial failure not reached"))?;
    let mut observed = PartialFailure {
        accepted: Vec::new(),
        limit: 11,
        flush_calls: 0,
    };
    let mut observation = ResponseWriteObservation {
        writer: &mut observed,
        accepted_plaintext_bytes: 0,
        flush_attempted: false,
    };
    let observed_error = write_response(&mut observation, Response::error(400, "negative"), false)
        .err()
        .ok_or_else(|| io::Error::other("observed partial failure not reached"))?;
    assert_eq!(observed_error.kind(), direct_error.kind());
    assert_eq!(observation.accepted_plaintext_bytes, 11);
    assert!(!observation.flush_attempted);
    drop(observation);
    assert_eq!(observed.accepted, direct.accepted);
    assert_eq!(observed.flush_calls, direct.flush_calls);
    assert_eq!(observed.accepted, b"HTTP/1.1 40");
    Ok(())
}
