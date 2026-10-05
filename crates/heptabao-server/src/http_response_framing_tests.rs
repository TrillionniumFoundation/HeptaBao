use super::*;

fn json_response(body: Value) -> Response {
    Response {
        status: 200,
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
