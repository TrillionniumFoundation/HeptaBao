use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn lines(wire: &[u8]) -> Result<Vec<&str>, std::str::Utf8Error> {
    Ok(std::str::from_utf8(wire)?
        .split("\r\n\r\n")
        .next()
        .unwrap_or("")
        .split("\r\n")
        .collect())
}

#[test]
fn a_429_status_alone_does_not_add_retry_after_or_quota_metadata() -> TestResult {
    for head in [false, true] {
        let mut wire = Vec::new();
        write_response(
            &mut wire,
            Response::error(429, "rate limit quota exceeded"),
            head,
        )?;
        let headers = lines(&wire)?;
        assert!(headers[0].starts_with("HTTP/1.1 429 "));
        assert!(!headers.iter().any(|line| {
            let lowercase = line.to_ascii_lowercase();
            lowercase.starts_with("retry-after:") || lowercase.starts_with("x-ratelimit-")
        }));
    }
    Ok(())
}

#[test]
fn enabled_quota_metadata_is_written_once_with_its_real_numeric_values() -> TestResult {
    for (status, head) in [(200, false), (200, true), (429, false), (429, true)] {
        let mut response = Response::error(status, "fixture");
        let mut values = json!({
            "X-RateLimit-Limit":["3"], "X-RateLimit-Remaining":["0"],
            "X-RateLimit-Reset":["3598"], "X-Logical":["retained"],
        });
        if status == 429 {
            values["Retry-After"] = json!(["1798"]);
        }
        response.response_headers = crate::service::ResponseHeaders::from_sdk(
            Some(&values),
            &[
                "X-RateLimit-Limit".into(),
                "X-RateLimit-Remaining".into(),
                "X-RateLimit-Reset".into(),
                "Retry-After".into(),
                "X-Logical".into(),
            ],
        )
        .map_err(|()| "fixture headers")?;
        let mut wire = Vec::new();
        write_response(&mut wire, response, head)?;
        let headers = lines(&wire)?;
        for expected in [
            "X-Ratelimit-Limit: 3",
            "X-Ratelimit-Remaining: 0",
            "X-Ratelimit-Reset: 3598",
            "X-Logical: retained",
        ] {
            assert_eq!(headers.iter().filter(|line| **line == expected).count(), 1);
        }
        let retries: Vec<_> = headers
            .iter()
            .filter(|line| line.to_ascii_lowercase().starts_with("retry-after:"))
            .collect();
        if status == 429 {
            assert_eq!(retries, vec![&"Retry-After: 1798"]);
        } else {
            assert!(retries.is_empty());
        }
    }
    Ok(())
}
