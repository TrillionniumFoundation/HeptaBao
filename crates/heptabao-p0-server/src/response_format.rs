//! Formatting shared by the P0 library and its transport binary.

use heptabao_protocol::ProtocolError;

pub(crate) fn escape_json(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => output.push_str("\\uFFFD"),
            character => output.push(character),
        }
    }
    output
}

pub(crate) const fn protocol_status(error: ProtocolError) -> u16 {
    match error {
        ProtocolError::DeadlineExceeded => 408,
        ProtocolError::UnknownOperation | ProtocolError::UnsupportedMethod => 404,
        ProtocolError::RequestTooLarge
        | ProtocolError::HeadTooLarge
        | ProtocolError::BodyTooLarge => 413,
        _ => 400,
    }
}

pub(crate) const fn protocol_detail_code(error: ProtocolError) -> &'static str {
    match error {
        ProtocolError::RequestTooLarge => "protocol-request-too-large",
        ProtocolError::HeadTooLarge => "protocol-head-too-large",
        ProtocolError::BodyTooLarge => "protocol-body-too-large",
        ProtocolError::IncompleteHead => "protocol-incomplete-head",
        ProtocolError::BareLineFeed => "protocol-bare-line-feed",
        ProtocolError::BareCarriageReturn => "protocol-bare-carriage-return",
        ProtocolError::ControlCharacter => "protocol-control-character",
        ProtocolError::NonUtf8Head => "protocol-non-utf8-head",
        ProtocolError::NonAsciiHead => "protocol-non-ascii-head",
        ProtocolError::InvalidRequestLine => "protocol-invalid-request-line",
        ProtocolError::UnsupportedHttpVersion => "protocol-unsupported-http-version",
        ProtocolError::UnsupportedMethod => "protocol-unsupported-method",
        ProtocolError::InvalidTarget => "protocol-invalid-target",
        ProtocolError::AmbiguousPath => "protocol-ambiguous-path",
        ProtocolError::FragmentForbidden => "protocol-fragment-forbidden",
        ProtocolError::InvalidPercentEncoding => "protocol-invalid-percent-encoding",
        ProtocolError::NonCanonicalPercentEncoding => "protocol-noncanonical-percent-encoding",
        ProtocolError::AmbiguousQuery => "protocol-ambiguous-query",
        ProtocolError::DuplicateQueryKey => "protocol-duplicate-query-key",
        ProtocolError::UnsupportedQuery => "protocol-unsupported-query",
        ProtocolError::TooManyHeaders => "protocol-too-many-headers",
        ProtocolError::InvalidHeader => "protocol-invalid-header",
        ProtocolError::InvalidHeaderName => "protocol-invalid-header-name",
        ProtocolError::NonCanonicalHeaderValue => "protocol-noncanonical-header-value",
        ProtocolError::DuplicateHeader => "protocol-duplicate-header",
        ProtocolError::MissingHost => "protocol-missing-host",
        ProtocolError::TransferEncodingForbidden => "protocol-transfer-encoding-forbidden",
        ProtocolError::InvalidContentLength => "protocol-invalid-content-length",
        ProtocolError::ContentLengthMismatch => "protocol-content-length-mismatch",
        ProtocolError::ContentLengthExceeded => "protocol-content-length-exceeded",
        ProtocolError::UnknownOperation => "protocol-unknown-operation",
        ProtocolError::InvalidDeadline => "protocol-invalid-deadline",
        ProtocolError::DeadlineBudgetTooLarge => "protocol-deadline-budget-too-large",
        ProtocolError::ClockRegression => "protocol-clock-regression",
        ProtocolError::DeadlineExceeded => "protocol-deadline-exceeded",
        ProtocolError::InvalidRequestId => "protocol-invalid-request-id",
        ProtocolError::InvalidSecret => "protocol-invalid-secret",
    }
}
