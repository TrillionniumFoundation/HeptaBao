//! A bounded RESP2 client for deployment-enrolled Valkey endpoints.
//!
//! The database service uses this module only over the TLS stream created by
//! `Outbound`.  It never resolves names, falls back to clear text, evaluates
//! arbitrary commands, or retries an operation after an indeterminate write.
use crate::outbound::{Endpoint, Target, TlsStream};
use std::io::{Read, Write};
use zeroize::Zeroizing;

const MAX_FRAME: usize = 256 * 1024;
const MAX_DEPTH: usize = 8;
const MAX_NODES: usize = 1024;

/// Tracks the complete RESP reply, rather than just individual bulk values.
/// Without an aggregate budget a bounded array of individually-small values
/// could still force unbounded allocation and CPU before the caller sees it.
struct ParseBudget {
    frame_remaining: usize,
    nodes_remaining: usize,
}

impl ParseBudget {
    fn new() -> Self {
        Self {
            frame_remaining: MAX_FRAME,
            nodes_remaining: MAX_NODES,
        }
    }

    fn bytes(&mut self, count: usize) -> Result<(), &'static str> {
        if count > self.frame_remaining {
            return Err("Valkey RESP response exceeds frame bound");
        }
        self.frame_remaining -= count;
        Ok(())
    }

    fn node(&mut self) -> Result<(), &'static str> {
        self.nodes_remaining = self
            .nodes_remaining
            .checked_sub(1)
            .ok_or("Valkey RESP response exceeds node bound")?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RespValue {
    Simple(String),
    Error,
    Integer(i64),
    Bulk(Zeroizing<Vec<u8>>),
    Array(Vec<RespValue>),
    Null,
}

impl RespValue {
    pub(crate) fn is_ok(&self) -> bool {
        matches!(self, Self::Simple(value) if value == "OK")
    }

    pub(crate) fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

pub(crate) struct ValkeySession {
    stream: TlsStream,
}

impl ValkeySession {
    pub(crate) fn connect(
        endpoint: &Endpoint,
        target: &Target,
        username: &str,
        password: &str,
    ) -> Result<Self, &'static str> {
        if username.is_empty()
            || username.len() > 256
            || password.is_empty()
            || password.len() > 512
            || !username.is_ascii()
            || !password.is_ascii()
            || username.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
            || password.bytes().any(|byte| byte == 0)
        {
            return Err("invalid Valkey manager credentials");
        }
        let database = target
            .path
            .strip_prefix('/')
            .filter(|value| !value.is_empty())
            .ok_or("Valkey URL requires an explicit database index")?;
        let database: u8 = database
            .parse()
            .map_err(|_| "invalid Valkey database index")?;
        if database != 0 {
            return Err("Valkey ACL profile requires database zero");
        }
        let stream = endpoint.tls(endpoint.connect()?)?;
        let mut session = Self { stream };
        if !session.command(&["AUTH", username, password])?.is_ok() {
            return Err("Valkey manager authentication rejected");
        }
        if !session.command(&["SELECT", &database.to_string()])?.is_ok() {
            return Err("Valkey database selection rejected");
        }
        Ok(session)
    }

    pub(crate) fn command(&mut self, args: &[&str]) -> Result<RespValue, &'static str> {
        if args.is_empty()
            || args.len() > 32
            || args.iter().any(|arg| {
                arg.is_empty()
                    || arg.len() > 4096
                    || !arg.is_ascii()
                    || arg.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
            })
        {
            return Err("Valkey command exceeds bounded RESP profile");
        }
        // Commands can contain generated passwords. Keep the serialized frame
        // in zeroizing storage until it is released after the write.
        let mut request = Zeroizing::new(Vec::with_capacity(
            args.iter().map(|arg| arg.len() + 16).sum(),
        ));
        request.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
        for arg in args {
            request.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
            request.extend_from_slice(arg.as_bytes());
            request.extend_from_slice(b"\r\n");
        }
        if request.len() > MAX_FRAME {
            return Err("Valkey command exceeds frame bound");
        }
        self.stream
            .write_all(&request)
            .and_then(|()| self.stream.flush())
            .map_err(|_| "Valkey command delivery uncertain")?;
        let mut budget = ParseBudget::new();
        parse_value(&mut self.stream, 0, &mut budget)
    }
}

fn parse_value(
    stream: &mut impl Read,
    depth: usize,
    budget: &mut ParseBudget,
) -> Result<RespValue, &'static str> {
    if depth > MAX_DEPTH {
        return Err("Valkey RESP nesting exceeds bound");
    }
    budget.node()?;
    let mut prefix = [0u8; 1];
    budget.bytes(1)?;
    stream
        .read_exact(&mut prefix)
        .map_err(|_| "Valkey response unavailable")?;
    match prefix[0] {
        b'+' => Ok(RespValue::Simple(read_line(stream, budget)?)),
        b'-' => {
            discard_line(stream, budget)?;
            Ok(RespValue::Error)
        }
        b':' => {
            let line = read_line(stream, budget)?;
            let value = line
                .parse::<i64>()
                .map_err(|_| "invalid Valkey integer response")?;
            Ok(RespValue::Integer(value))
        }
        b'$' => {
            let length = read_length(stream, budget)?;
            if length == -1 {
                return Ok(RespValue::Null);
            }
            if length < -1 {
                return Err("invalid Valkey bulk length");
            }
            let length = usize::try_from(length).map_err(|_| "invalid Valkey bulk length")?;
            if length > MAX_FRAME {
                return Err("Valkey bulk response exceeds bound");
            }
            budget.bytes(length.checked_add(2).ok_or("invalid Valkey bulk length")?)?;
            let mut bytes = Zeroizing::new(vec![0; length]);
            stream
                .read_exact(&mut bytes)
                .map_err(|_| "truncated Valkey bulk response")?;
            read_crlf(stream)?;
            Ok(RespValue::Bulk(bytes))
        }
        b'*' => {
            let length = read_length(stream, budget)?;
            if length == -1 {
                return Ok(RespValue::Null);
            }
            if length < -1 {
                return Err("invalid Valkey array length");
            }
            let length = usize::try_from(length).map_err(|_| "invalid Valkey array length")?;
            if length > 256 {
                return Err("Valkey array response exceeds bound");
            }
            let mut values = Vec::with_capacity(length);
            for _ in 0..length {
                values.push(parse_value(stream, depth + 1, budget)?);
            }
            Ok(RespValue::Array(values))
        }
        _ => Err("invalid Valkey RESP type"),
    }
}

fn read_line(stream: &mut impl Read, budget: &mut ParseBudget) -> Result<String, &'static str> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        budget.bytes(1)?;
        stream
            .read_exact(&mut byte)
            .map_err(|_| "truncated Valkey response line")?;
        if byte[0] == b'\r' {
            let mut lf = [0u8; 1];
            budget.bytes(1)?;
            stream
                .read_exact(&mut lf)
                .map_err(|_| "truncated Valkey response line terminator")?;
            if lf[0] != b'\n' {
                return Err("invalid Valkey response line terminator");
            }
            return String::from_utf8(bytes).map_err(|_| "invalid Valkey response text");
        }
        if byte[0] == b'\n' || bytes.len() >= 4096 {
            return Err("invalid Valkey response line");
        }
        bytes.push(byte[0]);
    }
}

fn discard_line(stream: &mut impl Read, budget: &mut ParseBudget) -> Result<(), &'static str> {
    read_line(stream, budget).map(|_| ())
}

fn read_length(stream: &mut impl Read, budget: &mut ParseBudget) -> Result<i64, &'static str> {
    read_line(stream, budget)?
        .parse::<i64>()
        .map_err(|_| "invalid Valkey response length")
}

fn read_crlf(stream: &mut impl Read) -> Result<(), &'static str> {
    let mut suffix = [0u8; 2];
    stream
        .read_exact(&mut suffix)
        .map_err(|_| "truncated Valkey response terminator")?;
    if suffix != *b"\r\n" {
        return Err("invalid Valkey response terminator");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_bounded_resp_shapes() {
        let mut stream = Cursor::new(b"+OK\r\n:7\r\n$3\r\nfoo\r\n*2\r\n+on\r\n$-1\r\n".to_vec());
        let mut budget = ParseBudget::new();
        assert!(parse_value(&mut stream, 0, &mut budget).is_ok());
        assert_eq!(
            parse_value(&mut stream, 0, &mut budget),
            Ok(RespValue::Integer(7))
        );
        assert!(matches!(
            parse_value(&mut stream, 0, &mut budget),
            Ok(RespValue::Bulk(_))
        ));
        assert!(matches!(
            parse_value(&mut stream, 0, &mut budget),
            Ok(RespValue::Array(_))
        ));
    }

    #[test]
    fn rejects_malformed_or_oversized_resp() {
        let mut malformed = Cursor::new(b"$1\n".to_vec());
        assert!(parse_value(&mut malformed, 0, &mut ParseBudget::new()).is_err());
        let mut oversized = Cursor::new(format!("${}\r\n", MAX_FRAME + 1).into_bytes());
        assert!(parse_value(&mut oversized, 0, &mut ParseBudget::new()).is_err());
        for input in [&b"$-2\r\n"[..], &b"*-2\r\n"[..]] {
            let mut invalid = Cursor::new(input.to_vec());
            assert!(parse_value(&mut invalid, 0, &mut ParseBudget::new()).is_err());
        }
    }

    #[test]
    fn rejects_replies_that_exceed_aggregate_frame_budget() {
        let item = vec![b'x'; 2048];
        let mut response = b"*128\r\n".to_vec();
        for _ in 0..128 {
            response.extend_from_slice(format!("${}\r\n", item.len()).as_bytes());
            response.extend_from_slice(&item);
            response.extend_from_slice(b"\r\n");
        }
        let mut stream = Cursor::new(response);
        assert!(parse_value(&mut stream, 0, &mut ParseBudget::new()).is_err());
    }

    #[test]
    fn rejects_replies_that_exceed_aggregate_node_budget() {
        let mut response = b"*256\r\n".to_vec();
        for _ in 0..256 {
            response.extend_from_slice(b"*5\r\n+OK\r\n+OK\r\n+OK\r\n+OK\r\n+OK\r\n");
        }
        let mut stream = Cursor::new(response);
        assert!(parse_value(&mut stream, 0, &mut ParseBudget::new()).is_err());
    }
}
