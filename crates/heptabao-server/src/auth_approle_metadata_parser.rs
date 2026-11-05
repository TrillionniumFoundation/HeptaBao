//! The Go parser validates JSON syntax before decoding a string map. A JSON
//! type error preserves decoded entries (including empty string placeholders)
//! before CSV fallback; a syntax error has no partial map. Both matter.
use super::*;
use serde::de::{IgnoredAny, Visitor};
use std::fmt;

struct Text(Zeroizing<String>);
impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor;
        impl Visitor<'_> for TextVisitor {
            type Value = Text;
            fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                out.write_str("metadata string")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Text, E> {
                Ok(Text(Zeroizing::new(value.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Text, E> {
                Ok(Text(Zeroizing::new(value)))
            }
        }
        deserializer.deserialize_string(TextVisitor)
    }
}

/// Go's DecodeRune replaces each invalid byte separately, including a truncated
/// multi-byte suffix. Rust's from_utf8_lossy instead groups some invalid bytes.
pub(super) fn replace_invalid_utf8(mut bytes: &[u8]) -> Result<Zeroizing<String>, AuthError> {
    let mut text = Zeroizing::new(String::with_capacity(bytes.len() * 3));
    loop {
        match std::str::from_utf8(bytes) {
            Ok(valid) => {
                text.push_str(valid);
                return Ok(text);
            }
            Err(error) => {
                let (valid, tail) = bytes.split_at(error.valid_up_to());
                text.push_str(std::str::from_utf8(valid).map_err(|_| invalid())?);
                text.push('\u{fffd}');
                bytes = &tail[1..];
            }
        }
    }
}

fn unicode_escape(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 6 || bytes[..2] != *b"\\u" {
        return None;
    }
    bytes[2..6].iter().try_fold(0_u16, |value, digit| {
        Some(value * 16 + char::from(*digit).to_digit(16)? as u16)
    })
}

// Syntax has already passed IgnoredAny. Replace only isolated surrogate escape
// units, leaving paired units and escaped backslashes untouched. Standard serde
// still decodes all JSON escapes. Its internal scratch has the same lifetime
// limitation as the HTTP JSON parser; buffers owned here are drop-cleared.
fn string_prefix(input: &str) -> Result<(Text, usize), AuthError> {
    let length = skip_prefix(input)?;
    let mut raw = Zeroizing::new(input.as_bytes()[..length].to_vec());
    let mut cursor = 0;
    while cursor < raw.len() {
        if raw[cursor] != b'\\' {
            cursor += 1;
            continue;
        }
        let Some(unit) = unicode_escape(&raw[cursor..]) else {
            cursor += 2;
            continue;
        };
        if (0xd800..=0xdbff).contains(&unit)
            && unicode_escape(&raw[cursor + 6..])
                .is_some_and(|low| (0xdc00..=0xdfff).contains(&low))
        {
            cursor += 12;
            continue;
        }
        if (0xd800..=0xdfff).contains(&unit) {
            raw[cursor + 2..cursor + 6].copy_from_slice(b"FFFD");
        }
        cursor += 6;
    }
    let mut decoder = serde_json::Deserializer::from_slice(&raw);
    let value = Text::deserialize(&mut decoder).map_err(|_| invalid())?;
    Ok((value, length))
}
fn skip_prefix(input: &str) -> Result<usize, AuthError> {
    let mut decoder = serde_json::Deserializer::from_str(input);
    IgnoredAny::deserialize(&mut decoder).map_err(|_| invalid())?;
    Ok(decoder.into_iter::<IgnoredAny>().byte_offset())
}
fn whitespace(input: &str) -> &str {
    input.trim_start_matches([' ', '\t', '\r', '\n'])
}

/// `false` means run CSV against the same map. Never discard a type-error map.
pub(super) fn json(input: &str, map: &mut Metadata) -> Result<bool, AuthError> {
    let mut syntax = serde_json::Deserializer::from_str(input);
    if IgnoredAny::deserialize(&mut syntax).is_err() || syntax.end().is_err() {
        return Ok(false);
    }
    let input = whitespace(input);
    if input.trim_end_matches([' ', '\t', '\r', '\n']) == "null" {
        return Ok(true);
    }
    let Some(mut rest) = input.strip_prefix('{') else {
        return Ok(false);
    };
    let mut type_error = false;
    loop {
        rest = whitespace(rest);
        if rest.starts_with('}') {
            return Ok(!type_error);
        }
        let (mut key, used) = string_prefix(rest)?;
        rest = whitespace(&rest[used..])
            .strip_prefix(':')
            .ok_or_else(invalid)?;
        rest = whitespace(rest);
        // Syntax is already checked. IgnoredAny consumes nested/number values
        // without an intermediate Value tree or a lossy float conversion.
        let used = skip_prefix(rest)?;
        let raw = &rest[..used];
        let mut value = if raw.starts_with('"') {
            string_prefix(raw)?.0.0
        } else {
            if raw != "null" {
                type_error = true;
            }
            Zeroizing::new(String::new())
        };
        // Map decoding creates a fresh zero-value element for each duplicate.
        // Null and non-string values therefore replace any prior string with "".
        map.insert(std::mem::take(&mut *key.0), std::mem::take(&mut *value));
        rest = whitespace(&rest[used..]);
        if rest.starts_with('}') {
            return Ok(!type_error);
        }
        rest = rest.strip_prefix(',').ok_or_else(invalid)?;
    }
}

pub(super) fn csv(input: &str, map: &mut Metadata) -> Result<(), AuthError> {
    // Keep every owned pair in a drop-cleared buffer, including duplicates and
    // the unprocessed tail when a later pair fails. Reserve enough UTF-8 space
    // before appending so case mapping does not leave old plaintext allocations.
    let mut pairs: Vec<Zeroizing<String>> = input
        .split(',')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let mut lowered = Zeroizing::new(String::with_capacity(pair.len() * 4));
            for c in pair.chars() {
                lowered.push(c.to_lowercase().next().unwrap_or(c));
            }
            lowered
        })
        .collect();
    pairs.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
    pairs.dedup_by(|a, b| a.as_str() == b.as_str());
    for pair in pairs {
        let mut parts = pair.split('=');
        let key = parts.next().unwrap_or_default().trim();
        let value = parts.next().ok_or_else(invalid)?.trim();
        if parts.next().is_some() || key.is_empty() || value.is_empty() {
            return Err(invalid());
        }
        map.insert(key.to_owned(), value.to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn type_error_retains_zero_placeholders_and_duplicate_error_flag() -> Result<(), AuthError> {
        let mut map = Metadata::default();
        assert!(!json(r#"{"a=x":"good","b=y":42}"#, &mut map)?);
        assert_eq!(map.0.get("a=x").map(String::as_str), Some("good"));
        assert_eq!(map.0.get("b=y").map(String::as_str), Some(""));
        let mut duplicate = Metadata::default();
        assert!(!json(r#"{"a=x":42,"a=x":"good"}"#, &mut duplicate)?);
        assert_eq!(duplicate.0.get("a=x").map(String::as_str), Some("good"));
        let mut null = Metadata::default();
        assert!(json(r#"{"a":"good","a":null}"#, &mut null)?);
        assert_eq!(null.0.get("a").map(String::as_str), Some(""));
        // A type error is not a float-conversion operation. Go keeps a zero
        // string even when the literal is larger than any finite f64.
        let mut huge = Metadata::default();
        assert!(!json(r#"{"b=x":1e999}"#, &mut huge)?);
        assert_eq!(huge.0.get("b=x").map(String::as_str), Some(""));
        Ok(())
    }
    #[test]
    fn standard_string_decoder_preserves_escapes_and_unicode() -> Result<(), AuthError> {
        let mut map = Metadata::default();
        assert!(json(r#"{"a\u003dx":"line\n\t\uD83D\uDE00"}"#, &mut map)?);
        assert_eq!(map.0.get("a=x").map(String::as_str), Some("line\n\t😀"));
        Ok(())
    }
    #[test]
    fn native_unicode_replacement_preserves_pairs_literals_and_duplicate_order()
    -> Result<(), AuthError> {
        let mut map = Metadata::default();
        assert!(json(
            r#"{"\ud800":"\udc00","pair":"\uD83D\uDE00","literal":"\\ud800","mix":"\ud800\ud800\udc00\udc00","dup":"\ud800","dup":"last"}"#,
            &mut map
        )?);
        assert_eq!(map.0.get("�").map(String::as_str), Some("�"));
        assert_eq!(map.0.get("pair").map(String::as_str), Some("😀"));
        assert_eq!(map.0.get("literal").map(String::as_str), Some(r"\ud800"));
        assert_eq!(map.0.get("mix").map(String::as_str), Some("�𐀀�"));
        assert_eq!(map.0.get("dup").map(String::as_str), Some("last"));
        let mut syntax_error = Metadata::default();
        assert!(!json(r#"{"a":"\ud800",broken"#, &mut syntax_error)?);
        assert!(syntax_error.0.is_empty());
        csv(r"env=\ud800", &mut syntax_error)?;
        assert_eq!(
            syntax_error.0.get("env").map(String::as_str),
            Some(r"\ud800")
        );
        Ok(())
    }
    #[test]
    fn base64_invalid_utf8_uses_one_replacement_per_byte_before_json_or_csv()
    -> Result<(), AuthError> {
        for (bytes, expected) in [
            (&b"\xff"[..], "�"),
            (&b"\xe2\x82"[..], "��"),
            (&b"a\xf0\x90\x80z"[..], "a���z"),
            (&b"\xed\xa0\x80"[..], "���"),
            (&b"\xf0\x9f\x98\x80\xff"[..], "😀�"),
        ] {
            assert_eq!(replace_invalid_utf8(bytes)?.as_str(), expected);
        }
        for (bytes, expected) in [
            (&b"{\"env\":\"\xe2\x82\"}"[..], "��"),
            (&b"env=\xed\xa0\x80"[..], "���"),
        ] {
            let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
            let map = super::super::parse(&json!({"metadata":encoded}))?.ok_or_else(invalid)?;
            assert_eq!(map.get("env").map(String::as_str), Some(expected));
        }
        let invalid_prefix =
            base64::engine::general_purpose::STANDARD.encode(b"\xff{\"env\":\"ok\"}");
        assert!(super::super::parse(&json!({"metadata":invalid_prefix})).is_err());
        Ok(())
    }
    #[test]
    fn syntax_and_trailing_data_do_not_leave_a_partial_map() -> Result<(), AuthError> {
        for input in [r#"{"a=x":"good","b=y":"#, r#"{"a=x":"good"} false"#] {
            let mut map = Metadata::default();
            assert!(!json(input, &mut map)?);
            assert!(map.0.is_empty());
        }
        Ok(())
    }
}
