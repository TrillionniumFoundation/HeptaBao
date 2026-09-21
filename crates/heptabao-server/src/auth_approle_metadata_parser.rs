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

// Standard serde handles escapes. We clear strings we own; serde's internal
// decoding scratch has the same lifetime limitation as the HTTP JSON parser.
fn string_prefix(input: &str) -> Result<(Text, usize), AuthError> {
    let mut decoder = serde_json::Deserializer::from_str(input);
    let value = Text::deserialize(&mut decoder).map_err(|_| invalid())?;
    let length = decoder.into_iter::<IgnoredAny>().byte_offset();
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
    fn syntax_and_trailing_data_do_not_leave_a_partial_map() -> Result<(), AuthError> {
        for input in [r#"{"a=x":"good","b=y":"#, r#"{"a=x":"good"} false"#] {
            let mut map = Metadata::default();
            assert!(!json(input, &mut map)?);
            assert!(map.0.is_empty());
        }
        Ok(())
    }
}
