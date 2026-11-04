//! Secret-bearing JSON buffers must wipe old allocations when they grow, not
//! merely their last allocation. Limits are chosen by the owning protocol.
use serde::Serialize;
use zeroize::Zeroizing;

pub(crate) enum Error {
    TooLarge,
    Serialization,
}

pub(crate) fn to_vec(value: &impl Serialize, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    struct Writer {
        bytes: Zeroizing<Vec<u8>>,
        limit: usize,
        overflowed: bool,
    }
    impl std::io::Write for Writer {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            let Some(next_len) = self
                .bytes
                .len()
                .checked_add(input.len())
                .filter(|size| *size <= self.limit)
            else {
                self.overflowed = true;
                return Err(std::io::Error::other("secret JSON exceeds protocol limit"));
            };
            if next_len > self.bytes.capacity() {
                let capacity = next_len
                    .max(self.bytes.capacity().saturating_mul(2))
                    .min(self.limit);
                let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
                grown.extend_from_slice(&self.bytes);
                self.bytes = grown;
            }
            self.bytes.extend_from_slice(input);
            Ok(input.len())
        }
        fn write_all(&mut self, input: &[u8]) -> std::io::Result<()> {
            self.write(input).map(|_| ())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer {
        bytes: Zeroizing::new(Vec::new()),
        limit,
        overflowed: false,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        if writer.overflowed {
            Error::TooLarge
        } else {
            Error::Serialization
        }
    })?;
    Ok(writer.bytes)
}

// Compare the full serialization without retaining a second secret byte buffer.
// Mismatches must not hide later serialization errors or protocol-limit errors.
pub(crate) fn matches_bytes(
    value: &impl Serialize,
    expected: &[u8],
    limit: usize,
) -> Result<bool, Error> {
    struct Writer<'a> {
        expected: &'a [u8],
        position: usize,
        limit: usize,
        matches: bool,
        overflowed: bool,
    }
    impl std::io::Write for Writer<'_> {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            let Some(next_len) = self
                .position
                .checked_add(input.len())
                .filter(|size| *size <= self.limit)
            else {
                self.overflowed = true;
                return Err(std::io::Error::other("secret JSON exceeds protocol limit"));
            };
            if self.expected.get(self.position..next_len) != Some(input) {
                self.matches = false;
            }
            self.position = next_len;
            Ok(input.len())
        }
        fn write_all(&mut self, input: &[u8]) -> std::io::Result<()> {
            self.write(input).map(|_| ())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer {
        expected,
        position: 0,
        limit,
        matches: true,
        overflowed: false,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        if writer.overflowed {
            Error::TooLarge
        } else {
            Error::Serialization
        }
    })?;
    Ok(writer.matches && writer.position == expected.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::ser::{Error as _, SerializeSeq};

    fn exact_and_original_limit(value: &impl Serialize, expected: &[u8]) {
        assert!(
            to_vec(value, expected.len()).is_ok_and(|actual| actual.as_slice() == expected),
            "exact bound or bytes changed"
        );
        assert!(matches!(
            to_vec(value, expected.len() - 1),
            Err(Error::TooLarge)
        ));
        assert!(matches_bytes(value, expected, expected.len()).is_ok_and(|matched| matched));
        assert!(matches!(
            matches_bytes(value, expected, expected.len() - 1),
            Err(Error::TooLarge)
        ));
    }

    #[test]
    fn secret_json_keeps_fixed_utf8_escape_numeric_and_empty_bytes() {
        #[derive(Serialize)]
        struct Golden<'a> {
            text: &'a str,
            numbers: [u64; 3],
            values: (bool, Option<u8>, &'a str),
        }
        let value = Golden {
            text: "é\n\0\"\\",
            numbers: [0, 127, u64::MAX],
            values: (true, None, ""),
        };
        exact_and_original_limit(
            &value,
            r#"{"text":"é\n\u0000\"\\","numbers":[0,127,18446744073709551615],"values":[true,null,""]}"#
                .as_bytes(),
        );
        exact_and_original_limit(&"", b"\"\"");
        exact_and_original_limit(&true, b"true");
        exact_and_original_limit(&(), b"null");
        assert!(matches!(to_vec(&"", 0), Err(Error::TooLarge)));
    }

    #[test]
    fn secret_json_original_byte_limits_hold_across_secure_growth_boundaries() {
        for length in [
            0, 1, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 1023, 1024, 8191, 8192, 262_169,
        ] {
            let value = "x".repeat(length);
            let expected = format!("\"{value}\"");
            exact_and_original_limit(&value, expected.as_bytes());
        }
    }

    #[test]
    fn secret_json_original_error_mapping_survives_partial_output_refusals() {
        struct Refuse;
        impl Serialize for Refuse {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(S::Error::custom("fixed synthetic serialization refusal"))
            }
        }
        struct PrefixThenRefuse;
        impl Serialize for PrefixThenRefuse {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut sequence = serializer.serialize_seq(Some(1))?;
                sequence.serialize_element(&7_u8)?;
                Err(S::Error::custom("fixed synthetic refusal after a prefix"))
            }
        }
        assert!(matches!(to_vec(&Refuse, 0), Err(Error::Serialization)));
        assert!(matches!(
            matches_bytes(&Refuse, b"x", 0),
            Err(Error::Serialization)
        ));
        assert!(matches!(
            to_vec(&PrefixThenRefuse, 2),
            Err(Error::Serialization)
        ));
        assert!(matches!(to_vec(&PrefixThenRefuse, 1), Err(Error::TooLarge)));
        assert!(matches!(
            matches_bytes(&PrefixThenRefuse, b"xx", 2),
            Err(Error::Serialization)
        ));
        assert!(matches!(
            matches_bytes(&PrefixThenRefuse, b"x", 1),
            Err(Error::TooLarge)
        ));
    }

    #[test]
    fn secret_json_stream_comparison_rejects_noncanonical_and_trailing_bytes() {
        let value = serde_json::json!({"a":[7,"é\n"]});
        let canonical = r#"{"a":[7,"é\n"]}"#.as_bytes();
        assert!(matches_bytes(&value, canonical, canonical.len()).is_ok_and(|matched| matched));
        for different in [
            r#" {"a":[7,"é\n"]}"#.as_bytes(),
            r#"{"a":[7,"\u00e9\n"]}"#.as_bytes(),
            r#"{"a":[7,"e\n"]}"#.as_bytes(),
            r#"{"a":[7,"é\n"]"#.as_bytes(),
            r#"{"a":[7,"é\n"]} "#.as_bytes(),
        ] {
            assert!(matches_bytes(&value, different, 128).is_ok_and(|matched| !matched));
        }
        // The limit bounds output, not the supplied comparison bytes.
        assert!(matches_bytes(&7_u8, b"7 ", 1).is_ok_and(|matched| !matched));
        assert!(matches!(
            matches_bytes(&999_u16, b"", 1),
            Err(Error::TooLarge)
        ));
    }

    #[test]
    fn secret_json_stream_mismatch_keeps_all_serializer_visits() {
        use std::cell::Cell;
        struct Observed<'a>(&'a Cell<usize>);
        impl Serialize for Observed<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut sequence = serializer.serialize_seq(Some(2))?;
                for item in [1_u8, 2_u8] {
                    self.0.set(self.0.get() + 1);
                    sequence.serialize_element(&item)?;
                }
                sequence.end()
            }
        }
        let visits = Cell::new(0);
        assert!(matches_bytes(&Observed(&visits), b"xxxxx", 5).is_ok_and(|matched| !matched));
        assert_eq!(visits.get(), 2);
        visits.set(0);
        assert!(matches_bytes(&Observed(&visits), b"[1,2]", 5).is_ok_and(|matched| matched));
        assert_eq!(visits.get(), 2);
    }
}
