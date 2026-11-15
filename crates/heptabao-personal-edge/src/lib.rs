#![forbid(unsafe_code)]

//! Personal-vault edge adapters. Opaque storage has no decryption key.
//! Browser origins are exact, explicitly supported HTTPS origins; there is no
//! suffix, eTLD, wildcard, cross-frame or native-app association inference.

pub mod sync;

/// Deliberately bounded ASCII HTTPS subset. Unsupported forms fail closed;
/// browser URL canonicalization must happen before this boundary. In
/// particular Unicode display names, credentials, paths, queries, fragments,
/// noncanonical ports, trailing dots and IPv6 literals are not accepted.
pub fn validate_origin(origin: &str) -> bool {
    heptabao_personal_vault::valid_https_origin(origin)
}

pub fn authorize_fill(stored: &str, actual: &str, top_frame: bool, unlocked: bool) -> bool {
    unlocked && top_frame && validate_origin(stored) && stored == actual
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_https_origin_only() {
        assert!(authorize_fill(
            "https://login.example",
            "https://login.example",
            true,
            true
        ));
        assert!(validate_origin("https://login.example:8443"));
        assert!(!validate_origin("https://127.0.0.1:8443"));
        for rejected in [
            "http://login.example",
            "https://login.example.evil",
            "https://evil@login.example",
            "https://login.example.",
            "https://LOGIN.example",
            "https://login.example:443",
            "https://login.example:08443",
            "https://login.example/path",
            "https://login.example?x",
            "https://login.example/#x",
            "https://login.exаmple",
            "https://[::1]",
            "https://x:0",
        ] {
            assert!(!authorize_fill(
                "https://login.example",
                rejected,
                true,
                true
            ));
        }
        assert!(!authorize_fill(
            "https://login.example",
            "https://login.example",
            false,
            true
        ));
        assert!(!authorize_fill(
            "https://login.example",
            "https://login.example",
            true,
            false
        ));
    }
}
