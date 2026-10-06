//! SDK route metadata is policy, never a Principal. Matching follows the
//! pinned OpenBao 2.7.0 routing router's distinct Root and Login path trees.

/// Validate bounded literal Root metadata. Plus is a literal character here.
pub fn valid_root(patterns: &[String]) -> bool {
    patterns.len() <= 128
        && patterns.iter().map(String::len).sum::<usize>() <= 32 * 1024
        && patterns
            .iter()
            .all(|p| p.len() <= 2048 && !p.chars().any(char::is_control))
}

/// Validate bounded Login expressions using the native router's grammar.
pub fn valid(patterns: &[String]) -> bool {
    valid_root(patterns)
        && patterns.iter().all(|pattern| {
            !pattern.strip_suffix('*').unwrap_or(pattern).contains('*')
                && !pattern.contains("+*")
                && pattern
                    .split('/')
                    .all(|part| !part.contains('+') || part == "+")
        })
}

// Native PathsToRadix inserts duplicate keys in order, and LongestPrefix picks
// one key. A longer exact entry may deliberately shadow a shorter prefix entry.
fn radix_match(patterns: &[String], path: &str, ignore_plus: bool) -> Option<bool> {
    let mut selected: Option<(&str, bool)> = None;
    for pattern in patterns {
        if ignore_plus && pattern.contains('+') {
            continue;
        }
        let prefix = pattern.ends_with('*');
        let key = pattern.strip_suffix('*').unwrap_or(pattern);
        if path.starts_with(key) && selected.is_none_or(|(old, _)| key.len() >= old.len()) {
            selected = Some((key, prefix));
        }
    }
    selected.map(|(key, prefix)| prefix || key == path)
}

/// Root uses only the literal radix tree: suffix star is a prefix marker.
pub fn root_matches(patterns: &[String], path: &str) -> bool {
    radix_match(patterns, path, false).unwrap_or(false)
}

/// Login checks the radix tree first, then its separate segment wildcard set.
pub fn matches(patterns: &[String], path: &str) -> bool {
    if radix_match(patterns, path, true) == Some(true) {
        return true;
    }
    let actual: Vec<_> = path.split('/').collect();
    patterns
        .iter()
        .filter(|pattern| pattern.contains('+'))
        .any(|pattern| {
            let prefix = pattern.ends_with('*');
            let pattern = pattern.strip_suffix('*').unwrap_or(pattern);
            let expected: Vec<_> = pattern.split('/').collect();
            actual.len() >= expected.len()
                && (prefix || actual.len() == expected.len())
                && expected.iter().enumerate().all(|(i, part)| {
                    *part == "+"
                        || *part == actual[i]
                        || prefix && i + 1 == expected.len() && actual[i].starts_with(part)
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sdk_special_path_expressions_follow_literal_root_and_login_radix_priority() {
        assert!(valid(&[
            "login".into(),
            "public/+/*".into(),
            "status*".into()
        ]));
        for bad in ["foo+", "foo/+bar", "foo*bar", "foo/+*", "login\n"] {
            assert!(!valid(&[bad.into()]));
        }
        assert!(valid_root(&["root/+/config".into(), "foo*bar".into()]));
        assert!(!root_matches(
            &["root/+/config".into()],
            "root/alice/config"
        ));
        assert!(root_matches(&["root/+/config".into()], "root/+/config"));
        assert!(matches(&["public/+/*".into()], "public/alice/item"));
        assert!(matches(&["public/+/*".into()], "public//item"));
        let shadow = ["root*".into(), "root-exact".into()];
        assert!(root_matches(&shadow, "root-other"));
        assert!(!root_matches(&shadow, "root-exact-more"));
        assert!(!matches(&shadow, "root-exact-more"));
        assert!(!root_matches(&["a*".into(), "a".into()], "ab"));
        assert!(root_matches(&["a".into(), "a*".into()], "ab"));
        assert!(matches(&["login".into()], "login"));
        assert!(!matches(&["login".into()], "login/extra"));
    }
}
