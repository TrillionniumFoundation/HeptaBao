//! SDK route metadata is policy, never a Principal. Only exact strings,
//! a trailing prefix star and complete plus segments are accepted.

/// Validate bounded SDK path expressions before storing or matching them.
pub fn valid(patterns: &[String]) -> bool {
    patterns.len() <= 128
        && patterns.iter().map(String::len).sum::<usize>() <= 32 * 1024
        && patterns.iter().all(|pattern| {
            pattern.len() <= 2048
                && !pattern.starts_with('/')
                && !pattern.chars().any(char::is_control)
                && !pattern.strip_suffix('*').unwrap_or(pattern).contains('*')
                && pattern
                    .split('/')
                    .all(|part| !part.contains('+') || part == "+")
        })
}

/// Match SDK exact/prefix/one-segment expressions against a relative API path.
pub fn matches(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|pattern| {
        let prefix = pattern.ends_with('*');
        let pattern = if prefix {
            &pattern[..pattern.len() - 1]
        } else {
            pattern.as_str()
        };
        let mut expected = pattern.split('/').peekable();
        let mut actual = path.split('/');
        while let Some(part) = expected.next() {
            let Some(value) = actual.next() else {
                return false;
            };
            if part == "+" {
                if value.is_empty() {
                    return false;
                }
            } else if prefix && expected.peek().is_none() {
                if !value.starts_with(part) {
                    return false;
                }
            } else if part != value {
                return false;
            }
        }
        prefix || actual.next().is_none()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sdk_special_path_expressions_do_not_expand_adjacent_plus_or_interior_star() {
        assert!(valid(&[
            "login".into(),
            "public/+/*".into(),
            "status*".into()
        ]));
        for bad in ["foo+", "foo/+bar", "foo*bar", "/login", "login\n"] {
            assert!(!valid(&[bad.into()]));
        }
        assert!(matches(&["login".into()], "login"));
        assert!(!matches(&["login".into()], "login/extra"));
        assert!(matches(&["public/+/*".into()], "public/alice/item"));
        assert!(!matches(&["public/+/*".into()], "public//item"));
        assert!(matches(&["status*".into()], "status/ready"));
        assert!(!matches(&["status*".into()], "other/status"));
    }
}
