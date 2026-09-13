//! Deterministic specificity ordering for the supported OpenBao ACL dialect.
//! Select one highest-priority matching pattern, then union only identical
//! patterns across policies. Deny wins inside that selected union.

use std::cmp::Ordering;

pub(super) const DEFAULT_RULES: &[(&str, &[&str])] = &[
    ("auth/token/lookup-self", &["read"]),
    ("auth/token/renew-self", &["update"]),
    ("auth/token/revoke-self", &["update"]),
    (
        "cubbyhole/*",
        &["create", "read", "update", "delete", "list"],
    ),
];

fn priority(left: &str, right: &str) -> Ordering {
    let first_wildcard = |path: &str| path.find(['+', '*']).unwrap_or(path.len());
    first_wildcard(left)
        .cmp(&first_wildcard(right))
        .then_with(|| right.ends_with('*').cmp(&left.ends_with('*')))
        .then_with(|| {
            right
                .split('/')
                .filter(|part| *part == "+")
                .count()
                .cmp(&left.split('/').filter(|part| *part == "+").count())
        })
        .then_with(|| left.len().cmp(&right.len()))
        .then_with(|| left.cmp(right))
}

#[derive(Default)]
pub(super) struct Decision<'a> {
    pattern: Option<&'a str>,
    allowed: bool,
    denied: bool,
}

impl<'a> Decision<'a> {
    pub(super) fn consider<'b>(
        &mut self,
        pattern: &'a str,
        capabilities: impl Iterator<Item = &'b str>,
        request_path: &str,
        requested: &str,
    ) {
        if !super::path_matches(pattern, request_path) {
            return;
        }
        match self.pattern.map(|old| priority(pattern, old)) {
            Some(Ordering::Less) => return,
            Some(Ordering::Equal) => {}
            None | Some(Ordering::Greater) => {
                self.pattern = Some(pattern);
                self.allowed = false;
                self.denied = false;
            }
        }
        for capability in capabilities {
            self.allowed |= capability == requested;
            self.denied |= capability == "deny";
        }
    }

    pub(super) fn allowed(&self) -> bool {
        self.allowed && !self.denied
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_specificity_applies_all_five_tie_breaks() {
        for (higher, lower) in [
            ("secret/team/*", "secret/+/item"),
            ("secret/+/item", "secret/+/item*"),
            ("secret/*", "secret/+/+/item/*"),
            ("secret/+/item", "secret/+/x"),
            ("secret/+/z", "secret/+/a"),
            ("secret/item", "secret/*"),
        ] {
            assert_eq!(priority(higher, lower), Ordering::Greater);
            assert_eq!(priority(lower, higher), Ordering::Less);
        }
    }

    #[test]
    fn acl_narrow_rule_does_not_inherit_broad_capabilities() {
        for reverse in [false, true] {
            let mut rules = vec![
                ("secret/*", vec!["read", "delete"]),
                ("secret/item", vec!["read"]),
            ];
            if reverse {
                rules.reverse();
            }
            let mut decision = Decision::default();
            for (path, caps) in rules {
                decision.consider(path, caps.into_iter(), "secret/item", "delete");
            }
            assert!(!decision.allowed());
        }
    }

    #[test]
    fn acl_same_pattern_union_and_deny_are_order_independent() {
        let mut decision = Decision::default();
        decision.consider("secret/item", ["read"].into_iter(), "secret/item", "delete");
        decision.consider(
            "secret/item",
            ["delete"].into_iter(),
            "secret/item",
            "delete",
        );
        assert!(decision.allowed());
        decision.consider("secret/item", ["deny"].into_iter(), "secret/item", "delete");
        assert!(!decision.allowed());
        decision.consider(
            "secret/item",
            ["sudo", "delete"].into_iter(),
            "secret/item",
            "delete",
        );
        assert!(!decision.allowed());
    }

    #[test]
    fn acl_only_selected_pattern_can_grant_or_deny() {
        let mut decision = Decision::default();
        decision.consider("secret/*", ["deny"].into_iter(), "secret/item", "read");
        decision.consider("secret/item", ["read"].into_iter(), "secret/item", "read");
        assert!(decision.allowed());
        decision.consider("secret/other", ["deny"].into_iter(), "secret/item", "read");
        assert!(decision.allowed());
        decision.consider("secret/*", ["deny"].into_iter(), "secret/item", "read");
        assert!(decision.allowed());
    }
}
