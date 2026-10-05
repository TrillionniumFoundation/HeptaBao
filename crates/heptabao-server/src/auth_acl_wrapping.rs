//! Whole-second ACL wrapping bounds are checked before effects and again at
//! late authorization. Request TTL is affine metadata, never a durable grant.
use super::*;

// Largest whole-second positive Go time.Duration; multiplication cannot wrap.
const MAX_DURATION_SECONDS: u64 = 9_223_372_036;

#[derive(Clone, Copy, Default)]
pub(super) struct Bounds {
    pub(super) min: u64,
    pub(super) max: u64,
}

pub(super) fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl Bounds {
    pub(super) fn parse(body: &Value) -> Result<Self, AuthError> {
        let bounds = Self {
            min: duration(body, "min_wrapping_ttl", 0)?,
            max: duration(body, "max_wrapping_ttl", 0)?,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    pub(super) fn validate(self) -> Result<(), AuthError> {
        if self.min > MAX_DURATION_SECONDS || self.max > MAX_DURATION_SECONDS {
            return Err(bad("ACL wrapping duration exceeds supported range"));
        }
        if self.max != 0 && self.min > self.max {
            return Err(bad("minimum wrapping TTL exceeds maximum wrapping TTL"));
        }
        Ok(())
    }

    pub(super) fn merge(&mut self, other: Self) {
        // OpenBao 2.6.2 selects the shortest nonzero bound on both fields when
        // identical winning paths merge. Do not intersect minima as maxima.
        fn nonzero_min(left: u64, right: u64) -> u64 {
            match (left, right) {
                (0, value) | (value, 0) => value,
                _ => left.min(right),
            }
        }
        self.min = nonzero_min(self.min, other.min);
        self.max = nonzero_min(self.max, other.max);
    }

    pub(super) fn allows(self, ttl: Option<u64>) -> bool {
        if self.min == 0 && self.max == 0 {
            return true;
        }
        let Some(ttl) = ttl else {
            return false;
        };
        ttl >= self.min && (self.max == 0 || ttl <= self.max)
    }
}

impl Principal {
    pub(crate) fn bind_request_wrapping_ttl(&mut self, ttl: Option<u64>) {
        self.wrap_ttl_seconds = ttl;
    }
}

impl AuthState {
    pub(crate) fn has_acl_wrapping_ttl_state(&self) -> bool {
        self.policies
            .values()
            .flat_map(|entries| entries.values())
            .flat_map(|policy| &policy.rules)
            .any(|rule| rule.min_wrapping_ttl != 0 || rule.max_wrapping_ttl != 0)
    }

    pub(crate) fn validate_acl_wrapping_ttl_state(&self) -> Result<(), AuthError> {
        for rule in self
            .policies
            .values()
            .flat_map(|entries| entries.values())
            .flat_map(|policy| &policy.rules)
        {
            Bounds {
                min: rule.min_wrapping_ttl,
                max: rule.max_wrapping_ttl,
            }
            .validate()?;
        }
        Ok(())
    }

    pub(super) fn wrapping_policy_allows(
        &self,
        principal: &Principal,
        namespace: &str,
        path: &str,
        policies: &BTreeSet<String>,
    ) -> Result<bool, AuthError> {
        let mut decision = acl::Decision::default();
        for name in policies.iter().chain(&principal.identity_policies) {
            if let Some(policy) = self
                .policies
                .get(namespace)
                .and_then(|entries| entries.get(name))
            {
                for rule in &policy.rules {
                    let Some(rendered) =
                        acl_template::render(&rule.path, &principal.identity_templates)?
                    else {
                        continue;
                    };
                    decision.consider_wrapping(
                        &rendered,
                        Bounds {
                            min: rule.min_wrapping_ttl,
                            max: rule.max_wrapping_ttl,
                        },
                        path,
                    );
                }
            } else if name == "default" {
                for rule in &default_policy::compiled()?.rules {
                    let Some(rendered) =
                        acl_template::render(&rule.path, &principal.identity_templates)?
                    else {
                        continue;
                    };
                    decision.consider_wrapping(
                        &rendered,
                        Bounds {
                            min: rule.min_wrapping_ttl,
                            max: rule.max_wrapping_ttl,
                        },
                        path,
                    );
                }
            }
        }
        Ok(decision.wrapping_allowed(principal.wrap_ttl_seconds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_wrapping_native_bound_union_and_required_wrapper_are_order_independent() {
        for (left, right) in [
            (Bounds { min: 10, max: 30 }, Bounds { min: 40, max: 50 }),
            (Bounds { min: 40, max: 50 }, Bounds { min: 10, max: 30 }),
        ] {
            let mut merged = left;
            merged.merge(right);
            assert!(!merged.allows(None));
            assert!(!merged.allows(Some(0)));
            assert!(!merged.allows(Some(9)));
            assert!(merged.allows(Some(10)));
            assert!(merged.allows(Some(20)));
            assert!(merged.allows(Some(30)));
            assert!(!merged.allows(Some(31)));
        }
        assert!(!Bounds { min: 0, max: 30 }.allows(None));
        assert!(
            Bounds { min: 0, max: 30 }.allows(Some(0)),
            "OpenBao distinguishes an explicit zero header from an absent header"
        );
        assert!(Bounds::default().allows(None));
        let mut conflict = Bounds { min: 40, max: 0 };
        conflict.merge(Bounds { min: 0, max: 30 });
        assert!(!conflict.allows(Some(30)));
        assert!(!conflict.allows(Some(40)));
    }

    #[test]
    fn acl_wrapping_path_priority_does_not_inherit_broad_constraints() {
        let mut decision = acl::Decision::default();
        decision.consider_wrapping("secret/*", Bounds { min: 60, max: 0 }, "secret/item");
        decision.consider_wrapping("secret/item", Bounds { min: 10, max: 30 }, "secret/item");
        assert!(decision.wrapping_allowed(Some(20)));
        decision.consider_wrapping("*", Bounds { min: 90, max: 0 }, "secret/item");
        assert!(decision.wrapping_allowed(Some(20)));
    }

    #[test]
    fn acl_wrapping_policy_hcl_json_and_zero_legacy_serialization_agree() -> Result<(), AuthError> {
        let hcl = parse_policy(&json!(
            r#"path "secret/item" { capabilities=["read"] min_wrapping_ttl=10 max_wrapping_ttl="30s" }"#
        ))?;
        let json = parse_policy(
            &json!({"path":{"secret/item":{"capabilities":["read"],"min_wrapping_ttl":"10s","max_wrapping_ttl":30}}}),
        )?;
        assert_eq!(
            (hcl.rules[0].min_wrapping_ttl, hcl.rules[0].max_wrapping_ttl),
            (10, 30)
        );
        assert_eq!(
            (
                json.rules[0].min_wrapping_ttl,
                json.rules[0].max_wrapping_ttl
            ),
            (10, 30)
        );
        let old = parse_policy(&json!(r#"path "secret/item" { capabilities=["read"] }"#))?;
        let value = serde_json::to_value(&old.rules[0]).map_err(|_| bad("serialization"))?;
        assert!(value.get("min_wrapping_ttl").is_none());
        assert!(value.get("max_wrapping_ttl").is_none());
        for bounds in [
            json!({"min_wrapping_ttl":40,"max_wrapping_ttl":30}),
            json!({"min_wrapping_ttl":-1}),
            json!({"max_wrapping_ttl":"0.5s"}),
            json!({"min_wrapping_ttl":u64::MAX}),
        ] {
            assert!(Bounds::parse(&bounds).is_err());
        }
        Ok(())
    }
}
