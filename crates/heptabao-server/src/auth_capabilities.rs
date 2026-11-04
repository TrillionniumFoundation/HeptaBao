//! Read-only inspection is not an execution Principal and cannot be dispatched.
//! The permission evaluator is shared with real request authorization.
use super::*;

const INVALID_TOKEN: &str = "1 error occurred:\n\t* invalid token\n\n";
const INVALID_ACCESSOR: &str = "1 error occurred:\n\t* invalid accessor\n\n";

#[derive(Eq, PartialEq)]
enum InspectionSubject {
    Service { digest: [u8; 32], accessor: String },
    Batch { digest: [u8; 32] },
}

#[derive(Eq, PartialEq)]
pub(crate) struct InspectionTarget {
    // Read-only identity, not a second execution Principal. Equal policies do
    // not equate different service tokens, accessors or authenticated batches.
    subject: InspectionSubject,
    pub(crate) entity_id: Option<String>,
    root: bool,
    wrapping: bool,
    policies: BTreeSet<String>,
}

/// A single immutable policy observation, separate from inspected credential
/// identity. Advancing a clock must never make credential equality fail or give
/// an already computed capability response a new validity period.
pub(crate) struct InspectionObservation {
    #[cfg(feature = "native-v6-storage")]
    target: InspectionTarget,
    observed_at: AuthorityTime,
    valid_through: Option<policy_expiration::Deadline>,
}

impl InspectionObservation {
    #[cfg(feature = "native-v6-storage")]
    pub(crate) fn target(&self) -> &InspectionTarget {
        &self.target
    }

    pub(crate) fn check_at(&self, time: AuthorityTime) -> Result<(), AuthError> {
        let ordered = match (self.observed_at, time) {
            (AuthorityTime::Precise(before), AuthorityTime::Precise(now)) => now >= before,
            (AuthorityTime::Coarse(before), AuthorityTime::Coarse(now)) => now >= before,
            (AuthorityTime::Coarse(before), AuthorityTime::Precise(now)) => now.seconds() >= before,
            (AuthorityTime::Precise(_), AuthorityTime::Coarse(_)) => false,
        };
        if !ordered
            || self
                .valid_through
                .is_some_and(|deadline| !matches!(deadline.live(time), Ok(true)))
        {
            return Err(err(
                503,
                "capabilities policy observation expired or changed clock",
            ));
        }
        Ok(())
    }
}

impl InspectionTarget {
    pub(super) fn retirement_policies(&self) -> Option<&BTreeSet<String>> {
        if self.root || self.wrapping {
            None
        } else {
            Some(&self.policies)
        }
    }

    fn from_checked(token: &batch_principal::CheckedCredential<'_>, digest: &str) -> Self {
        let digest = crate::crypto::digest(digest.as_bytes());
        let subject = match token {
            batch_principal::CheckedCredential::Service(token) => InspectionSubject::Service {
                digest,
                accessor: token.accessor.clone(),
            },
            batch_principal::CheckedCredential::Batch(_) => InspectionSubject::Batch { digest },
        };
        Self {
            subject,
            entity_id: token.entity_id().map(str::to_owned),
            root: token.is_root(),
            wrapping: token.is_wrapping(),
            policies: token.policies().clone(),
        }
    }
    fn from_token(token: &Token, digest: &str) -> Self {
        Self {
            subject: InspectionSubject::Service {
                digest: crate::crypto::digest(digest.as_bytes()),
                accessor: token.accessor.clone(),
            },
            entity_id: token.entity_id.clone(),
            root: token.root,
            wrapping: token.wrapping.is_some(),
            policies: token.policies.clone(),
        }
    }
}

impl AuthState {
    pub(crate) fn inspection_target(
        &self,
        actor: &Principal,
        namespace: &str,
        route: &str,
        body: &Value,
        now: u64,
    ) -> Result<InspectionTarget, AuthError> {
        self.inspection_target_observed(actor, namespace, route, body, AuthorityTime::Coarse(now))
    }

    pub(crate) fn inspection_target_observed(
        &self,
        actor: &Principal,
        namespace: &str,
        route: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> Result<InspectionTarget, AuthError> {
        let time = actor.request_authority_time(time)?;
        if route == "sys/capabilities-self" {
            // The original actor has already paid its one admission use. Bao
            // 2.7.1 still resolves self as an inspection target: a service token
            // consumed to zero is invalid here (400), without a second charge.
            // Keep actor authorization/CIDRs and its original exact clock; batch
            // targets retain their authenticated claims and parent liveness.
            let token = self.check_principal_observed(actor, namespace, time)?;
            if matches!(&token, batch_principal::CheckedCredential::Service(_)) {
                self.active_token_observed(&actor.digest, time, true)
                    .map_err(|_| bad(INVALID_TOKEN))?;
            }
            return Ok(InspectionTarget::from_checked(&token, &actor.digest));
        }
        let id = if route == "sys/capabilities" {
            let raw = string_field(body, "token")?;
            if raw.starts_with("hvb.") {
                let target = self
                    .inspect_raw_target_observed(raw, namespace, time)
                    .map_err(|_| bad(INVALID_TOKEN))?;
                return Ok(InspectionTarget::from_checked(
                    &target
                        .view_observed(self, time)
                        .map_err(|_| bad(INVALID_TOKEN))?,
                    &hash(raw),
                ));
            }
            if raw.len() > 256 || !raw.starts_with("hvs.") {
                return Err(bad(INVALID_TOKEN));
            }
            hash(raw)
        } else {
            let accessor = string_field(body, "accessor")?;
            if accessor.is_empty() || accessor.len() > 256 {
                return Err(bad(INVALID_ACCESSOR));
            }
            let mut matches = self.tokens.iter().filter(|(_, token)| {
                token.accessor == accessor && (token.root || token.namespace == namespace)
            });
            let id = matches
                .next()
                .map(|(id, _)| id.clone())
                .ok_or_else(|| bad(INVALID_ACCESSOR))?;
            if matches.next().is_some() {
                return Err(bad("ambiguous accessor"));
            }
            id
        };
        // Metadata inspection never decrements the target's finite-use count.
        let invalid_target = if route == "sys/capabilities-accessor" {
            INVALID_ACCESSOR
        } else {
            INVALID_TOKEN
        };
        let token = self
            .active_token_observed(&id, time, true)
            .map_err(|_| bad(invalid_target))?;
        if !token.root && token.namespace != namespace {
            return Err(bad(invalid_target));
        }
        Ok(InspectionTarget::from_token(token, &id))
    }

    pub(crate) fn inspection_template_selectors_observed(
        &self,
        namespace: &str,
        target: &InspectionTarget,
        policies: &BTreeSet<String>,
        time: AuthorityTime,
    ) -> Result<BTreeSet<String>, AuthError> {
        self.policy_template_selectors_observed(namespace, &target.policies, policies, time)
    }

    fn inspection_acl_path<'p>(
        &self,
        namespace: &str,
        path: &'p str,
        target: &InspectionTarget,
        identity_policies: &BTreeSet<String>,
        templates: &IdentityTemplateValues,
        time: AuthorityTime,
    ) -> Result<&'p str, AuthError> {
        // OpenBao ACL.Capabilities uses ListOperation. Leading separators are
        // removed from the full namespace-prefixed path, and an exact rule for
        // a single trailing-slash trim wins only when the original has no exact
        // rule. This adjusts metadata evaluation, never an execution route.
        let path = if namespace.is_empty() {
            path.trim_start_matches('/')
        } else {
            path
        };
        let Some(trimmed) = path.strip_suffix('/') else {
            return Ok(path);
        };
        let mut original_exact = false;
        let mut trimmed_exact = false;
        let mut inspect = |policy: &Policy| -> Result<(), AuthError> {
            if !policy.live(time)? {
                return Ok(());
            }
            for rule in &policy.rules {
                if !rule.live(time)? {
                    continue;
                }
                if let Some(rendered) = policy.render(&rule.path, templates)?
                    && !rendered.ends_with('*')
                    && !rendered.split('/').any(|part| part == "+")
                {
                    original_exact |= rendered == path;
                    trimmed_exact |= rendered == trimmed;
                }
            }
            Ok(())
        };
        for name in target.policies.iter().chain(identity_policies) {
            if let Some(policy) = self
                .policies
                .get(namespace)
                .and_then(|entries| entries.get(name))
            {
                inspect(policy)?;
            } else if name == "default" {
                inspect(default_policy::compiled()?)?;
            }
        }
        Ok(if !original_exact && trimmed_exact {
            trimmed
        } else {
            path
        })
    }

    #[cfg(test)]
    pub(crate) fn inspect_capabilities(
        &self,
        namespace: &str,
        path: &str,
        target: &InspectionTarget,
        identity_policies: &BTreeSet<String>,
        identity_disabled: bool,
        identity_templates: &IdentityTemplateValues,
    ) -> Result<Vec<&'static str>, AuthError> {
        self.inspect_capabilities_observed(
            namespace,
            path,
            target,
            identity_policies,
            identity_disabled,
            identity_templates,
            AuthorityTime::Coarse(0),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn inspect_capabilities_observed(
        &self,
        namespace: &str,
        path: &str,
        target: &InspectionTarget,
        identity_policies: &BTreeSet<String>,
        identity_disabled: bool,
        identity_templates: &IdentityTemplateValues,
        time: AuthorityTime,
    ) -> Result<Vec<&'static str>, AuthError> {
        validate_namespace(namespace)?;
        // Introspection accepts literal query strings even when they are not
        // admissible execution routes. It produces capabilities, never a grant.
        if path.is_empty() {
            return Err(bad("1 error occurred:\n\t* missing path\n\n"));
        }
        if identity_disabled {
            return Ok(vec!["deny"]);
        }
        if target.root {
            return Ok(vec!["root"]);
        }
        if target.wrapping {
            return Ok(if wrapping::allows_token_operation(path, "update") {
                vec!["update"]
            } else {
                vec!["deny"]
            });
        }
        let path = self
            .inspection_acl_path(
                namespace,
                path,
                target,
                identity_policies,
                identity_templates,
                time,
            )
            .map_err(|_| denied())?;
        let mut capabilities = Vec::new();
        for capability in CAPABILITIES
            .iter()
            .copied()
            .filter(|capability| *capability != "deny")
        {
            if self
                .policy_allows_observed(
                    namespace,
                    path,
                    capability,
                    &target.policies,
                    identity_policies,
                    identity_templates,
                    time,
                )
                // Inspecting an invalid target ACL is a denied introspection,
                // distinct from that target's own malformed request (HTTP 400).
                // Do not return a partial capability list or Identity contents.
                .map_err(|_| denied())?
            {
                capabilities.push(capability);
            }
        }
        capabilities.sort_unstable();
        if capabilities.is_empty() {
            capabilities.push("deny");
        }
        Ok(capabilities)
    }
    pub(crate) fn retain_inspection_observation(
        &self,
        namespace: &str,
        target: InspectionTarget,
        identity_policies: &BTreeSet<String>,
        time: AuthorityTime,
    ) -> Result<InspectionObservation, AuthError> {
        let valid_through = if target.root || target.wrapping {
            None
        } else {
            self.inspection_policy_deadline(namespace, &target.policies, identity_policies, time)?
        };
        Ok(InspectionObservation {
            #[cfg(feature = "native-v6-storage")]
            target,
            observed_at: time,
            valid_through,
        })
    }
}
