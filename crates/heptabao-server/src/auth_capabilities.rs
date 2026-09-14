//! Read-only inspection is not an execution Principal and cannot be dispatched.
//! The permission evaluator is shared with real request authorization.
use super::*;

pub(crate) struct InspectionTarget {
    pub(crate) entity_id: Option<String>,
    root: bool,
    wrapping: bool,
    policies: BTreeSet<String>,
}

impl InspectionTarget {
    fn from_token(token: &Token) -> Self {
        Self {
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
        if route == "sys/capabilities-self" {
            // The authenticated request owns its final-use view. Inspecting it
            // neither mints a second Principal nor consumes a second token use.
            let token = self.check_principal(actor, namespace, now)?;
            return Ok(InspectionTarget::from_token(token));
        }
        let id = if route == "sys/capabilities" {
            let raw = string_field(body, "token")?;
            if raw.len() > 256 || !raw.starts_with("hvs.") {
                return Err(bad("invalid token"));
            }
            hash(raw)
        } else {
            let accessor = string_field(body, "accessor")?;
            if accessor.is_empty() || accessor.len() > 256 {
                return Err(bad("invalid accessor"));
            }
            let mut matches = self.tokens.iter().filter(|(_, token)| {
                token.accessor == accessor && (token.root || token.namespace == namespace)
            });
            let id = matches
                .next()
                .map(|(id, _)| id.clone())
                .ok_or_else(|| bad("invalid accessor"))?;
            if matches.next().is_some() {
                return Err(bad("ambiguous accessor"));
            }
            id
        };
        // Metadata inspection never decrements the target's finite-use count.
        let token = self
            .active_token(&id, now, true)
            .map_err(|_| bad("invalid inspection target"))?;
        if !token.root && token.namespace != namespace {
            return Err(bad("invalid inspection target"));
        }
        Ok(InspectionTarget::from_token(token))
    }

    pub(crate) fn inspect_capabilities(
        &self,
        namespace: &str,
        path: &str,
        target: &InspectionTarget,
        identity_policies: &BTreeSet<String>,
        identity_disabled: bool,
    ) -> Result<Vec<&'static str>, AuthError> {
        validate_namespace(namespace)?;
        validate_path(path, false)?;
        if identity_disabled {
            return Ok(vec!["deny"]);
        }
        if target.root {
            return Ok(vec!["root"]);
        }
        if target.wrapping {
            return Ok(if path == "sys/wrapping/unwrap" {
                vec!["update"]
            } else {
                vec!["deny"]
            });
        }
        let mut capabilities: Vec<_> = CAPABILITIES
            .iter()
            .copied()
            .filter(|capability| {
                *capability != "deny"
                    && self.policy_allows(
                        namespace,
                        path,
                        capability,
                        &target.policies,
                        identity_policies,
                    )
            })
            .collect();
        capabilities.sort_unstable();
        if capabilities.is_empty() {
            capabilities.push("deny");
        }
        Ok(capabilities)
    }
}
