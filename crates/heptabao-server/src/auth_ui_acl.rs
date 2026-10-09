//! UI permission metadata uses the same verified actor, current policies and
//! identity substitutions as data authorization. It never grants a capability.
use super::*;

#[derive(Default)]
struct ProjectedRule {
    capabilities: BTreeSet<String>,
    allowed_parameters: acl::ParameterMap,
    denied_parameters: acl::ParameterMap,
    required_parameters: BTreeSet<String>,
    wrapping: acl_wrapping::Bounds,
}

fn merge_parameters(target: &mut acl::ParameterMap, source: &acl::ParameterMap) {
    for (key, values) in source {
        match target.get_mut(key) {
            Some(existing) if existing.is_empty() || values.is_empty() => existing.clear(),
            Some(existing) => existing.extend(values.iter().cloned()),
            None => {
                target.insert(key.clone(), values.clone());
            }
        }
    }
}

impl ProjectedRule {
    fn merge(&mut self, rule: &Rule) {
        self.capabilities.extend(rule.capabilities.iter().cloned());
        merge_parameters(&mut self.allowed_parameters, &rule.allowed_parameters);
        merge_parameters(&mut self.denied_parameters, &rule.denied_parameters);
        self.required_parameters
            .extend(rule.required_parameters.iter().cloned());
        self.wrapping.merge(acl_wrapping::Bounds {
            min: rule.min_wrapping_ttl,
            max: rule.max_wrapping_ttl,
        });
    }

    fn json(self) -> Value {
        let capabilities = if self.capabilities.contains("deny") {
            BTreeSet::from(["deny".to_owned()])
        } else {
            self.capabilities
        };
        json!({
            "capabilities": capabilities,
            "allowed_parameters": self.allowed_parameters,
            "denied_parameters": self.denied_parameters,
            "required_parameters": self.required_parameters,
            "min_wrapping_ttl": self.wrapping.min,
            "max_wrapping_ttl": self.wrapping.max,
        })
    }
}

impl AuthState {
    pub(crate) fn ui_discovery_actor(
        &self,
        principal: &Principal,
        namespace: &str,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        if matches!(principal.admission, PrincipalAdmission::MountMetadata) {
            return Err(denied());
        }
        let token = self.check_principal_observed(principal, namespace, time)?;
        if token.is_wrapping() {
            return Err(denied());
        }
        Ok(())
    }

    fn ui_resultant_acl(
        &self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> Result<AuthResponse, AuthError> {
        if method != "GET" {
            return Err(err(405, "resultant ACL discovery requires GET"));
        }
        if !body.as_object().is_some_and(serde_json::Map::is_empty) {
            return Err(bad("resultant ACL discovery does not accept parameters"));
        }
        let principal = self.permission_observed(principal, namespace, path, "read", time)?;
        self.ui_discovery_actor(principal, namespace, time)?;
        let token = self.check_principal_observed(principal, namespace, time)?;
        if token.is_root() {
            return Ok(response(
                json!({"root":true,"exact_paths":{},"glob_paths":{}}),
                false,
            ));
        }
        let mut rules: BTreeMap<String, ProjectedRule> = BTreeMap::new();
        for name in token.policies().iter().chain(&principal.identity_policies) {
            let policy = self
                .policies
                .get(namespace)
                .and_then(|entries| entries.get(name));
            let policy = match policy {
                Some(policy) => policy,
                None if name == "default" => default_policy::compiled()?,
                None => continue,
            };
            for rule in &policy.rules {
                let Some(rendered) =
                    acl_template::render(&rule.path, &principal.identity_templates)?
                else {
                    continue;
                };
                rules.entry(rendered).or_default().merge(rule);
            }
        }
        let mut exact = serde_json::Map::new();
        let mut glob = serde_json::Map::new();
        for (pattern, rule) in rules {
            let (path, target) = if let Some(prefix) = pattern.strip_suffix('*') {
                (prefix, &mut glob)
            } else if pattern.split('/').any(|part| part == "+") {
                // The UI's projection is advisory; preserve the actual segment
                // wildcard text instead of broadening it to an empty prefix.
                (pattern.as_str(), &mut glob)
            } else {
                (pattern.as_str(), &mut exact)
            };
            let path = if namespace.is_empty() {
                path.to_owned()
            } else {
                format!("{namespace}/{path}")
            };
            target.insert(path, rule.json());
        }
        Ok(response(
            json!({"root":false,"exact_paths":exact,"glob_paths":glob}),
            false,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_and_identical_rule_parameter_merge_follow_existing_acl_semantics() {
        let make = |capabilities: &[&str], values: Vec<Value>, min, max| Rule {
            path: "secret/*".into(),
            capabilities: capabilities.iter().map(|value| (*value).into()).collect(),
            allowed_parameters: BTreeMap::from([("field".into(), values)]),
            denied_parameters: BTreeMap::new(),
            required_parameters: BTreeSet::from(["field".into()]),
            min_wrapping_ttl: min,
            max_wrapping_ttl: max,
        };
        let mut projected = ProjectedRule::default();
        projected.merge(&make(&["read"], vec![json!("a")], 30, 90));
        projected.merge(&make(&["update", "deny"], vec![], 10, 60));
        let projected = projected.json();
        assert_eq!(projected["capabilities"], json!(["deny"]));
        assert_eq!(projected["allowed_parameters"]["field"], json!([]));
        assert_eq!(projected["required_parameters"], json!(["field"]));
        assert_eq!(projected["min_wrapping_ttl"], 10);
        assert_eq!(projected["max_wrapping_ttl"], 60);
    }
}
