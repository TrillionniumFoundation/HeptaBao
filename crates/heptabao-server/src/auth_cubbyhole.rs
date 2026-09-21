//! Token-private storage owned by the authenticated, encrypted service state.
//! No caller-supplied token ID, namespace field or mount can select another
//! token's storage. These values never enter token lookup or audit descriptors.

use super::{AuthError, AuthResponse, AuthState, Principal, bad, denied, empty, err, response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

const MAX_ENTRIES: usize = 256;
const MAX_VALUE_BYTES: usize = 256 * 1024;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TokenCubbyhole {
    // Dimensions remain separate, including for a root token using a child
    // namespace. Neither delimiter concatenation nor a raw bearer is a key.
    namespaces: BTreeMap<String, BTreeMap<String, Value>>,
}

impl Drop for TokenCubbyhole {
    fn drop(&mut self) {
        for (mut namespace, entries) in std::mem::take(&mut self.namespaces) {
            namespace.zeroize();
            for (mut path, mut value) in entries {
                path.zeroize();
                super::erase_parsed_json(&mut value);
            }
        }
    }
}

impl TokenCubbyhole {
    fn entries(&self, namespace: &str) -> Option<&BTreeMap<String, Value>> {
        self.namespaces.get(namespace)
    }

    fn len(&self) -> usize {
        self.namespaces.values().map(BTreeMap::len).sum()
    }
}

impl AuthState {
    pub(super) fn cubbyhole_route(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let principal = principal.ok_or_else(denied)?;
        self.check_principal(principal, namespace, now)?;
        let relative = path.strip_prefix("cubbyhole/").unwrap_or("");
        // The outer HTTP parser turns ?list=true into a bounded body field.
        let method = if method == "GET"
            && body
                .get("list")
                .is_some_and(|value| value == true || value == "true")
        {
            "LIST"
        } else {
            method
        };
        // Writes run the backend existence check before ACL classification.
        // OpenBao rejects batch there; reads still pass through the ACL first.
        if principal.service_token().is_none() {
            if matches!(method, "POST" | "PUT") {
                return Err(bad(
                    "cubbyhole operations are only supported by service tokens",
                ));
            }
            let capability = match method {
                "GET" | "HEAD" => "read",
                "LIST" => "list",
                "POST" | "PUT" => "update",
                "DELETE" => "delete",
                _ => return Err(err(405, "method not allowed")),
            };
            let acl_path = if path == "cubbyhole" || method == "LIST" && !path.ends_with('/') {
                format!("{path}/")
            } else {
                path.to_owned()
            };
            self.authorize_request(principal, namespace, &acl_path, capability, now)?;
            return Err(bad(
                "cubbyhole operations are only supported by service tokens",
            ));
        }
        let request_token = principal
            .require_service("cubbyhole operations are only supported by service tokens")?;
        // Only the request-local view may still contain values on a final use.
        // authenticate() already durably clears the live copy at admission.
        let final_use = request_token.uses_remaining == Some(0);
        let view = if final_use {
            &request_token.cubbyhole
        } else {
            &self
                .tokens
                .get(&principal.digest)
                .ok_or_else(denied)?
                .cubbyhole
        };
        let existing = view
            .entries(namespace)
            .and_then(|entries| entries.get(relative));
        let capability = match method {
            "GET" | "HEAD" => "read",
            "LIST" => "list",
            "POST" | "PUT" => {
                if existing.is_some() {
                    "update"
                } else {
                    "create"
                }
            }
            "DELETE" => "delete",
            _ => return Err(err(405, "method not allowed")),
        };
        // OpenBao authorizes LIST against a directory prefix (trailing slash).
        // Other secret paths retain exact bytes. No path selects another token.
        let acl_path = if path == "cubbyhole" || method == "LIST" && !path.ends_with('/') {
            format!("{path}/")
        } else {
            path.to_owned()
        };
        self.authorize_request(principal, namespace, &acl_path, capability, now)?;
        match method {
            "GET" | "HEAD" => {
                super::reject_unknown(body, &[])?;
                if relative.is_empty() {
                    return Err(bad("missing secret path"));
                }
                let value = existing.ok_or_else(|| err(404, "no value found"))?;
                Ok(response(value.clone(), false))
            }
            "LIST" => {
                super::reject_unknown(body, &["list"])?;
                if body
                    .get("list")
                    .is_some_and(|value| value != true && value != "true")
                {
                    return Err(bad("invalid list parameter"));
                }
                let prefix = if relative.is_empty() || relative.ends_with('/') {
                    relative.to_owned()
                } else {
                    format!("{relative}/")
                };
                let mut keys = BTreeSet::new();
                if let Some(entries) = view.entries(namespace) {
                    for name in entries.keys() {
                        if let Some(tail) = name.strip_prefix(&prefix) {
                            if tail.is_empty() {
                                continue;
                            }
                            let key = match tail.find('/') {
                                Some(index) => &tail[..=index],
                                None => tail,
                            };
                            keys.insert(key.to_owned());
                        }
                    }
                }
                if keys.is_empty() {
                    return Err(err(404, "no value found"));
                }
                Ok(response(json!({"keys": keys}), false))
            }
            "POST" | "PUT" => {
                if relative.is_empty() {
                    return Err(bad("missing secret path"));
                }
                if body.as_object().is_none_or(|object| object.is_empty()) {
                    return Err(bad("missing data fields"));
                }
                let bytes = Zeroizing::new(
                    serde_json::to_vec(body).map_err(|_| bad("secret cannot be encoded"))?,
                );
                if bytes.len() > MAX_VALUE_BYTES {
                    return Err(err(413, "secret exceeds size bound"));
                }
                if existing.is_none() && view.len() >= MAX_ENTRIES {
                    return Err(err(507, "token cubbyhole entry capacity exhausted"));
                }
                // A token's final write cannot leave durable, unreachable data.
                if final_use {
                    return Ok(empty(false));
                }
                let entries = self
                    .tokens
                    .get_mut(&principal.digest)
                    .ok_or_else(denied)?
                    .cubbyhole
                    .namespaces
                    .entry(namespace.to_owned())
                    .or_default();
                if let Some(mut old) = entries.insert(relative.to_owned(), body.clone()) {
                    super::erase_parsed_json(&mut old);
                }
                Ok(empty(true))
            }
            "DELETE" => {
                super::reject_unknown(body, &[])?;
                if relative.is_empty() {
                    return Err(bad("missing secret path"));
                }
                if final_use {
                    return Ok(empty(false));
                }
                let token = self.tokens.get_mut(&principal.digest).ok_or_else(denied)?;
                let mut removed = false;
                let mut namespace_empty = false;
                if let Some(entries) = token.cubbyhole.namespaces.get_mut(namespace) {
                    if let Some((mut key, mut value)) = entries.remove_entry(relative) {
                        key.zeroize();
                        super::erase_parsed_json(&mut value);
                        removed = true;
                    }
                    namespace_empty = entries.is_empty();
                }
                if namespace_empty
                    && let Some((mut key, _)) = token.cubbyhole.namespaces.remove_entry(namespace)
                {
                    key.zeroize();
                }
                Ok(empty(removed))
            }
            _ => Err(err(405, "method not allowed")),
        }
    }
}

#[cfg(test)]
#[path = "auth_cubbyhole_tests.rs"]
mod tests;
