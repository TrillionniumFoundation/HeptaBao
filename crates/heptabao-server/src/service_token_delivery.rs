//! The original Token API admission survives candidate publication and audit.
use super::*;

pub(super) fn capability(method: &str, path: &str) -> &'static str {
    match path.strip_prefix("auth/token/").unwrap_or_default() {
        "lookup" | "lookup-self" | "lookup-accessor" => "read",
        "accessors" => "list",
        _ => match method {
            "GET" | "HEAD" => "read",
            "LIST" => "list",
            "DELETE" => "delete",
            _ => "update",
        },
    }
}

impl Service {
    pub(super) fn complete_pending_token_api_delivery(
        &mut self,
        expected: bool,
        mut response: Response,
        fingerprint: &str,
    ) -> Response {
        match (expected, self.pending_token_api_authority.take()) {
            (true, Some(authority)) => {
                self.complete_token_api_delivery(authority, response, fingerprint)
            }
            (false, None) => response,
            // A failed external completion may retain its original capsule for
            // erasure. It carries no successful response and must not be reused.
            (false, Some(_)) if response.status >= 300 => response,
            _ => {
                erase_json(&mut response.body);
                response.consistency_index = None;
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
                Response::error(503, "token delivery capsule was lost")
            }
        }
    }

    pub(super) fn complete_token_api_delivery(
        &mut self,
        mut authority: plugin::PluginResponseAuthority,
        mut response: Response,
        fingerprint: &str,
    ) -> Response {
        if response.status >= 300 {
            return response;
        }
        let checked = self
            .validate_plugin_response(&mut authority)
            .and_then(|()| {
                let state = self
                    .state
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "token response state unavailable"))?;
                authority.check_token_api_candidate(state, &state.auth, &self.unseal_nonce)
            });
        if let Err(error) = checked {
            erase_json(&mut response.body);
            response.consistency_index = None;
            if self
                .audit_event(
                    "token-delivery-veto",
                    fingerprint,
                    authority.now(),
                    Some(error.status),
                )
                .is_err()
            {
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(503, "token delivery veto audit failed; recovery required");
            }
            return error;
        }
        response
    }
}

#[cfg(test)]
#[path = "service_token_delivery_tests.rs"]
mod tests;
