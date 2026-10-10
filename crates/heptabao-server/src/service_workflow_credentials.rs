//! Native workflow credentials use the original affine logical request entry.
use super::*;

impl Service {
    pub(in crate::service::workflows) fn workflow_credential_dispatch_step(
        &mut self,
        state: &mut State,
        outer: &RequestView<'_>,
        step: &WorkflowStep,
        token: &str,
    ) -> Response {
        let envelopes = match request_normalization::envelopes(&step.method, &step.path, &step.body)
        {
            Ok(value) => value,
            Err(error) => return error,
        };
        let root = request_normalization::kv_root(
            Some(state),
            outer.namespace,
            &step.method,
            &step.path,
            envelopes.body,
        );
        let normalized = match request_normalization::operation(
            Some(state),
            outer.namespace,
            &step.method,
            root.as_deref().unwrap_or(&step.path),
            &step.path,
            envelopes.body,
        ) {
            Ok(value) => value,
            Err(error) => return error,
        };
        let local = state
            .engines
            .ordinary_kv_mount_binding(outer.namespace, &normalized.path)
            .is_some()
            || state.auth.is_native_workflow_login(
                outer.namespace,
                &normalized.method,
                &normalized.path,
            )
            || matches!(
                (normalized.method.as_str(), normalized.path.as_str()),
                (
                    "GET" | "POST" | "PUT",
                    "auth/token/lookup" | "auth/token/lookup-self" | "auth/token/lookup-accessor"
                )
            );
        if !local {
            return Response::error(
                400,
                "workflow credential request requires a supported native owner",
            );
        }
        let _ingress = crate::auth::IngressReplyScope::restore(
            crate::auth::current_ingress().map(|context| context.logical_subrequest()),
        );
        let execution = self.begin_at_mode_started_clock(
            RequestDispatch {
                method: &step.method,
                path: &step.path,
                namespace: outer.namespace,
                token,
                body: step.body.clone(),
                now: outer.now,
                allow_forward: false,
                enforce_namespace: true,
                wrap_ttl_seconds: None,
                origin_peer: outer.origin_peer,
                client_certificates: outer.client_certificates.map(<[Vec<u8>]>::to_vec),
            },
            outer.admission_started,
            outer.token_clock,
        );
        match execution {
            RequestExecution::Complete(response) => {
                if let Some(current) = &self.state {
                    *state = current.clone();
                    state.namespace_protected = current.namespace_protected.clone();
                }
                response
            }
            RequestExecution::External(pending) => {
                // Never execute, forget, or report an uncompleted provider plan.
                // Retain its actual affine owner and fence all later admissions.
                let fingerprint = pending.fingerprint.clone();
                let now = pending.now;
                let clock = pending.token_clock;
                self.pending_workflow_external_hold = Some(pending);
                self.recovery_required = true;
                self.audit_completed_response(
                    &fingerprint,
                    now,
                    clock,
                    Response::error(503, "native workflow request produced an external owner"),
                )
            }
        }
    }
}
