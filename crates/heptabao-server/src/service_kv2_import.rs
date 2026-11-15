//! Privileged migration route; the ordinary Service transaction is the publisher.
use super::*;

impl Service {
    pub(super) fn kv2_request_timestamp(time: AuthorityTime) -> Result<Timestamp, Response> {
        time.exact()
            .or_else(|| Timestamp::whole(time.seconds()).ok())
            .ok_or_else(|| Response::error(503, "KV2 accepted request clock is unavailable"))
    }

    pub(super) fn kv2_import_route(
        state: &mut State,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        if let Err(error) = state.auth.authorize_sudo_request_observed(
            principal,
            namespace,
            "sys/migration/openbao/kv2",
            "update",
            time,
        ) {
            return Response::error(error.status, &error.message);
        }
        if method != "POST" {
            return Response::error(405, "KV2 migration requires POST");
        }
        let Some(fields) = body.as_object() else {
            return Response::error(400, "KV2 migration requires a JSON object");
        };
        if fields.len() != 2
            || fields
                .keys()
                .any(|key| !matches!(key.as_str(), "mount" | "bundle"))
        {
            return Response::error(400, "unsupported KV2 migration parameter");
        }
        let Some(mount) = fields.get("mount").and_then(Value::as_str) else {
            return Response::error(400, "KV2 migration mount is required");
        };
        let Some(bundle) = fields.get("bundle").filter(|value| value.is_object()) else {
            return Response::error(400, "KV2 migration bundle is required");
        };
        let bytes = match crate::secret_serde::to_vec(bundle, crate::MAX_APPLICATION_STATE_BYTES) {
            Ok(bytes) => bytes,
            Err(_) => return Response::error(507, "KV2 migration bundle exceeds capacity"),
        };
        let mut engines = state.engines.clone();
        match engines.stage_openbao_kv2_import(namespace, mount, &bytes) {
            Ok(mut response) => {
                state.engines = engines;
                Response {
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                    status: response.status,
                    body: std::mem::take(&mut response.body),
                }
            }
            Err(error) => Response::from_engine_error(error),
        }
    }
}
