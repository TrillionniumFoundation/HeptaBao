//! One pure interpretation of the actual request-local HTTP carriers.
//! Namespace existence/seal/recovery guards remain between the two service phases.
use super::*;

pub(super) struct Envelopes<'a> {
    pub(super) token_fields: Option<crate::http::token_fields::Carrier<'a>>,
    pub(super) pki_role_fields: Option<crate::http::pki_role_fields::Carrier<'a>>,
    pub(super) body: &'a Value,
}
pub(super) fn envelopes<'a>(
    method: &str,
    path: &str,
    body: &'a Value,
) -> Result<Envelopes<'a>, Response> {
    let token_fields = crate::http::token_fields::request(method, path, body)
        .map_err(|message| Response::error(400, message))?;
    let body = token_fields
        .as_ref()
        .map_or(body, |carrier| carrier.original);
    let pki_role_fields = crate::http::pki_role_fields::request(method, path, body)
        .map_err(|message| Response::error(400, message))?;
    let body = pki_role_fields
        .as_ref()
        .map_or(body, |carrier| carrier.original);
    Ok(Envelopes {
        token_fields,
        pki_role_fields,
        body,
    })
}
pub(super) fn kv_root(
    state: Option<&State>,
    namespace: &str,
    method: &str,
    path: &str,
    body: &Value,
) -> Option<String> {
    state.and_then(|state| {
        state.engines.canonical_kv_enumeration_root(
            namespace,
            kv_authorization_method(method, body),
            path,
        )
    })
}
pub(super) fn token_namespace<'a>(path: &str, actor_namespace: Option<&'a str>) -> Option<&'a str> {
    if matches!(
        path,
        "auth/token/lookup-self" | "auth/token/renew-self" | "auth/token/revoke-self"
    ) {
        actor_namespace
    } else {
        None
    }
}
pub(super) struct Operation {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) body: crate::http::ocsp::CarrierBody,
}
pub(super) fn operation(
    state: Option<&State>,
    namespace: &str,
    method: &str,
    path: &str,
    carrier_path: &str,
    body: &Value,
) -> Result<Operation, Response> {
    let owner = state.and_then(|state| state.engines.query_owner(namespace, path));
    let sdk_auth = if crate::http::ocsp::query_request(method, carrier_path, body).is_some() {
        state
            .map(|state| state.auth.sdk_auth_binding(namespace, path))
            .transpose()
            .map_err(|error| Response::error(error.status, &error.message))?
            .flatten()
            .is_some()
    } else {
        false
    };
    operation_with_owner(owner.as_ref(), sdk_auth, method, path, carrier_path, body)
}
pub(super) fn operation_with_owner(
    owner: Option<&crate::engines::MountQueryOwner>,
    sdk_auth: bool,
    method: &str,
    path: &str,
    carrier_path: &str,
    body: &Value,
) -> Result<Operation, Response> {
    let opaque_ocsp_get = crate::http::ocsp::opaque_get_request(method, path, body);
    let mut ordinary_get = None;
    let ocsp_get = if opaque_ocsp_get {
        if let Some((canonical, suffix)) = owner.and_then(|owner| owner.pki_ocsp_get(path)) {
            if matches!(method, "LIST" | "SCAN") {
                return Err(Response::error(405, "unsupported OCSP operation"));
            }
            Some((
                canonical,
                crate::http::ocsp::CarrierBody(crate::http::ocsp::decoded_get_body(&suffix)),
            ))
        } else if valid_path(path) {
            let Some(carrier) = crate::http::ocsp::get_request(method, carrier_path, body) else {
                return Err(Response::error(400, "invalid request-local GET carrier"));
            };
            let actual_kv = owner.is_some_and(|owner| owner.is_kv(path));
            ordinary_get = Some(carrier.ordinary(actual_kv)?);
            None
        } else {
            return Err(Response::error(404, "OCSP mount not found"));
        }
    } else if let Some(carrier) = crate::http::ocsp::query_request(method, carrier_path, body) {
        if !valid_path(path) && !owner.is_some_and(|owner| owner.is_pki_path(path)) {
            return Err(Response::error(404, "opaque header owner not found"));
        }
        let actual_kv = owner.is_some_and(|owner| owner.is_kv(path));
        let actual_ocsp = owner.is_some_and(|owner| owner.is_ocsp(path));
        let actual_sdk_auth = sdk_auth;
        let actual_transit_export =
            method == "GET" && owner.is_some_and(|owner| owner.is_transit_export(path));
        let resolved = if actual_transit_export {
            carrier.resolve_transit_export()
        } else if method == "GET" && owner.is_some_and(|owner| owner.is_transit_byok_export(path)) {
            carrier.resolve_transit_byok_export()
        } else if owner.is_none() && !actual_sdk_auth && carrier.unmounted_byok_query() {
            // No mount is inferred from the spelling. Identity, namespace and
            // ordinary ACL still run, then the actual unmatched route returns404.
            carrier.resolve_transit_byok_export()
        } else {
            carrier.resolve(actual_kv || actual_ocsp || actual_sdk_auth)
        };
        ordinary_get = Some(match resolved {
            Ok((method, body)) => (
                match method {
                    "LIST" => "LIST",
                    "SCAN" => "SCAN",
                    "HEAD" => "HEAD",
                    _ => "GET",
                },
                body,
            ),
            Err(response) => return Err(response),
        });
        None
    } else {
        None
    };
    let method = ordinary_get.as_ref().map_or(method, |(method, _)| *method);
    let path = ocsp_get
        .as_ref()
        .map_or(path, |(canonical, _)| canonical.as_str());
    let body = ocsp_get.as_ref().map_or(body, |(_, body)| &body.0);
    let body = ordinary_get.as_ref().map_or(body, |(_, body)| &body.0);
    let post_body = if let Some(carrier) = crate::http::ocsp::json_post_request(method, path, body)
    {
        let actual_pki_ocsp = owner.is_some_and(|owner| owner.is_ocsp(path));
        {
            let body = carrier.resolve(actual_pki_ocsp)?;
            Some(body)
        }
    } else if let Some(carrier) = crate::http::ocsp::raw_post_request(method, path, body) {
        let actual_pki_ocsp = owner.is_some_and(|owner| owner.is_ocsp(path));
        {
            let body = carrier.resolve(actual_pki_ocsp)?;
            Some(body)
        }
    } else {
        None
    };
    let body = post_body.as_ref().map_or(body, |body| &body.0);
    Ok(Operation {
        method: method.to_owned(),
        path: path.to_owned(),
        body: crate::http::ocsp::CarrierBody(body.clone()),
    })
}
