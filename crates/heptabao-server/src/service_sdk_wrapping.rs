//! Request-owned wrapping metadata, retained across the unlocked SDK callback.
//! It contains neither a Principal nor permission to bypass callback publication.
use super::*;

pub(super) struct Owner {
    path: String,
    ttl: u64,
    ingress: Option<crate::auth::IngressReplyContext>,
}
impl Owner {
    pub(super) fn capture(request: &RequestView<'_>) -> Result<Option<Self>, Response> {
        let Some(ttl) = request.wrap_ttl_seconds.filter(|ttl| *ttl > 0) else {
            return Ok(None);
        };
        crate::auth::validate_sdk_wrap_ttl(ttl)
            .map_err(|error| Response::error(error.status, &error.message))?;
        Ok(Some(Self {
            path: request.path.into(),
            ttl,
            ingress: crate::auth::current_ingress(),
        }))
    }
    pub(super) fn apply(
        &self,
        auth: &mut AuthState,
        namespace: &str,
        body: &Value,
        at: Timestamp,
    ) -> Result<Value, Response> {
        let mut wrapped = auth
            .wrap_sdk_response(
                namespace,
                &self.path,
                self.ttl,
                body,
                at.seconds(),
                self.ingress.as_ref(),
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
        auth.mark_sdk_advanced_state();
        Ok(std::mem::take(&mut wrapped.body))
    }
    pub(super) fn check_delivery<'a>(
        &self,
        auth: &'a AuthState,
        namespace: &str,
        response: &Response,
        time: AuthorityTime,
    ) -> Result<Option<&'a str>, Response> {
        if response.status != 200 {
            return Ok(None);
        }
        let raw = response.body["wrap_info"]["token"]
            .as_str()
            .ok_or_else(|| Response::error(503, "SDK native wrapper delivery owner missing"))?;
        auth.sdk_wrapped_auth_token(raw, namespace, &self.path, time)
            .map_err(|error| Response::error(error.status, &error.message))
    }
}
