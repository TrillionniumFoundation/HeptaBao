//! Affine custody of the existing native SSH public-key HTTP projection.
//! This binds an actual mount-produced response; it never manufactures raw
//! bytes, an ingress, a bearer or a response-wrapping token.
use super::*;
use crate::v6_native_custody::OriginalDeadline;

fn unavailable() -> AuthError {
    err(503, "native SSH public-key response ownership changed")
}

fn digest(
    response: &UnwrappedJson,
    logical: &Value,
    nonce: [u8; 32],
    deadline: OriginalDeadline,
) -> Result<[u8; 32], AuthError> {
    deadline.check().map_err(|_| unavailable())?;
    if response.state.native_owner != Some(nonce)
        || response.state.workflow_output_failure.is_some()
        || response.state.static_kv1_lease.is_some()
        || response.raw_http_transport(logical)? != Some((200, "text/plain"))
    {
        return Err(unavailable());
    }
    // Audit may attach its actual selected ingress to the same private object.
    // That is not permission to substitute another stored projection.
    response.framing_wire(logical)?;
    let stored = response.stored_reply().ok_or_else(unavailable)?;
    let bytes = crate::secret_serde::to_vec(
        &(nonce, logical, stored),
        crate::MAX_APPLICATION_STATE_BYTES,
    )
    .map_err(|_| unavailable())?;
    let result = crate::crypto::digest(&bytes);
    deadline.check().map_err(|_| unavailable())?;
    Ok(result)
}

pub(crate) struct NativeSshPublicReplyOwner {
    nonce: [u8; 32],
    projection: [u8; 32],
    deadline: OriginalDeadline,
}
impl NativeSshPublicReplyOwner {
    pub(crate) fn check(&self, response: &UnwrappedJson, logical: &Value) -> Result<(), AuthError> {
        if digest(response, logical, self.nonce, self.deadline)? != self.projection {
            return Err(unavailable());
        }
        Ok(())
    }
}

impl UnwrappedJson {
    pub(crate) fn bind_native_ssh_public_reply(
        &mut self,
        logical: &Value,
        deadline: OriginalDeadline,
    ) -> Result<NativeSshPublicReplyOwner, AuthError> {
        deadline.check().map_err(|_| unavailable())?;
        if self.state.native_owner.is_some() {
            return Err(unavailable());
        }
        let nonce = crate::crypto::random::<32>().map_err(|_| unavailable())?;
        self.state.native_owner = Some(nonce);
        Ok(NativeSshPublicReplyOwner {
            nonce,
            projection: digest(self, logical, nonce, deadline)?,
            deadline,
        })
    }
}
