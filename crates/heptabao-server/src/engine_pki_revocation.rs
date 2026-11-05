//! Global precise revocation floor and retained public records survive mount
//! retirement. Admission still owns the original Actor and request clock.
use super::*;
use crate::auth::{AuthorityTime, Timestamp};
impl EngineState {
    pub(crate) fn has_ordinary_pki_revocation_state(&self) -> bool {
        self.pki_revocation_clock.is_some() || self.namespaces.values().any(|ns|
            ns.mounts.values().any(|mount| matches!(&mount.backend,Backend::Pki(pki) if pki.ordinary_revocation_floor().is_some())))
    }
    pub(crate) fn validate_pki_revocation_clock(&self, previous: Option<&Self>) -> Result<()> {
        if previous
            .and_then(|old| old.pki_revocation_clock)
            .is_some_and(|floor| self.pki_revocation_clock.is_none_or(|at| at < floor))
        {
            return Err(error(
                503,
                "PKI revocation clock was removed or rolled back",
            ));
        }
        for (namespace, ns) in &self.namespaces {
            for (path, mount) in &ns.mounts {
                let Backend::Pki(pki) = &mount.backend else {
                    continue;
                };
                if pki
                    .ordinary_revocation_floor()
                    .is_some_and(|at| self.pki_revocation_clock.is_none_or(|floor| floor < at))
                {
                    return Err(error(
                        503,
                        "PKI revocation clock does not cover retained records",
                    ));
                }
                if let Some(old) = previous
                    .and_then(|old| old.namespaces.get(namespace))
                    .and_then(|ns| ns.mounts.get(path))
                    && old.incarnation == mount.incarnation
                    && let Backend::Pki(old) = &old.backend
                {
                    pki.validate_ordinary_revocation_successor(old)?;
                }
            }
        }
        Ok(())
    }
    pub(super) fn with_pki_revocation_floor<'a>(
        &self,
        context: PkiRequestContext<'a>,
    ) -> Result<PkiRequestContext<'a>> {
        let Some(floor) = self.pki_revocation_clock else {
            return Ok(context);
        };
        let time = context.observed_time(self.lease_clock)?;
        let at = time
            .exact()
            .or_else(|| Timestamp::whole(time.seconds()).ok())
            .ok_or_else(|| error(503, "trusted PKI revocation clock unavailable"))?
            .max(floor);
        Ok(PkiRequestContext {
            time: AuthorityTime::Precise(at),
            clock: context.clock.map(|clock| clock.with_timestamp_floor(at)),
            ..context
        })
    }
}
