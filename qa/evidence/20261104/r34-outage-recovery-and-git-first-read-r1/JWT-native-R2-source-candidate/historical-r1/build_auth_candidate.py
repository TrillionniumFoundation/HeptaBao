"""Rebuild only isolated SOURCE files from pinned originals; no Rust execution."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parent
def replace(s, old, new, count=1):
    assert s.count(old) == count, (old[:100], s.count(old), count)
    return s.replace(old, new)
def read(name): return (ROOT/'before'/name).read_text()
def write(name, s): (ROOT/'candidate'/name).write_text(s)

s=read('federated_native_jwt.rs')
anchor='fn missing_claim_leeway(value: i64) -> i128 {'
new='''/// Signed time bounds produced by the same successful verifier invocation.
/// It carries no identity, policy, token or publication authority.
pub(crate) struct NativeJwtLifetime {
    issued: i128,
    expiry: i128,
    not_before: i128,
    skew: i128,
    legacy_strict_expiry: bool,
}

impl NativeJwtLifetime {
    pub(crate) fn check_at(&self, now: u64) -> Result<(), AuthError> {
        let now = i128::from(now);
        let expired = if self.legacy_strict_expiry {
            now >= self.expiry
        } else {
            now - self.skew > self.expiry
        };
        if now + self.skew < self.not_before || expired || now + self.skew < self.issued {
            return Err(AuthError::TokenTimeInvalid);
        }
        Ok(())
    }
}

'''
s=replace(s,anchor,new+anchor)
s=replace(s,'''    ) -> Result<NativeJwtIdentity, AuthError> {
        let (mut claims, _) = self.verified_claims(token)?;''','''    ) -> Result<NativeJwtIdentity, AuthError> {
        self.verify_native_with_user_claim_and_lifetime(token, now, time, bounds, user_claim)
            .map(|(identity, _)| identity)
    }

    pub(crate) fn verify_native_with_user_claim_and_lifetime(
        &self,
        token: &str,
        now: u64,
        time: NativeJwtTimePolicy,
        bounds: Option<&NativeJwtBoundClaims>,
        user_claim: &str,
    ) -> Result<(NativeJwtIdentity, NativeJwtLifetime), AuthError> {
        let (mut claims, _) = self.verified_claims(token)?;''')
s=replace(s,'''        let now = i128::from(now);
        let skew = i128::from(time.clock_skew_seconds);
        let expired = if time.legacy_strict_expiry {
            now >= expiry
        } else {
            now - skew > expiry
        };
        if now + skew < not_before || expired || now + skew < issued {
            return Err(AuthError::TokenTimeInvalid);
        }''','''        let lifetime = NativeJwtLifetime {
            issued,
            expiry,
            not_before,
            skew: i128::from(time.clock_skew_seconds),
            legacy_strict_expiry: time.legacy_strict_expiry,
        };
        lifetime.check_at(now)?;''')
s=replace(s,'        Ok(NativeJwtIdentity {','        Ok((NativeJwtIdentity {')
s=replace(s,'            groups,\n        })','            groups,\n        }, lifetime))')
write('federated_native_jwt.rs',s)
write('federated_auth.rs',replace(read('federated_auth.rs'),
 'pub(crate) use native_jwt::NativeJwtTimePolicy;',
 'pub(crate) use native_jwt::{NativeJwtLifetime, NativeJwtTimePolicy};'))

s=read('auth.rs')
start=s.index('    pub(super) fn handle_with_connection_clock_for_cluster(')
body=s.index('        let time = self.token_api_observed_time(time);',start)
header=s[start:body]
wrapper=header+'''        self.handle_with_connection_clock_and_native_jwt_lifetime_for_cluster(
            principal, namespace, method, path, body, time, clock,
            peer_certificates, origin_peer, cluster_id, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
'''
inner=header.replace('handle_with_connection_clock_for_cluster(',
 'handle_with_connection_clock_and_native_jwt_lifetime_for_cluster(')
inner=inner.replace('        cluster_id: Option<&str>,\n',
 '        cluster_id: Option<&str>,\n'
 '        native_jwt_lifetime: Option<&mut Option<crate::federated_auth::NativeJwtLifetime>>,\n')
inner+='''        if native_jwt_lifetime.as_deref().is_some_and(Option::is_some) {
            return Err(err(503, "native JWT output slot is not fresh"));
        }
'''
s=s[:start]+wrapper+inner+s[body:]
s=replace(s,'                "jwt" => self.jwt_route(principal, scope, method, path, body, now),','''                "jwt" => match native_jwt_lifetime {
                    Some(lifetime) => self.jwt_route_with_native_lifetime(
                        principal, scope, method, path, body, now, Some(lifetime),
                    ),
                    None => self.jwt_route(principal, scope, method, path, body, now),
                },''')
start=s.index('    fn jwt_route(\n')
body=s.index('        let AuthScope { namespace, mount } = scope;',start)
header=s[start:body]
wrapper=header+'''        self.jwt_route_with_native_lifetime(principal, scope, method, path, body, now, None)
    }

    #[allow(clippy::too_many_arguments)]
'''
inner=header.replace('fn jwt_route(', 'fn jwt_route_with_native_lifetime(')
inner=inner.replace('        now: u64,\n', '        now: u64,\n'
 '        native_lifetime: Option<&mut Option<crate::federated_auth::NativeJwtLifetime>>,\n')
s=s[:start]+wrapper+inner+s[body:]
s=replace(s,'''            let verified = verification_config
                .verifier()?
                .verify_native_with_user_claim(
                    jwt,
                    now,
                    jwt_login::native_time_policy(&config, &role),
                    role.bound_claims.as_ref(),
                    role.user_claim.as_deref().unwrap_or("sub"),
                )
                .map_err(|_| bad("JWT signature or claims validation failed"))?;''','''            let verifier = verification_config.verifier()?;
            let time_policy = jwt_login::native_time_policy(&config, &role);
            let user_claim = role.user_claim.as_deref().unwrap_or("sub");
            let (verified, lifetime) = if native_lifetime.is_some() {
                verifier.verify_native_with_user_claim_and_lifetime(
                    jwt, now, time_policy, role.bound_claims.as_ref(), user_claim,
                ).map(|(identity, lifetime)| (identity, Some(lifetime)))
            } else {
                verifier.verify_native_with_user_claim(
                    jwt, now, time_policy, role.bound_claims.as_ref(), user_claim,
                ).map(|identity| (identity, None))
            }.map_err(|_| bad("JWT signature or claims validation failed"))?;''')
s=replace(s,'''            self.jwt_at_mut(scope)
                .identities
                .insert(identity_key, identity);
            return Ok(response);''','''            self.jwt_at_mut(scope)
                .identities
                .insert(identity_key, identity);
            if let Some(output) = native_lifetime {
                *output = lifetime;
            }
            return Ok(response);''')
anchor='pub(crate) use native_userpass::NativeUserpassOwner;\n'
s=replace(s,anchor,anchor+'''
#[cfg(feature = "native-v6-storage")]
#[path = "auth_native_jwt.rs"]
mod native_jwt;
#[cfg(feature = "native-v6-storage")]
pub(crate) use native_jwt::NativeJwtOwner;
''')
write('auth.rs',s)

s=read('auth_native_v6_routes.rs')
s=replace(s,'            && self.jwt_mounts.values().all(BTreeMap::is_empty)',
 '            && self.native_v6_jwt_state_supported()')
s=replace(s,'                            "token" | "approle" | "cert" | "userpass"',
 '                            "token" | "approle" | "cert" | "userpass" | "jwt"')
s=replace(s,'                            Some(TokenAuthProvenance::Userpass { .. })\n',
 '                            Some(TokenAuthProvenance::Userpass { .. })\n'
 '                                | Some(TokenAuthProvenance::Jwt { .. })\n')
s=replace(s,'                            | Some(TokenAuthProvenance::Userpass { .. })\n',
 '                            | Some(TokenAuthProvenance::Userpass { .. })\n'
 '                            | Some(TokenAuthProvenance::Jwt { .. })\n')
anchor='''        if self.native_v6_userpass_route(namespace, method, path, body) {
            return true;
        }'''
s=replace(s,anchor,anchor+'''
        if self.native_v6_jwt_route(namespace, method, path, body) {
            return true;
        }''')
write('auth_native_v6_routes.rs',s)
# Keep this existing negative about unsupported providers, not an obsolete
# assertion that the newly implemented local JWT provider is unsupported.
write('service_native_userpass_tests.rs', replace(read('service_native_userpass_tests.rs'),
 '("sys/auth/other", json!({"type":"jwt"}))',
 '("sys/auth/other", json!({"type":"oidc"}))'))
print(json.dumps({'source_only':True,'updated':['auth.rs','auth_native_v6_routes.rs',
 'federated_auth.rs','federated_native_jwt.rs','service_native_userpass_tests.rs'],
 'runtime_calls':0}))
