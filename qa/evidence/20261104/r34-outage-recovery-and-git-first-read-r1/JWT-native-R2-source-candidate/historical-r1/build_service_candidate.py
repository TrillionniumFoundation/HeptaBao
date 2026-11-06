"""Rebuild the isolated Service SOURCE plumbing. No product execution."""
from pathlib import Path
import json
import re

ROOT=Path(__file__).resolve().parent
def read(name):return (ROOT/'before'/name).read_text()
def write(name,s):(ROOT/'candidate'/name).write_text(s)
def replace(s,old,new,count=1):
    assert s.count(old)==count,(old[:100],s.count(old),count)
    return s.replace(old,new)

s=read('service.rs')
s=replace(s,'            approle_secret_consumption,\n            false,\n',
 '            approle_secret_consumption,\n            false,\n            None,\n')
s=replace(s,'            approle_secret_consumption,\n            true,\n',
 '            approle_secret_consumption,\n            true,\n            native_jwt_lifetime,\n')
start=s.index('    fn dispatch_native_authorized_subrequest(')
end=s.index('        Self::dispatch_authorized_subrequest_inner(', start)
header=s[start:end]
header=replace(header,'    ) -> Response {\n',
 '        native_jwt_lifetime: Option<&mut Option<crate::federated_auth::NativeJwtLifetime>>,\n'
 '    ) -> Response {\n')
s=s[:start]+header+s[end:]
s=replace(s,'        defer_mount_quota_retirement: bool,\n    ) -> Response {',
 '        defer_mount_quota_retirement: bool,\n'
 '        native_jwt_lifetime: Option<&mut Option<crate::federated_auth::NativeJwtLifetime>>,\n'
 '    ) -> Response {\n'
 '        if native_jwt_lifetime.as_deref().is_some_and(Option::is_some) {\n'
 '            return Response::error(503, "native JWT output slot is not fresh");\n'
 '        }')
s=replace(s,'        let auth_result = if path == "sys/quotas/config"',
 '        // Export this request-local witness only after real Identity finalization.\n'
 '        let mut authenticated_jwt_lifetime = None;\n'
 '        let auth_result = if path == "sys/quotas/config"')
old='''            auth.handle_with_connection_clock_for_cluster(
                principal,
                namespace,
                method,
                path,
                auth_body,
                time,
                token_clock,
                client_certificates,
                origin_peer,
                Some(&state.cluster_id),
            )'''
new=old.replace('handle_with_connection_clock_for_cluster(',
 'handle_with_connection_clock_and_native_jwt_lifetime_for_cluster(')
new=new.replace('                Some(&state.cluster_id),\n',
 '                Some(&state.cluster_id),\n'
 '                native_jwt_lifetime.is_some().then_some(&mut authenticated_jwt_lifetime),\n')
s=replace(s,old,new)
old='''                if response.mutated {
                    state.auth = auth;
                    state.engines = engines;
                    state.namespaces = namespaces;
                }
                return Response {'''
new=old.replace('                return Response {','''                if response.status == 200 && let Some(output) = native_jwt_lifetime {
                    *output = authenticated_jwt_lifetime;
                }
                return Response {''')
s=replace(s,old,new)
write('service.rs',s)

s=read('service_native_auth.rs')
s=replace(s,'    Userpass(Box<crate::auth::NativeUserpassOwner>),\n',
 '    Userpass(Box<crate::auth::NativeUserpassOwner>),\n'
 '    Jwt(Box<crate::auth::NativeJwtOwner>),\n')
s=replace(s,'    userpass_reply: Option<[u8; 32]>,\n',
 '    userpass_reply: Option<[u8; 32]>,\n'
 '    jwt_owner: Option<crate::auth::NativeJwtOwner>,\n'
 '    jwt_reply: Option<[u8; 32]>,\n')
s=replace(s,'            || self.userpass_owner.is_some()\n',
 '            || self.userpass_owner.is_some()\n            || self.jwt_owner.is_some()\n',3)
s=replace(s,'            || delivery.userpass_owner.is_some()\n',
 '            || delivery.userpass_owner.is_some()\n            || delivery.jwt_owner.is_some()\n')
s=replace(s,'''        if let Some(owner) = self.batch_issuer_owner.as_ref() {
            owner
                .check_source(auth)''','''        if let Some(owner) = self.jwt_owner.as_ref() {
            owner.check_source(auth)
                .and_then(|()| owner.check_login_lifetime(time))
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        if let Some(owner) = self.batch_issuer_owner.as_ref() {
            owner
                .check_source(auth)''')
s=replace(s,'''        if let Some(owner) = self.batch_issuer_owner.as_ref() {
            owner
                .check_current(auth, time)''','''        if let Some(owner) = self.jwt_owner.as_ref() {
            owner.authorize_reply(auth, self.principal.as_ref(), status, time)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        if let Some(owner) = self.batch_issuer_owner.as_ref() {
            owner
                .check_current(auth, time)''')
old='''                .userpass_owner
                .as_ref()
                .is_some_and(|owner| !owner.permits_empty_actor_retirement())'''
s=replace(s,old,old+'''
            || self.jwt_owner.as_ref()
                .is_some_and(|owner| !owner.permits_empty_actor_retirement())''')
s=replace(s,'                && (status < 300 || self.userpass_owner.is_none())',
 '                && (status < 300 || (self.userpass_owner.is_none() && self.jwt_owner.is_none()))')
s=replace(s,'                Ok(None) => NativeLocalOwner::Auth,','''                Ok(None) => match source.auth.capture_native_v6_jwt_owner(
                    principal.as_ref(), request.namespace, request.method, request.path, request.body,
                ) {
                    Ok(Some(owner)) => NativeLocalOwner::Jwt(Box::new(owner)),
                    Ok(None) => NativeLocalOwner::Auth,
                    Err(error) => return Response::error(error.status, &error.message),
                },''')
# Append a new tuple column. All 13 columns of every original owner are preserved.
start=s.index('        let (\n            mount_owner,',s.index('fn dispatch_native_owner_request_with_pki'))
end=s.index('        if self.pending_native_auth_delivery.is_some()',start)
block=s[start:end]
block=replace(block,'            ssh_owner,\n','            ssh_owner,\n            jwt_owner,\n')
arms=list(re.finditer(r'(            NativeLocalOwner::\w+(?:\(owner\))? => \()(.*?)(            \),)',block,re.S))
assert len(arms)==14,len(arms)
for a in reversed(arms):block=block[:a.end(2)]+'                None,\n'+block[a.end(2):]
pos=block.rindex('        };\n')
block=block[:pos]+'''            NativeLocalOwner::Jwt(owner) => (
                None, None, None, None, None, None, None,
                None, None, None, None, None, None, Some(*owner),
            ),
'''+block[pos:]
s=s[:start]+block+s[end:]
s=replace(s,'                && (userpass_owner.is_some()\n',
 '                && (userpass_owner.is_some()\n                    || jwt_owner.is_some()\n')
s=replace(s,'            userpass_reply: None,\n',
 '            userpass_reply: None,\n            jwt_owner,\n            jwt_reply: None,\n')
s=replace(s,'        let mut consumption = None;\n        let mut response =',
 '        let mut consumption = None;\n'
 '        // One fresh output slot for this request, never a prior login witness.\n'
 '        let mut jwt_lifetime = None;\n        let mut response =')
s=replace(s,'                &mut consumption,\n            )\n        };','''                &mut consumption,
                delivery.jwt_owner.as_ref().is_some_and(|owner| owner.is_login())
                    .then_some(&mut jwt_lifetime),
            )
        };''')
anchor='        if public_login && response.status == 200 {\n'
new='''        if response.status == 200 && delivery.jwt_owner.as_ref().is_some_and(|owner| owner.is_login()) {
            let bound = (|| -> Result<(), Response> {
                let lifetime = jwt_lifetime.take().ok_or_else(rejected)?;
                let time = delivery.time(&delivery.source_auth)?;
                delivery.jwt_owner.as_mut().ok_or_else(rejected)?
                    .bind_successful_login(&delivery.source_auth, &candidate.auth,
                        request.body, &response.body, lifetime, time)
                    .map_err(|error| Response::error(error.status, &error.message))
            })();
            if let Err(error) = bound {
                erase_json(&mut response.body);
                return error;
            }
        }
        if jwt_lifetime.is_some() {
            erase_json(&mut response.body);
            return rejected();
        }
'''
s=replace(s,anchor,new+anchor)
anchor='        // A catalog read cannot acquire a writer merely to normalize schema.\n'
new='''        // Bind JWT status/body before publication: a veto persists no new
        // candidate token, alias or assertion metadata.
        if let Some(owner) = delivery.jwt_owner.as_mut() {
            if owner.is_login() && response.status == 200 && delivery.issued_token.is_none() {
                erase_json(&mut response.body);
                return rejected();
            }
            let bound = owner.bind_response(response.status, &response.body)
                .map_err(|error| Response::error(error.status, &error.message))
                .and_then(|()| transit_reply_digest(response.status, &response.body, deadline));
            match bound {
                Ok(digest) => delivery.jwt_reply = Some(digest),
                Err(error) => {
                    erase_json(&mut response.body);
                    return error;
                }
            }
        }
        #[cfg(test)]
        if delivery.jwt_owner.as_ref().is_some_and(|owner| owner.is_login()) && response.status == 200 {
            jwt_tests::before_actual_jwt_publication();
        }
'''
s=replace(s,anchor,new+anchor)
anchor='            if let Some(owner) = delivery.batch_lifecycle_owner.as_mut() {\n'
s=replace(s,anchor,'''            if let Some(owner) = delivery.jwt_owner.as_ref() {
                owner.admit_candidate(&delivery.source_auth, &candidate.auth)
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
'''+anchor)
s=replace(s,'                } else if delivery.userpass_owner.is_some() {\n                    "userpass"',
 '                } else if delivery.jwt_owner.is_some() {\n                    "jwt-local"\n'
 '                } else if delivery.userpass_owner.is_some() {\n                    "userpass"')
s=replace(s,'            && delivery.userpass_owner.is_none()\n',
 '            && delivery.userpass_owner.is_none()\n            && delivery.jwt_owner.is_none()\n')
anchor='            if let Some(owner) = delivery.response_wrapping_owner.as_ref() {\n                owner\n                    .check_reply(&response)'
new='''            if delivery.jwt_owner.is_some()
                && delivery.jwt_reply != Some(transit_reply_digest(
                    response.status, &response.body, delivery.deadline,
                )?)
            {
                return Err(rejected());
            }
'''
s=replace(s,anchor,new+anchor)
s+='''
#[cfg(test)]
#[path = "service_native_jwt_tests.rs"]
mod jwt_tests;
'''
write('service_native_auth.rs',s)
print(json.dumps({'source_only':True,'updated':['service.rs','service_native_auth.rs'],'runtime_calls':0}))
