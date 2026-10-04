//! Narrow HTTP envelopes for admitted Namespace and Token API replies.
//! Metadata remains the exact producer value pending its owned format.
use super::*;

fn request_id(random: &[u8; 16]) -> String {
    let mut bytes = *random;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut id = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            id.push('-');
        }
        id.push(char::from(HEX[usize::from(byte >> 4)]));
        id.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    id
}

fn selected(path: &str) -> bool {
    path == "sys/namespaces"
        || path.starts_with("sys/namespaces/")
        || matches!(path, "auth/token/create" | "auth/token/create-orphan")
        || path.starts_with("auth/token/create/")
}

pub(super) fn project(reply: &mut snapshot::NativeReply, random: &[u8; 16], path: &str) {
    if !selected(path) {
        return;
    }
    let snapshot::NativeReply::Json(response) = reply else {
        return;
    };
    if response.status != 200 {
        return;
    }
    let Some(body) = response.body.as_object_mut() else {
        return;
    };
    // Selection applies to the admitted outer reply, never a user value inside
    // data. A HELP body has no logical data/auth/wrap_info envelope to project.
    if !["data", "auth", "wrap_info", "warnings"]
        .iter()
        .any(|key| body.contains_key(*key))
    {
        return;
    }
    let wrapped = body.get("wrap_info").is_some_and(|value| !value.is_null());
    body.entry("request_id").or_insert_with(|| {
        json!(if wrapped {
            String::new()
        } else {
            request_id(random)
        })
    });
    for (name, default) in [
        ("lease_id", json!("")),
        ("lease_duration", json!(0)),
        ("renewable", json!(false)),
        ("data", Value::Null),
        ("auth", Value::Null),
        ("warnings", Value::Null),
        ("wrap_info", Value::Null),
    ] {
        body.entry(name).or_insert(default);
    }
    if let Some(auth) = body.get_mut("auth").and_then(Value::as_object_mut) {
        auth.entry("mfa_requirement").or_insert(Value::Null);
        // HTTPAuth has omitempty for these collections. Do not derive metadata
        // nil/empty semantics here: the issuer must own that distinction.
        for name in ["identity_policies", "token_policies"] {
            if auth
                .get(name)
                .is_some_and(|value| value.is_null() || value.as_array().is_some_and(Vec::is_empty))
            {
                auth.remove(name);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_envelope_preserves_actual_owner_data_and_uses_attempt_uuid() {
        let data = json!({"path":"owned/", "uuid":"actual-namespace-uuid",
            "nonce":"actual-runtime-progress", "sealed":true});
        let mut reply = snapshot::NativeReply::Json(Response {
            status: 200,
            consistency_index: None,
            body: json!({"data":data}),
        });
        project(&mut reply, &[0; 16], "sys/namespaces/owned/unseal");
        let snapshot::NativeReply::Json(response) = reply else {
            unreachable!();
        };
        assert_eq!(response.body["data"], data);
        assert_eq!(
            response.body["request_id"],
            "00000000-0000-4000-8000-000000000000"
        );
        assert_eq!(response.body.as_object().map(|body| body.len()), Some(8));
        assert!(response.body["auth"].is_null());
    }

    #[test]
    fn token_envelope_retains_nil_empty_and_public_metadata_without_kv_projection() {
        for metadata in [
            Value::Null,
            json!({}),
            json!({"public_marker":"actual-input"}),
        ] {
            let mut reply = snapshot::NativeReply::Json(Response {
                status: 200,
                consistency_index: None,
                body: json!({"auth":{"metadata":metadata,"policies":["reader"],
                    "token_policies":["reader"],"identity_policies":[],"lease_duration":3600}}),
            });
            project(&mut reply, &[0; 16], "auth/token/create/role");
            let snapshot::NativeReply::Json(response) = reply else {
                unreachable!();
            };
            assert_eq!(response.body["auth"]["metadata"], metadata);
            assert_eq!(response.body["auth"]["token_policies"], json!(["reader"]));
            assert!(response.body["auth"]["mfa_requirement"].is_null());
            assert!(response.body["auth"].get("identity_policies").is_none());
        }
        for path in ["secret/sys/namespaces/value", "secret/auth/token/create"] {
            let body = json!({"data":{"auth":{"metadata":{},"policies":["userdata"]}}});
            let mut reply = snapshot::NativeReply::Json(Response {
                status: 200,
                consistency_index: None,
                body: body.clone(),
            });
            project(&mut reply, &[0; 16], path);
            let snapshot::NativeReply::Json(response) = reply else {
                unreachable!();
            };
            assert_eq!(response.body, body);
        }
    }
}
