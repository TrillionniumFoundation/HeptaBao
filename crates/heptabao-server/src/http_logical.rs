//! HTTP projection of trusted logical response envelopes. Raw system and PKI
//! replies retain their dedicated transport. This changes no logical authority.
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

pub(super) fn project(reply: &mut snapshot::NativeReply, random: &[u8; 16]) {
    let snapshot::NativeReply::Json(response) = reply else {
        return;
    };
    if response.status != 200 {
        return;
    }
    let Some(body) = response.body.as_object_mut() else {
        return;
    };
    // These are logical envelopes constructed by the admitted backend. User KV
    // values stay inside data; they cannot select this projection or an issuer.
    if !["data", "auth", "wrap_info"]
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
        // HTTPAuth marks these two policy collections omitempty. The request
        // local identity projection and effective grant remain unchanged.
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
    fn logical_wire_projection_keeps_grants_and_raw_transport_distinct() -> io::Result<()> {
        let mut reply = snapshot::NativeReply::Json(Response {
            status: 200,
            consistency_index: None,
            body: json!({"auth":{"client_token":"test-token","policies":["p"],
                "token_policies":["p"],"identity_policies":[],"lease_duration":10}}),
        });
        project(&mut reply, &[0; 16]);
        let snapshot::NativeReply::Json(response) = &reply else {
            unreachable!();
        };
        assert_eq!(
            response.body["request_id"],
            "00000000-0000-4000-8000-000000000000"
        );
        assert_eq!(response.body.as_object().map(|value| value.len()), Some(8));
        assert!(response.body["auth"].get("identity_policies").is_none());
        assert!(response.body["auth"]["mfa_requirement"].is_null());
        assert_eq!(response.body["auth"]["token_policies"], json!(["p"]));
        assert_eq!(response.body["auth"]["lease_duration"], 10);
        let mut wire = Vec::new();
        reply.write(&mut wire, false)?;
        assert!(String::from_utf8_lossy(&wire).contains("test-token"));
        let raw = json!({"initialized":true,"sealed":false});
        let mut reply = snapshot::NativeReply::Json(Response {
            status: 200,
            consistency_index: None,
            body: raw.clone(),
        });
        project(&mut reply, &[0; 16]);
        let snapshot::NativeReply::Json(response) = &reply else {
            unreachable!();
        };
        assert_eq!(response.body, raw);
        Ok(())
    }
}
