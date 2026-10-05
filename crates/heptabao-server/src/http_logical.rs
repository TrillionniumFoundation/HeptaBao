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

fn inject_system_data(path: &str) -> bool {
    // Match the pinned HTTP router's explicitly registered injector routes.
    // Ordinary sys logical routes use the standard envelope.
    [
        "sys/audit",
        "sys/audit/",
        "sys/audit-hash/",
        "sys/auth",
        "sys/auth/",
        "sys/config/cors",
        "sys/config/auditing/request-headers/",
        "sys/config/auditing/request-headers",
        "sys/capabilities",
        "sys/capabilities-accessor",
        "sys/capabilities-self",
        "sys/ha-status",
        "sys/key-status",
        "sys/mounts",
        "sys/mounts/",
        "sys/policy",
        "sys/policy/",
        "sys/rekey/backup",
        "sys/rekey/recovery-key-backup",
        "sys/rotate/root/backup",
        "sys/rotate/recovery/backup",
        "sys/remount",
        "sys/rotate",
        "sys/rotate/keyring",
        "sys/wrapping/wrap",
    ]
    .iter()
    .any(|route| {
        if route.ends_with('/') {
            path.starts_with(route)
        } else {
            path == *route
        }
    })
}

pub(super) fn project(reply: &mut snapshot::NativeReply, random: &[u8; 16], path: &str) {
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
        // The credential issuer owns nil versus allocated-empty metadata.
        auth.entry("metadata").or_insert(Value::Null);
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
    if matches!(
        path,
        "auth/token/lookup" | "auth/token/lookup-self" | "auth/token/lookup-accessor"
    ) && let Some(data) = body.get_mut("data").and_then(Value::as_object_mut)
    {
        // These values come from the admitted credential owner. This wire
        // projection cannot add a token, namespace capability or lease.
        data.remove("namespace");
        data.remove("expire_time_unix");
        data.entry("meta").or_insert(Value::Null);
        if !data.contains_key("issue_time")
            && let Some(created) = data.get("creation_time").and_then(Value::as_u64)
        {
            data.insert(
                "issue_time".into(),
                json!(crate::engines::timestamp(created)),
            );
        }
        if data.contains_key("identity_policies") {
            data.entry("external_namespace_policies")
                .or_insert_with(|| json!({}));
        }
    }
    if path.ends_with("/tune")
        && (path.starts_with("sys/mounts/") || path.starts_with("sys/auth/"))
        && let Some(data) = body.get_mut("data").and_then(Value::as_object_mut)
    {
        for field in ["revision", "incarnation", "accessor"] {
            data.remove(field);
        }
    }
    if path == "sys/mounts"
        && let Some(data) = body.get_mut("data").and_then(Value::as_object_mut)
    {
        for mount in data.values_mut().filter_map(Value::as_object_mut) {
            mount.remove("revision");
            mount.remove("incarnation");
        }
    }
    if inject_system_data(path)
        && let Some(data) = body.get("data").and_then(Value::as_object).cloned()
    {
        for (key, value) in data {
            // Go writes data keys first and the HTTP envelope last. For a
            // duplicate key, decoding keeps the envelope's value.
            body.entry(key).or_insert(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tune_wire_projection_retains_config_and_keeps_user_values_outside_control_routes() {
        let data = json!({"default_lease_ttl":2764800,"force_no_cache":false,
            "revision":7,"incarnation":3,"accessor":"native-owner-control"});
        for path in ["sys/mounts/probe/tune", "sys/auth/token/tune"] {
            let mut reply = snapshot::NativeReply::Json(Response {
                status: 200,
                consistency_index: None,
                body: json!({"data":data}),
            });
            project(&mut reply, &[0; 16], path);
            let snapshot::NativeReply::Json(response) = reply else {
                unreachable!()
            };
            assert_eq!(response.body["data"]["default_lease_ttl"], 2764800);
            assert_eq!(response.body["default_lease_ttl"], 2764800);
            for field in ["revision", "incarnation", "accessor"] {
                assert!(response.body["data"].get(field).is_none());
                assert!(response.body.get(field).is_none());
            }
        }
        let mut reply = snapshot::NativeReply::Json(Response {
            status: 200,
            consistency_index: None,
            body: json!({"data":data}),
        });
        project(&mut reply, &[0; 16], "records/value");
        let snapshot::NativeReply::Json(response) = reply else {
            unreachable!()
        };
        assert_eq!(response.body["data"], data);
    }
    #[test]
    fn logical_wire_projection_keeps_grants_and_raw_transport_distinct() -> io::Result<()> {
        let mut reply = snapshot::NativeReply::Json(Response {
            status: 200,
            consistency_index: None,
            body: json!({"auth":{"client_token":"test-token","policies":["p"],
                "token_policies":["p"],"identity_policies":[],"lease_duration":10}}),
        });
        project(&mut reply, &[0; 16], "auth/token/create");
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
        project(&mut reply, &[0; 16], "sys/health");
        let snapshot::NativeReply::Json(response) = &reply else {
            unreachable!();
        };
        assert_eq!(response.body, raw);
        Ok(())
    }

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
            assert_eq!(response.body["data"], body["data"]);
            assert!(response.body["auth"].is_null());
        }
    }
}
