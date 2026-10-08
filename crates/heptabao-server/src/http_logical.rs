//! HTTP projection of trusted logical response envelopes. Raw system and PKI
//! replies retain their dedicated transport. This changes no logical authority.
use super::*;

fn request_id(random: &[u8; 16]) -> String {
    crate::crypto::uuid_from_bytes(random)
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
    if let Some(origin) = response.unwrapped_json.as_mut()
        && origin.has_stored_reply()
    {
        // The stored original ID/bytes remain immutable. Only this real final
        // ingress binds the ordinary selected-Data HTTP envelope and its ID.
        if origin
            .bind_selected_http_ingress(&response.body, random)
            .is_err()
        {
            *response = Response::error(503, "selected JSON ingress projection rejected");
        }
        return;
    }
    let Some(original) = response.body.as_object() else {
        return;
    };
    if ["data", "auth", "warnings"]
        .iter()
        .any(|key| original.contains_key(*key))
        && original.get("wrap_info").is_none_or(Value::is_null)
    {
        match crate::auth::logical_envelope(&response.body, &request_id(random), path) {
            Ok(mut envelope) => {
                crate::service::erase_json(&mut response.body);
                response.body = std::mem::take(&mut envelope);
            }
            Err(_) => {
                *response = Response::error(503, "logical envelope projection rejected");
                return;
            }
        }
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
    if !wrapped && body.get("request_id").and_then(Value::as_str) == Some("") {
        body.insert("request_id".into(), json!(request_id(random)));
    }
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
                unwrapped_json: None,
                response_headers: Default::default(),
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
            unwrapped_json: None,
            response_headers: Default::default(),
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
            unwrapped_json: None,
            response_headers: Default::default(),
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
            "00000000-0000-0000-0000-000000000000"
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
            unwrapped_json: None,
            response_headers: Default::default(),
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
            unwrapped_json: None,
            response_headers: Default::default(),
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
            "00000000-0000-0000-0000-000000000000"
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
                unwrapped_json: None,
                response_headers: Default::default(),
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
                unwrapped_json: None,
                response_headers: Default::default(),
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
    #[test]
    fn complete_external_sign_envelope_uses_current_ingress_id_and_keeps_owned_data()
    -> io::Result<()> {
        let data = json!({"certificate":"public-test-certificate",
            "issuer_id":"actual-issuer-identity","serial_number":"aa:bb",
            "request_id":""});
        for (wrapped, prior) in [
            (false, ""),
            (true, ""),
            (false, "11111111-2222-3333-4444-555555555555"),
            (false, "backend-selected-invalid-attempt-id"),
        ] {
            let wrap = if wrapped {
                json!({"token":"test-wrap-token","ttl":10})
            } else {
                Value::Null
            };
            let mut reply = snapshot::NativeReply::Json(Response {
                status: 200,
                unwrapped_json: None,
                response_headers: Default::default(),
                consistency_index: None,
                body: json!({"request_id":prior,"lease_id":"","lease_duration":0,
                    "renewable":false,"data":data,"auth":null,"warnings":null,
                    "wrap_info":wrap}),
            });
            let random = [0x35; 16];
            project(&mut reply, &random, "pki/sign/revoke-global");
            let snapshot::NativeReply::Json(response) = &reply else {
                unreachable!()
            };
            // OpenBao 2.7.0 HTTP logical.go assigns httpResp.RequestID = req.ID.
            // A previous body field cannot mint ordinary HTTP ingress identity.
            // Actual stored unwrap is privately recognized before this projection.
            let expected = if wrapped {
                prior.to_owned()
            } else {
                request_id(&random)
            };
            assert_eq!(response.body["request_id"], expected);
            if !wrapped && !prior.is_empty() {
                assert_ne!(response.body["request_id"], prior);
            }
            assert_eq!(response.body["data"], data);
            assert_eq!(response.body["data"]["request_id"], "");
            assert_eq!(response.body["wrap_info"], wrap);
            assert!(response.body["auth"].is_null());
            assert_eq!(response.body.as_object().map(|v| v.len()), Some(8));
            let mut wire = Vec::new();
            reply.write(&mut wire, false)?;
            let split = wire
                .windows(4)
                .position(|part| part == b"\r\n\r\n")
                .ok_or_else(|| io::Error::other("missing HTTP framing"))?;
            let header = String::from_utf8_lossy(&wire[..split]);
            let declared = header
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(|| io::Error::other("missing Content-Length"))?;
            assert_eq!(declared, wire.len() - split - 4);
        }
        Ok(())
    }
}
