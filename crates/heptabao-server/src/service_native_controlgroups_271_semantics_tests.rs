//! Native File CG: canonical self authorization, raw KV side effects and cold claims.
use super::*;

#[test]
fn native_cg271_self_authorization_matrix_and_spent_claim_survive_cold() -> TestResult {
    for global in [None, Some(false), Some(true)] {
        for nested in [None, Some(false), Some(true)] {
            let mut f = setup_native(true)?;
            let global_text = global.map_or_else(String::new, |v| format!("self_auth_allowed={v}"));
            let nested_text =
                nested.map_or_else(String::new, |v| format!("self_authorization={v}"));
            let policy = format!(
                r#"path "secret/data/cg/*" {{
                capabilities=["create","update","read"]
                control_group={{ttl="600s" {global_text}
                    factor "review" {{controlled_capabilities=["create","update"]
                        identity {{group_names=["cg-team"] approvals=1 {nested_text} }}
                    }}
                }}
                }}
                path "sys/control-group/request" {{capabilities=["update"]}}
                path "sys/control-group/authorize" {{capabilities=["update"]}}"#
            );
            assert_eq!(
                f.request(
                    Actor::Admin,
                    "PUT",
                    "sys/policies/acl/cg-requester",
                    json!({"policy":policy})
                )?
                .status,
                204
            );
            // No CAS option: a duplicate execution would create another version.
            let deferred = f.request(
                Actor::Requester,
                "POST",
                "secret/data/cg/key",
                json!({"data":{"value":"after"}}),
            )?;
            assert_eq!(deferred.status, 200);
            let raw = Zeroizing::new(text(&deferred.body, "/wrap_info/token")?);
            let accessor = text(&deferred.body, "/wrap_info/accessor")?;
            let own = f.request(
                Actor::Requester,
                "POST",
                "sys/control-group/authorize",
                json!({"accessor":accessor}),
            )?;
            let allowed = global.unwrap_or(false);
            assert_eq!(own.status, if allowed { 200 } else { 500 });
            if allowed {
                assert_eq!(own.body["data"]["approved"], true);
            } else {
                assert!(own.body["data"].is_null());
            }
            let review = f.request(
                Actor::First,
                "POST",
                "sys/control-group/request",
                json!({"accessor":accessor}),
            )?;
            assert_eq!(review.status, 200);
            assert_eq!(review.body["data"]["approved"], allowed);
            assert_eq!(
                review.body["data"]["authorizations"]
                    .as_array()
                    .map(Vec::len),
                Some(usize::from(allowed))
            );
            assert_eq!(
                f.request(Actor::Admin, "GET", "secret/metadata/cg/key", json!({}))?
                    .status,
                404,
                "approval cannot execute the request"
            );
            if !allowed {
                let other = f.request(
                    Actor::First,
                    "POST",
                    "sys/control-group/authorize",
                    json!({"accessor":accessor}),
                )?;
                assert_eq!(other.status, 200);
                assert_eq!(other.body["data"]["approved"], true);
            }
            assert_eq!(f.unwrap(&raw)?.status, 200);
            f.assert_value(1, "after")?;
            assert_eq!(f.unwrap(&raw)?.status, 400);
            f.assert_value(1, "after")?;
            let mut f = f.restart()?;
            assert_eq!(f.unwrap(&raw)?.status, 400);
            f.assert_value(1, "after")?;
        }
    }
    Ok(())
}
