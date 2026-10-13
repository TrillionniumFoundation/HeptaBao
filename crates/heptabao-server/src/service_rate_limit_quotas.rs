//! Node-local OpenBao 2.7.1 memorystore semantics for the bounded native slice.
use super::*;
use crate::auth::rate_limit_quotas::{Definition, Registry};
use std::net::IpAddr;
const MAX_CLIENTS: usize = 8192;
#[derive(Default)]
pub(super) struct Runtime {
    buckets: BTreeMap<(String, u64, IpAddr), Bucket>,
    sweep: BTreeMap<(String, u64), (Instant, u64)>,
    owner: Option<Arc<()>>,
}
struct Limiter {
    start: Instant,
    last_tick: u64,
    remaining: u64,
}
struct Bucket {
    limiter: Option<Limiter>,
    blocked_until: Option<Instant>,
}
struct Rejected {
    retry_after: u64,
}
impl Runtime {
    fn purge_at(&mut self, definition: &Definition, now: Instant) {
        let sweep = self
            .sweep
            .entry((definition.name.clone(), definition.revision))
            .or_insert((now, 0));
        let tick = now.saturating_duration_since(sweep.0).as_secs() / 60;
        if tick <= sweep.1 {
            return;
        }
        sweep.1 = tick;
        let swept_at = sweep.0 + Duration::from_secs(tick * 60);
        self.buckets.retain(|(name, revision, _), bucket| {
            if name != &definition.name || *revision != definition.revision {
                return true;
            }
            if bucket.limiter.as_ref().is_some_and(|b| {
                let last_time = b.start + Duration::from_secs(b.last_tick * definition.interval);
                swept_at.saturating_duration_since(last_time) > Duration::from_secs(180)
            }) {
                bucket.limiter = None;
            }
            bucket.limiter.is_some() || bucket.blocked_until.is_some_and(|until| swept_at < until)
        });
    }
    fn take_at(
        &mut self,
        definition: &Definition,
        peer: IpAddr,
        now: Instant,
    ) -> Result<Option<Rejected>, ()> {
        self.purge_at(definition, now);
        self.buckets.retain(|(name, revision, _), _| {
            name != &definition.name || *revision == definition.revision
        });
        let key = (definition.name.clone(), definition.revision, peer);
        if !self.buckets.contains_key(&key) && self.buckets.len() >= MAX_CLIENTS {
            return Err(());
        }
        let bucket = self.buckets.entry(key).or_insert(Bucket {
            limiter: None,
            blocked_until: None,
        });
        // Blocked clients are an independent clock/owner, as in upstream. An
        // idle limiter sweep cannot shorten a configured block interval.
        if let Some(until) = bucket.blocked_until {
            if now < until {
                return Ok(Some(Rejected {
                    retry_after: until.saturating_duration_since(now).as_secs(),
                }));
            }
            bucket.blocked_until = None;
        }
        let limiter = bucket.limiter.get_or_insert_with(|| Limiter {
            start: now,
            last_tick: 0,
            remaining: definition.tokens(),
        });
        let elapsed = now.saturating_duration_since(limiter.start);
        let tick = elapsed.as_secs() / definition.interval;
        if tick > limiter.last_tick {
            limiter.last_tick = tick;
            limiter.remaining = definition.tokens();
        }
        if limiter.remaining > 0 {
            limiter.remaining -= 1;
            return Ok(None);
        }
        let retry_after = if definition.block_interval > 0 {
            let until = now
                .checked_add(Duration::from_secs(definition.block_interval))
                .ok_or(())?;
            bucket.blocked_until = Some(until);
            definition.block_interval.saturating_sub(1)
        } else {
            let next = Duration::from_secs((tick + 1).checked_mul(definition.interval).ok_or(())?);
            next.saturating_sub(elapsed).as_secs()
        };
        Ok(Some(Rejected { retry_after }))
    }
    fn synchronize(&mut self, registry: &Registry) {
        if self
            .owner
            .as_ref()
            .is_none_or(|owner| !Arc::ptr_eq(owner, &registry.runtime_owner))
        {
            self.buckets.clear();
            self.sweep.clear();
            self.owner = Some(registry.runtime_owner.clone());
        }
        self.buckets.retain(|(name, revision, _), _| {
            registry
                .definitions
                .get(name)
                .is_some_and(|d| d.revision == *revision)
        });
        self.sweep.retain(|(name, revision), _| {
            registry
                .definitions
                .get(name)
                .is_some_and(|d| d.revision == *revision)
        });
    }
}
impl Service {
    pub(super) fn rate_limit_quota_response(
        &mut self,
        request: &RequestView<'_>,
    ) -> Option<Response> {
        let state = self.state.as_ref()?;
        let registry = state.auth.rate_limit_quota_registry()?;
        self.rate_limit_quotas.synchronize(registry);
        if registry.definitions.is_empty() || registry.config.exempt(request.path) {
            return None;
        }
        let (mount, role) = match state.auth.rate_limit_approle_scope(
            request.namespace,
            request.method,
            request.path,
            request.body,
        ) {
            Ok(Some(scope)) => scope,
            Ok(None) => return None,
            Err(e) => return Some(Response::error(e.status, &e.message)),
        };
        let selected = registry
            .definitions
            .values()
            .find(|d| !role.is_empty() && d.path == mount && d.role == role)
            .or_else(|| {
                registry
                    .definitions
                    .values()
                    .find(|d| d.role.is_empty() && d.path == request.path)
            })
            .or_else(|| {
                registry
                    .definitions
                    .values()
                    .find(|d| d.role.is_empty() && d.path == mount)
            });
        let definition = selected?;
        // A forwarded-only active counter would claim the wrong per-node
        // semantics. Until ingress-node quota admission is implemented, refuse
        // this bounded profile on HA rather than silently moving the bucket.
        if self.ha.is_some() {
            return Some(Response::error(
                503,
                "rate limit quota ingress admission is not supported on HA",
            ));
        }
        let Some(peer) = request.origin_peer else {
            return Some(Response::error(
                503,
                "rate limit quota requires an observed transport peer",
            ));
        };
        match self
            .rate_limit_quotas
            .take_at(definition, peer, Instant::now())
        {
            Ok(None) => None,
            Ok(Some(rejected)) => {
                let mut response = Response::error(429, "rate limit quota exceeded");
                response.response_headers = ResponseHeaders::from_sdk(
                    Some(&json!({"Retry-After":[rejected.retry_after.to_string()]})),
                    &["Retry-After".into()],
                )
                .unwrap_or_default();
                Some(response)
            }
            Err(()) => Some(Response::error(
                503,
                "rate limit quota client capacity exhausted",
            )),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn definition(rate: f64, interval: u64, block: u64) -> Definition {
        Definition {
            name: "quota".into(),
            path: "auth/approle/".into(),
            role: "".into(),
            rate,
            interval,
            block_interval: block,
            revision: 1,
        }
    }
    #[test]
    fn quota_bucket_refills_full_burst_only_at_interval_tick_and_is_peer_local() {
        let mut runtime = Runtime::default();
        let d = definition(2.0, 10, 0);
        let now = Instant::now();
        let ip = "127.0.0.1".parse().unwrap();
        assert!(runtime.take_at(&d, ip, now).unwrap().is_none());
        assert!(runtime.take_at(&d, ip, now).unwrap().is_none());
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(5))
                .unwrap()
                .is_some()
        );
        assert!(
            runtime
                .take_at(&d, "127.0.0.2".parse().unwrap(), now)
                .unwrap()
                .is_none()
        );
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(10))
                .unwrap()
                .is_none()
        );
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(10))
                .unwrap()
                .is_none()
        );
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(10))
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn quota_block_is_not_extended_by_retry_and_update_resets_bucket() {
        let mut runtime = Runtime::default();
        let mut d = definition(1.0, 1, 5);
        let now = Instant::now();
        let ip = "127.0.0.1".parse().unwrap();
        assert!(runtime.take_at(&d, ip, now).unwrap().is_none());
        assert!(runtime.take_at(&d, ip, now).unwrap().is_some());
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(4))
                .unwrap()
                .is_some()
        );
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(5))
                .unwrap()
                .is_none()
        );
        d.revision = 2;
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(5))
                .unwrap()
                .is_none()
        );
    }
}

#[cfg(test)]
mod service_tests {
    use super::super::tests::{Root, bootstrap, call};
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn peer_call(
        service: &mut Service,
        method: &str,
        path: &str,
        token: &str,
        body: Value,
    ) -> Response {
        service.handle_request_at(
            ServiceRequest::new(method, path, "", token, body)
                .with_origin_peer("127.0.0.1".parse().unwrap()),
            100,
        )
    }
    #[test]
    fn rate_limit_denial_preserves_single_use_secret_id_and_invalid_secret_still_counts()
    -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        for mount in ["approle", "forms"] {
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    &format!("sys/auth/{mount}"),
                    &admin,
                    json!({"type":"approle"})
                )
                .status,
                204
            );
            let role = format!("auth/{mount}/role/limited");
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    &role,
                    &admin,
                    json!({"secret_id_num_uses":1})
                )
                .status,
                204
            );
            let role_id = call(
                &mut service,
                "GET",
                &format!("{role}/role-id"),
                &admin,
                json!({}),
            )
            .body["data"]["role_id"]
                .as_str()
                .ok_or("role")?
                .to_owned();
            let sid = call(
                &mut service,
                "POST",
                &format!("{role}/secret-id"),
                &admin,
                json!({}),
            )
            .body["data"]["secret_id"]
                .as_str()
                .ok_or("sid")?
                .to_owned();
            let rule = format!("sys/quotas/rate-limit/{mount}");
            let settings =
                json!({"path":format!("auth/{mount}/"),"role":"limited","rate":1,"interval":"1h"});
            assert_eq!(
                call(&mut service, "POST", &rule, &admin, settings.clone()).status,
                204
            );
            let login = format!("auth/{mount}/login");
            assert_eq!(
                peer_call(
                    &mut service,
                    "POST",
                    &login,
                    "",
                    json!({"role_id":role_id,"secret_id":"wrong-secret"})
                )
                .status,
                400
            );
            let wire = format!(
                "POST /v1/{login} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\nrole_id={role_id}&secret_id={sid}",
                "role_id=&secret_id=".len() + role_id.len() + sid.len()
            );
            let denied =
                crate::http::logical_data_wire_fixture(&mut service, wire.as_bytes(), 100)?;
            assert_eq!(denied.status, 429);
            assert!(denied.body.get("auth").is_none());
            for ((name, _, _), bucket) in &mut service.rate_limit_quotas.buckets {
                if name == mount {
                    bucket.limiter.as_mut().unwrap().start =
                        Instant::now() - Duration::from_secs(3600);
                }
            }
            assert_eq!(
                peer_call(
                    &mut service,
                    "POST",
                    &login,
                    "",
                    json!({"role_id":role_id,"secret_id":sid})
                )
                .status,
                200
            );
            assert_eq!(
                call(&mut service, "POST", &rule, &admin, settings).status,
                204
            );
            assert_eq!(
                peer_call(
                    &mut service,
                    "POST",
                    &login,
                    "",
                    json!({"role_id":role_id,"secret_id":sid})
                )
                .status,
                400
            );
        }
        Ok(())
    }
    #[test]
    fn rate_limit_acl_api_namespace_scope_and_unsupported_ranges_fail_closed() -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        assert_eq!(
            call(&mut service, "GET", "sys/quotas/config", "", json!({})).status,
            403
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/auth/forms",
                &admin,
                json!({"type":"approle"})
            )
            .status,
            204
        );
        assert_eq!(call(&mut service,"POST","sys/policies/acl/quota-manager",&admin,json!({"policy":"path \"sys/quotas/*\" { capabilities = [\"read\", \"update\", \"list\", \"delete\"] }"})).status,204);
        let issued = call(
            &mut service,
            "POST",
            "auth/token/create",
            &admin,
            json!({"policies":["quota-manager"],"ttl":60}),
        );
        assert_eq!(issued.status, 200);
        let manager = issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("manager token")?
            .to_owned();
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/quotas/rate-limit/managed",
                &manager,
                json!({"path":"auth/forms","rate":2})
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "sys/quotas/rate-limit/managed",
                &manager,
                json!({})
            )
            .body["data"]["path"],
            "auth/forms/"
        );
        assert_eq!(
            call(
                &mut service,
                "LIST",
                "sys/quotas/rate-limit",
                &manager,
                json!({})
            )
            .body["data"]["keys"],
            json!(["managed"])
        );
        for body in [
            json!({"path":"","rate":2}),
            json!({"path":"secret/","rate":2}),
            json!({"path":"auth/forms/","rate":0}),
            json!({"path":"auth/forms/","rate":2,"inheritable":true}),
            json!({"path":"auth/forms/login","role":"r","rate":2}),
        ] {
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/quotas/rate-limit/unsupported",
                    &manager,
                    body
                )
                .status,
                400
            );
        }
        for field in [
            "enable_rate_limit_audit_logging",
            "enable_rate_limit_response_headers",
        ] {
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/quotas/config",
                    &manager,
                    json!({field:true})
                )
                .status,
                400
            );
        }
        assert_eq!(
            call(
                &mut service,
                "DELETE",
                "sys/quotas/rate-limit/managed",
                &manager,
                json!({})
            )
            .status,
            204
        );
        Ok(())
    }
    #[test]
    fn rate_limit_native_owner_reopens_and_floor_survives_delete_remount_and_snapshot() -> TestResult
    {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, admin) = bootstrap(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/auth/forms",
                &admin,
                json!({"type":"approle"})
            )
            .status,
            204
        );
        let previous = service.state.clone().ok_or("previous state")?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/quotas/rate-limit/retained",
                &admin,
                json!({"path":"auth/forms/login","rate":1,"interval":"1h"})
            )
            .status,
            204
        );
        let current = service.state.clone().ok_or("current state")?;
        assert_eq!(current.schema, RATE_LIMIT_QUOTA_STATE_SCHEMA);
        assert!(Service::validate_snapshot_protected_floor(&current, &previous).is_err());
        assert!(
            previous
                .validate_publication_schema(Some(&current))
                .is_err()
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/remount",
                &admin,
                json!({"from":"auth/forms/","to":"auth/moved/"})
            )
            .status,
            400
        );
        drop(service);
        let mut reopened = root.service()?;
        assert_eq!(
            call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        assert_eq!(
            call(
                &mut reopened,
                "GET",
                "sys/quotas/rate-limit/retained",
                &admin,
                json!({})
            )
            .body["data"]["interval"],
            3600
        );
        assert_eq!(
            call(&mut reopened, "DELETE", "sys/auth/forms", &admin, json!({})).status,
            204
        );
        assert_eq!(
            call(
                &mut reopened,
                "GET",
                "sys/quotas/rate-limit/retained",
                &admin,
                json!({})
            )
            .status,
            404
        );
        assert_eq!(
            reopened.state.as_ref().ok_or("reopened state")?.schema,
            RATE_LIMIT_QUOTA_STATE_SCHEMA
        );
        assert_eq!(
            call(
                &mut reopened,
                "POST",
                "sys/auth/forms",
                &admin,
                json!({"type":"approle"})
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut reopened,
                "GET",
                "sys/quotas/rate-limit/retained",
                &admin,
                json!({})
            )
            .status,
            404
        );
        Ok(())
    }
    #[test]
    fn rate_limit_idle_limiter_purge_cannot_shorten_independent_block_interval() {
        let mut runtime = Runtime::default();
        let d = super::tests::definition(1.0, 3600, 300);
        let now = Instant::now();
        let ip = "127.0.0.1".parse().unwrap();
        assert!(runtime.take_at(&d, ip, now).unwrap().is_none());
        assert!(runtime.take_at(&d, ip, now).unwrap().is_some());
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(241))
                .unwrap()
                .is_some()
        );
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(300))
                .unwrap()
                .is_none()
        );
    }
}
