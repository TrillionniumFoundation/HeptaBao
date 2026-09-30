//! UI and CLI preflight use the current namespace registry and admitted actor.
use super::*;

impl Service {
    pub(super) fn ui_mounts_route(
        state: &State,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        now: u64,
    ) -> Response {
        if method != "GET" {
            return Response::error(405, "mount discovery requires GET");
        }
        let suffix = path.strip_prefix("sys/internal/ui/mounts").unwrap_or("");
        let mut mounts = state.engines.ui_secret_mounts(namespace);
        mounts.extend(state.auth.ui_auth_mounts(namespace));
        let visible = |mount: &str| -> Result<bool, Response> {
            match principal {
                Some(actor) => state
                    .auth
                    .ui_mount_visible(actor, namespace, mount, now)
                    .map_err(|error| Response::error(error.status, &error.message)),
                None => Ok(false),
            }
        };
        if suffix.is_empty() || suffix == "/" {
            let mut auth = serde_json::Map::new();
            let mut secret = serde_json::Map::new();
            for (mount, descriptor) in mounts {
                match visible(&mount) {
                    Ok(true) => {
                        if let Some(name) = mount.strip_prefix("auth/") {
                            auth.insert(name.to_owned(), descriptor);
                        } else {
                            secret.insert(mount, descriptor);
                        }
                    }
                    Ok(false) => {}
                    Err(response) => return response,
                }
            }
            return Response::ok(json!({"data":{"auth":auth,"secret":secret}}));
        }
        let target = suffix.trim_start_matches('/');
        let Some((mount, mut descriptor)) = mounts
            .into_iter()
            .filter(|(mount, _)| target == mount.trim_end_matches('/') || target.starts_with(mount))
            .max_by_key(|(mount, _)| mount.len())
        else {
            return Response::error(403, "mount preflight access denied");
        };
        match visible(&mount) {
            Ok(true) => {
                descriptor["path"] = Value::String(mount);
                Response::ok(json!({"data":descriptor}))
            }
            Ok(false) => Response::error(403, "mount preflight access denied"),
            Err(response) => response,
        }
    }
}
