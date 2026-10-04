//! Public immutable HelpOperation documents, selected by the actual owner.
//! Templates retain the pinned 2.7.0 backend documentation and OpenAPI schema.
use super::*;
pub(crate) struct HelpProjection {
    pub(crate) anonymous: bool,
    pub(crate) body: Value,
}
fn render(template: &str, relative: &str, anonymous: bool) -> Result<HelpProjection> {
    let mut body: Value =
        serde_json::from_str(template).map_err(|_| bad("invalid built-in help document"))?;
    if let Some(help) = body.get_mut("help")
        && let Some(text) = help.as_str()
        && text.starts_with("Request:        ")
    {
        let suffix = text.split_once('\n').map_or("", |(_, suffix)| suffix);
        *help = Value::String(format!("Request:        {relative}\n{suffix}"));
    }
    Ok(HelpProjection { anonymous, body })
}
impl EngineState {
    pub(crate) fn help_projection(
        &self,
        namespace: &str,
        path: &str,
    ) -> Result<Option<HelpProjection>> {
        // These logical owners are always present, after Service's catalog fence.
        if path == "sys/mounts" {
            return render(
                include_str!("help_templates/sys-mounts.json"),
                "mounts",
                false,
            )
            .map(Some);
        }
        if path == "auth/token/lookup-self" {
            return render(
                include_str!("help_templates/auth-lookup.json"),
                "lookup-self",
                false,
            )
            .map(Some);
        }
        let Some(state) = self.namespaces.get(namespace) else {
            return Ok(None);
        };
        let Some((mount, owner)) = state
            .mounts
            .iter()
            .filter(|(mount, _)| {
                path == mount.trim_end_matches('/') || path.starts_with(mount.as_str())
            })
            .max_by_key(|(mount, _)| mount.len())
        else {
            return Ok(None);
        };
        let relative = path.strip_prefix(mount.as_str()).unwrap_or("");
        let (template, anonymous) = match &owner.backend {
            Backend::Kv1(_) | Backend::Kv1Records => (
                if relative.is_empty() {
                    include_str!("help_templates/kv1-root.json")
                } else {
                    include_str!("help_templates/kv1-key.json")
                },
                false,
            ),
            Backend::Kv2(_) => (
                if relative.is_empty() {
                    include_str!("help_templates/kv2-root.json")
                } else if relative.starts_with("data/") {
                    include_str!("help_templates/kv2-data.json")
                } else if relative.starts_with("metadata/") {
                    include_str!("help_templates/kv2-metadata.json")
                } else if relative.starts_with("delete/") {
                    include_str!("help_templates/kv2-delete.json")
                } else if relative.starts_with("undelete/") {
                    include_str!("help_templates/kv2-undelete.json")
                } else if relative.starts_with("destroy/") {
                    include_str!("help_templates/kv2-destroy.json")
                } else if relative == "config" {
                    include_str!("help_templates/kv2-config.json")
                } else {
                    include_str!("help_templates/kv2-unknown.json")
                },
                false,
            ),
            Backend::Pki(_) if relative == "ocsp" => {
                (include_str!("help_templates/pki-ocsp.json"), true)
            }
            Backend::Pki(_) if relative.starts_with("ocsp/") => {
                (include_str!("help_templates/pki-ocsp-suffix.json"), true)
            }
            _ => return Ok(None),
        };
        render(template, relative, anonymous).map(Some)
    }
}
