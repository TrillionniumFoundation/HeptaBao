//! Native Transit parameter verification retains deployment egress authority.
//! This is not a cryptographic operation or a proof that a remote key exists.
use super::*;

pub(super) struct NativeTransitVerification {
    outbound: crate::outbound::Outbound,
    enrolled_mount_url: String,
}

fn bad(message: &'static str) -> Response {
    Response::error(400, message)
}

fn optional_string<'a>(
    value: &'a Value,
    field: &str,
    default: &'a str,
) -> Result<&'a str, Response> {
    value
        .get(field)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| bad("external Transit parameter must be a string"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
}

fn canonical_mount(value: &str) -> Result<String, Response> {
    let value = value.trim_end_matches('/');
    if value.is_empty()
        || value.len() > 1024
        || value.starts_with('/')
        || value.split('/').any(|segment| !valid_name(segment))
    {
        return Err(bad("external Transit mount or namespace is invalid"));
    }
    Ok(format!("{value}/"))
}

impl NativeTransitVerification {
    pub(super) fn prepare(
        outbound: &crate::outbound::Outbound,
        action: &str,
        request: &SecretValue,
    ) -> Result<Self, Response> {
        let value = VerificationResponse(
            crate::auth::parse_strict_json(request.expose())
                .map_err(|_| Response::error(503, "invalid native external key plan"))?,
        );
        let object = value
            .0
            .as_object()
            .ok_or_else(|| Response::error(503, "invalid native external key plan"))?;
        let expected_fields: &[&str] = match action {
            "verify_config" => &["action", "namespace", "plugin", "config", "values"],
            "verify_key" => &[
                "action",
                "namespace",
                "plugin",
                "config",
                "key",
                "config_values",
                "key_values",
            ],
            _ => {
                return Err(Response::error(
                    503,
                    "invalid native external key verification action",
                ));
            }
        };
        if object.len() != expected_fields.len()
            || object
                .keys()
                .any(|field| !expected_fields.contains(&field.as_str()))
            || value.0["action"].as_str() != Some(action)
            || value.0["plugin"].as_str() != Some("transit")
            || !value.0["config"].as_str().is_some_and(valid_name)
            || value.0["namespace"].as_str().is_none()
            || (action == "verify_key" && !value.0["key"].as_str().is_some_and(valid_name))
        {
            return Err(Response::error(
                503,
                "native external key plan binding is invalid",
            ));
        }
        let config = match action {
            "verify_config" => &value.0["values"],
            "verify_key" => &value.0["config_values"],
            _ => {
                return Err(Response::error(
                    503,
                    "invalid native external key verification action",
                ));
            }
        };
        let object = config
            .as_object()
            .ok_or_else(|| bad("external Transit parameters must be an object"))?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "address"
                    | "token"
                    | "namespace"
                    | "mount_path"
                    | "tls_server_name"
                    | "tls_skip_verify"
                    | "tls_ca_cert_bytes"
                    | "tls_client_cert_bytes"
                    | "tls_client_key_bytes"
            )
        }) {
            return Err(bad("unsupported native external Transit parameter"));
        }
        let address =
            optional_string(config, "address", "https://127.0.0.1:8200")?.trim_end_matches('/');
        let target = crate::outbound::Target::parse(address, "https")
            .map_err(|_| bad("invalid external Transit address"))?;
        if target.path != "/" {
            return Err(bad("external Transit address must be an HTTPS origin"));
        }
        let mount = canonical_mount(optional_string(config, "mount_path", "transit")?)?;
        let enrolled_mount_url = format!("{address}/v1/{mount}");
        if outbound.endpoint(&enrolled_mount_url, "https").is_err() {
            return Err(Response::error(
                501,
                "native external Transit verification requires enrolled HTTPS",
            ));
        }
        match config.get("tls_skip_verify") {
            None | Some(Value::Bool(false)) => {}
            Some(Value::Bool(true)) => return Err(bad("external Transit requires verified TLS")),
            Some(_) => {
                return Err(bad(
                    "external Transit TLS verification flag must be boolean",
                ));
            }
        }
        for field in ["tls_client_cert_bytes", "tls_client_key_bytes"] {
            if config
                .get(field)
                .is_some_and(|value| value.as_str() != Some(""))
            {
                return Err(Response::error(
                    501,
                    "external Transit mutual TLS requires deployment enrollment",
                ));
            }
        }
        outbound
            .validate_external_transit_tls(
                &enrolled_mount_url,
                optional_string(config, "tls_server_name", "")?,
                optional_string(config, "tls_ca_cert_bytes", "")?,
            )
            .map_err(|message| Response::error(503, message))?;
        let token = optional_string(config, "token", "")?;
        if token.is_empty()
            || token.len() > 32 * 1024
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(bad("invalid remote Transit token"));
        }
        let namespace = optional_string(config, "namespace", "")?;
        if !namespace.is_empty() {
            canonical_mount(namespace)?;
        }
        if action == "verify_key" {
            let key = value.0["key_values"]
                .as_object()
                .ok_or_else(|| bad("external Transit key parameters must be an object"))?;
            if key
                .keys()
                .any(|key| !matches!(key.as_str(), "name" | "version" | "disable_prehashing"))
            {
                return Err(bad("unsupported native external Transit key parameter"));
            }
            if !key
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(valid_name)
                || !key
                    .get("version")
                    .and_then(Value::as_u64)
                    .is_some_and(|version| version > 0)
            {
                return Err(bad(
                    "native external Transit requires a named fixed positive version",
                ));
            }
            if key
                .get("disable_prehashing")
                .is_some_and(|value| !value.is_boolean())
            {
                return Err(bad("external Transit prehashing flag must be boolean"));
            }
        }
        Ok(Self {
            outbound: outbound.clone(),
            enrolled_mount_url,
        })
    }

    pub(super) fn execute(&self) -> Result<(), Response> {
        // Parameter validation completed before staging. A verification result
        // must never be used as a signature, key descriptor or crypto success.
        // Remote operations are performed only by the actual consumer owner.
        if self
            .outbound
            .endpoint(&self.enrolled_mount_url, "https")
            .is_err()
        {
            return Err(Response::error(
                503,
                "native external Transit enrollment unavailable before publication",
            ));
        }
        Ok(())
    }

    pub(super) fn enrollment_current(&self, outbound: &crate::outbound::Outbound) -> bool {
        outbound.same_https_enrollment(&self.outbound, &self.enrolled_mount_url)
    }
}
