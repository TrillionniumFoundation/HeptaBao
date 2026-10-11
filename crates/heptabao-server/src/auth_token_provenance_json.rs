//! Preserve the original internal-tag wire without serde Content projection.
//! The equivalent external-tag helper sees actual RawValue-capable fields.
use super::*;
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Wire {
    Sdk {
        origin: Box<sdk::TokenOrigin>,
    },
    Cert {
        issued_metadata: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issued_creation_ttl: Option<u64>,
    },
    Userpass {
        username: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issued_creation_ttl: Option<u64>,
    },
    AppRole {
        role_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issued_metadata: Option<BTreeMap<String, String>>,
    },
    Radius {
        username: String,
        credential: ProviderCredential,
    },
    RadiusNative {
        username: String,
        credential: ProviderCredential,
        policy_metadata: String,
    },
    Ldap {
        username: String,
        credential: ProviderCredential,
    },
    LdapNative {
        username: String,
        alias: String,
        credential: ProviderCredential,
    },
    Jwt {
        role_name: String,
    },
    Kubernetes {
        role_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        renewal_custody: Option<kubernetes::KubernetesRenewalCustody>,
    },
    Oidc {
        role_name: String,
    },
    Kerberos {
        provider: String,
        service_account: String,
        realm: String,
        service: String,
        mount_revision: u64,
        config_revision: String,
    },
    TokenApi {
        /// The initial granted TTL is immutable across renewal. Historical
        /// markers omit it rather than guessing from a later expiry or grant.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issued_creation_ttl: Option<u64>,
    },
}
impl<'de> Deserialize<'de> for TokenAuthProvenance {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let mut parsed = StrictJson(heptabao_domain::json::deserialize(deserializer)?);
        let object = parsed
            .0
            .as_object_mut()
            .ok_or_else(|| serde::de::Error::custom("invalid token provenance object"))?;
        let kind = object
            .remove("kind")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| serde::de::Error::custom("invalid token provenance kind"))?;
        let mut external = serde_json::Map::new();
        external.insert(kind, std::mem::take(&mut parsed.0));
        let wire: Wire =
            serde_json::from_value(Value::Object(external)).map_err(serde::de::Error::custom)?;
        Ok(match wire {
            Wire::Sdk { origin } => Self::Sdk { origin },
            Wire::Cert {
                issued_metadata,
                issued_creation_ttl,
            } => Self::Cert {
                issued_metadata,
                issued_creation_ttl,
            },
            Wire::Userpass { username, issued_creation_ttl } => Self::Userpass { username, issued_creation_ttl },
            Wire::AppRole {
                role_name,
                issued_metadata,
            } => Self::AppRole {
                role_name,
                issued_metadata,
            },
            Wire::Radius {
                username,
                credential,
            } => Self::Radius {
                username,
                credential,
            },
            Wire::RadiusNative {
                username,
                credential,
                policy_metadata,
            } => Self::RadiusNative {
                username,
                credential,
                policy_metadata,
            },
            Wire::Ldap {
                username,
                credential,
            } => Self::Ldap {
                username,
                credential,
            },
            Wire::LdapNative {
                username,
                alias,
                credential,
            } => Self::LdapNative {
                username,
                alias,
                credential,
            },
            Wire::Jwt { role_name } => Self::Jwt { role_name },
            Wire::Kubernetes { role_name, renewal_custody } => Self::Kubernetes { role_name, renewal_custody },
            Wire::Oidc { role_name } => Self::Oidc { role_name },
            Wire::Kerberos {
                provider,
                service_account,
                realm,
                service,
                mount_revision,
                config_revision,
            } => Self::Kerberos {
                provider,
                service_account,
                realm,
                service,
                mount_revision,
                config_revision,
            },
            Wire::TokenApi {
                issued_creation_ttl,
            } => Self::TokenApi {
                issued_creation_ttl,
            },
        })
    }
}
