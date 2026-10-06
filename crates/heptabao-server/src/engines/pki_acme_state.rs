//! Durable ACME account identity is separate from a Vault token. Public JWK
//! proofs cannot grant a Vault ACL, create a token, or manufacture a clock.
use super::acme_jws::Jwk;
use super::*;
use crate::auth::Timestamp;

const MAX_ACCOUNTS: usize = 4096;
const MAX_CONTACTS: usize = 64;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub cluster_id: String,
    pub namespace: String,
    pub namespace_incarnation: Option<u64>,
    pub mount: String,
    pub mount_incarnation: u64,
}

impl Binding {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.cluster_id.is_empty()
            || self.cluster_id.len() > 256
            || self.cluster_id.bytes().any(|b| {
                !b.is_ascii_alphanumeric() && !matches!(b, b'-' | b'_' | b'+' | b'/' | b'=')
            })
            || self.namespace.len() > 512
            || self.namespace.starts_with('/')
            || self.namespace.ends_with('/')
            || self
                .namespace
                .split('/')
                .any(|part| matches!(part, "." | ".."))
            || if self.namespace.is_empty() {
                self.namespace_incarnation != Some(0)
            } else {
                self.namespace_incarnation.is_none_or(|v| v == 0)
            }
            || self.mount.is_empty()
            || self.mount.len() > 512
            || self.mount.starts_with('/')
            || !self.mount.ends_with('/')
            || self.mount.split('/').any(|part| matches!(part, "." | ".."))
            || self.mount_incarnation == 0
        {
            return Err(error(
                503,
                "ACME durable mount and namespace owner rejected",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Account {
    pub id: String,
    pub directory: String,
    pub status: AccountStatus,
    pub jwk: Jwk,
    pub thumbprint: String,
    pub contact: Vec<String>,
    pub terms_of_service_agreed: bool,
    pub created: Timestamp,
    pub deactivated: Option<Timestamp>,
}

fn valid_identifier(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        })
}

pub(crate) fn valid_directory(directory: &str) -> bool {
    !directory.is_empty()
        && directory.len() <= 512
        && directory.ends_with("acme/")
        && !directory.starts_with('/')
        && !directory
            .bytes()
            .any(|b| b < 32 || b == 127 || matches!(b, b'?' | b'#' | b'\\'))
        && !directory.split('/').any(|part| matches!(part, "." | ".."))
}

impl Account {
    pub(crate) fn validate(&self, clock: Timestamp) -> Result<()> {
        if !valid_identifier(&self.id)
            || !valid_directory(&self.directory)
            || self.thumbprint != self.jwk.thumbprint()?
            || self.contact.len() > MAX_CONTACTS
            || self
                .contact
                .iter()
                .any(|c| c.len() > 2048 || c.bytes().any(|b| b < 32 || b == 127))
            || self.created > clock
            || self
                .deactivated
                .is_some_and(|at| at < self.created || at > clock)
            || (self.status == AccountStatus::Valid) != self.deactivated.is_none()
        {
            return Err(error(503, "ACME durable account owner rejected"));
        }
        Ok(())
    }

    pub(crate) fn descriptor(&self, base: &str) -> Value {
        let status = match self.status {
            AccountStatus::Valid => "valid",
            AccountStatus::Deactivated => "deactivated",
            AccountStatus::Revoked => "revoked",
        };
        let mut value =
            json!({"status":status,"orders":format!("{base}account/{}/orders", self.id)});
        if !self.contact.is_empty() {
            value["contact"] = json!(self.contact);
        }
        value
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Protocol {
    pub owner: Binding,
    // Only the issuance frontier persists. Nonce secrets and redemption state
    // belong to one Service process and disappear at restart, as in Bao 2.7.
    pub nonce_issue_count: u64,
    pub response_config_revision: u64,
    pub allowed_response_headers: Vec<String>,
    pub clock: Timestamp,
    pub accounts: BTreeMap<String, Account>,
    pub native_defaults: bool,
}

impl Protocol {
    pub(crate) fn new(owner: Binding, at: Timestamp) -> Result<Self> {
        owner.validate()?;
        Ok(Self {
            owner,
            nonce_issue_count: 0,
            response_config_revision: 1,
            allowed_response_headers: Vec::new(),
            clock: at,
            accounts: BTreeMap::new(),
            native_defaults: true,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.owner.validate()?;
        if self.response_config_revision == 0
            || !crate::service::validate_sdk_header_allowlist(&self.allowed_response_headers)
            || self.accounts.len() > MAX_ACCOUNTS
            || !self.native_defaults
        {
            return Err(error(503, "ACME durable protocol owner rejected"));
        }
        let mut thumbprints = BTreeSet::new();
        for (id, account) in &self.accounts {
            account.validate(self.clock)?;
            if id != &account.id || !thumbprints.insert((&account.directory, &account.thumbprint)) {
                return Err(error(503, "ACME account key ownership is ambiguous"));
            }
        }
        Ok(())
    }

    pub(crate) fn observe_time(&mut self, now: Timestamp) -> Timestamp {
        self.clock = self.clock.max(now);
        self.clock
    }

    pub(crate) fn by_thumbprint(&self, thumbprint: &str, directory: &str) -> Option<&Account> {
        self.accounts
            .values()
            .find(|a| a.thumbprint == thumbprint && a.directory == directory)
    }

    pub(crate) fn by_id(&self, id: &str, directory: &str) -> Option<&Account> {
        self.accounts.get(id).filter(|a| a.directory == directory)
    }

    pub(crate) fn insert_account(&mut self, account: Account) -> Result<()> {
        account.validate(self.clock)?;
        if self.accounts.len() >= MAX_ACCOUNTS
            || self.accounts.contains_key(&account.id)
            || self
                .accounts
                .values()
                .any(|a| a.directory == account.directory && a.thumbprint == account.thumbprint)
        {
            return Err(error(
                507,
                "ACME account capacity or key ownership rejected",
            ));
        }
        self.accounts.insert(account.id.clone(), account);
        Ok(())
    }
}
