//! OpenBao-compatible PostgreSQL statement-template normalization.
//!
//! Templates are persisted as configuration, while rendered statements exist
//! only in the process-local provider plan. The provider ledger stores digests,
//! never statement text or generated credentials.
use super::*;

const MAX_STATEMENTS_PER_PHASE: usize = 16;
const MAX_RENDERED_STATEMENTS: usize = 64;
const MAX_STATEMENT_BYTES: usize = 16 * 1024;
const MAX_STATEMENTS_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct DatabaseStatements {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) creation: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) revocation: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) rollback: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) renewal: Vec<String>,
}

impl DatabaseStatements {
    pub(super) fn is_empty(&self) -> bool {
        self.creation.is_empty()
            && self.revocation.is_empty()
            && self.rollback.is_empty()
            && self.renewal.is_empty()
    }

    pub(super) fn validate(&self) -> Result<(), Response> {
        let groups = [
            ("creation", &self.creation),
            ("revocation", &self.revocation),
            ("rollback", &self.rollback),
            ("renewal", &self.renewal),
        ];
        let mut total = 0usize;
        for (phase, statements) in groups {
            if statements.len() > MAX_STATEMENTS_PER_PHASE {
                return Err(invalid("database statement count exceeds bound"));
            }
            for statement in statements {
                let value = statement.trim();
                if value.is_empty()
                    || value.len() > MAX_STATEMENT_BYTES
                    || value.contains('\0')
                    || value.chars().any(|character| {
                        character.is_control() && !matches!(character, '\n' | '\r' | '\t')
                    })
                {
                    return Err(invalid("database statement is empty or outside bounds"));
                }
                validate_placeholders(value).map_err(|_| {
                    invalid(match phase {
                        "creation" => "invalid creation statement placeholder",
                        "revocation" => "invalid revocation statement placeholder",
                        "rollback" => "invalid rollback statement placeholder",
                        _ => "invalid renewal statement placeholder",
                    })
                })?;
                total = total
                    .checked_add(value.len())
                    .ok_or_else(|| invalid("database statement bytes exceed bound"))?;
            }
        }
        if total > MAX_STATEMENTS_BYTES {
            return Err(invalid("database statement bytes exceed bound"));
        }
        if !self.is_empty() && self.creation.is_empty() {
            return Err(invalid(
                "creation_statements are required for a statement-backed role",
            ));
        }
        Ok(())
    }

    pub(super) fn templates_for_action(&self, action: &str) -> Result<Vec<String>, Response> {
        self.validate()?;
        let defaults;
        let templates = match action {
            "issue" => &self.creation,
            "renew" if self.renewal.is_empty() => {
                defaults = vec!["ALTER ROLE \"{{name}}\" VALID UNTIL '{{expiration}}'".to_owned()];
                &defaults
            }
            "renew" => &self.renewal,
            "revoke" if self.revocation.is_empty() => {
                defaults = vec![
                    "SELECT heptabao_provider.default_statement_revoke('{{name}}'::name)"
                        .to_owned(),
                ];
                &defaults
            }
            "revoke" => &self.revocation,
            _ => return Err(failure("database statement action is not supported")),
        };
        let mut normalized = Vec::new();
        for template in templates {
            for statement in split_sql_statements(template)? {
                if normalized.len() >= MAX_RENDERED_STATEMENTS {
                    return Err(invalid("rendered database statement count exceeds bound"));
                }
                normalized.push(statement);
            }
        }
        if normalized.is_empty() {
            return Err(invalid("database statement set rendered empty"));
        }
        Ok(normalized)
    }

    #[cfg(test)]
    pub(super) fn render(
        &self,
        action: &str,
        username: &str,
        password: &str,
        expiration: &str,
    ) -> Result<Vec<String>, Response> {
        self.templates_for_action(action)?
            .into_iter()
            .map(|template| {
                Ok(template
                    .replace("{{name}}", username)
                    .replace("{{username}}", username)
                    .replace("{{password}}", password)
                    .replace("{{expiration}}", expiration))
            })
            .collect()
    }
}

pub(super) fn parse_statement_field(
    body: &Value,
    key: &str,
) -> Result<Option<Vec<String>>, Response> {
    let Some(value) = body.get(key) else {
        return Ok(None);
    };
    let values = match value {
        Value::String(value) => vec![value.to_owned()],
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("database statements must be strings"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(invalid(
                "database statements must be a string or string array",
            ));
        }
    };
    Ok(Some(
        values
            .into_iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect(),
    ))
}

pub(super) fn parse_credential_type(body: &Value) -> Result<Option<&str>, Response> {
    let Some(value) = body.get("credential_type") else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| invalid("credential_type must be a string"))?;
    if value != "password" {
        return Err(Response::error(
            400,
            "PostgreSQL statement roles currently support password credentials only",
        ));
    }
    Ok(Some(value))
}

pub(super) fn validate_credential_config(body: &Value) -> Result<(), Response> {
    let Some(value) = body.get("credential_config") else {
        return Ok(());
    };
    let object = value
        .as_object()
        .ok_or_else(|| invalid("credential_config must be an object"))?;
    if !object.is_empty() {
        return Err(Response::error(
            400,
            "password credential_config requires an integrated password-policy owner",
        ));
    }
    Ok(())
}

fn validate_placeholders(statement: &str) -> Result<(), ()> {
    let mut cursor = 0usize;
    while cursor < statement.len() {
        let next_open = statement[cursor..].find("{{").map(|index| cursor + index);
        let next_close = statement[cursor..].find("}}").map(|index| cursor + index);
        match (next_open, next_close) {
            (None, None) => return Ok(()),
            (None, Some(_)) => return Err(()),
            (Some(open), Some(close)) if close < open => return Err(()),
            (Some(open), _) => {
                let close = statement[open + 2..]
                    .find("}}")
                    .map(|index| open + 2 + index)
                    .ok_or(())?;
                let name = &statement[open + 2..close];
                if name.contains("{{")
                    || !matches!(name, "name" | "username" | "password" | "expiration")
                {
                    return Err(());
                }
                cursor = close + 2;
            }
        }
    }
    Ok(())
}

fn split_sql_statements(value: &str) -> Result<Vec<String>, Response> {
    let bytes = value.as_bytes();
    let mut statements = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut single = false;
    let mut escape_single = false;
    let mut double = false;
    let mut dollar: Option<Vec<u8>> = None;
    let mut line_comment = false;
    let mut block_comment_depth = 0usize;
    while index < bytes.len() {
        if line_comment {
            if bytes[index] == b'\n' {
                line_comment = false;
            }
            index += 1;
            continue;
        }
        if block_comment_depth != 0 {
            if bytes[index..].starts_with(b"/*") {
                block_comment_depth = block_comment_depth
                    .checked_add(1)
                    .ok_or_else(|| invalid("database statement comment nesting exhausted"))?;
                if block_comment_depth > 16 {
                    return Err(invalid("database statement comment nesting exceeds bound"));
                }
                index += 2;
            } else if bytes[index..].starts_with(b"*/") {
                block_comment_depth -= 1;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if let Some(tag) = &dollar {
            if bytes[index..].starts_with(tag) {
                index += tag.len();
                dollar = None;
            } else {
                index += 1;
            }
            continue;
        }
        if single {
            if (bytes[index] == b'\'' && bytes.get(index + 1) == Some(&b'\''))
                || (escape_single && bytes[index] == b'\\' && index + 1 < bytes.len())
            {
                index += 2;
            } else if bytes[index] == b'\'' {
                single = false;
                escape_single = false;
                index += 1;
            } else {
                index += 1;
            }
            continue;
        }
        if double {
            if bytes[index] == b'"' && bytes.get(index + 1) == Some(&b'"') {
                index += 2;
            } else if bytes[index] == b'"' {
                double = false;
                index += 1;
            } else {
                index += 1;
            }
            continue;
        }
        if bytes[index..].starts_with(b"--") {
            line_comment = true;
            index += 2;
            continue;
        }
        if bytes[index..].starts_with(b"/*") {
            block_comment_depth = 1;
            index += 2;
            continue;
        }
        match bytes[index] {
            b'\'' => {
                let prefix = index.checked_sub(1).filter(|position| {
                    matches!(bytes[*position], b'e' | b'E')
                        && position.checked_sub(1).is_none_or(|before| {
                            !bytes[before].is_ascii_alphanumeric() && bytes[before] != b'_'
                        })
                });
                escape_single = prefix.is_some();
                single = true;
                index += 1;
            }
            b'"' => {
                double = true;
                index += 1;
            }
            b'$' => {
                let tail = &bytes[index + 1..];
                if let Some(end) = tail.iter().position(|byte| *byte == b'$') {
                    let name = &tail[..end];
                    let valid = name.is_empty()
                        || name.first().is_some_and(|byte| {
                            (byte.is_ascii_alphabetic() || *byte == b'_')
                                && name[1..]
                                    .iter()
                                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                        });
                    if valid && name.len() <= 63 {
                        let tag = bytes[index..index + end + 2].to_vec();
                        index += tag.len();
                        dollar = Some(tag);
                        continue;
                    }
                }
                index += 1;
            }
            b';' => {
                let statement = value[start..index].trim();
                if !statement.is_empty() {
                    statements.push(statement.to_owned());
                }
                start = index + 1;
                index += 1;
            }
            _ => index += 1,
        }
    }
    if single || double || dollar.is_some() || block_comment_depth != 0 {
        return Err(invalid(
            "unterminated quoted or commented database statement",
        ));
    }
    let statement = value[start..].trim();
    if !statement.is_empty() {
        statements.push(statement.to_owned());
    }
    Ok(statements)
}

impl DatabaseState {
    pub(crate) fn has_statement_template_state(&self) -> bool {
        self.mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .any(|mount| {
                mount.roles.values().any(|role| !role.statements.is_empty())
                    || mount
                        .leases
                        .values()
                        .any(|lease| !lease.statements.is_empty())
            })
    }
}

fn statement_failure(message: &str, lease_id: &str) -> Response {
    Response {
        status: 503,
        body: json!({
            "errors":[message],
            "lease_id":lease_id,
            "reconcile_required":true,
            "retry_allowed":false
        }),
    }
}

fn statement_observation_matches(
    value: &str,
    plan: &DatabaseEffectPlan,
    expected_action: &str,
    expected_statements_digest: &str,
) -> Result<bool, Response> {
    let object = crate::auth::parse_strict_json(value.as_bytes())
        .map_err(|_| statement_failure("statement provider returned invalid JSON", &plan.lease.id))?
        .as_object()
        .cloned()
        .ok_or_else(|| {
            statement_failure("statement provider returned a non-object", &plan.lease.id)
        })?;
    if object.len() != 14
        || object.get("found") != Some(&json!(true))
        || object.get("fence_id") != Some(&json!(plan.fence_id))
        || object.get("lease_id") != Some(&json!(plan.lease.provider_id))
        || object.get("username") != Some(&json!(plan.lease.username))
        || object.get("seq") != Some(&json!(plan.lease.seq))
        || object.get("action") != Some(&json!(expected_action))
        || object.get("expires") != Some(&json!(plan.lease.expires))
        || object.get("request_digest") != Some(&json!(plan.lease.request_digest))
        || object.get("statements_digest") != Some(&json!(expected_statements_digest))
        || !object.get("role_present").is_some_and(Value::is_boolean)
        || !object.get("login").is_some_and(Value::is_boolean)
        || !object.get("active_sessions").is_some_and(Value::is_u64)
    {
        return Ok(false);
    }
    Ok(if expected_action == "revoke" {
        object.get("terminal") == Some(&json!(true))
    } else {
        object.get("controlled") == Some(&json!(true))
            && object.get("terminal") == Some(&json!(false))
    })
}

impl DatabaseEffectPlan {
    pub(super) fn execute_postgresql_statements(&self) -> Result<(), Response> {
        let indeterminate = || {
            statement_failure(
                "statement provider outcome indeterminate; durable intent retained",
                &self.lease.id,
            )
        };
        let action = action(&self.lease);
        let templates = self.lease.statements.templates_for_action(action)?;
        let encoded = Zeroizing::new(
            serde_json::to_string(&templates)
                .map_err(|_| failure("database statement encoding failed"))?,
        );
        if encoded.len() > MAX_STATEMENTS_BYTES + 4096 {
            return Err(invalid("database statement encoding exceeds bound"));
        }
        let statements_digest = hex(&crypto::digest(encoded.as_bytes()));
        let mut pg = self
            .connection
            .session(&self.outbound)
            .map_err(|_| indeterminate())?;
        if pg
            .scalar("SELECT heptabao_provider.statement_protocol()", &[])
            .map_err(|_| indeterminate())?
            != "heptabao-postgresql-statements-v1"
        {
            return Err(indeterminate());
        }
        let seq = self.lease.seq.to_string();
        let expires = self.lease.expires.to_string();
        if self.lease.phase == Phase::PendingRevoke {
            let retired = pg
                .scalar(
                    "SELECT heptabao_provider.statement_retired($1,$2,$3,$4::bigint)::text",
                    &[
                        &self.fence_id,
                        &self.lease.provider_id,
                        &self.lease.username,
                        &seq,
                    ],
                )
                .map_err(|_| indeterminate())?;
            if retired == "true" {
                return Ok(());
            }
        }
        let provider_password = if self.lease.phase == Phase::PendingIssue {
            let password = self
                .lease
                .password
                .as_ref()
                .ok_or_else(|| failure("pending statement issue lost client password"))?;
            self.connection
                .password_authentication
                .provider_password(&password.0, self.lease.provider_password.as_ref())?
        } else {
            ""
        };
        pg.scalar_large(
            self.connection.statement_apply_function(),
            &[
                &self.fence_id,
                &self.lease.provider_id,
                &self.lease.username,
                &seq,
                action,
                &expires,
                provider_password,
                &self.lease.request_digest,
                encoded.as_str(),
            ],
        )
        .map_err(|_| indeterminate())?;
        let observed = pg
            .scalar(
                "SELECT heptabao_provider.observe_statement($1)::text",
                &[&self.lease.provider_id],
            )
            .map_err(|_| indeterminate())?;
        if !statement_observation_matches(&observed, self, action, &statements_digest)? {
            return Err(statement_failure(
                "statement provider completion not established",
                &self.lease.id,
            ));
        }
        if self.lease.phase == Phase::PendingRevoke {
            if pg
                .scalar(
                    "SELECT heptabao_provider.retire_statement($1,$2,$3,$4::bigint)::text",
                    &[
                        &self.fence_id,
                        &self.lease.provider_id,
                        &self.lease.username,
                        &seq,
                    ],
                )
                .map_err(|_| indeterminate())?
                != "true"
            {
                return Err(indeterminate());
            }
            if pg
                .scalar(
                    "SELECT heptabao_provider.statement_retired($1,$2,$3,$4::bigint)::text",
                    &[
                        &self.fence_id,
                        &self.lease.provider_id,
                        &self.lease.username,
                        &seq,
                    ],
                )
                .map_err(|_| indeterminate())?
                != "true"
            {
                return Err(indeterminate());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type ParseTestResult = Result<(), &'static str>;

    #[test]
    fn official_placeholders_and_postgresql_dollar_blocks_are_bounded() -> ParseTestResult {
        let statements = DatabaseStatements {
            creation: vec![
                "DO $$ BEGIN PERFORM '{{password}}'; END $$; CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"
                    .into(),
            ],
            ..DatabaseStatements::default()
        };
        let rendered = statements
            .render("issue", "role", "secret", "2026-09-26 12:00:00+0000")
            .map_err(|_| "render failed")?;
        assert_eq!(rendered.len(), 2);
        assert!(rendered[0].starts_with("DO $$"));
        assert!(rendered[1].contains("CREATE ROLE \"role\""));
        assert!(
            DatabaseStatements {
                creation: vec!["SELECT '{{unknown}}'".into()],
                ..DatabaseStatements::default()
            }
            .validate()
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn semicolons_inside_quotes_and_dollar_blocks_do_not_split() -> ParseTestResult {
        let values = split_sql_statements(
            "SELECT ';'; DO $body$ BEGIN RAISE NOTICE 'a;b'; END $body$; SELECT \"a;b\";",
        )
        .map_err(|_| "split failed")?;
        assert_eq!(values.len(), 3);
        Ok(())
    }

    #[test]
    fn unmatched_closing_placeholders_and_nested_openers_are_rejected() {
        for statement in [
            "SELECT '}}'; SELECT '{{name}}'",
            "SELECT '{{name {{password}}'",
            "SELECT '{{name'",
        ] {
            assert!(validate_placeholders(statement).is_err(), "{statement}");
        }
    }

    #[test]
    fn comments_and_escape_strings_do_not_create_phantom_statements() -> ParseTestResult {
        let comments = split_sql_statements(
            "-- line; comment\nSELECT 1; /* outer; /* inner; */ end; */ SELECT 2;",
        )
        .map_err(|_| "comment split failed")?;
        assert_eq!(comments.len(), 2);
        let escaped = split_sql_statements(r"SELECT E'a\';b'; SELECT 2;")
            .map_err(|_| "escape string split failed")?;
        assert_eq!(escaped.len(), 2);
        assert!(split_sql_statements("SELECT 1; /* unterminated").is_err());
        Ok(())
    }

    #[test]
    fn default_renewal_and_revocation_are_explicit() -> ParseTestResult {
        let statements = DatabaseStatements {
            creation: vec!["CREATE ROLE \"{{name}}\" LOGIN".into()],
            ..DatabaseStatements::default()
        };
        let renewed = statements
            .render("renew", "role", "", "2026-09-26 12:00:00+0000")
            .map_err(|_| "renew render failed")?;
        assert_eq!(renewed.len(), 1);
        let revoked = statements
            .render("revoke", "role", "", "1970-01-01 00:00:00+0000")
            .map_err(|_| "revoke render failed")?;
        assert_eq!(revoked.len(), 1);
        Ok(())
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn configured_service()
    -> Result<(super::super::super::tests::Root, Service, String), Box<dyn std::error::Error>> {
        use super::super::super::tests::{Root, bootstrap, call};
        let root = Root::new();
        let mut service = root.service()?;
        let (_, root_token) = bootstrap(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/mounts/database",
                &root_token,
                json!({"type":"database"}),
            )
            .status,
            204
        );
        let mut state = service.state.clone().ok_or("state")?;
        state
            .database
            .mount_mut("", "database/")
            .connections
            .insert(
                "local".into(),
                Connection {
                    provider: DatabaseProvider::Postgresql,
                    plugin_id: None,
                    connection_url: "postgresql://localhost:5432/app".into(),
                    username: "hb_manager".into(),
                    password: PrivateString("synthetic-manager".into()),
                    allowed_roles: BTreeSet::from(["templated".into()]),
                    password_authentication: PostgresqlPasswordAuthentication::Password,
                    root_rotation: None,
                },
            );
        service
            .publish_database(state)
            .map_err(|_| "publish database fixture")?;
        Ok((root, service, root_token))
    }

    #[test]
    fn role_api_persists_official_statement_fields_and_partial_updates() -> TestResult {
        use super::super::super::tests::call;
        let (_root, mut service, root_token) = configured_service()?;
        let creation = vec![
            "DO $$ BEGIN PERFORM 1; END $$;".to_owned(),
            "CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'"
                .to_owned(),
        ];
        let revocation =
            vec!["SELECT heptabao_provider.default_statement_revoke('{{name}}'::name)".to_owned()];
        assert_eq!(
            call(
                &mut service,
                "POST",
                "database/roles/templated",
                &root_token,
                json!({
                    "db_name":"local",
                    "creation_statements":creation,
                    "revocation_statements":revocation,
                    "rollback_statements":["DROP ROLE IF EXISTS \"{{name}}\""],
                    "renew_statements":["ALTER ROLE \"{{name}}\" VALID UNTIL '{{expiration}}'"],
                    "credential_type":"password",
                    "credential_config":{},
                    "default_ttl":120,
                    "max_ttl":600
                }),
            )
            .status,
            204
        );
        let read = call(
            &mut service,
            "GET",
            "database/roles/templated",
            &root_token,
            json!({}),
        );
        assert_eq!(read.status, 200);
        assert_eq!(read.body["data"]["db_name"], "local");
        assert_eq!(read.body["data"]["creation_statements"], json!(creation));
        assert_eq!(
            read.body["data"]["revocation_statements"],
            json!(revocation)
        );
        assert_eq!(read.body["data"]["credential_type"], "password");
        assert_eq!(read.body["data"]["credential_config"], json!({}));
        assert!(read.body["data"].get("provider_role").is_none());

        assert_eq!(
            call(
                &mut service,
                "POST",
                "database/roles/templated",
                &root_token,
                json!({"max_ttl":900}),
            )
            .status,
            204
        );
        let updated = call(
            &mut service,
            "GET",
            "database/roles/templated",
            &root_token,
            json!({}),
        );
        assert_eq!(updated.body["data"]["creation_statements"], json!(creation));
        assert_eq!(updated.body["data"]["max_ttl"], 900);

        for body in [
            json!({"credential_type":"rsa_private_key"}),
            json!({"credential_config":{"password_policy":"external"}}),
            json!({"provider_role":"app_reader"}),
            json!({"creation_statements":["SELECT '{{unsupported}}'"]}),
        ] {
            let rejected = call(
                &mut service,
                "POST",
                "database/roles/templated",
                &root_token,
                body,
            );
            assert_eq!(rejected.status, 400);
            let unchanged = call(
                &mut service,
                "GET",
                "database/roles/templated",
                &root_token,
                json!({}),
            );
            assert_eq!(unchanged.body, updated.body);
        }
        Ok(())
    }

    #[test]
    fn statement_state_requires_schema54_and_remains_valid_under_schema55() -> TestResult {
        use super::super::super::tests::call;
        let (_root, mut service, root_token) = configured_service()?;
        let legacy = service.state.clone().ok_or("legacy state")?;
        let mut legacy53 = legacy.clone();
        legacy53.schema = 53;
        assert!(legacy53.validate_format().is_ok());

        assert_eq!(
            call(
                &mut service,
                "POST",
                "database/roles/templated",
                &root_token,
                json!({
                    "db_name":"local",
                    "creation_statements":["CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'"],
                    "default_ttl":60,
                    "max_ttl":300
                }),
            )
            .status,
            204
        );
        let state = service.state.clone().ok_or("statement state")?;
        assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
        assert!(state.database.has_statement_template_state());
        assert!(state.validate_format().is_ok());
        let bytes = serde_json::to_vec(&state)?;
        let reopened: State = serde_json::from_slice(&bytes)?;
        assert!(reopened.validate_format().is_ok());
        assert_eq!(bytes, serde_json::to_vec(&reopened)?);

        let mut statement54 = state.clone();
        statement54.schema = 54;
        assert!(statement54.validate_format().is_ok());

        let mut downgraded = state;
        downgraded.schema = 53;
        let error = downgraded
            .validate_format()
            .err()
            .ok_or("statement downgrade admitted")?;
        assert_eq!(error.status, 503);
        assert_eq!(
            error.body["errors"][0],
            "database statement templates require schema 54"
        );
        Ok(())
    }

    #[test]
    fn scram_connection_requires_schema55_while_default_connection_remains_schema54() -> TestResult
    {
        let (_root, service, _) = configured_service()?;
        let mut state = service.state.clone().ok_or("state")?;
        state.schema = 54;
        assert!(state.validate_format().is_ok());
        let connection = state
            .database
            .mount_mut("", "database/")
            .connections
            .get_mut("local")
            .ok_or("connection")?;
        connection.password_authentication = PostgresqlPasswordAuthentication::ScramSha256;
        let error = state
            .validate_format()
            .err()
            .ok_or("schema54 admitted SCRAM")?;
        assert_eq!(error.status, 503);
        assert_eq!(
            error.body["errors"][0],
            "PostgreSQL SCRAM password authentication requires schema 55"
        );
        state.schema = CURRENT_STATE_SCHEMA;
        assert!(state.validate_format().is_ok());
        let bytes = serde_json::to_vec(&state)?;
        assert!(
            bytes
                .windows(b"scram-sha-256".len())
                .any(|window| window == b"scram-sha-256")
        );
        let reopened: State = serde_json::from_slice(&bytes)?;
        assert!(reopened.validate_format().is_ok());
        Ok(())
    }

    #[test]
    fn statement_digest_is_domain_separated_and_legacy_digest_is_unchanged() -> TestResult {
        use base64::Engine as _;
        let owner = LeaseOwner::service(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
        )?;
        let mut lease = DatabaseLease {
            id: "database/creds/templated/001122".into(),
            provider_id: "hb1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            username: format!("hbp_{}", "ab".repeat(16)),
            db_name: "local".into(),
            provider_role: "app_reader".into(),
            statements: DatabaseStatements::default(),
            owner,
            issued: 100,
            expires: 200,
            max_expires: 400,
            last_renewal: None,
            seq: 9,
            phase: Phase::PendingIssue,
            password: Some(PrivateString("cd".repeat(32))),
            provider_password: None,
            request_digest: String::new(),
        };
        let legacy_bytes = Zeroizing::new(serde_json::to_vec(&(
            lease.id.as_str(),
            lease.provider_id.as_str(),
            lease.username.as_str(),
            lease.seq,
            action(&lease),
            lease.expires,
            lease.provider_role.as_str(),
            lease
                .password
                .as_ref()
                .map(|password| password.0.as_str())
                .unwrap_or(""),
        ))?);
        let legacy_digest = hex(&crypto::digest(&legacy_bytes));
        assert_eq!(
            digest_lease(&lease).map_err(|_| "legacy digest")?.as_str(),
            legacy_digest
        );

        lease.provider_role.clear();
        lease.statements.creation = vec![
            "CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'"
                .into(),
        ];
        lease.request_digest = digest_lease(&lease).map_err(|_| "statement digest")?;
        assert_ne!(lease.request_digest, legacy_digest);
        let restored: DatabaseLease = serde_json::from_slice(&serde_json::to_vec(&lease)?)?;
        assert_eq!(
            digest_lease(&restored).map_err(|_| "restored digest")?,
            lease.request_digest
        );
        Ok(())
    }
}
