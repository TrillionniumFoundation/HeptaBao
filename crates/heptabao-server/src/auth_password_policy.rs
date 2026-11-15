//! Namespace-owned OpenBao-compatible password policies.
//!
//! The durable owner stores the reviewed HCL source. Parsing is repeated at
//! validation/generation boundaries so malformed restored state cannot become
//! an authority. Only OpenBao 2.6.2's password-policy grammar is admitted:
//! `length` and `rule "charset" { charset, min-chars }`.
use super::*;
use ring::rand::{SecureRandom, SystemRandom};

const MAX_PASSWORD_POLICY_SOURCE_BYTES: usize = 64 * 1024;
const MAX_PASSWORD_POLICY_COUNT: usize = 128;
const MAX_PASSWORD_POLICY_RULES: usize = 64;
const MIN_PASSWORD_LENGTH: usize = 4;
const MAX_PASSWORD_LENGTH: usize = 100;
const MAX_PASSWORD_CHARSET: usize = 255;
const DEFAULT_PASSWORD_LENGTH: usize = 20;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PasswordPolicy {
    source: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CharsetRule {
    charset: Vec<char>,
    min_chars: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PasswordPolicySpec {
    length: usize,
    rules: Vec<CharsetRule>,
    charset: Vec<char>,
}

fn default_spec() -> PasswordPolicySpec {
    let rules = [
        ("abcdefghijklmnopqrstuvwxyz", 1),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1),
        ("0123456789", 1),
        ("-", 1),
    ]
    .into_iter()
    .map(|(charset, min_chars)| CharsetRule {
        charset: charset.chars().collect(),
        min_chars,
    })
    .collect::<Vec<_>>();
    let charset = deduplicated_charset(rules.iter().flat_map(|rule| rule.charset.iter().copied()));
    PasswordPolicySpec {
        length: DEFAULT_PASSWORD_LENGTH,
        rules,
        charset,
    }
}

fn deduplicated_charset(chars: impl IntoIterator<Item = char>) -> Vec<char> {
    let mut seen = BTreeSet::new();
    chars
        .into_iter()
        .filter(|value| seen.insert(*value))
        .collect()
}

fn take_number(tokens: &[Lex], cursor: &mut usize) -> Result<usize, AuthError> {
    let Some(Lex::Number(value)) = tokens.get(*cursor) else {
        return Err(bad("password policy integer required"));
    };
    *cursor += 1;
    usize::try_from(*value).map_err(|_| bad("password policy integer exceeds platform bound"))
}

fn parse_password_policy(source: &str) -> Result<PasswordPolicySpec, AuthError> {
    if source.is_empty() || source.len() > MAX_PASSWORD_POLICY_SOURCE_BYTES {
        return Err(bad("password policy source is empty or too large"));
    }
    let tokens = lex_hcl(source)?;
    let mut cursor = 0usize;
    let mut length = None;
    let mut rules = Vec::new();
    while cursor < tokens.len() {
        match tokens.get(cursor) {
            Some(Lex::Word(word)) if word == "length" => {
                cursor += 1;
                if length.is_some() {
                    return Err(bad("duplicate password policy length"));
                }
                take(&tokens, &mut cursor, Lex::Symbol('='))?;
                length = Some(take_number(&tokens, &mut cursor)?);
            }
            Some(Lex::Word(word)) if word == "rule" => {
                cursor += 1;
                let rule_type = take_string(&tokens, &mut cursor)?;
                if rule_type != "charset" {
                    return Err(bad("unsupported password policy rule type"));
                }
                take(&tokens, &mut cursor, Lex::Symbol('{'))?;
                let mut charset = None;
                let mut min_chars = None;
                while tokens.get(cursor) != Some(&Lex::Symbol('}')) {
                    let Some(Lex::Word(field)) = tokens.get(cursor) else {
                        return Err(bad("malformed password policy charset rule"));
                    };
                    let field = field.clone();
                    cursor += 1;
                    take(&tokens, &mut cursor, Lex::Symbol('='))?;
                    match field.as_str() {
                        "charset" => {
                            if charset.is_some() {
                                return Err(bad("duplicate password policy charset"));
                            }
                            charset = Some(take_string(&tokens, &mut cursor)?);
                        }
                        "min-chars" => {
                            if min_chars.is_some() {
                                return Err(bad("duplicate password policy min-chars"));
                            }
                            min_chars = Some(take_number(&tokens, &mut cursor)?);
                        }
                        _ => return Err(bad("unsupported password policy rule field")),
                    }
                    if cursor >= tokens.len() {
                        return Err(bad("unterminated password policy rule"));
                    }
                }
                take(&tokens, &mut cursor, Lex::Symbol('}'))?;
                let charset = charset.ok_or_else(|| bad("password policy charset is required"))?;
                let charset = deduplicated_charset(charset.chars());
                if charset.is_empty()
                    || charset.len() > MAX_PASSWORD_CHARSET
                    || charset.iter().any(|value| value.is_control())
                {
                    return Err(bad(
                        "password policy charset is empty, too large, or non-printable",
                    ));
                }
                rules.push(CharsetRule {
                    charset,
                    min_chars: min_chars.unwrap_or(0),
                });
                if rules.len() > MAX_PASSWORD_POLICY_RULES {
                    return Err(bad("too many password policy rules"));
                }
            }
            _ => return Err(bad("unsupported password policy field")),
        }
    }
    let length = length.ok_or_else(|| bad("password policy length is required"))?;
    if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&length) {
        return Err(bad(
            "password policy length must be between 4 and 100 characters",
        ));
    }
    let minimum = rules.iter().try_fold(0usize, |total, rule| {
        total
            .checked_add(rule.min_chars)
            .ok_or_else(|| bad("password policy minimum length overflow"))
    })?;
    if minimum > length {
        return Err(bad(
            "password policy rules require more characters than its length",
        ));
    }
    let charset = deduplicated_charset(rules.iter().flat_map(|rule| rule.charset.iter().copied()));
    if charset.is_empty() || charset.len() > MAX_PASSWORD_CHARSET {
        return Err(bad("password policy has no usable bounded charset"));
    }
    Ok(PasswordPolicySpec {
        length,
        rules,
        charset,
    })
}

fn random_index(random: &SystemRandom, bound: usize) -> Result<usize, AuthError> {
    if bound == 0 || bound > MAX_PASSWORD_CHARSET {
        return Err(err(503, "password generator bound is unavailable"));
    }
    let bound = u64::try_from(bound)
        .map_err(|_| err(503, "password generator bound exceeds platform range"))?;
    let accepted = u64::MAX - u64::MAX % bound;
    loop {
        let mut bytes = [0u8; 8];
        random
            .fill(&mut bytes)
            .map_err(|_| err(503, "operating system randomness unavailable"))?;
        let value = u64::from_le_bytes(bytes);
        if value < accepted {
            return usize::try_from(value % bound)
                .map_err(|_| err(503, "password generator index exceeds platform range"));
        }
    }
}

fn generate_from_spec(spec: &PasswordPolicySpec) -> Result<String, AuthError> {
    let random = SystemRandom::new();
    let mut value = Vec::with_capacity(spec.length);
    for rule in &spec.rules {
        for _ in 0..rule.min_chars {
            value.push(rule.charset[random_index(&random, rule.charset.len())?]);
        }
    }
    while value.len() < spec.length {
        value.push(spec.charset[random_index(&random, spec.charset.len())?]);
    }
    // Fisher-Yates with rejection-sampled indexes. Required characters remain
    // guaranteed while their locations carry no deterministic structure.
    for index in (1..value.len()).rev() {
        let selected = random_index(&random, index + 1)?;
        value.swap(index, selected);
    }
    Ok(value.into_iter().collect())
}

impl PasswordPolicy {
    fn parse(source: String) -> Result<Self, AuthError> {
        parse_password_policy(&source)?;
        Ok(Self { source })
    }
    fn generate(&self) -> Result<String, AuthError> {
        generate_from_spec(&parse_password_policy(&self.source)?)
    }
}

impl AuthState {
    pub(crate) fn has_password_policy_state(&self) -> bool {
        self.password_policies
            .values()
            .any(|policies| !policies.is_empty())
    }

    pub(crate) fn validate_password_policy_state(&self) -> Result<(), AuthError> {
        if self.password_policies.len() > 1024 {
            return Err(err(503, "password policy namespace capacity exceeded"));
        }
        for (namespace, policies) in &self.password_policies {
            validate_namespace(namespace)?;
            if policies.len() > MAX_PASSWORD_POLICY_COUNT {
                return Err(err(503, "password policy capacity exceeded"));
            }
            for (name, policy) in policies {
                if !valid_name(name) || parse_password_policy(&policy.source).is_err() {
                    return Err(err(503, "invalid persisted password policy"));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn generate_database_password(
        &self,
        namespace: &str,
        policy_name: &str,
    ) -> Result<String, AuthError> {
        if policy_name.is_empty() {
            return generate_from_spec(&default_spec());
        }
        self.password_policies
            .get(namespace)
            .and_then(|policies| policies.get(policy_name))
            .ok_or_else(|| err(404, "password policy not found"))?
            .generate()
    }

    pub(super) fn password_policy_route(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let suffix = path
            .strip_prefix("sys/policies/password")
            .ok_or_else(|| bad("invalid password policy route"))?
            .trim_start_matches('/');
        let (name, generate) = suffix
            .strip_suffix("/generate")
            .map_or((suffix, false), |name| (name, true));
        let capability = match (method, name.is_empty(), generate) {
            ("LIST" | "GET", true, false) => "list",
            ("GET", false, true) => "read",
            ("GET", false, false) => "read",
            ("DELETE", false, false) => "delete",
            ("POST" | "PUT", false, false) => "update",
            _ => return Err(err(405, "method not allowed")),
        };
        let actor = self.permission(principal, namespace, path, capability, now)?;
        if name.is_empty() {
            reject_unknown(body, &[])?;
            let keys = self
                .password_policies
                .get(namespace)
                .map(|policies| policies.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            return Ok(response(json!({"keys":keys, "policies":keys}), false));
        }
        if !valid_name(name) {
            return Err(bad("invalid password policy name"));
        }
        if generate {
            reject_unknown(body, &[])?;
            let password = self.generate_database_password(namespace, name)?;
            return Ok(response(json!({"password":password}), false));
        }
        if capability == "read" {
            reject_unknown(body, &[])?;
            let policy = self
                .password_policies
                .get(namespace)
                .and_then(|policies| policies.get(name))
                .ok_or_else(|| err(404, "password policy not found"))?;
            return Ok(response(json!({"policy":policy.source}), false));
        }
        self.authorize_request(actor, namespace, path, "sudo", now)?;
        if capability == "delete" {
            reject_unknown(body, &[])?;
            let remove_namespace =
                self.password_policies
                    .get_mut(namespace)
                    .is_some_and(|policies| {
                        policies.remove(name);
                        policies.is_empty()
                    });
            if remove_namespace {
                self.password_policies.remove(namespace);
            }
            return Ok(empty(true));
        }
        reject_unknown(body, &["policy"])?;
        let source = body
            .get("policy")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("password policy is required"))?;
        let policy = PasswordPolicy::parse(source.to_owned())?;
        let policies = self.password_policies.entry(namespace.into()).or_default();
        if policies.len() >= MAX_PASSWORD_POLICY_COUNT && !policies.contains_key(name) {
            return Err(err(507, "password policy capacity exhausted"));
        }
        policies.insert(name.into(), policy);
        Ok(empty(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
        # OpenBao HCL subset
        length = 24
        rule "charset" { charset = "abc" min-chars = 3 }
        rule "charset" { charset = "XYZ" min-chars = 2 }
        rule "charset" { charset = "09-" min-chars = 1 }
    "#;

    #[test]
    fn password_policy_parser_and_generator_enforce_all_rules()
    -> Result<(), Box<dyn std::error::Error>> {
        let spec = parse_password_policy(POLICY)?;
        assert_eq!(spec.length, 24);
        for _ in 0..64 {
            let value = generate_from_spec(&spec)?;
            assert_eq!(value.chars().count(), 24);
            assert!(value.chars().filter(|value| "abc".contains(*value)).count() >= 3);
            assert!(value.chars().filter(|value| "XYZ".contains(*value)).count() >= 2);
            assert!(value.chars().filter(|value| "09-".contains(*value)).count() >= 1);
        }
        Ok(())
    }

    #[test]
    fn default_password_matches_openbao_262_shape() -> Result<(), Box<dyn std::error::Error>> {
        for _ in 0..64 {
            let value = generate_from_spec(&default_spec())?;
            assert_eq!(value.len(), 20);
            assert!(value.bytes().any(|value| value.is_ascii_lowercase()));
            assert!(value.bytes().any(|value| value.is_ascii_uppercase()));
            assert!(value.bytes().any(|value| value.is_ascii_digit()));
            assert!(value.contains('-'));
        }
        Ok(())
    }

    #[test]
    fn password_policy_charset_larger_than_password_length_is_supported()
    -> Result<(), Box<dyn std::error::Error>> {
        let charset: String = (0x21u8..=0x7eu8).map(char::from).collect();
        assert!(charset.chars().count() > 90);
        let source = format!(
            "length = 12\nrule \"charset\" {{ charset = {} min-chars = 12 }}",
            serde_json::to_string(&charset)?
        );
        let spec = parse_password_policy(&source)?;
        for _ in 0..32 {
            let value = generate_from_spec(&spec)?;
            assert_eq!(value.chars().count(), 12);
            assert!(value.chars().all(|character| charset.contains(character)));
        }
        Ok(())
    }

    #[test]
    fn malformed_password_policies_fail_closed() {
        for source in [
            "",
            "length = 0 rule \"charset\" { charset = \"a\" }",
            "length = 2 rule \"charset\" { charset = \"a\" min-chars = 3 }",
            "length = 8 rule \"unknown\" { charset = \"a\" }",
            "length = 8 rule \"charset\" { charset = \"\n\" }",
            "length = 8 mystery = 1 rule \"charset\" { charset = \"a\" }",
        ] {
            assert!(parse_password_policy(source).is_err(), "{source:?}");
        }
    }
}
