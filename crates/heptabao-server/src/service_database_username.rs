//! Bounded OpenBao 2.6.2 PostgreSQL username templates.
//!
//! OpenBao uses Go text/templates. This runtime admits the data/functions used
//! by the official PostgreSQL template and the pure string helpers useful for
//! bounded usernames. It deliberately rejects control flow, variable binding,
//! template inclusion and ambient input rather than approximating them.
use super::*;
use ring::rand::{SecureRandom, SystemRandom};

pub(super) const DEFAULT_POSTGRESQL_USERNAME_TEMPLATE: &str = r#"{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 8) (.RoleName | truncate 8) (random 20) (unix_time) | truncate 63 }}"#;
const MAX_TEMPLATE_BYTES: usize = 4096;
const MAX_ACTION_TOKENS: usize = 256;
const MAX_TEMPLATE_DEPTH: usize = 16;
const MAX_FUNCTION_ARGUMENTS: usize = 32;
const MAX_INTERMEDIATE_BYTES: usize = 16 * 1024;
const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Ident(String),
    Field(String),
    String(String),
    Number(u64),
    Pipe,
    Open,
    Close,
}

#[derive(Clone, Debug)]
enum Value {
    Text(String),
    Number(u64),
    Function(String),
}
impl Value {
    fn text(self) -> Result<String, Response> {
        match self {
            Self::Text(value) => Ok(value),
            Self::Number(value) => Ok(value.to_string()),
            Self::Function(_) => Err(invalid("username template function used as a value")),
        }
    }
    fn number(self) -> Result<u64, Response> {
        match self {
            Self::Number(value) => Ok(value),
            Self::Text(value) => value
                .parse()
                .map_err(|_| invalid("username template integer argument required")),
            Self::Function(_) => Err(invalid("username template function used as an integer")),
        }
    }
}

#[derive(Clone, Copy)]
struct Metadata<'a> {
    display_name: &'a str,
    role_name: &'a str,
    now: u64,
}

fn tokenize(action: &str) -> Result<Vec<Token>, Response> {
    let bytes = action.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let token = match bytes[index] {
            b'|' => {
                index += 1;
                Token::Pipe
            }
            b'(' => {
                index += 1;
                Token::Open
            }
            b')' => {
                index += 1;
                Token::Close
            }
            b'"' => {
                let start = index;
                index += 1;
                let mut escaped = false;
                while index < bytes.len() {
                    if bytes[index] == b'"' && !escaped {
                        break;
                    }
                    escaped = bytes[index] == b'\\' && !escaped;
                    index += 1;
                }
                if index >= bytes.len() {
                    return Err(invalid("unterminated username template string"));
                }
                index += 1;
                let value = serde_json::from_str::<String>(&action[start..index])
                    .map_err(|_| invalid("invalid username template string escape"))?;
                Token::String(value)
            }
            b'.' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                if index == start + 1 {
                    return Err(invalid("invalid username template field"));
                }
                Token::Field(action[start..index].to_owned())
            }
            value if value.is_ascii_digit() => {
                let start = index;
                while index < bytes.len() && bytes[index].is_ascii_digit() {
                    index += 1;
                }
                Token::Number(
                    action[start..index]
                        .parse()
                        .map_err(|_| invalid("username template integer exceeds range"))?,
                )
            }
            value if value.is_ascii_alphabetic() || value == b'_' => {
                let start = index;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                Token::Ident(action[start..index].to_owned())
            }
            _ => return Err(invalid("unsupported username template character")),
        };
        tokens.push(token);
        if tokens.len() > MAX_ACTION_TOKENS {
            return Err(invalid("username template action exceeds token bound"));
        }
    }
    if tokens.is_empty() {
        return Err(invalid("username template action is empty"));
    }
    Ok(tokens)
}

struct Evaluator<'a> {
    tokens: &'a [Token],
    cursor: usize,
    metadata: Metadata<'a>,
    random: SystemRandom,
}
impl Evaluator<'_> {
    fn pipeline(&mut self, depth: usize) -> Result<Value, Response> {
        if depth > MAX_TEMPLATE_DEPTH {
            return Err(invalid("username template nesting exceeds bound"));
        }
        let mut value = self.command(None, depth)?;
        while self.tokens.get(self.cursor) == Some(&Token::Pipe) {
            self.cursor += 1;
            value = self.command(Some(value), depth)?;
        }
        Ok(value)
    }

    fn command(&mut self, piped: Option<Value>, depth: usize) -> Result<Value, Response> {
        let head = self.primary(depth)?;
        let (function, mut arguments) = match head {
            Value::Function(function) => (Some(function), Vec::new()),
            value => (None, vec![value]),
        };
        while self.cursor < self.tokens.len()
            && !matches!(self.tokens[self.cursor], Token::Pipe | Token::Close)
        {
            arguments.push(self.primary(depth)?);
            if arguments.len() > MAX_FUNCTION_ARGUMENTS {
                return Err(invalid("username template function has too many arguments"));
            }
        }
        if let Some(value) = piped {
            arguments.push(value);
        }
        match function {
            Some(function) => self.call(&function, arguments),
            None if arguments.len() == 1 => Ok(arguments.remove(0)),
            None => Err(invalid("username template value cannot take arguments")),
        }
    }

    fn primary(&mut self, depth: usize) -> Result<Value, Response> {
        let token = self
            .tokens
            .get(self.cursor)
            .cloned()
            .ok_or_else(|| invalid("username template expression ended early"))?;
        self.cursor += 1;
        match token {
            Token::String(value) => Ok(Value::Text(value)),
            Token::Number(value) => Ok(Value::Number(value)),
            Token::Field(field) => match field.as_str() {
                ".DisplayName" => Ok(Value::Text(self.metadata.display_name.to_owned())),
                ".RoleName" => Ok(Value::Text(self.metadata.role_name.to_owned())),
                _ => Err(invalid("unsupported username template metadata field")),
            },
            Token::Ident(function) => Ok(Value::Function(function)),
            Token::Open => {
                let value = self.pipeline(depth + 1)?;
                if self.tokens.get(self.cursor) != Some(&Token::Close) {
                    return Err(invalid("unterminated username template expression"));
                }
                self.cursor += 1;
                Ok(value)
            }
            _ => Err(invalid("unexpected username template token")),
        }
    }

    fn call(&self, encoded: &str, args: Vec<Value>) -> Result<Value, Response> {
        let function = encoded;
        let value = match function {
            "random" => {
                let [length] = args
                    .try_into()
                    .map_err(|_| invalid("random requires one length"))?;
                let length = usize::try_from(length.number()?)
                    .map_err(|_| invalid("random length exceeds platform range"))?;
                if length == 0 || length > 128 {
                    return Err(invalid("random length is outside 1..128"));
                }
                let mut value = String::with_capacity(length);
                while value.len() < length {
                    let mut byte = [0u8; 1];
                    self.random
                        .fill(&mut byte)
                        .map_err(|_| failure("operating system randomness unavailable"))?;
                    let accepted = (256 / BASE62.len()) * BASE62.len();
                    if usize::from(byte[0]) < accepted {
                        value.push(char::from(BASE62[usize::from(byte[0]) % BASE62.len()]));
                    }
                }
                value
            }
            "unix_time" => {
                if !args.is_empty() {
                    return Err(invalid("unix_time takes no arguments"));
                }
                self.metadata.now.to_string()
            }
            "unix_time_millis" => {
                if !args.is_empty() {
                    return Err(invalid("unix_time_millis takes no arguments"));
                }
                self.metadata
                    .now
                    .checked_mul(1000)
                    .ok_or_else(|| invalid("unix time milliseconds overflow"))?
                    .to_string()
            }
            "truncate" => {
                let [maximum, value] = args
                    .try_into()
                    .map_err(|_| invalid("truncate requires length and string"))?;
                let maximum = usize::try_from(maximum.number()?)
                    .map_err(|_| invalid("truncate length exceeds platform range"))?;
                let value = value.text()?;
                if maximum == 0 {
                    return Err(invalid("truncate length must be positive"));
                }
                if value.len() <= maximum {
                    value
                } else {
                    value
                        .get(..maximum)
                        .ok_or_else(|| invalid("truncate would split a UTF-8 codepoint"))?
                        .to_owned()
                }
            }
            "truncate_sha256" => {
                let [maximum, value] = args
                    .try_into()
                    .map_err(|_| invalid("truncate_sha256 requires length and string"))?;
                let maximum = usize::try_from(maximum.number()?)
                    .map_err(|_| invalid("truncate_sha256 length exceeds platform range"))?;
                let value = value.text()?;
                if maximum <= 8 {
                    return Err(invalid("truncate_sha256 length must exceed 8"));
                }
                if value.len() <= maximum {
                    value
                } else {
                    let split = maximum - 8;
                    let prefix = value
                        .get(..split)
                        .ok_or_else(|| invalid("truncate_sha256 would split a UTF-8 codepoint"))?;
                    let suffix = value
                        .get(split..)
                        .ok_or_else(|| invalid("truncate_sha256 would split a UTF-8 codepoint"))?;
                    format!("{prefix}{}", &hex(&crypto::digest(suffix.as_bytes()))[..8])
                }
            }
            "uppercase" | "lowercase" | "sha256" | "base64" | "hex" => {
                let [value] = args
                    .try_into()
                    .map_err(|_| invalid("string function requires one argument"))?;
                let value = value.text()?;
                match function {
                    "uppercase" => value.to_uppercase(),
                    "lowercase" => value.to_lowercase(),
                    "sha256" => hex(&crypto::digest(value.as_bytes())),
                    "base64" => STANDARD.encode(value.as_bytes()),
                    "hex" => hex(value.as_bytes()),
                    _ => unreachable!(),
                }
            }
            "decode_base64" => {
                let [value] = args
                    .try_into()
                    .map_err(|_| invalid("decode_base64 requires one argument"))?;
                String::from_utf8(
                    STANDARD
                        .decode(value.text()?)
                        .map_err(|_| invalid("invalid base64 in username template"))?,
                )
                .map_err(|_| invalid("decoded base64 username is not UTF-8"))?
            }
            "decode_hex" => {
                let [value] = args
                    .try_into()
                    .map_err(|_| invalid("decode_hex requires one argument"))?;
                decode_hex(&value.text()?)?
            }
            "replace" => {
                let [find, replacement, value] = args
                    .try_into()
                    .map_err(|_| invalid("replace requires find, replacement and string"))?;
                value.text()?.replace(&find.text()?, &replacement.text()?)
            }
            "printf" => format_printf(args)?,
            "uuid" => {
                if !args.is_empty() {
                    return Err(invalid("uuid takes no arguments"));
                }
                let mut bytes = [0u8; 16];
                self.random
                    .fill(&mut bytes)
                    .map_err(|_| failure("operating system randomness unavailable"))?;
                bytes[6] = bytes[6] & 0x0f | 0x40;
                bytes[8] = bytes[8] & 0x3f | 0x80;
                let value = hex(&bytes);
                format!(
                    "{}-{}-{}-{}-{}",
                    &value[..8],
                    &value[8..12],
                    &value[12..16],
                    &value[16..20],
                    &value[20..]
                )
            }
            _ => return Err(invalid("unsupported username template function")),
        };
        if value.len() > MAX_INTERMEDIATE_BYTES {
            return Err(invalid(
                "username template intermediate value exceeds bound",
            ));
        }
        Ok(Value::Text(value))
    }
}

fn decode_hex(value: &str) -> Result<String, Response> {
    if !value.len().is_multiple_of(2) || value.len() > MAX_INTERMEDIATE_BYTES * 2 {
        return Err(invalid("invalid hex in username template"));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for chunk in pairs {
        let text =
            std::str::from_utf8(chunk).map_err(|_| invalid("invalid hex in username template"))?;
        bytes.push(
            u8::from_str_radix(text, 16)
                .map_err(|_| invalid("invalid hex in username template"))?,
        );
    }
    String::from_utf8(bytes).map_err(|_| invalid("decoded hex username is not UTF-8"))
}

fn format_printf(mut args: Vec<Value>) -> Result<String, Response> {
    if args.is_empty() {
        return Err(invalid("printf requires a format string"));
    }
    let format = args.remove(0).text()?;
    let mut values = args.into_iter();
    let mut result = String::new();
    let bytes = format.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            result.push(char::from(bytes[index]));
            index += 1;
            continue;
        }
        index += 1;
        let Some(specifier) = bytes.get(index).copied() else {
            return Err(invalid("unterminated printf directive"));
        };
        index += 1;
        match specifier {
            b'%' => result.push('%'),
            b's' => result.push_str(
                &values
                    .next()
                    .ok_or_else(|| invalid("printf argument missing"))?
                    .text()?,
            ),
            b'd' => result.push_str(
                &values
                    .next()
                    .ok_or_else(|| invalid("printf argument missing"))?
                    .number()?
                    .to_string(),
            ),
            b'q' => result.push_str(
                &serde_json::to_string(
                    &values
                        .next()
                        .ok_or_else(|| invalid("printf argument missing"))?
                        .text()?,
                )
                .map_err(|_| invalid("printf quoting failed"))?,
            ),
            _ => return Err(invalid("unsupported printf directive")),
        }
        if result.len() > MAX_INTERMEDIATE_BYTES {
            return Err(invalid("printf output exceeds bound"));
        }
    }
    if values.next().is_some() {
        return Err(invalid("printf received unused arguments"));
    }
    Ok(result)
}

fn render_action(action: &str, metadata: Metadata<'_>) -> Result<String, Response> {
    let tokens = tokenize(action)?;
    let mut evaluator = Evaluator {
        tokens: &tokens,
        cursor: 0,
        metadata,
        random: SystemRandom::new(),
    };
    let value = evaluator.pipeline(0)?.text()?;
    if evaluator.cursor != tokens.len() {
        return Err(invalid("username template has trailing tokens"));
    }
    Ok(value)
}

pub(super) fn render_username_template(
    source: &str,
    display_name: &str,
    role_name: &str,
    now: u64,
) -> Result<String, Response> {
    if source.is_empty() || source.len() > MAX_TEMPLATE_BYTES {
        return Err(invalid("username_template is empty or too large"));
    }
    let metadata = Metadata {
        display_name,
        role_name,
        now,
    };
    let mut result = String::new();
    let mut cursor = 0usize;
    while cursor < source.len() {
        let Some(open) = source[cursor..].find("{{").map(|value| cursor + value) else {
            result.push_str(&source[cursor..]);
            break;
        };
        if source[cursor..open].contains("}}") {
            return Err(invalid(
                "username template has an unmatched close delimiter",
            ));
        }
        result.push_str(&source[cursor..open]);
        let close = source[open + 2..]
            .find("}}")
            .map(|value| open + 2 + value)
            .ok_or_else(|| invalid("username template has an unterminated action"))?;
        let action = &source[open + 2..close];
        if action.contains("{{") {
            return Err(invalid("username template actions cannot nest delimiters"));
        }
        result.push_str(&render_action(action, metadata)?);
        cursor = close + 2;
        if result.len() > MAX_INTERMEDIATE_BYTES {
            return Err(invalid("username template output exceeds bound"));
        }
    }
    if result.contains("}}") {
        return Err(invalid(
            "username template has an unmatched close delimiter",
        ));
    }
    if result.is_empty()
        || result.len() > 63
        || !result.is_ascii()
        || result
            .bytes()
            .any(|value| value == 0 || value.is_ascii_control())
    {
        return Err(invalid(
            "PostgreSQL username template must produce 1..63 printable ASCII bytes",
        ));
    }
    Ok(result)
}

pub(super) fn validate_username_template(source: &str) -> Result<(), Response> {
    render_username_template(source, "display-name", "role-name", 1).map(|_| ())
}

pub(super) fn generate_database_username(
    provider: DatabaseProvider,
    template: &str,
    display_name: &str,
    role_name: &str,
    now: u64,
    entropy: &[u8; 16],
) -> Result<String, Response> {
    match provider {
        DatabaseProvider::Postgresql if template.is_empty() => {
            let encoded = hex(entropy);
            Ok(format!("hbp_{}", &encoded[..32]))
        }
        DatabaseProvider::Postgresql => {
            render_username_template(template, display_name, role_name, now)
        }
        DatabaseProvider::Valkey | DatabaseProvider::Plugin => {
            if !template.is_empty() {
                return Err(invalid("username_template is supported only by PostgreSQL"));
            }
            let encoded = hex(entropy);
            let digits = if provider == DatabaseProvider::Plugin {
                28
            } else {
                32
            };
            Ok(format!("hbp_{}", &encoded[..digits]))
        }
    }
}

pub(super) fn valid_database_username(provider: DatabaseProvider, value: &str) -> bool {
    match provider {
        DatabaseProvider::Postgresql => {
            (value.starts_with("hbp_")
                && value.len() == 36
                && value[4..].bytes().all(|byte| byte.is_ascii_hexdigit()))
                || (!value.is_empty()
                    && value.len() <= 63
                    && value.is_ascii()
                    && !value
                        .bytes()
                        .any(|byte| byte == 0 || byte.is_ascii_control()))
        }
        DatabaseProvider::Valkey => {
            value.starts_with("hbp_")
                && value.len() == 36
                && value[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
        }
        DatabaseProvider::Plugin => {
            value.starts_with("hbp_")
                && value.len() == 32
                && value[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_default_template_matches_postgresql_shape() -> Result<(), String> {
        for _ in 0..64 {
            let value = render_username_template(
                DEFAULT_POSTGRESQL_USERNAME_TEMPLATE,
                "display-name-too-long",
                "role-name-too-long",
                1_700_000_000,
            )
            .map_err(|error| format!("official default failed with status {}", error.status))?;
            assert!(value.starts_with("v-display--role-nam-"), "{value}");
            assert!(value.ends_with("-1700000000"), "{value}");
            assert!(value.len() <= 63);
        }
        Ok(())
    }

    #[test]
    fn custom_pipeline_and_pure_helpers_are_bounded() -> Result<(), String> {
        let value = render_username_template(
            r#"pg-{{ .DisplayName | uppercase | truncate 4 }}-{{ .RoleName | sha256 | truncate 8 }}-{{ random 6 }}"#,
            "alice",
            "reader",
            100,
        )
        .map_err(|error| format!("custom template failed with status {}", error.status))?;
        assert!(value.starts_with("pg-ALIC-3d094196-"), "{value}");
        assert_eq!(value.len(), "pg-ALIC-3d094196-".len() + 6);
        Ok(())
    }

    #[test]
    fn invalid_templates_fail_closed() {
        for source in [
            "",
            "{{ unknown 1 }}",
            "{{ .Missing }}",
            "{{ random 0 }}",
            "{{ printf \"%v\" \"x\" }}",
            "{{ if .DisplayName }}x{{ end }}",
            "{{ .DisplayName",
            "x}}",
            &"x".repeat(64),
        ] {
            assert!(validate_username_template(source).is_err(), "{source:?}");
        }
    }
}
