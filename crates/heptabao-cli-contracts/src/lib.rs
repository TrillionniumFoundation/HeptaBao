#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! CLI parsing contracts that prohibit secret material in process arguments.

use std::error::Error;
use std::fmt;

use heptabao_domain::{CanonicalPath, Id};

pub const MAX_ARGUMENTS: usize = 128;
pub const MAX_ARGUMENT_BYTES: usize = 4096;

const SENSITIVE_FLAGS: &[&str] = &[
    "--token",
    "--secret",
    "--password",
    "--unseal-key",
    "--recovery-key",
    "--client-key",
];

const SENSITIVE_ASSIGNMENTS: &[&str] = &[
    "HEPTABAO_TOKEN=",
    "HEPTABAO_SECRET=",
    "HEPTABAO_PASSWORD=",
    "VAULT_TOKEN=",
];

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct EnvironmentName(String);

impl EnvironmentName {
    pub fn parse(value: impl Into<String>) -> Result<Self, CliError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 {
            return Err(CliError::InvalidEnvironmentName);
        }
        let mut bytes = value.bytes();
        let first = bytes.next().ok_or(CliError::InvalidEnvironmentName)?;
        if !(first.is_ascii_uppercase() || first == b'_')
            || !bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(CliError::InvalidEnvironmentName);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EnvironmentName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnvironmentName([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum SecretInput {
    StandardInput,
    InheritedFileDescriptor(u32),
    EnvironmentVariable(EnvironmentName),
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StandardInput => formatter.write_str("StandardInput"),
            Self::InheritedFileDescriptor(fd) => formatter
                .debug_tuple("InheritedFileDescriptor")
                .field(fd)
                .finish(),
            Self::EnvironmentVariable(_) => formatter.write_str("EnvironmentVariable([REDACTED])"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputMode {
    Human,
    Json,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CliInvocation {
    pub command: Id,
    pub target: Option<CanonicalPath>,
    pub secret_input: Option<SecretInput>,
    pub output: OutputMode,
}

impl CliInvocation {
    pub fn parse(arguments: &[String]) -> Result<Self, CliError> {
        if arguments.is_empty() || arguments.len() > MAX_ARGUMENTS {
            return Err(CliError::InvalidArgumentCount);
        }
        let mut command = None;
        let mut target = None;
        let mut secret_input = None;
        let mut output = OutputMode::Human;

        for argument in arguments {
            validate_argument_bytes(argument)?;
            reject_secret_argument(argument)?;
            if argument == "--secret-stdin" {
                set_secret_input(&mut secret_input, SecretInput::StandardInput)?;
            } else if let Some(value) = argument.strip_prefix("--secret-fd=") {
                let fd = value
                    .parse::<u32>()
                    .map_err(|_| CliError::InvalidFileDescriptor)?;
                if !(3..=1024).contains(&fd) {
                    return Err(CliError::InvalidFileDescriptor);
                }
                set_secret_input(&mut secret_input, SecretInput::InheritedFileDescriptor(fd))?;
            } else if let Some(value) = argument.strip_prefix("--secret-env=") {
                set_secret_input(
                    &mut secret_input,
                    SecretInput::EnvironmentVariable(EnvironmentName::parse(value)?),
                )?;
            } else if let Some(value) = argument.strip_prefix("--target=") {
                if target.is_some() {
                    return Err(CliError::DuplicateOption);
                }
                target =
                    Some(CanonicalPath::parse(value).map_err(|_| CliError::InvalidTargetPath)?);
            } else if let Some(value) = argument.strip_prefix("--output=") {
                output = match value {
                    "human" => OutputMode::Human,
                    "json" => OutputMode::Json,
                    _ => return Err(CliError::InvalidOutputMode),
                };
            } else if argument.starts_with('-') {
                return Err(CliError::UnknownOption);
            } else if command.is_some() {
                return Err(CliError::UnexpectedPositionalArgument);
            } else {
                command = Some(Id::parse(argument).map_err(|_| CliError::InvalidCommand)?);
            }
        }

        Ok(Self {
            command: command.ok_or(CliError::MissingCommand)?,
            target,
            secret_input,
            output,
        })
    }
}

impl fmt::Debug for CliInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CliInvocation")
            .field("command", &self.command)
            .field("target", &self.target.as_ref().map(|_| "[REDACTED]"))
            .field("secret_input", &self.secret_input)
            .field("output", &self.output)
            .finish()
    }
}

fn set_secret_input(
    current: &mut Option<SecretInput>,
    candidate: SecretInput,
) -> Result<(), CliError> {
    if current.is_some() {
        return Err(CliError::MultipleSecretSources);
    }
    *current = Some(candidate);
    Ok(())
}

fn validate_argument_bytes(argument: &str) -> Result<(), CliError> {
    if argument.is_empty()
        || argument.len() > MAX_ARGUMENT_BYTES
        || argument
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0x7f)
    {
        return Err(CliError::InvalidArgumentBytes);
    }
    Ok(())
}

fn reject_secret_argument(argument: &str) -> Result<(), CliError> {
    let lower = argument.to_ascii_lowercase();
    if SENSITIVE_FLAGS.iter().any(|flag| {
        lower == *flag
            || lower
                .strip_prefix(flag)
                .is_some_and(|suffix| suffix.starts_with('='))
    }) || SENSITIVE_ASSIGNMENTS
        .iter()
        .any(|prefix| argument.starts_with(prefix))
    {
        return Err(CliError::SecretInArguments);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliError {
    InvalidArgumentCount,
    InvalidArgumentBytes,
    SecretInArguments,
    MissingCommand,
    InvalidCommand,
    InvalidTargetPath,
    InvalidFileDescriptor,
    InvalidEnvironmentName,
    MultipleSecretSources,
    DuplicateOption,
    InvalidOutputMode,
    UnknownOption,
    UnexpectedPositionalArgument,
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgumentCount => "CLI argument count is invalid",
            Self::InvalidArgumentBytes => "CLI argument bytes are invalid",
            Self::SecretInArguments => "secret material is prohibited in CLI arguments",
            Self::MissingCommand => "CLI command is missing",
            Self::InvalidCommand => "CLI command is invalid",
            Self::InvalidTargetPath => "CLI target path is invalid",
            Self::InvalidFileDescriptor => "CLI secret file descriptor is invalid",
            Self::InvalidEnvironmentName => "CLI secret environment name is invalid",
            Self::MultipleSecretSources => "multiple CLI secret sources are prohibited",
            Self::DuplicateOption => "CLI option is duplicated",
            Self::InvalidOutputMode => "CLI output mode is invalid",
            Self::UnknownOption => "CLI option is unknown",
            Self::UnexpectedPositionalArgument => "unexpected CLI positional argument",
        })
    }
}

impl Error for CliError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn secret_bearing_arguments_fail_closed() {
        for arguments in [
            args(&["read", "--token=real-secret"]),
            args(&["read", "--password", "real-secret"]),
            args(&["read", "VAULT_TOKEN=real-secret"]),
        ] {
            assert_eq!(
                Err(CliError::SecretInArguments),
                CliInvocation::parse(&arguments)
            );
        }
    }

    #[test]
    fn indirect_secret_sources_are_explicit_and_exclusive() -> Result<(), Box<dyn Error>> {
        let stdin = CliInvocation::parse(&args(&[
            "write",
            "--target=/secret/app",
            "--secret-stdin",
            "--output=json",
        ]))?;
        assert_eq!(Some(SecretInput::StandardInput), stdin.secret_input);
        assert_eq!(OutputMode::Json, stdin.output);

        let fd = CliInvocation::parse(&args(&["write", "--secret-fd=9"]))?;
        assert_eq!(
            Some(SecretInput::InheritedFileDescriptor(9)),
            fd.secret_input
        );

        assert_eq!(
            Err(CliError::MultipleSecretSources),
            CliInvocation::parse(&args(&[
                "write",
                "--secret-stdin",
                "--secret-env=HEPTABAO_TOKEN_FD"
            ]))
        );
        Ok(())
    }

    #[test]
    fn environment_source_carries_only_a_valid_name() -> Result<(), Box<dyn Error>> {
        let invocation = CliInvocation::parse(&args(&["write", "--secret-env=HEPTABAO_TOKEN_FD"]))?;
        match invocation.secret_input {
            Some(SecretInput::EnvironmentVariable(name)) => {
                assert_eq!("HEPTABAO_TOKEN_FD", name.as_str());
            }
            _ => {
                return Err(std::io::Error::other("environment source was not selected").into());
            }
        }
        assert_eq!(
            Err(CliError::InvalidEnvironmentName),
            EnvironmentName::parse("HEPTABAO_TOKEN=secret")
        );
        Ok(())
    }

    #[test]
    fn debug_output_redacts_target_and_environment_name() -> Result<(), Box<dyn Error>> {
        let invocation = CliInvocation::parse(&args(&[
            "write",
            "--target=/secret/private/customer",
            "--secret-env=HEPTABAO_TOKEN_FD",
        ]))?;
        let rendered = format!("{invocation:?}");
        assert!(!rendered.contains("/secret/private/customer"));
        assert!(!rendered.contains("HEPTABAO_TOKEN_FD"));
        assert!(rendered.contains("[REDACTED]"));
        Ok(())
    }
}
