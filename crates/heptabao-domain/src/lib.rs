#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Shared bounded identifiers, canonical paths, monotonic ticks and secret values.

use std::error::Error;
use std::fmt;

pub const MAX_ID_BYTES: usize = 64;
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_SECRET_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainError {
    EmptyIdentifier,
    IdentifierTooLong,
    InvalidIdentifierCharacter,
    InvalidIdentifierBoundary,
    EmptyPath,
    PathTooLong,
    PathMustBeAbsolute,
    InvalidPathSegment,
    InvalidPathCharacter,
    EmptySecret,
    SecretTooLarge,
    TickOverflow,
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyIdentifier => "identifier is empty",
            Self::IdentifierTooLong => "identifier is too long",
            Self::InvalidIdentifierCharacter => "identifier contains an invalid character",
            Self::InvalidIdentifierBoundary => "identifier has an invalid boundary",
            Self::EmptyPath => "path is empty",
            Self::PathTooLong => "path is too long",
            Self::PathMustBeAbsolute => "path must be absolute",
            Self::InvalidPathSegment => "path contains an invalid segment",
            Self::InvalidPathCharacter => "path contains an invalid character",
            Self::EmptySecret => "secret value is empty",
            Self::SecretTooLarge => "secret value is too large",
            Self::TickOverflow => "monotonic tick overflow",
        })
    }
}

impl Error for DomainError {}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Id(String);

impl Id {
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DomainError::EmptyIdentifier);
        }
        if value.len() > MAX_ID_BYTES {
            return Err(DomainError::IdentifierTooLong);
        }
        if value.starts_with('-')
            || value.starts_with('_')
            || value.ends_with('-')
            || value.ends_with('_')
        {
            return Err(DomainError::InvalidIdentifierBoundary);
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        }) {
            return Err(DomainError::InvalidIdentifierCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Id").field(&self.0).finish()
    }
}

impl fmt::Display for Id {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalPath(String);

impl CanonicalPath {
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DomainError::EmptyPath);
        }
        if value.len() > MAX_PATH_BYTES {
            return Err(DomainError::PathTooLong);
        }
        if !value.starts_with('/') {
            return Err(DomainError::PathMustBeAbsolute);
        }
        if value == "/" {
            return Ok(Self(value));
        }
        if value.ends_with('/') {
            return Err(DomainError::InvalidPathSegment);
        }
        for segment in value.split('/').skip(1) {
            if segment.is_empty() || matches!(segment, "." | "..") {
                return Err(DomainError::InvalidPathSegment);
            }
            if !segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            }) {
                return Err(DomainError::InvalidPathCharacter);
            }
        }
        Ok(Self(value))
    }

    pub fn root() -> Self {
        Self("/".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn child(&self, child: &Id) -> Result<Self, DomainError> {
        let value = if self.0 == "/" {
            format!("/{}", child.as_str())
        } else {
            format!("{}/{}", self.0, child.as_str())
        };
        Self::parse(value)
    }

    pub fn matches_prefix(&self, prefix: &Self) -> bool {
        if prefix.0 == "/" {
            return true;
        }
        self.0 == prefix.0
            || self
                .0
                .strip_prefix(&prefix.0)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }

    pub fn relative_to<'a>(&'a self, prefix: &Self) -> Option<&'a str> {
        if self.0 == prefix.0 {
            return Some("");
        }
        self.0
            .strip_prefix(&prefix.0)
            .and_then(|suffix| suffix.strip_prefix('/'))
    }
}

impl fmt::Debug for CanonicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("CanonicalPath").field(&self.0).finish()
    }
}

impl fmt::Display for CanonicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Tick(u64);

impl Tick {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, delta: u64) -> Result<Self, DomainError> {
        self.0
            .checked_add(delta)
            .map(Self)
            .ok_or(DomainError::TickOverflow)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretValue {
    bytes: Vec<u8>,
}

impl SecretValue {
    pub fn new(bytes: Vec<u8>) -> Result<Self, DomainError> {
        if bytes.is_empty() {
            return Err(DomainError::EmptySecret);
        }
        if bytes.len() > MAX_SECRET_BYTES {
            return Err(DomainError::SecretTooLarge);
        }
        Ok(Self { bytes })
    }

    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretValue")
            .field("bytes", &"[REDACTED]")
            .field("length", &self.bytes.len())
            .finish()
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_and_path_validation_are_fail_closed() -> Result<(), DomainError> {
        let id = Id::parse("team_alpha")?;
        let path = CanonicalPath::parse("/secret/team_alpha")?;
        let prefix = CanonicalPath::parse("/secret")?;
        assert_eq!("team_alpha", id.as_str());
        assert!(path.matches_prefix(&prefix));
        assert!(CanonicalPath::parse("/secret/../root").is_err());
        assert!(Id::parse("Root").is_err());
        Ok(())
    }

    #[test]
    fn relative_paths_respect_segment_boundaries() -> Result<(), DomainError> {
        let path = CanonicalPath::parse("/secret/app/config")?;
        let prefix = CanonicalPath::parse("/secret/app")?;
        let false_prefix = CanonicalPath::parse("/secret/ap")?;
        assert_eq!(Some("config"), path.relative_to(&prefix));
        assert!(!path.matches_prefix(&false_prefix));
        Ok(())
    }

    #[test]
    fn secret_debug_output_is_redacted() -> Result<(), DomainError> {
        let value = SecretValue::new(b"sensitive-value".to_vec())?;
        let rendered = format!("{value:?}");
        assert!(!rendered.contains("sensitive-value"));
        assert_eq!(15, value.len());
        Ok(())
    }

    #[test]
    fn tick_addition_detects_overflow() {
        assert_eq!(
            Err(DomainError::TickOverflow),
            Tick::new(u64::MAX).checked_add(1)
        );
    }
}
