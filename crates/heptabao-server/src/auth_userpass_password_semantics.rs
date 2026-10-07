//! A persisted input rule separates newly written bcrypt-compatible passwords
//! from historical PBKDF2 credentials, whose complete bytes remain significant.
use super::*;

pub(super) fn password_bytes<'a>(
    user: Option<&User>,
    password: &'a str,
) -> Result<&'a [u8], AuthError> {
    match user {
        None
        | Some(User {
            imported_bcrypt: Some(_),
            ..
        })
        | Some(User {
            password_semantics: Some(PasswordSemantics::Bcrypt72),
            ..
        }) => {
            // This may end inside a UTF-8 codepoint. The KDF accepts bytes;
            // constructing a replacement string would change the credential.
            Ok(&password.as_bytes()[..password.len().min(72)])
        }
        Some(_) => {
            if password.len() > 1024 {
                return Err(bad("invalid username or password"));
            }
            Ok(password.as_bytes())
        }
    }
}

impl AuthState {
    pub(crate) fn has_userpass_password_semantics(&self) -> bool {
        self.users
            .values()
            .flat_map(|users| users.values())
            .chain(
                self.mounted_users
                    .values()
                    .flat_map(|mounts| mounts.values())
                    .flat_map(|users| users.values()),
            )
            .any(|user| user.password_semantics.is_some() || user.imported_bcrypt.is_some())
    }

    pub(crate) fn validate_userpass_password_semantics(&self) -> Result<(), AuthError> {
        for user in self.users.values().flat_map(|users| users.values()).chain(
            self.mounted_users
                .values()
                .flat_map(|mounts| mounts.values())
                .flat_map(|users| users.values()),
        ) {
            userpass_bcrypt::validate_user(user)?;
        }
        for (namespace, users) in &self.users {
            if users
                .values()
                .any(|user| user.password_semantics.is_some() || user.imported_bcrypt.is_some())
                && !self.online_mount_enabled(namespace, "userpass", "userpass")
            {
                return Err(bad(
                    "password comparison semantics require a live userpass mount",
                ));
            }
        }
        for (namespace, mounts) in &self.mounted_users {
            for (mount, users) in mounts {
                if users
                    .values()
                    .any(|user| user.password_semantics.is_some() || user.imported_bcrypt.is_some())
                    && !self.online_mount_enabled(namespace, mount, "userpass")
                {
                    return Err(bad(
                        "password comparison semantics require a live userpass mount",
                    ));
                }
            }
        }
        Ok(())
    }
}
