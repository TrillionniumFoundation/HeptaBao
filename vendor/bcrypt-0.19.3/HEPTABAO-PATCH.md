# Fixed bcrypt dependency: Go decoded-salt compatibility

Original release: bcrypt 0.19.3, https://github.com/Keats/rust-bcrypt, MIT (LICENSE retained).
Archive SHA256: `a0cd0bd35a28836d528d2b58ad499bc3c5641d59379421b1be9eeb0c2f2b912a` (matches the registry checksum in the pre-change Cargo.lock).

Unchanged release files: Cargo.toml, Cargo.toml.orig, LICENSE, src/errors.rs. README.md only has two trailing spaces removed. Do not format or rewrite the upstream source wholesale.

Two narrow source changes:

* src/bcrypt.rs: existing `bcrypt` delegates to `bcrypt_with_salt(&[u8])`; the existing single setup/round/output implementation is shared unchanged. The slice entry is crate-private and rejects empty or >16-byte salts before the cipher.
* src/lib.rs: `verify_with_decoded_salt` is the only new public entry. Cost is 5..=12, salt length is 1..=16 and expected encoded hash is exactly31 bytes. The password buffer follows existing 72-byte truncation/NUL rules. The returned encoded digest is compared with `subtle::ConstantTimeEq`; password/output/encoded buffers are cleared with the enabled zeroize feature. Blowfish's zeroize feature remains unified by the server's existing dependency.

Existing public APIs and normal password hashing are unchanged. The server remains responsible for Go Cost/header admission and Go base64 CR/LF/padding rules. There is no fallback KDF or second cryptographic round implementation. The crate is excluded from workspace-wide formatting/tests to preserve upstream sources and avoid introducing its test-only quickcheck dependency into ordinary builds. Server behavior tests exercise this entry directly. Root integration regenerates Cargo.lock; the staging task does not run Cargo.
