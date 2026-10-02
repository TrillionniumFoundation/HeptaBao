# Bounded wrapped AES import provider

The initial scope implements non-derived `aes128-gcm96` and `aes256-gcm96`
material under `wrapping_key`, `keys/{name}/import` and
`keys/{name}/import_version`. The exact 87 HTTP-row comparison uses a fresh
candidate and checksum-pinned OpenBao 2.7.0, fixed 2-second HTTP and 360-second
lane budgets, independent AES-GCM verification, both allow-rotation policies,
ACL rejection and encrypted restart. A controller must separately bind source,
locked Python dependencies, binary/build receipt, and independent exact
exe/config/PID/SID cleanup. This profile has no full-Transit or full-replacement
claim.

The provider uses exact `aws-lc-rs=1.17.1` / `aws-lc-sys=0.42.0` safe padded
key-wrap APIs alongside the existing exact `openssl=0.10.81` AWS-LC bridge.
RSA4096 private custody is bounded, canonical PKCS8 and checked by the maintained
provider; public custody is SPKI. The encrypted envelope is exactly512 RSA bytes
and24/40 padded AES bytes. OAEP and MGF1 use the same selected hash. The
RFC5649 KWP integrity result and exact 16/32-byte target length must both pass
before a candidate key is installed. No handwritten AES/RSA/KWP or unsafe FFI
bridge is introduced.

Application-owned private/target/KEK temporary buffers are zeroizing. The safe
AWS-LC key-wrap wrapper retains its own KEK copy; its source does not establish
zeroization on Drop. The increment therefore does not claim complete provider
key erasure or an independent security review. SHA1 import support is an
explicit compatibility option rather than a recommendation. The existing
default legacy convergent-AAD nonce risk remains open.

Primary provider contracts:
- [AWS-LC safe key-wrap API](https://github.com/aws/aws-lc-rs/blob/v1.17.1/aws-lc-rs/src/key_wrap.rs)
- [OpenSSL Rust0.10.81 release](https://github.com/rust-openssl/rust-openssl/releases/tag/openssl-v0.10.81)
- [RFC5649](https://www.rfc-editor.org/rfc/rfc5649.html)
- [Public OpenBao Transit API](https://openbao.org/docs/api/secret/transit/)

Ordinary key bytes remain unchanged with absent optional custody/policy fields.
All-namespace conditional schema 70, sticky retirement and protected restore
floors retain the complete69 reader. True active/retired prior 69-reader
refusal, ordinary forward/backward controls and fresh paired qualification
are required evidence. Public-only material, explicit version replacement,
derived/other-type imports, BYOK export and plaintext backups remain open.
The independent-security and full-replacement flags remain false.
