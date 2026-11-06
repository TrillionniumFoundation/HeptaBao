# Native local JWT batch source proposal R2

Frozen base: 02b90762b3d6cc8699cc88bffb6f76cb1f07e270. This package is a source proposal only; zero Rust compilation or runtime tests have run.

The existing issuer and single verifier remain unchanged. The actual sealed batch is checked against original JWT lifetime and Identity, then admitted through the existing paired Auth/Namespace lifecycle and audit delivery gates.

The independent review found one regression-evidence gap: namespace lifecycle state was absent from failure snapshots. R2 adds the complete Auth namespace batch registry and complete Namespace owner through existing serializers to the private Zeroizing snapshot. No production source changed from R1.

Six meaningful File V6 regressions were added and one old negative test was renamed to retain remote-key and invalid-signature rejection while allowing locally verified batch issuance. See MANIFEST.public.json for exact names and file pins. The next candidate must also include the separately reviewed nine Service-lock compile fix and must pass actual fresh builds before any capability claim.
