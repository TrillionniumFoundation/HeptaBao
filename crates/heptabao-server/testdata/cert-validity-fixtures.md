These are signed X.509 unit fixtures, not TLS or compatibility receipts.

- cert-selector.der retains the existing subject, issuer, serial, SANs and
  extensions. Its validity spans 1970-01-01 through 2060-01-01 so historical
  coarse test clocks and current epoch clocks both use valid DER.
- cert-selector-other.der has the same constraints and broad validity but a
  different serial and digest, providing a valid wrong-certificate control.
- cert-validity-boundary.der is valid only from 2026-10-13T00:00:00Z through
  2026-10-13T00:02:00Z. Tests assert its actual DER endpoints and check precise
  time one nanosecond outside each endpoint.

All three certificates were signed locally with an ephemeral P-256 key.
Their signatures and retained extensions were verified before publication.
No private fixture key is stored. Production validation has no fixture exception.
