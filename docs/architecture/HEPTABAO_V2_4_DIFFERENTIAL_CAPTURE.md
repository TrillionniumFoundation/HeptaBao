# HeptaBao V2.4 differential compatibility capture

## Purpose

`scripts/openbao_differential_runner_v2_4.py` captures bounded, normalized observations from an OpenBao oracle or HeptaBao candidate. A capture profile must contain exactly the same surface IDs as the immutable compatibility denominator.

## Security boundary

The profile cannot contain bearer credentials. A capture token is read only from process environment and is never written to the artifact. HTTPS is mandatory, redirects are rejected, request and response sizes are bounded, duplicate JSON members are rejected, and fields whose names indicate secrets are replaced with SHA-256/length records.

## Admission boundary

Repository-controlled candidate capture and independently controlled Oracle capture remain different origins. Comparison requires exact profile, denominator and surface-set bindings. This runner does not self-issue independent Oracle, compatibility, qualification or production authority.

## Operations

Use a pinned CA, optional client certificate, an isolated synthetic test tenant and a short-lived token. Preserve the profile, denominator, source ref and output artifact together. Submit the Oracle artifact through the independent evidence-admission process before any compatibility claim.

Before comparison, each capture artifact self-authenticates its canonical JSON structure and validates every bounded observation. This integrity check detects accidental or adversarial modification but does not replace an independent signature or admission authority.
