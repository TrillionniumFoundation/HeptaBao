# HeptaBao Security Policy

## Current status

HeptaBao is in `H00 / planning and governance implementation`. It is **not** a production secrets server, has no compatibility claim and has no production, migration, release or mixed-cluster authority.

Do not deploy this repository to protect real secrets. Do not place real tokens, unseal shares, recovery keys, root tokens, private keys or production snapshots in issues, pull requests, CI, fixtures or ordinary development environments.

## Private reporting

A dedicated private disclosure channel and 24/7 incident owner are required by `H00-WP07` but are not yet qualified. Until that channel is operational:

1. Do not open a public issue for a suspected vulnerability.
2. Use GitHub's private security-advisory mechanism for this repository when available.
3. Otherwise contact the repository owner through an already established private channel and share only the minimum reproduction metadata.
4. Never transmit live credentials or real customer secret material.

The absence of a qualified disclosure channel is an H00 release blocker; it is not permission to disclose publicly.

## What to include

- affected commit, artifact digest and configuration digest;
- affected operation, namespace/mount profile and storage/seal profile;
- impact and preconditions;
- sanitized reproduction steps;
- whether a secret, key, token, audit record, authority grant or durable state may be exposed;
- evidence of duplicate effects, writer overlap, audit bypass, policy bypass, split brain or data loss;
- safe contact details and embargo constraints.

## Immediate revocation triggers

Any of the following invalidates affected qualification receipts, compatibility claims and authority grants until a signed disposition exists:

- secret, token, unseal share or private-key leak;
- policy, identity, token, namespace, audit, seal or plugin bypass;
- committed-write loss, split brain or unexplained consistency violation;
- blind retry or duplicate external effect after an ambiguous outcome;
- source/target writer overlap during migration;
- invalid provenance, signature, dependency, toolchain or evidence;
- a newly confirmed critical/high issue affecting the qualified scope.

Revocation has precedence over every claim or grant.

## Supported versions

No version is currently supported. The first support matrix may be published only through a signed compatibility claim and a separate scoped authority grant. A green unit test, merged pull request, tag, release asset or qualification receipt alone does not create support or authority.
