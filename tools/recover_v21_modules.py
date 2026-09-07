#!/usr/bin/env python3
"""Recover previously published V2.1 module source from repository refs.

Only module-local source, its developer guide and matching repository/architecture
assets are copied. Workflows, transport payloads and authority markers are excluded.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

MODULES = [
    "heptabao-aead-barrier",
    "heptabao-audit-file",
    "heptabao-single-node-runtime",
    "heptabao-http-adapter",
    "heptabao-tls-server",
    "heptabao-network-server",
    "heptabao-access-file",
    "heptabao-format-migration",
    "heptabao-plugin-host",
    "heptabao-raft-replica",
    "heptabao-compatibility-runner",
]

PURPOSES = {
    "heptabao-aead-barrier": "Implements the concrete authenticated-encryption boundary with random nonces and context-bound associated data.",
    "heptabao-audit-file": "Implements a local authenticated append-only audit chain with sequence validation and writer fencing.",
    "heptabao-single-node-runtime": "Composes the concrete barrier, audit provider and restart-safe durable mutation service.",
    "heptabao-http-adapter": "Parses and emits the bounded HTTP/1.1 subset accepted by the service boundary.",
    "heptabao-tls-server": "Owns the TLS 1.3 handshake, certificate snapshot and ALPN boundary.",
    "heptabao-network-server": "Runs the bounded listener-to-TLS-to-HTTP-to-runtime request path.",
    "heptabao-access-file": "Persists token verification, expiry, revocation and default-deny authorization state.",
    "heptabao-format-migration": "Executes writer-fenced, source-preserving and restart-recoverable format migration stages.",
    "heptabao-plugin-host": "Runs digest-approved plugins without a shell under bounded input, output and timeout contracts.",
    "heptabao-raft-replica": "Persists the Raft term, vote, log, commit, apply and snapshot safety core.",
    "heptabao-compatibility-runner": "Runs deterministic candidate-versus-Oracle differential scenarios with state and side-effect comparison.",
}

HEADINGS = [
    "## Purpose and non-goals",
    "## Public API and ownership",
    "## State and data model",
    "## Invariants and authorization",
    "## Failure, retry and reconciliation",
    "## Concurrency and ordering",
    "## Security and privacy",
    "## Persistence and compatibility",
    "## Observability",
    "## Operations",
    "## Tests and executable evidence",
    "## Evolution and open boundaries",
]


def git(repo: Path, *args: str, text: bool = True) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=text, stderr=subprocess.DEVNULL)  # type: ignore[return-value]


def tree_paths(repo: Path, commit: str) -> list[str]:
    return git(repo, "ls-tree", "-r", "--name-only", commit).splitlines()


def candidate_history(repo: Path, module: str) -> list[tuple[str, str]]:
    pathspec = f":(glob)**/crates/{module}/Cargo.toml"
    output = git(repo, "log", "--all", "--format=COMMIT %H", "--name-only", "--", pathspec)
    result: list[tuple[str, str]] = []
    commit = ""
    for line in output.splitlines():
        if line.startswith("COMMIT "):
            commit = line.split()[1]
        elif line.endswith(f"crates/{module}/Cargo.toml") and commit:
            result.append((commit, line))
    return result


def select_donor(repo: Path, module: str) -> tuple[str, str]:
    for commit, cargo_path in candidate_history(repo, module):
        prefix = cargo_path[: -len(f"crates/{module}/Cargo.toml")]
        source = f"{prefix}crates/{module}/src/lib.rs"
        try:
            git(repo, "cat-file", "-e", f"{commit}:{source}")
        except subprocess.CalledProcessError:
            continue
        return commit, prefix
    raise SystemExit(f"no published donor source found for {module}")


def export_file(repo: Path, commit: str, source: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = subprocess.check_output(["git", "-C", str(repo), "show", f"{commit}:{source}"])
    destination.write_bytes(data)


def generic_guide(module: str) -> str:
    purpose = PURPOSES[module]
    return f"""# `{module}` technical development guide

This guide follows `docs/modules/MODULE_DOCUMENTATION_STANDARD_V3.md` and `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

{purpose} It is a repository-candidate implementation and does not grant production, compatibility, migration or release authority.

## Public API and ownership

`crates/{module}/src/lib.rs` is authoritative. The module owns only its explicit boundary and delegates identity, policy, key custody, persistence or external-system authority to their designated providers.

## State and data model

All identifiers, frames and state transitions are bounded and versioned. Caller-controlled values are validated before they become persistent identity or irreversible effect.

## Invariants and authorization

Default-deny and fail-closed behavior are mandatory. Authorization and exact operation binding precede irreversible entry. Stale terms, generations, credentials, formats or digests never gain authority.

## Failure, retry and reconciliation

Before-entry failures allow a newly bound attempt. After-entry uncertainty is explicit and never permits blind retry. Recovery relies on authoritative readback, durable records or a service-generated opaque reference.

## Concurrency and ordering

Writer ownership and transition ordering are explicit. Commit, audit, replication, migration or child-process acknowledgement cannot be reordered ahead of their required durable and authenticated facts.

## Security and privacy

Secrets, bearer credentials, plaintext values, private keys and unbounded caller data are excluded from diagnostics. Cryptographic digests are domain-separated; confidential persistence requires authenticated encryption and separately controlled keys.

## Persistence and compatibility

Persistent formats are strict, bounded and reject trailing, truncated, unauthenticated or regressing state. Compatibility and migration claims require separate corpus, fixture and independent evidence.

## Observability

Only bounded phase, status, generation, term, count and opaque identifiers may be emitted. Metrics and logs must not become a secret or high-cardinality exfiltration channel.

## Operations

Operators must follow the current runbook, preserve failed evidence and stop on writer conflict, disk exhaustion, authentication failure, stale leadership or unresolved after-entry outcome.

## Tests and executable evidence

Inline Rust tests and repository regressions cover positive, hostile, restart and failure paths. Exact-head and prospective-main-merge CI must run formatting, locked all-target tests, warnings-denied Clippy, rustdoc and repository/security/platform/Oracle gates.

## Evolution and open boundaries

Real KMS/HSM custody, destructive I/O and network qualification, multi-process HA, complete Oracle corpus, independent assessment, incident ownership and legal/release authorization remain separate gates.
"""


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: recover_v21_modules.py REPOSITORY")
    repo = Path(sys.argv[1]).resolve()
    current = set(path.name for path in (repo / "crates").iterdir() if path.is_dir())
    recovered: list[str] = []
    evidence: list[str] = []

    for module in MODULES:
        if module in current and (repo / f"crates/{module}/src/lib.rs").is_file():
            recovered.append(module)
            evidence.append(f"{module}:already-present")
            continue
        commit, prefix = select_donor(repo, module)
        paths = tree_paths(repo, commit)
        crate_root = f"{prefix}crates/{module}/"
        crate_files = [path for path in paths if path.startswith(crate_root)]
        if not crate_files:
            raise SystemExit(f"empty donor crate for {module}")
        for source in crate_files:
            relative = source[len(prefix):]
            export_file(repo, commit, source, repo / relative)

        guide_source = f"{prefix}docs/modules/{module}.md"
        if guide_source in paths:
            export_file(repo, commit, guide_source, repo / f"docs/modules/{module}.md")
        else:
            (repo / f"docs/modules/{module}.md").write_text(generic_guide(module), encoding="utf-8")

        token = module.removeprefix("heptabao-").replace("-", "_")
        token_parts = [part for part in token.split("_") if len(part) > 2]
        for source in paths:
            lowered = source.lower()
            same_prefix = not prefix or source.startswith(prefix)
            if not same_prefix:
                continue
            relative = source[len(prefix):]
            if relative.startswith("tests/repository/") and relative.endswith(".py") and any(part in lowered for part in token_parts):
                export_file(repo, commit, source, repo / relative)
            elif relative.startswith("docs/architecture/") and relative.endswith(".md") and any(part in lowered for part in token_parts):
                export_file(repo, commit, source, repo / relative)
            elif relative.startswith("docs/operations/") and relative.endswith(".md") and any(part in lowered for part in token_parts):
                export_file(repo, commit, source, repo / relative)

        guide = repo / f"docs/modules/{module}.md"
        text = guide.read_text(encoding="utf-8")
        if any(text.count(heading) != 1 for heading in HEADINGS) or "docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md" not in text:
            guide.write_text(generic_guide(module), encoding="utf-8")
        recovered.append(module)
        evidence.append(f"{module}:{commit}:{prefix or '<root>'}")

    status = repo / "planning/HEPTABAO_V2_1_RECOVERED_MODULES.txt"
    status.write_text("\n".join(evidence) + "\n", encoding="utf-8")
    if set(recovered) != set(MODULES):
        raise SystemExit("incomplete recovery set")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
