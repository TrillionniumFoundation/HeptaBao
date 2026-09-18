#!/usr/bin/env python3
"""Generate and validate a deterministic SPDX 2.3 release-candidate SBOM.

The document is source/binary bound and intentionally non-authoritative. It uses
only Cargo.lock and the exact built server binary; no network lookup, license
guessing, release signing or authority transition occurs here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import tomllib

SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"
SPDX_ID_RE = re.compile(r"[^A-Za-z0-9.-]")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def spdx_id(name: str, version: str, index: int) -> str:
    value = SPDX_ID_RE.sub("-", f"{name}-{version}")
    return f"SPDXRef-Package-{index}-{value}"


def locked_packages(lock_path: Path) -> list[dict[str, object]]:
    data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = data.get("package")
    if not isinstance(packages, list) or not packages:
        raise ValueError("Cargo.lock has no packages")
    out: list[dict[str, object]] = []
    for item in packages:
        if not isinstance(item, dict):
            raise ValueError("Cargo.lock package is invalid")
        name, version = item.get("name"), item.get("version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise ValueError("Cargo.lock package identity is invalid")
        out.append({
            "name": name,
            "version": version,
            "source": item.get("source") if isinstance(item.get("source"), str) else None,
            "checksum": item.get("checksum") if isinstance(item.get("checksum"), str) else None,
        })
    return sorted(out, key=lambda row: (str(row["name"]), str(row["version"]), str(row["source"] or "")))


def generate(lock_path: Path, binary: Path, source_sha: str) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("source SHA must be lowercase Git SHA-1")
    packages = locked_packages(lock_path)
    binary_digest = sha256(binary)
    namespace = f"https://heptabao.invalid/spdx/{source_sha}/{binary_digest}"
    spdx_packages = []
    relationships = []
    for index, package in enumerate(packages, start=1):
        identifier = spdx_id(str(package["name"]), str(package["version"]), index)
        refs = []
        source = package["source"]
        if source:
            refs.append({
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:cargo/{package['name']}@{package['version']}",
            })
        entry: dict[str, object] = {
            "name": package["name"],
            "SPDXID": identifier,
            "versionInfo": package["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        if refs:
            entry["externalRefs"] = refs
        comment = []
        if source:
            comment.append(f"Cargo.lock source: {source}")
        checksum = package["checksum"]
        if checksum:
            comment.append(f"Cargo.lock registry checksum: {checksum}")
        if comment:
            entry["comment"] = "; ".join(comment)
        spdx_packages.append(entry)
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": identifier,
        })
    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"HeptaBao release candidate {source_sha}",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Tool: HeptaBao deterministic release_candidate_sbom.py"],
            "comment": "Deterministic repository-controlled candidate inventory; not a release signature or production authority.",
        },
        "documentComment": json.dumps({
            "source_commit": source_sha,
            "server_binary_sha256": binary_digest,
            "release_authority": False,
            "production_authority": False,
            "independent_attestation": False,
        }, sort_keys=True, separators=(",", ":")),
        "packages": spdx_packages,
        "relationships": relationships,
    }


def validate(document: dict[str, object], lock_path: Path, binary: Path, source_sha: str) -> None:
    if document.get("spdxVersion") != SPDX_VERSION or document.get("dataLicense") != DATA_LICENSE:
        raise ValueError("unsupported SPDX document")
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ValueError("invalid document SPDXID")
    packages = document.get("packages")
    relationships = document.get("relationships")
    locked = locked_packages(lock_path)
    if not isinstance(packages, list) or len(packages) != len(locked):
        raise ValueError("SBOM package denominator differs from Cargo.lock")
    if not isinstance(relationships, list) or len(relationships) != len(packages):
        raise ValueError("SBOM relationship denominator is incomplete")
    identities = [(p.get("name"), p.get("versionInfo")) for p in packages if isinstance(p, dict)]
    expected = [(p["name"], p["version"]) for p in locked]
    if identities != expected:
        raise ValueError("SBOM package identities differ from Cargo.lock")
    ids = [p.get("SPDXID") for p in packages if isinstance(p, dict)]
    if len(ids) != len(set(ids)) or any(not isinstance(value, str) for value in ids):
        raise ValueError("SBOM SPDXIDs are invalid or duplicated")
    comment = document.get("documentComment")
    if not isinstance(comment, str):
        raise ValueError("SBOM binding comment is missing")
    binding = json.loads(comment)
    if binding != {
        "independent_attestation": False,
        "production_authority": False,
        "release_authority": False,
        "server_binary_sha256": sha256(binary),
        "source_commit": source_sha,
    }:
        raise ValueError("SBOM source/binary binding differs from candidate")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=Path("Cargo.lock"))
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    if args.validate:
        document = json.loads(args.output.read_text(encoding="utf-8"))
        validate(document, args.lock, args.binary, args.source_sha)
        print(json.dumps({"status": "valid", "sbom_sha256": sha256(args.output)}, sort_keys=True))
        return 0
    document = generate(args.lock, args.binary, args.source_sha)
    encoded = json.dumps(document, indent=2, sort_keys=True) + "\n"
    args.output.write_text(encoded, encoding="utf-8")
    validate(document, args.lock, args.binary, args.source_sha)
    print(json.dumps({
        "status": "generated",
        "packages": len(document["packages"]),
        "binary_sha256": sha256(args.binary),
        "sbom_sha256": sha256(args.output),
        "release_authority": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
