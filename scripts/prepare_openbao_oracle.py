#!/usr/bin/env python3
"""Acquire only the existing pinned official binary for isolated synthetic CI.

No upstream source is imported; this is repository-controlled input acquisition,
not an independent Oracle observation, compatibility admission or release.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tarfile
import urllib.request
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'qa/openbao-acceptance'))
from official_openbao_launcher import (
    ARTIFACT_SHA256, BINARY_SHA256, VERSION, PINNED_ARTIFACTS,
    SUPPORTED_VERSIONS, _platform_key, pinned_artifact, release_artifacts,
)

LIMIT = 256 * 1024 * 1024
RELEASE = f'https://api.github.com/repos/openbao/openbao/releases/tags/v{VERSION}'
PREFIX = f'https://github.com/openbao/openbao/releases/download/v{VERSION}/'


def selected_pins(version: str | None) -> dict:
    # Omitted version preserves the historical helper contract (including unit
    # fixtures). Executable acquisition always supplies a validated version.
    if version is None:
        return {'artifact_sha256': ARTIFACT_SHA256, 'binary_sha256': BINARY_SHA256}
    return pinned_artifact(version=version)


def select_asset(release: dict, *, version: str | None = None) -> dict:
    pins = selected_pins(version)
    version = VERSION if version is None else version
    prefix = f'https://github.com/openbao/openbao/releases/download/v{version}/'
    if release.get('tag_name') != f'v{version}' or release.get('draft') is not False or release.get('prerelease') is not False:
        raise ValueError('official_release_identity_mismatch')
    assets = [a for a in release.get('assets', []) if a.get('digest') == 'sha256:' + pins['artifact_sha256']]
    if len(assets) != 1:
        raise ValueError('pinned_official_archive_not_unique')
    asset = assets[0]
    if not isinstance(asset.get('browser_download_url'), str) or not asset['browser_download_url'].startswith(prefix):
        raise ValueError('untrusted_artifact_origin')
    if type(asset.get('size')) is not int or not 0 < asset['size'] <= LIMIT:
        raise ValueError('artifact_size_outside_bound')
    return asset


def extract_verified(raw: bytes, size: int, *, version: str | None = None) -> bytes:
    pins = selected_pins(version)
    if type(size) is not int or len(raw) != size or len(raw) > LIMIT or hashlib.sha256(raw).hexdigest() != pins['artifact_sha256']:
        raise ValueError('official_archive_integrity_mismatch')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        members = [m for m in archive.getmembers() if m.name.removeprefix('./') == 'bao']
        if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= LIMIT:
            raise ValueError('invalid_executable_archive_member')
        with archive.extractfile(members[0]) as stream:
            binary = stream.read(LIMIT + 1)
    if len(binary) > LIMIT or hashlib.sha256(binary).hexdigest() != pins['binary_sha256']:
        raise ValueError('official_binary_integrity_mismatch')
    return binary


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != 'https':
            raise ValueError('non_tls_artifact_redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, limit: int) -> bytes:
    request = urllib.request.Request(url, headers={'User-Agent': 'HeptaBao-synthetic-oracle', 'Accept': 'application/vnd.github+json'})
    opener = urllib.request.build_opener(HttpsOnlyRedirect())
    with opener.open(request, timeout=60) as response:
        if not response.geturl().startswith('https://'):
            raise ValueError('non_tls_artifact_redirect')
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('download_exceeds_bound')
    return raw


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', choices=SUPPORTED_VERSIONS, default=VERSION,
                        help='Exact verified release; defaults to the historical 2.6.2 baseline')
    args = parser.parse_args()
    platform_key = _platform_key()
    artifacts = release_artifacts(args.version)
    if platform_key not in artifacts:
        parser.error('no pinned official oracle artifact for this version and platform')
    pins = artifacts[platform_key]
    release_url = f'https://api.github.com/repos/openbao/openbao/releases/tags/v{args.version}'
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    old_mask = os.umask(0o077)
    try:
        asset = select_asset(json.loads(download(release_url, 2 * 1024 * 1024)), version=args.version)
        raw = download(asset['browser_download_url'], LIMIT)
        binary = extract_verified(raw, asset['size'], version=args.version)
        (output / 'oracle-official.tar.gz').write_bytes(raw)
        (output / 'bao').write_bytes(binary)
        (output / 'bao').chmod(0o700)
        print(json.dumps({'status': 'verified_pinned_input', 'version': args.version,
                          'archive_sha256': pins['artifact_sha256'], 'binary_sha256': pins['binary_sha256'],
                          'independent_qualification': False, 'compatibility_claim': False}))
        return 0
    except Exception as error:
        shutil.rmtree(output)
        print(json.dumps({'status': 'blocked_prerequisite', 'reason': type(error).__name__,
                          'independent_qualification': False, 'compatibility_claim': False}))
        return 77
    finally:
        os.umask(old_mask)


if __name__ == '__main__':
    raise SystemExit(main())
