#!/usr/bin/env python3
"""Read bounded SDK code only; never import/execute SDK code or read credentials.

The output contains source files and static import metadata for exact-source
review. Existing output files are refused. No service or installed file changes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

MAX_FILE = 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_FILES = 24
EXPECTED = {
    'dist/oauth-B4aOCsid.js': '505d561b6fe271c95d29d7b93b44cd0780ac5859342a98e46f20b4e08487234e',
    'dist/profiles-DyU-YCq2.js': '075f9d6ecd43103c32a6908816bf42720076fd0aaedb2b5e7e96481d64a29ba5',
    'dist/store-DH33UrUj.js': '25a5c7075e13b8fb32f498a90e5ee91d93b7e15972b3b74796f1325b5ba98ebf',
}
DEFINITIONS = re.compile(r'(?:async\s+)?function\s+(?:upsertAuthProfileWithLock|saveAuthProfileStore|updateAuthProfileStoreWithLock|createOAuthManager|resolveOAuthApiKey|getOAuthApiKey|refreshOAuthToken)\s*\(|class\s+OAuthManagerRefreshError\b')
IMPORTS = re.compile(r'^import\s+(.{0,2000}?)\s+from\s+[\"\']([^\"\']+)[\"\'];?', re.MULTILINE)
RELEVANT = re.compile(r'oauth|refresh|AuthProfileStore|AuthProfileWithLock', re.IGNORECASE)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.sdk_root.is_absolute() or not args.output.is_absolute():
        parser.error('absolute paths required')
    sdk_root = args.sdk_root.resolve(strict=True)
    if not (sdk_root / 'package.json').is_file():
        parser.error('SDK package.json missing')
    if args.output.exists():
        parser.error('output already exists; choose a new inspection receipt')
    os.umask(0o077)
    package_path = sdk_root / 'package.json'
    if package_path.is_symlink() or package_path.stat().st_size > MAX_FILE:
        parser.error('SDK package metadata outside bounded regular-file contract')
    package = json.loads(package_path.read_text())
    report = {'schema': 'authbus-r5-sdk-source-inspection', 'sdk_root': str(sdk_root),
              'package_name': package.get('name'), 'package_version': package.get('version'),
              'sdk_code_executed': False, 'credential_files_read': False,
              'discovery': 'three-known-R4-files-and-relevant-static-imports',
              'global_dist_scan_performed': False,
              'files': [], 'unresolved_external_imports': [], 'skipped': []}
    queue = [(sdk_root / name, 'known-R4-boundary') for name in EXPECTED]
    visited, total = set(), 0
    while queue:
        filename, reason = queue.pop(0)
        if filename in visited:
            continue
        visited.add(filename)
        if filename.is_symlink() or not filename.is_file() or not filename.is_relative_to(sdk_root) or not filename.resolve().is_relative_to(sdk_root):
            report['skipped'].append({'path': str(filename), 'reason': 'not-a-direct-sdk-code-file'})
            continue
        if filename.suffix not in {'.js', '.mjs'}:
            continue
        size = filename.stat().st_size
        if size > MAX_FILE or total + size > MAX_TOTAL or len(report['files']) >= MAX_FILES:
            report['skipped'].append({'path': str(filename), 'reason': 'bounded-inspection-budget'})
            continue
        content = filename.read_bytes()
        relative = str(filename.relative_to(sdk_root))
        sha256 = hashlib.sha256(content).hexdigest()
        source = content.decode('utf-8')
        imports = []
        for clause, specifier in IMPORTS.findall(source):
            entry = {'specifier': specifier, 'clause': clause}
            imports.append(entry)
            if not RELEVANT.search(clause + ' ' + specifier):
                continue
            if specifier.startswith('.'):
                resolved = Path(os.path.normpath(filename.parent / specifier))
                if resolved.is_relative_to(sdk_root):
                    queue.append((resolved, 'static-refresh-or-owner-import'))
            else:
                report['unresolved_external_imports'].append({'from': relative, **entry})
        report['files'].append({'path': relative, 'reason': reason, 'size': len(content), 'sha256': sha256,
                                'expected_sha256': EXPECTED.get(relative),
                                'matches_R4_binding': sha256 == EXPECTED[relative] if relative in EXPECTED else None,
                                'imports': imports, 'content': source})
        total += len(content)
    report['file_count'] = len(report['files'])
    report['source_bytes'] = total
    found_bindings = {item['path']: item['matches_R4_binding'] for item in report['files'] if item['expected_sha256']}
    report['all_expected_bindings_match'] = all(found_bindings.get(name) is True for name in EXPECTED)
    encoded = (json.dumps(report, ensure_ascii=False, indent=2) + '\n').encode()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        raise
    print(json.dumps({'output': str(args.output), 'file_count': len(report['files']),
                      'source_bytes': total, 'all_expected_bindings_match': report['all_expected_bindings_match'], 'output_sha256': hashlib.sha256(encoded).hexdigest(),
                      'bindings': [{'path': item['path'], 'matches_R4_binding': item['matches_R4_binding']}
                                   for item in report['files'] if item['expected_sha256']],
                      'sdk_code_executed': False, 'credential_files_read': False}))

if __name__ == '__main__':
    main()
