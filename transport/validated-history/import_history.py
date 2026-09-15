"""Restore exact reviewed Git history without executing any candidate source.

The fixed destination is an isolated review branch; this script never changes main.
"""
import hashlib
import json
import lzma
import subprocess
from pathlib import Path

BASE = 'b316cb841868c64e27e62a5fc0c7306c98631a00'
HEAD = '08d2954f7c6b2fc094f61b39ef73d1aa508e08b2'
TREE = 'a0767a089039c842668d5194521a5aa671bd535b'
SHA256 = '4db6795708bf0c093cabb2412ad464a38483050ce2d5c5343f15ac3f53e85511'


def git(*args: str, data: bytes | None = None) -> str:
    return subprocess.check_output(['git', *args], input=data).decode().strip()


def restore(root: Path) -> None:
    expected = [f'upload-{i:02d}.xz' for i in range(45)]
    if sorted(p.name for p in root.glob('upload-*.xz')) != expected:
        raise ValueError('unexpected transport inventory')
    parts = []
    for name in expected:
        path = root / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4500:
            raise ValueError('invalid transport part')
        parts.append(path.read_bytes())
    compressed = b''.join(parts)
    if len(compressed) != 202136 or hashlib.sha256(compressed).hexdigest() != SHA256:
        raise ValueError('compressed history integrity mismatch')
    decoder = lzma.LZMADecompressor(memlimit=128 * 1024 * 1024)
    raw = decoder.decompress(compressed, max_length=4 * 1024 * 1024)
    if not decoder.eof or decoder.unused_data:
        raise ValueError('invalid or oversized compressed history')
    payload = json.loads(raw)
    if (payload['base'], payload['head'], payload['tree']) != (BASE, HEAD, TREE):
        raise ValueError('candidate binding mismatch')
    commits = payload['commits']
    if len(commits) != 15:
        raise ValueError('unexpected commit count')
    git('read-tree', BASE)
    predecessor = BASE
    for item in commits:
        commit = item['commit'].encode('utf-8')
        headers = commit.split(b'\n\n', 1)[0].splitlines()
        parents = [h[7:].decode() for h in headers if h.startswith(b'parent ')]
        trees = [h[5:].decode() for h in headers if h.startswith(b'tree ')]
        if parents != [predecessor] or len(trees) != 1:
            raise ValueError('nonlinear or invalid source history')
        patch = item['patch'].encode('utf-8')
        if patch:
            git('apply', '--cached', '--binary', '--whitespace=nowarn', data=patch)
        if git('write-tree') != trees[0]:
            raise ValueError('restored source tree mismatch')
        result = git('hash-object', '-t', 'commit', '-w', '--stdin', data=commit)
        if result != item['sha']:
            raise ValueError('restored source commit mismatch')
        predecessor = result
    if predecessor != HEAD or git('rev-parse', f'{HEAD}^{{tree}}') != TREE:
        raise ValueError('final source identity mismatch')
    git('merge-base', '--is-ancestor', BASE, HEAD)
    print(json.dumps({'base': BASE, 'head': HEAD, 'tree': TREE,
                      'history_sha256': SHA256, 'commit_count': 15,
                      'runtime_executed': False, 'compatibility_claim': False},
                     sort_keys=True))


if __name__ == '__main__':
    restore(Path(__file__).resolve().parent)
