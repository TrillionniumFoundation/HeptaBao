#!/usr/bin/env python3
"""Generate source-bound module closure dossiers for every workspace crate."""
from __future__ import annotations
import hashlib, re, tomllib
from pathlib import Path
import yaml

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'docs/module-closure'; OUT.mkdir(parents=True, exist_ok=True)
mat=yaml.safe_load((ROOT/'planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml').read_text())
domains={x['crate']:x for x in mat['modules']}

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def sha_many(paths):
    h=hashlib.sha256()
    for path in paths:
        h.update(str(path).encode()); h.update(b'\0'); h.update(path.read_bytes())
    return h.hexdigest()
def rust_files(crate): return sorted((ROOT/crate).glob('src/**/*.rs'))
def symbols(text):
    out=[]
    for m in re.finditer(r'(?m)^\s*pub(?:\([^)]*\))?\s+(struct|enum|trait|fn|type|const|static|mod)\s+([A-Za-z_][A-Za-z0-9_]*)', text):
        out.append(f'{m.group(1)} `{m.group(2)}`')
    return out

def errors(text):
    vals=[]
    for m in re.finditer(r'enum\s+([A-Za-z_][A-Za-z0-9_]*(?:Error|Failure|Reject|Outcome))\s*\{([^}]*)\}', text, re.S):
        vs=re.findall(r'(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^\n]*\)|\{[^\n]*\})?\s*,?',m.group(2))
        vals.extend(f'{m.group(1)}::{v}' for v in vs[:20])
    return vals

def tests(text):
    return re.findall(r'#\[test\][\s\S]{0,160}?\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(', text)

def deps(manifest):
    m=tomllib.loads(manifest.read_text()); out=[]
    for sec in ('dependencies','dev-dependencies','build-dependencies'):
        for k in (m.get(sec) or {}):
            if k.startswith('heptabao-'): out.append(k)
    return sorted(set(out))

rows=[]
for manifest in sorted((ROOT/'crates').glob('*/Cargo.toml')):
    m=tomllib.loads(manifest.read_text()); name=m['package']['name']; crate=str(manifest.parent.relative_to(ROOT)); files=rust_files(crate)
    text='\n'.join(p.read_text(errors='replace') for p in files)
    syms=symbols(text); ers=errors(text); ts=tests(text); info=domains.get(name,{})
    test_anchor=ts[0] if ts else None
    p=OUT/f'{name}.md'
    source_list=', '.join(f'`{x.relative_to(ROOT)}`' for x in files) or 'none'
    dep_list=', '.join(f'`{x}`' for x in deps(manifest)) or 'none'
    sym_list='; '.join(syms[:30]) or 'No public Rust declarations; behavior is represented by private implementation or build metadata.'
    err_list='; '.join(f'`{x}`' for x in ers) or 'No public error enum matching the repository naming convention; callers must treat Result/Option and validation branches in the source as the failure contract.'
    test_text=f'`{test_anchor}` in `{files[0].relative_to(ROOT) if files else crate}`' if test_anchor else 'No in-crate test function was discovered; acceptance is currently limited to repository/documentation validation and this is an open evidence item.'
    runtime='yes' if info.get('state','').startswith('IMPLEMENTED') and name in {'heptabao-server','heptabao-durable-service','heptabao-filesystem-guard','heptabao-ha-service','heptabao-raft-runtime'} else 'no/standalone or indirect; verify CURRENT_RUNTIME_MAP'
    state=info.get('state','UNMAPPED')
    body=f'''# {name} module closure dossier

This dossier is the independently reviewable design, boundary, failure-semantics, and acceptance record for **`{name}`**. It is generated from the exact candidate tree and must be reviewed whenever the source or manifest hash changes. It does not grant compatibility, production, migration, or release authority.

## Design and state ownership

- **Capability domain:** {info.get('domain','No capability-matrix domain is registered; this is a documentation blocker.')}
- **Repository state:** `{state}`.
- **Source root:** `{crate}`; Rust files: {source_list}.
- **Internal dependencies:** {dep_list}.
- **Runtime placement:** `{runtime}`. The current runtime map is authoritative for whether this package is in the executable server dependency closure.
- **Public design surface:** {sym_list}

The module owns only the state and transitions described by its source files. It must not silently create an HTTP route, persistence format, authorization decision, external effect, or production guarantee unless that responsibility is visible in the source and in the current runtime map. Cross-module state is passed through typed APIs; callers remain responsible for transaction scope and durable publication where this package has no storage dependency.

## Module boundaries and trust assumptions

The package boundary is `{crate}`. Inputs crossing it are untrusted unless the source validates them; secrets, credentials, bearer tokens, and provider responses must not be placed in logs or debug output. {name} has no authority to claim OpenBao compatibility merely because a type or contract exists. Runtime integration, if any, is limited to the routes and owners recorded in `docs/modules/CURRENT_RUNTIME_MAP.md`; otherwise this is a standalone model, contract, or qualification tool.

The module does not own external clocks, network peers, KMS/HSM custody, filesystem ownership, process supervision, or operator approval unless its source explicitly implements and tests that boundary. Those concerns remain caller obligations and are listed as open evidence below.

## Failure semantics and ordering

The source-defined failure vocabulary is: {err_list}

Validation must happen before irreversible state mutation. A caller must distinguish a definite pre-entry rejection from an outcome that became unknown after provider, journal, network, or publication entry. Unknown-after-entry outcomes require authoritative readback/reconciliation and must not be retried blindly. Invalid transitions, stale generations/terms, malformed identifiers, unauthorized inputs, exhausted capacity, and I/O/transport errors remain failures unless the source explicitly converts them into a typed safe state. This dossier does not reinterpret a missing error enum as success.

Ordering obligations are source-specific: inspect the public functions and tests listed below before changing call order. If this module is later given durable or external effects, add a persisted intent/readback test and update this dossier rather than relying on a happy-path unit test.

## Acceptance evidence

- **Source/manifest evidence:** source tree SHA-256 `{sha_many(files) if files else 'none'}`; manifest SHA-256 `{sha(manifest)}`.
- **Named executable anchor:** {test_text}.
- **Required command:** `cargo +1.98.0 test --locked -p {name}` (must be executed against this exact source tree; historical CI output is not current evidence).
- **Repository/documentation checks:** `python scripts/validate_module_closure.py`; `python scripts/validate_current_documentation_semantics.py`.
- **Acceptance interpretation:** a passing unit test proves only the named module behavior. It does not prove server integration, OpenBao parity, HA, external provider correctness, crash recovery, or production qualification. Those require separate executable profiles and independent admission.

The acceptance status for this dossier is **source-bound, execution-pending** until the exact-head command and applicable integration profile produce a receipt bound to the same commit. {('The absence of a discovered test is itself an open acceptance gap.' if not test_anchor else '')}

## Known gaps and evolution

Current open boundaries include full API/error-surface review, adversarial and crash/reopen cases, platform qualification, and any integration claimed by a different package. When behavior changes, update this dossier, the module guide, capability matrix, runtime map and named tests together. Never replace an unexecuted or failed acceptance result with prose claiming completion.
'''
    p.write_text(body)
    guide=ROOT/'docs/modules'/f'{name}.md'
    link=f'\n\n## Independent module closure dossier\n\nThe detailed design, boundary, failure-semantics and exact-head acceptance record is maintained in [the module closure dossier](../module-closure/{name}.md).\n'
    gt=guide.read_text()
    if '## Independent module closure dossier' not in gt: guide.write_text(gt.rstrip()+link)
    rows.append({'crate':name,'dossier':str(p.relative_to(ROOT)),'guide':str(guide.relative_to(ROOT)),'source':str((manifest.parent/'src').relative_to(ROOT)),'manifest_sha256':sha(manifest),'source_sha256':sha_many(files) if files else None,'test_anchor':test_anchor,'state':state})
(ROOT/'planning/HEPTABAO_MODULE_CLOSURE_REGISTRY_V1.yaml').write_text(yaml.safe_dump({'schema':'heptabao.module-closure-registry.v1','commit':'generated-at-source-review','required_sections':['Design and state ownership','Module boundaries and trust assumptions','Failure semantics and ordering','Acceptance evidence','Known gaps and evolution'],'modules':rows},sort_keys=False))
print(f'generated {len(rows)} dossiers')
