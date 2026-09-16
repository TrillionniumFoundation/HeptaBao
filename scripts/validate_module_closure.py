#!/usr/bin/env python3
"""Fail-closed validation for the per-module design/semantics/evidence dossiers."""
from __future__ import annotations
import hashlib, re, sys, tomllib
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]
REQUIRED=['Design and state ownership','Module boundaries and trust assumptions','Failure semantics and ordering','Acceptance evidence','Known gaps and evolution']
def sha_many(paths):
 h=hashlib.sha256()
 for p in sorted(paths): h.update(str(p).encode()); h.update(b'\0'); h.update(p.read_bytes())
 return h.hexdigest()
def crates():
 m=tomllib.loads((ROOT/'Cargo.toml').read_text()); out={}
 for member in m['workspace']['members']:
  for d in sorted(ROOT.glob(member)) if '*' in member else [ROOT/member]:
   if not d.is_dir(): continue
   mp=d/'Cargo.toml'
   if mp.is_file(): out[tomllib.loads(mp.read_text())['package']['name']]=d
 return out

def main():
 errs=[]; cs=crates(); rp=ROOT/'planning/HEPTABAO_MODULE_CLOSURE_REGISTRY_V1.yaml'
 reg=yaml.safe_load(rp.read_text()); entries={x['crate']:x for x in reg.get('modules',[])}
 if set(cs)!=set(entries): errs.append(f'registry/workspace mismatch missing={sorted(set(cs)-set(entries))} extra={sorted(set(entries)-set(cs))}')
 for name,d in sorted(cs.items()):
  e=entries.get(name); dossier=ROOT/e['dossier'] if e else ROOT/'missing'; guide=ROOT/e['guide'] if e else ROOT/'missing'
  if not dossier.is_file(): errs.append(f'{name}: missing dossier'); continue
  t=dossier.read_text()
  if not t.startswith(f'# {name} module closure dossier'): errs.append(f'{name}: title mismatch')
  for h in REQUIRED:
   if f'## {h}' not in t: errs.append(f'{name}: missing section {h}')
  if 'source tree SHA-256 `' not in t or 'manifest SHA-256 `' not in t: errs.append(f'{name}: missing source binding hashes')
  if not guide.is_file(): errs.append(f'{name}: missing guide')
  elif f'../module-closure/{name}.md' not in guide.read_text(): errs.append(f'{name}: guide does not link dossier')
  src=sorted((d/'src').glob('**/*.rs')); actual=sha_many(src) if src else None
  m=tomllib.loads((d/'Cargo.toml').read_text()); expected=e.get('source_sha256')
  if actual!=expected: errs.append(f'{name}: source hash drift (registry {expected}, current {actual})')
  if e.get('test_anchor'):
   if e['test_anchor'] not in dossier.read_text(): errs.append(f'{name}: registry test anchor absent from dossier')
  elif 'No in-crate test function was discovered' not in t: errs.append(f'{name}: missing explicit no-test evidence')
  if any(x in t for x in ('production_authority: true','qualification: true','authority_effect: GRANT','TODO','TBD','PLACEHOLDER')): errs.append(f'{name}: forbidden claim/placeholder')
 if len(entries)!=46: errs.append(f'expected 46 modules, found {len(entries)}')
 if errs:
  print('\n'.join(errs),file=sys.stderr); return 1
 print(f'module closure validation: PASS ({len(entries)} modules)'); return 0
if __name__=='__main__': raise SystemExit(main())
