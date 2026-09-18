#!/usr/bin/env python3
"""Selected current runtime/schema drift guards, not semantic completeness proof."""
from __future__ import annotations
import re
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORMAT = 'docs/architecture/HEPTABAO_CURRENT_STATE_FORMAT.md'
ENGINE = 'docs/engines/HEPTABAO_SINGLE_NODE_ENGINES.md'
SERVER = 'docs/modules/heptabao-server.md'
ARCH = 'docs/architecture/HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md'
CAPACITY = 'docs/operations/HEPTABAO_CAPACITY_AND_GROWTH.md'
REPLAY = 'docs/architecture/HEPTABAO_REPLAY_EPOCH_PROTOCOL.md'
REPLAY_HA = 'qa/openbao-acceptance/replay_epoch_ha.py'
ACCEPTANCE = 'docs/compatibility/HEPTABAO_REPLACEMENT_ACCEPTANCE.md'
CORPUS = 'qa/openbao-acceptance/complete_surface_corpus_v1.json'
SERVER_LIB = 'crates/heptabao-server/src/lib.rs'
STATE_STORE = 'crates/heptabao-server/src/service_state_store.rs'


def _one(pattern: str, text: str, error: str, errors: list[str]) -> str | None:
    matches = re.findall(pattern, text, re.M)
    if len(matches) != 1:
        errors.append(error)
        return None
    return matches[0]


def _without_rust_comments(text: str) -> str:
    """Remove Rust comments while preserving strings and source line structure.

    These guards are deliberately lexical, but comments must never be able to
    satisfy a runtime semantic anchor.  Keep quoted route/mode literals intact
    because several anchors are intentionally string-valued protocol constants.
    """
    out: list[str] = []
    i = 0
    block_depth = 0
    in_string = False
    escaped = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if block_depth:
            if ch == "/" and nxt == "*":
                block_depth += 1
                out.extend((" ", " "))
                i += 2
                continue
            if ch == "*" and nxt == "/":
                block_depth -= 1
                out.extend((" ", " "))
                i += 2
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            while i < len(text) and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and nxt == "*":
            block_depth = 1
            out.extend((" ", " "))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def validate(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    try:
        source = (root / 'crates/heptabao-server/src/service.rs').read_text()
        matches = re.findall(
            r'\bconst\s+CURRENT_STATE_SCHEMA\s*:\s*u32\s*=\s*(\d+)\s*;',
            source,
            re.M,
        )
        if len(matches) != 1:
            return ['current Service schema constant is missing or ambiguous']
        schema = matches[0]
        contract = (root / FORMAT).read_text()
        if f'The current Service state schema is **{schema}**.' not in contract:
            errors.append('current format contract differs from the source schema')
        engine = (root / ENGINE).read_text()
        backend = (root / 'crates/heptabao-server/src/engines.rs').read_text()
        match = re.search(r'^enum Backend \{\n(.*?)^\}', backend, re.M | re.S)
        if match is None:
            errors.append('current Backend enum could not be identified')
        else:
            variants = re.findall(r'^    ([A-Z]\w*)(?:\(|,)', match[1], re.M)
            if not variants or '.backend.{' + ' | '.join(variants) + '}' not in engine:
                errors.append('engine state diagram differs from current Backend variants')
        for path in ('README.md', 'docs/CURRENT_DOCUMENTATION.md', SERVER, ARCH):
            text = (root / path).read_text()
            if Path(FORMAT).name not in text:
                errors.append(f'{path}: missing current state-format navigation')
            for found in re.findall(r'(?:Service schema remains |Existing state remains schema |`State` schema )(\d+)', text):
                if found != schema:
                    errors.append(f'{path}: obsolete current-tense schema assertion')
        compact = re.sub(r'\s+', ' ', engine)
        if 'PKI, SSH, database, LDAP, Kubernetes and other engine types return HTTP 501' in compact:
            errors.append('engine guide still denies currently implemented backends')
        if 'HEPTABAO_POSTGRESQL_PROVIDER.md' not in engine:
            errors.append('engine guide must distinguish Service-owned database effects')

        server_guide = (root / SERVER).read_text()
        capacity_guide = (root / CAPACITY).read_text()
        replay_guide = (root / REPLAY).read_text()
        replay_fixture = (root / REPLAY_HA).read_text()
        server_lib = (root / SERVER_LIB).read_text()
        state_store = (root / STATE_STORE).read_text()
        # Bind semantic constants without coupling CI to visibility, indentation
        # or rustfmt line layout. Exact Git bytes remain the source authority.
        state_mib = _one(
            r'\bMAX_APPLICATION_STATE_BYTES\s*:\s*usize\s*=\s*(\d+)\s*\*\s*1024\s*\*\s*1024\s*;',
            server_lib,
            'shared application-state bound is missing or ambiguous',
            errors,
        )
        chunk_kib = _one(
            r'\bSTATE_CHUNK_BYTES\s*:\s*usize\s*=\s*(\d+)\s*\*\s*1024\s*;',
            state_store,
            'state chunk bound is missing or ambiguous',
            errors,
        )
        operations_raw = _one(
            r'\bMAX_OPERATIONS\s*:\s*usize\s*=\s*([\d_]+)\s*;',
            source,
            'replay operation-identity bound is missing or ambiguous',
            errors,
        )
        if state_mib is not None:
            if f'**{state_mib} MiB**' not in capacity_guide or f'{state_mib} MiB' not in server_guide:
                errors.append('current capacity documentation differs from MAX_APPLICATION_STATE_BYTES')
            if f'**{state_mib} MiB**' not in replay_guide:
                errors.append('replay protocol differs from MAX_APPLICATION_STATE_BYTES')
        if chunk_kib is not None:
            if f'**{chunk_kib} KiB**' not in capacity_guide or f'{chunk_kib} KiB' not in server_guide:
                errors.append('current capacity documentation differs from STATE_CHUNK_BYTES')
            if f'**{chunk_kib} KiB**' not in replay_guide:
                errors.append('replay protocol differs from STATE_CHUNK_BYTES')
        if operations_raw is not None:
            operations = int(operations_raw.replace('_', ''))
            formatted = f'{operations:,}'
            if formatted not in server_guide or f'**{formatted}**' not in replay_guide:
                errors.append('replay documentation differs from MAX_OPERATIONS')
        stale_server_claims = (
            'limits state to 768 KiB',
            'A single `(system,state)` record stores its serialization',
            'current discriminator is 4',
            'New initialization starts at 4',
        )
        for claim in stale_server_claims:
            if claim in server_guide:
                errors.append(f'{SERVER}: stale current storage/schema claim')
        if 'heptabao-state-chunks-v1' not in server_guide:
            errors.append(f'{SERVER}: missing current chunk-manifest storage format')

        replay_code = _without_rust_comments(source)
        replay_source_checks = (
            (
                'cluster replay_epoch field',
                re.search(r'\breplay_epoch\s*:\s*u64\b', replay_code) is not None,
            ),
            ('root replay-retire route', 'sys/storage/raft/replay-retire' in replay_code),
            (
                'durable replay retirement call',
                re.search(r'\bretire_replay_epoch\s*\(', replay_code) is not None,
            ),
            (
                'epoch-scoped durable batch call',
                re.search(r'\bapply_batch_in_replay_epoch\b', replay_code) is not None,
            ),
            ('raft-coordinated capacity mode', 'raft-coordinated' in replay_code),
        )
        for label, present in replay_source_checks:
            if not present:
                errors.append(f'current replay source missing semantic anchor: {label}')
        replay_doc_markers = (
            'replay_epoch',
            'sys/storage/raft/replay-retire',
            'raft-coordinated',
            'heptabao-state-chunks-v1',
            'qa/openbao-acceptance/replay_epoch_ha.py',
        )
        for marker in replay_doc_markers:
            if marker not in replay_guide:
                errors.append(f'{REPLAY}: missing current replay marker: {marker}')
        if Path(REPLAY).name not in server_guide:
            errors.append(f'{SERVER}: missing replay protocol navigation')
        for marker in ('replay_epoch', 'sys/storage/raft/replay-retire', '32,000'):
            if marker not in server_guide:
                errors.append(f'{SERVER}: missing current replay lifecycle marker: {marker}')
        stale_replay_claims = (
            'replay retirement requires single-node mode',
            'current HA state codec remains separately bounded to 768 KiB',
        )
        for claim in stale_replay_claims:
            if claim in server_guide or claim in replay_guide:
                errors.append('replay documentation contains a superseded single-node/768 KiB claim')
        replay_fixture_markers = (
            'heptabao.replay-epoch-ha.v1',
            'sys/storage/raft/replay-retire',
            'sys/step-down',
            'replay_retirement_not_raft_coordinated',
            'leader_before.stop()',
            'second_leader.stop()',
        )
        for marker in replay_fixture_markers:
            if marker not in replay_fixture:
                errors.append(f'{REPLAY_HA}: missing cross-node replay lifecycle marker: {marker}')

        rows = json.loads((root / CORPUS).read_text())["surfaces"]
        expected = []
        for row in rows:
            cases = ', '.join('`' + case + '`' for case in row['fixture_case_ids']) or 'None'
            expected.append(f"| `{row['surface_id']}` | `{row['category']}` | `{row['fixture_state']}` | {cases} |")
        acceptance = (root / ACCEPTANCE).read_text()
        start = '<!-- BEGIN CURRENT REPLACEMENT SURFACES -->'
        end = '<!-- END CURRENT REPLACEMENT SURFACES -->'
        if acceptance.count(start) != 1 or acceptance.count(end) != 1 or acceptance.index(start) >= acceptance.index(end):
            errors.append('missing or ambiguous replacement surface projection')
        else:
            section = acceptance.split(start, 1)[1].split(end, 1)[0]
            actual = [line for line in section.splitlines() if line.startswith('| `HB-SURFACE-')]
            if actual != expected:
                errors.append('replacement execution map differs from fixed corpus rows')
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
        errors.append(f'runtime documentation inputs unavailable: {type(error).__name__}')
    return errors


if __name__ == '__main__':
    problems = validate()
    for problem in problems:
        print('runtime-doc-truth: ' + problem)
    if not problems:
        print('runtime-doc-truth: PASS (selected source drift guards only)')
    raise SystemExit(bool(problems))
