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
STATE_STORE = 'crates/heptabao-server/src/service_owner_store.rs'
RECORD_ROOT = 'crates/heptabao-server/src/state_record_root.rs'
RECORD_CORE = 'crates/heptabao-server/src/state_records.rs'


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


def _capacity_rows(text: str) -> dict[tuple[str, str], list[str]]:
    """Read the operator-facing source table, retaining duplicates as errors."""
    rows: dict[tuple[str, str], list[str]] = {}
    for line in text.splitlines():
        cells = [cell.strip() for cell in line.strip().strip('|').split('|')]
        if not line.lstrip().startswith('|') or len(cells) != 4:
            continue
        layout, constant, value, _scope = cells
        if not re.fullmatch(r'`[A-Za-z_]+::[A-Z_]+`', constant):
            continue
        rows.setdefault((layout, constant.strip('`')), []).append(
            re.sub(r'\s+', '', value.replace('**', '').replace('`', '')))
    return rows


def _check_capacity_constant(rows, layout: str, qualified: str, value: str,
                             errors: list[str]) -> None:
    if rows.get((layout, qualified)) != [re.sub(r'\s+', '', value)]:
        errors.append(f'capacity source table differs from {layout} {qualified}')


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
            for found in re.findall(r'(?:Service schema (?:remains |is )|Service state is (?:now )?schema |Existing state remains schema |`State` schema |[Cc]urrent(?: application)? writes use schema |[Cc]urrent application writes use schema |[Cc]urrent schema )(\d+)', text):
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
        # The V4 bounds remain active for legacy decoding/publication. V5
        # separates the opaque-owner bound from its immutable KV1 graph; neither
        # component sum is a usable durable or HA capacity promise.
        rows = _capacity_rows(capacity_guide)
        sources = {
            'server': _without_rust_comments(server_lib),
            'service_owner_store': _without_rust_comments(state_store),
            'state_record_root': _without_rust_comments((root / RECORD_ROOT).read_text()),
            'state_records': _without_rust_comments((root / RECORD_CORE).read_text()),
        }
        limits = (
            ('Shared', 'server', 'MAX_APPLICATION_STATE_BYTES', 'MiB'),
            ('V4 legacy', 'service_owner_store', 'STATE_CHUNK_BYTES', 'KiB'),
            ('V4 legacy', 'service_owner_store', 'STATE_CHUNK_MIN_BYTES', 'KiB'),
            ('V4 legacy', 'service_owner_store', 'STATE_CHUNK_MAX_BYTES', 'KiB'),
            ('V5 records', 'state_record_root', 'MAX_ROOT_BYTES', 'KiB'),
            ('V5 records', 'state_record_root', 'OWNER_CHUNK_BYTES', 'KiB'),
            ('V5 records', 'state_records', 'BLOCK_BYTES', 'KiB'),
            ('V5 records', 'state_records', 'PAGE_BYTES', 'KiB'),
            ('V5 records', 'state_records', 'MAX_VALUE_BYTES', 'MiB'),
            ('V5 records', 'state_records', 'MAX_GRAPH_BYTES', 'MiB'),
        )
        for layout, owner, constant, unit in limits:
            scale = r'\s*\*\s*1024' * (2 if unit == 'MiB' else 1)
            number = _one(
                rf'\b{constant}\s*:\s*usize\s*=\s*([\d_]+){scale}\s*;',
                sources[owner], f'{owner}::{constant} missing or ambiguous', errors)
            if number is not None:
                _check_capacity_constant(rows, layout, f'{owner}::{constant}',
                                         f'{int(number.replace("_", ""))} {unit}', errors)
        for layout, owner, constant in (
            ('V4 legacy', 'service_owner_store', 'STATE_STORAGE_FORMAT'),
            ('V5 records', 'state_record_root', 'STORAGE_FORMAT'),
        ):
            storage_format = _one(
                rf'\b{constant}\s*:\s*&str\s*=\s*"([^\"]+)"\s*;',
                sources[owner], f'{owner}::{constant} missing or ambiguous', errors)
            if storage_format is not None:
                _check_capacity_constant(rows, layout, f'{owner}::{constant}', storage_format, errors)
                for path, guide in ((SERVER, server_guide), (REPLAY, replay_guide)):
                    if storage_format not in guide:
                        errors.append(f'{path}: missing {layout} storage format')
        for path, guide in ((SERVER, server_guide), (REPLAY, replay_guide)):
            if Path(CAPACITY).name not in guide:
                errors.append(f'{path}: missing shared capacity-contract navigation')
        for stale in (
            'The serialized logical application state is bounded to **16 MiB**. Local durability uses the current',
            'The bounded profile limits the serialized logical application state to 16 MiB locally and in HA;',
        ):
            if any(stale in re.sub(r'\s+', ' ', guide) for guide in (server_guide, replay_guide)):
                errors.append('runtime docs describe legacy whole-state ownership as the sole current layout')
        operations_raw = _one(
            r'\bMAX_OPERATIONS\s*:\s*usize\s*=\s*([\d_]+)\s*;',
            source, 'replay operation-identity bound is missing or ambiguous', errors)
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
        # Rust source text is not a behavioral proof.  In particular, regexes
        # over field declarations/call layout produced false drift alarms after
        # harmless refactors.  Replay semantics are exercised by compiled native
        # tests and the mandatory real three-process replay_epoch_ha.py fixture.
        # Keep only stable public route/protocol markers here so documentation can
        # still fail closed when the operator surface itself disappears.
        replay_code = _without_rust_comments(source)
        for label, marker in (
            ('root replay-retire route', 'sys/storage/raft/replay-retire'),
            ('raft-coordinated capacity mode', 'raft-coordinated'),
        ):
            if marker not in replay_code:
                errors.append(f'current replay source missing stable protocol marker: {label}')
        replay_doc_markers = (
            'replay_epoch',
            'sys/storage/raft/replay-retire',
            'raft-coordinated',
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
