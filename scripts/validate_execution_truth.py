#!/usr/bin/env python3
"""Small current-tense drift checks for the delivered runtime, not test evidence."""
from pathlib import Path
import json
import re
import yaml

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    'README.md', 'docs/auth/HEPTABAO_SINGLE_NODE_AUTH.md',
    'docs/engines/HEPTABAO_POSTGRESQL_PROVIDER.md',
    'docs/plan/HEPTABAO_SINGLE_NODE_EXECUTION_STATUS.md',
    'docs/modules/heptabao-server.md', 'docs/modules/heptabao-durable-service.md',
    'docs/operations/HEPTABAO_CAPACITY_AND_GROWTH.md',
    'planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml',
    'qa/openbao-acceptance/complete_surface_corpus_v1.json',
    'crates/heptabao-server/src/service.rs', 'crates/heptabao-durable-service/src/lib.rs',
)


def validate(root: Path = ROOT) -> list[str]:
    try:
        text = {p: (root/p).read_text(encoding='utf-8') for p in FILES}
        problems = []
        forbidden = {
            'README.md': ['Actual PostgreSQL server/SQL acceptance has not been executed in this delivery'],
            'docs/auth/HEPTABAO_SINGLE_NODE_AUTH.md': ['It still does not fetch a `jwks_url`', 'OIDC discovery/browser login'],
            'docs/modules/heptabao-server.md': ['A signed manifest', 'Invalid framing rejected before service dispatch has no service audit record'],
            'docs/modules/heptabao-durable-service.md': ['automatic journal compaction are unimplemented'],
        }
        for path, phrases in forbidden.items():
            if any(phrase in text[path] for phrase in phrases):
                problems.append(path + ': obsolete current-tense execution/crypto statement')
        status = text['docs/plan/HEPTABAO_SINGLE_NODE_EXECUTION_STATUS.md']
        for anchor in ('0ddbb3a3abae30f14d9267fa56c6dd67d8de08f5', '34924284502',
                       '104238879906', '104238880100'):
            if anchor not in status:
                problems.append('baseline execution observation lost exact source/run/job binding')
        # The baseline receipt is historical, never a current candidate's pass.
        if 'later' not in status.lower() or 'independent' not in status.lower():
            problems.append('execution status lost non-inheritance or independent boundary')
        blockers = yaml.safe_load(text['planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml'])
        corpus = json.loads(text['qa/openbao-acceptance/complete_surface_corpus_v1.json'])
        remaining = sum(row['fixture_state']=='DEFINED_NOT_IMPLEMENTED' for row in corpus['surfaces'])
        rows = blockers.get('repository_blockers', [])
        target = next(v for v in rows if v['id']=='HB-V2-REP-016')
        current = target['title'] + ' ' + ' '.join(target['closure_criteria'])
        for a, b in re.findall(r'(\d+) surface fixtures|remaining (\d+) surfaces', current):
            if int(a or b) != remaining:
                problems.append('REP-016 remaining fixture count differs from corpus rows')
        for symbol in ('capacity', 'preflight_new_identity', 'put_with_compaction'):
            if f'pub fn {symbol}(' not in text['crates/heptabao-durable-service/src/lib.rs']:
                problems.append('capacity guide has no current native API: ' + symbol)
        if 'sys/internal/capacity' not in text['crates/heptabao-server/src/service.rs']:
            problems.append('capacity guide has no current Service route')
        service_source = text['crates/heptabao-server/src/service.rs']
        # The real Service state writer must bind compaction to the currently
        # authenticated replay epoch. Matching the legacy epoch-0 wrapper is not
        # sufficient after replay retirement because it would reject every write
        # following an epoch transition.
        epoch_compaction_writer = re.compile(
            r"let\s+replay_epoch\s*=\s*durable\.replay_epoch\(\);\s*"
            r"if\s+compact_before_entry\s*\{\s*"
            r"durable\.apply_batch_with_compaction_in_replay_epoch\(\s*"
            r"replay_epoch\s*,",
            re.S,
        )
        if epoch_compaction_writer.search(service_source) is None:
            problems.append(
                'atomic batch compaction is not bound to the current replay epoch in the real Service writer'
            )
        return problems
    except (OSError, ValueError, KeyError, TypeError, StopIteration, yaml.YAMLError) as exc:
        return ['execution truth inputs invalid: ' + type(exc).__name__]


if __name__=='__main__':
    errors = validate()
    for error in errors:
        print('execution-truth: ' + error)
    if not errors:
        print('execution-truth: PASS (source/doc drift guard, not execution admission)')
    raise SystemExit(bool(errors))
