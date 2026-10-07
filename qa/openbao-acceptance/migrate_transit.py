#!/usr/bin/env python3
"""Explicit Transit decrypt/re-encrypt with private per-record restart checkpoints."""
from pathlib import Path
import json
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'clients/python'))
from heptabao.private_state import StateDirectory
from heptabao.transport import BaoError, SafeArgumentParser, private_json
from heptabao.transit_migration import TransitMigrator, load_configuration, records_from


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--state-dir', required=True, type=Path)
    parser.add_argument('--allow-reencryption', action='store_true')
    args = parser.parse_args(argv)
    config = load_configuration(args.config)
    records = records_from(private_json(args.input))
    if not args.allow_reencryption:
        print(json.dumps({'status': 'dry_run_no_network', 'record_count': len(records), 'full_format_migration': False}))
        return 0
    with StateDirectory(args.state_dir, writer=True) as directory:
        result = TransitMigrator(directory, config, records).migrate()
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (BaoError, OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'status': 'blocked_or_failed', 'reason': 'inspect_private_checkpoint_no_blind_retry',
                          'full_format_migration': False}))
        raise SystemExit(2) from None
