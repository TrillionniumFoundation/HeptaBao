#!/usr/bin/env python3
"""Verify selected runtime regressions are compiled, not merely inventoried.

This is a test-discovery gate, NOT a passing test suite or product qualification.
The workspace tests must still execute separately. The named tests bind the
recent ACL/proxy integration to the Rust module graph; they are not all modules.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SERVER_TESTS = frozenset({
    'auth::acl::tests::priority_uses_documented_specificity_and_not_capability_union',
    'auth::acl::tests::persisted_policy_cache_is_checked_against_source',
    'service::acl_service_tests::constrained_denial_consumes_use_without_business_mutation_across_reopen',
    'service::acl_service_tests::capability_inspection_never_consumes_target_and_reads_current_policy',
})
PROXY_TESTS = frozenset({
    'runtime::tests::credentials_are_not_part_of_the_forwarded_request_and_wrap_is_preserved',
    'runtime::tests::socket_publication_requires_private_owner_directory_and_stable_lock',
    'runtime::tests::a_failed_worker_does_not_detach_remaining_workers',
})


def missing_tests(output: str, linux: bool) -> list[str]:
    observed = {line[:-6] for line in output.splitlines() if line.endswith(': test')}
    required = SERVER_TESTS | (PROXY_TESTS if linux else frozenset())
    return sorted(required - observed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    command = ['cargo', 'test', '--locked']
    if args.offline:
        command.append('--offline')
    command += ['-p', 'heptabao-server', '-p', 'heptabao-proxy', '--all-targets', '--', '--list']
    try:
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=(os.name == 'posix'))
            try:
                code = process.wait(timeout=300)
            except subprocess.TimeoutExpired:
                if os.name == 'posix':
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait()
                raise ValueError('compiled test discovery timed out') from None
            output.seek(0)
            raw = output.read(8 * 1024 * 1024 + 1)
        if code != 0 or len(raw) > 8 * 1024 * 1024:
            raise ValueError('compiled test discovery failed or exceeded output limit')
        missing = missing_tests(raw.decode('utf-8'), sys.platform.startswith('linux'))
        print(json.dumps({'gate': 'compiled-runtime-test-discovery',
                          'missing_tests': missing, 'test_execution': False,
                          'qualification': False, 'status': 'failed' if missing else 'passed'}))
        return int(bool(missing))
    except (OSError, ValueError) as error:
        print(json.dumps({'gate': 'compiled-runtime-test-discovery', 'status': 'failed',
                          'error_type': type(error).__name__, 'qualification': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
