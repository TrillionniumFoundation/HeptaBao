#!/usr/bin/env python3
"""Lossless validation of captured public output; no host API or child run."""
import hashlib
import json
from pathlib import Path


def main():
    data = json.loads(Path(__file__).with_name('inputs.json').read_text())
    r, a, streams, ack, request, go = [json.loads(data[name]) for name in ('stdout', 'authority', 'streams', 'ack', 'request_without_stdin', 'go')]
    checks = []

    def check(label, condition):
        if not condition:
            raise AssertionError(label)
        checks.append(label)

    check('request whole SHA previously recomputed', data['request_full_sha256'] == go['request']['sha256'])
    check('ACK exact requested host exe args cwd key', all(ack['job'][f] == request[f] for f in ('host', 'executable', 'args', 'cwd', 'idempotency_key')))
    check('ACK new launched', ack['reused'] is False and ack['job']['launch_state'] == 'launched' and ack['launch']['ok'])
    check('authority exact job', a['job_id'] == ack['job']['id'] == '1a1aaced08e-fc05-478b')
    check('authority succeeded zero', a['state'] == 'succeeded' and a['exit_code'] == 0)
    check('authority full durable confirmed', a['output_complete'] and a['output_durable'] and a['terminal_publication_confirmed'])
    check('authority no timeout cancellation retry', not a['timed_out'] and not a['cancelled'] and a['automatic_retry'] is False)
    for name in ('stdout', 'stderr'):
        s = streams[name]
        raw = bytes.fromhex(s['bytes_hex'])
        check(name + ' bytes text exact', raw == s['text'].encode())
        check(name + ' complete zero offset EOF', s['offset'] == 0 and s['size'] == s['next_offset'] == len(raw) and s['eof'])
        check(name + ' authoritative length', a['log_bytes'][name] == {'seen': len(raw), 'stored': len(raw)})
        check(name + ' no truncation log error', a['log_synced'][name] and a['log_errors'][name] is None and a['log_truncated'][name] is False)
    check('stdout exact report', streams['stdout']['text'] == data['stdout'])
    check('stderr empty', streams['stderr']['text'] == '')
    check('component passed', r['status'] == 'passed')
    check('original caps', (r['shared_component_seconds'], r['cleanup_term_seconds'], r['cleanup_kill_seconds']) == (15, 5, 5))
    check('single original absolute deadline', r['deadline_monotonic_ns'] - r['started_monotonic_ns'] == 15_000_000_000)
    check('closure within original deadline', r['started_monotonic_ns'] < r['completed_monotonic_ns'] < r['deadline_monotonic_ns'] and r['within_shared_15s'])
    check('all input fds closed', r['all_input_fds_closed'])
    check('no Cargo product network disk outputs', r['product_or_cargo_requests'] == r['network_requests'] == r['on_disk_output_files'] == 0 and r['candidate_main_executed'] is False)
    check('whole tool identities unchanged losslessly', r['tools_before'] == r['tools_after'])
    check('exact two tools', set(r['tools_before']) == {'git', 'python'})
    check('exact three cases cleanup', len(r['cases']) == len(r['cleanup']) == 3)
    check('three unique PIDs', len({c['pid'] for c in r['cases']}) == 3)
    for index, (case, name, code) in enumerate(zip(r['cases'], ['ordinary_short_owned_git', 'already_terminal_unreaped_git', 'nonzero_terminal_preserved'], (0, 0, 129))):
        p = case['custody']
        check(name + ' passed exact exit', case['case'] == name and case['passed'] and case['returncode'] == code)
        check(name + ' registered before observation', p['popen_returned'] and p['provisionally_registered_before_observation'] and p['custody_verified'])
        check(name + ' no false cmdline proof', p['live_proc_argv_observed'] is False)
        before, after = p['identity_before'], p['identity_after']
        check(name + ' same unreaped identity', all(before[f] == after[f] for f in ('pid', 'ppid', 'pgid', 'start_ticks')) and before['pid'] == before['pgid'] == case['pid'] and before['start_ticks'] > 0)
        event = p['terminal_event']
        check(name + ' WNOWAIT terminal preserved', event['not_reaped'] and event['pid'] == case['pid'] and event['uid'] == 1000 and event['expected_returncode'] == code)
        check(name + ' exact terminal consumed', p['terminal_consumed'] and p['wait_returncode'] == code and p['waitid_calls'] >= 2)
        check(name + ' group empty', case['remaining'] == [])
        if index:
            check(name + ' actual forced zombie', case['terminal_before_stat_forced'] and before['state'] == after['state'] == 'Z')
        rows = [row for row in r['cleanup'] if row['pid'] == case['pid']]
        check(name + ' one cleanup row', len(rows) == 1)
        row = rows[0]
        check(name + ' cleanup exact and closed', row['owned_stopped'] and row['direct_child_reaped'] and row['stop_terminal_captured'] and row['remaining'] == [] and row['wait_returncode'] == code and row['start_ticks'] == before['start_ticks'])
    check('two forced terminal observations', len(r['forced_terminal_observations']) == 2 and [e['expected_returncode'] for e in r['forced_terminal_observations']] == [0, 129])
    print(json.dumps({'schema': 'heptabao.qa-custody-r2-actual-lossless-review.v1', 'status': 'PASS_COMPONENT_SCOPE_ONLY', 'checks': checks, 'passed': len(checks), 'job_id': a['job_id'], 'elapsed_ns': r['completed_monotonic_ns'] - r['started_monotonic_ns'], 'limits': ['Three public Git custody components only.', 'No Cargo, client TLS, service, provider or production qualification.', 'Original R1 unknown remains unchanged.', 'All original numeric fields parsed with Python integers; full request hash verified separately.']}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
