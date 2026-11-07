#!/usr/bin/env python3
"""Fixed registry row across the actual post-stop SQLite namespace modes.

The nonempty WAL route is the original qualified registry implementation.
Absent/strictly empty WAL uses the actual qualified auth reader's held-FD
immutable URI and the same tracked connection/cursor/close mechanics, with the
original registry-only query. No original sidecar is created or removed.
Caller authority must establish current consumer quiescence independently.
"""
from __future__ import annotations

from pathlib import Path
import time

LIVE = Path('/Users/qianqi/.openclaw')
DATABASE = LIVE / 'state/openclaw.sqlite'
WAL_ROUTE = 'qualified_named_readonly_wal_transaction'
IMMUTABLE_ROUTE = 'tracked_held_fd_immutable_registry_transaction'


def registry_database(auth, inputs):
    wal, base = auth.wal, auth.base
    base.need(inputs.live == LIVE, 'poststop_registry_fixed_live_root')
    inputs.current_phase = 'poststop_registry_namespace_admission'
    main = inputs.hold(DATABASE)
    base.need(int(main['expected'][6]) >= 512, 'poststop_registry_main_header_bound')
    log = inputs.hold(Path(str(DATABASE) + '-wal'), optional=True, maximum=wal.WAL_MAXIMUM)
    shared = inputs.hold(Path(str(DATABASE) + '-shm'), optional=True, maximum=8 * base.MIB)
    journal = inputs.hold(Path(str(DATABASE) + '-journal'), optional=True, maximum=0)
    base.need(journal is None, 'poststop_registry_rollback_journal_refused')
    nonempty = log is not None and int(log['expected'][6]) > 0
    if nonempty:
        base.need(int(log['expected'][6]) >= 32 and shared is not None
                  and int(shared['expected'][6]) > 0, 'poststop_registry_nonempty_wal_requires_existing_shm')
    if log is None:
        base.need(shared is None, 'poststop_registry_orphan_shm_refused')
    base.need(all(row['expected'][3] == '20' for row in (main, log, shared) if row is not None),
              'poststop_registry_exact_group')
    inputs.verify()
    wanted = set(DATABASE.parents)
    parents = [{'row': row, 'expected': wal._full_parent(row)}
               for key, row in inputs.parents.items() if Path(key) in wanted]
    base.need(len(parents) == len(wanted), 'poststop_registry_complete_original_parent_chain')
    bundle = {'main': main, 'wal': log, 'shm': shared, 'parents': parents,
              'journal': str(DATABASE) + '-journal', 'verified': False, 'checks': 0,
              'nonemptyWal': nonempty}
    inputs.bundles.append(bundle)
    verify(auth, inputs, bundle, until=inputs.until)
    return bundle


def verify(auth, inputs, bundle, *, until):
    auth.base.need(bundle['main']['path'] == str(DATABASE), 'poststop_registry_only_fixed_database')
    # This original verifier already handles absent, zero, and nonempty WAL
    # plus optional SHM with complete held/named full9 and journal absence.
    return auth.verify_auth_bundle(inputs, bundle, until=until)


def read_registry(auth, inputs, bundle):
    wal, base = auth.wal, auth.base
    verify(auth, inputs, bundle, until=inputs.until)
    if bundle['nonemptyWal']:
        return wal.readonly_wal_query(inputs, bundle), WAL_ROUTE
    started = time.monotonic()
    until = min(inputs.until, started + base.MAX_QUERY_SECONDS)
    row = {'route': 'registry_held_fd_immutable', 'startedMonotonic': started,
           'deadlineMonotonic': until, 'connectionIndex': None, 'completedMonotonic': None,
           'success': False, 'error': None, 'dataResultPublished': False,
           'rolledBack': False, 'queryClosureKnown': False}
    inputs.queries.append(row)
    connection, value, error = None, None, None
    try:
        inputs.current_phase = 'poststop_registry_immutable_preconnect_fence'
        verify(auth, inputs, bundle, until=until)
        base.need(bundle['wal'] is None or int(bundle['wal']['expected'][6]) == 0,
                  'poststop_registry_immutable_requires_absent_or_empty_wal')
        expected_path = '/dev/fd/' + str(bundle['main']['fd'])
        uri = 'file:' + expected_path + '?mode=ro&immutable=1'
        inputs.current_phase = 'poststop_registry_immutable_connect'
        connection = inputs.connect(uri, until=until, label='registry-held-fd-immutable')
        row['connectionIndex'] = len(inputs.connections) - 1
        wal.configure_connection(inputs, connection, until=until)
        actual = inputs.execute(connection, 'PRAGMA database_list', until=until, limit=1,
                                label='poststop-registry-database-list')
        base.need(len(actual) == 1 and actual[0][1] == 'main' and actual[0][2] == expected_path,
                  'poststop_registry_exact_original_held_inode_uri')
        inputs.execute(connection, 'BEGIN', until=until, label='poststop-registry-begin')
        verify(auth, inputs, bundle, until=until)
        inputs.current_phase = 'poststop_registry_fixed_row_read'
        value = wal.read_registry(inputs, connection, until=until)
        verify(auth, inputs, bundle, until=until)
        inputs.execute(connection, 'ROLLBACK', until=until, label='poststop-registry-rollback')
        row['rolledBack'] = True
    except BaseException as caught:
        error = caught
    finally:
        if connection is not None:
            inputs.close_connection_once(connection)
        row['queryClosureKnown'] = ((connection is None or connection['closed'])
                                   and all(cursor['closed'] for cursor in inputs.cursors))
    try:
        base.need(row['queryClosureKnown'], 'poststop_registry_query_close_unconfirmed')
        if error is None:
            verify(auth, inputs, bundle, until=until)
    except BaseException as caught:
        if error is None:
            error = caught
    completed = time.monotonic()
    row['completedMonotonic'] = completed
    if (inputs.cancelled() or completed >= until) and error is None:
        error = base.CaptureRefused('poststop_registry_original_query_deadline_after_closure')
    if error is not None:
        row['error'] = wal.failure_record(error)
        raise error
    row['success'] = True
    return value, IMMUTABLE_ROUTE
