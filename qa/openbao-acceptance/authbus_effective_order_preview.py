#!/usr/bin/env python3
"""Prepare auth-only copies and run a bounded actual-SDK ordering preview.

Never changes live config, credentials, auth rows, services or provider state.
The production source remains live; per-database snapshots are not one global
transaction. A before/after logical-row comparison is reported separately.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import time


AGENT = re.compile(r'[a-z0-9][a-z0-9_-]{0,127}\Z')
CONFIG = {
    'mac': {
        'home': '/Users/qianqi', 'sdk': '/opt/homebrew/lib/node_modules/openclaw',
        'node': '/opt/homebrew/bin/node',
        'configSha256': 'ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d',
        'agentIds': ['main', 'trnm', 'hepta-ui', 'hepta', 'hepta-backend'],
    },
    'rog': {
        'home': '/home/qian-qi', 'sdk': '/home/qian-qi/.npm-global/lib/node_modules/openclaw',
        'node': '/usr/bin/node',
        'configSha256': 'a042bc7fba4ac1295e323e0112598972a2872a040c5464af9614e4c2e600bd15',
        'agentIds': ['main', 'azi2', 'azi3', 'azi4', 'azi5', 'zbj-llm-runtime'],
    },
}
SDK_PINS = {
    'dist/plugin-sdk/agent-runtime.js': '7831532d17eeaddd62889b2e8bb7b65ea7a7851901f69ceec23607a8c579dd95',
    'dist/store-DH33UrUj.js': '25a5c7075e13b8fb32f498a90e5ee91d93b7e15972b3b74796f1325b5ba98ebf',
    'dist/order-CeBlX0NH.js': '4674b1d9ccf77f2b3ef7dd87c394ad99404ba34e6b2a0efed661c4546ac5c732',
}
ORDER_POLICY_SHA = '16bddaa7d18600f9f09dac7b5fb4999a141c86aab1fb15d3e9d6abc24e1cf301'
TABLES = [('store', 'auth_profile_store', 'store_key', 'store_json'),
          ('state', 'auth_profile_state', 'state_key', 'state_json')]


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def read(path, bound=4 * 1024 * 1024, owner=True):
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= bound,
             'source_file_custody')
        need(not owner or before.st_uid == os.geteuid(), 'source_file_owner')
        data = bytearray()
        while len(data) <= bound:
            part = os.read(descriptor, min(65536, bound + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        after = os.fstat(descriptor)
        need(len(data) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'source_changed_while_reading')
        return bytes(data)
    finally:
        os.close(descriptor)


def put(path, value):
    payload = value if isinstance(value, bytes) else encoded(value) + b'\n'
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())


def metadata(path):
    result = {}
    for suffix in ('', '-wal', '-shm'):
        target = Path(str(path) + suffix)
        if not target.exists():
            continue
        value = target.lstat()
        need(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == os.geteuid(), 'database_custody')
        result[suffix] = [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns]
    return result


def capture(live, config, settings):
    need(sha(read(live / 'openclaw.json')) == settings['configSha256'], 'production_config_changed')
    need([entry['id'] for entry in config['agents']['list']] == settings['agentIds'], 'configured_agent_scope_changed')
    output = []
    for entry in config['agents']['list']:
        agent = entry['id']
        need(AGENT.fullmatch(agent) is not None, 'agent_identifier')
        directory = live / 'agents' / agent / 'agent'
        need(Path(entry.get('agentDir', str(directory))) == directory, 'configured_agent_path_changed')
        pathname = directory / 'openclaw-agent.sqlite'
        before = metadata(pathname)
        need('' in before and ('-wal' not in before or '-shm' in before), 'existing_readonly_database_required')
        database = sqlite3.connect(pathname.as_uri() + '?mode=ro', uri=True, timeout=3)
        try:
            database.execute('PRAGMA query_only=ON')
            database.execute('PRAGMA temp_store=MEMORY')
            database.execute('BEGIN')
            rows = {}
            for kind, table, key, column in TABLES:
                values = database.execute('SELECT ' + key + ',' + column + ',updated_at FROM ' + table
                                          + ' WHERE ' + key + '=?', ('primary',)).fetchall()
                need(len(values) <= 1 and all(isinstance(value[1], str) and len(value[1].encode()) <= 1024 * 1024
                                              for value in values), 'primary_auth_row_bound')
                rows[kind] = [list(value) for value in values]
            need(len(rows['store']) == 1, 'existing_primary_store_required')
            profile_count = len(json.loads(rows['store'][0][1]).get('profiles', {}))
            need(profile_count <= 128, 'profile_count_bound')
            output.append({'agent': agent, 'rows': rows, 'profileCount': profile_count,
                           'sourceMetadataBefore': before, 'sourceMetadataAfter': metadata(pathname)})
        finally:
            database.rollback()
            database.close()
    return output


def capture_registry(live):
    pathname = live / 'state/openclaw.sqlite'
    before = metadata(pathname)
    need('' in before and ('-wal' not in before or '-shm' in before), 'existing_readonly_registry_required')
    database = sqlite3.connect(pathname.as_uri() + '?mode=ro', uri=True, timeout=3)
    try:
        database.execute('PRAGMA query_only=ON')
        database.execute('BEGIN')
        schema = database.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='installed_plugin_index'").fetchone()[0]
        cursor = database.execute("SELECT * FROM installed_plugin_index WHERE index_key='installed-plugin-index'")
        columns, rows = [column[0] for column in cursor.description], cursor.fetchall()
        need(len(rows) == 1, 'single_actual_plugin_registry_row')
        return {'schema': schema, 'columns': columns, 'row': list(rows[0]),
                'sourceMetadataBefore': before, 'sourceMetadataAfter': metadata(pathname)}
    finally:
        database.rollback()
        database.close()


def materialize(state, captures, registry):
    for capture_value in captures:
        directory = state / 'agents' / capture_value['agent'] / 'agent'
        directory.mkdir(parents=True, mode=0o700)
        database = sqlite3.connect(str(directory / 'openclaw-agent.sqlite'))
        try:
            database.execute('PRAGMA journal_mode=DELETE')
            database.execute('PRAGMA synchronous=FULL')
            for kind, table, key, column in TABLES:
                database.execute('CREATE TABLE ' + table + ' (' + key + ' TEXT PRIMARY KEY,' + column
                                 + ' TEXT NOT NULL,updated_at INTEGER NOT NULL)')
                database.executemany('INSERT INTO ' + table + ' VALUES (?,?,?)', capture_value['rows'][kind])
            database.commit()
        finally:
            database.close()
        (directory / 'openclaw-agent.sqlite').chmod(0o600)
    folder = state / 'state'
    folder.mkdir(mode=0o700)
    database = sqlite3.connect(str(folder / 'openclaw.sqlite'))
    try:
        database.execute(registry['schema'])
        database.execute('INSERT INTO installed_plugin_index VALUES (' + ','.join('?' for _ in registry['columns']) + ')', registry['row'])
        database.commit()
    finally:
        database.close()
    (folder / 'openclaw.sqlite').chmod(0o600)


def containment(root, live, native, host):
    if host == 'mac':
        base = '/Volumes/T5/hepta-vnext-recovery-20261013'
        rules = ['(version 1)', '(deny default)', '(allow process*)', '(allow signal (target children))',
                 '(allow sysctl-read)', '(allow mach-lookup)', '(allow file-read-metadata)',
                 '(allow file-read* (require-not (subpath ' + json.dumps(base) + ')))',
                 '(allow file-read* (subpath ' + json.dumps(str(root)) + '))',
                 '(allow file-write* (subpath ' + json.dumps(str(root)) + '))',
                 '(allow file-write* (literal "/dev/null"))']
        for directory in (live / 'agents', live / 'state', live / 'credentials', live / 'authbus', native):
            rules.append('(deny file-read* (subpath ' + json.dumps(str(directory)) + '))')
        rules.append('(deny file-read* (literal ' + json.dumps(str(live / 'openclaw.json')) + '))')
        put(root / 'consumer.sb', ('\n'.join(rules) + '\n').encode())
        return ['/usr/bin/sandbox-exec', '-f', str(root / 'consumer.sb')]
    binary = shutil.which('bwrap')
    need(binary is not None, 'bwrap_required')
    args = [binary, '--ro-bind', '/', '/', '--bind', str(root), str(root), '--unshare-net', '--unshare-pid',
            '--proc', '/proc', '--die-with-parent', '--new-session']
    for directory in (live / 'agents', live / 'state', live / 'credentials', live / 'authbus', native):
        need(directory.is_dir(), 'existing_sensitive_directory_required')
        args += ['--ro-bind', str(root / 'empty'), str(directory)]
    args += ['--ro-bind', '/dev/null', str(live / 'openclaw.json')]
    return args


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', choices=tuple(CONFIG), required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--consumer', type=Path, required=True)
    parser.add_argument('--consumer-sha256', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    settings = CONFIG[args.host]
    root = args.work_dir.resolve()
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'schema': 'heptabao.actual-sdk-effective-order-preview-controller.v1', 'ok': False,
              'host': args.host, 'productionConfigChanged': False, 'productionAuthWriteStatementsExecuted': False,
              'providerRequests': 0, 'nativeFactoriesStarted': 0, 'globalProductionSnapshot': False,
              'checks': [], 'productionCutover': False}
    start = time.monotonic()
    captured = registry = None
    process = None
    live = Path(settings['home']) / '.openclaw'
    def check(name, value):
        report['checks'].append({'case': name, 'passed': value is True})
        need(value is True, name)
    try:
        consumer = read(args.consumer)
        check('frozen_consumer', sha(consumer) == args.consumer_sha256)
        put(root / 'consumer.mjs', consumer)
        source_pins = {str(Path(settings['sdk']) / name): pin for name, pin in SDK_PINS.items()}
        policy = live / 'extensions/openclaw-authbus/order-policy.js'
        source_pins[str(policy)] = ORDER_POLICY_SHA
        source_pins[str(root / 'consumer.mjs')] = args.consumer_sha256
        for pathname, expected in source_pins.items():
            check('source.' + Path(pathname).name, sha(read(Path(pathname), owner=False)) == expected)
        config_bytes = read(live / 'openclaw.json')
        check('exact_current_config', sha(config_bytes) == settings['configSha256'])
        config = json.loads(config_bytes)
        captured = capture(live, config, settings)
        registry = capture_registry(live)
        put(root / 'production-config.private.json', config_bytes)
        put(root / 'auth-rows.private.json', captured)
        put(root / 'registry.private.json', registry)
        state = root / 'state'
        state.mkdir(mode=0o700)
        materialize(state, captured, registry)
        preview_config = copy.deepcopy(config)
        for entry in preview_config['agents']['list']:
            entry['agentDir'] = str(state / 'agents' / entry['id'] / 'agent')
            if 'workspace' in entry:
                entry['workspace'] = str(root / 'workspace')
        if 'workspace' in preview_config.get('agents', {}).get('defaults', {}):
            preview_config['agents']['defaults']['workspace'] = str(root / 'workspace')
        put(state / 'openclaw.json', preview_config)
        for directory in (root / 'tmp', root / 'home', root / 'empty', root / 'workspace', state / 'oauth'):
            directory.mkdir(mode=0o700)
        plan = {'host': args.host, 'stateRoot': str(state), 'sdkRoot': settings['sdk'], 'orderPolicyPath': str(policy),
                'sourcePins': source_pins, 'agentIds': settings['agentIds'],
                'localProfilesByAgent': {value['agent']: value['profileCount'] for value in captured},
                'expectedProfileIdSha256': ['7b0b24e17c166c04c73864d9d276562e30c15bd5bf9f719ea3abd1a9687b0c0d',
                                           'eef0b72e4a8ba90bee622442f4d489172568664397a6da152e3faf0bf9eac6a1']}
        put(root / 'plan.private.json', plan)
        argv = containment(root, live, Path(settings['home']) / '.codex', args.host)
        argv += [settings['node'], str(root / 'consumer.mjs'), str(root / 'plan.private.json')]
        env = {'PATH': '/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(root / 'home'),
               'TMPDIR': str(root / 'tmp'), 'OPENCLAW_STATE_DIR': str(state),
               'OPENCLAW_CONFIG_PATH': str(state / 'openclaw.json'), 'OPENCLAW_OAUTH_DIR': str(state / 'oauth'),
               'OPENCLAW_HOME': str(root / 'home'), 'OPENCLAW_AUTH_STORE_READONLY': '1'}
        with open(root / 'stdout.private', 'xb') as stdout, open(root / 'stderr.private', 'xb') as stderr:
            process = subprocess.Popen(argv, cwd=str(root), env=env, stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                process.wait(timeout=35)
            except subprocess.TimeoutExpired:
                report['timedOut'] = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                raise Refused('pure_consumer_deadline') from None
        check('actual_consumer_exited_successfully', process.returncode == 0)
        result_bytes = read(root / 'result.public.json')
        result = json.loads(result_bytes)
        check('actual_sdk_preservation_preview', result.get('ok') is True and bool(result.get('qualifyingPolicies')))
        report['consumerResultSha256'] = sha(result_bytes)
        report['qualifyingPolicies'] = result['qualifyingPolicies']
        report['sourcePins'] = source_pins
        report['ok'] = True
    except Exception as error:
        report['error'] = str(error) if isinstance(error, Refused) else type(error).__name__
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        report['ownedProcessReaped'] = process is None or process.poll() is not None
        if captured is not None:
            try:
                after = capture(live, config, settings)
                exact_rows = [value['rows'] for value in after] == [value['rows'] for value in captured]
                report['productionPrimaryAuthRowsUnchanged'] = exact_rows
                report['perDatabaseMetadataStableThroughoutCapture'] = all(value['sourceMetadataBefore'] == value['sourceMetadataAfter'] for value in captured + after)
                report['productionSourceScope'] = 'Separate read-only SQL transactions with exact primary-row equality before/after; running-production sidecar metadata is observed separately and is not a global snapshot claim.'
                if not exact_rows:
                    report['ok'] = False
            except Exception as error:
                report['ok'] = False
                report['sourceRecheckError'] = str(error) if isinstance(error, Refused) else type(error).__name__
        if registry is not None:
            try:
                registry_after = capture_registry(live)
                report['actualRegistryUnchanged'] = all(registry_after[key] == registry[key]
                                                        for key in ('schema', 'columns', 'row'))
                report['registryMetadataStableThroughoutCapture'] = all(value['sourceMetadataBefore'] == value['sourceMetadataAfter']
                                                                         for value in (registry, registry_after))
                report['registryReadScope'] = 'Exact installed-plugin-index row in separate read-only SQL transactions; preexisting WAL requires preexisting SHM, metadata stability is reported separately.'
                if not report['actualRegistryUnchanged']:
                    report['ok'] = False
            except Exception:
                report['actualRegistryUnchanged'] = False
                report['ok'] = False
        report['elapsedSeconds'] = time.monotonic() - start
        put(root / 'controller.public.json', report)
        print(json.dumps({'ok': report['ok'], 'error': report.get('error'), 'result': str(root / 'controller.public.json'),
                          'sha256': sha(read(root / 'controller.public.json'))}))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
