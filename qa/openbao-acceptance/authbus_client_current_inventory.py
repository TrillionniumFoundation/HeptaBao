#!/usr/bin/env python3
"""Bounded, read-only metadata for existing AuthBus clients and entrypoints.

Run as the existing owner on one authorized host. No network, SDK import,
credential resolution, service action, OAuth refresh, or recursive home scan.
Only configuration metadata, paths, field names, code hashes and syntax-derived
entrypoints leave the host. Credential values and quoted source are omitted.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shlex
import stat
import time
from urllib.parse import urlsplit

LIMIT = 2 * 1024 * 1024
CODE_LIMIT = 262144
END = time.monotonic() + 18
HOME_PATH = Path.home()
STATE = HOME_PATH / '.openclaw'
LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,179}\Z')
MATCH = re.compile(r'authbus|auth-bus|credential[-_]?sync|auth[-_]?coordinator', re.I)
CODE_SUFFIXES = {'.py', '.sh', '.js', '.mjs', '.ts', '.service', '.timer', '.plist'}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def label(value):
    return value if isinstance(value, str) and LABEL.fullmatch(value) else None


def metadata(path):
    result = {'path': str(path)}
    try:
        item = path.lstat()
        result.update(exists=True, uid=item.st_uid, gid=item.st_gid,
                      mode=oct(stat.S_IMODE(item.st_mode)), size=item.st_size,
                      mtime_ns=item.st_mtime_ns, symlink=stat.S_ISLNK(item.st_mode),
                      regular_file=stat.S_ISREG(item.st_mode), directory=stat.S_ISDIR(item.st_mode))
    except OSError as exc:
        result.update(exists=False, error=type(exc).__name__)
    return result


def read(path, maximum=LIMIT):
    item = metadata(path)
    if time.monotonic() >= END or not item.get('regular_file') or item.get('symlink') or item['size'] > maximum:
        item['content_read'] = False
        return item, None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                raise ValueError('bounded_regular_file_required')
            chunks, size = [], 0
            while True:
                chunk = os.read(fd, min(65536, maximum + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > maximum:
                    raise ValueError('file_exceeded_bound')
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError('file_changed_during_read')
            payload = b''.join(chunks)
        finally:
            os.close(fd)
        item.update(content_read=True, sha256=digest(payload))
        return item, payload
    except (OSError, ValueError) as exc:
        item.update(content_read=False, error=type(exc).__name__)
        return item, None


def read_json(path):
    item, payload = read(path)
    if payload is not None:
        try:
            value = json.loads(payload)
            if isinstance(value, dict):
                return item, value
        except (ValueError, UnicodeError):
            pass
        item['parse_error'] = True
    return item, {}


def reference(value):
    if not isinstance(value, str) or len(value) > 1024:
        return None
    for prefix in ('${HOME}/', '$HOME/', '%h/', '~/'):
        if value.startswith(prefix):
            value = str(HOME_PATH / value[len(prefix):])
            break
    if value.startswith('/') and re.fullmatch(r'/[A-Za-z0-9_./@+ :\-]+', value):
        return value
    return None


def endpoint(value):
    try:
        parsed = urlsplit(value if isinstance(value, str) else '')
        return {'configured': bool(parsed.hostname), 'scheme': label(parsed.scheme),
                'host': label(parsed.hostname), 'port': parsed.port,
                'has_userinfo': bool(parsed.username or parsed.password),
                'has_query': bool(parsed.query), 'path_sha256': digest(parsed.path.encode()),
                'references_j3160': (parsed.hostname or '').lower() in ('j3160', '100.66.117.33')}
    except ValueError:
        return {'parse_error': True}


def model(value):
    if isinstance(value, str):
        return {'primary': label(value)}
    if isinstance(value, dict):
        return {'primary': label(value.get('primary')),
                'fallbacks': [label(x) for x in value.get('fallbacks', [])[:32]
                              if isinstance(value.get('fallbacks'), list) and label(x)]}
    return None


def command_metadata(value):
    if not isinstance(value, str) or len(value) > 16384:
        return {'omitted': True}
    try:
        argv = shlex.split(value)
    except ValueError:
        return {'parse_error': True}
    executable = reference(argv[0].lstrip('-@:+!')) if argv else None
    return {'executable': executable, 'argument_count': max(0, len(argv) - 1),
            'path_references': sorted({r for v in argv for r in [reference(v)] if r}),
            'inline_code_present': any(v in ('-c', '-e', '--eval') for v in argv)}


def source_metadata(path):
    item, payload = read(path, CODE_LIMIT)
    if payload is None:
        return item
    if path.suffix == '.plist':
        try:
            value = plistlib.loads(payload)
            item['launch_label'] = label(value.get('Label'))
            args = value.get('ProgramArguments', [])
            item['launch_program'] = reference(value.get('Program'))
            item['argument_count'] = len(args) if isinstance(args, list) else None
            item['path_references'] = [p for v in args[:32] for p in [reference(v)] if p]
            item['environment_field_names'] = sorted(value.get('EnvironmentVariables', {}))[:64]
        except (ValueError, TypeError, KeyError):
            item['parse_error'] = True
        return item
    try:
        text = payload.decode('utf8')
    except UnicodeError:
        item['non_utf8'] = True
        return item
    item['mentions_j3160'] = bool(re.search(r'j3160|100\.66\.117\.33', text, re.I))
    if path.suffix in ('.service', '.timer'):
        directives = []
        for line in text.splitlines():
            if not line or line.startswith(('#', ';', '[')) or '=' not in line:
                continue
            key, val = line.split('=', 1)
            if key in ('ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecStop'):
                directives.append({'directive': key, **command_metadata(val)})
            elif key in ('EnvironmentFile', 'WorkingDirectory'):
                directives.append({'directive': key, 'path': reference(val.lstrip('-'))})
        item['directives'] = directives[:32]
    elif path.suffix == '.py':
        try:
            tree = ast.parse(text)
            item['functions'] = sorted({node.name for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))})[:160]
            item['imports'] = sorted({node.module or '' for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)} | {alias.name for node in ast.walk(tree)
                if isinstance(node, ast.Import) for alias in node.names})[:80]
        except SyntaxError:
            item['parse_error'] = True
    else:
        item['functions'] = sorted(set(re.findall(r'\b(?:function|class)\s+([A-Za-z_$][\w$]*)', text)))[:160]
        item['path_references'] = sorted({p for quoted in re.findall(r'[\'\"]([^\'\"\n]{1,1024})[\'\"]', text)
                                          for p in [reference(quoted)] if p})[:64]
    # These are existence indicators, never a claim that the code runs there.
    item['operation_indicators'] = {
        'manifest': 'manifest' in text, 'inbox': 'inbox' in text,
        'cas': bool(re.search(r'\bcas\b', text, re.I)),
        'scheduler': 'scheduler' in text, 'writer': bool(re.search(r'publisher|coordinator|writer|process.?inbox', text, re.I)),
        'oauth_refresh': bool(re.search(r'refreshOAuth|refresh_token|refresh.?credential', text, re.I)),
        'restart': 'restart' in text, 'backup_or_restore': bool(re.search(r'backup|restore|snapshot', text, re.I))}
    return item


def entries(path, bound=256):
    info = metadata(path)
    result = []
    if info.get('directory') and not info.get('symlink') and time.monotonic() < END:
        try:
            with os.scandir(path) as iterator:
                for index, item in enumerate(iterator):
                    if index >= bound:
                        info['entry_bound_hit'] = True
                        break
                    result.append(Path(item.path))
        except OSError as exc:
            info['error'] = type(exc).__name__
    return info, sorted(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, choices=('main', 'macbook-pro', 'rog', 'pocket4', 'x230', 'ai395'))
    args = parser.parse_args()
    out = {'schema': 'authbus-current-client-source-metadata-v1', 'host_label': args.host,
           'created_at': datetime.now(timezone.utc).isoformat(), 'read_only': True,
           'provider_called': False, 'sdk_imported': False, 'credentials_exported': False,
           'production_mutation': False, 'home': str(HOME_PATH), 'platform': platform.system()}
    config_meta, config = read_json(STATE / 'openclaw.json')
    out['config'] = config_meta
    agents = config.get('agents', {}) if isinstance(config.get('agents'), dict) else {}
    defaults = agents.get('defaults', {}) if isinstance(agents.get('defaults'), dict) else {}
    out['defaults'] = {'model': model(defaults.get('model')), 'heartbeat_model': model(defaults.get('heartbeat', {}).get('model'))
                       if isinstance(defaults.get('heartbeat'), dict) else None,
                       'agent_dir': reference(defaults.get('agentDir')),
                       'named_models': [label(k) for k in list(defaults.get('models', {}))[:64] if label(k)]}
    out['agents'] = []
    known_dirs = {str(STATE / 'agents/main/agent')}
    for item in agents.get('list', [])[:64] if isinstance(agents.get('list'), list) else []:
        if not isinstance(item, dict):
            continue
        agent_id = label(item.get('id'))
        candidate = reference(item.get('agentDir'))
        if candidate is None and agent_id and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', agent_id):
            candidate = str(STATE / 'agents' / agent_id / 'agent')
        if candidate:
            known_dirs.add(candidate)
        out['agents'].append({'id': agent_id, 'default': item.get('default') if isinstance(item.get('default'), bool) else None,
                              'agent_dir': candidate, 'model': model(item.get('model'))})
    out['providers'] = []
    providers = config.get('models', {}).get('providers', {}) if isinstance(config.get('models'), dict) else {}
    for name, provider in list(providers.items())[:64] if isinstance(providers, dict) else []:
        if not isinstance(provider, dict):
            continue
        api_key = provider.get('apiKey')
        secret_ref = None
        if isinstance(api_key, dict):
            secret_ref = {'fields': sorted(api_key), 'source': label(api_key.get('source')),
                          'provider': label(api_key.get('provider')), 'id_sha256': digest(str(api_key.get('id', '')).encode())}
        out['providers'].append({'id': label(name), 'api': label(provider.get('api')), 'auth': label(provider.get('auth')),
              'base_url': endpoint(provider.get('baseUrl')), 'api_key_configured': api_key is not None,
              'api_key_representation': 'secret_reference' if isinstance(api_key, dict) else 'literal_or_marker' if isinstance(api_key, str) else None,
              'secret_ref': secret_ref,
              'model_ids': [label(m.get('id')) for m in provider.get('models', [])[:64] if isinstance(m, dict) and label(m.get('id'))]
                  if isinstance(provider.get('models'), list) else []})
    entry = config.get('plugins', {}).get('entries', {}).get('openclaw-authbus', {})
    raw = entry.get('config', {}) if isinstance(entry, dict) else {}
    out['authbus'] = {'enabled': entry.get('enabled') if isinstance(entry, dict) else None,
                     'address': endpoint(raw.get('address')), 'host_id': label(raw.get('hostId')),
                     'raw_field_names': sorted(raw),
                     'raw_flags': {k: raw.get(k) if isinstance(raw.get(k), bool) else None
                                   for k in ('leader', 'publishNew', 'manageOrder', 'enforceRefreshLeases')},
                     'effective_flags': {'leader': raw.get('leader') is True, 'publishNew': raw.get('publishNew') is True,
                           'manageOrder': raw.get('manageOrder') is not False, 'enforceRefreshLeases': raw.get('enforceRefreshLeases') is True,
                           'schedulerMode': 'enforce' if raw.get('schedulerMode') == 'enforce' else 'shadow'},
                     'binding_files': {k: metadata(Path(p)) for k in ('caFile', 'roleIdFile', 'secretIdFile')
                                      for p in [reference(raw.get(k))] if p}}
    out['secret_providers'] = []
    secret_providers = config.get('secrets', {}).get('providers', {}) if isinstance(config.get('secrets'), dict) else {}
    for name, value in list(secret_providers.items())[:64] if isinstance(secret_providers, dict) else []:
        if isinstance(value, dict):
            out['secret_providers'].append({'id': label(name), 'source': label(value.get('source')),
                 'field_names': sorted(value), 'path': reference(value.get('path')), 'command': reference(value.get('command'))})
    out['client_store_metadata'] = []
    for name in sorted(known_dirs)[:64]:
        directory = Path(name)
        out['client_store_metadata'].append({'agent_dir': name, 'directory': metadata(directory),
            'files': [metadata(directory / filename) for filename in ('openclaw-agent.sqlite', 'openclaw-agent.sqlite-wal',
                'openclaw-agent.sqlite-shm', 'auth-profiles.json', 'auth-state.json')]})
    out['backup_references'] = []
    for directory in (STATE, HOME_PATH / '.config', STATE / 'backups', STATE / 'backup'):
        info, children = entries(directory)
        references = [metadata(p) for p in children if re.search(r'backup|backups|\.bak(?:\.|$)|authbus', p.name, re.I)][:40]
        if references:
            out['backup_references'].append({'directory': info, 'references': references, 'contents_not_read': True})
    out['entrypoint_directories'], out['entrypoints'] = [], []
    queue = []
    for directory in (HOME_PATH / '.local/bin', HOME_PATH / '.config/systemd/user', HOME_PATH / 'Library/LaunchAgents',
                      HOME_PATH / '.authbus-relay-maintenance', STATE / 'extensions/openclaw-authbus'):
        info, children = entries(directory)
        out['entrypoint_directories'].append(info)
        for child in children:
            if MATCH.search(child.name) or directory == STATE / 'extensions/openclaw-authbus':
                if child.suffix in CODE_SUFFIXES or (child.suffix == '' and metadata(child).get('regular_file')):
                    queue.append(child)
                elif metadata(child).get('directory') and not child.is_symlink():
                    out['entrypoints'].append({'directory_reference': metadata(child), 'contents_not_read': True})
    for file in list(dict.fromkeys(queue))[:32]:
        out['entrypoints'].append(source_metadata(file))
    out['code_root_candidates'] = []
    for directory in (HOME_PATH / 'projects', HOME_PATH / 'repos', HOME_PATH / 'src', HOME_PATH / 'code'):
        info, children = entries(directory, 128)
        candidates = [metadata(p) for p in children if MATCH.search(p.name) or re.search(r'openclaw', p.name, re.I)]
        if candidates:
            out['code_root_candidates'].append({'parent': info, 'references': candidates[:32]})
    out['bounded_stop'] = time.monotonic() >= END
    print(json.dumps(out, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'schema': 'authbus-current-client-source-metadata-v1', 'read_only': True,
                          'ok': False, 'error_class': type(exc).__name__, 'production_mutation': False}))
        raise SystemExit(2)
