"""Owned local Agent/Proxy API: mTLS loopback and a bounded online lease cache.

This is a deliberately bounded process owner, not the complete OpenBao Agent
template, watcher, persistent cache or managed lease renewal implementation.
"""
from __future__ import annotations
import hashlib
import ipaddress
from pathlib import Path
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

from .private_state import read_trusted_ca
from .transport import BaoError, Response, canonical, private_read


class CacheClearValueMissing(BaoError):
    pass


def validate_listener(value):
    if not isinstance(value, dict):
        raise BaoError('invalid_local_listener')
    allowed = {'address', 'tls_cert_file', 'tls_key_file', 'tls_client_ca_file',
               'require_request_header', 'enable_quit', 'routes', 'allow_effects',
               'timeout', 'max_requests', 'max_runtime_seconds', 'cache_enabled',
               'cache_max_entries', 'cache_max_bytes'}
    if set(value) - allowed:
        raise BaoError('invalid_local_listener')
    result = dict(value)
    try:
        address = urlsplit(result['address'])
        if (address.scheme != 'https' or address.username is not None
                or address.password is not None or address.path or address.query
                or address.fragment or address.port is None
                or not ipaddress.ip_address(address.hostname).is_loopback):
            raise BaoError('local_listener_requires_literal_loopback_mtls')
        for name in ('tls_cert_file', 'tls_key_file', 'tls_client_ca_file'):
            if not isinstance(result[name], str) or not Path(result[name]).is_absolute():
                raise BaoError('local_listener_requires_absolute_tls_paths')
        for name, default in (('require_request_header', True), ('enable_quit', False),
                              ('cache_enabled', False), ('allow_effects', False)):
            result.setdefault(name, default)
            if type(result[name]) is not bool:
                raise BaoError('invalid_local_listener_flag')
        for name, default, low, high in (('timeout', 5, 1, 30),
                ('max_requests', 10000, 1, 100000),
                ('max_runtime_seconds', 3600, 1, 86400),
                ('cache_max_entries', 64, 1, 1024),
                ('cache_max_bytes', 1048576, 1024, 16777216)):
            result.setdefault(name, default)
            if type(result[name]) is not int or not low <= result[name] <= high:
                raise BaoError('invalid_local_listener_bound')
        return result
    except (KeyError, ValueError, TypeError):
        raise BaoError('invalid_local_listener') from None


class LeaseCache:
    """Only leased responses, keyed by the admitted token/namespace/request.

    Every hit still validates the live upstream token. A backend outage fails
    closed. Leases are never extended here; monotonic and wall expiry both apply.
    """
    def __init__(self, config):
        self.enabled = config.get('cache_enabled', False)
        self.maximum_entries = config.get('cache_max_entries', 64)
        self.maximum_bytes = config.get('cache_max_bytes', 1048576)
        self.records = {}

    @staticmethod
    def key(token, namespace, method, path, payload, consistency):
        return (hashlib.sha256(token.encode('ascii')).hexdigest(), namespace,
                method, path, hashlib.sha256(canonical(payload)).hexdigest(),
                consistency.index, consistency.behavior)

    def prune(self):
        now, mono = time.time(), time.monotonic()
        for key, row in list(self.records.items()):
            if not row['observed_wall'] <= now < row['wall_deadline'] or mono >= row['deadline']:
                del self.records[key]

    def get(self, key):
        self.prune()
        row=self.records.get(key)
        if row is None:return None
        response=row['response']
        ttl=max(0,int(min(row['wall_deadline']-time.time(),row['deadline']-time.monotonic())))
        return Response(response.status,{**response.body,'lease_duration':ttl},
                        response.consistency_index,response.consistency_valid,response.retry_after_seconds)

    def put(self, key, response, state, accessor, start_wall, start_mono):
        body = response.body
        ttl, lease = body.get('lease_duration'), body.get('lease_id')
        if (not self.enabled or response.status != 200 or body.get('wrap_info') is not None
                or body.get('renewable') is not True
                or type(ttl) is not int or ttl <= 0 or not isinstance(lease, str) or not lease):
            return
        expiry = min(start_wall + ttl, state['expires_at'])
        duration = expiry - start_wall
        size = len(canonical(body))
        if duration <= 0 or size > self.maximum_bytes:
            return
        self.prune()
        self.records.pop(key, None)
        while self.records and (len(self.records) >= self.maximum_entries
                or sum(row['size'] for row in self.records.values()) + size > self.maximum_bytes):
            del self.records[next(iter(self.records))]
        self.records[key] = {'response': response, 'lease': lease, 'accessor': accessor,
                'size': size, 'observed_wall': start_wall, 'wall_deadline': expiry,
                'deadline': start_mono + duration}

    def clear(self, payload):
        if not isinstance(payload, dict):
            raise BaoError('invalid_cache_clear')
        for name in ('type','value','namespace'):
            if payload.get(name) is not None and not isinstance(payload[name],str):
                raise BaoError('invalid_cache_clear')
        kind = payload.get('type')
        if kind not in ('all', 'request_path', 'lease', 'token', 'token_accessor'):
            raise BaoError('invalid_cache_clear')
        value = payload.get('value')
        if kind != 'all' and not value:
            raise CacheClearValueMissing('cache_value_required')
        if kind != 'all' and (not isinstance(value, str) or len(value) > 8192):
            raise BaoError('invalid_cache_clear')
        namespace = payload.get('namespace')
        if namespace is not None and (not isinstance(namespace, str) or len(namespace) > 1024):
            raise BaoError('invalid_cache_clear')
        self.prune()
        token_hash = hashlib.sha256(value.encode()).hexdigest() if kind == 'token' else None
        for key, row in list(self.records.items()):
            match = (kind == 'all' or kind == 'request_path' and ('/v1/' + key[3]).startswith(value)
                or kind == 'lease' and value == row['lease']
                or kind == 'token' and token_hash == key[0]
                or kind == 'token_accessor' and value == row['accessor'])
            required_namespace = '' if namespace is None or namespace == 'root/' else namespace.rstrip('/')
            if match and (kind != 'request_path' or required_namespace == key[1]):
                del self.records[key]


class LocalAPI:
    """One serial TLS listener with a shared process stop event."""
    def __init__(self, config, agent_config, stop, kind):
        self.config = validate_listener(config)
        self.agent_config, self.stop, self.kind = agent_config, stop, kind
        self.cache = LeaseCache(self.config)
        self.listener = None
        self.thread = None
        self.failed = False

    def start(self):
        from .proxy import validate_routes
        validate_routes(self.config)
        ca = read_trusted_ca(self.config['tls_client_ca_file'])
        read_trusted_ca(self.config['tls_cert_file'])
        private_read(self.config['tls_key_file'])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.config['tls_cert_file'], self.config['tls_key_file'])
        context.load_verify_locations(cadata=ca.decode('ascii'))
        context.verify_mode = ssl.CERT_REQUIRED
        address = urlsplit(self.config['address'])
        self.listener = socket.socket(socket.AF_INET6 if ':' in address.hostname else socket.AF_INET,
                                      socket.SOCK_STREAM)
        try:
            self.listener.bind((address.hostname, address.port))
            self.listener.listen(16)
            self.listener.settimeout(0.2)
            self.context = context
            self.thread = threading.Thread(target=self._run, name='heptabao-local-api')
            self.thread.start()
        except BaseException:
            self.listener.close()
            raise

    def _run(self):
        from .proxy import handle_request
        deadline = time.monotonic() + self.config['max_runtime_seconds']
        requests = 0
        try:
            while not self.stop.is_set() and requests < self.config['max_requests'] and time.monotonic() < deadline:
                try:
                    raw, _ = self.listener.accept()
                except socket.timeout:
                    continue
                requests += 1
                with raw:
                    try:
                        end=time.monotonic()+self.config['timeout']
                        raw.settimeout(self.config['timeout'])
                        with self.context.wrap_socket(raw, server_side=True) as stream:
                            handle_request(stream, self.config, self.agent_config,
                                           self.stop, self.kind, self.cache,end=end)
                    except (BaoError, OSError, ValueError, TypeError):
                        pass
        except (BaoError, OSError, ValueError, TypeError):
            self.failed = True
        finally:
            self.cache.records.clear()
            self.listener.close()
            self.stop.set()

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(self.config['timeout'] + 1)
            if self.thread.is_alive():
                raise BaoError('local_listener_failed_to_join')
        if self.listener is not None:
            self.listener.close()
        if self.failed:
            raise BaoError('local_listener_failed')
