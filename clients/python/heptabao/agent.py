"""AppRole auto-auth with durable admission, one private token sink and renewal.

Only unwrapped, renewable, unlimited-use service tokens are accepted. Ambiguous
login/renewal or a pending crash checkpoint fences reauthentication: no blind
retry. This is a bounded POSIX process, not the entire OpenBao Agent feature set.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import signal
import sys
import threading
import time

from .transport import BaoError, Client, SafeArgumentParser, canonical, endpoint, key_path, private_read, private_json
from .private_state import StateDirectory, token_snapshot, read_trusted_ca


@dataclass(frozen=True, repr=False)
class AgentConfig:
    address: str
    ca_file: str
    role_id_file: str
    secret_id_file: str
    state_dir: str
    namespace: str = ''
    auth_mount: str = 'auth/approle'
    timeout: float = 5
    interval_seconds: float = 1
    renew_increment_seconds: int = 60
    max_token_ttl_seconds: int = 3600
    max_authentications: int = 32
    max_runtime_seconds: int = 3600

    @classmethod
    def load(cls, path: str):
        value = private_json(path)
        fields = set(cls.__dataclass_fields__)
        if not isinstance(value, dict) or set(value) - fields:
            raise BaoError('invalid_agent_configuration')
        try:
            result = cls(**value)
            result.validate()
            return result
        except (TypeError, ValueError):
            raise BaoError('invalid_agent_configuration') from None

    def validate(self):
        if endpoint(self.address) != self.address.rstrip('/'):
            # Normalize only an absent standard port, not paths or credentials.
            endpoint(self.address)
        for value in (self.ca_file, self.role_id_file, self.secret_id_file, self.state_dir):
            if not isinstance(value, str) or not Path(value).is_absolute() or '..' in Path(value).parts:
                raise BaoError('agent_requires_absolute_file_paths')
        reserved = {str(Path(self.state_dir) / name) for name in ('state.json', 'token', '.agent.lock')}
        if self.role_id_file == self.secret_id_file or {self.role_id_file, self.secret_id_file} & reserved:
            raise BaoError('agent_credential_paths_conflict')
        if not isinstance(self.namespace, str) or self.namespace.startswith('/') or self.namespace.endswith('/'):
            if self.namespace != '':
                raise BaoError('invalid_agent_namespace')
        key_path(self.namespace, allow_empty=True)
        if not isinstance(self.auth_mount, str) or not self.auth_mount.startswith('auth/'):
            raise BaoError('invalid_approle_mount')
        if key_path(self.auth_mount) != self.auth_mount:
            raise BaoError('invalid_approle_mount')
        for value, low, high in ((self.timeout, 0.1, 30), (self.interval_seconds, 0.1, 60)):
            if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
                raise BaoError('invalid_agent_timing')
        for value, low, high in ((self.renew_increment_seconds, 1, 3600), (self.max_token_ttl_seconds, 2, 86400),
                                 (self.max_authentications, 1, 256), (self.max_runtime_seconds, 1, 86400)):
            if type(value) is not int or not low <= value <= high:
                raise BaoError('invalid_agent_resource_bound')
        if self.renew_increment_seconds > self.max_token_ttl_seconds:
            raise BaoError('agent_renewal_exceeds_ttl_bound')

    def binding(self):
        # Public configuration and trust-root bytes, not credential hashes.
        ca = read_trusted_ca(self.ca_file)
        fields = {name: getattr(self, name) for name in self.__dataclass_fields__}
        fields['ca_sha256'] = hashlib.sha256(ca).hexdigest()
        return hashlib.sha256(canonical(fields)).hexdigest()


def _secret(path: str) -> str:
    try:
        result = private_read(path, 8192).decode('ascii').strip()
    except UnicodeError:
        raise BaoError('invalid_approle_credential_file') from None
    if not result or len(result) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in result):
        raise BaoError('invalid_approle_credential_file')
    return result


class Agent:
    """Single process/writer. StateDirectory may be supplied by deterministic tests.

    Checkpoints contain phases/digests/timestamps only, never token/SecretID bytes.
    A token file alone is NOT an admitted token: consumers must read token_snapshot.
    """
    def __init__(self, config: AgentConfig, directory: StateDirectory, *, client_factory=Client,
                 wall=time.time, monotonic=time.monotonic):
        config.validate()
        self.config, self.directory = config, directory
        self._trusted_ca = read_trusted_ca(config.ca_file)
        self.binding = config.binding()
        if read_trusted_ca(config.ca_file) != self._trusted_ca:
            raise BaoError('agent_trust_configuration_changed')
        self.factory, self.wall, self.monotonic = client_factory, wall, monotonic
        self._deadline = None
        self._token = None
        self.state = directory.json('state.json', optional=True)
        if self.state is None:
            # Never adopt an orphan token after a crash in publication.
            if directory.read('token', optional=True) is not None:
                raise BaoError('orphan_token_requires_reconciliation')
            self.state = {'schema': 1, 'binding': self.binding, 'phase': 'empty', 'generation': 0,
                          'authentications': 0, 'observed_wall': self.wall()}
        else:
            if (not isinstance(self.state, dict) or type(self.state.get('schema')) is not int or self.state.get('schema') != 1
                    or self.state.get('binding') != self.binding
                    or self.state.get('phase') not in ('empty', 'ready', 'stopped')
                    or type(self.state.get('authentications')) is not int
                    or not 0 <= self.state['authentications'] <= config.max_authentications
                    or type(self.state.get('generation')) is not int or self.state['generation'] < 0):
                raise BaoError('pending_or_invalid_agent_state_requires_reconciliation')
            if self.state['phase'] == 'ready':
                if (type(self.state.get('expires_at')) not in (int, float)
                        or type(self.state.get('observed_wall')) not in (int, float)
                        or self.wall() < self.state['observed_wall']):
                    raise BaoError('invalid_agent_expiry')
                if self.wall() >= self.state['expires_at']:
                    self._invalidate('empty')
                else:
                    token, _ = token_snapshot(directory, self.wall(), self.binding)
                    self._token = token
                    # Conservative restart deadline; revalidate before reuse.
                    self._deadline = self.monotonic() + self.state['expires_at'] - self.wall()
        self._resumed = self._token is not None

    def _checkpoint(self, phase, **updates):
        current = self.wall()
        if (not math.isfinite(current) or type(self.state.get('observed_wall')) not in (int, float)
                or current < self.state['observed_wall']):
            raise BaoError('agent_clock_regression')
        state = {**self.state, **updates, 'phase': phase, 'generation': self.state['generation'] + 1,
                 'observed_wall': current}
        self.directory.publish('state.json', state)
        self.state = state

    def _client(self, token: str):
        if self.config.binding() != self.binding:
            raise BaoError('agent_trust_configuration_changed')
        return self.factory(self.config.address, self.config.ca_file, token, self.config.namespace, self.config.timeout,
                            trusted_ca_pem=self._trusted_ca)

    def _invalidate(self, phase):
        self._checkpoint(phase)
        self.directory.remove('token')
        self._token, self._deadline = None, None

    def _admit_token(self, response, start_wall, start_mono):
        auth = response.body.get('auth')
        if (response.status != 200 or response.body.get('wrap_info') is not None or not isinstance(auth, dict)
                or auth.get('token_type') != 'service' or auth.get('renewable') is not True
                or 'root' in auth.get('policies', []) or 'root' in auth.get('token_policies', [])):
            raise BaoError('agent_requires_unwrapped_nonroot_renewable_service_token')
        ttl, token = auth.get('lease_duration'), auth.get('client_token')
        if (type(ttl) is not int or not 1 < ttl <= self.config.max_token_ttl_seconds
                or not isinstance(token, str) or not token or len(token) > 8192
                or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise BaoError('agent_token_response_invalid')
        # Account for the entire login/renewal/lookup duration, not response receipt time.
        deadline, expiry = start_mono + ttl, start_wall + ttl
        client = self._client(token)
        lookup = client.request('GET', '/v1/auth/token/lookup-self')
        data = lookup.data() if lookup.status == 200 else {}
        if (type(data.get('num_uses')) is not int or data['num_uses'] != 0
                or data.get('type') != 'service' or data.get('renewable') is not True
                or 'root' in data.get('policies', []) or type(data.get('ttl')) is not int
                or data['ttl'] <= 0):
            raise BaoError('agent_token_must_have_unlimited_uses_and_live_ttl')
        if self.wall() >= expiry or self.monotonic() >= deadline:
            raise BaoError('agent_token_expired_during_admission')
        raw = token.encode('ascii') + b'\n'
        self.directory.write('token', raw)
        self._checkpoint('ready', token_sha256=hashlib.sha256(raw).hexdigest(), expires_at=expiry,
                         ttl=ttl, renew_at=start_wall + ttl / 2)
        self._token, self._deadline, self._resumed = token, deadline, False

    def step(self) -> str:
        self.directory.check()
        if self.config.binding() != self.binding:
            raise BaoError('agent_trust_configuration_changed')
        now, mono = self.wall(), self.monotonic()
        if now < self.state['observed_wall']:
            raise BaoError('agent_clock_regression')
        if self.state['phase'] not in ('ready', 'empty', 'stopped'):
            raise BaoError('pending_agent_effect_requires_reconciliation')
        if self._token is not None:
            if now >= self.state['expires_at'] or (self._deadline is not None and mono >= self._deadline):
                self._invalidate('empty')
                return 'expired'
            token, _ = token_snapshot(self.directory, now, self.binding)
            if token != self._token:
                raise BaoError('agent_token_changed')
            if self._deadline is None or mono >= self._deadline:
                self._invalidate('empty')
                return 'expired'
            # A restarted token is authoritatively checked before any use/renewal.
            if self._resumed:
                response = self._client(token).request('GET', '/v1/auth/token/lookup-self')
                if response.status == 403:
                    self._invalidate('empty')
                    return 'reauthenticate'
                if response.status != 200:
                    raise BaoError('agent_resume_lookup_failed')
                data = response.data()
                if (type(data.get('num_uses')) is not int or data['num_uses'] != 0
                        or type(data.get('ttl')) is not int or data['ttl'] <= 0
                        or data.get('type') != 'service' or data.get('renewable') is not True
                        or 'root' in data.get('policies', [])):
                    raise BaoError('agent_resumed_token_rejected')
                self._resumed = False
            if now < self.state['renew_at'] and mono < self._deadline - self.state['ttl'] / 2:
                return 'ready'
            self._checkpoint('renew_pending')
            self.directory.remove('token')
            response = self._client(token).request('POST', '/v1/auth/token/renew-self',
                                                   {'increment': self.config.renew_increment_seconds})
            if response.status == 403:
                self._invalidate('empty')
                return 'reauthenticate'
            self._admit_token(response, now, mono)
            return 'renewed'
        if self.state['authentications'] >= self.config.max_authentications:
            raise BaoError('agent_authentication_budget_exhausted')
        role, secret = _secret(self.config.role_id_file), _secret(self.config.secret_id_file)
        self._checkpoint('auth_pending', authentications=self.state['authentications'] + 1)
        self.directory.remove('token')
        response = self._client('heptabao-unauthenticated').request('POST', '/v1/' + self.config.auth_mount + '/login',
                                                                {'role_id': role, 'secret_id': secret}, token='')
        self._admit_token(response, now, mono)
        return 'authenticated'

    def stop(self):
        # Sink invalidation is NOT remote revocation. Cached copies remain subject
        # to server TTL/revocation. Pending phases are retained, never cleared.
        if self.state['phase'] in ('ready', 'empty', 'stopped'):
            self._invalidate('stopped')
        else:
            self.directory.remove('token')


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, help='Owner-only JSON config, no credentials in argv')
    parser.add_argument('--once', action='store_true', help='One admitted step; leave a ready sink until its stored TTL')
    args = parser.parse_args(argv)
    stop = threading.Event()
    handlers = {}
    try:
        config = AgentConfig.load(args.config)
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, lambda *_: stop.set())
        with StateDirectory(config.state_dir, writer=True) as directory:
            agent = Agent(config, directory)
            end = time.monotonic() + config.max_runtime_seconds
            try:
                while not stop.is_set() and time.monotonic() < end:
                    agent.step()
                    if args.once:
                        return 0
                    stop.wait(config.interval_seconds)
            finally:
                if not args.once:
                    agent.stop()
        return 0
    except (BaoError, OSError, ValueError, TypeError):
        # No exception/HTTP text, token, path, or credentials on diagnostics.
        print('heptabao-agent: blocked; inspect private state and reconcile before restart', file=sys.stderr)
        return 2
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    raise SystemExit(main())
