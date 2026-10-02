"""One-shot SSH OTP verification with pinned HTTPS trust and explicit host binding.

Reads a single OTP line from a pipe, never argv or PAM_RHOST. The trusted host
caller supplies the login username; private configuration supplies allowed roles,
users and this host's IPs. No shell, retries or authentication-policy edits occur.
This helper alone does not configure sshd/PAM or grant a local login.
"""
from __future__ import annotations
import ipaddress
import os
import re
import select
import sys
import time

from .private_state import read_trusted_ca
from .transport import BaoError, Client, SafeArgumentParser, endpoint, key_path, private_json


def config_file(path):
    config = private_json(path)
    allowed = {'address', 'ca_file', 'namespace', 'mount', 'host_ips', 'allowed_roles', 'allowed_users', 'timeout'}
    if not isinstance(config, dict) or set(config) - allowed:
        raise BaoError('invalid_ssh_helper_configuration')
    try:
        endpoint(config['address'])
        if not os.path.isabs(config['ca_file']):
            raise BaoError('absolute_ca_file_required')
        for name in ('allowed_users', 'allowed_roles'):
            values = config[name]
            if (not isinstance(values, list) or not 1 <= len(values) <= 64 or len(values) != len(set(values))
                    or any(not isinstance(v, str) or not re.fullmatch(r'[A-Za-z0-9_.$-]{1,64}', v) for v in values)):
                raise BaoError('invalid_ssh_helper_allowlist')
        ips = config['host_ips']
        if not isinstance(ips, list) or not 1 <= len(ips) <= 64:
            raise BaoError('invalid_host_addresses')
        config['host_ips'] = [str(ipaddress.ip_address(v)) for v in ips if isinstance(v, str)]
        if len(config['host_ips']) != len(ips) or len(set(config['host_ips'])) != len(ips):
            raise BaoError('invalid_host_addresses')
        config.setdefault('mount', 'ssh')
        if key_path(config['mount']) != config['mount']:
            raise BaoError('invalid_ssh_mount')
        config.setdefault('namespace', '')
        key_path(config['namespace'], allow_empty=True)
        config.setdefault('timeout', 5)
        if type(config['timeout']) not in (int, float) or not 0.1 <= config['timeout'] <= 30:
            raise BaoError('invalid_helper_timeout')
        config['_trusted_ca'] = read_trusted_ca(config['ca_file'])
        return config
    except (KeyError, TypeError, ValueError):
        raise BaoError('invalid_ssh_helper_configuration') from None


def read_otp(fd: int, timeout: float) -> str:
    if os.isatty(fd):
        raise BaoError('otp_pipe_required')
    # Require EOF as well as one line; reject concatenated credentials/extra input.
    raw = bytearray()
    end = time.monotonic() + timeout
    try:
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                raise BaoError('otp_input_deadline')
            part = os.read(fd, 257 - len(raw))
            if not part:
                break
            raw.extend(part)
            if len(raw) > 256:
                raise BaoError('otp_input_bound')
        value = bytes(raw).decode('ascii')
        if value.endswith('\n'):
            value = value[:-1]
        if not value or len(value) > 255 or any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise BaoError('invalid_otp_line')
        return value
    except UnicodeError:
        raise BaoError('invalid_otp_line') from None
    finally:
        raw[:] = b'\0' * len(raw)


def verify(config: dict, username: str, otp: str, *, client_factory=Client) -> None:
    if username not in config['allowed_users']:
        raise BaoError('ssh_username_not_allowed')
    client = client_factory(config['address'], config['ca_file'], 'heptabao-public-otp-verifier',
                            config['namespace'], config['timeout'], trusted_ca_pem=config.get('_trusted_ca'))
    response = client.request('POST', '/v1/' + config['mount'] + '/verify', {'otp': otp}, token='')
    if response.status != 200:
        raise BaoError('ssh_otp_rejected_or_unknown')
    data = response.data()
    try:
        host_ip = str(ipaddress.ip_address(data['ip']))
    except (KeyError, TypeError, ValueError):
        raise BaoError('ssh_response_host_invalid') from None
    if (data.get('username') != username or host_ip not in config['host_ips']
            or data.get('role_name') not in config['allowed_roles']):
        # The OTP may already be consumed. Never retry a rejected host binding.
        raise BaoError('ssh_response_binding_rejected')


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--username', required=True, help='Trusted login caller username; not remote peer address')
    args = parser.parse_args(argv)
    try:
        config = config_file(args.config)
        if args.username not in config['allowed_users']:
            raise BaoError('ssh_username_not_allowed')
        otp = read_otp(sys.stdin.fileno(), config['timeout'])
        verify(config, args.username, otp)
        return 0
    except (BaoError, OSError, ValueError, TypeError):
        print('heptabao-ssh-helper: authentication denied', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
