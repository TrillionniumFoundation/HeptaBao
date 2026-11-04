#!/usr/bin/env python3
"""Observe the current guard and independently query its exact public endpoints.

All probes bind to the guard's already selected tunnel. No credential, provider
request, VPN change, guard restart, allowed-country change or traffic switch is
performed. Private response bodies remain under the newly created work root.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse
import datetime
import hashlib
import http.client
import json
import os
import plistlib
import re
import subprocess
import time

ENDPOINTS = {
    'country-is': 'https://api.country.is/',
    'geojs': 'https://get.geojs.io/v1/ip/country.json',
    'cloudflare': 'https://www.cloudflare.com/cdn-cgi/trace',
}


def sha(value):
    return hashlib.sha256(value).hexdigest()


def save(path, value):
    if not isinstance(value, bytes):
        value = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def health():
    conn = http.client.HTTPConnection('127.0.0.1', 8819, timeout=4)
    try:
        conn.request('GET', '/healthz')
        response = conn.getresponse()
        data = json.loads(response.read(8192))
        return {'httpStatus': response.status, **{k: data.get(k) for k in
                ('allowed', 'checkedAt', 'country', 'interface', 'reason')}}
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.work_dir
    root.mkdir(mode=0o700)
    report = {'schema': 'heptabao.relay-bound-geoip-diagnostic.v1', 'ok': False,
              'startedUnixMs': int(time.time() * 1000), 'productionChanged': False,
              'providerCalled': False, 'credentialUsed': False, 'j3160Contacted': False,
              'guardSemanticsChanged': False, 'vpnChanged': False, 'probes': []}
    try:
        plist_path = Path('/Users/qianqi/Library/LaunchAgents/ai.openclaw.authbus-relay.egressguard.plist')
        plist_bytes = plist_path.read_bytes()
        config = plistlib.loads(plist_bytes)
        argv = config['ProgramArguments']
        assert argv[0] == '/Users/qianqi/.openclaw/authbus-relay/bin/egressguard'
        assert argv[argv.index('-listen') + 1] == '127.0.0.1:8819'
        executable = Path(argv[0])
        binary = executable.read_bytes()
        assert sha(binary) == '982f5f69fbe5e13b6350da19e3aa13ee24ef395b8fa454ab9e0dafdbd502f791'
        assert all(url.encode() in binary for url in ENDPOINTS.values())
        report['allowedCountries'] = argv[argv.index('-allowed-countries') + 1].split(',')
        report['configuredService'] = argv[argv.index('-service') + 1]
        report['guardSha256'] = sha(binary)
        report['launchdPlistSha256'] = sha(plist_bytes)
        report['guardBefore'] = health()
        interface = report['guardBefore']['interface']
        assert isinstance(interface, str) and re.fullmatch(r'utun[0-9]+', interface)
        report['boundInterface'] = interface
        route_interfaces = {}
        for family, flag in [('ipv4', '-inet'), ('ipv6', '-inet6')]:
            proc = subprocess.run(['/sbin/route', '-n', 'get', flag, 'default'], capture_output=True, timeout=5)
            match = re.search(rb'^\s*interface:\s*(\S+)\s*$', proc.stdout, re.M)
            route_interfaces[family] = match[1].decode() if match else None
        report['defaultRouteInterfaces'] = route_interfaces
        report['bothDefaultRoutesMatchGuard'] = all(x == interface for x in route_interfaces.values())

        def probe(item):
            family, flag, name, url = item
            proc = subprocess.run(['/usr/bin/curl', flag, '--interface', interface, '--noproxy', '*',
                '--silent', '--show-error', '--proto', '=https', '--connect-timeout', '5', '--max-time', '12',
                '--max-filesize', '65536', '--header', 'Cache-Control: no-cache', '--header', 'Pragma: no-cache',
                '--write-out', '\n%{http_code}', url], capture_output=True, timeout=15,
                env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
            stem = family + '-' + name
            save(root / (stem + '.response.private'), proc.stdout)
            save(root / (stem + '.stderr.private'), proc.stderr)
            body, _, status = proc.stdout.rpartition(b'\n')
            observation = {'family': family, 'provider': name, 'endpoint': url,
                'curlExitCode': proc.returncode, 'httpStatus': int(status) if status.isdigit() else None,
                'responseSha256': sha(body), 'stderrSha256': sha(proc.stderr), 'country': None,
                'tlsVerificationDisabled': False, 'interfaceBound': interface}
            if proc.returncode == 0 and observation['httpStatus'] == 200:
                if name == 'cloudflare':
                    data = dict(line.split('=', 1) for line in body.decode().splitlines() if '=' in line)
                    country, ip = data.get('loc'), data.get('ip')
                else:
                    data = json.loads(body)
                    country, ip = data.get('country'), data.get('ip')
                if isinstance(country, str) and re.fullmatch(r'[A-Z]{2}', country):
                    observation['country'] = country
                observation['egressIpSha256'] = sha(ip.encode()) if isinstance(ip, str) else None
            return observation

        tasks = [(family, flag, name, url) for family, flag in [('ipv4', '-4'), ('ipv6', '-6')]
                 for name, url in ENDPOINTS.items()]
        with ThreadPoolExecutor(max_workers=3) as executor:
            report['probes'] = list(executor.map(probe, tasks))
        report['guardAfter'] = health()
        families = {}
        for family in ('ipv4', 'ipv6'):
            items = [x for x in report['probes'] if x['family'] == family]
            countries = sorted(set(x['country'] for x in items if x['country']))
            count = sum(x['country'] is not None for x in items)
            families[family] = {'successfulCountries': countries, 'successfulProviderCount': count,
                'quorum': count >= 2, 'anyDisagreement': len(countries) > 1}
        report['independentFamilies'] = families
        all_countries = sorted(set(c for f in families.values() for c in f['successfulCountries']))
        report['independentGuardWouldAllow'] = all(f['quorum'] and not f['anyDisagreement'] for f in families.values()) \
            and len(all_countries) == 1 and all_countries[0] in report['allowedCountries']
        stamp = datetime.datetime.fromisoformat(report['guardAfter']['checkedAt'].replace('Z', '+00:00'))
        report['guardCheckAgeSeconds'] = round(time.time() - stamp.timestamp(), 3)
        report['guardInputSourcesUnchanged'] = plist_path.read_bytes() == plist_bytes and executable.read_bytes() == binary
        assert report['guardInputSourcesUnchanged']
        report['ok'] = True
    except Exception as error:
        report['errorClass'] = type(error).__name__
    report['finishedUnixMs'] = int(time.time() * 1000)
    save(root / 'result.public.json', report)
    print(json.dumps({'ok': report['ok'], 'result': str(root / 'result.public.json')}))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
