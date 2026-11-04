#!/usr/bin/env python3
"""Project two frozen verified generations from four exact existing Mac files.

Observe is read-only. Materialize writes only the new fixed owned output root.
This does not establish current provider availability or a latest native source.
"""
from pathlib import Path
import argparse, base64, hashlib, json, os, stat, time

BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013')
ROOT = BASE / 'pocket-first-cycle-trusted-projection-20261104-r1'
CORE = BASE / 'authbus-profile2-selector-c138-20261104-r1'
INPUTS = {
    'prepare': (CORE / 'multisource-prepare-r2/prepare.public.json',
        'bb4f2e2c421102f9a0a31c70db7c26457a97a8a5bfac8227a3e372a2f3923228'),
    'bundle': (CORE / 'multisource-prepare-r2/source-bundle.private.json',
        'b38233cb4e0c2838bd26d93afb623c93d984b97930ecc769b4450704343e4957'),
    'profile1_proof': (BASE / 'authbus-profile1-source-36076-20261104-r1/source-private/provider-proof.public.json',
        '3050622c35bacb53ac47f532d4d5230c7c5c68bd2db243376c3c27385744a878'),
    'profile2_core': (CORE / 'final360-core-r2/result.public.json',
        '3ac84a78cb6f6fb145508adbb6918cf7de40478ec92854eeb4427ec5c04242a7'),
}
GENERATIONS = (
    ('bca88c7adde84057871fd63f202e6aba80d453a04f75151df1d29f269dfaa5f1',
     '332c2cdd98cd0650de22a4506f7f67c3cbc69a9154e0cbafa4344f7a691640b9',
     'c40f74bc2c0190ebb30259e25534f78f7048346814d1a02cd99274340add0606'),
    ('48e095587f180413f65274d6d25d88d4ee6f9f99d981575f54bc4fb3399c286e',
     '899445c0e083199d67988e1db5bc7ac6d4d158bf913bb54669e5afc7714f2fb2',
     'c6b074866138e3ed265414016ed7ba4a88bdbe062e3983269c61be8496f22caa'),
)

class Refused(Exception):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def frozen_file(path, expected):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'exact_input_no_symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) & 0o077 == 0
             and before.st_size <= 1024 * 1024, 'frozen_input_custody')
        raw = bytearray()
        while len(raw) <= 1024 * 1024:
            part = os.read(fd, min(65536, 1024 * 1024 + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        need(len(raw) == before.st_size and sha(raw) == expected, 'frozen_input_pin')
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
             and path.resolve(strict=True) == path, 'frozen_input_changed')
        return bytes(raw), {'path': str(path), 'sha256': expected,
                            'bytes': len(raw), 'identity': list(identity(before))}
    finally:
        os.close(fd)

def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    sync_dir(path.parent)

def capture():
    raw, records, values = {}, {}, {}
    for name, (path, pin) in INPUTS.items():
        raw[name], records[name] = frozen_file(path, pin)
        values[name] = json.loads(raw[name])
    p, bundle, proof1, proof2 = (values[k] for k in ('prepare', 'bundle', 'profile1_proof', 'profile2_core'))
    need(p.get('ok') is True and len(p.get('checks', [])) == 16
         and all(x.get('passed') is True for x in p['checks'])
         and p.get('sourceBundleSha256') == INPUTS['bundle'][1], 'exact_successful_prepare')
    need(proof1.get('single_current_credential_provider_validated') is True
         and proof1.get('selected_source_sha256') == GENERATIONS[0][0]
         and proof1.get('jwt_account_matches_stored') is True
         and proof1.get('source_custody_verified') is True
         and proof1.get('source_unchanged') is True
         and proof1.get('provider_read', {}).get('httpStatus') == 200
         and proof1.get('provider_read', {}).get('tlsVerified') is True,
         'profile1_frozen_provider_proof_binding')
    need(proof2.get('ok') is True and proof2.get('selectedCredentialSha256') == GENERATIONS[1][0]
         and proof2.get('priorProviderCredentialBindingQualified') is True
         and proof2.get('providerValidationLink', {}).get('credentialAndResolvedAccessByteIdentical') is True
         and proof2.get('providerValidationLink', {}).get('reused') is True,
         'profile2_frozen_provider_proof_binding')
    ids = bundle.get('targetProfileIds')
    credentials = bundle.get('credentials')
    need(isinstance(ids, list) and len(ids) == len(set(ids)) == 2
         and isinstance(credentials, dict) and set(credentials) == set(ids), 'exact_two_managed_sources')
    projected = {}; public = []
    now = time.time()
    for ordinal, (pid, pins) in enumerate(zip(ids, GENERATIONS), 1):
        credential = credentials[pid]
        need(isinstance(pid, str) and 0 < len(pid) <= 240
             and credential.get('provider') == 'openai' and credential.get('type') == 'oauth'
             and sha(encoded(credential)) == pins[0]
             and sha(credential['accountId'].encode()) == pins[1]
             and sha(credential['access'].encode()) == pins[2], 'exact_frozen_credential_generation')
        claims = json.loads(base64.urlsafe_b64decode(credential['access'].split('.')[1] + '==='))
        need(claims['https://api.openai.com/auth']['chatgpt_account_id'] == credential['accountId']
             and claims['exp'] > now + 900 and credential['expires'] > now * 1000 + 900000
             and isinstance(credential.get('refresh'), str) and bool(credential['refresh']),
             'frozen_generation_identity_or_expiry')
        source = p['sources'][ordinal - 1]
        need(source['destinationOrdinal'] == ordinal and source['credentialSha256'] == pins[0]
             and source['accountIdSha256'] == pins[1], 'prepare_ordinal_provenance')
        projected[pid] = credential
        public.append({'ordinal': ordinal, 'profileIdSha256': sha(pid.encode()),
                       'credentialSha256': pins[0], 'accountIdSha256': pins[1],
                       'accessSha256': pins[2], 'expiresUnixMs': credential['expires'],
                       'identityClaimMatches': True, 'expiryFuture': True})
    for name, (path, pin) in INPUTS.items():
        after, record = frozen_file(path, pin)
        need(after == raw[name] and record == records[name], 'frozen_four_file_after_fence')
    packet = {'schema': 'heptabao.frozen-managed-profile12-private.v1',
              'credentials': projected, 'targetProfileIds': ids,
              'sourcePins': {k: v[1] for k, v in INPUTS.items()}}
    report = {'schema': 'heptabao.frozen-managed-profile12-projection.v1', 'ok': True,
              'sourceGeneration': 'frozen_previously_verified_generation',
              'latestActiveGenerationClaimed': False, 'providerAvailabilityQualified': False,
              'providerCalled': False, 'refreshCalled': False, 'modelCalled': False,
              'productionChanged': False, 'credentialValuesPublished': False,
              'accountIdentitiesPublished': False, 'sourceRecords': records,
              'projectedProfiles': public, 'packetSha256': sha(encoded(packet)),
              'packetBytes': len(encoded(packet)), 'sourceUnchanged': True,
              'copiedUsageOrderOrExcludedProfiles': False}
    return packet, report

def main():
    p = argparse.ArgumentParser(description=__doc__)
    choice = p.add_mutually_exclusive_group(required=True)
    choice.add_argument('--observe', action='store_true')
    choice.add_argument('--materialize', action='store_true')
    args = p.parse_args(); os.umask(0o077)
    created = False
    try:
        packet, report = capture()
        report['materialized'] = args.materialize
        if args.materialize:
            need(ROOT.parent.resolve(strict=True) == ROOT.parent, 'output_parent_no_symlink')
            ROOT.mkdir(mode=0o700); created = True; sync_dir(ROOT.parent)
            create(ROOT / 'managed-profile12.private.json', encoded(packet))
            create(ROOT / 'source-projection.public.json', encoded(report))
        print(json.dumps(report, sort_keys=True)); return 0
    except Exception as exc:
        report = {'schema': 'heptabao.frozen-managed-profile12-projection.v1', 'ok': False,
                  'error': str(exc) if isinstance(exc, Refused) else type(exc).__name__,
                  'createdOutputRoot': created, 'automaticRetry': False,
                  'providerCalled': False, 'refreshCalled': False, 'productionChanged': False}
        print(json.dumps(report, sort_keys=True)); return 1

if __name__ == '__main__':
    raise SystemExit(main())
