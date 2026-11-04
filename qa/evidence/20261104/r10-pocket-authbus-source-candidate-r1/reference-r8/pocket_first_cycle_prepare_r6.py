#!/usr/bin/env python3
"""Bind new QA and exact transferred inputs. Does not start a service or provider."""
from pathlib import Path
import argparse, hashlib, json, os, re, stat

P = Path('/home/alex/heptabao-installed-authbus-consumer-36076-20261104-r1')
Q = P / 'shared-first-cycle-qa-r6'
I = P / 'shared-first-cycle-inputs-r1'
OLD = P / 'current-native-inputs-r1/prepare-r2.public.json'
OLD_SHA = '3ae1e850de5bd7feed62598705529dcad06493467ccbd671d72865f7fc127ccb'
PACKET_SHA = '40fc5cd1f2558994c3097b60e3359bf3044f5fdd1a40ba91ff0fe5bd406bb8fe'
PROJECTION_SHA = 'df47c9d560868fea6a88eb60f035c53efcdd101046bfb7ea55778a1ba073f21a'
CORE_SHA = 'eaf83832144e7ecf1f369ec91007b0d8b4dc55f59342f3ce27ca64a4aea6f76d'
SCENARIO = 'shared-managed12-original-local-source'

class Refused(Exception):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def read(path, maximum=1024 * 1024):
    need(path.resolve(strict=True) == path, 'prepare_input_no_symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size <= maximum, 'prepare_input_custody')
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        shape = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
                           s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and shape(before) == shape(os.fstat(fd)) == shape(path.lstat()),
             'prepare_input_changed')
        return bytes(raw)
    finally:
        os.close(fd)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qa-pins-sha256', required=True)
    args = parser.parse_args(); os.umask(0o077)
    need(re.fullmatch('[a-f0-9]{64}', args.qa_pins_sha256), 'qa_manifest_digest_shape')
    for directory in (P, Q, I):
        info = directory.lstat()
        need(stat.S_ISDIR(info.st_mode) and directory.resolve(strict=True) == directory
             and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) & 0o077 == 0,
             'prepare_directory_custody')
    qa_raw = read(Q / 'qa-pins.public.json')
    need(sha(qa_raw) == args.qa_pins_sha256, 'qa_manifest_external_pin')
    qa = json.loads(qa_raw)
    need(qa['schema'] == 'heptabao.pocket-shared-first-cycle-qa-pins.v1'
         and qa['scenario'] == SCENARIO, 'qa_manifest_scope')
    source_pins = {}
    for name, pin in qa['files'].items():
        need(re.fullmatch('[a-z0-9_.-]+', name), 'qa_filename_scope')
        raw = read(Q / name)
        need(sha(raw) == pin['sha256'] and len(raw) == pin['bytes'], 'qa_source_pin')
        if name.endswith('.py'):
            compile(raw, str(Q / name), 'exec')
        source_pins[str(Q / name)] = pin['sha256']
    need(source_pins[str(Q / 'authbus_coordinator.py')] == CORE_SHA, 'exact_original_coordinator_core')
    old_raw = read(OLD); need(sha(old_raw) == OLD_SHA, 'original_prepare_pin')
    old = json.loads(old_raw)
    need(old['ok'] is True and old['nativeVersion'] == '0.144.3'
         and old['agents'] == ['main', 'tg8687951891'], 'original_prepare_scope')
    packet_raw = read(I / 'managed-profile12.private.json')
    projection_raw = read(I / 'source-projection.public.json')
    need(sha(packet_raw) == PACKET_SHA and sha(projection_raw) == PROJECTION_SHA,
         'trusted_transferred_input_digest')
    projection = json.loads(projection_raw)
    need(projection['ok'] is True and projection['packetSha256'] == PACKET_SHA
         and projection['packetBytes'] == len(packet_raw) and projection['materialized'] is True
         and projection['sourceUnchanged'] is True and projection['providerCalled'] is False
         and projection['refreshCalled'] is False and projection['latestActiveGenerationClaimed'] is False,
         'frozen_source_projection_scope')
    # This is a new preparation receipt, not an edit to the old preparation or
    # a claim that its old registry observation is still current. The isolated
    # preflight/live controller will read the current exact row and both stores.
    value = {key: old[key] for key in (
        'agents', 'sourceConfigSha256', 'nativeVersion', 'nativePlatformPackageVersion',
        'nativePluginRoot', 'nativeManagedCommand', 'nativeBinary', 'enabledHarnessOwnersPlusOpenai',
        'registryCapturePath', 'registryCaptureSha256', 'registrySchema',
        'normalBuildResultSha256', 'nativeBuildReceiptSha256', 'normalBuildSourceHost')}
    value.update(schema='heptabao.pocket-shared-first-cycle-preparation.v1', ok=True,
        normalBuildResultSha256='2dad4d882854850cbe05825785e77532656da255a11ce7a551969bd7439456a5',
        nativeBuildReceiptSha256='f96740372ada668a566aa1b90b2cd8daf463c009de8eed5ba86cb20a2883b8f9',
        normalBuildSourceHost='rog',
        scenario=SCENARIO, originalPreparationPath=str(OLD), originalPreparationSha256=OLD_SHA,
        qaPinsSha256=args.qa_pins_sha256, runtimeExecuted=False, productionChanged=False,
        providerCalled=False, refreshCalled=False, latestActiveManagedGenerationClaimed=False,
        currentRegistryBindingPending=True, currentAgentStoresAndCachesBindingPending=True,
        trustedSources={'packetPath': str(I / 'managed-profile12.private.json'), 'packetSha256': PACKET_SHA,
                        'projectionPath': str(I / 'source-projection.public.json'), 'projectionSha256': PROJECTION_SHA,
                        'scope': 'Frozen previously verified generation only'},
        consumerSha256=source_pins[str(Q / 'pocket_first_cycle_consumer_r1.mjs')],
        controllerSha256=source_pins[str(Q / 'pocket_shared_first_cycle_live_r2.py')],
        sourcePins={**old['sourcePins'], **source_pins, str(Q / 'qa-pins.public.json'): args.qa_pins_sha256})
    target = I / 'prepare-r6.public.json'
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    fd = os.open(I, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps({'ok': True, 'path': str(target), 'sha256': sha(raw), 'bytes': len(raw),
                      'runtimeExecuted': False, 'productionChanged': False, 'providerCalled': False}))

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'ok': False, 'error': str(error) if isinstance(error, Refused) else type(error).__name__,
                          'automaticRetry': False, 'runtimeExecuted': False, 'productionChanged': False}))
        raise SystemExit(1)
