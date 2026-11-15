#!/usr/bin/env python3
"""Derive reviewable production-only plugin variants from exact public sources.

This edits only local preparation files. It does not install a plugin, edit a
client configuration, open credential stores, or dispatch any network request.
"""
import difflib
import hashlib
import json
from pathlib import Path

WORK = Path(__file__).resolve().parent
REPO = WORK.parent / 'HeptaBao-current-924b'
MAC = WORK.parent / 'main3-authbus-work/reference/current-plugin'
MAC_MANIFEST = WORK.parent / 'authbus-refresh-work/reference/gateway-loader/openclaw.plugin.json'
POCKET = WORK / 'public-client-sources/pocket4'
OUTPUT = WORK / 'production-plugin-r1'
ORIGINAL_INDEX = {
    'mac-rog': ('b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b', 54455),
    'pocket4': ('8e10c52df53d6d16d0e5890a6ccdaaff9515469e4419b46270b9bdc62b9be7af', 54578),
}
TRANSPORT_PINS = {
    'production-client.js': ('0dc35bf575c1933272a4c3351bb07d37358748d7add968d1c577755477a97ea2', 3434),
    'strict-bao-client.js': ('3c226b335257ff67c4f6e23091468d99cba97399eea40b396bb89a8e691e5294', 26161),
    'bounded-outbox.js': ('77c86c49fca655d1c60112ce36ac9c3ef154f620b3e917f42ffa412307de9fa1', 18043),
    'private-outbox-store.js': ('e948edb2d461eedabd03e0acd83cc8b998553516e01ad41c16641360221c145d', 8660),
}
FILES = ('index.js', 'order-policy.js', 'lease-assignments.js',
         'provider-error-classifier.js', 'bad-refresh-quarantine.js',
         'runtime-refresh-policy.js', 'codex-client-recycler.js', 'package.json',
         'openclaw.plugin.json')

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def replace_once(text, old, new):
    assert text.count(old) == 1, old[:100]
    return text.replace(old, new, 1)

LIFECYCLE_HELPERS = '''    function transportFor(ctx) {
      if (!ctx || typeof ctx.stateDir !== "string" || !path.isAbsolute(ctx.stateDir)) {
        throw new Error("AuthBus production state directory is invalid");
      }
      if (transportStateDir !== null && transportStateDir !== ctx.stateDir) {
        throw new Error("AuthBus production state directory changed during one service lifetime");
      }
      if (bao === null) {
        transportStateDir = ctx.stateDir;
        bao = new ProductionTransportClient(config, ctx.stateDir);
      }
      return bao;
    }

    function stopService() {
      // Closing admission is synchronous. Every previously admitted callback
      // is already represented by the captured operation tail.
      stopped = true;
      serviceContext = null;
      if (timer) clearInterval(timer);
      timer = null;
      if (closePromise === null) {
        const admittedTail = operationTail;
        closePromise = (async () => {
          await admittedTail;
          if (bao !== null) await bao.close();
        })();
      }
      // A failed/unknown close remains the same original promise. Repeating
      // stop does not dispatch another revoke or reset transport history.
      return closePromise;
    }

'''

START_STOP = '''      async start(ctx) {
        if (serviceContext !== null || closePromise !== null) {
          throw new Error("AuthBus service requires a new registration after stop or failed start");
        }
        stopped = false;
        serviceContext = ctx;
        try {
          const releaseOperation = await acquireOperationLock();
          try {
            if (stopped || serviceContext !== ctx) return;
            await transportFor(ctx).reconcile();
          } finally {
            releaseOperation();
          }
          if (stopped || serviceContext !== ctx) return;
          await cycle(ctx);
          if (stopped || serviceContext !== ctx) return;
          timer = setInterval(() => void cycle(ctx), config.pollIntervalMs);
          timer.unref?.();
        } catch (error) {
          try {
            await stopService();
          } catch (closeError) {
            throw new AggregateError([error, closeError], "AuthBus startup and original transport closure failed");
          }
          throw error;
        }
      },
      async stop() {
        await stopService();
      },'''

OLD_START_STOP = '''      async start(ctx) {
        stopped = false;
        serviceContext = ctx;
        await cycle(ctx);
        timer = setInterval(() => void cycle(ctx), config.pollIntervalMs);
        timer.unref?.();
      },
      async stop() {
        stopped = true;
        serviceContext = null;
        if (timer) clearInterval(timer);
        timer = null;
      },'''

def integrated_index(original):
    text = original.decode()
    text = replace_once(text, 'import https from "node:https";\n', '')
    text = replace_once(text, 'import path from "node:path";\n',
        'import path from "node:path";\n\n'
        'import { ProductionTransportClient } from "./production-transport/production-client.js";\n'
        'import { normalizeTransport } from "./production-transport/bounded-outbox.js";\n')
    text = replace_once(text, 'const KV_MOUNT = "openclaw-auth";\n', '')
    begin = text.index('class BaoClient {\n')
    end = text.index('function discoverAgentDirs(stateDir) {\n', begin)
    text = text[:begin] + text[end:]
    text = replace_once(text, '    hostId: raw.hostId,\n',
        '    hostId: raw.hostId,\n'
        '    productionTransport: normalizeTransport(raw.productionTransport, raw.hostId),\n')
    text = replace_once(text, '    let stopped = false;\n', '    let stopped = true;\n')
    text = replace_once(text, '    let bao = null;\n',
        '    let bao = null;\n    let transportStateDir = null;\n    let closePromise = null;\n')
    text = replace_once(text, '    function ensureBadRefreshQuarantineLoaded(stateDir) {\n',
        LIFECYCLE_HELPERS + '    function ensureBadRefreshQuarantineLoaded(stateDir) {\n')
    text = replace_once(text,
        '        const releaseOperation = await acquireOperationLock();\n        try {\n          const agentDirs',
        '        const releaseOperation = await acquireOperationLock();\n        try {\n'
        '          if (stopped || serviceContext !== ctx) return;\n          const agentDirs')
    text = replace_once(text, '      try {\n        bao ??= new BaoClient(config);\n',
        '      try {\n        if (stopped || serviceContext !== ctx) return;\n'
        '        bao = transportFor(ctx);\n')
    text = replace_once(text, '          bao ??= new BaoClient(config);\n',
        '          bao = transportFor(ctx);\n')
    text = replace_once(text, OLD_START_STOP, START_STOP)
    text = replace_once(text, 'description: "Synchronizes auth credentials through OpenBao",',
        'description: "Synchronizes auth credentials through HeptaBao",')
    assert 'new BaoClient' not in text and 'class BaoClient' not in text
    assert text.count('new ProductionTransportClient(') == 1
    return text.encode()

def manifest(original):
    value = json.loads(original)
    schema = value['configSchema']
    assert schema['additionalProperties'] is False and 'productionTransport' not in schema['properties']
    schema['required'].append('productionTransport')
    sha = {'type': 'string', 'pattern': '^[a-f0-9]{64}$'}
    schema['properties']['productionTransport'] = {
        'type': 'object', 'additionalProperties': False,
        'required': ['schema', 'production', 'epoch', 'slots', 'agents', 'controlDigest', 'serverCertificateSha256'],
        'properties': {
            'schema': {'type': 'string', 'const': 'heptabao-authbus-fixed-slots-v1'},
            'production': {'type': 'boolean', 'const': True},
            'epoch': {'type': 'string', 'pattern': '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'},
            'slots': {'type': 'integer', 'minimum': 1, 'maximum': 32},
            'agents': {'type': 'array', 'minItems': 1, 'maxItems': 128, 'uniqueItems': True,
                       'items': {'type': 'string', 'pattern': '^[a-z0-9][a-z0-9_-]{0,127}$'}},
            'controlDigest': sha, 'serverCertificateSha256': sha,
        },
    }
    value['description'] = 'Synchronizes auth credentials through the HeptaBao production control plane'
    return (json.dumps(value, indent=2) + '\n').encode()

def main():
    OUTPUT.mkdir(exist_ok=False)
    report = {'schema': 'heptabao.production-plugin-integration-source.r1',
              'installed': False, 'productionServicesChanged': False, 'networkRequests': 0,
              'lifecycleQualification': False, 'actualProviderCredentialsRead': False, 'variants': {}}
    transport = {}
    for name, expected in TRANSPORT_PINS.items():
        raw = (REPO / 'tools/authbus/production-transport/plugin' / name).read_bytes()
        assert (hashlib.sha256(raw).hexdigest(), len(raw)) == expected
        transport[name] = raw
    for variant, source in [('mac-rog', MAC), ('pocket4', POCKET)]:
        target = OUTPUT / variant
        target.mkdir()
        (target / 'production-transport').mkdir()
        changes, sources, products = [], {}, {}
        for name in FILES:
            original = (MAC_MANIFEST if variant == 'mac-rog' and name == 'openclaw.plugin.json' else source / name).read_bytes()
            sources[name] = pin(original)
            raw = original
            if name == 'index.js':
                assert (hashlib.sha256(original).hexdigest(), len(original)) == ORIGINAL_INDEX[variant]
                raw = integrated_index(original)
            elif name == 'openclaw.plugin.json':
                raw = manifest(original)
            elif name == 'package.json':
                value = json.loads(original)
                assert 'production-transport' not in value['files']
                value['files'].append('production-transport')
                value['version'] += '-heptabao.1'
                raw = (json.dumps(value, indent=2) + '\n').encode()
            (target / name).write_bytes(raw)
            products[name] = pin(raw)
            if raw != original:
                changes.extend(difflib.unified_diff(original.decode().splitlines(True), raw.decode().splitlines(True),
                    fromfile=variant + '/original/' + name, tofile=variant + '/prepared/' + name))
        for name, raw in transport.items():
            (target / 'production-transport' / name).write_bytes(raw)
            products['production-transport/' + name] = pin(raw)
        (OUTPUT / (variant + '.diff')).write_text(''.join(changes))
        report['variants'][variant] = {'sourceFiles': sources, 'preparedFiles': products,
            'originalIndex': ORIGINAL_INDEX[variant][0], 'sourceHelpersUnchanged': True,
            'requiresColdNewRegistrationAfterStop': True}
    (OUTPUT / 'manifest.public.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'ok': True, 'variants': list(report['variants']), 'installed': False,
                      'manifest': str(OUTPUT / 'manifest.public.json')}))

if __name__ == '__main__':
    main()
