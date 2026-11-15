// Read only reconstructed private auth tables through the current installed SDK.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import dgram from 'node:dgram';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

let blocked = 0;
const deny = () => { blocked++; throw Object.assign(new Error('offline_sdk_operation_refused'), { code: 'offline_sdk_operation_refused' }); };
net.Socket.prototype.connect = deny; tls.connect = deny;
http.request = deny; http.get = deny; https.request = deny; https.get = deny;
dgram.createSocket = deny; globalThis.fetch = deny;
for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) childProcess[name] = deny;
syncBuiltinESMExports();
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const sha = value => createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');
const result = { ok: false, networkOrChildOperationsAttempted: 0, providerCalled: false, stores: [] };
try {
  const plan = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  const moduleBytes = fs.readFileSync(plan.sdkStoreModule);
  if (createHash('sha256').update(moduleBytes).digest('hex') !== plan.sdkStoreSha256) throw new Error('sdk_source_changed');
  const sdk = await import(pathToFileURL(plan.sdkStoreModule));
  if (typeof sdk.u !== 'function') throw new Error('sdk_loader_missing');
  for (const agent of plan.agents) {
    const store = sdk.u(path.join(plan.stateRoot, 'agents', agent, 'agent'), { allowKeychainPrompt: false });
    if (!store || typeof store.profiles !== 'object') throw new Error('sdk_store_shape');
    result.stores.push({ agent, profileCount: Object.keys(store.profiles).length, storeSha256: sha(store),
      profilesSha256: sha(store.profiles) });
  }
  result.networkOrChildOperationsAttempted = blocked;
  result.ok = blocked === 0;
} catch (error) { result.error = error.code === 'offline_sdk_operation_refused' ? error.code : 'sdk_read_failed'; }
result.networkOrChildOperationsAttempted = blocked;
process.stdout.write(JSON.stringify(result) + '\n');
process.exitCode = result.ok ? 0 : 1;
