// Fresh AppRole clients read actual captured credentials only into private files.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
const plan = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const sha = value => createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');
const report = { ok: false, providerCalled: false, credentialValuesPublished: false, checks: [] };
const docs = [];
const check = (name, condition) => {
  report.checks.push({ case: name, passed: condition === true });
  if (!condition) throw Object.assign(new Error(name), { code: name });
};
try {
  const { StrictBaoClient } = await import(pathToFileURL(path.join(plan.moduleRoot, 'strict-bao-client.js')));
  const { PrivateOutboxStore } = await import(pathToFileURL(path.join(plan.moduleRoot, 'private-outbox-store.js')));
  for (const entry of plan.entries) {
    const store = new PrivateOutboxStore(entry.stateDir, { schema: 'heptabao.current-private-stage', address: entry.address, key: entry.key });
    const client = new StrictBaoClient(entry, store);
    try {
      const value = await client.readSecret(entry.key, { deadlineMs: Date.now() + 20000 });
      check(entry.agent + '.exact_app_role_read', value?.version === 1 && sha(value.data) === entry.expectedSha256);
      let denied = false;
      try { await client.readSecret(entry.deniedKey, { deadlineMs: Date.now() + 10000 }); }
      catch (error) { denied = error.status === 403 && error.unknown === false; }
      check(entry.agent + '.cross_agent_policy_denied', denied);
      docs.push(value.data);
      const closed = await client.close({ revoke: true, deadlineMs: Date.now() + 10000 });
      check(entry.agent + '.self_revoke_confirmed', closed.revoked === true && closed.originalBearerLookupStatus === 403);
    } finally { store.close(); }
  }
  fs.writeFileSync(plan.privateOutput, JSON.stringify(docs), { mode: 0o600, flag: 'wx' });
  report.documentsSha256 = sha(docs);
  report.ok = true;
} catch (error) { report.error = /^[A-Za-z0-9_.-]{1,100}$/.test(error.code ?? '') ? error.code : 'private_stage_client_failed'; }
process.stdout.write(JSON.stringify(report) + '\n');
process.exitCode = report.ok ? 0 : 1;
