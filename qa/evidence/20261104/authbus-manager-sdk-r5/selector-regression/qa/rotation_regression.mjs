import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const modulePath = path.resolve(process.argv[2]);
const policy = await import(pathToFileURL(modulePath));
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const profile = 'openai:managed-rotation';
const b = hash('known-applied-generation-b');
const c = hash('canonical-generation-c');
const d = hash('new-local-generation-d');
const identity = hash('same-managed-provider-account');
const canonical = { profileId: profile, digest: c, identity, type: 'oauth', expires: 200 };
const candidate = { profileId: profile, digest: d, identity,
  credential: { provider: 'openai', type: 'oauth', expires: 300 } };
const checks = [];
const check = (name, fn) => {
  try { fn(); checks.push({ case: name, passed: true }); }
  catch (error) { checks.push({ case: name, passed: false, error: error.name }); }
};
const select = (local = candidate, remote = canonical, applied = b) => policy.selectPendingRuntimeRefreshes(
  new Map([[profile, local]]), remote ? new Map([[profile, remote]]) : new Map(),
  applied === undefined ? new Map() : new Map([[profile, applied]]));

check('unacknowledged_c_must_not_overwrite_newer_managed_local_d', () => {
  const result = select();
  assert.equal(result.get(profile)?.digest, d);
  assert.equal(policy.expectedCredentialDigest(canonical, result), d);
});
check('previously_acknowledged_refresh_contract_unchanged', () => {
  assert.equal(select(candidate, canonical, c).get(profile)?.digest, d);
});
check('already_canonical_profile_has_no_pending_refresh', () => {
  assert.equal(select({ ...candidate, digest: c }).size, 0);
});
check('unmanaged_profile_has_no_implicit_refresh_authority', () => {
  assert.equal(select(candidate, null).size, 0);
});
check('never_applied_profile_has_no_implicit_refresh_authority', () => {
  const result = policy.selectPendingRuntimeRefreshes(new Map([[profile, candidate]]),
    new Map([[profile, canonical]]), new Map());
  assert.equal(result.size, 0);
});
check('malformed_applied_marker_is_not_management_proof', () => {
  for (const value of ['', 'broken', {}, false, 12]) assert.equal(select(candidate, canonical, value).size, 0);
});
check('different_provider_identity_cannot_be_pending', () => {
  assert.equal(select({ ...candidate, identity: hash('different-account') }).size, 0);
});
check('local_api_key_is_not_promoted_to_oauth_rotation', () => {
  assert.equal(select({ ...candidate, credential: { ...candidate.credential, type: 'api_key' } }).size, 0);
});
check('canonical_api_key_is_not_promoted_to_oauth_rotation', () => {
  assert.equal(select(candidate, { ...canonical, type: 'api_key' }).size, 0);
});
check('equal_or_older_local_expiry_is_not_pending', () => {
  for (const expires of [100, 200, 0, undefined]) {
    assert.equal(select({ ...candidate, credential: { ...candidate.credential, expires } }).size, 0);
  }
});
check('canonical_and_management_inputs_remain_unchanged', () => {
  const local = new Map([[profile, candidate]]), manifest = new Map([[profile, canonical]]), applied = new Map([[profile, b]]);
  const before = JSON.stringify([Array.from(local), Array.from(manifest), Array.from(applied)]);
  policy.selectPendingRuntimeRefreshes(local, manifest, applied);
  assert.equal(JSON.stringify([Array.from(local), Array.from(manifest), Array.from(applied)]), before);
});
check('unmanaged_effective_digest_stays_canonical', () => {
  assert.equal(policy.expectedCredentialDigest(canonical, new Map()), c);
});

const report = { schema: 'heptabao.authbus-unacknowledged-rotation-regression.v1',
  moduleSha256: hash(fs.readFileSync(modulePath)), checks,
  ok: checks.every(row => row.passed), providerCalled: false,
  productionModified: false, canonicalPublicationAuthorizedBySelector: false };
process.stdout.write(JSON.stringify(report, null, 2) + '\n');
process.exitCode = report.ok ? 0 : 1;
