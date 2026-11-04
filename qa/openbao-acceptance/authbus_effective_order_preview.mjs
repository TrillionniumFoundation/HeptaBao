#!/usr/bin/env node
/** Pure current-store preview. No credential replacement, native factory or network. */
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import childProcess from 'node:child_process';
import { createHash } from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { pathToFileURL } from 'node:url';

process.umask(0o077);
const planPath = path.resolve(process.argv[2]);
const planBytes = fs.readFileSync(planPath);
const plan = JSON.parse(planBytes);
const root = path.dirname(planPath);
const sha = value => createHash('sha256').update(value).digest('hex');
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const digest = value => sha(JSON.stringify(stable(value)));
const report = { schema: 'heptabao.actual-sdk-effective-order-preview.v1', ok: false,
  host: plan.host, checks: [], agents: [], policies: [], providerRequests: 0,
  nativeFactoriesStarted: 0, authStoreWriteApiInvoked: false, productionCutover: false,
  credentialsReplaced: false, blockedOperationAttempts: 0,
  scope: 'Actual installed SDK loads every configured agent from private copies of its current raw auth rows, including main-store inheritance. Two explicit non-enforced central candidate permutations are evaluated using the installed pure order policy and resolver. This is not a full AuthBus import, production restart, or provider availability test.' };
const sensitive = [];
const check = (name, value) => {
  report.checks.push({ case: name, passed: value === true });
  if (value !== true) throw Object.assign(new Error(name), { safeCode: name });
};
const deny = () => { report.blockedOperationAttempts++; throw Object.assign(new Error('network_or_child_refused'), { safeCode: 'network_or_child_refused' }); };
function save(name, value) {
  const bytes = Buffer.from(JSON.stringify(value, null, 2) + '\n');
  const fd = fs.openSync(path.join(root, name), fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return sha(bytes);
}
try {
  check('private_state_and_readonly_mode', process.env.OPENCLAW_STATE_DIR === plan.stateRoot
    && process.env.OPENCLAW_AUTH_STORE_READONLY === '1'
    && process.env.OPENCLAW_CONFIG_PATH === path.join(plan.stateRoot, 'openclaw.json'));
  const originalExecFileSync = childProcess.execFileSync;
  for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) childProcess[name] = deny;
  childProcess.execFileSync = (file, args, options) => {
    if (process.platform !== 'darwin' || file !== 'mount' || !Array.isArray(args) || args.length !== 0 || options !== undefined) return deny();
    const stat = fs.lstatSync('/sbin/mount');
    check('fixed_readonly_mount_probe', stat.isFile() && stat.uid === 0 && (stat.mode & 0o022) === 0);
    return originalExecFileSync('/sbin/mount', [], { timeout: 3000, maxBuffer: 262144,
      env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' }, stdio: ['ignore', 'pipe', 'pipe'] });
  };
  globalThis.fetch = deny;
  http.request = deny; http.get = deny; https.request = deny; https.get = deny;
  net.connect = deny; net.createConnection = deny;
  syncBuiltinESMExports();
  for (const [file, expected] of Object.entries(plan.sourcePins)) check('source.' + path.basename(file), sha(fs.readFileSync(file)) === expected);
  const sdk = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/plugin-sdk/agent-runtime.js')));
  const order = await import(pathToFileURL(path.join(plan.sdkRoot, 'dist/order-CeBlX0NH.js')));
  const policyApi = await import(pathToFileURL(plan.orderPolicyPath));
  const cfg = JSON.parse(fs.readFileSync(path.join(plan.stateRoot, 'openclaw.json')));
  const pluginConfig = cfg.plugins.entries['openclaw-authbus'].config;
  const excludes = new Set(pluginConfig.orderExcludeAgentIds ?? []);
  check('original_management_flags', pluginConfig.manageOrder === true && pluginConfig.publishNew === true && pluginConfig.leader === false);
  check('exact_configured_agents', JSON.stringify(cfg.agents.list.map(value => value.id)) === JSON.stringify(plan.agentIds));
  check('default_main_private_path', path.resolve(sdk.resolveDefaultAgentDir({})) === path.join(plan.stateRoot, 'agents/main/agent'));
  const stores = new Map();
  for (const agentId of plan.agentIds) {
    const agentDir = path.join(plan.stateRoot, 'agents', agentId, 'agent');
    check('database_scope.' + agentId, path.resolve(sdk.resolveAuthStorePathForDisplay(agentDir)) === path.join(agentDir, 'openclaw-agent.sqlite'));
    const store = sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    stores.set(agentId, store);
    for (const [id, credential] of Object.entries(store.profiles)) {
      sensitive.push(id);
      for (const [key, value] of Object.entries(credential)) if (typeof value === 'string' && value.length >= 8 && !['type', 'provider', 'chatgptPlanType'].includes(key)) sensitive.push(value);
    }
  }
  const main = stores.get('main');
  const identities = ['332c2cdd98cd0650de22a4506f7f67c3cbc69a9154e0cbafa4344f7a691640b9', '899445c0e083199d67988e1db5bc7ac6d4d158bf913bb54669e5afc7714f2fb2'];
  const ids = identities.map(account => {
    const matches = Object.entries(main.profiles).filter(([, value]) => sha(String(value.accountId ?? '')) === account);
    check('unique_same_managed_identity.' + (identities.indexOf(account) + 1), matches.length === 1);
    return matches[0][0];
  });
  check('cross_host_same_profile_ids', JSON.stringify(ids.map(sha)) === JSON.stringify(plan.expectedProfileIdSha256));
  const alternatives = [ids, [...ids].reverse()];
  const provider = sdk.resolveProviderIdForAuth('openai');
  check('actual_auth_provider_openai', provider === 'openai');
  const providerOrder = store => {
    const key = Object.keys(store.order ?? {}).find(key => sdk.resolveProviderIdForAuth(key) === provider);
    return key ? store.order[key] : [];
  };
  for (const [index, candidateIds] of alternatives.entries()) {
    const policy = policyApi.normalizeOrderPolicy({ schemaVersion: 1, generation: 1,
      providers: { openai: { candidates: candidateIds.map(profileId => ({ profileId, digest: digest(main.profiles[profileId]), enrolledAt: 0 })),
        activeProfile: null, enforceManagedOrder: false } } });
    check('non_enforced_policy_shape.' + index, policy.providers.openai.activeProfile === null
      && policy.providers.openai.enforceManagedOrder === false && policy.providers.openai.scheduler === null);
    const evaluations = [];
    for (const agentId of plan.agentIds) {
      const before = stores.get(agentId);
      const existing = providerOrder(before);
      const eligible = policy.providers.openai.candidates.map(value => value.profileId).filter(profileId =>
        sdk.resolveProviderIdForAuth(before.profiles[profileId]?.provider ?? '') === provider);
      const excluded = excludes.has(agentId);
      const next = excluded ? [...existing] : policyApi.mergeManagedOrder(existing, eligible, null, { enforceManagedOrder: false });
      const candidate = structuredClone(before);
      if (!excluded) candidate.order = { ...(candidate.order ?? {}), [provider]: next };
      const beforeResolved = order.i({ cfg, store: structuredClone(before), provider });
      const candidateResolved = order.i({ cfg, store: structuredClone(candidate), provider });
      check('credential_and_usage_untouched.' + index + '.' + agentId, digest(before.profiles) === digest(candidate.profiles)
        && digest(before.usageStats ?? null) === digest(candidate.usageStats ?? null)
        && digest(before.lastGood ?? null) === digest(candidate.lastGood ?? null));
      evaluations.push({ agentId, excluded, effectiveProfileCount: Object.keys(before.profiles).length,
        existingOrderProfileIdSha256: existing.map(sha), proposedOrderProfileIdSha256: next.map(sha),
        exactStoredOrderPreserved: policyApi.sameOrder(existing, next),
        sdkResolvedBeforeProfileIdSha256: beforeResolved.map(sha), sdkResolvedAfterProfileIdSha256: candidateResolved.map(sha),
        actualResolvedOrderPreserved: policyApi.sameOrder(beforeResolved, candidateResolved) });
    }
    report.policies.push({ name: index === 0 ? 'managed_1_then_2' : 'managed_2_then_1',
      candidatesProfileIdSha256: candidateIds.map(sha), activeProfile: null, enforceManagedOrder: false, scheduler: null,
      credentialDigestsScope: 'Candidate digests come from the current captured main store for a pure ordering preview; final trusted credential generations are a separate publication binding.',
      allStoredOrdersPreserved: evaluations.every(value => value.exactStoredOrderPreserved),
      allActualSdkOrdersPreserved: evaluations.every(value => value.actualResolvedOrderPreserved), evaluations });
  }
  for (const agentId of plan.agentIds) {
    const store = stores.get(agentId);
    const again = sdk.loadAuthProfileStoreWithoutExternalProfiles(path.join(plan.stateRoot, 'agents', agentId, 'agent'), { allowKeychainPrompt: false });
    check('whole_effective_store_unchanged.' + agentId, digest(store) === digest(again));
    report.agents.push({ agentId, localProfileCount: plan.localProfilesByAgent[agentId], effectiveProfileCount: Object.keys(store.profiles).length,
      effectiveStoreSha256: digest(store), effectiveUsageSha256: digest(store.usageStats ?? null),
      inheritedMainCredential: plan.localProfilesByAgent[agentId] === 0 && Object.keys(store.profiles).length > 0 });
  }
  for (const [file, expected] of Object.entries(plan.sourcePins)) check('source_unchanged.' + path.basename(file), sha(fs.readFileSync(file)) === expected);
  check('zero_network_or_unapproved_child_attempts', report.blockedOperationAttempts === 0);
  report.qualifyingPolicies = report.policies.filter(value => value.allStoredOrdersPreserved && value.allActualSdkOrdersPreserved).map(value => value.name);
  check('at_least_one_original_semantics_policy_preserves_all_current_agents', report.qualifyingPolicies.length > 0);
  check('private_plan_bytes_unchanged', sha(fs.readFileSync(planPath)) === sha(planBytes));
  report.sourcePins = plan.sourcePins;
  report.ok = true;
} catch (error) {
  report.error = error?.safeCode ?? error?.name ?? 'Error';
}
const publicBytes = JSON.stringify(report);
if (sensitive.some(value => publicBytes.includes(value))) {
  report.ok = false; report.error = 'public_sensitive_value_rejected'; delete report.agents; delete report.policies; delete report.sourcePins;
}
const resultSha256 = save('result.public.json', report);
process.stdout.write(JSON.stringify({ ok: report.ok, error: report.error ?? null, result: path.join(root, 'result.public.json'), sha256: resultSha256 }) + '\n');
process.exitCode = report.ok ? 0 : 1;
