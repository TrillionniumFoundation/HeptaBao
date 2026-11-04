#!/usr/bin/env node
/** One pinned SDK usage GET for one explicitly typed, current ROG source. */
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import http from 'node:http';
import childProcess from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { syncBuiltinESMExports } from 'node:module';

process.umask(0o077);
const ROOT = '/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-fresh-managed2-61ff8bef-r1';
const LIVE = '/home/qian-qi/.openclaw';
const NATIVE = '/home/qian-qi/.codex';
const SDK_MODULE = '/home/qian-qi/.npm-global/lib/node_modules/openclaw/dist/provider-usage-BxQS-VWA.js';
const MODULE_SHA = 'cab428b63c6e8912f444089e120c95aea4a1d5edf4258c7fd1b20346558d12e6';
const CONFIG_SHA = 'a042bc7fba4ac1295e323e0112598972a2872a040c5464af9614e4c2e600bd15';
const NATIVE_SHA = 'f4aee2935351eaa6d56ce99166a0123c3c9e3260ae8737e6d7ad8ce2c8c12b78';
const NATIVE_CONFIG_SHA = '57c13259d009c266c37d1c4578596c0a6236dae3862eccedb3eb74a99084c350';
const MANAGED_SHA = '131b8515d48433365dd84555e7659297d4d62de631f9a526a8a4293f03396175';
const NATIVE_SDK_SHA = '63a40b812af24584847961eeaff54e780eacc66625970ee40ea2d9b1e0a70398';
const SELECTION = ROOT + '/resolve-r1/selection.private.json';
const ENDPOINT = 'https://chatgpt.com/backend-api/wham/usage';
const hash = b => createHash('sha256').update(b).digest('hex');
const stable = v => Array.isArray(v) ? v.map(stable) : v && typeof v === 'object'
  ? Object.fromEntries(Object.keys(v).sort().map(k => [k, stable(v[k])])) : v;
const digest = v => hash(JSON.stringify(stable(v)));
const report = { schema: 'heptabao.rog-current-typed-source-fresh-usage.v1', ok: false,
  providerCalled: false, authbusMigrationClaimed: false, providerMutationAttempted: false, refreshAttempted: false, modelCalled: false,
  productionChanged: false, productionCutover: false, j3160Contacted: false,
  credentialValuesPublished: false, accountIdentitiesPublished: false, allAccountsQualified: false,
  nativeSourceAdoptedByAuthBus: false, productionGatewaySelectionQualified: false,
  automaticRetry: false, requestCount: 0, unexpectedOperations: 0 };
let plan, work, selection, token, account;
const secrets = [];
function need(v, code) { if (!v) throw Object.assign(new Error(code), { safeCode: code }); }
function privateRead(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const s = fs.fstatSync(fd);
    need(s.isFile() && s.uid === process.getuid() && (s.mode & 0o077) === 0 && s.nlink === 1 && s.size <= 2 * 1024 * 1024, 'private_input_custody');
    const data = fs.readFileSync(fd), t = fs.fstatSync(fd), u = fs.lstatSync(file);
    need([t,u].every(x => x.dev === s.dev && x.ino === s.ino && x.size === s.size && x.mtimeMs === s.mtimeMs && x.ctimeMs === s.ctimeMs), 'private_input_changed');
    return data;
  } finally { fs.closeSync(fd); }
}
function save(file, value) {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(value));
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const dirfd = fs.openSync(path.dirname(file), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(dirfd); } finally { fs.closeSync(dirfd); }
  return hash(data);
}
function deny() { report.unexpectedOperations++; throw Object.assign(new Error('unexpected_operation_refused'), { safeCode: 'unexpected_operation_refused' }); }
function currentSource() {
  const cfgRaw = privateRead(LIVE + '/openclaw.json');
  const nativeRaw = privateRead(NATIVE + '/auth.json');
  need(hash(cfgRaw) === CONFIG_SHA && hash(nativeRaw) === NATIVE_SHA && hash(privateRead(NATIVE + '/config.toml')) === NATIVE_CONFIG_SHA, 'production_configuration_or_native_generation_changed');
  const cfg = JSON.parse(cfgRaw), native = JSON.parse(nativeRaw);
  const app = cfg.plugins.entries.codex.config.appServer;
  need(app.homeScope === 'user' && app.transport === 'stdio' && cfg.agents.defaults.model.primary === 'codex/gpt-6.1-sol', 'production_default_contract_changed');
  const dbpath = LIVE + '/agents/main/agent/openclaw-agent.sqlite';
  const before = fs.lstatSync(dbpath);
  need(before.isFile() && before.uid === process.getuid() && (before.mode & 0o777) === 0o600 && before.nlink === 1, 'source_database_custody');
  need(!fs.existsSync(dbpath + '-wal') || fs.existsSync(dbpath + '-shm'), 'readonly_wal_requires_shm');
  const db = new DatabaseSync(dbpath, { readOnly: true });
  let profiles;
  try {
    db.exec('PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; BEGIN');
    const rows = db.prepare("SELECT store_json FROM auth_profile_store WHERE store_key='primary'").all();
    need(rows.length === 1, 'unique_current_store');
    profiles = JSON.parse(rows[0].store_json).profiles;
    db.exec('ROLLBACK');
  } finally { db.close(); }
  const after = fs.lstatSync(dbpath);
  need(after.dev === before.dev && after.ino === before.ino && after.uid === before.uid && after.mode === before.mode && after.nlink === 1, 'source_database_replaced');
  need(Object.keys(profiles).length === 3, 'source_profile_shape_changed');
  const [p1, p2, p4] = Object.entries(profiles), t = native.tokens;
  need(digest(p1[1]) === 'bca88c7adde84057871fd63f202e6aba80d453a04f75151df1d29f269dfaa5f1' && digest(p2[1]) === MANAGED_SHA && digest(p4[1]) === NATIVE_SDK_SHA, 'current_sdk_generations_changed');
  need(native.auth_mode === 'chatgpt' && t.access_token === p4[1].access && t.refresh_token === p4[1].refresh && t.account_id === p4[1].accountId, 'native4_sdk_same_generation');
  need(plan.sourceKind === 'managed-profile2-current-sdk-explicit', 'exact_current_managed2_source');
  const bytes = privateRead(SELECTION);
  need(hash(bytes) === plan.selectionFileSha256, 'actual_sdk_selection_file_changed');
  selection = JSON.parse(bytes);
  need(selection.source === 'actual_installed_sdk_explicit_profile_resolver_current_source_no_authbus_migration_claim'
    && selection.profileId === p2[0] && digest(selection.credential) === MANAGED_SHA
    && digest(selection.credential) === digest(p2[1]) && selection.resolvedApiKey === selection.credential.access,
    'actual_current_sdk_selection_origin_and_generation');
  const credential = selection.credential;
  const claims = JSON.parse(Buffer.from(credential.access.split('.')[1], 'base64url'));
  need(claims.exp * 1000 > Date.now() + 120000 && claims['https://api.openai.com/auth']?.chatgpt_account_id === credential.accountId, 'current_source_expiry_or_identity');
  secrets.push(credential.access, credential.refresh, credential.accountId, ...Object.keys(profiles));
  return { token: credential.access, account: credential.accountId, public: {
    credentialSha256: digest(credential), nativeFileSha256: hash(nativeRaw), configurationSha256: hash(cfgRaw),
    accountIdSha256: hash(credential.accountId), jwtExpiresUnixSeconds: claims.exp,
    sourceKind: plan.sourceKind, nativeSourceGeneration: digest({ access:t.access_token, refresh:t.refresh_token, accountId:t.account_id }),
    actualSdkCurrentSelectionSha256: plan.selectionFileSha256 } };
}
try {
  need(process.argv.length === 3, 'argument_shape');
  plan = JSON.parse(privateRead(process.argv[2]));
  need(process.argv[2] === ROOT + '/control/' + plan.caseId + '.plan.json', 'exact_plan_path');
  need(plan.caseId === 'managed2-r1' && plan.sourceKind === 'managed-profile2-current-sdk-explicit', 'exact_case_scope');
  work = ROOT + '/' + plan.caseId;
  need(plan.work === work && fs.lstatSync(work).isDirectory() && !fs.existsSync(work + '/request-started.public.json'), 'fresh_one_request_scope');
  need(hash(fs.readFileSync(import.meta.filename)) === plan.helperSha256, 'helper_source_pin');
  need(hash(fs.readFileSync(SDK_MODULE)) === MODULE_SHA, 'sdk_usage_module_pin');
  const resolverBytes = privateRead(ROOT + '/resolve-r1/result.public.json');
  need(hash(resolverBytes) === plan.resolverReceiptSha256, 'current_sdk_resolver_receipt_pin');
  const resolver = JSON.parse(resolverBytes);
  need(resolver.ok === true && resolver.actualCurrentSdkExplicitSelectionQualified === true
    && resolver.selectionSha256 === plan.selectionFileSha256 && resolver.unexpectedOperations === 0,
    'actual_current_sdk_resolution_success');
  const outerBytes = privateRead(ROOT + '/resolve-r1/outer-result.public.json');
  need(hash(outerBytes) === plan.resolverOuterSha256, 'current_sdk_resolver_outer_pin');
  const outer = JSON.parse(outerBytes);
  need(outer.ok === true && outer.returnCode === 0 && outer.sourcePinsUnchanged === true
    && outer.productionUnitUnchanged === true && outer.ownedNamespaceProcessExited === true,
    'current_sdk_resolver_complete_and_clean');
  for (const k of ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy','NODE_OPTIONS']) need(!process.env[k], 'unexpected_proxy_or_preload_configuration');
  const initial = currentSource(); token = initial.token; account = initial.account;
  report.sourceKind = plan.sourceKind; report.sourceBindingBefore = initial.public;
  report.sourceKindPreserved = true; report.sdkUsageModuleSha256 = MODULE_SHA;
  const originalRequest = https.request;
  globalThis.fetch = deny; http.request = deny; http.get = deny; https.request = deny; https.get = deny;
  for (const k of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork']) childProcess[k] = deny;
  syncBuiltinESMExports();
  need(process.env.TMPDIR === work + '/tmp', 'private_tmpdir_scope');
  const tmpModulePath = '/home/qian-qi/.npm-global/lib/node_modules/openclaw/dist/tmp-openclaw-dir-uPgNO8da.js';
  need(hash(fs.readFileSync(tmpModulePath)) === 'c12ed50f959d17d9e4ca3e3cce60aa471ee160bdd705035a6d1ed63c47207b23', 'sdk_tmp_contract_pin');
  const sdk = await import(pathToFileURL(SDK_MODULE));
  const tmpApi = await import(pathToFileURL(tmpModulePath));
  need(tmpApi.n() === work + '/tmp/openclaw-' + process.getuid(), 'actual_sdk_private_tmp_fallback');
  report.actualSdkPrivateTmpFallback = true;
  let calls = 0;
  const fetchOne = async (input, init = {}) => {
    need(++calls === 1 && String(input) === ENDPOINT && init.method === 'GET', 'one_fixed_readonly_usage_request');
    const headers = new Headers(init.headers);
    need(headers.get('authorization') === 'Bearer ' + token && headers.get('chatgpt-account-id') === account, 'actual_sdk_headers_source_binding');
    const atDispatch = currentSource();
    need(atDispatch.token === token && atDispatch.account === account && digest(atDispatch.public) === digest(initial.public), 'source_generation_changed_before_dispatch');
    report.currentSourceBoundImmediatelyBeforeDispatch = true;
    report.requestLedgerSha256 = save(work + '/request-started.public.json', { schema:'heptabao.exact-once-readonly-provider-request.v1',
      startedAt:new Date().toISOString(), sourceBinding:atDispatch.public, method:'GET', endpoint:ENDPOINT,
      retryAllowed:false, helperSha256:plan.helperSha256, sdkUsageModuleSha256:MODULE_SHA });
    report.requestCount = 1; report.providerCalled = true;
    return await new Promise((resolve, reject) => {
      const request = originalRequest(ENDPOINT, { method:'GET', minVersion:'TLSv1.2', rejectUnauthorized:true,
        agent:false, signal:init.signal, headers:Object.fromEntries(headers) }, response => {
        report.httpStatus = response.statusCode; report.tlsVerified = response.socket.authorized === true;
        let size = 0; const parts = [];
        response.on('data', part => { size += part.length; if (size > 1024 * 1024) request.destroy(Object.assign(new Error('body_bound'), {safeCode:'body_bound'})); else parts.push(part); });
        response.on('end', () => {
          try {
            need(size <= 1024 * 1024, 'body_bound');
            const body = Buffer.concat(parts); report.responseBytes = body.length;
            report.responseSha256 = save(work + '/response.private', body);
            report.responseDurableBeforeSdkParse = true;
            resolve(new Response(body, {status:response.statusCode, headers:{'content-type':response.headers['content-type'] ?? ''}}));
          } catch (e) { reject(e); }
        });
        response.on('error', reject);
      });
      request.on('socket', socket => {
        socket.on('lookup', e => { report.dnsResolved = !e; });
        socket.on('connect', () => { report.tcpConnected = true; report.remoteFamily = socket.remoteFamily; });
        socket.on('secureConnect', () => { report.tlsConnected = true; report.tlsVerified = socket.authorized === true; });
      });
      request.on('finish', () => { report.requestWritten = true; });
      request.setTimeout(15000, () => request.destroy(Object.assign(new Error('read_timeout'), {safeCode:'read_timeout'})));
      request.on('error', reject); request.end();
    });
  };
  const snapshot = await sdk.a(token, account, 18000, fetchOne);
  report.sdkParsed = snapshot?.provider === 'openai' && Array.isArray(snapshot.windows) && !snapshot.error;
  report.usageWindowCount = Array.isArray(snapshot?.windows) ? snapshot.windows.length : 0;
  report.usageWindowStructureValid = Array.isArray(snapshot?.windows) && snapshot.windows.every(w => typeof w.label === 'string' && Number.isFinite(w.usedPercent) && (w.resetAt === undefined || Number.isFinite(w.resetAt)));
  report.sdkErrorPresent = !!snapshot?.error;
  const after = currentSource(); report.sourceBindingAfter = after.public;
  report.currentSourceGenerationUnchangedAfterResponse = digest(initial.public) === digest(after.public);
  need(report.currentSourceGenerationUnchangedAfterResponse && hash(fs.readFileSync(SDK_MODULE)) === MODULE_SHA, 'source_or_sdk_changed_after_response');
  need(report.httpStatus === 200 && report.tlsVerified && report.sdkParsed && report.usageWindowStructureValid && report.requestCount === 1 && report.unexpectedOperations === 0, 'current_source_provider_read_failed');
  report.freshReadOnlyProviderValidityQualified = true; report.modelAvailabilityQualified = false; report.ok = true;
} catch (error) {
  report.error = error?.safeCode ?? 'typed_source_read_failed'; report.errorClass = error?.constructor?.name ?? 'unknown';
  if (typeof error?.code === 'string' && /^[A-Z_]{2,40}$/.test(error.code)) report.errorCode = error.code;
  report.providerOutcomeUnknown = report.providerCalled && !report.responseDurableBeforeSdkParse;
}
need(work && secrets.every(x => typeof x !== 'string' || x.length < 8 || !JSON.stringify(report).includes(x)), 'public_report_secret_guard');
save(work + '/result.public.json', report);
process.stdout.write(JSON.stringify({ok:report.ok,sourceKind:report.sourceKind,httpStatus:report.httpStatus ?? null,requestCount:report.requestCount,result:work+'/result.public.json'})+'\n');
process.exitCode = report.ok ? 0 : 1;
