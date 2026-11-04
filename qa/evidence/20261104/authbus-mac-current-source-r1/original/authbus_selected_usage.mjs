#!/usr/bin/env node
/** One read-only provider validation of the SDK's actual default selection. */
import fs from 'node:fs';
import https from 'node:https';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
process.umask(0o077);
const [selectionPath, sdkModule, expectedModuleSha, resultPath] = process.argv.slice(2);
const hash = value => createHash('sha256').update(value).digest('hex');
const report = { schema: 'heptabao.actual-default-selected-account-read.v1', ok: false,
  providerCalled: false, providerMutationAttempted: false, refreshAttempted: false,
  modelCalled: false, productionChanged: false, productionCutover: false, j3160Contacted: false,
  credentialValuesPublished: false, accountIdentitiesPublished: false, allAccountsQualified: false };
function need(value, code) { if (!value) throw Object.assign(new Error(code), { safeCode: code }); }
try {
  const info = fs.lstatSync(selectionPath);
  need(info.isFile() && !info.isSymbolicLink() && info.uid === process.getuid() && (info.mode & 0o777) === 0o600 && info.nlink === 1, 'selection_custody');
  const bytes = fs.readFileSync(selectionPath), selected = JSON.parse(bytes);
  need(selected.source === 'actual_installed_sdk_default_model_resolver_after_actual_authbus_cycle', 'selection_origin');
  const token = selected.resolvedApiKey, account = selected.credential.accountId;
  need(token === selected.credential.access && typeof account === 'string', 'selection_binding');
  const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
  need(claims.exp * 1000 > Date.now() + 120000 && claims['https://api.openai.com/auth']?.chatgpt_account_id === account, 'selection_claims');
  need(hash(fs.readFileSync(sdkModule)) === expectedModuleSha, 'usage_module_pin');
  const sdk = await import(pathToFileURL(sdkModule));
  let count = 0;
  const endpoint = 'https://chatgpt.com/backend-api/wham/usage';
  const fetchOne = async (input, init = {}) => {
    need(++count === 1 && String(input) === endpoint && init.method === 'GET', 'one_read_only_usage_request');
    report.requestCount = count;
    const headers = new Headers(init.headers);
    need(headers.get('authorization') === 'Bearer ' + token && headers.get('chatgpt-account-id') === account, 'sdk_selected_auth_binding');
    report.providerCalled = true;
    return await new Promise((resolve, reject) => {
      const request = https.request(endpoint, { method: 'GET', minVersion: 'TLSv1.2', rejectUnauthorized: true,
        agent: false, signal: init.signal, headers: Object.fromEntries(headers) }, response => {
        report.httpStatus = response.statusCode; report.tlsVerified = response.socket.authorized === true;
        let size = 0; const parts = [];
        response.on('data', part => { size += part.length; if (size > 1024 * 1024) request.destroy(new Error('body_bound')); else parts.push(part); });
        response.on('end', () => { report.responseBytes = size; resolve(new Response(Buffer.concat(parts),
          { status: response.statusCode, headers: { 'content-type': response.headers['content-type'] ?? '' } })); });
        response.on('error', reject);
      });
      request.on('socket', socket => {
        socket.on('lookup', error => { report.dnsResolved = !error; });
        socket.on('connect', () => { report.tcpConnected = true; report.remoteFamily = socket.remoteFamily; });
        socket.on('secureConnect', () => { report.tlsConnected = true; report.tlsVerified = socket.authorized === true; });
      });
      request.on('finish', () => { report.requestWritten = true; });
      request.setTimeout(15000, () => request.destroy(Object.assign(new Error('read_timeout'), { safeCode: 'read_timeout' })));
      request.on('error', reject); request.end();
    });
  };
  const snapshot = await sdk.a(token, account, 18000, fetchOne);
  report.requestCount = count;
  report.sdkParsed = snapshot?.provider === 'openai' && Array.isArray(snapshot.windows) && !snapshot.error;
  report.usageWindowCount = Array.isArray(snapshot?.windows) ? snapshot.windows.length : 0;
  report.selectionSha256 = hash(bytes); report.sdkUsageModuleSha256 = expectedModuleSha;
  need(report.httpStatus === 200 && report.tlsVerified && report.sdkParsed, 'selected_account_provider_read_failed');
  need(hash(fs.readFileSync(selectionPath)) === hash(bytes) && hash(fs.readFileSync(sdkModule)) === expectedModuleSha, 'inputs_changed');
  report.actualDefaultSelectedAccountProviderValidated = true; report.ok = true;
} catch (error) {
  report.error = error?.safeCode ?? 'selected_account_read_failed';
  report.errorClass = error?.constructor?.name ?? 'unknown';
  if (typeof error?.code === 'string' && /^[A-Z_]{2,40}$/.test(error.code)) report.errorCode = error.code;
}
const fd = fs.openSync(resultPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
try { fs.writeFileSync(fd, JSON.stringify(report)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
process.stdout.write(JSON.stringify({ ok: report.ok, httpStatus: report.httpStatus ?? null, result: resultPath }) + '\n');
process.exitCode = report.ok ? 0 : 1;
