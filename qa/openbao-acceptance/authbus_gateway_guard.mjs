/** Private test process envelope for the unmodified installed OpenClaw gateway.
 * Permit only this test's AppRole/TLS endpoint and at most one provider POST.
 * Actual provider request/body/credentials must be chosen by the real gateway.
 * No refresh, redirection, external tool, retry or alternative account is sent.
 */
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import cp from 'node:child_process';
import dns from 'node:dns';
import { createHash } from 'node:crypto';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { zstdDecompressSync } from 'node:zlib';
import { pathToFileURL } from 'node:url';

process.umask(0o077);
const sha = b => createHash('sha256').update(b).digest('hex');
const plan = JSON.parse(fs.readFileSync(process.env.HEPTABAO_GATEWAY_PLAN, 'utf8'));
const selection = JSON.parse(fs.readFileSync(plan.selectionPath, 'utf8'));
const reportPath = path.join(plan.workRoot, `network-${process.pid}.public.json`);
const report = { schema: 'heptabao.isolated-real-gateway-network.v1', pid: process.pid,
  credentialValuesPublished: false, accountIdentitiesPublished: false,
  providerRequests: [], baoRequests: [], blocked: [], phase: plan.phase };
const flush = () => {
  const temp = reportPath + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(report), { mode: 0o600 }); fs.renameSync(temp, reportPath);
};
const deny = code => {
  const frames=String(new Error().stack).split('\n').slice(1,8)
    .map(line=>line.match(/([A-Za-z0-9_.-]+\.(?:js|mjs)):(\d+):(\d+)/)?.slice(1)??['native']);
  report.blocked.push({ code, at: Date.now(), sourceFrames:frames }); flush();
  throw Object.assign(new Error('Request was aborted'), { name: 'AbortError', safeCode: code });
};
const need = (v, code) => { if (!v) deny(code); };
need(process.env.OPENCLAW_STATE_DIR === plan.stateRoot, 'state_scope');
need(process.env.OPENCLAW_CONFIG_PATH === path.join(plan.stateRoot, 'openclaw.json'), 'config_scope');
need(process.env.OPENCLAW_SKIP_CHANNELS === '1' && process.env.OPENCLAW_SKIP_CRON === '1', 'background_scope');
const cfg = JSON.parse(fs.readFileSync(process.env.OPENCLAW_CONFIG_PATH));
need(cfg.agents.defaults.model.primary === plan.defaultModel && cfg.agents.defaults.model.fallbacks.length === 0,
  'default_model_scope');
need(cfg.tools.deny.includes('*') && cfg.cron.enabled === false && !Object.keys(cfg.channels).length
  && cfg.agents.defaults.heartbeat.every === '0s' && cfg.skills.workshop.autonomous.enabled === false,
  'no_tools_channels_or_autonomous_jobs');
for (const [file, pin] of Object.entries(plan.sourcePins)) need(sha(fs.readFileSync(file)) === pin, 'source_pin');
const target = new URL(plan.baoAddress);
const httpsRequest = https.request;
const execFileSync = cp.execFileSync;
const spawnSync = cp.spawnSync;
const ordinaryFetch = globalThis.fetch;
const tlsConnect = tls.connect;
const listen = net.Server.prototype.listen;
let providerInFlight = false;
let activeProviderRequest = null;
net.Server.prototype.listen = function(...args) {
  const options=typeof args[0]==='object'?args[0]:{port:args[0],host:args[1]};
  need(['127.0.0.1','::1','localhost'].includes(options.host)
    && [0,plan.gatewayPort].includes(Number(options.port)),'gateway_listener_scope');
  return listen.apply(this,args);
};
const baoAgent = new https.Agent({ keepAlive: false, maxCachedSessions: 0 });
dns.setDefaultResultOrder('ipv4first');
// The installed runtime resolves this same CJS export on every actual fetch.
// Observe that real entry point; do not inject a mock or replace its dispatcher.
const installedUndici = createRequire(pathToFileURL(path.join(plan.sdkRoot,'package.json')))('undici');
const runtimeFetch = installedUndici.fetch;

for (const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork']) cp[name] = () => deny('child_process');
cp.spawnSync = (file,args,options) => {
  const allowed = file === 'sysctl' && JSON.stringify(args) === '["-n","hw.model"]'
    || file === 'sw_vers' && JSON.stringify(args) === '["-productVersion"]';
  need(allowed && options?.encoding === 'utf-8' && Object.keys(options).length === 1,'child_process');
  const absolute=file==='sysctl'?'/usr/sbin/sysctl':'/usr/bin/sw_vers';
  const s=fs.lstatSync(absolute);need(s.isFile()&&s.uid===0&&(s.mode&0o022)===0,'system_presence_binary');
  return spawnSync(absolute,args,{encoding:'utf-8',timeout:3000,maxBuffer:4096,
    stdio:['ignore','pipe','pipe'],env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin'}});
};
cp.execFileSync = (file, args, options) => {
  if (file !== 'mount' || !Array.isArray(args) || args.length || options !== undefined) return deny('child_process');
  return execFileSync('/sbin/mount', [], { timeout: 3000, maxBuffer: 262144,
    stdio: ['ignore','pipe','pipe'], env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } });
};
http.request = () => deny('outbound_http'); http.get = http.request;
https.get = () => deny('outbound_https_get');
tls.connect = (...args) => {
  const options = args[0];
  need(options && typeof options === 'object', 'tls_connect_shape');
  const host = options.host || options.hostname;
  const isBao = host === '127.0.0.1' && String(options.port) === target.port;
  const isProvider = providerInFlight && String(options.port) === '443'
    && options.servername === 'chatgpt.com'
    && (host === 'chatgpt.com' || plan.providerAddresses.includes(host));
  need((isBao || isProvider) && options.rejectUnauthorized !== false, 'tls_connect_endpoint_or_trust');
  const socket=tlsConnect(...args);
  if(isProvider){
    socket.once('secureConnect',()=>{
      const item=activeProviderRequest;
      if(item){const cert=socket.getPeerCertificate?.();
        item.tlsVerified=socket.authorized===true;
        item.peerSha256=cert?.raw?sha(cert.raw):null;flush();}
    });
  }
  return socket;
};
https.request = (options, callback) => {
  need(options && typeof options === 'object' && !(options instanceof URL), 'https_shape');
  need((options.hostname || options.host) === '127.0.0.1'
    && String(options.port || 443) === target.port && options.rejectUnauthorized === true, 'bao_endpoint_trust');
  const p = options.path;
  need(options.method === 'POST' && p === '/v1/auth/approle/login'
    || options.method === 'GET' && p.startsWith('/v1/openclaw-auth/data/')
    || options.method === 'POST' && p.startsWith('/v1/openclaw-auth/data/inbox/gateway-profile2-canary/'),
    'bao_operation');
  const item = { method: options.method, route: p, at: Date.now() }; report.baoRequests.push(item); flush();
  return httpsRequest({ ...options, agent: baoAgent }, res => {
    item.status = res.statusCode; item.tlsVerified = res.socket.authorized === true;
    const cert = res.socket.getPeerCertificate?.(); item.peerSha256 = cert?.raw ? sha(cert.raw) : null;
    need(item.tlsVerified && item.peerSha256 === plan.baoCertificateSha256, 'bao_tls_pin');flush();callback(res);
  });
};
const observeProviderFetch = async (actualFetch,entryPoint,input, options = {}) => {
  const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
  need(url.href === plan.providerEndpoint && options.method === 'POST', 'only_actual_provider_post');
  need(plan.phase === 'candidate-initial' && fs.existsSync(path.join(plan.workRoot, 'provider-armed.private')), 'provider_not_armed');
  const headers = new Headers(options.headers);
  need(headers.get('authorization') === 'Bearer ' + selection.resolvedApiKey, 'actual_selected_access_mismatch');
  const accountHeader=headers.get('chatgpt-account-id');
  const accountObservation={at:Date.now(),headerPresent:accountHeader!==null,
    headerSha256:accountHeader!==null?sha(accountHeader):null,
    selectedAccountSha256:sha(selection.credential.accountId),
    selectedAccessMatched:true,headerNames:[...headers.keys()].sort()};
  (report.accountBindingObservations??=[]).push(accountObservation);flush();
  const accessJwt=JSON.parse(Buffer.from(selection.resolvedApiKey.split('.')[1],'base64url').toString('utf8'));
  need(accessJwt['https://api.openai.com/auth']?.chatgpt_account_id===selection.credential.accountId,
    'actual_access_jwt_account_mismatch');
  need(plan.accountBindingContract==='pinned-installed-openai-transport-bearer-jwt-v1'
    && plan.sourcePins[path.join(plan.sdkRoot,'dist/openai-transport-stream-B0WkSqXp.js')]
      ==='82712e39d2863f055210df3a33f4a725872bcbf3dfef1b7ba181dba882f60edc',
    'actual_account_binding_contract');
  need(accountHeader===null||accountHeader===selection.credential.accountId,'actual_selected_account_mismatch');
  let raw = typeof options.body === 'string' ? Buffer.from(options.body) : Buffer.from(options.body);
  if (headers.get('content-encoding') === 'zstd') raw = zstdDecompressSync(raw);
  need(raw.length <= 262144, 'provider_request_bound');
  const body = JSON.parse(raw.toString('utf8'));
  need(body.model === selection.model.id && body.store === false && body.stream === true, 'actual_default_model_body');
  need(!body.tools || body.tools.length === 0, 'provider_tools_disabled');
  const bodyString = raw.toString('utf8');
  need(bodyString.includes(plan.probeText), 'probe_missing');
  for (const secret of [selection.profileId, selection.credential.access, selection.credential.refresh,
    selection.credential.accountId, selection.credential.idToken].filter(x=>typeof x==='string' && x.length>7))
    need(!bodyString.includes(secret), 'sensitive_provider_body');
  const item = { at: Date.now(), method: 'POST', endpoint: plan.providerEndpoint,
    model: body.model, requestBytes: raw.length, requestBodySha256: sha(raw),
    actualDefaultModelMatched: true, actualSelectedCredentialMatched: true, actualAccountMatched: true,
    accountBinding:'exact-authorization-and-wire-jwt-account',accountHeaderPresent:accountHeader!==null,
    optionalAccountHeaderMatched:accountHeader===null?null:true,
    toolsCount: body.tools?.length ?? 0, requestCount: 1, responseBytes: 0, redirect: 'error',
    tlsVerificationDisabled: false, maxDurationMs: 45000, transport: 'sse', entryPoint,
    actualInstalledDispatcherPreserved: true };
  try {
    for(const ledger of [plan.providerLedgerPath,path.join(plan.workRoot,'provider-dispatch.private.json')]){
      const fd=fs.openSync(ledger,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
      fs.writeFileSync(fd,JSON.stringify({...item,workRoot:plan.workRoot}));fs.fsyncSync(fd);fs.closeSync(fd);
    }
  } catch { return deny('provider_request_budget_exhausted_no_replay'); }
  report.providerRequests.push(item);flush();
  const timeout = AbortSignal.timeout(45000);
  const envelopeAbort = new AbortController();
  const signal = AbortSignal.any([timeout,envelopeAbort.signal,...(options.signal?[options.signal]:[])]);
  try {
    providerInFlight=true;activeProviderRequest=item;
    const res=await actualFetch(input,{...options,redirect:'error',signal});
    item.status=res.status;item.responseHeadersReceived=true;flush();
    need(item.tlsVerified===true,'actual_provider_tls_verified');
    if(!res.body)return res;
    // Observe a clone while the installed provider consumes the original
    // Response object and byte stream. No response/header/body is substituted.
    const reader=res.clone().body.getReader();
    (async()=>{
      try{
        while(true){
          const part=await reader.read();
          if(part.done){item.complete=true;providerInFlight=false;flush();break;}
          item.responseBytes+=part.value.byteLength;flush();
          if(item.responseBytes>262144){item.responseBoundExceeded=true;flush();envelopeAbort.abort();await reader.cancel();break;}
        }
      }catch(error){item.streamErrorClass=error?.name??'Error';flush();}
    })();
    return res;
  }catch(error){providerInFlight=false;item.errorClass=error?.name??'Error';item.outcomeUnknown=true;flush();throw new DOMException('Request was aborted','AbortError');}
};
globalThis.fetch=(input,options)=>observeProviderFetch(ordinaryFetch,'global-fetch',input,options);
installedUndici.fetch=(input,options)=>observeProviderFetch(runtimeFetch,'actual-installed-undici',input,options);
syncBuiltinESMExports();
flush();
process.on('exit',flush);
