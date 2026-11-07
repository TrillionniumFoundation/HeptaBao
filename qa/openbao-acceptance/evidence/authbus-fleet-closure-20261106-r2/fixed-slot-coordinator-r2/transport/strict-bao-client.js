/** One-dispatch OpenBao client for the fixed-slot AuthBus production adapter.
 *
 * Every HTTP request receives an already CA/hostname/leaf-pin verified socket.
 * Durable authentication intents precede https.request(), and an uncertain
 * authentication attempt is never retried or replaced with a fresh login.
 * The SQLite adapter owns private storage and synchronous revision CAS.
 */
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import https from 'node:https';
import net from 'node:net';
import { createHash, timingSafeEqual } from 'node:crypto';
import { performance } from 'node:perf_hooks';

const SCHEMA = 'heptabao.authbus-bearer-state.v1';
const LIMIT = 2 * 1024 * 1024;
const REQUEST_MS = 15_000;
const CAS_ERROR = 'check-and-set parameter did not match the current version';
const PHASES = new Set(['login-dispatched', 'active', 'renew-dispatched', 'revoke-dispatched', 'revoked']);
const MUTATIONS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export class BaoError extends Error {
  constructor(code, { status = null, conflict = false, unknown = false } = {}) {
    super(code);
    this.name = 'BaoError';
    this.code = code;
    this.status = Number.isInteger(status) ? status : null;
    this.conflict = conflict === true;
    this.unknown = unknown === true;
  }
  toJSON() { return { code: this.code, status: this.status, conflict: this.conflict, unknown: this.unknown }; }
}

export class Conflict extends BaoError {
  constructor(status = 400) { super('cas_conflict', { status, conflict: true }); this.name = 'Conflict'; }
}

export class UnknownOutcome extends BaoError {
  constructor(code = 'mutation_outcome_unknown', status = null) {
    super(code, { status, unknown: true }); this.name = 'UnknownOutcome';
  }
}

function requireValue(condition, code) { if (!condition) throw new BaoError(code); }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function uint(value) { return Number.isSafeInteger(value) && value >= 0; }
function hash(value) { return createHash('sha256').update(value).digest('hex'); }
function fixed(info) {
  return ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].map(key => info[key]);
}
function sameStat(left, right) { return fixed(left).every((value, index) => value === fixed(right)[index]); }

function readBoundFile(filename, { secret = false, maximum = 1024 * 1024 } = {}) {
  requireValue(typeof filename === 'string' && path.isAbsolute(filename), 'absolute_input_file_required');
  let fd;
  try {
    requireValue(fs.realpathSync(filename) === filename, 'input_file_alias_refused');
    const parentPath = path.dirname(filename);
    const parent = fs.lstatSync(parentPath, { bigint: true });
    const uid = BigInt(process.geteuid());
    requireValue(parent.isDirectory() && (parent.mode & 0o022n) === 0n, 'input_parent_custody');
    if (secret) requireValue(parent.uid === uid && (parent.mode & 0o777n) === 0o700n, 'credential_parent_custody');
    fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const before = fs.fstatSync(fd, { bigint: true });
    requireValue(before.isFile() && before.nlink === 1n && before.size > 0n && before.size <= BigInt(maximum), 'input_file_custody');
    if (secret) {
      requireValue(before.uid === uid && (before.mode & 0o777n) === 0o600n, 'credential_file_custody');
    } else {
      requireValue((before.uid === uid || before.uid === 0n) && (before.mode & 0o022n) === 0n, 'trust_file_custody');
    }
    const buffer = Buffer.alloc(maximum + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = fs.readSync(fd, buffer, length, buffer.length - length, null);
      if (count === 0) break;
      length += count;
    }
    requireValue(length <= maximum && BigInt(length) === before.size
      && sameStat(before, fs.fstatSync(fd, { bigint: true }))
      && sameStat(before, fs.lstatSync(filename, { bigint: true }))
      && sameStat(parent, fs.lstatSync(parentPath, { bigint: true })), 'input_file_changed');
    return buffer.subarray(0, length);
  } catch (error) {
    if (error instanceof BaoError) throw error;
    throw new BaoError('input_file_read_failed');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function credential(raw) {
  requireValue(Buffer.isBuffer(raw) && raw.length <= 32768 && raw.every(byte => byte < 128), 'credential_format');
  const value = raw.toString('ascii').trim();
  requireValue(/^[A-Za-z0-9._~+/=:-]{8,32768}$/.test(value), 'credential_format');
  return value;
}

function tokenValue(value) {
  requireValue(typeof value === 'string' && /^[\x21-\x7e]{8,32768}$/.test(value), 'bearer_format');
  return value;
}

function budget(options = {}) {
  requireValue(object(options), 'request_options_shape');
  const wall = Date.now();
  let milliseconds = REQUEST_MS;
  if (options.deadlineMs !== undefined) {
    requireValue(Number.isSafeInteger(options.deadlineMs), 'absolute_deadline_shape');
    milliseconds = Math.min(milliseconds, options.deadlineMs - wall);
  }
  requireValue(milliseconds > 0, 'request_deadline_expired');
  return { wallStart: wall, wallEnd: wall + milliseconds, monoEnd: performance.now() + milliseconds };
}

function remaining(bound) {
  const now = Date.now();
  requireValue(now >= bound.wallStart, 'wall_clock_moved_backwards');
  const milliseconds = Math.min(bound.monoEnd - performance.now(), bound.wallEnd - now);
  requireValue(milliseconds > 0, 'request_deadline_expired');
  return milliseconds;
}

function routeValue(route) {
  requireValue(typeof route === 'string' && route.startsWith('/v1/') && route.length <= 8192
    && !/[\x00-\x20\x7f#]/.test(route), 'request_route_shape');
  let decoded;
  try { decoded = decodeURIComponent(route.split('?')[0]); } catch { throw new BaoError('request_route_encoding'); }
  requireValue(!decoded.split('/').some(part => part === '.' || part === '..'), 'request_route_traversal');
  return decoded;
}

function unresolved(value) {
  if (value?.phase.endsWith('-dispatched')) {
    if (value.outcome === 'rejected' && Number.isInteger(value.knownResponseStatus))
      throw new BaoError('authentication_intent_rejected', { status: value.knownResponseStatus });
    throw new UnknownOutcome('authentication_intent_unresolved');
  }
}

export class StrictBaoClient {
  #store;
  #origin;
  #host;
  #port;
  #ca;
  #pin;
  #role;
  #secret;
  #binding;
  #mount;
  #token;
  #tail = Promise.resolve();
  #closed = false;
  #leaseKey;
  #leaseMonoEnd;

  constructor(config, authStore) {
    requireValue(object(config) && object(authStore)
      && typeof authStore.loadAuth === 'function' && typeof authStore.saveAuth === 'function', 'client_configuration_shape');
    let origin;
    try { origin = new URL(config.address); } catch { throw new BaoError('https_origin_required'); }
    requireValue(origin.protocol === 'https:' && !origin.username && !origin.password
      && !origin.search && !origin.hash && (origin.pathname === '/' || origin.pathname === ''), 'https_origin_required');
    requireValue(typeof config.serverCertificateSha256 === 'string' && /^[0-9a-f]{64}$/.test(config.serverCertificateSha256), 'exact_leaf_pin_required');
    const mount = config.kvMount ?? 'openclaw-auth';
    requireValue(typeof mount === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(mount), 'kv_mount_shape');
    const ca = readBoundFile(config.caFile);
    const role = readBoundFile(config.roleIdFile, { secret: true, maximum: 32768 });
    const secret = readBoundFile(config.secretIdFile, { secret: true, maximum: 32768 });
    try {
      this.#role = credential(role);
      this.#secret = credential(secret);
      this.#binding = hash(JSON.stringify({ address: origin.origin, caSha256: hash(ca),
        serverCertificateSha256: config.serverCertificateSha256, roleIdSha256: hash(role), secretIdSha256: hash(secret),
        roleIdFile: config.roleIdFile, secretIdFile: config.secretIdFile, kvMount: mount }));
    } finally {
      role.fill(0); secret.fill(0);
    }
    this.#store = authStore;
    this.#origin = origin.origin;
    this.#host = origin.hostname.replace(/^\[|\]$/g, '');
    this.#port = Number(origin.port || 443);
    this.#ca = ca;
    this.#pin = Buffer.from(config.serverCertificateSha256, 'hex');
    this.#mount = mount;
  }

  get token() { return this.#token; }
  get bindingSha256() { return this.#binding; }
  toJSON() { return { type: 'StrictBaoClient', address: this.#origin, credentialsPublished: false }; }

  #serial(task) {
    const run = this.#tail.then(() => { requireValue(!this.#closed, 'client_closed'); return task(); });
    this.#tail = run.catch(() => {});
    return run;
  }

  #load() {
    let state;
    try { state = this.#store.loadAuth(); } catch { throw new BaoError('auth_store_read_failed'); }
    requireValue(object(state) && uint(state.revision) && (state.value === null || object(state.value)), 'auth_store_contract');
    if (state.value !== null) {
      const value = state.value;
      requireValue(value.schema === SCHEMA && value.bindingSha256 === this.#binding && PHASES.has(value.phase), 'auth_state_binding_or_schema');
      requireValue(uint(value.lastObservedAtUnixMs) && Date.now() >= value.lastObservedAtUnixMs, 'wall_clock_moved_backwards');
    }
    return state;
  }

  #save(revision, value) {
    let updated;
    try { updated = this.#store.saveAuth(revision, value); } catch { throw new BaoError('auth_state_cas_conflict'); }
    requireValue(uint(updated) && updated > revision, 'auth_store_revision_contract');
    return { revision: updated, value };
  }

  #activeValue(state) {
    unresolved(state.value);
    requireValue(state.value?.phase === 'active', 'authentication_not_active');
    const value = state.value;
    tokenValue(value.token);
    requireValue(uint(value.issuedAtUnixMs) && uint(value.leaseSeconds) && value.leaseSeconds > 0
      && uint(value.expiresAtUnixMs) && Number.isSafeInteger(value.leaseSeconds * 1000)
      && value.expiresAtUnixMs === value.issuedAtUnixMs + value.leaseSeconds * 1000
      && value.lastObservedAtUnixMs >= value.issuedAtUnixMs && Date.now() >= value.issuedAtUnixMs,
    'active_lease_shape');
    return value;
  }

  #active(bound) {
    const state = this.#load();
    const value = this.#activeValue(state);
    const wall = Date.now();
    requireValue(wall >= value.lastObservedAtUnixMs, 'wall_clock_moved_backwards');
    const left = value.expiresAtUnixMs - wall;
    requireValue(left > 0, 'active_bearer_expired');
    const key = `${hash(value.token)}:${value.issuedAtUnixMs}:${value.expiresAtUnixMs}`;
    const monoEnd = performance.now() + Math.min(left, value.leaseSeconds * 1000);
    this.#leaseMonoEnd = this.#leaseKey === key ? Math.min(this.#leaseMonoEnd, monoEnd) : monoEnd;
    this.#leaseKey = key;
    requireValue(this.#leaseMonoEnd > performance.now(), 'active_bearer_expired');
    bound.monoEnd = Math.min(bound.monoEnd, this.#leaseMonoEnd);
    bound.wallEnd = Math.min(bound.wallEnd, value.expiresAtUnixMs);
    remaining(bound);
    // Store the observed wall-clock high-water mark before using this bearer.
    // A revision conflict dispatches no request and is not retried here.
    const saved = this.#save(state.revision, { ...value, lastObservedAtUnixMs: wall });
    this.#token = value.token;
    return saved;
  }

  async #ensureActive(bound) {
    const state = this.#load();
    if (state.value === null || state.value.phase === 'revoked'
      || (state.value.phase === 'active' && Date.now() >= this.#activeValue(state).expiresAtUnixMs))
      await this.#login(bound);
    return this.#active(bound);
  }

  #intent(state, phase, wall) {
    const prior = state.value ?? {};
    const now = Date.now();
    requireValue(now >= wall && now >= (prior.lastObservedAtUnixMs ?? wall), 'wall_clock_moved_backwards');
    const value = { ...prior, schema: SCHEMA, bindingSha256: this.#binding, phase,
      lastObservedAtUnixMs: now, intentStartedAtUnixMs: wall };
    delete value.outcome; delete value.knownResponseStatus;
    if (phase === 'login-dispatched') delete value.token;
    this.#token = undefined;
    return this.#save(state.revision, value);
  }

  #lease(auth, startWall, priorToken = undefined) {
    requireValue(object(auth), 'authentication_response_shape');
    const token = tokenValue(auth.client_token);
    requireValue(priorToken === undefined || token === priorToken, 'renewal_changed_bearer');
    requireValue(uint(auth.lease_duration) && auth.lease_duration > 0
      && Number.isSafeInteger(auth.lease_duration * 1000)
      && Number.isSafeInteger(startWall + auth.lease_duration * 1000)
      && typeof auth.renewable === 'boolean', 'authentication_lease_shape');
    const now = Date.now();
    requireValue(now >= startWall && startWall + auth.lease_duration * 1000 > now, 'authentication_lease_expired');
    return { schema: SCHEMA, bindingSha256: this.#binding, phase: 'active', token,
      issuedAtUnixMs: startWall, leaseSeconds: auth.lease_duration,
      expiresAtUnixMs: startWall + auth.lease_duration * 1000, lastObservedAtUnixMs: now,
      renewable: auth.renewable };
  }

  #wire(method, route, body, token, bound, beforeDispatch = undefined) {
    routeValue(route);
    requireValue(['GET', 'HEAD', 'LIST', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method), 'request_method_shape');
    if (token !== null && token !== undefined) tokenValue(token);
    let payload;
    try { payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), 'utf8'); }
    catch { throw new BaoError('request_json_shape'); }
    requireValue(payload === undefined || payload.length <= LIMIT, 'request_body_limit');
    const mutation = MUTATIONS.has(method);
    const timeout = remaining(bound);
    return new Promise((resolve, reject) => {
      let socket, request, response, timer, done = false, dispatched = false;
      const finish = (error, value) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        response?.destroy(); request?.destroy(); socket?.destroy();
        if (error) reject(error); else resolve(value);
      };
      const fail = (code, status = null) => finish(mutation && dispatched
        ? new UnknownOutcome(code, status) : new BaoError(code, { status }));
      timer = setTimeout(() => fail('request_deadline_expired'), Math.max(1, Math.ceil(timeout)));
      try {
        socket = tls.connect({ host: this.#host, port: this.#port,
          servername: net.isIP(this.#host) ? undefined : this.#host,
          ca: this.#ca, rejectUnauthorized: true, minVersion: 'TLSv1.2', ALPNProtocols: ['http/1.1'] });
        socket.on('error', () => fail('tls_or_transport_failed'));
        socket.once('secureConnect', () => {
          try {
            remaining(bound);
            requireValue(socket.authorized === true && ['TLSv1.2', 'TLSv1.3'].includes(socket.getProtocol()), 'tls_verification_failed');
            const peer = socket.getPeerCertificate(true);
            requireValue(tls.checkServerIdentity(this.#host, peer) === undefined && Buffer.isBuffer(peer.raw), 'tls_hostname_verification_failed');
            const actual = createHash('sha256').update(peer.raw).digest();
            requireValue(actual.length === this.#pin.length && timingSafeEqual(actual, this.#pin), 'tls_leaf_pin_mismatch');
            // No authentication header or HTTP body has been given to an HTTP
            // object yet. The synchronous durable intent CAS happens here.
            if (beforeDispatch) beforeDispatch();
            remaining(bound);
            const headers = { Accept: 'application/json', Connection: 'close' };
            if (token !== null && token !== undefined) headers['X-Vault-Token'] = token;
            if (payload !== undefined) {
              headers['Content-Type'] = 'application/json'; headers['Content-Length'] = String(payload.length);
            }
            let handedOff = false;
            dispatched = true; // Conservative: constructor failure cannot license a replay.
            request = https.request({ protocol: 'https:', hostname: this.#host, port: this.#port,
              method, path: route, headers, agent: null, maxHeaderSize: 16 * 1024,
              createConnection: () => {
                requireValue(!handedOff && !socket.destroyed, 'verified_socket_reuse_refused');
                handedOff = true; return socket;
              } }, incoming => {
                response = incoming;
                const status = incoming.statusCode;
                if (!Number.isInteger(status)) { fail('response_status_shape'); return; }
                if (status >= 300 && status < 400) { fail('redirect_refused', status); return; }
                let size = 0;
                const chunks = [];
                incoming.on('data', chunk => {
                  size += chunk.length;
                  if (size > LIMIT) { fail('response_body_limit', status); return; }
                  chunks.push(chunk);
                });
                incoming.on('aborted', () => fail('response_incomplete', status));
                incoming.on('error', () => fail('response_incomplete', status));
                incoming.on('end', () => {
                  if (done) return;
                  try {
                    remaining(bound);
                    requireValue(incoming.complete === true, 'response_incomplete');
                    const raw = Buffer.concat(chunks, size);
                    const decoded = raw.length === 0 ? null : JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
                    requireValue(decoded === null || object(decoded), 'response_json_object_required');
                    finish(null, { status, body: decoded });
                  } catch { fail('response_invalid_or_late', status); }
                });
              });
            request.on('error', () => fail('http_transport_failed'));
            request.on('socket', assigned => {
              if (assigned !== socket) fail('verified_socket_binding_changed');
            });
            request.end(payload);
          } catch (error) {
            if (!dispatched && error instanceof BaoError) finish(error);
            else fail('request_dispatch_failed');
          }
        });
      } catch { fail('tls_connection_failed'); }
    });
  }

  #http(result, mutation) {
    if (result.status >= 200 && result.status < 300) return result.body;
    if (result.status === 404 && !mutation) return null;
    if (mutation && result.status >= 500) throw new UnknownOutcome('mutation_server_outcome_unknown', result.status);
    throw new BaoError('http_request_rejected', { status: result.status });
  }

  #authHttp(result, intent) {
    if (result.status >= 400 && result.status < 500) {
      // A returned HTTP denial is known. Keep the attempt non-replayable while
      // preserving that distinction across restart instead of relabelling it
      // as a transport-unknown login/renewal/revocation.
      try {
        this.#save(intent.revision, { ...intent.value, outcome: 'rejected',
          knownResponseStatus: result.status, lastObservedAtUnixMs: Date.now() });
      } catch { throw new BaoError('authentication_denial_state_update_failed', { status: result.status }); }
    }
    return this.#http(result, true);
  }

  async #login(bound) {
    const state = this.#load();
    unresolved(state.value);
    if (state.value?.phase === 'active') {
      const value = this.#activeValue(state);
      if (Date.now() < value.expiresAtUnixMs) return this.#active(bound).value;
      // A fully validated, expired active lease is a known terminal lifetime,
      // not an unresolved authentication attempt. Preserve it until the new
      // AppRole request has a verified TLS socket and a durable login intent.
    } else {
      requireValue(state.value === null || state.value.phase === 'revoked', 'login_not_admitted');
    }
    let intent;
    const startWall = Date.now();
    const result = await this.#wire('POST', '/v1/auth/approle/login', { role_id: this.#role, secret_id: this.#secret },
      null, bound, () => { intent = this.#intent(state, 'login-dispatched', startWall); });
    const body = this.#authHttp(result, intent);
    try {
      requireValue(result.status === 200, 'login_response_status');
      const active = this.#lease(body?.auth, startWall);
      this.#save(intent.revision, active);
      this.#token = active.token;
      return active;
    } catch { throw new UnknownOutcome('authentication_acknowledgment_uncommitted', result.status); }
  }

  login(options = {}) {
    const bound = budget(options);
    return this.#serial(async () => {
      const active = await this.#login(bound);
      return { leaseSeconds: active.leaseSeconds, expiresAtUnixMs: active.expiresAtUnixMs, renewable: active.renewable };
    });
  }

  request(method, route, body = undefined, token = undefined, options = {}) {
    const bound = budget(options);
    return this.#serial(async () => {
      const decoded = routeValue(route);
      requireValue(!MUTATIONS.has(method) || !/^\/v1\/auth\/.*\/(?:login|renew-self|revoke-self)$/.test(decoded), 'use_durable_auth_lifecycle_method');
      let bearer = token;
      if (bearer === undefined) bearer = (await this.#ensureActive(bound)).value.token;
      else if (bearer !== null) {
        const active = this.#active(bound);
        requireValue(bearer === active.value.token, 'explicit_bearer_not_current');
      }
      return this.#http(await this.#wire(method, route, body, bearer, bound), MUTATIONS.has(method));
    });
  }

  #key(key) {
    requireValue(typeof key === 'string' && key.length > 0 && key.length <= 4096
      && !/[\x00-\x1f\x7f]/.test(key)
      && key.split('/').every(part => part.length > 0 && part !== '.' && part !== '..'), 'secret_key_shape');
    try { return key.split('/').map(part => encodeURIComponent(part)).join('/'); }
    catch { throw new BaoError('secret_key_encoding'); }
  }

  readSecret(key, options = {}) {
    const bound = budget(options);
    const route = `/v1/${this.#mount}/data/${this.#key(key)}`;
    return this.#serial(async () => {
      const active = await this.#ensureActive(bound);
      const result = await this.#wire('GET', route, undefined, active.value.token, bound);
      const body = this.#http(result, false);
      if (body === null && result.status === 404) return null;
      requireValue(result.status === 200 && object(body?.data?.data)
        && uint(body?.data?.metadata?.version) && body.data.metadata.version > 0, 'kv_read_response_shape');
      return { data: body.data.data, version: body.data.metadata.version };
    });
  }

  writeSecret(key, data, cas, options = {}) {
    const bound = budget(options);
    const route = `/v1/${this.#mount}/data/${this.#key(key)}`;
    requireValue(object(data) && uint(cas) && cas < Number.MAX_SAFE_INTEGER, 'kv_write_input_shape');
    return this.#serial(async () => {
      const active = await this.#ensureActive(bound);
      const result = await this.#wire('POST', route, { data, options: { cas } }, active.value.token, bound);
      if (result.status === 400 && Array.isArray(result.body?.errors) && result.body.errors.length === 1
          && result.body.errors[0] === CAS_ERROR) throw new Conflict();
      const body = this.#http(result, true);
      if (result.status !== 200 || !uint(body?.data?.version) || body.data.version !== cas + 1)
        throw new UnknownOutcome('kv_write_acknowledgment_invalid', result.status);
      return body.data.version;
    });
  }

  renew(options = {}) {
    const bound = budget(options);
    return this.#serial(async () => {
      const active = this.#active(bound);
      requireValue(active.value.renewable === true, 'bearer_not_renewable');
      let intent;
      const token = active.value.token;
      const startWall = Date.now();
      const result = await this.#wire('POST', '/v1/auth/token/renew-self', {}, token, bound,
        () => { intent = this.#intent(active, 'renew-dispatched', startWall); });
      const body = this.#authHttp(result, intent);
      try {
        requireValue(result.status === 200, 'renew_response_status');
        const next = this.#lease(body?.auth, startWall, token);
        this.#save(intent.revision, next);
        this.#token = token;
        return { leaseSeconds: next.leaseSeconds, expiresAtUnixMs: next.expiresAtUnixMs, renewable: next.renewable };
      } catch { throw new UnknownOutcome('renewal_acknowledgment_uncommitted', result.status); }
    });
  }

  close({ revoke = false, deadlineMs } = {}) {
    const bound = budget(deadlineMs === undefined ? {} : { deadlineMs });
    return this.#serial(async () => {
      if (!revoke) { this.#closed = true; this.#token = undefined; return { closed: true, revoked: false }; }
      const active = this.#active(bound);
      let intent;
      const token = active.value.token;
      const startWall = Date.now();
      const response = await this.#wire('POST', '/v1/auth/token/revoke-self', {}, token, bound,
        () => { intent = this.#intent(active, 'revoke-dispatched', startWall); });
      this.#authHttp(response, intent);
      if (response.status !== 204) throw new UnknownOutcome('revocation_acknowledgment_invalid', response.status);
      // This is the original bearer, not a newly authenticated replacement.
      const proof = await this.#wire('GET', '/v1/auth/token/lookup-self', undefined, token, bound);
      if (proof.status !== 403) throw new UnknownOutcome('revocation_not_confirmed', proof.status);
      try {
        this.#save(intent.revision, { schema: SCHEMA, bindingSha256: this.#binding, phase: 'revoked',
          lastObservedAtUnixMs: Date.now(), revokedAtUnixMs: Date.now() });
      } catch { throw new UnknownOutcome('revocation_acknowledgment_uncommitted', 403); }
      this.#token = undefined; this.#closed = true;
      return { closed: true, revoked: true, originalBearerLookupStatus: 403 };
    });
  }
}

export default StrictBaoClient;
