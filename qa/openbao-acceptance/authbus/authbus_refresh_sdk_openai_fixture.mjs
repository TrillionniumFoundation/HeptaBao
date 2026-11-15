/** Owned loopback CONNECT transport and process-local TLS/env custody.
 * No OAuth authority, provider result, DNS override or SDK replacement lives
 * here. The real SDK retains its URL, TLS verification and Undici fetch.
 */
import crypto from "node:crypto";
import http from "node:http";
import net from "node:net";
import tls from "node:tls";

const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
const hash = value => crypto.createHash("sha256").update(value).digest("hex");
const caSetDigest = certificates => hash(JSON.stringify([...new Set(certificates.map(cert =>
  hash(new crypto.X509Certificate(cert).raw)))].sort()));
const ENV_KEYS = Object.freeze(["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
  "http_proxy", "https_proxy", "all_proxy", "no_proxy", "OPENCLAW_PROXY_ACTIVE",
  "OPENCLAW_PROXY_CA_FILE", "OPENCLAW_PROXY_LOOPBACK_MODE", "OPENCLAW_DEBUG_PROXY_ENABLED", "NODE_USE_ENV_PROXY", "VITEST"]);

export function ownOpenAiFixtureEnvironment() {
  const previous = new Map(ENV_KEYS.map(key => [key, process.env[key]]));
  for (const key of ENV_KEYS) delete process.env[key];
  let restored = false;
  return Object.freeze({
    clearProxy() { for (const key of ENV_KEYS) delete process.env[key]; },
    useProxy(origin) {
      if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]*$/.test(origin)) fail("openai_fixture_proxy_origin_invalid");
      for (const key of ENV_KEYS) delete process.env[key];
      // This is the actual SDK's inherited managed proxy route. The proxy is
      // an owned exact-target CONNECT listener, not a test runtime override.
      process.env.HTTPS_PROXY = origin;
      process.env.OPENCLAW_PROXY_ACTIVE = "1";
    },
    restore() {
      if (restored) return;
      for (const [key, value] of previous) {
        if (value === undefined) delete process.env[key]; else process.env[key] = value;
      }
      restored = true;
    },
    isRestored() { return restored && [...previous].every(([key, value]) => process.env[key] === value); },
  });
}

export function ownOpenAiFixtureTrust(certificate) {
  if (typeof tls.getCACertificates !== "function" || typeof tls.setDefaultCACertificates !== "function")
    fail("openai_fixture_process_local_ca_api_unavailable");
  if (!Buffer.isBuffer(certificate) || certificate.length < 1 || certificate.length > 65536)
    fail("openai_fixture_ca_size_invalid");
  const previous = tls.getCACertificates("default");
  // Node canonicalizes/deduplicates the certificate list on set. Trust is the
  // exact set of DER certificates, not PEM whitespace, array order or copies.
  const before = caSetDigest(previous);
  const cert = certificate.toString("utf8");
  tls.setDefaultCACertificates([...previous, cert]);
  const active = tls.getCACertificates("default");
  if (!active.includes(cert)) { tls.setDefaultCACertificates(previous); fail("openai_fixture_ca_not_installed"); }
  let restored = false;
  return Object.freeze({
    certificateSha256: hash(certificate),
    restorationComparison: "exact-DER-certificate-set",
    restore() { if (!restored) { tls.setDefaultCACertificates(previous); restored = true; } },
    isRestored() { return restored && caSetDigest(tls.getCACertificates("default")) === before; },
  });
}

export async function createOwnedOpenAiConnectProxy({ providerPort, activeCell, observations }) {
  if (!Number.isInteger(providerPort) || providerPort < 1 || providerPort > 65535 || typeof activeCell !== "function")
    fail("openai_fixture_proxy_binding_invalid");
  const connections = new Set();
  const track = socket => { connections.add(socket); socket.on("close", () => connections.delete(socket)); return socket; };
  const reject = socket => { observations.denials++; socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); };
  const server = http.createServer((_request, response) => {
    observations.denials++;
    response.writeHead(405, { connection: "close", "content-length": "0" }); response.end();
  });
  server.on("connection", track);
  server.on("clientError", (_error, socket) => { observations.denials++; socket.destroy(); });
  server.on("connect", (request, socket, head) => {
    const cell = activeCell();
    // Actual Undici 8.5 sends the default :443 in the CONNECT request target
    // while retaining the URL's portless host in the Host field. Accept only
    // those two spellings of the same fixed TLS authority. Count raw fields
    // because Node otherwise discards duplicate Host fields before this check.
    let hostFields = 0;
    for (let index = 0; index < request.rawHeaders.length; index += 2)
      if (request.rawHeaders[index].toLowerCase() === "host") hostFields++;
    const exactHost = request.headers.host === "auth.openai.com" || request.headers.host === "auth.openai.com:443";
    if (!cell || cell.transport !== "undici" || request.method !== "CONNECT" || request.url !== "auth.openai.com:443" ||
        !exactHost || hostFields !== 1 || request.headers["transfer-encoding"] !== undefined ||
        request.headers["content-length"] !== undefined || head.length > 65536)
      return reject(socket);
    observations.connections++;
    cell.undiciConnects = (cell.undiciConnects ?? 0) + 1;
    // The only upstream address is construction-time loopback + the owned
    // provider port. CONNECT never selects an arbitrary destination or DNS.
    const upstream = track(net.createConnection({ host: "127.0.0.1", port: providerPort }));
    let established = false;
    const close = () => { upstream.destroy(); socket.destroy(); };
    socket.setTimeout(30000, close); upstream.setTimeout(30000, close);
    socket.once("error", close); upstream.once("error", () => {
      if (!established) observations.upstreamFailures++;
      close();
    });
    socket.once("close", () => upstream.destroy()); upstream.once("close", () => socket.destroy());
    upstream.once("connect", () => {
      established = true;
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      socket.pipe(upstream); upstream.pipe(socket);
    });
  });
  await new Promise((resolve, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", () => { server.removeListener("error", rejectListen); resolve(); });
  });
  let closed = false;
  return Object.freeze({
    port: server.address().port,
    origin: "http://127.0.0.1:" + server.address().port,
    async close() {
      if (closed) return;
      closed = true;
      // Membership lasts until our close listener runs. Node may already set
      // socket.closed before emitting that event, so it cannot qualify the
      // tracked socket as retired; await the actual event for every member.
      const retired = [...connections].map(socket => new Promise(resolve => socket.once("close", resolve)));
      for (const socket of connections) socket.destroy();
      await Promise.all([...retired, new Promise((resolve, rejectClose) => server.close(error => error ? rejectClose(error) : resolve()))]);
    },
    isClosed() { return closed && !server.listening && connections.size === 0; },
  });
}
