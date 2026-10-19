import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { createOwnedOpenAiConnectProxy, ownOpenAiFixtureTrust } from "./authbus_refresh_sdk_openai_fixture.mjs";

// This regression uses a supplied installed Undici package. It does not
// import an SDK, run OAuth, read credentials or qualify the 32 live cases.
const packageRoot = process.argv[2];
assert.ok(packageRoot && path.isAbsolute(packageRoot));
const localRequire = createRequire(path.join(packageRoot, "package.json"));
const undici = localRequire(packageRoot);
const packageBytes = fs.readFileSync(path.join(packageRoot, "package.json"));
const info = JSON.parse(packageBytes);
const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
assert.equal(info.name, "undici");
process.umask(0o077);
const root = fs.mkdtempSync(path.join(os.tmpdir(), "heptabao-undici-connect-r4-"));
const key = path.join(root, "server.key"), cert = path.join(root, "server.crt");
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
  "-days", "1", "-subj", "/CN=auth.openai.com", "-addext", "subjectAltName=DNS:auth.openai.com,IP:127.0.0.1"],
  { stdio: "ignore", timeout: 10000 });
const checks = [];
const check = (name, condition) => { assert.ok(condition, name); checks.push(name); };
const observations = { connections: 0, denials: 0, upstreamFailures: 0 };
const cell = { transport: "undici", undiciConnects: 0 };
let provider, proxy, trust;
let providerRequests = 0, verifiedRequestShape = 0;
try {
  provider = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, (request, response) => {
    providerRequests++;
    if (request.method === "GET" && request.url === "/oauth/token" && request.headers.host === "auth.openai.com" &&
        request.socket.servername === "auth.openai.com" && request.socket.localAddress === "127.0.0.1") verifiedRequestShape++;
    response.writeHead(204, { connection: "close" }); response.end();
  });
  provider.on("tlsClientError", () => {});
  await new Promise((resolve, reject) => { provider.once("error", reject); provider.listen(0, "127.0.0.1", resolve); });
  proxy = await createOwnedOpenAiConnectProxy({ providerPort: provider.address().port, activeCell: () => cell, observations });
  trust = ownOpenAiFixtureTrust(fs.readFileSync(cert));
  for (const kind of ["ProxyAgent", "EnvHttpProxyAgent"]) {
    const options = { allowH2: false, clientFactory: (origin, opts) => new undici.Pool(origin, opts) };
    const dispatcher = kind === "ProxyAgent" ? new undici.ProxyAgent({ ...options, uri: proxy.origin }) :
      new undici.EnvHttpProxyAgent({ ...options, httpsProxy: proxy.origin, httpProxy: proxy.origin, noProxy: "" });
    const before = providerRequests;
    try {
      const response = await undici.fetch("https://auth.openai.com/oauth/token", {
        method: "GET", dispatcher, signal: AbortSignal.timeout(5000), redirect: "error" });
      check(kind + ":actual_dispatch_verified_tls_exact_authority", response.status === 204 &&
        providerRequests === before + 1 && verifiedRequestShape === providerRequests);
    } finally { await dispatcher.destroy(); }
  }
  check("both_actual_library_dispatchers_used_only_owned_connect", providerRequests === 2 &&
    verifiedRequestShape === 2 && cell.undiciConnects === 2 && observations.connections === 2 &&
    observations.denials === 0 && observations.upstreamFailures === 0);
} finally {
  await proxy?.close(); trust?.restore();
  if (provider) { provider.closeAllConnections(); await new Promise(resolve => provider.close(resolve)); }
}
const cleanup = { ownedProxyClosed: proxy.isClosed(), processCaRestored: trust.isRestored() };
if (!cleanup.ownedProxyClosed || !cleanup.processCaRestored) process.stderr.write(JSON.stringify({ cleanup }) + "\n");
check("owned_proxy_sockets_and_process_ca_closed_restored", cleanup.ownedProxyClosed && cleanup.processCaRestored);
check("library_package_metadata_unchanged", hash(fs.readFileSync(path.join(packageRoot, "package.json"))) === hash(packageBytes));
process.stdout.write(JSON.stringify({ schema: "heptabao.authbus-openai-undici-connect-regression.v1",
  actualSdkExecution: false, actualNativeHeptaBao: false, actualOAuthRefresh: false, realExternalProvider: false,
  actualInstalledUndiciDispatch: true, actualOwnedConnectAndTls: true, credentialInput: false,
  library: { name: info.name, version: info.version, packageSha256: hash(packageBytes) },
  nodeVersion: process.version, checksPassed: checks.length, checks, observations }, null, 2) + "\n");
