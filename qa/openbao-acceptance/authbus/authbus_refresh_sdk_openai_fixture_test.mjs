import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import tls from "node:tls";
import https from "node:https";
import { execFileSync } from "node:child_process";
import { ownOpenAiFixtureEnvironment, ownOpenAiFixtureTrust, createOwnedOpenAiConnectProxy } from "./authbus_refresh_sdk_openai_fixture.mjs";

process.umask(0o077);
const root = fs.mkdtempSync(path.join(os.tmpdir(), "heptabao-openai-proxy-unit-"));
const key = path.join(root, "server.key"), cert = path.join(root, "server.crt");
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
  "-days", "1", "-subj", "/CN=auth.openai.com", "-addext", "subjectAltName=DNS:auth.openai.com,IP:127.0.0.1"],
{ stdio: "ignore", timeout: 10000 });
const observations = { connections: 0, denials: 0, upstreamFailures: 0 };
const cell = { transport: "undici", undiciConnects: 0 };
const checks = []; let trust, proxy, server;
const environment = ownOpenAiFixtureEnvironment();
const check = (name, condition) => { assert.ok(condition, name); checks.push(name); };

async function tunnel(target = "auth.openai.com:443") {
  const socket = net.createConnection({ host: "127.0.0.1", port: proxy.port });
  socket.setTimeout(3000, () => socket.destroy(new Error("unit tunnel timeout")));
  return await new Promise((resolve, reject) => {
    let header = "";
    const onData = bytes => {
      header += bytes.toString("latin1");
      if (header.length > 8192) return socket.destroy(new Error("unit header too large"));
      if (!header.includes("\r\n\r\n")) return;
      socket.removeListener("data", onData); socket.removeListener("error", reject);
      resolve({ socket, status: Number(header.split(" ")[1]) });
    };
    socket.on("data", onData); socket.once("error", reject);
    socket.once("connect", () => socket.write("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"));
  });
}
async function roundTrip() {
  const { socket, status } = await tunnel(); assert.equal(status, 200);
  return await new Promise((resolve, reject) => {
    const secured = tls.connect({ socket, servername: "auth.openai.com" });
    let result = "";
    secured.setTimeout(3000, () => secured.destroy(new Error("unit TLS timeout")));
    secured.once("error", reject);
    secured.once("secureConnect", () => {
      assert.equal(secured.authorized, true);
      secured.write("POST /oauth/token HTTP/1.1\r\nHost: auth.openai.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    });
    secured.on("data", bytes => { result += bytes.toString("utf8"); if (result.length > 8192) secured.destroy(new Error("unit response too large")); });
    secured.once("end", () => resolve(result));
  });
}
try {
  let providerRequests = 0, lastServername;
  server = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, (request, response) => {
    providerRequests++; lastServername = request.socket.servername;
    assert.equal(request.url, "/oauth/token"); assert.equal(request.headers.host, "auth.openai.com");
    response.writeHead(204, { connection: "close" }); response.end();
  });
  server.on("tlsClientError", () => {});
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  proxy = await createOwnedOpenAiConnectProxy({ providerPort: server.address().port, activeCell: () => cell, observations });
  await assert.rejects(roundTrip(), error => ["DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN"].includes(error.code));
  check("untrusted_provider_certificate_is_rejected", providerRequests === 0);
  trust = ownOpenAiFixtureTrust(fs.readFileSync(cert));
  check("actual_tls_through_exact_loopback_connect", (await roundTrip()).startsWith("HTTP/1.1 204") && providerRequests === 1 && lastServername === "auth.openai.com");
  const before = observations.connections;
  const denied = await tunnel("unowned.invalid:443"); denied.socket.destroy();
  check("noncanonical_connect_target_rejected_without_upstream", denied.status === 403 && observations.connections === before && observations.denials === 1);
  cell.transport = "mapped-https";
  const wrongPhase = await tunnel(); wrongPhase.socket.destroy();
  check("connect_requires_an_active_undici_case", wrongPhase.status === 403 && observations.connections === before && observations.denials === 2);
  environment.useProxy(proxy.origin);
  check("proxy_environment_is_exact_loopback", process.env.HTTPS_PROXY === proxy.origin && process.env.OPENCLAW_PROXY_ACTIVE === "1" && process.env.HTTP_PROXY === undefined);
  environment.clearProxy();
  check("mock_lane_clears_owned_proxy_environment", process.env.HTTPS_PROXY === undefined && process.env.OPENCLAW_PROXY_ACTIVE === undefined);
  assert.throws(() => environment.useProxy("http://unowned.invalid:8080"), error => error.diagnosticCode === "openai_fixture_proxy_origin_invalid");
  check("nonlocal_proxy_configuration_rejected", process.env.HTTPS_PROXY === undefined);
  check("upstream_transports_have_no_unclassified_failure", observations.upstreamFailures === 0 && observations.connections === 2);
} finally {
  await proxy?.close();
  trust?.restore(); environment.restore();
  if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}
check("proxy_closes_all_owned_sockets", proxy.isClosed());
check("process_default_ca_restored", trust.isRestored());
check("process_environment_restored", environment.isRestored());
process.stdout.write(JSON.stringify({ schema: "authbus-openai-owned-proxy-unit", nodeVersion: process.version,
  actualSdkExecution: false, actualUndiciRefreshTransport: false, actualNativeHeptaBao: false, realExternalProvider: false,
  actualOwnedConnectAndTls: true, checksPassed: checks.length, checks, observations }, null, 2) + "\n");
