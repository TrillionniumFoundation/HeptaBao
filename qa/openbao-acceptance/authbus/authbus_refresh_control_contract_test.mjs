#!/usr/bin/env node
/** R5 process/HTTP regression. Real HTTPS and process death; TLS KV2 emulator,
 * JSON fixture credential owner, NOT a native HeptaBao or actual SDK claim. */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import https from "node:https";
import http from "node:http";
import { spawn, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { digest } from "./authbus_admission_authority_candidate.mjs";
import { TrustedAdmissionAuthority, applyFromTrustedControl } from "./authbus_trusted_admission_candidate.mjs";
import { TrustedRefreshAdmissionRegistry } from "./authbus_refresh_registry_candidate.mjs";
import { TrustedBaoControlSource, TrustedBaoCoordinator } from "./authbus_trusted_control_candidate.mjs";
const self = fileURLToPath(import.meta.url);
process.umask(0o077);
const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
const safe = error => ({ code: error.diagnosticCode ?? error.code ?? "test_error" });
function durable(file, value) {
  const temp = file + ".new-" + crypto.randomUUID();
  const fd = fs.openSync(temp, "wx", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temp, file);
  const dir = fs.openSync(path.dirname(file), "r"); try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
}
const originalCredential = { type: "oauth", provider: "openai-codex", access: "synthetic-old-access", refresh: "synthetic-old-refresh", expires: 1 };
if (process.argv[2] === "--worker") {
  const input = JSON.parse(fs.readFileSync(process.argv[3]));
  const { config, root, scenario, providerAddress } = input;
  const scope = { hostId: "main-r5", agentId: "main", provider: originalCredential.provider, agentDir: path.join(root, "agent") };
  const currentFile = path.join(root, "credential.json"), closeFile = path.join(root, "admission.json");
  const credential = fs.existsSync(currentFile) ? JSON.parse(fs.readFileSync(currentFile)) : originalCredential;
  const bindingCredential = input.useCurrent ? credential : originalCredential;
  const source = new TrustedBaoControlSource(config), binding = { scope, model: "synthetic-r5", profileId: "openai-codex:fixture", credentialDigest: digest(bindingCredential) };
  const coordinator = new TrustedBaoCoordinator(config, { bindings: [binding] });
  const request = source.bootstrapRequest(scope, binding);
  const counts = { providerCalls: 0, writes: 0, closes: 0 };
  try {
    if (input.operation === "issue") {
      const issued = await coordinator.issue(request, { leaseMs: 3000 });
      const grant = await source.readGrant(scope);
      process.stdout.write(JSON.stringify({ ok: true, issuedEpoch: issued.grant.epoch, readEpoch: grant.grant.epoch }) + "\n");
    } else {
      await coordinator.issue(request, { leaseMs: 3000 });
      if (!fs.existsSync(currentFile)) durable(currentFile, originalCredential);
      const callbacks = {
        readCredential: () => JSON.parse(fs.readFileSync(currentFile)),
        closeAdmission: () => { counts.closes++; if (scenario === "close-fails") return false; durable(closeFile, { allowed: false }); return true; },
        refreshCredential: async (current, dispatch) => {
          counts.providerCalls++;
          if (scenario === "dispatch-deadline-expired") await new Promise(resolve => setTimeout(resolve, 3500));
          const response = await dispatch(() => fetch(providerAddress + "/rotate", { method: "POST", body: JSON.stringify({ refresh_token: current.refresh }) }));
          const next = await response.json();
          if (scenario === "duplicate-dispatch") await dispatch(() => fetch(providerAddress + "/rotate", { method: "POST", body: JSON.stringify({ refresh_token: current.refresh }) }));
          if (scenario === "kill-after-response") process.kill(process.pid, "SIGKILL");
          return next;
        },
        writeCredential: value => {
          counts.writes++;
          if (scenario === "sdk-false") return false;
          if (scenario !== "sdk-lying-success") durable(currentFile, value);
          return true;
        },
      };
      let result, nextEpoch, successorChecked = false;
      if (scenario === "registry-success") {
        const directory = path.join(root, "authority"); fs.mkdirSync(directory, { mode: 0o700 });
        const authority = new TrustedAdmissionAuthority({ directory, scope, controlSource: source });
        const readStore = () => ({ version: 1, profiles: { [binding.profileId]: callbacks.readCredential() },
          order: { [scope.provider]: [binding.profileId] } });
        const fixtureSdk = { upsertAuthProfileWithLock: ({ credential }) => callbacks.writeCredential(credential) };
        const registry = new TrustedRefreshAdmissionRegistry({ authorities: [authority],
          resolveDefaultAgentDir: () => scope.agentDir, resolveProviderIdForAuth: value => value,
          readStore, refreshBindings: [{ scope, controlSource: source, coordinator, sdk: fixtureSdk, leaseMs: 3000 }] });
        const uninstall = registry.install();
        try {
          await applyFromTrustedControl({ authority, controlSource: source, updateStore: () => true,
            verifyStore: grant => grant.digest === digest(callbacks.readCredential()) });
          const oldPermit = authority.inspect();
          const params = { provider: scope.provider, agentDir: scope.agentDir, profileId: binding.profileId, credential: originalCredential };
          const refreshed = await registry.refreshManagedOAuth(params, callbacks.refreshCredential);
          result = refreshed.receipt;
          const newer = registry.advanceAfterRefresh(params, oldPermit, binding.profileId, callbacks.readCredential().access);
          assert.ok(newer.epoch > oldPermit.epoch); nextEpoch = newer.epoch;
          assert.throws(() => registry.advanceAfterRefresh(params, oldPermit, binding.profileId, originalCredential.access), /successor_result_unbound/);
          assert.equal(registry.refreshObservations.published, 1); successorChecked = true;
        } finally { uninstall(); }
      } else if (scenario === "same-owner-race") {
        const attempts = await Promise.allSettled([coordinator.refreshOnce(request, callbacks), coordinator.refreshOnce(request, callbacks)]);
        const good = attempts.filter(item => item.status === "fulfilled");
        assert.equal(good.length, 1); result = good[0].value;
      } else result = await coordinator.refreshOnce(request, callbacks);
      if (!nextEpoch) {
        const nextRequest = source.bootstrapRequest(scope, { ...binding, credentialDigest: result.credentialDigest });
        nextEpoch = (await coordinator.issue(nextRequest, { leaseMs: 3000 })).grant.epoch;
      }
      const read = await source.readGrant(scope);
      process.stdout.write(JSON.stringify({ ok: true, fenceEpoch: result.fenceEpoch, publishedEpoch: result.publishedEpoch,
        newGrantEpoch: nextEpoch, newGrantReadable: read.grant.epoch === nextEpoch, successorChecked, counts }) + "\n");
    }
  } catch (error) { process.stdout.write(JSON.stringify({ ok: false, ...safe(error), counts }) + "\n"); }
  finally { try { await source.close(); await coordinator.close(); } catch {} }
} else {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "authbus-refresh-r5-"));
  const key = path.join(root, "server.key"), cert = path.join(root, "server.crt");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
    "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"], { stdio: "ignore" });
  const checks = [], observations = [];
  const report = { schema: "authbus-refresh-r5-process-http-contract", ok: false, actualNativeHeptaBao: false,
    actualSdk: false, actualColdProcess: true, actualProviderHttp: true, providerSynthetic: true, tlsControlEmulator: true,
    productionMutation: false, checks, observations, sourceManifest: [path.basename(self), "authbus_trusted_control_candidate.mjs", "authbus_admission_authority_candidate.mjs", "authbus_trusted_admission_candidate.mjs", "authbus_refresh_registry_candidate.mjs", "authbus_dispatch_registry_candidate.mjs", "authbus_admission_registry_candidate.mjs"].map(name => ({ name, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(path.dirname(self), name))).digest("hex") })) };
  let control, provider, active = null;
  const tokens = new Map();
  async function runWorker(input) {
    const file = path.join(input.root, "input-" + crypto.randomUUID() + ".json"); durable(file, input);
    return await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [self, "--worker", file], { stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "", stderr = "";
      child.stdout.on("data", value => { stdout += value; }); child.stderr.on("data", value => { stderr += value; });
      child.on("error", reject); child.on("exit", (code, signal) => {
        const lines = stdout.trim().split("\n").filter(Boolean);
        resolve({ code, signal, result: lines.length ? JSON.parse(lines.at(-1)) : null, stderrSha256: digest(stderr) });
      });
    });
  }
  const reply = (res, status, value) => { res.writeHead(status, { "content-type": "application/json" }); res.end(value ? JSON.stringify(value) : undefined); };
  try {
    control = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, async (req, res) => {
      let body = ""; for await (const part of req) body += part; body = body ? JSON.parse(body) : null;
      if (req.url === "/v1/auth/approle/login") {
        if (!["reader", "issuer"].includes(body?.role_id) || body?.secret_id !== "synthetic-" + body.role_id) return reply(res, 403, {});
        const token = crypto.randomUUID(); tokens.set(token, body.role_id); return reply(res, 200, { auth: { client_token: token, lease_duration: 300 } });
      }
      const role = tokens.get(req.headers["x-vault-token"]);
      if (!role) return reply(res, 403, {});
      if (req.url === "/v1/auth/token/revoke-self") { tokens.delete(req.headers["x-vault-token"]); return reply(res, 204); }
      if (req.url === "/v1/auth/token/lookup-self") return reply(res, 200, { data: {} });
      if (req.url !== "/v1/authbus/data/control") return reply(res, 404, {});
      const state = fs.existsSync(active.controlFile) ? JSON.parse(fs.readFileSync(active.controlFile)) : { version: 0, document: null };
      if (req.method === "GET") return state.document ? reply(res, 200, { data: { data: state.document,
        metadata: { version: state.version, destroyed: false, deletion_time: "" } } }) : reply(res, 404, {});
      if (role !== "issuer") return reply(res, 403, {});
      if (body.options.cas !== state.version) return reply(res, 400, {});
      const attempt = body.data.refreshAttempts?.at(-1), oldAttempt = state.document?.refreshAttempts?.at(-1);
      const beginning = attempt?.status === "UNKNOWN" && oldAttempt?.status !== "UNKNOWN";
      const finishing = attempt?.status === "PUBLISHED" && oldAttempt?.status === "UNKNOWN";
      if (beginning && active.scenario === "fence-write-denied") return reply(res, 500, {});
      durable(active.controlFile, { version: state.version + 1, document: body.data });
      if (beginning && active.scenario === "fence-commit-response-lost" || finishing && active.scenario === "completion-response-lost") return res.destroy();
      return reply(res, 200, { data: { version: state.version + 1 } });
    });
    provider = http.createServer(async (req, res) => {
      let body = ""; for await (const part of req) body += part;
      assert.equal(req.url, "/rotate"); assert.equal(JSON.parse(body).refresh_token, originalCredential.refresh);
      const state = fs.existsSync(active.providerFile) ? JSON.parse(fs.readFileSync(active.providerFile)) : { count: 0 };
      durable(active.providerFile, { count: state.count + 1 });
      if (active.scenario === "provider-response-lost") return res.destroy();
      return reply(res, 200, { type: "oauth", provider: originalCredential.provider, access: "synthetic-new-access",
        refresh: "synthetic-new-refresh", expires: Date.now() + 60000 });
    });
    await Promise.all([new Promise(resolve => control.listen(0, "127.0.0.1", resolve)), new Promise(resolve => provider.listen(0, "127.0.0.1", resolve))]);
    for (const scenario of ["close-fails", "fence-write-denied", "fence-commit-response-lost", "provider-response-lost",
      "kill-after-response", "sdk-false", "sdk-lying-success", "duplicate-dispatch", "dispatch-deadline-expired", "completion-response-lost", "success", "same-owner-race", "registry-success"]) {
      const cell = path.join(root, scenario); fs.mkdirSync(cell, { mode: 0o700 }); fs.mkdirSync(path.join(cell, "agent"));
      for (const role of ["reader", "issuer"]) { fs.writeFileSync(path.join(cell, role + ".role"), role, { mode: 0o600 }); fs.writeFileSync(path.join(cell, role + ".secret"), "synthetic-" + role, { mode: 0o600 }); }
      const config = { schemaVersion: 1, address: "https://127.0.0.1:" + control.address().port, caFile: cert,
        kvMount: "authbus", controlPath: "control", issuerId: "r5-local-fixture", maxLeaseMs: 30000,
        ...Object.fromEntries(["reader", "issuer"].map(role => [role, { roleIdFile: path.join(cell, role + ".role"), secretIdFile: path.join(cell, role + ".secret") }])) };
      active = { scenario, controlFile: path.join(cell, "control.json"), providerFile: path.join(cell, "provider-count.json") };
      const input = { config, root: cell, scenario, providerAddress: "http://127.0.0.1:" + provider.address().port, operation: "refresh" };
      const worker = await runWorker(input);
      const state = JSON.parse(fs.readFileSync(active.controlFile));
      const attempts = state.document.refreshAttempts;
      const providerCount = fs.existsSync(active.providerFile) ? JSON.parse(fs.readFileSync(active.providerFile)).count : 0;
      const successful = ["success", "same-owner-race", "registry-success"].includes(scenario);
      assert.equal(providerCount, ["close-fails", "fence-write-denied", "fence-commit-response-lost", "dispatch-deadline-expired"].includes(scenario) ? 0 : 1);
      checks.push({ case: scenario + ": exact provider request count", passed: true });
      if (scenario === "kill-after-response") assert.equal(worker.signal, "SIGKILL");
      else assert.equal(worker.result?.ok, successful);
      checks.push({ case: scenario + ": actual process outcome", passed: true });
      if (scenario === "registry-success") {
        assert.equal(worker.result.successorChecked, true);
        checks.push({ case: "registry successor admits exact new wire credential and rejects old credential", passed: true });
      }
      if (["close-fails", "fence-write-denied"].includes(scenario)) {
        assert.equal(attempts.length, 0);
      } else if (successful || scenario === "completion-response-lost") {
        assert.equal(attempts[0].status, "PUBLISHED"); assert.equal(attempts[0].sdkVerified, true);
        assert.equal(attempts[0].publishedDigest, digest(JSON.parse(fs.readFileSync(path.join(cell, "credential.json")))));
        assert.ok(attempts[0].publishedEpoch > attempts[0].fenceEpoch);
        // Independent cold coordinator still configured with OLD digest must
        // reject from the persisted fence, not merely from changed bindings.
        const cold = await runWorker({ ...input, operation: "issue" });
        assert.equal(cold.result?.ok, false); assert.equal(cold.result?.code, "trusted_refresh_old_credential_fenced");
        checks.push({ case: scenario + ": cold old-credential reissue denied", passed: true });
        if (scenario === "completion-response-lost") {
          const recovered = await runWorker({ ...input, operation: "issue", useCurrent: true });
          assert.equal(recovered.result?.ok, true); assert.ok(recovered.result.issuedEpoch > attempts[0].publishedEpoch);
          assert.equal(JSON.parse(fs.readFileSync(active.providerFile)).count, 1);
          checks.push({ case: scenario + ": verified publication cold reissue without repeating provider I/O", passed: true });
        }
      } else {
        assert.equal(attempts[0].status, "UNKNOWN");
        assert.equal(state.document.assignments[0].status, "REFRESH_PENDING");
        const expiry = Math.max(...state.document.refreshLeases.map(x => x.expiresAt));
        await new Promise(resolve => setTimeout(resolve, Math.max(0, expiry - Date.now()) + 1005));
        const cold = await runWorker({ ...input, operation: "issue" });
        assert.equal(cold.result?.ok, false); assert.equal(cold.result?.code, "trusted_refresh_outcome_unknown");
        checks.push({ case: scenario + ": cold retry after lease expiry denied", passed: true });
      }
      checks.push({ case: scenario + ": durable control state", passed: true });
      observations.push({ scenario, providerCount, processSignal: worker.signal, result: worker.result,
        attemptStatus: attempts[0]?.status ?? null, controlVersion: state.version });
    }
    report.ok = true;
  } catch (error) { report.failure = { ...safe(error), message: String(error.message).slice(0, 300), stack: String(error.stack).split("\n").slice(0, 4) }; }
  finally {
    for (const server of [control, provider]) if (server?.listening) { server.closeAllConnections?.(); await new Promise(resolve => server.close(resolve)); }
    report.checksPassed = checks.length;
    const output = process.env.AUTHBUS_R5_RECEIPT ?? path.join(path.dirname(self), "refresh-r5-contract-receipt.json");
    fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
    process.stdout.write(JSON.stringify(report) + "\n");
    if (!report.ok) process.exitCode = 1;
  }
}
