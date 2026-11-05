#!/usr/bin/env node
/** Local TLS control-protocol emulator; this does NOT qualify native HeptaBao. */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import https from "node:https";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { AdmissionAuthority, digest } from "./authbus_admission_authority_candidate.mjs";
import { TrustedAdmissionAuthority } from "./authbus_trusted_admission_candidate.mjs";
import { TrustedBaoControlSource, TrustedBaoCoordinator } from "./authbus_trusted_control_candidate.mjs";

const here = path.dirname(fileURLToPath(import.meta.url)), fixture = path.join(here, "local-fixture");
process.umask(0o077);
const checks = [], check = async (name, run) => { await run(); checks.push({ case: name, passed: true }); };
const credential = { type: "api_key", provider: "openai", key: "synthetic-r4-local-contract" };
const tokens = new Map(); let document = null, version = 0, tlsRequests = 0;
const server = https.createServer({ key: fs.readFileSync(path.join(fixture, "server.key")), cert: fs.readFileSync(path.join(fixture, "server.crt")) }, async (req, res) => {
  tlsRequests += 1;
  let bytes = ""; for await (const chunk of req) bytes += chunk;
  const body = bytes ? JSON.parse(bytes) : null;
  const response = (status, value = null) => { res.writeHead(status, { "content-type": "application/json" }); res.end(value ? JSON.stringify(value) : undefined); };
  if (req.url === "/v1/auth/approle/login") {
    if (!["reader-role", "issuer-role"].includes(body?.role_id) || body.secret_id !== "synthetic-" + body.role_id) return response(403, {});
    const token = crypto.randomUUID(); tokens.set(token, body.role_id);
    return response(200, { auth: { client_token: token, lease_duration: 120 } });
  }
  const role = tokens.get(req.headers["x-vault-token"]);
  if (!role) return response(403, { errors: ["synthetic-denied"] });
  if (req.url === "/v1/auth/token/revoke-self") { tokens.delete(req.headers["x-vault-token"]); return response(204); }
  if (req.url === "/v1/auth/token/lookup-self") return response(200, { data: {} });
  if (req.url === "/v1/auth/token/renew-self") return response(200, { auth: { client_token: req.headers["x-vault-token"], lease_duration: 120 } });
  if (req.url !== "/v1/openclaw-auth/data/scheduler-assignments") return response(404, {});
  if (req.method === "GET") return document ? response(200, { data: { data: document, metadata: { version, deletion_time: "", destroyed: false } } }) : response(404, {});
  if (role !== "issuer-role") return response(403, {});
  if (body?.options?.cas !== version) return response(400, { errors: ["synthetic-cas-conflict"] });
  document = body.data; version += 1; return response(200, { data: { version } });
});
const report = { schema: "authbus-trusted-control-local-tls-contract-r4", ok: false, checks,
  actualNativeHeptaBao: false, actualSdk: false, actualColdProcess: false, tlsControlEmulator: true, productionMutation: false };
let source, coordinator;
try {
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const root = fs.mkdtempSync(path.join(fixture, "state-"));
  for (const part of ["authority", "agent"]) fs.mkdirSync(path.join(root, part), { mode: 0o700 });
  for (const role of ["reader", "issuer"]) {
    fs.writeFileSync(path.join(root, role + "-role"), role + "-role", { mode: 0o600 });
    fs.writeFileSync(path.join(root, role + "-secret"), "synthetic-" + role + "-role", { mode: 0o600 });
  }
  const config = { schemaVersion: 1, address: "https://127.0.0.1:" + server.address().port, caFile: path.join(fixture, "server.crt"),
    kvMount: "openclaw-auth", controlPath: "scheduler-assignments", issuerId: "local-tls-emulator",
    issuer: { roleIdFile: path.join(root, "issuer-role"), secretIdFile: path.join(root, "issuer-secret") },
    reader: { roleIdFile: path.join(root, "reader-role"), secretIdFile: path.join(root, "reader-secret") } };
  const scope = { hostId: "main-r4", agentId: "main", agentDir: path.join(root, "agent"), provider: "openai" };
  const binding = { scope, model: "fixture-r4", profileId: "openai:synthetic", credentialDigest: digest(credential) };
  source = new TrustedBaoControlSource(config);
  coordinator = new TrustedBaoCoordinator(config, { bindings: [binding] });
  const authority = new TrustedAdmissionAuthority({ directory: path.join(root, "authority"), scope, controlSource: source });
  let touched = 0;
  const callbacks = { updateStore: () => { touched += 1; return true; }, verifyStore: () => true };
  await check("no_json_proof_or_verifier_can_mint_admission", async () => {
    await assert.rejects(() => authority.apply({ epoch: 1, status: "ASSIGNED", mode: "enforce", model: binding.model,
      profileId: binding.profileId, digest: binding.credentialDigest, leaseId: "fake", expiresAt: Date.now() + 10000 }, { ...callbacks, controlProof: {} }), /fresh_proof_required/);
    assert.equal(touched, 0); assert.equal(authority.inspect().allowed, false);
  });
  await check("unresolved_cold_bootstrap_can_publish_durable_negative_without_a_clock_proof", async () => {
    authority.closeUnresolved();
    assert.equal(authority._read().phase, "unresolved");
    assert.equal(authority.inspect().allowed, false);
  });
  const request = source.bootstrapRequest(scope, binding);
  let issued, fresh;
  await check("pinned_tls_approle_cas_mints_opaque_single_use_proof", async () => {
    issued = await coordinator.issue(request, { leaseMs: 6000 });
    fresh = await source.readGrant(scope);
    assert.equal(digest(fresh.grant), digest(issued.grant));
    await authority.apply(fresh.grant, { ...callbacks, controlProof: fresh.proof });
    assert.equal(authority.inspect().allowed, true); assert.equal(touched, 1);
    assert.equal(JSON.parse(fs.readFileSync(authority.filename)).trustedControl.bootId, request.bootId);
  });
  await check("active_refresh_owner_blocks_other_bootstrap", async () => {
    await assert.rejects(() => coordinator.issue({ ...request, bootId: crypto.randomUUID() }), /refresh_owner_busy/);
  });
  await check("fresh_authenticated_same_epoch_cannot_boot_a_cold_authority", async () => {
    const cold = new TrustedAdmissionAuthority({ directory: path.join(root, "authority"), scope, controlSource: source });
    const proof = await source.readGrant(scope);
    await assert.rejects(() => cold.apply(proof.grant, { ...callbacks, controlProof: proof.proof }), /cold_higher_epoch_required/);
    await assert.rejects(() => cold.reconcileCommitted(proof.grant, { verifyStore: () => true }), /cold_higher_epoch_required/);
    assert.equal(touched, 1); assert.equal(cold.inspect().allowed, false); assert.equal(authority.inspect().allowed, true);
  });
  await check("replayed_or_serialized_proof_cannot_warm_reconcile", async () => {
    await assert.rejects(() => authority.reconcileCommitted(fresh.grant, { verifyStore: () => true, controlProof: fresh.proof }), /fresh_proof_required/);
    assert.equal(authority.inspect().allowed, false);
    const next = await source.readGrant(scope);
    await assert.rejects(() => authority.reconcileCommitted(next.grant, { verifyStore: () => true, controlProof: JSON.parse(JSON.stringify(next.proof)) }), /fresh_proof_required/);
    await authority.reconcileCommitted(next.grant, { verifyStore: () => true, controlProof: next.proof });
    assert.equal(authority.inspect().allowed, true);
  });
  await check("grant_mutation_and_scope_escape_fail_proof_binding", async () => {
    const next = await source.readGrant(scope);
    await assert.rejects(() => authority.apply({ ...next.grant, epoch: next.grant.epoch + 1 }, { ...callbacks, controlProof: next.proof }), /proof_binding_mismatch/);
    await authority.reconcileCommitted(next.grant, { verifyStore: () => true, controlProof: next.proof });
    const other = new TrustedAdmissionAuthority({ directory: path.join(root, "authority"), scope: { ...scope, agentId: "other" }, controlSource: source });
    const again = await source.readGrant(scope);
    await assert.rejects(() => other.apply(again.grant, { ...callbacks, controlProof: again.proof }), /proof_binding_mismatch/);
    assert.equal(authority.inspect().allowed, true);
  });
  await check("new_process_boot_id_cannot_read_old_control_grant", async () => {
    const coldSource = new TrustedBaoControlSource(config);
    try { await assert.rejects(() => coldSource.readGrant(scope), /bootstrap_assignment_mismatch/); }
    finally { await coldSource.close(); }
  });
  await check("cold_strictly_higher_actual_tls_issuance_survives_raw_wall_rollback", async () => {
    const cold = new TrustedAdmissionAuthority({ directory: path.join(root, "authority"), scope, controlSource: source });
    const currentEpoch = authority._read().grant.epoch;
    await coordinator.issue(request, { leaseMs: 6000, epochFloor: currentEpoch });
    const next = await source.readGrant(scope), rawNow = Date.now;
    Date.now = () => rawNow() - 60000;
    try { await cold.apply(next.grant, { ...callbacks, controlProof: next.proof }); assert.equal(cold.inspect().allowed, true); }
    finally { Date.now = rawNow; }
    assert.equal(next.grant.epoch > currentEpoch, true); assert.equal(authority.inspect().allowed, false);
  });
  await check("failed_store_leaves_pending_and_cold_needs_another_new_epoch", async () => {
    const cold = new TrustedAdmissionAuthority({ directory: path.join(root, "authority"), scope, controlSource: source });
    await coordinator.issue(request, { leaseMs: 3000, epochFloor: cold._read().grant.epoch });
    const next = await source.readGrant(scope);
    await assert.rejects(() => cold.apply(next.grant, { updateStore: () => { throw new Error("synthetic-store-abort"); }, verifyStore: () => true, controlProof: next.proof }), /synthetic-store-abort/);
    assert.equal(cold._read().phase, "pending");
    const again = await source.readGrant(scope);
    await assert.rejects(() => cold.apply(again.grant, { ...callbacks, controlProof: again.proof }), /cold_higher_epoch_required/);
    await coordinator.issue(request, { leaseMs: 2000, epochFloor: cold._read().grant.epoch });
    const recovery = await source.readGrant(scope);
    await cold.apply(recovery.grant, { ...callbacks, controlProof: recovery.proof });
    assert.equal(cold.inspect().allowed, true);
    const originalDeadline = cold.activation.deadlineMono;
    const proof = await source.readGrant(scope);
    await cold.reconcileCommitted(proof.grant, { verifyStore: () => true, controlProof: proof.proof });
    assert.equal(cold.activation.deadlineMono <= originalDeadline, true);
    await new Promise(resolve => setTimeout(resolve, Math.max(0, originalDeadline - performance.now()) + 25));
    assert.equal(cold.inspect().allowed, false); assert.equal(cold._read().phase, "expired");
  });
  await check("tls_reader_write_denied_and_approle_tokens_renewed", async () => {
    assert.equal(await source.probeWriteDenial(), true);
    assert.equal(await source.renew(), true); assert.equal(await coordinator.renew(), true);
  });
  report.ok = true;
} catch (error) {
  report.errorCode = error.diagnosticCode ?? error.code ?? "local_contract_failed";
  report.errorMessage = String(error.message).slice(0, 512);
  report.stack = String(error.stack).split("\n").slice(0, 5);
} finally {
  try { report.readerCleanup = await source?.close(); report.issuerCleanup = await coordinator?.close(); }
  catch (error) { report.ok = false; report.cleanupError = error.diagnosticCode ?? "local_cleanup_failed"; }
  report.tlsRequests = tlsRequests;
  if (server.listening) { server.closeAllConnections?.(); await new Promise(resolve => server.close(resolve)); }
  fs.writeFileSync(path.join(here, "local-contract-receipt.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  process.stdout.write(JSON.stringify(report) + "\n");
  if (!report.ok) process.exitCode = 1;
}
