#!/usr/bin/env node
/** Local guard tests only; no SDK, Bao, provider, credential, or live socket. */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import dns from "node:dns";
import childProcess from "node:child_process";
import { installFixtureSafety } from "./authbus_refresh_sdk_native_openai_fixture.mjs";

const checks = [];
const test = (name, action) => { action(); checks.push({ case: name, passed: true }); };
const refused = (action, code) => assert.throws(action, error => error.diagnosticCode === code);
const folder = fs.mkdtempSync(path.join(os.tmpdir(), "native-openai-local-guard-"));
const parentRoot = path.join(folder, "run"), root = path.join(parentRoot, "sdk");
const sdkRoot = path.join(folder, "synthetic-sdk");
fs.mkdirSync(root, { recursive: true, mode: 0o700 }); fs.mkdirSync(sdkRoot, { mode: 0o700 });
const privateOutside = path.join(parentRoot, "synthetic-outside.json");
fs.writeFileSync(privateOutside, "synthetic-fixture-only", { mode: 0o600 });
const report = { externalNetworkAttempts: 0, externalProcessAttempts: 0,
  outsideFixtureWriteAttempts: 0, outsideFixtureHomeReadAttempts: 0, blockedHomeReads: [] };
const before = { fetch: globalThis.fetch, connect: net.Socket.prototype.connect,
  readFileSync: fs.readFileSync, writeFileSync: fs.writeFileSync, spawn: childProcess.spawn };
const input = { root, parentRoot, sdkRoot, report, deadlineNs: String(process.hrtime.bigint() + 5_000_000_000n),
  controlPort: 41001, providerPort: 41002, connectProxyPort: 41003, certificate: Buffer.from("synthetic-unused-ca") };
let safety;
try {
  test("three_distinct_owned_listener_bindings_required", () => refused(() => installFixtureSafety({ ...input,
    connectProxyPort: input.providerPort }), "native_openai_sdk_owned_listener_bindings_invalid"));
  safety = installFixtureSafety(input);
  test("mapped_or_global_fetch_has_no_provider_lane", () => {
    assert.equal(globalThis.fetch.mock, undefined);
    refused(() => globalThis.fetch("https://auth.openai.com/oauth/token"),
      "native_openai_sdk_non_undici_provider_request_forbidden");
  });
  test("unowned_loopback_or_foreign_network_is_denied_before_connect", () => {
    refused(() => net.connect({ host: "127.0.0.1", port: 41004 }), "native_sdk_external_network_forbidden");
    refused(() => net.connect({ host: "auth.openai.com", port: 443 }), "native_sdk_external_network_forbidden");
  });
  test("external_dns_resolution_is_denied", () => refused(() => dns.lookup("auth.openai.com", () => {}),
    "native_sdk_external_dns_forbidden"));
  test("external_process_creation_is_denied", () => refused(() => childProcess.spawn("true", []),
    "native_sdk_external_process_forbidden"));
  test("outside_fixture_write_is_denied", () => refused(() => fs.writeFileSync(path.join(folder, "must-not-exist"), "x"),
    "native_sdk_outside_write_forbidden"));
  test("parent_fixture_private_read_is_denied", () => refused(() => fs.readFileSync(privateOutside),
    "native_sdk_external_private_read_forbidden"));
  test("owned_store_read_and_write_remain_usable", () => {
    const file = path.join(root, "synthetic-owned.json");
    fs.writeFileSync(file, "owned", { mode: 0o600 }); assert.equal(fs.readFileSync(file, "utf8"), "owned");
  });
  safety.restore(); safety = null;
  test("all_original_process_functions_are_restored", () => {
    assert.equal(globalThis.fetch, before.fetch); assert.equal(net.Socket.prototype.connect, before.connect);
    assert.equal(fs.readFileSync, before.readFileSync); assert.equal(fs.writeFileSync, before.writeFileSync);
    assert.equal(childProcess.spawn, before.spawn); assert.equal(fs.existsSync(path.join(folder, "must-not-exist")), false);
  });
  test("expired_original_deadline_refuses_before_guard_install", () => refused(() => installFixtureSafety({ ...input,
    deadlineNs: String(process.hrtime.bigint() - 1n) }), "native_sdk_original_deadline"));
  safety = installFixtureSafety({ ...input, deadlineNs: String(process.hrtime.bigint() + 5_000_000n) });
  await new Promise(resolve => setTimeout(resolve, 12));
  test("elapsed_original_deadline_denies_before_any_fetch_attempt", () => {
    const count = report.externalNetworkAttempts;
    refused(() => globalThis.fetch("https://auth.openai.com/oauth/token"), "native_sdk_original_deadline");
    assert.equal(report.externalNetworkAttempts, count);
  });
} finally {
  safety?.restore(); fs.rmSync(folder, { recursive: true, force: true });
}
assert.equal(checks.length, 11);
assert.equal(report.externalNetworkAttempts, 4);
assert.equal(report.externalProcessAttempts, 1);
assert.equal(report.outsideFixtureWriteAttempts, 1);
assert.equal(report.outsideFixtureHomeReadAttempts, 1);
process.stdout.write(JSON.stringify({ schema: "authbus.native-openai.local-guard-test.v1", ok: true,
  actualSdk: false, actualNativeHeptaBao: false, realExternalProvider: false,
  liveNetworkConnections: 0, checksPassed: checks.length, checks,
  intentionalDeniedInputCounts: { network: report.externalNetworkAttempts, process: report.externalProcessAttempts,
    write: report.outsideFixtureWriteAttempts, privateRead: report.outsideFixtureHomeReadAttempts } }) + "\n");
