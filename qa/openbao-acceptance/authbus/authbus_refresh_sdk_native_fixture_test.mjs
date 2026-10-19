/** Local synthetic-path fixtures only; no installed SDK or native evidence. */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import dns from "node:dns";
import childProcess from "node:child_process";
import { fileURLToPath } from "node:url";
import { selectOwnedSdkEntrypoint, readOwned, durable, hash, installFixtureSafety }
  from "./authbus_refresh_sdk_native_fixture.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const rows = [];
const test = (name, action) => { action(); rows.push({ case: name, passed: true }); };
const root = fs.mkdtempSync(path.join(os.tmpdir(), "authbus-native-helper-unit-"));
fs.chmodSync(root, 0o700);
const sdkRoot = path.join(root, "fake-sdk"), parentRoot = path.join(root, "controller"), workerRoot = path.join(parentRoot, "worker");
for (const dir of [sdkRoot, parentRoot, workerRoot]) fs.mkdirSync(dir, { mode: 0o700 });
const packageFile = path.join(sdkRoot, "package.json"), binFile = path.join(sdkRoot, "openclaw.mjs");
const pkg = { name: "openclaw", version: "2026.7.1-2", bin: { openclaw: "openclaw.mjs" } };
fs.writeFileSync(packageFile, JSON.stringify(pkg), { mode: 0o600 }); fs.writeFileSync(binFile, "// synthetic fixture, never executed\n", { mode: 0o600 });
try {
  test("native_fixture_discovery_body_matches_frozen_actual_r5", () => {
    const original = fs.readFileSync(path.join(here, "authbus_refresh_sdk_caller_live.mjs"), "utf8");
    const candidate = fs.readFileSync(path.join(here, "authbus_refresh_sdk_native_fixture.mjs"), "utf8");
    const a = original.slice(original.indexOf("function selectOwnedSdkEntrypoint("), original.indexOf("\nconst args = {};")).trim();
    const b = candidate.slice(candidate.indexOf("function selectOwnedSdkEntrypoint("), candidate.indexOf("\nexport function installFixtureSafety(")).trim();
    assert.equal(b, a);
  });
  test("native_fixture_package_bin_metadata_is_not_execution", () => {
    const selected = selectOwnedSdkEntrypoint(sdkRoot);
    assert.equal(selected.entrypoint, binFile); assert.equal(selected.entrypointSha256, hash(fs.readFileSync(binFile)));
  });
  test("native_fixture_entrypoint_change_is_detectable", () => {
    const old = selectOwnedSdkEntrypoint(sdkRoot);
    fs.appendFileSync(binFile, "// another synthetic line\n");
    assert.notEqual(selectOwnedSdkEntrypoint(sdkRoot).entrypointSha256, old.entrypointSha256);
  });
  test("native_fixture_escape_bin_rejected", () => {
    fs.writeFileSync(packageFile, JSON.stringify({ ...pkg, bin: { openclaw: "../outside.mjs" } }));
    assert.throws(() => selectOwnedSdkEntrypoint(sdkRoot)); fs.writeFileSync(packageFile, JSON.stringify(pkg));
  });
  test("native_fixture_symlink_bin_rejected", () => {
    fs.renameSync(binFile, binFile + ".real"); fs.symlinkSync(binFile + ".real", binFile);
    assert.throws(() => selectOwnedSdkEntrypoint(sdkRoot)); fs.unlinkSync(binFile); fs.renameSync(binFile + ".real", binFile);
  });
  test("native_fixture_private_file_roundtrip_and_excess_rejected", () => {
    const file = path.join(workerRoot, "owned.json"); durable(file, { fixture: true }, { create: true });
    assert.deepEqual(JSON.parse(readOwned(file)), { fixture: true }); assert.throws(() => readOwned(file, 2));
    assert.throws(() => durable(file, { overwrite: true }, { create: true }));
    assert.deepEqual(JSON.parse(readOwned(file)), { fixture: true });
  });
  const report = { externalNetworkAttempts: 0, externalProcessAttempts: 0, outsideFixtureWriteAttempts: 0,
    outsideFixtureHomeReadAttempts: 0, blockedHomeReads: [] };
  const privateServer = path.join(parentRoot, "server.key"); fs.writeFileSync(privateServer, "synthetic-controller-only", { mode: 0o600 });
  let safety = installFixtureSafety({ sdkRoot, root: workerRoot, parentRoot, deadlineNs: String(process.hrtime.bigint() + 5_000_000_000n),
    controlPort: 38001, providerPort: 38002, certificate: Buffer.from("synthetic-unused-ca"), report });
  try {
    test("native_fixture_original_budget_is_finite", () => { assert.ok(safety.remainingMs() <= 5000); });
    test("native_fixture_controller_private_root_unreadable_even_outside_home", () => {
      assert.throws(() => fs.readFileSync(privateServer)); assert.equal(report.outsideFixtureHomeReadAttempts, 1);
    });
    test("native_fixture_outside_write_refused", () => {
      assert.throws(() => fs.writeFileSync(path.join(parentRoot, "outside"), "unit")); assert.equal(report.outsideFixtureWriteAttempts, 1);
    });
    test("native_fixture_external_dns_refused_before_lookup", () => {
      assert.throws(() => dns.lookup("external-fixture.invalid", () => {})); assert.equal(report.externalNetworkAttempts, 1);
    });
    test("native_fixture_process_spawn_refused_before_exec", () => {
      assert.throws(() => childProcess.spawn(process.execPath, ["-e", "process.exit(0)"])); assert.equal(report.externalProcessAttempts, 1);
    });
    test("native_fixture_owned_private_store_still_accessible", () => {
      assert.deepEqual(JSON.parse(readOwned(path.join(workerRoot, "owned.json"))), { fixture: true });
    });
  } finally { safety.restore(); safety = null; }
  test("native_fixture_expired_parent_budget_refused_before_install", () => {
    assert.throws(() => installFixtureSafety({ sdkRoot, root: workerRoot, parentRoot, deadlineNs: String(process.hrtime.bigint() - 1n),
      controlPort: 38001, providerPort: 38002, certificate: Buffer.from("synthetic-unused-ca"), report }));
  });
  test("native_fixture_restores_guard_after_worker", () => { assert.equal(fs.readFileSync(privateServer, "utf8"), "synthetic-controller-only"); });
  process.stdout.write(JSON.stringify({ schema: "authbus-native-fixture-unit", ok: true, actualSdk: false, actualNativeHeptaBao: false,
    syntheticPathsOnly: true, checks: rows, checksPassed: rows.length }) + "\n");
} finally { fs.rmSync(root, { recursive: true, force: true }); }
