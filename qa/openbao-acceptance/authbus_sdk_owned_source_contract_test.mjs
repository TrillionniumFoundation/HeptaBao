#!/usr/bin/env node
/** Synthetic-only ownership and write/network guard regressions. No actual
 * installed SDK is substituted or qualified by this local contract test. */
import assert from "node:assert/strict";
import fs from "node:fs";
import https from "node:https";
import childProcess from "node:child_process";
import path from "node:path";
import os from "node:os";
import { collectOwnedProfiles, selectOwnedProfiles, credentialDigest, sha,
  protectReadPhase } from "./authbus_sdk_owned_source.mjs";

const main = "/synthetic/agents/main/agent", helper = "/synthetic/agents/helper/agent";
const profileId = "google:synthetic-owned-source";
const credential = { type: "api_key", provider: "google", key: "synthetic-never-provider-credential" };
let changed = false, mismatch = false, unlisted = false;
const calls = [];
const sdk = {
  clearRuntimeAuthProfileStoreSnapshots() { calls.push("clear"); },
  loadAuthProfileStoreWithoutExternalProfiles(agentDir, options) {
    assert.equal(options.allowKeychainPrompt, false); calls.push(["read", agentDir]);
    return { profiles: { [profileId]: changed ? { ...credential, key: "synthetic-new-owner-value" } : credential } };
  },
  resolvePersistedAuthProfileOwnerAgentDir({ agentDir }) { return unlisted ? "/unlisted/agent" : undefined; },
  findPersistedAuthProfileCredential({ agentDir, profileId: id }) {
    assert.equal(agentDir, main); assert.equal(id, profileId);
    return mismatch ? { ...credential, key: "synthetic-unmatched-owner" }
      : changed ? { ...credential, key: "synthetic-new-owner-value" } : credential;
  },
};
const secrets = new Set();
const current = collectOwnedProfiles(sdk, [main, helper], main, secrets);
assert.equal(current.rows.length, 2);
assert.equal(current.rows[1].ownerAgentDir, main);
assert.equal(current.rows[1].inheritedFromMain, true);
assert.equal(current.rows[1].persistedOwnerMatchesEffective, true);
assert.equal(current.rows[0].providerLivenessVerified, false);
assert.equal(JSON.stringify(current.rows).includes(credential.key), false);
assert.equal(secrets.has(credential.key), true);
const select = scopeAgentDir => ({ scopeAgentDir, ownerAgentDir: main, profileIdSha256: sha(profileId),
  credentialDigest: credentialDigest(credential), identityDigest: current.rows[0].identityDigest });
assert.equal(selectOwnedProfiles([select(helper)], current.rows, current)[0].profileId, profileId);
assert.throws(() => selectOwnedProfiles([select(main), select(helper)], current.rows, current), /duplicate_source_owner_export/);
assert.throws(() => selectOwnedProfiles([{ ...select(main), ownerAgentDir: helper }], current.rows, current), /export_selection_not_in_inspection/);
changed = true;
assert.throws(() => selectOwnedProfiles([select(main)], current.rows, collectOwnedProfiles(sdk, [main, helper], main)), /owned_source_changed_since_inspection/);
changed = false; mismatch = true;
assert.equal(collectOwnedProfiles(sdk, [main], main).rows[0].persistedOwnerMatchesEffective, false);
assert.throws(() => selectOwnedProfiles([select(main)], current.rows, collectOwnedProfiles(sdk, [main], main)), /owned_source_changed_since_inspection/);
mismatch = false; unlisted = true;
assert.throws(() => collectOwnedProfiles(sdk, [main], main), /sdk_resolved_unlisted_owner_directory/);
unlisted = false;
assert.throws(() => collectOwnedProfiles(sdk, [helper], main), /default_owner_not_explicitly_allowed/);

const root = fs.mkdtempSync(path.join(os.tmpdir(), "authbus-read-guards-"));
try {
  const filename = path.join(root, "existing.txt"); fs.writeFileSync(filename, "synthetic-read-only");
  const diagnostics = { bytes: 0, stdout: [], stderr: [] };
  const restore = protectReadPhase(diagnostics);
  try {
    assert.equal(fs.readFileSync(filename, "utf8"), "synthetic-read-only");
    assert.throws(() => fs.writeFileSync(filename, "changed"), /sdk_attempted_mutation_or_network/);
    assert.throws(() => fs.openSync(filename, "r+"), /sdk_attempted_writable_open/);
    assert.throws(() => https.get("https://example.invalid"), /sdk_attempted_mutation_or_network/);
    assert.throws(() => childProcess.spawnSync("/bin/true"), /sdk_attempted_mutation_or_network/);
    process.stdout.write("synthetic-captured-diagnostic");
  } finally { restore(); }
  assert.equal(fs.readFileSync(filename, "utf8"), "synthetic-read-only");
  assert.equal(Buffer.concat(diagnostics.stdout).toString(), "synthetic-captured-diagnostic");
} finally { fs.rmSync(root, { recursive: true, force: true }); }
process.stdout.write(JSON.stringify({ schema: "authbus-owned-sdk-source-synthetic-contract-v1", ok: true,
  actualSdkQualified: false, providerCalled: false, tests: ["persisted_owner_binding", "main_inheritance", "no_public_secret",
    "selected_digest_recheck", "duplicate_owner_rejection", "owner_mismatch_rejection", "unlisted_owner_rejection",
    "default_owner_scope", "read_only_file_guard", "write_open_guard", "network_guard", "child_guard", "captured_diagnostics"] }) + "\n");
