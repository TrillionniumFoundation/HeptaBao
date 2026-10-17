#!/usr/bin/env node
/** Read existing, explicit owner stores through the unchanged actual SDK.
 * inspect: public metadata only. export: selected records stay in a new private
 * directory on the source host. Neither operation resolves a provider key,
 * refreshes OAuth, imports external CLI profiles, or changes a production store.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import dns from "node:dns";
import childProcess from "node:child_process";
import path from "node:path";
import { syncBuiltinESMExports } from "node:module";
import { pathToFileURL } from "node:url";

const LIMIT = 2 * 1024 * 1024;
const SDK_FILES = {
  "dist/store-DH33UrUj.js": "25a5c7075e13b8fb32f498a90e5ee91d93b7e15972b3b74796f1325b5ba98ebf",
  "dist/source-check-ZSz5NzGW.js": "9c02bbf2df3cf123efe8c34c423ae4ea044371aab91d727f38986351695ce1c9",
  "dist/sqlite-B1ze-fre.js": "ed940f0ba0877eea0f00b2da30e727714993db60156fefc6fe80ac8564984c50",
  "dist/plugin-sdk/agent-runtime.js": "7831532d17eeaddd62889b2e8bb7b65ea7a7851901f69ceec23607a8c579dd95",
  "dist/agent-scope-config-BxAUeF6t.js": "83ef65476ae41bfcf040b1503f468074f36d602e9fa46551822cb7768bef3a1f",
};
export const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === "object"
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
export const sha = value => crypto.createHash("sha256").update(value).digest("hex");
export const credentialDigest = value => sha(JSON.stringify(stable(value)));
export const identityDigest = value => credentialDigest(Object.fromEntries(
  ["provider", "type", "email", "accountId", "projectId"].map(key => [key, value[key] ?? null])));
const safeLabel = value => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:\-]{0,99}$/.test(value) ? value : null;
function fail(code) { throw Object.assign(new Error(code), { sourceCode: code }); }
function requireValue(value, code) { if (!value) fail(code); }
function within(root, target) {
  const relative = path.relative(root, target);
  return relative === "" || (relative !== ".." && !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative));
}
function ownedDirectory(directory, privateOnly = false) {
  requireValue(path.isAbsolute(directory) && fs.realpathSync(directory) === path.resolve(directory), "source_directory_alias_rejected");
  const info = fs.lstatSync(directory);
  requireValue(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid()
    && (!privateOnly || (info.mode & 0o777) === 0o700), "source_directory_custody_invalid");
}
function readFile(filename, privateOnly = false, maximum = LIMIT) {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(fd);
    requireValue(before.isFile() && before.size <= maximum
      && (!privateOnly || (before.uid === process.getuid() && (before.mode & 0o777) === 0o600)), "source_file_custody_invalid");
    const value = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    requireValue(value.length <= maximum && before.ino === after.ino && before.dev === after.dev
      && before.size === after.size && before.mtimeMs === after.mtimeMs, "source_file_changed_during_read");
    return value;
  } finally { fs.closeSync(fd); }
}
function writeExclusive(filename, value) {
  const bytes = Buffer.from(JSON.stringify(value) + "\n");
  requireValue(bytes.length <= 8 * LIMIT, "source_output_bound_exceeded");
  const fd = fs.openSync(filename, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const parent = fs.openSync(path.dirname(filename), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
  return sha(bytes);
}
function rememberSecrets(value, secrets) {
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    if (/^(?:key|access|refresh|token|password|clientSecret|client_secret|secret)$/i.test(key)
        && typeof item === "string" && item.length >= 8) secrets.add(item);
    else if (item && typeof item === "object") rememberSecrets(item, secrets);
  }
}
function requireRedacted(value, secrets) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  requireValue([...secrets].every(secret => !text.includes(secret)), "public_source_evidence_contains_credential");
}
function checkSdk(root) {
  const observed = {};
  for (const [relative, expected] of Object.entries(SDK_FILES)) {
    observed[relative] = sha(readFile(path.join(root, relative)));
    requireValue(observed[relative] === expected, "actual_sdk_contract_fingerprint_changed");
  }
  const version = JSON.parse(readFile(path.join(root, "package.json"))).version;
  requireValue(version === "2026.7.1-2", "actual_sdk_version_changed");
  return { version, files: observed };
}

/** Guards cover JS writes, child creation and all normal network paths. The
 * pinned SDK SQLite adapter separately opens DatabaseSync({readOnly:true}). */
export function protectReadPhase(diagnostics) {
  const changes = [];
  const replace = (object, key, value) => {
    if (typeof object[key] !== "function") return;
    changes.push([object, key, object[key]]); object[key] = value;
  };
  const denied = () => fail("sdk_attempted_mutation_or_network");
  for (const prefix of ["writeFile", "appendFile", "mkdir", "mkdtemp", "rename", "unlink", "rm", "rmdir", "copyFile", "cp", "link", "symlink", "truncate", "chmod", "chown", "utimes", "write", "writev"]) {
    replace(fs, prefix, denied); replace(fs, prefix + "Sync", denied); replace(fsp, prefix, denied);
  }
  const readOnlyFlags = flags => typeof flags === "string" ? ["r", "rs", "sr"].includes(flags)
    : Number.isInteger(flags) && !(flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND));
  for (const [object, name] of [[fs, "openSync"], [fs, "open"], [fsp, "open"]]) {
    const original = object[name];
    replace(object, name, function (filename, flags, ...rest) {
      requireValue(readOnlyFlags(flags), "sdk_attempted_writable_open");
      return original.call(this, filename, flags, ...rest);
    });
  }
  for (const object of [http, https]) for (const key of ["request", "get"]) replace(object, key, denied);
  replace(net.Socket.prototype, "connect", denied);
  for (const key of ["lookup", "lookupService", "resolve", "resolve4", "resolve6", "resolveAny", "resolveCname", "resolveMx", "resolveTxt", "reverse"]) {
    replace(dns, key, denied); replace(dns.promises, key, denied);
  }
  for (const key of ["exec", "execFile", "execSync", "execFileSync", "spawn", "spawnSync", "fork"]) replace(childProcess, key, denied);
  const previousFetch = globalThis.fetch; globalThis.fetch = denied;
  const capture = name => function (chunk, encoding, callback) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), typeof encoding === "string" ? encoding : "utf8");
    diagnostics.bytes += bytes.length;
    if (diagnostics.bytes > LIMIT) fail("sdk_diagnostic_bound_exceeded");
    diagnostics[name].push(bytes);
    if (typeof encoding === "function") encoding(); else if (typeof callback === "function") callback();
    return true;
  };
  replace(process.stdout, "write", capture("stdout")); replace(process.stderr, "write", capture("stderr"));
  syncBuiltinESMExports();
  return () => {
    for (const [object, key, original] of changes.reverse()) object[key] = original;
    globalThis.fetch = previousFetch; syncBuiltinESMExports();
  };
}

/** The fake-SDK regression calls this same ownership/selection code. Real
 * execution supplies the unchanged, hash-bound SDK and existing SQLite paths. */
export function collectOwnedProfiles(sdk, agentDirs, defaultAgentDir, secrets = new Set()) {
  const allowed = new Set(agentDirs.map(value => path.resolve(value)));
  requireValue(allowed.has(path.resolve(defaultAgentDir)), "default_owner_not_explicitly_allowed");
  const rows = [], values = new Map();
  for (const agentDir of agentDirs) {
    sdk.clearRuntimeAuthProfileStoreSnapshots();
    const store = sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir, { allowKeychainPrompt: false });
    const profiles = Object.entries(store.profiles ?? {});
    requireValue(profiles.length <= 128, "source_profile_bound_exceeded");
    for (const [profileId, credential] of profiles) {
      rememberSecrets(credential, secrets);
      const ownerDir = path.resolve(sdk.resolvePersistedAuthProfileOwnerAgentDir({ agentDir, profileId }) ?? defaultAgentDir);
      requireValue(allowed.has(ownerDir), "sdk_resolved_unlisted_owner_directory");
      const persisted = sdk.findPersistedAuthProfileCredential({ agentDir: ownerDir, profileId });
      rememberSecrets(persisted, secrets);
      const currentDigest = credentialDigest(credential);
      const ownerMatches = Boolean(persisted) && credentialDigest(persisted) === currentDigest;
      const idHash = sha(profileId);
      const row = {
        scopeAgentDir: agentDir, ownerAgentDir: ownerDir, ownerDatabasePath: path.join(ownerDir, "openclaw-agent.sqlite"),
        profileIdSha256: idHash, provider: safeLabel(credential.provider), type: safeLabel(credential.type),
        credentialFieldNames: Object.keys(credential).sort(), credentialDigest: currentDigest, identityDigest: identityDigest(credential),
        persistedOwnerMatchesEffective: ownerMatches, inheritedFromMain: ownerDir !== path.resolve(agentDir),
        hasSecretReference: ["keyRef", "tokenRef", "accessRef", "refreshRef"].some(key => credential[key] !== undefined),
        expiresMs: Number.isFinite(credential.expires) ? credential.expires : null,
        expiredAtInspection: Number.isFinite(credential.expires) ? credential.expires <= Date.now() : null,
        providerLivenessVerified: false, oauthRefreshAttempted: false,
      };
      rows.push(row);
      values.set(agentDir + "\0" + idHash, { profileId, credential, row });
    }
  }
  return { rows, values };
}

export function selectOwnedProfiles(selection, inspectedRows, current) {
  requireValue(Array.isArray(selection) && selection.length > 0 && selection.length <= 64, "explicit_export_selection_required");
  const result = [], unique = new Set();
  for (const item of selection) {
    requireValue(item && typeof item === "object" && Object.keys(item).sort().join(",") ===
      "credentialDigest,identityDigest,ownerAgentDir,profileIdSha256,scopeAgentDir", "export_selection_shape_invalid");
    const existing = inspectedRows.find(row => row.scopeAgentDir === item.scopeAgentDir && row.profileIdSha256 === item.profileIdSha256);
    requireValue(existing?.persistedOwnerMatchesEffective === true
      && ["ownerAgentDir", "credentialDigest", "identityDigest"].every(key => existing[key] === item[key]), "export_selection_not_in_inspection");
    const value = current.values.get(item.scopeAgentDir + "\0" + item.profileIdSha256);
    requireValue(value?.row.persistedOwnerMatchesEffective === true
      && ["ownerAgentDir", "credentialDigest", "identityDigest"].every(key => value.row[key] === item[key]), "owned_source_changed_since_inspection");
    const key = item.ownerAgentDir + "\0" + item.profileIdSha256;
    requireValue(!unique.has(key), "duplicate_source_owner_export"); unique.add(key);
    result.push(value);
  }
  return result;
}

async function execute(config, report, secrets, diagnostics) {
  requireValue(config.schema === "authbus-owned-sdk-source-v1" && ["inspect", "export"].includes(config.mode), "source_config_schema_invalid");
  requireValue(safeLabel(config.hostId) && path.isAbsolute(config.sdkRoot) && path.isAbsolute(config.stateDir)
    && path.isAbsolute(config.configPath) && path.isAbsolute(config.outputDir), "source_config_paths_invalid");
  requireValue(Array.isArray(config.agentDirs) && config.agentDirs.length > 0 && config.agentDirs.length <= 64
    && new Set(config.agentDirs).size === config.agentDirs.length, "explicit_source_directories_required");
  ownedDirectory(config.stateDir); readFile(config.configPath, true);
  requireValue(config.configPath === path.join(config.stateDir, "openclaw.json"), "source_config_scope_mismatch");
  for (const directory of config.agentDirs) {
    ownedDirectory(directory);
    const db = path.join(directory, "openclaw-agent.sqlite");
    // Checking custody never prints database bytes or forces a WAL checkpoint.
    const info = fs.lstatSync(db);
    requireValue(info.isFile() && !info.isSymbolicLink() && info.uid === process.getuid()
      && (info.mode & 0o077) === 0, "existing_owned_sqlite_required");
  }
  requireValue(!fs.existsSync(config.outputDir) && !within(config.stateDir, config.outputDir)
    && !within(config.sdkRoot, config.outputDir) && config.agentDirs.every(dir => !within(dir, config.outputDir)), "new_private_export_directory_required");
  ownedDirectory(path.dirname(config.outputDir));
  const contract = checkSdk(config.sdkRoot);
  const configSha = sha(readFile(config.configPath, true));
  let inspected;
  if (config.mode === "export") {
    requireValue(typeof config.inspectReceiptPath === "string" && /^[0-9a-f]{64}$/.test(config.inspectReceiptSha256), "inspection_receipt_binding_required");
    const bytes = readFile(config.inspectReceiptPath, true);
    requireValue(sha(bytes) === config.inspectReceiptSha256, "inspection_receipt_fingerprint_changed");
    inspected = JSON.parse(bytes);
    requireValue(inspected.schema === "authbus-owned-sdk-source-public-v1" && inspected.mode === "inspect" && inspected.ok === true
      && inspected.hostId === config.hostId && inspected.stateDir === config.stateDir
      && inspected.configSha256 === configSha && JSON.stringify(inspected.sdkContract) === JSON.stringify(contract), "inspection_scope_changed");
  }
  fs.mkdirSync(config.outputDir, { mode: 0o700 }); ownedDirectory(config.outputDir, true);
  report.outputDir = config.outputDir;
  report.mode = config.mode; report.hostId = config.hostId; report.stateDir = config.stateDir;
  report.configSha256 = configSha; report.sdkContract = contract; report.agentDirs = config.agentDirs;
  process.env.OPENCLAW_STATE_DIR = config.stateDir;
  process.env.OPENCLAW_CONFIG_PATH = config.configPath;
  process.env.OPENCLAW_AUTH_STORE_READONLY = "1";
  delete process.env.NODE_OPTIONS; delete process.env.NODE_PATH;
  let selected = [], sdk, defaultAgentDir;
  const restore = protectReadPhase(diagnostics);
  try {
    sdk = await import(pathToFileURL(path.join(config.sdkRoot, "dist/plugin-sdk/agent-runtime.js")).href);
    defaultAgentDir = path.resolve(sdk.resolveDefaultAgentDir({}));
    requireValue(config.agentDirs.includes(defaultAgentDir), "default_owner_not_explicitly_allowed");
    const current = collectOwnedProfiles(sdk, config.agentDirs, defaultAgentDir, secrets);
    report.defaultAgentDir = defaultAgentDir; report.profiles = current.rows;
    report.profileCount = current.rows.length;
    if (config.mode === "export") selected = selectOwnedProfiles(config.selection, inspected.profiles, current);
  } finally { restore(); }
  requireValue(sha(readFile(config.configPath, true)) === configSha, "production_config_changed_during_inspection");
  checkSdk(config.sdkRoot);
  if (config.mode === "export") {
    // A second fresh SDK read closes the obvious import/export race. It is an
    // observed source snapshot, not a promise against future OAuth rotation.
    const restoreAgain = protectReadPhase(diagnostics);
    try {
      const reloaded = collectOwnedProfiles(sdk, config.agentDirs, defaultAgentDir, secrets);
      selected = selectOwnedProfiles(config.selection, inspected.profiles, reloaded);
    } finally { restoreAgain(); }
    const candidate = {
      schema: "authbus-owned-sdk-source-snapshot-v1", createdAt: new Date().toISOString(),
      hostId: config.hostId, stateDir: config.stateDir, sdkContract: contract, configSha256: configSha,
      inspectReceiptSha256: config.inspectReceiptSha256,
      profiles: selected.map(value => ({ profileId: value.profileId, credential: value.credential,
        digest: value.row.credentialDigest, identity: value.row.identityDigest,
        source: { scopeAgentDir: value.row.scopeAgentDir, ownerAgentDir: value.row.ownerAgentDir,
                  databasePath: value.row.ownerDatabasePath, method: "actual_sdk_readonly_persisted_owner" } })),
      constraints: { providerLivenessVerified: false, oauthRefreshed: false, productionCutover: false,
                     snapshotRequiresRecheckBeforePublication: true, coordinatorOwnershipQualified: false },
    };
    const candidatePath = path.join(config.outputDir, "candidate.private.json");
    const candidateSha = writeExclusive(candidatePath, candidate);
    try {
      const restoreAfterExport = protectReadPhase(diagnostics);
      try {
        const afterExport = collectOwnedProfiles(sdk, config.agentDirs, defaultAgentDir, secrets);
        selectOwnedProfiles(config.selection, inspected.profiles, afterExport);
      } finally { restoreAfterExport(); }
      requireValue(sha(readFile(config.configPath, true)) === configSha, "production_config_changed_during_export");
      requireValue(sha(readFile(candidatePath, true, 8 * LIMIT)) === candidateSha, "private_candidate_changed_after_export");
    } catch (error) {
      // This file was created by this operation with O_EXCL in a new owned
      // directory. Remove only this unqualified snapshot; no source is edited.
      fs.unlinkSync(candidatePath);
      const parent = fs.openSync(config.outputDir, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
      try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
      throw error;
    }
    report.privateCandidateSha256 = candidateSha;
    report.privateCandidatePath = candidatePath; report.exportedProfileCount = selected.length;
    report.privateCandidateMode = "0o600";
    report.persistedOwnerRecheckedAfterExport = true;
  }
  report.sdkDiagnosticBytes = diagnostics.bytes;
  report.sdkDiagnosticSha256 = sha(Buffer.concat([...diagnostics.stdout, ...diagnostics.stderr]));
  report.actualSdkReadOnlyOwnerApiUsed = true;
  report.providerLivenessVerified = false; report.productionStoreWriteAttempted = false;
  report.sourceSnapshotNotARefreshLease = true;
  report.ok = true;
}

async function cli() {
  const report = { schema: "authbus-owned-sdk-source-public-v1", createdAt: new Date().toISOString(), ok: false,
    readOnlyProductionAccess: true, productionMutation: false, productionCutover: false,
    providerCalled: false, oauthRefreshed: false, externalCliProfilesImported: false, j3160Contacted: false };
  const secrets = new Set(); const diagnostics = { bytes: 0, stdout: [], stderr: [] };
  // Keep SDK diagnostics private for the entire process, including queued
  // warnings after an awaited import/read returns. Only this retained writer
  // can emit the explicitly constructed public JSON.
  const publicWrite = process.stdout.write.bind(process.stdout);
  for (const name of ["stdout", "stderr"]) process[name].write = function (chunk, encoding, callback) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), typeof encoding === "string" ? encoding : "utf8");
    diagnostics.bytes += bytes.length;
    if (diagnostics.bytes <= LIMIT) diagnostics[name].push(bytes);
    if (typeof encoding === "function") encoding(); else if (typeof callback === "function") callback();
    return true;
  };
  let config, code = 2;
  try {
    requireValue(process.argv.length === 3, "one_private_source_config_required");
    config = JSON.parse(readFile(process.argv[2], true));
    await execute(config, report, secrets, diagnostics);
    requireValue(diagnostics.bytes <= LIMIT, "sdk_diagnostic_bound_exceeded");
    requireRedacted(report, secrets); code = 0;
  } catch (error) {
    report.ok = false; report.error = error.sourceCode ?? "unexpected_sdk_source_error";
    report.errorClass = safeLabel(error?.name) ?? "Error";
  }
  let publicPath;
  try {
    requireRedacted(report, secrets);
    if (report.outputDir) {
      publicPath = path.join(report.outputDir, "public-receipt.json");
      const receiptSha = writeExclusive(publicPath, report);
      const summary = { schema: report.schema, ok: report.ok, mode: report.mode, hostId: report.hostId,
        profileCount: report.profileCount, exportedProfileCount: report.exportedProfileCount ?? 0,
        publicReceiptPath: publicPath, publicReceiptSha256: receiptSha,
        privateCandidatePath: report.privateCandidatePath, privateCandidateSha256: report.privateCandidateSha256,
        productionMutation: false, providerLivenessVerified: false, error: report.error };
      requireRedacted(summary, secrets); publicWrite(JSON.stringify(summary) + "\n");
    } else publicWrite(JSON.stringify(report) + "\n");
  } catch {
    publicWrite(JSON.stringify({ schema: report.schema, ok: false, error: "public_receipt_refused", productionMutation: false }) + "\n");
    code = 2;
  }
  process.exitCode = code;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) await cli();
