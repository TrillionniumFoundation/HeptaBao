#!/usr/bin/env node
/** Actual SDK/SQLite OAuth storage runner. No provider I/O, production state,
 * external CLI synchronization or native HeptaBao qualification is performed. */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import net from "node:net";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { digest } from "./authbus_admission_authority_candidate.mjs";
import { installRefreshStoreSdkCandidate, verifyRefreshStoreSdkUnchanged } from "./authbus_refresh_store_sdk_candidate.mjs";
const args = {};
const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
const hash = value => crypto.createHash("sha256").update(value).digest("hex");
for (let i = 2; i < process.argv.length; i += 2) {
  if (!["--openclaw-root", "--work-dir"].includes(process.argv[i]) || !path.isAbsolute(process.argv[i + 1] ?? "")) fail("trusted_refresh_absolute_cli_required");
  args[process.argv[i]] = path.resolve(process.argv[i + 1]);
}
if (!args["--openclaw-root"] || !args["--work-dir"]) fail("trusted_refresh_missing_cli_argument");
process.umask(0o077);
const root = args["--work-dir"], sdkRoot = fs.realpathSync(args["--openclaw-root"]), here = path.dirname(fileURLToPath(import.meta.url));
fs.mkdirSync(root, { mode: 0o700 });
const state = path.join(root, "state"), agent = path.join(state, "agents/main/agent"), hostHomeDirectory = os.homedir();
for (const part of [state, path.join(state, "agents"), path.join(state, "agents/main"), agent,
  path.join(state, "home"), path.join(state, "credentials")]) fs.mkdirSync(part, { mode: 0o700 });
const cfgPath = path.join(state, "openclaw.json");
fs.writeFileSync(cfgPath, JSON.stringify({ agents: { list: [{ id: "main", default: true, agentDir: agent }] } }) + "\n", { mode: 0o600 });
process.env.OPENCLAW_STATE_DIR = state; process.env.OPENCLAW_CONFIG_PATH = cfgPath;
process.env.OPENCLAW_HOME = path.join(state, "home"); process.env.OPENCLAW_OAUTH_DIR = path.join(state, "credentials");
for (const key of ["GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENCLAW_GATEWAY_TOKEN"]) delete process.env[key];
if (process.env.OPENCLAW_AUTH_STORE_READONLY === "1") fail("trusted_refresh_inherited_readonly_store");
const report = { schema: "authbus-refresh-r5-actual-sdk-store", ok: false, syntheticCredentials: true,
  actualSdk: false, actualSqlite: false, actualSdkOAuthRefreshCaller: false, actualProviderRefresh: false,
  actualNativeHeptaBao: false, productionMutation: false, externalNetworkAttempts: 0, externalProcessAttempts: 0,
  outsideFixtureWriteAttempts: 0, outsideFixtureHomeReadAttempts: 0, checks: [],
  sourceManifest: ["authbus_refresh_sdk_store_live.mjs", "authbus_refresh_store_sdk_candidate.mjs", "authbus_sdk_explicit_deny_candidate.mjs", "authbus_admission_authority_candidate.mjs"]
    .map(name => ({ name, sha256: hash(fs.readFileSync(path.join(here, name))) })) };
const check = (name, passed) => { report.checks.push({ case: name, passed: Boolean(passed) }); if (!passed) fail(name); };
const inside = (candidate, directory) => candidate === directory || candidate.startsWith(directory + path.sep);
const asPath = value => value instanceof URL ? fileURLToPath(value) : Buffer.isBuffer(value) ? value.toString("utf8") : typeof value === "string" ? value : null;
const checkWrite = value => { const decoded = asPath(value); if (decoded !== null) {
  const absolute = path.resolve(decoded);
  if (!inside(absolute, root)) { report.outsideFixtureWriteAttempts++; fail("trusted_refresh_outside_fixture_write_forbidden"); }
  let current = root;
  for (const part of path.relative(root, absolute).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try { if (fs.lstatSync(current).isSymbolicLink()) { report.outsideFixtureWriteAttempts++; fail("trusted_refresh_fixture_symlink_write_forbidden"); } }
    catch (error) { if (error.code === "ENOENT") break; throw error; }
  }
} };
const checkRead = value => { const decoded = asPath(value); if (decoded !== null) { const absolute = path.resolve(decoded);
  if (inside(absolute, hostHomeDirectory) && !inside(absolute, root) && !inside(absolute, sdkRoot)) {
    report.outsideFixtureHomeReadAttempts++; fail("trusted_refresh_external_home_read_forbidden");
  }
} };
const originals = [], guard = (object, name, inspect) => {
  const fn = object[name]; if (typeof fn !== "function") return;
  originals.push(() => { object[name] = fn; }); object[name] = function (...values) { inspect(values); return fn.apply(this, values); };
};
const isWrite = flags => typeof flags === "string" ? /[wa+]/.test(flags) : Number.isInteger(flags) && Boolean(flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND));
let hook, database;
try {
  guard(net.Socket.prototype, "connect", () => { report.externalNetworkAttempts++; fail("trusted_refresh_network_forbidden"); });
  for (const name of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]) guard(childProcess, name, () => { report.externalProcessAttempts++; fail("trusted_refresh_external_process_forbidden"); });
  for (const object of [fs, fs.promises]) {
    for (const name of ["writeFile", "writeFileSync", "appendFile", "appendFileSync", "mkdir", "mkdirSync", "mkdtemp", "mkdtempSync", "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync", "truncate", "truncateSync", "chmod", "chmodSync", "chown", "chownSync", "createWriteStream"])
      guard(object, name, values => checkWrite(values[0]));
    for (const name of ["symlink", "symlinkSync"]) guard(object, name, values => {
      checkWrite(values[1]); checkWrite(path.resolve(path.dirname(asPath(values[1])), asPath(values[0])));
    });
    for (const name of ["rename", "renameSync", "link", "linkSync"]) guard(object, name, values => { checkWrite(values[0]); checkWrite(values[1]); });
    for (const name of ["copyFile", "copyFileSync", "cp", "cpSync"]) guard(object, name, values => { checkRead(values[0]); checkWrite(values[1]); });
    for (const name of ["open", "openSync"]) guard(object, name, values => isWrite(values[1]) ? checkWrite(values[0]) : checkRead(values[0]));
    for (const name of ["readFile", "readFileSync", "createReadStream"]) guard(object, name, values => checkRead(values[0]));
  }
  syncBuiltinESMExports();
  hook = installRefreshStoreSdkCandidate(sdkRoot, report);
  const sdk = await import(pathToFileURL(path.join(sdkRoot, "dist/plugin-sdk/agent-runtime.js")).href);
  const bridge = await import(pathToFileURL(path.join(sdkRoot, "dist/profiles-DyU-YCq2.js")).href);
  check("all_exact_store_modules_loaded", report.refreshStoreSdkModules.every(item => item.loaded));
  check("managed_commit_bridge_loaded", typeof bridge.heptaBaoCommitManagedOAuthCredential === "function");
  report.actualSdk = true; report.sdkVersion = JSON.parse(fs.readFileSync(path.join(sdkRoot, "package.json"))).version;
  const profileId = "openai-codex:authbus-r5-fixture", unrelatedId = "fixture:unrelated";
  const original = { type: "oauth", provider: "openai-codex", access: "synthetic-r5-old-access", refresh: "synthetic-r5-old-refresh", expires: Date.now() + 30000 };
  const unrelated = { type: "api_key", provider: "fixture", key: "synthetic-r5-unrelated" };
  const newer = { ...original, access: "synthetic-r5-new-access", refresh: "synthetic-r5-new-refresh", expires: Date.now() + 60000 };
  const third = { ...newer, access: "synthetic-r5-third-access", refresh: "synthetic-r5-third-refresh", expires: Date.now() + 90000 };
  const read = () => { sdk.clearRuntimeAuthProfileStoreSnapshots(); return sdk.loadAuthProfileStoreWithoutExternalProfiles(agent, { allowKeychainPrompt: false }); };
  const databasePath = path.join(agent, "openclaw-agent.sqlite");
  check("actual_sqlite_initially_absent", !fs.existsSync(databasePath));
  sdk.saveAuthProfileStore({ version: 1, profiles: { [profileId]: original, [unrelatedId]: unrelated },
    order: { "openai-codex": [profileId] }, lastGood: { "openai-codex": profileId } }, agent,
    { filterExternalAuthProfiles: false, syncExternalCli: false });
  check("actual_oauth_seed_readback", digest(read().profiles[profileId]) === digest(original));
  check("actual_sqlite_created", fs.existsSync(databasePath)); report.actualSqlite = true;
  const commit = (expected, credential) => bridge.heptaBaoCommitManagedOAuthCredential({ agentDir: agent, profileId,
    expectedCredentialDigest: digest(expected), credential });
  check("actual_locked_sdk_commit_success", await commit(original, newer) === true);
  check("actual_new_oauth_readback", digest(read().profiles[profileId]) === digest(newer));
  check("unrelated_profile_preserved", digest(read().profiles[unrelatedId]) === digest(unrelated));
  check("selection_metadata_preserved", read().order?.["openai-codex"]?.[0] === profileId && read().lastGood?.["openai-codex"] === profileId);
  const beforeStale = digest(read());
  check("stale_sdk_credential_digest_rejected", await commit(original, third) === false);
  check("stale_commit_no_store_change", digest(read()) === beforeStale);
  check("cross_provider_commit_rejected", await commit(newer, { ...third, provider: "anthropic" }) === false);
  check("cross_provider_no_store_change", digest(read()) === beforeStale);
  const { DatabaseSync } = await import("node:sqlite"); database = new DatabaseSync(databasePath);
  const tables = database.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND sql NOT LIKE 'CREATE VIRTUAL%'").all();
  check("actual_sqlite_tables_found", tables.length > 0);
  const quote = value => '"' + value.replaceAll('"', '""') + '"';
  const triggerNames = [];
  for (let i = 0; i < tables.length; i++) for (const event of ["INSERT", "UPDATE"]) {
    const name = "authbus_r5_abort_" + i + "_" + event.toLowerCase(); triggerNames.push(name);
    database.exec("CREATE TRIGGER " + quote(name) + " BEFORE " + event + " ON " + quote(tables[i].name) + " BEGIN SELECT RAISE(ABORT,'synthetic_authbus_r5_commit_abort'); END");
  }
  const beforeAbort = digest(read()); let saved = null, threw = false;
  try { saved = await commit(newer, third); } catch (error) { threw = true; report.injectedErrorSha256 = hash(String(error.message)); }
  finally { for (const name of triggerNames) database.exec("DROP TRIGGER " + quote(name)); database.close(); database = null; }
  report.abortEvidence = { triggerCount: triggerNames.length, sdkSaved: saved, threw, beforeStoreDigest: beforeAbort, afterStoreDigest: digest(read()) };
  check("actual_sqlite_abort_not_reported_success", saved !== true);
  check("actual_sqlite_abort_keeps_credential", digest(read()) === beforeAbort && digest(read().profiles[profileId]) === digest(newer));
  check("actual_sdk_commit_recovers_after_abort", await commit(newer, third) === true);
  check("recovery_actual_readback", digest(read().profiles[profileId]) === digest(third));
  check("no_external_cli_or_home_write_attempt", report.outsideFixtureWriteAttempts === 0);
  check("no_external_home_credential_read", report.outsideFixtureHomeReadAttempts === 0);
  check("no_external_network_or_process", report.externalNetworkAttempts === 0 && report.externalProcessAttempts === 0);
  report.ok = true;
} catch (error) {
  report.error = { code: error.diagnosticCode ?? error.code ?? "trusted_refresh_store_runner_failure", messageSha256: hash(String(error.message)) };
} finally {
  try { database?.close(); } catch {}
  hook?.deregister();
  for (const restore of originals.reverse()) restore();
  syncBuiltinESMExports();
  try { report.installedSdkUnchanged = verifyRefreshStoreSdkUnchanged(sdkRoot); if (!report.installedSdkUnchanged) report.ok = false; }
  catch { report.ok = false; report.installedSdkUnchanged = false; }
  report.checksPassed = report.checks.filter(item => item.passed).length;
  fs.writeFileSync(path.join(root, "public-receipt.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  process.stdout.write(JSON.stringify(report) + "\n"); if (!report.ok) process.exitCode = 1;
}
