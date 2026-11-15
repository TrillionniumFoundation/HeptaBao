import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { pathToFileURL } from "node:url";

const hash = value => crypto.createHash("sha256").update(value).digest("hex");
const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
const candidatePath = process.argv[2];
const sdkResolverPath = process.argv[3];
const catalogPath = process.argv[4], aliasPath = process.argv[5];
if (!candidatePath || !sdkResolverPath || !catalogPath || !aliasPath)
  throw new Error("runner and exact SDK resolver/catalog/alias source paths required");
const candidate = fs.readFileSync(candidatePath, "utf8");
const originalResolver = fs.readFileSync(sdkResolverPath, "utf8");
const catalog = fs.readFileSync(catalogPath, "utf8"), aliases = fs.readFileSync(aliasPath, "utf8");
if (hash(originalResolver) !== "b38ffc9ed9d1de4b79213bf9aab474985ae62127ba5f148b14433d8cbb51b7b9")
  throw new Error("actual SDK package resolver hash changed");
if (hash(catalog) !== "046b4e9b63337848e1801407305d711695aa6b1858b8c59ee6afcb4e39f8a5b8" ||
    hash(aliases) !== "a08f997f961d42aedf70699cfcb52b2785861412131cd718234aa31eca1dcb32")
  throw new Error("actual SDK discovery caller hash changed");
const start = candidate.indexOf("function selectOwnedSdkEntrypoint(sdkRoot) {");
const end = candidate.indexOf("\nconst args = {};", start);
if (start < 0 || end < 0) throw new Error("candidate discovery selector not found");
const select = new Function("fs", "path", "hash", "fail", candidate.slice(start, end) + "\nreturn selectOwnedSdkEntrypoint;")(fs, path, hash, fail);
const sdkResolver = await import("data:text/javascript;base64," + Buffer.from(originalResolver).toString("base64"));
function extractFunction(source, startToken, endToken) {
  const start = source.indexOf(startToken), end = source.indexOf(endToken, start);
  if (start < 0 || end < 0) throw new Error("bound SDK caller span missing");
  return source.slice(start, end);
}
const root = fs.mkdtempSync(path.join(os.tmpdir(), "authbus-owner-discovery-"));
const sdkRoot = path.join(root, "sdk"), packagePath = path.join(sdkRoot, "package.json");
const outside = path.join(root, "unowned", "fixture", "runner.mjs");
const outsideCwd = path.join(root, "unowned-cwd", "fixture"), outsideAlias = path.join(root, "unowned-alias", "fixture", "runner.mjs");
fs.mkdirSync(path.dirname(outside), { recursive: true });
fs.mkdirSync(outsideCwd, { recursive: true });
fs.mkdirSync(path.dirname(outsideAlias), { recursive: true });
fs.mkdirSync(path.join(sdkRoot, "dist"), { recursive: true });
fs.writeFileSync(outside, "export {};\n");
fs.writeFileSync(outsideAlias, "export {};\n");
fs.writeFileSync(path.join(sdkRoot, "openclaw.mjs"), "export {};\n");
const pkg = { name: "openclaw", version: "2026.7.1-2", bin: { openclaw: "openclaw.mjs" } };
const writePackage = value => fs.writeFileSync(packagePath, JSON.stringify(value));
writePackage(pkg);
const checks = [];
function check(name, condition) {
  if (!condition) throw new Error(name);
  checks.push(name);
}
function rejects(name, action, code) {
  let error;
  try { action(); } catch (caught) { error = caught; }
  check(name, Boolean(error) && (!code || error.diagnosticCode === code));
}
const previousRead = fs.readFileSync;
const previousOpen = fs.openSync, previousCwd = process.cwd();
let outsideReads = 0;
try {
  const checkRead = filename => {
    if (typeof filename === "number") return;
    const absolute = path.resolve(filename instanceof URL ? filename.pathname : String(filename));
    if (!absolute.startsWith(sdkRoot + path.sep)) { outsideReads++; throw new Error("outside SDK package fixture read blocked"); }
  };
  fs.readFileSync = function (filename, ...options) {
    checkRead(filename);
    return previousRead.call(this, filename, ...options);
  };
  fs.openSync = function (filename, ...options) {
    checkRead(filename);
    return previousOpen.call(this, filename, ...options);
  };
  check("actual_sdk_external_qa_argv_reproduces_metadata_probe", sdkResolver.n({ argv1: outside }) === null && outsideReads > 0);
  outsideReads = 0;
  const discovery = select(sdkRoot);
  check("declared_package_bin_selected_without_execution", discovery.entrypoint === path.join(sdkRoot, "openclaw.mjs") && discovery.relative === "openclaw.mjs");
  check("actual_sdk_owned_argv_resolves_exact_package", sdkResolver.n({ argv1: discovery.entrypoint }) === sdkRoot);
  check("actual_sdk_owned_module_and_argv_resolve_exact_package", sdkResolver.n({
    moduleUrl: pathToFileURL(path.join(sdkRoot, "dist", "fixture.mjs")).href, argv1: discovery.entrypoint,
  }) === sdkRoot);
  check("actual_sdk_owned_discovery_has_zero_outside_reads", outsideReads === 0);
  const listPackageRoots = new Function("resolveOpenClawPackageRootSync", "uniqueStrings", "ownedModuleUrl",
    extractFunction(catalog, "function listPackageRoots() {", "function readBundledExtensionCatalogEntriesSync() {")
      .replace("import.meta.url", "ownedModuleUrl") + "\nreturn listPackageRoots;")(
        sdkResolver.n, values => [...new Set(values)], pathToFileURL(path.join(sdkRoot, "dist", "catalog.mjs")).href);
  process.chdir(outsideCwd);
  check("actual_channel_cwd_probe_reproduced_despite_owned_module", listPackageRoots().includes(sdkRoot) && outsideReads > 0);
  outsideReads = 0;
  process.chdir(sdkRoot);
  check("actual_channel_owned_cwd_has_zero_outside_reads", listPackageRoots().includes(sdkRoot) && outsideReads === 0);
  const rootIndicator = new Function("fs", "path", "normalizeLowercaseStringOrEmpty",
    extractFunction(aliases, "function hasTrustedOpenClawRootIndicator(params) {", "function readPluginSdkSubpathsFromPackageRoot(packageRoot) {")
      + "\nreturn hasTrustedOpenClawRootIndicator;")(fs, path, value => String(value).trim().toLowerCase());
  const resolveAliasRoot = new Function("resolveOpenClawPackageRootSync", "readPluginSdkPackageJson", "hasTrustedOpenClawRootIndicator",
    extractFunction(aliases, "function resolveTrustedOpenClawRootFromArgvHint(params) {", "function findNearestPluginSdkPackageRoot(startDir, maxDepth = 12) {")
      + "\nreturn resolveTrustedOpenClawRootFromArgvHint;")(
        sdkResolver.n, directory => JSON.parse(fs.readFileSync(path.join(directory, "package.json"))), rootIndicator);
  writePackage({ ...pkg, exports: { "./plugin-sdk": "./dist/plugin-sdk/index.js" } });
  check("actual_alias_external_argv_probe_reproduced_despite_owned_cwd", resolveAliasRoot({
    cwd: path.join(sdkRoot, "dist"), argv1: outsideAlias,
  }) === sdkRoot && outsideReads > 0);
  outsideReads = 0;
  check("actual_alias_owned_argv_has_zero_outside_reads", resolveAliasRoot({
    cwd: path.join(sdkRoot, "dist"), argv1: discovery.entrypoint,
  }) === sdkRoot && outsideReads === 0);
  writePackage(pkg);
  check("discovery_identity_stable_on_recheck", JSON.stringify(select(sdkRoot)) === JSON.stringify(discovery));
  fs.writeFileSync(path.join(sdkRoot, "openclaw.mjs"), "export const changed = true;\n");
  check("entrypoint_change_changes_discovery_identity", select(sdkRoot).entrypointSha256 !== discovery.entrypointSha256);
  for (const [name, value] of [
    ["wrong-package", { ...pkg, name: "another-sdk" }],
    ["wrong-version", { ...pkg, version: "unknown" }],
    ["missing-bin", { ...pkg, bin: {} }],
    ["absolute-bin", { ...pkg, bin: { openclaw: outside } }],
    ["parent-bin", { ...pkg, bin: { openclaw: "../unowned/fixture/runner.mjs" } }],
  ]) {
    writePackage(value);
    rejects("discovery_rejects_" + name, () => select(sdkRoot), "trusted_refresh_caller_sdk_discovery_package_invalid");
  }
  writePackage({ ...pkg, bin: { openclaw: "escape.mjs" } });
  fs.symlinkSync(outside, path.join(sdkRoot, "escape.mjs"));
  rejects("discovery_rejects_symlink_before_content_read", () => select(sdkRoot), "trusted_refresh_caller_sdk_discovery_symlink_forbidden");
  writePackage(pkg);
  fs.writeFileSync(packagePath, " ".repeat(262145));
  rejects("discovery_rejects_oversize_package_before_parse", () => select(sdkRoot), "trusted_refresh_caller_sdk_discovery_file_invalid");
  check("all_rejections_preserve_zero_outside_reads", outsideReads === 0);
} finally {
  fs.readFileSync = previousRead;
  fs.openSync = previousOpen;
  process.chdir(previousCwd);
  fs.rmSync(root, { recursive: true, force: true });
}
process.stdout.write(JSON.stringify({ schema: "authbus-sdk-owner-discovery-r5-unit", actualSdkModuleSource: true,
  actualSdkInstalledExecution: false, actualNativeHeptaBao: false, actualProvider: false,
  candidateSha256: hash(candidate), sdkResolverSha256: hash(originalResolver),
  catalogSha256: hash(catalog), aliasSha256: hash(aliases), checksPassed: checks.length, checks }, null, 2) + "\n");
