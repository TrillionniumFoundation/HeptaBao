/** Shared custody/transport limits for a disposable native R5 SDK process.
 * This is fixture plumbing. It creates no grant, provider result or KV state.
 * The package discovery and read/write restrictions retain the actual R5
 * owner-r5 boundaries; a parent-owned absolute deadline only shortens I/O.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import net from "node:net";
import dns from "node:dns";
import https from "node:https";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { fileURLToPath } from "node:url";

export const fail = code => { throw Object.assign(new Error(code), { diagnosticCode: code }); };
export const hash = value => crypto.createHash("sha256").update(value).digest("hex");
export const inside = (candidate, directory) => candidate === directory || candidate.startsWith(directory + path.sep);

export function readOwned(file, maxBytes = 262144) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.uid !== process.getuid() || (before.mode & 0o077) !== 0 ||
        before.size < 1 || before.size > maxBytes) fail("native_sdk_private_file_invalid");
    const bytes = Buffer.alloc(before.size + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = fs.readSync(fd, bytes, length, bytes.length - length, length);
      if (!count) break;
      length += count;
    }
    const after = fs.fstatSync(fd);
    if (length !== before.size || before.dev !== after.dev || before.ino !== after.ino ||
        before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs)
      fail("native_sdk_private_file_changed");
    return bytes.subarray(0, length);
  } finally { fs.closeSync(fd); }
}

export function durable(file, value, { create = false } = {}) {
  const temporary = file + ".new-" + crypto.randomUUID();
  const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT |
    fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value) + "\n"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  if (create && fs.existsSync(file)) { fs.unlinkSync(temporary); fail("native_sdk_private_destination_exists"); }
  fs.renameSync(temporary, file);
  const directory = fs.openSync(path.dirname(file), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}

// Byte-identical discovery body to the frozen, actual-127/127 owner-r5 runner.
export function selectOwnedSdkEntrypoint(sdkRoot) {
  const readSource = file => {
    const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
      const before = fs.fstatSync(fd);
      if (!before.isFile() || before.size < 1 || before.size > 262144)
        fail("trusted_refresh_caller_sdk_discovery_file_invalid");
      const bytes = Buffer.alloc(before.size + 1);
      let length = 0;
      while (length < bytes.length) {
        const count = fs.readSync(fd, bytes, length, bytes.length - length, length);
        if (!count) break;
        length += count;
      }
      const after = fs.fstatSync(fd);
      if (length !== before.size || before.dev !== after.dev || before.ino !== after.ino ||
          before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs)
        fail("trusted_refresh_caller_sdk_discovery_file_changed");
      return bytes.subarray(0, length);
    } finally { fs.closeSync(fd); }
  };
  const packageBytes = readSource(path.join(sdkRoot, "package.json"));
  const pkg = JSON.parse(packageBytes.toString("utf8"));
  const bin = pkg.bin?.openclaw;
  if (pkg.name !== "openclaw" || pkg.version !== "2026.7.1-2" || typeof bin !== "string" ||
      !bin || path.isAbsolute(bin) || bin.includes("\\") || bin.split("/").includes(".."))
    fail("trusted_refresh_caller_sdk_discovery_package_invalid");
  const entrypoint = path.resolve(sdkRoot, bin);
  if (!entrypoint.startsWith(sdkRoot + path.sep)) fail("trusted_refresh_caller_sdk_discovery_entrypoint_outside");
  let component = sdkRoot;
  for (const part of path.relative(sdkRoot, entrypoint).split(path.sep)) {
    component = path.join(component, part);
    if (fs.lstatSync(component).isSymbolicLink()) fail("trusted_refresh_caller_sdk_discovery_symlink_forbidden");
  }
  const entryBytes = readSource(entrypoint);
  return Object.freeze({ entrypoint, relative: path.relative(sdkRoot, entrypoint),
    packageSha256: hash(packageBytes), entrypointSha256: hash(entryBytes) });
}

export function installFixtureSafety({ sdkRoot, root, parentRoot, deadlineNs, controlPort, providerPort, connectProxyPort,
  certificate, report }) {
  const hostHomeDirectory = os.homedir(), allowedPorts = new Set([controlPort, providerPort, connectProxyPort]);
  if (allowedPorts.size !== 3 || ![...allowedPorts].every(port => Number.isInteger(port) && port > 1023 && port <= 65535))
    fail("native_openai_sdk_owned_listener_bindings_invalid");
  const deadline = BigInt(deadlineNs), restores = [], requests = new Set();
  let phase = "guard-install";
  const remainingMs = () => {
    const ns = deadline - process.hrtime.bigint();
    if (ns <= 0n) fail("native_sdk_original_deadline");
    return Math.max(1, Math.floor(Number(ns) / 1e6));
  };
  remainingMs();
  const asPath = value => value instanceof URL ? fileURLToPath(value) : Buffer.isBuffer(value) ? value.toString("utf8") : typeof value === "string" ? value : null;
  const checkWrite = value => {
    const decoded = asPath(value); if (decoded === null) return;
    const absolute = path.resolve(decoded);
    if (!inside(absolute, root)) { report.outsideFixtureWriteAttempts++; fail("native_sdk_outside_write_forbidden"); }
    let current = root;
    for (const part of path.relative(root, absolute).split(path.sep).filter(Boolean)) {
      current = path.join(current, part);
      try { if (fs.lstatSync(current).isSymbolicLink()) { report.outsideFixtureWriteAttempts++; fail("native_sdk_symlink_write_forbidden"); } }
      catch (error) { if (error.code === "ENOENT") break; throw error; }
    }
  };
  const checkRead = value => {
    const decoded = asPath(value); if (decoded === null) return;
    const absolute = path.resolve(decoded);
    if ((inside(absolute, hostHomeDirectory) && !inside(absolute, root) && !inside(absolute, sdkRoot)) ||
        (inside(absolute, parentRoot) && !inside(absolute, root))) {
      report.outsideFixtureHomeReadAttempts++;
      if (report.blockedHomeReads.length < 24) report.blockedHomeReads.push({ phase,
        targetSha256: hash(absolute), targetClass: path.basename(absolute) === "package.json" ? "outside-package-metadata" : "outside-owned-root",
        sdkFrames: String(new Error("owned-read-guard").stack).split("\n").filter(line => line.includes(sdkRoot + path.sep))
          .slice(0, 8).map(line => line.slice(line.indexOf(sdkRoot) + sdkRoot.length + 1).slice(0, 240)) });
      fail("native_sdk_external_private_read_forbidden");
    }
  };
  const guard = (object, name, inspect) => {
    const previous = object[name]; if (typeof previous !== "function") return;
    restores.push(() => { object[name] = previous; });
    object[name] = function (...values) { inspect(values); return previous.apply(this, values); };
  };
  const isWrite = flags => typeof flags === "string" ? /[wa+]/.test(flags) : Number.isInteger(flags) &&
    Boolean(flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND));
  guard(net.Socket.prototype, "connect", values => {
    remainingMs();
    const args = Array.isArray(values[0]) ? values[0] : values, first = args[0];
    const port = Number(typeof first === "object" && first ? first.port : first);
    const host = typeof first === "object" && first ? first.host ?? first.hostname : typeof args[1] === "string" ? args[1] : "localhost";
    if (host !== "127.0.0.1" || !allowedPorts.has(port)) { report.externalNetworkAttempts++; fail("native_sdk_external_network_forbidden"); }
  });
  for (const name of ["lookup", "resolve", "resolve4", "resolve6", "resolveAny", "resolveCname", "resolveMx", "resolveTxt", "reverse"])
    for (const object of [dns, dns.promises]) guard(object, name, values => {
      if (values[0] !== "127.0.0.1") { report.externalNetworkAttempts++; fail("native_sdk_external_dns_forbidden"); }
    });
  for (const name of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"])
    guard(childProcess, name, () => { report.externalProcessAttempts++; fail("native_sdk_external_process_forbidden"); });
  for (const object of [fs, fs.promises]) {
    for (const name of ["writeFile", "writeFileSync", "appendFile", "appendFileSync", "mkdir", "mkdirSync", "mkdtemp", "mkdtempSync",
      "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync", "truncate", "truncateSync", "chmod", "chmodSync", "chown", "chownSync", "createWriteStream"])
      guard(object, name, values => checkWrite(values[0]));
    for (const name of ["symlink", "symlinkSync"]) guard(object, name, values => {
      checkWrite(values[1]); checkWrite(path.resolve(path.dirname(asPath(values[1])), asPath(values[0])));
    });
    for (const name of ["rename", "renameSync", "link", "linkSync"]) guard(object, name, values => { checkWrite(values[0]); checkWrite(values[1]); });
    for (const name of ["copyFile", "copyFileSync", "cp", "cpSync"]) guard(object, name, values => { checkRead(values[0]); checkWrite(values[1]); });
    for (const name of ["open", "openSync"]) guard(object, name, values => isWrite(values[1]) ? checkWrite(values[0]) : checkRead(values[0]));
    for (const name of ["readFile", "readFileSync", "createReadStream"]) guard(object, name, values => checkRead(values[0]));
  }
  const originalHttpsRequest = https.request;
  https.request = function (...args) {
    const remaining = remainingMs();
    const request = originalHttpsRequest.apply(this, args);
    const timer = setTimeout(() => request.destroy(Object.assign(new Error("native_sdk_original_deadline"),
      { diagnosticCode: "native_sdk_original_deadline" })), remaining);
    timer.unref(); requests.add(request);
    request.once("close", () => { clearTimeout(timer); requests.delete(request); });
    return request;
  };
  restores.push(() => { https.request = originalHttpsRequest; });
  const previousFetch = globalThis.fetch;
  globalThis.fetch = () => {
    remainingMs();
    // There is no mapped fetch lane in this profile. The SDK must select its
    // real runtime-fetch -> installed Undici fetch under the private ticket.
    report.externalNetworkAttempts++;
    fail("native_openai_sdk_non_undici_provider_request_forbidden");
  };
  restores.push(() => { globalThis.fetch = previousFetch; });
  syncBuiltinESMExports();
  return Object.freeze({ remainingMs, setPhase: value => { phase = value; },
    restore: () => { for (const request of requests) request.destroy(); for (const restore of restores.reverse()) restore(); syncBuiltinESMExports(); } });
}
