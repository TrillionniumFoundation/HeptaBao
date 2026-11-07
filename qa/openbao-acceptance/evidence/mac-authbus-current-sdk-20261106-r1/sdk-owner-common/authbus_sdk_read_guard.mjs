/** Exact installed-source read guard, with denial counters; no credential hashing. */
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import dns from "node:dns";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
const LIMIT=2*1024*1024;
function fail(code){const error=new Error(code);error.code=code;throw error;}
function requireValue(value,code){if(!value)fail(code);}
export function protectReadPhase(diagnostics) {
  const changes = [];
  const replace = (object, key, value) => {
    if (typeof object[key] !== "function") return;
    changes.push([object, key, object[key]]); object[key] = value;
  };
  const denied = () => { diagnostics.blockedAttempts += 1; fail("sdk_attempted_mutation_or_network"); };
  for (const prefix of ["writeFile", "appendFile", "mkdir", "mkdtemp", "rename", "unlink", "rm", "rmdir", "copyFile", "cp", "link", "symlink", "truncate", "chmod", "chown", "utimes", "write", "writev"]) {
    replace(fs, prefix, denied); replace(fs, prefix + "Sync", denied); replace(fsp, prefix, denied);
  }
  const readOnlyFlags = flags => typeof flags === "string" ? ["r", "rs", "sr"].includes(flags)
    : Number.isInteger(flags) && !(flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND));
  for (const [object, name] of [[fs, "openSync"], [fs, "open"], [fsp, "open"]]) {
    const original = object[name];
    replace(object, name, function (filename, flags, ...rest) {
      if (!readOnlyFlags(flags)) diagnostics.blockedAttempts += 1;
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


