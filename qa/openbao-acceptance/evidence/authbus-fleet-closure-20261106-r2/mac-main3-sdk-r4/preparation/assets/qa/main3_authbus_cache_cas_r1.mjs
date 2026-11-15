/** Six exact AuthBus cache files in a new owned fixture. No production writer. */
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

export const CACHE_NAMES = Object.freeze(['applied-profiles.json', 'publish-baseline.json',
  'bad-refresh-quarantine.json', 'refresh-backoff.json', 'lease-epochs.json', 'status.json']);
const hash = raw => createHash('sha256').update(raw).digest('hex');
const stable = v => Array.isArray(v) ? v.map(stable) : v && typeof v === 'object'
  ? Object.fromEntries(Object.keys(v).sort().map(k => [k, stable(v[k])])) : v;
const digest = v => hash(JSON.stringify(stable(v)));
function need(value, code) { if (!value) throw Object.assign(new Error(code), { safeCode: code }); }
function identity(s) {
  return ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs']
    .map(k => s[k].toString());
}
function folder(stateRoot) {
  const state = path.resolve(stateRoot);
  need(state === '/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r4/state', 'cache_fixed_main3_fixture_only');
  need(fs.realpathSync(state) === state, 'cache_state_root_no_symlink');
  const root = path.join(state, 'authbus');
  let info;
  try { info = fs.lstatSync(root, { bigint: true }); }
  catch (e) { if (e.code === 'ENOENT') return { root, absent: true }; throw e; }
  need(info.isDirectory() && info.uid === BigInt(process.getuid()) && (info.mode & 0o022n) === 0n
    && fs.realpathSync(root) === root, 'cache_directory_custody');
  return { root, absent: false, identity: identity(info) };
}
function one(root, name) {
  const file = path.join(root, name);
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); }
  catch (e) { if (e.code === 'ENOENT') return { present: false }; throw e; }
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    need(before.isFile() && before.uid === BigInt(process.getuid()) && before.nlink === 1n
      && (before.mode & 0o077n) === 0n && before.size <= 1048576n, 'cache_file_custody');
    const raw = fs.readFileSync(fd);
    need(BigInt(raw.length) === before.size
      && digest(identity(before)) === digest(identity(fs.fstatSync(fd, { bigint: true })))
      && digest(identity(before)) === digest(identity(fs.lstatSync(file, { bigint: true }))),
      'cache_file_changed_during_read');
    return { present: true, mode: Number(before.mode & 0o777n), bytes: raw.length,
      sha256: hash(raw), base64: raw.toString('base64'), identity: identity(before) };
  } finally { fs.closeSync(fd); }
}
export function captureAuthBusCaches(stateRoot) {
  const directory = folder(stateRoot);
  const files = Object.fromEntries(CACHE_NAMES.map(name => [name,
    directory.absent ? { present: false } : one(directory.root, name)]));
  const after = folder(stateRoot);
  need(digest(directory) === digest(after), 'cache_directory_changed_during_read');
  return { schema: 'heptabao.six-authbus-cache-custody.private.v1', directory, files };
}
export function cacheContentDigest(snapshot) {
  return digest({ directoryPresent: !snapshot.directory.absent,
    files: Object.fromEntries(CACHE_NAMES.map(name => {
      const value = snapshot.files[name];
      return [name, value.present ? { present: true, mode: value.mode, bytes: value.bytes,
        sha256: value.sha256, base64: value.base64 } : { present: false }];
    })) });
}
function syncDir(root) {
  const fd = fs.openSync(root, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
export function restoreAuthBusCachesWithCas(stateRoot, expected, baseline) {
  need(Object.keys(expected.files).sort().join('\0') === [...CACHE_NAMES].sort().join('\0')
    && Object.keys(baseline.files).sort().join('\0') === [...CACHE_NAMES].sort().join('\0'),
    'cache_exact_six_file_scope');
  need(digest(captureAuthBusCaches(stateRoot)) === digest(expected), 'cache_complete_candidate_cas');
  const root = path.join(path.resolve(stateRoot), 'authbus');
  // Validate every original byte value before any delete/replace. A foreign
  // child prevents restoring an originally absent directory without mutation.
  for (const name of CACHE_NAMES) {
    const target = baseline.files[name];
    if (target.present) {
      const raw = Buffer.from(target.base64, 'base64');
      need(!baseline.directory.absent && raw.length === target.bytes && hash(raw) === target.sha256
        && target.mode === 0o600, 'cache_baseline_bytes_or_mode');
    }
  }
  if (baseline.directory.absent && !expected.directory.absent)
    need(fs.readdirSync(root).every(name => CACHE_NAMES.includes(name)), 'cache_directory_foreign_child');
  if (expected.directory.absent && !baseline.directory.absent) {
    fs.mkdirSync(root, { mode: 0o700 }); syncDir(stateRoot);
  }
  const folderIdentity = folder(stateRoot);
  const needOriginalDirectory = () => {
    const now = folder(stateRoot);
    need(now.absent === folderIdentity.absent && (now.absent ||
      digest(now.identity.slice(0, 5)) === digest(folderIdentity.identity.slice(0, 5))),
      'cache_directory_identity_changed_during_restore');
  };
  for (const name of CACHE_NAMES) {
    needOriginalDirectory();
    const old = expected.files[name], target = baseline.files[name], file = path.join(root, name);
    // Each actual candidate must still have the observed identity and bytes.
    if (!expected.directory.absent) need(digest(one(root, name)) === digest(old), 'cache_member_candidate_cas');
    if (!target.present) {
      if (old.present) { fs.unlinkSync(file); syncDir(root); }
      continue;
    }
    const raw = Buffer.from(target.base64, 'base64');
    need(raw.length === target.bytes && hash(raw) === target.sha256 && target.mode === 0o600,
      'cache_baseline_bytes_or_mode');
    if (old.present && old.sha256 === target.sha256 && old.mode === target.mode) continue;
    const temporary = path.join(root, '.heptabao-cache-rollback-' + randomUUID());
    const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT
      | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, target.mode);
    try { fs.writeFileSync(fd, raw); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    if (old.present) {
      need(digest(one(root, name)) === digest(old), 'cache_pre_replace_candidate_cas');
      fs.renameSync(temporary, file);
    } else {
      // Link is create-only; a concurrently appeared destination is refused.
      fs.linkSync(temporary, file); fs.unlinkSync(temporary);
    }
    syncDir(root);
  }
  if (baseline.directory.absent && !expected.directory.absent) {
    need(fs.readdirSync(root).length === 0, 'cache_directory_not_empty_for_original_absence');
    fs.rmdirSync(root); syncDir(stateRoot);
  }
  need(cacheContentDigest(captureAuthBusCaches(stateRoot)) === cacheContentDigest(baseline),
    'cache_full_original_bytes_modes_absence_not_restored');
  return true;
}
