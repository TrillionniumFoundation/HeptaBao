// Public-only startup/import probe. No SDK, plan, database, provider, or CAS calls.
const stages = ["fs","path","crypto","sqlite","rows-cas","cache-cas","https","http","child-process","url","module"];
const modules = ["node:fs","node:path","node:crypto","node:sqlite","./mac_auth_rows_cas_r1.mjs","./mac_authbus_cache_cas_r1.mjs","node:https","node:http","node:child_process","node:url","node:module"];
let current = 'entered-js';
function emit(value) {
  return new Promise((resolve, reject) => {
    process.stdout.write(value + '\n', error => error ? reject(error) : resolve());
  });
}
try {
  await emit('entered-js');
  for (let i = 0; i < stages.length; i++) {
    current = 'before-' + stages[i];
    await emit(current);
    await import(modules[i]);
    current = 'after-' + stages[i];
    await emit(current);
  }
  current = 'complete';
  await emit(current);
} catch (_error) {
  // No exception text, stack, paths, or hashes cross this public marker channel.
  try { await emit('failed-' + current); } catch {}
  process.exitCode = 1;
}
