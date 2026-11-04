import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';

const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
export const authRowsDigest = value => createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');
const tables = { store: ['auth_profile_store','store_key','store_json'],
  state: ['auth_profile_state','state_key','state_json'] };
function boundDatabase(stateRoot, agentId) {
  if (!['main','tg8687951891'].includes(agentId)) throw new Error('auth_rows_agent_not_allowlisted');
  const root = path.resolve(stateRoot);
  if (!root.startsWith('/home/alex/heptabao-installed-authbus-consumer-36076-20261104-r1/')
    || !root.includes('/current-native-') || !root.endsWith('/state'))
    throw new Error('auth_rows_not_new_owned_state');
  return path.join(root, 'agents', agentId, 'agent', 'openclaw-agent.sqlite');
}
function rowsFrom(db) {
  return Object.fromEntries(Object.entries(tables).map(([kind,[table,key,column]]) =>
    [kind, db.prepare('SELECT '+key+','+column+',updated_at FROM '+table+' ORDER BY '+key)
      .all().map(row => [row[key],row[column],row.updated_at])]));
}
export function captureAuthRows(stateRoot, agentId) {
  const db = new DatabaseSync(boundDatabase(stateRoot,agentId), { readOnly: true });
  try { db.exec('PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; BEGIN');
    const rows = rowsFrom(db); db.exec('ROLLBACK'); return rows;
  } finally { db.close(); }
}
export function restoreAuthRowsWithCas(stateRoot, agentId, expectedRows, baselineRows) {
  const db = new DatabaseSync(boundDatabase(stateRoot,agentId));
  try {
    db.exec('PRAGMA temp_store=MEMORY; BEGIN IMMEDIATE');
    if (authRowsDigest(rowsFrom(db)) !== authRowsDigest(expectedRows))
      throw new Error('auth_rows_cas_conflict');
    for (const [kind,[table,key,column]] of Object.entries(tables)) {
      db.exec('DELETE FROM '+table);
      const insert = db.prepare('INSERT INTO '+table+'('+key+','+column+',updated_at) VALUES (?,?,?)');
      for (const row of baselineRows[kind]) {
        if (!Array.isArray(row) || row.length !== 3) throw new Error('auth_rows_baseline_shape');
        insert.run(...row);
      }
    }
    if (authRowsDigest(rowsFrom(db)) !== authRowsDigest(baselineRows))
      throw new Error('auth_rows_restore_inexact');
    db.exec('COMMIT');
  } catch (error) { try { db.exec('ROLLBACK'); } catch {} throw error; }
  finally { db.close(); }
  return authRowsDigest(captureAuthRows(stateRoot,agentId)) === authRowsDigest(baselineRows);
}
