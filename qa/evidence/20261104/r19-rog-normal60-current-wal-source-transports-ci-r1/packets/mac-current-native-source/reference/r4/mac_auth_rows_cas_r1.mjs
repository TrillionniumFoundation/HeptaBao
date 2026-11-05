import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';

const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
export const authRowsDigest = value => createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');
const tables = { store: ['auth_profile_store','store_key','store_json'],
  state: ['auth_profile_state','state_key','state_json'] };
function boundDatabase(stateRoot, agentId) {
  if (!['main','trnm','hepta-ui','hepta','hepta-backend'].includes(agentId)) throw new Error('auth_rows_agent_not_allowlisted');
  const root = path.resolve(stateRoot);
  if (!['initial','cold-new-process'].some(phase => root ===
    '/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1/'+phase+'/state'))
    throw new Error('auth_rows_not_new_owned_state');
  const file=path.join(root,'agents',agentId,'agent','openclaw-agent.sqlite');
  if(fs.realpathSync(root)!==root||fs.realpathSync(path.dirname(file))!==path.dirname(file)
    ||fs.realpathSync(file)!==file)throw new Error('auth_rows_symlink_or_alias_refused');
  const st=fs.lstatSync(file);
  if(!st.isFile()||st.uid!==501||st.nlink!==1||(st.mode&0o777)!==0o600)
    throw new Error('auth_rows_file_custody');
  return file;
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
