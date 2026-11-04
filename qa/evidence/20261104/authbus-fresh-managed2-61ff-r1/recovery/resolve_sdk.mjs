#!/usr/bin/env node
/** Resolve current managed profile2 with the actual installed SDK in a new auth-only clone. */
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import http from 'node:http';
import https from 'node:https';
import cp from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
process.umask(0o077);
const ROOT='/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-fresh-managed2-61ff8bef-r1';
const LIVE='/home/qian-qi/.openclaw';
const SDK='/home/qian-qi/.npm-global/lib/node_modules/openclaw';
const EXPECTED=['bca88c7adde84057871fd63f202e6aba80d453a04f75151df1d29f269dfaa5f1','131b8515d48433365dd84555e7659297d4d62de631f9a526a8a4293f03396175','63a40b812af24584847961eeaff54e780eacc66625970ee40ea2d9b1e0a70398'];
const CONFIG='a042bc7fba4ac1295e323e0112598972a2872a040c5464af9614e4c2e600bd15';
const hash=b=>createHash('sha256').update(b).digest('hex');
const stable=v=>Array.isArray(v)?v.map(stable):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
const digest=v=>hash(JSON.stringify(stable(v)));
const report={schema:'heptabao.rog-current-managed2-sdk-selection.v1',ok:false,providerCalled:false,refreshAttempted:false,modelCalled:false,productionChanged:false,authbusMigrationClaimed:false,productionGatewaySelectionQualified:false,credentialValuesPublished:false,accountIdentitiesPublished:false,unexpectedOperations:0,checks:[]};
const secrets=[];
let work,plan;
function need(v,c){report.checks.push({name:c,ok:!!v});if(!v)throw Object.assign(new Error(c),{safeCode:c});}
function read(p){const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);need(s.isFile()&&s.uid===process.getuid()&&(s.mode&0o077)===0&&s.nlink===1&&s.size<=2097152,'private_input_custody');const b=fs.readFileSync(fd),t=fs.fstatSync(fd),u=fs.lstatSync(p);need([t,u].every(x=>x.ino===s.ino&&x.dev===s.dev&&x.size===s.size&&x.mtimeMs===s.mtimeMs&&x.ctimeMs===s.ctimeMs),'private_input_stable');return b;}finally{fs.closeSync(fd);}}
function save(p,v){const b=Buffer.isBuffer(v)?v:Buffer.from(JSON.stringify(v));const fd=fs.openSync(p,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,b);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}const d=fs.openSync(path.dirname(p),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);try{fs.fsyncSync(d);}finally{fs.closeSync(d);}return hash(b);}
function deny(){report.unexpectedOperations++;throw Object.assign(new Error('unexpected_operation_refused'),{safeCode:'unexpected_operation_refused'});}
function capture(){
 const cfgRaw=read(LIVE+'/openclaw.json');need(hash(cfgRaw)===CONFIG,'current_config_pin');
 const filename=LIVE+'/agents/main/agent/openclaw-agent.sqlite',st=fs.lstatSync(filename);
 need(st.isFile()&&st.uid===process.getuid()&&(st.mode&0o777)===0o600&&st.nlink===1,'live_database_custody');
 need(!fs.existsSync(filename+'-wal')||fs.existsSync(filename+'-shm'),'readonly_wal_existing_shm');
 const db=new DatabaseSync(filename,{readOnly:true});const out={rows:{}};
 try{db.exec('PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; BEGIN');
  for(const[k,table,key,col]of [['store','auth_profile_store','store_key','store_json'],['state','auth_profile_state','state_key','state_json']]){
   const rows=db.prepare('SELECT '+key+' AS k,'+col+' AS v,updated_at AS t FROM '+table+' ORDER BY '+key).all();need(rows.length<=32&&rows.every(r=>typeof r.v==='string'&&Buffer.byteLength(r.v)<=1048576),'bounded_auth_rows');out.rows[k]=rows.map(r=>[r.k,r.v,r.t]);}
  db.exec('ROLLBACK');
 }finally{db.close();}
 const after=fs.lstatSync(filename);need(after.dev===st.dev&&after.ino===st.ino&&after.uid===st.uid&&after.mode===st.mode&&after.nlink===1,'live_database_identity');
 const main=out.rows.store.filter(r=>r[0]==='primary');need(main.length===1,'unique_primary_store');
 const store=JSON.parse(main[0][1]),entries=Object.entries(store.profiles);need(entries.length===3&&entries.every(([,c],i)=>digest(c)===EXPECTED[i]),'all_current_generations_exact');
 return {document:out,cfg:JSON.parse(cfgRaw),entries};
}
try{
 need(process.argv.length===3,'argument_shape');plan=JSON.parse(read(process.argv[2]));work=ROOT+'/resolve-r1';
 need(plan.work===work&&process.argv[2]===ROOT+'/control/resolve-r1.plan.json','exact_work_plan');
 const state=work+'/state',agent=state+'/agents/main/agent';
 need(process.env.OPENCLAW_STATE_DIR===state&&process.env.OPENCLAW_CONFIG_PATH===state+'/openclaw.json'&&process.env.OPENCLAW_OAUTH_DIR===state+'/oauth'&&process.env.HOME===work+'/home'&&process.env.TMPDIR===work+'/tmp','private_application_roots');
 for(const[p,h]of Object.entries(plan.sourcePins))need(hash(fs.readFileSync(p))===h,'source.'+path.basename(p));
 const before=capture();const[id,credential]=before.entries[1];
 for(const[k,c]of before.entries){secrets.push(k);for(const field of ['access','refresh','accountId','email'])if(typeof c[field]==='string')secrets.push(c[field]);}
 const claims=JSON.parse(Buffer.from(credential.access.split('.')[1],'base64url'));
 need(credential.provider==='openai'&&credential.type==='oauth'&&credential.expires>Date.now()+120000&&claims.exp*1000>Date.now()+120000&&claims['https://api.openai.com/auth']?.chatgpt_account_id===credential.accountId,'selected_identity_and_expiry');
 save(work+'/source-auth-rows.private.json',before.document);
 fs.mkdirSync(state,{mode:0o700});fs.mkdirSync(state+'/oauth',{mode:0o700});fs.mkdirSync(agent,{recursive:true,mode:0o700});
 const target=agent+'/openclaw-agent.sqlite',db=new DatabaseSync(target);
 try{db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; BEGIN');
  for(const[k,table,key,col]of [['store','auth_profile_store','store_key','store_json'],['state','auth_profile_state','state_key','state_json']]){
   db.exec('CREATE TABLE '+table+' ('+key+' TEXT PRIMARY KEY,'+col+' TEXT NOT NULL,updated_at INTEGER NOT NULL)');
   const q=db.prepare('INSERT INTO '+table+' VALUES (?,?,?)');for(const row of before.document.rows[k])q.run(...row);}
  db.exec('COMMIT');
 }finally{db.close();}fs.chmodSync(target,0o600);
 const cfg={agents:{defaults:structuredClone(before.cfg.agents.defaults),list:[{id:'main',agentDir:agent}]},auth:structuredClone(before.cfg.auth??{}),models:structuredClone(before.cfg.models??{})};
 save(state+'/openclaw.json',cfg);
 globalThis.fetch=deny;http.request=deny;http.get=deny;https.request=deny;https.get=deny;
 for(const k of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[k]=deny;
 syncBuiltinESMExports();
 const sdk=await import(pathToFileURL(SDK+'/dist/plugin-sdk/agent-runtime.js'));
 const auth=await import(pathToFileURL(SDK+'/dist/oauth-B4aOCsid.js'));
 need(path.resolve(sdk.resolveDefaultAgentDir({}))===agent,'actual_sdk_private_main_scope');
 const original=sdk.loadAuthProfileStoreWithoutExternalProfiles(agent,{allowKeychainPrompt:false});
 need(digest(original.profiles[id])===EXPECTED[1],'actual_sdk_current_profile2');
 const resolved=await auth.n({cfg,store:structuredClone(original),profileId:id,agentDir:agent,forceRefresh:false});
 need(resolved?.profileId===id&&resolved?.apiKey===credential.access,'actual_original_sdk_explicit_profile2_resolver');
 sdk.clearRuntimeAuthProfileStoreSnapshots();const afterSdk=sdk.loadAuthProfileStoreWithoutExternalProfiles(agent,{allowKeychainPrompt:false});
 need(digest(afterSdk)===digest(original),'private_whole_logical_store_unchanged');
 const after=capture();
 need(digest(after.entries)===digest(before.entries)&&digest(after.cfg)===digest(before.cfg),'live_current_generations_and_config_unchanged');
 report.sourceBinding={profileOrdinal:2,profileIdSha256:hash(id),credentialSha256:EXPECTED[1],accountIdSha256:hash(credential.accountId),jwtExpiresUnixSeconds:claims.exp,configurationSha256:CONFIG};
 report.selectionSha256=save(work+'/selection.private.json',{schema:'heptabao.current-explicit-sdk-selection.private.v1',source:'actual_installed_sdk_explicit_profile_resolver_current_source_no_authbus_migration_claim',profileId:id,credential,resolvedApiKey:resolved.apiKey,credentialSha256:EXPECTED[1],storeSha256:digest(afterSdk)});
 report.sourceAuthRowsBeforeSha256=digest(before.document.rows);report.sourceAuthRowsAfterSha256=digest(after.document.rows);report.sourceFullAuthRowsUnchanged=digest(before.document.rows)===digest(after.document.rows);
 report.privateLogicalStoreSha256=digest(afterSdk);report.privateOrderSha256=digest(afterSdk.order??null);report.privateUsageSha256=digest(afterSdk.usageStats??null);
 need(report.unexpectedOperations===0,'zero_network_or_child_operations');
 for(const[p,h]of Object.entries(plan.sourcePins))need(hash(fs.readFileSync(p))===h,'source_after.'+path.basename(p));
 report.actualCurrentSdkExplicitSelectionQualified=true;report.ok=true;
}catch(e){report.error=e.safeCode??'current_sdk_selection_failed';report.errorClass=e.constructor?.name??'unknown';}
if(!work)throw new Error('no_owned_work_scope');
need(secrets.every(v=>v.length<8||!JSON.stringify(report).includes(v)),'public_secret_guard');
save(work+'/result.public.json',report);process.stdout.write(JSON.stringify({ok:report.ok,result:work+'/result.public.json',selectionSha256:report.selectionSha256??null,error:report.error??null})+'\n');process.exitCode=report.ok?0:1;
