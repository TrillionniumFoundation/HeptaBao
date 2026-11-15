/** Source-bound SQLite read adapter for a fresh private whole-database clone.
 * Actual SDK logical agent/owner paths and methods stay unchanged. Only the
 * five exact readOnly:true DatabaseSync constructors receive physical clone
 * paths. This is an observation adapter, not production gateway consumption.
 */
import fs from 'node:fs';
import path from 'node:path';
import {isDeepStrictEqual} from 'node:util';

const LIVE='/Users/qianqi/.openclaw';
const MAINT='/Users/qianqi/heptabao-authbus-writer-maintenance-20261106-r1';
const AGENTS=['main','trnm','hepta-ui','hepta','hepta-backend'];
const WHOLE='6a6a6630204687c56e12bc0e616e062b4e574c0665bb177d938409e739b30f4a';
const full=s=>['dev','ino','uid','gid','mode','nlink','size','mtimeNs','ctimeNs'].map(k=>String(s[k]));
const exact=isDeepStrictEqual;
export class CloneReadRefused extends Error{
 constructor(code){super(code);this.name='CloneReadRefused';this.code=code;}
}
const need=(v,c)=>{if(!v)throw new CloneReadRefused(c);};

export function bindFreshCloneReader({root,binding,until,io=fs,clock=()=>process.hrtime.bigint()},report={}){
 need(typeof root==='string'&&new RegExp('^'+MAINT+'/captures/owner-0[123]$').test(root)
  &&path.normalize(root)===root&&typeof until==='bigint'&&clock()<until,
  'clone_exact_new_owner_capture_root');
 need(binding?.schema==='heptabao.fresh-whole-clone-read.private.r1'
  &&binding.backupSourceSha256===WHOLE&&binding.sourcePhase==='after_writer_quiescence'
  &&Array.isArray(binding.entries)&&binding.entries.length===5,
  'clone_original_complete_five_backup_binding');
 const files=[],parents=new Map(),byLogical=new Map();let closed=false,failed=false;
 Object.assign(report,{schema:'heptabao.actual-sdk-private-clone-reader.public.r1',
  fixedLogicalSourceCount:5,physicalWholeCloneCount:5,originalSdkLogicalPathsPreserved:true,
  originalSdkReadonlyOptionPreserved:true,sourceDatabaseConstructorsDispatched:0,
  cloneDatabaseConstructorsRouted:0,wholeCloneDigestRecomputedBySdkAdapter:false,
  physicalReadBoundByOriginalFull9:true,productionGatewayConsumptionProven:false,
  credentialOrPrivateConfigurationDigestsPublished:false,descriptorsOpened:0,closeAttempts:0,descriptorsClosed:0});
 const within=()=>need(!closed&&!failed&&clock()<until,'clone_original_reader_deadline');
 function hold(filename,flags){
  const fd=io.openSync(filename,flags),row={fd,filename,closeAttempts:0,closed:false};
  files.push(row);report.descriptorsOpened++;row.identity=full(io.fstatSync(fd,{bigint:true}));return row;
 }
 function closeOne(row){
  need(row.closeAttempts===0,'clone_original_descriptor_close_once');row.closeAttempts++;report.closeAttempts++;
  try{io.closeSync(row.fd);row.closed=true;report.descriptorsClosed++;}catch(error){row.closeError=true;throw error;}
 }
 function stableRow(row,width=9){
  need(!row.closeAttempts&&exact(full(io.fstatSync(row.fd,{bigint:true})).slice(0,width),row.identity.slice(0,width))
   &&exact(full(io.lstatSync(row.filename,{bigint:true})).slice(0,width),row.identity.slice(0,width)),
   'clone_original_named_and_held_generation');
 }
 function parent(filename){
  if(parents.has(filename))return parents.get(filename);
  if(path.dirname(filename)!==filename)parent(path.dirname(filename));
  const row=hold(filename,io.constants.O_RDONLY|io.constants.O_DIRECTORY|io.constants.O_NOFOLLOW);
  const s=io.fstatSync(row.fd,{bigint:true});
  need(s.isDirectory()&&[0n,501n].includes(s.uid)&&(s.mode&18n)===0n,
   'clone_original_parent_custody');
  if(filename===root||filename.startsWith(root+'/'))need(s.uid===501n&&(s.mode&511n)===448n,
   'clone_private_capture_directory');
  stableRow(row);parents.set(filename,row);return row;
 }
 function verify(){
  within();
  for(const row of parents.values()){
   // Only the original output tree receives private SDK artifacts/sidecars.
   const mutable=row.filename===root+'/output'||row.filename===root+'/output/source-clones';
   stableRow(row,mutable?5:9);
  }
  for(const row of byLogical.values())stableRow(row);
  report.sourceNamespaceMetadataChecks=(report.sourceNamespaceMetadataChecks??0)+1;
  return true;
 }
 function retire(){
  if(closed)return;closed=true;
  for(const row of [...files].reverse())if(!row.closeAttempts){try{closeOne(row);}catch{failed=true;}}
  report.allOriginalDescriptorsClosedOnce=files.every(row=>row.closed&&row.closeAttempts===1);
 }
 try{
  for(let i=0;i<5;i++){
   within();const item=binding.entries[i];
   const logical=LIVE+'/agents/'+AGENTS[i]+'/agent/openclaw-agent.sqlite';
   const physical=root+'/output/source-clones/candidate-'+i+'.sqlite';
   need(item?.ordinal===i&&item.logicalPath===logical&&item.physicalPath===physical
    &&item.twoCompleteBackupOutputsEqual===true&&item.freshIndependentTransaction===true
    &&item.keeperUsedAsLatestSource===false&&item.sourceContentCopyAuthority==='sqlite_online_backup_api'
    &&Array.isArray(item.physicalFull9)&&item.physicalFull9.length===9
    &&item.physicalFull9.every(v=>typeof v==='string'&&/^[0-9]{1,30}$/.test(v)),
    'clone_exact_original_backup_slot');
   parent(path.dirname(physical));
   const row=hold(physical,io.constants.O_RDONLY|io.constants.O_NOFOLLOW|io.constants.O_NONBLOCK);
   const s=io.fstatSync(row.fd,{bigint:true});
   need(s.isFile()&&s.uid===501n&&s.gid===20n&&s.nlink===1n&&(s.mode&511n)===384n
    &&s.size>=512n&&s.size<=4294967296n&&exact(row.identity,item.physicalFull9),
    'clone_original_private_complete_database_identity');
   stableRow(row);byLogical.set(logical,row);
  }
  verify();
  return Object.freeze({
   route(filename,options){
    try{
     verify();const row=byLogical.get(filename);
     need(typeof filename==='string'&&row&&options?.readOnly===true,
      'clone_only_exact_logical_readonly_database_constructor');
     report.cloneDatabaseConstructorsRouted++;return row.filename;
    }catch(error){failed=true;throw error;}
   },
   verify,
   close(){retire();need(report.allOriginalDescriptorsClosedOnce,'clone_original_descriptor_closure_unknown');}
  });
 }catch(error){failed=true;retire();throw error;}
}
