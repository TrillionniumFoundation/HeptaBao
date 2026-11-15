import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { need, stable, SHA } from './protocol.mjs';

const ROOT=path.dirname(fileURLToPath(import.meta.url));
export const RUNTIME_FILES=['cli.mjs','coordinator.mjs','private-journal.mjs','protocol.mjs','source-verification.mjs',
  'transport/bounded-outbox.js','transport/private-outbox-store.js','transport/production-client.js','transport/strict-bao-client.js'];
const identity=info=>['dev','ino','uid','gid','mode','nlink','size','mtimeNs','ctimeNs'].map(key=>String(info[key])).join(':');
export function implementationPins(){return [...RUNTIME_FILES].sort().map(relative=>{
  const filename=path.join(ROOT,relative),fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{const before=fs.fstatSync(fd,{bigint:true});need(before.isFile()&&[0n,BigInt(process.getuid())].includes(before.uid)
    &&(before.mode&0o022n)===0n&&before.nlink===1n&&before.size>0n&&before.size<=131072n,'coordinator_runtime_source_custody');
    const buffer=Buffer.alloc(65536),hash=createHash('sha256');let count=0;
    for(;;){const n=fs.readSync(fd,buffer,0,buffer.length,null);if(!n)break;count+=n;need(count<=131072,'coordinator_runtime_source_bound');hash.update(buffer.subarray(0,n));}
    need(BigInt(count)===before.size&&identity(before)===identity(fs.fstatSync(fd,{bigint:true}))&&identity(before)===identity(fs.lstatSync(filename,{bigint:true})),
      'coordinator_runtime_source_changed');return {path:relative,bytes:count,sha256:hash.digest('hex')};
  }finally{fs.closeSync(fd);}
});}
export function verifyImplementation(expected){need(typeof expected==='string'&&SHA.test(expected),'coordinator_implementation_pin_required');
  const pins=implementationPins(),actual=createHash('sha256').update(JSON.stringify(stable(pins))).digest('hex');
  need(actual===expected,'coordinator_implementation_pin_mismatch');return pins;
}
