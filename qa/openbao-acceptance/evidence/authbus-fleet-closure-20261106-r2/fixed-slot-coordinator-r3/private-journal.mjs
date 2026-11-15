import fs from 'node:fs';
import path from 'node:path';
import { stable, digest, equal, need, object, SHA } from './protocol.mjs';

const FLAGS = fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK;
const identity = info => ['dev','ino','uid','gid','mode','nlink','size','mtimeNs','ctimeNs'].map(k => String(info[k]));
const inode = info => ['dev','ino','uid','gid','mode'].map(k => String(info[k])).join(':');
export function readPrivateJson(filename, maximum = 8 * 1024 * 1024) {
  need(typeof filename === 'string' && path.isAbsolute(filename) && path.resolve(filename) === filename, 'journal_absolute_private_path');
  const fd = fs.openSync(filename, FLAGS);
  try {
    const before = fs.fstatSync(fd,{bigint:true});
    need(before.isFile() && before.uid === BigInt(process.getuid()) && (before.mode & 0o777n) === 0o600n
      && before.nlink === 1n && before.size <= BigInt(maximum), 'journal_private_file_custody');
    const raw = Buffer.alloc(Number(before.size)+1);let offset=0;
    while (offset<raw.length) { const n=fs.readSync(fd,raw,offset,raw.length-offset,null);if(n===0)break;offset+=n; }
    need(offset===Number(before.size) && identity(before).join(':')===identity(fs.fstatSync(fd,{bigint:true})).join(':')
      && identity(before).join(':')===identity(fs.lstatSync(filename,{bigint:true})).join(':'), 'journal_exact_private_read');
    try { return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw.subarray(0,offset))); }
    finally { raw.fill(0); }
  } finally { fs.closeSync(fd); }
}

export class PrivateJournal {
  #dir; #fd; #identity; #closed=false;
  constructor(stateDir) {
    const parent=fs.lstatSync(stateDir,{bigint:true});
    need(path.isAbsolute(stateDir) && fs.realpathSync(stateDir)===stateDir && parent.isDirectory()
      && parent.uid===BigInt(process.getuid()) && (parent.mode&0o777n)===0o700n, 'journal_parent_custody');
    this.#dir=path.join(stateDir,'operations');
    try { fs.mkdirSync(this.#dir,{mode:0o700}); }
    catch(error){if(error.code!=='EEXIST')throw error;}
    // A prior mkdir may have completed before its parent fsync failed. Reopen
    // the same parent and sync that exact directory entry on either path.
    const parentFd=fs.openSync(stateDir,FLAGS|fs.constants.O_DIRECTORY);
    try{const sameParent=()=>inode(fs.fstatSync(parentFd,{bigint:true}))===inode(parent)
        &&inode(fs.lstatSync(stateDir,{bigint:true}))===inode(parent);
      need(sameParent(),'journal_parent_replaced');fs.fsyncSync(parentFd);need(sameParent(),'journal_parent_replaced');
    }finally{fs.closeSync(parentFd);}
    const named=fs.lstatSync(this.#dir,{bigint:true});
    need(named.isDirectory() && named.uid===BigInt(process.getuid()) && (named.mode&0o777n)===0o700n
      && fs.realpathSync(this.#dir)===this.#dir, 'journal_directory_custody');
    this.#fd=fs.openSync(this.#dir,FLAGS|fs.constants.O_DIRECTORY);this.#identity=inode(named);
    try{this.assertCustody();}catch(error){try{fs.closeSync(this.#fd);}finally{this.#closed=true;}throw error;}
  }
  assertCustody(){need(!this.#closed && inode(fs.fstatSync(this.#fd,{bigint:true}))===this.#identity
    && inode(fs.lstatSync(this.#dir,{bigint:true}))===this.#identity,'journal_directory_replaced');}
  #path(name){this.assertCustody();need(typeof name==='string'&&/^[a-f0-9]{64}(?:\.step-[0-9]{4}\.(?:intent|response|confirmed)|\.completed)?\.json$/.test(name),'journal_fixed_name');return path.join(this.#dir,name);}
  read(name){const p=this.#path(name);let value;try{value=readPrivateJson(p);}catch(e){if(e.code==='ENOENT')return null;throw e;}this.assertCustody();return value;}
  writeOnce(name,value){const filename=this.#path(name);const raw=Buffer.from(JSON.stringify(stable(value))+'\n');
    need(raw.length<=8*1024*1024,'journal_document_bound');let fd,existing=false,readback;
    try {
      try{fd=fs.openSync(filename,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);}
      catch(error){if(error.code!=='EEXIST')throw error;
        fd=fs.openSync(filename,fs.constants.O_RDWR|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);existing=true;}
      if(existing){
        const before=fs.fstatSync(fd,{bigint:true});
        need(before.isFile()&&before.uid===BigInt(process.getuid())&&(before.mode&0o777n)===0o600n
          &&before.nlink===1n&&before.size===BigInt(raw.length),'journal_existing_file_custody');
        readback=Buffer.alloc(raw.length+1);let offset=0;
        while(offset<readback.length){const n=fs.readSync(fd,readback,offset,readback.length-offset,null);if(n===0)break;offset+=n;}
        const unchanged=()=>identity(before).join(':')===identity(fs.fstatSync(fd,{bigint:true})).join(':')
          &&identity(before).join(':')===identity(fs.lstatSync(filename,{bigint:true})).join(':');
        need(offset===raw.length&&readback.subarray(0,offset).equals(raw)&&unchanged(),'journal_existing_document_mismatch');
        this.assertCustody();fs.fsyncSync(fd);need(unchanged(),'journal_existing_file_changed_during_sync');
        fs.fsyncSync(this.#fd);this.assertCustody();need(unchanged(),'journal_existing_file_changed_during_sync');
        return;
      }
      let offset=0;while(offset<raw.length){const n=fs.writeSync(fd,raw,offset,raw.length-offset,null);need(n>0,'journal_complete_write');offset+=n;}
      fs.fsyncSync(fd);const held=fs.fstatSync(fd,{bigint:true}),named=fs.lstatSync(filename,{bigint:true});
      need(held.isFile()&&held.uid===BigInt(process.getuid())&&(held.mode&0o777n)===0o600n&&held.nlink===1n
        &&held.size===BigInt(raw.length)&&identity(held).join(':')===identity(named).join(':'),'journal_durable_file_binding');
      fs.fsyncSync(this.#fd);this.assertCustody();
    }finally{raw.fill(0);readback?.fill(0);if(fd!==undefined)fs.closeSync(fd);}
  }
  close(){if(this.#closed)return;let error;try{this.assertCustody();}catch(e){error=e;}try{fs.closeSync(this.#fd);}catch(e){error??=e;}this.#closed=true;if(error)throw error;}
}
