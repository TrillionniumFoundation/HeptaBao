#!/usr/bin/env python3
"""Make existing private journal entries prove durability before dispatch."""
import difflib
import hashlib
import json
from pathlib import Path

OLD = Path('/workspace/scratch/c9fe536787d9/fixed-slot-coordinator-r2-work')
NEW = Path(__file__).resolve().parent
manifest = json.loads((OLD / 'source-manifest.public.json').read_text())
assert manifest['implementationSha256'] == 'efc5139e0fe226136a73b5577e92f42ceff20dd639b2d6da5e1c79755e6985d3'
for row in manifest['runtimeFiles']:
    raw = (OLD / row['path']).read_bytes()
    assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
for filename in ['build_manifest.py', 'package.json', 'README.md', 'transport-source-pins.public.json'] + [x['path'] for x in manifest['runtimeFiles']]:
    target = NEW / filename
    assert not target.exists(), filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((OLD / filename).read_bytes())
for directory in ['tests', 'reference']:
    for source in sorted((OLD / directory).iterdir()):
        if source.is_file():
            target = NEW / directory / source.name
            assert not target.exists()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())

source = (NEW / 'private-journal.mjs').read_text()
old_parent = """    try { fs.mkdirSync(this.#dir,{mode:0o700});const parentFd=fs.openSync(stateDir,FLAGS|fs.constants.O_DIRECTORY);try{fs.fsyncSync(parentFd);}finally{fs.closeSync(parentFd);} }
    catch(error){if(error.code!=='EEXIST')throw error;}
"""
new_parent = """    try { fs.mkdirSync(this.#dir,{mode:0o700}); }
    catch(error){if(error.code!=='EEXIST')throw error;}
    // A prior mkdir may have completed before its parent fsync failed. Reopen
    // the same parent and sync that exact directory entry on either path.
    const parentFd=fs.openSync(stateDir,FLAGS|fs.constants.O_DIRECTORY);
    try{const sameParent=()=>inode(fs.fstatSync(parentFd,{bigint:true}))===inode(parent)
        &&inode(fs.lstatSync(stateDir,{bigint:true}))===inode(parent);
      need(sameParent(),'journal_parent_replaced');fs.fsyncSync(parentFd);need(sameParent(),'journal_parent_replaced');
    }finally{fs.closeSync(parentFd);}
"""
assert source.count(old_parent) == 1
changed = source.replace(old_parent, new_parent)
start = changed.index('  writeOnce(name,value){')
end = changed.index('  close(){', start)
old_write = changed[start:end]
new_write = """  writeOnce(name,value){const filename=this.#path(name);const raw=Buffer.from(JSON.stringify(stable(value))+'\\n');
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
"""
changed = changed[:start] + new_write + changed[end:]
(NEW / 'private-journal.mjs').write_text(changed)
(NEW / 'r2-to-r3-journal.diff').write_text(''.join(difflib.unified_diff(
    source.splitlines(True), changed.splitlines(True), fromfile='frozen-r2/private-journal.mjs', tofile='candidate-r3/private-journal.mjs')))
with (NEW / 'README.md').open('a') as stream:
    stream.write('''\n## Revision 3 journal durability\n\nAn equal existing operation file is insufficient evidence of a successful earlier fsync. Revision 3 reopens the exact existing private inode, checks the canonical complete bytes and all nine identity fields, synchronizes that file and the original held operations directory, and repeats the identity checks before returning. Any failure leaves the original step un-dispatched. The operations directory parent is synchronized on both initial creation and reopening, because a previous mkdir may have completed before its parent synchronization failed. No existing file is rewritten and no remote request is repeated to establish this durability. Revision 2 and its 21 local test results remain unchanged.\n''')
(NEW / 'qualification').mkdir()
print(json.dumps({'runtimeChanged':['private-journal.mjs'],'previousImplementationSha256':manifest['implementationSha256'],
    'journalSha256':hashlib.sha256(changed.encode()).hexdigest(),'previousTreeUnchanged':True}))
