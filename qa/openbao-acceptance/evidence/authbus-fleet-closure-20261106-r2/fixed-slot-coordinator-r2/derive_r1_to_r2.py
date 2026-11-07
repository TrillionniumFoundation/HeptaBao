#!/usr/bin/env python3
"""Derive stricter effect confirmation without modifying the frozen r1 tree."""
import difflib
import hashlib
import json
from pathlib import Path

OLD = Path('/workspace/scratch/c9fe536787d9/fixed-slot-coordinator-implementation-work')
NEW = Path(__file__).resolve().parent
manifest = json.loads((OLD / 'source-manifest.public.json').read_text())
assert manifest['implementationSha256'] == 'a9de47653ad09469c6a8b651063495261835852364a7b35c42208331c7dbf933'
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

source = (NEW / 'coordinator.mjs').read_text()
old = """  async #confirm(step,until){const expected=(step.expected?.version??0)+1;let actual=await this.adapter.read(step.key,until);
    if(actual?.version!==expected||!equal(actual.data,step.desired))actual=await this.adapter.history(step.key,expected,until);
    if(!(actual?.version===expected&&equal(actual.data,step.desired)))throw new CoordinatorError('coordinator_original_effect_unresolved',{unknown:true});
    return expected;}
"""
new = """  async #confirm(step,until){const targetVersion=(step.expected?.version??0)+1;
    const head=await this.adapter.read(step.key,until);let retainedHistoryUsed=false,slotHeadVersion=null;
    const unresolved=()=>{throw new CoordinatorError('coordinator_original_effect_unresolved',{unknown:true});};
    const exactHead=head?.version===targetVersion&&equal(head.data,step.desired);
    if(['profile','receipt','enrollment'].includes(step.role)){
      // Immutable profiles/receipts/control and pre-control enrollment writes
      // cannot be confirmed by an older version beneath a modified head.
      if(!(step.expected===null&&targetVersion===1&&exactHead))unresolved();
    }else if(step.role==='manifest'){
      // An operator may have published one further authorization update. The
      // fixed two-version contract can prove only this exact retained target.
      if(!head||![targetVersion,targetVersion+1].includes(head.version))unresolved();
      try{validateManifest(head.data,this.owner,this.hosts);}catch{unresolved();}
      if(head.version===targetVersion){if(!exactHead)unresolved();}
      else{const original=await this.adapter.history(step.key,targetVersion,until);
        if(!(original?.version===targetVersion&&equal(original.data,step.desired)))unresolved();
        retainedHistoryUsed=true;}
    }else if(step.role==='ack'){
      // The producer never writes ack. It can only reuse the acknowledged slot
      // once; a later ack or a two-generation slot leap is not our confirmation.
      if(!exactHead||step.guard===null||!step.guard.expected)unresolved();
      const originalSlot=step.guard.expected,data=originalSlot.data;
      const topology=this.topology.find(row=>row.host_id===data?.sourceHost&&row.epoch===data?.epoch);
      if(!topology||!integer(data.slot)||data.slot>=topology.slots)unresolved();
      const source=sourceFor(topology,this.owner);
      if(step.guard.key!==slotKey(source,data.slot)||step.key!==slotKey(source,data.slot,'ack'))unresolved();
      const slot=await this.adapter.read(step.guard.key,until);
      if(!slot||![originalSlot.version,originalSlot.version+1].includes(slot.version))unresolved();
      try{validatePair(source,data.slot,originalSlot,head);validatePair(source,data.slot,slot,head);}catch{unresolved();}
      slotHeadVersion=slot.version;
    }else unresolved();
    return {version:targetVersion,observedHeadVersion:head.version,retainedHistoryUsed,
      originalTargetDigest:digest(step.desired),slotHeadVersion};}
"""
assert source.count(old) == 1
changed = source.replace(old, new)
before = """        const version=await this.#confirm(step,until);
        this.journal.writeOnce(base+'.confirmed.json',{schema:SCHEMA+'.effect-confirmed',operationDigest:active.id,index,version,desiredDigest:digest(step.desired)});"""
after = """        const confirmation=await this.#confirm(step,until);
        this.journal.writeOnce(base+'.confirmed.json',{schema:SCHEMA+'.effect-confirmed',operationDigest:active.id,index,
          ...confirmation,desiredDigest:digest(step.desired)});"""
assert changed.count(before) == 1
changed = changed.replace(before, after)
(NEW / 'coordinator.mjs').write_text(changed)
(NEW / 'r1-to-r2-confirmation.diff').write_text(''.join(difflib.unified_diff(
    source.splitlines(True), changed.splitlines(True), fromfile='frozen-r1/coordinator.mjs', tofile='candidate-r2/coordinator.mjs')))
note = """\n## Revision 2 confirmation boundary\n\n+Revision 1 and its 19 local results remain frozen. Revision 2 requires the current immutable profile, receipt, control and pre-control enrollment head to remain version 1 with the exact original postimage. Only manifest confirmation can consult retained history, and only when its validated current head is exactly one version above the saved original target. Ack confirmation requires the original target as the current ack; the producer's bound slot may remain at the acknowledged version or advance once, with the original pair validator passing in both cases. A larger head, an old preimage, a changed immutable head, or an invalid pair leaves the original operation unresolved and never authorizes another write.\n\n+Private confirmation records retain the original target digest, observed current head version, whether retained history was used, and the observed slot version. This is a stricter source revision; it cannot adopt a previous implementation's private state binding.\n+"""
note = note.replace('\n+', '\n')
with (NEW / 'README.md').open('a') as stream:
    stream.write(note)
(NEW / 'qualification').mkdir()
print(json.dumps({'runtimeChanged':['coordinator.mjs'], 'frozenR1Unchanged':True,
    'previousImplementationSha256':manifest['implementationSha256'],
    'newCoordinatorSha256':hashlib.sha256(changed.encode()).hexdigest()}))
