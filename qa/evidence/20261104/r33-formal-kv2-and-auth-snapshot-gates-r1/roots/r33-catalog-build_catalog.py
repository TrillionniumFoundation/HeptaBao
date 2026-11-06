import hashlib
import json
import re
from pathlib import Path

ROOT=Path('/workspace/scratch/f86faac821c4')
RECOVERY=ROOT/'r32_recovery'
OUT=ROOT/'ha_r33_catalog_delta_r1'
OUT.mkdir(exist_ok=True)

def blob_meta(text):
    b=text.encode('utf-8')
    return {'blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),
            'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}

def load_original(path):
    raw=path.read_text()
    o=json.loads(raw)
    if isinstance(o,dict) and set(o)=={'text'}:
        raw=o['text'];o=json.loads(raw)
    return o,raw

def extract_tree(o,depth=0):
    if depth>5:return None
    if isinstance(o,str):
        try:return extract_tree(json.loads(o),depth+1)
        except (ValueError,TypeError):return None
    if not isinstance(o,dict):return None
    if re.fullmatch('[0-9a-f]{40}',str(o.get('sha',''))) and isinstance(o.get('tree'),list):
        return o
    for key in ['text','structuredContent','content']:
        v=o.get(key)
        if isinstance(v,list):
            for block in v:
                if isinstance(block,dict) and isinstance(block.get('text'),str):
                    t=extract_tree(block['text'],depth+1)
                    if t:return t
        elif isinstance(v,(str,dict)):
            t=extract_tree(v,depth+1)
            if t:return t
    return None

def audit_tree(tree):
    assert not tree.get('truncated'),tree['sha']
    rows=tree['tree'];by_path={r['path']:r for r in rows}
    assert len(by_path)==len(rows),'duplicate paths'
    tree_nodes={'':tree['sha'],**{r['path']:r['sha'] for r in rows if r['type']=='tree'}}
    for directory, expected in tree_nodes.items():
        children=[]
        for path,row in by_path.items():
            parent,_,name=path.rpartition('/')
            if parent!=directory:continue
            assert row['type'] in ['tree','blob'],'unexpected Git node'
            mode='40000' if row['type']=='tree' else row['mode']
            sort_key=(name+('/' if row['type']=='tree' else '')).encode()
            raw=mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(row['sha'])
            children.append((sort_key,raw))
        data=b''.join(raw for _,raw in sorted(children))
        actual=hashlib.sha1(b'tree '+str(len(data)).encode()+b'\0'+data).hexdigest()
        assert actual==expected,(directory,expected,actual)
    leaves=[r for r in rows if r['type']=='blob']
    return {'files':len(leaves),'bytes':sum(r['size'] for r in leaves),'merkle':len(tree_nodes)}

draft_path=RECOVERY/'r33-checkpoint-packet-plan-draft.json'
draft,draft_raw=load_original(draft_path)
assert len(draft['packets'])==16
additions=[
 {'name':'H2-current-stage-original106','tree':'a78dc168435d5951385ef2a01d377524bfc68d83','scope':'actual stage original chain; no H2 prepare/live',
  'review_references':['9f6617e593a66d63da9f7fc10200a2e28ba56c4d'],'count_reference':'root395 / existing stage packet'},
 {'name':'Auth-registration-original-chain-peer7','tree':'6d1bfe6fb193bb2ad172fccdb441602e3715c7af','scope':'714 independent original-chain checks; not SDK or product execution',
  'review_references':['7bf70816e5cb26e8f627b77135b50a4c8918b7b5','65b6f2235fcf055ff15fc9177fd6f80727449462']},
 {'name':'Auth-Google-entry-original38','tree':'135407c6d3156a8602da63184c0df4143aa137ea','scope':'fixed public entry metadata/body originals; actual selected owner not inferred',
  'review_local_reference':str(RECOVERY/'r33-Auth-entry38-root-result.public.json')},
 {'name':'Auth-owner-bound-source88','tree':'71a1656fbe227fcea1e92558a5004e22eaab69c6','scope':'bound SOURCE, no runtime qualification',
  'review_references':['68838a0c45042258358892d20778b0aee3b14b27','fb57872b59c10fe82ca348986cd4ddf5ac8bfc58']},
 {'name':'Auth-owner-stdin-overlay10','tree':'2f213b0e8de72fac88fec0039761390f34f9e946','scope':'exact request schema correction, preserving old proposal',
  'review_local_reference':str(RECOVERY/'r33-Auth-source88-overlay10-root-result.public.json')},
 {'name':'Auth-owner-archive-recovery14','tree':'bb48916a5f83d37eb7faae2ed139db976bfef658','scope':'Git archive errors and same public byte recovery; no Runtime replay',
  'review_references':['fb57872b59c10fe82ca348986cd4ddf5ac8bfc58']},
 {'name':'Auth-owner-three-target-source6','tree':'c780abd37895a5cab64775bf3166c67da0f1faf6','scope':'three fixed public target observation SOURCE only',
  'known_source':str(RECOVERY/'owner-postinert-three-targets-fetch-sdk.json')},
 {'name':'H2-target-actual-original123','tree':'51e78b6600d671e0565c8911b452650812410474','scope':'5 original observers / 10 pages / 38845 bytes, 2 independent file_infos; no prepare/live',
  'review_references':['b5aa3ca4cc494fc3fcf0737b083876b3931fee3c','0093a0be7a54f88393626276c864b5a46b1c8770','c2545057a868ae12869df0dc8e904398118a5ab8']},
 {'name':'X230-comparison69-complete-original193','tree':'045449626f3b1d62154ce6e5c42e2c9c7dc36bfd','scope':'192 original leaves plus manifest; 69 cases per implementation, scoped compatibility only',
  'review_references':['661060e634ee99e2c67c1403f1344a062fd76ee2'],
  'original_local_map':str(RECOVERY/'comparison69-complete-files-index.json')}
]
optional=[{'name':'H2-prepare-bound-SOURCE13','tree':'2aa05d9fcb6006c3086edb25c6ab83f8f30e7328',
 'scope':'SOURCE-only original prepare request; args[7] actual binding SHA resolved, not submitted or authorized',
 'request':'2059cf884472ae55dc799be4b781f9fe96efd10e','runtime_GO':False,'submitted':False,
 'original_local_map':str(RECOVERY/'ha-prepare-complete-packet.json')}]
desired={r['tree'] for r in draft['packets']+additions+optional}
found={}
scanned=0
for path in sorted(RECOVERY.glob('*.json')):
    if 'tree' not in path.name.lower() and path.name!='owner-postinert-three-targets-fetch-sdk.json':continue
    scanned+=1
    try:raw=path.read_text();o=json.loads(raw);t=extract_tree(o)
    except (ValueError,TypeError):continue
    if not t or t['sha'] not in desired:continue
    previous=found.get(t['sha'])
    if previous and len(previous['tree']['tree'])>=len(t['tree']):continue
    found[t['sha']]={'tree':t,'source':str(path),'source_bytes':len(raw.encode()),'source_sha256':hashlib.sha256(raw.encode()).hexdigest()}

adopted={
 '385b356167187308221d8c2d5c12ece7c1da24e3':{
     'source':str(RECOVERY/'r33-google78-root-result.public.json'),
     'root_review':'58c08e40c4d72f3060b053c034e88c1ffa906232',
     'files':78,'bytes':374228,'merkle':26,
     'basis':'Existing root244 whole/26-Merkle result; neither checker nor original reads rerun.'},
 'a74af927eedfddd78ae23b3fd03afc6638d76e8f':{
     'source':str(draft_path),'files':7,'bytes':59808,'merkle':3,
     'basis':'Existing root draft16 exact prior-peer packet count; this local pass does not reconstruct its directory from a new fetch.'}
}
missing=sorted(desired-set(found)-set(adopted))
if missing:
    (OUT/'missing-local-trees.public.json').write_text(json.dumps({'missing':missing,'scanned_tree_wrappers':scanned},indent=2)+'\n')
    raise RuntimeError('missing existing local trees: '+str(missing))
checks=[]
def enrich(row,origin):
    entry=dict(row)
    if row['tree'] in found:
        v=found[row['tree']];counts=audit_tree(v['tree'])
        entry['immutable_tree_source']={'path':v['source'],'wrapper_bytes':v['source_bytes'],'wrapper_sha256':v['source_sha256']}
        entry['local_tree_identity_recomputed']=True
    else:
        v=adopted[row['tree']];counts={k:v[k] for k in ['files','bytes','merkle']}
        source=Path(v['source']);source_o,source_raw=load_original(source)
        if 'root_review' in v:
            assert blob_meta(source_raw)['blob']==v['root_review']
            assert source_o['ok'] and source_o['packet']==row['tree']
            assert (source_o['whole_files'],source_o['whole_bytes'],source_o['Merkle_trees'])==(counts['files'],counts['bytes'],counts['merkle'])
        entry['inherited_count_source']={**v,'original_inner':blob_meta(source_raw)}
        entry['local_tree_identity_recomputed']=False
    for k in ['files','bytes','merkle']:
        if k in entry:assert entry[k]==counts[k],(row['name'],k,entry[k],counts[k])
    entry.update(counts)
    entry['catalog_origin']=origin
    entry['runtime_or_semantic_verifier_rerun']=False
    entry['suggested_mount']=draft['prefix']+'/'+row['name']
    checks.append({'name':row['name'],'tree':row['tree'],**counts,'local_tree_identity_recomputed':entry['local_tree_identity_recomputed'],'ok':True})
    return entry

base=[enrich(r,'unchanged draft16') for r in draft['packets']]
delta=[enrich(r,'explicit root requested addition') for r in additions]
proposal=[enrich(r,'new SOURCE proposal, separately listed for root choice') for r in optional]
def totals(rows):return {'packets':len(rows),'files':sum(r['files'] for r in rows),'bytes':sum(r['bytes'] for r in rows),'merkle_nodes':sum(r['merkle'] for r in rows)}
catalog={'schema':'heptabao.R33.local-public-packet-catalog-delta.v1',
 'not_a_commit_or_publication':True,'Runtime_calls':0,'root_doc_index_branch_modified':False,
 'draft_source':{'path':str(draft_path),'inner':blob_meta(draft_raw)},
 'previous_commit':draft['previous_commit'],'previous_tree':draft['previous_tree'],'evidence_prefix':draft['prefix'],
 'base_packets_unchanged':base,'additions':delta,'separate_SOURCE_proposals_for_root_choice':proposal,
 'totals':{'base':totals(base),'requested_additions':totals(delta),'requested_combined':totals(base+delta),'SOURCE_proposal_optional':totals(proposal),'including_optional_SOURCE':totals(base+delta+proposal)},
 'counts_are_sums_of_packet_paths_not_cross_packet_unique_blobs':True,
 'tree_count_verification':'Rebuilt 24 immutable tree identities from existing local recursive Git-tree SDK wrappers; inherited Google78 root244 and prior-peer7 draft counts explicitly. Existing author/root business and original-chain checkers were not rerun.',
 'original_pending_now_has_packet':draft['pending_packets'],
 'boundaries':['H2 target observations prove only their two fixed file identities plus three whole body chunks, not independently statted identities for all staged targets.',
  'H2 and CLI prepare/live remain distinct future actions; packet inclusion does not authorize any action.',
  'X230 full34 original 39 framework index leaves remain unlocated; new current observers do not replace them.',
  'X230 comparison69 remains scoped compatibility, including 67 numeric matches and 2 normalized PKI rejection cases; no full compatibility claim.',
  'Git archive transport errors, cache-recovery histories and stage status-query UNKNOWN are preserved; none are converted to new product execution.']}
(OUT/'catalog-delta.public.json').write_text(json.dumps(catalog,ensure_ascii=False,indent=2)+'\n')
result={'schema':'heptabao.R33.local-catalog-tree-identity-result.v1','ok':True,'scanned_existing_local_tree_wrappers':scanned,
 'listed_trees':len(checks),'local_recomputed_tree_count':sum(r['local_tree_identity_recomputed'] for r in checks),
 'all_local_merkle_nodes':sum(r['merkle'] for r in checks if r['local_tree_identity_recomputed']),
 'inherited_merkle_nodes':sum(r['merkle'] for r in checks if not r['local_tree_identity_recomputed']),
 'tree_results':checks,'Runtime_calls':0,'new_Git_reads':0,'root_files_modified':False,
 'first_local_index_gap_preserved':'missing-local-trees.public.json and r32_recovery/ha-r33-catalog-first-local-executor.json; no Runtime or Git request resulted'}
(OUT/'verification-result.public.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
lines=['# R33 public packet catalog delta','',
 'This is a local catalog for root to merge. It does not update the checkpoint, index, branch or any Runtime job.','',
 '| Group | Packets | File leaves | Bytes | Merkle nodes |','|---|---:|---:|---:|---:|']
for k,v in catalog['totals'].items():lines.append(f"| {k} | {v['packets']} | {v['files']} | {v['bytes']} | {v['merkle_nodes']} |")
lines += ['', '## Requested additions','', '| Packet | Tree | Files | Bytes | Merkle nodes |','|---|---|---:|---:|---:|']
for r in delta:lines.append(f"| {r['name']} | `{r['tree']}` | {r['files']} | {r['bytes']} | {r['merkle']} |")
lines += ['', 'The H2 prepare SOURCE13 is listed separately for root choice. Its original request has not been submitted.', '',
 'Counts are sums over packet paths. Repeated immutable blobs across packets are counted once per path, not deduplicated.', '',
 'Twenty-four recursive tree objects were already local and their identities were reconstructed. Google78 root244 and the prior-peer7 draft counts are explicitly inherited. This pass did not rerun business tests or original-chain verifiers.', '']
(OUT/'README.md').write_text('\n'.join(lines))
print(json.dumps({'catalog_path':str(OUT/'catalog-delta.public.json'),'result_path':str(OUT/'verification-result.public.json'),'totals':catalog['totals'],'local_Merkle_nodes':result['all_local_merkle_nodes'],'Runtime_calls':0,'new_Git_reads':0}))
