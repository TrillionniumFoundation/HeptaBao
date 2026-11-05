import json,sys
c=json.loads(sys.argv[1]);f=json.loads(sys.argv[2]);b=c['bundle'];i=b['identity']
assert c['status']=='exported' and c['all_owned_stopped'] and c['deadline_before_receipt_passed']
assert c['source_before']==c['source_after'] and c['canonical_proof']['commit_count']==3755 and c['canonical_proof']['full_fsck_passed']
assert len(c['commands'])==len(c['cleanup'])==27 and len({r['pid'] for r in c['cleanup']})==27
assert all(r['direct_child_reaped'] and r['remaining']==[] for r in c['cleanup'])
assert i[2]==1000 and i[5]==1 and i[4]&0o777==0o600 and i[6]==b['bytes']
print(json.dumps({'bundle':{'path':b['path'],'name':'canonical-3cb-full.bundle','bytes':b['bytes'],'sha256':b['sha256'],'source_mode':384,'target_mode':256,'version':':'.join(str(i[n]) for n in (0,1,6,7,8))},'receipt':{'path':f['path'],'name':'source-export.result.public.json','bytes':f['size'],'sha256':f['sha256'],'source_mode':384,'target_mode':256,'version':f['version']},'identity_integer_preservation':'parsed original JSON with Python integer semantics'},sort_keys=True))
