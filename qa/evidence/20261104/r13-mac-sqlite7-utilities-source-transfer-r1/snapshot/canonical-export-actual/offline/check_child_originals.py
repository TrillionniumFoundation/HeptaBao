import hashlib,json,sys
x=json.loads(sys.argv[1]);c=json.loads(x['core']);b=json.loads(x['body']);by={r['label']:r for r in c['commands']};verified=[]
root='/home/qian-qi/heptabao-phaseb-ingress-observer-source-export-20261104-r1'
head=c['canonical_commit'];tree=c['canonical_tree'];source=c['source']
expected_stdout={'source-before-head':head+'\n','source-after-head':head+'\n','source-before-tree':tree+'\n','source-after-tree':tree+'\n','source-before-status':'','source-after-status':'','source-before-git-dir':source+'/.git\n','source-after-git-dir':source+'/.git\n','source-before-common-dir':'.git\n','source-after-common-dir':'.git\n','source-before-shallow':'false\n','source-after-shallow':'false\n','source-before-partial-config':'','source-after-partial-config':'','source-before-origin':'https://github.com/TrillionniumFoundation/HeptaBao.git\n','source-after-origin':'https://github.com/TrillionniumFoundation/HeptaBao.git\n','source-before-refs':'','source-after-refs':'','export-proof-kind':'commit\n','export-proof-tree':tree+'\n','export-proof-parents':'bf0aaec1dcafbf476c0ab3a75544bb0eafaeff24\n','export-proof-count':'3755\n','export-proof-roots':'67d79b3b5442ed033d38929eab2010403463e56d\n','export-proof-full-fsck':'','bundle-create':'','bundle-heads':head+' HEAD\n'}
assert not b['truncated']
for f in b['files']:
 name=f['path'].removeprefix(root+'/');assert f['path']==root+'/'+name
 raw=f['text'].encode();assert f['eof'] and len(raw)==f['size'] and hashlib.sha256(raw).hexdigest()==f['sha256']
 if name=='intent.public.json':
  intent=json.loads(f['text'])
  assert intent['controller']==c['controller'] and intent['canonical_commit']==head and intent['canonical_tree']==tree and intent['source']==source and intent['bundle']==root+'/canonical-3cb-full.bundle'
  assert intent['expected_prerequisites']==[] and intent['expected_full_commit_count']==3755 and intent['overall_seconds']==300 and intent['git_command_seconds']==90 and not intent['server_started'] and not intent['compiler_started']
  kind='intent'
 elif name.endswith('.public.json'):
  label=name[:-12];assert json.loads(f['text'])==by[label];kind='record'
 else:
  suffix='.stdout' if name.endswith('.stdout') else '.stderr';assert name.endswith(suffix)
  label=name[:-len(suffix)];kind=suffix[1:];r=by[label]
  assert len(raw)==r[kind+'_bytes'] and hashlib.sha256(raw).hexdigest()==r[kind+'_sha256']
  plain=label[4:]
  if kind=='stdout' and plain in expected_stdout:assert f['text']==expected_stdout[plain],plain
 verified.append({'name':name,'kind':kind,'bytes':len(raw),'sha256':f['sha256']})
print(json.dumps({'schema':'heptabao.phaseb3cb.export-child-originals-check.v1','status':'passed','batch':x['batch'],'files':verified,'no_candidate_or_host_execution':True},sort_keys=True))
