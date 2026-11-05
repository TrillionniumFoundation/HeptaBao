import pathlib,hashlib,json,sys
base=pathlib.Path('/workspace/scratch/f86faac821c4/official271-matrix-review-r1')
traw=(base/'official-tree.original.json').read_bytes()
tree=json.loads(traw)
entries=sorted([[x['path'],x['mode'],x['type'],x['sha'],x.get('size')] for x in tree['tree']],key=lambda x:x[0])
assert hashlib.sha256(json.dumps(entries,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()==sys.argv[1]
tm={x['path']:x for x in tree['tree']}
corpus=json.loads((base/'source-corpus-r3.json').read_bytes())
assert len(corpus['sources'])==242
bad=[];total=0
for m in corpus['metas']:
 b=corpus['sources'][m['path']].encode()
 if m['path'] not in tm or tm[m['path']]['type']!='blob' or tm[m['path']]['sha']!=m['blob'] or tm[m['path']]['size']!=m['bytes'] or hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()!=m['blob'] or hashlib.sha256(b).hexdigest()!=m['sha256'] or len(b)!=m['bytes']:bad.append(m['path'])
 total+=len(b)
assert not bad,bad
d=json.loads((base/'official271-source-contract-declarations-v2.public.json').read_bytes())
print(json.dumps({'schema':'heptabao.root.official271-corpus-membership.v1','official_commit':'a5db72cef75c24b920ade02065b18dd8eb666bac','canonical_tree':'3a8ba726d8d557a5f9b3f2ed28b406da33632182','root_retrieved_canonical_entries_sha256':sys.argv[1],'local_raw_tree_sha256':hashlib.sha256(traw).hexdigest(),'full_tree_entries':len(tree['tree']),'source_files_verified':len(corpus['sources']),'source_bytes_verified':total,'wrong_paths_or_hashes':bad,'declaration_keys':list(d),'counts':{k:v for k,v in d.items() if not isinstance(v,(dict,list))},'family_keys':list(d.get('families',{}))},sort_keys=True))
