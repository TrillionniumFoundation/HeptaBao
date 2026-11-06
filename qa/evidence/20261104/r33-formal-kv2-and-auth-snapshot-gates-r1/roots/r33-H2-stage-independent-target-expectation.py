import json,hashlib,pathlib
B=pathlib.Path('/workspace/scratch/f86faac821c4/r32_recovery')
def read(sha):
 s=json.loads((B/('blob-'+sha+'.json')).read_text())['text']; d=s.encode()
 assert hashlib.sha1(b'blob '+str(len(d)).encode()+b'\0'+d).hexdigest()==sha
 return s
def pin(d):
 return {'blob':hashlib.sha1(b'blob '+str(len(d)).encode()+b'\0'+d).hexdigest(),'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()}
src=read('678e519f17c474b5610651bcbb93b43d186124c5')
text=read('e4b2ab7d6800225ad1f8c87e5cb51fb330840907')
assert hashlib.sha256(src.encode()).hexdigest()=='a8bf27675b1a00b08f60d33fbed84405c033d537fb9562d963b9ff725264fca1'
assert hashlib.sha256(text.encode()).hexdigest()=='cd7de0b60ff21476b5812c2159f8c44b55484fd9d1cd1a0900477a61853dd249'
o=json.loads(text)
assert o['status']=='passed' and o['all_stage_fds_closed'] is True and o['fd_close_errors']==[] and o['fd_close_pending'] is False and o['within_stage_deadline'] is True
removed={k:o.pop(k) for k in ['all_stage_fds_closed','fd_close_errors','elapsed_after_closure_ms','within_stage_deadline']}
o['fd_close_pending']=True
d=(json.dumps(o,sort_keys=True,indent=2)+'\n').encode()
expected=pin(d)
assert expected=={'blob':'f492ce4e681ba7d5917d1cda1ebd4a3f8d67f13c','bytes':28615,'sha256':'f2bcc9227a235a40afa11c1703595180a925fbd39abd29d4550872ed3a05ae6a'}
binding=o['binding']
assert binding['bytes']==10230 and binding['sha256']=='b241c6fc78bbe77ea69fc3b8a707b1747324a81f1da1ade3d9bb15c5cea5b7d8'
assert binding['mode']==384 and binding['uid']==binding['gid']==1000 and binding['links']==1
assert binding['mtime_ns']==binding['ctime_ns']==1793915867275098276
assert binding['device']==2050 and binding['inode']==7874334
print(json.dumps({'schema':'heptabao.H2-stage.root-independent-preclose-expectation.v1','ok':True,'source_candidate':'678e519f17c474b5610651bcbb93b43d186124c5','original_stdout':'e4b2ab7d6800225ad1f8c87e5cb51fb330840907','source_tail_manually_reviewed_by_root':True,'expected_receipt':expected,'removed_post_finally_fields':removed,'restored_field':{'fd_close_pending':True},'binding_writer_identity':binding,'target_info_reads':0,'target_body_reads':0,'candidate_executed':False,'author_deriver_executed':False,'expectation_is_not_observation':True},indent=2))
