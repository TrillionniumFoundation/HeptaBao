import os, sys, json, hashlib, base64, stat
from pathlib import Path
os.umask(0o077)
PARENT=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
SOURCE=PARENT/'official271-standby-policy-oracle-live-61ff-r2'
DEST=PARENT/'official271-standby-policy-oracle-recovery-61ff-r1'
PIN='efc6b9f60aa0caa1c06afa5057277050473433f1361b670eb08f2cb6ebbc84ee'
assert os.geteuid()!=0 and PARENT.resolve(strict=True)==PARENT
assert SOURCE.resolve(strict=True)==SOURCE
for path in (PARENT,SOURCE,SOURCE/'operations'):
    st=path.lstat()
    assert stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid()
def owned_read(directory,name):
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
        try:
            before=os.fstat(f)
            assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.geteuid() and before.st_size<=65536
            with os.fdopen(f,'rb',closefd=False) as stream: raw=stream.read(65537)
            after=os.fstat(f)
            assert len(raw)==before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
            return raw
        finally: os.close(f)
    finally: os.close(fd)
result_raw=owned_read(SOURCE,'result.public.json')
assert hashlib.sha256(result_raw).hexdigest()==PIN
result=json.loads(result_raw)
assert result['http_intents']==result['http_outcomes']==70 and result['http_unknown']==0 and result['all_owned_stopped'] is True
entries=[]
labels=[]
complete=preconnect=unknown=0
methods={}
for sequence in range(1,71):
    pair={}
    for kind in ('intent','outcome'):
        name=f'{sequence:04d}.{kind}.public.json'
        raw=owned_read(SOURCE/'operations',name)
        value=json.loads(raw)
        assert value['sequence']==sequence
        pair[kind]=value
        entries.append({'path':'operations/'+name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'data_base64':base64.b64encode(raw).decode()})
    intent,outcome=pair['intent'],pair['outcome']
    assert intent['label']==outcome['label']
    labels.append(intent['label'])
    methods[intent['method']]=methods.get(intent['method'],0)+1
    complete+=outcome['response_complete'] is True
    preconnect+=outcome['response_complete'] is False and outcome['request_sent'] is False
    unknown+=outcome['outcome_unknown'] is True
assert complete==67 and preconnect==3 and unknown==0
packet={'schema':'owned-public-http-journal-packet-v1','source_root':str(SOURCE),'source_result_sha256':PIN,'file_count':140,'intents':70,'outcomes':70,'complete_http_responses':complete,'definite_preconnect_failures':preconnect,'outcome_unknown':unknown,'methods':methods,'files':entries,'private_files_read':False,'service_actions':False,'operation_replay':False}
raw=(json.dumps(packet,sort_keys=True,indent=2)+'\n').encode()
assert len(raw)<=1048576
DEST.mkdir(mode=0o700)
def save(name,data):
    fd=os.open(DEST/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
save('collect_public_journal.py',SOURCE_BYTES)
save('public-journal.packet.json',raw)
receipt={'schema':'owned-public-http-journal-recovery-v1','status':'completed','source_result_sha256':PIN,'source_helper_sha256':hashlib.sha256(SOURCE_BYTES).hexdigest(),'packet_path':str(DEST/'public-journal.packet.json'),'packet_bytes':len(raw),'packet_sha256':hashlib.sha256(raw).hexdigest(),'file_count':140,'intents':70,'outcomes':70,'complete_http_responses':67,'definite_preconnect_failures':3,'outcome_unknown':0,'service_actions':False,'operation_replay':False,'private_files_read':False}
save('collection.public.json',(json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode())
fd=os.open(DEST,os.O_RDONLY|os.O_DIRECTORY)
try: os.fsync(fd)
finally: os.close(fd)
print(json.dumps(receipt,sort_keys=True))
