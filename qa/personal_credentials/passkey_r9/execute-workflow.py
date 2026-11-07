#!/usr/bin/env python3
"""One dispatch per fixed stage; checkpoint arguments never bypass peer admission."""
import argparse,hashlib,json,os,re,stat,time
from pathlib import Path
BASE=Path('/home/alex/HeptaBaoPasskey-20261106-r9')
BUILD='97a6daec5bb7276b935498fb3c8501df9ecc57a118641cffb9f2df3ae6edd009'
PROFILE='b6b7754bad0e34cf55b0c2635683b03093555fa5d3f096533ee36b3e02eec55b'
STAGES={'RP': {'path': 'artifacts/passkey_rp.py', 'sha256': '386de84bb5335f21998a000b4a1267eaa17fadbde1e1753d5df1c30325709a63'}, 'SETUP': {'path': 'runtime-sources/setup-r9.py', 'sha256': 'd215bdf2d8d002b961b598f5f7d2e0ab73b898cf44ec3a7d4690c4876da5b66b'}, 'DOCUMENTS': {'path': 'runtime-sources/documents-prepare-r9.py', 'sha256': '4107b925ecf37f7930d3f1b06805e72e16b23fb3f593109eb6c050fff859cf89'}, 'M01': {'path': 'runtime-sources/M01-ordinary-saf-r9.py', 'sha256': '215a99236c454cafbf02b83b870109e4a5fe304c1c69f0dfe9427a5c67ef308f'}, 'M02': {'path': 'runtime-sources/M02-real-cm-create-r9.py', 'sha256': '2c147e1d2b90e21fb18789138a4c936471fe2c377923b59f01dea6b4810a6ec5'}, 'M03': {'path': 'runtime-sources/M03-real-cm-get-r9.py', 'sha256': '2560ac82f4a35b3834cb938fc01a1deb928e38c7d3eac1912ecc4a994f3c4052'}, 'M04': {'path': 'runtime-sources/M04-ordinary-saf-backup-r9.py', 'sha256': 'c49ec9c5473ce911c9df63066c6a49258f69b9bc9ca62846317765a88aa8d2c6'}, 'M05_OBSERVE': {'path': 'runtime-sources/reset-input-observer-r9.py', 'sha256': '5442708c50e8616fd803a86b3f842c28c192313205e2762bb9e5fe7e32155e6f'}, 'M05_RESET': {'path': 'passkey_reset_provider_r9.py', 'sha256': 'c3d7da8f20fd03b7463eb59ad846718bcae5cad1668972eb626a7fd368aa4d30'}, 'M05_RESTORE': {'path': 'runtime-sources/M05-fresh-process-saf-restore-r9.py', 'sha256': '6d3618c50bba58596aa65276b55255682c62b5aa3a2fd3ae546016eab2fa5e3b'}, 'M06': {'path': 'runtime-sources/M06-real-get-after-restore-r9.py', 'sha256': '3b27a1cc7826e6d6898243a44633645dfcbf136d25413e91488895068ef586c5'}, 'G11_RECOVERY_EXPORT': {'path': 'runtime-sources/G11-current-ordinary-saf-backup-r9.py', 'sha256': '6572507dfb9bdbea1af5285e59fd4574d7c9a29a54b51ac79a6022d7468e7e47'}, 'G11_OBSERVE': {'path': 'runtime-sources/reset-input-observer-r9.py', 'sha256': '5442708c50e8616fd803a86b3f842c28c192313205e2762bb9e5fe7e32155e6f'}, 'G11_RESET': {'path': 'passkey_reset_provider_r9.py', 'sha256': 'c3d7da8f20fd03b7463eb59ad846718bcae5cad1668972eb626a7fd368aa4d30'}, 'G11_STALE': {'path': 'runtime-sources/G11-stale-saf-restore-real-cm-get-r9.py', 'sha256': 'a03f794df6da0e09da423fbea87c32315e42d5d050a0d65d4f1bb71adcfab96f'}, 'G02_G06': {'path': 'runtime-sources/G02-G06-real-CM-guards-r9.py', 'sha256': 'c7c8baad3f9b26894f1bd7b4bded39cec95d776d5010e8d0299dc7c0ffb7a6b5'}, 'G07': {'path': 'runtime-sources/G07-real-CM-cancel-r9.py', 'sha256': 'c1b52486e9f8520612a5a845272b7b4acb14fc2c76acb7c7ef3f2620dea90c13'}, 'SAF_GUARDS': {'path': 'runtime-sources/G01-G08-G09-G10-ordinary-SAF-guards-r9.py', 'sha256': 'ad9ac360041028c8522df1330ade5305cbd1f612cff03830ee92a238cb944444'}, 'M07_RESTORE': {'path': 'runtime-sources/M07-core-compare-restore-r9.py', 'sha256': 'b7b2ff3fc418f4fbac54116f49aff0b01d52906bdf94e6286acaed26cd281388'}, 'M07_CLEANUP': {'path': 'runtime-sources/M07-cleanup-r9.py', 'sha256': '3c61c5c3eb09d28e1811e60386b4803374c601779e5669d8962c9b0778e9d3e1'}, 'RELEASE': {'path': 'runtime-sources/independent-release-r9.py', 'sha256': '7009a3577780eedeaae9f5d8124f4811e4fe68651f2a8c8c2e7159c67486936f'}}

def sha(b):return hashlib.sha256(b).hexdigest()
def private_file(path,limit):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600 and s.st_uid==os.geteuid() and s.st_nlink==1 and s.st_size<=limit
  with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(limit+1)
  assert len(raw)==s.st_size;return raw
 finally:os.close(fd)
def arguments(stage,checkpoint,result,witness,dispatcher=None):
 supplied=[x is not None for x in (checkpoint,result,witness)]
 for x in (checkpoint,result,witness,dispatcher):assert x is None or re.fullmatch(r'[0-9a-f]{64}',x)
 if stage.endswith('_OBSERVE'):
  assert supplied==[False,False,False] and dispatcher is not None
  return ['--case-id',stage.split('_')[0],'--expected-dispatcher-sha256',dispatcher]
 assert dispatcher is None
 if stage.endswith('_RESET'):
  assert supplied==[True,False,False];case=stage.split('_')[0]
  return ['--driver',str(BASE/'passkey_live.r9.py'),'--adb','/home/alex/.local/bin/adb','--root',str(BASE/'live-r9'),'--artifacts',str(BASE/'artifacts'),'--expected-build-sha256',BUILD,'--case-id',case,'--expected-checkpoint-sha256',checkpoint]
 if stage in ('M05_RESTORE','G11_STALE'):
  assert supplied==[True,True,True]
  return ['--checkpoint-sha256',checkpoint,'--reset-result-sha256',result,'--completion-sha256',witness]
 assert supplied==[False,False,False]
 if stage=='RP':return ['--root',str(BASE/'rp-r9'),'--fixture-cert-sha256','cb684e07720b0233e9aa87bc74e87cf40956476770dabc2a426bee30dcba6135','--port','38491','--challenge-ttl','180','--crypto-backend','openssl']
 return []
def main():
 os.umask(0o077);ap=argparse.ArgumentParser();ap.add_argument('--stage',choices=sorted(STAGES),required=True)
 ap.add_argument('--checkpoint-sha256');ap.add_argument('--reset-result-sha256');ap.add_argument('--completion-sha256');ap.add_argument('--expected-dispatcher-sha256');a=ap.parse_args()
 argv=arguments(a.stage,a.checkpoint_sha256,a.reset_result_sha256,a.completion_sha256,a.expected_dispatcher_sha256)
 if a.expected_dispatcher_sha256 is not None:assert sha(Path(__file__).read_bytes())==a.expected_dispatcher_sha256
 for directory in (BASE,BASE/'stage-invocations'):
  s=directory.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o700
 assert sha(private_file(BASE/'artifacts/build.receipt.json',1048576))==BUILD and sha(private_file(BASE/'profile.public.json',65536))==PROFILE
 row=STAGES[a.stage];source=BASE/row['path'];assert sha(private_file(source,131072))==row['sha256']
 command=['/usr/bin/python3','-I','-B',str(source),*argv]
 value={'schema':1,'stage':a.stage,'source_sha256':row['sha256'],'dispatcher_sha256':sha(Path(__file__).read_bytes()),'argv':command,'created_unix_ns':time.time_ns(),'unknown_result_must_not_be_reissued':True,'case_passed_by_dispatch':False}
 data=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode();path=BASE/'stage-invocations'/(a.stage+'.intent.public.json')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 os.execv(command[0],command)
if __name__=='__main__':main()
