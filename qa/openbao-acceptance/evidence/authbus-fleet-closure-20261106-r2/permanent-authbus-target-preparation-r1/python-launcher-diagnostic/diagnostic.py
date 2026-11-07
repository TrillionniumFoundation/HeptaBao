import json,os,sys
from pathlib import Path
print(json.dumps({'schema':'heptabao.python-launcher-runtime-path.r1','uid':os.getuid(),'euid':os.geteuid(),'sysExecutable':sys.executable,'resolvedSysExecutable':str(Path(sys.executable).resolve(strict=True)),'requestedLauncherResolved':str(Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14').resolve(strict=True)),'children':0,'networkOperations':0,'fileWrites':0,'credentialReads':0},sort_keys=True),flush=True)
