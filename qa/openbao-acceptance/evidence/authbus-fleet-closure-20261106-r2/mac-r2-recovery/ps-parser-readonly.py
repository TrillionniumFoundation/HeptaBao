import json,os,re,subprocess,sys
assert sys.platform=='darwin' and os.geteuid()==501
p=subprocess.run(['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,stat='],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4,check=False,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
assert p.returncode==0 and not p.stderr and len(p.stdout)<=262144
bad=[];related=[];total=0
for line in p.stdout.decode('ascii','strict').splitlines():
    total+=1;f=line.split()
    ok=len(f)==5 and all(v.isdecimal() for v in f[:4]) and re.fullmatch(r'[A-Za-z0-9+<>=-]{1,16}',f[4]) is not None
    safe=len(f)==5 and all(re.fullmatch(r'-?[0-9]{1,12}',v) is not None for v in f[:4]) and re.fullmatch(r'[A-Za-z0-9+<>=?/.-]{1,16}',f[4]) is not None
    if not ok:
        assert safe and len(bad)<16
        bad.append({'pid':f[0],'ppid':f[1],'pgid':f[2],'uid':f[3],'stat':f[4],
                    'decimalChecks':[v.isdecimal() for v in f[:4]],
                    'statAcceptedByR1':re.fullmatch(r'[A-Za-z0-9+<>=-]{1,16}',f[4]) is not None})
    if len(f)==5 and any(v=='32527' for v in f[:3]):
        assert safe;related.append({'pid':f[0],'ppid':f[1],'pgid':f[2],'uid':f[3],'stat':f[4]})
print(json.dumps({'schema':'heptabao.mac-authbus-r2-ps-parser-readonly.r1','ok':True,
 'rowCount':total,'rawMetadataBytes':len(p.stdout),'rejectedRows':bad,'relatedRows':related,
 'serviceActions':0,'processArgumentsRead':False,'credentialValuesOrDigestsIncluded':False},sort_keys=True),flush=True)
