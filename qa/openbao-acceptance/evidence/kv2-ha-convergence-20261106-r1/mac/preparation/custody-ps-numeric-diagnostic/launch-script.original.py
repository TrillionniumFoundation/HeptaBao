import subprocess,json
p=subprocess.run(['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,state='],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
rows=p.stdout.decode('ascii','strict').splitlines();bad=[]
for line in rows:
 c=line.split()
 if not (len(c)==5 and all(v.isdecimal() for v in c[:4]) and c[4][0] in 'RSDTIUZX?'):
  bad.append({'columns':c,'column_count':len(c),'decimal_flags':[v.isdecimal() for v in c[:4]]})
print(json.dumps({'exit_code':p.returncode,'stderr_bytes':len(p.stderr),'row_count':len(rows),'bad_shape_rows':bad[:30],'bad_shape_count':len(bad),'all_state_prefixes':sorted(set(c.split()[-1][0] for c in rows if c.split()))}),flush=True)
