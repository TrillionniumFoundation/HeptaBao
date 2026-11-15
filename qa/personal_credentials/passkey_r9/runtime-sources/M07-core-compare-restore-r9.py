import pathlib,hashlib,subprocess,sys
b=pathlib.Path("/home/alex/HeptaBaoPasskey-20261106-r9");p=b/"run_phases.input-r9.public.py"
assert hashlib.sha256(p.read_bytes()).hexdigest()=="38793057a126e755fd965a218aa5c4f7d078dd78a3af4386a7cb6accfe679e60"
r=subprocess.run(["/usr/bin/python3","-B",str(p),"--case","M07","--steps",'[{"phase":"restore"}]'],timeout=240)
raise SystemExit(r.returncode)
