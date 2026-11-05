import ast,hashlib,io,json,sys
from pathlib import Path
root=Path('/tmp/authbus-production-p01-source-r1')
source=(root/'project_public_registration.py').read_bytes()
parts=[(root/('fixture-'+str(i)+'.bin')).read_bytes() for i in range(7)]
raw=b''.join(parts)
assert len(raw)==328295 and hashlib.sha256(raw).hexdigest()=='d0bab0c53bd92524b6a7ca7c3d5bc7ab60b26eb742c4a8e2c6f094c62e3f7b59'
parsed_ast=ast.parse(source,filename='project_public_registration.py')
imports=[alias.name for node in ast.walk(parsed_ast) if isinstance(node,ast.Import) for alias in node.names]
assert imports==['hashlib','json','sys','time'],imports
code=compile(parsed_ast,'project_public_registration.py','exec')
old=(sys.stdin,sys.stdout,sys.stderr)
in_stream=io.TextIOWrapper(io.BytesIO(raw),encoding='utf-8')
out_memory=io.BytesIO(); err_memory=io.BytesIO()
out_stream=io.TextIOWrapper(out_memory,encoding='utf-8'); err_stream=io.TextIOWrapper(err_memory,encoding='utf-8')
exit_code=None
try:
    sys.stdin,sys.stdout,sys.stderr=in_stream,out_stream,err_stream
    try:
        exec(code,{'__name__':'__main__'})
    except SystemExit as e:
        exit_code=e.code
    finally:
        out_stream.flush();err_stream.flush()
    stdout=out_memory.getvalue();stderr=err_memory.getvalue()
finally:
    sys.stdin,sys.stdout,sys.stderr=old
for name,data in [('input.public.json',raw),('stdout.original.json',stdout),('stderr.original.txt',stderr)]:
    with (root/name).open('xb') as f:f.write(data)
report={'schema':'heptabao.authbus-p01-local-projection-execution.r1','candidateExitCode':exit_code,'sourceBytes':len(source),'sourceSha256':hashlib.sha256(source).hexdigest(),'inputBytes':len(raw),'inputSha256':hashlib.sha256(raw).hexdigest(),'stdoutBytes':len(stdout),'stdoutSha256':hashlib.sha256(stdout).hexdigest(),'stderrBytes':len(stderr),'stderrSha256':hashlib.sha256(stderr).hexdigest(),'sourceImports':imports,'candidateInvokedWithInMemoryStdin':True,'executorReadAndWroteOnlyLocalPublicArtifacts':True,'candidateHostCalls':0,'candidateSqlite':0,'candidateNetwork':0,'candidateChild':0,'fullCaptureOrConsumerModuleExecuted':False}
if stdout:
    result=json.loads(stdout)
    report['projectedHosts']=[{'host':h['host'],'agents':h.get('observedConfiguredAgentIds'),'serviceDefinitionCount':len(h['serviceDefinitions'])} for h in result['hosts']]
    report['exactPublicReadsetCount']=len(result['exactExistingPublicReceiptReadset'])
    report['newRegistrationProposalCount']=len(result['proposedNewCreateOnlyHostRegistrations'])
with (root/'execution.public.json').open('x') as f:json.dump(report,f,indent=2);f.write('\n')
print(json.dumps(report,sort_keys=True))
if stderr:print(stderr.decode(),file=sys.stderr,end='')
sys.exit(0 if exit_code==0 else 1)
