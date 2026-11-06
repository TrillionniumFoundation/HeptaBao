"""Fresh isolated-process audit guards; no real generation or remote service."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
ORIGINAL = Path('/tmp/heptabao-formal-kv2-projection-20261106-r1/mac_formal_kv2_allrows_projection.py')
CURRENT = HERE / 'mac_formal_kv2_allrows_projection.py'
PROTOCOL = Path('/tmp/heptabao-formal-kv2-protocol-20261106-r1/formal_kv2_protocol.py')
CHILD = r'''
import hashlib,json,os,sys,types
from pathlib import Path
source,source_sha,protocol_path,fixture,kind=sys.argv[1:]
raw=Path(source).read_bytes()
assert hashlib.sha256(raw).hexdigest()==source_sha
p=Path(protocol_path);body=p.read_bytes()
assert len(body)==91070 and hashlib.sha256(body).hexdigest()=='f93749dcac3d4f8517c71ff97171aa3cf2083d33f09a16638861e3c4bb012f20'
m=types.ModuleType('isolated_projection_audit_fixture');m.__file__=source;sys.modules[m.__name__]=m
exec(compile(raw,source,'exec',dont_inherit=True),m.__dict__)
observations=[]
def audit(event,args):
 try:m.audit(event,args)
 except m.Refused:
  basename=str(args[0]).rsplit('/',1)[-1] if event=='open' and args else ''
  observations.append({'event':event if event in ('open','sqlite3.connect') else 'other',
                       'future_module':basename.startswith('__future__.') and basename.endswith(('.py','.pyc'))})
  raise
cached='__future__' in sys.modules
sys.addaudithook(audit)
if kind=='old':
 try:m.extract_protocol(body,p)
 except m.Refused as error:assert str(error)=='forbidden_projection_effect'
 else:raise AssertionError('old cold extraction unexpectedly accepted')
 assert not cached and observations==[{'event':'open','future_module':True}] and m.DENIALS==1
 result={'old_cold_refusal_observed':True,'future_cached_before_extraction':cached,'events':observations}
else:
 result=m.extract_protocol(body,p)
 assert cached and m.DENIALS==0 and len(result)>16
 for action in (lambda:os.open(fixture,os.O_RDONLY),lambda:m.sqlite3.connect(':memory:')):
  try:action()
  except m.Refused as error:assert str(error)=='forbidden_projection_effect'
  else:raise AssertionError('original restrictive audit was widened')
 assert observations==[{'event':'open','future_module':False},{'event':'sqlite3.connect','future_module':False}]
 result={'new_cold_extraction_succeeded':True,'future_cached_before_extraction':cached,
         'undeclared_read_and_connection_still_refused':True,'events':observations}
print(json.dumps(result,sort_keys=True,separators=(',',':')))
'''


class ColdImportAuditGuards(unittest.TestCase):
    def run_child(self, source, kind):
        with tempfile.TemporaryDirectory(prefix='hb-cold-audit-synthetic-') as name:
            fixture = Path(name) / 'synthetic-undeclared'
            fixture.write_bytes(b'synthetic only')
            before = fixture.read_bytes()
            result = subprocess.run([sys.executable, '-I', '-S', '-B', '-', str(source),
                hashlib.sha256(source.read_bytes()).hexdigest(), str(PROTOCOL), str(fixture), kind],
                input=CHILD.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                cwd='/', env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
            if os.environ.get('HB_COLD_GUARD_OUTPUT'):
                out = Path(os.environ['HB_COLD_GUARD_OUTPUT'])
                for suffix, raw in (('stdout.original', result.stdout), ('stderr.original', result.stderr)):
                    with (out / (kind + '.' + suffix)).open('xb') as stream:
                        stream.write(raw)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stderr, b'')
            self.assertEqual(fixture.read_bytes(), before)
            return json.loads(result.stdout)

    def test_original_r1_cold_isolated_extraction_reproduces_future_audit_denial(self):
        self.assertTrue(self.run_child(ORIGINAL, 'old')['old_cold_refusal_observed'])

    def test_new_r2_cold_extraction_passes_without_widening_read_or_sqlite_guard(self):
        self.assertTrue(self.run_child(CURRENT, 'new')['undeclared_read_and_connection_still_refused'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
