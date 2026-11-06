"""Fresh-process pure URI guard; no SQLite connection or real data access."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
CHILD = r'''
import ast,hashlib,json,os,sys,types
from pathlib import Path,PureWindowsPath
source,source_sha,reference=sys.argv[1:]
raw=Path(source).read_bytes();assert hashlib.sha256(raw).hexdigest()==source_sha
ref=Path(reference).read_bytes();assert hashlib.sha256(ref).hexdigest()=='0c56f2caa1eaef1f66e8c01849abac5cf98eef12a18fd743191cb3e0223f9470'
tree=ast.parse(ref);assert len(tree.body)==1 and isinstance(tree.body[0],ast.FunctionDef) and tree.body[0].name=='pathname2url'
m=types.ModuleType('fixed_projection_uri_fixture');m.__file__=source;sys.modules[m.__name__]=m
exec(compile(raw,source,'exec',dont_inherit=True),m.__dict__)
namespace={'__builtins__':{},'os':os,'sys':sys,'quote':m.urllib.parse.quote}
exec(compile(tree,'official_pure_pathname2url_reference','exec'),namespace)
assert os.name=='posix' and 'urllib.request' not in sys.modules
class Captured(Exception):pass
captured=[]
def capture_uri(uri):
 captured.append(uri);raise Captured()
m.RESOURCES.connect=capture_uri
def forbidden_lazy_api(self):raise AssertionError('do not use the platform lazy Path.as_uri API here')
old_as_uri=m.Path.as_uri;m.Path.as_uri=forbidden_lazy_api
sys.addaudithook(m.audit)
cases=[
 Path('/synthetic-only/plain.sqlite'),
 Path('/synthetic-only/中文-é/😀.sqlite'),
 Path('/synthetic-only/with space/db file.sqlite'),
 Path('/synthetic-only/literal%25/percent%.sqlite'),
 Path('/synthetic-only/query?mode=rw&immutable=0.sqlite'),
 Path('/synthetic-only/fragment#one.sqlite'),
 Path('/synthetic-only/mixed ?%# /a+b:c.sqlite'),
 Path(os.fsdecode(b'/synthetic-only/raw-\xff.sqlite')),
]
rows=[]
try:
 for path in cases:
  expected=namespace['pathname2url'](str(path),add_scheme=True)+'?mode=ro&immutable=1'
  try:m.cold_database(path,{})
  except Captured:pass
  else:raise AssertionError('URI capture boundary missing')
  actual=captured[-1];assert actual==expected
  parsed=m.urllib.parse.urlsplit(actual)
  assert parsed.scheme=='file' and parsed.netloc=='' and parsed.fragment==''
  assert parsed.query=='mode=ro&immutable=1' and m.urllib.parse.unquote_to_bytes(parsed.path)==os.fsencode(path)
  assert not m.ALLOWED_URIS
  rows.append({'reference_equal':True,'original_filesystem_bytes_equal':True,'readonly_query_exact':True})
 before=len(captured)
 for path in (Path('relative.sqlite'),Path('//synthetic-only/db.sqlite'),PureWindowsPath('C:/synthetic-only/db.sqlite')):
  try:m.cold_database(path,{})
  except m.Refused as error:assert str(error)=='fixed_absolute_posix_database_uri'
  else:raise AssertionError('invalid URI scope accepted')
 assert len(captured)==before and not m.ALLOWED_URIS and m.OPENED==m.CLOSED==0
 assert m.DENIALS==0 and 'urllib.request' not in sys.modules
finally:m.Path.as_uri=old_as_uri
print(json.dumps({'same_official_3143_reference_cases':rows,'invalid_scope_rejections':3,
 'audit_denials':m.DENIALS,'urllib_request_imported':False,'sqlite_connections':0,
 'real_generation_or_network_or_file_write':False},sort_keys=True,separators=(',',':')))
'''


class PosixUriAuditGuards(unittest.TestCase):
    def test_filesystem_bytes_match_official_3143_reference_without_lazy_request_import(self):
        source = HERE / 'mac_formal_kv2_allrows_projection.py'
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-', str(source),
            hashlib.sha256(source.read_bytes()).hexdigest(),
            str(HERE / 'cpython_v3143_pathname2url.reference.py')], input=CHILD.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, cwd='/',
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        if os.environ.get('HB_COLD_GUARD_OUTPUT'):
            out = Path(os.environ['HB_COLD_GUARD_OUTPUT'])
            for suffix, raw in (('stdout.original', result.stdout), ('stderr.original', result.stderr)):
                with (out / ('posix-uri.' + suffix)).open('xb') as stream:
                    stream.write(raw)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b'')
        value = json.loads(result.stdout)
        self.assertEqual(len(value['same_official_3143_reference_cases']), 8)
        self.assertEqual(value['invalid_scope_rejections'], 3)
        self.assertEqual(value['sqlite_connections'], 0)
        self.assertFalse(value['urllib_request_imported'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
