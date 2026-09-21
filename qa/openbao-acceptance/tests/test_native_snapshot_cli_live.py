import gzip
import hashlib
import io
import json
import os
import re
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import native_snapshot_cli_live as fixture


class NativeSnapshotCliGuards(unittest.TestCase):
    def setUp(self):
        # Guard-only scratch stays beside this SSD-staged source, never ambient TMP.
        self.directory = tempfile.TemporaryDirectory(prefix='guard-', dir=Path(fixture.__file__).parent)
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def archive(self, name='input.snap', *, state=b'HBB2'+b'encrypted-placeholder'*20, extra=False):
        metadata = json.dumps({'format':'heptabao-native-snapshot-v1',
            'state_format':'heptabao-encrypted-backup-v1/HBB2','generation':7,'state_bytes':len(state)}).encode()
        sums = (hashlib.sha256(metadata).hexdigest()+'  meta.json\n'+hashlib.sha256(state).hexdigest()+'  state.bin\n').encode()
        path = self.root/name
        with tarfile.open(path,'w:gz',format=tarfile.USTAR_FORMAT) as archive:
            for name,data in [('meta.json',metadata),('state.bin',state),('SHA256SUMS',sums),('SHA256SUMS.sealed',b'authenticated-placeholder')]:
                member=tarfile.TarInfo(name);member.size=len(data);archive.addfile(member,io.BytesIO(data))
            if extra:
                member=tarfile.TarInfo('foreign');archive.addfile(member,io.BytesIO())
        return path

    def test_required_real_milestones_unique_not_case_count(self):
        rows=[{'case':name,'passed':True} for name in sorted(fixture.REQUIRED-{'complete'})]+[{'case':'complete','passed':True}]
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1]+[{'case':'additional_actual_observation','passed':True}]+rows[-1:]))
        for i in range(len(rows)):
            self.assertFalse(fixture.complete(rows[:i]+rows[i+1:]))
        self.assertFalse(fixture.complete([{'case':f'case_{i}','passed':True} for i in range(1000)]+[{'case':'complete','passed':True}]))
        self.assertFalse(fixture.complete(rows+[rows[0]]))
        self.assertFalse(fixture.complete(rows[:-1]+[{'case':'complete','passed':1}]))
        self.assertFalse(fixture.complete(rows[:-1]+[{'case':'complete','passed':True,'raw':'secret'}]))

    def test_archive_is_streamed_with_native_metadata_and_exact_members(self):
        path=self.archive()
        summary=fixture.inspect_archive(path)
        self.assertEqual(summary['generation'],7)
        self.assertEqual(summary['members'],fixture.NAMES)
        self.assertNotIn('state',summary)
        with self.assertRaises(ValueError):fixture.inspect_archive(self.archive('extra.snap',extra=True))
        with self.assertRaises(ValueError):fixture.inspect_archive(self.archive('foreign.snap',state=b'not-HBB2'))

    def test_tamper_preserves_outer_gzip_tar_and_plain_checksums(self):
        original=self.archive();tampered=self.root/'tampered.snap'
        fixture.tamper_sealed(original,tampered)
        self.assertEqual(fixture.inspect_archive(original),fixture.inspect_archive(tampered))
        with tarfile.open(original,'r:gz') as a,tarfile.open(tampered,'r:gz') as b:
            for name in fixture.NAMES[:-1]:
                self.assertEqual(a.extractfile(name).read(),b.extractfile(name).read())
            before=a.extractfile(fixture.NAMES[-1]).read();after=b.extractfile(fixture.NAMES[-1]).read()
            self.assertEqual(before[1:],after[1:]);self.assertEqual(before[0]^after[0],1)
        self.assertEqual(tampered.stat().st_mode & 0o777,0o600)

    def test_cli_is_fixed_operator_command_with_no_ambient_credentials(self):
        instance=SimpleNamespace(address='https://127.0.0.1:1234',root=self.root,token='synthetic-token')
        with mock.patch.dict(os.environ,{'VAULT_NAMESPACE':'evil','HTTPS_PROXY':'bad','BAO_SKIP_VERIFY':'true'}):
            env=fixture.cli_environment(instance,self.root)
        self.assertNotIn('VAULT_NAMESPACE',env);self.assertNotIn('HTTPS_PROXY',env);self.assertNotIn('BAO_SKIP_VERIFY',env)
        self.assertEqual(env['TMPDIR'],str(self.root));self.assertEqual(env['BAO_MAX_RETRIES'],'0')
        with mock.patch.object(subprocess,'run',return_value=SimpleNamespace(returncode=2,stderr=b'Code: 400. Errors:\nredacted')) as run:
            self.assertTrue(fixture.cli(Path('/fixed/bao'),instance,self.root,'restore',self.root/'input.snap',True,400))
            args=run.call_args.args[0]
            self.assertEqual(args[:6],['/fixed/bao','operator','raft','snapshot','restore','-force'])
            self.assertNotIn(instance.token,args)
        with mock.patch.object(subprocess,'run',return_value=SimpleNamespace(returncode=2,stderr=b'Code: 503. Errors:')):
            self.assertFalse(fixture.cli(Path('/fixed/bao'),instance,self.root,'restore',self.root/'input.snap',True,400))

    def test_work_parent_and_report_samples_have_no_ambient_fallback(self):
        self.assertEqual(fixture.private_parent(self.root),self.root)
        link=self.root/'link';link.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(ValueError):fixture.private_parent(link)
        path=self.root/'scan';path.write_bytes(b'x'*(fixture.BLOCK-3)+b'synthetic-secret')
        self.assertTrue(fixture.contains_any(path,[b'synthetic-secret']))
        self.assertFalse(fixture.contains_any(path,[b'absent-secret']))

    def test_postgres_milestones_cannot_be_satisfied_by_file_profile(self):
        rows=[{'case':n,'passed':True} for n in sorted(fixture.REQUIRED-{'complete'})]+[{'case':'complete','passed':True}]
        self.assertTrue(fixture.complete(rows))
        self.assertFalse(fixture.complete(rows,postgres=True))
        rows=rows[:-1]+[{'case':n,'passed':True} for n in sorted(fixture.POSTGRES_REQUIRED)]+rows[-1:]
        self.assertTrue(fixture.complete(rows,postgres=True))
        for name in fixture.POSTGRES_REQUIRED:
            self.assertFalse(fixture.complete([r for r in rows if r['case'] != name],postgres=True))
        self.assertFalse(fixture.complete(rows+[rows[0]],postgres=True))
        bad=[dict(r) for r in rows];bad[0]['passed']=1
        self.assertFalse(fixture.complete(bad,postgres=True))
        self.assertFalse(fixture.complete(rows[:-1],postgres=True))

    def test_postgres_profile_pins_real_major_and_three_tool_bytes(self):
        for name in ('postgres','initdb','psql'):(self.root/name).write_bytes(name.encode())
        with mock.patch.object(subprocess,'check_output',return_value='postgres (PostgreSQL) 17.6 (Debian)\n'):
            before=fixture.postgres_identity(self.root)
            self.assertEqual(set(before['binary_sha256']),{'postgres','initdb','psql'})
            (self.root/'psql').write_bytes(b'changed')
            self.assertNotEqual(before,fixture.postgres_identity(self.root))
        with mock.patch.object(subprocess,'check_output',return_value='postgres (PostgreSQL) 16.9\n'):
            with self.assertRaises(ValueError):fixture.postgres_identity(self.root)
        (self.root/'initdb').unlink()
        with self.assertRaises(ValueError):fixture.postgres_identity(self.root)

    def test_postgres_storage_owner_has_no_privileged_fallback(self):
        (self.root/'ca.crt').write_text('synthetic-ca')
        pg=SimpleNamespace(start=mock.Mock(),manager_password='synthetic-pg-password',
            origin='postgresql://localhost:2345',port=2345,
            sql=mock.Mock(side_effect=[SimpleNamespace(returncode=0),
                SimpleNamespace(returncode=0,stdout='t\n'),SimpleNamespace(returncode=0,stdout='hb_storage\n')]))
        checks=[]
        def check(name, passed):
            checks.append((name,passed))
            if not passed:raise ValueError(name)
        config={};fixture.configure_postgres(pg,SimpleNamespace(root=self.root),config,check)
        self.assertTrue(all(passed for _,passed in checks))
        self.assertEqual(config['postgres_durable']['username'],'hb_storage')
        self.assertEqual(config['postgres_durable']['scope'],fixture.PG_SCOPE)
        self.assertNotIn('outbound_endpoints',config)
        pg.sql=mock.Mock(return_value=SimpleNamespace(returncode=1))
        failed={}
        with self.assertRaises(ValueError):fixture.configure_postgres(pg,SimpleNamespace(root=self.root),failed,check)
        self.assertEqual(failed,{})

    def test_postgres_setup_failure_stops_provider_without_starting_file_backend(self):
        import remote_jwks_live
        import postgres_live
        (self.root/'server.json').write_text('{}')
        instance=SimpleNamespace(root=self.root,start=mock.Mock(),stop=mock.Mock())
        pg=SimpleNamespace(stop=mock.Mock())
        with mock.patch.object(remote_jwks_live,'Instance',return_value=instance), \
             mock.patch.object(postgres_live,'Postgres',return_value=pg), \
             mock.patch.object(fixture,'configure_postgres',side_effect=ValueError('setup_failed')):
            with self.assertRaises(ValueError):
                fixture.run(Path('/candidate'),Path('/bao'),self.root,[],{},Path('/pg17'))
        instance.start.assert_not_called();instance.stop.assert_called_once();pg.stop.assert_called_once()

    def test_postgres_pending_init_recovers_only_with_original_nonce(self):
        calls=[];response={'root_token':'synthetic-root','keys_base64':['synthetic-key']}
        def call(method,path,body):
            calls.append(dict(body));number=len(calls)
            return (400,{}) if number==1 else (503,{}) if number==2 else (403,{}) if number==3 else (200,response)
        instance=SimpleNamespace(call=call,start=mock.Mock(),stop=mock.Mock())
        pg=SimpleNamespace(start=mock.Mock(),stop=mock.Mock())
        checks=[]
        initialized,nonce=fixture.initialize(instance,pg,lambda n,c:checks.append((n,c)))
        self.assertEqual(initialized,response);self.assertTrue(all(c for _,c in checks))
        self.assertNotIn('recovery_nonce',calls[0]);self.assertEqual(calls[1]['recovery_nonce'],nonce)
        self.assertNotEqual(calls[2]['recovery_nonce'],nonce)
        self.assertEqual(calls[3],calls[1]);self.assertEqual(calls[4],calls[1])
        pg.stop.assert_called_once();pg.start.assert_called_once()
        instance.stop.assert_called_once();instance.start.assert_called_once()
        self.assertNotIn(nonce,json.dumps(checks));self.assertNotIn('synthetic-root',json.dumps(checks))

    def test_postgres_local_metadata_cannot_mask_artifact_fallback(self):
        data=self.root/'data';data.mkdir()
        marker={'schema':2,'backend':'postgresql','scope':fixture.PG_SCOPE,'binding':'a'*64}
        (data/'durable-backend.json').write_text(json.dumps(marker))
        instance=SimpleNamespace(root=self.root)
        self.assertTrue(fixture.postgres_metadata_only(instance))
        for name in ('state.hbs','ledger.hbl','journal.hbj'):
            (data/name).write_bytes(b'encrypted-but-local')
            self.assertFalse(fixture.postgres_metadata_only(instance));(data/name).unlink()
        (data/'state.hbs').symlink_to(data/'missing')
        self.assertFalse(fixture.postgres_metadata_only(instance));(data/'state.hbs').unlink()
        marker['scope']='foreign';(data/'durable-backend.json').write_text(json.dumps(marker))
        self.assertFalse(fixture.postgres_metadata_only(instance))

    def pg_reader(self, artifacts, *, missing=None, extra=0, revision=2, manifest_change=False):
        queries=[];manifest_reads=0
        def sql(query):
            nonlocal manifest_reads
            queries.append(query)
            if 'FROM heptabao_durable_v1.manifest_v1' in query:
                manifest_reads+=1
                current=revision+1 if manifest_change and manifest_reads>1 else revision
                return SimpleNamespace(returncode=0,stdout='1|'+str(current)+'|'+
                    '|'.join(str(len(artifacts[n])) for n in ('snapshot','ledger','journal'))+'\n')
            if 'SELECT count(*)' in query:
                count=sum((len(a)+fixture.PG_CHUNK_BYTES-1)//fixture.PG_CHUNK_BYTES for a in artifacts.values())+extra
                return SimpleNamespace(returncode=0,stdout=str(count)+'\n')
            artifact=re.search("artifact='([a-z]+)'",query).group(1)
            number=int(re.search('chunk_no=([0-9]+)',query).group(1))
            payload=artifacts[artifact][number*fixture.PG_CHUNK_BYTES:(number+1)*fixture.PG_CHUNK_BYTES]
            return SimpleNamespace(returncode=0,stdout='' if missing==(artifact,number) else '1|2|'+payload.hex()+'\n')
        return SimpleNamespace(sql=sql,queries=queries)

    def test_postgres_observer_checks_whole_layout_without_aggregate_hex(self):
        artifacts={'snapshot':b'HBS2'+b'x'*(fixture.PG_CHUNK_BYTES+10),
                   'ledger':b'HBL2sealed','journal':b''}
        pg=self.pg_reader(artifacts);observed=fixture.inspect_postgres_artifacts(pg,[b'synthetic-secret'])
        self.assertEqual(observed['chunk_count'],3);self.assertTrue(observed['plaintext_absent'])
        self.assertFalse(observed['standalone_aead_verified'])
        self.assertEqual(observed['artifacts']['snapshot']['sha256'],hashlib.sha256(artifacts['snapshot']).hexdigest())
        reads=[q for q in pg.queries if 'encode(bytes' in q]
        self.assertEqual(len(reads),3);self.assertTrue(all('chunk_no=' in q and 'LIMIT 2' in q for q in reads))
        for kwargs in ({'missing':('snapshot',1)},{'extra':1},{'manifest_change':True}):
            with self.assertRaises(ValueError):fixture.inspect_postgres_artifacts(self.pg_reader(artifacts,**kwargs),[b'synthetic-secret'])
        wrong=dict(artifacts,snapshot=b'HBP2plaintext')
        with self.assertRaises(ValueError):fixture.inspect_postgres_artifacts(self.pg_reader(wrong),[b'synthetic-secret'])

    def test_postgres_plaintext_scan_catches_chunk_boundary_and_never_exports_bytes(self):
        secret=b'synthetic-secret-across-boundary'
        prefix=b'HBS2'+b'x'*(fixture.PG_CHUNK_BYTES-4-9)
        artifacts={'snapshot':prefix+secret+b'tail','ledger':b'HBL2sealed','journal':b'HBJ2sealed'}
        observed=fixture.inspect_postgres_artifacts(self.pg_reader(artifacts),[secret])
        self.assertFalse(observed['plaintext_absent'])
        self.assertNotIn(secret.decode(),json.dumps(observed))
        with self.assertRaises(ValueError):fixture.inspect_postgres_artifacts(self.pg_reader(artifacts,revision=1),[secret])

if __name__=='__main__':unittest.main()
