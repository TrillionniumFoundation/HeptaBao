import unittest
import kv1_record_backup_live as fixture

class RecordBackupGuards(unittest.TestCase):
    def test_postgres_requires_observed_remote_authority_without_local_fallback(self):
        rows=[{'case':name,'passed':True} for name in sorted(fixture.REQUIRED-{'complete'})]
        self.assertFalse(fixture.complete(rows+[{'case':'complete','passed':True}],postgres=True))
        rows.extend({'case':name,'passed':True} for name in sorted(fixture.POSTGRES_REQUIRED))
        rows.append({'case':'complete','passed':True})
        self.assertTrue(fixture.complete(rows,postgres=True))
        for name in fixture.POSTGRES_REQUIRED:
            self.assertFalse(fixture.complete([row for row in rows if row['case']!=name],postgres=True))

    def test_success_requires_rollback_corruption_full_reads_other_owner_and_restart(self):
        rows=[{'case':name,'passed':True} for name in sorted(fixture.REQUIRED-{'complete'})]
        rows.append({'case':'complete','passed':True})
        self.assertTrue(fixture.complete(rows))
        for i in range(len(rows)):
            self.assertFalse(fixture.complete(rows[:i]+rows[i+1:]))
        for bad in ([],rows+[rows[0]],rows[:-1]+[dict(rows[-1],passed=1)],
                    rows[:-1]+[dict(rows[-1],raw='secret')]):
            self.assertFalse(fixture.complete(bad))

if __name__=='__main__':unittest.main()
