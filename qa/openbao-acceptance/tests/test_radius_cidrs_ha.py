import unittest
import radius_cidrs_ha as fixture
class ForwardingCompletionTests(unittest.TestCase):
    def test_election_and_both_origin_directions_are_required(self):
        names=sorted(fixture.MILESTONES-{'ha.complete'})+['ha.complete']
        rows=[{'case':'radius_cidrs.'+n,'passed':True} for n in names]
        self.assertTrue(fixture.complete(rows))
        for required in ['ha.forwarded_login','ha.forwarded_wrong_login','ha.after_election_denied','ha.after_election_renew.self.shape','ha.health_only_catchup','ha.no_quorum_head']:
            self.assertFalse(fixture.complete([r for r in rows if r['case']!='radius_cidrs.'+required]))
        self.assertFalse(fixture.complete(rows+[rows[-1]]))
if __name__=='__main__':unittest.main()
