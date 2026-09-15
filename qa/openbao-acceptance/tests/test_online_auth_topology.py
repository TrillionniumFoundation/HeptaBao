"""A callback race must address a leader and one follower after every election."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from online_auth_ha import callback_targets


class CallbackTopologyTests(unittest.TestCase):
    def test_every_possible_leader_is_in_the_distinct_target_pair(self):
        nodes=[SimpleNamespace(node_id=i) for i in [1,2,3]]
        for leader in nodes:
            selected=callback_targets(nodes,leader)
            self.assertEqual(len(selected),2)
            self.assertIs(selected[0],leader)
            self.assertIsNot(selected[1],leader)
            self.assertNotEqual(selected[0].node_id,selected[1].node_id)
    def test_missing_or_equal_but_unowned_leader_cannot_enter(self):
        nodes=[SimpleNamespace(node_id=i) for i in [1,2,3]]
        for leader in [None,SimpleNamespace(node_id=1)]:
            with self.assertRaises(ValueError): callback_targets(nodes,leader)
    def test_invalid_cardinality_duplicate_or_boolean_ids_reject(self):
        for ids in [[1,2],[1,1,3],[True,2,3],[0,2,3]]:
            nodes=[SimpleNamespace(node_id=i) for i in ids]
            with self.assertRaises(ValueError): callback_targets(nodes,nodes[0])

if __name__=='__main__':unittest.main()
