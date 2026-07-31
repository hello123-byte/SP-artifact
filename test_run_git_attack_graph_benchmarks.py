# -*- coding: utf-8 -*-
"""Tests for real git_atack_graph target selection semantics."""

import unittest

from run_git_attack_graph_benchmarks import (
    choose_goals,
    closure_ids,
    validate_visual_terminal_goals,
    visual_terminal_or_nodes,
)


class GitAttackGraphBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.vertices = {
            1: {"id": 1, "label": "ttpExists(host,CVE)", "type": "LEAF", "score": 1},
            2: {"id": 2, "label": "RULE exploit", "type": "AND", "score": 0},
            3: {"id": 3, "label": "execCode(host,user)", "type": "OR", "score": 0},
            4: {"id": 4, "label": "RULE escalate", "type": "AND", "score": 0},
            5: {"id": 5, "label": "execCode(host,root)", "type": "OR", "score": 0},
            6: {"id": 6, "label": "ttpExists(other,CVE)", "type": "LEAF", "score": 1},
            7: {"id": 7, "label": "RULE other", "type": "AND", "score": 0},
            8: {"id": 8, "label": "execCode(other,root)", "type": "OR", "score": 0},
        }
        # CSV direction: conclusion -> prerequisite.
        self.arcs = [(3, 2), (2, 1), (5, 4), (4, 3), (8, 7), (7, 6)]

    def test_terminal_condition_uses_visual_prerequisite_to_conclusion_direction(self):
        self.assertEqual([5, 8], visual_terminal_or_nodes(self.vertices, self.arcs))

    def test_nonterminal_or_is_rejected_as_goal(self):
        with self.assertRaisesRegex(SystemExit, "has visual-direction successor"):
            validate_visual_terminal_goals(self.vertices, self.arcs, [3])

    def test_all_terminal_goals_cover_every_component(self):
        _, goals = choose_goals(self.vertices, self.arcs, "all-terminal")
        self.assertEqual([5, 8], goals)
        self.assertEqual(set(self.vertices), closure_ids(self.vertices, self.arcs, goals))

    def test_max_closure_goal_is_terminal(self):
        _, goals = choose_goals(self.vertices, self.arcs, "max-closure")
        self.assertEqual([5], goals)
        validate_visual_terminal_goals(self.vertices, self.arcs, goals)


if __name__ == "__main__":
    unittest.main()
