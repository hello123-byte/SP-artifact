# -*- coding: utf-8 -*-
"""Unit tests for the key-path warm-start heuristic."""

import unittest

from solve_mulval__stackelberg_main import (
    build_key_path_warm_start,
    evaluate_defense_state,
)


class KeyPathWarmStartTests(unittest.TestCase):
    def setUp(self):
        self.vertices = {
            1: {"id": 1, "label": "vulExists(host,CVE)", "type": "LEAF", "score": 0},
            2: {"id": 2, "label": "attackerLocated(internet)", "type": "LEAF", "score": 0},
            3: {"id": 3, "label": "RULE exploit", "type": "AND", "score": 5},
            4: {"id": 4, "label": "execCode(host,root,goal)", "type": "OR", "score": 0},
        }
        self.arcs = [(4, 3), (3, 1), (3, 2)]
        self.attack_costs = {1: 0.0, 2: 0.0, 3: 5.0, 4: 0.0}

    def test_evaluation_propagates_and_or_costs(self):
        state = evaluate_defense_state(self.vertices, self.arcs, self.attack_costs, set())
        self.assertTrue(state["reachable"][4])
        self.assertEqual(5.0, state["min_cost"][4])
        self.assertEqual(3, state["or_choice"][4])

    def test_key_path_greedy_blocks_profitable_goal(self):
        warm_start = build_key_path_warm_start(
            vertices=self.vertices,
            arcs=self.arcs,
            attack_costs=self.attack_costs,
            defendable=[1],
            defense_costs={1: 1.0},
            default_defense_cost=1.0,
            budget=None,
            goals=[4],
            rewards={4: 100.0},
            losses={4: 100.0},
        )
        self.assertEqual({1}, warm_start["defended"])
        self.assertIsNone(warm_start["selected_goal"])
        self.assertEqual(1.0, warm_start["objective"])
        self.assertFalse(warm_start["state"]["reachable"][4])


if __name__ == "__main__":
    unittest.main()
