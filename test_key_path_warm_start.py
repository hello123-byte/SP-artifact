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


    def test_multi_goal_greedy_follows_attacker_target_switches(self):
        vertices = {
            1: {"id": 1, "label": "vulExists(hostA,CVE-A)", "type": "LEAF", "score": 0},
            2: {"id": 2, "label": "vulExists(hostB,CVE-B)", "type": "LEAF", "score": 0},
            3: {"id": 3, "label": "RULE exploit A", "type": "AND", "score": 1},
            4: {"id": 4, "label": "RULE exploit B", "type": "AND", "score": 1},
            5: {"id": 5, "label": "goalA", "type": "OR", "score": 0},
            6: {"id": 6, "label": "goalB", "type": "OR", "score": 0},
        }
        warm_start = build_key_path_warm_start(
            vertices=vertices,
            arcs=[(5, 3), (3, 1), (6, 4), (4, 2)],
            attack_costs={1: 0.0, 2: 0.0, 3: 1.0, 4: 1.0, 5: 0.0, 6: 0.0},
            defendable=[1, 2],
            defense_costs={1: 1.0, 2: 1.0},
            default_defense_cost=1.0,
            budget=None,
            goals=[5, 6],
            rewards={5: 100.0, 6: 90.0},
            losses={5: 100.0, 6: 90.0},
        )
        self.assertEqual({1, 2}, warm_start["defended"])
        self.assertEqual(2, warm_start["iterations"])
        self.assertIsNone(warm_start["selected_goal"])
        self.assertEqual(2.0, warm_start["objective"])

    def test_parallel_paths_allow_temporary_nonimproving_defense(self):
        vertices = {
            1: {"id": 1, "label": "vulExists(host,CVE-A)", "type": "LEAF", "score": 0},
            2: {"id": 2, "label": "vulExists(host,CVE-B)", "type": "LEAF", "score": 0},
            3: {"id": 3, "label": "RULE path A", "type": "AND", "score": 1},
            4: {"id": 4, "label": "RULE path B", "type": "AND", "score": 1},
            5: {"id": 5, "label": "goal", "type": "OR", "score": 0},
        }
        warm_start = build_key_path_warm_start(
            vertices=vertices,
            arcs=[(5, 3), (5, 4), (3, 1), (4, 2)],
            attack_costs={1: 0.0, 2: 0.0, 3: 1.0, 4: 1.0, 5: 0.0},
            defendable=[1, 2],
            defense_costs={1: 1.0, 2: 1.0},
            default_defense_cost=1.0,
            budget=None,
            goals=[5],
            rewards={5: 100.0},
            losses={5: 100.0},
        )
        self.assertEqual({1, 2}, warm_start["defended"])
        self.assertEqual(2, warm_start["iterations"])
        self.assertEqual(2, warm_start["explored_iterations"])
        self.assertIsNone(warm_start["selected_goal"])
        self.assertEqual(2.0, warm_start["objective"])

    def test_fifty_goals_with_shared_bottleneck_need_one_defense(self):
        vertices = {
            1: {"id": 1, "label": "vulExists(entry,CVE-COMMON)", "type": "LEAF", "score": 0},
            2: {"id": 2, "label": "RULE compromise entry", "type": "AND", "score": 1},
            3: {"id": 3, "label": "execCode(entry,root)", "type": "OR", "score": 0},
        }
        arcs = [(3, 2), (2, 1)]
        attack_costs = {1: 0.0, 2: 1.0, 3: 0.0}
        goals = []
        next_id = 4
        for goal_index in range(50):
            asset_id = next_id
            rule_id = next_id + 1
            goal_id = next_id + 2
            next_id += 3
            vertices[asset_id] = {
                "id": asset_id,
                "label": f"criticalAsset(asset{goal_index})",
                "type": "LEAF",
                "score": 0,
            }
            vertices[rule_id] = {
                "id": rule_id,
                "label": f"RULE goal {goal_index}",
                "type": "AND",
                "score": 0,
            }
            vertices[goal_id] = {
                "id": goal_id,
                "label": f"goal{goal_index}",
                "type": "OR",
                "score": 0,
            }
            arcs.extend([(goal_id, rule_id), (rule_id, 3), (rule_id, asset_id)])
            attack_costs.update({asset_id: 0.0, rule_id: 0.0, goal_id: 0.0})
            goals.append(goal_id)

        warm_start = build_key_path_warm_start(
            vertices=vertices,
            arcs=arcs,
            attack_costs=attack_costs,
            defendable=[1],
            defense_costs={1: 1.0},
            default_defense_cost=1.0,
            budget=None,
            goals=goals,
            rewards={goal: 100.0 for goal in goals},
            losses={goal: 100.0 for goal in goals},
        )
        self.assertEqual({1}, warm_start["defended"])
        self.assertEqual(1, warm_start["iterations"])
        self.assertIsNone(warm_start["selected_goal"])
        self.assertEqual(1.0, warm_start["objective"])


if __name__ == "__main__":
    unittest.main()
