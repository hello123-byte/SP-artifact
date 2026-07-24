# -*- coding: utf-8 -*-
"""Structural regression tests for the synthetic MulVAL graph generator."""

import csv
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path

from generate_large_mulval_csv import build_graph, validate_graph_structure, write_csv


class GenerateLargeMulvalCsvTests(unittest.TestCase):
    def test_arcs_csv_uses_mulval_three_column_format(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            vertices_path = temp_path / "VERTICES.CSV"
            arcs_path = temp_path / "ARCS.CSV"
            write_csv(
                [(1, "state", "OR", 1), (2, "RULE", "AND", 1)],
                [(1, 2)],
                vertices_path,
                arcs_path,
            )
            with arcs_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.reader(handle))
            self.assertEqual([["1", "2", "-1"]], rows)

    def test_every_or_node_has_an_and_rule_derivation(self):
        vertices, arcs, _, structure = build_graph(
            hosts=20,
            services_per_host=2,
            vuln_per_service=1,
            lateral_rules_per_host=1,
            goals=4,
            seed=7,
        )
        node_types = {node_id: node_type for node_id, _, node_type, _ in vertices}
        producer_ids = {
            source
            for source, target in arcs
            if node_types[source] == "OR" and node_types[target] == "AND"
        }

        self.assertTrue(producer_ids)
        self.assertTrue(
            all(node_id in producer_ids for node_id, _, node_type, _ in vertices if node_type == "OR")
        )
        self.assertEqual(0, structure["diagnostics"]["or_nodes_without_producers"])
        self.assertEqual(0, structure["diagnostics"]["or_nodes_with_non_and_producers"])

    def test_goal_requires_root_on_the_same_target_host(self):
        vertices, arcs, goals, structure = build_graph(
            hosts=20,
            services_per_host=2,
            vuln_per_service=1,
            lateral_rules_per_host=1,
            goals=10,
            seed=7,
        )
        nodes = {node_id: (label, node_type) for node_id, label, node_type, _ in vertices}
        outgoing = defaultdict(list)
        for source, target in arcs:
            outgoing[source].append(target)

        self.assertEqual(len(goals), structure["goal_rules"])
        for goal_id in goals:
            goal_label = nodes[goal_id][0]
            target_host = goal_label.split("crown_jewel_", 1)[1].split(",root", 1)[0]
            self.assertEqual(1, len(outgoing[goal_id]))
            rule_id = outgoing[goal_id][0]
            or_prerequisites = [
                nodes[node_id][0]
                for node_id in outgoing[rule_id]
                if nodes[node_id][1] == "OR"
            ]
            self.assertEqual([f"execCode({target_host},root)"], or_prerequisites)

    def test_target_closed_graph_has_no_node_outside_final_goal_closure(self):
        vertices, arcs, goals, structure = build_graph(
            hosts=40,
            services_per_host=2,
            vuln_per_service=1,
            lateral_rules_per_host=1,
            goals=4,
            seed=7,
            target_closed=True,
        )
        outgoing = defaultdict(list)
        for source, target in arcs:
            outgoing[source].append(target)
        closure = set(goals)
        stack = list(goals)
        while stack:
            node_id = stack.pop()
            for prerequisite_id in outgoing[node_id]:
                if prerequisite_id not in closure:
                    closure.add(prerequisite_id)
                    stack.append(prerequisite_id)

        self.assertTrue(structure["target_closed"])
        self.assertEqual(0, structure["pruned_outside_goal_closure_count"])
        self.assertEqual({node_id for node_id, *_ in vertices}, closure)

    def test_structure_validation_rejects_or_without_and_derivation(self):
        vertices = [
            (1, "derivedState(host1)", "OR", 1),
            (2, "attackerLocated(internet)", "LEAF", 1),
        ]
        with self.assertRaisesRegex(SystemExit, r"OR node\(s\) are not derived by any AND rule"):
            validate_graph_structure(vertices, [(1, 2)], [])

    def test_multi_host_graph_requires_lateral_derivation_rules(self):
        with self.assertRaisesRegex(SystemExit, "lateral-rules-per-host must be at least 1"):
            build_graph(
                hosts=2,
                services_per_host=1,
                vuln_per_service=1,
                lateral_rules_per_host=0,
                goals=1,
                seed=7,
            )

    def test_single_host_graph_allows_no_lateral_rules(self):
        _, _, _, structure = build_graph(
            hosts=1,
            services_per_host=1,
            vuln_per_service=1,
            lateral_rules_per_host=0,
            goals=1,
            seed=7,
        )
        self.assertEqual(0, structure["diagnostics"]["or_nodes_without_producers"])


if __name__ == "__main__":
    unittest.main()
