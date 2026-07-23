# -*- coding: utf-8 -*-
"""Structural regression tests for the synthetic MulVAL graph generator."""

import unittest

from generate_large_mulval_csv import build_graph, validate_graph_structure


class GenerateLargeMulvalCsvTests(unittest.TestCase):
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
