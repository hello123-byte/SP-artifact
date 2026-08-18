import sys
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "baselines"))

from baseline_common import Problem, build_graph_indexes
from ga_defense_baseline import run_ga_baseline


def make_parallel_problem():
    vertices = {
        1: {"id": 1, "label": "goal", "type": "OR", "score": 0.0},
        2: {"id": 2, "label": "left rule", "type": "AND", "score": 1.0},
        3: {"id": 3, "label": "right rule", "type": "AND", "score": 1.0},
        4: {"id": 4, "label": "vulExists(h1,cve1)", "type": "LEAF", "score": 0.0},
        5: {"id": 5, "label": "vulExists(h2,cve2)", "type": "LEAF", "score": 0.0},
    }
    arcs = [(1, 2), (1, 3), (2, 4), (3, 5)]
    outgoing, parents, _ = build_graph_indexes(vertices, arcs)
    return Problem(
        vertices=vertices,
        arcs=arcs,
        goals=[1],
        rewards={1: 1000.0},
        losses={1: 1000.0},
        attack_costs={1: 0.0, 2: 1.0, 3: 1.0, 4: 0.0, 5: 0.0},
        defense_costs={},
        default_defense_cost=1.0,
        budget=2.0,
        attack_cost_source="score",
        default_action_cost=1.0,
        default_leaf_cost=0.0,
        defendable=[4, 5],
        outgoing=outgoing,
        parents=parents,
        target_closure={"enabled": True},
        vertices_path="test_VERTICES.CSV",
        arcs_path="test_ARCS.CSV",
    )


def test_pymoo_ga_blocks_both_parallel_attack_derivations():
    result = run_ga_baseline(
        problem=make_parallel_problem(),
        budget=2.0,
        runs=2,
        population_size=12,
        generations=8,
        seed=7,
        empty_objective=1000.0,
    )
    assert result["algorithm_library"] == "pymoo"
    assert result["algorithm_class"] == "pymoo.algorithms.soo.nonconvex.ga.GA"
    assert {item["id"] for item in result["selected_defenses"]} == {4, 5}
    assert result["objective_cost_form"] == 2.0
    assert result["budget_feasible"] is True
    assert result["ga_runs"] == 2
