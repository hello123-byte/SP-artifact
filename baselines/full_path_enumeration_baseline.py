# -*- coding: utf-8 -*-
"""Full AND/OR derivation enumeration baseline for small graphs."""

from __future__ import annotations

import argparse
import itertools
import math
import time
from dataclasses import dataclass

from baseline_common import (
    add_problem_arguments,
    attach_benefit,
    evaluate_defense_set,
    infer_budget,
    load_problem,
    load_reference_result,
    safe_print,
    write_json,
)
from empty_defense_baseline import run_empty_baseline


class PathEnumerationLimit(RuntimeError):
    pass


class PathEnumerationCycle(RuntimeError):
    pass


@dataclass(frozen=True)
class Derivation:
    leaves: frozenset[int]
    vuln_leaves: frozenset[int]
    cost: float


@dataclass
class GoalPath:
    goal: int
    leaves: frozenset[int]
    vuln_leaves: frozenset[int]
    cost: float
    reward: float
    loss: float
    attacker_net_utility: float


def combine_derivations(problem, node_id: int, children: list[int], child_derivations: list[list[Derivation]], max_paths: int):
    combinations = [Derivation(frozenset(), frozenset(), problem.attack_costs[node_id])]
    for options in child_derivations:
        next_combinations = []
        for left, right in itertools.product(combinations, options):
            next_combinations.append(
                Derivation(
                    leaves=left.leaves | right.leaves,
                    vuln_leaves=left.vuln_leaves | right.vuln_leaves,
                    cost=left.cost + right.cost,
                )
            )
            if len(next_combinations) > max_paths:
                raise PathEnumerationLimit(f"AND node {node_id} exceeds max paths")
        combinations = next_combinations
        if not combinations:
            break
    return combinations


def enumerate_derivations(problem, node_id: int, max_paths: int, max_depth: int, memo: dict[int, list[Derivation]], stack: set[int]):
    if node_id in memo:
        return memo[node_id]
    if len(stack) > max_depth:
        raise PathEnumerationLimit(f"maximum depth {max_depth} exceeded")
    if node_id in stack:
        raise PathEnumerationCycle(f"cycle detected at node {node_id}")

    stack.add(node_id)
    node = problem.vertices[node_id]
    node_type = node["type"]
    children = sorted(problem.outgoing[node_id])

    if node_type == "LEAF":
        vuln_leaves = frozenset({node_id}) if node_id in problem.defendable else frozenset()
        result = [
            Derivation(
                leaves=frozenset({node_id}),
                vuln_leaves=vuln_leaves,
                cost=problem.attack_costs[node_id],
            )
        ]
    elif node_type == "AND":
        if not children:
            result = []
        else:
            child_derivations = [
                enumerate_derivations(problem, child, max_paths, max_depth, memo, stack)
                for child in children
            ]
            if any(not items for items in child_derivations):
                result = []
            else:
                result = combine_derivations(problem, node_id, children, child_derivations, max_paths)
    elif node_type == "OR":
        result = []
        for child in children:
            result.extend(enumerate_derivations(problem, child, max_paths, max_depth, memo, stack))
            if len(result) > max_paths:
                raise PathEnumerationLimit(f"OR node {node_id} exceeds max paths")
    else:
        raise SystemExit(f"Unknown node type for {node_id}: {node_type}")

    stack.remove(node_id)
    memo[node_id] = result
    return result


def enumerate_goal_paths(problem, max_paths: int, max_depth: int) -> list[GoalPath]:
    memo: dict[int, list[Derivation]] = {}
    paths = []
    for goal in problem.goals:
        derivations = enumerate_derivations(problem, goal, max_paths, max_depth, memo, set())
        for derivation in derivations:
            net = problem.rewards[goal] - derivation.cost
            paths.append(
                GoalPath(
                    goal=goal,
                    leaves=derivation.leaves,
                    vuln_leaves=derivation.vuln_leaves,
                    cost=derivation.cost,
                    reward=problem.rewards[goal],
                    loss=problem.losses[goal],
                    attacker_net_utility=net,
                )
            )
            if len(paths) > max_paths:
                raise PathEnumerationLimit("total enumerated goal paths exceeds max paths")
    return paths


def greedy_path_cover(problem, paths: list[GoalPath], budget: float) -> set[int]:
    attackable = {
        index
        for index, path in enumerate(paths)
        if path.attacker_net_utility > 0 and path.vuln_leaves
    }
    selected: set[int] = set()
    spent = 0.0

    while attackable:
        best_node = None
        best_score = 0.0
        best_covered: set[int] = set()
        for node_id in problem.defendable:
            if node_id in selected:
                continue
            cost = problem.defense_costs.get(node_id, problem.default_defense_cost)
            if spent + cost > budget + 1e-9:
                continue
            covered = {
                index
                for index in attackable
                if node_id in paths[index].vuln_leaves
            }
            if not covered:
                continue
            risk_reduction = sum(max(0.0, paths[index].loss) for index in covered)
            score = risk_reduction / cost if cost > 0 else math.inf
            if (
                score,
                risk_reduction,
                -cost,
                -node_id,
            ) > (
                best_score,
                sum(max(0.0, paths[index].loss) for index in best_covered),
                -problem.defense_costs.get(best_node, problem.default_defense_cost) if best_node else -math.inf,
                -best_node if best_node else -math.inf,
            ):
                best_node = node_id
                best_score = score
                best_covered = covered

        if best_node is None:
            break
        selected.add(best_node)
        spent += problem.defense_costs.get(best_node, problem.default_defense_cost)
        attackable -= best_covered

    return selected


def skipped_result(method: str, status: str, reason: str, empty_objective: float | None, start_time: float, max_paths: int, max_depth: int):
    result = {
        "method": method,
        "status": status,
        "defense_scope": "vul",
        "objective_cost_form": None,
        "empty_objective_cost_form": empty_objective,
        "benefit_score": None,
        "selected_defenses": [],
        "attacker_response": None,
        "reachable_goals": [],
        "defense_cost": None,
        "attack_loss": None,
        "attacker_utility": None,
        "budget_used": None,
        "skip_reason": reason,
        "enumerated_path_count": None,
        "max_paths": max_paths,
        "max_depth": max_depth,
        "limit_hit": status == "skipped_limit",
        "timings_seconds": {"total_wall": time.perf_counter() - start_time},
    }
    return result


def run_path_enumeration_baseline(
    problem,
    budget: float,
    max_paths: int,
    max_depth: int,
    empty_objective: float,
):
    if max_paths < 1:
        raise SystemExit("--max-paths must be at least 1")
    if max_depth < 1:
        raise SystemExit("--max-depth must be at least 1")

    start_time = time.perf_counter()
    try:
        paths = enumerate_goal_paths(problem, max_paths=max_paths, max_depth=max_depth)
    except PathEnumerationLimit as exc:
        return skipped_result(
            method="full_path_enumeration",
            status="skipped_limit",
            reason=str(exc),
            empty_objective=empty_objective,
            start_time=start_time,
            max_paths=max_paths,
            max_depth=max_depth,
        )
    except PathEnumerationCycle as exc:
        return skipped_result(
            method="full_path_enumeration",
            status="skipped_cycle",
            reason=str(exc),
            empty_objective=empty_objective,
            start_time=start_time,
            max_paths=max_paths,
            max_depth=max_depth,
        )

    selected = greedy_path_cover(problem, paths, budget)
    result = evaluate_defense_set(
        problem,
        selected,
        method="full_path_enumeration",
        start_time=start_time,
    )
    result["budget"] = budget
    result["budget_used"] = result["defense_cost"]
    result["budget_feasible"] = result["defense_cost"] <= budget + 1e-9
    result["enumerated_path_count"] = len(paths)
    result["attackable_path_count"] = sum(1 for path in paths if path.attacker_net_utility > 0)
    result["path_cover_selected_count"] = len(selected)
    result["max_paths"] = max_paths
    result["max_depth"] = max_depth
    result["limit_hit"] = False
    attach_benefit(result, empty_objective)
    return result


def main():
    parser = argparse.ArgumentParser()
    add_problem_arguments(parser)
    parser.add_argument("--out", default="baseline_results/full_path_enumeration.json")
    parser.add_argument("--path-budget", type=float, default=None)
    parser.add_argument("--max-paths", type=int, default=100000)
    parser.add_argument("--max-depth", type=int, default=200)
    parser.add_argument("--reference-result", default=None)
    args = parser.parse_args()

    problem = load_problem(args)
    reference_result = load_reference_result(args.reference_result)
    budget = infer_budget(problem, args.path_budget, reference_result, "path enumeration baseline")
    empty_result = run_empty_baseline(problem)
    result = run_path_enumeration_baseline(
        problem=problem,
        budget=budget,
        max_paths=args.max_paths,
        max_depth=args.max_depth,
        empty_objective=empty_result["objective_cost_form"],
    )
    write_json(args.out, result)
    safe_print(f"method: {result['method']}")
    safe_print(f"status: {result['status']}")
    safe_print(f"objective cost form: {result['objective_cost_form']}")
    safe_print(f"benefit_score: {result['benefit_score']}")
    safe_print(f"wrote: {args.out}")


if __name__ == "__main__":
    main()

