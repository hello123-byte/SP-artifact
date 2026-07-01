# -*- coding: utf-8 -*-
"""Random vulnerability-defense baseline."""

from __future__ import annotations

import argparse
import random
import time

from baseline_common import (
    add_problem_arguments,
    attach_benefit,
    evaluate_defense_set,
    infer_budget,
    load_problem,
    load_reference_result,
    safe_print,
    summarize_objectives,
    write_json,
)
from empty_defense_baseline import run_empty_baseline


def sample_random_defense(problem, budget: float, rng: random.Random) -> set[int]:
    candidates = list(problem.defendable)
    rng.shuffle(candidates)
    selected: set[int] = set()
    total = 0.0
    for node_id in candidates:
        cost = problem.defense_costs.get(node_id, problem.default_defense_cost)
        if total + cost <= budget + 1e-9:
            selected.add(node_id)
            total += cost
    return selected


def run_random_baseline(
    problem,
    budget: float,
    random_trials: int,
    seed: int,
    empty_objective: float,
):
    if random_trials < 1:
        raise SystemExit("--random-trials must be at least 1")

    rng = random.Random(seed)
    trial_summaries = []
    objective_values = []
    best_result = None
    wall_start = time.perf_counter()

    for trial_index in range(random_trials):
        selected = sample_random_defense(problem, budget, rng)
        result = evaluate_defense_set(problem, selected, method="random_defense")
        objective = result["objective_cost_form"]
        objective_values.append(objective)
        trial_summaries.append(
            {
                "trial": trial_index,
                "objective_cost_form": objective,
                "defense_cost": result["defense_cost"],
                "attack_loss": result["attack_loss"],
                "selected_defense_count": len(result["selected_defenses"]),
                "attacker_response_type": result["attacker_response"]["type"],
            }
        )
        if best_result is None or (
            objective,
            result["defense_cost"],
            len(result["selected_defenses"]),
        ) < (
            best_result["objective_cost_form"],
            best_result["defense_cost"],
            len(best_result["selected_defenses"]),
        ):
            best_result = result

    assert best_result is not None
    best_result["method"] = "random_defense"
    best_result["budget"] = budget
    best_result["budget_used"] = best_result["defense_cost"]
    best_result["budget_feasible"] = best_result["defense_cost"] <= budget + 1e-9
    best_result["random_budget"] = budget
    best_result["random_trials"] = random_trials
    best_result["seed"] = seed
    best_result["trial_summaries"] = trial_summaries
    best_result.update(summarize_objectives(objective_values))
    best_result["timings_seconds"]["total_wall"] = time.perf_counter() - wall_start
    attach_benefit(best_result, empty_objective)
    return best_result


def main():
    parser = argparse.ArgumentParser()
    add_problem_arguments(parser)
    parser.add_argument("--out", default="baseline_results/random_defense.json")
    parser.add_argument("--random-budget", type=float, default=None)
    parser.add_argument("--random-trials", type=int, default=50)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--reference-result", default=None)
    args = parser.parse_args()

    problem = load_problem(args)
    reference_result = load_reference_result(args.reference_result)
    budget = infer_budget(problem, args.random_budget, reference_result, "random baseline")
    empty_result = run_empty_baseline(problem)
    result = run_random_baseline(
        problem=problem,
        budget=budget,
        random_trials=args.random_trials,
        seed=args.seed,
        empty_objective=empty_result["objective_cost_form"],
    )
    write_json(args.out, result)
    safe_print(f"method: {result['method']}")
    safe_print(f"status: {result['status']}")
    safe_print(f"objective cost form: {result['objective_cost_form']}")
    safe_print(f"benefit_score: {result['benefit_score']}")
    safe_print(f"selected defenses: {len(result['selected_defenses'])}")
    safe_print(f"wrote: {args.out}")


if __name__ == "__main__":
    main()

