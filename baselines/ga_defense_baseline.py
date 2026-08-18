# -*- coding: utf-8 -*-
"""Genetic-algorithm defense baseline backed by the open-source pymoo GA."""

from __future__ import annotations

import statistics
import time

import numpy as np

from baseline_common import (
    attach_benefit,
    choose_attacker_response,
    compute_reachability_and_costs,
    defense_cost,
    evaluate_defense_set,
)


def _load_pymoo():
    try:
        import pymoo
        from pymoo.algorithms.soo.nonconvex.ga import GA
        from pymoo.core.problem import ElementwiseProblem
        from pymoo.operators.crossover.pntx import TwoPointCrossover
        from pymoo.operators.mutation.bitflip import BitflipMutation
        from pymoo.optimize import minimize
    except ImportError as exc:
        raise SystemExit(
            "GA baseline requires the open-source pymoo package. "
            "Install it with: python3 -m pip install -r requirements-baselines.txt"
        ) from exc
    return pymoo, GA, ElementwiseProblem, TwoPointCrossover, BitflipMutation, minimize


def _metrics(problem, selected: set[int], budget: float) -> tuple[float, float]:
    reachable, costs, _ = compute_reachability_and_costs(problem, selected)
    _, _, attacker_utility, attack_loss = choose_attacker_response(problem, reachable, costs)
    defense_total = defense_cost(problem, selected)
    objective = defense_total + attack_loss
    # Until an attack is fully stopped, partial defenses pay more while often
    # retaining the full loss. Use attacker utility only to guide the search;
    # final solution selection still uses the exact objective.
    loss_scale = max(problem.rewards.values(), default=0.0) + budget + 1.0
    search_fitness = attack_loss * loss_scale + attacker_utility + defense_total / (budget + 1.0)
    return objective, search_fitness


def _initial_population(problem, budget: float, population_size: int, seed: int) -> np.ndarray:
    """Build a reproducible, budget-feasible binary initial population."""
    size = len(problem.defendable)
    population = np.zeros((population_size, size), dtype=bool)
    if size == 0 or population_size == 1:
        return population

    costs = np.asarray(
        [problem.defense_costs.get(node_id, problem.default_defense_cost) for node_id in problem.defendable],
        dtype=float,
    )
    rng = np.random.default_rng(seed)
    for individual in population[1:]:
        running_cost = 0.0
        for index in rng.permutation(size):
            candidate_cost = float(costs[index])
            if running_cost + candidate_cost <= budget + 1e-9:
                individual[index] = True
                running_cost += candidate_cost
    return population


def _run_once(problem, budget: float, population_size: int, generations: int, seed: int):
    pymoo, GA, ElementwiseProblem, TwoPointCrossover, BitflipMutation, minimize = _load_pymoo()
    defendable = tuple(problem.defendable)
    costs = np.asarray(
        [problem.defense_costs.get(node_id, problem.default_defense_cost) for node_id in defendable],
        dtype=float,
    )
    candidate_cache: dict[bytes, tuple[float, float, frozenset[int]]] = {}

    class AttackGraphDefenseProblem(ElementwiseProblem):
        def __init__(self):
            super().__init__(
                n_var=len(defendable),
                n_obj=1,
                n_ieq_constr=1,
                xl=0,
                xu=1,
                vtype=bool,
            )

        def _evaluate(self, x, out, *args, **kwargs):
            bits = np.asarray(x, dtype=bool)
            key = np.packbits(bits).tobytes()
            cached = candidate_cache.get(key)
            if cached is None:
                selected = {node_id for node_id, enabled in zip(defendable, bits) if enabled}
                objective, search_fitness = _metrics(problem, selected, budget)
                cached = (objective, search_fitness, frozenset(selected))
                candidate_cache[key] = cached
            out["F"] = cached[1]
            out["G"] = float(costs[bits].sum()) - budget

    if not defendable:
        return set(), 1, pymoo.__version__

    algorithm = GA(
        pop_size=population_size,
        sampling=_initial_population(problem, budget, population_size, seed),
        crossover=TwoPointCrossover(prob=0.9),
        mutation=BitflipMutation(),
        eliminate_duplicates=True,
    )
    minimize(
        AttackGraphDefenseProblem(),
        algorithm,
        termination=("n_gen", generations),
        seed=seed,
        verbose=False,
    )
    feasible_candidates = [
        cached
        for cached in candidate_cache.values()
        if defense_cost(problem, set(cached[2])) <= budget + 1e-9
    ]
    if not feasible_candidates:
        return set(), len(candidate_cache), pymoo.__version__
    def candidate_key(item):
        selected = set(item[2])
        return item[0], defense_cost(problem, selected), len(selected), tuple(sorted(selected))

    best = min(feasible_candidates, key=candidate_key)
    return set(best[2]), len(candidate_cache), pymoo.__version__


def run_ga_baseline(
    problem,
    budget: float,
    runs: int,
    population_size: int,
    generations: int,
    seed: int,
    empty_objective: float,
):
    if runs < 1:
        raise SystemExit("--ga-runs must be positive")
    if population_size < 2:
        raise SystemExit("--ga-population-size must be at least 2")
    if generations < 1:
        raise SystemExit("--ga-generations must be positive")

    start_time = time.perf_counter()
    run_results = []
    total_evaluations = 0
    library_version = None
    for run_index in range(runs):
        selected, evaluations, library_version = _run_once(
            problem=problem,
            budget=budget,
            population_size=population_size,
            generations=generations,
            seed=seed + run_index,
        )
        evaluated = evaluate_defense_set(problem, selected, method="ga")
        total_evaluations += evaluations
        run_results.append(evaluated)

    best = min(
        run_results,
        key=lambda item: (
            item["objective_cost_form"],
            item["defense_cost"],
            tuple(defense["id"] for defense in item["selected_defenses"]),
        ),
    )
    objectives = [float(item["objective_cost_form"]) for item in run_results]
    result = dict(best)
    result["method"] = "ga"
    result["status"] = "ok"
    result["budget"] = budget
    result["budget_used"] = result["defense_cost"]
    result["budget_feasible"] = result["defense_cost"] <= budget + 1e-9
    result["objective_mean"] = statistics.fmean(objectives)
    result["objective_std"] = statistics.pstdev(objectives) if len(objectives) > 1 else 0.0
    result["ga_runs"] = runs
    result["ga_population_size"] = population_size
    result["ga_generations"] = generations
    result["function_evaluations"] = total_evaluations
    result["algorithm_library"] = "pymoo"
    result["algorithm_library_version"] = library_version
    result["algorithm_class"] = "pymoo.algorithms.soo.nonconvex.ga.GA"
    result["search_fitness"] = "loss_then_attacker_utility_then_defense_cost"
    result["reported_solution_selection"] = "minimum_exact_objective_over_all_evaluated_feasible_candidates"
    result["ga_run_objectives"] = objectives
    result["timings_seconds"] = {"total_wall": time.perf_counter() - start_time}
    attach_benefit(result, empty_objective)
    return result
