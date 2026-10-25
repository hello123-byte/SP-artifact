"""Worker for the paired budget-300 versus unbudgeted effectiveness study."""
import argparse
import json
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "baselines")]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    args = parser.parse_args()
    task = json.loads(args.task.read_text())
    started = time.perf_counter()
    costs = json.loads(Path(task["cost_file"]).read_text())
    attack_raw = json.dumps(costs["attack_costs"])
    defense_raw = json.dumps(costs["defense_costs"])

    from baseline_common import (
        add_problem_arguments,
        attach_benefit,
        evaluate_defense_set,
        load_problem,
    )

    problem_parser = argparse.ArgumentParser()
    add_problem_arguments(problem_parser)
    options = [
        "--vertices", task["vertices"], "--arcs", task["arcs"],
        "--goals", ",".join(map(str, task["goals"])),
        "--default-reward", str(task["reward"]),
        "--default-loss", str(task["loss"]),
        "--defense-cost", "1", "--attack-cost-source", "constant",
        "--default-action-cost", "1", "--target-closure",
        "--node-attack-costs", attack_raw, "--defense-costs", defense_raw,
    ]
    if task["budget"] is not None:
        options.extend(["--budget", str(task["budget"])])
    problem = load_problem(problem_parser.parse_args(options))
    empty = evaluate_defense_set(problem, set(), method="empty")
    empty_objective = empty["objective_cost_form"]
    method = task["method"]
    # A finite value equal to the cost of every candidate is non-binding and
    # lets baseline implementations retain their established interfaces.
    unrestricted_budget = sum(
        problem.defense_costs.get(node_id, problem.default_defense_cost)
        for node_id in problem.defendable
    )
    search_budget = task["budget"] if task["budget"] is not None else unrestricted_budget

    if method == "empty":
        result = empty
    elif method == "random":
        from random_defense_baseline import run_random_baseline
        if task["budget"] is not None:
            result = run_random_baseline(problem, search_budget, 50, task["seed"], empty_objective)
            mean_objective = float(result["objective_mean"])
            result["sampling_rule"] = "budget-filling random permutation"
        else:
            rng = random.Random(task["seed"])
            candidates = sorted(problem.defendable)
            trials = []
            evaluated = []
            for trial in range(50):
                k = rng.randint(0, len(candidates))
                selected = set(rng.sample(candidates, k))
                item = evaluate_defense_set(problem, selected, method="random_defense")
                evaluated.append(item)
                trials.append({
                    "trial": trial,
                    "objective_cost_form": item["objective_cost_form"],
                    "defense_cost": item["defense_cost"],
                    "selected_defense_count": len(selected),
                })
            result = dict(min(evaluated, key=lambda item: (
                item["objective_cost_form"], item["defense_cost"],
                len(item["selected_defenses"]))))
            values = [float(item["objective_cost_form"]) for item in evaluated]
            mean_objective = sum(values) / len(values)
            result.update({
                "method": "random_defense", "status": "ok", "budget": None,
                "random_trials": 50, "trial_summaries": trials,
                "objective_mean": mean_objective,
                "objective_min": min(values), "objective_max": max(values),
                "sampling_rule": "uniform k in 0..n, then uniform k-subset without replacement",
            })
        result["comparison_objective"] = mean_objective
        result["comparison_benefit"] = (empty_objective - mean_objective) / empty_objective
    elif method == "ga":
        from ga_defense_baseline import run_ga_baseline
        result = run_ga_baseline(problem, search_budget, 1, 64, 50, task["seed"], empty_objective)
        result["reported_budget"] = task["budget"]
    elif method == "path_enum":
        from full_path_enumeration_baseline import run_path_enumeration_baseline
        result = run_path_enumeration_baseline(problem, search_budget, 100000, 200, empty_objective)
        result["reported_budget"] = task["budget"]
    elif method == "stackelberg":
        import solve_mulval__stackelberg_main as core
        original_backend = core.create_model_backend
        models = []

        def backend(solver, time_limit, mip_gap):
            remaining = max(0.01, task["limit"] - (time.perf_counter() - task["started"]) - 1)
            model, variables = original_backend(solver, remaining, mip_gap)
            model.setIntParam("parallel/maxnthreads", 1)
            model.setIntParam("randomization/randomseedshift", task["seed"])
            models.append(model)
            return model, variables

        core.create_model_backend = backend
        result = core.solve_game(
            problem.vertices, problem.arcs, None, problem.goals,
            task["reward"], task["loss"], None, None, 1, defense_raw,
            "vul", task["budget"], "constant", 1, 0.0, attack_raw,
            None, True, task["limit"], 0.0, False, "scip", None,
        )
        model = models[0]
        result["model_stats"] = {
            "variables": model.getNVars(transformed=False),
            "constraints": model.getNConss(transformed=False),
            "dual_bound": model.getDualbound(),
            "primal_bound": model.getPrimalbound(),
            "search_nodes": model.getNNodes(), "threads": 1,
        }
        attach_benefit(result, empty_objective)
    else:
        raise ValueError(method)

    if result.get("objective_cost_form") is not None:
        selected = {item["id"] for item in result.get("selected_defenses", [])}
        check = evaluate_defense_set(problem, selected, method="validation")
        if abs(check["objective_cost_form"] - result["objective_cost_form"]) > 1e-5:
            raise RuntimeError("Selected strategy disagrees with independent evaluator")
        result["independent_strategy_check"] = True
    result["empty_objective_cost_form"] = empty_objective
    result["budget_mode"] = task["budget_mode"]
    result["worker_wall_seconds"] = time.perf_counter() - started
    Path(task["result"]).write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
