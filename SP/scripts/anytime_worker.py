"""Trace existing algorithms in isolated processes; no heuristic substitutions."""
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
    parser.add_argument("--method", required=True)
    parser.add_argument("--cost-file", type=Path, required=True)
    parser.add_argument("--dataset", default="D14654")
    parser.add_argument("--vertices", required=True)
    parser.add_argument("--arcs", required=True)
    parser.add_argument("--goals", required=True)
    parser.add_argument("--budget", type=lambda value: None if value.lower() in {"none", "unlimited"} else float(value), default=60)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--started", type=float, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    costs = json.loads(args.cost_file.read_text())
    attack_raw = json.dumps(costs['attack_costs'])
    defense_raw = json.dumps(costs['defense_costs'])
    from baseline_common import add_problem_arguments, load_problem, evaluate_defense_set, defense_cost
    p = argparse.ArgumentParser()
    add_problem_arguments(p)
    option_args = ["--vertices", args.vertices, "--arcs", args.arcs,
                   "--goals", args.goals, "--default-reward", "1000", "--default-loss", "1000",
                            "--attack-cost-source", "constant", "--default-action-cost", "1", "--target-closure"]
    if args.budget is not None:
        option_args.extend(["--budget", str(args.budget)])
    settings = p.parse_args(option_args)
    settings.node_attack_costs = attack_raw
    settings.defense_costs = defense_raw
    problem = load_problem(settings)
    empty = evaluate_defense_set(problem, set(), method="empty")
    search_budget = args.budget if args.budget is not None else sum(
        defense_cost(problem, {node}) for node in problem.defendable
    )
    j0 = float(empty["objective_cost_form"])
    best = j0
    best_set = set()
    evaluations = 0
    trace_path = args.output / "trace.jsonl"

    def elapsed():
        return time.perf_counter() - args.started

    def emit(kind, **data):
        with trace_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"time": elapsed(), "kind": kind, **data}) + "\n")

    class Deadline(Exception):
        pass

    def check():
        if elapsed() >= args.seconds:
            raise Deadline()

    def record(selected, objective=None):
        nonlocal best, best_set, evaluations
        check()
        evaluations += 1
        if args.budget is not None and defense_cost(problem, selected) > args.budget + 1e-9:
            return
        if objective is None:
            objective = evaluate_defense_set(problem, selected, method=args.method)["objective_cost_form"]
        if elapsed() <= args.seconds and objective < best - 1e-7:
            best = float(objective)
            best_set = set(selected)
            emit("improvement", objective=best, benefit=(j0-best)/j0,
                 selected_ids=sorted(best_set))

    emit("ready", empty_objective=j0, goals=problem.goals, defendable_count=len(problem.defendable))
    status = "finished"
    try:
        check()
        if args.method == "random":
            from random_defense_baseline import sample_random_defense
            rng = random.Random(args.seed)
            while True:
                check()
                if args.budget is None:
                    candidates = sorted(problem.defendable)
                    selected = set(rng.sample(candidates, rng.randint(0, len(candidates))))
                else:
                    selected = sample_random_defense(problem, search_budget, rng)
                record(selected)
        elif args.method == "ga":
            import ga_defense_baseline as ga
            original = ga._metrics

            def measured(problem_arg, selected, budget):
                check()
                objective, fitness = original(problem_arg, selected, budget)
                record(selected, objective)
                return objective, fitness

            ga._metrics = measured
            # Existing population, crossover, mutation, cache and fitness unchanged.
            # A time horizon replaces the generation cap only in this anytime test.
            ga._run_once(problem, search_budget, 64, 10**9, args.seed)
        elif args.method == "path_enum":
            from full_path_enumeration_baseline import (enumerate_goal_paths, exact_path_cover,
                                                        PathEnumerationLimit, PathEnumerationCycle)
            try:
                paths = enumerate_goal_paths(problem, max_paths=100000, max_depth=200)
                check()
                selected, stats = exact_path_cover(problem, paths, search_budget, on_improvement=record)
                record(selected)
                emit("enumeration_complete", **stats)
            except (PathEnumerationLimit, PathEnumerationCycle) as exc:
                status = "skipped_limit"
                emit("enumeration_skipped", reason=str(exc))
        elif args.method == "stackelberg":
            import solve_mulval__stackelberg_main as core
            from pyscipopt import Eventhdlr, SCIP_EVENTTYPE

            class Incumbent(Eventhdlr):
                def eventinit(self):
                    self.model.catchEvent(SCIP_EVENTTYPE.BESTSOLFOUND, self)

                def eventexit(self):
                    self.model.dropEvent(SCIP_EVENTTYPE.BESTSOLFOUND, self)

                def eventexec(self, event):
                    if elapsed() > args.seconds:
                        self.model.interruptSolve()
                        return
                    sol = self.model.getBestSol()
                    objective = self.model.getSolObjVal(sol)
                    if objective < best - 1e-7:
                        selected = {int(v.name[2:]) for v in self.model.getVars(transformed=False)
                                    if v.name.startswith("d_") and self.model.getSolVal(sol, v) > .5}
                        # Validate every reported MIP incumbent with the baseline evaluator.
                        checked = evaluate_defense_set(problem, selected, method="check")["objective_cost_form"]
                        if abs(checked-objective) > 1e-4:
                            raise RuntimeError("MIP incumbent disagrees with independent evaluator")
                        if elapsed() < args.seconds:
                            record(selected, checked)

            original_backend = core.create_model_backend

            def backend(solver, time_limit, mip_gap):
                model, quicksum = original_backend(solver, max(.001, args.seconds-elapsed()), mip_gap)
                model.setIntParam("parallel/maxnthreads", 1)
                model.setIntParam("randomization/randomseedshift", args.seed)
                model.includeEventhdlr(Incumbent(), "incumbent_trace", "Record best feasible objective")
                return model, quicksum

            core.create_model_backend = backend
            result = core.solve_game(problem.vertices, problem.arcs, None, problem.goals,
                1000., 1000., None, None, 1., defense_raw, "vul", args.budget, "constant", 1., 0.,
                attack_raw, None, True, args.seconds, 0., False, "scip", None)
            status = result["status"]
            if elapsed() < args.seconds and result.get("objective_cost_form") is not None:
                record({d["id"] for d in result["selected_defenses"]}, result["objective_cost_form"])
            (args.output / "solver_result.json").write_text(json.dumps(result, indent=2))
        elif args.method != "empty":
            raise ValueError(args.method)
    except Deadline:
        status = "time_limit"
    emit("finish", status=status, objective=best, benefit=(j0-best)/j0, evaluations=evaluations)
    verified = evaluate_defense_set(problem, best_set, method="final_check")
    assert abs(verified["objective_cost_form"]-best) < 1e-5
    (args.output / "result.json").write_text(json.dumps({
        "status": status, "objective": best, "benefit": (j0-best)/j0,
        "selected_ids": sorted(best_set), "evaluations": evaluations,
        "wall_seconds": elapsed(), "empty_objective": j0,
    }, indent=2))


if __name__ == "__main__":
    main()
