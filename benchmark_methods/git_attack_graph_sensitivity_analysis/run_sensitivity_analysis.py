#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""One-factor sensitivity analysis for the proposed Stackelberg defender.

The graph convention is deliberately the same as the real-data benchmark:
CSV arcs are conclusion -> prerequisite, while a legal goal is a visual
(prerequisite -> conclusion) terminal OR node.  All terminal OR nodes are used
so the target closure covers every node in each of the six supplied instances.

Each factor is varied independently around the published baseline:
  * budget ratio beta: 0.10 ... 0.60 (baseline 0.40),
  * unit defense cost c_d: 0.5, 1, 2, 3 (baseline 1),
  * attacker reward R: 250, 500, 1000, 2000 (baseline 1000).

The loss remains 1000.  For the defense-cost sweep the monetary budget is
beta * number_of_defendable_vulnerabilities * c_d.  Thus beta continues to
mean the same maximum *fraction of vulnerabilities* that can be defended;
only the economic tradeoff in the defender objective changes.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import signal
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from mulval_cost_calibration import estimate_goal_min_attack_costs, parse_csv_files
from run_git_attack_graph_benchmarks import (
    choose_goals,
    dataset_sort_key,
    discover_datasets,
    is_real_vulnerability,
    parse_dataset_list,
    validate_csv_format,
    validate_visual_terminal_goals,
)


BASE_BUDGET_RATIO = 0.40
BASE_DEFENSE_COST = 1.0
BASE_REWARD = 1000.0
BASE_LOSS = 1000.0
BASE_ACTION_COST_SCALE = 1.0
FACTOR_VALUES = {
    "budget_ratio": (0.10, 0.20, 0.30, 0.40, 0.50, 0.60),
    "defense_cost": (0.5, 1.0, 2.0, 3.0),
    "reward": (250.0, 500.0, 1000.0, 2000.0),
    "action_cost_scale": (0.5, 1.0, 2.0, 4.0),
}

SUMMARY_FIELDS = [
    "factor", "factor_value", "dataset", "status", "timed_out",
    "returncode", "wall_seconds", "time_limit_seconds", "node_count",
    "arc_count", "goal_count", "defendable_vulnerability_count",
    "budget_ratio", "defense_cost_parameter", "action_cost_scale", "budget", "reward", "loss",
    "objective_cost_form", "empty_objective_cost_form", "benefit_score",
    "selected_defense_count", "selected_defense_ids", "defense_cost_used",
    "attack_loss", "attacker_response_type", "attacker_goal_id",
    "solver_status", "relative_gap", "result_json", "log_file",
]


def closure_ids(arcs: list[tuple[int, int]], goals: list[int]) -> set[int]:
    outgoing: dict[int, list[int]] = defaultdict(list)
    for conclusion, prerequisite in arcs:
        outgoing[conclusion].append(prerequisite)
    kept, stack = set(goals), list(goals)
    while stack:
        for prerequisite in outgoing[stack.pop()]:
            if prerequisite not in kept:
                kept.add(prerequisite)
                stack.append(prerequisite)
    return kept


def parse_floats(raw: str, name: str) -> list[float]:
    try:
        values = [float(item.strip()) for item in raw.split(",") if item.strip()]
    except ValueError as exc:
        raise SystemExit(f"--{name} must be comma-separated numbers") from exc
    if not values or any(not math.isfinite(value) or value <= 0 for value in values):
        raise SystemExit(f"--{name} must contain positive finite numbers")
    return values


def parse_factors(raw: str) -> list[str]:
    values = [item.strip() for item in raw.split(",") if item.strip()]
    unknown = [item for item in values if item not in FACTOR_VALUES]
    if unknown or not values:
        raise SystemExit(f"--factors must use: {', '.join(FACTOR_VALUES)}")
    return values


def terminate_process_group(proc: subprocess.Popen, grace_seconds: float) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        proc.wait()


def run_with_hard_timeout(cmd: list[str], log_path: Path, limit: float, grace: float):
    start = time.perf_counter()
    timed_out = threading.Event()
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)

        def expire() -> None:
            if proc.poll() is None:
                timed_out.set()
                terminate_process_group(proc, grace)

        timer = threading.Timer(limit, expire)
        timer.daemon = True
        timer.start()
        returncode = proc.wait()
        timer.cancel()
    return (None if timed_out.is_set() else returncode, time.perf_counter() - start, timed_out.is_set())


def parameters(factor: str, value: float) -> dict[str, float]:
    result = {
        "budget_ratio": BASE_BUDGET_RATIO,
        "defense_cost": BASE_DEFENSE_COST,
        "reward": BASE_REWARD,
        "loss": BASE_LOSS,
        "action_cost_scale": BASE_ACTION_COST_SCALE,
    }
    result[factor] = value
    return result


def prepare_case(
    dataset: str,
    vertices_path: Path,
    arcs_path: Path,
    attack_cost_source: str,
    default_action_cost: float,
) -> dict:
    validate_csv_format(vertices_path, arcs_path)
    vertices, arcs = parse_csv_files(vertices_path, arcs_path)
    _, goals = choose_goals(vertices, arcs, "all-terminal")
    validate_visual_terminal_goals(vertices, arcs, goals)
    closure = closure_ids(arcs, goals)
    if closure != set(vertices):
        raise SystemExit(f"{dataset}: all terminal goals do not cover the full graph")
    defendable = [
        node_id for node_id, node in vertices.items()
        if node["type"] == "LEAF" and is_real_vulnerability(node["label"])
    ]
    if not defendable:
        raise SystemExit(f"{dataset}: no defendable vulnerability facts")
    goal_min_attack_costs = estimate_goal_min_attack_costs(
        vertices=vertices,
        arcs=arcs,
        goals=goals,
        attack_cost_source=attack_cost_source,
        default_action_cost=default_action_cost,
    )
    return {
        "dataset": dataset, "vertices": vertices_path, "arcs": arcs_path,
        "node_count": len(vertices), "arc_count": len(arcs), "goals": goals,
        "goal_count": len(goals), "defendable_count": len(defendable),
        "type_counts": dict(Counter(node["type"] for node in vertices.values())),
        "goal_min_attack_costs": goal_min_attack_costs,
    }


def scaled_action_costs(case: dict, attack_cost_source: str, default_action_cost: float, scale: float) -> dict[int, float]:
    """Return explicit costs for every AND action after applying a common scale."""
    vertices, _ = parse_csv_files(case["vertices"], case["arcs"])
    return {
        node_id: ((node["score"] if attack_cost_source == "score" and node["score"] > 0 else default_action_cost) * scale)
        for node_id, node in vertices.items()
        if node["type"] == "AND"
    }


def empty_objective(case: dict, params: dict, action_costs: dict[int, float]) -> float:
    """Compute J(empty) under exactly the same scaled action-cost model."""
    vertices, arcs = parse_csv_files(case["vertices"], case["arcs"])
    for node_id, cost in action_costs.items():
        vertices[node_id]["score"] = cost
    min_costs = estimate_goal_min_attack_costs(
        vertices=vertices, arcs=arcs, goals=case["goals"],
        attack_cost_source="score", default_action_cost=0.0,
    )
    return params["loss"] if max(params["reward"] - cost for cost in min_costs.values()) > 1e-9 else 0.0


def attach_comparable_metrics(result: dict, case: dict, params: dict, action_costs: dict[int, float]) -> dict:
    """Attach the same empty-defense-normalized benefit used by baselines."""
    empty_cost = empty_objective(case, params, action_costs)
    result["empty_objective_cost_form"] = empty_cost
    selected = result.get("selected_defenses") or []
    defense_cost = sum(float(item.get("cost", 0.0)) for item in selected)
    result["defense_cost"] = defense_cost
    objective = result.get("objective_cost_form")
    if objective is None:
        result["attack_loss"] = None
        result["benefit_score"] = None
    else:
        result["attack_loss"] = float(objective) - defense_cost
        result["benefit_score"] = ((empty_cost - float(objective)) / empty_cost if empty_cost > 0 else 0.0)
    return result


def make_row(factor: str, value: float, case: dict, params: dict, result: dict,
             returncode: int | None, wall: float, timed_out: bool,
             result_path: Path, log_path: Path, time_limit: float) -> dict:
    selected = result.get("selected_defenses") or []
    response = result.get("attacker_response") or {}
    response_goal = response.get("goal") or {}
    return {
        "factor": factor, "factor_value": value, "dataset": case["dataset"],
        "status": "timeout" if timed_out else result.get("status", "failed" if returncode else "unknown"),
        "timed_out": timed_out, "returncode": returncode, "wall_seconds": wall,
        "time_limit_seconds": time_limit, "node_count": case["node_count"],
        "arc_count": case["arc_count"], "goal_count": case["goal_count"],
        "defendable_vulnerability_count": case["defendable_count"],
        "budget_ratio": params["budget_ratio"], "defense_cost_parameter": params["defense_cost"],
        "action_cost_scale": params["action_cost_scale"],
        "budget": result.get("budget"), "reward": params["reward"], "loss": params["loss"],
        "objective_cost_form": result.get("objective_cost_form"),
        "empty_objective_cost_form": result.get("empty_objective_cost_form"),
        "benefit_score": result.get("benefit_score"), "selected_defense_count": len(selected),
        "selected_defense_ids": ";".join(str(item.get("id")) for item in selected),
        "defense_cost_used": result.get("defense_cost"), "attack_loss": result.get("attack_loss"),
        "attacker_response_type": response.get("type"), "attacker_goal_id": response_goal.get("id"),
        "solver_status": result.get("status"), "relative_gap": result.get("relative_gap"),
        "result_json": str(result_path.resolve()), "log_file": str(log_path.resolve()),
    }


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_factor_tables(output_root: Path, rows: list[dict], factors: list[str]) -> None:
    for factor in factors:
        subset = [row for row in rows if row["factor"] == factor]
        datasets = sorted({row["dataset"] for row in subset}, key=dataset_sort_key)
        values = sorted({float(row["factor_value"]) for row in subset})
        lookup = {(float(row["factor_value"]), row["dataset"]): row for row in subset}
        fields = ["parameter_value"] + datasets + ["mean_benefit", "timeout_count"]
        table = []
        for value in values:
            picked = [lookup.get((value, dataset)) for dataset in datasets]
            completed = [row for row in picked if row is not None]
            finite = [
                float(row["benefit_score"])
                for row in completed
                if row["benefit_score"] not in (None, "")
            ]
            line = {"parameter_value": value}
            for dataset, row in zip(datasets, picked):
                line[dataset] = "" if row is None else ("timeout" if row["timed_out"] else row["benefit_score"])
            line["mean_benefit"] = sum(finite) / len(finite) if finite else ""
            line["timeout_count"] = sum(bool(row["timed_out"]) for row in completed)
            table.append(line)
        write_csv(output_root / f"{factor}_benefit_table.csv", table, fields)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", default="git_atack_graph")
    parser.add_argument("--output-root", default="git_attack_graph_sensitivity_analysis")
    parser.add_argument("--datasets", default="S1,S2,S3,S300,S500,S1000")
    parser.add_argument("--factors", default="budget_ratio,defense_cost,reward,action_cost_scale")
    parser.add_argument("--budget-ratios", default="0.1,0.2,0.3,0.4,0.5,0.6")
    parser.add_argument("--defense-costs", default="0.5,1,2,3")
    parser.add_argument("--rewards", default="250,500,1000,2000")
    parser.add_argument("--action-cost-scales", default="0.5,1,2,4")
    parser.add_argument("--loss", type=float, default=BASE_LOSS)
    parser.add_argument("--attack-cost-source", choices=["constant", "score"], default="score")
    parser.add_argument("--default-action-cost", type=float, default=1.0)
    parser.add_argument("--solver", choices=["scip", "gurobi"], default="scip")
    parser.add_argument("--mip-gap", type=float, default=0.0)
    parser.add_argument("--time-limit", type=float, default=60.0)
    parser.add_argument("--termination-grace", type=float, default=2.0)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--resume", action="store_true", help="Preserve completed factor/value/dataset rows and run only missing cases.")
    args = parser.parse_args()
    if args.loss <= 0 or args.time_limit <= 0 or args.termination_grace <= 0 or args.default_action_cost < 0:
        raise SystemExit("loss/time limits must be positive; action cost must be non-negative")
    factors = parse_factors(args.factors)
    configured = {
        "budget_ratio": parse_floats(args.budget_ratios, "budget-ratios"),
        "defense_cost": parse_floats(args.defense_costs, "defense-costs"),
        "reward": parse_floats(args.rewards, "rewards"),
        "action_cost_scale": parse_floats(args.action_cost_scales, "action-cost-scales"),
    }
    data_root = Path(args.data_root)
    if not data_root.is_absolute(): data_root = REPOSITORY_ROOT / data_root
    output_root = Path(args.output_root)
    if not output_root.is_absolute(): output_root = REPOSITORY_ROOT / output_root
    available = discover_datasets(data_root)
    datasets = parse_dataset_list(args.datasets, available)
    cases = {
        name: prepare_case(
            name, *available[name],
            attack_cost_source=args.attack_cost_source,
            default_action_cost=args.default_action_cost,
        )
        for name in datasets
    }
    (output_root / "protocol.json").parent.mkdir(parents=True, exist_ok=True)
    protocol = {
        "method": "stackelberg_model", "goal_policy": "all-terminal",
        "graph_direction": {"csv": "conclusion -> prerequisite", "paper": "prerequisite -> conclusion"},
        "base_parameters": {"budget_ratio": BASE_BUDGET_RATIO, "defense_cost": BASE_DEFENSE_COST, "reward": BASE_REWARD, "loss": args.loss, "action_cost_scale": BASE_ACTION_COST_SCALE},
        "one_factor_values": {factor: configured[factor] for factor in factors},
        "fixed_parameters": {"attack_cost_source": args.attack_cost_source, "default_action_cost": args.default_action_cost, "mip_gap": args.mip_gap, "time_limit": args.time_limit},
        "cases": {name: {key: value for key, value in case.items() if key not in {"vertices", "arcs"}} for name, case in cases.items()},
    }
    (output_root / "protocol.json").write_text(json.dumps(protocol, ensure_ascii=False, indent=2), encoding="utf-8")
    summary_path = output_root / "sensitivity_summary.csv"
    if args.resume and summary_path.exists():
        with summary_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
    else:
        rows = []
    completed = {
        (row["factor"], float(row["factor_value"]), row["dataset"])
        for row in rows
        if row.get("status") == "optimal"
    }
    for factor in factors:
        for value in configured[factor]:
            params = parameters(factor, value)
            params["loss"] = args.loss
            for dataset in datasets:
                if (factor, value, dataset) in completed:
                    print(f"[skip] {factor}={value:g}, {dataset}: completed", flush=True)
                    continue
                case = cases[dataset]
                # Scale monetary budget with c_d only in the c_d sweep, keeping beta's
                # cardinality interpretation unchanged across that sweep.
                budget = max(1.0, math.floor(case["defendable_count"] * params["budget_ratio"])) * params["defense_cost"]
                case_dir = output_root / "results" / factor / f"{value:g}" / dataset
                case_dir.mkdir(parents=True, exist_ok=True)
                result_path, log_path = case_dir / "result.json", case_dir / "run.log"
                result_path.unlink(missing_ok=True)
                action_costs = scaled_action_costs(
                    case, args.attack_cost_source, args.default_action_cost,
                    params["action_cost_scale"],
                )
                cmd = [
                    args.python, str(REPOSITORY_ROOT / "solve_mulval__stackelberg_main.py"),
                    "--vertices", str(case["vertices"]), "--arcs", str(case["arcs"]),
                    "--goals", ",".join(map(str, case["goals"]),), "--target-closure",
                    "--defendable", "vul", "--budget", str(budget),
                    "--defense-cost", str(params["defense_cost"]),
                    "--default-reward", str(params["reward"]), "--default-loss", str(params["loss"]),
                    "--attack-cost-source", args.attack_cost_source,
                    "--default-action-cost", str(args.default_action_cost),
                    "--node-attack-costs", json.dumps(action_costs, separators=(",", ":")),
                    "--solver", args.solver, "--mip-gap", str(args.mip_gap),
                    "--time-limit", str(args.time_limit), "--out", str(result_path),
                ]
                print(f"[run] {factor}={value:g}, {dataset}: budget={budget:g}, limit={args.time_limit:g}s", flush=True)
                returncode, wall, timed_out = run_with_hard_timeout(cmd, log_path, args.time_limit, args.termination_grace)
                if timed_out:
                    result = {"status": "timeout", "budget": budget, "selected_defenses": []}
                elif returncode != 0 or not result_path.exists():
                    result = {"status": "failed", "budget": budget, "selected_defenses": []}
                else:
                    result = json.loads(result_path.read_text(encoding="utf-8"))
                    result = attach_comparable_metrics(result, case, params, action_costs)
                    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
                row = make_row(factor, value, case, params, result, returncode, wall, timed_out, result_path, log_path, args.time_limit)
                rows.append(row)
                write_csv(summary_path, rows, SUMMARY_FIELDS)
                write_factor_tables(output_root, rows, factors)
                print(f"[done] {factor}={value:g}, {dataset}: status={row['status']}, wall={wall:.3f}s, benefit={row['benefit_score']}", flush=True)
    print(f"summary: {output_root / 'sensitivity_summary.csv'}")


if __name__ == "__main__":
    main()
