#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compare four defense methods on the six git_atack_graph instances.

Every dataset/method pair runs in its own process group.  The outer runner
enforces a hard wall-clock timeout, including full-path enumeration, and writes
an explicit ``timeout`` result when the limit is reached.
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
import time
from collections import Counter
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from mulval_cost_calibration import calibrate_goal_values, parse_csv_files
from run_git_attack_graph_benchmarks import (
    choose_goals,
    closure_ids,
    dataset_sort_key,
    discover_datasets,
    is_real_vulnerability,
    parse_dataset_list,
    validate_csv_format,
    validate_visual_terminal_goals,
)


METHODS = ("empty", "random", "path_enum", "stackelberg")
RESULT_FILENAMES = {
    "empty": "empty_defense.json",
    "random": "random_defense.json",
    "path_enum": "full_path_enumeration.json",
    "stackelberg": "stackelberg_model.json",
}
DISPLAY_NAMES = {
    "empty": "Empty",
    "random": "Random",
    "path_enum": "Path enumeration",
    "stackelberg": "Our",
}
SUMMARY_FIELDS = [
    "dataset",
    "method",
    "display_name",
    "status",
    "timed_out",
    "returncode",
    "time_limit_seconds",
    "wall_seconds",
    "node_count",
    "arc_count",
    "goal_count",
    "defendable_vulnerability_count",
    "budget",
    "objective_cost_form",
    "objective_mean",
    "objective_std",
    "best_benefit_score",
    "mean_benefit_score",
    "effectiveness_score",
    "selected_defense_count",
    "defense_cost",
    "attack_loss",
    "attacker_response_type",
    "reachable_goal_count",
    "enumerated_path_count",
    "max_paths",
    "limit_hit",
    "exact_cover",
    "relevant_defendable_count",
    "defense_combination_count_evaluated",
    "blocking_combination_count",
    "blocking_strategy_found",
    "relative_gap",
    "result_json",
    "log_file",
]


def parse_methods(raw: str | None) -> list[str]:
    if not raw:
        return list(METHODS)
    methods = [item.strip() for item in raw.split(",") if item.strip()]
    unknown = [method for method in methods if method not in METHODS]
    if unknown:
        raise SystemExit(f"Unknown method(s): {unknown}. Available: {list(METHODS)}")
    return methods


def compute_budget(defendable_count: int, fixed_budget: float | None, budget_ratio: float) -> float:
    if fixed_budget is not None:
        if fixed_budget < 0:
            raise SystemExit("--budget must be non-negative")
        return float(fixed_budget)
    if not 0 < budget_ratio <= 1:
        raise SystemExit("--budget-ratio must be in (0, 1]")
    return float(max(1, math.floor(defendable_count * budget_ratio)))


def terminate_process_group(proc: subprocess.Popen, grace_seconds: float) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    proc.wait()


def run_with_hard_timeout(
    cmd: list[str],
    log_path: Path,
    timeout_seconds: float,
    termination_grace_seconds: float,
) -> tuple[int | None, float, bool]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(
            cmd,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            returncode = proc.wait(timeout=timeout_seconds)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_process_group(proc, termination_grace_seconds)
            returncode = None
    return returncode, time.perf_counter() - start, timed_out


def build_method_command(
    args,
    method: str,
    vertices_path: Path,
    arcs_path: Path,
    goals: list[int],
    budget: float,
    reward: float,
    loss: float,
    method_dir: Path,
) -> list[str]:
    cmd = [
        args.python,
        str(REPOSITORY_ROOT / "baselines" / "run_baseline_experiments.py"),
        "--vertices", str(vertices_path),
        "--arcs", str(arcs_path),
        "--goals", ",".join(map(str, goals)),
        "--default-reward", str(reward),
        "--default-loss", str(loss),
        "--defense-cost", str(args.defense_cost),
        "--budget", str(budget),
        "--attack-cost-source", args.attack_cost_source,
        "--default-action-cost", str(args.default_action_cost),
        "--target-closure",
        "--methods", method,
        "--out-dir", str(method_dir),
        "--random-budget", str(budget),
        "--path-budget", str(budget),
        "--random-trials", str(args.random_trials),
        "--seed", str(args.seed),
        "--max-paths", str(args.max_paths),
        "--max-depth", str(args.max_depth),
        "--solver", args.solver,
        "--mip-gap", str(args.mip_gap),
        "--time-limit", str(args.method_time_limit),
        "--skip-chart",
    ]
    return cmd


def timeout_result(method: str, timeout_seconds: float, wall_seconds: float) -> dict:
    return {
        "method": method,
        "status": "timeout",
        "timed_out": True,
        "time_limit_seconds": timeout_seconds,
        "objective_cost_form": None,
        "benefit_score": None,
        "selected_defenses": [],
        "reachable_goals": [],
        "attacker_response": None,
        "defense_cost": None,
        "attack_loss": None,
        "timings_seconds": {"runner_wall": wall_seconds},
    }


def failed_result(method: str, returncode: int | None, wall_seconds: float, reason: str) -> dict:
    return {
        "method": method,
        "status": "failed",
        "timed_out": False,
        "failure_reason": reason,
        "returncode": returncode,
        "objective_cost_form": None,
        "benefit_score": None,
        "selected_defenses": [],
        "reachable_goals": [],
        "attacker_response": None,
        "defense_cost": None,
        "attack_loss": None,
        "timings_seconds": {"runner_wall": wall_seconds},
    }


def mean_benefit(result: dict) -> float | None:
    empty_objective = result.get("empty_objective_cost_form")
    objective_mean = result.get("objective_mean")
    if empty_objective in (None, 0) or objective_mean is None:
        return result.get("benefit_score")
    return (float(empty_objective) - float(objective_mean)) / float(empty_objective)


def result_row(
    dataset: str,
    method: str,
    case: dict,
    result: dict,
    result_path: Path,
    log_path: Path,
    returncode: int | None,
    wall_seconds: float,
    timed_out: bool,
    timeout_seconds: float,
) -> dict:
    best_benefit = result.get("benefit_score")
    average_benefit = mean_benefit(result) if method == "random" else best_benefit
    response = result.get("attacker_response") or {}
    return {
        "dataset": dataset,
        "method": method,
        "display_name": DISPLAY_NAMES[method],
        "status": result.get("status"),
        "timed_out": timed_out,
        "returncode": returncode,
        "time_limit_seconds": timeout_seconds,
        "wall_seconds": round(wall_seconds, 6),
        "node_count": case["node_count"],
        "arc_count": case["arc_count"],
        "goal_count": case["goal_count"],
        "defendable_vulnerability_count": case["defendable_vulnerability_count"],
        "budget": case["budget"],
        "objective_cost_form": result.get("objective_cost_form"),
        "objective_mean": result.get("objective_mean", result.get("objective_cost_form")),
        "objective_std": result.get("objective_std", 0.0 if result.get("objective_cost_form") is not None else None),
        "best_benefit_score": best_benefit,
        "mean_benefit_score": average_benefit,
        "effectiveness_score": average_benefit,
        "selected_defense_count": len(result.get("selected_defenses") or []),
        "defense_cost": result.get("defense_cost"),
        "attack_loss": result.get("attack_loss"),
        "attacker_response_type": response.get("type"),
        "reachable_goal_count": len(result.get("reachable_goals") or []),
        "enumerated_path_count": result.get("enumerated_path_count"),
        "max_paths": result.get("max_paths"),
        "limit_hit": result.get("limit_hit"),
        "exact_cover": result.get("exact_cover"),
        "relevant_defendable_count": result.get("relevant_defendable_count"),
        "defense_combination_count_evaluated": result.get("defense_combination_count_evaluated"),
        "blocking_combination_count": result.get("blocking_combination_count"),
        "blocking_strategy_found": result.get("blocking_strategy_found"),
        "relative_gap": result.get("relative_gap"),
        "result_json": str(result_path.resolve()),
        "log_file": str(log_path.resolve()),
    }


def write_summary(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in SUMMARY_FIELDS} for row in rows)


def write_effectiveness_chart(path: Path, rows: list[dict], dpi: int) -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise SystemExit("matplotlib is required unless --skip-chart is used") from exc

    datasets = sorted({row["dataset"] for row in rows}, key=dataset_sort_key)
    methods = [method for method in METHODS if any(row["method"] == method for row in rows)]
    lookup = {(row["dataset"], row["method"]): row for row in rows}
    colors = {
        "empty": "#666666",
        "random": "#0072B2",
        "path_enum": "#009E73",
        "stackelberg": "#D55E00",
    }
    width = 0.18
    x = list(range(len(datasets)))
    finite_scores = [
        float(row["effectiveness_score"])
        for row in rows
        if row.get("effectiveness_score") not in (None, "")
    ]
    fig, ax = plt.subplots(figsize=(7.0, 3.2), constrained_layout=True)
    for method_index, method in enumerate(methods):
        offset = (method_index - (len(methods) - 1) / 2) * width
        positions = [value + offset for value in x]
        values = []
        for dataset in datasets:
            value = lookup.get((dataset, method), {}).get("effectiveness_score")
            values.append(float(value) if value not in (None, "") else math.nan)
        ax.bar(
            positions,
            values,
            width=width * 0.86,
            color=colors[method],
            label=DISPLAY_NAMES[method],
        )
        for position, dataset, value in zip(positions, datasets, values):
            row = lookup.get((dataset, method), {})
            if not math.isnan(value):
                continue
            status = row.get("status")
            marker = "T/O" if status == "timeout" else "Limit" if status == "skipped_limit" else "N/A"
            ax.text(position, 0.02, marker, rotation=90, ha="center", va="bottom", fontsize=6)

    ax.axhline(0, color="black", linewidth=0.7)
    ax.set_xticks(x)
    ax.set_xticklabels(datasets)
    ax.set_ylabel("defense benefit")
    lower_bound = min([-0.05] + finite_scores) - 0.02
    ax.set_ylim(lower_bound, 1.08)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(frameon=False, ncol=len(methods), loc="upper center")
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=dpi, bbox_inches="tight")
    plt.close(fig)


def prepare_case(args, dataset: str, vertices_path: Path, arcs_path: Path) -> dict:
    validate_csv_format(vertices_path, arcs_path)
    vertices, arcs = parse_csv_files(vertices_path, arcs_path)
    _, goals = choose_goals(vertices, arcs, args.goal_policy)
    validate_visual_terminal_goals(vertices, arcs, goals)
    closure = closure_ids(vertices, arcs, goals)
    closure_arcs = [edge for edge in arcs if edge[0] in closure and edge[1] in closure]
    if args.goal_policy == "all-terminal" and len(closure) != len(vertices):
        raise SystemExit(f"{dataset}: terminal-goal closure does not cover the full graph")
    defendable_count = sum(
        1
        for node in vertices.values()
        if node["type"] == "LEAF" and is_real_vulnerability(node["label"])
    )
    budget = compute_budget(defendable_count, args.budget, args.budget_ratio)
    calibration = calibrate_goal_values(
        vertices=vertices,
        arcs=arcs,
        goals=goals,
        attack_cost_source=args.attack_cost_source,
        reward_multiplier=2.0,
        min_goal_reward=1000.0,
        explicit_reward=args.default_reward,
        explicit_loss=args.default_loss,
    )
    return {
        "dataset": dataset,
        "vertices": str(vertices_path.resolve()),
        "arcs": str(arcs_path.resolve()),
        "node_count": len(vertices),
        "arc_count": len(arcs),
        "type_counts": dict(Counter(node["type"] for node in vertices.values())),
        "goal_policy": args.goal_policy,
        "goals": goals,
        "goal_count": len(goals),
        "targets_visual_terminal": True,
        "closure_node_count": len(closure),
        "closure_arc_count": len(closure_arcs),
        "closure_removed_nodes": len(vertices) - len(closure),
        "closure_removed_arcs": len(arcs) - len(closure_arcs),
        "defendable_vulnerability_count": defendable_count,
        "budget": budget,
        "budget_source": "fixed" if args.budget is not None else "floor(defendable_count * budget_ratio), min 1",
        "budget_ratio": args.budget_ratio if args.budget is None else None,
        "attack_cost_source": args.attack_cost_source,
        "default_action_cost": args.default_action_cost,
        "defense_cost": args.defense_cost,
        "reward": calibration["reward"],
        "loss": calibration["loss"],
        "method_time_limit_seconds": args.method_time_limit,
        "random_trials": args.random_trials,
        "seed": args.seed,
        "max_paths": args.max_paths,
        "max_depth": args.max_depth,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", default="git_atack_graph")
    parser.add_argument("--output-root", default="git_attack_graph_baseline_comparison")
    parser.add_argument("--datasets", default="S1,S2,S3,S300,S500,S1000")
    parser.add_argument("--methods", default=None, help="Comma-separated subset of empty,random,path_enum,stackelberg")
    parser.add_argument("--goal-policy", choices=["all-terminal", "max-closure"], default="all-terminal")
    parser.add_argument("--budget", type=float, default=None, help="Fixed budget for every dataset; overrides --budget-ratio")
    parser.add_argument("--budget-ratio", type=float, default=0.4)
    parser.add_argument("--method-time-limit", type=float, default=60.0)
    parser.add_argument("--termination-grace", type=float, default=2.0)
    parser.add_argument("--attack-cost-source", choices=["constant", "score"], default="score")
    parser.add_argument("--default-action-cost", type=float, default=1.0)
    parser.add_argument("--defense-cost", type=float, default=1.0)
    parser.add_argument("--default-reward", type=float, default=1000.0)
    parser.add_argument("--default-loss", type=float, default=1000.0)
    parser.add_argument("--random-trials", type=int, default=50)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--max-paths", type=int, default=100000)
    parser.add_argument("--max-depth", type=int, default=200)
    parser.add_argument("--solver", choices=["scip", "gurobi"], default="scip")
    parser.add_argument("--mip-gap", type=float, default=0.0)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--skip-chart", action="store_true")
    parser.add_argument("--figure-dpi", type=int, default=300)
    args = parser.parse_args()

    if args.method_time_limit <= 0:
        raise SystemExit("--method-time-limit must be positive")
    if args.termination_grace <= 0:
        raise SystemExit("--termination-grace must be positive")
    if args.random_trials < 1:
        raise SystemExit("--random-trials must be positive")
    if args.max_paths < 1 or args.max_depth < 1:
        raise SystemExit("--max-paths and --max-depth must be positive")

    data_root = Path(args.data_root)
    if not data_root.is_absolute():
        data_root = REPOSITORY_ROOT / data_root
    output_root = Path(args.output_root)
    if not output_root.is_absolute():
        output_root = REPOSITORY_ROOT / output_root
    datasets = parse_dataset_list(args.datasets, discover_datasets(data_root))
    methods = parse_methods(args.methods)
    available = discover_datasets(data_root)
    rows: list[dict] = []

    for dataset in datasets:
        vertices_path, arcs_path = available[dataset]
        case = prepare_case(args, dataset, vertices_path, arcs_path)
        case_dir = output_root / "results" / dataset
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "case.json").write_text(
            json.dumps(case, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(
            f"[case] {dataset}: nodes={case['node_count']}, goals={case['goal_count']}, "
            f"defendable={case['defendable_vulnerability_count']}, budget={case['budget']:g}",
            flush=True,
        )
        for method in methods:
            method_dir = case_dir / method
            method_dir.mkdir(parents=True, exist_ok=True)
            source_result_path = method_dir / RESULT_FILENAMES[method]
            normalized_result_path = method_dir / "result.json"
            log_path = method_dir / "run.log"
            source_result_path.unlink(missing_ok=True)
            normalized_result_path.unlink(missing_ok=True)
            cmd = build_method_command(
                args=args,
                method=method,
                vertices_path=vertices_path,
                arcs_path=arcs_path,
                goals=case["goals"],
                budget=case["budget"],
                reward=case["reward"],
                loss=case["loss"],
                method_dir=method_dir,
            )
            print(f"[run] {dataset}/{method}: limit={args.method_time_limit:g}s", flush=True)
            returncode, wall_seconds, timed_out = run_with_hard_timeout(
                cmd=cmd,
                log_path=log_path,
                timeout_seconds=args.method_time_limit,
                termination_grace_seconds=args.termination_grace,
            )
            if timed_out:
                result = timeout_result(method, args.method_time_limit, wall_seconds)
            elif returncode != 0:
                result = failed_result(method, returncode, wall_seconds, "non-zero return code")
            elif not source_result_path.exists():
                result = failed_result(method, returncode, wall_seconds, "result JSON was not produced")
            else:
                result = json.loads(source_result_path.read_text(encoding="utf-8"))
                result["timed_out"] = False
                result["time_limit_seconds"] = args.method_time_limit
                result.setdefault("timings_seconds", {})["comparison_runner_wall"] = wall_seconds
            normalized_result_path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            row = result_row(
                dataset=dataset,
                method=method,
                case=case,
                result=result,
                result_path=normalized_result_path,
                log_path=log_path,
                returncode=returncode,
                wall_seconds=wall_seconds,
                timed_out=timed_out,
                timeout_seconds=args.method_time_limit,
            )
            rows.append(row)
            write_summary(output_root / "benchmark_summary.csv", rows)
            print(
                f"[done] {dataset}/{method}: status={row['status']}, "
                f"wall={row['wall_seconds']:.3f}s, benefit={row['effectiveness_score']}",
                flush=True,
            )

    if not args.skip_chart:
        write_effectiveness_chart(
            output_root / "defense_effectiveness_comparison.png",
            rows,
            dpi=args.figure_dpi,
        )
        write_effectiveness_chart(
            output_root / "defense_effectiveness_comparison.pdf",
            rows,
            dpi=args.figure_dpi,
        )
    print(f"summary: {output_root / 'benchmark_summary.csv'}")


if __name__ == "__main__":
    main()
