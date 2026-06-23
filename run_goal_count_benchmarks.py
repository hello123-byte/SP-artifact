# -*- coding: utf-8 -*-
"""Prepare and run goal-count timing benchmarks for synthetic MulVAL graphs.

The benchmark protocol uses the latest generate_large_mulval_csv.py graph
mechanism and evaluates three graph scales:
  * scale_1k
  * scale_10k
  * scale_100k

For every scale, the solver is run with goal counts 1, 50, 100, and 200. All
runs use target-closure optimization, defendable=vul, score-based attack costs,
and reward/loss values calibrated from no-defense goal derivation costs.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from pathlib import Path

from generate_large_mulval_csv import build_graph, write_csv
from mulval_cost_calibration import calibrate_goal_values, parse_csv_files


DEFAULT_GOAL_COUNTS = {
    "scale_1k": [1, 50, 100, 200],
    "scale_10k": [1, 50, 100, 200],
    "scale_100k": [1, 50, 100, 200],
}

DEFAULT_ATTACK_COST_SOURCE = "score"
DEFAULT_REWARD_MULTIPLIER = 2.0
DEFAULT_MIN_GOAL_REWARD = 1000.0

# These parameters are chosen to land near thousand-, ten-thousand-, and
# hundred-thousand-node graph sizes while always generating 200 target goals.
DEFAULT_SCALE_CONFIGS = {
    "scale_1k": {
        "hosts": 20,
        "services_per_host": 2,
        "vuln_per_service": 1,
        "lateral_rules_per_host": 1,
        "goals": 200,
    },
    "scale_10k": {
        "hosts": 600,
        "services_per_host": 2,
        "vuln_per_service": 2,
        "lateral_rules_per_host": 1,
        "goals": 200,
    },
    "scale_100k": {
        "hosts": 6500,
        "services_per_host": 2,
        "vuln_per_service": 2,
        "lateral_rules_per_host": 1,
        "goals": 200,
    },
}


def parse_csv_list(raw: str | None, allowed: list[str]) -> list[str]:
    if not raw:
        return allowed
    requested = [item.strip() for item in raw.split(",") if item.strip()]
    unknown = [item for item in requested if item not in allowed]
    if unknown:
        raise SystemExit(f"Unknown value(s): {unknown}. Allowed: {allowed}")
    return requested


def parse_goal_counts(raw: str | None, defaults: dict[str, list[int]]) -> dict[str, list[int]]:
    if not raw:
        return defaults
    counts = [int(item.strip()) for item in raw.split(",") if item.strip()]
    return {scale: counts for scale in defaults}


def load_result(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def append_summary(summary_path: Path, rows: list[dict]):
    if not rows:
        return
    fieldnames = [
        "scale",
        "goal_count",
        "returncode",
        "wall_seconds",
        "status",
        "solver",
        "attack_cost_source",
        "default_reward",
        "default_loss",
        "reward_source",
        "loss_source",
        "goal_min_attack_cost_min",
        "goal_min_attack_cost_max",
        "goal_min_attack_cost_avg",
        "cost_bound_formulation",
        "cost_big_m",
        "legacy_global_cost_big_m",
        "utility_big_m",
        "utility_upper_bound",
        "defendable_mode",
        "target_closure_enabled",
        "objective_cost_form",
        "attacker_utility",
        "defendable_leaf_count",
        "original_vertices",
        "original_arcs",
        "reduced_vertices",
        "reduced_arcs",
        "removed_vertices",
        "removed_arcs",
        "read_csv_seconds",
        "read_config_seconds",
        "target_closure_seconds",
        "build_parameters_seconds",
        "build_mip_seconds",
        "optimize_seconds",
        "total_solver_wall_seconds",
        "result_json",
        "log_file",
    ]
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def write_goal_sets(scale_dir: Path, scale: str, goals: list[int], goal_counts: list[int]):
    goal_sets_dir = scale_dir / "goal_sets"
    goal_sets_dir.mkdir(parents=True, exist_ok=True)
    for goal_count in goal_counts:
        if goal_count > len(goals):
            raise SystemExit(
                f"Scale {scale} has only {len(goals)} generated goals; cannot write goals_{goal_count}.txt"
            )
        selected = goals[:goal_count]
        (goal_sets_dir / f"goals_{goal_count}.txt").write_text(
            ",".join(str(goal_id) for goal_id in selected),
            encoding="utf-8",
        )
        summary = {
            "scale": scale,
            "goal_count": goal_count,
            "goals": selected,
        }
        (goal_sets_dir / f"summary_goals_{goal_count}.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


def prepare_scale(
    root: Path,
    scale: str,
    goal_counts: list[int],
    seed: int,
    attack_cost_source: str,
    reward_multiplier: float,
    min_goal_reward: float,
    default_reward: float | None,
    default_loss: float | None,
):
    if scale not in DEFAULT_SCALE_CONFIGS:
        raise SystemExit(f"No generator config for scale: {scale}")

    scale_dir = root / scale
    scale_dir.mkdir(parents=True, exist_ok=True)
    config = dict(DEFAULT_SCALE_CONFIGS[scale])
    config["seed"] = seed

    vertices, arcs, goal_nodes, structure = build_graph(**config)
    calibration = calibrate_goal_values(
        vertices=vertices,
        arcs=arcs,
        goals=goal_nodes,
        attack_cost_source=attack_cost_source,
        reward_multiplier=reward_multiplier,
        min_goal_reward=min_goal_reward,
        explicit_reward=default_reward,
        explicit_loss=default_loss,
    )
    write_csv(vertices, arcs, scale_dir / "VERTICES.CSV", scale_dir / "ARCS.CSV")
    write_goal_sets(scale_dir, scale, goal_nodes, goal_counts)

    summary = {
        "scale": scale,
        "vertices": len(vertices),
        "arcs": len(arcs),
        "goals": goal_nodes,
        "parameters": config,
        "structure": structure,
        "diagnostics": structure["diagnostics"],
        "benchmark_goal_counts": goal_counts,
        "benchmark_protocol": {
            "target_closure": True,
            "defendable": "vul",
            "attack_cost_source": attack_cost_source,
            "default_reward": calibration["reward"],
            "default_loss": calibration["loss"],
            "reward_calibration": calibration,
        },
        "format": {
            "VERTICES.CSV": "id,label,type,score",
            "ARCS.CSV": "source,target",
            "edge_direction": "conclusion -> prerequisite",
        },
    }
    (scale_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(
        f"[prepare] {scale}: vertices={len(vertices)}, arcs={len(arcs)}, "
        f"goals={len(goal_nodes)}, goal_counts={goal_counts}, "
        f"cost={attack_cost_source}, reward={calibration['reward']:g}, loss={calibration['loss']:g}",
        flush=True,
    )


def prepare_inputs(
    root: Path,
    scales: list[str],
    goal_counts_by_scale: dict[str, list[int]],
    seed: int,
    attack_cost_source: str,
    reward_multiplier: float,
    min_goal_reward: float,
    default_reward: float | None,
    default_loss: float | None,
):
    for scale in scales:
        prepare_scale(
            root=root,
            scale=scale,
            goal_counts=goal_counts_by_scale[scale],
            seed=seed,
            attack_cost_source=attack_cost_source,
            reward_multiplier=reward_multiplier,
            min_goal_reward=min_goal_reward,
            default_reward=default_reward,
            default_loss=default_loss,
        )


def load_scale_goals(scale_dir: Path, goal_counts: list[int]) -> list[int]:
    summary_path = scale_dir / "summary.json"
    if summary_path.exists():
        data = json.loads(summary_path.read_text(encoding="utf-8"))
        goals = data.get("goals")
        if goals:
            return [int(goal) for goal in goals]

    largest_goal_count = max(goal_counts)
    goal_file = scale_dir / "goal_sets" / f"goals_{largest_goal_count}.txt"
    if not goal_file.exists():
        raise SystemExit(f"Missing goal file for calibration: {goal_file}")
    return [
        int(item.strip())
        for item in goal_file.read_text(encoding="utf-8").split(",")
        if item.strip()
    ]


def calibrate_scale_from_files(
    scale_dir: Path,
    goal_counts: list[int],
    attack_cost_source: str,
    reward_multiplier: float,
    min_goal_reward: float,
    default_reward: float | None,
    default_loss: float | None,
) -> dict:
    vertices, arcs = parse_csv_files(scale_dir / "VERTICES.CSV", scale_dir / "ARCS.CSV")
    goals = load_scale_goals(scale_dir, goal_counts)
    return calibrate_goal_values(
        vertices=vertices,
        arcs=arcs,
        goals=goals,
        attack_cost_source=attack_cost_source,
        reward_multiplier=reward_multiplier,
        min_goal_reward=min_goal_reward,
        explicit_reward=default_reward,
        explicit_loss=default_loss,
    )


def build_row(
    scale: str,
    goal_count: int,
    returncode: int,
    wall_seconds: float,
    result_path: Path,
    log_path: Path,
    calibration: dict,
) -> dict:
    result = load_result(result_path)
    closure = result.get("target_closure", {}) or {}
    timings = result.get("timings_seconds", {}) or {}
    return {
        "scale": scale,
        "goal_count": goal_count,
        "returncode": returncode,
        "wall_seconds": round(wall_seconds, 6),
        "status": result.get("status"),
        "solver": result.get("solver"),
        "attack_cost_source": result.get("attack_cost_source", calibration.get("attack_cost_source")),
        "default_reward": calibration.get("reward"),
        "default_loss": calibration.get("loss"),
        "reward_source": calibration.get("reward_source"),
        "loss_source": calibration.get("loss_source"),
        "goal_min_attack_cost_min": calibration.get("goal_min_attack_cost_min"),
        "goal_min_attack_cost_max": calibration.get("goal_min_attack_cost_max"),
        "goal_min_attack_cost_avg": calibration.get("goal_min_attack_cost_avg"),
        "cost_bound_formulation": result.get("cost_bound_formulation"),
        "cost_big_m": result.get("cost_big_m"),
        "legacy_global_cost_big_m": result.get("legacy_global_cost_big_m"),
        "utility_big_m": result.get("utility_big_m"),
        "utility_upper_bound": result.get("utility_upper_bound"),
        "defendable_mode": result.get("defendable_mode"),
        "target_closure_enabled": closure.get("enabled"),
        "objective_cost_form": result.get("objective_cost_form"),
        "attacker_utility": result.get("attacker_utility"),
        "defendable_leaf_count": result.get("defendable_leaf_count"),
        "original_vertices": closure.get("original_vertices"),
        "original_arcs": closure.get("original_arcs"),
        "reduced_vertices": closure.get("reduced_vertices"),
        "reduced_arcs": closure.get("reduced_arcs"),
        "removed_vertices": closure.get("removed_vertices"),
        "removed_arcs": closure.get("removed_arcs"),
        "read_csv_seconds": timings.get("read_csv"),
        "read_config_seconds": timings.get("read_config"),
        "target_closure_seconds": timings.get("target_closure"),
        "build_parameters_seconds": timings.get("build_parameters"),
        "build_mip_seconds": timings.get("build_mip"),
        "optimize_seconds": timings.get("optimize"),
        "total_solver_wall_seconds": timings.get("total_wall"),
        "result_json": str(result_path),
        "log_file": str(log_path),
    }


def run_case(
    python_exe: str,
    solver_script: Path,
    scale_dir: Path,
    scale: str,
    goal_count: int,
    results_dir: Path,
    solver: str,
    defendable: str,
    attack_cost_source: str,
    default_reward: float,
    default_loss: float,
    calibration: dict,
    time_limit: float | None,
) -> dict:
    goal_file = scale_dir / "goal_sets" / f"goals_{goal_count}.txt"
    if not goal_file.exists():
        raise SystemExit(f"Missing goal file: {goal_file}")

    goals = goal_file.read_text(encoding="utf-8").strip()
    result_path = results_dir / f"{scale}_goals_{goal_count}.json"
    log_path = results_dir / f"{scale}_goals_{goal_count}.log"

    cmd = [
        python_exe,
        str(solver_script),
        "--vertices",
        str(scale_dir / "VERTICES.CSV"),
        "--arcs",
        str(scale_dir / "ARCS.CSV"),
        "--goals",
        goals,
        "--defendable",
        defendable,
        "--target-closure",
        "--attack-cost-source",
        attack_cost_source,
        "--default-reward",
        str(default_reward),
        "--default-loss",
        str(default_loss),
        "--solver",
        solver,
        "--out",
        str(result_path),
    ]
    if time_limit is not None:
        cmd.extend(["--time-limit", str(time_limit)])

    print(
        f"[run] {scale}, goals={goal_count}, closure=on, defendable={defendable}, "
        f"cost={attack_cost_source}, reward={default_reward:g}, loss={default_loss:g}",
        flush=True,
    )
    print("      " + " ".join(cmd[:2]) + " ...", flush=True)
    start = time.perf_counter()
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
    wall_seconds = time.perf_counter() - start
    print(f"[done] {scale}, goals={goal_count}, returncode={proc.returncode}, wall={wall_seconds:.3f}s", flush=True)

    return build_row(
        scale=scale,
        goal_count=goal_count,
        returncode=proc.returncode,
        wall_seconds=wall_seconds,
        result_path=result_path,
        log_path=log_path,
        calibration=calibration,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="csv_scale_benchmarks")
    parser.add_argument("--solver-script", default="solve_mulval__stackelberg_main.py")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--solver", choices=["scip", "gurobi"], default="scip")
    parser.add_argument(
        "--defendable",
        choices=["vul"],
        default="vul",
        help="Benchmark protocol uses vul-only defense.",
    )
    parser.add_argument("--scales", default=None, help="Comma-separated subset, e.g. scale_1k,scale_10k")
    parser.add_argument("--goal-counts", default=None, help="Comma-separated override, e.g. 1,50,100,200")
    parser.add_argument("--seed", type=int, default=7, help="Seed passed to synthetic graph generation.")
    parser.add_argument(
        "--attack-cost-source",
        choices=["constant", "score"],
        default=DEFAULT_ATTACK_COST_SOURCE,
        help="Benchmark attack-cost source. Defaults to score so generated random costs enter the solver.",
    )
    parser.add_argument(
        "--default-reward",
        type=float,
        default=None,
        help="Override the calibrated goal reward. By default it is calibrated from no-defense goal costs.",
    )
    parser.add_argument(
        "--default-loss",
        type=float,
        default=None,
        help="Override the calibrated goal loss. By default it equals the calibrated reward.",
    )
    parser.add_argument(
        "--reward-multiplier",
        type=float,
        default=DEFAULT_REWARD_MULTIPLIER,
        help="Auto reward is at least this multiplier times the largest no-defense goal cost.",
    )
    parser.add_argument(
        "--min-goal-reward",
        type=float,
        default=DEFAULT_MIN_GOAL_REWARD,
        help="Minimum auto-calibrated reward/loss value.",
    )
    parser.add_argument(
        "--skip-prepare",
        action="store_true",
        help="Use existing benchmark CSV/goal_sets instead of regenerating them first.",
    )
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="Regenerate benchmark CSV/goal_sets and exit without running solvers.",
    )
    parser.add_argument(
        "--time-limit",
        type=float,
        default=None,
        help="Optional solver time limit. Omit this argument for unlimited runs.",
    )
    args = parser.parse_args()

    repo = Path(__file__).resolve().parent
    root = Path(args.root)
    if not root.is_absolute():
        root = repo / root
    solver_script = Path(args.solver_script)
    if not solver_script.is_absolute():
        solver_script = repo / solver_script

    allowed_scales = list(DEFAULT_GOAL_COUNTS)
    scales = parse_csv_list(args.scales, allowed_scales)
    goal_counts_by_scale = parse_goal_counts(args.goal_counts, DEFAULT_GOAL_COUNTS)

    if not args.skip_prepare:
        prepare_inputs(
            root=root,
            scales=scales,
            goal_counts_by_scale=goal_counts_by_scale,
            seed=args.seed,
            attack_cost_source=args.attack_cost_source,
            reward_multiplier=args.reward_multiplier,
            min_goal_reward=args.min_goal_reward,
            default_reward=args.default_reward,
            default_loss=args.default_loss,
        )
    if args.prepare_only:
        return

    results_dir = root / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    summary_path = results_dir / "benchmark_runtime_summary.csv"

    rows = []
    for scale in scales:
        scale_dir = root / scale
        calibration = calibrate_scale_from_files(
            scale_dir=scale_dir,
            goal_counts=goal_counts_by_scale[scale],
            attack_cost_source=args.attack_cost_source,
            reward_multiplier=args.reward_multiplier,
            min_goal_reward=args.min_goal_reward,
            default_reward=args.default_reward,
            default_loss=args.default_loss,
        )
        for goal_count in goal_counts_by_scale[scale]:
            row = run_case(
                python_exe=args.python,
                solver_script=solver_script,
                scale_dir=scale_dir,
                scale=scale,
                goal_count=goal_count,
                results_dir=results_dir,
                solver=args.solver,
                defendable=args.defendable,
                attack_cost_source=args.attack_cost_source,
                default_reward=calibration["reward"],
                default_loss=calibration["loss"],
                calibration=calibration,
                time_limit=args.time_limit,
            )
            rows.append(row)
            append_summary(summary_path, rows)

    print(f"summary: {summary_path}")


if __name__ == "__main__":
    main()
