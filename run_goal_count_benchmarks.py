# -*- coding: utf-8 -*-
"""Run scale/goal-count timing benchmarks on Linux or Windows.

By default this script does not pass --time-limit to the solver, so each case
runs until the solver stops by itself. It writes per-case result JSON files,
solver logs, and one CSV summary table under csv_scale_benchmarks/results.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from pathlib import Path


DEFAULT_GOAL_COUNTS = {
    "scale_10k": [1, 10, 100, 300, 500],
    "scale_100k": [1, 10, 100, 300, 500],
    "scale_1m": [1, 10, 100, 300, 500],
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


def build_row(
    scale: str,
    goal_count: int,
    returncode: int,
    wall_seconds: float,
    result_path: Path,
    log_path: Path,
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
    use_target_closure: bool,
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
        "--solver",
        solver,
        "--out",
        str(result_path),
    ]
    if use_target_closure:
        cmd.append("--target-closure")
    if time_limit is not None:
        cmd.extend(["--time-limit", str(time_limit)])

    print(f"[run] {scale}, goals={goal_count}", flush=True)
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
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="csv_scale_benchmarks")
    parser.add_argument("--solver-script", default="solve_mulval__stackelberg_main.py")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--solver", choices=["scip", "gurobi"], default="scip")
    parser.add_argument("--defendable", choices=["all", "vul", "hacl", "vul_hacl"], default="vul")
    parser.add_argument("--scales", default=None, help="Comma-separated subset, e.g. scale_10k,scale_100k")
    parser.add_argument("--goal-counts", default=None, help="Comma-separated override, e.g. 1,10,100")
    parser.add_argument("--no-target-closure", action="store_true")
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

    results_dir = root / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    summary_path = results_dir / "benchmark_runtime_summary.csv"

    rows = []
    for scale in scales:
        scale_dir = root / scale
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
                use_target_closure=not args.no_target_closure,
                time_limit=args.time_limit,
            )
            rows.append(row)
            append_summary(summary_path, rows)

    print(f"summary: {summary_path}")


if __name__ == "__main__":
    main()
