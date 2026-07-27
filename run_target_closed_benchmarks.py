# -*- coding: utf-8 -*-
"""Prepare and run independent target-closed MulVAL scale benchmarks.

Unlike run_goal_count_benchmarks.py, every scale/goal-count case gets its own
graph.  The graph contains exactly the requested final goals and every output
node is an ancestor of at least one of those goals in the visual
prerequisite -> conclusion direction.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

from generate_large_mulval_csv import build_graph, write_csv
from mulval_cost_calibration import calibrate_goal_values


DEFAULT_GOAL_COUNTS = [1, 50, 100, 200]
TARGET_NODE_COUNTS = {
    "scale_1k": 1_000,
    "scale_10k": 10_000,
    "scale_100k": 100_000,
}
# base_hosts/base_nodes are the current 200-goal reference points.  The
# preparation routine refines the host count from the graph it actually builds.
SCALE_CONFIGS = {
    "scale_1k": {
        "base_hosts": 38,
        "base_nodes": 1_001,
        "services_per_host": 2,
        "vuln_per_service": 1,
        "lateral_rules_per_host": 1,
    },
    "scale_10k": {
        "base_hosts": 700,
        "base_nodes": 9_590,
        "services_per_host": 2,
        "vuln_per_service": 2,
        "lateral_rules_per_host": 1,
    },
    "scale_100k": {
        "base_hosts": 8_000,
        "base_nodes": 100_413,
        "services_per_host": 2,
        "vuln_per_service": 2,
        "lateral_rules_per_host": 1,
    },
}
DEFAULT_ATTACK_COST_SOURCE = "score"
DEFAULT_REWARD_MULTIPLIER = 2.0
DEFAULT_MIN_GOAL_REWARD = 1_000.0
DEFAULT_MIP_GAP = 0.0


def parse_csv_list(raw: str | None, allowed: list[str]) -> list[str]:
    if not raw:
        return allowed
    values = [value.strip() for value in raw.split(",") if value.strip()]
    unknown = [value for value in values if value not in allowed]
    if unknown:
        raise SystemExit(f"Unknown value(s): {unknown}. Allowed: {allowed}")
    return values


def parse_goal_counts(raw: str | None) -> list[int]:
    if not raw:
        return list(DEFAULT_GOAL_COUNTS)
    counts = [int(value.strip()) for value in raw.split(",") if value.strip()]
    if not counts or any(count < 1 for count in counts):
        raise SystemExit("--goal-counts must contain one or more positive integers")
    if len(set(counts)) != len(counts):
        raise SystemExit("--goal-counts must not contain duplicates")
    return counts


def goal_closure_ids(vertices, arcs, goals: list[int]) -> set[int]:
    vertex_ids = {node_id for node_id, _, _, _ in vertices}
    missing_goals = [goal_id for goal_id in goals if goal_id not in vertex_ids]
    if missing_goals:
        raise SystemExit(f"Unknown goal id(s): {missing_goals}")

    outgoing = defaultdict(list)
    for source, target in arcs:
        if source in vertex_ids and target in vertex_ids:
            outgoing[source].append(target)

    kept = set(goals)
    stack = list(goals)
    while stack:
        node_id = stack.pop()
        for prerequisite_id in outgoing[node_id]:
            if prerequisite_id not in kept:
                kept.add(prerequisite_id)
                stack.append(prerequisite_id)
    return kept


def validate_case_graph(vertices, arcs, goals: list[int]) -> dict:
    vertices_by_id = {node_id: (label, node_type) for node_id, label, node_type, _ in vertices}
    outgoing = defaultdict(list)
    for source, target in arcs:
        outgoing[source].append(target)

    closure = goal_closure_ids(vertices, arcs, goals)
    all_ids = set(vertices_by_id)
    if closure != all_ids:
        raise SystemExit(
            f"Target-closed graph has {len(all_ids - closure)} node(s) outside final-goal closure"
        )

    for goal_id in goals:
        goal_label, goal_type = vertices_by_id[goal_id]
        if goal_type != "OR" or len(outgoing[goal_id]) != 1:
            raise SystemExit(f"Goal {goal_id} is not a single-rule OR target")
        target_host = goal_label.split("crown_jewel_", 1)[1].split(",root", 1)[0]
        rule_id = outgoing[goal_id][0]
        or_prerequisites = [
            vertices_by_id[node_id][0]
            for node_id in outgoing[rule_id]
            if vertices_by_id[node_id][1] == "OR"
        ]
        if or_prerequisites != [f"execCode({target_host},root)"]:
            raise SystemExit(f"Goal {goal_id} has a cross-host or invalid root prerequisite")

    closure_arcs = [
        (source, target)
        for source, target in arcs
        if source in closure and target in closure
    ]
    if len(closure_arcs) != len(arcs):
        raise SystemExit("Target closure unexpectedly removed one or more arcs")
    return {
        "closure_vertices": len(closure),
        "closure_arcs": len(closure_arcs),
        "removed_vertices": len(vertices) - len(closure),
        "removed_arcs": len(arcs) - len(closure_arcs),
    }


def build_case_graph(scale: str, goal_count: int, seed: int):
    config = SCALE_CONFIGS[scale]
    target_nodes = TARGET_NODE_COUNTS[scale]
    goal_wrapper_nodes = 3 * goal_count
    baseline_density = max(
        1.0,
        (config["base_nodes"] - 3 * 200) / config["base_hosts"],
    )
    hosts = max(
        1,
        round((target_nodes - goal_wrapper_nodes) / baseline_density),
    )
    best = None
    visited = set()

    for _ in range(6):
        if hosts in visited:
            break
        visited.add(hosts)
        vertices, arcs, goals, structure = build_graph(
            hosts=hosts,
            services_per_host=config["services_per_host"],
            vuln_per_service=config["vuln_per_service"],
            lateral_rules_per_host=config["lateral_rules_per_host"],
            goals=goal_count,
            seed=seed,
            target_closed=True,
        )
        candidate = (vertices, arcs, goals, structure, hosts)
        if best is None or abs(len(vertices) - target_nodes) < abs(len(best[0]) - target_nodes):
            best = candidate
        if len(vertices) == target_nodes:
            break

        density = max(1.0, (len(vertices) - goal_wrapper_nodes) / hosts)
        next_hosts = max(1, round((target_nodes - goal_wrapper_nodes) / density))
        if next_hosts == hosts:
            next_hosts += 1 if len(vertices) < target_nodes else -1
        hosts = max(1, next_hosts)

    vertices, arcs, goals, structure, selected_hosts = best
    closure = validate_case_graph(vertices, arcs, goals)
    return vertices, arcs, goals, structure, {
        "target_nodes": target_nodes,
        "actual_nodes": len(vertices),
        "actual_arcs": len(arcs),
        "host_count": selected_hosts,
        "node_delta": len(vertices) - target_nodes,
        "closure": closure,
    }


def prepare_case(
    root: Path,
    scale: str,
    goal_count: int,
    seed: int,
    attack_cost_source: str,
    reward_multiplier: float,
    min_goal_reward: float,
    default_reward: float | None,
    default_loss: float | None,
) -> Path:
    vertices, arcs, goals, structure, scale_info = build_case_graph(scale, goal_count, seed)
    case_dir = root / scale / f"goals_{goal_count}"
    case_dir.mkdir(parents=True, exist_ok=True)
    write_csv(vertices, arcs, case_dir / "VERTICES.CSV", case_dir / "ARCS.CSV")
    (case_dir / "goals.txt").write_text(",".join(map(str, goals)), encoding="utf-8")

    calibration = calibrate_goal_values(
        vertices=vertices,
        arcs=arcs,
        goals=goals,
        attack_cost_source=attack_cost_source,
        reward_multiplier=reward_multiplier,
        min_goal_reward=min_goal_reward,
        explicit_reward=default_reward,
        explicit_loss=default_loss,
    )
    summary = {
        "scale": scale,
        "goal_count": goal_count,
        "goals": goals,
        "parameters": {
            **SCALE_CONFIGS[scale],
            "seed": seed,
            "target_closed": True,
        },
        "scale_reference": scale_info,
        "structure": structure,
        "diagnostics": structure["diagnostics"],
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
            "ARCS.CSV": "source,target,-1",
            "edge_direction": "conclusion -> prerequisite",
        },
    }
    (case_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(
        f"[prepare] {scale}, goals={goal_count}: "
        f"target={scale_info['target_nodes']}, actual={scale_info['actual_nodes']}, "
        f"arcs={scale_info['actual_arcs']}, hosts={scale_info['host_count']}, "
        f"delta={scale_info['node_delta']:+d}",
        flush=True,
    )
    return case_dir


def load_case(case_dir: Path):
    summary = json.loads((case_dir / "summary.json").read_text(encoding="utf-8"))
    goals = [
        int(item)
        for item in (case_dir / "goals.txt").read_text(encoding="utf-8").split(",")
        if item.strip()
    ]
    return summary, goals


def run_case(
    python_exe: str,
    solver_script: Path,
    case_dir: Path,
    scale: str,
    goal_count: int,
    results_dir: Path,
    solver: str,
    defendable: str,
    attack_cost_source: str,
    mip_gap: float,
    time_limit: float | None,
    warm_start_key_path: bool,
) -> dict:
    summary, goals = load_case(case_dir)
    protocol = summary["benchmark_protocol"]
    calibration = protocol["reward_calibration"]
    case_name = f"{scale}_goals_{goal_count}"
    result_path = results_dir / f"{case_name}.json"
    log_path = results_dir / f"{case_name}.log"
    result_path.unlink(missing_ok=True)

    cmd = [
        python_exe,
        str(solver_script),
        "--vertices", str(case_dir / "VERTICES.CSV"),
        "--arcs", str(case_dir / "ARCS.CSV"),
        "--goals", ",".join(map(str, goals)),
        "--defendable", defendable,
        "--target-closure",
        "--attack-cost-source", attack_cost_source,
        "--default-reward", str(protocol["default_reward"]),
        "--default-loss", str(protocol["default_loss"]),
        "--solver", solver,
        "--mip-gap", str(mip_gap),
        "--out", str(result_path),
    ]
    if time_limit is not None:
        cmd.extend(["--time-limit", str(time_limit)])
    if warm_start_key_path:
        cmd.append("--warm-start-key-path")

    print(
        f"[run] {case_name}: nodes={summary['scale_reference']['actual_nodes']}, "
        f"goals={goal_count}, reward={protocol['default_reward']:g}, "
        f"warm_start={'key_path' if warm_start_key_path else 'off'}",
        flush=True,
    )
    start = time.perf_counter()
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
    wall_seconds = time.perf_counter() - start

    result = {}
    if result_path.exists():
        result = json.loads(result_path.read_text(encoding="utf-8"))
    closure = result.get("target_closure", {})
    warm_start = result.get("warm_start", {})
    timings = result.get("timings_seconds", {})
    row = {
        "scale": scale,
        "goal_count": goal_count,
        "target_nodes": summary["scale_reference"]["target_nodes"],
        "actual_nodes": summary["scale_reference"]["actual_nodes"],
        "actual_arcs": summary["scale_reference"]["actual_arcs"],
        "node_delta": summary["scale_reference"]["node_delta"],
        "closure_original_vertices": closure.get("original_vertices"),
        "closure_reduced_vertices": closure.get("reduced_vertices"),
        "closure_original_arcs": closure.get("original_arcs"),
        "closure_reduced_arcs": closure.get("reduced_arcs"),
        "closure_removed_vertices": closure.get("removed_vertices"),
        "closure_removed_arcs": closure.get("removed_arcs"),
        "warm_start_enabled": warm_start.get("enabled"),
        "warm_start_submitted": warm_start.get("submitted"),
        "warm_start_accepted": warm_start.get("accepted"),
        "warm_start_defense_count": warm_start.get("defense_count"),
        "warm_start_objective": warm_start.get("heuristic_objective"),
        "warm_start_seconds": timings.get("key_path_warm_start"),
        "returncode": proc.returncode,
        "status": result.get("status"),
        "wall_seconds": round(wall_seconds, 6),
        "solver": result.get("solver"),
        "relative_gap": result.get("relative_gap"),
        "default_reward": protocol["default_reward"],
        "default_loss": protocol["default_loss"],
        "goal_min_attack_cost_min": calibration["goal_min_attack_cost_min"],
        "goal_min_attack_cost_max": calibration["goal_min_attack_cost_max"],
        "goal_min_attack_cost_avg": calibration["goal_min_attack_cost_avg"],
        "read_csv_seconds": timings.get("read_csv"),
        "target_closure_seconds": timings.get("target_closure"),
        "build_mip_seconds": timings.get("build_mip"),
        "optimize_seconds": timings.get("optimize"),
        "total_solver_wall_seconds": timings.get("total_wall"),
        "result_json": str(result_path),
        "log_file": str(log_path),
    }
    print(
        f"[done] {case_name}: returncode={proc.returncode}, wall={wall_seconds:.3f}s; "
        f"closure nodes {row['closure_original_vertices']} -> {row['closure_reduced_vertices']} "
        f"(removed {row['closure_removed_vertices']}), arcs "
        f"{row['closure_original_arcs']} -> {row['closure_reduced_arcs']} "
        f"(removed {row['closure_removed_arcs']}); warm start "
        f"submitted={row['warm_start_submitted']}, accepted={row['warm_start_accepted']}",
        flush=True,
    )
    return row


def write_summary(path: Path, rows: list[dict]):
    fields = [
        "scale", "goal_count", "target_nodes", "actual_nodes", "actual_arcs",
        "node_delta", "closure_original_vertices", "closure_reduced_vertices",
        "closure_original_arcs", "closure_reduced_arcs", "closure_removed_vertices",
        "closure_removed_arcs", "warm_start_enabled", "warm_start_submitted",
        "warm_start_accepted", "warm_start_defense_count", "warm_start_objective",
        "warm_start_seconds", "returncode", "status", "wall_seconds", "solver", "relative_gap",
        "default_reward", "default_loss", "goal_min_attack_cost_min",
        "goal_min_attack_cost_max", "goal_min_attack_cost_avg",
        "read_csv_seconds", "target_closure_seconds", "build_mip_seconds",
        "optimize_seconds", "total_solver_wall_seconds", "result_json", "log_file",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in fields} for row in rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="csv_target_closed_benchmarks")
    parser.add_argument("--solver-script", default="solve_mulval__stackelberg_main.py")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--solver", choices=["scip", "gurobi"], default="scip")
    parser.add_argument("--defendable", choices=["vul"], default="vul")
    parser.add_argument("--scales", default=None)
    parser.add_argument("--goal-counts", default=None)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--attack-cost-source", choices=["constant", "score"], default=DEFAULT_ATTACK_COST_SOURCE)
    parser.add_argument("--default-reward", type=float, default=None)
    parser.add_argument("--default-loss", type=float, default=None)
    parser.add_argument("--reward-multiplier", type=float, default=DEFAULT_REWARD_MULTIPLIER)
    parser.add_argument("--min-goal-reward", type=float, default=DEFAULT_MIN_GOAL_REWARD)
    parser.add_argument("--skip-prepare", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--mip-gap", type=float, default=DEFAULT_MIP_GAP)
    parser.add_argument(
        "--warm-start-key-path",
        action="store_true",
        help="Submit a greedy key-path defender solution to the MIP solver before optimization.",
    )
    parser.add_argument("--time-limit", type=float, default=None)
    args = parser.parse_args()
    if args.mip_gap < 0:
        raise SystemExit("--mip-gap must be non-negative")

    repo = Path(__file__).resolve().parent
    root = Path(args.root)
    if not root.is_absolute():
        root = repo / root
    solver_script = Path(args.solver_script)
    if not solver_script.is_absolute():
        solver_script = repo / solver_script

    scales = parse_csv_list(args.scales, list(TARGET_NODE_COUNTS))
    goal_counts = parse_goal_counts(args.goal_counts)

    case_dirs = {}
    if not args.skip_prepare:
        for scale in scales:
            for goal_count in goal_counts:
                case_dirs[(scale, goal_count)] = prepare_case(
                    root=root,
                    scale=scale,
                    goal_count=goal_count,
                    seed=args.seed,
                    attack_cost_source=args.attack_cost_source,
                    reward_multiplier=args.reward_multiplier,
                    min_goal_reward=args.min_goal_reward,
                    default_reward=args.default_reward,
                    default_loss=args.default_loss,
                )
    else:
        for scale in scales:
            for goal_count in goal_counts:
                case_dirs[(scale, goal_count)] = root / scale / f"goals_{goal_count}"

    if args.prepare_only:
        return

    results_dir = root / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for scale in scales:
        for goal_count in goal_counts:
            rows.append(
                run_case(
                    python_exe=args.python,
                    solver_script=solver_script,
                    case_dir=case_dirs[(scale, goal_count)],
                    scale=scale,
                    goal_count=goal_count,
                    results_dir=results_dir,
                    solver=args.solver,
                    defendable=args.defendable,
                    attack_cost_source=args.attack_cost_source,
                    mip_gap=args.mip_gap,
                    time_limit=args.time_limit,
                    warm_start_key_path=args.warm_start_key_path,
                )
            )
            write_summary(results_dir / "benchmark_runtime_summary.csv", rows)

    print(f"summary: {results_dir / 'benchmark_runtime_summary.csv'}")


if __name__ == "__main__":
    main()
