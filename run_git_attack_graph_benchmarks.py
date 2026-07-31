# -*- coding: utf-8 -*-
"""Benchmark the solver on the real CSV graphs under git_atack_graph/.

CSV arcs are stored as conclusion -> prerequisite.  In the visual/paper
direction they are reversed, prerequisite -> conclusion.  A legal target must
therefore be an OR node that never appears in the CSV target column: it has no
successor in the visual direction.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from mulval_cost_calibration import calibrate_goal_values, parse_csv_files


DEFAULT_ATTACK_COST_SOURCE = "score"
DEFAULT_REWARD_MULTIPLIER = 2.0
DEFAULT_MIN_GOAL_REWARD = 1_000.0
DEFAULT_MIP_GAP = 0.0


def dataset_sort_key(name: str):
    match = re.fullmatch(r"S(\d+)", name)
    return (int(match.group(1)), name) if match else (sys.maxsize, name)


def discover_datasets(data_root: Path) -> dict[str, tuple[Path, Path]]:
    datasets = {}
    for vertices_path in data_root.glob("*_vertices.csv"):
        name = vertices_path.name.removesuffix("_vertices.csv")
        arcs_path = data_root / f"{name}_arc.csv"
        if arcs_path.exists():
            datasets[name] = (vertices_path, arcs_path)
    if not datasets:
        raise SystemExit(f"No *_vertices.csv / *_arc.csv pairs found under {data_root}")
    return dict(sorted(datasets.items(), key=lambda item: dataset_sort_key(item[0])))


def parse_dataset_list(raw: str | None, available: dict) -> list[str]:
    if not raw:
        return list(available)
    names = [part.strip() for part in raw.split(",") if part.strip()]
    unknown = [name for name in names if name not in available]
    if unknown:
        raise SystemExit(f"Unknown dataset(s): {unknown}. Available: {list(available)}")
    return names


def validate_csv_format(vertices_path: Path, arcs_path: Path):
    with vertices_path.open(newline="", encoding="utf-8-sig") as handle:
        vertex_rows = [row for row in csv.reader(handle) if row]
    with arcs_path.open(newline="", encoding="utf-8-sig") as handle:
        arc_rows = [row for row in csv.reader(handle) if row]

    bad_vertices = [row for row in vertex_rows if len(row) != 4]
    bad_arcs = [row for row in arc_rows if len(row) != 3 or row[2].strip() != "-1"]
    if bad_vertices:
        raise SystemExit(f"{vertices_path} has malformed vertex rows: {bad_vertices[:3]}")
    if bad_arcs:
        raise SystemExit(f"{arcs_path} must use source,target,-1 rows: {bad_arcs[:3]}")


def visual_terminal_or_nodes(vertices: dict, arcs: list[tuple[int, int]]) -> list[int]:
    """Return OR nodes with no successor under prerequisite -> conclusion."""
    nodes_with_visual_successors = {
        prerequisite_id
        for conclusion_id, prerequisite_id in arcs
        if conclusion_id in vertices and prerequisite_id in vertices
    }
    return sorted(
        node_id
        for node_id, node in vertices.items()
        if node["type"] == "OR" and node_id not in nodes_with_visual_successors
    )


def validate_visual_terminal_goals(
    vertices: dict,
    arcs: list[tuple[int, int]],
    goals: list[int],
):
    nodes_with_visual_successors = {prerequisite_id for _, prerequisite_id in arcs}
    invalid = []
    for goal_id in goals:
        node = vertices.get(goal_id)
        if node is None:
            invalid.append((goal_id, "missing"))
        elif node["type"] != "OR":
            invalid.append((goal_id, f"type={node['type']}"))
        elif goal_id in nodes_with_visual_successors:
            invalid.append((goal_id, "has visual-direction successor"))
    if invalid:
        raise SystemExit(f"Illegal target node(s): {invalid[:10]}")


def closure_ids(
    vertices: dict,
    arcs: list[tuple[int, int]],
    goals: list[int],
) -> set[int]:
    outgoing = defaultdict(list)
    for conclusion_id, prerequisite_id in arcs:
        if conclusion_id in vertices and prerequisite_id in vertices:
            outgoing[conclusion_id].append(prerequisite_id)

    kept = set(goals)
    stack = list(goals)
    while stack:
        for prerequisite_id in outgoing[stack.pop()]:
            if prerequisite_id not in kept:
                kept.add(prerequisite_id)
                stack.append(prerequisite_id)
    return kept


def choose_goals(
    vertices: dict,
    arcs: list[tuple[int, int]],
    policy: str,
) -> tuple[list[int], list[int]]:
    candidates = visual_terminal_or_nodes(vertices, arcs)
    if not candidates:
        raise SystemExit("No visual-direction terminal OR target candidates found")
    if policy == "all-terminal":
        goals = candidates
    elif policy == "max-closure":
        goals = [
            max(
                candidates,
                key=lambda goal_id: (len(closure_ids(vertices, arcs, [goal_id])), -goal_id),
            )
        ]
    else:
        raise SystemExit(f"Unknown goal policy: {policy}")
    validate_visual_terminal_goals(vertices, arcs, goals)
    return candidates, goals


def is_real_vulnerability(label: str) -> bool:
    return label.startswith(("vulExists", "ttpExists"))


def prepare_dataset(
    output_root: Path,
    dataset: str,
    vertices_path: Path,
    arcs_path: Path,
    goal_policy: str,
    attack_cost_source: str,
    reward_multiplier: float,
    min_goal_reward: float,
    default_reward: float | None,
    default_loss: float | None,
) -> Path:
    validate_csv_format(vertices_path, arcs_path)
    vertices, arcs = parse_csv_files(vertices_path, arcs_path)
    vertex_ids = set(vertices)
    missing_endpoints = [
        (source, target)
        for source, target in arcs
        if source not in vertex_ids or target not in vertex_ids
    ]
    if missing_endpoints:
        raise SystemExit(f"{dataset} has missing arc endpoints: {missing_endpoints[:10]}")

    candidates, goals = choose_goals(vertices, arcs, goal_policy)
    closure = closure_ids(vertices, arcs, goals)
    closure_arcs = [
        (source, target)
        for source, target in arcs
        if source in closure and target in closure
    ]
    if goal_policy == "all-terminal" and closure != vertex_ids:
        raise SystemExit(
            f"{dataset}: all terminal OR goals leave {len(vertex_ids - closure)} nodes outside closure"
        )

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
    defendable = sorted(
        node_id
        for node_id, node in vertices.items()
        if node["type"] == "LEAF" and is_real_vulnerability(node["label"])
    )
    if not defendable:
        raise SystemExit(f"{dataset}: no vulExists/ttpExists defendable facts found")

    case_dir = output_root / "prepared" / dataset
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "goals.txt").write_text(",".join(map(str, goals)), encoding="utf-8")
    summary = {
        "dataset": dataset,
        "input": {
            "vertices": str(vertices_path.resolve()),
            "arcs": str(arcs_path.resolve()),
        },
        "goal_policy": goal_policy,
        "candidate_goal_count": len(candidates),
        "candidate_goals": [
            {"id": goal_id, "label": vertices[goal_id]["label"]}
            for goal_id in candidates
        ],
        "selected_goal_count": len(goals),
        "selected_goals": [
            {"id": goal_id, "label": vertices[goal_id]["label"]}
            for goal_id in goals
        ],
        "target_rule": {
            "visual_direction": "prerequisite -> conclusion",
            "csv_direction": "conclusion -> prerequisite",
            "requirement": "selected OR target has no successor in visual direction",
            "equivalent_csv_check": "selected target id never appears in ARCS.CSV column 2",
            "all_selected_targets_valid": True,
        },
        "graph": {
            "original_vertices": len(vertices),
            "original_arcs": len(arcs),
            "type_counts": dict(Counter(node["type"] for node in vertices.values())),
            "defendable_vulnerability_count": len(defendable),
            "closure_vertices": len(closure),
            "closure_arcs": len(closure_arcs),
            "removed_vertices": len(vertices) - len(closure),
            "removed_arcs": len(arcs) - len(closure_arcs),
            "closure_covers_full_graph": closure == vertex_ids,
        },
        "benchmark_protocol": {
            "target_closure": True,
            "defendable": "vul",
            "vulnerability_labels": ["vulExists", "ttpExists"],
            "attack_cost_source": attack_cost_source,
            "default_reward": calibration["reward"],
            "default_loss": calibration["loss"],
            "reward_calibration": calibration,
        },
    }
    (case_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(
        f"[prepare] {dataset}: nodes={len(vertices)}, arcs={len(arcs)}, "
        f"terminal_goals={len(candidates)}, selected={len(goals)}, "
        f"closure={len(closure)}, defendable={len(defendable)}",
        flush=True,
    )
    return case_dir


def load_case(case_dir: Path):
    summary = json.loads((case_dir / "summary.json").read_text(encoding="utf-8"))
    goals = [
        int(part)
        for part in (case_dir / "goals.txt").read_text(encoding="utf-8").split(",")
        if part.strip()
    ]
    return summary, goals


def run_case(
    python_exe: str,
    solver_script: Path,
    case_dir: Path,
    results_dir: Path,
    solver: str,
    mip_gap: float,
    time_limit: float | None,
    warm_start_key_path: bool,
) -> dict:
    summary, goals = load_case(case_dir)
    dataset = summary["dataset"]
    vertices_path = Path(summary["input"]["vertices"])
    arcs_path = Path(summary["input"]["arcs"])
    vertices, arcs = parse_csv_files(vertices_path, arcs_path)
    validate_visual_terminal_goals(vertices, arcs, goals)

    protocol = summary["benchmark_protocol"]
    result_path = results_dir / f"{dataset}.json"
    log_path = results_dir / f"{dataset}.log"
    result_path.unlink(missing_ok=True)
    cmd = [
        python_exe,
        str(solver_script),
        "--vertices", str(vertices_path),
        "--arcs", str(arcs_path),
        "--goals", ",".join(map(str, goals)),
        "--defendable", "vul",
        "--target-closure",
        "--attack-cost-source", protocol["attack_cost_source"],
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
        f"[run] {dataset}: original_nodes={summary['graph']['original_vertices']}, "
        f"closure_nodes={summary['graph']['closure_vertices']}, goals={len(goals)}, "
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
    closure = result.get("target_closure", {}) or {}
    warm = result.get("warm_start", {}) or {}
    timings = result.get("timings_seconds", {}) or {}
    row = {
        "dataset": dataset,
        "goal_policy": summary["goal_policy"],
        "goal_count": len(goals),
        "targets_visual_terminal": True,
        "original_vertices": summary["graph"]["original_vertices"],
        "original_arcs": summary["graph"]["original_arcs"],
        "expected_closure_vertices": summary["graph"]["closure_vertices"],
        "expected_closure_arcs": summary["graph"]["closure_arcs"],
        "reduced_vertices": closure.get("reduced_vertices"),
        "reduced_arcs": closure.get("reduced_arcs"),
        "removed_vertices": closure.get("removed_vertices"),
        "removed_arcs": closure.get("removed_arcs"),
        "defendable_vulnerability_count": summary["graph"]["defendable_vulnerability_count"],
        "returncode": proc.returncode,
        "status": result.get("status"),
        "solver": result.get("solver"),
        "mip_gap_limit": result.get("mip_gap_limit"),
        "relative_gap": result.get("relative_gap"),
        "wall_seconds": round(wall_seconds, 6),
        "warm_start_submitted": warm.get("submitted"),
        "warm_start_accepted": warm.get("accepted"),
        "warm_start_defense_count": warm.get("defense_count"),
        "selected_defense_count": len(result.get("selected_defenses", [])),
        "read_csv_seconds": timings.get("read_csv"),
        "target_closure_seconds": timings.get("target_closure"),
        "build_mip_seconds": timings.get("build_mip"),
        "warm_start_seconds": timings.get("key_path_warm_start"),
        "optimize_seconds": timings.get("optimize"),
        "total_solver_wall_seconds": timings.get("total_wall"),
        "result_json": str(result_path),
        "log_file": str(log_path),
    }
    print(
        f"[done] {dataset}: returncode={proc.returncode}, status={row['status']}, "
        f"wall={wall_seconds:.3f}s, closure={row['reduced_vertices']}, "
        f"defenses={row['selected_defense_count']}, gap={row['relative_gap']}",
        flush=True,
    )
    return row


def write_runtime_summary(path: Path, rows: list[dict]):
    fields = [
        "dataset", "goal_policy", "goal_count", "targets_visual_terminal",
        "original_vertices", "original_arcs", "expected_closure_vertices",
        "expected_closure_arcs", "reduced_vertices", "reduced_arcs",
        "removed_vertices", "removed_arcs", "defendable_vulnerability_count",
        "returncode", "status", "solver", "mip_gap_limit", "relative_gap",
        "wall_seconds", "warm_start_submitted", "warm_start_accepted",
        "warm_start_defense_count", "selected_defense_count", "read_csv_seconds",
        "target_closure_seconds", "build_mip_seconds", "warm_start_seconds",
        "optimize_seconds", "total_solver_wall_seconds", "result_json", "log_file",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in fields} for row in rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", default="git_atack_graph")
    parser.add_argument("--output-root", default="git_attack_graph_benchmarks")
    parser.add_argument("--datasets", default=None, help="Comma-separated subset, e.g. S1,S3,S300")
    parser.add_argument(
        "--goal-policy",
        choices=["all-terminal", "max-closure"],
        default="all-terminal",
        help=(
            "all-terminal selects every visual-direction terminal OR and preserves the full "
            "real graph; max-closure selects one legal terminal with the largest closure."
        ),
    )
    parser.add_argument("--solver-script", default="solve_mulval__stackelberg_main.py")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--solver", choices=["scip", "gurobi"], default="scip")
    parser.add_argument("--attack-cost-source", choices=["constant", "score"], default=DEFAULT_ATTACK_COST_SOURCE)
    parser.add_argument("--default-reward", type=float, default=None)
    parser.add_argument("--default-loss", type=float, default=None)
    parser.add_argument("--reward-multiplier", type=float, default=DEFAULT_REWARD_MULTIPLIER)
    parser.add_argument("--min-goal-reward", type=float, default=DEFAULT_MIN_GOAL_REWARD)
    parser.add_argument("--mip-gap", type=float, default=DEFAULT_MIP_GAP)
    parser.add_argument("--time-limit", type=float, default=None)
    parser.add_argument("--warm-start-key-path", action="store_true")
    parser.add_argument("--skip-prepare", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    if args.mip_gap < 0:
        raise SystemExit("--mip-gap must be non-negative")

    repo = Path(__file__).resolve().parent
    data_root = Path(args.data_root)
    if not data_root.is_absolute():
        data_root = repo / data_root
    output_root = Path(args.output_root)
    if not output_root.is_absolute():
        output_root = repo / output_root
    solver_script = Path(args.solver_script)
    if not solver_script.is_absolute():
        solver_script = repo / solver_script

    available = discover_datasets(data_root)
    datasets = parse_dataset_list(args.datasets, available)
    case_dirs = {}
    if not args.skip_prepare:
        for dataset in datasets:
            vertices_path, arcs_path = available[dataset]
            case_dirs[dataset] = prepare_dataset(
                output_root=output_root,
                dataset=dataset,
                vertices_path=vertices_path,
                arcs_path=arcs_path,
                goal_policy=args.goal_policy,
                attack_cost_source=args.attack_cost_source,
                reward_multiplier=args.reward_multiplier,
                min_goal_reward=args.min_goal_reward,
                default_reward=args.default_reward,
                default_loss=args.default_loss,
            )
    else:
        case_dirs = {
            dataset: output_root / "prepared" / dataset
            for dataset in datasets
        }

    if args.prepare_only:
        return

    results_dir = output_root / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for dataset in datasets:
        rows.append(
            run_case(
                python_exe=args.python,
                solver_script=solver_script,
                case_dir=case_dirs[dataset],
                results_dir=results_dir,
                solver=args.solver,
                mip_gap=args.mip_gap,
                time_limit=args.time_limit,
                warm_start_key_path=args.warm_start_key_path,
            )
        )
        write_runtime_summary(results_dir / "benchmark_runtime_summary.csv", rows)
    print(f"summary: {results_dir / 'benchmark_runtime_summary.csv'}")


if __name__ == "__main__":
    main()
