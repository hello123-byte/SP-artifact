#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Repeated end-to-end runtime comparison on S1--S1000."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import subprocess
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMPARISON_SCRIPT = (
    REPOSITORY_ROOT
    / "benchmark_methods"
    / "git_attack_graph_baseline_comparison"
    / "run_benchmarks.py"
)
METHODS = ("empty", "random", "path_enum", "stackelberg")
DISPLAY_NAMES = {
    "empty": "Empty",
    "random": "Random",
    "path_enum": "Path enumeration",
    "stackelberg": "Our",
}

RUN_FIELDS = [
    "repetition", "dataset", "method", "display_name", "status", "timed_out",
    "time_limit_seconds", "wall_seconds", "algorithm_seconds", "node_count",
    "arc_count", "goal_count", "budget", "result_json", "source_summary",
]
SUMMARY_FIELDS = [
    "dataset", "method", "display_name", "status", "repetitions",
    "completed_count", "timeout_count", "failure_count", "time_limit_seconds",
    "wall_mean_seconds", "wall_std_seconds", "wall_median_seconds",
    "wall_min_seconds", "wall_max_seconds", "algorithm_mean_seconds",
    "algorithm_std_seconds", "algorithm_median_seconds", "node_count",
    "arc_count", "goal_count", "budget",
]


def parse_csv_list(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def finite_float(value) -> float | None:
    if value in (None, ""):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def algorithm_seconds(result_path: str, timed_out: bool, time_limit: float) -> float | None:
    if timed_out:
        return time_limit
    path = Path(result_path)
    if not path.exists():
        return None
    result = json.loads(path.read_text(encoding="utf-8"))
    timings = result.get("timings_seconds") or {}
    return finite_float(timings.get("total_wall"))


def summarize_group(rows: list[dict]) -> dict:
    completed = [row for row in rows if row["status"] not in {"timeout", "failed"}]
    timeouts = [row for row in rows if row["status"] == "timeout"]
    failures = [row for row in rows if row["status"] == "failed"]
    wall_values = [float(row["wall_seconds"]) for row in completed]
    algorithm_values = [
        float(row["algorithm_seconds"])
        for row in completed
        if row.get("algorithm_seconds") not in (None, "")
    ]
    if timeouts and completed:
        status = "partial_timeout"
    elif timeouts:
        status = "timeout"
    elif failures and not completed:
        status = "failed"
    elif failures:
        status = "partial_failure"
    else:
        status = "completed"

    first = rows[0]
    return {
        "dataset": first["dataset"],
        "method": first["method"],
        "display_name": first["display_name"],
        "status": status,
        "repetitions": len(rows),
        "completed_count": len(completed),
        "timeout_count": len(timeouts),
        "failure_count": len(failures),
        "time_limit_seconds": first["time_limit_seconds"],
        "wall_mean_seconds": statistics.fmean(wall_values) if wall_values else None,
        "wall_std_seconds": statistics.pstdev(wall_values) if len(wall_values) > 1 else (0.0 if wall_values else None),
        "wall_median_seconds": statistics.median(wall_values) if wall_values else None,
        "wall_min_seconds": min(wall_values) if wall_values else None,
        "wall_max_seconds": max(wall_values) if wall_values else None,
        "algorithm_mean_seconds": statistics.fmean(algorithm_values) if algorithm_values else None,
        "algorithm_std_seconds": statistics.pstdev(algorithm_values) if len(algorithm_values) > 1 else (0.0 if algorithm_values else None),
        "algorithm_median_seconds": statistics.median(algorithm_values) if algorithm_values else None,
        "node_count": first["node_count"],
        "arc_count": first["arc_count"],
        "goal_count": first["goal_count"],
        "budget": first["budget"],
    }


def summarize_runs(rows: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        groups.setdefault((row["dataset"], row["method"]), []).append(row)
    dataset_order = {name: index for index, name in enumerate(parse_csv_list("S1,S2,S3,S300,S500,S1000"))}
    method_order = {name: index for index, name in enumerate(METHODS)}
    keys = sorted(groups, key=lambda key: (dataset_order.get(key[0], 999), method_order.get(key[1], 999)))
    return [summarize_group(groups[key]) for key in keys]


def write_csv(path: Path, rows: list[dict], fieldnames: list[str], encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding=encoding) as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in fieldnames} for row in rows)


def runtime_cell(row: dict | None) -> str:
    if not row:
        return ""
    if row["status"] == "timeout":
        return "timeout"
    median = finite_float(row.get("wall_median_seconds"))
    if median is None:
        return row["status"]
    value = f"{median:.6f}"
    if row["status"] == "partial_timeout":
        value += f" ({row['timeout_count']}/{row['repetitions']} timeout)"
    return value


def write_wide_table(path: Path, rows: list[dict]) -> None:
    datasets = []
    for row in rows:
        if row["dataset"] not in datasets:
            datasets.append(row["dataset"])
    lookup = {(row["dataset"], row["method"]): row for row in rows}
    fields = ["数据集", "节点数", "Empty(s)", "Random(s)", "Path enumeration(s)", "Our(s)"]
    output = []
    for dataset in datasets:
        sample = next(row for row in rows if row["dataset"] == dataset)
        output.append({
            "数据集": dataset,
            "节点数": sample["node_count"],
            "Empty(s)": runtime_cell(lookup.get((dataset, "empty"))),
            "Random(s)": runtime_cell(lookup.get((dataset, "random"))),
            "Path enumeration(s)": runtime_cell(lookup.get((dataset, "path_enum"))),
            "Our(s)": runtime_cell(lookup.get((dataset, "stackelberg"))),
        })
    write_csv(path, output, fields, encoding="utf-8-sig")


def write_chart(path: Path, rows: list[dict], dpi: int) -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise SystemExit("matplotlib is required unless --skip-chart is used") from exc

    datasets = []
    for row in rows:
        if row["dataset"] not in datasets:
            datasets.append(row["dataset"])
    lookup = {(row["dataset"], row["method"]): row for row in rows}
    colors = {"empty": "#666666", "random": "#0072B2", "path_enum": "#009E73", "stackelberg": "#D55E00"}
    width = 0.18
    x = list(range(len(datasets)))
    fig, ax = plt.subplots(figsize=(7.2, 3.4), constrained_layout=True)
    for method_index, method in enumerate(METHODS):
        positions = [value + (method_index - 1.5) * width for value in x]
        values = []
        timeout_flags = []
        for dataset in datasets:
            row = lookup[(dataset, method)]
            timeout = row["status"] == "timeout"
            timeout_flags.append(timeout)
            value = row["time_limit_seconds"] if timeout else row["wall_median_seconds"]
            values.append(float(value))
        bars = ax.bar(positions, values, width=width * 0.86, color=colors[method], label=DISPLAY_NAMES[method])
        for bar, timeout in zip(bars, timeout_flags):
            if timeout:
                bar.set_hatch("///")
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), "T/O", ha="center", va="bottom", fontsize=6)
    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(datasets)
    ax.set_ylabel("end-to-end wall time (s)")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(frameon=False, ncol=4, loc="upper left")
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=dpi, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--datasets", default="S1,S2,S3,S300,S500,S1000")
    parser.add_argument("--methods", default="empty,random,path_enum,stackelberg")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--method-time-limit", type=float, default=30.0)
    parser.add_argument("--output-root", default="git_attack_graph_runtime_comparison")
    parser.add_argument("--data-root", default="git_atack_graph")
    parser.add_argument("--budget-ratio", type=float, default=0.4)
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
    if args.repetitions < 1:
        raise SystemExit("--repetitions must be positive")
    if args.method_time_limit <= 0:
        raise SystemExit("--method-time-limit must be positive")

    output_root = Path(args.output_root)
    if not output_root.is_absolute():
        output_root = REPOSITORY_ROOT / output_root
    all_rows: list[dict] = []
    run_log = output_root / "runtime_driver.log"
    run_log.parent.mkdir(parents=True, exist_ok=True)
    with run_log.open("w", encoding="utf-8") as log:
        for repetition in range(1, args.repetitions + 1):
            run_root = output_root / "runs" / f"run_{repetition:02d}"
            cmd = [
                args.python, str(COMPARISON_SCRIPT),
                "--datasets", args.datasets,
                "--methods", args.methods,
                "--method-time-limit", str(args.method_time_limit),
                "--output-root", str(run_root),
                "--data-root", args.data_root,
                "--budget-ratio", str(args.budget_ratio),
                "--random-trials", str(args.random_trials),
                "--seed", str(args.seed + repetition - 1),
                "--max-paths", str(args.max_paths),
                "--max-depth", str(args.max_depth),
                "--solver", args.solver,
                "--mip-gap", str(args.mip_gap),
                "--skip-chart",
            ]
            print(f"[repetition {repetition}/{args.repetitions}]", flush=True)
            proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
            if proc.returncode != 0:
                raise SystemExit(f"repetition {repetition} failed; see {run_log}")
            source_summary = run_root / "benchmark_summary.csv"
            with source_summary.open(newline="", encoding="utf-8") as handle:
                for source in csv.DictReader(handle):
                    timed_out = str(source.get("timed_out", "")).lower() == "true"
                    result_path = source.get("result_json", "")
                    all_rows.append({
                        "repetition": repetition,
                        "dataset": source["dataset"],
                        "method": source["method"],
                        "display_name": source["display_name"],
                        "status": source["status"],
                        "timed_out": timed_out,
                        "time_limit_seconds": float(source["time_limit_seconds"]),
                        "wall_seconds": float(source["wall_seconds"]),
                        "algorithm_seconds": algorithm_seconds(result_path, timed_out, args.method_time_limit),
                        "node_count": int(source["node_count"]),
                        "arc_count": int(source["arc_count"]),
                        "goal_count": int(source["goal_count"]),
                        "budget": float(source["budget"]),
                        "result_json": result_path,
                        "source_summary": str(source_summary.resolve()),
                    })
            write_csv(output_root / "runtime_runs.csv", all_rows, RUN_FIELDS)
            summary_rows = summarize_runs(all_rows)
            write_csv(output_root / "runtime_summary.csv", summary_rows, SUMMARY_FIELDS)
            write_wide_table(output_root / "runtime_table.csv", summary_rows)

    summary_rows = summarize_runs(all_rows)
    if not args.skip_chart:
        write_chart(output_root / "runtime_comparison.png", summary_rows, args.figure_dpi)
        write_chart(output_root / "runtime_comparison.pdf", summary_rows, args.figure_dpi)
    print(f"runs: {output_root / 'runtime_runs.csv'}")
    print(f"summary: {output_root / 'runtime_summary.csv'}")
    print(f"table: {output_root / 'runtime_table.csv'}")


if __name__ == "__main__":
    main()
