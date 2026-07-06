#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Plot benchmark_runtime_summary.csv as compact research-style figures."""

from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path


def to_float(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def scale_key(scale: str) -> tuple[int, str]:
    suffix = scale.split("_", 1)[-1].lower()
    if suffix.endswith("k"):
        try:
            return (int(float(suffix[:-1]) * 1000), scale)
        except ValueError:
            pass
    try:
        return (int(suffix), scale)
    except ValueError:
        return (10**12, scale)


def load_rows(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        for key in (
            "goal_count",
            "wall_seconds",
            "read_csv_seconds",
            "target_closure_seconds",
            "build_parameters_seconds",
            "build_mip_seconds",
            "optimize_seconds",
            "total_solver_wall_seconds",
            "original_vertices",
            "reduced_vertices",
            "original_arcs",
            "reduced_arcs",
            "objective_cost_form",
            "relative_gap",
        ):
            row[key] = to_float(row.get(key))
    rows.sort(key=lambda r: (scale_key(str(r.get("scale", ""))), r.get("goal_count") or -1))
    return rows


def seconds_label(value: float | None) -> str:
    if value is None:
        return ""
    if value < 1:
        return f"{value:.2f}s"
    if value < 10:
        return f"{value:.1f}s"
    return f"{value:.0f}s"


def configure_matplotlib():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "figure.dpi": 150,
            "savefig.dpi": 300,
            "font.size": 9,
            "axes.titlesize": 10,
            "axes.labelsize": 9,
            "legend.fontsize": 8,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "axes.linewidth": 0.8,
            "grid.linewidth": 0.45,
            "lines.linewidth": 1.3,
            "lines.markersize": 4.5,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )
    return plt


def grouped(rows: list[dict]) -> tuple[list[str], list[float], dict[str, list[dict]]]:
    scales = sorted({str(row["scale"]) for row in rows}, key=scale_key)
    goals = sorted({row["goal_count"] for row in rows if row.get("goal_count") is not None})
    by_scale = {scale: [row for row in rows if row["scale"] == scale] for scale in scales}
    return scales, goals, by_scale


def plot_overview(rows: list[dict], out: Path):
    plt = configure_matplotlib()
    import numpy as np

    scales, goals, by_scale = grouped(rows)
    colors = {
        scale: color
        for scale, color in zip(scales, ["#1b9e77", "#d95f02", "#7570b3", "#666666"])
    }
    markers = ["o", "s", "^", "D"]

    fig, axes = plt.subplots(2, 2, figsize=(9.2, 6.6), constrained_layout=True)
    ax_runtime, ax_closure, ax_breakdown, ax_eff = axes.flat

    for idx, scale in enumerate(scales):
        scale_rows = by_scale[scale]
        x = [row["goal_count"] for row in scale_rows]
        y = [row["wall_seconds"] for row in scale_rows]
        ax_runtime.plot(
            x,
            y,
            marker=markers[idx % len(markers)],
            color=colors[scale],
            label=scale.replace("scale_", ""),
        )
    ax_runtime.set_yscale("log")
    ax_runtime.set_xlabel("number of goals")
    ax_runtime.set_ylabel("wall time (s, log)")
    ax_runtime.set_title("(a) End-to-end runtime")
    ax_runtime.grid(True, which="both", alpha=0.35)
    ax_runtime.legend(title="graph")

    for idx, scale in enumerate(scales):
        scale_rows = by_scale[scale]
        x = [row["goal_count"] for row in scale_rows]
        reduced = [row["reduced_vertices"] for row in scale_rows]
        original = [row["original_vertices"] for row in scale_rows if row.get("original_vertices") is not None]
        ax_closure.plot(
            x,
            reduced,
            marker=markers[idx % len(markers)],
            color=colors[scale],
            label=scale.replace("scale_", ""),
        )
        if original:
            ax_closure.axhline(
                original[0],
                color=colors[scale],
                linestyle=":",
                linewidth=0.9,
                alpha=0.5,
            )
    ax_closure.set_yscale("log")
    ax_closure.set_xlabel("number of goals")
    ax_closure.set_ylabel("vertices after target closure (log)")
    ax_closure.set_title("(b) Effective graph size")
    ax_closure.grid(True, which="both", alpha=0.35)

    labels = [f"{row['scale'].replace('scale_', '')}\n{int(row['goal_count'])}" for row in rows]
    x_pos = np.arange(len(rows))
    read_csv = np.array([row.get("read_csv_seconds") or 0.0 for row in rows])
    closure = np.array([row.get("target_closure_seconds") or 0.0 for row in rows])
    build = np.array(
        [
            (row.get("build_parameters_seconds") or 0.0) + (row.get("build_mip_seconds") or 0.0)
            for row in rows
        ]
    )
    optimize = np.array([row.get("optimize_seconds") or 0.0 for row in rows])
    tiny = 1e-4
    bottom = np.full(len(rows), tiny)
    for values, label, color in (
        (read_csv, "read csv", "#8dd3c7"),
        (closure, "target closure", "#ffffb3"),
        (build, "build mip", "#bebada"),
        (optimize, "optimize", "#fb8072"),
    ):
        ax_breakdown.bar(x_pos, np.maximum(values, tiny), bottom=bottom, label=label, color=color, width=0.72)
        bottom = bottom + np.maximum(values, tiny)
    ax_breakdown.set_yscale("log")
    ax_breakdown.set_xticks(x_pos)
    ax_breakdown.set_xticklabels(labels, rotation=45, ha="right")
    ax_breakdown.set_ylabel("seconds (stacked, log)")
    ax_breakdown.set_title("(c) Runtime decomposition")
    ax_breakdown.grid(True, axis="y", which="both", alpha=0.3)
    ax_breakdown.legend(ncols=2, frameon=False, loc="upper left")

    for idx, scale in enumerate(scales):
        scale_rows = by_scale[scale]
        x = [row["goal_count"] for row in scale_rows]
        y = []
        for row in scale_rows:
            reduced_vertices = row.get("reduced_vertices") or 0.0
            optimize_seconds = row.get("optimize_seconds") or 0.0
            y.append(optimize_seconds / reduced_vertices if reduced_vertices > 0 else math.nan)
        ax_eff.plot(
            x,
            y,
            marker=markers[idx % len(markers)],
            color=colors[scale],
            label=scale.replace("scale_", ""),
        )
    ax_eff.set_yscale("log")
    ax_eff.set_xlabel("number of goals")
    ax_eff.set_ylabel("optimize time / reduced vertex (s, log)")
    ax_eff.set_title("(d) Solver effort normalized by closure size")
    ax_eff.grid(True, which="both", alpha=0.35)

    statuses = sorted({str(row.get("status", "")) for row in rows})
    gaps = [row.get("relative_gap") for row in rows if row.get("relative_gap") is not None]
    gap_text = f"relative gap range: {min(gaps):.3g}-{max(gaps):.3g}" if gaps else "relative gap: n/a"
    fig.suptitle(
        f"MulVAL Stackelberg benchmark summary ({', '.join(statuses)}; {gap_text})",
        fontsize=11,
    )
    fig.savefig(out.with_suffix(".png"))
    fig.savefig(out.with_suffix(".pdf"))
    plt.close(fig)


def plot_heatmap(rows: list[dict], out: Path):
    plt = configure_matplotlib()
    import numpy as np

    scales, goals, _ = grouped(rows)
    matrix = np.full((len(scales), len(goals)), np.nan)
    labels = [["" for _ in goals] for _ in scales]
    by_key = {(row["scale"], row["goal_count"]): row for row in rows}
    for i, scale in enumerate(scales):
        for j, goal in enumerate(goals):
            row = by_key.get((scale, goal))
            if not row:
                continue
            wall = row.get("wall_seconds")
            if wall is None:
                continue
            matrix[i, j] = math.log10(max(wall, 1e-4))
            labels[i][j] = seconds_label(wall)

    fig, ax = plt.subplots(figsize=(6.6, 2.8), constrained_layout=True)
    cmap = plt.get_cmap("viridis")
    image = ax.imshow(matrix, cmap=cmap, aspect="auto")
    ax.set_xticks(range(len(goals)))
    ax.set_xticklabels([str(int(goal)) for goal in goals])
    ax.set_yticks(range(len(scales)))
    ax.set_yticklabels([scale.replace("scale_", "") for scale in scales])
    ax.set_xlabel("number of goals")
    ax.set_ylabel("graph scale")
    ax.set_title("Wall time heatmap")
    for i in range(len(scales)):
        for j in range(len(goals)):
            value = matrix[i, j]
            if math.isnan(value):
                continue
            color = "white" if value > np.nanmedian(matrix) else "black"
            ax.text(j, i, labels[i][j], ha="center", va="center", fontsize=8, color=color)
    cbar = fig.colorbar(image, ax=ax)
    cbar.set_label("log10(wall seconds)")
    fig.savefig(out.with_suffix(".png"))
    fig.savefig(out.with_suffix(".pdf"))
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--summary",
        default="csv_scale_benchmarks/results/benchmark_runtime_summary.csv",
        help="Path to benchmark_runtime_summary.csv.",
    )
    parser.add_argument(
        "--out-prefix",
        default="csv_scale_benchmarks/results/benchmark_runtime",
        help="Output prefix. The script writes *_overview and *_heatmap PNG/PDF files.",
    )
    args = parser.parse_args()

    summary = Path(args.summary)
    out_prefix = Path(args.out_prefix)
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    rows = load_rows(summary)
    if not rows:
        raise SystemExit(f"No rows found in {summary}")

    plot_overview(rows, out_prefix.with_name(out_prefix.name + "_overview"))
    plot_heatmap(rows, out_prefix.with_name(out_prefix.name + "_heatmap"))
    print(f"Wrote {out_prefix}_overview.png/.pdf")
    print(f"Wrote {out_prefix}_heatmap.png/.pdf")


if __name__ == "__main__":
    main()
