#!/usr/bin/env python3
"""Create a publication-ready one-factor sensitivity figure for one dataset."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


FACTOR_STYLE = {
    "budget_ratio": {
        "title": "(a) Defense budget ratio",
        "xlabel": r"Budget ratio $\beta$",
        "baseline": 0.4,
        "color": "#0072B2",
    },
    "defense_cost": {
        "title": "(b) Unit defense cost",
        "xlabel": r"Unit defense cost $c_d$",
        "baseline": 1.0,
        "color": "#D55E00",
    },
    "reward": {
        "title": "(c) Attacker goal reward",
        "xlabel": r"Goal reward $R$",
        "baseline": 1000.0,
        "color": "#009E73",
    },
    "action_cost_scale": {
        "title": "(d) Attack action-cost multiplier",
        "xlabel": r"Action-cost multiplier $\alpha$",
        "baseline": 1.0,
        "color": "#CC79A7",
    },
}


def parse_rows(path: Path, dataset: str) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = [row for row in csv.DictReader(handle) if row["dataset"] == dataset]
    if not rows:
        raise SystemExit(f"No rows for {dataset} in {path}")
    return rows


def number(raw: str | None) -> float | None:
    if raw in (None, ""):
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def write_data(path: Path, rows: list[dict]) -> None:
    fields = [
        "factor", "factor_value", "status", "timed_out", "budget",
        "objective_cost_form", "empty_objective_cost_form", "benefit_score",
        "selected_defense_count", "defense_cost_used", "attack_loss", "wall_seconds",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def draw(rows: list[dict], dataset: str, output: Path, dpi: int) -> None:
    import matplotlib.pyplot as plt

    figure, axes = plt.subplots(2, 2, figsize=(6.8, 4.8), sharey=True, constrained_layout=True)
    for axis, factor in zip(axes.flat, FACTOR_STYLE):
        style = FACTOR_STYLE[factor]
        points = sorted(
            (number(row["factor_value"]), number(row["benefit_score"]), row)
            for row in rows
            if row["factor"] == factor
        )
        x = [value for value, _, _ in points]
        y = [benefit for _, benefit, _ in points]
        valid_x = [value for value, benefit in zip(x, y) if benefit is not None]
        valid_y = [benefit for benefit in y if benefit is not None]
        axis.plot(valid_x, valid_y, marker="o", markersize=4.5, linewidth=1.55, color=style["color"])
        for value, benefit, row in points:
            if benefit is None:
                axis.annotate("T/O" if row["timed_out"] == "True" else "N/A", (value, 0.02),
                              rotation=90, ha="center", va="bottom", fontsize=7)
        axis.axvline(style["baseline"], color="#555555", linewidth=0.75, linestyle="--", zorder=0)
        axis.axhline(0, color="#333333", linewidth=0.6, zorder=0)
        axis.set_title(style["title"], fontsize=9.5, pad=5)
        axis.set_xlabel(style["xlabel"], fontsize=9)
        axis.set_xticks(x)
        axis.tick_params(axis="both", labelsize=8)
        axis.spines["top"].set_visible(False)
        axis.spines["right"].set_visible(False)
        axis.set_ylim(-0.04, 1.04)
    axes[0, 0].set_ylabel("Defense benefit", fontsize=9)
    axes[1, 0].set_ylabel("Defense benefit", fontsize=9)
    figure.suptitle(f"Parameter sensitivity of defense effectiveness on {dataset}", fontsize=10.5)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output.with_suffix(".png"), dpi=dpi, bbox_inches="tight")
    figure.savefig(output.with_suffix(".pdf"), bbox_inches="tight")
    plt.close(figure)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="git_attack_graph_sensitivity_analysis/sensitivity_summary.csv")
    parser.add_argument("--dataset", default="S3")
    parser.add_argument("--output", default="git_attack_graph_sensitivity_analysis/S3_sensitivity_effectiveness")
    parser.add_argument("--data-output", default="git_attack_graph_sensitivity_analysis/S3_sensitivity_benefit.csv")
    parser.add_argument("--dpi", type=int, default=300)
    args = parser.parse_args()
    rows = parse_rows(Path(args.input), args.dataset)
    draw(rows, args.dataset, Path(args.output), args.dpi)
    write_data(Path(args.data_output), rows)
    print(f"figure: {Path(args.output).with_suffix('.png')}")
    print(f"data: {args.data_output}")


if __name__ == "__main__":
    main()
