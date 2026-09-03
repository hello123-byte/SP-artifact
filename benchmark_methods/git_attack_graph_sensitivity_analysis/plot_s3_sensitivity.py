#!/usr/bin/env python3
"""Create a publication-ready one-factor sensitivity figure for one dataset."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


FACTOR_STYLE = {
    "budget_ratio": {
        "xlabel": "Defense budget",
        "baseline": 0.4,
        "color": "#0072B2",
    },
    "reward": {
        "xlabel": "Attacker payoff after a successful attack",
        "baseline": 1000.0,
        "color": "#009E73",
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

    output.parent.mkdir(parents=True, exist_ok=True)
    for factor, style in FACTOR_STYLE.items():
        points = sorted(
            (
                number(row["budget"]) if factor == "budget_ratio" else number(row["factor_value"]),
                number(row["benefit_score"]),
                row,
            )
            for row in rows
            if row["factor"] == factor
        )
        if not points:
            continue
        x = [value for value, _, _ in points]
        y = [benefit for _, benefit, _ in points]
        valid = [(value, benefit) for value, benefit in zip(x, y) if benefit is not None]
        figure, axis = plt.subplots(figsize=(3.55, 2.65), constrained_layout=True)
        axis.plot(*zip(*valid), marker="o", markersize=4.5, linewidth=1.55, color=style["color"])
        for value, benefit, row in points:
            if benefit is None:
                axis.annotate("T/O" if row["timed_out"] == "True" else "N/A", (value, 0.02),
                              rotation=90, ha="center", va="bottom", fontsize=7)
        baseline = style["baseline"]
        if factor == "budget_ratio":
            baseline = next(
                value for value, _, row in points
                if abs(number(row["factor_value"]) - 0.4) < 1e-9
            )
        axis.axvline(baseline, color="#555555", linewidth=0.75, linestyle="--", zorder=0)
        axis.axhline(0, color="#333333", linewidth=0.6, zorder=0)
        axis.set_xlabel(style["xlabel"], fontsize=9)
        axis.set_ylabel("Defense benefit", fontsize=9)
        axis.set_xticks(x)
        if factor == "action_cost_scale":
            axis.set_xticklabels([f"{value:g}×" for value in x])
        axis.tick_params(axis="both", labelsize=8)
        axis.spines["top"].set_visible(False)
        axis.spines["right"].set_visible(False)
        axis.set_ylim(-0.04, 1.04)
        path = output.parent / f"{dataset}_{factor}_sensitivity"
        figure.savefig(path.with_suffix(".png"), dpi=dpi, bbox_inches="tight")
        figure.savefig(path.with_suffix(".pdf"), bbox_inches="tight")
        plt.close(figure)
        print(f'figure: {path.with_suffix(".png")}')


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
    print(f"data: {args.data_output}")


if __name__ == "__main__":
    main()
