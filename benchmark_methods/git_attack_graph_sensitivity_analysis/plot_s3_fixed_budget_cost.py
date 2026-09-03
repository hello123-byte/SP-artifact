#!/usr/bin/env python3
"""Plot fixed-budget defense-cost sensitivity for a selected dataset."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="git_attack_graph_sensitivity_analysis/sensitivity_summary.csv")
    parser.add_argument("--dataset", default="S3")
    parser.add_argument("--output", default="git_attack_graph_sensitivity_analysis/S3_fixed_budget_defense_cost_effectiveness")
    parser.add_argument("--data-output", default="git_attack_graph_sensitivity_analysis/S3_fixed_budget_defense_cost.csv")
    parser.add_argument("--dpi", type=int, default=300)
    args = parser.parse_args()

    with Path(args.input).open(newline="", encoding="utf-8") as handle:
        rows = [row for row in csv.DictReader(handle) if row["dataset"] == args.dataset and row["factor"] == "defense_cost_fixed_budget"]
    if not rows:
        raise SystemExit("No fixed-budget defense-cost results found; run the fixed-budget sweep first.")
    rows.sort(key=lambda row: float(row["factor_value"]))

    fields = ["factor_value", "budget", "status", "timed_out", "benefit_score", "objective_cost_form", "selected_defense_count", "defense_cost_used", "attack_loss"]
    with Path(args.data_output).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    import matplotlib.pyplot as plt

    x = [float(row["factor_value"]) for row in rows]
    y = [float(row["benefit_score"]) if row["benefit_score"] else None for row in rows]
    valid = [(cost, benefit) for cost, benefit in zip(x, y) if benefit is not None]
    budget = float(rows[0]["budget"])
    figure, axis = plt.subplots(figsize=(4.5, 3.05), constrained_layout=True)
    axis.plot(*zip(*valid), marker="o", markersize=5, linewidth=1.65, color="#D55E00")
    axis.axvline(1.0, color="#555555", linewidth=0.75, linestyle="--", zorder=0)
    axis.axhline(0, color="#333333", linewidth=0.6, zorder=0)
    axis.set_xticks(x)
    axis.set_ylim(-0.04, 1.04)
    axis.set_xlabel("Defense cost per vulnerability", fontsize=9)
    axis.set_ylabel("Defense benefit", fontsize=9)
    axis.tick_params(axis="both", labelsize=8)
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output.with_suffix(".png"), dpi=args.dpi, bbox_inches="tight")
    figure.savefig(output.with_suffix(".pdf"), bbox_inches="tight")
    plt.close(figure)
    print(f'figure: {output.with_suffix(".png")}')
    print(f"data: {args.data_output}")


if __name__ == "__main__":
    main()
