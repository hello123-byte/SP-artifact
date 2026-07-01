# -*- coding: utf-8 -*-
"""Run vulnerability-only baseline comparison experiments."""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
import time
from pathlib import Path

from baseline_common import (
    REPO_ROOT,
    add_problem_arguments,
    attach_benefit,
    infer_budget,
    load_problem,
    load_reference_result,
    safe_print,
    summary_row,
    write_json,
    write_summary_csv,
)
from empty_defense_baseline import run_empty_baseline
from full_path_enumeration_baseline import run_path_enumeration_baseline
from random_defense_baseline import run_random_baseline


DEFAULT_METHODS = ["empty", "random", "path_enum", "stackelberg"]


def parse_methods(raw: str | None) -> list[str]:
    if not raw:
        return list(DEFAULT_METHODS)
    methods = [item.strip() for item in raw.split(",") if item.strip()]
    allowed = set(DEFAULT_METHODS)
    unknown = [method for method in methods if method not in allowed]
    if unknown:
        raise SystemExit(f"Unknown method(s): {unknown}. Allowed: {sorted(allowed)}")
    return methods


def optional_extend(cmd: list[str], flag: str, value):
    if value is not None:
        cmd.extend([flag, str(value)])


def run_stackelberg_model(args, out_dir: Path, empty_objective: float) -> tuple[dict, Path]:
    result_path = out_dir / "stackelberg_model.json"
    log_path = out_dir / "stackelberg_model.log"
    solver_script = Path(args.solver_script)
    if not solver_script.is_absolute():
        solver_script = REPO_ROOT / solver_script

    cmd = [
        args.python,
        str(solver_script),
        "--vertices",
        str(args.vertices),
        "--arcs",
        str(args.arcs),
        "--out",
        str(result_path),
        "--defendable",
        "vul",
        "--default-reward",
        str(args.default_reward),
        "--default-loss",
        str(args.default_loss),
        "--defense-cost",
        str(args.defense_cost),
        "--default-action-cost",
        str(args.default_action_cost),
        "--default-leaf-cost",
        str(args.default_leaf_cost),
        "--solver",
        args.solver,
    ]
    optional_extend(cmd, "--config", args.config)
    optional_extend(cmd, "--goals", args.goals)
    optional_extend(cmd, "--goal-rewards", args.goal_rewards)
    optional_extend(cmd, "--goal-losses", args.goal_losses)
    optional_extend(cmd, "--defense-costs", args.defense_costs)
    optional_extend(cmd, "--budget", args.budget)
    optional_extend(cmd, "--attack-cost-source", args.attack_cost_source)
    optional_extend(cmd, "--node-attack-costs", args.node_attack_costs)
    optional_extend(cmd, "--time-limit", args.time_limit)
    optional_extend(cmd, "--mip-gap", args.mip_gap)
    if args.target_closure:
        cmd.append("--target-closure")

    result_path.unlink(missing_ok=True)
    start = time.perf_counter()
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
    wall_seconds = time.perf_counter() - start

    if not result_path.exists():
        result = {
            "method": "stackelberg_model",
            "status": "solver_failed",
            "defense_scope": "vul",
            "objective_cost_form": None,
            "empty_objective_cost_form": empty_objective,
            "benefit_score": None,
            "selected_defenses": [],
            "attacker_response": None,
            "reachable_goals": [],
            "defense_cost": None,
            "attack_loss": None,
            "attacker_utility": None,
            "budget_used": None,
            "solver_returncode": proc.returncode,
            "log_file": str(log_path),
            "timings_seconds": {"total_wall": wall_seconds},
        }
        write_json(result_path, result)
        return result, result_path

    result = json.loads(result_path.read_text(encoding="utf-8"))
    selected = result.get("selected_defenses") or []
    defense_cost = sum(float(item.get("cost", 0.0)) for item in selected)
    objective = result.get("objective_cost_form")
    attack_loss = None
    if objective is not None:
        attack_loss = float(objective) - defense_cost

    result["method"] = "stackelberg_model"
    result["defense_scope"] = "vul"
    result["empty_objective_cost_form"] = empty_objective
    result["defense_cost"] = defense_cost
    result["attack_loss"] = attack_loss
    result["budget_used"] = defense_cost
    result["solver_returncode"] = proc.returncode
    result["log_file"] = str(log_path)
    result["defense_scope_ok"] = all(
        str(item.get("label", "")).startswith("vulExists")
        for item in selected
    )
    result.setdefault("timings_seconds", {})
    result["timings_seconds"]["runner_wall"] = wall_seconds
    attach_benefit(result, empty_objective)
    write_json(result_path, result)
    return result, result_path


def build_reference_row(reference_result: dict, empty_objective: float, result_path: str | None):
    if not reference_result:
        return None
    selected = reference_result.get("selected_defenses") or []
    defense_cost = sum(float(item.get("cost", 0.0)) for item in selected)
    objective = reference_result.get("objective_cost_form")
    attack_loss = None
    if objective is not None:
        attack_loss = float(objective) - defense_cost
    converted = {
        "method": "stackelberg_reference",
        "status": reference_result.get("status"),
        "defense_scope": "vul",
        "objective_cost_form": objective,
        "empty_objective_cost_form": empty_objective,
        "benefit_score": None,
        "selected_defenses": selected,
        "attacker_response": reference_result.get("attacker_response"),
        "reachable_goals": reference_result.get("reachable_goals", []),
        "defense_cost": defense_cost,
        "attack_loss": attack_loss,
        "attacker_utility": reference_result.get("attacker_utility"),
        "budget_used": defense_cost,
        "timings_seconds": reference_result.get("timings_seconds", {}),
        "reference_defense_scope_ok": all(
            str(item.get("label", "")).startswith("vulExists")
            for item in selected
        ),
    }
    attach_benefit(converted, empty_objective)
    return summary_row("stackelberg_reference", converted, result_path)


def finite_number(value) -> float | None:
    if value in (None, ""):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return number


def format_metric(value, digits: int = 3) -> str:
    number = finite_number(value)
    if number is None:
        return "n/a"
    if abs(number) >= 1000:
        return f"{number:,.0f}"
    if abs(number) >= 100:
        return f"{number:.1f}"
    return f"{number:.{digits}g}"


def method_color(method: str) -> str:
    # Okabe-Ito inspired palette, readable in print and color-blind friendly.
    palette = {
        "empty": "#666666",
        "random": "#0072B2",
        "path_enum": "#009E73",
        "stackelberg": "#D55E00",
        "stackelberg_reference": "#CC79A7",
    }
    return palette.get(method, "#333333")


def finite_or_nan(value) -> float:
    number = finite_number(value)
    return number if number is not None else math.nan


def nice_ylim(values: list[float], minimum: float = 1.0) -> float:
    finite = [value for value in values if value is not None and math.isfinite(value)]
    max_value = max([minimum] + finite)
    if max_value <= 0:
        return minimum
    exponent = math.floor(math.log10(max_value))
    base = 10 ** exponent
    for multiplier in [1, 2, 5, 10]:
        upper = multiplier * base
        if upper >= max_value:
            return upper
    return 10 * base


def annotate_bars(ax, values: list[float | None], digits: int = 3, y_offset_fraction: float = 0.02):
    ymin, ymax = ax.get_ylim()
    offset = (ymax - ymin) * y_offset_fraction
    for index, value in enumerate(values):
        number = finite_number(value)
        if number is None:
            ax.text(index, ymin + offset, "n/a", ha="center", va="bottom", fontsize=7)
            continue
        va = "bottom" if number >= 0 else "top"
        y = number + offset if number >= 0 else number - offset
        ax.text(index, y, format_metric(number, digits=digits), ha="center", va=va, fontsize=7)


def style_axis(ax, methods: list[str], panel_title: str, ylabel: str):
    ax.set_title(panel_title, loc="left", fontsize=9, fontweight="bold")
    ax.set_ylabel(ylabel)
    ax.set_xticks(list(range(len(methods))))
    ax.set_xticklabels(methods, rotation=30, ha="right")
    ax.grid(axis="y", color="#d9d9d9", linewidth=0.6, alpha=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(axis="both", labelsize=7)


def write_benefit_line_chart(path: Path, rows: list[dict], dpi: int = 300):
    """Write a publication-style matplotlib experiment figure."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise SystemExit("No result rows available for plotting.")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.ticker import MaxNLocator
    except ImportError as exc:
        raise SystemExit(
            "matplotlib is required to generate experiment figures. Install it with: pip install matplotlib"
        ) from exc

    methods = [str(row.get("method", "")) for row in rows]
    x = list(range(len(methods)))
    colors = [method_color(method) for method in methods]

    benefits = [finite_number(row.get("benefit_score")) for row in rows]
    objectives = [finite_number(row.get("objective_cost_form")) for row in rows]
    defense_costs = [finite_number(row.get("defense_cost")) or 0.0 for row in rows]
    attack_losses = [finite_number(row.get("attack_loss")) or 0.0 for row in rows]
    runtimes = [finite_number(row.get("wall_seconds")) for row in rows]
    defense_counts = [finite_number(row.get("selected_defense_count")) or 0.0 for row in rows]
    responses = [str(row.get("attacker_response_type", "")) for row in rows]

    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 8,
        "axes.titlesize": 9,
        "axes.labelsize": 8,
        "legend.fontsize": 7,
        "figure.dpi": dpi,
        "savefig.dpi": dpi,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    })

    fig, axes = plt.subplots(2, 2, figsize=(7.2, 5.4), constrained_layout=True)
    fig.suptitle("Vulnerability-only defense comparison", fontsize=10, fontweight="bold")

    # (a) Defense benefit.
    ax = axes[0][0]
    benefit_values = [value if value is not None else math.nan for value in benefits]
    ax.bar(x, benefit_values, color=colors, width=0.62)
    ax.axhline(0, color="black", linewidth=0.8)
    benefit_max = nice_ylim([value for value in benefits if value is not None], minimum=1.0)
    benefit_min = min([0.0] + [value for value in benefits if value is not None])
    ax.set_ylim(benefit_min, benefit_max * 1.12)
    style_axis(ax, methods, "(a) Defense benefit", "benefit score")
    annotate_bars(ax, benefits)

    # (b) Objective decomposition.
    ax = axes[0][1]
    objective_available = [objective is not None for objective in objectives]
    defense_plot = [defense_costs[i] if objective_available[i] else math.nan for i in x]
    loss_plot = [attack_losses[i] if objective_available[i] else math.nan for i in x]
    ax.bar(x, defense_plot, color="#56B4E9", width=0.62, label="defense cost")
    ax.bar(x, loss_plot, bottom=defense_plot, color="#E69F00", width=0.62, label="attack loss")
    ax.set_ylim(0, nice_ylim([value for value in objectives if value is not None], minimum=1.0) * 1.12)
    style_axis(ax, methods, "(b) Objective decomposition", "objective J")
    ax.legend(frameon=False, loc="upper right")
    annotate_bars(ax, objectives)

    # (c) Runtime on log scale.
    ax = axes[1][0]
    runtime_plot = [value if value is not None and value > 0 else math.nan for value in runtimes]
    ax.bar(x, runtime_plot, color=colors, width=0.62)
    ax.set_yscale("log")
    style_axis(ax, methods, "(c) Runtime", "seconds, log scale")
    for index, value in enumerate(runtimes):
        number = finite_number(value)
        if number is None or number <= 0:
            ax.text(index, 1.0, "n/a", ha="center", va="bottom", fontsize=7)
            continue
        ax.text(index, number * 1.15, format_metric(number, digits=2), ha="center", va="bottom", fontsize=7)

    # (d) Defense size and attacker response.
    ax = axes[1][1]
    ax.bar(x, defense_counts, color=colors, width=0.62)
    ax.set_ylim(0, max(1.0, max(defense_counts) * 1.35))
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    style_axis(ax, methods, "(d) Defense size", "# defended vulnerabilities")
    for index, count in enumerate(defense_counts):
        ax.text(index, count + max(0.06, ax.get_ylim()[1] * 0.025), format_metric(count, digits=0), ha="center", va="bottom", fontsize=7)
        if responses[index]:
            ax.text(index, -0.26, responses[index], ha="center", va="top", fontsize=6.5, transform=ax.get_xaxis_transform())
    ax.text(0.5, -0.38, "attacker response", ha="center", va="top", fontsize=7, transform=ax.transAxes)

    suffix = path.suffix.lower()
    if not suffix:
        path = path.with_suffix(".png")
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)

def main():
    parser = argparse.ArgumentParser()
    add_problem_arguments(parser)
    parser.add_argument("--methods", default=None, help="Comma-separated: empty,random,path_enum,stackelberg")
    parser.add_argument("--out-dir", default="baseline_results")
    parser.add_argument("--reference-result", default=None)
    parser.add_argument("--solver-script", default="solve_mulval__stackelberg_main.py")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--solver", choices=["scip", "gurobi"], default="scip")
    parser.add_argument("--time-limit", type=float, default=None)
    parser.add_argument("--mip-gap", type=float, default=None)
    parser.add_argument("--random-budget", type=float, default=None)
    parser.add_argument("--path-budget", type=float, default=None)
    parser.add_argument("--random-trials", type=int, default=50)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--max-paths", type=int, default=100000)
    parser.add_argument("--max-depth", type=int, default=200)
    parser.add_argument("--chart-out", default=None, help="Figure output path. Use .png by default, or pass .pdf for vector output.")
    parser.add_argument("--figure-dpi", type=int, default=300)
    parser.add_argument("--skip-chart", action="store_true")
    args = parser.parse_args()

    methods = parse_methods(args.methods)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    problem = load_problem(args)
    reference_result = load_reference_result(args.reference_result)
    empty_result = run_empty_baseline(problem)
    empty_objective = empty_result["objective_cost_form"]

    rows = []
    if "empty" in methods:
        path = out_dir / "empty_defense.json"
        write_json(path, empty_result)
        rows.append(summary_row("empty", empty_result, path))

    if "random" in methods:
        random_budget = infer_budget(problem, args.random_budget, reference_result, "random baseline")
        result = run_random_baseline(
            problem=problem,
            budget=random_budget,
            random_trials=args.random_trials,
            seed=args.seed,
            empty_objective=empty_objective,
        )
        path = out_dir / "random_defense.json"
        write_json(path, result)
        rows.append(summary_row("random", result, path))

    if "path_enum" in methods:
        path_budget = infer_budget(problem, args.path_budget, reference_result, "path enumeration baseline")
        result = run_path_enumeration_baseline(
            problem=problem,
            budget=path_budget,
            max_paths=args.max_paths,
            max_depth=args.max_depth,
            empty_objective=empty_objective,
        )
        path = out_dir / "full_path_enumeration.json"
        write_json(path, result)
        rows.append(summary_row("path_enum", result, path))

    if "stackelberg" in methods:
        result, path = run_stackelberg_model(args, out_dir, empty_objective)
        rows.append(summary_row("stackelberg", result, path))

    reference_row = build_reference_row(reference_result, empty_objective, args.reference_result)
    if reference_row:
        rows.append(reference_row)

    summary_path = out_dir / "baseline_summary.csv"
    write_summary_csv(summary_path, rows)
    chart_path = Path(args.chart_out) if args.chart_out else out_dir / "baseline_experiment_figure.png"
    if not args.skip_chart:
        write_benefit_line_chart(chart_path, rows, dpi=args.figure_dpi)
    safe_print(f"summary: {summary_path}")
    if not args.skip_chart:
        safe_print(f"chart: {chart_path}")


if __name__ == "__main__":
    main()
