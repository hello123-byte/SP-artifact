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
from ga_defense_baseline import run_ga_baseline
from random_defense_baseline import run_random_baseline


DEFAULT_METHODS = ["empty", "random", "path_enum", "ga", "stackelberg"]


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
        str(item.get("label", "")).startswith(("vulExists", "ttpExists"))
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
            str(item.get("label", "")).startswith(("vulExists", "ttpExists"))
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
        "ga": "#E69F00",
        "stackelberg": "#D55E00",
        "stackelberg_reference": "#CC79A7",
    }
    return palette.get(method, "#333333")


def method_display_name(method: str) -> str:
    """Return the publication label used in baseline comparison figures."""
    return {
        "stackelberg": "Our",
    }.get(method, method)


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
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(axis="both", labelsize=7)


def write_benefit_line_chart(path: Path, rows: list[dict], dpi: int = 300):
    """Write a single-panel figure that reports defense benefit only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise SystemExit("No result rows available for plotting.")

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise SystemExit(
            "matplotlib is required to generate experiment figures. Install it with: pip install matplotlib"
        ) from exc

    methods = [str(row.get("method", "")) for row in rows]
    x = list(range(len(methods)))
    colors = [method_color(method) for method in methods]
    benefits = [finite_number(row.get("defense_benefit")) for row in rows]

    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 9,
        "axes.titlesize": 10,
        "axes.labelsize": 9,
        "figure.dpi": dpi,
        "savefig.dpi": dpi,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    })
    fig, ax = plt.subplots(figsize=(4.2, 3.0), constrained_layout=True)
    benefit_values = [value if value is not None else math.nan for value in benefits]
    ax.bar(x, benefit_values, color=colors, width=0.46)
    ax.axhline(0, color="black", linewidth=0.8)
    finite_benefits = [value for value in benefits if value is not None]
    if finite_benefits:
        benefit_max = nice_ylim(finite_benefits, minimum=1.0)
        benefit_min = min([0.0] + finite_benefits)
        ax.set_ylim(benefit_min, benefit_max * 1.12)
    display_methods = [method_display_name(method) for method in methods]
    style_axis(ax, display_methods, "", "benefit score")
    annotate_bars(ax, benefits)

    suffix = path.suffix.lower()
    if not suffix:
        path = path.with_suffix(".png")
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)

def main():
    parser = argparse.ArgumentParser()
    add_problem_arguments(parser)
    parser.add_argument("--methods", default=None, help="Comma-separated: empty,random,path_enum,ga,stackelberg")
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
    parser.add_argument("--ga-runs", type=int, default=10)
    parser.add_argument("--ga-population-size", type=int, default=64)
    parser.add_argument("--ga-generations", type=int, default=50)
    args = parser.parse_args()

    methods = parse_methods(args.methods)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    problem = load_problem(args)
    reference_result = load_reference_result(args.reference_result)
    empty_result = run_empty_baseline(problem)
    empty_objective = empty_result["objective_cost_form"]

    rows = []

    def print_defense_strategy(method: str, result: dict) -> None:
        selected = result.get("selected_defenses") or []
        safe_print(f"{method} selected defenses (total cost={result.get('defense_cost', 0.0)}):")
        if not selected:
            safe_print("  none")
            return
        for defense in selected:
            safe_print(
                f"  {defense.get('id')}: {defense.get('label')} "
                f"(cost={defense.get('cost')})"
            )
    if "empty" in methods:
        path = out_dir / "empty_defense.json"
        write_json(path, empty_result)
        rows.append(summary_row("empty", empty_result, path))
        print_defense_strategy("empty", empty_result)

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
        print_defense_strategy("random", result)

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
        print_defense_strategy("path_enum", result)

    if "ga" in methods:
        ga_budget = infer_budget(problem, args.budget, reference_result, "GA baseline")
        result = run_ga_baseline(
            problem=problem,
            budget=ga_budget,
            runs=args.ga_runs,
            population_size=args.ga_population_size,
            generations=args.ga_generations,
            seed=args.seed,
            empty_objective=empty_objective,
        )
        path = out_dir / "ga_defense.json"
        write_json(path, result)
        rows.append(summary_row("ga", result, path))
        print_defense_strategy("ga", result)

    if "stackelberg" in methods:
        result, path = run_stackelberg_model(args, out_dir, empty_objective)
        rows.append(summary_row("stackelberg", result, path))
        print_defense_strategy("stackelberg", result)

    reference_row = build_reference_row(reference_result, empty_objective, args.reference_result)
    if reference_row:
        rows.append(reference_row)
        reference_selected_defenses = reference_result.get("selected_defenses") or []
        reference_defense_cost = sum(
            float(item.get("cost", 0.0)) for item in reference_selected_defenses
        )
        print_defense_strategy(
            "stackelberg_reference",
            {
                "selected_defenses": reference_selected_defenses,
                "defense_cost": reference_defense_cost,
            },
        )

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
