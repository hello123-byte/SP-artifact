# -*- coding: utf-8 -*-
"""Empty-defense vulnerability baseline."""

from __future__ import annotations

import argparse

from baseline_common import (
    add_problem_arguments,
    attach_benefit,
    evaluate_defense_set,
    load_problem,
    safe_print,
    write_json,
)


def run_empty_baseline(problem):
    result = evaluate_defense_set(problem, set(), method="empty_defense")
    return attach_benefit(result, result["objective_cost_form"], is_empty=True)


def main():
    parser = argparse.ArgumentParser()
    add_problem_arguments(parser)
    parser.add_argument("--out", default="baseline_results/empty_defense.json")
    args = parser.parse_args()

    problem = load_problem(args)
    result = run_empty_baseline(problem)
    write_json(args.out, result)
    safe_print(f"method: {result['method']}")
    safe_print(f"status: {result['status']}")
    safe_print(f"objective cost form: {result['objective_cost_form']}")
    safe_print(f"benefit_score: {result['benefit_score']}")
    safe_print(f"wrote: {args.out}")


if __name__ == "__main__":
    main()

