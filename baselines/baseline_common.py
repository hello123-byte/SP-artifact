# -*- coding: utf-8 -*-
"""Shared helpers for vulnerability-only MulVAL baseline experiments."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFENSE_SCOPE = "vul"


def safe_print(text: str):
    encoding = sys.stdout.encoding or "utf-8"
    print(text.encode(encoding, errors="backslashreplace").decode(encoding))


def coalesce(*values):
    for value in values:
        if value is not None:
            return value
    return None


def parse_csv_files(vertices_path: Path, arcs_path: Path):
    vertices = {}
    with vertices_path.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.reader(f):
            if not row:
                continue
            node_id = int(row[0])
            vertices[node_id] = {
                "id": node_id,
                "label": row[1],
                "type": row[2],
                "score": float(row[3]) if len(row) > 3 and row[3] else 0.0,
            }

    arcs = []
    with arcs_path.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.reader(f):
            if not row:
                continue
            arcs.append((int(row[0]), int(row[1])))
    return vertices, arcs


def load_json(path: str | Path | None) -> dict:
    if not path:
        return {}
    with Path(path).open(encoding="utf-8") as f:
        return json.load(f)


def normalize_id_map(items, key_name: str = "id") -> dict[int, dict]:
    if not items:
        return {}
    if isinstance(items, dict):
        return {int(key): value for key, value in items.items()}
    return {int(item[key_name]): item for item in items}


def parse_int_list(raw: str | None) -> list[int] | None:
    if not raw:
        return None
    return [int(part.strip()) for part in raw.split(",") if part.strip()]


def parse_weight_map(raw: str | None, ids: list[int], default_value: float) -> dict[int, float]:
    if not raw:
        return {item_id: default_value for item_id in ids}

    raw = raw.strip()
    if raw.startswith("{"):
        data = json.loads(raw)
        return {item_id: float(data.get(str(item_id), default_value)) for item_id in ids}

    result = {item_id: default_value for item_id in ids}
    for item in raw.split(","):
        if not item.strip():
            continue
        key, value = item.split(":", 1)
        result[int(key.strip())] = float(value.strip())
    return result


def parse_node_costs(raw: str | None) -> dict[int, float]:
    if not raw:
        return {}

    raw = raw.strip()
    if raw.startswith("{"):
        data = json.loads(raw)
        return {int(key): float(value) for key, value in data.items()}

    result = {}
    for item in raw.split(","):
        if not item.strip():
            continue
        key, value = item.split(":", 1)
        result[int(key.strip())] = float(value.strip())
    return result


def node_attack_cost(
    node_id: int,
    node: dict,
    explicit_costs: dict[int, float],
    config_costs: dict[int, float],
    attack_cost_source: str,
    default_action_cost: float,
    default_leaf_cost: float,
) -> float:
    del default_leaf_cost
    node_type = node["type"]
    if node_type in {"OR", "LEAF"}:
        return 0.0
    if node_id in explicit_costs:
        return explicit_costs[node_id]
    if node_id in config_costs:
        return config_costs[node_id]
    if node_type == "AND" and attack_cost_source == "score" and node["score"] > 0:
        return float(node["score"])
    if node_type == "AND":
        return float(default_action_cost)
    return 0.0


def validate_nonnegative_values(name: str, values: dict[int, float]):
    negative = [(node_id, value) for node_id, value in values.items() if value < 0]
    if negative:
        preview = ", ".join(f"{node_id}:{value}" for node_id, value in negative[:10])
        raise SystemExit(f"{name} must be non-negative. Found: {preview}")


def build_graph_indexes(vertices: dict[int, dict], arcs: list[tuple[int, int]]):
    outgoing = defaultdict(list)
    parents = defaultdict(list)
    indegree = Counter()
    for src, dst in arcs:
        if src not in vertices or dst not in vertices:
            continue
        outgoing[src].append(dst)
        parents[dst].append(src)
        indegree[dst] += 1
    return outgoing, parents, indegree


def compute_dependency_closure(
    vertices: dict[int, dict],
    arcs: list[tuple[int, int]],
    goals: list[int],
):
    outgoing, _, _ = build_graph_indexes(vertices, arcs)
    kept_ids = set(goals)
    stack = list(goals)
    while stack:
        node_id = stack.pop()
        for child in outgoing[node_id]:
            if child in vertices and child not in kept_ids:
                kept_ids.add(child)
                stack.append(child)

    reduced_vertices = {node_id: vertices[node_id] for node_id in sorted(kept_ids)}
    reduced_arcs = [
        (src, dst)
        for src, dst in arcs
        if src in kept_ids and dst in kept_ids
    ]
    stats = {
        "enabled": True,
        "original_vertices": len(vertices),
        "original_arcs": len(arcs),
        "reduced_vertices": len(reduced_vertices),
        "reduced_arcs": len(reduced_arcs),
        "removed_vertices": len(vertices) - len(reduced_vertices),
        "removed_arcs": len(arcs) - len(reduced_arcs),
        "goal_count": len(goals),
    }
    return reduced_vertices, reduced_arcs, stats


@dataclass
class Problem:
    vertices: dict[int, dict]
    arcs: list[tuple[int, int]]
    goals: list[int]
    rewards: dict[int, float]
    losses: dict[int, float]
    attack_costs: dict[int, float]
    defense_costs: dict[int, float]
    default_defense_cost: float
    budget: float | None
    attack_cost_source: str
    default_action_cost: float
    default_leaf_cost: float
    defendable: list[int]
    outgoing: dict[int, list[int]]
    parents: dict[int, list[int]]
    target_closure: dict
    vertices_path: str
    arcs_path: str


def add_problem_arguments(parser: argparse.ArgumentParser):
    parser.add_argument("--vertices", default=str(REPO_ROOT / "VERTICES.CSV"))
    parser.add_argument("--arcs", default=str(REPO_ROOT / "ARCS.CSV"))
    parser.add_argument("--config", default=None)
    parser.add_argument("--goals", default=None, help="Comma-separated goal node ids.")
    parser.add_argument("--default-reward", type=float, default=100.0)
    parser.add_argument("--default-loss", type=float, default=100.0)
    parser.add_argument(
        "--goal-rewards",
        default=None,
        help='Goal rewards as JSON {"1":100} or comma form 1:100,55:80.',
    )
    parser.add_argument(
        "--goal-losses",
        default=None,
        help='Goal losses as JSON {"1":100} or comma form 1:100,55:80.',
    )
    parser.add_argument("--defense-cost", type=float, default=1.0)
    parser.add_argument(
        "--defense-costs",
        default=None,
        help='Defense costs by node id, e.g. {"20":4} or 20:4,29:2.',
    )
    parser.add_argument("--budget", type=float, default=None)
    parser.add_argument(
        "--attack-cost-source",
        choices=["constant", "score"],
        default=None,
    )
    parser.add_argument("--default-action-cost", type=float, default=1.0)
    parser.add_argument(
        "--default-leaf-cost",
        type=float,
        default=0.0,
        help="Compatibility option; LEAF costs remain zero.",
    )
    parser.add_argument(
        "--node-attack-costs",
        default=None,
        help='Attack costs by node id, e.g. {"3":2} or 3:2,10:5.',
    )
    parser.add_argument(
        "--target-closure",
        action="store_true",
        default=None,
        help="Reduce graph to selected goals and their recursive prerequisites.",
    )


def load_problem(args) -> Problem:
    vertices_path = Path(args.vertices)
    arcs_path = Path(args.arcs)
    vertices, arcs = parse_csv_files(vertices_path, arcs_path)

    config = load_json(args.config)
    config_defaults = config.get("defaults", {})
    config_goals = normalize_id_map(config.get("goals"))
    config_nodes = normalize_id_map(config.get("nodes"))

    outgoing, parents, indegree = build_graph_indexes(vertices, arcs)
    default_goals = sorted(
        node_id
        for node_id, node in vertices.items()
        if node["type"] == "OR" and indegree[node_id] == 0
    )

    cli_goals = parse_int_list(args.goals)
    if cli_goals:
        goals = cli_goals
    elif config_goals:
        goals = sorted(
            node_id
            for node_id, item in config_goals.items()
            if item.get("enabled", True)
        )
    else:
        goals = default_goals

    if not goals:
        raise SystemExit("No goals found. Pass --goals id1,id2 or provide enabled config goals.")
    missing_goals = [goal for goal in goals if goal not in vertices]
    if missing_goals:
        raise SystemExit(f"Unknown goal id(s): {missing_goals}")

    target_closure_enabled = bool(coalesce(args.target_closure, config_defaults.get("target_closure"), False))
    target_closure_stats = {
        "enabled": target_closure_enabled,
        "original_vertices": len(vertices),
        "original_arcs": len(arcs),
        "reduced_vertices": len(vertices),
        "reduced_arcs": len(arcs),
        "removed_vertices": 0,
        "removed_arcs": 0,
        "goal_count": len(goals),
    }
    if target_closure_enabled:
        vertices, arcs, target_closure_stats = compute_dependency_closure(vertices, arcs, goals)

    default_reward = float(config_defaults.get("goal_reward", args.default_reward))
    default_loss = float(config_defaults.get("goal_loss", args.default_loss))
    default_defense_cost = float(config_defaults.get("defense_cost", args.defense_cost))
    budget = coalesce(args.budget, config_defaults.get("budget"))
    if budget is not None:
        budget = float(budget)
        if budget < 0:
            raise SystemExit("--budget must be non-negative")

    attack_cost_source = coalesce(args.attack_cost_source, config_defaults.get("attack_cost_source"), "constant")
    default_action_cost = float(config_defaults.get("action_attack_cost", args.default_action_cost))
    default_leaf_cost = float(config_defaults.get("leaf_attack_cost", args.default_leaf_cost))

    rewards = parse_weight_map(args.goal_rewards, goals, default_reward)
    losses = parse_weight_map(args.goal_losses, goals, default_loss)
    for goal in goals:
        goal_config = config_goals.get(goal, {})
        if "reward" in goal_config and not args.goal_rewards:
            rewards[goal] = float(goal_config["reward"])
        if "loss" in goal_config and not args.goal_losses:
            losses[goal] = float(goal_config["loss"])

    defense_costs = parse_node_costs(args.defense_costs)
    config_defense_costs = {
        node_id: float(item["defense_cost"])
        for node_id, item in config_nodes.items()
        if item.get("defense_cost") is not None
    }
    if not args.defense_costs:
        defense_costs.update(config_defense_costs)

    explicit_attack_costs = parse_node_costs(args.node_attack_costs)
    config_attack_costs = {
        node_id: float(item["attack_cost"])
        for node_id, item in config_nodes.items()
        if item.get("attack_cost") is not None
    }
    attack_costs = {
        node_id: node_attack_cost(
            node_id=node_id,
            node=node,
            explicit_costs=explicit_attack_costs,
            config_costs=config_attack_costs,
            attack_cost_source=attack_cost_source,
            default_action_cost=default_action_cost,
            default_leaf_cost=default_leaf_cost,
        )
        for node_id, node in vertices.items()
    }
    validate_nonnegative_values("attack costs", attack_costs)
    validate_nonnegative_values("defense costs", defense_costs)

    outgoing, parents, _ = build_graph_indexes(vertices, arcs)
    defendable = sorted(
        node_id
        for node_id, node in vertices.items()
        if node["type"] == "LEAF"
        and node["label"].startswith(("vulExists", "ttpExists"))
    )

    return Problem(
        vertices=vertices,
        arcs=arcs,
        goals=goals,
        rewards=rewards,
        losses=losses,
        attack_costs=attack_costs,
        defense_costs=defense_costs,
        default_defense_cost=default_defense_cost,
        budget=budget,
        attack_cost_source=attack_cost_source,
        default_action_cost=default_action_cost,
        default_leaf_cost=default_leaf_cost,
        defendable=defendable,
        outgoing=outgoing,
        parents=parents,
        target_closure=target_closure_stats,
        vertices_path=str(vertices_path),
        arcs_path=str(arcs_path),
    )


def defense_cost(problem: Problem, defense_ids: set[int]) -> float:
    return sum(
        problem.defense_costs.get(node_id, problem.default_defense_cost)
        for node_id in defense_ids
    )


def selected_defense_items(problem: Problem, defense_ids: set[int]) -> list[dict]:
    return [
        {
            "id": node_id,
            "label": problem.vertices[node_id]["label"],
            "cost": problem.defense_costs.get(node_id, problem.default_defense_cost),
        }
        for node_id in sorted(defense_ids)
    ]


def compute_reachability_and_costs(problem: Problem, defense_ids: set[int]):
    remaining = {node_id: len(problem.outgoing[node_id]) for node_id in problem.vertices}
    reachable_child_count = defaultdict(int)
    child_cost_sum = defaultdict(float)
    child_cost_min = defaultdict(lambda: math.inf)
    reachable: dict[int, bool] = {}
    costs: dict[int, float] = {}

    queue = sorted(node_id for node_id, count in remaining.items() if count == 0)
    index = 0
    while index < len(queue):
        node_id = queue[index]
        index += 1
        node = problem.vertices[node_id]
        node_type = node["type"]

        if node_id not in reachable:
            if node_type == "LEAF":
                is_reachable = node_id not in defense_ids
                reachable[node_id] = is_reachable
                costs[node_id] = problem.attack_costs[node_id] if is_reachable else 0.0
            else:
                reachable[node_id] = False
                costs[node_id] = 0.0

        for parent_id in problem.parents[node_id]:
            if reachable[node_id]:
                reachable_child_count[parent_id] += 1
                child_cost_min[parent_id] = min(child_cost_min[parent_id], costs[node_id])
            child_cost_sum[parent_id] += costs[node_id]

            remaining[parent_id] -= 1
            if remaining[parent_id] != 0:
                continue

            parent = problem.vertices[parent_id]
            children = problem.outgoing[parent_id]
            parent_type = parent["type"]
            if parent_type == "LEAF":
                is_reachable = parent_id not in defense_ids
                reachable[parent_id] = is_reachable
                costs[parent_id] = problem.attack_costs[parent_id] if is_reachable else 0.0
            elif parent_type == "AND":
                is_reachable = bool(children) and reachable_child_count[parent_id] == len(children)
                reachable[parent_id] = is_reachable
                costs[parent_id] = (
                    problem.attack_costs[parent_id] + child_cost_sum[parent_id]
                    if is_reachable
                    else 0.0
                )
            elif parent_type == "OR":
                is_reachable = bool(children) and reachable_child_count[parent_id] > 0
                reachable[parent_id] = is_reachable
                costs[parent_id] = child_cost_min[parent_id] if is_reachable else 0.0
            else:
                raise SystemExit(f"Unknown node type for {parent_id}: {parent_type}")
            queue.append(parent_id)

    cycle_nodes = sorted(node_id for node_id in problem.vertices if node_id not in reachable)
    for node_id in cycle_nodes:
        reachable[node_id] = False
        costs[node_id] = 0.0
    return reachable, costs, cycle_nodes


def choose_attacker_response(problem: Problem, reachable: dict[int, bool], costs: dict[int, float]):
    reachable_goals = []
    for goal in problem.goals:
        if not reachable.get(goal, False):
            continue
        min_cost = costs[goal]
        reachable_goals.append(
            {
                "id": goal,
                "label": problem.vertices[goal]["label"],
                "reward": problem.rewards[goal],
                "loss": problem.losses[goal],
                "min_attack_cost": min_cost,
                "attacker_net_utility": problem.rewards[goal] - min_cost,
            }
        )

    if not reachable_goals:
        return reachable_goals, {"type": "empty"}, 0.0, 0.0

    best_utility = max(item["attacker_net_utility"] for item in reachable_goals)
    if best_utility <= 0:
        return reachable_goals, {"type": "empty"}, 0.0, 0.0

    eps = 1e-9
    tied = [
        item
        for item in reachable_goals
        if abs(item["attacker_net_utility"] - best_utility) <= eps
    ]
    # Strong Stackelberg convention: defender-favorable tie among attacker best responses.
    chosen = min(tied, key=lambda item: (item["loss"], item["id"]))
    response = {
        "type": "attack_goal",
        "goal": dict(chosen),
    }
    return reachable_goals, response, chosen["attacker_net_utility"], chosen["loss"]


def evaluate_defense_set(
    problem: Problem,
    defense_ids: set[int] | list[int],
    method: str,
    start_time: float | None = None,
    status: str = "ok",
) -> dict:
    start_time = time.perf_counter() if start_time is None else start_time
    defense_set = set(defense_ids)
    invalid = sorted(defense_set - set(problem.defendable))
    if invalid:
        preview = ", ".join(str(node_id) for node_id in invalid[:10])
        raise SystemExit(f"{method} selected non-vulnerability defenses: {preview}")

    reachable, costs, cycle_nodes = compute_reachability_and_costs(problem, defense_set)
    reachable_goals, attacker_response, attacker_utility, attack_loss = choose_attacker_response(
        problem, reachable, costs
    )
    total_defense_cost = defense_cost(problem, defense_set)
    objective = total_defense_cost + attack_loss
    wall_seconds = time.perf_counter() - start_time

    if cycle_nodes and status == "ok":
        status = "unsupported_cycle"

    return {
        "method": method,
        "status": status,
        "defense_scope": DEFENSE_SCOPE,
        "objective_cost_form": objective,
        "empty_objective_cost_form": None,
        "benefit_score": None,
        "selected_defenses": selected_defense_items(problem, defense_set),
        "attacker_response": attacker_response,
        "reachable_goals": reachable_goals,
        "defense_cost": total_defense_cost,
        "attack_loss": attack_loss,
        "attacker_utility": attacker_utility,
        "goal_count": len(problem.goals),
        "defendable_leaf_count": len(problem.defendable),
        "budget": problem.budget,
        "budget_used": total_defense_cost,
        "budget_feasible": problem.budget is None or total_defense_cost <= problem.budget + 1e-9,
        "attack_cost_source": problem.attack_cost_source,
        "default_action_cost": problem.default_action_cost,
        "default_leaf_cost": problem.default_leaf_cost,
        "target_closure": problem.target_closure,
        "cycle_node_count": len(cycle_nodes),
        "sample_cycle_nodes": cycle_nodes[:10],
        "timings_seconds": {"total_wall": wall_seconds},
    }


def attach_benefit(result: dict, empty_objective: float | None, is_empty: bool = False) -> dict:
    result["empty_objective_cost_form"] = empty_objective
    if is_empty:
        result["benefit_score"] = 0.0
    elif empty_objective is None or empty_objective == 0 or result.get("objective_cost_form") is None:
        result["benefit_score"] = None
    else:
        result["benefit_score"] = (
            empty_objective - float(result["objective_cost_form"])
        ) / empty_objective
    return result


def write_json(path: str | Path, data: dict):
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_reference_result(path: str | Path | None) -> dict:
    if not path:
        return {}
    return load_json(path)


def reference_defense_cost(reference_result: dict) -> float | None:
    selected = reference_result.get("selected_defenses")
    if not selected:
        return None
    return sum(float(item.get("cost", 0.0)) for item in selected)


def infer_budget(
    problem: Problem,
    explicit_budget: float | None,
    reference_result: dict | None,
    label: str,
) -> float:
    budget = coalesce(explicit_budget, problem.budget, reference_defense_cost(reference_result or {}))
    if budget is None:
        raise SystemExit(
            f"{label} needs a budget. Pass --budget, the method-specific budget flag, "
            "or --reference-result with selected_defenses."
        )
    budget = float(budget)
    if budget < 0:
        raise SystemExit(f"{label} budget must be non-negative")
    return budget


def summarize_objectives(values: list[float]) -> dict:
    if not values:
        return {
            "objective_mean": None,
            "objective_std": None,
            "objective_min": None,
            "objective_max": None,
        }
    return {
        "objective_mean": statistics.fmean(values),
        "objective_std": statistics.pstdev(values) if len(values) > 1 else 0.0,
        "objective_min": min(values),
        "objective_max": max(values),
    }


def summary_row(method: str, result: dict, result_path: str | Path | None = None) -> dict:
    del result_path
    return {
        "method": method,
        "defense_benefit": result.get("benefit_score"),
    }


def write_summary_csv(path: str | Path, rows: list[dict[str, Any]]):
    fieldnames = ["method", "defense_benefit"]
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})
