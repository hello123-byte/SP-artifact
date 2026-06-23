# -*- coding: utf-8 -*-
"""Shared attack-cost estimation and reward/loss calibration helpers."""

from __future__ import annotations

import csv
import math
from collections import defaultdict
from pathlib import Path


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


def normalize_vertices(vertices) -> dict[int, dict]:
    if isinstance(vertices, dict):
        return vertices
    return {
        int(node_id): {
            "id": int(node_id),
            "label": label,
            "type": node_type,
            "score": float(score),
        }
        for node_id, label, node_type, score in vertices
    }


def node_attack_cost(
    node: dict,
    attack_cost_source: str,
    default_action_cost: float,
    default_leaf_cost: float,
) -> float:
    node_type = node["type"]
    if node_type in {"OR", "LEAF"}:
        return 0.0
    if node_type == "AND" and attack_cost_source == "score" and node["score"] > 0:
        return float(node["score"])
    if node_type == "AND":
        return float(default_action_cost)
    return 0.0


def estimate_goal_min_attack_costs(
    vertices,
    arcs: list[tuple[int, int]],
    goals: list[int],
    attack_cost_source: str,
    default_action_cost: float = 1.0,
    default_leaf_cost: float = 0.0,
) -> dict[int, float]:
    """Estimate no-defense minimum derivation costs using the solver semantics.

    Edges are conclusion -> prerequisite. The graph is processed from
    prerequisites toward conclusions, so this works without recursion on very
    large synthetic DAGs.
    """
    vertex_map = normalize_vertices(vertices)
    outgoing = defaultdict(list)
    parents = defaultdict(list)
    for src, dst in arcs:
        if src not in vertex_map or dst not in vertex_map:
            continue
        outgoing[src].append(dst)
        parents[dst].append(src)

    remaining = {node_id: len(outgoing[node_id]) for node_id in vertex_map}
    child_cost_sum = defaultdict(float)
    child_cost_min = defaultdict(lambda: math.inf)
    costs: dict[int, float] = {}

    queue = [node_id for node_id, count in remaining.items() if count == 0]
    index = 0
    while index < len(queue):
        node_id = queue[index]
        index += 1
        node = vertex_map[node_id]

        if node_id not in costs:
            if node["type"] == "LEAF":
                costs[node_id] = node_attack_cost(
                    node,
                    attack_cost_source,
                    default_action_cost,
                    default_leaf_cost,
                )
            else:
                costs[node_id] = math.inf

        for parent_id in parents[node_id]:
            parent = vertex_map[parent_id]
            if parent["type"] == "AND":
                child_cost_sum[parent_id] += costs[node_id]
            elif parent["type"] == "OR":
                child_cost_min[parent_id] = min(child_cost_min[parent_id], costs[node_id])

            remaining[parent_id] -= 1
            if remaining[parent_id] != 0:
                continue

            if parent["type"] == "LEAF":
                costs[parent_id] = node_attack_cost(
                    parent,
                    attack_cost_source,
                    default_action_cost,
                    default_leaf_cost,
                )
            elif parent["type"] == "AND":
                costs[parent_id] = node_attack_cost(
                    parent,
                    attack_cost_source,
                    default_action_cost,
                    default_leaf_cost,
                ) + child_cost_sum[parent_id]
            elif parent["type"] == "OR":
                costs[parent_id] = child_cost_min[parent_id]
            else:
                costs[parent_id] = math.inf
            queue.append(parent_id)

    return {goal: costs.get(goal, math.inf) for goal in goals}


def calibrate_goal_values(
    vertices,
    arcs: list[tuple[int, int]],
    goals: list[int],
    attack_cost_source: str,
    reward_multiplier: float,
    min_goal_reward: float,
    explicit_reward: float | None = None,
    explicit_loss: float | None = None,
    default_action_cost: float = 1.0,
    default_leaf_cost: float = 0.0,
) -> dict:
    goal_costs = estimate_goal_min_attack_costs(
        vertices=vertices,
        arcs=arcs,
        goals=goals,
        attack_cost_source=attack_cost_source,
        default_action_cost=default_action_cost,
        default_leaf_cost=default_leaf_cost,
    )
    finite_costs = [cost for cost in goal_costs.values() if math.isfinite(cost)]
    if finite_costs:
        max_cost = max(finite_costs)
        min_cost = min(finite_costs)
        avg_cost = sum(finite_costs) / len(finite_costs)
        auto_reward = max(float(min_goal_reward), math.ceil(max_cost * reward_multiplier))
    else:
        max_cost = None
        min_cost = None
        avg_cost = None
        auto_reward = float(min_goal_reward)

    reward = float(explicit_reward) if explicit_reward is not None else float(auto_reward)
    loss = float(explicit_loss) if explicit_loss is not None else reward

    return {
        "attack_cost_source": attack_cost_source,
        "reward": reward,
        "loss": loss,
        "reward_source": "explicit" if explicit_reward is not None else "auto",
        "loss_source": "explicit" if explicit_loss is not None else "same_as_reward",
        "reward_multiplier": reward_multiplier,
        "min_goal_reward": min_goal_reward,
        "goal_count": len(goals),
        "finite_goal_cost_count": len(finite_costs),
        "goal_min_attack_cost_min": min_cost,
        "goal_min_attack_cost_max": max_cost,
        "goal_min_attack_cost_avg": avg_cost,
    }
