# -*- coding: utf-8 -*-
"""Build a JSON game configuration for the MulVAL Stackelberg MIP solver.

The generated JSON is intentionally editable. For large graphs, keep the two
MulVAL CSV files fixed and change costs/rewards/defendability in this JSON
instead of passing long command-line parameter lists.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

from mulval_cost_calibration import calibrate_goal_values


def safe_print(text: str):
    encoding = sys.stdout.encoding or "utf-8"
    print(text.encode(encoding, errors="backslashreplace").decode(encoding))


def parse_csv(vertices_path: Path, arcs_path: Path):
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


def is_defendable_leaf(label: str, mode: str) -> bool:
    if label.startswith("attackerLocated"):
        return False
    if mode == "all":
        return True
    if mode == "vul":
        return label.startswith("vulExists")
    if mode == "hacl":
        return label.startswith("hacl")
    if mode == "vul_hacl":
        return label.startswith("vulExists") or label.startswith("hacl")
    raise ValueError(f"unknown defendable mode: {mode}")


def default_attack_cost(node: dict, attack_cost_source: str, action_cost: float, leaf_cost: float) -> float:
    node_type = node["type"]
    if node_type in {"OR", "LEAF"}:
        return 0.0
    if node_type == "AND" and attack_cost_source == "score" and node["score"] > 0:
        return float(node["score"])
    if node_type == "AND":
        return action_cost
    return 0.0


def parse_goal_ids(raw: str | None) -> list[int] | None:
    if not raw:
        return None
    return [int(part.strip()) for part in raw.split(",") if part.strip()]


def parse_summary_goal_ids(path: str | None) -> list[int] | None:
    if not path:
        return None
    with Path(path).open(encoding="utf-8") as f:
        data = json.load(f)
    goals = data.get("goals")
    if not goals:
        return None
    return [int(goal) for goal in goals]


def select_goals(
    vertices: dict[int, dict],
    arcs: list[tuple[int, int]],
    goal_ids: list[int] | None,
    summary_goal_ids: list[int] | None,
) -> tuple[list[int], str]:
    if goal_ids:
        return sorted(goal_ids), "cli"

    if summary_goal_ids:
        return sorted(summary_goal_ids), "summary"

    synthetic_goals = sorted(
        node_id
        for node_id, node in vertices.items()
        if node["type"] == "OR" and node["label"].startswith("execCode(crown_jewel_")
    )
    if synthetic_goals:
        return synthetic_goals, "synthetic_crown_jewel_label"

    indegree = Counter()
    for src, dst in arcs:
        indegree[dst] += 1

    return sorted(
        node_id
        for node_id, node in vertices.items()
        if node["type"] == "OR" and indegree[node_id] == 0
    ), "or_indegree_zero"


def build_config(
    vertices,
    arcs,
    goal_ids: list[int] | None,
    summary_goal_ids: list[int] | None,
    defendable_mode: str,
    goal_reward: float | None,
    goal_loss: float | None,
    defense_cost: float,
    attack_cost_source: str,
    action_attack_cost: float,
    leaf_attack_cost: float,
    budget: float | None,
    cost_big_m: float | None,
    target_closure: bool,
    solver: str,
    reward_multiplier: float,
    min_goal_reward: float,
):
    goals, goal_source = select_goals(vertices, arcs, goal_ids, summary_goal_ids)
    missing_goals = [goal for goal in goals if goal not in vertices]
    if missing_goals:
        raise SystemExit(f"Unknown goal id(s): {missing_goals}")

    calibration = calibrate_goal_values(
        vertices=vertices,
        arcs=arcs,
        goals=goals,
        attack_cost_source=attack_cost_source,
        reward_multiplier=reward_multiplier,
        min_goal_reward=min_goal_reward,
        explicit_reward=goal_reward,
        explicit_loss=goal_loss,
        default_action_cost=action_attack_cost,
        default_leaf_cost=leaf_attack_cost,
    )
    goal_reward = calibration["reward"]
    goal_loss = calibration["loss"]

    nodes = []
    for node_id, node in sorted(vertices.items()):
        node_type = node["type"]
        item = {
            "id": node_id,
            "type": node_type,
            "label": node["label"],
            "score": node["score"],
            "attack_cost": default_attack_cost(
                node=node,
                attack_cost_source=attack_cost_source,
                action_cost=action_attack_cost,
                leaf_cost=leaf_attack_cost,
            ),
        }

        if node_type == "LEAF":
            defendable = is_defendable_leaf(node["label"], defendable_mode)
            item["defendable"] = defendable
            item["defense_cost"] = defense_cost if defendable else None
        else:
            item["defendable"] = False
            item["defense_cost"] = None

        nodes.append(item)

    return {
        "schema": "mulval_stackelberg_game_config_v1",
        "metadata": {
            "vertices": len(vertices),
            "arcs": len(arcs),
            "type_counts": dict(Counter(node["type"] for node in vertices.values())),
            "edge_direction": "conclusion -> prerequisite",
            "goal_source": goal_source,
            "notes": [
                "Edit goal reward/loss values in goals.",
                "Edit AND attack_cost values and LEAF defendable/defense_cost values in nodes.",
                "The solver does not enumerate attack paths; it computes minimum AND/OR derivation cost implicitly.",
                "When goal reward/loss is not provided, values are calibrated from no-defense minimum goal costs.",
            ],
            "reward_calibration": calibration,
        },
        "defaults": {
            "defendable_mode": defendable_mode,
            "goal_reward": goal_reward,
            "goal_loss": goal_loss,
            "defense_cost": defense_cost,
            "budget": budget,
            "attack_cost_source": attack_cost_source,
            "action_attack_cost": action_attack_cost,
            "leaf_attack_cost": leaf_attack_cost,
            "cost_big_m": cost_big_m,
            "target_closure": target_closure,
            "solver": solver,
        },
        "goals": [
            {
                "id": node_id,
                "label": vertices[node_id]["label"],
                "enabled": True,
                "reward": goal_reward,
                "loss": goal_loss,
            }
            for node_id in goals
        ],
        "nodes": nodes,
    }


def main():
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--vertices", default=str(script_dir / "VERTICES.CSV"))
    parser.add_argument("--arcs", default=str(script_dir / "ARCS.CSV"))
    parser.add_argument("--out", default=str(script_dir / "mulval_game_config.json"))
    parser.add_argument(
        "--goals",
        default=None,
        help=(
            "Comma-separated goal node ids. These are ids, not a count. "
            "If omitted, summary goals or synthetic crown_jewel goals are used when available."
        ),
    )
    parser.add_argument(
        "--summary",
        default=None,
        help="Optional summary JSON produced by generate_large_mulval_csv.py; its goals list is used as target ids.",
    )
    parser.add_argument(
        "--defendable",
        choices=["all", "vul", "hacl", "vul_hacl"],
        default="all",
    )
    parser.add_argument(
        "--goal-reward",
        type=float,
        default=None,
        help="Override the auto-calibrated goal reward.",
    )
    parser.add_argument(
        "--goal-loss",
        type=float,
        default=None,
        help="Override the auto-calibrated goal loss. Defaults to the calibrated reward.",
    )
    parser.add_argument("--defense-cost", type=float, default=1.0)
    parser.add_argument(
        "--attack-cost-source",
        choices=["constant", "score"],
        default="score",
    )
    parser.add_argument("--action-attack-cost", type=float, default=1.0)
    parser.add_argument(
        "--leaf-attack-cost",
        type=float,
        default=0.0,
        help="Compatibility option; generated LEAF attack_cost values are fixed to 0.",
    )
    parser.add_argument(
        "--reward-multiplier",
        type=float,
        default=2.0,
        help="Auto reward is at least this multiplier times the largest no-defense goal cost.",
    )
    parser.add_argument(
        "--min-goal-reward",
        type=float,
        default=1000.0,
        help="Minimum auto-calibrated reward/loss value.",
    )
    parser.add_argument("--budget", type=float, default=None)
    parser.add_argument("--cost-big-m", type=float, default=None)
    parser.add_argument(
        "--target-closure",
        action="store_true",
        help=(
            "Record that the solver should reduce the graph to the selected "
            "targets' dependency closure before building the MIP."
        ),
    )
    parser.add_argument(
        "--solver",
        choices=["scip", "gurobi"],
        default="scip",
        help="Record the default MIP solver backend in the generated config.",
    )
    args = parser.parse_args()

    vertices, arcs = parse_csv(Path(args.vertices), Path(args.arcs))
    config = build_config(
        vertices=vertices,
        arcs=arcs,
        goal_ids=parse_goal_ids(args.goals),
        summary_goal_ids=parse_summary_goal_ids(args.summary),
        defendable_mode=args.defendable,
        goal_reward=args.goal_reward,
        goal_loss=args.goal_loss,
        defense_cost=args.defense_cost,
        attack_cost_source=args.attack_cost_source,
        action_attack_cost=args.action_attack_cost,
        leaf_attack_cost=args.leaf_attack_cost,
        budget=args.budget,
        cost_big_m=args.cost_big_m,
        target_closure=args.target_closure,
        solver=args.solver,
        reward_multiplier=args.reward_multiplier,
        min_goal_reward=args.min_goal_reward,
    )

    out_path = Path(args.out)
    out_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")

    safe_print(f"wrote: {out_path.resolve()}")
    safe_print(f"goals: {[goal['id'] for goal in config['goals']]}")
    safe_print(f"nodes: {len(config['nodes'])}")
    safe_print(f"defendable leaves: {sum(1 for node in config['nodes'] if node['defendable'])}")
    calibration = config["metadata"].get("reward_calibration", {})
    safe_print(
        "cost/reward: "
        f"source={config['defaults']['attack_cost_source']} "
        f"reward={config['defaults']['goal_reward']} "
        f"loss={config['defaults']['goal_loss']} "
        f"max_goal_cost={calibration.get('goal_min_attack_cost_max')}"
    )


if __name__ == "__main__":
    main()
