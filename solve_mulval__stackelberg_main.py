# -*- coding: utf-8 -*-
"""Cost-sensitive Stackelberg game for a MulVAL AND/OR attack graph.

This model does NOT enumerate attack paths/plans.

Game semantics:
  1. Defender commits to a set of defenses on LEAF facts.
  2. The MulVAL AND/OR graph propagates which nodes remain reachable.
  3. For every reachable node, the model computes a minimum derivation cost:
       - LEAF: 0 if the fact is available;
       - AND: action cost + all prerequisite costs;
       - OR: minimum cost among reachable child derivations.
  4. The attacker observes the defense and chooses:
       - empty attack if every reachable goal has non-positive net utility;
       - otherwise a reachable goal with maximum net utility.

Attacker net utility for goal g:
  reward_g - min_attack_cost_g

Defender objective:
  defense_cost + loss_of_attacker_chosen_goal

The attacker response is represented by target-choice variables only. The
attack path itself is not enumerated; the least-cost derivation is represented
implicitly by the AND/OR cost constraints.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path


DEFAULT_KEY_PATH_MAX_NONIMPROVING_STEPS = 64


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


def parse_goal_ids(raw: str | None, default_goals: list[int]) -> list[int]:
    if not raw:
        return default_goals
    return [int(part.strip()) for part in raw.split(",") if part.strip()]


def parse_weight_map(raw: str | None, ids: list[int], default_value: float) -> dict[int, float]:
    """Parse either JSON {"1": 100} or comma form 1:100,55:80."""
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
    """Parse JSON {"12": 3.5} or comma form 12:3.5,18:2."""
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


def load_game_config(path: str | None) -> dict:
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


def coalesce(*values):
    for value in values:
        if value is not None:
            return value
    return None


def node_attack_cost(
    node_id: int,
    node: dict,
    explicit_costs: dict[int, float],
    config_costs: dict[int, float],
    attack_cost_source: str,
    default_action_cost: float,
    default_leaf_cost: float,
) -> float:
    node_type = node["type"]
    if node_type in {"OR", "LEAF"}:
        return 0.0

    if node_id in explicit_costs:
        return explicit_costs[node_id]
    if node_id in config_costs:
        return config_costs[node_id]

    if node_type == "AND" and attack_cost_source == "score" and node["score"] > 0:
        return node["score"]

    if node_type == "AND":
        return default_action_cost
    return 0.0


def compute_cost_big_m(vertices: dict[int, dict], node_costs: dict[int, float]) -> float:
    max_single_cost = max([1.0] + [abs(cost) for cost in node_costs.values()])
    return (len(vertices) + 1) * max_single_cost + 1.0


def validate_nonnegative_values(name: str, values: dict[int, float]):
    negative = [(node_id, value) for node_id, value in values.items() if value < 0]
    if negative:
        preview = ", ".join(f"{node_id}:{value}" for node_id, value in negative[:10])
        raise SystemExit(f"{name} must be non-negative for safe cost bounds. Found: {preview}")


def compute_cost_upper_bounds(
    vertices: dict[int, dict],
    arcs: list[tuple[int, int]],
    node_costs: dict[int, float],
    fallback_big_m: float,
) -> tuple[dict[int, float], dict]:
    """Compute local safe upper bounds for minimum derivation costs.

    Edges use conclusion -> prerequisite. For a DAG, a node's safe upper
    bound under any defense is:
      LEAF = 0
      AND  = action cost + sum(prerequisite upper bounds)
      OR   = max(prerequisite upper bounds)

    OR uses max, not min, because defenses may remove cheaper alternatives.
    If a cycle is present, the cycle-affected nodes fall back to the legacy
    global Big-M so the model remains buildable.
    """
    outgoing = defaultdict(list)
    parents = defaultdict(list)
    for src, dst in arcs:
        if src not in vertices or dst not in vertices:
            continue
        outgoing[src].append(dst)
        parents[dst].append(src)

    remaining_children = {node_id: len(outgoing[node_id]) for node_id in vertices}
    child_upper_sum = defaultdict(float)
    child_upper_max = defaultdict(float)
    cost_upper: dict[int, float] = {}

    queue = sorted(node_id for node_id, count in remaining_children.items() if count == 0)
    index = 0
    while index < len(queue):
        node_id = queue[index]
        index += 1
        node_type = vertices[node_id]["type"]

        if node_id not in cost_upper:
            if node_type == "LEAF":
                cost_upper[node_id] = node_costs[node_id]
            elif node_type in {"AND", "OR"}:
                cost_upper[node_id] = 0.0
            else:
                raise SystemExit(f"Unknown node type for {node_id}: {node_type}")

        for parent_id in parents[node_id]:
            parent_type = vertices[parent_id]["type"]
            if parent_type == "AND":
                child_upper_sum[parent_id] += cost_upper[node_id]
            elif parent_type == "OR":
                child_upper_max[parent_id] = max(child_upper_max[parent_id], cost_upper[node_id])

            remaining_children[parent_id] -= 1
            if remaining_children[parent_id] != 0:
                continue

            if parent_type == "LEAF":
                cost_upper[parent_id] = node_costs[parent_id]
            elif parent_type == "AND":
                cost_upper[parent_id] = node_costs[parent_id] + child_upper_sum[parent_id]
            elif parent_type == "OR":
                cost_upper[parent_id] = child_upper_max[parent_id]
            else:
                raise SystemExit(f"Unknown node type for {parent_id}: {parent_type}")
            queue.append(parent_id)

    fallback_nodes = sorted(node_id for node_id in vertices if node_id not in cost_upper)
    for node_id in fallback_nodes:
        cost_upper[node_id] = fallback_big_m

    values = list(cost_upper.values())
    stats = {
        "formulation": "local_dag_upper_bounds",
        "fallback_due_to_cycle": bool(fallback_nodes),
        "fallback_node_count": len(fallback_nodes),
        "fallback_big_m": fallback_big_m,
        "min": min(values) if values else 0.0,
        "max": max(values) if values else 0.0,
        "avg": sum(values) / len(values) if values else 0.0,
    }
    if fallback_nodes:
        stats["formulation"] = "local_bounds_with_global_fallback_for_cycles"
        stats["sample_fallback_nodes"] = fallback_nodes[:10]
    return cost_upper, stats


def build_graph_indexes(arcs: list[tuple[int, int]]):
    outgoing = defaultdict(list)
    indegree = Counter()
    for src, dst in arcs:
        outgoing[src].append(dst)
        indegree[dst] += 1
    return outgoing, indegree


def compute_dependency_closure(
    vertices: dict[int, dict],
    arcs: list[tuple[int, int]],
    goals: list[int],
):
    """Keep only goal nodes and their recursive prerequisites.

    MulVAL CSV edges use conclusion -> prerequisite, so the dependency closure
    is the set reached by traversing outgoing arcs from each goal.
    """
    missing_goals = [goal for goal in goals if goal not in vertices]
    if missing_goals:
        raise SystemExit(f"Unknown goal id(s): {missing_goals}")

    outgoing, _ = build_graph_indexes(arcs)
    kept_ids = set(goals)
    stack = list(goals)
    while stack:
        node_id = stack.pop()
        for child in outgoing[node_id]:
            if child not in vertices:
                continue
            if child not in kept_ids:
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
    return reduced_vertices, reduced_arcs, kept_ids, stats


def evaluate_defense_state(
    vertices: dict[int, dict],
    arcs: list[tuple[int, int]],
    attack_costs: dict[int, float],
    defended: set[int],
) -> dict:
    """Evaluate reachability and minimum derivation costs for fixed defenses.

    The returned state follows exactly the AND/OR and cost semantics used by
    the MIP. It also records the minimum-cost child selected at each reachable
    OR node, so it can be submitted as a complete MIP start.
    """
    outgoing, _ = build_graph_indexes(arcs)
    parents = defaultdict(list)
    remaining = {node_id: 0 for node_id in vertices}
    for source, target in arcs:
        if source in vertices and target in vertices:
            parents[target].append(source)
            remaining[source] += 1

    queue = sorted(node_id for node_id, count in remaining.items() if count == 0)
    order = []
    index = 0
    while index < len(queue):
        node_id = queue[index]
        index += 1
        order.append(node_id)
        for parent_id in parents[node_id]:
            remaining[parent_id] -= 1
            if remaining[parent_id] == 0:
                queue.append(parent_id)

    if len(order) != len(vertices):
        raise ValueError("Key-path warm start requires an acyclic dependency graph")

    reachable = {}
    min_cost = {}
    or_choice = {}
    for node_id in order:
        node_type = vertices[node_id]["type"]
        children = [child for child in outgoing[node_id] if child in vertices]
        if node_type == "LEAF":
            reachable[node_id] = node_id not in defended
            min_cost[node_id] = 0.0
        elif node_type == "AND":
            reachable[node_id] = bool(children) and all(reachable[child] for child in children)
            min_cost[node_id] = (
                attack_costs[node_id] + sum(min_cost[child] for child in children)
                if reachable[node_id]
                else 0.0
            )
        elif node_type == "OR":
            candidates = [child for child in children if reachable[child]]
            if candidates:
                chosen_child = min(candidates, key=lambda child: (min_cost[child], child))
                reachable[node_id] = True
                min_cost[node_id] = min_cost[chosen_child]
                or_choice[node_id] = chosen_child
            else:
                reachable[node_id] = False
                min_cost[node_id] = 0.0
        else:
            raise ValueError(f"Unknown node type for {node_id}: {node_type}")

    return {"reachable": reachable, "min_cost": min_cost, "or_choice": or_choice}


def choose_attacker_response(state: dict, goals: list[int], rewards: dict[int, float], losses: dict[int, float]):
    """Return the optimistic defender-favorable best response represented by the MIP."""
    utilities = {
        goal: rewards[goal] - state["min_cost"][goal]
        for goal in goals
        if state["reachable"][goal]
    }
    max_utility = max([0.0] + list(utilities.values()))
    if max_utility <= 1e-9:
        return None, 0.0
    best_goals = [
        goal for goal, utility in utilities.items()
        if abs(utility - max_utility) <= 1e-9
    ]
    return min(best_goals, key=lambda goal: (losses[goal], goal)), max_utility


def key_path_defendable_leaves(
    goal: int,
    vertices: dict[int, dict],
    outgoing: dict[int, list[int]],
    state: dict,
    defendable: set[int],
) -> list[int]:
    """Collect defendable leaves in deterministic current-path traversal order."""
    leaves = []
    leaf_seen = set()
    visited = set()
    stack = [goal]
    while stack:
        node_id = stack.pop()
        if node_id in visited:
            continue
        visited.add(node_id)
        node_type = vertices[node_id]["type"]
        if node_type == "LEAF":
            if node_id in defendable and node_id not in leaf_seen:
                leaves.append(node_id)
                leaf_seen.add(node_id)
        elif node_type == "AND":
            # Stack is LIFO: reverse preserves CSV prerequisite order during traversal.
            stack.extend(reversed([child for child in outgoing[node_id] if child in vertices]))
        elif node_type == "OR":
            child = state["or_choice"].get(node_id)
            if child is not None:
                stack.append(child)
    return leaves


def build_key_path_warm_start(
    vertices: dict[int, dict],
    arcs: list[tuple[int, int]],
    attack_costs: dict[int, float],
    defendable: list[int],
    defense_costs: dict[int, float],
    default_defense_cost: float,
    budget: float | None,
    goals: list[int],
    rewards: dict[int, float],
    losses: dict[int, float],
    max_nonimproving_steps: int = DEFAULT_KEY_PATH_MAX_NONIMPROVING_STEPS,
) -> dict:
    """Greedily defend key paths while retaining the best encountered state.

    A single defense may only make the attacker switch to an equivalent path.
    Limited non-improving steps let the heuristic cross that plateau and block
    several parallel paths before deciding whether their combination is useful.
    """
    if max_nonimproving_steps < 0:
        raise ValueError("max_nonimproving_steps must be non-negative")

    outgoing, _ = build_graph_indexes(arcs)
    defendable_set = set(defendable)
    defended = set()
    state = evaluate_defense_state(vertices, arcs, attack_costs, defended)
    selected_goal, attacker_utility = choose_attacker_response(state, goals, rewards, losses)

    initial_objective = losses[selected_goal] if selected_goal is not None else 0.0
    best_snapshot = {
        "defended": set(),
        "state": state,
        "selected_goal": selected_goal,
        "attacker_utility": attacker_utility,
        "defense_total": 0.0,
        "objective": initial_objective,
        "iterations": 0,
    }
    explored_iterations = 0
    consecutive_nonimproving_steps = 0

    while selected_goal is not None:
        current_defense_cost = sum(
            defense_costs.get(node_id, default_defense_cost)
            for node_id in defended
        )
        candidates = [
            candidate
            for candidate in key_path_defendable_leaves(
                selected_goal, vertices, outgoing, state, defendable_set
            )
            if candidate not in defended
        ]
        feasible_candidate_costs = [
            current_defense_cost + defense_costs.get(candidate, default_defense_cost)
            for candidate in candidates
            if budget is None
            or current_defense_cost + defense_costs.get(candidate, default_defense_cost) <= budget + 1e-9
        ]
        minimum_candidate_cost = min(feasible_candidate_costs, default=None)
        best = None
        for candidate in candidates:
            candidate_defended = defended | {candidate}
            candidate_defense_cost = current_defense_cost + defense_costs.get(candidate, default_defense_cost)
            if budget is not None and candidate_defense_cost > budget + 1e-9:
                continue
            candidate_state = evaluate_defense_state(vertices, arcs, attack_costs, candidate_defended)
            candidate_goal, candidate_utility = choose_attacker_response(
                candidate_state, goals, rewards, losses
            )
            candidate_objective = candidate_defense_cost + (
                losses[candidate_goal] if candidate_goal is not None else 0.0
            )
            candidate_rank = (
                candidate_objective,
                candidate_utility,
                candidate_defense_cost,
                candidate,
            )
            if best is None or candidate_rank < best[0]:
                best = (candidate_rank, candidate, candidate_state, candidate_goal, candidate_utility)
            # With zero attack loss and the lowest available added defense cost,
            # no later candidate can improve this iteration's objective.
            if candidate_goal is None and candidate_defense_cost <= minimum_candidate_cost + 1e-9:
                break

        if best is None:
            break

        candidate_objective = best[0][0]
        improves_best = candidate_objective < best_snapshot["objective"] - 1e-9
        if not improves_best and consecutive_nonimproving_steps >= max_nonimproving_steps:
            break

        _, selected_leaf, state, selected_goal, attacker_utility = best
        defended.add(selected_leaf)
        explored_iterations += 1
        defense_total = sum(
            defense_costs.get(node_id, default_defense_cost)
            for node_id in defended
        )
        objective = defense_total + (
            losses[selected_goal] if selected_goal is not None else 0.0
        )
        if objective < best_snapshot["objective"] - 1e-9:
            best_snapshot = {
                "defended": set(defended),
                "state": state,
                "selected_goal": selected_goal,
                "attacker_utility": attacker_utility,
                "defense_total": defense_total,
                "objective": objective,
                "iterations": explored_iterations,
            }
            consecutive_nonimproving_steps = 0
        else:
            consecutive_nonimproving_steps += 1

    best_snapshot["explored_iterations"] = explored_iterations
    best_snapshot["max_nonimproving_steps"] = max_nonimproving_steps
    best_snapshot["stopped_after_nonimproving_steps"] = consecutive_nonimproving_steps
    return best_snapshot


def submit_warm_start(
    model,
    solver: str,
    x: dict,
    d: dict,
    c: dict,
    or_selectors: dict[tuple[int, int], object],
    y_empty,
    y_goal: dict,
    attacker_max_utility,
    warm_start: dict,
) -> dict:
    """Submit a complete, feasible key-path solution to SCIP or Gurobi."""
    state = warm_start["state"]
    assignments = []
    assignments.extend((x[node_id], float(state["reachable"][node_id])) for node_id in x)
    assignments.extend((d[node_id], float(node_id in warm_start["defended"])) for node_id in d)
    assignments.extend((c[node_id], state["min_cost"][node_id]) for node_id in c)
    assignments.extend(
        (selector, float(state["or_choice"].get(or_id) == child_id))
        for (or_id, child_id), selector in or_selectors.items()
    )
    assignments.append((y_empty, float(warm_start["selected_goal"] is None)))
    assignments.extend(
        (variable, float(goal == warm_start["selected_goal"]))
        for goal, variable in y_goal.items()
    )
    assignments.append((attacker_max_utility, warm_start["attacker_utility"]))

    if solver == "scip":
        solution = model.createSol()
        for variable, value in assignments:
            model.setSolVal(solution, variable, value)
        accepted = bool(model.addSol(solution, free=True))
        return {"submitted": True, "accepted": accepted}
    if solver == "gurobi":
        for variable, value in assignments:
            variable.Start = value
        return {"submitted": True, "accepted": None}
    return {"submitted": False, "accepted": None, "reason": f"Unsupported solver: {solver}"}


class GurobiModelAdapter:
    """Small adapter so the model-building code can support SCIP and Gurobi."""

    def __init__(self, name: str, time_limit: float | None, mip_gap: float | None):
        try:
            import gurobipy as gp
        except ImportError as exc:
            raise SystemExit(
                "gurobipy is not installed in this Python environment. "
                "Install it and make sure a valid Gurobi license is available."
            ) from exc

        self.gp = gp
        self.GRB = gp.GRB
        self.model = gp.Model(name)
        if time_limit is not None:
            self.model.Params.TimeLimit = time_limit
        if mip_gap is not None:
            self.model.Params.MIPGap = mip_gap

    def addVar(self, vtype: str, lb: float = 0.0, ub=None, name: str | None = None):
        var_type = {
            "B": self.GRB.BINARY,
            "C": self.GRB.CONTINUOUS,
        }.get(vtype, vtype)
        kwargs = {"vtype": var_type, "lb": lb}
        if name is not None:
            kwargs["name"] = name
        if ub is not None:
            kwargs["ub"] = ub
        return self.model.addVar(**kwargs)

    def addCons(self, expr, name: str | None = None):
        if name is None:
            return self.model.addConstr(expr)
        return self.model.addConstr(expr, name=name)

    def setObjective(self, expr, sense: str):
        if sense != "minimize":
            raise ValueError(f"unsupported Gurobi objective sense: {sense}")
        self.model.setObjective(expr, self.GRB.MINIMIZE)

    def writeProblem(self, path: str):
        self.model.update()
        self.model.write(path)

    def optimize(self):
        self.model.optimize()

    def getStatus(self):
        status_map = {
            self.GRB.OPTIMAL: "optimal",
            self.GRB.TIME_LIMIT: "timelimit",
            self.GRB.INFEASIBLE: "infeasible",
            self.GRB.INF_OR_UNBD: "inforunbd",
            self.GRB.UNBOUNDED: "unbounded",
            self.GRB.INTERRUPTED: "interrupted",
            self.GRB.NUMERIC: "numeric",
            self.GRB.SUBOPTIMAL: "suboptimal",
        }
        return status_map.get(self.model.Status, str(self.model.Status))

    def getNSols(self):
        return self.model.SolCount

    def getObjVal(self):
        return self.model.ObjVal

    def getGap(self):
        return self.model.MIPGap

    def getVal(self, var):
        return var.X


def create_model_backend(solver: str, time_limit: float | None, mip_gap: float | None):
    if solver == "scip":
        try:
            from pyscipopt import Model, quicksum
        except ImportError as exc:
            raise SystemExit(
                "PySCIPOpt is not installed in this Python environment. "
                "Install it with: pip install pyscipopt"
            ) from exc

        model = Model("mulval_cost_sensitive_stackelberg")
        if time_limit is not None:
            model.setRealParam("limits/time", time_limit)
        if mip_gap is not None:
            model.setRealParam("limits/gap", mip_gap)
        return model, quicksum

    if solver == "gurobi":
        try:
            import gurobipy as gp
        except ImportError as exc:
            raise SystemExit(
                "gurobipy is not installed in this Python environment. "
                "Install it and make sure a valid Gurobi license is available."
            ) from exc
        return GurobiModelAdapter("mulval_cost_sensitive_stackelberg", time_limit, mip_gap), gp.quicksum

    raise SystemExit(f"Unknown solver: {solver}")


def solve_game(
    vertices,
    arcs,
    game_config: dict | None,
    goal_ids: list[int] | None,
    default_reward: float,
    default_loss: float,
    goal_rewards_raw: str | None,
    goal_losses_raw: str | None,
    default_defense_cost: float,
    defense_costs_raw: str | None,
    defendable_mode: str | None,
    budget: float | None,
    attack_cost_source: str,
    default_action_cost: float,
    default_leaf_cost: float,
    node_attack_costs_raw: str | None,
    cost_big_m_override: float | None,
    target_closure: bool | None,
    time_limit: float | None,
    mip_gap: float | None,
    warm_start_key_path: bool | None,
    solver: str | None,
    write_lp: str | None,
):
    timings = {}
    stage_start = time.perf_counter()

    original_vertices_count = len(vertices)
    original_arcs_count = len(arcs)
    outgoing, indegree = build_graph_indexes(arcs)

    default_goals = sorted(
        node_id
        for node_id, node in vertices.items()
        if node["type"] == "OR" and indegree[node_id] == 0
    )

    config = game_config or {}
    config_defaults = config.get("defaults", {})
    config_goals = normalize_id_map(config.get("goals"))
    config_nodes = normalize_id_map(config.get("nodes"))
    timings["prepare_goals_and_config"] = time.perf_counter() - stage_start

    stage_start = time.perf_counter()
    defendable_mode_from_cli = defendable_mode is not None
    default_reward = float(config_defaults.get("goal_reward", default_reward))
    default_loss = float(config_defaults.get("goal_loss", default_loss))
    default_defense_cost = float(config_defaults.get("defense_cost", default_defense_cost))
    defendable_mode = coalesce(defendable_mode, config_defaults.get("defendable_mode"), "all")
    budget = coalesce(budget, config_defaults.get("budget"))
    attack_cost_source = coalesce(attack_cost_source, config_defaults.get("attack_cost_source"), "constant")
    default_action_cost = float(config_defaults.get("action_attack_cost", default_action_cost))
    default_leaf_cost = float(config_defaults.get("leaf_attack_cost", default_leaf_cost))
    cost_big_m_override = coalesce(cost_big_m_override, config_defaults.get("cost_big_m"))
    target_closure = bool(coalesce(target_closure, config_defaults.get("target_closure"), False))
    mip_gap = coalesce(mip_gap, config_defaults.get("mip_gap"))
    if mip_gap is not None:
        mip_gap = float(mip_gap)
        if mip_gap < 0:
            raise SystemExit("--mip-gap must be non-negative")
    solver = coalesce(solver, config_defaults.get("solver"), "scip")
    warm_start_key_path = bool(
        coalesce(warm_start_key_path, config_defaults.get("warm_start_key_path"), False)
    )

    if goal_ids:
        goals = parse_goal_ids(",".join(map(str, goal_ids)), default_goals)
    elif config_goals:
        goals = sorted(
            node_id
            for node_id, item in config_goals.items()
            if item.get("enabled", True)
        )
    else:
        goals = default_goals

    if not goals:
        raise SystemExit("No goals found. Pass --goals id1,id2 or use OR nodes with indegree 0.")

    for goal in goals:
        if goal not in vertices:
            raise SystemExit(f"Unknown goal id: {goal}")
    timings["resolve_game_defaults"] = time.perf_counter() - stage_start

    stage_start = time.perf_counter()
    target_closure_stats = {
        "enabled": target_closure,
        "original_vertices": original_vertices_count,
        "original_arcs": original_arcs_count,
        "reduced_vertices": len(vertices),
        "reduced_arcs": len(arcs),
        "removed_vertices": 0,
        "removed_arcs": 0,
        "goal_count": len(goals),
    }
    if target_closure:
        vertices, arcs, _, target_closure_stats = compute_dependency_closure(vertices, arcs, goals)
        outgoing, indegree = build_graph_indexes(arcs)
    timings["target_closure"] = time.perf_counter() - stage_start

    stage_start = time.perf_counter()
    rewards = parse_weight_map(goal_rewards_raw, goals, default_reward)
    losses = parse_weight_map(goal_losses_raw, goals, default_loss)
    for goal in goals:
        goal_config = config_goals.get(goal, {})
        if "reward" in goal_config and not goal_rewards_raw:
            rewards[goal] = float(goal_config["reward"])
        if "loss" in goal_config and not goal_losses_raw:
            losses[goal] = float(goal_config["loss"])

    defense_costs = parse_node_costs(defense_costs_raw)
    config_defense_costs = {
        node_id: float(item["defense_cost"])
        for node_id, item in config_nodes.items()
        if item.get("defense_cost") is not None
    }
    if not defense_costs_raw:
        defense_costs.update(config_defense_costs)

    explicit_attack_costs = parse_node_costs(node_attack_costs_raw)
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

    legacy_cost_big_m = (
        cost_big_m_override
        if cost_big_m_override is not None
        else compute_cost_big_m(vertices, attack_costs)
    )
    if legacy_cost_big_m < 0:
        raise SystemExit("--cost-big-m must be non-negative")

    cost_upper_bounds, cost_upper_stats = compute_cost_upper_bounds(
        vertices=vertices,
        arcs=arcs,
        node_costs=attack_costs,
        fallback_big_m=legacy_cost_big_m,
    )
    cost_big_m = cost_upper_stats["max"]

    utility_upper_bound = max([0.0] + [rewards[g] for g in goals])
    utility_goal_big_m = {
        g: utility_upper_bound - min(0.0, rewards[g] - cost_upper_bounds[g])
        for g in goals
    }
    utility_empty_big_m = utility_upper_bound
    utility_big_m = max([utility_empty_big_m] + list(utility_goal_big_m.values()) + [0.0])

    leaves = sorted(node_id for node_id, node in vertices.items() if node["type"] == "LEAF")
    if defendable_mode_from_cli:
        defendable = [
            node_id
            for node_id in leaves
            if is_defendable_leaf(vertices[node_id]["label"], defendable_mode)
        ]
    else:
        defendable = [
            node_id
            for node_id in leaves
            if bool(
                config_nodes.get(node_id, {}).get(
                    "defendable",
                    is_defendable_leaf(vertices[node_id]["label"], defendable_mode),
                )
            )
        ]
    nondefendable = [node_id for node_id in leaves if node_id not in defendable]
    timings["build_parameters"] = time.perf_counter() - stage_start

    stage_start = time.perf_counter()
    model, quicksum = create_model_backend(solver, time_limit, mip_gap)

    # x_i: node i is true/reachable after defense.
    x = {node_id: model.addVar(vtype="B", name=f"x_{node_id}") for node_id in sorted(vertices)}

    # d_i: defender disables LEAF i.
    d = {node_id: model.addVar(vtype="B", name=f"d_{node_id}") for node_id in defendable}

    # c_i: minimum attack derivation cost for node i if x_i = 1; zero when x_i = 0.
    c = {
        node_id: model.addVar(
            vtype="C",
            lb=0.0,
            ub=cost_upper_bounds[node_id],
            name=f"min_cost_{node_id}",
        )
        for node_id in sorted(vertices)
    }

    # y_empty / y_goal: attacker response. These variables choose only the
    # final target (or empty attack), not a concrete attack path.
    y_empty = model.addVar(vtype="B", name="choose_empty")
    y_goal = {goal: model.addVar(vtype="B", name=f"choose_goal_{goal}") for goal in goals}

    # OR child choices used by the minimum-cost formulation.  Retaining these
    # variables lets the key-path heuristic submit a complete feasible solution.
    or_selectors = {}

    # U: maximum attacker net utility across all reachable goals and empty attack.
    # This avoids pairwise goal comparisons and keeps best-response constraints
    # linear in the number of goals.
    attacker_max_utility = model.addVar(
        vtype="C",
        lb=0.0,
        ub=utility_upper_bound,
        name="attacker_max_utility",
    )

    # LEAF semantics: defendable facts are true unless defended; non-defendable
    # facts remain true.
    for node_id in defendable:
        model.addCons(x[node_id] + d[node_id] == 1, name=f"leaf_{node_id}_defense_link")
    for node_id in nondefendable:
        model.addCons(x[node_id] == 1, name=f"leaf_{node_id}_fixed_true")

    # MulVAL AND/OR reachability semantics. CSV edge direction is
    # conclusion -> prerequisite.
    for node_id, node in sorted(vertices.items()):
        children = sorted(outgoing[node_id])
        node_type = node["type"]
        if node_type == "AND":
            if not children:
                model.addCons(x[node_id] == 0, name=f"and_{node_id}_no_child_false")
                continue
            for child in children:
                model.addCons(x[node_id] <= x[child], name=f"and_{node_id}_requires_{child}")
            model.addCons(
                x[node_id] >= quicksum(x[child] for child in children) - (len(children) - 1),
                name=f"and_{node_id}_all_preconditions_suffice",
            )
        elif node_type == "OR":
            if not children:
                model.addCons(x[node_id] == 0, name=f"or_{node_id}_no_child_false")
                continue
            for child in children:
                model.addCons(x[node_id] >= x[child], name=f"or_{node_id}_enabled_by_{child}")
            model.addCons(
                x[node_id] <= quicksum(x[child] for child in children),
                name=f"or_{node_id}_needs_one_child",
            )

    # Minimum-cost derivation semantics.
    for node_id, node in sorted(vertices.items()):
        children = sorted(outgoing[node_id])
        node_type = node["type"]

        node_cost_upper = cost_upper_bounds[node_id]
        model.addCons(c[node_id] <= node_cost_upper * x[node_id], name=f"cost_{node_id}_zero_if_unreachable")

        if node_type == "LEAF":
            model.addCons(c[node_id] == attack_costs[node_id] * x[node_id], name=f"cost_leaf_{node_id}")

        elif node_type == "AND":
            if not children:
                model.addCons(c[node_id] == 0.0, name=f"cost_and_{node_id}_no_child")
                continue
            rhs = attack_costs[node_id] + quicksum(c[child] for child in children)
            model.addCons(
                c[node_id] >= rhs - node_cost_upper * (1 - x[node_id]),
                name=f"cost_and_{node_id}_lower",
            )
            model.addCons(
                c[node_id] <= rhs + node_cost_upper * (1 - x[node_id]),
                name=f"cost_and_{node_id}_upper",
            )

        elif node_type == "OR":
            if not children:
                model.addCons(c[node_id] == 0.0, name=f"cost_or_{node_id}_no_child")
                continue

            selected_children = []
            for child in children:
                selector = model.addVar(vtype="B", name=f"or_{node_id}_select_{child}")
                or_selectors[(node_id, child)] = selector
                selected_children.append(selector)
                model.addCons(selector <= x[child], name=f"cost_or_{node_id}_select_reachable_{child}")

                child_cost_upper = cost_upper_bounds[child]

                # If child is reachable, OR cost cannot exceed that child's cost.
                model.addCons(
                    c[node_id] <= c[child] + node_cost_upper * (1 - x[child]),
                    name=f"cost_or_{node_id}_le_child_{child}",
                )

                # If this child is selected, OR cost equals this child's cost.
                model.addCons(
                    c[node_id] >= c[child] - child_cost_upper * (1 - selector),
                    name=f"cost_or_{node_id}_selected_lower_{child}",
                )
                model.addCons(
                    c[node_id] <= c[child] + node_cost_upper * (1 - selector),
                    name=f"cost_or_{node_id}_selected_upper_{child}",
                )

            model.addCons(
                quicksum(selected_children) == x[node_id],
                name=f"cost_or_{node_id}_select_one_if_reachable",
            )

    # Attacker chooses exactly one response: empty or one reachable goal.
    model.addCons(y_empty + quicksum(y_goal[g] for g in goals) == 1, name="attacker_choose_one")
    for goal in goals:
        model.addCons(y_goal[goal] <= x[goal], name=f"choose_goal_{goal}_only_if_reachable")

    # Best-response constraints. The attacker compares net utility:
    #   empty = 0
    #   goal g = reward_g - min_cost_g if reachable
    #
    # U is forced to be the maximum attacker utility. A selected response must
    # attain U, so the attacker can choose only empty or a maximum-utility goal.
    for g in goals:
        goal_utility = rewards[g] * x[g] - c[g]
        model.addCons(
            attacker_max_utility >= goal_utility,
            name=f"max_utility_ge_goal_{g}",
        )
        model.addCons(
            attacker_max_utility <= goal_utility + utility_goal_big_m[g] * (1 - y_goal[g]),
            name=f"choose_goal_{g}_attains_max_utility",
        )

    model.addCons(
        attacker_max_utility <= utility_empty_big_m * (1 - y_empty),
        name="choose_empty_attains_max_utility",
    )

    defense_cost = quicksum(
        defense_costs.get(node_id, default_defense_cost) * d[node_id] for node_id in defendable
    )
    if budget is not None:
        model.addCons(defense_cost <= budget, name="defense_budget")

    attack_loss = quicksum(losses[g] * y_goal[g] for g in goals)
    model.setObjective(defense_cost + attack_loss, "minimize")

    warm_start_info = {
        "enabled": warm_start_key_path,
        "strategy": "key_path_greedy" if warm_start_key_path else None,
        "submitted": False,
        "accepted": None,
        "defense_count": 0,
        "defense_total": 0.0,
        "heuristic_objective": None,
        "attacker_goal": None,
        "iterations": 0,
        "explored_iterations": 0,
        "max_nonimproving_steps": DEFAULT_KEY_PATH_MAX_NONIMPROVING_STEPS,
        "stopped_after_nonimproving_steps": 0,
    }
    if warm_start_key_path:
        warm_start_begin = time.perf_counter()
        try:
            warm_start = build_key_path_warm_start(
                vertices=vertices,
                arcs=arcs,
                attack_costs=attack_costs,
                defendable=defendable,
                defense_costs=defense_costs,
                default_defense_cost=default_defense_cost,
                budget=budget,
                goals=goals,
                rewards=rewards,
                losses=losses,
            )
            submission = submit_warm_start(
                model=model,
                solver=solver,
                x=x,
                d=d,
                c=c,
                or_selectors=or_selectors,
                y_empty=y_empty,
                y_goal=y_goal,
                attacker_max_utility=attacker_max_utility,
                warm_start=warm_start,
            )
            warm_start_info.update(submission)
            warm_start_info.update(
                {
                    "defense_count": len(warm_start["defended"]),
                    "defense_total": warm_start["defense_total"],
                    "heuristic_objective": warm_start["objective"],
                    "attacker_goal": warm_start["selected_goal"],
                    "iterations": warm_start["iterations"],
                    "explored_iterations": warm_start["explored_iterations"],
                    "max_nonimproving_steps": warm_start["max_nonimproving_steps"],
                    "stopped_after_nonimproving_steps": warm_start[
                        "stopped_after_nonimproving_steps"
                    ],
                }
            )
        except ValueError as exc:
            warm_start_info["reason"] = str(exc)
        timings["key_path_warm_start"] = time.perf_counter() - warm_start_begin

    if write_lp:
        model.writeProblem(write_lp)
    timings["build_mip"] = time.perf_counter() - stage_start

    stage_start = time.perf_counter()
    model.optimize()
    timings["optimize"] = time.perf_counter() - stage_start

    stage_start = time.perf_counter()
    status = str(model.getStatus())
    result = {
        "status": status,
        "solver": solver,
        "solution_concept": "cost-sensitive pure Stackelberg equilibrium",
        "does_not_enumerate_attack_paths": True,
        "attacker_utility_form": "reward(goal) - minimum_attack_derivation_cost(goal)",
        "defender_objective_form": "defense_cost + loss(attacker_chosen_goal)",
        "best_response_formulation": "max_attacker_utility_variable",
        "cost_model_note": (
            "The attack cost is a minimum AND/OR derivation cost. AND nodes add "
            "their action cost and all prerequisite costs; OR nodes select the "
            "least-cost reachable child derivation."
        ),
        "goals": [
            {
                "id": g,
                "label": vertices[g]["label"],
                "reward": rewards[g],
                "loss": losses[g],
            }
            for g in goals
        ],
        "defendable_leaf_count": len(defendable),
        "defendable_mode": defendable_mode,
        "default_defense_cost": default_defense_cost,
        "default_action_cost": default_action_cost,
        "default_leaf_cost": default_leaf_cost,
        "attack_cost_source": attack_cost_source,
        "cost_bound_formulation": cost_upper_stats["formulation"],
        "cost_big_m": cost_big_m,
        "legacy_global_cost_big_m": legacy_cost_big_m,
        "cost_upper_bound_stats": cost_upper_stats,
        "utility_big_m": utility_big_m,
        "utility_upper_bound": utility_upper_bound,
        "budget": budget,
        "mip_gap_limit": mip_gap,
        "relative_gap": None,
        "target_closure": target_closure_stats,
        "warm_start": warm_start_info,
        "timings_seconds": timings,
        "selected_defenses": [],
        "reachable_goals": [],
        "attacker_response": None,
        "attacker_utility": None,
        "defender_utility": None,
        "objective_cost_form": None,
    }

    if not hasattr(model, "getNSols") or model.getNSols() == 0:
        timings["extract_solution"] = time.perf_counter() - stage_start
        timings["total_solve_game"] = sum(timings.values())
        return result

    objective = model.getObjVal()
    result["objective_cost_form"] = objective
    result["defender_utility"] = -objective
    if hasattr(model, "getGap"):
        result["relative_gap"] = float(model.getGap())

    for node_id in defendable:
        if model.getVal(d[node_id]) > 0.5:
            result["selected_defenses"].append(
                {
                    "id": node_id,
                    "label": vertices[node_id]["label"],
                    "cost": defense_costs.get(node_id, default_defense_cost),
                }
            )

    for g in goals:
        if model.getVal(x[g]) > 0.5:
            min_cost = model.getVal(c[g])
            result["reachable_goals"].append(
                {
                    "id": g,
                    "label": vertices[g]["label"],
                    "reward": rewards[g],
                    "loss": losses[g],
                    "min_attack_cost": min_cost,
                    "attacker_net_utility": rewards[g] - min_cost,
                }
            )

    if model.getVal(y_empty) > 0.5:
        result["attacker_response"] = {"type": "empty"}
        result["attacker_utility"] = 0.0
    else:
        chosen_goal = None
        for g in goals:
            if model.getVal(y_goal[g]) > 0.5:
                chosen_goal = g
                break
        if chosen_goal is not None:
            min_cost = model.getVal(c[chosen_goal])
            result["attacker_response"] = {
                "type": "attack_goal",
                "goal": {
                    "id": chosen_goal,
                    "label": vertices[chosen_goal]["label"],
                    "reward": rewards[chosen_goal],
                    "loss": losses[chosen_goal],
                    "min_attack_cost": min_cost,
                    "attacker_net_utility": rewards[chosen_goal] - min_cost,
                },
            }
            result["attacker_utility"] = rewards[chosen_goal] - min_cost

    timings["extract_solution"] = time.perf_counter() - stage_start
    timings["total_solve_game"] = sum(timings.values())
    return result


def main():
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--vertices", default=str(script_dir / "VERTICES.CSV"))
    parser.add_argument("--arcs", default=str(script_dir / "ARCS.CSV"))
    parser.add_argument(
        "--config",
        default=None,
        help="Game cost/config JSON produced by build_mulval_game_config.py.",
    )
    parser.add_argument("--out", default=str(script_dir / "mulval_cost_stackelberg_result.json"))
    parser.add_argument(
        "--goals",
        default=None,
        help="Comma-separated goal node ids. Defaults to OR nodes with indegree 0.",
    )
    parser.add_argument("--default-reward", type=float, default=100.0)
    parser.add_argument("--default-loss", type=float, default=100.0)
    parser.add_argument(
        "--goal-rewards",
        default=None,
        help='Goal rewards as JSON {"1":100,"55":80} or comma form 1:100,55:80.',
    )
    parser.add_argument(
        "--goal-losses",
        default=None,
        help='Goal losses as JSON {"1":100,"55":80} or comma form 1:100,55:80.',
    )
    parser.add_argument("--defense-cost", type=float, default=1.0)
    parser.add_argument(
        "--defense-costs",
        default=None,
        help='Defense costs by node id, e.g. {"20":4,"29":2} or 20:4,29:2.',
    )
    parser.add_argument(
        "--defendable",
        choices=["all", "vul", "hacl", "vul_hacl"],
        default=None,
        help="Which LEAF facts can be defended/disabled.",
    )
    parser.add_argument("--budget", type=float, default=None)
    parser.add_argument(
        "--attack-cost-source",
        choices=["constant", "score"],
        default=None,
        help="Use constant costs, or use CSV score when it is positive.",
    )
    parser.add_argument("--default-action-cost", type=float, default=1.0)
    parser.add_argument(
        "--default-leaf-cost",
        type=float,
        default=0.0,
        help="Compatibility option; LEAF fact costs are fixed to 0 in the current model.",
    )
    parser.add_argument(
        "--node-attack-costs",
        default=None,
        help='Attack costs by node id, e.g. {"3":2,"10":5} or 3:2,10:5.',
    )
    parser.add_argument(
        "--cost-big-m",
        type=float,
        default=None,
        help="Optional legacy global Big-M used as fallback for cyclic graphs; DAGs use local cost upper bounds by default.",
    )
    parser.add_argument(
        "--target-closure",
        action="store_true",
        default=None,
        help=(
            "Reduce the in-memory graph to the dependency closure of the selected "
            "targets before building the MIP. Off by default unless enabled in config."
        ),
    )
    parser.add_argument("--time-limit", type=float, default=None)
    parser.add_argument(
        "--mip-gap",
        type=float,
        default=None,
        help="Optional relative MIP gap stopping threshold; 0.01 means 1 percent.",
    )
    parser.add_argument(
        "--warm-start-key-path",
        action="store_true",
        default=None,
        help=(
            "Construct a greedy defender solution by repeatedly blocking the "
            "attacker's current minimum-cost derivation, then submit it as a MIP start."
        ),
    )
    parser.add_argument(
        "--solver",
        choices=["scip", "gurobi"],
        default=None,
        help=(
            "MIP solver backend. Defaults to scip unless defaults.solver is set "
            "in the config. Use gurobi only when gurobipy and a license are available."
        ),
    )
    parser.add_argument(
        "--write-lp",
        default=None,
        help="Optional path to export the generated MIP model before solving.",
    )
    args = parser.parse_args()

    wall_start = time.perf_counter()
    stage_start = time.perf_counter()
    vertices, arcs = parse_csv(Path(args.vertices), Path(args.arcs))
    input_read_seconds = time.perf_counter() - stage_start

    stage_start = time.perf_counter()
    game_config = load_game_config(args.config)
    config_read_seconds = time.perf_counter() - stage_start

    stage_start = time.perf_counter()
    goal_ids = parse_goal_ids(args.goals, []) if args.goals else None
    result = solve_game(
        vertices=vertices,
        arcs=arcs,
        game_config=game_config,
        goal_ids=goal_ids,
        default_reward=args.default_reward,
        default_loss=args.default_loss,
        goal_rewards_raw=args.goal_rewards,
        goal_losses_raw=args.goal_losses,
        default_defense_cost=args.defense_cost,
        defense_costs_raw=args.defense_costs,
        defendable_mode=args.defendable,
        budget=args.budget,
        attack_cost_source=args.attack_cost_source,
        default_action_cost=args.default_action_cost,
        mip_gap=args.mip_gap,
        default_leaf_cost=args.default_leaf_cost,
        node_attack_costs_raw=args.node_attack_costs,
        cost_big_m_override=args.cost_big_m,
        target_closure=args.target_closure,
        time_limit=args.time_limit,
        warm_start_key_path=args.warm_start_key_path,
        solver=args.solver,
        write_lp=args.write_lp,
    )
    solve_game_seconds = time.perf_counter() - stage_start
    result.setdefault("timings_seconds", {})
    result["timings_seconds"]["read_csv"] = input_read_seconds
    result["timings_seconds"]["read_config"] = config_read_seconds
    result["timings_seconds"]["solve_game_call"] = solve_game_seconds
    result["timings_seconds"]["total_wall"] = time.perf_counter() - wall_start

    out_path = Path(args.out)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    safe_print(f"status: {result['status']}")
    safe_print(f"solver: {result['solver']}")
    closure = result.get("target_closure", {})
    if closure.get("enabled"):
        safe_print(
            "target closure: "
            f"{closure['original_vertices']} -> {closure['reduced_vertices']} vertices, "
            f"{closure['original_arcs']} -> {closure['reduced_arcs']} arcs"
        )
    warm_start = result.get("warm_start", {})
    if warm_start.get("enabled"):
        safe_print(
            "key-path warm start: "
            f"submitted={warm_start.get('submitted')}, accepted={warm_start.get('accepted')}, "
            f"defenses={warm_start.get('defense_count')}, "
            f"heuristic_objective={warm_start.get('heuristic_objective')}"
        )
    if result.get("objective_cost_form") is not None:
        safe_print(f"objective cost form: {result['objective_cost_form']}")
        safe_print(f"defender utility: {result['defender_utility']}")
        safe_print(f"attacker utility: {result['attacker_utility']}")
        safe_print(f"attacker response: {result['attacker_response']}")
        safe_print("reachable goals:")
        for item in result["reachable_goals"]:
            safe_print(
                f"  {item['id']}: {item['label']}  "
                f"min_cost={item['min_attack_cost']}  "
                f"net={item['attacker_net_utility']}"
            )
        safe_print("selected defenses:")
        for item in result["selected_defenses"]:
            safe_print(f"  {item['id']}: {item['label']}  cost={item['cost']}")
    timings = result.get("timings_seconds", {})
    if timings:
        safe_print("timings seconds:")
        for key in [
            "read_csv",
            "read_config",
            "prepare_goals_and_config",
            "resolve_game_defaults",
            "target_closure",
            "build_parameters",
            "build_mip",
            "optimize",
            "extract_solution",
            "total_wall",
        ]:
            if key in timings:
                safe_print(f"  {key}: {timings[key]:.3f}")
    safe_print(f"wrote: {out_path.resolve()}")


if __name__ == "__main__":
    main()
