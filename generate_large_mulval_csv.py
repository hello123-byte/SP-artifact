# -*- coding: utf-8 -*-
"""Generate a large synthetic MulVAL-style dependency attack graph.

Output format:
  VERTICES.CSV rows: id,label,type,score
  The score column is a randomized attack-cost value in [1, 100].
  ARCS.CSV rows: source,target,-1

Edge direction follows the MulVAL CSV convention used by the solver:
  conclusion -> prerequisite

The generated graph is designed to preserve common MulVAL attack-graph
structure rather than merely inflate node/edge counts:
  * LEAF nodes are facts such as attackerLocated, hacl, networkServiceInfo,
    vulExists, credentials, and critical assets.
  * AND nodes are inference/rule applications.
  * OR nodes are derived privileges or reachability states such as netAccess
    and execCode.
  * Multiple exploit rules converge on the same execCode OR node.
  * The graph is a DAG: no head-to-tail dependency cycle is allowed.
  * Each AND rule depends on at most one OR prerequisite plus one or more
    LEAF prerequisites; AND-to-AND prerequisites are rejected.
  * LEAF nodes have no prerequisite edges and every emitted LEAF is consumed
    by at least one AND rule.
  * Every OR node is derived by at least one AND rule; every AND node has one or more prerequisite edges.
  * Network reachability is segmented: only a small DMZ-like entry set is
    directly reachable from the internet; internal access is produced by
    lateral-movement rules from already-compromised earlier hosts.

The graph remains synthetic and scalable, but its dependencies are intended to
look like the shape of a real MulVAL-derived AND/OR graph.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path


SERVICE_CATALOG = [
    ("web", 80, "www"),
    ("ssh", 22, "user"),
    ("api", 8443, "svc"),
    ("smb", 445, "user"),
    ("postgres", 5432, "db"),
    ("rdp", 3389, "user"),
    ("modbus", 502, "plc"),
    ("opcua", 4840, "engineer"),
]


def safe_print(text: str):
    encoding = sys.stdout.encoding or "utf-8"
    print(text.encode(encoding, errors="backslashreplace").decode(encoding))


def score(rng: random.Random) -> int:
    return rng.randint(1, 100)


def add_vertex(vertices, node_id: int, label: str, node_type: str, value: float) -> tuple[int, int]:
    vertices.append((node_id, label, node_type, value))
    return node_id, node_id + 1


def add_rule(
    vertices,
    arcs,
    next_id: int,
    conclusion_id: int,
    label: str,
    prerequisite_ids: list[int],
    rng: random.Random,
) -> tuple[int, int]:
    rule_id, next_id = add_vertex(vertices, next_id, label, "AND", score(rng))
    arcs.append((conclusion_id, rule_id))
    for prerequisite_id in prerequisite_ids:
        arcs.append((rule_id, prerequisite_id))
    return rule_id, next_id


def host_zone(index: int, hosts: int) -> str:
    if hosts <= 1:
        return "dmz"
    ratio = index / max(1, hosts - 1)
    if ratio < 0.12:
        return "dmz"
    if ratio < 0.55:
        return "app"
    if ratio < 0.85:
        return "db"
    return "crown"


def host_name(index: int, hosts: int) -> str:
    return f"{host_zone(index, hosts)}{index}"


def service_for(host_index: int, service_index: int) -> tuple[str, int, str]:
    base_name, base_port, run_as = SERVICE_CATALOG[(host_index + service_index) % len(SERVICE_CATALOG)]
    port_offset = 100 * (service_index // len(SERVICE_CATALOG))
    return f"{base_name}{service_index}", base_port + port_offset, run_as


def choose_source_host(rng: random.Random, target_host: int) -> int:
    if target_host <= 1:
        return 0
    if rng.random() < 0.7:
        window = min(target_host, 25)
        return rng.randrange(target_host - window, target_host)
    return rng.randrange(0, target_host)


def add_network_access(
    vertices,
    arcs,
    next_id: int,
    src_label: str,
    dst_label: str,
    protocol: str,
    port: int,
    source_prerequisite_id: int,
    rng: random.Random,
    credential_label: str | None = None,
) -> tuple[int, int]:
    access_id, next_id = add_vertex(
        vertices,
        next_id,
        f"netAccess({src_label},{dst_label},{protocol},{port})",
        "OR",
        score(rng),
    )
    hacl_id, next_id = add_vertex(
        vertices,
        next_id,
        f"hacl({src_label},{dst_label},{protocol},{port})",
        "LEAF",
        score(rng),
    )

    prerequisites = [source_prerequisite_id, hacl_id]
    if credential_label is not None:
        credential_id, next_id = add_vertex(vertices, next_id, credential_label, "LEAF", score(rng))
        prerequisites.append(credential_id)

    _, next_id = add_rule(
        vertices=vertices,
        arcs=arcs,
        next_id=next_id,
        conclusion_id=access_id,
        label=f"RULE network access {src_label}->{dst_label}:{port}",
        prerequisite_ids=prerequisites,
        rng=rng,
    )
    return access_id, next_id


def validate_parameters(
    hosts: int,
    services_per_host: int,
    vuln_per_service: int,
    lateral_rules_per_host: int,
    goals: int,
):
    if hosts < 1:
        raise SystemExit("--hosts must be at least 1")
    if services_per_host < 1:
        raise SystemExit("--services-per-host must be at least 1")
    if vuln_per_service < 1:
        raise SystemExit("--vuln-per-service must be at least 1")
    if lateral_rules_per_host < 0:
        raise SystemExit("--lateral-rules-per-host must be non-negative")
    if hosts > 1 and lateral_rules_per_host == 0:
        raise SystemExit(
            "--lateral-rules-per-host must be at least 1 when --hosts is greater than 1 "
            "so every execCode(...,user) OR node has an AND-rule derivation"
        )
    if goals < 1:
        raise SystemExit("--goals must be at least 1")


def graph_diagnostics(vertices, arcs, goal_nodes: list[int]) -> dict:
    vertices_by_id = {node_id: {"label": label, "type": node_type} for node_id, label, node_type, _ in vertices}
    outgoing = defaultdict(list)
    incoming = defaultdict(list)
    for src, dst in arcs:
        outgoing[src].append(dst)
        incoming[dst].append(src)

    missing_arc_endpoints = [
        (src, dst)
        for src, dst in arcs
        if src not in vertices_by_id or dst not in vertices_by_id
    ]
    leaf_nodes_with_prerequisites = [
        node_id
        for node_id, node in vertices_by_id.items()
        if node["type"] == "LEAF" and outgoing[node_id]
    ]
    leaf_nodes_without_consumers = [
        node_id
        for node_id, node in vertices_by_id.items()
        if node["type"] == "LEAF" and not incoming[node_id]
    ]
    non_leaf_nodes_without_prerequisites = [
        node_id
        for node_id, node in vertices_by_id.items()
        if node["type"] != "LEAF" and not outgoing[node_id]
    ]
    and_without_prerequisites = [
        node_id
        for node_id, node in vertices_by_id.items()
        if node["type"] == "AND" and not outgoing[node_id]
    ]
    or_without_producers = [
        node_id
        for node_id, node in vertices_by_id.items()
        if node["type"] == "OR"
        and not any(
            vertices_by_id.get(child_id, {}).get("type") == "AND"
            for child_id in outgoing[node_id]
        )
    ]
    or_nodes_with_non_and_producers = []
    and_nodes_with_multiple_or_prerequisites = []
    and_nodes_without_leaf_prerequisites = []
    and_nodes_with_non_leaf_or_prerequisites = []
    for node_id, node in vertices_by_id.items():
        if node["type"] == "OR":
            invalid_producers = [
                child_id
                for child_id in outgoing[node_id]
                if vertices_by_id.get(child_id, {}).get("type") != "AND"
            ]
            if invalid_producers:
                or_nodes_with_non_and_producers.append((node_id, invalid_producers))
            continue
        if node["type"] != "AND":
            continue
        or_prerequisites = [
            child_id
            for child_id in outgoing[node_id]
            if vertices_by_id.get(child_id, {}).get("type") == "OR"
        ]
        leaf_prerequisites = [
            child_id
            for child_id in outgoing[node_id]
            if vertices_by_id.get(child_id, {}).get("type") == "LEAF"
        ]
        invalid_prerequisites = [
            child_id
            for child_id in outgoing[node_id]
            if vertices_by_id.get(child_id, {}).get("type") not in {"OR", "LEAF"}
        ]
        if len(or_prerequisites) > 1:
            and_nodes_with_multiple_or_prerequisites.append((node_id, or_prerequisites))
        if not leaf_prerequisites:
            and_nodes_without_leaf_prerequisites.append(node_id)
        if invalid_prerequisites:
            and_nodes_with_non_leaf_or_prerequisites.append((node_id, invalid_prerequisites))

    indegrees = {node_id: 0 for node_id in vertices_by_id}
    for src, dst in arcs:
        if src in vertices_by_id and dst in vertices_by_id:
            indegrees[dst] += 1
    queue = [node_id for node_id, degree in indegrees.items() if degree == 0]
    visited_count = 0
    while queue:
        node_id = queue.pop()
        visited_count += 1
        for child_id in outgoing[node_id]:
            if child_id not in indegrees:
                continue
            indegrees[child_id] -= 1
            if indegrees[child_id] == 0:
                queue.append(child_id)
    cyclic_node_count = len(vertices_by_id) - visited_count

    return {
        "type_counts": dict(Counter(node_type for _, _, node_type, _ in vertices)),
        "missing_arc_endpoints": len(missing_arc_endpoints),
        "leaf_nodes_with_prerequisites": len(leaf_nodes_with_prerequisites),
        "leaf_nodes_without_consumers": len(leaf_nodes_without_consumers),
        "non_leaf_nodes_without_prerequisites": len(non_leaf_nodes_without_prerequisites),
        "and_nodes_without_prerequisites": len(and_without_prerequisites),
        "or_nodes_without_producers": len(or_without_producers),
        "or_nodes_with_non_and_producers": len(or_nodes_with_non_and_producers),
        "and_nodes_with_multiple_or_prerequisites": len(and_nodes_with_multiple_or_prerequisites),
        "and_nodes_without_leaf_prerequisites": len(and_nodes_without_leaf_prerequisites),
        "and_nodes_with_non_leaf_or_prerequisites": len(and_nodes_with_non_leaf_or_prerequisites),
        "sample_leaf_nodes_with_prerequisites": [
            {
                "id": node_id,
                "label": vertices_by_id[node_id]["label"],
                "prerequisites": [
                    {"id": child_id, "type": vertices_by_id[child_id]["type"], "label": vertices_by_id[child_id]["label"]}
                    for child_id in outgoing[node_id][:10]
                ],
            }
            for node_id in leaf_nodes_with_prerequisites[:10]
        ],
        "sample_leaf_nodes_without_consumers": [
            {"id": node_id, "label": vertices_by_id[node_id]["label"]}
            for node_id in leaf_nodes_without_consumers[:10]
        ],
        "sample_non_leaf_nodes_without_prerequisites": [
            {"id": node_id, "type": vertices_by_id[node_id]["type"], "label": vertices_by_id[node_id]["label"]}
            for node_id in non_leaf_nodes_without_prerequisites[:10]
        ],
        "sample_or_nodes_without_producers": [
            {"id": node_id, "label": vertices_by_id[node_id]["label"]}
            for node_id in or_without_producers[:10]
        ],
        "sample_or_nodes_with_non_and_producers": [
            {
                "or_id": node_id,
                "or_label": vertices_by_id[node_id]["label"],
                "invalid_producers": [
                    {
                        "id": child_id,
                        "type": vertices_by_id[child_id]["type"],
                        "label": vertices_by_id[child_id]["label"],
                    }
                    for child_id in child_ids
                ],
            }
            for node_id, child_ids in or_nodes_with_non_and_producers[:10]
        ],
        "sample_and_nodes_with_multiple_or_prerequisites": [
            {
                "and_id": node_id,
                "and_label": vertices_by_id[node_id]["label"],
                "or_prerequisites": [
                    {"id": child_id, "label": vertices_by_id[child_id]["label"]}
                    for child_id in child_ids
                ],
            }
            for node_id, child_ids in and_nodes_with_multiple_or_prerequisites[:10]
        ],
        "sample_and_nodes_without_leaf_prerequisites": [
            {"and_id": node_id, "and_label": vertices_by_id[node_id]["label"]}
            for node_id in and_nodes_without_leaf_prerequisites[:10]
        ],
        "sample_and_nodes_with_non_leaf_or_prerequisites": [
            {
                "and_id": node_id,
                "and_label": vertices_by_id[node_id]["label"],
                "invalid_prerequisites": [
                    {"id": child_id, "type": vertices_by_id[child_id]["type"], "label": vertices_by_id[child_id]["label"]}
                    for child_id in child_ids
                ],
            }
            for node_id, child_ids in and_nodes_with_non_leaf_or_prerequisites[:10]
        ],
        "has_directed_cycle": cyclic_node_count > 0,
        "cyclic_node_count": cyclic_node_count,
        "default_or_indegree_zero_count": sum(
            1
            for node_id, node in vertices_by_id.items()
            if node["type"] == "OR" and len(incoming[node_id]) == 0
        ),
        "goal_count": len(goal_nodes),
    }


def validate_graph_structure(vertices, arcs, goal_nodes: list[int]) -> dict:
    diagnostics = graph_diagnostics(vertices, arcs, goal_nodes)
    errors = []
    if diagnostics["missing_arc_endpoints"]:
        errors.append(f"{diagnostics['missing_arc_endpoints']} arc(s) reference missing vertices")
    if diagnostics["has_directed_cycle"]:
        errors.append(f"directed cycle detected involving {diagnostics['cyclic_node_count']} node(s)")
    if diagnostics["leaf_nodes_with_prerequisites"]:
        errors.append(f"{diagnostics['leaf_nodes_with_prerequisites']} LEAF node(s) have prerequisites")
    if diagnostics["leaf_nodes_without_consumers"]:
        errors.append(
            f"{diagnostics['leaf_nodes_without_consumers']} LEAF node(s) are not consumed by any AND rule"
        )
    if diagnostics["non_leaf_nodes_without_prerequisites"]:
        errors.append(
            f"{diagnostics['non_leaf_nodes_without_prerequisites']} non-LEAF node(s) have no prerequisites"
        )
    if diagnostics["or_nodes_without_producers"]:
        errors.append(
            f"{diagnostics['or_nodes_without_producers']} OR node(s) are not derived by any AND rule"
        )
    if diagnostics["or_nodes_with_non_and_producers"]:
        errors.append(
            f"{diagnostics['or_nodes_with_non_and_producers']} OR node(s) have non-AND producer edges"
        )
    if diagnostics["and_nodes_with_multiple_or_prerequisites"]:
        errors.append(
            f"{diagnostics['and_nodes_with_multiple_or_prerequisites']} AND node(s) depend on more than one OR node"
        )
    if diagnostics["and_nodes_without_leaf_prerequisites"]:
        errors.append(
            f"{diagnostics['and_nodes_without_leaf_prerequisites']} AND node(s) have no LEAF prerequisite"
        )
    if diagnostics["and_nodes_with_non_leaf_or_prerequisites"]:
        errors.append(
            f"{diagnostics['and_nodes_with_non_leaf_or_prerequisites']} AND node(s) have prerequisites that are neither OR nor LEAF"
        )
    if errors:
        raise SystemExit("Generated graph violates structural constraints: " + "; ".join(errors))
    return diagnostics


def prune_unconsumed_leaves(vertices, arcs):
    """Remove LEAF facts that are not prerequisites of any AND rule."""
    vertices_by_id = {
        node_id: {"type": node_type}
        for node_id, _, node_type, _ in vertices
    }
    consumed_leaf_ids = {
        dst
        for src, dst in arcs
        if vertices_by_id.get(src, {}).get("type") == "AND"
        and vertices_by_id.get(dst, {}).get("type") == "LEAF"
    }
    removed = [
        vertex
        for vertex in vertices
        if vertex[2] == "LEAF" and vertex[0] not in consumed_leaf_ids
    ]
    removed_ids = {node_id for node_id, _, _, _ in removed}
    kept_vertices = [vertex for vertex in vertices if vertex[0] not in removed_ids]
    kept_arcs = [(src, dst) for src, dst in arcs if src not in removed_ids and dst not in removed_ids]
    return kept_vertices, kept_arcs, removed


def prune_to_goal_closure(vertices, arcs, goal_nodes: list[int]):
    """Keep only final goals and their recursive prerequisites.

    Arcs are stored as conclusion -> prerequisite. In the visual direction,
    the retained nodes are exactly those that can reach a final goal.
    """
    vertex_ids = {node_id for node_id, _, _, _ in vertices}
    missing_goals = [goal_id for goal_id in goal_nodes if goal_id not in vertex_ids]
    if missing_goals:
        raise SystemExit(f"Cannot close graph around missing goal id(s): {missing_goals}")

    outgoing = defaultdict(list)
    for source, target in arcs:
        if source in vertex_ids and target in vertex_ids:
            outgoing[source].append(target)

    kept_ids = set(goal_nodes)
    stack = list(goal_nodes)
    while stack:
        node_id = stack.pop()
        for prerequisite_id in outgoing[node_id]:
            if prerequisite_id not in kept_ids:
                kept_ids.add(prerequisite_id)
                stack.append(prerequisite_id)

    removed = [vertex for vertex in vertices if vertex[0] not in kept_ids]
    kept_vertices = [vertex for vertex in vertices if vertex[0] in kept_ids]
    kept_arcs = [(source, target) for source, target in arcs if source in kept_ids and target in kept_ids]
    return kept_vertices, kept_arcs, removed


def find_single_vulnerability_global_cuts(vertices, arcs, goal_nodes: list[int]) -> list[int]:
    """Find vulnerability LEAF nodes whose individual removal blocks every goal.

    For one blocked vulnerability in an acyclic monotone AND/OR graph, an AND
    node inherits the union of its prerequisites' cuts, while an OR node
    inherits the intersection of its alternative rules' cuts.
    """
    nodes = {node_id: (label, node_type) for node_id, label, node_type, _ in vertices}
    outgoing = defaultdict(list)
    parents = defaultdict(list)
    remaining = {node_id: 0 for node_id in nodes}
    for source, target in arcs:
        if source in nodes and target in nodes:
            outgoing[source].append(target)
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
    if len(order) != len(nodes):
        raise SystemExit("Single-vulnerability cut analysis requires an acyclic graph")

    cuts = {}
    for node_id in order:
        label, node_type = nodes[node_id]
        children = outgoing[node_id]
        if node_type == "LEAF":
            cuts[node_id] = (
                {node_id}
                if label.startswith(("vulExists", "ttpExists"))
                else set()
            )
        elif node_type == "AND":
            cuts[node_id] = set().union(*(cuts[child] for child in children))
        elif node_type == "OR":
            if not children:
                cuts[node_id] = set()
            else:
                common = set(cuts[children[0]])
                for child in children[1:]:
                    common.intersection_update(cuts[child])
                cuts[node_id] = common
        else:
            raise SystemExit(f"Unknown node type for cut analysis: {node_type}")

    if not goal_nodes:
        return []
    common_goal_cuts = set(cuts[goal_nodes[0]])
    for goal_id in goal_nodes[1:]:
        common_goal_cuts.intersection_update(cuts[goal_id])
    return sorted(common_goal_cuts)


def build_layered_host_layers(hosts: int, goals: int) -> list[list[int]]:
    """Partition hosts into balanced attack layers ending in goal hosts."""
    goal_host_count = min(hosts, goals)
    internal_host_count = hosts - goal_host_count
    if internal_host_count == 0:
        return [list(range(hosts))]

    target_width = max(2, math.ceil(math.sqrt(internal_host_count)))
    internal_layer_count = math.ceil(internal_host_count / target_width)
    base_size, extra = divmod(internal_host_count, internal_layer_count)
    layer_sizes = [
        base_size + (1 if layer_index < extra else 0)
        for layer_index in range(internal_layer_count)
    ]

    layers = []
    next_host = 0
    for layer_size in layer_sizes:
        layers.append(list(range(next_host, next_host + layer_size)))
        next_host += layer_size
    layers.append(list(range(internal_host_count, hosts)))
    return layers


def layered_source_plan(
    previous_hosts: list[int],
    current_hosts: list[int],
    minimum_paths_per_target: int = 2,
) -> dict[int, list[int]]:
    """Connect adjacent layers while covering every source and target host."""
    if not previous_hosts or not current_hosts:
        raise SystemExit("Layered topology requires non-empty adjacent host layers")

    sources_by_target = {target_host: [] for target_host in current_hosts}
    for target_position, target_host in enumerate(current_hosts):
        for offset in range(minimum_paths_per_target):
            sources_by_target[target_host].append(
                previous_hosts[(target_position + offset) % len(previous_hosts)]
            )

    used_sources = {
        source_host
        for source_hosts in sources_by_target.values()
        for source_host in source_hosts
    }
    for source_position, source_host in enumerate(previous_hosts):
        if source_host not in used_sources:
            target_host = current_hosts[source_position % len(current_hosts)]
            sources_by_target[target_host].append(source_host)
    return sources_by_target


def build_graph(
    hosts: int,
    services_per_host: int,
    vuln_per_service: int,
    lateral_rules_per_host: int,
    goals: int,
    seed: int,
    target_closed: bool = False,
    target_closed_topology: str = "serial",
):
    validate_parameters(hosts, services_per_host, vuln_per_service, lateral_rules_per_host, goals)
    if target_closed_topology not in {"serial", "redundant", "layered"}:
        raise SystemExit("--target-closed-topology must be serial, redundant, or layered")
    if target_closed_topology in {"redundant", "layered"} and not target_closed:
        raise SystemExit(
            f"{target_closed_topology} target-closed topology requires target_closed=True"
        )
    if target_closed_topology in {"redundant", "layered"} and services_per_host < 2:
        raise SystemExit(
            f"{target_closed_topology} target-closed topology requires at least two services per host"
        )
    redundant_target_closed = target_closed and target_closed_topology == "redundant"
    layered_target_closed = target_closed and target_closed_topology == "layered"
    resilient_target_closed = redundant_target_closed or layered_target_closed

    rng = random.Random(seed)
    vertices = []
    arcs = []
    next_id = 1

    attacker_leaf, next_id = add_vertex(vertices, next_id, "attackerLocated(internet)", "LEAF", score(rng))

    host_names = [host_name(index, hosts) for index in range(hosts)]
    zones = [host_zone(index, hosts) for index in range(hosts)]
    user_exec = {}
    root_exec = {}
    service_info = {}
    service_meta = {}
    vulnerability_facts = defaultdict(list)
    access_by_service = defaultdict(list)

    for host_index, name in enumerate(host_names):
        user_exec[host_index], next_id = add_vertex(vertices, next_id, f"execCode({name},user)", "OR", score(rng))
        root_exec[host_index], next_id = add_vertex(vertices, next_id, f"execCode({name},root)", "OR", score(rng))

        for service_index in range(services_per_host):
            service_name, port, run_as = service_for(host_index, service_index)
            service_meta[(host_index, service_index)] = (service_name, port, run_as)
            service_info[(host_index, service_index)], next_id = add_vertex(
                vertices,
                next_id,
                f"networkServiceInfo({name},{service_name},tcp,{port},{run_as})",
                "LEAF",
                score(rng),
            )
            for vuln_index in range(vuln_per_service):
                vuln_id, next_id = add_vertex(
                    vertices,
                    next_id,
                    (
                        f"vulExists({name},CVE-SYN-{host_index:04d}-{service_index:02d}-{vuln_index:02d},"
                        f"{service_name},remoteExploit,privEscalation)"
                    ),
                    "LEAF",
                    score(rng),
                )
                vulnerability_facts[(host_index, service_index)].append(vuln_id)

    host_layers = build_layered_host_layers(hosts, goals) if layered_target_closed else []
    entry_hosts = (
        host_layers[0]
        if layered_target_closed
        else list(range(min(hosts, max(1, min(20, max(1, hosts // 20))))))
    )
    entry_host_count = len(entry_hosts)
    public_service_count = max(1, min(services_per_host, 2))
    direct_access_rules = 0
    lateral_access_rules = 0

    for host_index in entry_hosts:
        for service_index in range(public_service_count):
            service_name, port, _ = service_meta[(host_index, service_index)]
            access_id, next_id = add_network_access(
                vertices=vertices,
                arcs=arcs,
                next_id=next_id,
                src_label="internet",
                dst_label=host_names[host_index],
                protocol="tcp",
                port=port,
                source_prerequisite_id=attacker_leaf,
                rng=rng,
            )
            access_by_service[(host_index, service_index)].append(access_id)
            direct_access_rules += 1

    lateral_source_hosts = defaultdict(set)

    def add_lateral_access(host_index: int, source_host: int, lateral_index: int):
        nonlocal next_id, lateral_access_rules
        service_index = (
            lateral_index % services_per_host
            if resilient_target_closed
            else rng.randrange(services_per_host)
        )
        _, port, _ = service_meta[(host_index, service_index)]
        source_privilege = (
            root_exec[source_host]
            if target_closed or rng.random() < 0.35
            else user_exec[source_host]
        )
        credential_label = None
        if rng.random() < 0.45:
            credential_label = (
                f"credentialAvailable({host_names[source_host]},{host_names[host_index]},cred{lateral_index})"
            )
        access_id, next_id = add_network_access(
            vertices=vertices,
            arcs=arcs,
            next_id=next_id,
            src_label=host_names[source_host],
            dst_label=host_names[host_index],
            protocol="tcp",
            port=port,
            source_prerequisite_id=source_privilege,
            rng=rng,
            credential_label=credential_label,
        )
        access_by_service[(host_index, service_index)].append(access_id)
        lateral_source_hosts[host_index].add(source_host)
        lateral_access_rules += 1

    if layered_target_closed:
        for layer_index in range(1, len(host_layers)):
            sources_by_target = layered_source_plan(
                host_layers[layer_index - 1],
                host_layers[layer_index],
            )
            for host_index in host_layers[layer_index]:
                for lateral_index, source_host in enumerate(sources_by_target[host_index]):
                    add_lateral_access(host_index, source_host, lateral_index)
    else:
        effective_lateral_rules_per_host = (
            max(2, lateral_rules_per_host)
            if redundant_target_closed
            else lateral_rules_per_host
        )
        for host_index in range(1, hosts):
            for lateral_index in range(effective_lateral_rules_per_host):
                source_host = host_index - 1 if target_closed else choose_source_host(rng, host_index)
                add_lateral_access(host_index, source_host, lateral_index)

    remote_exploit_rules = 0
    for host_index in range(hosts):
        for service_index in range(services_per_host):
            service_name, port, _ = service_meta[(host_index, service_index)]
            for access_id in access_by_service[(host_index, service_index)]:
                for vuln_id in vulnerability_facts[(host_index, service_index)]:
                    _, next_id = add_rule(
                        vertices=vertices,
                        arcs=arcs,
                        next_id=next_id,
                        conclusion_id=user_exec[host_index],
                        label=f"RULE remote exploit {host_names[host_index]} {service_name}:{port}",
                        prerequisite_ids=[access_id, service_info[(host_index, service_index)], vuln_id],
                        rng=rng,
                    )
                    remote_exploit_rules += 1

    local_privilege_rules = 0
    for host_index, name in enumerate(host_names):
        local_alternatives = 2 if resilient_target_closed else 1
        for local_index in range(local_alternatives):
            cve_suffix = (
                f"{host_index:04d}-{local_index:02d}"
                if resilient_target_closed
                else f"{host_index:04d}"
            )
            local_vuln_id, next_id = add_vertex(
                vertices,
                next_id,
                f"vulExists({name},CVE-LOCAL-{cve_suffix},kernel,localExploit,privEscalation)",
                "LEAF",
                score(rng),
            )
            _, next_id = add_rule(
                vertices=vertices,
                arcs=arcs,
                next_id=next_id,
                conclusion_id=root_exec[host_index],
                label=(
                    f"RULE local privilege escalation on {name} alt{local_index}"
                    if resilient_target_closed
                    else f"RULE local privilege escalation on {name}"
                ),
                prerequisite_ids=[user_exec[host_index], local_vuln_id],
                rng=rng,
            )
            local_privilege_rules += 1

    goal_nodes = []
    goal_rule_count = 0
    if layered_target_closed:
        crown_hosts = host_layers[-1]
    else:
        crown_pool_size = max(1, min(hosts, max(goals, hosts // 10)))
        crown_hosts = list(range(hosts - crown_pool_size, hosts))
    for goal_index in range(goals):
        target_host = crown_hosts[-1 - (goal_index % len(crown_hosts))]
        target_name = host_names[target_host]
        goal_id, next_id = add_vertex(
            vertices,
            next_id,
            f"execCode(crown_jewel_{target_name},root,goal{goal_index})",
            "OR",
            score(rng),
        )
        asset_id, next_id = add_vertex(
            vertices,
            next_id,
            f"criticalAsset({target_name},crown_jewel_{goal_index})",
            "LEAF",
            score(rng),
        )
        _, next_id = add_rule(
            vertices=vertices,
            arcs=arcs,
            next_id=next_id,
            conclusion_id=goal_id,
            label=f"RULE reach crown jewel goal{goal_index}",
            prerequisite_ids=[root_exec[target_host], asset_id],
            rng=rng,
        )
        goal_rule_count += 1
        goal_nodes.append(goal_id)

    vertices, arcs, pruned_leaf_nodes = prune_unconsumed_leaves(vertices, arcs)
    pruned_outside_goal_closure = []
    if target_closed:
        vertices, arcs, pruned_outside_goal_closure = prune_to_goal_closure(vertices, arcs, goal_nodes)

    structure = {
        "host_zones": dict(Counter(zones)),
        "entry_host_count": entry_host_count,
        "public_service_count_per_entry_host": public_service_count,
        "direct_access_rules": direct_access_rules,
        "lateral_access_rules": lateral_access_rules,
        "remote_exploit_rules": remote_exploit_rules,
        "local_privilege_rules": local_privilege_rules,
        "goal_rules": goal_rule_count,
        "pruned_unconsumed_leaf_count": len(pruned_leaf_nodes),
        "pruned_outside_goal_closure_count": len(pruned_outside_goal_closure),
        "target_closed": target_closed,
        "target_closed_topology": target_closed_topology if target_closed else None,
        "host_layer_count": len(host_layers) if layered_target_closed else None,
        "host_layer_sizes": [len(layer) for layer in host_layers] if layered_target_closed else [],
        "max_host_layer_width": max(map(len, host_layers)) if layered_target_closed else None,
        "max_visual_host_hops": max(0, len(host_layers) - 1) if layered_target_closed else None,
        "lateral_source_hosts_per_target": {
            "min": min(map(len, lateral_source_hosts.values()), default=0),
            "max": max(map(len, lateral_source_hosts.values()), default=0),
            "avg": (
                sum(map(len, lateral_source_hosts.values())) / len(lateral_source_hosts)
                if lateral_source_hosts
                else 0
            ),
        },
        "sample_pruned_unconsumed_leaves": [
            {"id": node_id, "label": label}
            for node_id, label, _, _ in pruned_leaf_nodes[:10]
        ],
        "score_range": [1, 100],
        "and_prerequisite_rule": "Each AND node has at most one OR prerequisite and at least one LEAF prerequisite. AND-to-AND prerequisites are rejected.",
        "leaf_prerequisite_rule": "LEAF nodes must have no prerequisite edges and must be consumed by at least one AND rule.",
        "or_producer_rule": "Every OR node must be derived by at least one AND rule; OR prerequisite edges may only target AND nodes.",
        "non_leaf_prerequisite_rule": "Every non-LEAF node must have at least one prerequisite edge.",
        "cycle_rule": "The generated dependency graph must be acyclic under conclusion -> prerequisite edges.",
        "notes": [
            "Only entry hosts receive internet-origin netAccess facts.",
            "Internal netAccess is inferred from compromised earlier hosts plus hacl facts.",
            "Remote exploit AND rules converge on per-host execCode(user) OR nodes.",
            "Local privilege escalation produces per-host execCode(root) OR nodes.",
            "Each crown-jewel goal requires root access on the same host that owns the critical asset.",
            "Unconsumed LEAF facts are pruned before CSV output.",
            "Target-closed mode retains only nodes that can reach one of the final goals.",
            *(
                [
                    "Resilient target-closed modes give every host at least two "
                    "vulnerability-distinct remote and local privilege derivations."
                ]
                if resilient_target_closed
                else []
            ),
            *(
                [
                    "Layered target-closed mode uses balanced host layers and multiple "
                    "sources from each preceding layer while retaining every host in a goal closure."
                ]
                if layered_target_closed
                else []
            ),
        ],
    }

    diagnostics = validate_graph_structure(vertices, arcs, goal_nodes)
    single_vulnerability_global_cuts = (
        find_single_vulnerability_global_cuts(vertices, arcs, goal_nodes)
        if resilient_target_closed
        else []
    )
    structure["single_vulnerability_global_cut_count"] = len(single_vulnerability_global_cuts)
    structure["sample_single_vulnerability_global_cuts"] = single_vulnerability_global_cuts[:10]
    if resilient_target_closed and single_vulnerability_global_cuts:
        raise SystemExit(
            f"{target_closed_topology.capitalize()} target-closed graph still has "
            "vulnerability nodes that individually block every goal: "
            f"{single_vulnerability_global_cuts[:10]}"
        )
    structure["diagnostics"] = diagnostics
    return vertices, arcs, goal_nodes, structure


def write_csv(vertices, arcs, vertices_path: Path, arcs_path: Path):
    with vertices_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(vertices)

    with arcs_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows((source, target, -1) for source, target in arcs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hosts", type=int, default=1200)
    parser.add_argument("--services-per-host", type=int, default=2)
    parser.add_argument("--vuln-per-service", type=int, default=2)
    parser.add_argument("--lateral-rules-per-host", type=int, default=1)
    parser.add_argument("--goals", type=int, default=4)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument(
        "--target-closed",
        action="store_true",
        help="Keep only final goals and their recursive prerequisites.",
    )
    parser.add_argument(
        "--target-closed-topology",
        choices=["serial", "redundant", "layered"],
        default="serial",
        help=(
            "Topology used with --target-closed. serial preserves the legacy chain; "
            "redundant adds local path redundancy; layered adds balanced multi-source host layers."
        ),
    )
    parser.add_argument("--vertices-out", default="large_mulval_VERTICES.CSV")
    parser.add_argument("--arcs-out", default="large_mulval_ARCS.CSV")
    parser.add_argument("--summary-out", default="large_mulval_summary.json")
    args = parser.parse_args()

    vertices, arcs, goal_nodes, structure = build_graph(
        hosts=args.hosts,
        services_per_host=args.services_per_host,
        vuln_per_service=args.vuln_per_service,
        lateral_rules_per_host=args.lateral_rules_per_host,
        goals=args.goals,
        seed=args.seed,
        target_closed=args.target_closed,
        target_closed_topology=args.target_closed_topology,
    )

    vertices_path = Path(args.vertices_out)
    arcs_path = Path(args.arcs_out)
    write_csv(vertices, arcs, vertices_path, arcs_path)

    summary = {
        "vertices": len(vertices),
        "arcs": len(arcs),
        "goals": goal_nodes,
        "parameters": vars(args),
        "structure": structure,
        "diagnostics": structure["diagnostics"],
        "format": {
            "VERTICES.CSV": "id,label,type,score",
            "ARCS.CSV": "source,target,-1",
            "edge_direction": "conclusion -> prerequisite",
        },
    }
    Path(args.summary_out).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    safe_print(f"wrote vertices: {vertices_path.resolve()} ({len(vertices)} rows)")
    safe_print(f"wrote arcs: {arcs_path.resolve()} ({len(arcs)} rows)")
    safe_print(f"goals: {goal_nodes}")
    safe_print(f"structure: {structure}")


if __name__ == "__main__":
    main()
