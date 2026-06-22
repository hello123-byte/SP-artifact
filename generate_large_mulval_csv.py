# -*- coding: utf-8 -*-
"""Generate a large synthetic MulVAL-style dependency attack graph.

Output format:
  VERTICES.CSV rows: id,label,type,score
  ARCS.CSV rows: source,target

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


def score(rng: random.Random, low: float = 0.01, high: float = 0.95) -> float:
    return round(rng.uniform(low, high), 4)


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
    and_without_prerequisites = [
        node_id
        for node_id, node in vertices_by_id.items()
        if node["type"] == "AND" and not outgoing[node_id]
    ]
    or_without_producers = [
        node_id
        for node_id, node in vertices_by_id.items()
        if node["type"] == "OR" and not outgoing[node_id]
    ]

    return {
        "type_counts": dict(Counter(node_type for _, _, node_type, _ in vertices)),
        "missing_arc_endpoints": len(missing_arc_endpoints),
        "and_nodes_without_prerequisites": len(and_without_prerequisites),
        "or_nodes_without_producers": len(or_without_producers),
        "default_or_indegree_zero_count": sum(
            1
            for node_id, node in vertices_by_id.items()
            if node["type"] == "OR" and len(incoming[node_id]) == 0
        ),
        "goal_count": len(goal_nodes),
    }


def build_graph(
    hosts: int,
    services_per_host: int,
    vuln_per_service: int,
    lateral_rules_per_host: int,
    goals: int,
    seed: int,
):
    validate_parameters(hosts, services_per_host, vuln_per_service, lateral_rules_per_host, goals)

    rng = random.Random(seed)
    vertices = []
    arcs = []
    next_id = 1

    attacker_leaf, next_id = add_vertex(vertices, next_id, "attackerLocated(internet)", "LEAF", 1.0)

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

    entry_host_count = min(hosts, max(1, min(20, max(1, hosts // 20))))
    public_service_count = max(1, min(services_per_host, 2))
    direct_access_rules = 0
    lateral_access_rules = 0

    for host_index in range(entry_host_count):
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

    for host_index in range(1, hosts):
        for lateral_index in range(lateral_rules_per_host):
            source_host = choose_source_host(rng, host_index)
            service_index = rng.randrange(services_per_host)
            _, port, _ = service_meta[(host_index, service_index)]
            source_privilege = root_exec[source_host] if rng.random() < 0.35 else user_exec[source_host]
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
            lateral_access_rules += 1

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
        local_vuln_id, next_id = add_vertex(
            vertices,
            next_id,
            f"vulExists({name},CVE-LOCAL-{host_index:04d},kernel,localExploit,privEscalation)",
            "LEAF",
            score(rng),
        )
        _, next_id = add_rule(
            vertices=vertices,
            arcs=arcs,
            next_id=next_id,
            conclusion_id=root_exec[host_index],
            label=f"RULE local privilege escalation on {name}",
            prerequisite_ids=[user_exec[host_index], local_vuln_id],
            rng=rng,
        )
        local_privilege_rules += 1

    goal_nodes = []
    goal_rule_count = 0
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
        alt_count = max(1, min(4, services_per_host + 1))
        candidate_hosts = sorted({target_host, *crown_hosts[max(0, len(crown_hosts) - alt_count):]})
        for alt_index in range(alt_count):
            prerequisite_host = candidate_hosts[alt_index % len(candidate_hosts)]
            _, next_id = add_rule(
                vertices=vertices,
                arcs=arcs,
                next_id=next_id,
                conclusion_id=goal_id,
                label=f"RULE reach crown jewel goal{goal_index} alt{alt_index}",
                prerequisite_ids=[root_exec[prerequisite_host], asset_id],
                rng=rng,
            )
            goal_rule_count += 1
        goal_nodes.append(goal_id)

    structure = {
        "host_zones": dict(Counter(zones)),
        "entry_host_count": entry_host_count,
        "public_service_count_per_entry_host": public_service_count,
        "direct_access_rules": direct_access_rules,
        "lateral_access_rules": lateral_access_rules,
        "remote_exploit_rules": remote_exploit_rules,
        "local_privilege_rules": local_privilege_rules,
        "goal_rules": goal_rule_count,
        "notes": [
            "Only entry hosts receive internet-origin netAccess facts.",
            "Internal netAccess is inferred from compromised earlier hosts plus hacl facts.",
            "Remote exploit AND rules converge on per-host execCode(user) OR nodes.",
            "Local privilege escalation produces per-host execCode(root) OR nodes.",
        ],
    }

    return vertices, arcs, goal_nodes, structure


def write_csv(vertices, arcs, vertices_path: Path, arcs_path: Path):
    with vertices_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(vertices)

    with arcs_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(arcs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hosts", type=int, default=1200)
    parser.add_argument("--services-per-host", type=int, default=2)
    parser.add_argument("--vuln-per-service", type=int, default=2)
    parser.add_argument("--lateral-rules-per-host", type=int, default=1)
    parser.add_argument("--goals", type=int, default=4)
    parser.add_argument("--seed", type=int, default=7)
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
        "diagnostics": graph_diagnostics(vertices, arcs, goal_nodes),
        "format": {
            "VERTICES.CSV": "id,label,type,score",
            "ARCS.CSV": "source,target",
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
