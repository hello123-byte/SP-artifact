# -*- coding: utf-8 -*-
"""Generate a large synthetic MulVAL-style dependency attack graph.

Output format:
  VERTICES.CSV rows: id,label,type,score
  ARCS.CSV rows: source,target

Edge direction follows the MulVAL CSV convention used by the solver:
  conclusion -> prerequisite

The generated graph is a layered AND/OR dependency graph:
  OR privilege/access nodes are produced by AND rule nodes;
  AND rule nodes depend on one previous OR node plus one or more LEAF facts.

This is for scalability testing, not for representing a real enterprise.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from pathlib import Path


def safe_print(text: str):
    encoding = sys.stdout.encoding or "utf-8"
    print(text.encode(encoding, errors="backslashreplace").decode(encoding))


def score(rng: random.Random, low: float = 0.01, high: float = 0.95) -> float:
    return round(rng.uniform(low, high), 4)


def add_vertex(vertices, node_id: int, label: str, node_type: str, value: float):
    vertices.append((node_id, label, node_type, value))
    return node_id + 1


def build_graph(
    hosts: int,
    services_per_host: int,
    vuln_per_service: int,
    lateral_rules_per_host: int,
    goals: int,
    seed: int,
):
    rng = random.Random(seed)
    vertices = []
    arcs = []
    next_id = 1

    attacker_leaf = next_id
    next_id = add_vertex(vertices, next_id, "attackerLocated(internet)", "LEAF", 1.0)

    # A small set of externally reachable starting access nodes.
    external_access = []
    for h in range(min(10, hosts)):
        or_id = next_id
        next_id = add_vertex(vertices, next_id, f"netAccess(host{h},tcp,80)", "OR", score(rng))
        and_id = next_id
        next_id = add_vertex(vertices, next_id, f"RULE external access to host{h}:80", "AND", score(rng))
        hacl_id = next_id
        next_id = add_vertex(vertices, next_id, f"hacl(internet,host{h},tcp,80)", "LEAF", score(rng))
        arcs.append((or_id, and_id))
        arcs.append((and_id, attacker_leaf))
        arcs.append((and_id, hacl_id))
        external_access.append(or_id)

    compromise_nodes = []
    access_nodes_by_host = [[] for _ in range(hosts)]
    for h in range(hosts):
        for s in range(services_per_host):
            port = 8000 + s
            access_or = next_id
            next_id = add_vertex(vertices, next_id, f"netAccess(host{h},tcp,{port})", "OR", score(rng))
            access_nodes_by_host[h].append(access_or)

            access_rule = next_id
            next_id = add_vertex(vertices, next_id, f"RULE network reachability host{h}:{port}", "AND", score(rng))
            hacl_id = next_id
            next_id = add_vertex(vertices, next_id, f"hacl(internet,host{h},tcp,{port})", "LEAF", score(rng))
            arcs.append((access_or, access_rule))
            arcs.append((access_rule, attacker_leaf))
            arcs.append((access_rule, hacl_id))

            service_leaf = next_id
            next_id = add_vertex(
                vertices,
                next_id,
                f"networkServiceInfo(host{h},svc{s},tcp,{port},user)",
                "LEAF",
                score(rng),
            )

            for v in range(vuln_per_service):
                comp_or = next_id
                next_id = add_vertex(vertices, next_id, f"execCode(host{h},user,svc{s},vuln{v})", "OR", score(rng))
                rule_id = next_id
                next_id = add_vertex(
                    vertices,
                    next_id,
                    f"RULE remote exploit host{h} svc{s} vuln{v}",
                    "AND",
                    score(rng),
                )
                vuln_leaf = next_id
                next_id = add_vertex(
                    vertices,
                    next_id,
                    f"vulExists(host{h},CVE-SYN-{h:04d}-{s:02d}-{v:02d},svc{s},remoteExploit,privEscalation)",
                    "LEAF",
                    score(rng),
                )
                arcs.append((comp_or, rule_id))
                arcs.append((rule_id, access_or))
                arcs.append((rule_id, service_leaf))
                arcs.append((rule_id, vuln_leaf))
                compromise_nodes.append(comp_or)

    # Lateral movement creates shared substructure and many alternative paths.
    for h in range(hosts):
        for r in range(lateral_rules_per_host):
            src_host = rng.randrange(hosts)
            src_comp = rng.choice(compromise_nodes)
            dst_access = rng.choice(access_nodes_by_host[h])
            lateral_or = next_id
            next_id = add_vertex(vertices, next_id, f"netAccess(host{h},tcp,lateral{r})", "OR", score(rng))
            lateral_rule = next_id
            next_id = add_vertex(
                vertices,
                next_id,
                f"RULE lateral movement from host{src_host} to host{h} rule{r}",
                "AND",
                score(rng),
            )
            credential_leaf = next_id
            next_id = add_vertex(vertices, next_id, f"credentialAvailable(host{src_host},host{h},cred{r})", "LEAF", score(rng))
            arcs.append((lateral_or, lateral_rule))
            arcs.append((lateral_rule, src_comp))
            arcs.append((lateral_rule, dst_access))
            arcs.append((lateral_rule, credential_leaf))

    # Root goals are OR nodes with indegree 0, so the solver detects them by default.
    goal_nodes = []
    for g in range(goals):
        target_host = hosts - 1 - (g % max(1, min(goals, hosts)))
        goal_or = next_id
        next_id = add_vertex(vertices, next_id, f"execCode(crown_jewel_{target_host},root,goal{g})", "OR", score(rng))
        goal_rule_count = max(2, min(8, services_per_host * vuln_per_service))
        for k in range(goal_rule_count):
            prerequisite = rng.choice(compromise_nodes)
            rule_id = next_id
            next_id = add_vertex(vertices, next_id, f"RULE privilege escalation to goal{g} alt{k}", "AND", score(rng))
            local_vuln = next_id
            next_id = add_vertex(
                vertices,
                next_id,
                f"vulExists(crown_jewel_{target_host},CVE-GOAL-{g:02d}-{k:02d},kernel,localExploit,privEscalation)",
                "LEAF",
                score(rng),
            )
            arcs.append((goal_or, rule_id))
            arcs.append((rule_id, prerequisite))
            arcs.append((rule_id, local_vuln))
        goal_nodes.append(goal_or)

    return vertices, arcs, goal_nodes


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

    vertices, arcs, goal_nodes = build_graph(
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


if __name__ == "__main__":
    main()
