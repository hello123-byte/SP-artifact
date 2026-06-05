# Scalable Stackelberg Security Strategy Synthesis on Native MulVAL Attack Graphs via Implicit Cost-Recursive MIP

## Draft Status

This manuscript draft implements the agreed paper plan in an English journal/conference style. It is written as a methods/algorithmic paper centered on large-scale native MulVAL attack graphs. Claims that require additional experiments are marked as `TODO`, so they can be replaced by final measurements after the experimental campaign is complete.

## One-Sentence Argument

In large native MulVAL AND/OR attack graphs, we show that Stackelberg defense strategies can be synthesized without enumerating attack paths by embedding the attacker response into a mixed-integer program through reachability and minimum derivation-cost recursion, supported by a correctness case study and a large generated MulVAL instance, with current scope limited to pure defender strategies and target-level attacker responses.

## Terminology Ledger

- **MulVAL attack graph**: A directed AND/OR dependency graph generated from MulVAL output, represented by `VERTICES.CSV` and `ARCS.CSV`.
- **LEAF node**: An initial fact, such as a vulnerability fact, connectivity fact, service fact, or attacker location.
- **AND node**: An attack rule or derivation step whose prerequisites must all hold.
- **OR node**: An attack state, privilege, or reachability condition that can be obtained through at least one child derivation.
- **Defendable node**: A LEAF node that the defender can disable, harden, isolate, filter, or patch.
- **Target node**: A high-value OR node selected as an attacker goal.
- **Minimum attack derivation cost**: The least cost required to derive a node under the current defense decision.
- **Implicit attacker response**: An embedded MIP representation of the attacker's best response that avoids explicit path enumeration.
- **Strong Stackelberg equilibrium**: A tie-breaking convention in which attacker indifference is resolved in favor of the defender.
- **Weak Stackelberg equilibrium**: A pessimistic tie-breaking convention in which attacker indifference is resolved against the defender.

## Abstract

Attack graphs provide a structured representation of how vulnerabilities, connectivity, and system facts can combine into multi-step compromises. However, strategic defense synthesis on large MulVAL attack graphs remains difficult because attack paths can grow combinatorially, and enumerating them before optimization can make Stackelberg security-game models impractical. This paper presents a path-free mixed-integer programming formulation for Stackelberg defense strategy synthesis on native MulVAL AND/OR attack graphs. The defender first commits to hardening selected defendable facts, after which the attacker observes the defense and chooses either a target node or an empty attack. Instead of enumerating attacker paths, the model introduces reachability and minimum derivation-cost variables for every graph node. LEAF, AND, and OR semantics are encoded by linear constraints, and the attacker's best response is represented through target-choice variables constrained by reward-minus-cost utility comparisons. We prove that, under finite acyclic AND/OR derivation semantics and non-negative costs, the recursive cost variables equal the attacker's minimum derivation costs under any fixed defense, and the response variables therefore encode an optimal attacker response. The resulting formulation computes a cost-sensitive pure Stackelberg equilibrium with optional budget constraints and strong or weak tie-breaking. A preliminary implementation solves a small MulVAL instance to optimality and prepares evaluation on a generated MulVAL graph with 27,667 vertices and 31,278 arcs. These results motivate implicit cost recursion as a route for applying game-theoretic security strategy synthesis directly to large MulVAL outputs, without reducing the attack graph to an explicitly enumerated path set.

**Keywords:** attack graph, MulVAL, Stackelberg game, mixed-integer programming, network hardening, security strategy synthesis

## 1. Introduction

Attack graphs are widely used to reason about multi-step intrusions because they expose how local vulnerabilities and connectivity facts can combine into high-value compromises. MulVAL is especially useful in this setting because it represents attack reasoning as an AND/OR dependency structure rather than as a single linear path. A defender can therefore inspect not only whether a target is reachable, but also which initial facts and rules support that reachability. This representation is valuable for security planning, but it also creates an optimization challenge: the number of possible attack derivations can be much larger than the number of graph nodes and edges.

Stackelberg security games provide a natural formalism for defensive planning on attack graphs. In a two-stage game, the defender commits to a set of defenses, and the attacker observes this decision before selecting an attack. This timing captures many hardening decisions in enterprise networks, where patching, filtering, isolation, or access-control changes are visible through scanning, failed exploitation attempts, or changed reachability. The main modeling challenge is not the Stackelberg structure itself. The challenge is how to represent the follower response without explicitly listing all possible attack paths.

Existing attack-graph security games often simplify the attack graph, enumerate a path or plan set, or solve a reduced interdiction problem. These choices are defensible for small graphs, shortest-path abstractions, or specific Active Directory attack-graph settings. They become limiting for native MulVAL outputs, where AND nodes aggregate prerequisites, OR nodes encode alternative derivations, and the graph can contain many overlapping derivation structures. If a model first enumerates all attack paths and then optimizes over that set, its input size may already be exponential in the original graph.

This paper proposes an implicit mixed-integer programming formulation for Stackelberg defense synthesis on native MulVAL attack graphs. The model borrows the central insight of implicit-response optimization from large attack-graph honeypot placement work, particularly Ngo et al.'s MIP formulation for Active Directory graphs, but adapts it to MulVAL's AND/OR semantics. Instead of recursively counting shortest paths or computing reachability in an Active Directory graph, our formulation recursively computes a minimum attack derivation cost over LEAF, AND, and OR nodes. The attacker then compares target rewards against these costs inside the same MIP.

The resulting formulation has three main benefits. First, it works directly on the MulVAL graph representation and does not require path extraction as a preprocessing step. Second, it keeps attacker best response constraints at the target level, while the least-cost derivation is computed implicitly by the graph constraints. Third, it produces interpretable outputs for security planning: selected defenses, reachable goals, minimum target costs, attacker response, attacker utility, and defender objective value. The current implementation supports strong and weak Stackelberg tie-breaking, optional defense budgets, configurable defense costs, and multiple defendable-node policies.

The contributions of this paper are as follows:

1. We formulate a cost-sensitive two-stage Stackelberg security game directly on native MulVAL AND/OR attack graphs.
2. We introduce an implicit attacker-response MIP that avoids attack-path enumeration by recursively computing minimum attack derivation costs.
3. We encode MulVAL LEAF, AND, and OR semantics, attacker best response, strong/weak tie-breaking, defense cost, target loss, and budget constraints in a single optimization model.
4. We prove that the cost-recursive variables recover the optimal target-level attacker response for any fixed defense strategy.
5. We implement the formulation in a PySCIPOpt-based solver, demonstrate its equilibrium semantics on a small MulVAL correctness case, and prepare scalability evaluation on a generated MulVAL graph with 27,667 vertices and 31,278 arcs.

## 2. Related Work

### 2.1 Attack-Graph Security Games

Attack-graph security games model the interaction between strategic attackers and defenders over graph-structured intrusion opportunities. In this literature, the defender typically modifies the graph by hardening nodes, blocking edges, deploying honeypots, or changing detection probabilities. The attacker then selects a route, target, or plan that maximizes expected utility. Stackelberg formulations are common because many security investments are commitments made before the attacker acts.

The main limitation for large graphs is the representation of the attacker strategy space. If attacker actions are modeled as full paths or plans, the defender's optimization problem may inherit an exponentially large action set. Double-oracle, decomposition, heuristic search, and approximation methods can mitigate this issue, but they still require an attacker oracle or a path-generation mechanism. This paper instead keeps the attacker action space at the target level and embeds the minimum derivation cost inside the defender's optimization problem.

### 2.2 MulVAL and AND/OR Attack Graphs

MulVAL generates attack graphs from logical facts and rules. The resulting graph can be interpreted as an AND/OR dependency graph. LEAF nodes represent initial facts, AND nodes represent derivation rules that require all prerequisites, and OR nodes represent attack states that may be derived in multiple ways. This structure is richer than a simple reachability graph because it distinguishes conjunctive prerequisites from alternative derivations.

This distinction matters for optimization. A shortest-path abstraction can understate the cost of attacks that require multiple simultaneous prerequisites, while a pure reachability abstraction can ignore the cost tradeoffs among alternative derivations. The proposed model preserves the MulVAL AND/OR structure by assigning reachability and cost variables to each node. AND nodes add the costs of all prerequisites, and OR nodes select the least-cost reachable derivation.

### 2.3 Honeypot Placement and Implicit MIP Responses

Ngo et al. studied honeypot placement in large dynamic Active Directory attack graphs using Stackelberg-style MIP formulations. Their work is relevant because it avoids treating all attacker paths as explicit defender variables. For simple attackers, their formulation recursively counts clean shortest paths; for competent attackers, it recursively encodes reachability after honeypot placement. They further extend the formulation to dynamic graph samples.

Our work adapts the implicit-response principle to a different graph semantics and a different defender objective. Rather than placing honeypots in an Active Directory graph to reduce success rates over shortest-path structures, we synthesize hardening strategies on native MulVAL AND/OR graphs. The central recursive quantity is not a path count or a binary reachability value alone. It is the minimum attack derivation cost induced by LEAF, AND, and OR constraints. This shift allows the model to compare attacker rewards and costs while preserving MulVAL's logical structure.

### 2.4 Network Hardening and Interdiction

Network hardening and interdiction models often ask which nodes or edges should be removed, patched, or blocked to increase attacker cost or disconnect high-value assets. These models provide useful abstractions for defense selection under budget constraints. However, many interdiction formulations are built on simple paths, shortest paths, or reachability in ordinary directed graphs. Native MulVAL graphs require a different treatment because a successful derivation may depend on both disjunctive choices and conjunctive prerequisites.

The model proposed here can be viewed as a MulVAL-specific hardening formulation embedded in a Stackelberg game. It chooses defenses over initial facts, propagates their effect through the attack graph, and computes the attacker's rational response based on target reward and derivation cost.

## 3. Problem Formulation

### 3.1 MulVAL Attack Graph

Let `A = (V, E)` denote a MulVAL attack graph. Each node `i in V` has a type in `{LEAF, AND, OR}`. The edge direction follows the implementation convention `conclusion -> prerequisite`. Thus, the outgoing neighbors of a node are the prerequisite or child nodes used to support that node. For a node `i`, let `Ch(i)` denote this set of outgoing children.

LEAF nodes represent initial facts. Examples include `vulExists(...)`, `hacl(...)`, `networkServiceInfo(...)`, and `attackerLocated(...)`. AND nodes represent attack rules that can be applied only if all prerequisite facts or states hold. OR nodes represent derived states, privileges, or reachability conditions that hold if at least one child derivation holds.

### 3.2 Defender Actions

The defender acts first and selects a subset of defendable LEAF nodes. A defense action may represent patching a vulnerability, disabling a connectivity fact, filtering traffic, isolating a service, or otherwise invalidating a fact used by MulVAL. The set of defendable nodes is denoted by `D subset V`. In the current implementation, `D` can be generated by one of four modes:

- `all`: all LEAF nodes except attacker-location facts are defendable.
- `vul`: only `vulExists(...)` facts are defendable.
- `hacl`: only `hacl(...)` facts are defendable.
- `vul_hacl`: both vulnerability and connectivity facts are defendable.

Each defendable node `i` has a defense cost `k_i`. The defender may also face a budget `B`, although the model can be run without an explicit budget.

### 3.3 Attacker Actions

The attacker observes the defender's selected actions and then chooses either a target node or an empty attack. Let `G subset V` denote the set of enabled targets. Each target `g in G` has an attacker reward `r_g` and a defender loss `l_g`.

The attacker's action is deliberately represented at the target level. The attacker does not choose an explicit path variable. Instead, the optimization model computes the minimum derivation cost `c_g` for each target under the chosen defense. The attacker's net utility for target `g` is

```text
U_A(g) = r_g - c_g.
```

The empty attack has utility

```text
U_A(empty) = 0.
```

The attacker chooses a reachable target with maximum non-negative utility, or chooses the empty attack if all reachable targets have non-positive utility.

### 3.4 Defender Objective

The defender minimizes the cost of selected defenses plus the loss caused by the attacker's chosen target. If the attacker chooses the empty attack, no target loss is incurred. For selected target indicators `y_g`, the defender's objective is

```text
minimize  sum_{i in D} k_i d_i + sum_{g in G} l_g y_g.
```

This objective represents a cost-sensitive hardening problem. It does not require all goals to become unreachable. Instead, the defender may prefer to spend a small amount of defense cost if doing so shifts the attacker toward a lower-loss target or makes attack unattractive.

### 3.5 Tie-Breaking

Stackelberg equilibria require a convention for attacker indifference. The model supports two conventions. In the strong Stackelberg setting, if multiple attacker responses have equal utility, the selected response is the one that is best for the defender. In the weak or pessimistic setting, attacker indifference is resolved against the defender. The implementation approximates weak tie-breaking by adding a small loss-weighted perturbation to the attacker comparison expression.

## 4. Implicit Cost-Recursive MIP Model

### 4.1 Decision Variables

The MIP uses four main classes of variables.

For every node `i in V`, a binary variable `x_i` indicates whether node `i` remains true or reachable after the defender's action:

```text
x_i = 1 if node i is available or derivable after defense;
x_i = 0 otherwise.
```

For every defendable node `i in D`, a binary variable `d_i` indicates whether the defender protects that node:

```text
d_i = 1 if the defender protects node i;
d_i = 0 otherwise.
```

For every node `i in V`, a continuous variable `c_i` represents the minimum attack derivation cost for node `i` when it is reachable:

```text
c_i >= 0.
```

For the attacker response, the model includes one binary variable `y_empty` and one binary variable `y_g` for every target `g in G`:

```text
y_empty = 1 if the attacker chooses no attack;
y_g = 1 if the attacker chooses target g.
```

For OR-node cost selection, the implementation also introduces auxiliary binary selector variables `s_{p,j}` that identify which reachable child `j` supplies the least-cost derivation for OR node `p`.

### 4.2 LEAF Reachability

For defendable LEAF nodes, defense disables the corresponding fact:

```text
x_i + d_i = 1,        for i in D.
```

Thus a defended fact is unavailable, and an undefended defendable fact remains available. Non-defendable LEAF nodes are fixed as available:

```text
x_i = 1,              for non-defendable LEAF nodes.
```

This convention treats defense actions as hard invalidation of initial facts. It is suitable for patching, firewalling, or isolating facts that MulVAL uses as attack prerequisites.

### 4.3 AND Reachability

An AND node is reachable if and only if all of its children are reachable. For an AND node `e` with children `Ch(e)`, the model uses

```text
x_e <= x_j,                         for all j in Ch(e),
x_e >= sum_{j in Ch(e)} x_j - |Ch(e)| + 1.
```

The first constraint ensures that an AND node cannot be true unless every prerequisite is true. The second constraint ensures that if all prerequisites are true, then the AND node is true.

### 4.4 OR Reachability

An OR node is reachable if and only if at least one of its children is reachable. For an OR node `p`, the model uses

```text
x_p >= x_j,                         for all j in Ch(p),
x_p <= sum_{j in Ch(p)} x_j.
```

These constraints encode alternative derivations. If any child derivation is reachable, the OR node is reachable. If no child is reachable, the OR node is unavailable.

### 4.5 Minimum Cost Recursion

The minimum-cost variables are the key mechanism that avoids attack-path enumeration. The model first forces unreachable nodes to have zero cost:

```text
c_i <= M x_i,                       for all i in V.
```

Here `M` is a Big-M value computed from graph size and configured attack costs unless provided manually.

For LEAF nodes, the cost is the configured fact cost if the fact is available:

```text
c_i = a_i x_i.
```

For an AND node `e`, the cost is the action cost plus the costs of all prerequisites:

```text
c_e = a_e + sum_{j in Ch(e)} c_j,    if x_e = 1.
```

The implementation encodes this equality with Big-M lower and upper bounds:

```text
c_e >= a_e + sum_{j in Ch(e)} c_j - M(1 - x_e),
c_e <= a_e + sum_{j in Ch(e)} c_j + M(1 - x_e).
```

For an OR node `p`, the cost is the minimum cost among reachable child derivations:

```text
c_p = min { c_j : j in Ch(p), x_j = 1 }.
```

This minimum is encoded by child selector variables. A child can be selected only if it is reachable:

```text
s_{p,j} <= x_j.
```

If the OR node is reachable, exactly one reachable child is selected:

```text
sum_{j in Ch(p)} s_{p,j} = x_p.
```

If child `j` is selected, the parent cost equals the child's cost:

```text
c_p >= c_j - M(1 - s_{p,j}),
c_p <= c_j + M(1 - s_{p,j}).
```

The model also enforces that the OR-node cost does not exceed the cost of any reachable child:

```text
c_p <= c_j + M(1 - x_j),             for all j in Ch(p).
```

Together, these constraints express least-cost derivation over the AND/OR graph. The attack path itself is not a variable and is not enumerated.

### 4.6 Attacker Best Response

The attacker chooses exactly one response:

```text
y_empty + sum_{g in G} y_g = 1.
```

A target can be selected only if it remains reachable:

```text
y_g <= x_g,                          for all g in G.
```

If the attacker selects target `g`, that target must have utility at least as high as every other reachable target:

```text
r_g - c_g >= r_h x_h - c_h - M_U(1 - y_g),
                                      for all g,h in G.
```

The selected target must also be at least as good as the empty attack:

```text
r_g - c_g >= -M_U(1 - y_g).
```

If the attacker selects the empty attack, all reachable targets must have non-positive utility:

```text
0 >= r_h x_h - c_h - M_U(1 - y_empty),
                                      for all h in G.
```

Here `M_U` is a utility Big-M value derived from the attack-cost Big-M and the largest configured target reward.

### 4.7 Defender Objective and Budget

The defender minimizes defense cost plus loss from the attacker-selected target:

```text
minimize  sum_{i in D} k_i d_i + sum_{g in G} l_g y_g.
```

If a defense budget is configured, the following constraint is added:

```text
sum_{i in D} k_i d_i <= B.
```

This single-level MIP therefore encodes both the defender commitment and the follower's best response.

### 4.8 Complexity of the Formulation

The formulation introduces one reachability variable and one cost variable per graph node, one defense variable per defendable LEAF node, one response variable per target plus the empty response, and one OR-selector variable per OR-child relation. The number of reachability constraints is linear in the number of graph edges. The number of attacker comparison constraints is quadratic in the number of targets, which is typically much smaller than the number of graph nodes and paths.

This structure is important for scalability. The model size depends primarily on the native graph size rather than on the number of complete attack paths. For graphs in which the number of paths is exponential in the number of nodes, this difference is the central computational advantage of the method.

## 5. Theoretical Analysis

This section states the proof obligations needed for the model. The goal is to show that the MIP does not merely compute some graph score. Under explicit assumptions, its cost-recursive representation gives the attacker's optimal response to any fixed defender strategy. The Stackelberg equilibrium claim then follows from embedding this best-response condition into the defender's optimization problem.

### 5.1 Assumptions and Semantic Cost Definition

The proofs use the following assumptions.

1. The MulVAL dependency graph is finite and acyclic after preprocessing, or the analysis is applied to an acyclic derivation subgraph. This ensures that recursive reachability and cost definitions are well founded.
2. Attack costs and defense costs are non-negative.
3. A defense action only disables defendable LEAF facts. It does not create new facts or new derivation rules.
4. AND-node costs are additive over their prerequisite derivations, and OR-node costs select the least-cost alternative derivation. If shared prerequisite derivations should be paid only once globally, the model must be extended with additional shared-cost variables.
5. The Big-M constants are at least as large as the maximum finite derivation cost and utility difference that can occur in the instance.

For a fixed defense strategy `d`, define the semantic reachability value `R_d(i)` and semantic minimum derivation cost `C_d(i)` for each node `i`. For unreachable nodes, set `C_d(i) = infinity`. For reachable nodes, define costs recursively:

```text
LEAF:  R_d(i) = 1 iff the fact is not disabled by d.
       C_d(i) = a_i if R_d(i) = 1.

AND:   R_d(i) = 1 iff R_d(j) = 1 for all j in Ch(i).
       C_d(i) = a_i + sum_{j in Ch(i)} C_d(j) if R_d(i) = 1.

OR:    R_d(i) = 1 iff R_d(j) = 1 for at least one j in Ch(i).
       C_d(i) = min { C_d(j) : j in Ch(i), R_d(j) = 1 } if R_d(i) = 1.
```

These definitions describe the attacker's best derivation cost inside the model. An attacker strategy for target `g` is therefore a finite AND/OR derivation tree rooted at `g`: an AND node includes all child derivations, an OR node chooses one child derivation, and a LEAF node uses an available fact.

### 5.2 Lemma 1: Reachability Correctness

**Lemma 1.** Fix any defender strategy `d`. In every feasible MIP solution consistent with `d`, the reachability variable `x_i` equals the semantic reachability value `R_d(i)` for every node `i`.

**Proof sketch.** Because the graph is acyclic, order nodes from prerequisites to conclusions. For LEAF nodes, the constraints `x_i + d_i = 1` for defendable facts and `x_i = 1` for non-defendable facts match the definition of `R_d(i)`. For an AND node, constraints `x_i <= x_j` for every child and `x_i >= sum_j x_j - |Ch(i)| + 1` force `x_i = 1` exactly when all children are reachable. For an OR node, constraints `x_i >= x_j` for every child and `x_i <= sum_j x_j` force `x_i = 1` exactly when at least one child is reachable. By induction over the topological order, `x_i = R_d(i)` for all nodes. 

### 5.3 Lemma 2: Cost-Recursion Optimality

**Lemma 2.** Fix any defender strategy `d`. For every reachable node `i`, the MIP cost variable `c_i` equals the semantic minimum derivation cost `C_d(i)`. For every unreachable node, the MIP sets `c_i = 0`.

**Proof sketch.** The constraint `c_i <= M x_i` sets `c_i = 0` whenever `x_i = 0`. For reachable LEAF nodes, the equality `c_i = a_i x_i` gives `c_i = a_i = C_d(i)`. For a reachable AND node, the Big-M lower and upper constraints are active because `x_i = 1`, so `c_i = a_i + sum_j c_j`. By induction, each child cost equals its semantic minimum cost, hence the AND-node cost equals `C_d(i)`. For a reachable OR node, selector constraints require exactly one reachable child to be selected. If child `j` is selected, the Big-M equality constraints force `c_i = c_j`. The additional upper constraints `c_i <= c_j` for every reachable child prevent selecting a child with cost greater than the minimum. Therefore, `c_i` equals the minimum child cost, which is exactly `C_d(i)`. Induction over the acyclic graph proves the claim for all nodes.

### 5.4 Theorem 1: Optimal Attacker Response Under Fixed Defense

**Theorem 1.** Fix any defender strategy `d`. Let the attacker's feasible pure actions be `empty` and every reachable target `g in G`. The MIP attacker-response constraints select an action with maximum attacker utility

```text
U_A(empty) = 0,
U_A(g) = r_g - C_d(g).
```

**Proof sketch.** By Lemma 1, the constraint `y_g <= x_g` allows the attacker to select only reachable targets. By Lemma 2, each selected target's MIP cost `c_g` equals the semantic minimum derivation cost `C_d(g)`. The constraint `y_empty + sum_g y_g = 1` forces exactly one response. If `y_g = 1`, the best-response constraints enforce `r_g - c_g >= r_h x_h - c_h` for every target `h`, and `r_g - c_g >= 0` against the empty attack. Thus selected target `g` maximizes attacker utility. If `y_empty = 1`, the empty-response constraints enforce `0 >= r_h x_h - c_h` for every target `h`; hence no target has positive utility, and the empty attack is optimal. Therefore every feasible selected response is an attacker best response under defense `d`.

### 5.5 Theorem 2: Pure Strong Stackelberg Equilibrium Correctness

**Theorem 2.** Under strong tie-breaking, any optimal solution of the MIP is a pure strong Stackelberg equilibrium for the modeled game.

**Proof sketch.** The defender variables define a pure defender strategy. By Theorem 1, the response variables are restricted to attacker best responses for that strategy. Under strong tie-breaking, if several attacker best responses have equal utility, the MIP objective `defense cost + selected target loss` chooses the response with minimum defender loss because `y_g` enters the defender objective directly. The MIP then minimizes the defender objective over all feasible defender strategies and their strong-tie attacker responses. This is exactly the definition of a pure strong Stackelberg equilibrium for the modeled finite game.

For weak or pessimistic tie-breaking, the implementation uses a small perturbation term in the attacker's comparison. This is exact if the perturbation is smaller than the minimum positive utility gap divided by the maximum target-loss difference. Under that condition, the perturbation cannot change strict attacker preferences and can only resolve utility ties against the defender.

### 5.6 Proposition 1: Polynomial-Size Path-Free Formulation

**Proposition 1.** The MIP size is polynomial in the native MulVAL graph size and does not depend on the number of explicit attack paths.

**Proof sketch.** The formulation creates one binary reachability variable and one continuous cost variable per node, one defense variable per defendable LEAF node, one response variable per target plus the empty response, and one selector variable per OR-child relation. Thus the variable count is

```text
O(|V| + |D| + |G| + |E_OR|).
```

The reachability and cost-recursion constraints are linear in nodes and edges, while the attacker-comparison constraints are `O(|G|^2)`. Thus the constraint count is

```text
O(|V| + |E| + |E_OR| + |G|^2).
```

In contrast, the number of complete attack derivations in an AND/OR graph can be exponential in graph depth. For example, a layered graph with two OR alternatives at each layer has `2^L` derivations but only `O(L)` layers. The proposed formulation is therefore path-free in the formal sense that its size is governed by graph nodes and edges, not by enumerated paths.

### 5.7 Proposition 2: Defense Monotonicity

**Proposition 2.** If defense strategy `d_2` disables every LEAF node disabled by `d_1`, and possibly more, then the reachable node set under `d_2` is a subset of the reachable node set under `d_1`. The extended minimum cost `C_d(i)`, with unreachable nodes assigned `infinity`, cannot decrease when moving from `d_1` to `d_2`.

**Proof sketch.** Additional defenses only remove available LEAF facts. They do not add facts or rules. By induction, an AND node cannot become newly reachable when one or more prerequisites are removed, and an OR node cannot become newly reachable when its child set of reachable derivations shrinks. Thus reachability is monotone decreasing. The set of feasible derivations for any target under `d_2` is a subset of the feasible derivations under `d_1`; the minimum over a subset cannot be smaller than the minimum over the original set. If no derivation remains, the extended cost becomes `infinity`.

### 5.8 Proposition 3: Target Dependency Closure Soundness

**Proposition 3.** For a fixed target set `G`, reducing the graph to the dependency closure reachable from `G` along `conclusion -> prerequisite` edges preserves target reachability, target minimum derivation costs, attacker utilities, and the Stackelberg solution over `G`.

**Proof sketch.** Under the MulVAL edge convention, every node that can contribute to a target derivation must be reachable by recursively following outgoing prerequisite edges from at least one target. Nodes outside this closure are not children, prerequisites, or subderivations of any selected target. Removing them therefore does not change the recursive reachability or cost equations for any target in `G`. Since attacker utilities depend only on target rewards and target costs, and the defender objective depends only on selected defenses and attacker-selected target loss, the reduced graph yields the same feasible target responses and the same optimal defender strategy restricted to defenses that can affect `G`. Defenses outside the closure are dominated because they cannot change any selected target's reachability or cost.

This proposition justifies an optional preprocessing step when the number of strategic targets is small relative to the full MulVAL graph. The reduction does not change the modeled game over the selected target set; it only removes variables and constraints that are irrelevant to those targets.

### 5.9 Proposition 4: Big-M Soundness Requirement

**Proposition 4.** If the attack-cost Big-M is at least the maximum finite recursive derivation cost over all nodes and feasible defenses, and the utility Big-M is at least the maximum possible utility difference, then the Big-M constraints are exact relaxations of the conditional cost and response statements.

**Proof sketch.** When the associated binary variable is active, each Big-M constraint reduces to the intended equality or inequality. When the binary variable is inactive, a sufficiently large Big-M makes the constraint non-binding over the full feasible range of costs or utilities. Therefore, no feasible semantic solution is excluded and no inactive implication incorrectly restricts the model.

This proposition is also a practical modeling caution. A simple bound such as `( |V| + 1 )` times the largest node cost is valid when each finite derivation can be bounded by at most one cost contribution per graph node. If shared subderivations are counted repeatedly by the additive AND semantics, a safer recursive upper bound or a user-specified Big-M should be used.

### 5.10 Proposition 5: Recovering a Representative Optimal Derivation

**Proposition 5.** For any selected reachable target, the OR-selector variables and AND-node child relations identify a representative minimum-cost derivation tree under the selected defense.

**Proof sketch.** Starting at the selected target, recursively follow the selected child at every OR node and include all children at every AND node. Lemma 2 ensures that each selected OR child has the minimum child cost and that each AND node's cost equals the sum of its prerequisite costs plus its action cost. The resulting finite derivation tree reaches available LEAF nodes and has total cost equal to the selected target's `c_g`. This derivation can be extracted after optimization if the implementation records selector values.

## 6. Implementation and Experimental Setup

### 6.1 Input Pipeline

The implementation consumes three files. `VERTICES.CSV` contains the node identifier, node label, node type, and optional score. `ARCS.CSV` contains directed edges in the `source,target` format, where `source` depends on `target`. A JSON configuration file supplies game parameters, including target rewards, target losses, node attack costs, defense costs, defendable-node flags, defense budget, and tie-breaking mode.

The configuration can be generated from MulVAL CSV files using `build_mulval_game_config.py`. This script identifies candidate targets, assigns default rewards and losses, marks defendable LEAF nodes according to a selected defendable mode, and writes the resulting game parameters into JSON.

The MIP is built and solved by `solve_mulval_reachability_stackelberg.py`. The solver reads the graph and configuration, optionally reduces the graph to the selected targets' dependency closure, constructs reachability constraints, constructs cost-recursion constraints, embeds attacker best-response constraints, applies the optional budget constraint, and optimizes the defender objective.

### 6.2 Solver

The current implementation uses PySCIPOpt with SCIP as the MIP solver. The solver output includes the optimization status, selected defenses, reachable goals, minimum attack costs, attacker response, attacker utility, defender utility, and objective value. It also records the solution concept, tie-breaking mode, attack-cost source, Big-M value, defendable-node mode, and target-closure reduction statistics when the optional reduction is enabled.

### 6.3 Datasets

The current workspace contains two evaluation inputs.

The first is a small MulVAL instance used for correctness and interpretability. In the available result file, the model solved this instance to optimality under the strong Stackelberg convention. The configuration used two targets, eight defendable vulnerability facts, constant action cost, zero default leaf cost, and no defense budget.

The second is a generated large MulVAL graph used for scalability preparation. This graph contains 27,667 vertices, 31,278 arcs, and four goal nodes. It was generated with 1,200 hosts, two services per host, two vulnerabilities per service, one lateral rule per host, and random seed 7.

TODO: Add at least three additional generated graph sizes to support a scalability curve, for example 300, 600, 1,200, and 2,400 hosts.

### 6.4 Baselines

The final experimental study should compare the proposed implicit MIP against the following baselines:

1. **No defense**: The defender selects no hardening actions. This baseline shows the attacker's natural best response and target utility.
2. **Greedy defense**: The defender iteratively selects the defendable node that gives the largest one-step decrease in defender objective or reachable target utility.
3. **Path-enumeration MIP on small graphs**: For small instances where path enumeration is feasible, enumerate attack derivations and solve a path-based interdiction or Stackelberg model.
4. **Reachability-only defense**: Remove cost recursion and optimize only for target disconnection. This ablation tests whether cost-sensitive modeling changes the selected strategy.

TODO: Implement or script these baselines before submission. The path-enumeration baseline should be restricted to small graphs because its expected failure on large graphs is part of the scalability argument.

### 6.5 Metrics

The evaluation should report both optimization and security metrics:

- solver status;
- wall-clock runtime;
- number of variables and constraints;
- memory use, if available;
- selected defense cost;
- defender objective;
- attacker utility;
- number of reachable targets;
- minimum attack derivation cost per reachable target;
- selected attacker response.

For scalability, runtime and model size should be plotted against vertices, arcs, defendable nodes, and OR-selector variables.

## 7. Results

### 7.1 Correctness Case Study

The small MulVAL instance demonstrates that the model produces an interpretable Stackelberg equilibrium. The solver returned the status `optimal` and reported the solution concept as a cost-sensitive pure strong Stackelberg equilibrium. The model used target utility `reward(goal) - minimum_attack_derivation_cost(goal)` and defender objective `defense_cost + loss(attacker_chosen_goal)`.

Under the available configuration, the defender selected one vulnerability fact:

```text
vulExists(historian,'CVE-2017-5155',http_server,remoteExploit,privEscalation)
```

The selected defense had cost 1.0. After this defense, no configured target remained reachable, and the attacker's best response was the empty attack. The attacker's final utility was 0.0, and the defender's objective value was 1.0. This result is consistent with the intended semantics: the defender spends a small amount to invalidate a critical initial fact, the AND/OR reachability constraints propagate the effect to target nodes, and the attacker rationally avoids attacks with non-positive utility.

This case study also illustrates why the output is useful for security planning. The model does not merely report that the graph was hardened. It identifies the specific MulVAL fact to defend, explains the post-defense attacker response, and reports whether any target remains reachable with positive utility.

### 7.2 Large-Graph Scalability Preparation

The generated large MulVAL graph contains 27,667 vertices and 31,278 arcs. It includes four target nodes and was produced from a synthetic setting with 1,200 hosts, two services per host, two vulnerabilities per service, one lateral rule per host, and seed 7. This graph is useful because it is large enough to stress path-based approaches while still preserving native MulVAL node and edge semantics.

TODO: Run the solver on this large configuration and report the following:

```text
solver status:
wall-clock runtime:
number of binary variables:
number of continuous variables:
number of constraints:
number of OR-selector variables:
objective value:
attacker response:
selected defense count:
selected defense cost:
reachable goal count:
```

The expected claim should be calibrated to the observed result. If SCIP solves the model to optimality, the paper can state that the formulation solved a 27,667-node native MulVAL graph without path enumeration. If SCIP reaches a time limit with a valid incumbent, the paper should instead report incumbent quality, optimality gap, and runtime.

### 7.3 Effectiveness Against Baselines

The main effectiveness result should compare the proposed MIP with no defense and greedy defense. The no-defense baseline establishes which targets are attractive before hardening. The greedy baseline tests whether local hardening choices are sufficient or whether the Stackelberg model finds different defenses by anticipating attacker substitution.

TODO: Produce a table with columns:

```text
method | objective | defense cost | attacker utility | attacker response | reachable targets | runtime
```

The strongest expected result would be that the implicit MIP achieves a lower defender objective than greedy defense under the same budget or defense-cost setting. If greedy performs similarly on some small instances, this should be reported because it helps identify when the full Stackelberg formulation is necessary.

### 7.4 Ablation Studies

The ablation study should isolate the design choices that make the method work.

First, compare defendable-node modes. The `vul` setting tests vulnerability patching only. The `hacl` setting tests connectivity control only. The `vul_hacl` setting tests a combined defense surface. This comparison shows whether the model's selected defenses depend primarily on software vulnerability facts or network reachability facts.

Second, compare strong and weak tie-breaking. Strong Stackelberg tie-breaking may select a lower-loss attacker response under equal attacker utility. Weak tie-breaking tests a more conservative setting in which equal-utility responses are resolved against the defender.

Third, compare budgeted and unbudgeted settings. A budgeted setting reflects operational constraints. An unbudgeted setting reveals the cost level at which complete or near-complete target protection becomes optimal.

Fourth, compare the full cost-recursive model against a reachability-only version. This ablation tests whether attack costs change defense selection beyond simple disconnection.

## 8. Discussion

The central advance of this paper is the replacement of path enumeration with graph-native cost recursion. In a native MulVAL graph, an attack target may be supported by many overlapping derivations. Enumerating each derivation can make the optimization input much larger than the graph itself. The proposed model keeps the optimization tied to nodes and edges by computing the least-cost derivation through LEAF, AND, and OR constraints.

The method also clarifies how attacker rationality can be embedded without explicitly solving a separate follower problem for every defender strategy. The attacker response is represented by target-choice variables, while the cost of each target is computed by the same MIP. This design converts a bilevel Stackelberg problem into a single-level mixed-integer formulation under a pure-strategy, target-choice attacker model.

The relationship to Ngo et al.'s honeypot-placement formulation is methodological rather than identical. Their model addresses Active Directory graphs and uses recursive quantities suited to shortest-path attackers and reachability under honeypot placement. This paper addresses MulVAL AND/OR graphs, where AND nodes require conjunctive prerequisite costs and OR nodes represent alternative derivations. The response quantity is therefore a minimum attack derivation cost, not a clean-path count or binary reachability measure alone.

The model has practical value because its output maps back to security actions. A selected `vulExists(...)` defense corresponds to patching or mitigating a vulnerability fact. A selected `hacl(...)` defense corresponds to blocking or filtering a connectivity fact. The attacker response identifies the residual target that remains attractive, or confirms that the empty attack is rational under the configured rewards and costs.

The current formulation has several limitations. The attacker chooses a single target or empty attack rather than a mixed strategy. The defender also commits to a pure strategy. The model reports minimum target costs but does not currently extract the corresponding representative derivation path. Cost parameters require calibration from vulnerability severity, exploit effort, operational impact, or domain expert input. Finally, the current model is static; dynamic attack graphs could be handled by extending the formulation across graph snapshots, but that extension is not evaluated in this draft.

These limitations suggest clear extensions. Representative derivation extraction could be added using the OR-selector variables after optimization. Mixed strategies could be explored through decomposition or double-oracle methods. Dynamic MulVAL settings could adapt the multi-snapshot idea used in Active Directory honeypot placement, but with cost-recursive MulVAL constraints in each snapshot.

## 9. Conclusion

This paper presents a path-free mixed-integer programming formulation for Stackelberg security strategy synthesis on native MulVAL attack graphs. The model embeds attacker response by recursively computing reachability and minimum attack derivation costs over LEAF, AND, and OR nodes. It then selects defenses that minimize defense cost plus attacker-induced target loss.

The preliminary implementation demonstrates the intended equilibrium semantics on a small MulVAL instance and prepares evaluation on a generated graph with 27,667 vertices and 31,278 arcs. The main implication is that game-theoretic defense synthesis can be applied directly to large MulVAL outputs without first enumerating attack paths. The current scope is limited to pure strategies and target-level attacker responses, but the formulation provides a foundation for dynamic graph extensions, calibrated probability-to-cost models, and post-solution derivation extraction.

## References

[1] H. Q. Ngo, M. Guo, and H. Nguyen, "Catch Me if You Can: Effective Honeypot Placement in Dynamic AD Attack Graphs," IEEE INFOCOM 2024, DOI: 10.1109/INFOCOM52122.2024.10621210.

[2] X. Ou, S. Govindavajhala, and A. W. Appel, "MulVAL: A Logic-based Network Security Analyzer," USENIX Security Symposium, 2005. TODO: verify final bibliographic metadata.

[3] K. Durkota, V. Lisy, B. Bosansky, and C. Kiekintveld, "Optimal Network Security Hardening Using Attack Graph Games," IJCAI, 2015. TODO: verify final bibliographic metadata.

[4] K. Durkota, V. Lisy, B. Bosansky, C. Kiekintveld, and M. Pechoucek, "Hardening Networks Against Strategic Attackers Using Attack Graph Games," Computers & Security, 2019. TODO: verify final bibliographic metadata.

[5] S. Milani, W. Shen, K. S. Chan, S. Venkatesan, N. O. Leslie, C. Kamhoua, and F. Fang, "Harnessing the Power of Deception in Attack Graph-Based Security Games," GameSec, 2020. TODO: verify final bibliographic metadata.

## Missing Inputs Before Submission

1. Runtime and optimality results for the 27,667-node graph.
2. A scalability sweep across at least three graph sizes.
3. Baseline implementations for no defense, greedy defense, and path enumeration on small graphs.
4. Ablation results for `vul`, `hacl`, `vul_hacl`, strong/weak tie-breaking, and budget settings.
5. Final calibrated cost policy for attack costs, defense costs, target rewards, and target losses.
6. Verified BibTeX entries for all references.
