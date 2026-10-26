# Cost-Recursive Stackelberg Defense on MulVAL Attack Graphs

Experimental artifact for **Beyond Path Enumeration: Cost-Recursive Stackelberg
Security Decision-Making on Large-Scale MulVAL Attack Graphs**.

The repository includes **six benchmark attack graphs**, **four case-study
scenarios**, and **1,003 archived experiment tasks**, together with the model,
baselines, fixed inputs, numerical summaries, and reproduction scripts.

## Overview

The project implements the following workflow:

1. Load frozen MulVAL attack graphs, target sets, and fixed attack/defense costs.
2. Model the defender's patch decisions and the attacker's best response with a cost-recursive Stackelberg formulation.
3. Solve the optimization model with SCIP through PySCIPOpt.
4. Compare the proposed method with no defense, random defense, genetic-algorithm, and path-enumeration baselines.
5. Evaluate defense effectiveness, runtime, parameter sensitivity, budget effects, and anytime performance.
6. Independently verify archived strategies and regenerate figures from numerical summaries.

Graph generation from scratch requires external components that are not bundled
here. [AUDIT.txt](AUDIT.txt) records manuscript discrepancies and provenance
qualifications; the archived data retain the measured outcomes.

## Contents

- [Project Structure](#project-structure)
- [Node and Edge Types](#node-and-edge-types)
- [Model and Comparison Methods](#model-and-comparison-methods)
- [Benchmark Datasets](#benchmark-datasets)
- [Quick Start](#quick-start)
- [Experiments and Paper Correspondence](#experiments-and-paper-correspondence)
- [Case Study](#case-study)
- [Environment and Running Experiments](#environment-and-running-experiments)
- [Results and Metrics](#results-and-metrics)
- [Verification and Provenance](#verification-and-provenance)
- [Manuscript Notes and Anonymous Distribution](#manuscript-notes-and-anonymous-distribution)

## Project Structure

```text
submission-artifact/
├── README.md                         # Project overview and reproduction guide
├── AUDIT.txt                         # Manuscript-to-data audit
├── requirements.txt                  # Pinned Python dependencies
├── environment.json                  # Software-version evidence
├── MANIFEST.json                     # Release-file SHA-256 hashes
├── experiment_index.json             # Index of 1,003 archived tasks
│
├── run.py                            # Run selected frozen-input experiments
├── verify.py                         # Verify archived results independently
├── plot.py                           # Regenerate benchmark Figures 3–5
├── solve_mulval__stackelberg_main.py  # Proposed optimization model
├── mulval_cost_calibration.py        # Cost-calibration support
│
├── baselines/                        # Comparison methods
│   ├── baseline_common.py
│   ├── empty_defense_baseline.py
│   ├── random_defense_baseline.py
│   ├── ga_defense_baseline.py
│   └── full_path_enumeration_baseline.py
│
├── data/                             # Frozen graphs and fixed cost maps
│   ├── D64/                          # AG1
│   ├── D244/                         # AG2
│   ├── D1045/                        # AG3, including sensitivity cost map
│   ├── D2822/                        # AG4
│   ├── D6330/                        # AG5
│   └── D11026/                       # AG6 and generation evidence
│
├── experiments/                      # Archived tasks, metadata, and results
│   ├── tables/
│   ├── sensitivity/
│   ├── budget/
│   ├── anytime_budget300/
│   ├── anytime_unbudgeted_supplement/
│   ├── anytime_AG6/
│   └── case/
│
├── SP/
│   ├── scripts/                      # Fixed-work and anytime workers
│   └── 08_case_study/                 # Six-host case study
│       ├── graph/                    # Actual 45-node solver input
│       ├── configs/                  # Scenario parameters S1–S4
│       ├── case_data.py
│       └── run_case_study.py
│
├── tables/                           # CSV summaries and manuscript tables
├── figures/                          # PNG/PDF plots and DOT/SVG case graph
└── audit/                            # Source, hash, and privacy audit records
```

## Node and Edge Types

The MulVAL attack graph contains three node types:

| Type | Meaning |
| --- | --- |
| `LEAF` | Input facts, including patchable vulnerability facts. |
| `AND` | Inference rules that require all prerequisites. |
| `OR` | Derived facts that can be reached through alternative derivations. |

An arc in `ARCS.CSV` is stored as a dependency: in `(i, j, ...)`, node `i`
depends on prerequisite `j`. A drawing may reverse the arrows to show
prerequisites leading to conclusions. Node IDs belong to a particular graph;
use the target IDs recorded in that graph's task files.

## Model and Comparison Methods

The defender chooses vulnerabilities to patch. After observing that defense,
the attacker chooses a reachable target and a minimum-cost attack that reaches
it, or abandons the attack for zero utility. The model uses a strong
Stackelberg convention: equal-utility attacker choices favor the defender.

For a defense set D and a reachable target g:

```text
attacker utility = target reward R_g - minimum attack cost C_g(D)
defender objective J(D) = patch cost(D) + loss of the selected target
defense benefit = [J(empty) - J(D)] / J(empty)
```

Abandonment produces no target loss. When a budget B is specified, patch cost
must not exceed B. Removing the budget constraint does not remove patch costs
from the objective. Benefit is undefined when J(empty) is zero; the benchmark
experiments use a nonzero empty-defense objective.

Patching disables the corresponding vulnerability fact. Reachability and
minimum attack costs propagate through the graph. The proposed formulation
embeds these relations in a mixed-integer optimization model, avoiding an
explicit enumeration of all attack paths. All six benchmark graphs satisfy
the DAG and at-most-one-OR-prerequisite-per-AND conditions checked for the
paper's cost-recursion argument.

| Task identifier | Method |
| --- | --- |
| `stackelberg` | Proposed cost-recursive Stackelberg formulation |
| `empty` | No-defense reference |
| `random` | Random defense baseline |
| `ga` | Genetic-algorithm defense baseline |
| `path_enum` | Explicit path-enumeration baseline |

The core formulation is in [solve_mulval__stackelberg_main.py](solve_mulval__stackelberg_main.py). Comparison
methods are in baselines/. The experiment workers in SP/scripts/ apply the
recorded task parameters and collect results. The anytime worker implements
the corresponding search-and-record procedures over a fixed time window.

## Benchmark Datasets

| Instance | Directory | Hosts | Nodes | Edges | OR | AND | LEAF | Targets | Patches |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| AG1 | D64 | 8 | 64 | 72 | 14 | 21 | 29 | 2 | 9 |
| AG2 | D244 | 22 | 244 | 307 | 42 | 90 | 112 | 6 | 37 |
| AG3 | D1045 | 75 | 1045 | 1437 | 148 | 411 | 486 | 20 | 204 |
| AG4 | D2822 | 180 | 2822 | 4041 | 358 | 1142 | 1322 | 60 | 615 |
| AG5 | D6330 | 420 | 6330 | 8974 | 838 | 2536 | 2956 | 150 | 1366 |
| AG6 | D11026 | 676 | 11026 | 16575 | 1350 | 4500 | 5176 | 300 | 3075 |

"Patches" counts hardenable vulnerability nodes, not distinct CVE identifiers.
The machine-readable version is [tables/table1_recomputed.csv](tables/table1_recomputed.csv).

AG6 uses a directional layered local extension of vul-net-ng. Its network
contains layers of size [1, 75, 300, 300]: one attack origin, 75 entry hosts,
300 intermediate hosts, and 300 target hosts. Thus, 676 includes the attack
origin; excluding it gives 675. The network topology has 1,425 directed edges.
These are network edges, distinct from the 16,575 attack-graph edges. The
300 goals are execCode targets on h376--h675. AG6's generation evidence includes
input.P, summary.json, network_topology.json, and blocking_certificate.json
under data/D11026/. The topology export contains devices and edges rather
than the full upstream vulnerability-description inventory.

Each benchmark provides these principal inputs:

| File | Contents |
| --- | --- |
| `VERTICES.CSV` | Headerless node records: ID, label, type, score. |
| `ARCS.CSV` | Headerless MulVAL dependency records. |
| `costs.json` | Fixed `attack_costs` and `defense_costs` keyed by node ID. |

In the stored ARCS.CSV convention, the first node depends on the second node:
a row (i, j, ...) records that j is a prerequisite of i. Drawings can reverse
the arrow direction to show prerequisites leading to conclusions. Use CSV
parsing for vertex labels, which may themselves contain commas.

Task files explicitly identify the graph paths, cost path, target IDs, and
input hashes. Use these task definitions to select targets; do not substitute
a guessed target set based on the appearance of a graph.

For the main benchmark cost maps, AND action costs and patch costs are
independently sampled integers from 1 to 10 using sorted node IDs and seeds
7 + node_count and 1000007 + node_count, respectively. All methods share the
same frozen maps. Repeating a search with another seed does not redraw costs.
Target reward and loss are both 1000 in the base benchmark settings.
Sensitivity experiments use the separately recorded sensitivity_costs.json
for cost replicate 1 and modify the factor specified in each task. The case
study has its own cost and reward/loss configuration.

## Quick Start

Run all commands from this artifact's root directory, on the
submission-artifact branch. The directory containing this README must also
contain [run.py](run.py), [verify.py](verify.py), and [experiment_index.json](experiment_index.json).

### Verify archived results

```bash
python3 verify.py
```

This uses the Python standard library. Successful execution prints a JSON
report with status "passed" and tasks 1003. It checks release-file hashes,
archived strategies and aggregates, anytime traces, and all 416 case-study
solutions. It does not run a new optimization experiment.

### Install dependencies

```bash
python3.13 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

### Run a small benchmark

```bash
python run.py --list
python run.py --id tables/D64/budget_300/stackelberg/seed_7
```

The new output appears in:

```text
reruns/tables/D64/budget_300/stackelberg/seed_7/
```

The archived result for this task has objective 11 and defense benefit 0.989.
Use objective values, feasibility, and solver status for comparison; measured
runtime can differ across systems.

### Regenerate figures

```bash
python plot.py
```

This writes PNG and PDF versions of Figures 3, 4, and 5 into figures/.
It reads tables/, not reruns/. It replaces the corresponding figure files.
Run [verify.py](verify.py) before plotting, or use a separate checkout for regenerated
figures: rendering differences can change file hashes in [MANIFEST.json](MANIFEST.json).

## Experiments and Paper Correspondence

The experiment index records seven groups:

| Group | Tasks | Purpose |
| --- | ---: | --- |
| `tables` | 192 | Budgeted/unbudgeted comparison; Tables 2 and 3 |
| `sensitivity` | 36 | AG3 parameter sensitivity; Figure 3 |
| `budget` | 224 | AG3 budget sweep; Figure 4 |
| `anytime_budget300` | 60 | AG1–AG5 anytime curves; Figure 5a–e |
| `anytime_unbudgeted_supplement` | 60 | Unbudgeted AG1–AG5 supplementary runs |
| `anytime_AG6` | 15 | AG6 anytime curves; Figure 5f |
| `case` | 416 | Four case-study scenarios |
| **Total** | **1,003** |  |

The first three groups contain 452 fixed-work tasks. The next three contain
135 anytime tasks. The no-defense anytime curve is a constant reference and
does not require a separate timed search task.

### Tables 2 and 3: effectiveness and runtime

The tables group compares all six graphs under budget 300 and without a
budget constraint. Fixed-work tasks have a 60-second limit. Table 2 uses the
Proposed seed-7 result, Random's mean over 50 samples, and GA's mean over ten
runs with seeds 7--16. Table 3 reports Proposed build, solve, and total times
averaged over seeds 7, 8, and 9. Numerical summaries are [tables/table2.csv](tables/table2.csv) and
[tables/table3.csv](tables/table3.csv). A task is one worker invocation; Random's 50 samples occur
inside its task and are not 50 separate indexed tasks.

### Figure 3: sensitivity

The 36 Proposed tasks use AG3, cost replicate 1, and a base budget of 300.
They vary attack-cost scale, defense-cost scale, budget, or target loss, one
factor at a time. The complete factor values are in task.json files and
[tables/figure3.csv](tables/figure3.csv). The base budget applies except when budget is the varied
factor. These are numerical sensitivity settings, not measured monetary costs.

### Figure 4: budget sweep

The budget group evaluates AG3 at B = 0, 20, ..., 300. Each budget includes the
no-defense, Random, path-enumeration, and Proposed tasks, plus ten GA seeds.
The plot uses [tables/figure4.csv](tables/figure4.csv). Missing benefit values from unsuccessful
path-enumeration runs remain missing; they are not plotted as zero benefits.

### Figure 5: anytime comparison

The time window is 100 seconds and search seeds are 7, 8, and 9. The main
figure imposes budget 300 on every instance, AG1--AG6. For AG6 only, it adds
the Proposed method without a budget constraint. The AG6 batch contains
12 budgeted tasks (four search methods times three seeds) and three
unbudgeted Proposed tasks. It does not contain unbudgeted AG6 anytime
baseline measurements.

The plotted curves are mean best-so-far benefits from [tables/figure5_AG1_AG5.csv](tables/figure5_AG1_AG5.csv)
and [tables/figure5_AG6.csv](tables/figure5_AG6.csv). Each run starts with the known empty defense;
only improvements are retained. The horizontal axis is symmetric logarithmic
(symlog), with a linear region near zero and threshold 0.02 seconds.

Actual unbudgeted AG1--AG5 trajectories are supplied separately in
experiments/anytime_unbudgeted_supplement/ and
[tables/anytime_unbudgeted_supplement.csv](tables/anytime_unbudgeted_supplement.csv). They are supplementary results and
are not the inputs to the main Figure 5a--e panels.

### Tables 4 and 5, Figure 8, and the case graph

Case configurations and archived runs are under SP/08_case_study/configs/
and experiments/case/. Table exports are [tables/table4.csv](tables/table4.csv) and table5.csv;
[tables/case_focus.csv](tables/case_focus.csv) contains selected budget points. The actual solver
input is documented by [tables/case_actual_nodes.csv](tables/case_actual_nodes.csv) and
figures/case_actual_graph.dot/.svg. [plot.py](plot.py) regenerates only Figures 3--5;
it does not regenerate the case-study figure or reaggregate fresh runs.

## Case Study

The case study contains six hosts and six vulnerabilities:

| Host | Service/controller | Vulnerability | Patchable |
| --- | --- | --- | --- |
| `h1` | Apache HTTP | CVE-2021-42013 | Yes |
| `h2` | FortiOS SSL VPN | CVE-2022-42475 | Yes |
| `h3` | Tomcat | CVE-2017-12617 | Yes |
| `h4` | Redis on Debian | CVE-2022-0543 | Yes |
| `h5` | Remote Desktop Services | CVE-2019-0708 | Yes |
| `h6` | Modicon M221 | CVE-2018-7798 | No |

The frozen solver graph has 45 nodes and 45 edges: 12 OR, 13 AND, and 20 LEAF
nodes. Six vulnerability-exploitation actions have scenario-specific attack
costs; auxiliary network-access rules have zero cost. The five patchable
vulnerabilities yield 2^5 = 32 possible defense sets per scenario.

There are two targets. Redis code execution is node 1, with attacker reward
60 and defender loss 200. Controller network-configuration modification is
node 32, with attacker reward 120 and defender loss 1000. Costs are numerical
model parameters; no currency unit is implied.

The four focal results illustrate different defense decisions:

| Scenario | Budget | Selected patch | Patch cost | Target loss | Objective J |
| --- | ---: | --- | ---: | ---: | ---: |
| S1 | 15 | Tomcat | 11 | 0 | 11 |
| S2 | 5 | Remote Desktop Services | 5 | 200 | 205 |
| S3 | 5 | None | 0 | 200 | 200 |
| S4 | 4 | Apache HTTP | 4 | 0 | 4 |

S1 blocks both targets. S2 blocks the controller route while the attacker
selects Redis. S3 leaves the network unchanged because the attacker's
preferred target is already the lower-loss Redis target. In S4 the targets
remain reachable, but the patch raises minimum attack costs sufficiently
that their utilities become -66 and -14; the attacker abandons the attack.
This distinguishes economic deterrence from making all targets unreachable.

The archive contains 336 budget-sweep solves and 80 repeated solves.
[verify.py](verify.py) compares all 416 solutions with exhaustive enumeration of the
32 defense sets per scenario. The scenario parameters and input facts are
included with the case-study code. Use [run.py](run.py) for frozen-input replay; the
original full-generation entry point requires external MulVAL dependencies.

## Environment and Running Experiments

The recorded environment uses Python 3.13.9 and these pinned packages:

| Package | Version |
| --- | --- |
| PySCIPOpt | 6.2.1 |
| NumPy | 2.3.5 |
| pymoo | 0.6.1.5 |
| Matplotlib | 3.10.6 |

SCIP 10.0.2 was observed in the audited installation. Its historical version
was not separately archived; [environment.json](environment.json) states this evidence limit.
The runner uses POSIX process groups and signals, so use Linux or a compatible
POSIX environment. Native Windows execution is not covered by this runner.
No XSB or MulVAL installation is needed to solve the supplied frozen graphs.

To inspect tasks from one group:

```bash
python run.py --experiment anytime_AG6 --list
python run.py --experiment case --list
```

To rerun a full group, choose the corresponding command:

```bash
python run.py --experiment tables
python run.py --experiment sensitivity
python run.py --experiment budget
python run.py --experiment anytime_budget300
python run.py --experiment anytime_unbudgeted_supplement
python run.py --experiment anytime_AG6
python run.py --experiment case
```

Groups run sequentially, with one task per subprocess and one solver/BLAS
thread per process. A full replay can take hours. Prefer a small task first,
then select the groups relevant to the result being checked.

Each new task directory contains task.json, meta.json, stdout.log, and the
worker's outputs when available. The runner refuses an already-existing task
output directory. To repeat a task, choose a fresh output root:

```bash
python run.py --id tables/D64/budget_300/stackelberg/seed_7 --output reruns/repeat_2
```

It does not overwrite experiments/. A failed or interrupted invocation may
leave its task directory in place; use a new output root for the next attempt.
Fixed-work and anytime processes receive two seconds of external grace
beyond the recorded limit; case tasks receive ten seconds beyond the default
60-second limit. A hard timeout is recorded in meta.json and may leave no
result.json. Check metadata as well as the runner's terminal output: hard
timeouts are recorded outcomes and do not themselves cause a nonzero exit.

Neither [verify.py](verify.py) nor [plot.py](plot.py) automatically imports reruns/. Fresh outputs
retain the worker result formats for comparison with their archived task.
The supplied tables remain summaries of the archived experiments.

## Results and Metrics

[experiment_index.json](experiment_index.json) maps each task ID to an experiment group, worker kind,
folder, and task.json. Task files are the source of exact method, seed,
budget, target, input-file, and time-limit settings. A null budget represents
an unbudgeted task. Case tasks embed their scenario configuration.

Archived task folders contain task specifications, sanitized execution
metadata, and returned results where available. Anytime tasks additionally
contain trace.jsonl event records. A trailing incomplete event can occur
when a process reaches a hard timeout; verification handles the recorded
terminal truncation condition.

Important distinctions when reading outputs:

* Objective and benefit: lower J is better; higher benefit is better. A
  negative benefit means patch spending and remaining loss exceed J(empty).
* Budget: it limits patch spending, not the total objective or attacker cost.
* Random: the fixed-work comparison reports the mean of 50 samples, whereas
  an anytime curve reports the best strategy found so far. These are different
  statistics. The stored best Random strategy is not its sample mean.
* Timing: Table 3 Total uses total_solve_game. It is not process wall time and
  need not equal Build + Solve because other work is included.
* Status: TL denotes a time-limit outcome; EL denotes an enumeration-limit
  outcome. An absent objective for either is not a zero-valued objective.
* Optimality: a returned feasible strategy and a solver-certified optimum are
  different claims. Inspect status, gap, and bounds in the archived result.
* Anytime aggregation: curves average best-so-far benefits over three seeds;
  the std column uses population standard deviation. No smoothing or shifting
  of observed improvement times is applied by [plot.py](plot.py).

## Verification and Provenance

The verifier is independent of the optimization model's MIP constraints. It
uses an AND/OR graph evaluator to recompute saved strategies and enumerates
all case-study defenses. Its expected successful check counts are:

| Check | Count |
| --- | ---: |
| Fixed-work tasks | 452 |
| Returned strategies independently checked | 427 |
| Random sample means checked | 28 |
| Fixed tasks with no result after timeout | 21 |
| Anytime tasks | 135 |
| Anytime improvement events | 1812 |
| Anytime summary rows | 19305 |
| Case-study solves | 416 |
| Table 2 benefit/status cells | 60 |
| Table 3 rows | 12 |

Four other fixed-work records report enumeration limits without objectives.
For the large benchmark graphs, independent evaluation confirms the saved
strategy's feasibility and objective, not global optimality. Global
optimality claims rely on the archived solver statuses, gaps, and bounds.
Random records retain sample summaries and the best defense, but not every
sampled defense set; their means and spending can be checked, while the
included seeds and sampling implementation support fresh reruns.

[MANIFEST.json](MANIFEST.json) hashes release files. Task hashes separately identify the
frozen graph and cost bytes. Source input graph/cost bytes are preserved.
The main solver, baselines, and execution workers are preserved; packaging
adds the portable runner, verifier, plotting script, and relative task paths.
A case report generator's interpreter example was normalized to python3,
with old/new hashes documented in [audit/source_transformations.json](audit/source_transformations.json).

The original source audit performed 53 historical source-hash comparisons:
52 matched, and one orchestration/reporting driver differed. The recorded
workers, core solver, and baseline modules for that experiment matched.
The reason for the driver change is not established. See
AUDIT.txt, [audit/source_hash_checks.json](audit/source_hash_checks.json), and [audit/source_audit.json](audit/source_audit.json).

This artifact reproduces optimization on frozen graphs. It does not bundle
XSB, MulVAL, the full upstream CVE inventory, or a complete graph-generation
environment. AG6 uses a disclosed local extension rather than an unmodified
upstream topology preset. Public vulnerability references and upstream
attributions remain in the supplied materials.

Historical runtime is a measurement, not a bit-identical reproduction target.
The archive does not independently attest the original CPU model or RAM.
Some original queues ran concurrently, whereas [run.py](run.py) is sequential. Fresh
wall times should therefore be reported as new measurements rather than
silently substituted into the archived tables.

## Manuscript Notes and Anonymous Distribution

AUDIT.txt documents three main discrepancies in the audited manuscript:

* AG6 has 676 hosts including the attack origin, not 617. Both the table entry
  and the surrounding host-count range require this correction.
* Figure 5a--e uses budget 300. Figure 5f adds only the Proposed unbudgeted
  curve to the budget-300 comparison. The axis uses symlog, not a purely
  logarithmic scale. The unbudgeted AG1--AG5 data are a separate supplement.
* The manuscript's 39-node case illustration and appendix are not the raw
  45-node graph used by the archived solver runs. This artifact identifies the
  actual graph and node list explicitly. Matching node counts requires an
  updated figure/list or a documented mapping between the representations.

The release excludes the manuscript, original repository history, original
author metadata, machine-specific environment dumps, and original shell logs.
The privacy scan checks known source identities, local machine/account
markers, and credential signatures while retaining public source attribution.
Fresh rerun logs may contain local paths; reruns/ is ignored by Git and should
be excluded from a review archive.

Publishing under an existing account does not anonymize the account or its
other branches. If the review process requires an anonymous repository,
distribute this artifact through an independent anonymous mirror. This
README contains no author contact details or personal repository URLs.
