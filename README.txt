Anonymous experimental artifact
===============================

This artifact accompanies a cost-recursive Stackelberg defense model on MulVAL
attack graphs. It contains frozen graph inputs, fixed costs, solver/baseline
source, 1,003 archived task records, independently checked results, and portable
rerun/plot scripts. It does not include a manuscript, original Git history,
account URLs, machine-specific environment dumps, or shell logs.

IMPORTANT: the audited manuscript has inconsistencies described in AUDIT.txt.
The data have NOT been changed to match erroneous manuscript statements.
Publishing these files under an existing personal account does not anonymize
that account or its other branches. A blind-review mirror must be independent.

Quick start (run from the artifact root)
---------------------------------------
python3 verify.py

This requires only the Python standard library. It verifies checksums, saved
strategies, budgets, Table 2/3 aggregates, all anytime trajectories/means, and
all 416 case-study solutions against complete enumeration. No solver is run.

For fresh experiments, use Python 3.13 and the recorded dependencies:
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 run.py --list
python3 run.py --id tables/D64/budget_300/stackelberg/seed_7
python3 run.py --experiment sensitivity
python3 run.py --experiment budget
python3 run.py --experiment tables
python3 run.py --experiment anytime_budget300
python3 run.py --experiment anytime_AG6
python3 run.py --experiment case
python3 plot.py

Each selected task runs in a separate process with one solver/BLAS thread.
New results are written under reruns/, never over archived results. Existing
output directories are refused; use --output with a fresh directory to repeat.
A full rerun can take substantial time. Original timings are observations on
the original execution host, not expected bit-identical reproduction targets.
The archive records 60-second fixed-work limits (+2 seconds external grace),
100-second anytime windows, and case-study solver limits of 60 seconds.
A hard timeout remains a timeout; it is not a zero-valued fixed-work result.

Correspondence to the manuscript
--------------------------------
Table 1: tables/table1_recomputed.csv (AG6 host count corrected to 676).
Table 2: tables/table2.csv; experiments/tables/ (seed 7 Proposed,
         Random mean of 50 samples, GA mean over seeds 7--16).
Table 3: tables/table3.csv; same experiment, Proposed seeds 7,8,9.
Figure 3: tables/figure3.csv; experiments/sensitivity/; cost replicate 1.
Figure 4: tables/figure4.csv; experiments/budget/; budgets 0,20,...,300.
Figure 5(a--e): tables/figure5_AG1_AG5.csv; experiments/anytime_budget300/.
Figure 5(f): tables/figure5_AG6.csv; experiments/anytime_AG6/.
             Five budget-300 reference/algorithm curves plus only Proposed
             without a budget constraint. Three seeds 7,8,9; 100 seconds.
Supplement: tables/anytime_unbudgeted_supplement.csv and the correspondingly
            named experiment contain actual unbudgeted AG1--AG5 trajectories.
Tables 4/5 and Figure 8: SP/08_case_study/configs/, tables/case_focus.csv,
                       experiments/case/; S1--S4, five possible patches.
Figure 7/Appendix: figures/case_actual_graph.dot and
                  tables/case_actual_nodes.csv document the ACTUAL 45 nodes.
                  The manuscript's 39-node diagram is not this raw graph.

Cost and statistical conventions
-------------------------------
The defender minimizes J = defense cost + loss of the attacker's selected
target. Benefit = (J(empty)-J(defense))/J(empty); undefined if J(empty)=0.
Attacker utility = target reward - minimum reachable attack cost, with the
zero-utility abandonment option and defender-favorable utility ties.
Main-graph AND action/patch costs are independently sampled integers 1--10,
using sorted node IDs and seeds 7+node_count and 1000007+node_count. Fixed
cost maps are shared across algorithms and seeds. Reward=loss=1000.
Sensitivity scales multiply these maps; the case study uses separate costs.
All six graphs are DAGs; every AND node has at most one OR prerequisite.

Anytime records start with the known empty defense and retain only improvements.
Their means are NOT the Random fixed-sample means in Table 2. The time axis is
symlog with linear threshold 0.02 seconds, not a pure logarithmic axis.
The new plotting script labels budgets explicitly. It uses only archived
numeric summaries; no smoothing or shifting of measured times is performed.

Reproducibility and provenance limits
------------------------------------
verify.py uses an independent AND/OR evaluator, not the MIP, and exhaustively
enumerates the case study. It validates saved solution feasibility/objectives;
it does not independently certify global optimality on the six large graphs.
Their optimality claims come from archived solver status/gap/bound records.
Random trial summaries do not retain every sampled node set; their means and
budget spending are checked, and their stored best strategy is re-evaluated.
The deterministic sampling code and seeds are included for rerunning samples.

The main solver, baseline code and worker code are preserved. Packaging adds
portable task paths, a new output-isolating runner, verifier and figure script.
The case report generator's interpreter example was normalized to python3;
this is documented by hashes in audit/source_transformations.json.
Source input graph/cost bytes are preserved exactly. The new MANIFEST.json
hashes the RELEASE files, not the original machine-specific task metadata.
Source-data audit results are in audit/source_audit.json. Of 53 historical
source-hash comparisons, one orchestration/reporting script differs; all
recorded execution workers/core/baselines match. See AUDIT.txt for the limit.

This package reproduces optimization experiments from frozen MulVAL graphs;
it does not bundle XSB, MulVAL, the upstream vulnerability database or a full
network-generator environment. AG6 input.P, a topology-only network_topology.json export (devices and edges), and its blocking
certificate are included. AG6 used an explicit directional layered extension
of vul-net-ng, not an unmodified upstream topology preset. Upstream tools and
public vulnerability sources must still receive their normal attribution.
The archived environment confirms package versions; it does not contain a
historical CPU/RAM attestation. See AUDIT.txt for the unresolved hardware claim.

Do not invoke the original case-study full-generation entry point directly
without separately installing its external dependencies. Use run.py for the
supported frozen-input replay. Fresh output logs can contain local paths;
exclude reruns/ when preparing an anonymous archive.
