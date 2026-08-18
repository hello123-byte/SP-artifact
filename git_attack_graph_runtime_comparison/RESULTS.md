# Runtime comparison on the Git attack-graph datasets

## Experimental protocol

- Datasets: S1, S2, S3, S300, S500, and S1000.
- Methods: Empty, Random, exact Path enumeration, and Our.
- Each dataset-method pair was executed independently three times.
- The hard time limit was 30 seconds for every individual run.
- Random used 50 trials per run.
- Defense costs were one for every defendable vulnerability, and the budget was
  `floor(0.4 * number_of_defendable_vulnerabilities)`.
- Reported times are median end-to-end wall-clock times. They include input
  parsing, method execution, and result serialization.
- A timeout is reported as right-censored rather than as a completed 30-second
  observation.

## Median wall-clock time

| Dataset | Nodes | Empty (s) | Random (s) | Path enumeration (s) | Our (s) |
|---|---:|---:|---:|---:|---:|
| S1 | 35 | 0.030007 | 0.031802 | 0.031018 | 0.102636 |
| S2 | 65 | 0.032234 | 0.033177 | 0.033081 | 0.110572 |
| S3 | 142 | 0.031432 | 0.035464 | 0.185323 | 0.109814 |
| S300 | 379 | 0.032676 | 0.046293 | timeout | 0.144581 |
| S500 | 517 | 0.032526 | 0.048528 | timeout | 0.155219 |
| S1000 | 1027 | 0.036370 | 0.067608 | timeout | 0.214133 |

## Main observations

Empty and Random have low running times because they do not perform exact
optimization. Exact Path enumeration is inexpensive on S1 and S2, becomes
slower than Our on S3, and times out in every repetition on S300, S500, and
S1000. Our completes every instance; its median wall-clock time increases from
0.102636 seconds on S1 to 0.214133 seconds on S1000.

Runtime should be interpreted together with defense effectiveness: a faster
baseline is not preferable if it returns a substantially weaker defense
strategy.
