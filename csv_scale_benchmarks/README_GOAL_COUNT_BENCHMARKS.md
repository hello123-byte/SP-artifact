# Goal Count Benchmarks

这个目录用于测试 MulVAL Stackelberg 求解器在不同图规模和不同目标数量下的运行时间。

当前 benchmark 使用 `generate_large_mulval_csv.py` 的最新合成攻击图机制。生成图满足：

```text
LEAF 节点无前提
AND 节点必须有前提；每个 OR 节点必须由至少一个 AND 节点推导
AND 节点最多依赖 1 个 OR 节点
AND 节点至少依赖 1 个 LEAF 节点
图必须是 conclusion -> prerequisite 方向下的有向无环图
节点 score / 攻击成本为 1 到 100 的随机整数
```

## 默认规模

`run_goal_count_benchmarks.py` 默认准备并测试三档图规模：

```text
scale_1k      千级攻击图
scale_10k     万级攻击图
scale_100k    十万级攻击图
```

每个规模都生成 200 个目标，并测试以下目标数量：

```text
1, 50, 100, 200
```

每个 case 都固定使用：

```text
--target-closure
--defendable vul
--attack-cost-source score
```

benchmark 会在运行前按无防御状态估算所有目标的最小攻击成本，并自动设置 reward/loss。默认标定规则是：

```text
reward = loss = max(1000, 2 * max_goal_min_attack_cost)
```

这样 1..100 的随机 score 成本会真正进入求解，同时避免 reward=100 导致攻击者几乎总是选择 empty。

## 准备数据

只生成 / 重新生成 benchmark CSV 和 goal_sets，不运行求解器：

```bash
python run_goal_count_benchmarks.py --prepare-only
```

生成后每个 scale 目录包含：

```text
VERTICES.CSV
ARCS.CSV
summary.json
goal_sets/goals_1.txt
goal_sets/goals_50.txt
goal_sets/goals_100.txt
goal_sets/goals_200.txt
```

## 运行 benchmark

运行全部规模和目标数量：

```bash
python run_goal_count_benchmarks.py --time-limit 600
```

只运行某个规模：

```bash
python run_goal_count_benchmarks.py --scales scale_10k --time-limit 600
```

只运行部分目标数量：

```bash
python run_goal_count_benchmarks.py --goal-counts 1,50 --time-limit 600
```

如果已经准备好 CSV，不想重新生成输入数据：

```bash
python run_goal_count_benchmarks.py --skip-prepare --time-limit 600
```

## 输出

每个 case 会写：

```text
csv_scale_benchmarks/results/<scale>_goals_<N>.json
csv_scale_benchmarks/results/<scale>_goals_<N>.log
```

汇总表写到：

```text
csv_scale_benchmarks/results/benchmark_runtime_summary.csv
```

汇总表包含原始图规模、目标闭包后的图规模、成本来源、标定后的 reward/loss、目标成本统计、局部 Big-M / 旧全局 Big-M 对比、建模时间、求解时间和总 wall time。
