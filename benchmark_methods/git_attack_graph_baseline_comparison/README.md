# S1–S1000 四方法防御效果对比

本目录在 `git_atack_graph/` 的 S1、S2、S3、S300、S500 和 S1000 六个实例上比较：

- `empty`：不防御；
- `random`：随机防御；
- `path_enum`：完整攻击推导枚举 + 全部可行防御组合枚举，从中选择精确最优策略；
- `stackelberg`：本文方法，图中显示为 `Our`。

它与旧的 SWaT 基线目录相互独立，不修改或复用旧实验结果。

## 公平性设置

- 图方向按论文和可视化方向解释为“前提 -> 结论”。
- 默认选择全部无可视化后继的终点 OR 节点，六张图的目标闭包均覆盖整张图。
- 四种方法使用完全相同的目标、单位漏洞防御成本、攻击成本、收益/损失和防御预算。
- 默认预算为可防御漏洞数的 40%，向下取整且至少为 1；可用 `--budget` 改成固定预算。
- 随机方法默认运行 50 次。CSV 同时保留最好结果与均值；对比图使用 50 次平均防御收益，避免只报告最好一次。
- 路径枚举不使用贪心：它枚举预算内所有相关防御组合，筛选能够阻断全部正效用攻击路径的组合，并按防御成本、节点数和节点 ID 依次选择最优解。预算内没有完整阻断策略时返回空防御，而不是花费无效成本。
- 每个“数据集 × 方法”在独立进程组中运行，默认硬时间上限为 60 秒。路径或防御组合枚举超过时间后会被终止，并记录 `status=timeout`；达到路径数量上限则单独记录为 `skipped_limit`。

## 运行

```bash
python3 benchmark_methods/git_attack_graph_baseline_comparison/run_benchmarks.py \
  --method-time-limit 60
```

快速检查：

```bash
python3 benchmark_methods/git_attack_graph_baseline_comparison/run_benchmarks.py \
  --datasets S1 \
  --method-time-limit 30 \
  --output-root /tmp/git_baseline_smoke
```

只验证路径枚举超时标记：

```bash
python3 benchmark_methods/git_attack_graph_baseline_comparison/run_benchmarks.py \
  --datasets S1 \
  --methods path_enum \
  --method-time-limit 0.001 \
  --skip-chart \
  --output-root /tmp/git_baseline_timeout_check
```

## 输出

- `git_attack_graph_baseline_comparison/benchmark_summary.csv`：六个实例的统一汇总；
- `git_attack_graph_baseline_comparison/defense_effectiveness_table.csv`：每个数据集一行、四种方法各一列的直观防御收益表；
- `git_attack_graph_baseline_comparison/selected_defense_strategies.csv`：每种方法选择的防御节点ID、标签、成本和策略口径；
- `git_attack_graph_baseline_comparison/results/<dataset>/<method>/result.json`：标准化逐项结果；
- `git_attack_graph_baseline_comparison/results/<dataset>/<method>/run.log`：运行日志；
- `git_attack_graph_baseline_comparison/defense_effectiveness_comparison.png`：论文用位图；
- `git_attack_graph_baseline_comparison/defense_effectiveness_comparison.pdf`：论文用矢量图。

`effectiveness_score` 是用于对比图的防御收益。随机方法使用 50 次试验的平均收益；其 `best_benefit_score` 仍保留最好一次的结果。超时结果不填充为 0，图中以 `T/O` 标识，避免把“未完成”误写成“无防御效果”。
