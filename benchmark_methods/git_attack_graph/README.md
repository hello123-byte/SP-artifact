# git_atack_graph真实攻击图基准

本方法直接读取 `git_atack_graph/` 中的CSV，不再生成合成攻击图。输入文件不会被复制或修改。

边方向规则：

- CSV存储方向：`结论 -> 前提`
- 论文和可视化方向：`前提 -> 结论`
- 合法目标必须是OR节点，并且在可视化方向没有后继节点
- 等价CSV检查：目标ID不能出现在 `ARCS.CSV` 第二列

默认 `--goal-policy all-terminal` 会选择每张图的全部合法终点OR节点。对当前6张图，这些目标的联合闭包正好覆盖原图全部节点，因此测试规模就是原始CSV规模。

| 数据集 | 节点 | 边 | 合法终点目标 | 可防御漏洞 |
|---|---:|---:|---:|---:|
| S1 | 35 | 37 | 2 | 4 |
| S2 | 65 | 74 | 3 | 9 |
| S3 | 142 | 160 | 6 | 20 |
| S300 | 379 | 558 | 15 | 48 |
| S500 | 517 | 714 | 21 | 72 |
| S1000 | 1027 | 1420 | 42 | 152 |

真实数据用 `ttpExists(...)` 表示漏洞/TTP事实，因此 `--defendable vul` 同时识别 `vulExists(...)` 和 `ttpExists(...)`。

准备并检查目标：

```bash
python3 benchmark_methods/git_attack_graph/run_benchmarks.py \
  --prepare-only
```

精确测试：

```bash
python3 benchmark_methods/git_attack_graph/run_benchmarks.py \
  --skip-prepare \
  --datasets S1,S2,S3,S300,S500,S1000 \
  --goal-policy all-terminal \
  --warm-start-key-path \
  --solver scip \
  --mip-gap 0 \
  --time-limit 600
```

如果需要固定为单目标，可以使用 `--goal-policy max-closure`。该模式会在所有合法终点中选择目标闭包最大的一个；此时算法实际处理的是闭包后的节点数，而不是原始CSV总节点数。

输出：

- `git_attack_graph_benchmarks/prepared/<dataset>/goals.txt`
- `git_attack_graph_benchmarks/prepared/<dataset>/summary.json`
- `git_attack_graph_benchmarks/results/benchmark_runtime_summary.csv`
- `git_attack_graph_benchmarks/results/<dataset>.json`
- `git_attack_graph_benchmarks/results/<dataset>.log`
