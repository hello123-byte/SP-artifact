# S1–S1000 四方法时间分析

本实验在 S1、S2、S3、S300、S500 和 S1000 上重复运行 Empty、Random、精确 Path enumeration 和 Our，比较端到端 wall time。

默认设置：

- 重复3次；
- 每个“数据集 × 方法 × 重复”最大30秒；
- 防御预算为可防御漏洞数的40%；
- Random每次执行50个随机策略；
- 所有方法都在独立进程中运行，时间包含CSV读取、建模、求解和结果写出；
- 超时记录为 `timeout`，统计时不作为普通完成时间参与均值和中位数，图中按30秒上限以斜线柱和 `T/O` 显示。

运行：

```bash
python3 benchmark_methods/git_attack_graph_runtime_comparison/run_benchmarks.py
```

输出：

- `git_attack_graph_runtime_comparison/runtime_runs.csv`：每次独立运行；
- `git_attack_graph_runtime_comparison/runtime_summary.csv`：均值、标准差、中位数、最小值、最大值和超时次数；
- `git_attack_graph_runtime_comparison/runtime_table.csv`：每个数据集一行的直观中位数表；
- `git_attack_graph_runtime_comparison/runtime_comparison.png`：对数纵轴时间图；
- `git_attack_graph_runtime_comparison/runtime_comparison.pdf`：论文用矢量图；
- `git_attack_graph_runtime_comparison/runs/`：每次运行的完整JSON、日志和中间CSV。

Random的时间对应完整50次随机试验，不是单次随机策略的时间。Path enumeration 是精确防御组合枚举；大图出现 `timeout` 是组合爆炸的实验结果。
