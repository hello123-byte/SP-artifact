# 真实攻击图基准输出

本目录由 `run_git_attack_graph_benchmarks.py` 生成，输入数据来自 `git_atack_graph/`。

- `prepared/`：合法终点目标、闭包规模、成本校准和方向校验元数据
- `results/`：SCIP结果、日志和运行时间汇总

目标方向检查以“前提 -> 结论”的可视化方向为准。被选目标必须没有任何可视化后继节点。
