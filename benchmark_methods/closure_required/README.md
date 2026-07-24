# 方法 A：运行时目标闭包裁剪

生成一张每个规模含 200 个最终目标的总图，策略案例从该总图中选择 `1`、`50`、`100` 或 `200` 个目标；求解器的 `--target-closure` 再只保留这些已选目标所需的节点。

- 生成和测试代码入口：[run_benchmarks.py](run_benchmarks.py)
- 保留的原实现：[run_goal_count_benchmarks.py](../../run_goal_count_benchmarks.py)
- 图和策略案例数据：[`csv_scale_benchmarks/`](../../csv_scale_benchmarks/)
- 策略案例目标集合：`csv_scale_benchmarks/<scale>/goal_sets/goals_<n>.txt`

示例：

```bash
python3 benchmark_methods/closure_required/run_benchmarks.py \
  --skip-prepare \
  --scales scale_1k,scale_10k,scale_100k \
  --goal-counts 1,50,100,200 \
  --solver scip --mip-gap 0 --time-limit 600
```

这个方法的“实际求解规模”是运行时闭包后的规模，而不是总图规模。
