# 方法 B：生成时目标闭包（新方法）

每个 `规模 × 目标数` 都独立生成一张图，并且图中只包含该策略案例的最终目标及其全部前提。因此运行 `--target-closure` 时不会移除任何节点或边。

- 生成和测试代码入口：[run_benchmarks.py](run_benchmarks.py)
- 独立实现：[run_target_closed_benchmarks.py](../../run_target_closed_benchmarks.py)
- 图和策略案例数据：[`csv_target_closed_benchmarks/`](../../csv_target_closed_benchmarks/)
- 策略案例目标集合：`csv_target_closed_benchmarks/<scale>/goals_<n>/goals.txt`

示例：

```bash
python3 benchmark_methods/target_closed/run_benchmarks.py \
  --skip-prepare \
  --scales scale_1k,scale_10k,scale_100k \
  --goal-counts 1,50,100,200 \
  --solver scip --mip-gap 0 --time-limit 600
```

这个方法中 `summary.json` 的 `actual_nodes` 就是实际求解规模。
