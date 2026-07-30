# 方法 B：生成时目标闭包（分层多分支拓扑）

每个 `规模 × 目标数` 都独立生成一张图，并且图中只包含该策略案例的最终目标及其全部前提。因此运行 `--target-closure` 时不会移除任何节点或边。

- 生成和测试代码入口：[run_benchmarks.py](run_benchmarks.py)
- 独立实现：[run_target_closed_benchmarks.py](../../run_target_closed_benchmarks.py)
- 当前分层图和策略案例数据：[`csv_target_closed_layered_benchmarks/`](../../csv_target_closed_layered_benchmarks/)
- 上一版串行链内冗余图：[`csv_target_closed_redundant_benchmarks/`](../../csv_target_closed_redundant_benchmarks/)
- 旧串行图（保留用于对照）：[`csv_target_closed_benchmarks/`](../../csv_target_closed_benchmarks/)
- 策略案例目标集合：`csv_target_closed_layered_benchmarks/<scale>/goals_<n>/goals.txt`

当前基准采用 `layered` 拓扑。按照论文中的“前提 -> 结论”方向，主机被划分为平衡层，相邻层之间采用多来源攻击路径；每个目标主机至少有两条漏洞不同的远程和本地推导路径。生成后会检查全图闭包和单漏洞全局割点，发现异常后立即拒绝输出。

示例：

```bash
python3 benchmark_methods/target_closed/run_benchmarks.py \
  --skip-prepare \
  --scales scale_1k,scale_10k,scale_100k \
  --goal-counts 1,50,100,200 \
  --warm-start-key-path \
  --solver scip --mip-gap 0 --time-limit 600
```

这个方法中 `summary.json` 的 `actual_nodes` 就是实际求解规模。

`--warm-start-key-path` 是可选项：它在当前攻击者最低成本推导链上贪心选择防御漏洞，并提交完整的 MIP 初始解。结果中的 `warm_start.accepted=true` 表示 SCIP 已接受该初始解；不加此选项可得到无 warm-start 的基线。
