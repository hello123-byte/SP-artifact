# 闭包规模基准集

这里的每个目录都是一张独立生成的 MulVAL 攻击图，而不是从一张包含更多目标的图中选择目标后再裁剪。

目录 `scale_<规模>/goals_<目标数>/` 中只包含该案例要求的最终目标。以论文和 MulVAL 可视化采用的“前提 -> 结论”理解，图中每一个节点都能推导出至少一个最终目标；在 CSV 的存储方向中，这等价于从每个最终目标沿 `source -> target`（结论 -> 前提）回溯，得到全图。

- `VERTICES.CSV`：`id,label,type,score`
- `ARCS.CSV`：`source,target,-1`；前两列的存储方向为结论 -> 前提，第三列固定为 `-1`。
- `goals.txt`：该案例仅有的最终目标 ID。
- `summary.json`：实际节点/边数、闭包验证结果和成本校准。

`scale_1k`、`scale_10k`、`scale_100k` 的目标节点数分别约为 1,000、10,000、100,000。因主机/规则是离散单位，实际节点数最多相差几个节点，`summary.json` 的 `scale_reference.actual_nodes` 是应报告的实际规模。

完整求解测试：

```bash
python3 run_target_closed_benchmarks.py \
  --skip-prepare \
  --scales scale_1k,scale_10k,scale_100k \
  --goal-counts 1,50,100,200 \
  --solver scip \
  --mip-gap 0 \
  --time-limit 600
```

求解器仍会启用 `--target-closure` 作防御性检查；对于这些输入，结果中的 `removed_vertices` 和 `removed_arcs` 均应为 `0`。
