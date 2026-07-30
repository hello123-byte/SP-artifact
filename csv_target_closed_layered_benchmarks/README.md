# 分层多分支目标闭包基准集

当前默认基准采用 `layered` 拓扑。按照论文和 MulVAL 可视化采用的“前提 -> 结论”方向，主机被划分为若干平衡层：

- 第一层主机由互联网入口事实推出网络访问；
- 后续主机至少从前一层的两个攻击来源获得路径；
- 前一层的每台主机都参与至少一条通向下一层的推导；
- 最后一层覆盖全部目标主机；
- 每台主机具有漏洞不同的远程利用和本地提权备选路径。

因此所有输出节点都能推导到至少一个最终目标，启用 `--target-closure` 后应删除 0 个节点和 0 条边。生成器还会拒绝包含单漏洞全局割点的图。

文件：

- `VERTICES.CSV`：`id,label,type,score`
- `ARCS.CSV`：`source,target,-1`，CSV 存储方向为“结论 -> 前提”
- `goals.txt`：该案例的最终目标 ID
- `summary.json`：节点、边、层数、层宽、最大主机跳数、结构诊断和闭包验证结果

当前包括约 1k、10k、100k 节点三种规模，每种规模分别有 1、50、100、200 个目标的独立攻击图。实际规模以 `summary.json` 中的 `scale_reference.actual_nodes` 为准。

重新生成：

```bash
python3 run_target_closed_benchmarks.py --prepare-only --seed 7
```

运行：

```bash
python3 benchmark_methods/target_closed/run_benchmarks.py \
  --skip-prepare \
  --scales scale_1k,scale_10k,scale_100k \
  --goal-counts 1,50,100,200 \
  --warm-start-key-path \
  --solver scip \
  --mip-gap 0 \
  --time-limit 600
```
