# 冗余目标闭包规模基准集（上一版串行链内冗余）

本目录保留修改前的长串行链冗余数据用于对照，不会被当前分层生成命令覆盖。当前默认数据位于 `csv_target_closed_layered_benchmarks/`。

这里的每个目录都是一张独立生成的 MulVAL 攻击图。每张图只包含该案例要求的最终目标及其全部前提，所以算法实际处理的规模就是 CSV 中的规模，启用 `--target-closure` 后应删除 0 个节点和 0 条边。

按照论文和 MulVAL 可视化采用的“前提 -> 结论”方向：

- 每个 OR 结论都由 AND 规则推出；
- 每个 LEAF 都参与至少一条推导，不存在独立漂浮的 LEAF；
- 每个最终目标只能由目标所属主机的 root 权限和关键资产事实共同推出；
- 每台主机的远程利用和本地提权至少各有两条漏洞不同的平行路径；
- 生成器会拒绝存在“防御单个漏洞即可阻断全部最终目标”的图；
- 图是无环的，且所有节点都能推导到至少一个最终目标。

文件格式：

- `VERTICES.CSV`：`id,label,type,score`
- `ARCS.CSV`：`source,target,-1`。CSV 方向为“结论 -> 前提”，第三列固定为 `-1`
- `goals.txt`：该案例的最终目标 ID
- `summary.json`：实际节点/边数、结构诊断、闭包结果和单漏洞割点检查结果

当前包含约 1k、10k、100k 节点三种规模，每种规模分别包含 1、50、100、200 个目标的独立图。由于按完整主机和规则增减，实际节点数可能与标称规模相差少量节点，应以 `summary.json` 中的 `scale_reference.actual_nodes` 为准。

重新生成：

```bash
python3 run_target_closed_benchmarks.py --prepare-only --seed 7
```

运行测试：

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
