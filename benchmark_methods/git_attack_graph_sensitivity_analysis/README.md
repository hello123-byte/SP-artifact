# 参数敏感性分析：真实攻击图

本实验仅测试提出的 Stackelberg 防御模型（`Our`），并和已有的基线对比完全复用真实 `git_atack_graph` 数据、目标选择和成本语义。

- CSV 边为 `结论 -> 前提`；论文/可视化边为 `前提 -> 结论`。
- 每个数据集选择全部可视化终点 OR 节点，因此目标节点没有可视化后继节点，且当前六个实例的目标闭包覆盖原图全部节点。
- 可防御节点仅为 `vulExists(...)` / `ttpExists(...)` 类型的 LEAF。
- 所有非当前扫描参数固定为基准值：`预算比例 β=0.4`、单位防御成本 `c_d=1`、目标收益 `R=1000`、目标损失 `L=1000`、攻击动作成本倍率 `α=1`、`mip-gap=0`。
- 每个求解任务具备独立的 60 秒硬时限；超时明确写为 `timeout`，不被当作数值结果。

四个单因素扫描如下：

| 因素 | 取值 | 不变的含义 |
|---|---|---|
| 防御预算比例 `β` | 0.1, 0.2, 0.3, 0.4, 0.5, 0.6 | `c_d=1`，预算为 `floor(β·N_vul)` |
| 单位防御成本 `c_d` | 0.5, 1, 2, 3 | 预算同步为 `floor(0.4·N_vul)·c_d`，因而每个设置可防御的漏洞数量上限相同；只考察经济权衡变化 |
| 固定预算下的单位防御成本 `c_d` | 0.5, 1, 1.5, 2, 3, 4 | 固定货币预算 `B=8`（S3 的基准预算），因此成本越高，可部署的漏洞防御数量越少 |
| 攻击者目标收益 `R` | 250, 500, 1000, 2000 | 目标损失固定为 1000，考察攻击动机变化 |
| 攻击动作成本倍率 `α` | 0.5, 1, 2, 4 | 对每个 AND 攻击动作成本统一乘以 `α`，保留 score 相对差异 |

运行完整实验：

```bash
python3 benchmark_methods/git_attack_graph_sensitivity_analysis/run_sensitivity_analysis.py
```

若已有前三类因素的结果，只补跑新加入的攻击动作成本扫描：

```bash
python3 benchmark_methods/git_attack_graph_sensitivity_analysis/run_sensitivity_analysis.py --resume
```

运行 S3 的固定预算成本扫描：

```bash
python3 benchmark_methods/git_attack_graph_sensitivity_analysis/run_sensitivity_analysis.py \
  --resume \
  --datasets S3 \
  --factors defense_cost_fixed_budget \
  --fixed-budget 8
```

先快速验证一个实例和一个因素：

```bash
python3 benchmark_methods/git_attack_graph_sensitivity_analysis/run_sensitivity_analysis.py \
  --datasets S1 \
  --factors budget_ratio \
  --budget-ratios 0.2,0.4,0.6
```

结果写入 `git_attack_graph_sensitivity_analysis/`：

- `protocol.json`：完整实验协议和各图规模；
- `sensitivity_summary.csv`：每个“因素 × 取值 × 数据集”的原始结果；
- `budget_ratio_benefit_table.csv`、`defense_cost_benefit_table.csv`、`defense_cost_fixed_budget_benefit_table.csv`、`reward_benefit_table.csv`、`action_cost_scale_benefit_table.csv`：适合直接绘图/写论文的透视表；
- `results/<factor>/<value>/<dataset>/`：求解器 JSON 和运行日志。

`benefit_score = (J(空防御)-J(D))/J(空防御)`，其中 `J(D)=防御成本+攻击者最优响应所致损失`。因此各参数取值下的分数都使用该取值本身的空防御作为基准；它衡量该设置内的相对防御收益，不应跨不同收益/损失设置直接解释为绝对经济量。
