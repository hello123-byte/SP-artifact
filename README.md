# MulVAL 成本敏感斯塔克博弈求解器

本项目把 MulVAL 的 AND/OR 攻击图建模为**成本敏感、纯策略、强斯塔克博弈**，使用 SCIP 或 Gurobi 求解防御者的最优防御方案。

模型不枚举攻击路径。防御者先禁用部分可防御的 `LEAF` 事实；图随后传播可达性并递推每个目标的最小攻击推导成本；攻击者观察防御结果后，在可达目标和“空攻击”之间选择净效用最大的响应。

## 1. 项目文件

| 文件 | 功能 |
| --- | --- |
| `solve_mulval__stackelberg_main.py` | 主求解器：读取图和配置、构建 MIP、调用 SCIP/Gurobi、输出均衡结果。 |
| `build_mulval_game_config.py` | 配置生成器：生成可编辑 JSON，并自动标定目标奖励和损失。 |
| `mulval_cost_calibration.py` | 公共成本标定模块，供配置生成器和 benchmark 调用。 |
| `generate_large_mulval_csv.py` | 生成满足项目结构约定的大规模 MulVAL 风格 DAG。 |
| `run_goal_count_benchmarks.py` | 准备不同规模的图，改变目标数量并汇总求解耗时。 |
| `VERTICES.CSV` / `ARCS.CSV` | 默认节点和边文件。 |
| `large_config.json` | 当前大图的游戏配置示例。 |
| `csv_scale_benchmarks/` | benchmark 输入、结果和补充说明。 |

## 2. 博弈流程与假设

1. 防御者选择一组可防御 `LEAF`，并支付防御成本。
2. 被防御的 `LEAF` 变为不可用，AND/OR 图重新传播可达性。
3. 对每个可达节点计算最小攻击推导成本。
4. 攻击者选择一个可达目标，或者选择效用为 0 的空攻击。
5. 防御者最小化“防御成本 + 被攻击目标造成的损失”。

当前假设：

- 防御只直接作用于 `LEAF`，不能直接删除 `AND` 或 `OR`。
- `LEAF` 是已有事实，直接攻击成本固定为 0；攻击成本由 `AND` 动作节点累加。
- 攻击者只选择最终目标，不显式选择路径；最低成本推导由约束隐式表示。
- 目标奖励和防御者损失相互独立，不要求相等。
- 攻击成本必须非负，否则求解器会拒绝输入。

## 3. 数学符号与变量

攻击图记为 \(G=(V,E)\)。CSV 边方向为：

\[
(i,j)\in E
\quad\Longleftrightarrow\quad
i\text{ 是结论，}j\text{ 是 }i\text{ 的前提}
\]

即 `source -> target = conclusion -> prerequisite`。

| 符号 | 含义 |
| --- | --- |
| \(V_L,V_A,V_O\) | `LEAF`、`AND`、`OR` 节点集合。 |
| \(G_T\subseteq V_O\) | 攻击目标集合。 |
| \(D\subseteq V_L\) | 可防御 LEAF 集合。 |
| \(C(i)=\{j:(i,j)\in E\}\) | 节点 \(i\) 的前提集合，即代码中的 `children`。 |
| \(a_i\ge0\) | 节点直接攻击成本；当前只有 AND 可能非零。 |
| \(k_i\ge0\) | 防御节点 \(i\in D\) 的成本。 |
| \(R_g\ge0\) | 攻击者攻破目标 \(g\) 获得的奖励。 |
| \(L_g\ge0\) | 目标 \(g\) 被攻击时防御者承受的损失。 |
| \(B\) | 可选防御预算。 |
| \(\bar c_i\) | 节点推导成本的安全上界，用于变量上界和 Big-M。 |

MIP 变量：

| 变量 | 类型 | 含义 |
| --- | --- | --- |
| \(d_i\) | 二进制 | \(d_i=1\) 表示禁用可防御 LEAF \(i\)。 |
| \(x_i\) | 二进制 | 防御后节点 \(i\) 是否可达。 |
| \(c_i\in[0,\bar c_i]\) | 连续 | 节点可达时的最小推导成本；不可达时为 0。 |
| \(z_{ij}\) | 二进制 | OR 节点 \(i\) 是否选择前提 \(j\) 作为最低成本推导。 |
| \(y_g\) | 二进制 | 攻击者是否选择目标 \(g\)。 |
| \(y_0\) | 二进制 | 攻击者是否选择空攻击。 |
| \(U\ge0\) | 连续 | 攻击者在所有响应中的最大净效用。 |

## 4. 四类成本和收益

| 参数 | 承担方 | 模型作用 |
| --- | --- | --- |
| 攻击动作成本 \(a_i\) | 攻击者 | 沿图累加，降低攻击者净效用。 |
| 目标奖励 \(R_g\) | 攻击者获得 | 决定目标吸引力。 |
| 目标损失 \(L_g\) | 防御者承担 | 进入防御者目标，不进入攻击者效用。 |
| 防御成本 \(k_i\) | 防御者承担 | 进入预算和防御者目标。 |

### 4.1 攻击动作成本

节点成本按以下优先级确定：

1. `--node-attack-costs` 显式值。
2. JSON 的 `nodes[].attack_cost`。
3. `score` 模式下，AND 节点 CSV 中大于 0 的 `score`。
4. 其他 AND 使用 `--default-action-cost`，默认 1。
5. LEAF 和 OR 始终为 0。

`--default-leaf-cost` 和 `leaf_attack_cost` 仅兼容旧命令，不改变当前 LEAF 成本。

### 4.2 奖励和损失

可达目标 \(g\) 的攻击者净效用为：

\[
u_g=R_g-c_g
\]

`reward` 决定攻击者是否攻击，`loss` 决定防御者多想避免该目标。主求解器默认两者均为 100。

配置生成器和 benchmark 默认按无防御成本自动标定：

\[
R=\max\left(
R_{\min},
\left\lceil\alpha\max_{g\in G_T}c_g^{(0)}\right\rceil
\right)
\]

其中 \(c_g^{(0)}\) 是无防御最小成本，默认 \(\alpha=2\)、\(R_{\min}=1000\)。未指定 loss 时令 \(L=R\)。大图使用 1 到 100 的随机 score 时，不应盲目使用奖励 100，否则攻击者很可能合理地选择空攻击。

### 4.3 防御成本和预算

\[
C_D=\sum_{i\in D}k_i d_i
\]

`--defense-costs` 或 `nodes[].defense_cost` 可逐节点设置 \(k_i\)，否则默认 1。提供预算时加入：

\[
\sum_{i\in D}k_i d_i\le B
\]

没有硬预算时，防御成本仍在目标函数中，因此防御并非免费。

## 5. AND/OR 递推公式

### 5.1 可达性递推

\[
x_i=1-d_i\quad(i\in D),
\qquad
x_i=1\quad(i\in V_L\setminus D)
\]

\[
x_i=\bigwedge_{j\in C(i)}x_j\quad(i\in V_A)
\]

\[
x_i=\bigvee_{j\in C(i)}x_j\quad(i\in V_O)
\]

没有前提的 AND/OR 在当前实现中固定为不可达。

### 5.2 最小攻击成本递推

\[
c_i=
\begin{cases}
0, & i\in V_L,\ x_i=1,\\
a_i+\displaystyle\sum_{j\in C(i)}c_j,
  & i\in V_A,\ x_i=1,\\
\displaystyle\min_{j\in C(i):x_j=1}c_j,
  & i\in V_O,\ x_i=1,\\
0, & x_i=0.
\end{cases}
\]

AND 表示一次动作及全部前提，成本相加；OR 表示替代推导，选择仍可达的最低成本分支。

同一前提若在 AND 推导树的不同分支重复出现，会按递推式重复计入。模型计算的是 AND/OR **推导成本**，不是对全局共享动作去重后的攻击计划成本。

## 6. MIP 约束的实际形式

### 6.1 可达性约束

LEAF：

\[
x_i+d_i=1\quad(i\in D),
\qquad
x_i=1\quad(i\in V_L\setminus D)
\]

对有 \(m=|C(i)|>0\) 个前提的 AND：

\[
x_i\le x_j\quad(\forall j\in C(i))
\]

\[
x_i\ge\sum_{j\in C(i)}x_j-(m-1)
\]

对 OR：

\[
x_i\ge x_j\quad(\forall j\in C(i))
\]

\[
x_i\le\sum_{j\in C(i)}x_j
\]

### 6.2 成本归零和 AND 等式

所有节点：

\[
0\le c_i\le\bar c_i x_i
\]

因此不可达节点成本为 0。LEAF 额外满足 \(c_i=a_ix_i=0\)。

令 \(q_i=a_i+\sum_{j\in C(i)}c_j\)，对有前提的 AND：

\[
c_i\ge q_i-\bar c_i(1-x_i)
\]

\[
c_i\le q_i+\bar c_i(1-x_i)
\]

当 \(x_i=1\) 时得到 \(c_i=q_i\)；不可达时 Big-M 放松该等式。

### 6.3 OR 最小值线性化

每条 OR 分支创建 \(z_{ij}\)：

\[
z_{ij}\le x_j,
\qquad
\sum_{j\in C(i)}z_{ij}=x_i
\]

对全部可达分支施加上界：

\[
c_i\le c_j+\bar c_i(1-x_j)
\]

使被选择分支和 OR 成本相等：

\[
c_i\ge c_j-\bar c_j(1-z_{ij})
\]

\[
c_i\le c_j+\bar c_i(1-z_{ij})
\]

第一组保证 \(c_i\) 不高于任何可达分支，后两组保证它等于某个可达分支，最终得到最小值。

### 6.4 攻击者最佳响应

攻击者恰好选择一个响应，不可达目标不能被选：

\[
y_0+\sum_{g\in G_T}y_g=1,
\qquad
y_g\le x_g
\]

代码将目标效用写为：

\[
u_g=R_gx_g-c_g
\]

可达时等于 \(R_g-c_g\)；不可达时为 0，但由 \(y_g\le x_g\) 排除。空攻击效用为 0。最大效用变量满足：

\[
U\ge u_g\quad(\forall g\in G_T)
\]

\[
U\le u_g+M_g^U(1-y_g)\quad(\forall g\in G_T)
\]

\[
U\le M_0^U(1-y_0)
\]

若 \(y_g=1\)，则 \(U=u_g\)，只能选择最大效用目标。若 \(y_0=1\)，则 \(U=0\)，只有所有可达目标净效用不大于 0 时空攻击才是最佳响应。

### 6.5 防御者目标和平局规则

\[
\min\quad
\sum_{i\in D}k_id_i+
\sum_{g\in G_T}L_gy_g
\]

`objective_cost_form` 是该最小值，`defender_utility` 是其相反数。

模型采用**强斯塔克博弈平局规则**：多个响应具有相同最大攻击者效用时，联合 MIP 选择使防御者目标最小的响应。若某目标净效用恰好为 0，它与空攻击并列，模型选择对防御者更有利者。当前没有 `weak`、`tie_epsilon`、`--tie-breaking` 或 `--tie-epsilon` 参数。

## 7. 局部成本上界和 Big-M

对 DAG，从前提向结论递推安全上界：

\[
\bar c_i=
\begin{cases}
0, & i\in V_L,\\
a_i+\displaystyle\sum_{j\in C(i)}\bar c_j, & i\in V_A,\\
\displaystyle\max_{j\in C(i)}\bar c_j, & i\in V_O.
\end{cases}
\]

OR 上界使用 `max` 而不是成本语义中的 `min`，因为防御可能删除便宜分支。局部上界比全图统一的大 Big-M 更紧。

若检测到环，无法拓扑计算的节点回退到：

\[
M_{global}=(|V|+1)\max\left(1,\max_i|a_i|\right)+1
\]

`--cost-big-m` 只覆盖循环图回退值；DAG 节点仍使用局部上界。结果中的 `cost_big_m` 是局部上界最大值，`legacy_global_cost_big_m` 是全局回退值，`utility_big_m` 是最佳响应约束的最大松弛值。

## 8. 输入格式和安装

### VERTICES.CSV

无表头：

```text
id,label,type,score
```

示例：

```text
1,execCode(plc1,root),OR,0.9
2,RULE remote exploit plc1,AND,0.5
3,vulExists(plc1,CVE-EXAMPLE,svc,remoteExploit,privEscalation),LEAF,0.2
```

`type` 为 `LEAF`、`AND` 或 `OR`。score 模式下，仅 AND 节点大于 0 的 score 作为直接成本。

### ARCS.CSV

无表头：

```text
source,target
```

若 OR 目标 1 由 AND 规则 2 推出，规则依赖 LEAF 3：

```text
1,2
2,3
```

需要 Python 3.10 或更新版本。默认 SCIP：

```bash
pip install pyscipopt
```

也可安装 `gurobipy`，但还需要有效的 Gurobi license。

## 9. 主求解器用法

```bash
python3 solve_mulval__stackelberg_main.py \
  --vertices VERTICES.CSV \
  --arcs ARCS.CSV \
  --goals 1,55 \
  --defendable vul \
  --budget 2 \
  --target-closure \
  --out mulval_result.json
```

`--goals` 是节点 ID，不是目标数量。省略时选择入度为 0 的 OR。

| 参数 | 说明 |
| --- | --- |
| `--config` | 配置生成器产生的 JSON。 |
| `--default-reward` / `--default-loss` | 默认奖励和损失，均为 100。 |
| `--goal-rewards` / `--goal-losses` | 如 `1:100,55:80` 或 JSON 字符串。 |
| `--defense-cost` / `--defense-costs` | 默认或逐节点防御成本。 |
| `--defendable` | `all`、`vul`、`hacl`、`vul_hacl`。 |
| `--budget` | 防御成本上限。 |
| `--attack-cost-source` | `constant` 或 `score`。 |
| `--default-action-cost` | 默认 AND 成本，默认 1。 |
| `--node-attack-costs` | 逐节点攻击成本。 |
| `--target-closure` | 仅保留目标及递归前提，大图建议开启。 |
| `--cost-big-m` | 循环图全局回退值。 |
| `--time-limit` | 求解时间限制，单位秒。 |
| `--solver` | `scip` 或 `gurobi`。 |
| `--write-lp` | 求解前导出 MIP。 |

可防御范围：

| 模式 | 节点 |
| --- | --- |
| `all` | 除 `attackerLocated` 外全部 LEAF。 |
| `vul` | `vulExists` 开头的 LEAF。 |
| `hacl` | `hacl` 开头的 LEAF。 |
| `vul_hacl` | `vulExists` 或 `hacl` 开头的 LEAF。 |

显式传 `--defendable` 会重新计算整个集合；不传时可使用配置中的逐节点 `defendable`。

### JSON 配置工作流

```bash
python3 build_mulval_game_config.py \
  --vertices VERTICES.CSV \
  --arcs ARCS.CSV \
  --goals 1,55 \
  --defendable vul \
  --attack-cost-source score \
  --target-closure \
  --out mulval_game_config.json
```

可编辑 `goals[].enabled/reward/loss`、`nodes[].attack_cost/defendable/defense_cost` 和 `defaults.budget/target_closure/solver`。

```bash
python3 solve_mulval__stackelberg_main.py \
  --vertices VERTICES.CSV \
  --arcs ARCS.CSV \
  --config mulval_game_config.json \
  --out mulval_result.json
```

若要保留逐节点 `defendable`，不要额外传 `--defendable`。目标闭包从目标沿 `conclusion -> prerequisite` 递归保留全部前提，不改变所选目标语义，却常能显著缩小模型。

## 10. 输出结果

| 字段 | 含义 |
| --- | --- |
| `status` | `optimal`、`timelimit`、`infeasible` 等。 |
| `selected_defenses` | 被选择的防御节点及成本。 |
| `reachable_goals` | 可达目标、最小攻击成本和净效用。 |
| `attacker_response` | `empty` 或被攻击目标。 |
| `attacker_utility` | 被选响应的净效用。 |
| `objective_cost_form` | 防御成本与目标损失之和。 |
| `defender_utility` | `-objective_cost_form`。 |
| `target_closure` | 裁剪前后节点数和边数。 |
| `cost_upper_bound_stats` | 上界和循环回退统计。 |
| `timings_seconds` | 读入、建模、优化和提取耗时。 |

达到时间限制但已有可行解时会输出当前最好解；没有解时响应和目标值保持 `null` 或空列表。

## 11. 各 Python 文件的详细使用

### solve_mulval__stackelberg_main.py

项目入口，依次完成输入解析、目标闭包、局部上界、MIP 构建、求解和结果提取：

```bash
python3 solve_mulval__stackelberg_main.py --help
```

### build_mulval_game_config.py

它不求解博弈，而是选择目标、计算无防御目标成本、标定 reward/loss，并为节点写出成本和防御属性。

省略 `--goals` 时，目标来源依次是：`--summary` 的目标、合成图中的 `execCode(crown_jewel_...)`、入度为 0 的 OR。

```bash
python3 build_mulval_game_config.py \
  --vertices large_mulval_VERTICES.CSV \
  --arcs large_mulval_ARCS.CSV \
  --summary large_mulval_summary.json \
  --defendable vul \
  --attack-cost-source score \
  --reward-multiplier 2 \
  --min-goal-reward 1000 \
  --target-closure \
  --out large_config.json
```

### mulval_cost_calibration.py

内部模块，没有命令行入口：

| 函数 | 功能 |
| --- | --- |
| `estimate_goal_min_attack_costs(...)` | 无防御状态下递推目标成本。 |
| `calibrate_goal_values(...)` | 根据最大成本、倍率和下限生成 reward/loss。 |
| `parse_csv_files(...)` | 为 benchmark 读取 CSV。 |

成本估计使用拓扑迭代，适合大 DAG；含环且无法递推的目标成本为无穷。

### generate_large_mulval_csv.py

生成网络访问、远程利用、权限提升、横向移动和 crown-jewel 目标组成的合成 DAG：

```bash
python3 generate_large_mulval_csv.py \
  --hosts 1200 \
  --services-per-host 2 \
  --vuln-per-service 2 \
  --lateral-rules-per-host 1 \
  --goals 4 \
  --seed 7 \
  --vertices-out large_mulval_VERTICES.CSV \
  --arcs-out large_mulval_ARCS.CSV \
  --summary-out large_mulval_summary.json
```

生成器验证图无环、LEAF 无前提、非 LEAF 有前提、AND 不依赖 AND、每个 AND 至多一个 OR 前提且至少一个 LEAF 前提。score 随机取 1 到 100；summary 包含目标 ID 和结构诊断。

### run_goal_count_benchmarks.py

默认准备 `scale_1k`、`scale_10k`、`scale_100k`，每档运行 1、50、100、200 个目标；固定开启目标闭包、仅防御漏洞、使用 score 成本和自动标定值。

只准备输入：

```bash
python3 run_goal_count_benchmarks.py --prepare-only
```

完整运行：

```bash
python3 run_goal_count_benchmarks.py --solver scip --time-limit 600
```

只运行部分 case：

```bash
python3 run_goal_count_benchmarks.py \
  --skip-prepare \
  --scales scale_10k \
  --goal-counts 1,50 \
  --time-limit 600
```

每个 case 的 JSON 和日志写入 `csv_scale_benchmarks/results/`，总表是 `benchmark_runtime_summary.csv`。

## 12. 实验注意事项

- 大图优先启用 `--target-closure`。
- reward 远小于目标成本而导致空攻击不是错误，而是理性响应。
- loss 不影响攻击者选哪个目标，只影响防御者的防御选择。
- budget 限制可行域，defense cost 同时仍进入目标函数。
- 当前结果给出目标最小成本，但不恢复具体攻击路径。
- 循环图虽可回退到全局 Big-M，但递推语义和数值表现都更适合 DAG。
- 若需要最坏情况的弱斯塔克博弈，必须修改平局建模，不能使用已移除的旧参数。
