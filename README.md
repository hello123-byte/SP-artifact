# MulVAL 成本敏感斯塔克博弈求解器

这个仓库把 MulVAL 生成的 AND/OR 攻击图建模为一个成本敏感的纯策略斯塔克博弈，并用 MIP 求解防御者的最优防御选择。

当前模型不枚举攻击路径或攻击计划。攻击者只选择最终目标或空攻击；每个目标的最小攻击代价由 AND/OR 图上的约束隐式计算。

## 模型语义

1. 防御者先承诺一组防御动作。防御动作只作用在 `LEAF` 事实节点上。
2. MulVAL AND/OR 图根据防御结果传播节点是否仍然可达。
3. 对每个可达节点计算最小推导成本：
   - `LEAF`：如果事实可用，成本固定为 0；LEAF 只表示事实前提，不额外累加攻击成本。
   - `AND`：成本为该动作节点成本加上所有前提节点成本。
   - `OR`：成本为所有可达子推导中的最小成本。
4. 攻击者观察防御后选择：
   - 如果所有可达目标的净效用都不为正，则选择空攻击。
   - 否则选择净效用最大的可达目标。

攻击者目标 `g` 的净效用为：

```text
reward(g) - min_attack_cost(g)
```

防御者最小化：

```text
defense_cost + loss(attacker_chosen_goal)
```

注意：当前版本不提供弱斯塔克博弈的 `weak` / `tie_epsilon` 扰动功能，也没有 `--tie-breaking` 或 `--tie-epsilon` 参数。

## 文件说明

```text
solve_mulval__stackelberg_main.py   主要求解器，读取 CSV/配置并求解 MIP
build_mulval_game_config.py         生成可编辑的 JSON 游戏配置
generate_large_mulval_csv.py        生成合成的大规模 MulVAL 风格 CSV 图
mulval_cost_calibration.py          估算目标攻击成本并自动标定 reward/loss
run_goal_count_benchmarks.py        对固定图规模、不同目标数量运行耗时 benchmark
VERTICES.CSV                        示例节点文件
ARCS.CSV                            示例边文件
csv_scale_benchmarks/               规模实验数据和说明
```

## 环境依赖

需要 Python 3.10 或更新版本。

默认求解器是 SCIP，需要安装 PySCIPOpt：

```bash
pip install pyscipopt
```

也可以使用 Gurobi：

```bash
pip install gurobipy
```

使用 Gurobi 时需要本机已有可用的 Gurobi license，并在命令中传入 `--solver gurobi`。

## 输入格式

### VERTICES.CSV

无表头，每行格式为：

```text
id,label,type,score
```

示例：

```text
1,execCode(plc1,root),OR,0.9
2,RULE remote exploit plc1,AND,0.5
3,vulExists(plc1,CVE-EXAMPLE,svc,remoteExploit,privEscalation),LEAF,0.2
```

`type` 支持：

```text
LEAF
AND
OR
```

### ARCS.CSV

无表头，每行格式为：

```text
source,target
```

边方向沿用求解器中的 MulVAL CSV 约定：

```text
conclusion -> prerequisite
```

也就是说，如果 `OR` 目标由某个 `AND` 规则推出，则边是：

```text
OR节点,AND规则节点
```

## 快速开始

使用仓库自带的 `VERTICES.CSV` 和 `ARCS.CSV`：

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

常用参数：

```text
--vertices              节点 CSV，默认 VERTICES.CSV
--arcs                  边 CSV，默认 ARCS.CSV
--goals                 逗号分隔的目标节点 id；不传时默认选择入度为 0 的 OR 节点
--default-reward        默认目标奖励，默认 100；大规模随机 score 成本建议显式调高
--default-loss          默认目标损失，默认 100；大规模随机 score 成本建议与 reward 同量级
--goal-rewards          按目标设置奖励，如 '{"1":100,"55":80}' 或 1:100,55:80
--goal-losses           按目标设置损失，如 '{"1":40,"55":100}' 或 1:40,55:100
--defense-cost          默认防御成本，默认 1
--defense-costs         按 LEAF 节点设置防御成本，如 '{"20":4,"29":2}' 或 20:4,29:2
--defendable            可防御 LEAF 范围：all、vul、hacl、vul_hacl
--budget                防御预算上限
--attack-cost-source    攻击成本来源：constant 或 score
--default-action-cost   AND 节点默认动作成本，默认 1
--default-leaf-cost     兼容旧命令；当前 LEAF 成本固定为 0
--node-attack-costs     按节点设置攻击成本；当前仅非 LEAF/OR 节点会生效
--cost-big-m            手动指定循环图回退用的全局 Big-M；DAG 默认使用局部成本上界
--target-closure        只保留目标及其递归前提，再构建 MIP；大图强烈建议开启
--time-limit            求解器时间限制，单位秒
--solver                scip 或 gurobi，默认 scip
--write-lp              导出生成的 MIP 模型文件
```

`--defendable` 的含义：

```text
all       除 attackerLocated 开头的 LEAF 外全部可防御
vul       只防御 vulExists 开头的 LEAF
hacl      只防御 hacl 开头的 LEAF
vul_hacl  防御 vulExists 或 hacl 开头的 LEAF
```

## 使用 JSON 配置

当图较大、参数较多时，可以先生成一个可编辑的配置文件：

```bash
python3 build_mulval_game_config.py \
  --vertices VERTICES.CSV \
  --arcs ARCS.CSV \
  --goals 1,55 \
  --defendable vul \
  --attack-cost-source score \
  --defense-cost 1 \
  --target-closure \
  --out mulval_game_config.json
```

如果没有显式传入 `--goal-reward` / `--goal-loss`，配置生成器会先按无防御状态估算目标最小攻击成本，再自动设置 reward/loss，默认取“不小于最大目标成本 2 倍，且至少 1000”。

然后编辑 `mulval_game_config.json` 中的：

```text
goals[].reward          每个目标的攻击者奖励
goals[].loss            每个目标被攻破后的防御者损失
nodes[].attack_cost     节点攻击成本；OR/LEAF 固定为 0，AND 表示动作成本
nodes[].defendable      LEAF 节点是否可防御
nodes[].defense_cost    LEAF 节点防御成本
defaults.budget         防御预算
defaults.solver         默认求解器
```

使用配置求解：

```bash
python3 solve_mulval__stackelberg_main.py \
  --vertices VERTICES.CSV \
  --arcs ARCS.CSV \
  --config mulval_game_config.json \
  --out mulval_result.json
```

如果希望使用配置文件中逐节点的 `defendable` 设置，运行求解器时不要再传 `--defendable`。一旦传入 `--defendable`，求解器会按该模式重新计算可防御节点集合。

## 输出结果

求解器会写出 JSON，例如 `mulval_result.json`。主要字段包括：

```text
status                    求解状态，如 optimal、timelimit、infeasible
solver                    使用的求解器
solution_concept          成本敏感纯策略斯塔克博弈均衡
attacker_utility_form     攻击者效用形式
defender_objective_form   防御者目标函数形式
goals                     目标节点、奖励和损失
defendable_leaf_count     可防御 LEAF 数量
selected_defenses         最优选择的防御节点及成本
reachable_goals           防御后仍可达的目标及最小攻击成本
attacker_response         攻击者选择：empty 或 attack_goal
attacker_utility          攻击者效用
defender_utility          防御者效用，即目标成本的相反数
objective_cost_form       defense_cost + attack_loss 的最优值
target_closure            目标闭包裁剪统计
cost_bound_formulation    成本 Big-M 形式，默认 local_dag_upper_bounds
cost_big_m                实际局部成本上界中的最大值
legacy_global_cost_big_m  旧全局 Big-M 公式对应值，用于对比数值尺度
utility_big_m             攻击者最佳响应约束使用的最大效用松弛值
timings_seconds           读入、建模、求解、提取结果等耗时
```

## 生成合成大图

`generate_large_mulval_csv.py` 可以生成用于规模测试的合成 MulVAL 风格图：

```bash
python3 generate_large_mulval_csv.py \
  --hosts 1200 \
  --services-per-host 2 \
  --vuln-per-service 2 \
  --lateral-rules-per-host 1 \
  --goals 4 \
  --vertices-out large_VERTICES.CSV \
  --arcs-out large_ARCS.CSV \
  --summary-out large_summary.json
```

输出包括：

```text
large_VERTICES.CSV
large_ARCS.CSV
large_summary.json
```

`large_summary.json` 中包含生成的目标节点 id，可以传给配置生成器的 `--summary` 参数。

## 运行目标数量 benchmark

`run_goal_count_benchmarks.py` 会先按最新合成攻击图机制准备三档输入图，再运行求解器并把结果写到：

```text
csv_scale_benchmarks/results/benchmark_runtime_summary.csv
```

默认规模和目标数量为：

```text
scale_1k      goals: 1, 50, 100, 200
scale_10k     goals: 1, 50, 100, 200
scale_100k    goals: 1, 50, 100, 200
```

每个 case 固定使用 `--target-closure`、`--defendable vul` 和 `--attack-cost-source score`。脚本会基于无防御状态下目标最小攻击成本自动标定 `--default-reward` / `--default-loss`，默认取“不小于最大目标成本 2 倍，且至少 1000”。

只准备 CSV 和 goal_sets，不运行求解器：

```bash
python3 run_goal_count_benchmarks.py --prepare-only
```

运行全部 benchmark：

```bash
python3 run_goal_count_benchmarks.py \
  --solver scip \
  --time-limit 600

# 如需手动固定收益/损失，而不是自动标定：
python3 run_goal_count_benchmarks.py \
  --solver scip \
  --default-reward 20000 \
  --default-loss 20000 \
  --time-limit 600
```

只运行部分规模或目标数量：

```bash
python3 run_goal_count_benchmarks.py \
  --skip-prepare \
  --scales scale_10k \
  --goal-counts 1,50 \
  --time-limit 600
```

## 建模和使用注意事项

- 求解器不枚举具体攻击路径，只通过 AND/OR 成本约束得到每个目标的最小攻击推导成本。
- 防御动作只作用于 `LEAF` 节点；非 LEAF 节点不会被直接防御。
- `attackerLocated` 开头的 LEAF 默认不可防御。
- 大规模图建议使用 `--target-closure`，否则 MIP 规模可能非常大。
- 求解器默认对 DAG 使用局部 Big-M：LEAF 上界为 0，AND 用自身动作成本加所有前提上界，OR 用前提上界最大值；这比旧的全局 Big-M 更紧，能缓解 LP 松弛和数值问题。
- 如果使用 `--attack-cost-source score`，AND 节点 CSV 的 `score` 为正时会作为动作攻击成本；OR/LEAF 的直接攻击成本固定为 0。
- 对 1..100 随机 score 成本的大图，不建议继续使用默认 reward=100。否则很多目标的最小攻击成本会远高于 reward，攻击者会大量选择空攻击，实验无法反映防御选择。benchmark 和配置生成器现在默认使用自动 reward/loss 标定。
- 旧的弱斯塔克博弈扰动参数已经移除；不要再使用 `--tie-breaking weak` 或 `--tie-epsilon`。
