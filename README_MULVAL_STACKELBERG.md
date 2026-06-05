# MulVAL Stackelberg MIP 使用说明

这个版本使用三个输入文件：

```text
VERTICES.CSV
ARCS.CSV
mulval_game_config.json
```

其中：

```text
VERTICES.CSV / ARCS.CSV 负责描述 MulVAL 攻击图结构
mulval_game_config.json 负责描述目标收益、防御损失、攻击成本、防御成本、哪些节点可防御
```

## 1. 生成配置文件

```bash
/root/anaconda3/bin/python /workspace/MIP/M3/build_mulval_game_config.py \
  --vertices /workspace/MIP/VERTICES.CSV \
  --arcs /workspace/MIP/ARCS.CSV \
  --out /workspace/MIP/M3/mulval_game_config.json \
  --defendable vul_hacl
```

`--defendable` 可选：

```text
all       所有 LEAF 节点可防御，除了 attackerLocated
vul       只有 vulExists(...) 漏洞节点可防御
hacl      只有 hacl(...) 网络连通性节点可防御
vul_hacl  只有 vulExists(...) 和 hacl(...) 可防御
```

如果希望在配置文件中记录目标依赖闭包优化选项，可以生成配置时加入：

```bash
/root/anaconda3/bin/python /workspace/MIP/M3/build_mulval_game_config.py \
  --vertices /workspace/MIP/VERTICES.CSV \
  --arcs /workspace/MIP/ARCS.CSV \
  --out /workspace/MIP/M3/mulval_game_config.json \
  --defendable vul_hacl \
  --target-closure
```

## 2. 修改配置文件

在 `mulval_game_config.json` 中可以改：

```text
goals[].reward          攻击者攻下该目标的收益
goals[].loss            防御者失去该目标的损失
goals[].enabled         是否把该节点作为攻击目标

nodes[].attack_cost     该节点攻击成本
nodes[].defendable      该节点是否允许防御
nodes[].defense_cost    防御该节点的成本

defaults.budget         防御预算，null 表示不设预算
defaults.target_closure 是否在求解前只保留目标节点依赖闭包
```

## 3. 求解 Stackelberg 均衡

```bash
/root/anaconda3/bin/python /workspace/MIP/M3/solve_mulval_reachability_stackelberg.py \
  --vertices /workspace/MIP/VERTICES.CSV \
  --arcs /workspace/MIP/ARCS.CSV \
  --config /workspace/MIP/M3/mulval_game_config.json \
  --tie-breaking strong \
  --out /workspace/MIP/M3/mulval_cost_stackelberg_result.json
```

输出结果中：

```text
selected_defenses     防御者均衡策略
attacker_response     攻击者最优响应，可能是 empty
reachable_goals       防御后仍可达的目标及其最小攻击成本
objective_cost_form   防御成本 + 被攻击目标损失
attacker_utility      攻击者净收益
defender_utility      防御者效用
target_closure        目标依赖闭包优化的原始/缩减图规模统计
```

`--tie-breaking` 控制攻击者打平时的选择：

```text
strong  攻击者打平时选择对防御者更有利的目标
weak    攻击者打平时选择对防御者更不利的目标
```

例如要使用弱/悲观 Stackelberg：

```bash
/root/anaconda3/bin/python /workspace/MIP/M3/solve_mulval_reachability_stackelberg.py \
  --vertices /workspace/MIP/VERTICES.CSV \
  --arcs /workspace/MIP/ARCS.CSV \
  --config /workspace/MIP/M3/mulval_game_config.json \
  --tie-breaking weak
```

## 4. 可选：目标节点依赖闭包优化

使用 `--target-closure` 可以在建立 MIP 前，只保留已选目标节点及其递归前提节点：

```bash
/root/anaconda3/bin/python /workspace/MIP/M3/solve_mulval_reachability_stackelberg.py \
  --vertices /workspace/MIP/VERTICES.CSV \
  --arcs /workspace/MIP/ARCS.CSV \
  --config /workspace/MIP/M3/mulval_game_config.json \
  --target-closure \
  --out /workspace/MIP/M3/mulval_cost_stackelberg_result.json
```

当前 CSV 边方向是：

```text
conclusion -> prerequisite
```

因此目标依赖闭包从每个目标节点出发，沿 outgoing arc 递归遍历所有前提节点。闭包外节点不会影响这些目标的可达性、最小攻击成本、攻击者效用或防御者目标函数，因此该缩减对当前目标集合是无损的。

该选项默认关闭。命令行传入 `--target-closure` 会开启它；如果配置文件中 `defaults.target_closure` 为 `true`，也会自动开启。

## 5. 模型含义

攻击者效用：

```text
攻击目标 g 的净收益 = reward_g - min_attack_cost_g
空攻击收益 = 0
```

防御者目标：

```text
最小化 防御成本 + 攻击者最终选择目标造成的损失
```

该模型不枚举攻击路径，而是在 MIP 中隐式计算最小攻击成本：

```text
LEAF 节点成本 = leaf_attack_cost
AND 节点成本 = action_attack_cost + 所有前提节点成本
OR 节点成本 = 可达子节点中的最小成本
```
